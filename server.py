from dotenv import load_dotenv
load_dotenv(override=True)

from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash, get_flashed_messages, g
from flask_mail import Mail, Message
import psycopg2
import psycopg2.extras
import psycopg2.errors
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
import os
import secrets
import hashlib
import re
import logging
import traceback
from collections import defaultdict
# ─── AUTH MODULE ──────────────────────────────────────────────
from auth import authenticate_user, otp_service, email_service
from auth.auth_settings import get_otp_expiry_minutes, get_resend_delay_seconds, get_max_resend_attempts
from auth.local_auth import get_user_by_id
from auth.database import get_db as _get_pg_db, dict_cursor
from auth.ldap_auth import (
    search_ldap_user_by_email,
    verify_user_credentials_with_ldap,
    create_ldap_user,
    update_ldap_password,
    ldap_bind_as_user,
    get_user_profile_by_email,
    get_ldap_user_by_email,
)
from ldap3.core.exceptions import LDAPException, LDAPBindError
from utils.exporter import generate_generic_excel, generate_generic_pdf

app = Flask(__name__)

# Mail Configuration
app.config["MAIL_SERVER"] = os.getenv("MAIL_SERVER", "")
app.config["MAIL_PORT"] = int(os.getenv("MAIL_PORT", "0") or "0")
app.config["MAIL_USE_TLS"] = os.getenv("MAIL_USE_TLS") == "True"
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME", "")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD", "")
app.config["MAIL_DEFAULT_SENDER"] = os.getenv("MAIL_DEFAULT_SENDER", "")

mail = Mail(app)
app.secret_key = os.getenv("FLASK_SECRET_KEY", secrets.token_hex(32))

# LDAP Configuration from environment
_ldap_host = os.getenv("LDAP_SERVER", "ldap://127.0.0.1")
_ldap_port = os.getenv("LDAP_PORT", "389")
app.config["LDAP_SERVER"] = f"{_ldap_host}:{_ldap_port}" if ":" not in _ldap_host.split("//")[-1] else _ldap_host
app.config["LDAP_BASE_DN"] = os.getenv("LDAP_BASE_DN", "dc=pdmh,dc=hospital,dc=local")
app.config["LDAP_ADMIN_DN"] = os.getenv("LDAP_ADMIN_DN", "cn=admin,dc=pdmh,dc=hospital,dc=local")

# ─── LOGGING CONFIGURATION ────────────────────────────────────
if not logging.getLogger("eam").handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    _eam_logger = logging.getLogger("eam")
    _eam_logger.addHandler(_handler)
    _eam_logger.setLevel(logging.DEBUG)
    _eam_logger.propagate = False
logger = logging.getLogger("eam")

# Legacy DB_NAME removed — database is now PostgreSQL (see .env / auth/database.py)

def get_db():
    return _get_pg_db()


def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS departments (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS roles (
            id SERIAL PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            display_name TEXT NOT NULL,
            is_system_role INTEGER DEFAULT 0,
            created_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS permissions (
            id SERIAL PRIMARY KEY,
            code TEXT UNIQUE NOT NULL,
            display_name TEXT NOT NULL,
            description TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS role_permissions (
            role_id INTEGER NOT NULL,
            permission_id INTEGER NOT NULL,
            PRIMARY KEY (role_id, permission_id),
            FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
            FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            ldap_uid TEXT DEFAULT NULL,
            company_id TEXT DEFAULT NULL,
            role TEXT DEFAULT NULL,
            is_super_admin INTEGER DEFAULT 0,
            is_approved INTEGER DEFAULT 0,
            account_status TEXT DEFAULT 'pending_approval',
            approved_by INTEGER DEFAULT NULL,
            approved_at TEXT DEFAULT NULL,
            role_id INTEGER DEFAULT NULL,
            department_id INTEGER DEFAULT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (role_id) REFERENCES roles(id),
            FOREIGN KEY (department_id) REFERENCES departments(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS asset_types (
            id SERIAL PRIMARY KEY,
            department_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            prefix TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (department_id) REFERENCES departments(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS assets (
            id SERIAL PRIMARY KEY,
            asset_type_id INTEGER NOT NULL,
            department_id INTEGER NOT NULL,
            asset_id TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            serial_number TEXT NOT NULL,
            location TEXT,
            warranty_start TEXT,
            warranty_end TEXT,
            created_at TEXT NOT NULL,
            assigned_to_user_id INTEGER DEFAULT NULL,
            FOREIGN KEY (asset_type_id) REFERENCES asset_types(id),
            FOREIGN KEY (department_id) REFERENCES departments(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS asset_type_fields (
            id SERIAL PRIMARY KEY,
            asset_type_id INTEGER NOT NULL,
            field_name TEXT NOT NULL,
            field_type TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (asset_type_id) REFERENCES asset_types(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS asset_type_field_values (
            id SERIAL PRIMARY KEY,
            asset_id INTEGER NOT NULL,
            field_id INTEGER NOT NULL,
            value TEXT,
            FOREIGN KEY (asset_id) REFERENCES assets(id),
            FOREIGN KEY (field_id) REFERENCES asset_type_fields(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS asset_custom_fields (
            id SERIAL PRIMARY KEY,
            asset_id INTEGER NOT NULL,
            field_name TEXT NOT NULL,
            field_type TEXT NOT NULL,
            value TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (asset_id) REFERENCES assets(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tickets (
            id SERIAL PRIMARY KEY,
            ticket_type TEXT NOT NULL,
            department_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            asset_id INTEGER,
            created_by_user_id INTEGER NOT NULL,
            assigned_to_user_id INTEGER DEFAULT NULL,
            status TEXT NOT NULL DEFAULT 'raised',
            created_at TEXT NOT NULL,
            FOREIGN KEY (department_id) REFERENCES departments(id),
            FOREIGN KEY (asset_id) REFERENCES assets(id),
            FOREIGN KEY (created_by_user_id) REFERENCES users(id),
            FOREIGN KEY (assigned_to_user_id) REFERENCES users(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ticket_status_history (
            id SERIAL PRIMARY KEY,
            ticket_id INTEGER NOT NULL,
            status TEXT NOT NULL,
            changed_by INTEGER DEFAULT NULL,
            changed_at TEXT NOT NULL,
            FOREIGN KEY (ticket_id) REFERENCES tickets(id) ON DELETE CASCADE,
            FOREIGN KEY (changed_by) REFERENCES users(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS pending_registrations (
            id              SERIAL PRIMARY KEY,
            first_name      TEXT    NOT NULL,
            last_name       TEXT    NOT NULL,
            email           TEXT    NOT NULL,
            username        TEXT    NOT NULL,
            password_hash   TEXT    NOT NULL,
            otp             TEXT,
            otp_created_at  TEXT,
            otp_expires_at  TEXT,
            created_at      TEXT    NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS otp_codes (
            id          SERIAL PRIMARY KEY,
            user_id     INTEGER NOT NULL,
            otp_code    TEXT    NOT NULL,
            purpose     TEXT    NOT NULL DEFAULT 'login',
            created_at  TEXT    NOT NULL,
            expires_at  TEXT    NOT NULL,
            used        INTEGER NOT NULL DEFAULT 0,
            attempts    INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id          SERIAL PRIMARY KEY,
            user_id     INTEGER NOT NULL,
            token_hash  TEXT    NOT NULL,
            created_at  TEXT    NOT NULL,
            expires_at  TEXT    NOT NULL,
            used        INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ldap_config (
            id              INTEGER PRIMARY KEY DEFAULT 1,
            ldap_server     TEXT NOT NULL DEFAULT '',
            ldap_port       TEXT NOT NULL DEFAULT '',
            search_base_dn  TEXT NOT NULL DEFAULT '',
            admin_bind_dn   TEXT NOT NULL DEFAULT '',
            admin_bind_pw   TEXT NOT NULL DEFAULT '',
            attr_mail       TEXT NOT NULL DEFAULT 'mail',
            attr_uid        TEXT NOT NULL DEFAULT 'uid',
            attr_given_name TEXT NOT NULL DEFAULT 'givenName',
            attr_sn         TEXT NOT NULL DEFAULT 'sn',
            is_enabled      INTEGER NOT NULL DEFAULT 0,
            updated_at      TEXT
        )
    """)
    # ─── INCIDENT MANAGEMENT TABLES ─────────────────────────────────
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id SERIAL PRIMARY KEY,
            incident_code TEXT UNIQUE NOT NULL,
            title TEXT NOT NULL,
            location TEXT NOT NULL,
            department_id INTEGER,
            priority TEXT NOT NULL DEFAULT 'Medium',
            severity TEXT DEFAULT 'Medium',
            description TEXT NOT NULL,
            incident_date TEXT NOT NULL,
            reported_by_id INTEGER NOT NULL,
            assigned_manager_id INTEGER,
            assigned_technician_id INTEGER,
            status TEXT NOT NULL DEFAULT 'NEW',
            estimated_repair_cost DOUBLE PRECISION,
            estimated_repair_time TEXT,
            actual_repair_cost DOUBLE PRECISION,
            completion_time TEXT,
            labour_hours DOUBLE PRECISION,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (department_id) REFERENCES departments(id),
            FOREIGN KEY (reported_by_id) REFERENCES users(id),
            FOREIGN KEY (assigned_manager_id) REFERENCES users(id),
            FOREIGN KEY (assigned_technician_id) REFERENCES users(id)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incident_investigations (
            id SERIAL PRIMARY KEY,
            incident_id INTEGER NOT NULL,
            notes TEXT,
            cause_suspected TEXT,
            estimated_cost DOUBLE PRECISION,
            estimated_time TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (incident_id) REFERENCES incidents(id)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incident_rcas (
            id SERIAL PRIMARY KEY,
            incident_id INTEGER NOT NULL,
            root_cause_category TEXT,
            why1 TEXT,
            why2 TEXT,
            why3 TEXT,
            why4 TEXT,
            why5 TEXT,
            final_root_cause TEXT,
            contributing_factors TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (incident_id) REFERENCES incidents(id)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incident_corrective_actions (
            id SERIAL PRIMARY KEY,
            incident_id INTEGER NOT NULL,
            repair_actions TEXT,
            parts_replaced TEXT,
            materials_used TEXT,
            labour_hours DOUBLE PRECISION,
            actual_cost DOUBLE PRECISION,
            completion_time TEXT,
            comments TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (incident_id) REFERENCES incidents(id)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incident_verifications (
            id SERIAL PRIMARY KEY,
            incident_id INTEGER NOT NULL,
            result TEXT,
            verified_by_id INTEGER,
            comments TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (incident_id) REFERENCES incidents(id),
            FOREIGN KEY (verified_by_id) REFERENCES users(id)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incident_closures (
            id SERIAL PRIMARY KEY,
            incident_id INTEGER NOT NULL,
            resolution_summary TEXT,
            final_root_cause TEXT,
            total_repair_cost DOUBLE PRECISION,
            preventive_action_required INTEGER DEFAULT 0,
            preventive_recommendations TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (incident_id) REFERENCES incidents(id)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incident_media (
            id SERIAL PRIMARY KEY,
            incident_id INTEGER NOT NULL,
            step_name TEXT NOT NULL,
            file_path TEXT NOT NULL,
            uploaded_by_id INTEGER,
            uploaded_at TEXT NOT NULL,
            FOREIGN KEY (incident_id) REFERENCES incidents(id),
            FOREIGN KEY (uploaded_by_id) REFERENCES users(id)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incident_audit_logs (
            id SERIAL PRIMARY KEY,
            incident_id INTEGER NOT NULL,
            step_name TEXT,
            performed_by_id INTEGER,
            action TEXT NOT NULL,
            old_value TEXT,
            new_value TEXT,
            timestamp TEXT NOT NULL,
            FOREIGN KEY (incident_id) REFERENCES incidents(id),
            FOREIGN KEY (performed_by_id) REFERENCES users(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS system_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    for _k, _v in [('MAIL_SERVER',''), ('MAIL_PORT',''), ('MAIL_USERNAME',''), ('MAIL_PASSWORD',''), ('MAIL_DEFAULT_SENDER','')]:
        cursor.execute("INSERT INTO system_settings (key, value) VALUES (%s, %s) ON CONFLICT (key) DO NOTHING", (_k, _v))

    # ── MIGRATION: clear hardcoded personal email from SMTP defaults ──
    cursor.execute("UPDATE system_settings SET value = '' WHERE key = 'MAIL_USERNAME' AND value LIKE '%@gmail.com'")
    cursor.execute("UPDATE system_settings SET value = '' WHERE key = 'MAIL_DEFAULT_SENDER' AND value LIKE '%@gmail.com'")

    # ── MIGRATION: add attempts column if missing ────────────────────
    cursor.execute("SAVEPOINT sp_migration_1")
    try:
        cursor.execute("ALTER TABLE otp_codes ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0")
        cursor.execute("RELEASE SAVEPOINT sp_migration_1")
    except Exception:
        cursor.execute("ROLLBACK TO SAVEPOINT sp_migration_1")

    # ── MIGRATION: add users columns if missing ──────────────────────
    columns_to_add = [
        ("is_super_admin", "INTEGER DEFAULT 0"),
        ("is_approved", "INTEGER DEFAULT 0"),
        ("account_status", "TEXT DEFAULT 'pending_approval'"),
        ("approved_by", "INTEGER DEFAULT NULL"),
        ("approved_at", "TEXT DEFAULT NULL"),
        ("role_id", "INTEGER DEFAULT NULL"),
        ("department_id", "INTEGER DEFAULT NULL")
    ]
    for col_name, col_type in columns_to_add:
        cursor.execute(f"SAVEPOINT sp_migration_col_{col_name}")
        try:
            cursor.execute(f"ALTER TABLE users ADD COLUMN {col_name} {col_type}")
            cursor.execute(f"RELEASE SAVEPOINT sp_migration_col_{col_name}")
        except Exception:
            cursor.execute(f"ROLLBACK TO SAVEPOINT sp_migration_col_{col_name}")

    # ── MIGRATION: add assets assigned_to_user_id if missing ─────────
    cursor.execute("SAVEPOINT sp_migration_2")
    try:
        cursor.execute("ALTER TABLE assets ADD COLUMN assigned_to_user_id INTEGER DEFAULT NULL")
        cursor.execute("RELEASE SAVEPOINT sp_migration_2")
    except Exception:
        cursor.execute("ROLLBACK TO SAVEPOINT sp_migration_2")

    # ── MIGRATION: convert legacy ticket statuses to new lifecycle ──
    cursor.execute("SAVEPOINT sp_migration_3")
    try:
        cursor.execute("UPDATE tickets SET status = 'raised' WHERE status = 'Open'")
        cursor.execute("RELEASE SAVEPOINT sp_migration_3")
    except Exception:
        cursor.execute("ROLLBACK TO SAVEPOINT sp_migration_3")

    # Seed history for existing tickets that have no history entry yet
    cursor.execute("SAVEPOINT sp_migration_4")
    try:
        cursor.execute("""
            INSERT INTO ticket_status_history (ticket_id, status, changed_at)
            SELECT t.id, t.status, t.created_at
            FROM tickets t
            WHERE NOT EXISTS (
                SELECT 1 FROM ticket_status_history h WHERE h.ticket_id = t.id
            )
        """)
        cursor.execute("RELEASE SAVEPOINT sp_migration_4")
    except Exception:
        cursor.execute("ROLLBACK TO SAVEPOINT sp_migration_4")

    # ── MIGRATION: add ldap_uid column if missing ─────────────────
    cursor.execute("SAVEPOINT sp_migration_ldap_uid")
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN ldap_uid TEXT DEFAULT NULL")
        cursor.execute("RELEASE SAVEPOINT sp_migration_ldap_uid")
    except Exception:
        cursor.execute("ROLLBACK TO SAVEPOINT sp_migration_ldap_uid")

    # ── MIGRATION: drop password_hash column (LDAP is sole identity provider)
    cursor.execute("SAVEPOINT sp_migration_drop_pw")
    try:
        cursor.execute("ALTER TABLE users DROP COLUMN password_hash")
        cursor.execute("RELEASE SAVEPOINT sp_migration_drop_pw")
    except Exception:
        cursor.execute("ROLLBACK TO SAVEPOINT sp_migration_drop_pw")

    # Run roles and permissions bootstrap
    bootstrap_roles_and_permissions(cursor)

    # Migrate existing users that don't have account_status set properly
    cursor.execute("""
        UPDATE users SET
            account_status = 'active',
            is_approved = 1
        WHERE company_id IS NOT NULL AND role IS NOT NULL AND role != 'super_admin' AND (account_status IS NULL OR account_status = 'pending_approval')
    """)

    cursor.execute("""
        UPDATE users SET
            account_status = 'pending_approval',
            is_approved = 0
        WHERE (company_id IS NULL OR role IS NULL) AND is_super_admin = 0 AND (account_status IS NULL OR account_status = 'pending_approval')
    """)

    conn.commit()
    conn.close()


def bootstrap_roles_and_permissions(cursor):
    # Roles
    roles = [
        ('super_admin', 'Super Admin', 1),
        ('admin', 'Admin', 0),
        ('technician', 'Technician', 0),
        ('manager', 'Manager', 0),
        ('department_head', 'Department Head', 0),
        ('employee', 'Employee', 0)
    ]
    for name, display_name, is_system in roles:
        cursor.execute("""
            INSERT INTO roles (name, display_name, is_system_role, created_at)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT(name) DO UPDATE SET
                display_name=excluded.display_name,
                is_system_role=excluded.is_system_role
        """, (name, display_name, is_system, datetime.now(ZoneInfo("Asia/Kolkata")).isoformat()))

    # Permissions
    permissions = [
        ('users.view', 'View Users', 'Allow viewing list of pending and active users'),
        ('users.approve', 'Approve Users', 'Allow authorizing pending user accounts'),
        ('users.edit', 'Edit Users', 'Allow modifying user profile, roles, and company IDs'),

        ('roles.view', 'View Roles', 'Allow viewing list of roles and permissions'),
        ('roles.manage_permissions', 'Manage Role Permissions', 'Allow editing permission mapping for roles'),
        ('departments.view_all', 'View All Departments', 'Allow accessing all departments'),
        ('departments.view_assigned', 'View Assigned Department', 'Restrict access to assigned department only'),
        ('assets.view', 'View Assets', 'Allow viewing assets'),
        ('assets.create', 'Create Assets', 'Allow adding new assets'),
        ('assets.edit', 'Edit Assets', 'Allow editing assets'),
        ('assets.delete', 'Delete Assets', 'Allow deleting assets'),
        ('assets.export', 'Export Assets', 'Allow exporting asset details to Excel or PDF'),
        ('tickets.view', 'View Tickets', 'Allow viewing tickets (placeholder)'),
        ('tickets.review', 'Review Tickets', 'Allow reviewing tickets (placeholder)'),
        ('tickets.assign_technician', 'Assign Technician', 'Allow assigning technicians (placeholder)'),
        ('tickets.view_reports', 'View Reports', 'Allow viewing aggregated ticket logs, summaries, and timeline phases'),
        ('tickets.assign', 'Assign Requests', 'Allow allocating and assigning technicians to incoming support tickets'),
        ('global.export.excel', 'Export to Excel', 'Allow generating and downloading spreadsheet files'),
        ('global.export.pdf', 'Export to PDF', 'Allow generating and downloading PDF documents'),
        ('settings.manage', 'Manage System Settings', 'Allow configuring LDAP and other system-level settings'),
        ('incidents.create', 'Create Incidents', 'Allow raising new incident reports'),
        ('incidents.view_own', 'View Own Incidents', 'Allow employees to view their own incidents'),
        ('incidents.view_dept', 'View Department Incidents', 'Allow viewing all department incidents'),
        ('incidents.review_assign', 'Review & Assign Incidents', 'Allow managers to review and assign incidents'),
        ('incidents.investigate', 'Investigate Incidents', 'Allow technicians to perform investigations'),
        ('incidents.rca', 'Perform Root Cause Analysis', 'Allow technicians to perform RCA'),
        ('incidents.corrective_action', 'Perform Corrective Actions', 'Allow technicians to perform corrective actions'),
        ('incidents.verify_close', 'Verify & Close Incidents', 'Allow managers to verify and close incidents'),
        ('incidents.reassign_manager', 'Reassign Manager', 'Allow department heads to reassign managers'),
        ('incidents.override_edit', 'Override & Edit', 'Allow department heads to edit any workflow step'),
        ('incidents.reports', 'Incident Reports', 'Allow viewing incident analytics and reports')
    ]
    for code, display_name, desc in permissions:
        cursor.execute("""
            INSERT INTO permissions (code, display_name, description)
            VALUES (%s, %s, %s)
            ON CONFLICT(code) DO UPDATE SET
                display_name=excluded.display_name,
                description=excluded.description
        """, (code, display_name, desc))

    # Fetch role IDs and permission IDs to build mappings
    cursor.execute("SELECT id, name FROM roles")
    role_ids = {row['name']: row['id'] for row in cursor.fetchall()}

    cursor.execute("SELECT id, code FROM permissions")
    perm_ids = {row['code']: row['id'] for row in cursor.fetchall()}

    # Mappings
    admin_perms = [
        'users.view', 'users.approve', 'users.edit',
        'roles.view', 'departments.view_all',
        'assets.view', 'assets.create', 'assets.edit', 'assets.delete', 'assets.export',
        'tickets.view_reports', 'tickets.assign',
        'global.export.excel', 'global.export.pdf',
        'settings.manage',
        'incidents.create', 'incidents.view_dept', 'incidents.reports'
    ]
    dept_head_perms = [
        'departments.view_assigned', 'assets.view', 'assets.export',
        'global.export.excel', 'global.export.pdf',
        'incidents.create', 'incidents.view_dept', 'incidents.review_assign',
        'incidents.verify_close', 'incidents.reassign_manager', 'incidents.override_edit',
        'incidents.reports'
    ]
    tech_perms = [
        'tickets.view',
        'global.export.excel', 'global.export.pdf',
        'incidents.create', 'incidents.investigate', 'incidents.rca', 'incidents.corrective_action'
    ]
    manager_perms = [
        'tickets.view', 'tickets.review', 'tickets.assign_technician',
        'tickets.view_reports', 'tickets.assign',
        'global.export.excel', 'global.export.pdf',
        'assets.export',
        'incidents.create', 'incidents.view_dept', 'incidents.review_assign',
        'incidents.verify_close', 'incidents.reports'
    ]

    employee_perms = [
        'incidents.create', 'incidents.view_own'
    ]

    mappings = [
        ('admin', admin_perms),
        ('department_head', dept_head_perms),
        ('technician', tech_perms),
        ('manager', manager_perms),
        ('employee', employee_perms)
    ]

    for r_name, p_codes in mappings:
        r_id = role_ids.get(r_name)
        if r_id:
            for p_code in p_codes:
                p_id = perm_ids.get(p_code)
                if p_id:
                    cursor.execute("""
                        INSERT INTO role_permissions (role_id, permission_id)
                        VALUES (%s, %s)
                        ON CONFLICT (role_id, permission_id) DO NOTHING
                    """, (r_id, p_id))


def _create_super_admin_ldap_entry(username: str, email: str, password: str) -> bool:
    """
    Self-healing: create the super admin LDAP directory entry directly
    via the admin service account when the identity is missing from the
    directory tree.

    Returns True if the entry was created or already exists, False on failure.
    """
    try:
        created = create_ldap_user(username, password, "Super", "Admin", email)
        if created:
            logger.info("[SUPER ADMIN BOOTSTRAP] LDAP entry created: uid=%s", username)
            return True
        logger.warning("[SUPER ADMIN BOOTSTRAP] LDAP create_ldap_user returned False for uid=%s", username)
        return False
    except Exception as exc:
        logger.warning("[SUPER ADMIN BOOTSTRAP] LDAP entry creation failed for uid=%s: %s", username, exc)
        return False


def seed_demo_data():
    """
    No-op. Dummy seed data has been removed.
    Only the super admin account is bootstrapped via bootstrap_super_admin().
    """
    pass


def bootstrap_super_admin():
    """
    Self-healing super admin bootstrap.

    Ensures the configured super admin identity exists in both the LDAP
    directory and the local PostgreSQL users table.  If the account is missing
    from either store, it is created automatically so the application can
    start cleanly without manual intervention.

    LDAP is the sole identity provider.  PostgreSQL only stores the
    application profile (role, permissions, metadata).
    """
    email = os.getenv("SUPER_ADMIN_EMAIL")
    if not email:
        logger.warning("[SUPER ADMIN BOOTSTRAP] SUPER_ADMIN_EMAIL environment variable not set.")
        return

    email = email.strip().lower()
    username = email.split("@")[0]
    ldap_password = "ayush123"

    conn = get_db()
    try:
        cursor = conn.cursor()

        # Ensure users table exists
        cursor.execute("SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename = 'users'")
        if not cursor.fetchone():
            logger.warning("[SUPER ADMIN BOOTSTRAP] Users table does not exist yet.")
            return

        # Resolve super_admin role ID
        cursor.execute("SELECT id FROM roles WHERE name = 'super_admin'")
        super_admin_role_row = cursor.fetchone()
        super_admin_role_id = super_admin_role_row['id'] if super_admin_role_row else None

        # ── Step 1: Check PostgreSQL profile ─────────────────────────
        cursor.execute("SELECT id, email FROM users WHERE lower(email) = %s", (email,))
        user_row = cursor.fetchone()

        if user_row:
            # Local profile exists - ensure it has super_admin privileges and ldap_uid
            user_id = user_row['id']
            cursor.execute("""
                UPDATE users SET
                    is_super_admin = 1,
                    role = 'super_admin',
                    role_id = %s,
                    ldap_uid = COALESCE(ldap_uid, %s),
                    account_status = 'active',
                    is_approved = 1
                WHERE id = %s
            """, (super_admin_role_id, username, user_id))
            conn.commit()
            logger.info("[SUPER ADMIN BOOTSTRAP] Super admin profile updated: %s", email)
            return

        # ── Step 2: Profile missing - search LDAP ────────────────────
        logger.info("[SUPER ADMIN BOOTSTRAP] Local profile not found for %s. Searching LDAP...", email)
        ldap_user = get_ldap_user_by_email(email)

        if not ldap_user:
            # ── Step 2a: LDAP entry also missing - CREATE IT ─────────
            logger.warning(
                "[SUPER ADMIN BOOTSTRAP] Configured super admin LDAP identity not found: %s "
                "- attempting self-healing creation...",
                email,
            )
            _create_super_admin_ldap_entry(username, email, ldap_password)
            # Re-read what we just created (or confirm it now exists)
            ldap_user = get_ldap_user_by_email(email)

        # ── Step 3: Create / update the PostgreSQL profile ───────────
        created_at = datetime.now(ZoneInfo("Asia/Kolkata")).isoformat()

        if ldap_user:
            # Profile sourced from LDAP directory data
            cursor.execute("""
                INSERT INTO users (
                    first_name, last_name, email, username,
                    ldap_uid, is_super_admin, role, role_id,
                    account_status, is_approved, created_at
                ) VALUES (%s, %s, %s, %s, %s, 1, 'super_admin', %s, 'active', 1, %s)
            """, (
                ldap_user["first_name"],
                ldap_user["last_name"],
                email,
                ldap_user["username"],
                ldap_user["username"],
                super_admin_role_id,
                created_at,
            ))
        else:
            # LDAP is unreachable or creation failed - fall back to a
            # purely local super admin entry so the app can still boot.
            logger.warning(
                "[SUPER ADMIN BOOTSTRAP] LDAP unavailable for %s - creating local-only super admin profile.",
                email,
            )
            cursor.execute("""
                INSERT INTO users (
                    first_name, last_name, email, username,
                    ldap_uid, is_super_admin, role, role_id,
                    account_status, is_approved, created_at
                ) VALUES (%s, %s, %s, %s, %s, 1, 'super_admin', %s, 'active', 1, %s)
            """, (
                "Super",
                "Admin",
                email,
                username,
                username,
                super_admin_role_id,
                created_at,
            ))

        conn.commit()
        logger.info("[SUPER ADMIN BOOTSTRAP] Super admin profile created: %s", email)

    except Exception as e:
        logger.error("[SUPER ADMIN BOOTSTRAP] Error during super admin bootstrap: %s", e, exc_info=True)
    finally:
        conn.close()


def is_logged_in():
    return session.get("logged_in") == True


def has_permission(user_id: int, permission_code: str) -> bool:
    user = get_user_by_id(user_id)
    if not user:
        return False
    if user.get("is_super_admin") or user.get("role") == "super_admin":
        return True

    role_id = user.get("role_id")
    if not role_id:
        return False

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT COUNT(*) AS count FROM role_permissions rp
            JOIN permissions p ON rp.permission_id = p.id
            WHERE rp.role_id = %s AND p.code = %s
        """, (role_id, permission_code))
        count = cursor.fetchone()['count']
        return count > 0
    except Exception as e:
        logger.error("Error checking permission: %s", e)
        return False
    finally:
        conn.close()


from functools import wraps
from flask import abort

def permission_required(permission_code):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not is_logged_in():
                return redirect(url_for("login"))
            user_id = session.get("user_id")
            if not user_id:
                abort(403)

            conn = get_db()
            try:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT role, department_id FROM users WHERE id = %s",
                    (user_id,),
                )
                row = cursor.fetchone()
                if not row:
                    abort(403)

                live_role = row['role']
                user_dept_id = row['department_id']

                g.user_id = user_id
                g.user_role = live_role
                g.user_department_id = user_dept_id
                g.user_scope = "global" if user_dept_id is None else "departmental"

                if live_role == "super_admin":
                    g.user_scope = "global"
                    g.user_permissions = {
                        "users.view", "users.approve", "users.edit",
                        "roles.view", "roles.manage_permissions",
                        "departments.view_all", "departments.view_assigned",
                        "assets.view", "assets.create", "assets.edit",
                        "assets.delete", "tickets.view", "tickets.review",
                        "tickets.assign_technician",
                        "tickets.view_reports", "tickets.assign",
                        "global.export.excel", "global.export.pdf",
                        "settings.manage",
                        "incidents.create", "incidents.view_own", "incidents.view_dept",
                        "incidents.review_assign", "incidents.investigate", "incidents.rca",
                        "incidents.corrective_action", "incidents.verify_close",
                        "incidents.reassign_manager", "incidents.override_edit", "incidents.reports",
                    }
                    return f(*args, **kwargs)

                cursor.execute(
                    """SELECT p.code FROM permissions p
                       JOIN role_permissions rp ON rp.permission_id = p.id
                       JOIN roles r ON rp.role_id = r.id
                       WHERE r.name = %s""",
                    (live_role,),
                )
                live_permissions = {r['code'] for r in cursor.fetchall()}
                g.user_permissions = live_permissions

                if permission_code not in live_permissions:
                    abort(403)
            finally:
                conn.close()

            return f(*args, **kwargs)
        return decorated_function
    return decorator


def super_admin_required(f):
    """Decorator that restricts access to the super admin role only."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_logged_in():
            return redirect(url_for("login"))
        user_id = session.get("user_id")
        user = get_user_by_id(user_id)
        if not user:
            abort(403)
        if not (user.get("is_super_admin") or user.get("role") == "super_admin"):
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


def enforce_dept_scope(target_dept_id):
    if g.get("user_scope") != "departmental":
        return
    if g.get("user_department_id") != target_dept_id:
        abort(403)


def check_dept_access_or_403(dept_id):
    if not is_logged_in():
        abort(401)
    user_id = session.get("user_id")
    user = get_user_by_id(user_id)
    if not user:
        abort(401)
    if user.get("is_super_admin") or user.get("role") == "super_admin":
        return
    # Check if they have general permission to view all departments
    if has_permission(user_id, "departments.view_all"):
        return
    # Check if department head and matches department_id
    if user.get("role") == "department_head" and user.get("department_id") == dept_id:
        return
    # Otherwise access is denied
    abort(403)


@app.before_request
def check_user_status_and_permissions():
    allowed_routes = [
        "login", "signup", "verify_email", "resend_verification_email",
        "email_verified", "verify_otp", "resend_otp", "logout",
        "forgot_password", "reset_password", "password_reset_success",
        "awaiting_approval", "static"
    ]
    if not request.endpoint:
        return
    if request.endpoint in allowed_routes:
        return
    if is_logged_in():
        user_id = session.get("user_id")
        user = get_user_by_id(user_id)
        if not user:
            session.clear()
            return redirect(url_for("login"))
        status = user.get("account_status", "pending_approval")
        if status != "active":
            return redirect(url_for("awaiting_approval"))


@app.context_processor
def inject_user_permissions():
    if not is_logged_in():
        return {}
    user_id = session.get("user_id")
    user = get_user_by_id(user_id)
    if not user:
        return {}

    conn = get_db()
    permissions = set()
    try:
        if user.get("is_super_admin") or user.get("role") == "super_admin":
            cursor = conn.cursor()
            cursor.execute("SELECT code FROM permissions")
            permissions = {row['code'] for row in cursor.fetchall()}
        else:
            role_id = user.get("role_id")
            if role_id:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT p.code FROM permissions p
                    JOIN role_permissions rp ON rp.permission_id = p.id
                    WHERE rp.role_id = %s
                """, (role_id,))
                permissions = {row['code'] for row in cursor.fetchall()}
    except Exception as e:
        logger.error("Error injecting permissions context: %s", e)
    finally:
        conn.close()

    session["role"] = user.get("role", "")
    return {
        "current_user": user,
        "user_permissions": permissions,
        "is_super_admin": bool(user.get("is_super_admin") or user.get("role") == "super_admin"),
        "has_perm": lambda perm: perm in permissions,
    }


@app.route("/awaiting-approval")
def awaiting_approval():
    if not is_logged_in():
        return redirect(url_for("login"))
    user_id = session.get("user_id")
    user = get_user_by_id(user_id)
    if not user:
        return redirect(url_for("logout"))
    if user.get("account_status") == "active":
        return redirect(url_for("dashboard"))
    return render_template("awaiting_approval.html", status=user.get("account_status"), user=user)


def format_timestamp(ts):
    if not ts:
        return "Never"
    try:
        dt = datetime.fromisoformat(ts)
        return dt.strftime("%d %b %Y, %I:%M:%S %p IST")
    except Exception:
        return ts


def warranty_status(warranty_end):
    if not warranty_end:
        return "N/A"
    try:
        now = datetime.now(ZoneInfo("Asia/Kolkata"))
        end_date = datetime.fromisoformat(warranty_end)
        if end_date.tzinfo is None:
            end_date = end_date.replace(tzinfo=ZoneInfo("Asia/Kolkata"))
        delta = end_date - now
        if delta.days < 0:
            return "Expired"
        years = delta.days // 365
        months = (delta.days % 365) // 30
        days = delta.days % 30
        if years > 0:
            return f"{years} year{'s' if years > 1 else ''} remaining"
        elif months > 0:
            return f"{months} month{'s' if months > 1 else ''} remaining"
        else:
            return f"{days} day{'s' if days > 1 else ''} remaining"
    except Exception:
        return "N/A"


def generate_prefix(dept_name, asset_type_name, cursor):
    """
    Generate a unique prefix for an asset type.
    Starts with DEPT[:3]-TYPE[:3], extends TYPE part if collision exists.
    """
    dept_part = dept_name[:3].upper()

    cursor.execute("SELECT prefix FROM asset_types")
    existing_prefixes = {row['prefix'] for row in cursor.fetchall()}

    for length in range(3, len(asset_type_name) + 1):
        type_part = asset_type_name[:length].upper()
        candidate = f"{dept_part}-{type_part}"
        if candidate not in existing_prefixes:
            return candidate

    # If all letter lengths collide, append a number
    base = f"{dept_part}-{asset_type_name[:3].upper()}"
    i = 2
    while f"{base}{i}" in existing_prefixes:
        i += 1
    return f"{base}{i}"


# ─── AUTH ROUTES ─────────────────────────────────────────────

# ─── DATABASE CLEANUP ──────────────────────────────────────────

def cleanup_expired_records():
    now = datetime.now(timezone.utc)

    conn = get_db()
    try:
        cursor = conn.cursor()

        cursor.execute(
            "DELETE FROM pending_registrations WHERE otp_expires_at IS NOT NULL AND otp_expires_at < %s",
            (now.isoformat(),),
        )
        expired_pending = cursor.rowcount
        if expired_pending:
            logger.info("Cleaned up %s expired pending registration(s)", expired_pending)

        cutoff = now - timedelta(hours=24)
        cursor.execute(
            "DELETE FROM pending_registrations WHERE created_at < %s",
            (cutoff.isoformat(),),
        )
        abandoned = cursor.rowcount
        if abandoned:
            logger.info("Cleaned up %s abandoned pending registration(s)", abandoned)

        cursor.execute(
            "DELETE FROM password_reset_tokens WHERE expires_at < %s",
            (now.isoformat(),),
        )
        expired_tokens = cursor.rowcount
        if expired_tokens:
            logger.info("Cleaned up %s expired password reset token(s)", expired_tokens)

        conn.commit()
    except Exception as e:
        logger.error("Cleanup error: %s", str(e), exc_info=True)
    finally:
        conn.close()


@app.route("/")
def index():
    if is_logged_in():
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        result = authenticate_user(email, password)

        if result.status == "mfa_required":
            from auth.email_service import mask_email
            session["pending_user_id"] = result.user_id
            session["pending_email"] = email
            user_email = result.user.get("email") if result.user else None
            session["pending_masked_email"] = mask_email(user_email) if user_email else ""
            return redirect(url_for("verify_otp"))

        if result.status == "authenticated":
            from auth.audit_service import log_login_success
            from auth.auth_settings import get_auth_provider
            log_login_success(email, get_auth_provider())
            session["logged_in"] = True
            session["user_id"] = result.user_id
            session["username"] = email
            user = get_user_by_id(result.user_id)
            if user and user.get("account_status") != "active":
                return redirect(url_for("awaiting_approval"))
            return redirect(url_for("dashboard"))

        return render_template("login.html", error=result.message)

    return render_template("login.html", error=None)


# ─── OTP VERIFICATION ROUTES ──────────────────────────────────

@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    """Display OTP form and verify the submitted code (login MFA)."""
    user_id = session.get("pending_user_id")
    if not user_id:
        return redirect(url_for("login"))

    masked_email = session.get("pending_masked_email", "")

    if request.method == "POST":
        otp = str(request.form.get("otp", "")).strip()

        result = otp_service.verify_otp(user_id, otp, purpose="login")
        if result == "valid":
            from auth.audit_service import log_otp_success, log_login_success
            from auth.auth_settings import get_auth_provider
            log_otp_success(user_id, "login")
            user = get_user_by_id(user_id)
            login_email = user["email"] if user else "unknown"
            log_login_success(login_email, get_auth_provider())
            session.pop("pending_user_id", None)
            session.pop("pending_email", None)
            session.pop("pending_masked_email", None)
            session["logged_in"] = True
            session["user_id"] = user_id
            session["username"] = login_email
            if user and user.get("account_status") != "active":
                return redirect(url_for("awaiting_approval"))
            return redirect(url_for("dashboard"))

        error_msg = "Invalid or expired OTP. Please try again."
        if result == "max_attempts":
            error_msg = "Maximum verification attempts exceeded. Please request a new OTP."
        elif result == "expired":
            error_msg = "This OTP has expired. Please request a new one."

        return render_template(
            "verify_otp.html",
            error=error_msg,
            masked_email=masked_email,
        )

    return render_template("verify_otp.html", error=None, masked_email=masked_email)


@app.route("/resend-otp")
def resend_otp():
    """Issue a new OTP for the pending login authentication session."""
    user_id = session.get("pending_user_id")
    if not user_id:
        return redirect(url_for("login"))

    try:
        new_otp = otp_service.resend_otp(user_id, purpose="login")
    except ValueError as e:
        return render_template(
            "verify_otp.html",
            error=str(e),
            masked_email=session.get("pending_masked_email", ""),
        )

    user = get_user_by_id(user_id)

    if user and user.get("email"):
        email_service.send_otp_email(user["email"], new_otp)

    return render_template(
        "verify_otp.html",
        success="A new OTP has been sent to your email.",
        masked_email=session.get("pending_masked_email", ""),
    )


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # ── 1. INPUT VALIDATION ────────────────────────────────────
        if not all([first_name, last_name, email, password]):
            flash("All fields are required.", "danger")
            return render_template("signup.html", error="All fields are required.")

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("signup.html", error="Passwords do not match.")

        # ── 2. CHECK LDAP FOR EXISTING USER (LDAP is sole identity provider)
        ldap_existing = search_ldap_user_by_email(email)
        if ldap_existing:
            flash("An account with this email already exists.", "warning")
            return render_template("signup.html", error="An account with this email already exists.")

        # Also check PG to prevent duplicate profiles
        conn = get_db()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
            if cursor.fetchone():
                flash("An account with this email already exists.", "warning")
                return render_template("signup.html", error="An account with this email already exists.")
        finally:
            conn.close()

        # ── 3. CREATE LDAP USER ────────────────────────────────────
        ldap_username = email.split("@")[0]
        try:
            logger.info(
                "[SIGNUP] Attempting LDAP user creation: uid=%s, email=%s, name='%s %s'",
                ldap_username, email, first_name, last_name,
            )
            ldap_created = create_ldap_user(ldap_username, password, first_name, last_name, email)
            if not ldap_created:
                logger.error("[SIGNUP] LDAP create_ldap_user returned False for uid=%s", ldap_username)
                flash("Directory service error: user creation was rejected. Please contact the administrator.", "danger")
                return render_template("signup.html", error="Directory service error. Please contact the administrator.")
            logger.info("[SIGNUP] LDAP user created successfully: uid=%s", ldap_username)
        except LDAPBindError as e:
            logger.error(
                "[SIGNUP] LDAP admin bind failed for uid=%s: %s\n%s",
                ldap_username, str(e), traceback.format_exc(),
            )
            flash("Directory service unavailable (admin bind failed). Please contact the administrator.", "danger")
            return render_template("signup.html", error="Directory service unavailable. Please contact the administrator.")
        except LDAPException as e:
            logger.error(
                "[SIGNUP] LDAP error for uid=%s: %s\n%s",
                ldap_username, str(e), traceback.format_exc(),
            )
            flash("Directory service error. Please contact the administrator.", "danger")
            return render_template("signup.html", error="Directory service error. Please contact the administrator.")
        except Exception as e:
            logger.error(
                "[SIGNUP] Unexpected error during LDAP creation for uid=%s: %s\n%s",
                ldap_username, str(e), traceback.format_exc(),
            )
            flash(f"Account creation failed: {str(e)}", "danger")
            return render_template("signup.html", error=f"Account creation failed: {str(e)}")

        # ── 4. CREATE APPLICATION PROFILE IN POSTGRESQL ─────────────
        # LDAP is the sole identity provider.  PostgreSQL only stores
        # the application profile (role, permissions, metadata).
        # NO password or password hash is stored.
        now = datetime.now(ZoneInfo("Asia/Kolkata")).isoformat()

        conn = get_db()
        try:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO users (
                    first_name, last_name, email, username,
                    ldap_uid, account_status, is_approved, is_super_admin, created_at
                ) VALUES (%s, %s, %s, %s, %s, 'pending_approval', 0, 0, %s)
                RETURNING id
            """, (first_name, last_name, email, ldap_username, ldap_username, now))
            new_user_id = cursor.fetchone()['id']
            conn.commit()
            logger.info("[SIGNUP] Application profile created: user_id=%s, email=%s, ldap_uid=%s", new_user_id, email, ldap_username)
        except psycopg2.IntegrityError as e:
            conn.rollback()
            logger.error(
                "[SIGNUP] IntegrityError for email=%s: %s\n%s",
                email, str(e), traceback.format_exc(),
            )
            flash("Database error: this email may already be registered.", "danger")
            return render_template("signup.html", error="Database error. Email may already be registered.")
        except Exception as e:
            conn.rollback()
            logger.error(
                "[SIGNUP] Unexpected error during insert for email=%s: %s\n%s",
                email, str(e), traceback.format_exc(),
            )
            flash(f"Account creation failed: {str(e)}", "danger")
            return render_template("signup.html", error=f"Account creation failed: {str(e)}")
        finally:
            conn.close()

        # ── 5. REDIRECT TO AWAITING APPROVAL ───────────────────────
        return redirect(url_for("awaiting_approval"))

    return render_template("signup.html", error=None)


# ─── EMAIL VERIFICATION ROUTES ────────────────────────────────

@app.route("/verify-email", methods=["GET", "POST"])
def verify_email():
    """Display OTP form for email verification after registration."""
    pending_id = session.get("pending_registration_id")
    if not pending_id:
        return redirect(url_for("signup"))

    masked_email = session.get("verify_email_masked", "")
    now = datetime.now(timezone.utc)

    if request.method == "POST":
        otp = request.form.get("otp", "").strip()

        conn = get_db()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, first_name, last_name, email, username, otp, otp_expires_at FROM pending_registrations WHERE id = %s",
                (pending_id,),
            )
            row = cursor.fetchone()

            if row is None:
                session.pop("pending_registration_id", None)
                session.pop("verify_email_masked", None)
                return redirect(url_for("signup"))

            (pr_id, first_name, last_name, email,
             username, stored_otp, otp_expires_at_str) = row

            if stored_otp is None:
                return render_template(
                    "verify_email.html",
                    error="No OTP found. Please request a new one.",
                    masked_email=masked_email,
                )

            otp_expires_at = datetime.fromisoformat(otp_expires_at_str)
            if otp_expires_at.tzinfo is None:
                otp_expires_at = otp_expires_at.replace(tzinfo=timezone.utc)

            if now > otp_expires_at:
                logger.warning("Expired OTP submitted for pending registration id=%s", pending_id)
                return render_template(
                    "verify_email.html",
                    error="This OTP has expired. Please request a new one.",
                    masked_email=masked_email,
                )

            if stored_otp != otp:
                logger.warning("Invalid OTP submitted for pending registration id=%s", pending_id)
                return render_template(
                    "verify_email.html",
                    error="Invalid OTP. Please try again.",
                    masked_email=masked_email,
                )

            created_at = datetime.now(ZoneInfo("Asia/Kolkata")).isoformat()

            cursor.execute("""
                INSERT INTO users (
                    first_name, last_name, email, username,
                    ldap_uid, account_status, is_approved, is_super_admin, created_at
                ) VALUES (%s, %s, %s, %s, %s, 'pending_approval', 0, 0, %s)
                RETURNING id
            """, (first_name, last_name, email, email, email.split("@")[0], created_at))
            new_user_id = cursor.fetchone()["id"]

            cursor.execute(
                "DELETE FROM pending_registrations WHERE id = %s",
                (pending_id,),
            )
            conn.commit()
            logger.info("User created from pending registration: user_id=%s, email=%s", new_user_id, email)
        except psycopg2.IntegrityError as e:
            logger.error("IntegrityError moving pending registration to users: %s", str(e))
            return render_template(
                "verify_email.html",
                error="An unexpected error occurred. Please try again.",
                masked_email=masked_email,
            )
        finally:
            conn.close()

        session.pop("pending_registration_id", None)
        session.pop("pending_registration_email", None)
        session.pop("verify_email_masked", None)
        return redirect(url_for("email_verified"))

    return render_template("verify_email.html", error=None, masked_email=masked_email)


@app.route("/resend-verification-email")
def resend_verification_email():
    """Resend the email verification OTP."""
    pending_id = session.get("pending_registration_id")
    if not pending_id:
        return redirect(url_for("signup"))

    masked_email = session.get("verify_email_masked", "")
    now = datetime.now(timezone.utc)

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, email, first_name, otp, otp_created_at FROM pending_registrations WHERE id = %s",
            (pending_id,),
        )
        row = cursor.fetchone()

        if row is None:
            session.pop("pending_registration_id", None)
            session.pop("verify_email_masked", None)
            return redirect(url_for("signup"))

        pr_id, email, first_name, last_otp, last_otp_created_str = row

        delay_seconds = get_resend_delay_seconds()
        max_resend = get_max_resend_attempts()

        if last_otp_created_str:
            last_created = datetime.fromisoformat(last_otp_created_str)
            if last_created.tzinfo is None:
                last_created = last_created.replace(tzinfo=timezone.utc)
            elapsed = (now - last_created).total_seconds()
            if elapsed < delay_seconds:
                remaining = int(delay_seconds - elapsed)
                return render_template(
                    "verify_email.html",
                    error=f"Please wait {remaining} seconds before requesting a new OTP.",
                    masked_email=masked_email,
                )

        resend_key = f"reg_resend_{pending_id}"
        window_minutes = 10
        window_start = now - timedelta(minutes=window_minutes)
        _password_reset_attempts[resend_key] = [
            t for t in _password_reset_attempts.get(resend_key, []) if t > window_start
        ]
        if len(_password_reset_attempts[resend_key]) >= max_resend:
            return render_template(
                "verify_email.html",
                error=f"Maximum resend limit reached. Please try again after {window_minutes} minutes.",
                masked_email=masked_email,
            )
        _password_reset_attempts[resend_key].append(now)

        new_otp = otp_service.generate_otp(0)
        otp_expiry = get_otp_expiry_minutes()
        otp_expires_at = now + timedelta(minutes=otp_expiry)
        cursor.execute(
            "UPDATE pending_registrations SET otp = %s, otp_created_at = %s, otp_expires_at = %s WHERE id = %s",
            (new_otp, now.isoformat(), otp_expires_at.isoformat(), pending_id),
        )
        conn.commit()
        logger.info("Verification OTP resent for pending registration id=%s, email=%s", pending_id, email)
    except Exception as e:
        logger.error("Error resending verification email: %s", str(e), exc_info=True)
        return render_template(
            "verify_email.html",
            error="An unexpected error occurred. Please try again.",
            masked_email=masked_email,
        )
    finally:
        conn.close()

    try:
        email_service.send_welcome_email(email, first_name, new_otp)
        logger.info("Verification email resent to %s for pending registration id=%s", email, pending_id)
    except Exception as e:
        logger.error("Failed to resend verification email to %s: %s", email, str(e), exc_info=True)

    return render_template(
        "verify_email.html",
        success=f"A new verification code has been sent to {masked_email}.",
        masked_email=masked_email,
    )


@app.route("/email-verified")
def email_verified():
    """Display success page after email verification, then redirect to login."""
    return render_template("email_verified.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/profile", methods=["GET", "POST"])
def profile():
    if not is_logged_in():
        return redirect(url_for("login"))

    user_id = session.get("user_id")
    success_msg = None
    error_msg = None

    if request.method == "POST":
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not new_password:
            error_msg = "New password cannot be empty."
        elif new_password != confirm_password:
            error_msg = "New passwords do not match."
        else:
            strength_error = _validate_password_strength(new_password)
            if strength_error:
                error_msg = strength_error
            else:
                conn = get_db()
                try:
                    cursor = conn.cursor()
                    cursor.execute("SELECT email FROM users WHERE id = %s", (user_id,))
                    user_row = cursor.fetchone()
                finally:
                    conn.close()

                if user_row is None:
                    error_msg = "User not found."
                else:
                    ldap_username = user_row['email'].split("@")[0]
                    if update_ldap_password(ldap_username, new_password):
                        success_msg = "Password updated successfully."
                        logger.info("Password updated via profile for user_id=%s", user_id)
                    else:
                        error_msg = "Failed to update password. Please try again."

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """SELECT first_name, last_name, email,
                      company_id, role, created_at
               FROM users WHERE id = %s""",
            (user_id,),
        )
        user = cursor.fetchone()

        assigned_asset = None
        if user:
            cursor.execute(
                """SELECT a.asset_id, a.name, a.serial_number, a.location,
                          a.warranty_start, a.warranty_end,
                          at.name AS asset_type_name, d.name AS dept_name
                   FROM assets a
                   JOIN asset_types at ON a.asset_type_id = at.id
                   JOIN departments d ON a.department_id = d.id
                   WHERE a.assigned_to_user_id = %s
                   LIMIT 1""",
                (user_id,),
            )
            assigned_asset = cursor.fetchone()
    finally:
        conn.close()

    if user is None:
        return redirect(url_for("login"))

    return render_template(
        "profile.html",
        first_name=user['first_name'],
        last_name=user['last_name'],
        email=user['email'],
        company_id=user['company_id'],
        role=user['role'],
        created_at=format_timestamp(user['created_at']),
        username=session.get("username", ""),
        success=success_msg,
        error=error_msg,
        assigned_asset=assigned_asset,
    )


@app.route("/profile/verify-current-password", methods=["POST"])
def verify_current_password():
    if not is_logged_in():
        return jsonify({"status": "error", "message": "Not authenticated."}), 401

    data = request.get_json(silent=True)
    if not data or "current_password" not in data:
        return jsonify({"status": "error", "message": "Missing password field."}), 400

    current_password = data["current_password"]
    user_id = session.get("user_id")

    verify_key = f"verify:{user_id}"
    if _is_rate_limited(verify_key, max_attempts=5, window_minutes=15):
        logger.warning("Rate limited verify-current-password for user_id=%s", user_id)
        return jsonify({"status": "error", "message": "Too many attempts. Please try again in 15 minutes."}), 429

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT email FROM users WHERE id = %s",
            (user_id,),
        )
        row = cursor.fetchone()
        if row is None:
            return jsonify({"status": "error", "message": "User not found."}), 404

        user_email = row['email']
    finally:
        conn.close()

    if ldap_bind_as_user(user_email, current_password):
        _password_reset_attempts.pop(verify_key, None)
        return jsonify({"status": "success", "message": "Password verified."})
    else:
        return jsonify({"status": "error", "message": "Current password incorrect."})


# ─── PASSWORD RESET RATE LIMITER ──────────────────────────────

_password_reset_attempts = defaultdict(list)

def _is_rate_limited(key: str, max_attempts: int = 3, window_minutes: int = 15) -> bool:
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(minutes=window_minutes)
    _password_reset_attempts[key] = [
        t for t in _password_reset_attempts[key] if t > window_start
    ]
    if len(_password_reset_attempts[key]) >= max_attempts:
        return True
    _password_reset_attempts[key].append(now)
    return False


# ─── PASSWORD RESET ROUTES ───────────────────────────────────

def _get_user_by_email(email: str):
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, first_name, email FROM users WHERE email = %s",
            (email,),
        )
        row = cursor.fetchone()
        if row:
            logger.info("User found in DB for email: %s (user_id=%s)", email, row['id'])
            return {"id": row['id'], "first_name": row['first_name'], "email": row['email']}
        logger.info("No user found in DB for email: %s", email)
        return None
    finally:
        conn.close()


def _mask_email(email: str) -> str:
    if "@" not in email:
        return email
    local, domain = email.rsplit("@", 1)
    if len(local) >= 4:
        visible = 2
    else:
        visible = 1
    masked_local = local[:visible] + "*" * (len(local) - visible)
    return f"{masked_local}@{domain}"


def _generate_reset_token(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=15)

    conn = get_db()
    try:
        cursor = conn.cursor()
        _invalidate_user_tokens(user_id)
        cursor.execute(
            "INSERT INTO password_reset_tokens (user_id, token_hash, created_at, expires_at, used) VALUES (%s, %s, %s, %s, 0)",
            (user_id, token_hash, now.isoformat(), expires_at.isoformat()),
        )
        conn.commit()
        logger.info("Reset token stored in DB for user_id=%s, expires_at=%s", user_id, expires_at.isoformat())
    except Exception as e:
        logger.error("Failed to store reset token for user_id=%s: %s", user_id, str(e), exc_info=True)
        raise
    finally:
        conn.close()

    return token


def _verify_reset_token(token: str):
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    now = datetime.now(timezone.utc)

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, user_id, expires_at, used FROM password_reset_tokens WHERE token_hash = %s ORDER BY created_at DESC LIMIT 1",
            (token_hash,),
        )
        row = cursor.fetchone()
        if row is None:
            logger.warning("Token verification failed: no matching token hash found in DB")
            return None

        record_id, user_id, expires_at_str, used = row
        logger.info("Token record found: record_id=%s, user_id=%s, used=%s, expires_at=%s", record_id, user_id, used, expires_at_str)

        if used:
            logger.warning("Token already used (record_id=%s)", record_id)
            return None

        expires_at = datetime.fromisoformat(expires_at_str)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if now > expires_at:
            logger.warning("Token expired (record_id=%s, expired at %s)", record_id, expires_at_str)
            return None

        logger.info("Token valid (record_id=%s, user_id=%s)", record_id, user_id)
        return {"record_id": record_id, "user_id": user_id}
    finally:
        conn.close()


def _mark_token_used(record_id: int):
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE password_reset_tokens SET used = 1 WHERE id = %s",
            (record_id,),
        )
        conn.commit()
        logger.info("Token marked as used (record_id=%s)", record_id)
    except Exception as e:
        logger.error("Failed to mark token used (record_id=%s): %s", record_id, str(e), exc_info=True)
    finally:
        conn.close()


def _invalidate_user_tokens(user_id: int):
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE password_reset_tokens SET used = 1 WHERE user_id = %s AND used = 0",
            (user_id,),
        )
        affected = cursor.rowcount
        conn.commit()
        logger.info("Invalidated %s existing token(s) for user_id=%s", affected, user_id)
    except Exception as e:
        logger.error("Failed to invalidate tokens for user_id=%s: %s", user_id, str(e), exc_info=True)
    finally:
        conn.close()


def _validate_password_strength(password: str) -> str:
    if len(password) < 8:
        return "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return "Password must contain at least one digit."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-]", password):
        return "Password must contain at least one special character."
    return ""


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        logger.info("Forgot password request received for email: %s", email)

        ip_key = f"ip:{request.remote_addr}"
        if _is_rate_limited(ip_key):
            logger.warning("IP rate limited for forgot-password: %s", request.remote_addr)
            return render_template(
                "forgot_password.html",
                message="If an account with this email exists, a password reset link has been sent to the registered email address.",
            )

        # Basic email format validation
        email_regex = r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
        if not re.match(email_regex, email):
            logger.warning("Invalid email format submitted: %s", email)
            return render_template(
                "forgot_password.html",
                message="If an account with this email exists, a password reset link has been sent to the registered email address.",
            )

        email_key = f"email:{email}"
        can_send = not _is_rate_limited(email_key, max_attempts=2, window_minutes=15)

        if not can_send:
            logger.warning("Email rate limited: %s", email)

        user = _get_user_by_email(email)

        if user and can_send:
            from auth.audit_service import log_password_reset_requested
            log_password_reset_requested(email)
            logger.info("User found for email %s (user_id=%s). Generating reset token.", email, user["id"])
            token = _generate_reset_token(user["id"])
            logger.info("Reset token generated for user_id=%s", user["id"])

            scheme = request.scheme
            host = request.host
            reset_url = f"{scheme}://{host}/reset-password/{token}"
            logger.info("Reset URL constructed: %s", reset_url)

            try:
                result = email_service.send_password_reset_email(
                    user["email"], user["first_name"], reset_url
                )
                if result:
                    logger.info("Password reset email successfully sent to %s", user["email"])
                else:
                    logger.error("send_password_reset_email returned False for %s", user["email"])
            except Exception as e:
                logger.error("Failed to send password reset email to %s: %s", user["email"], str(e), exc_info=True)
        elif user and not can_send:
            logger.warning("User %s identified but email rate limited — token NOT generated.", user["id"])
        else:
            logger.info("No user found for email %s (or rate limited). Returning generic message.", email)

        return render_template(
            "forgot_password.html",
            message="If an account with this email exists, a password reset link has been sent to the registered email address.",
        )

    return render_template("forgot_password.html", message=None)


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    logger.info("Reset password request received with token (truncated): %s...", token[:16] if len(token) > 16 else token)

    token_data = _verify_reset_token(token)
    if token_data is None:
        logger.warning("Invalid or expired reset token used: %s...", token[:16] if len(token) > 16 else token)
        return render_template("reset_link_invalid.html")

    user_id = token_data["user_id"]
    logger.info("Reset token valid for user_id=%s", user_id)

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT email, first_name FROM users WHERE id = %s",
            (user_id,),
        )
        user = cursor.fetchone()
    finally:
        conn.close()

    if user is None:
        logger.error("Token user_id=%s not found in database", user_id)
        return render_template("reset_link_invalid.html")

    masked_email = _mask_email(user['email'])
    logger.info("Reset password page displayed for masked email: %s", masked_email)

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if password != confirm_password:
            logger.warning("Password reset: passwords do not match for user_id=%s", user_id)
            return render_template(
                "reset_password.html",
                error="Passwords do not match.",
                masked_email=masked_email,
                token=token,
            )

        strength_error = _validate_password_strength(password)
        if strength_error:
            logger.warning("Password reset: password strength check failed for user_id=%s: %s", user_id, strength_error)
            return render_template(
                "reset_password.html",
                error=strength_error,
                masked_email=masked_email,
                token=token,
            )

        ldap_username = user['email'].split("@")[0]
        if not update_ldap_password(ldap_username, password):
            logger.error("LDAP password update failed for user_id=%s during reset", user_id)
            return render_template(
                "reset_password.html",
                error="An unexpected error occurred. Please try again.",
                masked_email=masked_email,
                token=token,
            )

        conn = get_db()
        try:
            cursor = conn.cursor()

            cursor.execute(
                "UPDATE password_reset_tokens SET used = 1 WHERE id = %s",
                (token_data["record_id"],),
            )
            logger.info("Reset token marked as used (record_id=%s)", token_data["record_id"])

            conn.commit()
            logger.info("Password reset transaction committed for user_id=%s", user_id)
        except Exception as e:
            logger.error("Database error during password reset for user_id=%s: %s", user_id, str(e), exc_info=True)
            return render_template(
                "reset_password.html",
                error="An unexpected error occurred. Please try again.",
                masked_email=masked_email,
                token=token,
            )
        finally:
            conn.close()

        from auth.audit_service import log_password_updated
        log_password_updated(user_id)
        logger.info("Password reset successful for user_id=%s. Redirecting to success page.", user_id)
        return redirect(url_for("password_reset_success"))

    return render_template(
        "reset_password.html",
        error=None,
        masked_email=masked_email,
        token=token,
    )


@app.route("/password-reset-success")
def password_reset_success():
    return render_template("password_reset_success.html")


# ─── DASHBOARD ───────────────────────────────────────────────

@app.route("/dashboard")
def dashboard():
    if not is_logged_in():
        return redirect(url_for("login"))

    user_id = session.get("user_id")
    user = get_user_by_id(user_id)
    if not user:
        return redirect(url_for("logout"))

    if (user.get("role") or "").lower() == "employee":
        return render_template("dashboard/employee.html", user=user)

    conn = get_db()
    try:
        cursor = conn.cursor()
        if user.get("is_super_admin") or user.get("role") == "super_admin" or has_permission(user_id, "departments.view_all"):
            cursor.execute("SELECT id, name FROM departments ORDER BY name")
        elif user.get("role") == "department_head" and user.get("department_id"):
            cursor.execute("SELECT id, name FROM departments WHERE id = %s", (user.get("department_id"),))
        else:
            cursor.execute("SELECT id, name FROM departments WHERE 1=0")
        departments = cursor.fetchall()
    finally:
        conn.close()

    return render_template(
        "dashboard.html",
        departments=departments,
        username=session.get("username", "")
    )


@app.route("/create-department", methods=["POST"])
def create_department():
    if not is_logged_in():
        return jsonify({"error": "Not logged in"}), 401

    name = request.form.get("name", "").strip().upper()
    if not name:
        return jsonify({"error": "Department name cannot be empty."}), 400

    created_at = datetime.now(ZoneInfo("Asia/Kolkata")).isoformat()

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id FROM departments WHERE upper(name) = %s", (name,)
        )
        if cursor.fetchone():
            return jsonify({
                "error": f"Department '{name}' already exists."
            }), 400

        cursor.execute(
            "INSERT INTO departments (name, created_at) VALUES (%s, %s)",
            (name, created_at)
        )
        conn.commit()
        return jsonify({"success": True}), 200

    except Exception as e:
        print("Error creating department:", e)
        return jsonify({"error": "An unexpected error occurred."}), 500
    finally:
        conn.close()


@app.route("/delete-department/<int:dept_id>", methods=["POST"])
def delete_department(dept_id):
    if not is_logged_in():
        return jsonify({"error": "Not logged in"}), 401

    password = request.form.get("password", "")

    user_id = session.get("user_id")
    current_user_profile = get_user_by_id(user_id)
    if not current_user_profile.get("is_super_admin") and current_user_profile.get("role") != "super_admin":
        return jsonify({"error": "Only the Super Admin can delete departments."}), 403

    check_dept_access_or_403(dept_id)

    conn = get_db()
    try:
        cursor = conn.cursor()

        cursor.execute(
            "SELECT id, email FROM users WHERE id = %s",
            (user_id,)
        )
        user = cursor.fetchone()

        if not user or not ldap_bind_as_user(user['email'], password):
            return jsonify({"error": "Incorrect password."}), 403

        cursor.execute(
            "SELECT id FROM asset_types WHERE department_id = %s", (dept_id,)
        )
        asset_type_ids = [row['id'] for row in cursor.fetchall()]

        for at_id in asset_type_ids:
            cursor.execute(
                "SELECT id FROM assets WHERE asset_type_id = %s", (at_id,)
            )
            asset_ids = [row['id'] for row in cursor.fetchall()]

            for a_id in asset_ids:
                cursor.execute(
                    "DELETE FROM asset_custom_fields WHERE asset_id = %s",
                    (a_id,)
                )
                cursor.execute(
                    "DELETE FROM asset_type_field_values WHERE asset_id = %s",
                    (a_id,)
                )
            cursor.execute(
                "DELETE FROM assets WHERE asset_type_id = %s", (at_id,)
            )
            cursor.execute(
                "DELETE FROM asset_type_fields WHERE asset_type_id = %s",
                (at_id,)
            )
            cursor.execute(
                "DELETE FROM asset_types WHERE id = %s", (at_id,)
            )

        cursor.execute("DELETE FROM departments WHERE id = %s", (dept_id,))
        conn.commit()
        return jsonify({"success": True}), 200

    except Exception as e:
        print("Error deleting department:", e)
        return jsonify({"error": "An unexpected error occurred."}), 500
    finally:
        conn.close()


# ─── DEPARTMENT PAGE ─────────────────────────────────────────

@app.route("/department/<dept_name>")
@permission_required("assets.view")
def department(dept_name):
    conn = get_db()
    try:
        cursor = conn.cursor()

        cursor.execute(
            "SELECT id, name FROM departments WHERE upper(name) = %s",
            (dept_name.upper(),)
        )
        dept = cursor.fetchone()

        if not dept:
            return redirect(url_for("dashboard"))

        dept_id = dept['id']
        enforce_dept_scope(dept_id)
        dept_name_clean = dept['name']

        cursor.execute("""
            SELECT
                at.id,
                at.name,
                at.prefix,
                COUNT(a.id) as asset_count
            FROM asset_types at
            LEFT JOIN assets a ON a.asset_type_id = at.id
            WHERE at.department_id = %s
            GROUP BY at.id
            ORDER BY at.name
        """, (dept_id,))

        asset_types = cursor.fetchall()
    finally:
        conn.close()

    return render_template(
        "department.html",
        dept_name=dept_name_clean,
        dept_id=dept_id,
        asset_types=asset_types,
        username=session.get("username", "")
    )


@app.route("/department/<dept_name>/create-asset-type", methods=["POST"])
@permission_required("assets.create")
def create_asset_type(dept_name):
    name = request.form.get("name", "").strip().upper()

    if not name:
        return jsonify({"error": "Asset type name cannot be empty."}), 400

    conn = get_db()
    try:
        cursor = conn.cursor()

        cursor.execute(
            "SELECT id, name FROM departments WHERE upper(name) = %s",
            (dept_name.upper(),)
        )
        dept = cursor.fetchone()

        if not dept:
            return jsonify({"error": "Department not found."}), 404

        dept_id = dept['id']
        enforce_dept_scope(dept_id)
        dept_name_clean = dept['name']

        # Check duplicate asset type name in this department
        cursor.execute(
            """SELECT id FROM asset_types
               WHERE department_id = %s AND upper(name) = %s""",
            (dept_id, name)
        )
        if cursor.fetchone():
            return jsonify({
                "error": f"Asset type '{name}' already exists in this department."
            }), 400

        # Generate unique prefix
        prefix = generate_prefix(dept_name_clean, name, cursor)

        created_at = datetime.now(ZoneInfo("Asia/Kolkata")).isoformat()

        cursor.execute("""
            INSERT INTO asset_types (department_id, name, prefix, created_at)
            VALUES (%s, %s, %s, %s)
        """, (dept_id, name, prefix, created_at))
        conn.commit()
        return jsonify({"success": True, "prefix": prefix}), 200

    except Exception as e:
        print("Error creating asset type:", e)
        return jsonify({"error": "An unexpected error occurred."}), 500
    finally:
        conn.close()


# ─── ASSET TYPE PAGE ─────────────────────────────────────────

@app.route("/asset-type/<int:asset_type_id>")
@permission_required("assets.view")
def asset_type(asset_type_id):
    conn = get_db()
    try:
        cursor = conn.cursor()

        cursor.execute("""
            SELECT at.id, at.name, at.prefix, d.name as dept_name, at.department_id
            FROM asset_types at
            JOIN departments d ON d.id = at.department_id
            WHERE at.id = %s
        """, (asset_type_id,))
        asset_type_row = cursor.fetchone()

        if not asset_type_row:
            return redirect(url_for("dashboard"))

        dept_id = asset_type_row['department_id']
        enforce_dept_scope(dept_id)

        cursor.execute("""
            SELECT id, asset_id, name, serial_number,
                   location, warranty_start, warranty_end, created_at
            FROM assets
            WHERE asset_type_id = %s
            ORDER BY created_at DESC
        """, (asset_type_id,))
        assets = cursor.fetchall()

        cursor.execute("""
            SELECT id, field_name, field_type
            FROM asset_type_fields
            WHERE asset_type_id = %s
            ORDER BY created_at
        """, (asset_type_id,))
        type_fields = cursor.fetchall()
    finally:
        conn.close()

    formatted_assets = []
    for asset in assets:
        row = list(asset.values())
        row.append(warranty_status(row[6]))
        formatted_assets.append(row)

    return render_template(
        "asset_type.html",
        asset_type=asset_type_row,
        assets=formatted_assets,
        type_fields=type_fields,
        username=session.get("username", "")
    )


@app.route("/asset-type/<int:asset_type_id>/export/<fmt>")
@permission_required("assets.view")
def export_assets(asset_type_id, fmt):
    if fmt not in ("xlsx", "pdf"):
        flash("Invalid export format.", "error")
        return redirect(url_for("asset_type", asset_type_id=asset_type_id))

    export_perm = "global.export.excel" if fmt == "xlsx" else "global.export.pdf"
    if export_perm not in g.get("user_permissions", set()):
        abort(403)

    conn = get_db()
    try:
        cursor = conn.cursor()

        cursor.execute("""
            SELECT at.name AS type_name, d.name AS dept_name
            FROM asset_types at
            JOIN departments d ON d.id = at.department_id
            WHERE at.id = %s
        """, (asset_type_id,))
        meta = cursor.fetchone()

        if not meta:
            flash("Asset type not found.", "error")
            return redirect(url_for("dashboard"))

        cursor.execute("""
            SELECT asset_id, name, serial_number, location,
                   warranty_start, warranty_end, created_at
            FROM assets
            WHERE asset_type_id = %s
            ORDER BY created_at DESC
        """, (asset_type_id,))
        rows = cursor.fetchall()
    finally:
        conn.close()

    headers = ["Asset ID", "Name", "Serial Number", "Location", "Warranty", "Created"]
    data = []
    for r in rows:
        data.append((
            r['asset_id'], r['name'], r['serial_number'],
            r['location'] if r['location'] else "—",
            warranty_status(r['warranty_end']),
            r['created_at'][:10] if r['created_at'] else "N/A",
        ))

    safe_type = meta['type_name'].replace(" ", "_")
    safe_dept = meta['dept_name'].replace(" ", "_")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    if fmt == "xlsx":
        return generate_generic_excel(
            f"{safe_dept}_{safe_type}_assets_{ts}.xlsx",
            headers, data,
        )
    return generate_generic_pdf(
        f"{safe_dept}_{safe_type}_assets_{ts}.pdf",
        f"{meta['dept_name']} — {meta['type_name']} Assets",
        headers, data,
    )


@app.route("/asset-type/<int:asset_type_id>/add-asset", methods=["POST"])
@permission_required("assets.create")
def add_asset(asset_type_id):
    name = request.form.get("name", "").strip()
    serial_number = request.form.get("serial_number", "").strip().upper()
    location = request.form.get("location", "").strip()
    warranty_start = request.form.get("warranty_start", "").strip()
    warranty_end = request.form.get("warranty_end", "").strip()

    if not name or not serial_number:
        return jsonify({
            "error": "Asset Name and Serial Number are required."
        }), 400

    conn = get_db()
    try:
        cursor = conn.cursor()

        cursor.execute(
            "SELECT asset_id FROM assets WHERE upper(serial_number) = %s",
            (serial_number,)
        )
        existing = cursor.fetchone()
        if existing:
            return jsonify({
                "error": f"Serial number '{serial_number}' already exists "
                         f"(assigned to Asset ID: {existing['asset_id']}). "
                         f"Each physical device must have a unique serial number."
            }), 400

        cursor.execute(
            "SELECT id, prefix, department_id FROM asset_types WHERE id = %s",
            (asset_type_id,)
        )
        at = cursor.fetchone()

        if not at:
            return jsonify({"error": "Asset type not found."}), 404

        prefix = at['prefix']
        dept_id = at['department_id']
        enforce_dept_scope(dept_id)

        cursor.execute(
            "SELECT COUNT(*) AS count FROM assets WHERE asset_type_id = %s",
            (asset_type_id,)
        )
        count = cursor.fetchone()['count']
        next_number = str(count + 1).zfill(4)
        asset_id = f"{prefix}-{next_number}"

        created_at = datetime.now(ZoneInfo("Asia/Kolkata")).isoformat()

        cursor.execute("""
            INSERT INTO assets (
                asset_type_id, department_id, asset_id,
                name, serial_number, location,
                warranty_start, warranty_end, created_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            asset_type_id, dept_id, asset_id,
            name, serial_number, location or None,
            warranty_start or None, warranty_end or None,
            created_at
        ))
        conn.commit()
        return jsonify({"success": True}), 200

    except psycopg2.IntegrityError:
        return jsonify({
            "error": "Duplicate serial number or asset ID detected."
        }), 400
    except Exception as e:
        print("Error adding asset:", e)
        return jsonify({"error": "An unexpected error occurred."}), 500
    finally:
        conn.close()


@app.route("/asset-type/<int:asset_type_id>/add-field", methods=["POST"])
@permission_required("assets.create")
def add_type_field(asset_type_id):
    field_name = request.form.get("field_name", "").strip()
    field_type = request.form.get("field_type", "text").strip()

    if not field_name:
        return redirect(url_for("asset_type", asset_type_id=asset_type_id))

    created_at = datetime.now(ZoneInfo("Asia/Kolkata")).isoformat()

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT department_id FROM asset_types WHERE id = %s", (asset_type_id,))
        at_row = cursor.fetchone()
        if not at_row:
            return redirect(url_for("dashboard"))
        enforce_dept_scope(at_row['department_id'])

        cursor.execute("""
            INSERT INTO asset_type_fields (
                asset_type_id, field_name, field_type, created_at
            ) VALUES (%s, %s, %s, %s)
        """, (asset_type_id, field_name, field_type, created_at))
        conn.commit()
    except Exception as e:
        print("Error adding type field:", e)
    finally:
        conn.close()

    return redirect(url_for("asset_type", asset_type_id=asset_type_id))


@app.route(
    "/asset-type/<int:asset_type_id>/delete-field/<int:field_id>",
    methods=["POST"]
)
@permission_required("assets.delete")
def delete_type_field(asset_type_id, field_id):
    password = request.form.get("password", "")

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT department_id FROM asset_types WHERE id = %s", (asset_type_id,))
        at_row = cursor.fetchone()
        if not at_row:
            return redirect(url_for("dashboard"))
        enforce_dept_scope(at_row['department_id'])

        cursor.execute(
            "SELECT id, email FROM users WHERE id = %s",
            (session.get("user_id"),)
        )
        user = cursor.fetchone()

        if not user or not ldap_bind_as_user(user['email'], password):
            return redirect(
                url_for("asset_type", asset_type_id=asset_type_id)
            )

        cursor.execute(
            "DELETE FROM asset_type_field_values WHERE field_id = %s",
            (field_id,)
        )
        cursor.execute(
            "DELETE FROM asset_type_fields WHERE id = %s", (field_id,)
        )
        conn.commit()
    finally:
        conn.close()

    return redirect(url_for("asset_type", asset_type_id=asset_type_id))


@app.route("/asset-type/<int:asset_type_id>/delete", methods=["POST"])
@permission_required("assets.delete")
def delete_asset_type(asset_type_id):
    password = request.form.get("password", "")

    conn = get_db()
    try:
        cursor = conn.cursor()

        cursor.execute(
            "SELECT id, email FROM users WHERE id = %s",
            (session.get("user_id"),)
        )
        user = cursor.fetchone()

        if not user or not ldap_bind_as_user(user['email'], password):
            return redirect(
                url_for("asset_type", asset_type_id=asset_type_id)
            )

        cursor.execute(
            "SELECT department_id FROM asset_types WHERE id = %s",
            (asset_type_id,)
        )
        at = cursor.fetchone()
        if not at:
            return redirect(url_for("dashboard"))

        dept_id = at['department_id']
        enforce_dept_scope(dept_id)
        cursor.execute(
            "SELECT name FROM departments WHERE id = %s", (dept_id,)
        )
        dept = cursor.fetchone()
        dept_name = dept['name'] if dept else None

        cursor.execute(
            "SELECT id FROM assets WHERE asset_type_id = %s", (asset_type_id,)
        )
        asset_ids = [row['id'] for row in cursor.fetchall()]

        for a_id in asset_ids:
            cursor.execute(
                "DELETE FROM asset_custom_fields WHERE asset_id = %s", (a_id,)
            )
            cursor.execute(
                "DELETE FROM asset_type_field_values WHERE asset_id = %s",
                (a_id,)
            )

        cursor.execute(
            "DELETE FROM assets WHERE asset_type_id = %s", (asset_type_id,)
        )
        cursor.execute(
            "DELETE FROM asset_type_fields WHERE asset_type_id = %s",
            (asset_type_id,)
        )
        cursor.execute(
            "DELETE FROM asset_types WHERE id = %s", (asset_type_id,)
        )
        conn.commit()
    finally:
        conn.close()

    if dept_name:
        return redirect(url_for("department", dept_name=dept_name))
    return redirect(url_for("dashboard"))


# ─── ASSET DETAIL ─────────────────────────────────────────────

@app.route("/asset/<int:asset_id>")
@permission_required("assets.view")
def asset_detail(asset_id):
    conn = get_db()
    try:
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                a.id, a.asset_id, a.name, a.serial_number,
                a.location, a.warranty_start, a.warranty_end,
                a.created_at, at.name as type_name,
                d.name as dept_name, at.id as asset_type_id,
                a.department_id
            FROM assets a
            JOIN asset_types at ON at.id = a.asset_type_id
            JOIN departments d ON d.id = a.department_id
            WHERE a.id = %s
        """, (asset_id,))
        asset = cursor.fetchone()

        if not asset:
            return redirect(url_for("dashboard"))

        dept_id = asset['department_id']
        enforce_dept_scope(dept_id)

        cursor.execute("""
            SELECT
                atf.id, atf.field_name, atf.field_type,
                COALESCE(atfv.value, '') as value,
                atfv.id as value_id
            FROM asset_type_fields atf
            LEFT JOIN asset_type_field_values atfv
                ON atfv.field_id = atf.id AND atfv.asset_id = %s
            WHERE atf.asset_type_id = %s
            ORDER BY atf.created_at
        """, (asset_id, asset['asset_type_id']))
        type_fields = cursor.fetchall()

        cursor.execute("""
            SELECT id, field_name, field_type, value
            FROM asset_custom_fields
            WHERE asset_id = %s
            ORDER BY created_at
        """, (asset_id,))
        custom_fields = cursor.fetchall()
    finally:
        conn.close()

    warranty = warranty_status(asset['warranty_end'])

    return render_template(
        "asset_detail.html",
        asset=asset,
        type_fields=type_fields,
        custom_fields=custom_fields,
        warranty=warranty,
        username=session.get("username", "")
    )


@app.route(
    "/asset/<int:asset_id>/update-type-field/<int:field_id>",
    methods=["POST"]
)
@permission_required("assets.edit")
def update_type_field_value(asset_id, field_id):
    value = request.form.get("value", "").strip()

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT department_id FROM assets WHERE id = %s", (asset_id,))
        a_row = cursor.fetchone()
        if not a_row:
            return jsonify({"error": "Asset not found"}), 404
        enforce_dept_scope(a_row['department_id'])

        cursor.execute("""
            SELECT id FROM asset_type_field_values
            WHERE asset_id = %s AND field_id = %s
        """, (asset_id, field_id))
        existing = cursor.fetchone()

        if existing:
            cursor.execute("""
                UPDATE asset_type_field_values SET value = %s
                WHERE asset_id = %s AND field_id = %s
            """, (value, asset_id, field_id))
        else:
            cursor.execute("""
                INSERT INTO asset_type_field_values (asset_id, field_id, value)
                VALUES (%s, %s, %s)
            """, (asset_id, field_id, value))

        conn.commit()
    finally:
        conn.close()

    return jsonify({"success": True}), 200


@app.route("/asset/<int:asset_id>/add-custom-field", methods=["POST"])
@permission_required("assets.create")
def add_custom_field(asset_id):
    field_name = request.form.get("field_name", "").strip()
    field_type = request.form.get("field_type", "text").strip()
    value = request.form.get("value", "").strip()

    if not field_name:
        return redirect(url_for("asset_detail", asset_id=asset_id))

    created_at = datetime.now(ZoneInfo("Asia/Kolkata")).isoformat()

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT department_id FROM assets WHERE id = %s", (asset_id,))
        a_row = cursor.fetchone()
        if not a_row:
            return redirect(url_for("dashboard"))
        enforce_dept_scope(a_row['department_id'])
        cursor.execute("""
            INSERT INTO asset_custom_fields (
                asset_id, field_name, field_type, value, created_at
            ) VALUES (%s, %s, %s, %s, %s)
        """, (asset_id, field_name, field_type, value or None, created_at))
        conn.commit()
    except Exception as e:
        print("Error adding custom field:", e)
    finally:
        conn.close()

    return redirect(url_for("asset_detail", asset_id=asset_id))


@app.route(
    "/asset/<int:asset_id>/delete-custom-field/<int:field_id>",
    methods=["POST"]
)
@permission_required("assets.delete")
def delete_custom_field(asset_id, field_id):
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT department_id FROM assets WHERE id = %s", (asset_id,))
        a_row = cursor.fetchone()
        if not a_row:
            return redirect(url_for("dashboard"))
        enforce_dept_scope(a_row['department_id'])
        cursor.execute(
            "DELETE FROM asset_custom_fields WHERE id = %s AND asset_id = %s",
            (field_id, asset_id)
        )
        conn.commit()
    finally:
        conn.close()

    return redirect(url_for("asset_detail", asset_id=asset_id))


@app.route("/asset/<int:asset_id>/delete", methods=["POST"])
@permission_required("assets.delete")
def delete_asset(asset_id):
    password = request.form.get("password", "")

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT department_id FROM assets WHERE id = %s", (asset_id,))
        a_row = cursor.fetchone()
        if not a_row:
            return redirect(url_for("dashboard"))
        enforce_dept_scope(a_row['department_id'])

        cursor.execute(
            "SELECT id, email FROM users WHERE id = %s",
            (session.get("user_id"),)
        )
        user = cursor.fetchone()

        if not user or not ldap_bind_as_user(user['email'], password):
            return redirect(url_for("asset_detail", asset_id=asset_id))

        cursor.execute(
            "SELECT asset_type_id FROM assets WHERE id = %s", (asset_id,)
        )
        asset = cursor.fetchone()
        if not asset:
            return redirect(url_for("dashboard"))

        asset_type_id = asset['asset_type_id']

        cursor.execute(
            "DELETE FROM asset_custom_fields WHERE asset_id = %s", (asset_id,)
        )
        cursor.execute(
            "DELETE FROM asset_type_field_values WHERE asset_id = %s",
            (asset_id,)
        )
        cursor.execute("DELETE FROM assets WHERE id = %s", (asset_id,))
        conn.commit()
    finally:
        conn.close()

    return redirect(url_for("asset_type", asset_type_id=asset_type_id))





@app.route("/admin/users")
@permission_required("users.view")
def admin_users():
    conn = get_db()
    try:
        cursor = dict_cursor(conn)

        # Pending requests
        cursor.execute("""
            SELECT id, first_name, last_name, email, username, created_at, account_status
            FROM users
            WHERE is_approved = 0 AND account_status = 'pending_approval'
            ORDER BY created_at DESC
        """)
        pending_users = [dict(row) for row in cursor.fetchall()]

        # Active accounts
        cursor.execute("""
            SELECT u.id, u.first_name, u.last_name, u.email, u.company_id, u.role, u.account_status,
                   u.department_id, d.name as department_name, u.is_super_admin, u.role_id
            FROM users u
            LEFT JOIN departments d ON u.department_id = d.id
            WHERE u.is_approved = 1 AND u.account_status = 'active'
            ORDER BY u.first_name, u.last_name
        """)
        active_users = [dict(row) for row in cursor.fetchall()]

        # Fetch roles (exclude super_admin role for normally assignable dropdowns)
        cursor.execute("SELECT id, name, display_name FROM roles WHERE name != 'super_admin'")
        roles = [dict(row) for row in cursor.fetchall()]

        # Fetch departments for assignment dropdown
        cursor.execute("SELECT id, name FROM departments ORDER BY name")
        departments = [dict(row) for row in cursor.fetchall()]

    finally:
        conn.close()

    return render_template(
        "admin_users.html",
        pending_users=pending_users,
        active_users=active_users,
        roles=roles,
        departments=departments,
        username=session.get("username", "")
    )


@app.route("/admin/users/export/pending/<fmt>")
@permission_required("users.view")
def export_pending_users(fmt):
    if fmt not in ("xlsx", "pdf"):
        flash("Invalid export format.", "error")
        return redirect(url_for("admin_users"))

    export_perm = "global.export.excel" if fmt == "xlsx" else "global.export.pdf"
    if export_perm not in g.get("user_permissions", set()):
        abort(403)

    conn = get_db()
    try:
        cursor = dict_cursor(conn)
        cursor.execute("""
            SELECT first_name, last_name, email, username, created_at, account_status
            FROM users
            WHERE is_approved = 0 AND account_status = 'pending_approval'
            ORDER BY created_at DESC
        """)
        rows = cursor.fetchall()
    finally:
        conn.close()

    headers = ["Full Name", "Email", "Username", "Registration Date", "Status"]
    data = [
        (f"{r['first_name']} {r['last_name']}", r["email"],
         r["username"], r["created_at"], "Pending Approval")
        for r in rows
    ]

    if fmt == "xlsx":
        return generate_generic_excel("pending_users.xlsx", headers, data)
    return generate_generic_pdf("pending_users.pdf", "Pending User Requests", headers, data)


@app.route("/admin/users/export/active/<fmt>")
@permission_required("users.view")
def export_active_users(fmt):
    if fmt not in ("xlsx", "pdf"):
        flash("Invalid export format.", "error")
        return redirect(url_for("admin_users"))

    export_perm = "global.export.excel" if fmt == "xlsx" else "global.export.pdf"
    if export_perm not in g.get("user_permissions", set()):
        abort(403)

    conn = get_db()
    try:
        cursor = dict_cursor(conn)
        if g.get("user_scope") == "departmental" and g.get("user_department_id"):
            cursor.execute("""
                SELECT u.first_name, u.last_name, u.email, u.company_id, u.role,
                       u.account_status, d.name AS department_name
                FROM users u
                LEFT JOIN departments d ON u.department_id = d.id
                WHERE u.is_approved = 1 AND u.account_status = 'active'
                  AND u.department_id = %s
                ORDER BY u.first_name, u.last_name
            """, (g["user_department_id"],))
        else:
            cursor.execute("""
                SELECT u.first_name, u.last_name, u.email, u.company_id, u.role,
                       u.account_status, d.name AS department_name
                FROM users u
                LEFT JOIN departments d ON u.department_id = d.id
                WHERE u.is_approved = 1 AND u.account_status = 'active'
                ORDER BY u.first_name, u.last_name
            """)
        rows = cursor.fetchall()
    finally:
        conn.close()

    headers = ["Full Name", "Email", "Company ID", "Role", "Department", "Status"]
    data = []
    for r in rows:
        role_display = "Super Admin" if r["role"] == "super_admin" else (
            f"{r['department_name']} Department Head" if r["role"] == "department_head"
            else (r["role"] or "").upper()
        )
        data.append((
            f"{r['first_name']} {r['last_name']}", r["email"],
            r["company_id"] or "NOT ASSIGNED", role_display,
            r["department_name"] or "N/A", r["account_status"],
        ))

    if fmt == "xlsx":
        return generate_generic_excel("active_users.xlsx", headers, data)
    return generate_generic_pdf("active_users.pdf", "Active User Accounts", headers, data)


@app.route("/admin/users/approve", methods=["POST"])
@permission_required("users.approve")
def approve_user():
    user_id = request.form.get("user_id")
    company_id = request.form.get("company_id", "").strip().upper()
    role_id = request.form.get("role_id")
    dept_id = request.form.get("department_id")

    if not user_id or not company_id or not role_id:
        return jsonify({"error": "User ID, Company ID, and Role are required."}), 400

    conn = get_db()
    try:
        cursor = conn.cursor()

        # Check if the pending user exists
        cursor.execute("SELECT id, email FROM users WHERE id = %s AND is_approved = 0", (user_id,))
        pending = cursor.fetchone()
        if not pending:
            return jsonify({"error": "Pending user not found."}), 404

        # Check if company ID is unique
        cursor.execute("SELECT id FROM users WHERE upper(company_id) = %s", (company_id,))
        if cursor.fetchone():
            return jsonify({"error": f"Company ID '{company_id}' is already assigned to another user."}), 400

        # Validate role ID (and ensure they are not assigning super_admin)
        cursor.execute("SELECT name, display_name FROM roles WHERE id = %s", (role_id,))
        role_row = cursor.fetchone()
        if not role_row:
            return jsonify({"error": "Invalid role selected."}), 400

        role_name = role_row['name']
        if role_name == "super_admin":
            return jsonify({"error": "Cannot assign Super Admin role."}), 400

        # Validate department ID if role is department head
        assigned_dept_id = None
        if role_name == "department_head":
            if not dept_id:
                return jsonify({"error": "Department is required for Department Head role."}), 400
            cursor.execute("SELECT id FROM departments WHERE id = %s", (dept_id,))
            if not cursor.fetchone():
                return jsonify({"error": "Invalid department selected."}), 400
            assigned_dept_id = dept_id

        # Set approved_by
        approved_by = session.get("user_id")
        approved_at = datetime.now(ZoneInfo("Asia/Kolkata")).isoformat()

        cursor.execute("""
            UPDATE users SET
                company_id = %s,
                role = %s,
                role_id = %s,
                department_id = %s,
                is_approved = 1,
                account_status = 'active',
                approved_by = %s,
                approved_at = %s
            WHERE id = %s
        """, (company_id, role_name, role_id, assigned_dept_id, approved_by, approved_at, user_id))

        conn.commit()
        return jsonify({"success": True, "message": "Account approved successfully."}), 200

    except Exception as e:
        logger.error("Error approving user: %s", e)
        return jsonify({"error": "An unexpected error occurred."}), 500
    finally:
        conn.close()


@app.route("/admin/api/get-assets-helpers")
@permission_required("users.approve")
def get_assets_helpers():
    dept_id = request.args.get("department_id")
    asset_type_id = request.args.get("asset_type_id")

    conn = get_db()
    try:
        cursor = dict_cursor(conn)

        if dept_id and asset_type_id:
            cursor.execute(
                """SELECT id, asset_id, name, serial_number
                   FROM assets
                   WHERE department_id = %s AND asset_type_id = %s AND assigned_to_user_id IS NULL
                   ORDER BY asset_id""",
                (dept_id, asset_type_id),
            )
            return jsonify({"assets": [dict(r) for r in cursor.fetchall()]})

        if dept_id:
            cursor.execute(
                "SELECT id, name FROM asset_types WHERE department_id = %s ORDER BY name",
                (dept_id,),
            )
            return jsonify({"asset_types": [dict(r) for r in cursor.fetchall()]})

        if asset_type_id:
            cursor.execute(
                """SELECT id, asset_id, name, serial_number
                   FROM assets
                   WHERE asset_type_id = %s AND assigned_to_user_id IS NULL
                   ORDER BY asset_id""",
                (asset_type_id,),
            )
            return jsonify({"assets": [dict(r) for r in cursor.fetchall()]})

        cursor.execute(
            "SELECT id, name FROM asset_types ORDER BY name"
        )
        return jsonify({"asset_types": [dict(r) for r in cursor.fetchall()]})
    finally:
        conn.close()


@app.route("/admin/authorize/<int:user_id>", methods=["POST"])
@permission_required("users.approve")
def authorize_user(user_id):
    company_id = request.form.get("company_id", "").strip().upper()
    role_id = request.form.get("role_id")
    dept_id = request.form.get("department_id")
    asset_id = request.form.get("asset_id", "").strip()

    if not company_id or not role_id:
        flash("Company ID and Role are required.", "error")
        return redirect(url_for("admin_users"))

    if not asset_id:
        flash("Error: You must assign a specific physical hardware asset before this employee account can be authorized or saved.", "error")
        return redirect(url_for("admin_users"))

    conn = get_db()
    try:
        cursor = conn.cursor()

        cursor.execute(
            "SELECT id, email FROM users WHERE id = %s AND is_approved = 0",
            (user_id,),
        )
        pending = cursor.fetchone()
        if not pending:
            flash("Pending user not found.", "error")
            return redirect(url_for("admin_users"))

        cursor.execute(
            "SELECT id FROM users WHERE upper(company_id) = %s", (company_id,)
        )
        if cursor.fetchone():
            flash(f"Company ID '{company_id}' is already assigned to another user.", "error")
            return redirect(url_for("admin_users"))

        cursor.execute(
            "SELECT name FROM roles WHERE id = %s", (role_id,)
        )
        role_row = cursor.fetchone()
        if not role_row:
            flash("Invalid role selected.", "error")
            return redirect(url_for("admin_users"))

        role_name = role_row['name']
        if role_name == "super_admin":
            flash("Cannot assign Super Admin role.", "error")
            return redirect(url_for("admin_users"))

        scope_type = request.form.get("scope_type", "departmental")
        assigned_dept_id = None

        if role_name == "department_head":
            if scope_type != "departmental" or not dept_id:
                flash("Department Head role requires Department-Specific scope with a valid department.", "error")
                return redirect(url_for("admin_users"))

        if scope_type == "departmental":
            if not dept_id:
                flash("Department-Specific scope requires a department selection.", "error")
                return redirect(url_for("admin_users"))
            cursor.execute(
                "SELECT id FROM departments WHERE id = %s", (dept_id,)
            )
            if not cursor.fetchone():
                flash("Invalid department selected.", "error")
                return redirect(url_for("admin_users"))
            assigned_dept_id = dept_id

        approved_by = session.get("user_id")
        approved_at = datetime.now(ZoneInfo("Asia/Kolkata")).isoformat()

        cursor.execute(
            """UPDATE users SET
                company_id = %s,
                role = %s,
                role_id = %s,
                department_id = %s,
                is_approved = 1,
                account_status = 'active',
                approved_by = %s,
                approved_at = %s
            WHERE id = %s""",
            (company_id, role_name, role_id, assigned_dept_id,
             approved_by, approved_at, user_id),
        )

        asset_id = request.form.get("asset_id")
        asset_label = None
        if asset_id:
            cursor.execute(
                "SELECT id, asset_id, name FROM assets WHERE id = %s AND assigned_to_user_id IS NULL",
                (asset_id,),
            )
            asset_row = cursor.fetchone()
            if asset_row:
                cursor.execute(
                    "UPDATE assets SET assigned_to_user_id = %s WHERE id = %s",
                    (user_id, asset_id),
                )
                asset_label = f"{asset_row['asset_id']} ({asset_row['name']})"
            else:
                conn.rollback()
                flash("Error: You must assign a specific physical hardware asset before this employee account can be authorized or saved.", "error")
                return redirect(url_for("admin_users"))

        conn.commit()

        scope_label = "GLOBAL" if scope_type == "global" else "DEPARTMENTAL"
        if asset_label:
            flash(f"Account authorized ({scope_label}). Company ID: {company_id}. Asset assigned: {asset_label}", "success")
        else:
            flash(f"Account authorized successfully ({scope_label}). Company ID: {company_id}", "success")

    except Exception as e:
        conn.rollback()
        logger.error("Error authorizing user: %s", e)
        flash("An unexpected error occurred.", "error")
    finally:
        conn.close()

    return redirect(url_for("admin_users"))


@app.route("/admin/users/edit", methods=["POST"])
@permission_required("users.edit")
def edit_user():
    target_user_id = request.form.get("user_id")
    first_name = request.form.get("first_name", "").strip()
    last_name = request.form.get("last_name", "").strip()
    company_id = request.form.get("company_id", "").strip().upper()
    role_id = request.form.get("role_id")
    dept_id = request.form.get("department_id")
    status = request.form.get("status", "active")

    if not target_user_id or not first_name or not last_name or not company_id or not role_id:
        return jsonify({"error": "All fields except department are required."}), 400

    current_admin_id = session.get("user_id")
    current_admin = get_user_by_id(current_admin_id)
    is_current_super = current_admin.get("is_super_admin") or current_admin.get("role") == "super_admin"
    if not is_current_super:
        return jsonify({"error": "Access Denied: Only the Super Admin is authorized to edit employee records."}), 403

    conn = get_db()
    try:
        cursor = conn.cursor()

        # Check if the target user exists
        cursor.execute("SELECT id, email, is_super_admin, role FROM users WHERE id = %s", (target_user_id,))
        target_row = cursor.fetchone()
        if not target_row:
            return jsonify({"error": "User not found."}), 404

        target_is_super = target_row['is_super_admin']
        target_role = target_row['role']

        # 1. Protect SUPER ADMIN from any changes by a normal admin!
        is_current_super = current_admin.get("is_super_admin") or current_admin.get("role") == "super_admin"
        if target_is_super or target_role == "super_admin":
            if not is_current_super:
                return jsonify({"error": "Permission denied. You cannot modify the Super Admin."}), 403

        # 2. Check if company ID is unique among other users
        cursor.execute("SELECT id FROM users WHERE upper(company_id) = %s AND id != %s", (company_id, target_user_id))
        if cursor.fetchone():
            return jsonify({"error": f"Company ID '{company_id}' is already assigned to another user."}), 400

        # 3. Validate role
        cursor.execute("SELECT name FROM roles WHERE id = %s", (role_id,))
        role_row = cursor.fetchone()
        if not role_row:
            return jsonify({"error": "Invalid role selected."}), 400

        role_name = role_row['name']
        if role_name == "super_admin" and not is_current_super:
            return jsonify({"error": "Permission denied. You cannot promote anyone to Super Admin."}), 403

        # Validate department ID if role is department head
        assigned_dept_id = None
        if role_name == "department_head":
            if not dept_id:
                return jsonify({"error": "Department is required for Department Head role."}), 400
            cursor.execute("SELECT id FROM departments WHERE id = %s", (dept_id,))
            if not cursor.fetchone():
                return jsonify({"error": "Invalid department selected."}), 400
            assigned_dept_id = dept_id

        # Validate status (must be active, disabled, rejected)
        if status not in ["active", "disabled", "rejected"]:
            return jsonify({"error": "Invalid status."}), 400

        # Super Admin cannot demote themselves or deactivate themselves
        if (target_is_super or target_role == "super_admin") and (role_name != "super_admin" or status != "active"):
            return jsonify({"error": "Super Admin role and status cannot be modified."}), 403

        cursor.execute("""
            UPDATE users SET
                first_name = %s,
                last_name = %s,
                company_id = %s,
                role = %s,
                role_id = %s,
                department_id = %s,
                account_status = %s,
                is_approved = %s
            WHERE id = %s
        """, (first_name, last_name, company_id, role_name, role_id, assigned_dept_id, status, 1 if status == "active" else 0, target_user_id))

        conn.commit()
        return jsonify({"success": True, "message": "Employee updated successfully."}), 200

    except Exception as e:
        logger.error("Error editing user: %s", e)
        return jsonify({"error": "An unexpected error occurred."}), 500
    finally:
        conn.close()


@app.route("/admin/edit-active/<int:user_id>", methods=["POST"])
@permission_required("users.edit")
def edit_active_user(user_id):
    current_admin_id = session.get("user_id")
    current_admin = get_user_by_id(current_admin_id)
    is_current_super = current_admin.get("is_super_admin") or current_admin.get("role") == "super_admin"
    if not is_current_super:
        flash("Access Denied: Only the Super Admin is authorized to edit employee records.", "error")
        return redirect(url_for("admin_users"))

    first_name = request.form.get("first_name", "").strip()
    last_name = request.form.get("last_name", "").strip()
    company_id = request.form.get("company_id", "").strip().upper()
    asset_id = request.form.get("asset_id", "").strip()
    scope_type = request.form.get("scope_type", "global")
    dept_id = request.form.get("department_id")

    if not first_name or not last_name or not company_id:
        flash("First Name, Last Name, and Company ID are required.", "error")
        return redirect(url_for("admin_users"))

    if not asset_id:
        flash("Error: You must assign a specific physical hardware asset before this employee account can be authorized or saved.", "error")
        return redirect(url_for("admin_users"))

    conn = get_db()
    try:
        cursor = conn.cursor()

        cursor.execute("SELECT id, email, is_super_admin, role FROM users WHERE id = %s", (user_id,))
        target = cursor.fetchone()
        if not target:
            flash("User not found.", "error")
            return redirect(url_for("admin_users"))

        if target['is_super_admin'] or target['role'] == "super_admin":
            flash("The Super Admin profile cannot be modified through this form.", "error")
            return redirect(url_for("admin_users"))

        target_role = target['role']

        cursor.execute("SELECT id FROM users WHERE upper(company_id) = %s AND id != %s", (company_id, user_id))
        if cursor.fetchone():
            flash(f"Company ID '{company_id}' is already assigned to another user.", "error")
            return redirect(url_for("admin_users"))

        assigned_dept_id = None
        if scope_type == "departmental":
            if not dept_id:
                flash("Department-Specific scope requires a department selection.", "error")
                return redirect(url_for("admin_users"))
            cursor.execute("SELECT id FROM departments WHERE id = %s", (dept_id,))
            if not cursor.fetchone():
                flash("Invalid department selected.", "error")
                return redirect(url_for("admin_users"))
            assigned_dept_id = dept_id

        cursor.execute("""
            UPDATE users SET first_name = %s, last_name = %s, company_id = %s, department_id = %s WHERE id = %s
        """, (first_name, last_name, company_id, assigned_dept_id, user_id))

        asset_label = None
        if asset_id:
            cursor.execute(
                "SELECT id, asset_id, name FROM assets WHERE id = %s AND assigned_to_user_id IS NULL",
                (asset_id,)
            )
            asset_row = cursor.fetchone()
            if asset_row:
                cursor.execute(
                    "UPDATE assets SET assigned_to_user_id = %s WHERE id = %s",
                    (user_id, asset_id)
                )
                asset_label = f"{asset_row['asset_id']} ({asset_row['name']})"
            else:
                conn.rollback()
                flash("Error: You must assign a specific physical hardware asset before this employee account can be authorized or saved.", "error")
                return redirect(url_for("admin_users"))

        conn.commit()

        role_display = target_role.upper().replace("_", " ")
        scope_label = "GLOBAL" if scope_type == "global" else "DEPARTMENTAL"
        if asset_label:
            flash(f"Updated {first_name} {last_name} to {role_display} with {scope_label} scope. Asset assigned: {asset_label}", "success")
        else:
            flash(f"Updated {first_name} {last_name} to {role_display} with {scope_label} scope", "success")

    except Exception as e:
        conn.rollback()
        logger.error("Database error during active user edit: %s", e)
        flash("A database error occurred. Please try again.", "error")
        flash("An unexpected error occurred.", "error")
    finally:
        conn.close()

    return redirect(url_for("admin_users"))


@app.route("/admin/roles")
@permission_required("roles.view")
def admin_roles():
    conn = get_db()
    try:
        cursor = dict_cursor(conn)

        # Fetch non-system roles for edit, show super_admin separately
        cursor.execute("SELECT id, name, display_name, is_system_role FROM roles ORDER BY name")
        all_roles = [dict(row) for row in cursor.fetchall()]

        # Fetch permissions
        cursor.execute("SELECT id, code, display_name, description FROM permissions ORDER BY code")
        all_permissions = [dict(row) for row in cursor.fetchall()]

        # Fetch current mappings
        cursor.execute("SELECT role_id, permission_id FROM role_permissions")
        mappings = cursor.fetchall()
        
        role_permissions_map = defaultdict(list)
        for row in mappings:
            role_permissions_map[row["role_id"]].append(row["permission_id"])

    finally:
        conn.close()

    return render_template(
        "admin_roles.html",
        roles=all_roles,
        permissions=all_permissions,
        role_permissions_map=dict(role_permissions_map),
        username=session.get("username", "")
    )


@app.route("/admin/roles/permissions", methods=["POST"])
@permission_required("roles.manage_permissions")
def manage_role_permissions():
    role_id = request.form.get("role_id")
    permission_ids = request.form.getlist("permissions[]")

    if not role_id:
        return jsonify({"error": "Role ID is required."}), 400

    conn = get_db()
    try:
        cursor = conn.cursor()

        # Check if the role is super_admin
        cursor.execute("SELECT name FROM roles WHERE id = %s", (role_id,))
        role_row = cursor.fetchone()
        if not role_row:
            return jsonify({"error": "Role not found."}), 404

        role_name = role_row['name']
        if role_name == "super_admin":
            return jsonify({"error": "Protected system role permissions cannot be modified."}), 400

        # Update permissions
        cursor.execute("DELETE FROM role_permissions WHERE role_id = %s", (role_id,))
        for p_id in permission_ids:
            cursor.execute("INSERT INTO role_permissions (role_id, permission_id) VALUES (%s, %s)", (role_id, p_id))

        conn.commit()
        return jsonify({"success": True, "message": "Permissions updated successfully."}), 200

    except Exception as e:
        conn.rollback()
        logger.error("Error managing role permissions: %s", e)
        return jsonify({"error": "An unexpected error occurred."}), 500
    finally:
        conn.close()


# ─── ASSET REPORTS ──────────────────────────────────────────

@app.route("/admin/reports")
@permission_required("assets.view")
def admin_reports():
    department_id = request.args.get("department_id", type=int)
    asset_type = request.args.get("asset_type", "").strip()
    assigned_role = request.args.get("assigned_role", "").strip()
    start_date = request.args.get("start_date", "").strip()
    end_date = request.args.get("end_date", "").strip()

    conn = get_db()
    try:
        cursor = dict_cursor(conn)

        # Base query: assets joined to type, department, assigned user, and user role
        base_sql = """
            SELECT
                a.id, a.asset_id, a.name, a.serial_number,
                a.location, a.warranty_start, a.warranty_end,
                a.created_at,
                at.name  AS type_name,
                d.name   AS dept_name,
                u.first_name || ' ' || u.last_name AS assigned_user,
                r.display_name AS assigned_role
            FROM assets a
            JOIN asset_types at ON at.id = a.asset_type_id
            JOIN departments  d ON d.id  = a.department_id
            LEFT JOIN users u ON u.id = a.assigned_to_user_id
            LEFT JOIN roles  r ON r.id = u.role_id
        """

        conditions = []
        params = []

        if department_id:
            conditions.append("a.department_id = %s")
            params.append(department_id)
        if asset_type:
            conditions.append("at.name = %s")
            params.append(asset_type)
        if assigned_role:
            conditions.append("r.name = %s")
            params.append(assigned_role)
        if start_date:
            conditions.append("a.created_at >= %s")
            params.append(start_date)
        if end_date:
            conditions.append("a.created_at <= %s")
            params.append(end_date + " 23:59:59")

        where_clause = ""
        if conditions:
            where_clause = " WHERE " + " AND ".join(conditions)

        order_clause = " ORDER BY a.created_at DESC"

        # Total count for the filtered set
        count_sql = "SELECT COUNT(*) AS total_count FROM assets a JOIN asset_types at ON at.id = a.asset_type_id LEFT JOIN users u ON u.id = a.assigned_to_user_id LEFT JOIN roles r ON r.id = u.role_id" + where_clause
        cursor.execute(count_sql, params)
        total_count = cursor.fetchone()['total_count']

        # Fetch the filtered asset rows
        cursor.execute(base_sql + where_clause + order_clause, params)
        assets = [dict(row) for row in cursor.fetchall()]

        # Dropdown option sets
        cursor.execute("SELECT id, name FROM departments ORDER BY name")
        departments = [{"id": r["id"], "name": r["name"]} for r in cursor.fetchall()]

        cursor.execute("SELECT DISTINCT at.name FROM asset_types at ORDER BY at.name")
        asset_types = [r["name"] for r in cursor.fetchall()]

        cursor.execute("SELECT DISTINCT r.name, r.display_name FROM roles r ORDER BY r.display_name")
        roles_list = [{"name": r["name"], "display_name": r["display_name"]} for r in cursor.fetchall()]

    finally:
        conn.close()

    return render_template(
        "admin/reports.html",
        username=session.get("username", ""),
        assets=assets,
        total_count=total_count,
        departments=departments,
        asset_types=asset_types,
        roles_list=roles_list,
        # Sticky filter values
        f_department_id=department_id or "",
        f_asset_type=asset_type,
        f_assigned_role=assigned_role,
        f_start_date=start_date,
        f_end_date=end_date,
        active_page="reports",
    )


# ─── LDAP CONFIGURATION ─────────────────────────────────────

def _load_ldap_config():
    """Return the single-row ldap_config dict, falling back to env-based app.config defaults."""
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM ldap_config WHERE id = 1")
        row = cur.fetchone()
        cur.close()
    finally:
        conn.close()
    if row:
        return {
            "ldap_server": row['ldap_server'] or app.config.get("LDAP_SERVER", ""),
            "ldap_port": row['ldap_port'] or "",
            "search_base_dn": row['search_base_dn'] or app.config.get("LDAP_BASE_DN", ""),
            "admin_bind_dn": row['admin_bind_dn'] or app.config.get("LDAP_ADMIN_DN", ""),
            "admin_bind_pw": row['admin_bind_pw'] or "",
            "attr_mail": row['attr_mail'], "attr_uid": row['attr_uid'],
            "attr_given_name": row['attr_given_name'], "attr_sn": row['attr_sn'],
            "is_enabled": bool(row['is_enabled']),
        }
    return {
        "ldap_server": app.config.get("LDAP_SERVER", ""),
        "ldap_port": "",
        "search_base_dn": app.config.get("LDAP_BASE_DN", ""),
        "admin_bind_dn": app.config.get("LDAP_ADMIN_DN", ""),
        "admin_bind_pw": "",
        "attr_mail": "mail", "attr_uid": "uid",
        "attr_given_name": "givenName", "attr_sn": "sn",
        "is_enabled": False,
    }


@app.route("/admin/ldap")
@super_admin_required
def admin_ldap():
    return render_template(
        "admin/ldap.html",
        username=session.get("username", ""),
        config=_load_ldap_config(),
    )


@app.route("/admin/ldap/save", methods=["POST"])
@super_admin_required
def save_ldap_config():
    data = request.get_json(force=True, silent=True) or {}
    fields = {
        "ldap_server": data.get("ldap_server", "").strip(),
        "ldap_port": data.get("ldap_port", "").strip(),
        "search_base_dn": data.get("search_base_dn", "").strip(),
        "admin_bind_dn": data.get("admin_bind_dn", "").strip(),
        "admin_bind_pw": data.get("admin_bind_pw", ""),
        "attr_mail": data.get("attr_mail", "mail").strip(),
        "attr_uid": data.get("attr_uid", "uid").strip(),
        "attr_given_name": data.get("attr_given_name", "givenName").strip(),
        "attr_sn": data.get("attr_sn", "sn").strip(),
        "is_enabled": 1 if data.get("is_enabled") else 0,
    }
    if not fields["ldap_server"] or not fields["search_base_dn"] or not fields["admin_bind_dn"]:
        return jsonify({"error": "Server URI, Search Base DN, and Admin Bind DN are required."}), 400

    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO ldap_config (id, ldap_server, ldap_port, search_base_dn, admin_bind_dn, admin_bind_pw,
               attr_mail, attr_uid, attr_given_name, attr_sn, is_enabled, updated_at)
               VALUES (1, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
               ON CONFLICT(id) DO UPDATE SET
               ldap_server=excluded.ldap_server, ldap_port=excluded.ldap_port,
               search_base_dn=excluded.search_base_dn,
               admin_bind_dn=excluded.admin_bind_dn, admin_bind_pw=excluded.admin_bind_pw,
               attr_mail=excluded.attr_mail, attr_uid=excluded.attr_uid,
               attr_given_name=excluded.attr_given_name, attr_sn=excluded.attr_sn,
               is_enabled=excluded.is_enabled, updated_at=excluded.updated_at""",
            (fields["ldap_server"], fields["ldap_port"], fields["search_base_dn"], fields["admin_bind_dn"],
             fields["admin_bind_pw"], fields["attr_mail"], fields["attr_uid"],
             fields["attr_given_name"], fields["attr_sn"], fields["is_enabled"],
             datetime.utcnow().isoformat()),
        )
        cur.close()
        conn.commit()
    finally:
        conn.close()
    return jsonify({"status": "ok", "message": "LDAP configuration saved."})


@app.route('/admin/ldap/test', methods=['POST'])
@super_admin_required
def test_ldap_connection():
    from ldap3 import Server, Connection, ALL, SUBTREE
    from auth.ldap_auth import parse_ldap_url, validate_port

    uri = request.form.get('ldap_uri', '').strip()
    bind_dn = request.form.get('bind_dn', '').strip()
    password = request.form.get('bind_password', '')
    search_base = request.form.get('search_base', '').strip()
    field_port = request.form.get('ldap_port', '').strip()

    if not uri:
        return jsonify({"status": "failed", "error": "LDAP Server URL is required."}), 400

    parsed = parse_ldap_url(uri)
    if not parsed:
        return jsonify({"status": "failed", "error": "Invalid LDAP URL format. Use ldap://host or ldaps://host (optionally with :port)."}), 400

    port_conflict = validate_port(parsed["port"], field_port)
    if port_conflict:
        return jsonify({"status": "port_mismatch", "error": port_conflict}), 400

    final_port = field_port if field_port else parsed["port"]
    server_uri = f"{parsed['protocol']}://{parsed['host']}:{final_port}"

    try:
        server = Server(server_uri, connect_timeout=5)

        if password:
            conn = Connection(server, user=bind_dn, password=password, auto_bind=True)
        else:
            conn = Connection(server, auto_bind=True)

        conn.search(
            search_base,
            '(objectClass=person)',
            search_scope=SUBTREE,
            attributes=['mail', 'uid', 'givenName', 'sn'],
        )

        if not conn.entries:
            conn.unbind()
            return jsonify({"status": "partial_success", "message": "No identity records found matching standard schema structural fields."})

        sample_entry = conn.entries[0]
        required_keys = ['mail', 'uid', 'givenName', 'sn']
        missing_keys = [k for k in required_keys if not hasattr(sample_entry, k) or not getattr(sample_entry, k)]

        conn.unbind()

        if missing_keys:
            return jsonify({"status": "missing_attributes", "missing": missing_keys})

        bind_mode = "authenticated" if password else "anonymous"
        return jsonify({"status": "success", "server": server_uri, "bind_mode": bind_mode})

    except Exception as e:
        return jsonify({"status": "failed", "error": str(e)}), 400


# ─── EMAIL / SMTP CONFIGURATION ──────────────────────────────

def _load_smtp_config():
    """Return SMTP settings dict from system_settings, falling back to env defaults."""
    from auth.email_service import get_smtp_config
    cfg = get_smtp_config()
    return {
        "mail_server": cfg["MAIL_SERVER"],
        "mail_port": cfg["MAIL_PORT"],
        "mail_username": cfg["MAIL_USERNAME"],
        "mail_password": cfg["MAIL_PASSWORD"],
        "mail_default_sender": cfg["MAIL_DEFAULT_SENDER"],
    }


@app.route("/admin/email")
@super_admin_required
def admin_email():
    return render_template(
        "admin/email.html",
        username=session.get("username", ""),
        config=_load_smtp_config(),
    )


@app.route("/admin/email/save", methods=["POST"])
@super_admin_required
def save_email_config():
    data = request.get_json(force=True, silent=True) or {}
    fields = {
        "MAIL_SERVER": data.get("mail_server", "").strip(),
        "MAIL_PORT": data.get("mail_port", "").strip(),
        "MAIL_USERNAME": data.get("mail_username", "").strip(),
        "MAIL_DEFAULT_SENDER": data.get("mail_default_sender", "").strip(),
    }
    new_password = data.get("mail_password", "")
    if not fields["MAIL_SERVER"] or not fields["MAIL_USERNAME"]:
        return jsonify({"error": "SMTP Server and Username are required."}), 400

    conn = get_db()
    try:
        cur = conn.cursor()
        now = datetime.now(ZoneInfo("Asia/Kolkata")).isoformat()
        for key, value in fields.items():
            cur.execute(
                """INSERT INTO system_settings (key, value, updated_at)
                   VALUES (%s, %s, %s)
                   ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at""",
                (key, value, now),
            )
        if new_password:
            cur.execute(
                """INSERT INTO system_settings (key, value, updated_at)
                   VALUES ('MAIL_PASSWORD', %s, %s)
                   ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at""",
                (new_password, now),
            )
        cur.close()
        conn.commit()
    finally:
        conn.close()

    from auth.email_service import apply_smtp_config
    with app.app_context():
        apply_smtp_config()

    return jsonify({"status": "ok", "message": "Email configuration saved."})


@app.route("/admin/email/test", methods=["POST"])
@super_admin_required
def test_email_config():
    recipient = request.form.get("recipient", "").strip()
    if not recipient:
        return jsonify({"error": "Recipient email is required."}), 400

    try:
        with app.app_context():
            from auth.email_service import apply_smtp_config
            apply_smtp_config()

            if not app.config.get("MAIL_SERVER") or not app.config.get("MAIL_USERNAME"):
                return jsonify({"status": "failed", "error": "SMTP Server and Username must be configured before sending test emails."}), 400

            msg = Message(
                subject="EAM SMTP Configuration Test",
                recipients=[recipient],
            )
            msg.body = (
                "This is a test email from the Enterprise Asset Management system.\n\n"
                "If you received this message, your SMTP configuration is working correctly.\n\n"
                "Enterprise Asset Management System"
            )
            mail.send(msg)
        return jsonify({"status": "success", "message": f"Test email sent to {recipient}."})
    except Exception as e:
        return jsonify({"status": "failed", "error": str(e)}), 400


from routes import tickets_bp, incidents_bp, assets_bp
app.register_blueprint(tickets_bp)
app.register_blueprint(incidents_bp)
app.register_blueprint(assets_bp)


if __name__ == "__main__":
    init_db()
    bootstrap_super_admin()
    cleanup_expired_records()
    app.run(host="0.0.0.0", port=5000, debug=True)