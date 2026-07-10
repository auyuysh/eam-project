from dotenv import load_dotenv
load_dotenv()

from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_mail import Mail, Message
import sqlite3
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
import os
import secrets
import hashlib
import re
import logging
from collections import defaultdict

# ─── AUTH MODULE ──────────────────────────────────────────────
from auth import authenticate_user, otp_service, email_service
from auth.auth_settings import get_otp_expiry_minutes, get_resend_delay_seconds, get_max_resend_attempts
from auth.local_auth import get_user_by_id

app = Flask(__name__)

# Mail Configuration
app.config["MAIL_SERVER"] = os.getenv("MAIL_SERVER")
app.config["MAIL_PORT"] = int(os.getenv("MAIL_PORT"))
app.config["MAIL_USE_TLS"] = os.getenv("MAIL_USE_TLS") == "True"
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = os.getenv("MAIL_DEFAULT_SENDER")

mail = Mail(app)
app.secret_key = "eam_demo_secret_key_2024"

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

DB_NAME = "devices.db"

def get_db():
    return sqlite3.connect(DB_NAME, timeout=10, check_same_thread=False)


def init_db():
    conn = get_db()
    cursor = conn.cursor()

    

    

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS departments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            company_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            company_id TEXT DEFAULT NULL,
            role TEXT DEFAULT NULL,
            created_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS asset_types (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            department_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            prefix TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (department_id) REFERENCES departments(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_type_id INTEGER NOT NULL,
            department_id INTEGER NOT NULL,
            asset_id TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            serial_number TEXT NOT NULL,
            location TEXT,
            warranty_start TEXT,
            warranty_end TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (asset_type_id) REFERENCES asset_types(id),
            FOREIGN KEY (department_id) REFERENCES departments(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS asset_type_fields (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_type_id INTEGER NOT NULL,
            field_name TEXT NOT NULL,
            field_type TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (asset_type_id) REFERENCES asset_types(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS asset_type_field_values (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id INTEGER NOT NULL,
            field_id INTEGER NOT NULL,
            value TEXT,
            FOREIGN KEY (asset_id) REFERENCES assets(id),
            FOREIGN KEY (field_id) REFERENCES asset_type_fields(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS asset_custom_fields (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id INTEGER NOT NULL,
            field_name TEXT NOT NULL,
            field_type TEXT NOT NULL,
            value TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (asset_id) REFERENCES assets(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS pending_registrations (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name      TEXT    NOT NULL,
            last_name       TEXT    NOT NULL,
            company_name    TEXT    NOT NULL,
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
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            otp_code    TEXT    NOT NULL,
            purpose     TEXT    NOT NULL DEFAULT 'login',
            created_at  TEXT    NOT NULL,
            expires_at  TEXT    NOT NULL,
            used        INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            token_hash  TEXT    NOT NULL,
            created_at  TEXT    NOT NULL,
            expires_at  TEXT    NOT NULL,
            used        INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # ── MIGRATION: add attempts column if missing ────────────────────
    try:
        cursor.execute("ALTER TABLE otp_codes ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0")
    except sqlite3.OperationalError:
        pass  # column already exists

    # ── MIGRATION: add profile metadata columns if missing ──────────
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN company_id TEXT DEFAULT NULL")
    except sqlite3.OperationalError:
        pass

    try:
        cursor.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT NULL")
    except sqlite3.OperationalError:
        pass

    conn.commit()
    conn.close()


def is_logged_in():
    return session.get("logged_in") == True


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
    existing_prefixes = {row[0] for row in cursor.fetchall()}

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
            "DELETE FROM pending_registrations WHERE otp_expires_at IS NOT NULL AND otp_expires_at < ?",
            (now.isoformat(),),
        )
        expired_pending = cursor.rowcount
        if expired_pending:
            logger.info("Cleaned up %s expired pending registration(s)", expired_pending)

        cutoff = now - timedelta(hours=24)
        cursor.execute(
            "DELETE FROM pending_registrations WHERE created_at < ?",
            (cutoff.isoformat(),),
        )
        abandoned = cursor.rowcount
        if abandoned:
            logger.info("Cleaned up %s abandoned pending registration(s)", abandoned)

        cursor.execute(
            "DELETE FROM password_reset_tokens WHERE expires_at < ?",
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
            log_login_success(email, "LOCAL")
            session["logged_in"] = True
            session["user_id"] = result.user_id
            session["username"] = email
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
        otp = request.form.get("otp", "").strip()

        result = otp_service.verify_otp(user_id, otp, purpose="login")
        if result == "valid":
            from auth.audit_service import log_otp_success, log_login_success
            log_otp_success(user_id, "login")
            user = get_user_by_id(user_id)
            login_email = user["email"] if user else "unknown"
            log_login_success(login_email, "LOCAL")
            session.pop("pending_user_id", None)
            session.pop("pending_email", None)
            session.pop("pending_masked_email", None)
            session["logged_in"] = True
            session["user_id"] = user_id
            session["username"] = login_email
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
        company_name = request.form.get("company", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not all([first_name, last_name, company_name, email, password]):
            return render_template("signup.html", error="All fields are required.")

        if password != confirm_password:
            return render_template("signup.html", error="Passwords do not match.")

        session.pop("pending_registration_id", None)
        session.pop("pending_registration_email", None)
        session.pop("verify_email_masked", None)

        conn = get_db()
        try:
            cursor = conn.cursor()

            cursor.execute(
                "DELETE FROM pending_registrations WHERE email = ?",
                (email,),
            )

            cursor.execute(
                "SELECT id FROM users WHERE email = ?", (email,)
            )
            if cursor.fetchone():
                return render_template("signup.html", error="Email already registered.")

            cursor.execute(
                "SELECT id FROM pending_registrations WHERE email = ?", (email,)
            )
            if cursor.fetchone():
                return render_template("signup.html", error="Email already registered.")

            password_hash = generate_password_hash(password)
            now = datetime.now(timezone.utc)
            # user_id=0 because user doesn't exist yet — OTP stored in pending_registrations
            otp = otp_service.generate_otp(0)
            otp_expiry = get_otp_expiry_minutes()
            otp_expires_at = now + timedelta(minutes=otp_expiry)

            cursor.execute("""
                INSERT INTO pending_registrations (
                    first_name, last_name, company_name,
                    email, username, password_hash,
                    otp, otp_created_at, otp_expires_at, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                first_name, last_name, company_name,
                email, email, password_hash,
                otp, now.isoformat(), otp_expires_at.isoformat(), now.isoformat(),
            ))
            conn.commit()
            pending_id = cursor.lastrowid
            logger.info("Pending registration created: id=%s, email=%s", pending_id, email)
        except sqlite3.IntegrityError:
            return render_template("signup.html", error="Email already registered.")
        finally:
            conn.close()

        from auth.email_service import mask_email
        try:
            email_service.send_welcome_email(email, first_name, otp)
            logger.info("Verification email sent to %s for pending registration id=%s", email, pending_id)
        except Exception as e:
            logger.error("Failed to send welcome email to %s: %s", email, str(e), exc_info=True)

        session["pending_registration_id"] = pending_id
        session["pending_registration_email"] = email
        session["verify_email_masked"] = mask_email(email)
        return redirect(url_for("verify_email"))

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
                "SELECT id, first_name, last_name, company_name, email, username, password_hash, otp, otp_expires_at FROM pending_registrations WHERE id = ?",
                (pending_id,),
            )
            row = cursor.fetchone()

            if row is None:
                session.pop("pending_registration_id", None)
                session.pop("verify_email_masked", None)
                return redirect(url_for("signup"))

            (pr_id, first_name, last_name, company_name, email,
             username, password_hash, stored_otp, otp_expires_at_str) = row

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
                INSERT INTO users (first_name, last_name, company_name, email, username, password_hash, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (first_name, last_name, company_name, email, email, password_hash, created_at))
            new_user_id = cursor.lastrowid

            cursor.execute(
                "DELETE FROM pending_registrations WHERE id = ?",
                (pending_id,),
            )
            conn.commit()
            logger.info("User created from pending registration: user_id=%s, email=%s", new_user_id, email)
        except sqlite3.IntegrityError as e:
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
            "SELECT id, email, first_name, otp, otp_created_at FROM pending_registrations WHERE id = ?",
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
            "UPDATE pending_registrations SET otp = ?, otp_created_at = ?, otp_expires_at = ? WHERE id = ?",
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
                    new_hash = generate_password_hash(new_password)
                    cursor.execute(
                        "UPDATE users SET password_hash = ? WHERE id = ?",
                        (new_hash, user_id),
                    )
                    conn.commit()
                    success_msg = "Password updated successfully."
                    logger.info("Password updated via profile for user_id=%s", user_id)
                finally:
                    conn.close()

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """SELECT first_name, last_name, company_name, email,
                      company_id, role, created_at
               FROM users WHERE id = ?""",
            (user_id,),
        )
        user = cursor.fetchone()
    finally:
        conn.close()

    if user is None:
        return redirect(url_for("login"))

    return render_template(
        "profile.html",
        first_name=user[0],
        last_name=user[1],
        company_name=user[2],
        email=user[3],
        company_id=user[4],
        role=user[5],
        created_at=format_timestamp(user[6]),
        username=session.get("username", ""),
        success=success_msg,
        error=error_msg,
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
            "SELECT password_hash FROM users WHERE id = ?",
            (user_id,),
        )
        row = cursor.fetchone()
        if row is None:
            return jsonify({"status": "error", "message": "User not found."}), 404

        if check_password_hash(row[0], current_password):
            _password_reset_attempts.pop(verify_key, None)
            return jsonify({"status": "success", "message": "Password verified."})
        else:
            return jsonify({"status": "error", "message": "Current password incorrect."})
    finally:
        conn.close()


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
            "SELECT id, first_name, email FROM users WHERE email = ?",
            (email,),
        )
        row = cursor.fetchone()
        if row:
            logger.info("User found in DB for email: %s (user_id=%s)", email, row[0])
            return {"id": row[0], "first_name": row[1], "email": row[2]}
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
            "INSERT INTO password_reset_tokens (user_id, token_hash, created_at, expires_at, used) VALUES (?, ?, ?, ?, 0)",
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
            "SELECT id, user_id, expires_at, used FROM password_reset_tokens WHERE token_hash = ? ORDER BY created_at DESC LIMIT 1",
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
            "UPDATE password_reset_tokens SET used = 1 WHERE id = ?",
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
            "UPDATE password_reset_tokens SET used = 1 WHERE user_id = ? AND used = 0",
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
            "SELECT email, first_name FROM users WHERE id = ?",
            (user_id,),
        )
        user = cursor.fetchone()
    finally:
        conn.close()

    if user is None:
        logger.error("Token user_id=%s not found in database", user_id)
        return render_template("reset_link_invalid.html")

    masked_email = _mask_email(user[0])
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

        password_hash = generate_password_hash(password)

        conn = get_db()
        try:
            cursor = conn.cursor()

            cursor.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (password_hash, user_id),
            )
            logger.info("Password hash updated for user_id=%s", user_id)

            cursor.execute(
                "UPDATE password_reset_tokens SET used = 1 WHERE id = ?",
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

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id, name FROM departments ORDER BY name")
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
            "SELECT id FROM departments WHERE upper(name) = ?", (name,)
        )
        if cursor.fetchone():
            return jsonify({
                "error": f"Department '{name}' already exists."
            }), 400

        cursor.execute(
            "INSERT INTO departments (name, created_at) VALUES (?, ?)",
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

    conn = get_db()
    try:
        cursor = conn.cursor()

        cursor.execute(
            "SELECT id, password_hash FROM users WHERE id = ?",
            (session.get("user_id"),)
        )
        user = cursor.fetchone()

        if not user or not check_password_hash(user[1], password):
            return jsonify({"error": "Incorrect password."}), 403

        cursor.execute(
            "SELECT id FROM asset_types WHERE department_id = ?", (dept_id,)
        )
        asset_type_ids = [row[0] for row in cursor.fetchall()]

        for at_id in asset_type_ids:
            cursor.execute(
                "SELECT id FROM assets WHERE asset_type_id = ?", (at_id,)
            )
            asset_ids = [row[0] for row in cursor.fetchall()]

            for a_id in asset_ids:
                cursor.execute(
                    "DELETE FROM asset_custom_fields WHERE asset_id = ?",
                    (a_id,)
                )
                cursor.execute(
                    "DELETE FROM asset_type_field_values WHERE asset_id = ?",
                    (a_id,)
                )
            cursor.execute(
                "DELETE FROM assets WHERE asset_type_id = ?", (at_id,)
            )
            cursor.execute(
                "DELETE FROM asset_type_fields WHERE asset_type_id = ?",
                (at_id,)
            )
            cursor.execute(
                "DELETE FROM asset_types WHERE id = ?", (at_id,)
            )

        cursor.execute("DELETE FROM departments WHERE id = ?", (dept_id,))
        conn.commit()
        return jsonify({"success": True}), 200

    except Exception as e:
        print("Error deleting department:", e)
        return jsonify({"error": "An unexpected error occurred."}), 500
    finally:
        conn.close()


# ─── DEPARTMENT PAGE ─────────────────────────────────────────

@app.route("/department/<dept_name>")
def department(dept_name):
    if not is_logged_in():
        return redirect(url_for("login"))

    conn = get_db()
    try:
        cursor = conn.cursor()

        cursor.execute(
            "SELECT id, name FROM departments WHERE upper(name) = ?",
            (dept_name.upper(),)
        )
        dept = cursor.fetchone()

        if not dept:
            return redirect(url_for("dashboard"))

        dept_id = dept[0]
        dept_name_clean = dept[1]

        cursor.execute("""
            SELECT
                at.id,
                at.name,
                at.prefix,
                COUNT(a.id) as asset_count
            FROM asset_types at
            LEFT JOIN assets a ON a.asset_type_id = at.id
            WHERE at.department_id = ?
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
def create_asset_type(dept_name):
    if not is_logged_in():
        return jsonify({"error": "Not logged in"}), 401

    name = request.form.get("name", "").strip().upper()

    if not name:
        return jsonify({"error": "Asset type name cannot be empty."}), 400

    conn = get_db()
    try:
        cursor = conn.cursor()

        cursor.execute(
            "SELECT id, name FROM departments WHERE upper(name) = ?",
            (dept_name.upper(),)
        )
        dept = cursor.fetchone()

        if not dept:
            return jsonify({"error": "Department not found."}), 404

        dept_id = dept[0]
        dept_name_clean = dept[1]

        # Check duplicate asset type name in this department
        cursor.execute(
            """SELECT id FROM asset_types
               WHERE department_id = ? AND upper(name) = ?""",
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
            VALUES (?, ?, ?, ?)
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
def asset_type(asset_type_id):
    if not is_logged_in():
        return redirect(url_for("login"))

    conn = get_db()
    try:
        cursor = conn.cursor()

        cursor.execute("""
            SELECT at.id, at.name, at.prefix, d.name as dept_name
            FROM asset_types at
            JOIN departments d ON d.id = at.department_id
            WHERE at.id = ?
        """, (asset_type_id,))
        asset_type_row = cursor.fetchone()

        if not asset_type_row:
            return redirect(url_for("dashboard"))

        cursor.execute("""
            SELECT id, asset_id, name, serial_number,
                   location, warranty_start, warranty_end, created_at
            FROM assets
            WHERE asset_type_id = ?
            ORDER BY created_at DESC
        """, (asset_type_id,))
        assets = cursor.fetchall()

        cursor.execute("""
            SELECT id, field_name, field_type
            FROM asset_type_fields
            WHERE asset_type_id = ?
            ORDER BY created_at
        """, (asset_type_id,))
        type_fields = cursor.fetchall()
    finally:
        conn.close()

    formatted_assets = []
    for asset in assets:
        asset = list(asset)
        asset.append(warranty_status(asset[6]))
        formatted_assets.append(asset)

    return render_template(
        "asset_type.html",
        asset_type=asset_type_row,
        assets=formatted_assets,
        type_fields=type_fields,
        username=session.get("username", "")
    )


@app.route("/asset-type/<int:asset_type_id>/add-asset", methods=["POST"])
def add_asset(asset_type_id):
    if not is_logged_in():
        return jsonify({"error": "Not logged in"}), 401

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

        # Check duplicate serial number case-insensitively across all assets
        cursor.execute(
            "SELECT asset_id FROM assets WHERE upper(serial_number) = ?",
            (serial_number,)
        )
        existing = cursor.fetchone()
        if existing:
            return jsonify({
                "error": f"Serial number '{serial_number}' already exists "
                         f"(assigned to Asset ID: {existing[0]}). "
                         f"Each physical device must have a unique serial number."
            }), 400

        cursor.execute(
            "SELECT id, prefix, department_id FROM asset_types WHERE id = ?",
            (asset_type_id,)
        )
        at = cursor.fetchone()

        if not at:
            return jsonify({"error": "Asset type not found."}), 404

        prefix = at[1]
        dept_id = at[2]

        cursor.execute(
            "SELECT COUNT(*) FROM assets WHERE asset_type_id = ?",
            (asset_type_id,)
        )
        count = cursor.fetchone()[0]
        next_number = str(count + 1).zfill(4)
        asset_id = f"{prefix}-{next_number}"

        created_at = datetime.now(ZoneInfo("Asia/Kolkata")).isoformat()

        cursor.execute("""
            INSERT INTO assets (
                asset_type_id, department_id, asset_id,
                name, serial_number, location,
                warranty_start, warranty_end, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            asset_type_id, dept_id, asset_id,
            name, serial_number, location or None,
            warranty_start or None, warranty_end or None,
            created_at
        ))
        conn.commit()
        return jsonify({"success": True}), 200

    except sqlite3.IntegrityError:
        return jsonify({
            "error": "Duplicate serial number or asset ID detected."
        }), 400
    except Exception as e:
        print("Error adding asset:", e)
        return jsonify({"error": "An unexpected error occurred."}), 500
    finally:
        conn.close()


@app.route("/asset-type/<int:asset_type_id>/add-field", methods=["POST"])
def add_type_field(asset_type_id):
    if not is_logged_in():
        return redirect(url_for("login"))

    field_name = request.form.get("field_name", "").strip()
    field_type = request.form.get("field_type", "text").strip()

    if not field_name:
        return redirect(url_for("asset_type", asset_type_id=asset_type_id))

    created_at = datetime.now(ZoneInfo("Asia/Kolkata")).isoformat()

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO asset_type_fields (
                asset_type_id, field_name, field_type, created_at
            ) VALUES (?, ?, ?, ?)
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
def delete_type_field(asset_type_id, field_id):
    if not is_logged_in():
        return redirect(url_for("login"))

    password = request.form.get("password", "")

    conn = get_db()
    try:
        cursor = conn.cursor()

        cursor.execute(
            "SELECT id, password_hash FROM users WHERE id = ?",
            (session.get("user_id"),)
        )
        user = cursor.fetchone()

        if not user or not check_password_hash(user[1], password):
            return redirect(
                url_for("asset_type", asset_type_id=asset_type_id)
            )

        cursor.execute(
            "DELETE FROM asset_type_field_values WHERE field_id = ?",
            (field_id,)
        )
        cursor.execute(
            "DELETE FROM asset_type_fields WHERE id = ?", (field_id,)
        )
        conn.commit()
    finally:
        conn.close()

    return redirect(url_for("asset_type", asset_type_id=asset_type_id))


@app.route("/asset-type/<int:asset_type_id>/delete", methods=["POST"])
def delete_asset_type(asset_type_id):
    if not is_logged_in():
        return redirect(url_for("login"))

    password = request.form.get("password", "")

    conn = get_db()
    try:
        cursor = conn.cursor()

        cursor.execute(
            "SELECT id, password_hash FROM users WHERE id = ?",
            (session.get("user_id"),)
        )
        user = cursor.fetchone()

        if not user or not check_password_hash(user[1], password):
            return redirect(
                url_for("asset_type", asset_type_id=asset_type_id)
            )

        cursor.execute(
            "SELECT department_id FROM asset_types WHERE id = ?",
            (asset_type_id,)
        )
        at = cursor.fetchone()
        if not at:
            return redirect(url_for("dashboard"))

        dept_id = at[0]
        cursor.execute(
            "SELECT name FROM departments WHERE id = ?", (dept_id,)
        )
        dept = cursor.fetchone()
        dept_name = dept[0] if dept else None

        cursor.execute(
            "SELECT id FROM assets WHERE asset_type_id = ?", (asset_type_id,)
        )
        asset_ids = [row[0] for row in cursor.fetchall()]

        for a_id in asset_ids:
            cursor.execute(
                "DELETE FROM asset_custom_fields WHERE asset_id = ?", (a_id,)
            )
            cursor.execute(
                "DELETE FROM asset_type_field_values WHERE asset_id = ?",
                (a_id,)
            )

        cursor.execute(
            "DELETE FROM assets WHERE asset_type_id = ?", (asset_type_id,)
        )
        cursor.execute(
            "DELETE FROM asset_type_fields WHERE asset_type_id = ?",
            (asset_type_id,)
        )
        cursor.execute(
            "DELETE FROM asset_types WHERE id = ?", (asset_type_id,)
        )
        conn.commit()
    finally:
        conn.close()

    if dept_name:
        return redirect(url_for("department", dept_name=dept_name))
    return redirect(url_for("dashboard"))


# ─── ASSET DETAIL ─────────────────────────────────────────────

@app.route("/asset/<int:asset_id>")
def asset_detail(asset_id):
    if not is_logged_in():
        return redirect(url_for("login"))

    conn = get_db()
    try:
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                a.id, a.asset_id, a.name, a.serial_number,
                a.location, a.warranty_start, a.warranty_end,
                a.created_at, at.name as type_name,
                d.name as dept_name, at.id as asset_type_id
            FROM assets a
            JOIN asset_types at ON at.id = a.asset_type_id
            JOIN departments d ON d.id = a.department_id
            WHERE a.id = ?
        """, (asset_id,))
        asset = cursor.fetchone()

        if not asset:
            return redirect(url_for("dashboard"))

        cursor.execute("""
            SELECT
                atf.id, atf.field_name, atf.field_type,
                COALESCE(atfv.value, '') as value,
                atfv.id as value_id
            FROM asset_type_fields atf
            LEFT JOIN asset_type_field_values atfv
                ON atfv.field_id = atf.id AND atfv.asset_id = ?
            WHERE atf.asset_type_id = ?
            ORDER BY atf.created_at
        """, (asset_id, asset[10]))
        type_fields = cursor.fetchall()

        cursor.execute("""
            SELECT id, field_name, field_type, value
            FROM asset_custom_fields
            WHERE asset_id = ?
            ORDER BY created_at
        """, (asset_id,))
        custom_fields = cursor.fetchall()
    finally:
        conn.close()

    warranty = warranty_status(asset[6])

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
def update_type_field_value(asset_id, field_id):
    if not is_logged_in():
        return redirect(url_for("login"))

    value = request.form.get("value", "").strip()

    conn = get_db()
    try:
        cursor = conn.cursor()

        cursor.execute("""
            SELECT id FROM asset_type_field_values
            WHERE asset_id = ? AND field_id = ?
        """, (asset_id, field_id))
        existing = cursor.fetchone()

        if existing:
            cursor.execute("""
                UPDATE asset_type_field_values SET value = ?
                WHERE asset_id = ? AND field_id = ?
            """, (value, asset_id, field_id))
        else:
            cursor.execute("""
                INSERT INTO asset_type_field_values (asset_id, field_id, value)
                VALUES (?, ?, ?)
            """, (asset_id, field_id, value))

        conn.commit()
    finally:
        conn.close()

    return jsonify({"success": True}), 200


@app.route("/asset/<int:asset_id>/add-custom-field", methods=["POST"])
def add_custom_field(asset_id):
    if not is_logged_in():
        return redirect(url_for("login"))

    field_name = request.form.get("field_name", "").strip()
    field_type = request.form.get("field_type", "text").strip()
    value = request.form.get("value", "").strip()

    if not field_name:
        return redirect(url_for("asset_detail", asset_id=asset_id))

    created_at = datetime.now(ZoneInfo("Asia/Kolkata")).isoformat()

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO asset_custom_fields (
                asset_id, field_name, field_type, value, created_at
            ) VALUES (?, ?, ?, ?, ?)
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
def delete_custom_field(asset_id, field_id):
    if not is_logged_in():
        return redirect(url_for("login"))

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM asset_custom_fields WHERE id = ? AND asset_id = ?",
            (field_id, asset_id)
        )
        conn.commit()
    finally:
        conn.close()

    return redirect(url_for("asset_detail", asset_id=asset_id))


@app.route("/asset/<int:asset_id>/delete", methods=["POST"])
def delete_asset(asset_id):
    if not is_logged_in():
        return redirect(url_for("login"))

    password = request.form.get("password", "")

    conn = get_db()
    try:
        cursor = conn.cursor()

        cursor.execute(
            "SELECT id, password_hash FROM users WHERE id = ?",
            (session.get("user_id"),)
        )
        user = cursor.fetchone()

        if not user or not check_password_hash(user[1], password):
            return redirect(url_for("asset_detail", asset_id=asset_id))

        cursor.execute(
            "SELECT asset_type_id FROM assets WHERE id = ?", (asset_id,)
        )
        asset = cursor.fetchone()
        if not asset:
            return redirect(url_for("dashboard"))

        asset_type_id = asset[0]

        cursor.execute(
            "DELETE FROM asset_custom_fields WHERE asset_id = ?", (asset_id,)
        )
        cursor.execute(
            "DELETE FROM asset_type_field_values WHERE asset_id = ?",
            (asset_id,)
        )
        cursor.execute("DELETE FROM assets WHERE id = ?", (asset_id,))
        conn.commit()
    finally:
        conn.close()

    return redirect(url_for("asset_type", asset_type_id=asset_type_id))

# ─── test-email ─────────────────────────────────────────────

@app.route("/test-email")
def test_email():
    try:
        msg = Message(
            subject="EAM Email Test",
            recipients=[app.config["MAIL_USERNAME"]]   # Sends to your Gmail
        )

        msg.body = """
Hello!

Congratulations.

Your Flask application is successfully sending emails using Gmail SMTP.

Enterprise Asset Management System
"""

        mail.send(msg)

        return "✅ Email sent successfully."

    except Exception as e:
        return f"❌ Error: {e}"






if __name__ == "__main__":
    init_db()
    cleanup_expired_records()
    app.run(host="0.0.0.0", port=5000, debug=True)