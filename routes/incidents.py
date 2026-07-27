from flask import request, jsonify, render_template, redirect, url_for, session, flash, g
from datetime import datetime
from zoneinfo import ZoneInfo
import logging
import psycopg2
import psycopg2.extras
import psycopg2.errors

from auth.database import get_db as _get_pg_db, dict_cursor
import os
import uuid

from . import incidents_bp
from auth.local_auth import get_user_by_id

logger = logging.getLogger("eam.incidents")

VALID_STATUSES = [
    'NEW', 'ASSIGNED', 'WAITING_FOR_INVESTIGATION_APPROVAL',
    'INVESTIGATION_APPROVED', 'WAITING_FOR_RCA_APPROVAL',
    'RCA_APPROVED', 'WAITING_FOR_VERIFICATION', 'CLOSED'
]

ACTIVE_STATUSES = [
    'NEW', 'ASSIGNED', 'WAITING_FOR_INVESTIGATION_APPROVAL',
    'INVESTIGATION_APPROVED', 'WAITING_FOR_RCA_APPROVAL',
    'RCA_APPROVED', 'WAITING_FOR_VERIFICATION'
]

STATUS_COLORS = {
    'NEW': '#5c6bc0',
    'ASSIGNED': '#f57c00',
    'WAITING_FOR_INVESTIGATION_APPROVAL': '#0277bd',
    'INVESTIGATION_APPROVED': '#00897b',
    'WAITING_FOR_RCA_APPROVAL': '#6a1b9a',
    'RCA_APPROVED': '#2e7d32',
    'WAITING_FOR_VERIFICATION': '#e65100',
    'CLOSED': '#616161',
}

STATUS_LABELS = {
    'NEW': 'New',
    'ASSIGNED': 'Assigned',
    'WAITING_FOR_INVESTIGATION_APPROVAL': 'Pending Investigation Approval',
    'INVESTIGATION_APPROVED': 'Investigation Approved',
    'WAITING_FOR_RCA_APPROVAL': 'Pending RCA Approval',
    'RCA_APPROVED': 'RCA Approved',
    'WAITING_FOR_VERIFICATION': 'Pending Verification',
    'CLOSED': 'Closed',
}

PRIORITY_COLORS = {
    'Low': '#4caf50',
    'Medium': '#ff9800',
    'High': '#f44336',
    'Critical': '#b71c1c',
}

STEP_ORDER = [
    'Reporting', 'Review & Assignment', 'Investigation',
    'Root Cause Analysis', 'Corrective Action', 'Verification', 'Closure'
]


def get_db():
    return _get_pg_db()


def is_logged_in():
    return session.get("logged_in") == True


def has_permission(user_id, permission_code):
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
        return cursor.fetchone()['count'] > 0
    except Exception as e:
        logger.error("Error checking permission: %s", e)
        return False
    finally:
        conn.close()


def permission_required(permission_code):
    from functools import wraps
    from flask import abort, redirect, url_for, session, g
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
                cursor.execute("SELECT role, department_id FROM users WHERE id = %s", (user_id,))
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
                    g.user_permissions = set()
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


def _now():
    return datetime.now(ZoneInfo("Asia/Kolkata")).isoformat()


def _generate_incident_code(cursor):
    cursor.execute("SELECT incident_code FROM incidents ORDER BY id DESC LIMIT 1")
    row = cursor.fetchone()
    if row:
        try:
            last_num = int(row['incident_code'].split('-')[1])
            return f"INC-{last_num + 1:05d}"
        except (IndexError, ValueError):
            pass
    return "INC-00001"


def _get_user_name(cursor, user_id):
    if not user_id:
        return None
    cursor.execute("SELECT first_name, last_name FROM users WHERE id = %s", (user_id,))
    row = cursor.fetchone()
    return f"{row['first_name']} {row['last_name']}" if row else None


def _get_dept_name(cursor, dept_id):
    if not dept_id:
        return None
    cursor.execute("SELECT name FROM departments WHERE id = %s", (dept_id,))
    row = cursor.fetchone()
    return row['name'] if row else None


def _log_audit(cursor, incident_id, step_name, user_id, action, old_value=None, new_value=None):
    cursor.execute("""
        INSERT INTO incident_audit_logs (incident_id, step_name, performed_by_id, action, old_value, new_value, timestamp)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, (incident_id, step_name, user_id, action, old_value, new_value, _now()))


def _get_audit_logs(cursor, incident_id):
    cursor.execute("""
        SELECT al.step_name, al.action, al.old_value, al.new_value, al.timestamp,
               u.first_name, u.last_name
        FROM incident_audit_logs al
        LEFT JOIN users u ON al.performed_by_id = u.id
        WHERE al.incident_id = %s
        ORDER BY al.timestamp ASC
    """, (incident_id,))
    return [
        {'step_name': r['step_name'], 'action': r['action'], 'old_value': r['old_value'], 'new_value': r['new_value'],
         'timestamp': r['timestamp'], 'performed_by': f"{r['first_name']} {r['last_name']}" if r['first_name'] else 'System'}
        for r in cursor.fetchall()
    ]


def _get_media_files(cursor, incident_id, step_name=None):
    if step_name:
        cursor.execute("""
            SELECT m.id, m.step_name, m.file_path, m.uploaded_at, u.first_name, u.last_name
            FROM incident_media m LEFT JOIN users u ON m.uploaded_by_id = u.id
            WHERE m.incident_id = %s AND m.step_name = %s
            ORDER BY m.uploaded_at DESC
        """, (incident_id, step_name))
    else:
        cursor.execute("""
            SELECT m.id, m.step_name, m.file_path, m.uploaded_at, u.first_name, u.last_name
            FROM incident_media m LEFT JOIN users u ON m.uploaded_by_id = u.id
            WHERE m.incident_id = %s
            ORDER BY m.uploaded_at DESC
        """, (incident_id,))
    return [
        {'id': r['id'], 'step_name': r['step_name'], 'file_path': r['file_path'], 'uploaded_at': r['uploaded_at'],
         'uploaded_by': f"{r['first_name']} {r['last_name']}" if r['first_name'] else 'System'}
        for r in cursor.fetchall()
    ]


def _auto_assign_manager(cursor, department_id):
    if not department_id:
        return None
    cursor.execute("""
        SELECT u.id FROM users u
        JOIN roles r ON u.role_id = r.id
        WHERE r.name = 'manager' AND u.department_id = %s AND u.account_status = 'active'
    """, (department_id,))
    managers = cursor.fetchall()
    if not managers:
        return None
    manager_ids = [m['id'] for m in managers]
    placeholders = ','.join(['%s'] * len(manager_ids))
    status_placeholders = ','.join(['%s'] * len(ACTIVE_STATUSES))
    cursor.execute(f"""
        SELECT assigned_manager_id, COUNT(*) as cnt
        FROM incidents
        WHERE assigned_manager_id IN ({placeholders})
        AND status IN ({status_placeholders})
        GROUP BY assigned_manager_id
        ORDER BY cnt ASC
    """, manager_ids + ACTIVE_STATUSES)
    workload = {r['assigned_manager_id']: r['cnt'] for r in cursor.fetchall()}
    best_manager = None
    min_count = float('inf')
    for mid in manager_ids:
        count = workload.get(mid, 0)
        if count < min_count:
            min_count = count
            best_manager = mid
    return best_manager


def _get_latest_feedback(cursor, incident_id):
    cursor.execute("""
        SELECT al.step_name, al.action, al.new_value, al.timestamp,
               u.first_name, u.last_name
        FROM incident_audit_logs al
        LEFT JOIN users u ON al.performed_by_id = u.id
        WHERE al.incident_id = %s
          AND al.action LIKE '%%Rejected%%'
          AND al.new_value IS NOT NULL
          AND al.new_value != ''
        ORDER BY al.timestamp DESC
        LIMIT 1
    """, (incident_id,))
    row = cursor.fetchone()
    if not row:
        return None
    return {
        'step_name': row['step_name'],
        'action': row['action'],
        'feedback': row['new_value'],
        'timestamp': row['timestamp'],
        'performed_by': f"{row['first_name']} {row['last_name']}" if row['first_name'] else 'Manager',
    }


def _save_media(cursor, incident_id, step_name, user_id, files):
    if not files:
        return
    upload_dir = os.path.join("static", "uploads", "incidents", str(incident_id))
    os.makedirs(upload_dir, exist_ok=True)
    for f in files:
        if f and f.filename:
            ext = os.path.splitext(f.filename)[1]
            filename = f"{uuid.uuid4().hex}{ext}"
            filepath = os.path.join(upload_dir, filename)
            f.save(filepath)
            rel_path = os.path.join("uploads", "incidents", str(incident_id), filename)
            cursor.execute("""
                INSERT INTO incident_media (incident_id, step_name, file_path, uploaded_by_id, uploaded_at)
                VALUES (%s, %s, %s, %s, %s)
            """, (incident_id, step_name, rel_path, user_id, _now()))


def _get_incident_summary(cursor, inc):
    return dict(inc)


INCIDENT_COLUMNS = """id, incident_code, title, location, department_id, priority, severity,
    description, incident_date, reported_by_id, assigned_manager_id, assigned_technician_id,
    status, estimated_repair_cost, estimated_repair_time, actual_repair_cost,
    completion_time, labour_hours, created_at, updated_at"""


# ─── STEP 1: RAISE INCIDENT ─────────────────────────────────
@incidents_bp.route("/create", methods=["GET", "POST"])
def create_incident():
    if not is_logged_in():
        return redirect(url_for("login"))
    user_id = session.get("user_id")
    user = get_user_by_id(user_id)
    if not user:
        return redirect(url_for("login"))

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id, name FROM departments ORDER BY name")
        departments = [{'id': r['id'], 'name': r['name']} for r in cursor.fetchall()]
    finally:
        conn.close()

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        location = request.form.get("location", "").strip()
        department_id = request.form.get("department_id")
        priority = request.form.get("priority", "Medium")
        description = request.form.get("description", "").strip()
        incident_date = request.form.get("incident_date", "")

        if not title or not location or not description or not incident_date:
            flash("Please fill in all required fields.", "danger")
            return render_template("incidents/create.html", departments=departments, user=user, form_data=request.form)

        dept_id = int(department_id) if department_id else None
        now = _now()
        conn = get_db()
        try:
            cursor = conn.cursor()
            incident_code = _generate_incident_code(cursor)
            manager_id = _auto_assign_manager(cursor, dept_id)
            cursor.execute("""
                INSERT INTO incidents (
                    incident_code, title, location, department_id, priority, severity,
                    description, incident_date, reported_by_id, assigned_manager_id,
                    assigned_technician_id, status, estimated_repair_cost, estimated_repair_time,
                    actual_repair_cost, completion_time, labour_hours, created_at, updated_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'NEW', NULL, NULL, NULL, NULL, NULL, %s, %s) RETURNING id
            """, (
                incident_code, title, location, dept_id, priority, 'Medium',
                description, incident_date, user_id, manager_id, None,
                now, now
            ))
            incident_id = cursor.fetchone()['id']
            _log_audit(cursor, incident_id, 'Reporting', user_id, 'Incident Created',
                       None, f"Code: {incident_code}, Title: {title}")
            if manager_id:
                _log_audit(cursor, incident_id, 'Reporting', user_id, 'Auto-assigned Manager',
                           None, f"Manager ID: {manager_id}")

            files = request.files.getlist("photos")
            _save_media(cursor, incident_id, 'Reporting', user_id, files)

            conn.commit()
            flash(f"Incident {incident_code} reported successfully.", "success")
            return redirect(url_for("incidents.incident_detail", incident_id=incident_id))
        except Exception as e:
            conn.rollback()
            logger.error("Error creating incident: %s", e)
            flash("An error occurred while creating the incident.", "danger")
            return render_template("incidents/create.html", departments=departments, user=user, form_data=request.form)
        finally:
            conn.close()

    return render_template("incidents/create.html", departments=departments, user=user, form_data={})


# ─── INCIDENT DETAIL (WORKFLOW VIEWER) ──────────────────────
@incidents_bp.route("/<int:incident_id>")
def incident_detail(incident_id):
    if not is_logged_in():
        return redirect(url_for("login"))
    user_id = session.get("user_id")
    user = get_user_by_id(user_id)
    if not user:
        return redirect(url_for("login"))

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(f"SELECT {INCIDENT_COLUMNS} FROM incidents WHERE id = %s", (incident_id,))
        row = cursor.fetchone()
        if not row:
            flash("Incident not found.", "danger")
            return redirect(url_for("incidents.incident_history"))

        inc = _get_incident_summary(cursor, row)
        reporter = _get_user_name(cursor, inc['reported_by_id'])
        manager = _get_user_name(cursor, inc['assigned_manager_id'])
        technician = _get_user_name(cursor, inc['assigned_technician_id'])
        dept_name = _get_dept_name(cursor, inc['department_id'])

        cursor.execute("SELECT notes, cause_suspected, estimated_cost, estimated_time, created_at FROM incident_investigations WHERE incident_id = %s ORDER BY created_at DESC LIMIT 1", (incident_id,))
        inv_row = cursor.fetchone()
        investigation = {'notes': inv_row['notes'], 'cause_suspected': inv_row['cause_suspected'], 'estimated_cost': inv_row['estimated_cost'], 'estimated_time': inv_row['estimated_time'], 'created_at': inv_row['created_at']} if inv_row else None

        cursor.execute("SELECT root_cause_category, why1, why2, why3, why4, why5, final_root_cause, contributing_factors, created_at FROM incident_rcas WHERE incident_id = %s ORDER BY created_at DESC LIMIT 1", (incident_id,))
        rca_row = cursor.fetchone()
        rca = {'root_cause_category': rca_row['root_cause_category'], 'why1': rca_row['why1'], 'why2': rca_row['why2'], 'why3': rca_row['why3'], 'why4': rca_row['why4'], 'why5': rca_row['why5'], 'final_root_cause': rca_row['final_root_cause'], 'contributing_factors': rca_row['contributing_factors'], 'created_at': rca_row['created_at']} if rca_row else None

        cursor.execute("SELECT repair_actions, parts_replaced, materials_used, labour_hours, actual_cost, completion_time, comments, created_at FROM incident_corrective_actions WHERE incident_id = %s ORDER BY created_at DESC LIMIT 1", (incident_id,))
        ca_row = cursor.fetchone()
        corrective = {'repair_actions': ca_row['repair_actions'], 'parts_replaced': ca_row['parts_replaced'], 'materials_used': ca_row['materials_used'], 'labour_hours': ca_row['labour_hours'], 'actual_cost': ca_row['actual_cost'], 'completion_time': ca_row['completion_time'], 'comments': ca_row['comments'], 'created_at': ca_row['created_at']} if ca_row else None

        cursor.execute("SELECT result, verified_by_id, comments, created_at FROM incident_verifications WHERE incident_id = %s ORDER BY created_at DESC LIMIT 1", (incident_id,))
        ver_row = cursor.fetchone()
        verification = {'result': ver_row['result'], 'verified_by': _get_user_name(cursor, ver_row['verified_by_id']), 'comments': ver_row['comments'], 'created_at': ver_row['created_at']} if ver_row else None

        cursor.execute("SELECT resolution_summary, final_root_cause, total_repair_cost, preventive_action_required, preventive_recommendations, created_at FROM incident_closures WHERE incident_id = %s ORDER BY created_at DESC LIMIT 1", (incident_id,))
        clo_row = cursor.fetchone()
        closure = {'resolution_summary': clo_row['resolution_summary'], 'final_root_cause': clo_row['final_root_cause'], 'total_repair_cost': clo_row['total_repair_cost'], 'preventive_action_required': clo_row['preventive_action_required'], 'preventive_recommendations': clo_row['preventive_recommendations'], 'created_at': clo_row['created_at']} if clo_row else None

        audit_logs = _get_audit_logs(cursor, incident_id)
        media = _get_media_files(cursor, incident_id)
        latest_feedback = _get_latest_feedback(cursor, incident_id)
    finally:
        conn.close()

    return render_template("incidents/detail.html",
        inc=inc, reporter=reporter, manager=manager, technician=technician,
        dept_name=dept_name, investigation=investigation, rca=rca,
        corrective=corrective, verification=verification, closure=closure,
        audit_logs=audit_logs, media=media, user=user,
        latest_feedback=latest_feedback,
        status_colors=STATUS_COLORS, status_labels=STATUS_LABELS,
        priority_colors=PRIORITY_COLORS, step_order=STEP_ORDER)


# ─── STEP 2: REVIEW & ASSIGN (Manager/Dept Head) ───────────
@incidents_bp.route("/assign-requests")
def assign_requests():
    if not is_logged_in():
        return redirect(url_for("login"))
    user_id = session.get("user_id")
    user = get_user_by_id(user_id)
    if not user:
        return redirect(url_for("login"))

    can_review = (user.get("is_super_admin") or user.get("role") == "super_admin" or
                  has_permission(user_id, "incidents.review_assign"))
    can_override = (user.get("is_super_admin") or user.get("role") == "super_admin" or
                    has_permission(user_id, "incidents.reassign_manager"))

    if not can_review and not can_override:
        flash("You do not have permission to access this page.", "danger")
        return redirect(url_for("incidents.incident_history"))

    conn = get_db()
    try:
        cursor = conn.cursor()

        status_filter = request.args.get("filter", "all")
        query = f"SELECT {INCIDENT_COLUMNS} FROM incidents"
        params = []

        if can_review and not can_override:
            if user.get("department_id"):
                query += " WHERE department_id = %s"
                params.append(user["department_id"])

        if status_filter != "all":
            if "WHERE" in query:
                query += " AND status = %s"
            else:
                query += " WHERE status = %s"
            params.append(status_filter)

        query += " ORDER BY created_at DESC"
        cursor.execute(query, params)
        incidents = []
        for row in cursor.fetchall():
            inc = _get_incident_summary(cursor, row)
            inc['reporter_name'] = _get_user_name(cursor, inc['reported_by_id'])
            inc['manager_name'] = _get_user_name(cursor, inc['assigned_manager_id'])
            inc['technician_name'] = _get_user_name(cursor, inc['assigned_technician_id'])
            inc['dept_name'] = _get_dept_name(cursor, inc['department_id'])
            incidents.append(inc)

        cursor.execute("""
            SELECT u.id, u.first_name, u.last_name, u.email
            FROM users u
            JOIN roles r ON u.role_id = r.id
            WHERE r.name = 'technician' AND u.account_status = 'active'
            ORDER BY u.first_name
        """)
        technicians = [{'id': r['id'], 'name': f"{r['first_name']} {r['last_name']}", 'email': r['email']} for r in cursor.fetchall()]

        cursor.execute("""
            SELECT u.id, u.first_name, u.last_name
            FROM users u
            JOIN roles r ON u.role_id = r.id
            WHERE r.name = 'manager' AND u.account_status = 'active'
            ORDER BY u.first_name
        """)
        managers = [{'id': r['id'], 'name': f"{r['first_name']} {r['last_name']}"} for r in cursor.fetchall()]

    finally:
        conn.close()

    return render_template("incidents/assign_requests.html",
        incidents=incidents, technicians=technicians, managers=managers, user=user,
        status_colors=STATUS_COLORS, status_labels=STATUS_LABELS,
        priority_colors=PRIORITY_COLORS, current_filter=status_filter,
        can_review=can_review, can_override=can_override)


@incidents_bp.route("/<int:incident_id>/review", methods=["POST"])
def review_incident(incident_id):
    if not is_logged_in():
        return jsonify({"error": "Not authenticated"}), 401
    user_id = session.get("user_id")
    user = get_user_by_id(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 401

    if not (user.get("is_super_admin") or user.get("role") == "super_admin" or
            has_permission(user_id, "incidents.review_assign")):
        return jsonify({"error": "Permission denied"}), 403

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(f"SELECT {INCIDENT_COLUMNS} FROM incidents WHERE id = %s", (incident_id,))
        row = cursor.fetchone()
        if not row:
            return jsonify({"error": "Incident not found"}), 404

        inc = _get_incident_summary(cursor, row)
        if inc['status'] != 'NEW':
            return jsonify({"error": "Incident is not in NEW status"}), 400

        severity = request.form.get("severity", "Medium")
        decision = request.form.get("decision", "")
        tech_id = request.form.get("technician_id")
        comments = request.form.get("comments", "")

        if decision == "reject":
            cursor.execute("UPDATE incidents SET status = 'CLOSED', updated_at = %s WHERE id = %s", (_now(), incident_id))
            _log_audit(cursor, incident_id, 'Review & Assignment', user_id, 'Incident Rejected', inc['status'], 'CLOSED')
            conn.commit()
            return jsonify({"success": True, "message": "Incident rejected."})

        if not tech_id:
            return jsonify({"error": "Please select a technician."}), 400

        cursor.execute("""
            UPDATE incidents SET severity = %s, assigned_technician_id = %s, status = 'ASSIGNED',
            assigned_manager_id = %s, updated_at = %s WHERE id = %s
        """, (severity, int(tech_id), user_id, _now(), incident_id))
        _log_audit(cursor, incident_id, 'Review & Assignment', user_id, 'Incident Assigned',
                   f"Status: {inc['status']}", f"Status: ASSIGNED, Tech ID: {tech_id}")
        conn.commit()
        return jsonify({"success": True, "message": "Incident assigned successfully."})
    except Exception as e:
        conn.rollback()
        logger.error("Error reviewing incident: %s", e)
        return jsonify({"error": "An error occurred."}), 500
    finally:
        conn.close()


@incidents_bp.route("/<int:incident_id>/reassign-manager", methods=["POST"])
def reassign_manager(incident_id):
    if not is_logged_in():
        return jsonify({"error": "Not authenticated"}), 401
    user_id = session.get("user_id")
    user = get_user_by_id(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 401

    if not (user.get("is_super_admin") or user.get("role") == "super_admin" or
            has_permission(user_id, "incidents.reassign_manager")):
        return jsonify({"error": "Permission denied"}), 403

    new_manager_id = request.form.get("manager_id")
    if not new_manager_id:
        return jsonify({"error": "Please select a manager."}), 400

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(f"SELECT {INCIDENT_COLUMNS} FROM incidents WHERE id = %s", (incident_id,))
        row = cursor.fetchone()
        if not row:
            return jsonify({"error": "Incident not found"}), 404

        inc = _get_incident_summary(cursor, row)
        old_manager_id = inc['assigned_manager_id']

        cursor.execute("UPDATE incidents SET assigned_manager_id = %s, updated_at = %s WHERE id = %s",
                       (int(new_manager_id), _now(), incident_id))
        _log_audit(cursor, incident_id, 'Reassignment', user_id, 'Manager Reassigned',
                   f"Manager ID: {old_manager_id}", f"Manager ID: {new_manager_id}")
        conn.commit()
        return jsonify({"success": True, "message": "Manager reassigned successfully. Progress preserved."})
    except Exception as e:
        conn.rollback()
        logger.error("Error reassigning manager: %s", e)
        return jsonify({"error": "An error occurred."}), 500
    finally:
        conn.close()


# ─── STEP 3: INVESTIGATION (Technician) ─────────────────────
@incidents_bp.route("/<int:incident_id>/investigation", methods=["GET", "POST"])
def investigation(incident_id):
    if not is_logged_in():
        return redirect(url_for("login"))
    user_id = session.get("user_id")
    user = get_user_by_id(user_id)
    if not user:
        return redirect(url_for("login"))

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(f"SELECT {INCIDENT_COLUMNS} FROM incidents WHERE id = %s", (incident_id,))
        row = cursor.fetchone()
        if not row:
            flash("Incident not found.", "danger")
            return redirect(url_for("incidents.incident_history"))

        inc = _get_incident_summary(cursor, row)

        can_investigate = (user.get("is_super_admin") or user.get("role") == "super_admin" or
                          has_permission(user_id, "incidents.investigate"))
        is_assigned_tech = inc['assigned_technician_id'] == user_id
        can_override = (user.get("is_super_admin") or user.get("role") == "super_admin" or
                       has_permission(user_id, "incidents.override_edit"))

        if not (can_investigate and (is_assigned_tech or can_override)):
            flash("You do not have permission to investigate this incident.", "danger")
            return redirect(url_for("incidents.incident_detail", incident_id=incident_id))

        reporter = _get_user_name(cursor, inc['reported_by_id'])
        manager = _get_user_name(cursor, inc['assigned_manager_id'])
        dept_name = _get_dept_name(cursor, inc['department_id'])

        cursor.execute("SELECT notes, cause_suspected, estimated_cost, estimated_time, created_at FROM incident_investigations WHERE incident_id = %s ORDER BY created_at DESC LIMIT 1", (incident_id,))
        inv_row = cursor.fetchone()
        existing = {'notes': inv_row['notes'], 'cause_suspected': inv_row['cause_suspected'], 'estimated_cost': inv_row['estimated_cost'], 'estimated_time': inv_row['estimated_time']} if inv_row else None

        media = _get_media_files(cursor, incident_id, 'Investigation')
    finally:
        conn.close()

    if request.method == "POST":
        if inc['status'] not in ('ASSIGNED', 'WAITING_FOR_INVESTIGATION_APPROVAL'):
            flash("This incident is not in a valid state for investigation.", "danger")
            return redirect(url_for("incidents.incident_detail", incident_id=incident_id))

        notes = (
            request.form.get('investigation_notes') or
            request.form.get('notes') or
            request.form.get('investigation_details') or ''
        ).strip()

        cause_suspected = (
            request.form.get('cause_suspected') or
            request.form.get('suspected_cause') or
            request.form.get('cause') or ''
        ).strip()

        estimated_cost = (
            request.form.get('estimated_repair_cost') or
            request.form.get('estimated_cost') or ''
        ).strip()

        estimated_time = (
            request.form.get('estimated_repair_time') or
            request.form.get('estimated_time') or ''
        ).strip()

        if not notes:
            flash("Please provide investigation notes.", "danger")
            return render_template("incidents/investigation.html", inc=inc, reporter=reporter,
                manager=manager, dept_name=dept_name, existing=existing, media=media, user=user,
                status_colors=STATUS_COLORS, priority_colors=PRIORITY_COLORS)

        conn = get_db()
        try:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM incident_investigations WHERE incident_id = %s", (incident_id,))
            cursor.execute("""
                INSERT INTO incident_investigations (incident_id, notes, cause_suspected, estimated_cost, estimated_time, created_at)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (incident_id, notes, cause_suspected,
                  float(estimated_cost) if estimated_cost else None,
                  estimated_time, _now()))

            cursor.execute("UPDATE incidents SET status = 'WAITING_FOR_INVESTIGATION_APPROVAL', updated_at = %s WHERE id = %s", (_now(), incident_id))
            _log_audit(cursor, incident_id, 'Investigation', user_id, 'Investigation Submitted',
                       inc['status'], 'WAITING_FOR_INVESTIGATION_APPROVAL')

            photos = request.files.getlist("evidence_photos")
            reports = request.files.getlist("evidence_reports")
            _save_media(cursor, incident_id, 'Investigation', user_id, photos + reports)

            conn.commit()
            flash("Investigation submitted for approval.", "success")
        except Exception as e:
            conn.rollback()
            logger.error("Error submitting investigation: %s", e)
            flash("An error occurred.", "danger")
        finally:
            conn.close()

        return redirect(url_for("incidents.incident_detail", incident_id=incident_id))

    return render_template("incidents/investigation.html", inc=inc, reporter=reporter,
        manager=manager, dept_name=dept_name, existing=existing, media=media, user=user,
        status_colors=STATUS_COLORS, priority_colors=PRIORITY_COLORS)


@incidents_bp.route("/<int:incident_id>/review-investigation", methods=["POST"])
def review_investigation(incident_id):
    if not is_logged_in():
        return jsonify({"error": "Not authenticated"}), 401
    user_id = session.get("user_id")
    user = get_user_by_id(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 401

    if not (user.get("is_super_admin") or user.get("role") == "super_admin" or
            has_permission(user_id, "incidents.review_assign")):
        return jsonify({"error": "Permission denied"}), 403

    action = request.form.get("action", "")
    comments = request.form.get("comments", "").strip()
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(f"SELECT {INCIDENT_COLUMNS} FROM incidents WHERE id = %s", (incident_id,))
        row = cursor.fetchone()
        if not row:
            return jsonify({"error": "Incident not found"}), 404
        inc = _get_incident_summary(cursor, row)

        if inc['status'] != 'WAITING_FOR_INVESTIGATION_APPROVAL':
            return jsonify({"error": "Incident is not pending investigation approval"}), 400

        if action == "approve":
            new_status = "INVESTIGATION_APPROVED"
            cursor.execute("UPDATE incidents SET status = %s, updated_at = %s WHERE id = %s", (new_status, _now(), incident_id))
            _log_audit(cursor, incident_id, 'Investigation', user_id, 'Investigation Approved',
                       inc['status'], new_status)
        elif action == "reject":
            new_status = "CLOSED"
            cursor.execute("UPDATE incidents SET status = %s, updated_at = %s WHERE id = %s", (new_status, _now(), incident_id))
            _log_audit(cursor, incident_id, 'Investigation', user_id, 'Investigation Rejected – Incident Closed',
                       inc['status'], new_status)
        else:
            return jsonify({"error": "Invalid action"}), 400

        conn.commit()
        return jsonify({"success": True, "message": f"Investigation {'approved' if action == 'approve' else 'rejected'}."})
    except Exception as e:
        conn.rollback()
        logger.error("Error: %s", e)
        return jsonify({"error": "An error occurred."}), 500
    finally:
        conn.close()


# ─── STEP 4: ROOT CAUSE ANALYSIS (Technician) ──────────────
@incidents_bp.route("/<int:incident_id>/rca", methods=["GET", "POST"])
def rca(incident_id):
    if not is_logged_in():
        return redirect(url_for("login"))
    user_id = session.get("user_id")
    user = get_user_by_id(user_id)
    if not user:
        return redirect(url_for("login"))

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(f"SELECT {INCIDENT_COLUMNS} FROM incidents WHERE id = %s", (incident_id,))
        row = cursor.fetchone()
        if not row:
            flash("Incident not found.", "danger")
            return redirect(url_for("incidents.incident_history"))

        inc = _get_incident_summary(cursor, row)

        can_rca = (user.get("is_super_admin") or user.get("role") == "super_admin" or
                   has_permission(user_id, "incidents.rca"))
        is_assigned_tech = inc['assigned_technician_id'] == user_id
        can_override = (user.get("is_super_admin") or user.get("role") == "super_admin" or
                       has_permission(user_id, "incidents.override_edit"))

        if not (can_rca and (is_assigned_tech or can_override)):
            flash("You do not have permission to perform RCA on this incident.", "danger")
            return redirect(url_for("incidents.incident_detail", incident_id=incident_id))

        if inc['status'] not in ('INVESTIGATION_APPROVED', 'WAITING_FOR_RCA_APPROVAL'):
            flash("Investigation must be approved before performing RCA.", "danger")
            return redirect(url_for("incidents.incident_detail", incident_id=incident_id))

        cursor.execute("SELECT root_cause_category, why1, why2, why3, why4, why5, final_root_cause, contributing_factors FROM incident_rcas WHERE incident_id = %s ORDER BY created_at DESC LIMIT 1", (incident_id,))
        rca_row = cursor.fetchone()
        existing = {'root_cause_category': rca_row['root_cause_category'], 'why1': rca_row['why1'], 'why2': rca_row['why2'], 'why3': rca_row['why3'], 'why4': rca_row['why4'], 'why5': rca_row['why5'], 'final_root_cause': rca_row['final_root_cause'], 'contributing_factors': rca_row['contributing_factors']} if rca_row else None

        media = _get_media_files(cursor, incident_id, 'RCA')
    finally:
        conn.close()

    if request.method == "POST":
        root_cause_category = request.form.get("root_cause_category", "").strip()
        why1 = request.form.get("why1", "").strip()
        why2 = request.form.get("why2", "").strip()
        why3 = request.form.get("why3", "").strip()
        why4 = request.form.get("why4", "").strip()
        why5 = request.form.get("why5", "").strip()
        final_root_cause = request.form.get("final_root_cause", "").strip()
        contributing_factors = request.form.get("contributing_factors", "").strip()

        if not final_root_cause:
            flash("Please provide the final root cause.", "danger")
            return render_template("incidents/rca.html", inc=inc, existing=existing, media=media, user=user,
                status_colors=STATUS_COLORS, priority_colors=PRIORITY_COLORS)

        conn = get_db()
        try:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM incident_rcas WHERE incident_id = %s", (incident_id,))
            cursor.execute("""
                INSERT INTO incident_rcas (incident_id, root_cause_category, why1, why2, why3, why4, why5, final_root_cause, contributing_factors, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (incident_id, root_cause_category, why1, why2, why3, why4, why5, final_root_cause, contributing_factors, _now()))

            cursor.execute("UPDATE incidents SET status = 'WAITING_FOR_RCA_APPROVAL', updated_at = %s WHERE id = %s", (_now(), incident_id))
            _log_audit(cursor, incident_id, 'Root Cause Analysis', user_id, 'RCA Submitted',
                       inc['status'], 'WAITING_FOR_RCA_APPROVAL')

            files = request.files.getlist("photos")
            _save_media(cursor, incident_id, 'RCA', user_id, files)

            conn.commit()
            flash("RCA submitted for approval.", "success")
        except Exception as e:
            conn.rollback()
            logger.error("Error submitting RCA: %s", e)
            flash("An error occurred.", "danger")
        finally:
            conn.close()

        return redirect(url_for("incidents.incident_detail", incident_id=incident_id))

    return render_template("incidents/rca.html", inc=inc, existing=existing, media=media, user=user,
        status_colors=STATUS_COLORS, priority_colors=PRIORITY_COLORS)


@incidents_bp.route("/<int:incident_id>/review-rca", methods=["POST"])
def review_rca(incident_id):
    if not is_logged_in():
        return jsonify({"error": "Not authenticated"}), 401
    user_id = session.get("user_id")
    user = get_user_by_id(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 401

    if not (user.get("is_super_admin") or user.get("role") == "super_admin" or
            has_permission(user_id, "incidents.review_assign")):
        return jsonify({"error": "Permission denied"}), 403

    action = request.form.get("action", "")
    comments = request.form.get("comments", "").strip()
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(f"SELECT {INCIDENT_COLUMNS} FROM incidents WHERE id = %s", (incident_id,))
        row = cursor.fetchone()
        if not row:
            return jsonify({"error": "Incident not found"}), 404
        inc = _get_incident_summary(cursor, row)

        if inc['status'] != 'WAITING_FOR_RCA_APPROVAL':
            return jsonify({"error": "Incident is not pending RCA approval"}), 400

        if action == "approve":
            new_status = "RCA_APPROVED"
            cursor.execute("UPDATE incidents SET status = %s, updated_at = %s WHERE id = %s", (new_status, _now(), incident_id))
            _log_audit(cursor, incident_id, 'Root Cause Analysis', user_id, 'RCA Approved', inc['status'], new_status)
        elif action == "reject":
            new_status = "CLOSED"
            cursor.execute("UPDATE incidents SET status = %s, updated_at = %s WHERE id = %s", (new_status, _now(), incident_id))
            _log_audit(cursor, incident_id, 'Root Cause Analysis', user_id, 'RCA Rejected – Incident Closed',
                       inc['status'], new_status)
        else:
            return jsonify({"error": "Invalid action"}), 400

        conn.commit()
        return jsonify({"success": True, "message": f"RCA {'approved' if action == 'approve' else 'rejected'}."})
    except Exception as e:
        conn.rollback()
        logger.error("Error: %s", e)
        return jsonify({"error": "An error occurred."}), 500
    finally:
        conn.close()


# ─── STEP 5: CORRECTIVE ACTION (Technician) ─────────────────
@incidents_bp.route("/<int:incident_id>/corrective-action", methods=["GET", "POST"])
def corrective_action(incident_id):
    if not is_logged_in():
        return redirect(url_for("login"))
    user_id = session.get("user_id")
    user = get_user_by_id(user_id)
    if not user:
        return redirect(url_for("login"))

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(f"SELECT {INCIDENT_COLUMNS} FROM incidents WHERE id = %s", (incident_id,))
        row = cursor.fetchone()
        if not row:
            flash("Incident not found.", "danger")
            return redirect(url_for("incidents.incident_history"))

        inc = _get_incident_summary(cursor, row)

        can_ca = (user.get("is_super_admin") or user.get("role") == "super_admin" or
                  has_permission(user_id, "incidents.corrective_action"))
        is_assigned_tech = inc['assigned_technician_id'] == user_id
        can_override = (user.get("is_super_admin") or user.get("role") == "super_admin" or
                       has_permission(user_id, "incidents.override_edit"))

        if not (can_ca and (is_assigned_tech or can_override)):
            flash("You do not have permission to perform corrective actions.", "danger")
            return redirect(url_for("incidents.incident_detail", incident_id=incident_id))

        if inc['status'] not in ('RCA_APPROVED', 'WAITING_FOR_VERIFICATION'):
            flash("RCA must be approved before performing corrective actions.", "danger")
            return redirect(url_for("incidents.incident_detail", incident_id=incident_id))

        cursor.execute("SELECT repair_actions, parts_replaced, materials_used, labour_hours, actual_cost, completion_time, comments FROM incident_corrective_actions WHERE incident_id = %s ORDER BY created_at DESC LIMIT 1", (incident_id,))
        ca_row = cursor.fetchone()
        existing = {'repair_actions': ca_row['repair_actions'], 'parts_replaced': ca_row['parts_replaced'], 'materials_used': ca_row['materials_used'], 'labour_hours': ca_row['labour_hours'], 'actual_cost': ca_row['actual_cost'], 'completion_time': ca_row['completion_time'], 'comments': ca_row['comments']} if ca_row else None

        media = _get_media_files(cursor, incident_id, 'Corrective Action')
    finally:
        conn.close()

    if request.method == "POST":
        repair_actions = request.form.get("repair_actions", "").strip()
        parts_replaced = request.form.get("parts_replaced", "").strip()
        materials_used = request.form.get("materials_used", "").strip()
        labour_hours = request.form.get("labour_hours")
        actual_cost = request.form.get("actual_cost")
        completion_time = request.form.get("completion_time", "").strip()
        comments = request.form.get("comments", "").strip()

        if not repair_actions:
            flash("Please provide repair actions.", "danger")
            return render_template("incidents/corrective_action.html", inc=inc, existing=existing, media=media, user=user,
                status_colors=STATUS_COLORS, priority_colors=PRIORITY_COLORS)

        conn = get_db()
        try:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM incident_corrective_actions WHERE incident_id = %s", (incident_id,))
            cursor.execute("""
                INSERT INTO incident_corrective_actions (incident_id, repair_actions, parts_replaced, materials_used, labour_hours, actual_cost, completion_time, comments, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (incident_id, repair_actions, parts_replaced, materials_used,
                  float(labour_hours) if labour_hours else None,
                  float(actual_cost) if actual_cost else None,
                  completion_time, comments, _now()))

            cursor.execute("UPDATE incidents SET actual_repair_cost = %s, labour_hours = %s, completion_time = %s, status = 'WAITING_FOR_VERIFICATION', updated_at = %s WHERE id = %s",
                (float(actual_cost) if actual_cost else None,
                 float(labour_hours) if labour_hours else None,
                 completion_time, _now(), incident_id))
            _log_audit(cursor, incident_id, 'Corrective Action', user_id, 'Corrective Action Submitted',
                       inc['status'], 'WAITING_FOR_VERIFICATION')

            files = request.files.getlist("photos")
            _save_media(cursor, incident_id, 'Corrective Action', user_id, files)

            conn.commit()
            flash("Corrective action submitted for verification.", "success")
        except Exception as e:
            conn.rollback()
            logger.error("Error submitting corrective action: %s", e)
            flash("An error occurred.", "danger")
        finally:
            conn.close()

        return redirect(url_for("incidents.incident_detail", incident_id=incident_id))

    return render_template("incidents/corrective_action.html", inc=inc, existing=existing, media=media, user=user,
        status_colors=STATUS_COLORS, priority_colors=PRIORITY_COLORS)


# ─── STEP 5b: VERIFICATION (Manager) ───────────────────────
@incidents_bp.route("/<int:incident_id>/verify", methods=["POST"])
def verify_corrective_action(incident_id):
    if not is_logged_in():
        return jsonify({"error": "Not authenticated"}), 401
    user_id = session.get("user_id")
    user = get_user_by_id(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 401

    if not (user.get("is_super_admin") or user.get("role") == "super_admin" or
            has_permission(user_id, "incidents.verify_close")):
        return jsonify({"error": "Permission denied"}), 403

    result = request.form.get("result", "")
    comments = request.form.get("comments", "").strip()

    if result not in ('Passed', 'Failed'):
        return jsonify({"error": "Invalid verification result"}), 400

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(f"SELECT {INCIDENT_COLUMNS} FROM incidents WHERE id = %s", (incident_id,))
        row = cursor.fetchone()
        if not row:
            return jsonify({"error": "Incident not found"}), 404
        inc = _get_incident_summary(cursor, row)

        if inc['status'] != 'WAITING_FOR_VERIFICATION':
            return jsonify({"error": "Incident is not pending verification"}), 400

        cursor.execute("""
            INSERT INTO incident_verifications (incident_id, result, verified_by_id, comments, created_at)
            VALUES (%s, %s, %s, %s, %s)
        """, (incident_id, result, user_id, comments, _now()))

        if result == "Passed":
            cursor.execute("UPDATE incidents SET status = 'CLOSED', updated_at = %s WHERE id = %s", (_now(), incident_id))
            _log_audit(cursor, incident_id, 'Verification', user_id, 'Verification Passed - Incident Closed',
                       inc['status'], 'CLOSED')
        else:
            cursor.execute("UPDATE incidents SET status = 'RCA_APPROVED', updated_at = %s WHERE id = %s", (_now(), incident_id))
            _log_audit(cursor, incident_id, 'Verification', user_id, 'Verification Failed - Returned to Technician',
                       inc['status'], comments or None)

        conn.commit()
        return jsonify({"success": True, "message": f"Verification {result.lower()}."})
    except Exception as e:
        conn.rollback()
        logger.error("Error: %s", e)
        return jsonify({"error": "An error occurred."}), 500
    finally:
        conn.close()


# ─── STEP 6: CLOSURE (Manager) ─────────────────────────────
@incidents_bp.route("/<int:incident_id>/closure", methods=["GET", "POST"])
def closure(incident_id):
    if not is_logged_in():
        return redirect(url_for("login"))
    user_id = session.get("user_id")
    user = get_user_by_id(user_id)
    if not user:
        return redirect(url_for("login"))

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(f"SELECT {INCIDENT_COLUMNS} FROM incidents WHERE id = %s", (incident_id,))
        row = cursor.fetchone()
        if not row:
            flash("Incident not found.", "danger")
            return redirect(url_for("incidents.incident_history"))

        inc = _get_incident_summary(cursor, row)

        can_close = (user.get("is_super_admin") or user.get("role") == "super_admin" or
                     has_permission(user_id, "incidents.verify_close"))
        is_dept_head = (user.get("role") == "department_head" and user.get("department_id") == inc['department_id'])

        if not (can_close or is_dept_head):
            flash("You do not have permission to close this incident.", "danger")
            return redirect(url_for("incidents.incident_detail", incident_id=incident_id))

        if inc['status'] != 'CLOSED':
            flash("Incident must be in CLOSED status to access closure details.", "danger")
            return redirect(url_for("incidents.incident_detail", incident_id=incident_id))

        audit_logs = _get_audit_logs(cursor, incident_id)

        cursor.execute("SELECT resolution_summary, final_root_cause, total_repair_cost, preventive_action_required, preventive_recommendations FROM incident_closures WHERE incident_id = %s ORDER BY created_at DESC LIMIT 1", (incident_id,))
        clo_row = cursor.fetchone()
        existing = {'resolution_summary': clo_row['resolution_summary'], 'final_root_cause': clo_row['final_root_cause'], 'total_repair_cost': clo_row['total_repair_cost'], 'preventive_action_required': clo_row['preventive_action_required'], 'preventive_recommendations': clo_row['preventive_recommendations']} if clo_row else None

        if not existing:
            cursor.execute("SELECT actual_repair_cost FROM incident_corrective_actions WHERE incident_id = %s ORDER BY created_at DESC LIMIT 1", (incident_id,))
            ca_row = cursor.fetchone()
            suggested_cost = ca_row['actual_repair_cost'] if ca_row else None
        else:
            suggested_cost = existing.get('total_repair_cost')

    finally:
        conn.close()

    if request.method == "POST":
        resolution_summary = request.form.get("resolution_summary", "").strip()
        final_root_cause = request.form.get("final_root_cause", "").strip()
        total_repair_cost = request.form.get("total_repair_cost")
        preventive_action_required = 1 if request.form.get("preventive_action_required") else 0
        preventive_recommendations = request.form.get("preventive_recommendations", "").strip()

        if not resolution_summary:
            flash("Please provide a resolution summary.", "danger")
            return redirect(url_for("incidents.closure", incident_id=incident_id))

        conn = get_db()
        try:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM incident_closures WHERE incident_id = %s", (incident_id,))
            cursor.execute("""
                INSERT INTO incident_closures (incident_id, resolution_summary, final_root_cause, total_repair_cost, preventive_action_required, preventive_recommendations, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (incident_id, resolution_summary, final_root_cause,
                  float(total_repair_cost) if total_repair_cost else None,
                  preventive_action_required, preventive_recommendations, _now()))

            _log_audit(cursor, incident_id, 'Closure', user_id, 'Incident Closure Recorded',
                       None, f"Summary: {resolution_summary[:100]}")

            conn.commit()
            flash("Closure details saved successfully.", "success")
        except Exception as e:
            conn.rollback()
            logger.error("Error saving closure: %s", e)
            flash("An error occurred.", "danger")
        finally:
            conn.close()

        return redirect(url_for("incidents.incident_detail", incident_id=incident_id))

    return render_template("incidents/closure.html", inc=inc, existing=existing,
        audit_logs=audit_logs, suggested_cost=suggested_cost, user=user,
        status_colors=STATUS_COLORS, priority_colors=PRIORITY_COLORS)


# ─── MY ASSIGNED INCIDENTS ───────────────────────────────────
@incidents_bp.route("/my-incidents")
def my_assigned_incidents():
    if not is_logged_in():
        return redirect(url_for("login"))
    user_id = session.get("user_id")
    user = get_user_by_id(user_id)
    if not user:
        return redirect(url_for("login"))

    conn = get_db()
    try:
        cursor = conn.cursor()

        query = f"SELECT {INCIDENT_COLUMNS} FROM incidents WHERE (assigned_technician_id = %s OR assigned_manager_id = %s OR reported_by_id = %s)"
        params = [user_id, user_id, user_id]

        status_filter = request.args.get("status", "")
        if status_filter:
            query += " AND status = %s"
            params.append(status_filter)

        query += " ORDER BY updated_at DESC"
        cursor.execute(query, params)

        incidents = []
        for row in cursor.fetchall():
            inc = _get_incident_summary(cursor, row)
            inc['reporter_name'] = _get_user_name(cursor, inc['reported_by_id'])
            inc['manager_name'] = _get_user_name(cursor, inc['assigned_manager_id'])
            inc['technician_name'] = _get_user_name(cursor, inc['assigned_technician_id'])
            inc['dept_name'] = _get_dept_name(cursor, inc['department_id'])
            incidents.append(inc)

    finally:
        conn.close()

    return render_template("incidents/my_incidents.html",
        incidents=incidents, user=user, status_filter=status_filter,
        status_colors=STATUS_COLORS, status_labels=STATUS_LABELS,
        priority_colors=PRIORITY_COLORS)


# ─── HISTORY PAGE ───────────────────────────────────────────
@incidents_bp.route("/history")
def incident_history():
    if not is_logged_in():
        return redirect(url_for("login"))
    user_id = session.get("user_id")
    user = get_user_by_id(user_id)
    if not user:
        return redirect(url_for("login"))

    conn = get_db()
    try:
        cursor = conn.cursor()

        date_from = request.args.get("date_from", "")
        date_to = request.args.get("date_to", "")
        dept_filter = request.args.get("department", "")
        status_filter = request.args.get("status", "")
        manager_filter = request.args.get("manager", "")
        tech_filter = request.args.get("technician", "")

        query = f"SELECT {INCIDENT_COLUMNS} FROM incidents WHERE 1=1"
        params = []

        role = user.get("role", "")
        is_super = user.get("is_super_admin") or role == "super_admin"
        user_dept = user.get("department_id")

        if not is_super:
            if role == "employee":
                query += " AND reported_by_id = %s"
                params.append(user_id)
            elif role in ("department_head", "manager") and user_dept:
                query += " AND department_id = %s"
                params.append(user_dept)
            elif role == "technician":
                query += " AND assigned_technician_id = %s"
                params.append(user_id)

        if date_from:
            query += " AND incident_date >= %s"
            params.append(date_from)
        if date_to:
            query += " AND incident_date <= %s"
            params.append(date_to)
        if dept_filter:
            query += " AND department_id = %s"
            params.append(int(dept_filter))
        if status_filter:
            query += " AND status = %s"
            params.append(status_filter)
        if manager_filter:
            query += " AND assigned_manager_id = %s"
            params.append(int(manager_filter))
        if tech_filter:
            query += " AND assigned_technician_id = %s"
            params.append(int(tech_filter))

        query += " ORDER BY created_at DESC"
        cursor.execute(query, params)

        incidents = []
        for row in cursor.fetchall():
            inc = _get_incident_summary(cursor, row)
            inc['reporter_name'] = _get_user_name(cursor, inc['reported_by_id'])
            inc['manager_name'] = _get_user_name(cursor, inc['assigned_manager_id'])
            inc['technician_name'] = _get_user_name(cursor, inc['assigned_technician_id'])
            inc['dept_name'] = _get_dept_name(cursor, inc['department_id'])
            incidents.append(inc)

        cursor.execute("SELECT id, name FROM departments ORDER BY name")
        departments = [{'id': r['id'], 'name': r['name']} for r in cursor.fetchall()]

        cursor.execute("SELECT id, first_name, last_name FROM users WHERE role IN ('manager', 'department_head') AND account_status = 'active' ORDER BY first_name")
        managers = [{'id': r['id'], 'name': f"{r['first_name']} {r['last_name']}"} for r in cursor.fetchall()]

        cursor.execute("SELECT id, first_name, last_name FROM users WHERE role = 'technician' AND account_status = 'active' ORDER BY first_name")
        technicians = [{'id': r['id'], 'name': f"{r['first_name']} {r['last_name']}"} for r in cursor.fetchall()]

    finally:
        conn.close()

    return render_template("incidents/history.html",
        incidents=incidents, departments=departments, managers=managers, technicians=technicians,
        user=user, status_colors=STATUS_COLORS, status_labels=STATUS_LABELS,
        priority_colors=PRIORITY_COLORS,
        filters={'date_from': date_from, 'date_to': date_to, 'department': dept_filter,
                 'status': status_filter, 'manager': manager_filter, 'technician': tech_filter})


# ─── REPORTS / ANALYTICS ────────────────────────────────────
@incidents_bp.route("/reports")
def incident_reports():
    if not is_logged_in():
        return redirect(url_for("login"))
    user_id = session.get("user_id")
    user = get_user_by_id(user_id)
    if not user:
        return redirect(url_for("login"))

    can_view = (user.get("is_super_admin") or user.get("role") == "super_admin" or
                has_permission(user_id, "incidents.reports"))
    if not can_view:
        flash("You do not have permission to view incident reports.", "danger")
        return redirect(url_for("incidents.incident_history"))

    conn = get_db()
    try:
        cursor = conn.cursor()

        date_from = request.args.get("date_from", "")
        date_to = request.args.get("date_to", "")
        dept_filter = request.args.get("department", "")

        base_where = "1=1"
        params = []
        if date_from:
            base_where += " AND incident_date >= %s"
            params.append(date_from)
        if date_to:
            base_where += " AND incident_date <= %s"
            params.append(date_to)
        if dept_filter:
            base_where += " AND department_id = %s"
            params.append(int(dept_filter))

        cursor.execute(f"SELECT COUNT(*) AS count FROM incidents WHERE {base_where}", params)
        total_incidents = cursor.fetchone()['count']

        cursor.execute(f"""
            SELECT d.name, COUNT(*) AS count FROM incidents i
            JOIN departments d ON i.department_id = d.id
            WHERE {base_where}
            GROUP BY d.name ORDER BY COUNT(*) DESC
        """, params)
        dept_breakdown = [{'name': r['name'] or 'Unassigned', 'count': r['count']} for r in cursor.fetchall()]

        cursor.execute(f"""
            SELECT status, COUNT(*) AS count FROM incidents WHERE {base_where}
            GROUP BY status ORDER BY COUNT(*) DESC
        """, params)
        status_counts = {r['status']: r['count'] for r in cursor.fetchall()}

        open_count = sum(status_counts.get(s, 0) for s in ACTIVE_STATUSES)
        closed_count = status_counts.get('CLOSED', 0)

        cursor.execute(f"""
            SELECT AVG(EXTRACT(EPOCH FROM (completion_time::timestamp - incident_date::timestamp)) / 86400)
            FROM incidents
            WHERE {base_where} AND completion_time IS NOT NULL AND incident_date IS NOT NULL
        """, params)
        avg_resolution = cursor.fetchone()['avg']

        cursor.execute(f"""
            SELECT u.first_name || ' ' || u.last_name AS name, COUNT(*) AS cnt
            FROM incidents i
            JOIN users u ON i.assigned_manager_id = u.id
            WHERE {base_where} AND i.assigned_manager_id IS NOT NULL
            GROUP BY i.assigned_manager_id, u.first_name, u.last_name ORDER BY cnt DESC
        """, params)
        manager_workload = [{'name': r['name'], 'count': r['cnt']} for r in cursor.fetchall()]

        cursor.execute(f"""
            SELECT u.first_name || ' ' || u.last_name AS name, COUNT(*) AS cnt
            FROM incidents i
            JOIN users u ON i.assigned_technician_id = u.id
            WHERE {base_where} AND i.assigned_technician_id IS NOT NULL
            GROUP BY i.assigned_technician_id, u.first_name, u.last_name ORDER BY cnt DESC
        """, params)
        tech_performance = [{'name': r['name'], 'count': r['cnt']} for r in cursor.fetchall()]

        cursor.execute(f"""
            SELECT AVG(actual_repair_cost) AS avg FROM incidents
            WHERE {base_where} AND actual_repair_cost IS NOT NULL
        """, params)
        avg_repair_cost = cursor.fetchone()['avg']

        cursor.execute(f"""
            SELECT SUM(actual_repair_cost) AS total FROM incidents
            WHERE {base_where} AND actual_repair_cost IS NOT NULL
        """, params)
        total_repair_cost = cursor.fetchone()['total']

        cursor.execute(f"""
            SELECT priority, COUNT(*) AS count FROM incidents WHERE {base_where}
            GROUP BY priority
        """, params)
        priority_counts = {r['priority']: r['count'] for r in cursor.fetchall()}

        cursor.execute(f"""
            SELECT severity, COUNT(*) AS count FROM incidents WHERE {base_where}
            GROUP BY severity
        """, params)
        severity_counts = {r['severity']: r['count'] for r in cursor.fetchall()}

        cursor.execute("SELECT id, name FROM departments ORDER BY name")
        departments = [{'id': r['id'], 'name': r['name']} for r in cursor.fetchall()]

    finally:
        conn.close()

    return render_template("incidents/reports.html",
        user=user, total_incidents=total_incidents, dept_breakdown=dept_breakdown,
        status_counts=status_counts, open_count=open_count, closed_count=closed_count,
        avg_resolution=avg_resolution, manager_workload=manager_workload,
        tech_performance=tech_performance, avg_repair_cost=avg_repair_cost,
        total_repair_cost=total_repair_cost, priority_counts=priority_counts,
        severity_counts=severity_counts, departments=departments,
        status_colors=STATUS_COLORS, status_labels=STATUS_LABELS,
        priority_colors=PRIORITY_COLORS,
        filters={'date_from': date_from, 'date_to': date_to, 'department': dept_filter})


# ─── API: INCIDENT DETAIL JSON ──────────────────────────────
@incidents_bp.route("/<int:incident_id>/detail")
def incident_detail_json(incident_id):
    if not is_logged_in():
        return jsonify({"error": "Not authenticated"}), 401

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(f"SELECT {INCIDENT_COLUMNS} FROM incidents WHERE id = %s", (incident_id,))
        row = cursor.fetchone()
        if not row:
            return jsonify({"error": "Not found"}), 404

        inc = _get_incident_summary(cursor, row)
        inc['reporter_name'] = _get_user_name(cursor, inc['reported_by_id'])
        inc['manager_name'] = _get_user_name(cursor, inc['assigned_manager_id'])
        inc['technician_name'] = _get_user_name(cursor, inc['assigned_technician_id'])
        inc['dept_name'] = _get_dept_name(cursor, inc['department_id'])
        inc['audit_logs'] = _get_audit_logs(cursor, incident_id)

        for key, val in inc.items():
            if val is None:
                inc[key] = None

        return jsonify(inc)
    finally:
        conn.close()
