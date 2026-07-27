from flask import request, jsonify, render_template, redirect, url_for, session, flash, g
from datetime import datetime
from zoneinfo import ZoneInfo
import logging
import psycopg2
import psycopg2.extras
import psycopg2.errors

from auth.database import get_db as _get_pg_db, dict_cursor

from . import tickets_bp
from auth.local_auth import get_user_by_id
from auth.email_service import send_email

logger = logging.getLogger("eam.tickets")

VALID_STATUSES = ['raised', 'assigned', 'in_progress', 'resolved', 'verified', 'garbage']

STATUS_COLORS = {
    'raised': '#5c6bc0',
    'assigned': '#f57c00',
    'in_progress': '#00897b',
    'resolved': '#2e7d32',
    'verified': '#616161',
    'garbage': '#c62828',
}

STATUS_LABELS = {
    'raised': 'Raised',
    'assigned': 'Assigned',
    'in_progress': 'In Progress',
    'resolved': 'Resolved',
    'verified': 'Verified',
    'garbage': 'Unrepairable',
}


def get_db():
    return _get_pg_db()


def is_logged_in():
    from flask import session
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


# ─── HELPER: log status change ───────────────────────────────

def log_status_change(cursor, ticket_id, status, changed_by=None):
    now = datetime.now(ZoneInfo("Asia/Kolkata")).isoformat()
    cursor.execute("""
        INSERT INTO ticket_status_history (ticket_id, status, changed_by, changed_at)
        VALUES (%s, %s, %s, %s)
    """, (ticket_id, status, changed_by, now))


def get_ticket_status_date(cursor, ticket_id, status):
    cursor.execute("""
        SELECT changed_at FROM ticket_status_history
        WHERE ticket_id = %s AND status = %s
        ORDER BY changed_at DESC LIMIT 1
    """, (ticket_id, status))
    row = cursor.fetchone()
    return row['changed_at'] if row else None


def get_previous_status(cursor, ticket_id):
    cursor.execute("""
        SELECT status FROM ticket_status_history
        WHERE ticket_id = %s
        ORDER BY changed_at DESC LIMIT 1 OFFSET 1
    """, (ticket_id,))
    row = cursor.fetchone()
    return row['status'] if row else None


# ─── HELPER: email notifications ─────────────────────────────

def _send_single_email(subject, recipient_email, body):
    try:
        send_email(subject, [recipient_email], body)
    except Exception as e:
        logger.error("Failed to send email to %s: %s", recipient_email, e, exc_info=True)


def send_ticket_notification(cursor, ticket_id, new_status, triggered_by_user_id):
    cursor.execute("""
        SELECT t.title, t.description, t.created_by_user_id, t.assigned_to_user_id,
               t.department_id, t.asset_id, t.created_at,
               u.first_name AS raiser_first, u.last_name AS raiser_last, u.email AS raiser_email
        FROM tickets t
        JOIN users u ON t.created_by_user_id = u.id
        WHERE t.id = %s
    """, (ticket_id,))
    ticket = cursor.fetchone()
    if not ticket:
        return

    title = ticket['title']
    raiser_id = ticket['created_by_user_id']
    assigned_id = ticket['assigned_to_user_id']
    dept_id = ticket['department_id']
    asset_id = ticket['asset_id']
    raiser_name = f"{ticket['raiser_first']} {ticket['raiser_last']}"
    raiser_email = ticket['raiser_email']

    asset_label = "N/A"
    if asset_id:
        cursor.execute("""
            SELECT a.asset_id, a.name FROM assets a WHERE a.id = %s
        """, (asset_id,))
        a_row = cursor.fetchone()
        if a_row:
            asset_label = f"{a_row['asset_id']} - {a_row['name']}"

    dept_name = "N/A"
    if dept_id:
        cursor.execute("SELECT name FROM departments WHERE id = %s", (dept_id,))
        d_row = cursor.fetchone()
        if d_row:
            dept_name = d_row['name']

    ticket_url = url_for("tickets.ticket_history", _external=True)

    if new_status == 'raised':
        _send_single_email(
            "[Service Desk] Your Ticket Has Been Raised",
            raiser_email,
            f"Hello {raiser_name},\n\n"
            f"Your issue has been successfully raised.\n\n"
            f"Ticket #{ticket_id}: {title}\n"
            f"Department: {dept_name}\n"
            f"Asset: {asset_label}\n\n"
            f"You can track your ticket at: {ticket_url}\n\n"
            f"Best regards,\nEAM Service Desk"
        )

        cursor.execute("""
            SELECT u.email, u.first_name FROM users u
            JOIN role_permissions rp ON u.role_id = rp.role_id
            JOIN permissions p ON rp.permission_id = p.id
            WHERE p.code = 'tickets.assign_technician'
            AND u.account_status = 'active'
        """)
        assigners = cursor.fetchall()
        for assigner in assigners:
            _send_single_email(
                "[Service Desk] New Ticket Requires Technician Assignment",
                assigner['email'],
                f"Hello {assigner['first_name']},\n\n"
                f"A new ticket requires technician assignment.\n\n"
                f"Ticket #{ticket_id}: {title}\n"
                f"Department: {dept_name}\n"
                f"Asset: {asset_label}\n\n"
                f"Raised by: {raiser_name}\n"
                f"Please assign a technician from the Assign Requests portal.\n\n"
                f"Best regards,\nEAM Service Desk"
            )

    elif new_status == 'assigned' and assigned_id:
        tech = get_user_by_id(assigned_id)
        if tech:
            _send_single_email(
                "[Service Desk] You Have Been Assigned a Support Request",
                tech["email"],
                f"Hello {tech['first_name']},\n\n"
                f"You have been assigned to a new support request. Please accept or reject the job profile.\n\n"
                f"Ticket #{ticket_id}: {title}\n"
                f"Department: {dept_name}\n"
                f"Asset: {asset_label}\n"
                f"Raised by: {raiser_name}\n\n"
                f"Best regards,\nEAM Service Desk"
            )

    elif new_status == 'raised_rejected':
        cursor.execute("""
            SELECT changed_by FROM ticket_status_history
            WHERE ticket_id = %s AND status = 'assigned'
            ORDER BY changed_at DESC LIMIT 1
        """, (ticket_id,))
        disp_row = cursor.fetchone()
        if disp_row and disp_row['changed_by']:
            dispatcher = get_user_by_id(disp_row['changed_by'])
            if dispatcher:
                _send_single_email(
                    "[Service Desk] Technician Rejected Assignment",
                    dispatcher["email"],
                    f"Hello {dispatcher['first_name']},\n\n"
                    f"The technician has rejected the assignment for Ticket #{ticket_id}. "
                    f"The ticket has been returned to the queue.\n\n"
                    f"Ticket: {title}\n"
                    f"Please re-assign from the allocation portal.\n\n"
                    f"Best regards,\nEAM Service Desk"
                )

    elif new_status == 'assigned_accepted':
        cursor.execute("""
            SELECT changed_by FROM ticket_status_history
            WHERE ticket_id = %s AND status = 'assigned'
            ORDER BY changed_at DESC LIMIT 1 OFFSET 1
        """, (ticket_id,))
        disp_row = cursor.fetchone()
        if disp_row and disp_row['changed_by']:
            dispatcher = get_user_by_id(disp_row['changed_by'])
            if dispatcher:
                _send_single_email(
                    "[Service Desk] Technician Accepted the Task",
                    dispatcher["email"],
                    f"Hello {dispatcher['first_name']},\n\n"
                    f"The assigned technician has accepted the task for Ticket #{ticket_id}.\n\n"
                    f"Ticket: {title}\n\n"
                    f"Best regards,\nEAM Service Desk"
                )

        _send_single_email(
            "[Service Desk] Technician Accepted Your Request",
            raiser_email,
            f"Hello {raiser_name},\n\n"
            f"The assigned technician has accepted the task.\n\n"
            f"Ticket #{ticket_id}: {title}\n"
            f"Asset: {asset_label}\n\n"
            f"Best regards,\nEAM Service Desk"
        )

    elif new_status == 'in_progress':
        _send_single_email(
            "[Service Desk] Your Asset Is Being Serviced",
            raiser_email,
            f"Hello {raiser_name},\n\n"
            f"The technician has officially updated your asset status to In Progress and begun servicing.\n\n"
            f"Ticket #{ticket_id}: {title}\n"
            f"Asset: {asset_label}\n\n"
            f"Best regards,\nEAM Service Desk"
        )

    elif new_status == 'resolved':
        _send_single_email(
            "[Service Desk] Your Asset Has Been Serviced",
            raiser_email,
            f"Hello {raiser_name},\n\n"
            f"Your asset has been serviced. Please test your device and verify the resolution via your Service Desk History tab.\n\n"
            f"Ticket #{ticket_id}: {title}\n"
            f"Asset: {asset_label}\n\n"
            f"Best regards,\nEAM Service Desk"
        )

    elif new_status == 'garbage':
        _send_single_email(
            "[Service Desk] Asset Declared Unrepairable",
            raiser_email,
            f"Hello {raiser_name},\n\n"
            f"Your device is not usable anymore as the asset is no longer repairable.\n\n"
            f"Ticket #{ticket_id}: {title}\n"
            f"Asset: {asset_label}\n\n"
            f"Please contact your administrator for a replacement.\n\n"
            f"Best regards,\nEAM Service Desk"
        )

    elif new_status == 'verified':
        if assigned_id:
            tech = get_user_by_id(assigned_id)
            if tech:
                _send_single_email(
                    "[Service Desk] Ticket Verified and Closed",
                    tech["email"],
                    f"Hello {tech['first_name']},\n\n"
                    f"The user has verified the service. Ticket closed successfully.\n\n"
                    f"Ticket #{ticket_id}: {title}\n"
                    f"Asset: {asset_label}\n\n"
                    f"Best regards,\nEAM Service Desk"
                )


# ─── HELPER: get full ticket details ─────────────────────────

def get_ticket_full(cursor, ticket_id):
    cursor.execute("""
        SELECT t.id, t.ticket_type, t.department_id, t.title, t.description,
               t.asset_id, t.created_by_user_id, t.assigned_to_user_id,
               t.status, t.created_at,
               d.name AS dept_name,
               a.asset_id AS asset_code, a.name AS asset_name, a.serial_number,
               u.first_name AS raiser_first, u.last_name AS raiser_last, u.email AS raiser_email,
               u.company_id AS raiser_company_id, u.department_id AS raiser_dept_id
        FROM tickets t
        LEFT JOIN departments d ON t.department_id = d.id
        LEFT JOIN assets a ON t.asset_id = a.id
        LEFT JOIN users u ON t.created_by_user_id = u.id
        WHERE t.id = %s
    """, (ticket_id,))
    row = cursor.fetchone()
    if not row:
        return None

    tech_name = None
    tech_email = None
    if row['assigned_to_user_id']:
        tech = get_user_by_id(row['assigned_to_user_id'])
        if tech:
            tech_name = f"{tech['first_name']} {tech['last_name']}"
            tech_email = tech.get("email", "")

    status_date = get_ticket_status_date(cursor, ticket_id, row['status'])

    return {
        "id": row['id'], "ticket_type": row['ticket_type'], "department_id": row['department_id'],
        "title": row['title'], "description": row['description'], "asset_id": row['asset_id'],
        "created_by_user_id": row['created_by_user_id'], "assigned_to_user_id": row['assigned_to_user_id'],
        "status": row['status'], "created_at": row['created_at'],
        "dept_name": row['dept_name'],
        "asset_code": row['asset_code'], "asset_name": row['asset_name'], "asset_serial": row['serial_number'],
        "raiser_name": f"{row['raiser_first']} {row['raiser_last']}", "raiser_email": row['raiser_email'],
        "raiser_company_id": row['raiser_company_id'],
        "tech_name": tech_name, "tech_email": tech_email,
        "status_date": status_date,
    }


# ─── ROUTE: Raise Ticket ─────────────────────────────────────

@tickets_bp.route("/new", methods=["GET", "POST"])
def new_ticket():
    if not is_logged_in():
        return redirect(url_for("login"))

    user_id = session.get("user_id")
    user = get_user_by_id(user_id)
    if not user:
        return redirect(url_for("logout"))

    conn = get_db()
    try:
        cursor = conn.cursor()

        cursor.execute("SELECT id, name FROM departments ORDER BY name")
        departments = cursor.fetchall()

        cursor.execute("""
            SELECT a.id, a.asset_id, a.name, a.serial_number, at.name as asset_type_name
            FROM assets a
            JOIN asset_types at ON a.asset_type_id = at.id
            WHERE a.assigned_to_user_id = %s
            ORDER BY a.name
        """, (user_id,))
        user_assets = cursor.fetchall()

        if request.method == "POST":
            ticket_type = request.form.get("ticket_type", "").strip()
            department_id = request.form.get("department_id", "").strip()
            title = request.form.get("title", "").strip()
            description = request.form.get("description", "").strip()
            asset_id = request.form.get("asset_id", "").strip() or None

            errors = []
            if not ticket_type:
                errors.append("Ticket type is required")
            if not department_id:
                errors.append("Department is required")
            if not title:
                errors.append("Title is required")
            if not description:
                errors.append("Description is required")

            if errors:
                for error in errors:
                    flash(error, "danger")
                return render_template(
                    "new_ticket.html",
                    departments=departments,
                    user_assets=user_assets,
                    form_data=request.form
                )

            created_at = datetime.now(ZoneInfo("Asia/Kolkata")).isoformat()
            cursor.execute("""
                INSERT INTO tickets (ticket_type, department_id, title, description, asset_id, created_by_user_id, status, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, 'raised', %s) RETURNING id
            """, (ticket_type, department_id, title, description, asset_id, user_id, created_at))
            ticket_id = cursor.fetchone()['id']

            log_status_change(cursor, ticket_id, 'raised', user_id)
            conn.commit()

            send_ticket_notification(cursor, ticket_id, 'raised', user_id)
            conn.commit()

            flash(f"Ticket #{ticket_id} created successfully", "success")
            return redirect(url_for("tickets.new_ticket"))

    except Exception as e:
        logger.error("Error creating ticket: %s", e, exc_info=True)
        flash("An error occurred while creating the ticket", "danger")
    finally:
        conn.close()

    return render_template(
        "new_ticket.html",
        departments=departments,
        user_assets=user_assets,
        form_data={}
    )


# ─── ROUTE: Reports (Admin/Manager/SuperAdmin) ──────────────

@tickets_bp.route("/reports")
def ticket_reports():
    if not is_logged_in():
        return redirect(url_for("login"))

    user_id = session.get("user_id")
    user = get_user_by_id(user_id)
    if not user:
        return redirect(url_for("logout"))

    is_super = user.get("is_super_admin") or user.get("role") == "super_admin"
    if not is_super and user.get("role") not in ('admin', 'manager'):
        if not has_permission(user_id, "tickets.review"):
            flash("Access denied.", "danger")
            return redirect(url_for("dashboard"))

    status_filter = request.args.getlist("status")
    date_from = request.args.get("date_from", "")
    date_to = request.args.get("date_to", "")

    conn = get_db()
    try:
        cursor = conn.cursor()

        query = """
            SELECT t.id, t.ticket_type, t.title, t.description, t.status, t.created_at,
                   t.created_by_user_id, t.assigned_to_user_id, t.department_id,
                   d.name AS dept_name,
                   a.asset_id AS asset_code, a.name AS asset_name,
                   u.first_name AS raiser_first, u.last_name AS raiser_last
            FROM tickets t
            LEFT JOIN departments d ON t.department_id = d.id
            LEFT JOIN assets a ON t.asset_id = a.id
            LEFT JOIN users u ON t.created_by_user_id = u.id
            WHERE 1=1
        """
        params = []

        if status_filter:
            placeholders = ",".join("%s" * len(status_filter))
            query += f" AND t.status IN ({placeholders})"
            params.extend(status_filter)

        if date_from:
            query += " AND t.created_at >= %s"
            params.append(date_from)
        if date_to:
            query += " AND t.created_at <= %s"
            params.append(date_to + "T23:59:59")

        query += " ORDER BY t.created_at DESC"
        cursor.execute(query, params)
        raw_tickets = cursor.fetchall()

        tickets = []
        for row in raw_tickets:
            t = {
                "id": row['id'], "ticket_type": row['ticket_type'], "title": row['title'],
                "description": row['description'], "status": row['status'], "created_at": row['created_at'],
                "created_by_user_id": row['created_by_user_id'], "assigned_to_user_id": row['assigned_to_user_id'],
                "dept_name": row['dept_name'], "asset_code": row['asset_code'], "asset_name": row['asset_name'],
                "raiser_name": f"{row['raiser_first']} {row['raiser_last']}" if row['raiser_first'] else "Unknown",
                "status_date": get_ticket_status_date(cursor, row['id'], row['status']),
            }
            if row['assigned_to_user_id']:
                tech = get_user_by_id(row['assigned_to_user_id'])
                t["tech_name"] = f"{tech['first_name']} {tech['last_name']}" if tech else "Unknown"
            else:
                t["tech_name"] = "Unassigned"
            tickets.append(t)

    finally:
        conn.close()

    return render_template(
        "ticket_reports.html",
        tickets=tickets,
        status_colors=STATUS_COLORS,
        status_labels=STATUS_LABELS,
        selected_statuses=status_filter,
        date_from=date_from,
        date_to=date_to,
    )


# ─── ROUTE: Requests (Technician ONLY) ───────────────────────

@tickets_bp.route("/requests")
def ticket_requests():
    if not is_logged_in():
        return redirect(url_for("login"))

    user_id = session.get("user_id")
    user = get_user_by_id(user_id)
    if not user:
        return redirect(url_for("logout"))

    is_super = user.get("is_super_admin") or user.get("role") == "super_admin"
    if is_super or user.get("role") != "technician":
        flash("Access denied.", "danger")
        return redirect(url_for("dashboard"))

    filter_type = request.args.get("filter", "all")

    conn = get_db()
    try:
        cursor = conn.cursor()

        query = """
            SELECT t.id, t.ticket_type, t.title, t.description, t.status, t.created_at,
                   t.created_by_user_id, t.assigned_to_user_id, t.department_id,
                   d.name AS dept_name,
                   a.asset_id AS asset_code, a.name AS asset_name, a.serial_number,
                   u.first_name AS raiser_first, u.last_name AS raiser_last
            FROM tickets t
            LEFT JOIN departments d ON t.department_id = d.id
            LEFT JOIN assets a ON t.asset_id = a.id
            LEFT JOIN users u ON t.created_by_user_id = u.id
            WHERE t.assigned_to_user_id = %s
        """
        params = [user_id]

        if filter_type == "accepted":
            query += " AND t.status IN ('assigned', 'in_progress', 'resolved')"
        elif filter_type == "rejected":
            query += """ AND t.id IN (
                SELECT h.ticket_id FROM ticket_status_history h
                WHERE h.changed_by = %s AND h.status = 'raised'
                AND h.id > (
                    SELECT MIN(h2.id) FROM ticket_status_history h2
                    WHERE h2.ticket_id = h.ticket_id
                )
            )"""
            params.append(user_id)
        elif filter_type == "closed_before_verify":
            query += " AND t.status = 'garbage'"
        elif filter_type == "verified":
            query += " AND t.status = 'verified'"

        query += " ORDER BY t.created_at DESC"
        cursor.execute(query, params)
        raw_tickets = cursor.fetchall()

        tickets = []
        for row in raw_tickets:
            t = {
                "id": row['id'], "ticket_type": row['ticket_type'], "title": row['title'],
                "description": row['description'], "status": row['status'], "created_at": row['created_at'],
                "created_by_user_id": row['created_by_user_id'], "assigned_to_user_id": row['assigned_to_user_id'],
                "dept_name": row['dept_name'], "asset_code": row['asset_code'], "asset_name": row['asset_name'],
                "asset_serial": row['serial_number'],
                "raiser_name": f"{row['raiser_first']} {row['raiser_last']}" if row['raiser_first'] else "Unknown",
                "status_date": get_ticket_status_date(cursor, row['id'], row['status']),
            }
            tickets.append(t)

    finally:
        conn.close()

    return render_template(
        "ticket_requests.html",
        tickets=tickets,
        status_colors=STATUS_COLORS,
        status_labels=STATUS_LABELS,
        current_filter=filter_type,
    )


# ─── ROUTE: Assign Requests (Manager/Admin) ─────────────────

@tickets_bp.route("/assign")
def ticket_assign():
    if not is_logged_in():
        return redirect(url_for("login"))

    user_id = session.get("user_id")
    user = get_user_by_id(user_id)
    if not user:
        return redirect(url_for("logout"))

    is_super = user.get("is_super_admin") or user.get("role") == "super_admin"
    if not is_super and not has_permission(user_id, "tickets.assign_technician"):
        flash("Access denied.", "danger")
        return redirect(url_for("dashboard"))

    conn = get_db()
    try:
        cursor = conn.cursor()

        cursor.execute("""
            SELECT t.id, t.ticket_type, t.title, t.description, t.status, t.created_at,
                   t.created_by_user_id, t.assigned_to_user_id, t.department_id,
                   d.name AS dept_name,
                   a.asset_id AS asset_code, a.name AS asset_name,
                   u.first_name AS raiser_first, u.last_name AS raiser_last
            FROM tickets t
            LEFT JOIN departments d ON t.department_id = d.id
            LEFT JOIN assets a ON t.asset_id = a.id
            LEFT JOIN users u ON t.created_by_user_id = u.id
            WHERE t.status = 'raised'
            ORDER BY t.created_at DESC
        """)
        raw_tickets = cursor.fetchall()

        tickets = []
        for row in raw_tickets:
            t = {
                "id": row['id'], "ticket_type": row['ticket_type'], "title": row['title'],
                "description": row['description'], "status": row['status'], "created_at": row['created_at'],
                "created_by_user_id": row['created_by_user_id'], "assigned_to_user_id": row['assigned_to_user_id'],
                "dept_name": row['dept_name'], "asset_code": row['asset_code'], "asset_name": row['asset_name'],
                "raiser_name": f"{row['raiser_first']} {row['raiser_last']}" if row['raiser_first'] else "Unknown",
                "status_date": get_ticket_status_date(cursor, row['id'], row['status']),
            }
            tickets.append(t)

        cursor.execute("""
            SELECT u.id, u.first_name, u.last_name, u.email
            FROM users u
            JOIN roles r ON u.role_id = r.id
            WHERE r.name = 'technician' AND u.account_status = 'active'
            ORDER BY u.first_name
        """)
        technicians = [{"id": r['id'], "name": f"{r['first_name']} {r['last_name']}", "email": r['email']} for r in cursor.fetchall()]

    finally:
        conn.close()

    return render_template(
        "ticket_assign.html",
        tickets=tickets,
        technicians=technicians,
        status_colors=STATUS_COLORS,
        status_labels=STATUS_LABELS,
    )


# ─── ROUTE: History (Employee) ──────────────────────────────

@tickets_bp.route("/history")
def ticket_history():
    if not is_logged_in():
        return redirect(url_for("login"))

    user_id = session.get("user_id")
    user = get_user_by_id(user_id)
    if not user:
        return redirect(url_for("logout"))

    conn = get_db()
    try:
        cursor = conn.cursor()

        cursor.execute("""
            SELECT t.id, t.ticket_type, t.title, t.description, t.status, t.created_at,
                   t.created_by_user_id, t.assigned_to_user_id, t.department_id,
                   d.name AS dept_name,
                   a.asset_id AS asset_code, a.name AS asset_name,
                   u.first_name AS raiser_first, u.last_name AS raiser_last
            FROM tickets t
            LEFT JOIN departments d ON t.department_id = d.id
            LEFT JOIN assets a ON t.asset_id = a.id
            LEFT JOIN users u ON t.created_by_user_id = u.id
            WHERE t.created_by_user_id = %s
            ORDER BY t.created_at DESC
        """, (user_id,))
        raw_tickets = cursor.fetchall()

        tickets = []
        for row in raw_tickets:
            t = {
                "id": row['id'], "ticket_type": row['ticket_type'], "title": row['title'],
                "description": row['description'], "status": row['status'], "created_at": row['created_at'],
                "created_by_user_id": row['created_by_user_id'], "assigned_to_user_id": row['assigned_to_user_id'],
                "dept_name": row['dept_name'], "asset_code": row['asset_code'], "asset_name": row['asset_name'],
                "raiser_name": f"{row['raiser_first']} {row['raiser_last']}" if row['raiser_first'] else "Unknown",
                "status_date": get_ticket_status_date(cursor, row['id'], row['status']),
            }
            if row['assigned_to_user_id']:
                tech = get_user_by_id(row['assigned_to_user_id'])
                t["tech_name"] = f"{tech['first_name']} {tech['last_name']}" if tech else "Unknown"
            else:
                t["tech_name"] = "Unassigned"
            tickets.append(t)

    finally:
        conn.close()

    return render_template(
        "ticket_history.html",
        tickets=tickets,
        status_colors=STATUS_COLORS,
        status_labels=STATUS_LABELS,
    )


# ─── ACTION: Assign Technician ──────────────────────────────

@tickets_bp.route("/<int:ticket_id>/assign", methods=["POST"])
def assign_technician(ticket_id):
    if not is_logged_in():
        return jsonify({"error": "Not logged in"}), 401

    user_id = session.get("user_id")
    is_super = False
    user = get_user_by_id(user_id)
    if user:
        is_super = user.get("is_super_admin") or user.get("role") == "super_admin"

    if not is_super and not has_permission(user_id, "tickets.assign_technician"):
        return jsonify({"error": "Access denied"}), 403

    tech_id = request.form.get("technician_id")
    if not tech_id:
        return jsonify({"error": "Technician is required"}), 400

    conn = get_db()
    try:
        cursor = conn.cursor()

        cursor.execute("SELECT id, status FROM tickets WHERE id = %s", (ticket_id,))
        ticket = cursor.fetchone()
        if not ticket:
            return jsonify({"error": "Ticket not found"}), 404
        if ticket['status'] != 'raised':
            return jsonify({"error": "Ticket is not in 'raised' status"}), 400

        tech = get_user_by_id(int(tech_id))
        if not tech or tech.get("role") != "technician":
            return jsonify({"error": "Invalid technician"}), 400

        cursor.execute("""
            UPDATE tickets SET assigned_to_user_id = %s, status = 'assigned'
            WHERE id = %s
        """, (tech_id, ticket_id))

        log_status_change(cursor, ticket_id, 'assigned', user_id)
        conn.commit()

        send_ticket_notification(cursor, ticket_id, 'assigned', user_id)
        conn.commit()

        return jsonify({"success": True, "message": "Technician assigned successfully"})
    except Exception as e:
        logger.error("Error assigning technician: %s", e, exc_info=True)
        return jsonify({"error": "An unexpected error occurred"}), 500
    finally:
        conn.close()


# ─── ACTION: Accept Ticket (Technician) ─────────────────────

@tickets_bp.route("/<int:ticket_id>/accept", methods=["POST"])
def accept_ticket(ticket_id):
    if not is_logged_in():
        return jsonify({"error": "Not logged in"}), 401

    user_id = session.get("user_id")
    user = get_user_by_id(user_id)
    if not user or user.get("role") != "technician":
        return jsonify({"error": "Only technicians can accept tickets"}), 403

    conn = get_db()
    try:
        cursor = conn.cursor()

        cursor.execute("SELECT id, status, assigned_to_user_id FROM tickets WHERE id = %s", (ticket_id,))
        ticket = cursor.fetchone()
        if not ticket:
            return jsonify({"error": "Ticket not found"}), 404
        if ticket['status'] != 'raised':
            return jsonify({"error": "Ticket is not available for acceptance"}), 400
        if ticket['assigned_to_user_id'] != user_id:
            return jsonify({"error": "This ticket is not assigned to you"}), 403

        cursor.execute("""
            UPDATE tickets SET status = 'assigned' WHERE id = %s
        """, (ticket_id,))

        log_status_change(cursor, ticket_id, 'assigned', user_id)
        conn.commit()

        send_ticket_notification(cursor, ticket_id, 'assigned_accepted', user_id)
        conn.commit()

        return jsonify({"success": True, "message": "Ticket accepted successfully"})
    except Exception as e:
        logger.error("Error accepting ticket: %s", e, exc_info=True)
        return jsonify({"error": "An unexpected error occurred"}), 500
    finally:
        conn.close()


# ─── ACTION: Reject Ticket (Technician) ─────────────────────

@tickets_bp.route("/<int:ticket_id>/reject", methods=["POST"])
def reject_ticket(ticket_id):
    if not is_logged_in():
        return jsonify({"error": "Not logged in"}), 401

    user_id = session.get("user_id")
    user = get_user_by_id(user_id)
    if not user or user.get("role") != "technician":
        return jsonify({"error": "Only technicians can reject tickets"}), 403

    conn = get_db()
    try:
        cursor = conn.cursor()

        cursor.execute("SELECT id, status, assigned_to_user_id FROM tickets WHERE id = %s", (ticket_id,))
        ticket = cursor.fetchone()
        if not ticket:
            return jsonify({"error": "Ticket not found"}), 404
        if ticket['status'] != 'raised':
            return jsonify({"error": "Ticket is not available for rejection"}), 400
        if ticket['assigned_to_user_id'] != user_id:
            return jsonify({"error": "This ticket is not assigned to you"}), 403

        cursor.execute("""
            UPDATE tickets SET assigned_to_user_id = NULL, status = 'raised'
            WHERE id = %s
        """, (ticket_id,))

        log_status_change(cursor, ticket_id, 'raised', user_id)
        conn.commit()

        send_ticket_notification(cursor, ticket_id, 'raised_rejected', user_id)
        conn.commit()

        return jsonify({"success": True, "message": "Ticket rejected and returned to queue"})
    except Exception as e:
        logger.error("Error rejecting ticket: %s", e, exc_info=True)
        return jsonify({"error": "An unexpected error occurred"}), 500
    finally:
        conn.close()


# ─── ACTION: Start In Progress ──────────────────────────────

@tickets_bp.route("/<int:ticket_id>/in-progress", methods=["POST"])
def start_progress(ticket_id):
    if not is_logged_in():
        return jsonify({"error": "Not logged in"}), 401

    user_id = session.get("user_id")
    user = get_user_by_id(user_id)
    if not user or user.get("role") != "technician":
        return jsonify({"error": "Only technicians can start progress"}), 403

    conn = get_db()
    try:
        cursor = conn.cursor()

        cursor.execute("SELECT id, status, assigned_to_user_id FROM tickets WHERE id = %s", (ticket_id,))
        ticket = cursor.fetchone()
        if not ticket:
            return jsonify({"error": "Ticket not found"}), 404
        if ticket['status'] != 'assigned':
            return jsonify({"error": "Ticket must be in 'assigned' status to start work"}), 400
        if ticket['assigned_to_user_id'] != user_id:
            return jsonify({"error": "This ticket is not assigned to you"}), 403

        cursor.execute("UPDATE tickets SET status = 'in_progress' WHERE id = %s", (ticket_id,))
        log_status_change(cursor, ticket_id, 'in_progress', user_id)
        conn.commit()

        send_ticket_notification(cursor, ticket_id, 'in_progress', user_id)
        conn.commit()

        return jsonify({"success": True, "message": "Ticket moved to In Progress"})
    except Exception as e:
        logger.error("Error starting progress: %s", e, exc_info=True)
        return jsonify({"error": "An unexpected error occurred"}), 500
    finally:
        conn.close()


# ─── ACTION: Resolve Ticket ─────────────────────────────────

@tickets_bp.route("/<int:ticket_id>/resolve", methods=["POST"])
def resolve_ticket(ticket_id):
    if not is_logged_in():
        return jsonify({"error": "Not logged in"}), 401

    user_id = session.get("user_id")
    user = get_user_by_id(user_id)
    if not user or user.get("role") != "technician":
        return jsonify({"error": "Only technicians can resolve tickets"}), 403

    conn = get_db()
    try:
        cursor = conn.cursor()

        cursor.execute("SELECT id, status, assigned_to_user_id FROM tickets WHERE id = %s", (ticket_id,))
        ticket = cursor.fetchone()
        if not ticket:
            return jsonify({"error": "Ticket not found"}), 404
        if ticket['status'] != 'in_progress':
            return jsonify({"error": "Ticket must be 'in_progress' to resolve"}), 400
        if ticket['assigned_to_user_id'] != user_id:
            return jsonify({"error": "This ticket is not assigned to you"}), 403

        cursor.execute("UPDATE tickets SET status = 'resolved' WHERE id = %s", (ticket_id,))
        log_status_change(cursor, ticket_id, 'resolved', user_id)
        conn.commit()

        send_ticket_notification(cursor, ticket_id, 'resolved', user_id)
        conn.commit()

        return jsonify({"success": True, "message": "Ticket resolved successfully"})
    except Exception as e:
        logger.error("Error resolving ticket: %s", e, exc_info=True)
        return jsonify({"error": "An unexpected error occurred"}), 500
    finally:
        conn.close()


# ─── ACTION: Mark as Garbage ────────────────────────────────

@tickets_bp.route("/<int:ticket_id>/garbage", methods=["POST"])
def mark_garbage(ticket_id):
    if not is_logged_in():
        return jsonify({"error": "Not logged in"}), 401

    user_id = session.get("user_id")
    user = get_user_by_id(user_id)
    if not user or user.get("role") != "technician":
        return jsonify({"error": "Only technicians can mark garbage"}), 403

    conn = get_db()
    try:
        cursor = conn.cursor()

        cursor.execute("SELECT id, status, assigned_to_user_id FROM tickets WHERE id = %s", (ticket_id,))
        ticket = cursor.fetchone()
        if not ticket:
            return jsonify({"error": "Ticket not found"}), 404
        if ticket['status'] not in ('assigned', 'in_progress'):
            return jsonify({"error": "Ticket must be 'assigned' or 'in_progress' to mark as garbage"}), 400
        if ticket['assigned_to_user_id'] != user_id:
            return jsonify({"error": "This ticket is not assigned to you"}), 403

        cursor.execute("UPDATE tickets SET status = 'garbage' WHERE id = %s", (ticket_id,))
        log_status_change(cursor, ticket_id, 'garbage', user_id)
        conn.commit()

        send_ticket_notification(cursor, ticket_id, 'garbage', user_id)
        conn.commit()

        return jsonify({"success": True, "message": "Ticket marked as unrepairable"})
    except Exception as e:
        logger.error("Error marking garbage: %s", e, exc_info=True)
        return jsonify({"error": "An unexpected error occurred"}), 500
    finally:
        conn.close()


# ─── ACTION: Verify Ticket (Employee) ───────────────────────

@tickets_bp.route("/<int:ticket_id>/verify", methods=["POST"])
def verify_ticket(ticket_id):
    if not is_logged_in():
        return jsonify({"error": "Not logged in"}), 401

    user_id = session.get("user_id")

    conn = get_db()
    try:
        cursor = conn.cursor()

        cursor.execute("SELECT id, status, created_by_user_id FROM tickets WHERE id = %s", (ticket_id,))
        ticket = cursor.fetchone()
        if not ticket:
            return jsonify({"error": "Ticket not found"}), 404
        if ticket['created_by_user_id'] != user_id:
            return jsonify({"error": "You can only verify tickets you raised"}), 403
        if ticket['status'] != 'resolved':
            return jsonify({"error": "Ticket must be in 'resolved' status to verify"}), 400

        prev_status = get_previous_status(cursor, ticket_id)
        if prev_status != 'resolved':
            return jsonify({"error": "Verification guard failed: previous status must be 'resolved'"}), 400

        cursor.execute("UPDATE tickets SET status = 'verified' WHERE id = %s", (ticket_id,))
        log_status_change(cursor, ticket_id, 'verified', user_id)
        conn.commit()

        send_ticket_notification(cursor, ticket_id, 'verified', user_id)
        conn.commit()

        return jsonify({"success": True, "message": "Ticket verified and closed"})
    except Exception as e:
        logger.error("Error verifying ticket: %s", e, exc_info=True)
        return jsonify({"error": "An unexpected error occurred"}), 400
    finally:
        conn.close()


# ─── API: Ticket Detail ─────────────────────────────────────

@tickets_bp.route("/<int:ticket_id>/detail")
def ticket_detail(ticket_id):
    if not is_logged_in():
        return jsonify({"error": "Not logged in"}), 401

    conn = get_db()
    try:
        cursor = conn.cursor()
        ticket = get_ticket_full(cursor, ticket_id)
        if not ticket:
            return jsonify({"error": "Ticket not found"}), 404

        cursor.execute("""
            SELECT status, changed_at FROM ticket_status_history
            WHERE ticket_id = %s
            ORDER BY changed_at ASC
        """, (ticket_id,))
        history = [{"status": r['status'], "changed_at": r['changed_at']} for r in cursor.fetchall()]

        ticket["history"] = history
        return jsonify(ticket)
    finally:
        conn.close()
