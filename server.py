from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, send_file
import sqlite3
from datetime import datetime
from zoneinfo import ZoneInfo
import os

app = Flask(__name__)
app.secret_key = "eam_demo_secret_key_2024"

DB_NAME = "devices.db"


def get_db():
    return sqlite3.connect(DB_NAME, timeout=10, check_same_thread=False)


def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            uuid TEXT PRIMARY KEY,
            serial_number TEXT,
            hostname TEXT,
            os_version TEXT,
            mac_address TEXT,
            manufacturer TEXT,
            model TEXT,
            ssid TEXT,
            employee TEXT,
            department TEXT,
            battery_percentage INTEGER,
            purchase_value TEXT,
            purchase_date TEXT,
            warranty TEXT,
            status TEXT,
            last_seen TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS pending_devices (
            uuid TEXT PRIMARY KEY,
            serial_number TEXT,
            hostname TEXT,
            os_version TEXT,
            mac_address TEXT,
            manufacturer TEXT,
            model TEXT,
            detected_at TEXT
        )
    """)

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

@app.route("/")
def index():
    if is_logged_in():
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        conn = get_db()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, username, password_hash FROM users WHERE username = ?",
                (username,)
            )
            user = cursor.fetchone()
        finally:
            conn.close()

        if user and check_password_hash(user[2], password):
            session["logged_in"] = True
            session["user_id"] = user[0]
            session["username"] = user[1]
            return redirect(url_for("dashboard"))

        return render_template(
            "login.html", error="Invalid username or password."
        )

    return render_template("login.html", error=None)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        first_name = request.form.get("first_name")
        last_name = request.form.get("last_name")
        company_name = request.form.get("company")
        email = request.form.get("email")
        username = request.form.get("username")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        if password != confirm_password:
            return render_template(
                "signup.html", error="Passwords do not match."
            )

        conn = get_db()
        try:
            cursor = conn.cursor()

            cursor.execute(
                "SELECT id FROM users WHERE username = ?", (username,)
            )
            if cursor.fetchone():
                return render_template(
                    "signup.html", error="Username already exists."
                )

            cursor.execute(
                "SELECT id FROM users WHERE email = ?", (email,)
            )
            if cursor.fetchone():
                return render_template(
                    "signup.html", error="Email already registered."
                )

            password_hash = generate_password_hash(password)
            created_at = datetime.now(ZoneInfo("Asia/Kolkata")).isoformat()

            cursor.execute("""
                INSERT INTO users (
                    first_name, last_name, company_name,
                    email, username, password_hash, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                first_name, last_name, company_name,
                email, username, password_hash, created_at
            ))
            conn.commit()
            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            return render_template(
                "signup.html",
                error="Username or email already exists."
            )
        finally:
            conn.close()

    return render_template("signup.html", error=None)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ─── DOWNLOAD ROUTES ─────────────────────────────────────────

@app.route("/download")
def download():
    if not is_logged_in():
        return redirect(url_for("login"))
    return render_template("download.html")


@app.route("/download-agent")
def download_agent():
    if not is_logged_in():
        return redirect(url_for("login"))
    exe_path = os.path.join(
        os.path.dirname(__file__), "static", "agent", "getinfo.exe"
    )
    return send_file(
        exe_path, as_attachment=True, download_name="EAM_Agent.exe"
    )


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


# ─── PENDING & APPROVAL ──────────────────────────────────────

@app.route("/pending")
def pending():
    if not is_logged_in():
        return redirect(url_for("login"))

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM pending_devices")
        pending_devices = cursor.fetchall()
        cursor.execute("SELECT name FROM departments ORDER BY name")
        departments = [row[0] for row in cursor.fetchall()]
    finally:
        conn.close()

    return render_template(
        "pending.html",
        pending_devices=pending_devices,
        departments=departments
    )


@app.route("/approve", methods=["POST"])
def approve():
    if not is_logged_in():
        return redirect(url_for("login"))

    uuid = request.form.get("uuid")
    employee = request.form.get("employee")
    department = request.form.get("department")
    purchase_value = request.form.get("purchase_value")
    purchase_date = request.form.get("purchase_date")
    warranty = request.form.get("warranty")
    now = datetime.now(ZoneInfo("Asia/Kolkata")).isoformat()

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM pending_devices WHERE uuid = ?", (uuid,)
        )
        pending_device = cursor.fetchone()

        if pending_device:
            cursor.execute("""
                INSERT INTO devices (
                    uuid, serial_number, hostname, os_version, mac_address,
                    manufacturer, model, ssid, employee, department,
                    battery_percentage, purchase_value, purchase_date,
                    warranty, status, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                pending_device[0], pending_device[1], pending_device[2],
                pending_device[3], pending_device[4], pending_device[5],
                pending_device[6], None, employee, department,
                None, purchase_value, purchase_date, warranty, "online", now
            ))
            cursor.execute(
                "DELETE FROM pending_devices WHERE uuid = ?", (uuid,)
            )
            conn.commit()
            print(f"Approved device: {uuid}")
    finally:
        conn.close()

    return redirect(url_for("dashboard"))


# ─── HEARTBEAT ───────────────────────────────────────────────

@app.route("/heartbeat", methods=["POST"])
def heartbeat():
    data = request.get_json()
    print("Received payload:", data)
    uuid = data.get("uuid")
    now = datetime.now(ZoneInfo("Asia/Kolkata")).isoformat()

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT uuid FROM devices WHERE uuid = ?", (uuid,)
        )
        existing = cursor.fetchone()

        if existing:
            cursor.execute("""
                UPDATE devices SET
                    serial_number = ?, hostname = ?, os_version = ?,
                    mac_address = ?, manufacturer = ?, model = ?,
                    ssid = ?, battery_percentage = ?, status = ?, last_seen = ?
                WHERE uuid = ?
            """, (
                data.get("serial_number"), data.get("hostname"),
                data.get("os_version"), data.get("mac_address"),
                data.get("manufacturer"), data.get("model"),
                data.get("ssid"), data.get("battery_percentage"),
                "online", now, uuid
            ))
            conn.commit()
            print(f"Updated existing device: {uuid}")
            return jsonify({
                "status": "updated", "device_status": "existing"
            }), 200
        else:
            cursor.execute(
                "SELECT uuid FROM pending_devices WHERE uuid = ?", (uuid,)
            )
            pending = cursor.fetchone()
            if not pending:
                cursor.execute("""
                    INSERT INTO pending_devices (
                        uuid, serial_number, hostname, os_version,
                        mac_address, manufacturer, model, detected_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    uuid, data.get("serial_number"), data.get("hostname"),
                    data.get("os_version"), data.get("mac_address"),
                    data.get("manufacturer"), data.get("model"), now
                ))
                conn.commit()
                print(f"New device detected, added to pending: {uuid}")
            return jsonify({
                "status": "pending_approval", "device_status": "new"
            }), 200
    finally:
        conn.close()


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)