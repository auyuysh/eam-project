from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, send_file
import sqlite3
from datetime import datetime
from zoneinfo import ZoneInfo
import os

app = Flask(__name__)
app.secret_key = "eam_demo_secret_key_2024"

DB_NAME = "devices.db"





def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # Devices Table
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

    # Pending Devices Table
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

    # Users Table
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

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                id,
                username,
                password_hash
            FROM users
            WHERE username = ?
        """, (username,))

        user = cursor.fetchone()

        conn.close()

        if user and check_password_hash(user[2], password):

            session["logged_in"] = True
            session["user_id"] = user[0]
            session["username"] = user[1]

            return redirect(url_for("dashboard"))

        return render_template(
            "login.html",
            error="Invalid username or password."
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

        # Check if passwords match
        if password != confirm_password:
            return render_template(
                "signup.html",
                error="Passwords do not match."
            )

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        # Check if username already exists
        cursor.execute(
            "SELECT id FROM users WHERE username = ?",
            (username,)
        )

        if cursor.fetchone():
            conn.close()
            return render_template(
                "signup.html",
                error="Username already exists."
            )

        # Check if email already exists
        cursor.execute(
            "SELECT id FROM users WHERE email = ?",
            (email,)
        )

        if cursor.fetchone():
            conn.close()
            return render_template(
                "signup.html",
                error="Email already registered."
            )

        password_hash = generate_password_hash(password)

        created_at = datetime.now(
            ZoneInfo("Asia/Kolkata")
        ).isoformat()

        cursor.execute("""
            INSERT INTO users (
                first_name,
                last_name,
                company_name,
                email,
                username,
                password_hash,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            first_name,
            last_name,
            company_name,
            email,
            username,
            password_hash,
            created_at
        ))

        conn.commit()
        conn.close()

        return redirect(url_for("login"))

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
    exe_path = os.path.join(os.path.dirname(__file__), "static", "agent", "getinfo.exe")
    return send_file(exe_path, as_attachment=True, download_name="EAM_Agent.exe")


# ─── DASHBOARD ───────────────────────────────────────────────

@app.route("/dashboard")
def dashboard():

    if not is_logged_in():
        return redirect(url_for("login"))

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, name
        FROM departments
        ORDER BY name
    """)

    departments = cursor.fetchall()

    conn.close()

    return render_template(
        "dashboard.html",
        departments=departments
    )
@app.route("/create-department", methods=["POST"])
def create_department():

    if not is_logged_in():
        return redirect(url_for("login"))

    name = request.form.get("name").strip()

    if not name:
        return redirect(url_for("dashboard"))

    created_at = datetime.now(
        ZoneInfo("Asia/Kolkata")
    ).isoformat()

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute(
        "SELECT id FROM departments WHERE name = ?",
        (name,)
    )

    if cursor.fetchone():
        conn.close()
        return redirect(url_for("dashboard"))

    cursor.execute("""
        INSERT INTO departments(name, created_at)
        VALUES(?, ?)
    """, (
        name,
        created_at
    ))

    conn.commit()
    conn.close()

    return redirect(url_for("dashboard"))

# ─── DEPARTMENT VIEW ─────────────────────────────────────────

@app.route("/department/<dept_name>")
def department(dept_name):

    if not is_logged_in():
        return redirect(url_for("login"))

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # Check if the department exists
    cursor.execute(
        "SELECT id FROM departments WHERE name = ?",
        (dept_name,)
    )

    if cursor.fetchone() is None:
        conn.close()
        return redirect(url_for("dashboard"))

    # Fetch all devices in the department
    cursor.execute("""
        SELECT
            uuid,
            hostname,
            employee,
            battery_percentage,
            status,
            last_seen
        FROM devices
        WHERE department = ?
    """, (dept_name,))

    devices = cursor.fetchall()

    conn.close()

    formatted = []

    for device in devices:
        device = list(device)
        device[5] = format_timestamp(device[5])
        formatted.append(device)

    return render_template(
        "department.html",
        dept_name=dept_name,
        devices=formatted
    )


# ─── DEVICE DETAIL ───────────────────────────────────────────

@app.route("/device/<uuid>")
def device_detail(uuid):
    if not is_logged_in():
        return redirect(url_for("login"))

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM devices WHERE uuid = ?", (uuid,))
    device = cursor.fetchone()
    conn.close()

    if not device:
        return redirect(url_for("dashboard"))

    device = list(device)
    device[15] = format_timestamp(device[15])

    return render_template("device_detail.html", device=device)


# ─── PENDING & APPROVAL ──────────────────────────────────────

@app.route("/pending")
def pending():

    if not is_logged_in():
        return redirect(url_for("login"))

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # Fetch pending devices
    cursor.execute("SELECT * FROM pending_devices")
    pending_devices = cursor.fetchall()

    # Fetch department names from database
    cursor.execute("""
        SELECT name
        FROM departments
        ORDER BY name
    """)

    departments = [row[0] for row in cursor.fetchall()]

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

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM pending_devices WHERE uuid = ?", (uuid,))
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
        cursor.execute("DELETE FROM pending_devices WHERE uuid = ?", (uuid,))
        conn.commit()
        print(f"Approved device: {uuid}")

    conn.close()
    return redirect(url_for("dashboard"))


# ─── HEARTBEAT ───────────────────────────────────────────────

@app.route("/heartbeat", methods=["POST"])
def heartbeat():
    data = request.get_json()
    print("Received payload:", data)
    uuid = data.get("uuid")
    now = datetime.now(ZoneInfo("Asia/Kolkata")).isoformat()

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT uuid FROM devices WHERE uuid = ?", (uuid,))
    existing = cursor.fetchone()

    if existing:
        cursor.execute("""
            UPDATE devices SET
                serial_number = ?,
                hostname = ?,
                os_version = ?,
                mac_address = ?,
                manufacturer = ?,
                model = ?,
                ssid = ?,
                battery_percentage = ?,
                status = ?,
                last_seen = ?
            WHERE uuid = ?
        """, (
            data.get("serial_number"),
            data.get("hostname"),
            data.get("os_version"),
            data.get("mac_address"),
            data.get("manufacturer"),
            data.get("model"),
            data.get("ssid"),
            data.get("battery_percentage"),
            "online",
            now,
            uuid
        ))
        conn.commit()
        conn.close()
        print(f"Updated existing device: {uuid}")
        return jsonify({"status": "updated", "device_status": "existing"}), 200

    else:
        cursor.execute("SELECT uuid FROM pending_devices WHERE uuid = ?", (uuid,))
        pending = cursor.fetchone()
        if not pending:
            cursor.execute("""
                INSERT INTO pending_devices (
                    uuid, serial_number, hostname, os_version,
                    mac_address, manufacturer, model, detected_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                uuid,
                data.get("serial_number"),
                data.get("hostname"),
                data.get("os_version"),
                data.get("mac_address"),
                data.get("manufacturer"),
                data.get("model"),
                now
            ))
            conn.commit()
            print(f"New device detected, added to pending: {uuid}")
        conn.close()
        return jsonify({"status": "pending_approval", "device_status": "new"}), 200


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)