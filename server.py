from flask import Flask, request, jsonify, render_template, redirect, url_for, session, send_file
import sqlite3
from datetime import datetime
from zoneinfo import ZoneInfo
import os

app = Flask(__name__)
app.secret_key = "eam_demo_secret_key_2024"

DB_NAME = "devices.db"
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"

DEPARTMENTS = ["IT", "Medical", "Radiology", "Administration"]


def init_db():
    conn = sqlite3.connect(DB_NAME)
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
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["logged_in"] = True
            return redirect(url_for("download"))
        else:
            return render_template("login.html", error="Invalid username or password.")
    return render_template("login.html", error=None)


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

    dept_counts = {}
    for dept in DEPARTMENTS:
        cursor.execute(
            "SELECT COUNT(*) FROM devices WHERE department = ?", (dept,)
        )
        dept_counts[dept] = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM pending_devices")
    pending_count = cursor.fetchone()[0]

    conn.close()
    return render_template(
        "dashboard.html",
        departments=DEPARTMENTS,
        dept_counts=dept_counts,
        pending_count=pending_count
    )


# ─── DEPARTMENT VIEW ─────────────────────────────────────────

@app.route("/department/<dept_name>")
def department(dept_name):
    if not is_logged_in():
        return redirect(url_for("login"))

    if dept_name not in DEPARTMENTS:
        return redirect(url_for("dashboard"))

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT uuid, hostname, employee, battery_percentage, status, last_seen FROM devices WHERE department = ?",
        (dept_name,)
    )
    devices = cursor.fetchall()
    conn.close()

    formatted = []
    for d in devices:
        d = list(d)
        d[5] = format_timestamp(d[5])
        formatted.append(d)

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
    cursor.execute("SELECT * FROM pending_devices")
    pending_devices = cursor.fetchall()
    conn.close()
    return render_template(
        "pending.html",
        pending_devices=pending_devices,
        departments=DEPARTMENTS
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