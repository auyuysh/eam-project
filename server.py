from flask import Flask, request, jsonify, render_template, redirect, url_for, session
import sqlite3
from datetime import datetime
from flask import send_file
import os

app = Flask(__name__)
app.secret_key = "eam_demo_secret_key_2024"

DB_NAME = "devices.db"

# Hardcoded credentials for demo
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"

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
            employee TEXT,
            department TEXT,
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
            detected_at TEXT
        )
    """)
    conn.commit()
    conn.close()

def is_logged_in():
    return session.get("logged_in") == True

# ─── AUTH ROUTES ────────────────────────────────────────────

@app.route("/")
def index():
    if is_logged_in():
        return redirect(url_for("devices"))
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
# ─── PROTECTED ROUTES ───────────────────────────────────────

@app.route("/devices")
def devices():
    if not is_logged_in():
        return redirect(url_for("login"))
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM devices")
    all_devices = cursor.fetchall()
    conn.close()
    return render_template("devices.html", devices=all_devices)

@app.route("/pending")
def pending():
    if not is_logged_in():
        return redirect(url_for("login"))
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM pending_devices")
    pending_devices = cursor.fetchall()
    conn.close()
    return render_template("pending.html", pending_devices=pending_devices)

@app.route("/approve", methods=["POST"])
def approve():
    if not is_logged_in():
        return redirect(url_for("login"))
    uuid = request.form.get("uuid")
    employee = request.form.get("employee")
    department = request.form.get("department")
    now = datetime.now().isoformat()

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM pending_devices WHERE uuid = ?", (uuid,))
    pending_device = cursor.fetchone()

    if pending_device:
        cursor.execute("""
            INSERT INTO devices (uuid, serial_number, hostname, os_version, mac_address, employee, department, status, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (pending_device[0], pending_device[1], pending_device[2], pending_device[3],
              pending_device[4], employee, department, "online", now))
        cursor.execute("DELETE FROM pending_devices WHERE uuid = ?", (uuid,))
        conn.commit()
        print(f"Approved device: {uuid}")

    conn.close()
    return redirect(url_for("devices"))

# ─── HEARTBEAT (no login required — agent calls this) ───────

@app.route("/heartbeat", methods=["POST"])
def heartbeat():
    data = request.get_json()
    uuid = data.get("uuid")
    now = datetime.now().isoformat()

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("SELECT uuid FROM devices WHERE uuid = ?", (uuid,))
    existing = cursor.fetchone()

    if existing:
        cursor.execute("""
            UPDATE devices
            SET serial_number = ?, hostname = ?, os_version = ?, mac_address = ?, status = ?, last_seen = ?
            WHERE uuid = ?
        """, (data.get("serial_number"), data.get("hostname"), data.get("os_version"),
              data.get("mac_address"), "online", now, uuid))
        conn.commit()
        conn.close()
        print(f"Updated existing device: {uuid}")
        return jsonify({"status": "updated", "device_status": "existing"}), 200
    else:
        cursor.execute("SELECT uuid FROM pending_devices WHERE uuid = ?", (uuid,))
        pending = cursor.fetchone()
        if not pending:
            cursor.execute("""
                INSERT INTO pending_devices (uuid, serial_number, hostname, os_version, mac_address, detected_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (uuid, data.get("serial_number"), data.get("hostname"),
                  data.get("os_version"), data.get("mac_address"), now))
            conn.commit()
            print(f"New device detected, added to pending: {uuid}")
        conn.close()
        return jsonify({"status": "pending_approval", "device_status": "new"}), 200

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)