from flask import Flask, request, jsonify, render_template
import sqlite3
from datetime import datetime

app = Flask(__name__)
DB_NAME = "devices.db"

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

@app.route("/pending")
def pending():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM pending_devices")
    pending_devices = cursor.fetchall()
    conn.close()
    return render_template("pending.html", pending_devices=pending_devices)

@app.route("/devices")
def devices():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM devices")
    all_devices = cursor.fetchall()
    conn.close()
    return render_template("devices.html", devices=all_devices)

@app.route("/approve", methods=["POST"])
def approve():
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
    return devices()

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)