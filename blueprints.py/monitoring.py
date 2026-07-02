# blueprints/monitoring.py
from flask import Blueprint, request, jsonify
import sqlite3
from datetime import datetime
from zoneinfo import ZoneInfo
import os

monitoring = Blueprint("monitoring", __name__)

DB_NAME = "devices.db"

def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

# ─── AGENT REGISTRATION ──────────────────────────────────────

@monitoring.route("/api/agent/register", methods=["POST"])
def agent_register():
    api_key = request.headers.get("X-API-Key")
    if api_key != os.getenv("AGENT_API_KEY"):
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    if not data or not data.get("uuid"):
        return jsonify({"error": "Invalid data"}), 400

    uuid = data.get("uuid")
    now = datetime.now(ZoneInfo("Asia/Kolkata")).isoformat()

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT uuid FROM monitored_devices WHERE uuid = ?", (uuid,))
    existing = cursor.fetchone()

    if not existing:
        cursor.execute("""
            INSERT INTO monitored_devices (
                uuid, serial_number, hostname, os_version,
                mac_address, manufacturer, model, registered_at
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
        conn.close()
        return jsonify({"status": "registered"}), 201

    conn.close()
    return jsonify({"status": "already_registered"}), 200


# ─── HEARTBEAT ───────────────────────────────────────────────

@monitoring.route("/api/agent/heartbeat", methods=["POST"])
def agent_heartbeat():
    api_key = request.headers.get("X-API-Key")
    if api_key != os.getenv("AGENT_API_KEY"):
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    if not data or not data.get("uuid"):
        return jsonify({"error": "Invalid data"}), 400

    uuid = data.get("uuid")
    now = datetime.now(ZoneInfo("Asia/Kolkata")).isoformat()

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT uuid FROM monitored_devices WHERE uuid = ?", (uuid,)
    )
    existing = cursor.fetchone()

    if existing:
        cursor.execute("""
            UPDATE monitored_devices SET
                battery_percentage = ?,
                ssid = ?,
                logged_in_user = ?,
                status = ?,
                last_seen = ?
            WHERE uuid = ?
        """, (
            data.get("battery_percentage"),
            data.get("ssid"),
            data.get("logged_in_user"),
            "online",
            now,
            uuid
        ))
        conn.commit()
        conn.close()
        return jsonify({"status": "updated"}), 200

    conn.close()
    return jsonify({"status": "not_registered"}), 404


# ─── DEVICE INFO ─────────────────────────────────────────────

@monitoring.route("/api/agent/device-info", methods=["POST"])
def agent_device_info():
    api_key = request.headers.get("X-API-Key")
    if api_key != os.getenv("AGENT_API_KEY"):
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    uuid = data.get("uuid")
    now = datetime.now(ZoneInfo("Asia/Kolkata")).isoformat()

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE monitored_devices SET
            hostname = ?,
            os_version = ?,
            mac_address = ?,
            manufacturer = ?,
            model = ?,
            last_seen = ?
        WHERE uuid = ?
    """, (
        data.get("hostname"),
        data.get("os_version"),
        data.get("mac_address"),
        data.get("manufacturer"),
        data.get("model"),
        now,
        uuid
    ))
    conn.commit()
    conn.close()
    return jsonify({"status": "updated"}), 200


# ─── STATUS ──────────────────────────────────────────────────

@monitoring.route("/api/agent/status", methods=["POST"])
def agent_status():
    api_key = request.headers.get("X-API-Key")
    if api_key != os.getenv("AGENT_API_KEY"):
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    uuid = data.get("uuid")
    now = datetime.now(ZoneInfo("Asia/Kolkata")).isoformat()

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE monitored_devices SET
            status = ?,
            last_seen = ?
        WHERE uuid = ?
    """, (data.get("status", "online"), now, uuid))
    conn.commit()
    conn.close()
    return jsonify({"status": "updated"}), 200


# ─── BATTERY ─────────────────────────────────────────────────

@monitoring.route("/api/agent/battery", methods=["POST"])
def agent_battery():
    api_key = request.headers.get("X-API-Key")
    if api_key != os.getenv("AGENT_API_KEY"):
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    uuid = data.get("uuid")

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE monitored_devices SET battery_percentage = ?
        WHERE uuid = ?
    """, (data.get("battery_percentage"), uuid))
    conn.commit()
    conn.close()
    return jsonify({"status": "updated"}), 200


# ─── PENDING DEVICES (for future dashboard) ──────────────────

@monitoring.route("/api/agent/pending", methods=["GET"])
def get_pending():
    api_key = request.headers.get("X-API-Key")
    if api_key != os.getenv("AGENT_API_KEY"):
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM pending_devices")
    rows = cursor.fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows]), 200