# blueprints/monitoring.py
from flask import Blueprint, request, jsonify
from datetime import datetime
from zoneinfo import ZoneInfo
import logging
import os

from auth.database import get_db as _get_pg_db, dict_cursor

logger = logging.getLogger("eam.monitoring")

monitoring = Blueprint("monitoring", __name__)

def get_db():
    return _get_pg_db()

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
    try:
        cursor = conn.cursor()

        cursor.execute("SELECT uuid FROM monitored_devices WHERE uuid = %s", (uuid,))
        existing = cursor.fetchone()

        if not existing:
            cursor.execute("""
                INSERT INTO monitored_devices (
                    uuid, serial_number, hostname, os_version,
                    mac_address, manufacturer, model, registered_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
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
            return jsonify({"status": "registered"}), 201

        return jsonify({"status": "already_registered"}), 200
    except Exception as e:
        logger.error("[DB ERROR] file=blueprints/monitoring.py, function=agent_register, uuid=%s, error=%s", uuid, e, exc_info=True)
        return jsonify({"error": "Internal server error"}), 500
    finally:
        conn.close()


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
    try:
        cursor = conn.cursor()

        cursor.execute(
            "SELECT uuid FROM monitored_devices WHERE uuid = %s", (uuid,)
        )
        existing = cursor.fetchone()

        if existing:
            cursor.execute("""
                UPDATE monitored_devices SET
                    battery_percentage = %s,
                    ssid = %s,
                    logged_in_user = %s,
                    status = %s,
                    last_seen = %s
                WHERE uuid = %s
            """, (
                data.get("battery_percentage"),
                data.get("ssid"),
                data.get("logged_in_user"),
                "online",
                now,
                uuid
            ))
            conn.commit()
            return jsonify({"status": "updated"}), 200

        return jsonify({"status": "not_registered"}), 404
    except Exception as e:
        logger.error("[DB ERROR] file=blueprints/monitoring.py, function=agent_heartbeat, uuid=%s, error=%s", uuid, e, exc_info=True)
        return jsonify({"error": "Internal server error"}), 500
    finally:
        conn.close()


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
    try:
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE monitored_devices SET
                hostname = %s,
                os_version = %s,
                mac_address = %s,
                manufacturer = %s,
                model = %s,
                last_seen = %s
            WHERE uuid = %s
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
        return jsonify({"status": "updated"}), 200
    except Exception as e:
        logger.error("[DB ERROR] file=blueprints/monitoring.py, function=agent_device_info, uuid=%s, error=%s", uuid, e, exc_info=True)
        return jsonify({"error": "Internal server error"}), 500
    finally:
        conn.close()


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
    try:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE monitored_devices SET
                status = %s,
                last_seen = %s
            WHERE uuid = %s
        """, (data.get("status", "online"), now, uuid))
        conn.commit()
        return jsonify({"status": "updated"}), 200
    except Exception as e:
        logger.error("[DB ERROR] file=blueprints/monitoring.py, function=agent_status, uuid=%s, error=%s", uuid, e, exc_info=True)
        return jsonify({"error": "Internal server error"}), 500
    finally:
        conn.close()


# ─── BATTERY ─────────────────────────────────────────────────

@monitoring.route("/api/agent/battery", methods=["POST"])
def agent_battery():
    api_key = request.headers.get("X-API-Key")
    if api_key != os.getenv("AGENT_API_KEY"):
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    uuid = data.get("uuid")

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE monitored_devices SET battery_percentage = %s
            WHERE uuid = %s
        """, (data.get("battery_percentage"), uuid))
        conn.commit()
        return jsonify({"status": "updated"}), 200
    except Exception as e:
        logger.error("[DB ERROR] file=blueprints/monitoring.py, function=agent_battery, uuid=%s, error=%s", uuid, e, exc_info=True)
        return jsonify({"error": "Internal server error"}), 500
    finally:
        conn.close()


# ─── PENDING DEVICES (for future dashboard) ──────────────────

@monitoring.route("/api/agent/pending", methods=["GET"])
def get_pending():
    api_key = request.headers.get("X-API-Key")
    if api_key != os.getenv("AGENT_API_KEY"):
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db()
    try:
        cursor = dict_cursor(conn)
        cursor.execute("SELECT * FROM pending_devices")
        rows = cursor.fetchall()
        return jsonify([dict(row) for row in rows]), 200
    except Exception as e:
        logger.error("[DB ERROR] file=blueprints/monitoring.py, function=get_pending, error=%s", e, exc_info=True)
        return jsonify({"error": "Internal server error"}), 500
    finally:
        conn.close()
