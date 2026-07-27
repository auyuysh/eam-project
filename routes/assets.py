from flask import request, jsonify, session, g
from functools import wraps
from datetime import datetime
from zoneinfo import ZoneInfo
import logging
import psycopg2
import psycopg2.errors

from auth.database import get_db as _get_pg_db

from . import assets_bp

logger = logging.getLogger("eam.assets")


def get_db():
    return _get_pg_db()


def is_logged_in():
    return session.get("logged_in") == True


def permission_required(permission_code):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not is_logged_in():
                return jsonify({'success': False, 'message': 'Authentication required.'}), 401
            user_id = session.get("user_id")
            if not user_id:
                return jsonify({'success': False, 'message': 'Authentication required.'}), 401
            conn = get_db()
            try:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT role, department_id FROM users WHERE id = %s",
                    (user_id,),
                )
                row = cursor.fetchone()
                if not row:
                    return jsonify({'success': False, 'message': 'User not found.'}), 403

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
                    return jsonify({'success': False, 'message': 'Permission denied.'}), 403
            finally:
                conn.close()
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def enforce_dept_scope(target_dept_id):
    if g.get("user_scope") != "departmental":
        return
    if g.get("user_department_id") != target_dept_id:
        abort(403)


@assets_bp.route('/add', methods=['POST'])
@permission_required("assets.create")
def add_asset():
    data = request.get_json() if request.is_json else request.form

    asset_type_id = data.get('asset_type_id')
    name = data.get('name', '').strip()
    serial_number = data.get('serial_number', '').strip().upper()
    location = data.get('location', '').strip()
    warranty_start = data.get('warranty_start') or None
    warranty_end = data.get('warranty_end') or None

    if not name or not serial_number or not asset_type_id:
        return jsonify({
            'success': False,
            'message': 'Asset Name, Serial Number, and Asset Type are required.'
        }), 400

    conn = get_db()
    try:
        cursor = conn.cursor()

        cursor.execute(
            "SELECT id, prefix, department_id FROM asset_types WHERE id = %s",
            (asset_type_id,)
        )
        asset_type = cursor.fetchone()

        if not asset_type:
            return jsonify({
                'success': False, 'message': 'Asset type not found.'
            }), 404

        prefix = asset_type['prefix']
        dept_id = asset_type['department_id']

        if g.get("user_scope") == "departmental":
            if g.get("user_department_id") != dept_id:
                return jsonify({
                    'success': False, 'message': 'Access denied to this department.'
                }), 403

        cursor.execute(
            "SELECT asset_id FROM assets WHERE upper(serial_number) = %s",
            (serial_number,)
        )
        existing = cursor.fetchone()
        if existing:
            return jsonify({
                'success': False,
                'message': f"Serial number '{serial_number}' already exists "
                           f"(assigned to Asset ID: {existing['asset_id']}). "
                           f"Each physical device must have a unique serial number."
            }), 400

        cursor.execute(
            "SELECT COUNT(*) AS count FROM assets WHERE asset_type_id = %s",
            (asset_type_id,)
        )
        count_res = cursor.fetchone()
        count = count_res['count']

        generated_asset_id = f"{prefix}-{(count + 1):04d}"

        created_at = datetime.now(ZoneInfo("Asia/Kolkata")).isoformat()

        cursor.execute("""
            INSERT INTO assets (
                asset_type_id, department_id, asset_id,
                name, serial_number, location,
                warranty_start, warranty_end, created_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            asset_type_id, dept_id, generated_asset_id,
            name, serial_number, location or None,
            warranty_start, warranty_end,
            created_at
        ))

        conn.commit()
        return jsonify({
            'success': True,
            'message': 'Asset created successfully!',
            'asset_id': generated_asset_id
        }), 200

    except psycopg2.IntegrityError:
        conn.rollback()
        return jsonify({
            'success': False,
            'message': 'Duplicate serial number or asset ID detected.'
        }), 400
    except Exception as e:
        conn.rollback()
        logger.error("Error adding asset: %s", e)
        return jsonify({
            'success': False, 'message': 'An unexpected error occurred.'
        }), 500
    finally:
        conn.close()
