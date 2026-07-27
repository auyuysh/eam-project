"""
Local Database Profile Provider
================================

Retrieves user application profiles from the local PostgreSQL database.

LDAP is the **sole identity provider** for authentication.  This module
only fetches role, permissions, and employee metadata stored locally.

Responsibilities
-----------------
- Retrieve user profile records by email or user ID.

Out of scope
-------------
- Credential verification  -> handled exclusively by ``ldap_auth``
- OTP / MFA logic         -> see ``otp_service``
- Email delivery          -> see ``email_service``
- Session management      -> handled by server.py / Flask session
"""

import logging
from typing import Optional

from auth.database import get_db

logger = logging.getLogger("eam.auth.local")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_user(email: str) -> Optional[dict]:
    """
    Fetch a user application profile by email.

    Returns
    -------
    dict or None
        A dictionary with user profile fields or ``None`` if not found.
    """
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, email, first_name,
                   last_name, company_id, role,
                   is_super_admin, is_approved, account_status,
                   approved_by, approved_at, role_id, department_id,
                   ldap_uid
            FROM users
            WHERE email = %s
            """,
            (email,),
        )
        row = cursor.fetchone()
        if row is None:
            return None

        return dict(row)
    except Exception as e:
        logger.error(
            "[DB ERROR] file=auth/local_auth.py, function=get_user, email=%s, error=%s",
            email, e, exc_info=True,
        )
        return None
    finally:
        conn.close()


def get_user_by_id(user_id: int) -> Optional[dict]:
    """
    Fetch a user application profile by primary key.

    Returns
    -------
    dict or None
        A dictionary with user profile fields or ``None`` if not found.
    """
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, email, first_name,
                   last_name, company_id, role,
                   is_super_admin, is_approved, account_status,
                   approved_by, approved_at, role_id, department_id,
                   ldap_uid
            FROM users
            WHERE id = %s
            """,
            (user_id,),
        )
        row = cursor.fetchone()
        if row is None:
            return None

        return dict(row)
    except Exception as e:
        logger.error(
            "[DB ERROR] file=auth/local_auth.py, function=get_user_by_id, user_id=%s, error=%s",
            user_id, e, exc_info=True,
        )
        return None
    finally:
        conn.close()


def get_user_by_ldap_uid(ldap_uid: str) -> Optional[dict]:
    """
    Fetch a user application profile by LDAP uid.

    This is the preferred lookup method for post-authentication profile
    loading, since LDAP is the single source of truth for identity.

    Returns
    -------
    dict or None
        A dictionary with user profile fields or ``None`` if not found.
    """
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, email, first_name,
                   last_name, company_id, role,
                   is_super_admin, is_approved, account_status,
                   approved_by, approved_at, role_id, department_id,
                   ldap_uid
            FROM users
            WHERE ldap_uid = %s
            """,
            (ldap_uid,),
        )
        row = cursor.fetchone()
        if row is None:
            return None

        return dict(row)
    except Exception as e:
        logger.error(
            "[DB ERROR] file=auth/local_auth.py, function=get_user_by_ldap_uid, ldap_uid=%s, error=%s",
            ldap_uid, e, exc_info=True,
        )
        return None
    finally:
        conn.close()
