"""
Local Database Authentication
==============================

Handles email + password authentication against the local SQLite
database.  This provider does NOT communicate with any external
directory service.

Responsibilities
-----------------
- Verify a password hash stored in the ``users`` table.
- Retrieve user records by email or user ID.

Out of scope
-------------
- OTP / MFA logic   → see ``otp_service``
- Email delivery    → see ``email_service``
- Session management → handled by server.py / Flask session
"""

from typing import Optional

from werkzeug.security import check_password_hash

from auth.database import get_db
from auth.models import AuthResult


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_user(email: str) -> Optional[dict]:
    """
    Fetch a user record by email.

    Returns
    -------
    dict or None
        A dictionary with keys ``id``, ``email``, ``password_hash``,
        ``first_name``, ``last_name``, ``company_name``,
        ``company_id``, ``role`` or ``None`` if not found.
    """
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, email, password_hash, first_name,
                   last_name, company_name, company_id, role
            FROM users
            WHERE email = ?
            """,
            (email,),
        )
        row = cursor.fetchone()
        if row is None:
            return None

        return {
            "id": row[0],
            "email": row[1],
            "password_hash": row[2],
            "first_name": row[3],
            "last_name": row[4],
            "company_name": row[5],
            "company_id": row[6],
            "role": row[7],
        }
    finally:
        conn.close()


def get_user_by_id(user_id: int) -> Optional[dict]:
    """
    Fetch a user record by primary key.

    Returns
    -------
    dict or None
        A dictionary with user fields or ``None`` if not found.
    """
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, email, password_hash, first_name,
                   last_name, company_name, company_id, role
            FROM users
            WHERE id = ?
            """,
            (user_id,),
        )
        row = cursor.fetchone()
        if row is None:
            return None

        return {
            "id": row[0],
            "email": row[1],
            "password_hash": row[2],
            "first_name": row[3],
            "last_name": row[4],
            "company_name": row[5],
            "company_id": row[6],
            "role": row[7],
        }
    finally:
        conn.close()


def authenticate_local(email: str, password: str) -> AuthResult:
    """
    Authenticate a user against the local database.

    Parameters
    ----------
    email : str
        The login email address.
    password : str
        The plain-text password to verify.

    Returns
    -------
    AuthResult
        status ``'authenticated'`` on success, ``'failed'`` otherwise.
    """
    user = get_user(email)

    if user is None:
        return AuthResult(
            status="failed",
            message="Email address not registered.",
        )

    if not check_password_hash(user["password_hash"], password):
        return AuthResult(
            status="failed",
            message="Password incorrect.",
        )

    return AuthResult(
        status="authenticated",
        user=user,
        user_id=user["id"],
        username=user["email"],
        message="Local authentication successful.",
    )
