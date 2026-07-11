"""
LDAP Authentication Provider
=============================

Handles all credential verification and user lifecycle operations
against the local OpenLDAP directory server.

Responsibilities
-----------------
- Authenticate users via LDAP bind.
- Create new user entries in the LDAP directory tree.
- Modify userPassword attributes for password changes / resets.
- Look up user profile metadata from the local SQLite database.

Out of scope
-------------
- OTP / MFA logic   -> see ``otp_service``
- Email delivery    -> see ``email_service``
- Session management -> handled by server.py / Flask session
"""

import logging
from typing import Optional

from ldap3 import Server, Connection, ALL, SUBTREE

from auth.database import get_db
from auth.models import AuthResult

logger = logging.getLogger("eam")

# ---------------------------------------------------------------------------
# LDAP Configuration
# ---------------------------------------------------------------------------

LDAP_SERVER = "ldap://127.0.0.1:389"
LDAP_BASE_DN = "dc=pdmh,dc=hospital,dc=local"
LDAP_USERS_OU = "ou=users"
LDAP_ADMIN_DN = f"cn=admin,{LDAP_BASE_DN}"
LDAP_ADMIN_PASSWORD = "HospitalAdminPassword123"


# ---------------------------------------------------------------------------
# Credential Verification (User-facing bind)
# ---------------------------------------------------------------------------

def verify_user_credentials_with_ldap(user_email: str, password: str) -> bool:
    """
    Attempt an LDAP bind with the user's own credentials.

    Parameters
    ----------
    user_email : str
        The login email address (e.g. ``john@pdmh.hospital.local``).
    password : str
        The plain-text password to verify against the directory.

    Returns
    -------
    bool
        ``True`` if the bind succeeds (credentials are correct).
        ``False`` on any failure.
    """
    username = user_email.split("@")[0]

    server = Server(LDAP_SERVER, get_info=ALL)
    user_dn = f"uid={username},{LDAP_USERS_OU},{LDAP_BASE_DN}"

    try:
        conn = Connection(
            server,
            user=user_dn,
            password=password,
            check_names=True,
            raise_exceptions=True,
        )
        conn.bind()
        conn.unbind()
        return True
    except Exception as e:
        logger.warning("[LDAP Auth Failure] user=%s: %s", user_email, e)
        return False


# ---------------------------------------------------------------------------
# Authentication Provider Interface (for auth_service)
# ---------------------------------------------------------------------------

def get_user_profile_by_email(email: str) -> Optional[dict]:
    """
    Fetch user profile metadata from the local SQLite database.

    This only retrieves non-sensitive profile columns; passwords
    are never stored in SQLite.

    Returns
    -------
    dict or None
        Profile dictionary or ``None`` if the user does not exist locally.
    """
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, email, first_name, last_name,
                   company_name, company_id, role
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
            "first_name": row[2],
            "last_name": row[3],
            "company_name": row[4],
            "company_id": row[5],
            "role": row[6],
        }
    finally:
        conn.close()


def authenticate_ldap(email: str, password: str) -> AuthResult:
    """
    Authenticate a user against the LDAP directory and fetch their
    local profile metadata.

    Parameters
    ----------
    email : str
        The login email address.
    password : str
        The plain-text password.

    Returns
    -------
    AuthResult
        status ``'authenticated'`` on success, ``'failed'`` otherwise.
    """
    if not verify_user_credentials_with_ldap(email, password):
        return AuthResult(
            status="failed",
            message="Invalid email or password.",
        )

    user = get_user_profile_by_email(email)
    if user is None:
        logger.warning(
            "LDAP auth succeeded but no local profile found for %s", email
        )
        return AuthResult(
            status="failed",
            message="User account not found in local database.",
        )

    return AuthResult(
        status="authenticated",
        user=user,
        user_id=user["id"],
        username=user["email"],
        message="LDAP authentication successful.",
    )


# ---------------------------------------------------------------------------
# Administrative LDAP Operations (Service Account Bind)
# ---------------------------------------------------------------------------

def _admin_bind() -> Connection:
    """
    Establish an authenticated bind using the LDAP admin service account.

    Returns
    -------
    Connection
        A bound ldap3 Connection ready for administrative operations.

    Raises
    ------
    Exception
        If the admin bind fails.
    """
    server = Server(LDAP_SERVER, get_info=ALL)
    conn = Connection(
        server,
        user=LDAP_ADMIN_DN,
        password=LDAP_ADMIN_PASSWORD,
        check_names=True,
        raise_exceptions=True,
    )
    conn.bind()
    return conn


def create_ldap_user(
    username: str,
    password: str,
    first_name: str,
    last_name: str,
    email: str,
) -> bool:
    """
    Create a new user entry in the LDAP directory tree.

    Uses the admin service account to add the entry under
    ``uid=<username>,ou=users,dc=pdmh,dc=hospital,dc=local``.

    Parameters
    ----------
    username : str
        The uid for the new user (typically the email prefix).
    password : str
        The user's initial plain-text password.
    first_name : str
        The user's given name.
    last_name : str
        The user's surname.
    email : str
        The user's email address.

    Returns
    -------
    bool
        ``True`` if the user was created successfully.
    """
    user_dn = f"uid={username},{LDAP_USERS_OU},{LDAP_BASE_DN}"

    try:
        conn = _admin_bind()

        attributes = {
            "uid": str(username),
            "cn": str(f"{first_name} {last_name}"),
            "sn": str(last_name),
            "givenName": str(first_name),
            "mail": str(email),
            "userPassword": str(password),
        }

        result = conn.add(
            dn=user_dn,
            object_class=["top", "person", "organizationalPerson", "inetOrgPerson"],
            attributes=attributes,
        )
        conn.unbind()

        if result:
            logger.info("LDAP user created: %s", user_dn)
        else:
            logger.error(
                "LDAP user creation returned False for %s: %s",
                user_dn,
                conn.result,
            )
        return result

    except Exception as e:
        logger.error("[LDAP Create User Failure] %s: %s", user_dn, e)
        return False


def update_ldap_password(username: str, new_password: str) -> bool:
    """
    Modify a user's password in the LDAP directory.

    Uses the admin service account to perform the password change,
    so the user does not need to be re-authenticated.

    Parameters
    ----------
    username : str
        The uid of the user whose password is being changed.
    new_password : str
        The new plain-text password.

    Returns
    -------
    bool
        ``True`` if the password was updated successfully.
    """
    user_dn = f"uid={username},{LDAP_USERS_OU},{LDAP_BASE_DN}"

    try:
        conn = _admin_bind()
        conn.modify_password(user_dn, new_password)
        conn.unbind()
        logger.info("LDAP password updated for %s", user_dn)
        return True

    except Exception as e:
        logger.error("[LDAP Password Update Failure] %s: %s", user_dn, e)
        return False


def ldap_bind_as_user(user_email: str, password: str) -> bool:
    """
    Authenticate a user via LDAP bind.

    This is a convenience wrapper around ``verify_user_credentials_with_ldap``
    intended for secondary confirmation checks (e.g. delete operations,
    current-password verification on the profile page).

    Parameters
    ----------
    user_email : str
        The user's email address.
    password : str
        The plain-text password to verify.

    Returns
    -------
    bool
        ``True`` if the bind succeeds.
    """
    return verify_user_credentials_with_ldap(user_email, password)
