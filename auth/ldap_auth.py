"""
LDAP Authentication Provider
=============================

Handles all credential verification and user lifecycle operations
against the local OpenLDAP directory server.

LDAP is the **sole identity provider** for this application.
PostgreSQL only stores application profiles (role, permissions, metadata).

Responsibilities
-----------------
- Authenticate users via LDAP bind.
- Search the LDAP directory for user existence checks.
- Create new user entries in the LDAP directory tree.
- Modify userPassword attributes for password changes / resets.
- Look up application profile metadata from the local PostgreSQL database.

Out of scope
-------------
- OTP / MFA logic   -> see ``otp_service``
- Email delivery    -> see ``email_service``
- Session management -> handled by server.py / Flask session
"""

import logging
import os
from typing import Optional

from ldap3 import Server, Connection, ALL, SUBTREE

from auth.database import get_db
from auth.models import AuthResult

logger = logging.getLogger("eam")

# ---------------------------------------------------------------------------
# LDAP URL Parsing & Validation Helpers
# ---------------------------------------------------------------------------

_DEFAULT_PORTS = {
    "ldap": "389",
    "ldaps": "636",
}


def parse_ldap_url(url: str) -> dict | None:
    """Parse an LDAP URL into its components.

    Supported formats::

        ldap://host
        ldap://host:389
        ldaps://host
        ldaps://host:636

    Returns
    -------
    dict or None
        ``{"protocol": "ldap", "host": "...", "port": "389"}`` on success,
        ``None`` if the URL is invalid.
    """
    url = url.strip()
    if "://" not in url:
        return None

    protocol, rest = url.split("://", 1)
    protocol = protocol.lower()
    if protocol not in _DEFAULT_PORTS:
        return None

    host_part = rest.split("/", 1)[0]
    if not host_part:
        return None

    if ":" in host_part:
        host, port = host_part.rsplit(":", 1)
        if not host:
            return None
        try:
            int(port)
        except ValueError:
            return None
    else:
        host = host_part
        port = _DEFAULT_PORTS[protocol]

    return {"protocol": protocol, "host": host, "port": port}


def validate_port(url_port: str, field_port: str) -> str | None:
    """Check for port conflicts between the URL and the separate port field.

    Returns
    -------
    str or None
        An error message if ports conflict, ``None`` if they are compatible.
    """
    if not field_port or not url_port:
        return None
    if url_port == field_port:
        return None
    return (
        f"Port mismatch: URL uses {url_port} but port field contains {field_port}. "
        "Please use the same port or remove one value."
    )


def build_connection(
    protocol: str,
    host: str,
    port: str,
    bind_dn: str = "",
    password: str = "",
    connect_timeout: int = 5,
):
    """Build and return a bound (or unbound) ldap3 Connection.

    Parameters
    ----------
    protocol, host, port : str
        Connection target parsed from the URL.
    bind_dn : str
        Distinguished name for authenticated bind.  Empty for anonymous.
    password : str
        Password for authenticated bind.
    connect_timeout : int
        Seconds before the connection attempt times out.

    Returns
    -------
    ldap3.Connection
        A connection that has been auto-bound (anonymous or authenticated).
    """
    server_uri = f"{protocol}://{host}:{port}"
    server = Server(server_uri, connect_timeout=connect_timeout)
    if bind_dn and password:
        return Connection(server, user=bind_dn, password=password, auto_bind=True)
    return Connection(server, auto_bind=True)


# ---------------------------------------------------------------------------
# LDAP Configuration (loaded from ldap_config table at runtime)
# ---------------------------------------------------------------------------

_LDAP_HOST = os.getenv("LDAP_SERVER", "ldap://127.0.0.1")
_LDAP_PORT = os.getenv("LDAP_PORT", "389")
_DEFAULTS = {
    "ldap_server": f"{_LDAP_HOST}:{_LDAP_PORT}" if ":" not in _LDAP_HOST.split("//")[-1] else _LDAP_HOST,
    "search_base_dn": os.getenv("LDAP_BASE_DN", "dc=pdmh,dc=hospital,dc=local"),
    "admin_bind_dn": os.getenv("LDAP_ADMIN_DN", "cn=admin,dc=pdmh,dc=hospital,dc=local"),
    "admin_bind_pw": os.getenv("LDAP_ADMIN_PASSWORD", ""),
    "users_ou": "ou=users",
    "attr_mail": "mail",
    "attr_uid": "uid",
    "attr_given_name": "givenName",
    "attr_sn": "sn",
}


def _get_ldap_config() -> dict:
    """Return LDAP config dict from the ``ldap_config`` table (single row).

    Falls back to hardcoded defaults when no configuration has been saved
    yet or when the table is missing.
    """
    try:
        conn = get_db()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM ldap_config WHERE id = 1")
            row = cursor.fetchone()
        finally:
            conn.close()
    except Exception:
        row = None

    if row:
        return {
            "ldap_server":     row['ldap_server'] or _DEFAULTS["ldap_server"],
            "search_base_dn":  row['search_base_dn'] or _DEFAULTS["search_base_dn"],
            "admin_bind_dn":   row['admin_bind_dn'] or _DEFAULTS["admin_bind_dn"],
            "admin_bind_pw":   row['admin_bind_pw'] or _DEFAULTS["admin_bind_pw"],
            "users_ou":        _DEFAULTS["users_ou"],
            "attr_mail":       row['attr_mail'] or _DEFAULTS["attr_mail"],
            "attr_uid":        row['attr_uid'] or _DEFAULTS["attr_uid"],
            "attr_given_name": row['attr_given_name'] or _DEFAULTS["attr_given_name"],
            "attr_sn":         row['attr_sn'] or _DEFAULTS["attr_sn"],
        }
    return dict(_DEFAULTS)


# ---------------------------------------------------------------------------
# LDAP Directory Search
# ---------------------------------------------------------------------------

def search_ldap_user_by_email(email: str) -> Optional[dict]:
    """
    Search the LDAP directory for a user with the given email address.

    This is used for:
    - Login: Step 1 of authentication (find the user's DN before bind)
    - Registration: Check if an email already exists in LDAP

    Returns
    -------
    dict or None
        ``{"uid": "...", "email": "...", "first_name": "...", "last_name": "..."}``
        if found, ``None`` otherwise.
    """
    cfg = _get_ldap_config()
    try:
        conn = _admin_bind()
        search_filter = f"({cfg['attr_mail']}={email})"
        search_base = f"{cfg['users_ou']},{cfg['search_base_dn']}"
        conn.search(
            search_base=search_base,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=[
                cfg["attr_uid"],
                cfg["attr_given_name"],
                cfg["attr_sn"],
                cfg["attr_mail"],
            ],
        )
        if not conn.entries:
            conn.unbind()
            return None

        entry = conn.entries[0]
        uid_attr = cfg["attr_uid"]
        gn_attr  = cfg["attr_given_name"]
        sn_attr  = cfg["attr_sn"]
        uid = entry[uid_attr].value if hasattr(entry, uid_attr) and entry[uid_attr] else email.split("@")[0]
        first_name = entry[gn_attr].value if hasattr(entry, gn_attr) and entry[gn_attr] else ""
        last_name  = entry[sn_attr].value if hasattr(entry, sn_attr) and entry[sn_attr] else ""

        conn.unbind()
        return {
            "uid": uid,
            "email": email,
            "first_name": first_name,
            "last_name": last_name,
        }
    except Exception as e:
        logger.error("[LDAP Search Failure] email=%s: %s", email, e)
        return None


# ---------------------------------------------------------------------------
# Credential Verification (User-facing bind)
# ---------------------------------------------------------------------------

def verify_user_credentials_with_ldap(user_email: str, password: str) -> bool:
    """
    Attempt an LDAP bind with the user's own credentials.

    Searches LDAP by email to discover the user's DN, then binds
    with that DN and the provided password.

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
    cfg = _get_ldap_config()

    ldap_user = search_ldap_user_by_email(user_email)
    if ldap_user is None:
        logger.warning("[LDAP Auth Failure] user not found in directory: %s", user_email)
        return False

    uid = ldap_user["uid"]
    server = Server(cfg["ldap_server"], get_info=ALL)
    user_dn = f"uid={uid},{cfg['users_ou']},{cfg['search_base_dn']}"

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
    Fetch user application profile from the local PostgreSQL database.

    LDAP is the identity provider; PostgreSQL only stores role, permissions,
    and employee metadata.

    Returns
    -------
    dict or None
        Profile dictionary or ``None`` if the user has no local profile.
    """
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, email, first_name, last_name,
                   company_id, role,
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
    finally:
        conn.close()


def get_ldap_user_by_email(email: str) -> Optional[dict]:
    """
    Search LDAP directory for a user with the given email.

    Returns
    -------
    dict or None
        LDAP profile dictionary or ``None`` if not found.
    """
    cfg = _get_ldap_config()
    try:
        conn = _admin_bind()
        search_filter = f"({cfg['attr_mail']}={email})"
        search_base = f"{cfg['users_ou']},{cfg['search_base_dn']}"
        conn.search(
            search_base=search_base,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=[cfg["attr_uid"], cfg["attr_given_name"], cfg["attr_sn"], cfg["attr_mail"]],
        )
        if not conn.entries:
            conn.unbind()
            return None

        entry = conn.entries[0]
        uid_attr = cfg["attr_uid"]
        gn_attr  = cfg["attr_given_name"]
        sn_attr  = cfg["attr_sn"]
        username = entry[uid_attr].value if hasattr(entry, uid_attr) and entry[uid_attr] else email.split("@")[0]
        first_name = entry[gn_attr].value if hasattr(entry, gn_attr) and entry[gn_attr] else ""
        last_name  = entry[sn_attr].value if hasattr(entry, sn_attr) and entry[sn_attr] else ""

        conn.unbind()
        return {
            "username": username,
            "first_name": first_name,
            "last_name": last_name,
            "email": email
        }
    except Exception as e:
        logger.error("[LDAP Search Failure] email=%s: %s", email, e)
        return None



def authenticate_ldap(email: str, password: str) -> AuthResult:
    """
    Authenticate a user against LDAP (the sole identity provider) and
    fetch their application profile from PostgreSQL.

    Login flow:
        1. Search LDAP by email to discover the user.
        2. Authenticate via LDAP bind.
        3. On success, fetch role and permissions from PostgreSQL
           using the user's ldap_uid.

    PostgreSQL is NEVER checked for account existence or credentials.

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
    # Step 1 — Search LDAP for the user by email
    ldap_user = search_ldap_user_by_email(email)
    if ldap_user is None:
        return AuthResult(
            status="failed",
            message="Invalid email or password.",
        )

    # Step 2 — Authenticate via LDAP bind
    if not verify_user_credentials_with_ldap(email, password):
        return AuthResult(
            status="failed",
            message="Invalid email or password.",
        )

    # Step 3 — Fetch role and permissions from PostgreSQL using ldap_uid
    ldap_uid = ldap_user["uid"]
    user = get_user_profile_by_email(email)
    if user is None:
        logger.warning(
            "LDAP auth succeeded but no local profile found for %s (ldap_uid=%s)",
            email, ldap_uid,
        )
        return AuthResult(
            status="failed",
            message="User account not found. Please contact the administrator.",
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
    cfg = _get_ldap_config()
    server = Server(cfg["ldap_server"], get_info=ALL)
    conn = Connection(
        server,
        user=cfg["admin_bind_dn"],
        password=cfg["admin_bind_pw"],
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

    Raises
    ------
    ldap3.core.exceptions.LDAPException
        If the LDAP operation fails (bind error, add error, etc.).
        The caller is expected to catch this and provide user-facing feedback.
    """
    cfg = _get_ldap_config()
    user_dn = f"uid={username},{cfg['users_ou']},{cfg['search_base_dn']}"

    logger.info(
        "[LDAP CREATE] Attempting to add user: dn=%s, uid=%s, cn='%s %s', mail=%s, objectClass=['top','person','organizationalPerson','inetOrgPerson']",
        user_dn, username, first_name, last_name, email,
    )

    conn = _admin_bind()

    attributes = {
        cfg["attr_uid"]: str(username),
        "cn": str(f"{first_name} {last_name}"),
        cfg["attr_sn"]: str(last_name),
        cfg["attr_given_name"]: str(first_name),
        cfg["attr_mail"]: str(email),
        "userPassword": str(password),
    }

    result = conn.add(
        dn=user_dn,
        object_class=["top", "person", "organizationalPerson", "inetOrgPerson"],
        attributes=attributes,
    )
    conn.unbind()

    if result:
        logger.info("[LDAP CREATE] Success: user added at %s", user_dn)
        return True
    else:
        ldap_result = getattr(conn, 'result', 'No result info')
        logger.error(
            "[LDAP CREATE] Failed for %s: server returned False, result=%s",
            user_dn, ldap_result,
        )
        raise Exception(
            f"LDAP directory rejected the add operation for {user_dn}. "
            f"Server result: {ldap_result}"
        )


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
    cfg = _get_ldap_config()
    user_dn = f"uid={username},{cfg['users_ou']},{cfg['search_base_dn']}"

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
