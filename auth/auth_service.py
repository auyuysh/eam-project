"""
Central Authentication Controller
=================================

This module is the single entry-point for all authentication requests.

LDAP is the **sole identity provider**.  PostgreSQL only stores application
profiles (role, permissions, employee metadata).

It NEVER:
    - verifies passwords directly (LDAP handles this)
    - sends emails directly
    - creates OTPs directly
    - manages sessions directly

It ONLY:
    - delegates credential verification to the LDAP provider
    - coordinates the MFA (OTP) flow when required

Usage — called from server.py login route::

    from auth import authenticate_user

    result = authenticate_user(email, password)
    # result.status  -> "authenticated" | "mfa_required" | "failed"
    # result.user    -> user dict or None
    # result.message -> human-readable message
"""
from typing import Optional

from auth import auth_settings, otp_service
from auth.audit_service import log_login_success, log_login_failure, log_otp_generated
from auth.email_service import send_otp_email
from auth.ldap_auth import authenticate_ldap
from auth.local_auth import get_user_by_id as _local_get_user_by_id
from auth.models import AuthResult


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def authenticate_user(email: str, password: str) -> AuthResult:
    """
    Authenticate a user against the LDAP directory (sole identity provider).

    Flow:
        1. Search LDAP by email to discover the user.
        2. Verify credentials via LDAP bind.
        3. If credentials are valid, fetch role/permissions from PostgreSQL.
        4. If MFA is enabled, trigger OTP generation and mark as 'mfa_required'.
        5. If MFA is not enabled, mark the result as 'authenticated'.

    PostgreSQL is NEVER checked for account existence or credentials.

    Parameters
    ----------
    email : str
        The login email address.
    password : str
        The login password.

    Returns
    -------
    AuthResult
        A standardised result object containing status, user info, and messages.
    """
    # Step 1 + 2 — search LDAP + verify credentials via bind
    result = authenticate_ldap(email, password)

    if result.status != "authenticated":
        log_login_failure(email, "LDAP", result.message)
        return result

    # Step 3 — check whether MFA (OTP) is required
    mfa_enabled = auth_settings.is_mfa_enabled()

    if mfa_enabled:
        if result.user_id is not None:
            otp = otp_service.generate_otp(result.user_id)
            otp_service.save_otp(result.user_id, otp)
            log_otp_generated(result.user_id, "login")

            user_email = result.user.get("email") if result.user else None
            if user_email:
                send_otp_email(user_email, otp)

        result.mfa_required = True
        result.status = "mfa_required"
        result.message = "OTP has been sent to your registered email."
    else:
        result.status = "authenticated"
        log_login_success(email, "LDAP")
        result.message = "Authentication successful."

    return result


def get_user_by_id(user_id: int) -> Optional[dict]:
    """
    Retrieve a user application profile by primary key.

    This is a thin wrapper so that callers do not need to know which
    module to import.  Returns profile data from PostgreSQL only.
    """
    return _local_get_user_by_id(user_id)
