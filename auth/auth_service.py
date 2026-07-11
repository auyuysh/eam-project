"""
Central Authentication Controller
==================================

This module is the single entry-point for all authentication requests.

It NEVER:
    - verifies passwords directly
    - sends emails directly
    - creates OTPs directly
    - manages sessions directly

It ONLY:
    - reads the configured authentication provider
    - delegates credential verification to the correct provider
    - coordinates the MFA (OTP) flow when required

Usage (future) — called from server.py login route::

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
from auth.local_auth import authenticate_local, get_user_by_id as _local_get_user_by_id
from auth.models import AuthResult


# ---------------------------------------------------------------------------
# Provider delegation helpers
# ---------------------------------------------------------------------------

def _authenticate_provider(email: str, password: str) -> AuthResult:
    """
    Delegate credential verification to the configured provider.

    Returns an AuthResult with status 'authenticated' or 'failed'.
    """
    provider = auth_settings.get_auth_provider()

    if provider == "LDAP":
        from auth.ldap_auth import authenticate_ldap
        return authenticate_ldap(email, password)

    if provider == "LOCAL":
        return authenticate_local(email, password)

    return AuthResult(
        status="failed",
        message=f"Unknown authentication provider: {provider}",
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def authenticate_user(email: str, password: str) -> AuthResult:
    """
    Authenticate a user against the configured provider.

    Flow:
        1. Verify credentials via provider (Local or LDAP).
        2. If credentials are valid, determine whether MFA (OTP) is required.
        3. If MFA is enabled, mark the result as 'mfa_required' so the caller
           can trigger OTP generation and redirect to the OTP verification page.
        4. If MFA is not enabled, mark the result as 'authenticated'.

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
    # Step 1 — verify credentials
    result = _authenticate_provider(email, password)

    if result.status != "authenticated":
        log_login_failure(email, auth_settings.get_auth_provider(), result.message)
        return result

    # Step 2 — check whether MFA (OTP) is required
    mfa_enabled = auth_settings.is_mfa_enabled()

    if mfa_enabled:
        # Step 3a — trigger OTP generation and mark as MFA required
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
        # Step 3b — no MFA, authentication complete
        result.status = "authenticated"
        log_login_success(email, auth_settings.get_auth_provider())
        result.message = "Authentication successful."

    return result


def get_user_by_id(user_id: int) -> Optional[dict]:
    """
    Retrieve a user record by primary key.

    This is a thin wrapper so that callers do not need to know which
    provider module to import.
    """
    return _local_get_user_by_id(user_id)
