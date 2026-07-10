"""
Authentication Module
=====================

Enterprise-grade authentication system for the EAM application.

This package provides a modular, provider-agnostic authentication layer
that supports pluggable backends (Local, LDAP/AD) and multi-factor
authentication via email OTP.

Architecture
------------
    User --> auth_service --> Provider (Local | LDAP)
                            --> OTP Service (generate/verify)
                            --> Email Service (deliver OTP)
                            --> Audit Service (log events)
                            --> Session

Modules
-------
- auth_service    : Central orchestrator — routes auth to the correct provider.
- local_auth      : Local database (username + password_hash) authentication.
- ldap_auth       : LDAP / Active Directory authentication (future).
- otp_service     : OTP generation, storage, verification, and cleanup.
- email_service   : Email delivery abstraction (Flask-Mail).
- auth_settings   : Reads the active authentication provider configuration.
- database        : Centralised database connection factory.
- models          : Shared data classes (AuthResult).
- audit_service   : Authentication audit event logging.
"""

from auth.auth_service import authenticate_user, get_user_by_id
from auth.auth_settings import get_auth_provider, is_mfa_enabled
from auth.email_service import (
    send_email,
    send_otp_email,
    send_welcome_email,
    send_password_reset_email,
    mask_email,
)
from auth.local_auth import authenticate_local, get_user
from auth.models import AuthResult
from auth.otp_service import generate_otp, verify_otp

__all__ = [
    "AuthResult",
    "authenticate_user",
    "authenticate_local",
    "get_auth_provider",
    "get_user",
    "get_user_by_id",
    "generate_otp",
    "is_mfa_enabled",
    "mask_email",
    "send_email",
    "send_otp_email",
    "send_password_reset_email",
    "send_welcome_email",
    "verify_otp",
]
