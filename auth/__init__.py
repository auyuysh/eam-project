"""
Authentication Module
====================

Enterprise-grade authentication system for the EAM application.

LDAP is the **sole identity provider**.  PostgreSQL only stores
application profiles (role, permissions, employee metadata).

Architecture
------------
    User --> auth_service --> LDAP Provider (search + bind)
                            --> OTP Service (generate/verify)
                            --> Email Service (deliver OTP)
                            --> Audit Service (log events)
                            --> PostgreSQL (role / permissions only)
                            --> Session

Modules
-------
- auth_service    : Central orchestrator — delegates auth to LDAP.
- ldap_auth       : LDAP directory authentication (sole identity provider).
- local_auth      : PostgreSQL profile fetcher (role, permissions, metadata).
- otp_service     : OTP generation, storage, verification, and cleanup.
- email_service   : Email delivery abstraction (Flask-Mail).
- auth_settings   : Reads the active authentication configuration.
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
    get_smtp_config,
    apply_smtp_config,
)
from auth.ldap_auth import (
    search_ldap_user_by_email,
    verify_user_credentials_with_ldap,
    create_ldap_user,
    update_ldap_password,
    ldap_bind_as_user,
    get_user_profile_by_email,
    get_ldap_user_by_email,
    parse_ldap_url,
    validate_port,
    build_connection,
)
from auth.local_auth import get_user, get_user_by_id as _local_get_user_by_id, get_user_by_ldap_uid
from auth.models import AuthResult
from auth.otp_service import generate_otp, verify_otp

__all__ = [
    "AuthResult",
    "authenticate_user",
    "get_auth_provider",
    "get_smtp_config",
    "apply_smtp_config",
    "get_user",
    "get_user_by_id",
    "get_user_by_ldap_uid",
    "generate_otp",
    "is_mfa_enabled",
    "mask_email",
    "send_email",
    "send_otp_email",
    "send_password_reset_email",
    "send_welcome_email",
    "verify_otp",
    "search_ldap_user_by_email",
    "get_user_profile_by_email",
    "get_ldap_user_by_email",
]
