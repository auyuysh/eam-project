"""
LDAP / Active Directory Authentication
=======================================

This module will provide integration with enterprise LDAP or
Active Directory servers for credential verification.

Status: NOT YET IMPLEMENTED — all functions are placeholders.

Planned capabilities
---------------------
- Authenticate users against an LDAP / AD server.
- Test LDAP server connectivity.
- Load LDAP configuration from application settings.
"""

from auth.models import AuthResult


def authenticate_ldap(username: str, password: str) -> AuthResult:
    """
    Authenticate a user against the configured LDAP / AD server.

    Parameters
    ----------
    username : str
        The login username (often an email or UPN for AD).
    password : str
        The plain-text password.

    Returns
    -------
    AuthResult
        A standardised authentication result.

    Raises
    ------
    NotImplementedError
        Always — this provider is not yet implemented.
    """
    raise NotImplementedError(
        "LDAP authentication is not yet implemented. "
        "Configure auth_settings to use LOCAL until this module is ready."
    )


def test_connection() -> bool:
    """
    Test connectivity to the configured LDAP / AD server.

    Returns
    -------
    bool
        ``True`` if the connection is successful.

    Raises
    ------
    NotImplementedError
        Always — this provider is not yet implemented.
    """
    raise NotImplementedError(
        "LDAP connection testing is not yet implemented."
    )


def load_configuration() -> dict:
    """
    Load LDAP connection settings from the application configuration.

    Expected keys (future):
        - LDAP_SERVER        e.g. ``ldap://ad.example.com``
        - LDAP_PORT          e.g. ``389`` or ``636`` (LDAPS)
        - LDAP_BASE_DN       e.g. ``dc=example,dc=com``
        - LDAP_BIND_DN       Service account DN
        - LDAP_BIND_PASSWORD Service account password
        - LDAP_USE_SSL       ``True`` / ``False``
        - LDAP_USER_FILTER   e.g. ``(&(objectClass=user)(sAMAccountName={}))``

    Returns
    -------
    dict
        A dictionary of LDAP settings.

    Raises
    ------
    NotImplementedError
        Always — this provider is not yet implemented.
    """
    raise NotImplementedError(
        "LDAP configuration loading is not yet implemented."
    )
