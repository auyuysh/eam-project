"""
Authentication Settings
========================

Single source of truth for ALL authentication configuration.

This module reads values from environment variables with sensible
hardcoded defaults.  No database access is performed yet.

Configuration sources (future)
-------------------------------
Settings will ultimately be read from the ``authentication_settings``
database table, with environment-variable overrides.

Planned schema for ``authentication_settings`` (reference only)::

    CREATE TABLE authentication_settings (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        setting_key     TEXT    UNIQUE NOT NULL,
        setting_value   TEXT    NOT NULL,
        description     TEXT,
        updated_at      TEXT    NOT NULL
    );

Status: Returns hardcoded defaults / environment variable overrides only.
"""

import os
from typing import Optional


# ---------------------------------------------------------------------------
# Default constants
# ---------------------------------------------------------------------------

_DEFAULTS = {
    "AUTH_PROVIDER": "LOCAL",
    "MFA_ENABLED": False,
    "OTP_EXPIRY_MINUTES": 10,
    "OTP_LENGTH": 6,
    "OTP_RESEND_DELAY_SECONDS": 30,
    "OTP_MAX_ATTEMPTS": 5,
    "OTP_MAX_RESEND_ATTEMPTS": 3,
    "SESSION_TIMEOUT_MINUTES": 30,
}


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _env_int(key: str) -> int:
    """Read an integer from an environment variable, falling back to default."""
    value = os.environ.get(key, "")
    try:
        return int(value)
    except (ValueError, TypeError):
        return _DEFAULTS[key]


def _env_bool(key: str) -> bool:
    """Read a boolean from an environment variable, falling back to default."""
    value = os.environ.get(key, "")
    if not value:
        return _DEFAULTS[key]
    return value.lower() in ("true", "1", "yes")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_auth_provider() -> str:
    """
    Return the currently configured authentication provider.

    Returns
    -------
    str
        ``'LOCAL'`` or ``'LDAP'``.

    Environment variable: ``AUTH_PROVIDER``
    Default: ``'LOCAL'``
    """
    raw = os.environ.get("AUTH_PROVIDER")
    provider = (raw if raw is not None else _DEFAULTS["AUTH_PROVIDER"]).upper()
    return provider


def is_mfa_enabled() -> bool:
    """
    Check whether multi-factor authentication (email OTP) is required.

    Returns
    -------
    bool
        ``True`` if MFA is enabled.

    Environment variable: ``MFA_ENABLED``
    Default: ``False``
    """
    return _env_bool("MFA_ENABLED")


def get_otp_expiry_minutes() -> int:
    """
    Return the OTP validity period in minutes.

    Returns
    -------
    int
        Number of minutes an OTP remains valid.

    Environment variable: ``OTP_EXPIRY_MINUTES``
    Default: ``5``
    """
    return _env_int("OTP_EXPIRY_MINUTES")


def get_otp_length() -> int:
    """
    Return the length of generated OTP codes.

    Returns
    -------
    int
        Number of digits in an OTP code.

    Environment variable: ``OTP_LENGTH``
    Default: ``6``
    """
    return _env_int("OTP_LENGTH")


def get_resend_delay_seconds() -> int:
    """
    Return the minimum delay between OTP resend requests, in seconds.

    Returns
    -------
    int
        Seconds a user must wait before requesting a new OTP.

    Environment variable: ``OTP_RESEND_DELAY_SECONDS``
    Default: ``30``
    """
    return _env_int("OTP_RESEND_DELAY_SECONDS")


def get_max_otp_attempts() -> int:
    """
    Return the maximum number of failed OTP verification attempts
    allowed before the OTP is invalidated.

    Returns
    -------
    int
        Maximum allowed attempts.

    Environment variable: ``OTP_MAX_ATTEMPTS``
    Default: ``5``
    """
    return _env_int("OTP_MAX_ATTEMPTS")


def get_max_resend_attempts() -> int:
    """
    Return the maximum number of OTP resend requests allowed
    per authentication session.

    Returns
    -------
    int
        Maximum allowed resend requests.

    Environment variable: ``OTP_MAX_RESEND_ATTEMPTS``
    Default: ``3``
    """
    return _env_int("OTP_MAX_RESEND_ATTEMPTS")


def get_session_timeout_minutes() -> int:
    """
    Return the session inactivity timeout in minutes.

    Returns
    -------
    int
        Minutes of inactivity before a session expires.

    Environment variable: ``SESSION_TIMEOUT_MINUTES``
    Default: ``30``
    """
    return _env_int("SESSION_TIMEOUT_MINUTES")


def get_setting(key: str, default: Optional[str] = None) -> Optional[str]:
    """
    Retrieve a generic authentication setting by key.

    Parameters
    ----------
    key : str
        The setting name (e.g. ``'auth_provider'``, ``'mfa_enabled'``).
    default : str, optional
        Fallback value if the setting is not found.

    Returns
    -------
    str or None
        The setting value, or the provided default.

    Notes
    -----
    Currently reads from environment variables only.
    Will read from ``authentication_settings`` table in the future.
    """
    return os.environ.get(key, default)
