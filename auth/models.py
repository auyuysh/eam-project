"""
Shared Authentication Models
==============================

Data classes and types used across the authentication package.

Placing shared types here avoids circular imports between modules
(e.g. ``auth_service`` ↔ ``local_auth``).
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class AuthResult:
    """
    Uniform return type for every authentication attempt.

    Attributes
    ----------
    status : str
        One of ``'pending'``, ``'authenticated'``, ``'mfa_required'``,
        or ``'failed'``.
    user : dict or None
        User record dictionary when authentication succeeds.
    message : str
        Human-readable message for the caller / UI.
    mfa_required : bool
        ``True`` when the user must complete OTP verification.
    user_id : int or None
        Primary key of the authenticated user.
    username : str or None
        Username of the authenticated user.
    """

    status: str = "pending"
    user: Optional[dict] = None
    message: str = ""
    mfa_required: bool = False
    user_id: Optional[int] = None
    username: Optional[str] = None
