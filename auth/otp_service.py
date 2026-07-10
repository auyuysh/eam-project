"""
One-Time Password (OTP) Service
================================

Handles generation, storage, verification, and cleanup of email-based
one-time passwords used as the second authentication factor or for
email verification after registration.

All configuration values (OTP length, expiry, limits) are read from
``auth_settings`` — no constants are hardcoded in this module.

Database table
--------------
``otp_codes`` stores issued OTPs with metadata for verification and expiry.
"""

import random
import string
from datetime import datetime, timedelta, timezone

from auth import auth_settings
from auth.database import get_db


def _now_utc():
    return datetime.now(timezone.utc)


def generate_otp(user_id: int) -> str:
    """
    Generate a random numeric OTP for the given user.

    The OTP length is determined by ``auth_settings.get_otp_length()``.

    Parameters
    ----------
    user_id : int
        The primary key of the user requesting an OTP.

    Returns
    -------
    str
        A numeric string of the configured length.
    """
    length = auth_settings.get_otp_length()
    return "".join(random.choices(string.digits, k=length))


def save_otp(user_id: int, otp: str, purpose: str = "login") -> bool:
    """
    Persist an OTP record in the ``otp_codes`` table.

    Any previously unused OTPs for this user and purpose are invalidated
    first to ensure only one active OTP exists at a time.

    Parameters
    ----------
    user_id : int
        The primary key of the user.
    otp : str
        The OTP code to store.
    purpose : str
        The purpose of the OTP (``'login'`` or ``'registration'``).

    Returns
    -------
    bool
        ``True`` if saved successfully.
    """
    now = _now_utc()
    expires_at = now + timedelta(minutes=auth_settings.get_otp_expiry_minutes())

    conn = get_db()
    try:
        cursor = conn.cursor()

        # Invalidate any previous unused OTPs for this user and purpose
        cursor.execute(
            "UPDATE otp_codes SET used = 1 WHERE user_id = ? AND purpose = ? AND used = 0",
            (user_id, purpose),
        )

        cursor.execute(
            """
            INSERT INTO otp_codes (user_id, otp_code, purpose, created_at, expires_at, used, attempts)
            VALUES (?, ?, ?, ?, ?, 0, 0)
            """,
            (user_id, otp, purpose, now.isoformat(), expires_at.isoformat()),
        )
        conn.commit()
        return True
    finally:
        conn.close()


def verify_otp(user_id: int, otp: str, purpose: str = "login") -> str:
    """
    Verify that a submitted OTP matches an active, unexpired record.

    If the OTP is valid it is marked as used.  Verification limits are
    governed by ``auth_settings.get_max_otp_attempts()``.

    Parameters
    ----------
    user_id : int
        The primary key of the user.
    otp : str
        The OTP code submitted by the user.
    purpose : str
        The purpose of the OTP (``'login'`` or ``'registration'``).

    Returns
    -------
    str
        ``'valid'`` if the OTP is correct and not expired.
        ``'expired'`` if the OTP has expired.
        ``'used'`` if the OTP was already used.
        ``'max_attempts'`` if max verification attempts exceeded.
        ``'invalid'`` if the OTP code is incorrect.
        ``'not_found'`` if no OTP record exists.
    """
    now = _now_utc()
    max_attempts = auth_settings.get_max_otp_attempts()

    conn = get_db()
    try:
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT id, otp_code, expires_at, used, attempts
            FROM otp_codes
            WHERE user_id = ? AND purpose = ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (user_id, purpose),
        )
        row = cursor.fetchone()

        if row is None:
            return "not_found"

        record_id, stored_code, expires_at_str, used, attempts = row

        # Already used
        if used:
            return "used"

        # Expired
        expires_at = datetime.fromisoformat(expires_at_str)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if now > expires_at:
            return "expired"

        # Already at or over max attempts (guard for re-entry)
        if attempts >= max_attempts:
            cursor.execute(
                "UPDATE otp_codes SET used = 1 WHERE id = ?",
                (record_id,),
            )
            conn.commit()
            return "max_attempts"

        # Increment attempts
        cursor.execute(
            "UPDATE otp_codes SET attempts = attempts + 1 WHERE id = ?",
            (record_id,),
        )
        conn.commit()

        # Check if this attempt hits the limit
        if attempts + 1 >= max_attempts:
            cursor.execute(
                "UPDATE otp_codes SET used = 1 WHERE id = ?",
                (record_id,),
            )
            conn.commit()
            # Still validate the OTP on the last attempt
            if stored_code == otp:
                return "valid"
            return "max_attempts"

        # Incorrect OTP
        if stored_code != otp:
            return "invalid"

        # Valid — mark as used
        cursor.execute(
            "UPDATE otp_codes SET used = 1 WHERE id = ?",
            (record_id,),
        )
        conn.commit()
        return "valid"
    finally:
        conn.close()


def resend_otp(user_id: int, purpose: str = "login") -> str:
    """
    Invalidate any existing OTP for the user and issue a new one.

    Enforces a minimum delay between resend requests governed by
    ``auth_settings.get_resend_delay_seconds()`` and a maximum number
    of resend requests per 10-minute window governed by
    ``auth_settings.get_max_resend_attempts()``.

    Parameters
    ----------
    user_id : int
        The primary key of the user.
    purpose : str
        The purpose of the OTP (``'login'`` or ``'registration'``).

    Returns
    -------
    str
        The newly generated OTP code.

    Raises
    ------
    ValueError
        If the resend is rate-limited (too soon after the last OTP)
        or if max resend attempts have been exceeded.
    """
    now = _now_utc()
    delay_seconds = auth_settings.get_resend_delay_seconds()
    max_resend = auth_settings.get_max_resend_attempts()
    window_minutes = 10

    conn = get_db()
    try:
        cursor = conn.cursor()

        # Check the most recent OTP creation time for rate limiting
        cursor.execute(
            """
            SELECT created_at FROM otp_codes
            WHERE user_id = ? AND purpose = ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (user_id, purpose),
        )
        row = cursor.fetchone()

        if row is not None:
            last_created = datetime.fromisoformat(row[0])
            if last_created.tzinfo is None:
                last_created = last_created.replace(tzinfo=timezone.utc)
            elapsed = (now - last_created).total_seconds()
            if elapsed < delay_seconds:
                remaining = int(delay_seconds - elapsed)
                raise ValueError(
                    f"Please wait {remaining} seconds before requesting a new OTP."
                )

        # Count resends within the last 10-minute window
        window_start = now - timedelta(minutes=window_minutes)
        cursor.execute(
            """
            SELECT COUNT(*) FROM otp_codes
            WHERE user_id = ? AND purpose = ? AND created_at >= ?
            """,
            (user_id, purpose, window_start.isoformat()),
        )
        resend_count = cursor.fetchone()[0]
        if resend_count >= max_resend:
            raise ValueError(
                f"Maximum resend limit reached. Please try again after {window_minutes} minutes."
            )

        # Invalidate previous OTPs for this purpose
        cursor.execute(
            "UPDATE otp_codes SET used = 1 WHERE user_id = ? AND purpose = ? AND used = 0",
            (user_id, purpose),
        )
        conn.commit()
    finally:
        conn.close()

    # Generate and save new OTP
    new_otp = generate_otp(user_id)
    save_otp(user_id, new_otp, purpose=purpose)
    return new_otp


def cleanup_expired_otps() -> int:
    """
    Delete all OTP records that have passed their expiry time.

    Intended to be called periodically (e.g. via a scheduled job).

    Returns
    -------
    int
        The number of expired records removed.
    """
    now = _now_utc()

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM otp_codes WHERE expires_at < ?",
            (now.isoformat(),),
        )
        deleted = cursor.rowcount
        conn.commit()
        return deleted
    finally:
        conn.close()
