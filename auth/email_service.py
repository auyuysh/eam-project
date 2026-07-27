"""
Email Service
==============

Centralises all email-related functionality under a single module.

Responsibilities
-----------------
- Send generic emails via Flask-Mail.
- Send OTP emails as part of the MFA flow.
- Send welcome/verification emails after registration.
- Mask email addresses for safe display.
- Provide a reusable interface so that other auth modules never
  depend on Flask-Mail directly.

Safety guarantees
------------------
- Every call creates a FRESH ``Message`` instance.
- No global recipient lists, cached Message objects, or shared state.
- Every email is sent to exactly ONE recipient (asserted).
- No ``append()``, ``BCC``, ``CC``, or recipient list mutation.
"""
import logging
from typing import Dict, List, Optional

from flask import current_app
from flask_mail import Message

from auth.database import get_db

logger = logging.getLogger("eam.email")


def get_smtp_config() -> Dict[str, str]:
    """
    Read SMTP settings from the ``system_settings`` database table.

    Falls back to Flask ``app.config`` values (loaded from ``.env``) when
    a key is missing from the database.

    Returns
    -------
    dict
        Keys: ``MAIL_SERVER``, ``MAIL_PORT``, ``MAIL_USERNAME``,
        ``MAIL_PASSWORD``, ``MAIL_DEFAULT_SENDER``.
    """
    defaults = {
        "MAIL_SERVER": current_app.config.get("MAIL_SERVER", ""),
        "MAIL_PORT": str(current_app.config.get("MAIL_PORT", "")),
        "MAIL_USERNAME": current_app.config.get("MAIL_USERNAME", ""),
        "MAIL_PASSWORD": current_app.config.get("MAIL_PASSWORD", ""),
        "MAIL_DEFAULT_SENDER": current_app.config.get("MAIL_DEFAULT_SENDER", ""),
    }
    try:
        conn = get_db()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT key, value FROM system_settings WHERE key IN (%s,%s,%s,%s,%s)",
                tuple(defaults.keys()),
            )
            rows = cursor.fetchall()
            for key, value in rows:
                if value:
                    defaults[key] = value
        finally:
            conn.close()
    except Exception as exc:
        logger.warning("Could not read system_settings for SMTP: %s", exc)
    return defaults


def apply_smtp_config() -> None:
    """
    Load SMTP settings from the database and push them into
    ``current_app.config`` so Flask-Mail uses the latest values.
    """
    cfg = get_smtp_config()
    current_app.config["MAIL_SERVER"] = cfg["MAIL_SERVER"]
    current_app.config["MAIL_PORT"] = int(cfg["MAIL_PORT"] or "0")
    current_app.config["MAIL_USERNAME"] = cfg["MAIL_USERNAME"]
    current_app.config["MAIL_PASSWORD"] = cfg["MAIL_PASSWORD"]
    current_app.config["MAIL_DEFAULT_SENDER"] = cfg["MAIL_DEFAULT_SENDER"]


# ---------------------------------------------------------------------------
# Email masking
# ---------------------------------------------------------------------------

def mask_email(email: str) -> str:
    """
    Mask an email address for safe display.

    Shows the first 1-2 characters of the local part and the full domain.

    Rules:
        - If the local part length >= 4, show first 2 characters.
        - If the local part length < 4, show first 1 character.
        - Remaining characters of the local part are replaced with '*'.

    Examples
    --------
    >>> mask_email("ayush@gmail.com")
    'ay***@gmail.com'
    >>> mask_email("john.doe@hospital.com")
    'jo******@hospital.com'
    >>> mask_email("abc@gmail.com")
    'a**@gmail.com'
    >>> mask_email("ab@gmail.com")
    'a*@gmail.com'
    """
    if "@" not in email:
        return email

    local, domain = email.rsplit("@", 1)

    if len(local) >= 4:
        visible = 2
    else:
        visible = 1

    masked_local = local[:visible] + "*" * (len(local) - visible)
    return f"{masked_local}@{domain}"


# ---------------------------------------------------------------------------
# Generic email sender
# ---------------------------------------------------------------------------

def send_email(
    subject: str,
    recipients: List[str],
    body: str,
    html: Optional[str] = None,
) -> bool:
    """
    Send an email via the application's Flask-Mail configuration.

    Parameters
    ----------
    subject : str
        Email subject line.
    recipients : list of str
        List of recipient email addresses. Must contain exactly one address.
    body : str
        Plain-text body.
    html : str, optional
        HTML body.  If provided, email clients that support HTML will
        render this instead of the plain-text body.

    Returns
    -------
    bool
        ``True`` if the email was sent successfully.

    Raises
    ------
    Exception
        Re-raises any exception from Flask-Mail so the caller can handle it.
    """

    assert len(recipients) == 1, f"send_email must have exactly one recipient, got {len(recipients)}"
    recipient = recipients[0]

    apply_smtp_config()
    if not current_app.config.get("MAIL_SERVER") or not current_app.config.get("MAIL_USERNAME"):
        logger.error("SMTP is not configured. Cannot send email to %s.", recipient)
        raise RuntimeError(
            "Email is not configured. "
            "Please configure SMTP settings in Admin > Email Config."
        )

    logger.info("Preparing to send email: subject='%s', recipient='%s'", subject, recipient)

    msg = Message(
        subject=subject,
        recipients=[recipient],
        body=body,
    )
    if html:
        msg.html = html

    mail = current_app.extensions.get("mail")
    if mail is None:
        logger.error("Flask-Mail is not initialised. Mail(app) was not called or extensions not loaded.")
        raise RuntimeError(
            "Flask-Mail is not initialised. "
            "Ensure Mail(app) is called in server.py."
        )

    logger.info("Flask-Mail instance found. Sending via %s...", current_app.config.get("MAIL_SERVER", "unknown"))
    try:
        mail.send(msg)
        logger.info("Email successfully sent to %s", recipient)
    except Exception as e:
        logger.error("SMTP send failed for %s: %s", recipient, str(e), exc_info=True)
        raise

    return True


# ---------------------------------------------------------------------------
# OTP-specific email (login MFA)
# ---------------------------------------------------------------------------

def send_otp_email(recipient: str, otp_code: str) -> bool:
    """
    Send an OTP code to the user's email address for login verification.

    Parameters
    ----------
    recipient : str
        The user's email address.
    otp_code : str
        The one-time password to include in the email.

    Returns
    -------
    bool
        ``True`` if the email was sent successfully.
    """
    
    from auth import auth_settings

    expiry_minutes = auth_settings.get_otp_expiry_minutes()
    logger.info("Preparing OTP email for %s", recipient)

    subject = "Enterprise Asset Management Login Verification"
    body = (
        f"Your One-Time Password is: {otp_code}\n\n"
        f"This OTP expires in {expiry_minutes} minutes.\n\n"
        "If you did not request this login please ignore this email."
    )

    result = send_email(
        subject=subject,
        recipients=[recipient],
        body=body,
    )
    logger.info("OTP email send result for %s: %s", recipient, result)
    return result


# ---------------------------------------------------------------------------
# Welcome / registration verification email
# ---------------------------------------------------------------------------

def send_welcome_email(
    recipient: str,
    first_name: str,
    otp_code: str,
) -> bool:
    """
    Send a professional HTML welcome email with an OTP for email verification.

    Sent immediately after a user creates an account.  Contains a styled
    verification box displaying the OTP and instructions to verify.

    Parameters
    ----------
    recipient : str
        The user's email address.
    first_name : str
        The user's first name for personalisation.
    otp_code : str
        The one-time password for email verification.

    Returns
    -------
    bool
        ``True`` if the email was sent successfully.
    """
    from auth import auth_settings

    expiry_minutes = auth_settings.get_otp_expiry_minutes()
    logger.info("Preparing welcome email for %s (first_name=%s)", recipient, first_name)

    subject = "Welcome to PDMH Enterprise Asset Management"

    plain_body = (
        f"Hello {first_name},\n\n"
        f"Welcome to PDMH Enterprise Asset Management!\n\n"
        f"Your account has been successfully created. To complete your "
        f"registration, please verify your email address using the following "
        f"One-Time Password (OTP):\n\n"
        f"{otp_code}\n\n"
        f"This OTP expires in {expiry_minutes} minutes.\n\n"
        f"If you did not create this account, please ignore this email.\n\n"
        f"PDMH Enterprise Asset Management - IT Administration Team"
    )

    html_body = f"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin:0;padding:0;background-color:#f4f6f9;font-family:Arial,Helvetica,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f4f6f9;padding:40px 20px;">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background-color:#ffffff;border-radius:10px;overflow:hidden;box-shadow:0 8px 20px rgba(0,0,0,0.10);">
  <!-- Header -->
  <tr>
    <td style="background-color:#0b6efd;padding:30px 40px;text-align:center;">
      <h1 style="margin:0;color:#ffffff;font-size:22px;font-weight:700;letter-spacing:0.5px;">
        PDMH Enterprise Asset Management
      </h1>
    </td>
  </tr>
  <!-- Body -->
  <tr>
    <td style="padding:40px;">
      <h2 style="margin:0 0 10px;color:#222222;font-size:20px;">Hello {first_name},</h2>
      <p style="margin:0 0 20px;color:#555555;font-size:15px;line-height:1.6;">
        Welcome to <strong>PDMH Enterprise Asset Management</strong>! Your account has been
        successfully created. To complete your registration, please verify your email
        address using the One-Time Password (OTP) below.
      </p>

      <!-- OTP Box -->
      <table width="100%" cellpadding="0" cellspacing="0" style="margin:25px 0;">
        <tr>
          <td style="background-color:#eef4ff;border:2px dashed #0b6efd;border-radius:8px;padding:25px;text-align:center;">
            <p style="margin:0 0 8px;color:#555555;font-size:13px;text-transform:uppercase;letter-spacing:1px;">Your Verification Code</p>
            <p style="margin:0;font-size:36px;font-weight:700;color:#0b6efd;letter-spacing:6px;font-family:'Courier New',Courier,monospace;">{otp_code}</p>
          </td>
        </tr>
      </table>

      <p style="margin:0 0 10px;color:#555555;font-size:14px;line-height:1.6;">
        This code expires in <strong>{expiry_minutes} minutes</strong>.
      </p>
      <p style="margin:0;color:#999999;font-size:13px;line-height:1.5;">
        If you did not create this account, please ignore this email. No further
        action is required.
      </p>
    </td>
  </tr>
  <!-- Footer -->
  <tr>
    <td style="background-color:#f8f9fa;padding:20px 40px;text-align:center;border-top:1px solid #e9ecef;">
      <p style="margin:0;color:#888888;font-size:12px;">
        PDMH Enterprise Asset Management &ndash; IT Administration Team
      </p>
    </td>
  </tr>
</table>
</td></tr>
</table>
</body>
</html>
"""

    result = send_email(
        subject=subject,
        recipients=[recipient],
        body=plain_body,
        html=html_body,
    )
    logger.info("Welcome email send result for %s: %s", recipient, result)
    return result


# ---------------------------------------------------------------------------
# Password reset email
# ---------------------------------------------------------------------------

def send_password_reset_email(recipient: str, first_name: str, reset_url: str) -> bool:
    """
    Send a professional HTML password reset email.

    Parameters
    ----------
    recipient : str
        The user's email address.
    first_name : str
        The user's first name for personalisation.
    reset_url : str
        The full URL containing the reset token.

    Returns
    -------
    bool
        ``True`` if the email was sent successfully.
    """
    logger.info("Preparing password reset email for %s (first_name=%s)", recipient, first_name)

    subject = "Reset Your PDMH Enterprise Asset Management Password"

    plain_body = (
        f"Hello {first_name},\n\n"
        f"We received a request to reset the password for your PDMH Enterprise "
        f"Asset Management account. If you did not make this request, please "
        f"ignore this email.\n\n"
        f"To reset your password, click the link below:\n\n"
        f"{reset_url}\n\n"
        f"This link expires in 15 minutes and can only be used once.\n\n"
        f"If you did not request a password reset, no action is needed.\n\n"
        f"PDMH Enterprise Asset Management - IT Administration Team"
    )

    html_body = f"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin:0;padding:0;background-color:#f4f6f9;font-family:Arial,Helvetica,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f4f6f9;padding:40px 20px;">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background-color:#ffffff;border-radius:10px;overflow:hidden;box-shadow:0 8px 20px rgba(0,0,0,0.10);">
  <!-- Header -->
  <tr>
    <td style="background-color:#0b6efd;padding:30px 40px;text-align:center;">
      <h1 style="margin:0;color:#ffffff;font-size:22px;font-weight:700;letter-spacing:0.5px;">
        PDMH Enterprise Asset Management
      </h1>
    </td>
  </tr>
  <!-- Body -->
  <tr>
    <td style="padding:40px;">
      <h2 style="margin:0 0 10px;color:#222222;font-size:20px;">Hello {first_name},</h2>
      <p style="margin:0 0 20px;color:#555555;font-size:15px;line-height:1.6;">
        We received a request to reset the password for your
        <strong>PDMH Enterprise Asset Management</strong> account.
      </p>

      <!-- Reset Button -->
      <table width="100%" cellpadding="0" cellspacing="0" style="margin:25px 0;">
        <tr>
          <td align="center">
            <table cellpadding="0" cellspacing="0">
              <tr>
                <td align="center" style="background-color:#0b6efd;border-radius:6px;">
                  <a href="{reset_url}" target="_blank" style="display:inline-block;padding:14px 40px;color:#ffffff;text-decoration:none;font-size:16px;font-weight:700;border-radius:6px;">
                    Reset Password
                  </a>
                </td>
              </tr>
            </table>
          </td>
        </tr>
      </table>

      <p style="margin:0 0 10px;color:#555555;font-size:14px;line-height:1.6;">
        If the button above does not work, copy and paste the following URL into your browser:
      </p>
      <p style="margin:0 0 20px;color:#0b6efd;font-size:13px;line-height:1.5;word-break:break-all;">
        {reset_url}
      </p>

      <p style="margin:0 0 10px;color:#555555;font-size:14px;line-height:1.6;">
        This reset link expires in <strong>15 minutes</strong> and can only be used once.
      </p>
      <p style="margin:0;color:#999999;font-size:13px;line-height:1.5;">
        If you did not request a password reset, please ignore this email. No further
        action is required.
      </p>
    </td>
  </tr>
  <!-- Footer -->
  <tr>
    <td style="background-color:#f8f9fa;padding:20px 40px;text-align:center;border-top:1px solid #e9ecef;">
      <p style="margin:0;color:#888888;font-size:12px;">
        PDMH Enterprise Asset Management &ndash; IT Administration Team
      </p>
    </td>
  </tr>
</table>
</td></tr>
</table>
</body>
</html>
"""

    logger.info("Calling send_email for password reset to %s", recipient)
    result = send_email(
        subject=subject,
        recipients=[recipient],
        body=plain_body,
        html=html_body,
    )
    logger.info("send_email returned %s for password reset to %s", result, recipient)
    return result
