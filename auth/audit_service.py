import logging

logger = logging.getLogger("eam.auth.audit")


def log_registration_request(email: str, username: str) -> None:
    logger.info("Registration request: email=%s, username=%s", email, username)


def log_pending_registration_created(pending_id: int, email: str, username: str) -> None:
    logger.info("Pending registration created: id=%s, email=%s, username=%s", pending_id, email, username)


def log_otp_generated(user_id: int, purpose: str) -> None:
    logger.info("OTP generated: user_id=%s, purpose=%s", user_id, purpose)


def log_verification_email_sent(recipient: str, purpose: str) -> None:
    logger.info("Verification email sent: recipient=%s, purpose=%s", recipient, purpose)


def log_otp_verified(user_id: int, purpose: str) -> None:
    logger.info("OTP verified: user_id=%s, purpose=%s", user_id, purpose)


def log_user_created_from_pending(user_id: int, email: str, username: str) -> None:
    logger.info("User created from pending registration: user_id=%s, email=%s, username=%s", user_id, email, username)


def log_login_success(username: str, provider: str) -> None:
    logger.info("Login success: username=%s, provider=%s", username, provider)


def log_login_failure(username: str, provider: str, reason: str) -> None:
    logger.warning("Login failure: username=%s, provider=%s, reason=%s", username, provider, reason)


def log_otp_success(user_id: int, purpose: str) -> None:
    logger.info("OTP success: user_id=%s, purpose=%s", user_id, purpose)


def log_otp_failure(user_id: int, purpose: str, reason: str) -> None:
    logger.warning("OTP failure: user_id=%s, purpose=%s, reason=%s", user_id, purpose, reason)


def log_ldap_failure(username: str, reason: str) -> None:
    logger.warning("LDAP failure: username=%s, reason=%s", username, reason)


def log_password_reset_requested(email: str) -> None:
    logger.info("Password reset requested: email=%s", email)


def log_password_updated(user_id: int) -> None:
    logger.info("Password updated: user_id=%s", user_id)
