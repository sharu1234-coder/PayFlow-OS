import hashlib
import hmac
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models import AuditEvent


MAX_FAILED_ATTEMPTS = 5
FAILURE_WINDOW = timedelta(minutes=15)

FAILED_ACTION = "identity.login_failed"
FAILED_SUBJECT_TYPE = "login_identifier"


class LoginRateLimited(Exception):
    pass


def _login_digest(email: str) -> bytes:
    secret = (
        get_settings()
        .login_throttle_secret
        .get_secret_value()
    )

    if len(secret) < 32:
        raise RuntimeError(
            "Login throttle secret is too short"
        )

    normalized = email.strip().lower()

    return hmac.new(
        secret.encode("utf-8"),
        (
            "payflow.login.identifier.v1:"
            + normalized
        ).encode("utf-8"),
        hashlib.sha256,
    ).digest()


def login_fingerprint(email: str) -> str:
    # Truncated, keyed digest: no plain email address
    # appears in the failed-login audit event.
    return _login_digest(email)[:16].hex()


def enforce_login_attempt_limit(
    db: Session,
    email: str,
) -> str:
    """
    Must be called inside the login transaction.

    PostgreSQL transaction-scoped advisory locks serialize
    attempts for the same normalized login identifier,
    even when multiple application workers are running.
    """
    digest = _login_digest(email)
    fingerprint = digest[:16].hex()

    lock_key = int.from_bytes(
        digest[:8],
        byteorder="big",
        signed=True,
    )

    db.execute(
        text("SELECT pg_advisory_xact_lock(:lock_key)"),
        {"lock_key": lock_key},
    )

    cutoff = datetime.now(timezone.utc) - FAILURE_WINDOW

    recent_failures = db.scalar(
        select(func.count(AuditEvent.id))
        .where(
            AuditEvent.action == FAILED_ACTION,
            AuditEvent.subject_type == FAILED_SUBJECT_TYPE,
            AuditEvent.subject_id == fingerprint,
            AuditEvent.created_at >= cutoff,
        )
    )

    if recent_failures >= MAX_FAILED_ATTEMPTS:
        raise LoginRateLimited()

    return fingerprint


def record_failed_login(
    db: Session,
    fingerprint: str,
) -> None:
    # Caller must already hold the identifier's
    # transaction-scoped advisory lock.
    db.add(
        AuditEvent(
            organization_id=None,
            actor_user_id=None,
            action=FAILED_ACTION,
            subject_type=FAILED_SUBJECT_TYPE,
            subject_id=fingerprint,
            payload={"result": "authentication_failed"},
        )
    )

    db.flush()
