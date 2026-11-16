import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.core.security import generate_secure_token, hash_secure_token
from app.models import (
    AuditEvent,
    AuthToken,
    OrganizationMembership,
    User,
)


TOKEN_LIFETIME = timedelta(hours=24)


def issue_email_verification(
    db: Session,
    user_id: uuid.UUID,
) -> str:
    """
    Create a verification token inside the caller's transaction.

    The raw token must be passed only to a trusted delivery
    mechanism. Never log or persist the raw token.
    """
    user = db.get(User, user_id, with_for_update=True)

    if user is None or not user.is_active:
        raise ValueError("User is unavailable")

    if user.email_verified_at is not None:
        raise ValueError("Email already verified")

    raw_token = generate_secure_token()

    record = AuthToken(
        user_id=user.id,
        purpose="email_verification",
        token_hash=hash_secure_token(raw_token),
        expires_at=datetime.now(timezone.utc) + TOKEN_LIFETIME,
    )

    db.add(record)
    db.flush()

    return raw_token


def consume_email_verification(
    db: Session,
    raw_token: str,
) -> bool:
    """
    Verify and consume a token atomically.

    The caller must commit the surrounding transaction.
    Returns False for invalid, expired, consumed, or
    already-verified credentials.
    """
    if not raw_token or len(raw_token) > 256:
        return False

    token_digest = hash_secure_token(raw_token)
    now = datetime.now(timezone.utc)

    token_record = db.scalar(
        select(AuthToken)
        .where(
            AuthToken.token_hash == token_digest,
            AuthToken.purpose == "email_verification",
        )
        .with_for_update()
    )

    if token_record is None:
        return False

    if token_record.consumed_at is not None:
        return False

    if token_record.expires_at <= now:
        return False

    user = db.get(
        User,
        token_record.user_id,
        with_for_update=True,
    )

    if user is None or not user.is_active:
        return False

    if user.email_verified_at is not None:
        return False

    user.email_verified_at = now
    token_record.consumed_at = now

    # Activate registration-created owner memberships.
    # Other invited team memberships remain untouched.
    db.execute(
        update(OrganizationMembership)
        .where(
            OrganizationMembership.user_id == user.id,
            OrganizationMembership.role == "owner",
            OrganizationMembership.status == "invited",
        )
        .values(status="active")
    )

    db.add(
        AuditEvent(
            organization_id=None,
            actor_user_id=user.id,
            action="identity.email_verified",
            subject_type="user",
            subject_id=str(user.id),
            payload={},
        )
    )

    db.flush()
    return True