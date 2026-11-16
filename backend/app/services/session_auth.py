from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import (
    generate_secure_token,
    hash_password,
    hash_secure_token,
    verify_password,
)
from app.models import AuditEvent, User, UserSession


SESSION_LIFETIME_SECONDS = 8 * 60 * 60

# Do a password-hash verification even when an email
# doesn't exist, to reduce obvious timing differences.
_DUMMY_PASSWORD_HASH = hash_password(
    "PayFlow-Internal-Dummy-Password-Only"
)


def authenticate_and_create_session(
    db: Session,
    email: str,
    password: str,
) -> str | None:
    user = db.scalar(
        select(User).where(User.email == email.lower())
    )

    stored_hash = (
        user.password_hash
        if user is not None
        else _DUMMY_PASSWORD_HASH
    )

    valid_password = verify_password(
        password,
        stored_hash,
    )

    if (
        user is None
        or not valid_password
        or not user.is_active
        or user.email_verified_at is None
    ):
        return None

    raw_token = generate_secure_token()

    db.add(
        UserSession(
            user_id=user.id,
            token_hash=hash_secure_token(raw_token),
            expires_at=(
                datetime.now(timezone.utc)
                + timedelta(seconds=SESSION_LIFETIME_SECONDS)
            ),
        )
    )

    db.add(
        AuditEvent(
            organization_id=None,
            actor_user_id=user.id,
            action="identity.login",
            subject_type="user",
            subject_id=str(user.id),
            payload={},
        )
    )

    db.flush()

    return raw_token
