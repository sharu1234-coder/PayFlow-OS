from datetime import datetime, timezone

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.core.security import hash_secure_token
from app.models import User, UserSession


def valid_token_digest(raw_token: str | None) -> str | None:
    if (
        raw_token is None
        or len(raw_token) < 32
        or len(raw_token) > 256
    ):
        return None

    return hash_secure_token(raw_token)


def get_authenticated_user(
    db: Session,
    raw_token: str | None,
) -> User | None:
    token_digest = valid_token_digest(raw_token)

    if token_digest is None:
        return None

    now = datetime.now(timezone.utc)

    return db.scalar(
        select(User)
        .join(
            UserSession,
            UserSession.user_id == User.id,
        )
        .where(
            UserSession.token_hash == token_digest,
            UserSession.revoked_at.is_(None),
            UserSession.expires_at > now,
            User.is_active.is_(True),
            User.email_verified_at.is_not(None),
        )
    )


def revoke_current_session(
    db: Session,
    raw_token: str | None,
) -> None:
    token_digest = valid_token_digest(raw_token)

    if token_digest is None:
        return

    db.execute(
        update(UserSession)
        .where(
            UserSession.token_hash == token_digest,
            UserSession.revoked_at.is_(None),
        )
        .values(revoked_at=datetime.now(timezone.utc))
    )
