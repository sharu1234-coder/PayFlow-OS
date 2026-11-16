from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import AuthToken, User
from app.services.email_verification import issue_email_verification


RESEND_COOLDOWN = timedelta(minutes=2)
DAILY_TOKEN_LIMIT = 5


def prepare_verification_resend(
    db: Session,
    email: str,
) -> str | None:
    """
    Called inside a transaction.

    Lock the user row to serialize simultaneous resend requests.
    Return None when the account is ineligible or rate-limited.
    """
    user = db.scalar(
        select(User)
        .where(User.email == email)
        .with_for_update()
    )

    if user is None:
        return None

    if not user.is_active or user.email_verified_at is not None:
        return None

    now = datetime.now(timezone.utc)

    latest_issued = db.scalar(
        select(func.max(AuthToken.created_at))
        .where(
            AuthToken.user_id == user.id,
            AuthToken.purpose == "email_verification",
        )
    )

    if (
        latest_issued is not None
        and latest_issued > now - RESEND_COOLDOWN
    ):
        return None

    issued_in_day = db.scalar(
        select(func.count(AuthToken.id))
        .where(
            AuthToken.user_id == user.id,
            AuthToken.purpose == "email_verification",
            AuthToken.created_at >= now - timedelta(hours=24),
        )
    )

    if issued_in_day >= DAILY_TOKEN_LIMIT:
        return None

    return issue_email_verification(db, user.id)
