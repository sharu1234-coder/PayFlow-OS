import hashlib
import hmac

from app.core.config import get_settings


def csrf_token_for_session(session_token: str) -> str:
    secret = get_settings().csrf_secret.get_secret_value()

    return hmac.new(
        secret.encode("utf-8"),
        ("payflow.csrf.v1:" + session_token).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def valid_csrf_token(
    session_token: str,
    submitted_token: str | None,
) -> bool:
    if (
        submitted_token is None
        or len(submitted_token) != 64
        or any(c not in "0123456789abcdef"
               for c in submitted_token)
    ):
        return False

    expected = csrf_token_for_session(session_token)

    return hmac.compare_digest(
        expected,
        submitted_token,
    )
