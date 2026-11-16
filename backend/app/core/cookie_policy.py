from fastapi import Response

from app.core.config import get_settings


SESSION_COOKIE_NAME = "payflow_session"
SESSION_COOKIE_PATH = "/"


def secure_cookie_required() -> bool:
    # Only explicit local development permits HTTP cookies.
    # Staging, production and unknown environments fail secure.
    return get_settings().app_env != "development"


def set_auth_session_cookie(
    response: Response,
    token: str,
    lifetime_seconds: int,
) -> None:
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        max_age=lifetime_seconds,
        path=SESSION_COOKIE_PATH,
        secure=secure_cookie_required(),
        httponly=True,
        samesite="lax",
    )

    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"


def clear_auth_session_cookie(response: Response) -> None:
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        path=SESSION_COOKIE_PATH,
        secure=secure_cookie_required(),
        httponly=True,
        samesite="lax",
    )

    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
