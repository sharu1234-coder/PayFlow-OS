from fastapi import (
    Cookie,
    Header,
    HTTPException,
    status,
)

from app.services.session_csrf import valid_csrf_token


def _verify_csrf(
    session_token: str,
    csrf_header: str | None,
) -> None:
    if not valid_csrf_token(
        session_token,
        csrf_header,
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF validation failed",
        )


def require_authenticated_csrf(
    session_token: str | None = Cookie(
        default=None,
        alias="payflow_session",
    ),
    csrf_header: str | None = Header(
        default=None,
        alias="X-CSRF-Token",
    ),
) -> None:
    # Strict dependency for authenticated mutations.
    if not session_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    _verify_csrf(session_token, csrf_header)


def require_optional_csrf(
    session_token: str | None = Cookie(
        default=None,
        alias="payflow_session",
    ),
    csrf_header: str | None = Header(
        default=None,
        alias="X-CSRF-Token",
    ),
) -> None:
    # Logout is intentionally idempotent without a cookie.
    # A request carrying a cookie must provide valid CSRF.
    if session_token is None:
        return

    _verify_csrf(session_token, csrf_header)
