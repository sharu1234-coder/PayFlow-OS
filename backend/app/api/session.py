import uuid

from fastapi import (
    APIRouter,
    Cookie,
    Depends,
    HTTPException,
    Header,
    Response,
    status,
)
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from app.api.dependencies import get_db
from app.models import AuditEvent
from app.core.config import get_settings
from app.services.session_identity import (
    get_authenticated_user,
    revoke_current_session,
)
from app.services.session_csrf import csrf_token_for_session
from app.api.csrf_dependencies import require_optional_csrf
from app.core.cookie_policy import clear_auth_session_cookie


router = APIRouter(
    prefix="/api/v1/auth",
    tags=["Authentication"],
)


class CurrentUserResponse(BaseModel):
    id: uuid.UUID
    email: EmailStr
    display_name: str | None
    email_verified: bool


class CsrfResponse(BaseModel):
    token: str


class LogoutResponse(BaseModel):
    status: str


def require_development_mode() -> None:
    if get_settings().app_env != "development":
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Session endpoints are not enabled",
        )


@router.get(
    "/me",
    response_model=CurrentUserResponse,
)
def current_user(
    db: Session = Depends(get_db),
    session_token: str | None = Cookie(
        default=None,
        alias="payflow_session",
    ),
) -> CurrentUserResponse:
    require_development_mode()

    user = get_authenticated_user(
        db,
        session_token,
    )

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    return CurrentUserResponse(
        id=user.id,
        email=user.email,
        display_name=user.display_name,
        email_verified=True,
    )



@router.get(
    "/csrf",
    response_model=CsrfResponse,
)
def get_csrf(
    response: Response,
    db: Session = Depends(get_db),
    session_token: str | None = Cookie(
        default=None,
        alias="payflow_session",
    ),
) -> CsrfResponse:
    require_development_mode()

    user = get_authenticated_user(db, session_token)

    if user is None or session_token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"

    return CsrfResponse(
        token=csrf_token_for_session(session_token)
    )


@router.post(
    "/logout",
    response_model=LogoutResponse,
)
def logout(
    response: Response,
    db: Session = Depends(get_db),
    session_token: str | None = Cookie(
        default=None,
        alias="payflow_session",
    ),
    csrf_verified: None = Depends(
        require_optional_csrf
    ),
) -> LogoutResponse:
    require_development_mode()

    with db.begin():
        authenticated_user = get_authenticated_user(
            db,
            session_token,
        )

        revoke_current_session(
            db,
            session_token,
        )

        if authenticated_user is not None:
            db.add(
                AuditEvent(
                    organization_id=None,
                    actor_user_id=authenticated_user.id,
                    action="identity.logout",
                    subject_type="user",
                    subject_id=str(authenticated_user.id),
                    payload={
                        "result": "session_revoked",
                    },
                )
            )

    # Local HTTP development only.
    # Production requires HTTPS, Secure cookies and CSRF controls.
    clear_auth_session_cookie(response)

    return LogoutResponse(status="logged_out")
