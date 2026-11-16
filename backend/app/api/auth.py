import logging
import secrets
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy.exc import IntegrityError
from app.services.verification_resend import prepare_verification_resend
from app.services.session_auth import (
    SESSION_LIFETIME_SECONDS,
    authenticate_and_create_session,
)
from app.core.cookie_policy import set_auth_session_cookie
from app.services.login_throttle import (
    LoginRateLimited,
    enforce_login_attempt_limit,
    record_failed_login,
)
from app.services.login_source_throttle import (
    ClientAddressUnavailable,
    LoginSourceRateLimited,
    enforce_login_source_limit,
)
from sqlalchemy.orm import Session

from app.api.dependencies import get_db
from app.core.config import get_settings
from app.core.security import hash_password
from app.services.email_verification import (
    consume_email_verification,
    issue_email_verification,
)
from app.services.email_delivery import (
    VerificationEmailSender,
    get_verification_sender,
)
from app.models import (
    AuditEvent,
    MerchantProfile,
    Organization,
    OrganizationMembership,
    User,
)


router = APIRouter(
    prefix="/api/v1/auth",
    tags=["Authentication"],
)


class RegistrationRequest(BaseModel):
    email: EmailStr = Field(max_length=320)
    password: str = Field(min_length=12, max_length=128)
    display_name: str = Field(min_length=1, max_length=160)
    business_name: str = Field(min_length=2, max_length=200)

    @field_validator("display_name", "business_name")
    @classmethod
    def normalize_name(cls, value: str) -> str:
        result = " ".join(value.split())
        if not result:
            raise ValueError("Name cannot be empty")
        return result


class RegistrationResponse(BaseModel):
    user_id: uuid.UUID
    organization_id: uuid.UUID
    email: EmailStr
    status: str
    email_verified: bool
    verification_delivery: str


@router.post(
    "/register",
    response_model=RegistrationResponse,
    status_code=status.HTTP_201_CREATED,
)
def register_merchant(
    payload: RegistrationRequest,
    db: Session = Depends(get_db),
    sender: VerificationEmailSender | None = Depends(get_verification_sender),
) -> RegistrationResponse:
    # Public registration will remain disabled outside development
    # until email delivery, throttling, and security checks exist.
    if get_settings().app_env != "development":
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Registration is not enabled",
        )

    normalized_email = str(payload.email).lower()

    user = User(
        email=normalized_email,
        password_hash=hash_password(payload.password),
        display_name=payload.display_name,
    )

    organization = Organization(
        name=payload.business_name,
        slug=f"org-{secrets.token_hex(12)}",
    )

    verification_token: str | None = None

    try:
        # All records must either be committed together or
        # rolled back together.
        with db.begin():
            db.add(user)
            db.flush()

            db.add(organization)
            db.flush()

            db.add(
                OrganizationMembership(
                    organization_id=organization.id,
                    user_id=user.id,
                    role="owner",
                    status="invited",
                )
            )

            db.add(
                MerchantProfile(
                    organization_id=organization.id,
                    business_name=payload.business_name,
                    onboarding_status="draft",
                )
            )

            db.add(
                AuditEvent(
                    organization_id=organization.id,
                    actor_user_id=user.id,
                    action="identity.organization_registered",
                    subject_type="organization",
                    subject_id=str(organization.id),
                    payload={"email_verification": "pending"},
                )
            )

            if sender is not None:
                verification_token = issue_email_verification(
                    db, user.id
                )

    except IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Account registration could not be completed",
        ) from None


    delivery_status = "not_configured"

    # External email delivery happens only after database commit.
    # A delivery failure does not turn a committed registration
    # into a misleading HTTP 500 response.
    if sender is not None and verification_token is not None:
        try:
            sender.send_verification(
                normalized_email,
                verification_token,
            )
        except Exception as exc:
            # Do not log the verification token or SMTP credentials.
            logging.getLogger(__name__).warning(
                "Verification email delivery failed: %s",
                type(exc).__name__,
            )
            delivery_status = "failed"
        else:
            delivery_status = "sent"

    return RegistrationResponse(
        user_id=user.id,
        organization_id=organization.id,
        email=normalized_email,
        status="pending_email_verification",
        email_verified=False,
        verification_delivery=delivery_status,
    )


class VerifyEmailRequest(BaseModel):
    token: str = Field(min_length=32, max_length=256)


class VerifyEmailResponse(BaseModel):
    status: str


@router.post(
    "/verify-email",
    response_model=VerifyEmailResponse,
)
def verify_email(
    payload: VerifyEmailRequest,
    db: Session = Depends(get_db),
) -> VerifyEmailResponse:
    # Remain development-only until real email delivery,
    # throttling, and public-launch security checks exist.
    if get_settings().app_env != "development":
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Email verification is not enabled",
        )

    with db.begin():
        verified = consume_email_verification(
            db,
            payload.token,
        )

    if not verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification token",
        )

    return VerifyEmailResponse(status="verified")


class ResendVerificationRequest(BaseModel):
    email: EmailStr = Field(max_length=320)


class ResendVerificationResponse(BaseModel):
    status: str


@router.post(
    "/resend-verification",
    response_model=ResendVerificationResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def resend_verification(
    payload: ResendVerificationRequest,
    db: Session = Depends(get_db),
    sender: VerificationEmailSender | None = Depends(
        get_verification_sender
    ),
) -> ResendVerificationResponse:
    if get_settings().app_env != "development":
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Verification resend is not enabled",
        )

    # Use the same public response regardless of account existence,
    # verification status, cooldown, or delivery outcome.
    token = None
    email = str(payload.email).lower()

    if sender is not None:
        with db.begin():
            token = prepare_verification_resend(db, email)

    if token is not None and sender is not None:
        try:
            sender.send_verification(email, token)
        except Exception as exc:
            # Never log tokens, addresses, or SMTP credentials.
            logging.getLogger(__name__).warning(
                "Verification resend delivery failed: %s",
                type(exc).__name__,
            )

    return ResendVerificationResponse(status="accepted")


class MerchantLoginRequest(BaseModel):
    email: EmailStr = Field(max_length=320)
    password: str = Field(min_length=1, max_length=128)


class MerchantLoginResponse(BaseModel):
    status: str


@router.post(
    "/login",
    response_model=MerchantLoginResponse,
)
def login_merchant(
    payload: MerchantLoginRequest,
    response: Response,
    request: Request,
    db: Session = Depends(get_db),
) -> MerchantLoginResponse:
    # Keep login disabled outside local development
    # until production security controls are complete.
    if get_settings().app_env != "development":
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Login is not enabled",
        )

    raw_session_token = None
    email_limited = False

    try:
        with db.begin():
            # Lock source first, then email, maintaining
            # a consistent lock order across login requests.
            enforce_login_source_limit(
                db,
                client_address=(
                    request.client.host
                    if request.client is not None
                    else None
                ),
                environment=get_settings().app_env,
            )

            try:
                fingerprint = enforce_login_attempt_limit(
                    db,
                    str(payload.email),
                )

            except LoginRateLimited:
                # Preserve the source-attempt record even
                # when the per-email bucket is blocked.
                email_limited = True

            else:
                raw_session_token = authenticate_and_create_session(
                    db,
                    str(payload.email).lower(),
                    payload.password,
                )

                if raw_session_token is None:
                    record_failed_login(
                        db,
                        fingerprint,
                    )

    except LoginSourceRateLimited:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Try again later.",
            headers={"Retry-After": "900"},
        ) from None

    except ClientAddressUnavailable:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Login temporarily unavailable",
        ) from None

    if email_limited:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Try again later.",
            headers={"Retry-After": "900"},
        )

    if raw_session_token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    # Secure=False is ONLY for local HTTP development.
    # Public deployment will require HTTPS, Secure cookies,
    # CSRF protection and a hardened authentication gateway.
    set_auth_session_cookie(
        response,
        raw_session_token,
        SESSION_LIFETIME_SECONDS,
    )

    return MerchantLoginResponse(
        status="authenticated"
    )
