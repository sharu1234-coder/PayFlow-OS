"""Opt-in, development-only sandbox payment-attempt API.

Mounted only when the development environment and sandbox
feature flag are both enabled. Database use requires the
payment-attempt uniqueness and idempotency migrations.

No gateway calls, capture, settlement, refunds or webhooks.
"""

import uuid

from fastapi import (
    APIRouter,
    Depends,
    Header,
    HTTPException,
    Response,
    status,
)
from pydantic import BaseModel
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.api.csrf_dependencies import require_authenticated_csrf
from app.api.dependencies import get_db
from app.api.organizations import (
    authorize_organization_action,
    require_user,
)
from app.core.config import get_settings
from app.models import User
from app.payments.attempt_idempotency import CreateAttemptIntent
from app.services.payment_attempt_idempotency import (
    AttemptIdempotencyKeyConflict,
    AttemptIdempotencyStateUnavailable,
    create_sandbox_payment_attempt_idempotent,
)
from app.services.payment_attempts import (
    PaymentAttemptAccessDenied,
    PaymentAttemptConflict,
    PaymentAttemptOrderNotFound,
)


router = APIRouter(
    prefix="/api/v1/organizations",
    tags=["Sandbox Payment Attempts"],
)


class SandboxAttemptResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    order_id: uuid.UUID
    attempt_number: int
    amount_minor_units: int
    currency: str
    provider_code: str
    status: str
    replayed: bool


@router.post(
    "/{organization_id}/payment-orders/{order_id}/attempts",
    response_model=SandboxAttemptResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        status.HTTP_200_OK: {
            "model": SandboxAttemptResponse,
            "description": "Original attempt replayed",
        },
    },
)
def create_sandbox_attempt_api(
    organization_id: uuid.UUID,
    order_id: uuid.UUID,
    response: Response,
    idempotency_key: str = Header(
        ...,
        alias="Idempotency-Key",
        min_length=10,
        max_length=128,
        pattern=r"^[A-Za-z0-9_-]{10,128}$",
    ),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
    csrf_verified: None = Depends(
        require_authenticated_csrf
    ),
) -> SandboxAttemptResponse:
    """Create or replay a sandbox attempt; never process money."""

    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"

    # Defense in depth even if mistakenly mounted.
    if get_settings().app_env != "development":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Not found",
        )

    if organization_id.int == 0 or order_id.int == 0:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Invalid payment identifier",
        )

    try:
        authorize_organization_action(
            db,
            user.id,
            organization_id,
            "payments.create",
        )

        intent = CreateAttemptIntent(
            organization_id=organization_id,
            order_id=order_id,
            idempotency_key=idempotency_key,
        )

        result = create_sandbox_payment_attempt_idempotent(
            db,
            actor_user_id=user.id,
            intent=intent,
        )

        # Validate the complete response before committing.
        # A malformed result must not create a committed
        # payment attempt followed by an HTTP 500.
        attempt = result.attempt

        validated_response = SandboxAttemptResponse(
            id=attempt.id,
            organization_id=attempt.organization_id,
            order_id=attempt.order_id,
            attempt_number=attempt.attempt_number,
            amount_minor_units=attempt.amount.minor_units,
            currency=attempt.amount.currency,
            provider_code=attempt.provider_code,
            status=attempt.state.value,
            replayed=result.replayed,
        )

        # The attempt and completed idempotency mapping
        # are committed together only after validation.
        db.commit()

    except HTTPException:
        db.rollback()
        raise

    except (
        PaymentAttemptAccessDenied,
        PaymentAttemptOrderNotFound,
    ):
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Payment order not found",
        ) from None

    except (
        PaymentAttemptConflict,
        AttemptIdempotencyKeyConflict,
    ):
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Payment attempt conflicts with this request",
        ) from None

    except AttemptIdempotencyStateUnavailable:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Idempotency result is not available",
        ) from None

    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Payment storage is temporarily unavailable",
        ) from None

    except Exception:
        db.rollback()
        raise

    if result.replayed:
        response.status_code = status.HTTP_200_OK

    return validated_response
