"""Authenticated, tenant-scoped payment-order API.

Development-only under the existing application release gate.

No payment gateway, payment capture, settlement, or refund
processing is performed by these endpoints.
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
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.api.csrf_dependencies import require_authenticated_csrf
from app.api.dependencies import get_db
from app.api.organizations import (
    authorize_organization_action,
    require_user,
)
from app.models import User
from app.models.payments import PaymentOrder
from app.payments.contracts import (
    MAX_MINOR_UNITS,
    CreatePaymentCommand,
    Money,
)
from app.services.payment_order_idempotency import (
    PaymentIdempotencyKeyConflict,
    PaymentIdempotencyStateUnavailable,
    create_payment_order_idempotent,
)
from app.services.payment_orders import (
    PaymentOrderAccessDenied,
    PaymentOrderReferenceConflict,
)


router = APIRouter(
    prefix="/api/v1/organizations",
    tags=["Payment Orders"],
)


class CreatePaymentOrderRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    merchant_order_reference: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
    )

    amount_minor_units: int = Field(
        strict=True,
        gt=0,
        le=MAX_MINOR_UNITS,
    )

    currency: str = Field(
        min_length=3,
        max_length=3,
        pattern=r"^[A-Z]{3}$",
    )


class PaymentOrderResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    merchant_order_reference: str
    amount_minor_units: int
    currency: str
    status: str


class CreatePaymentOrderResponse(PaymentOrderResponse):
    replayed: bool


def _disable_response_caching(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"


def _validate_organization_id(
    organization_id: uuid.UUID,
) -> None:
    if organization_id.int == 0:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Invalid organization ID",
        )


@router.post(
    "/{organization_id}/payment-orders",
    response_model=CreatePaymentOrderResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        status.HTTP_200_OK: {
            "model": CreatePaymentOrderResponse,
            "description": "Idempotent replay",
        },
    },
)
def create_payment_order_api(
    organization_id: uuid.UUID,
    payload: CreatePaymentOrderRequest,
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
) -> CreatePaymentOrderResponse:
    """Create an order, or replay the original order safely."""

    _validate_organization_id(organization_id)

    try:
        # Keep the existing centralized RBAC decision.
        authorize_organization_action(
            db,
            user.id,
            organization_id,
            "payments.create",
        )

        command = CreatePaymentCommand(
            organization_id=organization_id,
            order_reference=payload.merchant_order_reference,
            amount=Money(
                minor_units=payload.amount_minor_units,
                currency=payload.currency,
            ),
            idempotency_key=idempotency_key,
        )

        result = create_payment_order_idempotent(
            db,
            actor_user_id=user.id,
            command=command,
        )

        # Commit the payment order and completed idempotency
        # record in the same database transaction.
        db.commit()

    except HTTPException:
        db.rollback()
        raise

    except PaymentOrderAccessDenied:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found",
        ) from None

    except PaymentOrderReferenceConflict:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Merchant order reference already exists",
        ) from None

    except PaymentIdempotencyKeyConflict:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Idempotency key conflicts with this request",
        ) from None

    except PaymentIdempotencyStateUnavailable:
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

    _disable_response_caching(response)

    if result.replayed:
        response.status_code = status.HTTP_200_OK

    order = result.order

    return CreatePaymentOrderResponse(
        id=order.id,
        organization_id=order.organization_id,
        merchant_order_reference=order.merchant_order_reference,
        amount_minor_units=order.amount.minor_units,
        currency=order.amount.currency,
        status=order.status,
        replayed=result.replayed,
    )


@router.get(
    "/{organization_id}/payment-orders/{order_id}",
    response_model=PaymentOrderResponse,
)
def get_payment_order_api(
    organization_id: uuid.UUID,
    order_id: uuid.UUID,
    response: Response,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
) -> PaymentOrderResponse:
    """Retrieve an order only within an authorized tenant."""

    _validate_organization_id(organization_id)

    if order_id.int == 0:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Invalid order ID",
        )

    try:
        authorize_organization_action(
            db,
            user.id,
            organization_id,
            "payments.read",
        )

        # Both tenant ID and order ID are mandatory filters.
        # Never fetch an order by its UUID alone.
        order = db.scalar(
            select(PaymentOrder).where(
                PaymentOrder.organization_id == organization_id,
                PaymentOrder.id == order_id,
            )
        )

    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Payment storage is temporarily unavailable",
        ) from None

    if order is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Payment order not found",
        )

    _disable_response_caching(response)

    return PaymentOrderResponse(
        id=order.id,
        organization_id=order.organization_id,
        merchant_order_reference=order.merchant_order_reference,
        amount_minor_units=order.amount_minor_units,
        currency=order.currency,
        status=order.status,
    )
