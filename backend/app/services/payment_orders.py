"""Tenant-authorized, provider-neutral payment-order creation.

This service performs validation and flushes one order into the caller's
SQLAlchemy transaction. The caller owns commit and rollback.

It does NOT process provider payments, reserve an idempotency key, expose
an API, or guarantee that a flushed record has been committed.
"""

import re
import uuid
from dataclasses import dataclass
from enum import Enum

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.payments import PaymentOrder
from app.payments.contracts import Money
from app.services.organization_access import get_accessible_organization
from app.services.organization_rbac import ROLE_PERMISSIONS, permissions_for_role


_REFERENCE_PATTERN = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z"
)

_ORDER_REFERENCE_CONSTRAINT = (
    "uq_payment_orders_tenant_reference"
)

# A deliberately restrictive interim policy. These role names must be
# checked against the existing RBAC policy before any API is exposed.
_WRITER_ROLES = frozenset(
    role
    for role in ROLE_PERMISSIONS
    if "payments.create" in permissions_for_role(role)
)


class PaymentOrderError(Exception):
    """Base exception for safe, normalized order errors."""


class PaymentOrderAccessDenied(PaymentOrderError):
    """The actor is not authorized to create an order."""


class PaymentOrderReferenceConflict(PaymentOrderError):
    """A merchant order reference is already used in this tenant."""


@dataclass(frozen=True, slots=True)
class CreatePaymentOrderInput:
    organization_id: uuid.UUID
    merchant_order_reference: str
    amount: Money

    def __post_init__(self) -> None:
        if (
            not isinstance(self.organization_id, uuid.UUID)
            or self.organization_id.int == 0
        ):
            raise ValueError("Valid organization UUID required")

        if (
            not isinstance(self.merchant_order_reference, str)
            or _REFERENCE_PATTERN.fullmatch(
                self.merchant_order_reference
            ) is None
        ):
            raise ValueError("Invalid merchant order reference")

        if not isinstance(self.amount, Money):
            raise TypeError("Payment amount must be Money")


@dataclass(frozen=True, slots=True)
class CreatedPaymentOrder:
    id: uuid.UUID
    organization_id: uuid.UUID
    merchant_order_reference: str
    amount: Money
    status: str


def _valid_actor(actor_user_id: uuid.UUID) -> bool:
    return (
        isinstance(actor_user_id, uuid.UUID)
        and actor_user_id.int != 0
    )


def _normalized_role(role: object) -> str | None:
    if isinstance(role, Enum):
        role = role.value

    return role if isinstance(role, str) else None


def _is_order_reference_conflict(error: IntegrityError) -> bool:
    original = error.orig

    sqlstate = getattr(original, "sqlstate", None)

    if sqlstate is None:
        sqlstate = getattr(original, "pgcode", None)

    diagnostic = getattr(original, "diag", None)
    constraint = getattr(
        diagnostic,
        "constraint_name",
        None,
    )

    return (
        sqlstate == "23505"
        and constraint == _ORDER_REFERENCE_CONSTRAINT
    )


def create_payment_order(
    db: Session,
    *,
    actor_user_id: uuid.UUID,
    request: CreatePaymentOrderInput,
) -> CreatedPaymentOrder:
    """Validate, authorize, and flush an order without committing.

    Use inside a transaction owned by the caller, for example:

        with SessionLocal.begin() as db:
            result = create_payment_order(
                db,
                actor_user_id=authenticated_user_id,
                request=validated_request,
            )

    On any exception, the caller must roll back its transaction.
    In particular, an IntegrityError leaves the PostgreSQL transaction
    unusable until it is rolled back.

    No provider operation or durable idempotency reservation occurs.
    """
    if not isinstance(request, CreatePaymentOrderInput):
        raise TypeError("Expected CreatePaymentOrderInput")

    if not _valid_actor(actor_user_id):
        raise ValueError("Valid actor user UUID required")

    # The existing organization access query requires an active
    # organization and an active membership for this actor.
    access = get_accessible_organization(
        db,
        actor_user_id,
        request.organization_id,
    )

    if access is None:
        raise PaymentOrderAccessDenied(
            "Payment-order creation is not permitted"
        )

    role = _normalized_role(access[1])

    if role not in _WRITER_ROLES:
        raise PaymentOrderAccessDenied(
            "Payment-order creation is not permitted"
        )

    # No pre-insert duplicate query: PostgreSQL's tenant-scoped
    # unique constraint is the concurrency authority.
    order = PaymentOrder(
        id=uuid.uuid4(),
        organization_id=request.organization_id,
        merchant_order_reference=request.merchant_order_reference,
        amount_minor_units=request.amount.minor_units,
        currency=request.amount.currency,
        status="open",
    )

    db.add(order)

    try:
        db.flush()
    except IntegrityError as error:
        if _is_order_reference_conflict(error):
            raise PaymentOrderReferenceConflict(
                "Merchant order reference already exists"
            ) from None
        raise

    return CreatedPaymentOrder(
        id=order.id,
        organization_id=order.organization_id,
        merchant_order_reference=order.merchant_order_reference,
        amount=Money(
            minor_units=order.amount_minor_units,
            currency=order.currency,
        ),
        status=order.status,
    )
