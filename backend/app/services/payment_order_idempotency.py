"""Durable, provider-neutral payment-order idempotency.

The caller owns the surrounding SQLAlchemy transaction.

The idempotency reservation, payment order, and completed marker
must be committed together. This module never commits, invokes a
payment provider, or starts a background payment operation.

A completed retry is resolved using the tenant-scoped merchant
reference because the current idempotency schema has no order_id.
"""

import hashlib
import json
import uuid
from dataclasses import dataclass
from enum import Enum

from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.models.payments import (
    PaymentIdempotencyRecord,
    PaymentOrder,
)
from app.payments.contracts import CreatePaymentCommand, Money
from app.services.organization_access import get_accessible_organization
from app.services.organization_rbac import permissions_for_role
from app.services.payment_orders import (
    CreatePaymentOrderInput,
    CreatedPaymentOrder,
    PaymentOrderAccessDenied,
    create_payment_order,
)


_OPERATION = "create_payment"
_CONSTRAINT = "uq_payment_idempotency_tenant_operation_key"
_REQUIRED_PERMISSION = "payments.create"


class PaymentIdempotencyError(Exception):
    """Base class for normalized idempotency failures."""


class PaymentIdempotencyKeyConflict(PaymentIdempotencyError):
    """The same tenant/key was used for a different request."""


class PaymentIdempotencyStateUnavailable(PaymentIdempotencyError):
    """A stored result is not safely replayable."""


@dataclass(frozen=True, slots=True)
class IdempotentPaymentOrderResult:
    order: CreatedPaymentOrder
    replayed: bool


def fingerprint_create_payment_command(
    command: CreatePaymentCommand,
) -> str:
    """Stable SHA-256 fingerprint of payment-order intent.

    An actor ID and idempotency key are intentionally excluded.
    Authorization is checked separately on every invocation.
    """
    if not isinstance(command, CreatePaymentCommand):
        raise TypeError("Expected CreatePaymentCommand")

    payload = {
        "schema": "payflow.payment-order.create.v1",
        "organization_id": str(command.organization_id),
        "merchant_order_reference": command.order_reference,
        "amount_minor_units": command.amount.minor_units,
        "currency": command.amount.currency,
    }

    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")

    return hashlib.sha256(canonical).hexdigest()


def _authorize(
    db: Session,
    actor_user_id: uuid.UUID,
    organization_id: uuid.UUID,
) -> None:
    if (
        not isinstance(actor_user_id, uuid.UUID)
        or actor_user_id.int == 0
    ):
        raise ValueError("Valid actor user UUID required")

    access = get_accessible_organization(
        db,
        actor_user_id,
        organization_id,
    )

    if access is None:
        raise PaymentOrderAccessDenied(
            "Payment-order creation is not permitted"
        )

    role = access[1]

    if isinstance(role, Enum):
        role = role.value

    if (
        not isinstance(role, str)
        or _REQUIRED_PERMISSION not in permissions_for_role(role)
    ):
        raise PaymentOrderAccessDenied(
            "Payment-order creation is not permitted"
        )


def _existing_order(
    db: Session,
    command: CreatePaymentCommand,
) -> CreatedPaymentOrder:
    """Resolve an existing order without creating another one."""

    order = db.scalar(
        select(PaymentOrder).where(
            PaymentOrder.organization_id == command.organization_id,
            PaymentOrder.merchant_order_reference
            == command.order_reference,
        )
    )

    if (
        order is None
        or order.amount_minor_units != command.amount.minor_units
        or order.currency != command.amount.currency
    ):
        raise PaymentIdempotencyStateUnavailable(
            "Completed idempotency result cannot be verified"
        )

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


def create_payment_order_idempotent(
    db: Session,
    *,
    actor_user_id: uuid.UUID,
    command: CreatePaymentCommand,
) -> IdempotentPaymentOrderResult:
    """Create or replay an order inside a caller-owned transaction.

    Use with:

        with SessionLocal.begin() as db:
            result = create_payment_order_idempotent(
                db,
                actor_user_id=authenticated_user_id,
                command=validated_command,
            )

    First request:
      - Claim the unique tenant/operation/key.
      - Create the order.
      - Mark idempotency completed.
      - Caller commits both together.

    Retry:
      - PostgreSQL resolves the unique-key conflict.
      - Verify the fingerprint and completed state.
      - Return the original tenant-scoped order.

    Unexpected reserved/failed/reconciliation records fail closed.

    The caller must roll back on exceptions. No gateway calls occur.
    """

    if not isinstance(command, CreatePaymentCommand):
        raise TypeError("Expected CreatePaymentCommand")

    # Authorization precedes key reservation and replay lookups.
    _authorize(
        db,
        actor_user_id,
        command.organization_id,
    )

    fingerprint = fingerprint_create_payment_command(command)

    statement = (
        pg_insert(PaymentIdempotencyRecord)
        .values(
            id=uuid.uuid4(),
            organization_id=command.organization_id,
            operation=_OPERATION,
            idempotency_key=command.idempotency_key,
            request_fingerprint=fingerprint,
            status="reserved",
        )
        .on_conflict_do_nothing(
            constraint=_CONSTRAINT,
        )
        .returning(PaymentIdempotencyRecord.id)
    )

    claimed_id = db.execute(statement).scalar_one_or_none()

    if claimed_id is None:
        record = db.scalar(
            select(PaymentIdempotencyRecord).where(
                PaymentIdempotencyRecord.organization_id
                == command.organization_id,
                PaymentIdempotencyRecord.operation == _OPERATION,
                PaymentIdempotencyRecord.idempotency_key
                == command.idempotency_key,
            )
        )

        if record is None:
            raise PaymentIdempotencyStateUnavailable(
                "Idempotency record is not visible"
            )

        if record.request_fingerprint != fingerprint:
            raise PaymentIdempotencyKeyConflict(
                "Idempotency key was used for a different request"
            )

        if record.status != "completed":
            raise PaymentIdempotencyStateUnavailable(
                "Idempotency result is not available for replay"
            )

        return IdempotentPaymentOrderResult(
            order=_existing_order(db, command),
            replayed=True,
        )

    # Reservation and order are in the same transaction.
    created = create_payment_order(
        db,
        actor_user_id=actor_user_id,
        request=CreatePaymentOrderInput(
            organization_id=command.organization_id,
            merchant_order_reference=command.order_reference,
            amount=command.amount,
        ),
    )

    updated = db.execute(
        update(PaymentIdempotencyRecord)
        .where(
            PaymentIdempotencyRecord.id == claimed_id,
            PaymentIdempotencyRecord.organization_id
            == command.organization_id,
            PaymentIdempotencyRecord.status == "reserved",
        )
        .values(status="completed")
    )

    if updated.rowcount != 1:
        raise PaymentIdempotencyStateUnavailable(
            "Idempotency completion failed"
        )

    return IdempotentPaymentOrderResult(
        order=created,
        replayed=False,
    )
