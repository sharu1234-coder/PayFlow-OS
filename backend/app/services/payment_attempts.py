"""Development-only, provider-neutral sandbox attempt creation.

Caller owns commit/rollback; no gateway operations or state transitions.
The parent order row is locked before examining its attempts. All
writers must follow this locking discipline until a database active-
attempt uniqueness invariant is introduced.
"""

import uuid
from dataclasses import dataclass
from enum import Enum

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.payments import PaymentAttempt, PaymentOrder
from app.payments.attempt_policy import (
    AttemptCreationBlocked,
    AttemptSnapshot,
    plan_next_attempt_number,
)
from app.payments.contracts import Money, PaymentState
from app.services.organization_access import get_accessible_organization
from app.services.organization_rbac import permissions_for_role


SANDBOX_PROVIDER_CODE = "sandbox"

_ATTEMPT_NUMBER_CONSTRAINT = (
    "uq_payment_attempts_order_number"
)

_ACTIVE_ATTEMPT_INDEX = (
    "ux_payment_attempts_one_live_or_successful"
)


class PaymentAttemptServiceError(Exception):
    """Base error; caller is responsible for rollback."""


class PaymentAttemptAccessDenied(PaymentAttemptServiceError):
    """Actor is not permitted to create a sandbox attempt."""


class PaymentAttemptOrderNotFound(PaymentAttemptServiceError):
    """Order is not visible within the authorized tenant."""


class PaymentAttemptConflict(PaymentAttemptServiceError):
    """An attempt cannot safely be created for this order."""


@dataclass(frozen=True, slots=True)
class CreatedSandboxPaymentAttempt:
    id: uuid.UUID
    organization_id: uuid.UUID
    order_id: uuid.UUID
    attempt_number: int
    amount: Money
    provider_code: str
    state: PaymentState


def _validate_uuid(value: uuid.UUID, label: str) -> None:
    if not isinstance(value, uuid.UUID) or value.int == 0:
        raise ValueError(f"Valid {label} UUID required")


def _is_attempt_uniqueness_conflict(
    error: IntegrityError,
) -> bool:
    original = error.orig

    sqlstate = getattr(original, "sqlstate", None)

    if sqlstate is None:
        sqlstate = getattr(original, "pgcode", None)

    diag = getattr(original, "diag", None)

    return (
        sqlstate == "23505"
        and getattr(diag, "constraint_name", None)
        in {
            _ATTEMPT_NUMBER_CONSTRAINT,
            _ACTIVE_ATTEMPT_INDEX,
        }
    )


def create_sandbox_payment_attempt(
    db: Session,
    *,
    actor_user_id: uuid.UUID,
    organization_id: uuid.UUID,
    order_id: uuid.UUID,
) -> CreatedSandboxPaymentAttempt:
    """Flush a sandbox attempt inside a caller-owned transaction.

    No commit, payment provider call or payment-state mutation.

    The parent SELECT FOR UPDATE serializes cooperative writers.
    PostgreSQL concurrency must be verified separately.

    The caller must rollback after any exception.
    """

    _validate_uuid(actor_user_id, "actor")
    _validate_uuid(organization_id, "organization")
    _validate_uuid(order_id, "order")

    # Never permit the sandbox service in production.
    if get_settings().app_env != "development":
        raise PaymentAttemptAccessDenied(
            "Sandbox attempt creation is disabled"
        )

    # Existing organization access checks active membership.
    access = get_accessible_organization(
        db,
        actor_user_id,
        organization_id,
    )

    if access is None:
        raise PaymentAttemptAccessDenied(
            "Payment attempt creation is not permitted"
        )

    role = access[1]

    if isinstance(role, Enum):
        role = role.value

    if (
        not isinstance(role, str)
        or "payments.create" not in permissions_for_role(role)
    ):
        raise PaymentAttemptAccessDenied(
            "Payment attempt creation is not permitted"
        )

    # Lock only the authorized tenant's parent order.
    # Other cooperating writers for this order must wait.
    order = db.scalar(
        select(PaymentOrder)
        .where(
            PaymentOrder.organization_id == organization_id,
            PaymentOrder.id == order_id,
        )
        .with_for_update(of=PaymentOrder)
    )

    if order is None:
        raise PaymentAttemptOrderNotFound(
            "Payment order not found"
        )

    # Read existing attempts only after locking the order.
    existing = db.scalars(
        select(PaymentAttempt)
        .where(
            PaymentAttempt.organization_id == organization_id,
            PaymentAttempt.order_id == order_id,
        )
        .order_by(PaymentAttempt.attempt_number)
    ).all()

    try:
        snapshots = [
            AttemptSnapshot(
                number=attempt.attempt_number,
                state=PaymentState(attempt.status),
            )
            for attempt in existing
        ]

        attempt_number = plan_next_attempt_number(
            order_status=order.status,
            attempts=snapshots,
        )

    except (
        AttemptCreationBlocked,
        TypeError,
        ValueError,
    ):
        raise PaymentAttemptConflict(
            "Payment attempt creation is not available"
        ) from None

    # The client cannot supply or override the amount.
    amount = Money(
        minor_units=order.amount_minor_units,
        currency=order.currency,
    )

    attempt = PaymentAttempt(
        id=uuid.uuid4(),
        organization_id=organization_id,
        order_id=order_id,
        attempt_number=attempt_number,
        amount_minor_units=amount.minor_units,
        currency=amount.currency,
        provider_code=SANDBOX_PROVIDER_CODE,
        provider_payment_id=None,
        status=PaymentState.CREATED.value,
    )

    db.add(attempt)

    try:
        db.flush()

    except IntegrityError as error:
        if _is_attempt_uniqueness_conflict(error):
            raise PaymentAttemptConflict(
                "Payment attempt already exists"
            ) from None

        raise

    # Intentionally no commit here.
    return CreatedSandboxPaymentAttempt(
        id=attempt.id,
        organization_id=attempt.organization_id,
        order_id=attempt.order_id,
        attempt_number=attempt.attempt_number,
        amount=amount,
        provider_code=attempt.provider_code,
        state=PaymentState.CREATED,
    )
