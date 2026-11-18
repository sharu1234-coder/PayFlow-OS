"""Atomic, development-only sandbox attempt idempotency.

The caller owns the database transaction.

Within one transaction:
1. Recheck authorization and lock the tenant-scoped order.
2. Claim the tenant-scoped idempotency key.
3. Create a sandbox attempt if the key is new.
4. Complete the original-attempt mapping.
5. Return the original attempt on an authorized replay.

No commits, gateway operations, capture or settlement occur here.

Requires the pending attempt-idempotency and partial-index
migrations to be installed before runtime use.
"""

import uuid
from dataclasses import dataclass
from enum import Enum

from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.payments import (
    PaymentAttempt,
    PaymentAttemptIdempotencyRecord,
    PaymentOrder,
)
from app.payments.attempt_idempotency import (
    CreateAttemptIntent,
    fingerprint_create_attempt_intent,
)
from app.payments.contracts import Money, PaymentState
from app.services.organization_access import (
    get_accessible_organization,
)
from app.services.organization_rbac import permissions_for_role
from app.services.payment_attempts import (
    SANDBOX_PROVIDER_CODE,
    CreatedSandboxPaymentAttempt,
    PaymentAttemptAccessDenied,
    PaymentAttemptOrderNotFound,
    create_sandbox_payment_attempt,
)


KEY_CONSTRAINT = "uq_attempt_idem_tenant_key"


class AttemptIdempotencyError(Exception):
    """Base exception; caller must rollback on errors."""


class AttemptIdempotencyKeyConflict(AttemptIdempotencyError):
    """Tenant/key is already bound to another request."""


class AttemptIdempotencyStateUnavailable(AttemptIdempotencyError):
    """A stored mapping cannot safely be replayed."""


@dataclass(frozen=True, slots=True)
class IdempotentSandboxAttemptResult:
    attempt: CreatedSandboxPaymentAttempt
    replayed: bool


def _authorize_and_lock_order(
    db: Session,
    *,
    actor_user_id: uuid.UUID,
    organization_id: uuid.UUID,
    order_id: uuid.UUID,
) -> PaymentOrder:
    if (
        not isinstance(actor_user_id, uuid.UUID)
        or actor_user_id.int == 0
    ):
        raise ValueError("Valid actor UUID required")

    if get_settings().app_env != "development":
        raise PaymentAttemptAccessDenied(
            "Sandbox attempt creation is disabled"
        )

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

    # Lock before claiming a key. This also serializes
    # competing DIFFERENT keys for the same payment order.
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

    # The initial authorization check happened before the
    # order lock. Another transaction may have downgraded or
    # revoked this membership while we waited for that lock.
    #
    # Issue a fresh authorization query after acquiring it.
    # Under READ COMMITTED, this sees role changes committed
    # during the lock wait, including for idempotent replays.
    current_access = get_accessible_organization(
        db,
        actor_user_id,
        organization_id,
    )

    if current_access is None:
        raise PaymentAttemptAccessDenied(
            "Payment attempt creation is not permitted"
        )

    current_role = current_access[1]

    if isinstance(current_role, Enum):
        current_role = current_role.value

    if (
        not isinstance(current_role, str)
        or "payments.create"
        not in permissions_for_role(current_role)
    ):
        raise PaymentAttemptAccessDenied(
            "Payment attempt creation is not permitted"
        )

    return order


def _replay_original(
    db: Session,
    *,
    intent: CreateAttemptIntent,
    fingerprint: str,
    order: PaymentOrder,
) -> IdempotentSandboxAttemptResult:
    record = db.scalar(
        select(PaymentAttemptIdempotencyRecord).where(
            PaymentAttemptIdempotencyRecord.organization_id
            == intent.organization_id,
            PaymentAttemptIdempotencyRecord.idempotency_key
            == intent.idempotency_key,
        )
    )

    if record is None:
        raise AttemptIdempotencyStateUnavailable(
            "Idempotency result is not available"
        )

    if (
        record.organization_id != intent.organization_id
        or record.idempotency_key != intent.idempotency_key
    ):
        raise AttemptIdempotencyStateUnavailable(
            "Idempotency result is not available"
        )

    if (
        record.order_id != intent.order_id
        or record.request_fingerprint != fingerprint
    ):
        raise AttemptIdempotencyKeyConflict(
            "Idempotency key conflicts with this request"
        )

    if (
        record.status != "completed"
        or type(record.attempt_number) is not int
        or record.attempt_number <= 0
    ):
        raise AttemptIdempotencyStateUnavailable(
            "Idempotency result is not completed"
        )

    original = db.scalar(
        select(PaymentAttempt).where(
            PaymentAttempt.organization_id
            == intent.organization_id,
            PaymentAttempt.order_id == intent.order_id,
            PaymentAttempt.attempt_number
            == record.attempt_number,
        )
    )

    if original is None:
        raise AttemptIdempotencyStateUnavailable(
            "Original attempt is not available"
        )

    if (
        original.organization_id != intent.organization_id
        or original.order_id != intent.order_id
        or original.attempt_number != record.attempt_number
        or original.provider_code != SANDBOX_PROVIDER_CODE
        or original.amount_minor_units
        != order.amount_minor_units
        or original.currency != order.currency
        or not isinstance(original.id, uuid.UUID)
        or original.id.int == 0
    ):
        raise AttemptIdempotencyStateUnavailable(
            "Original attempt mapping is invalid"
        )

    try:
        state = PaymentState(original.status)
        amount = Money(
            minor_units=original.amount_minor_units,
            currency=original.currency,
        )
    except (TypeError, ValueError):
        raise AttemptIdempotencyStateUnavailable(
            "Original attempt state is invalid"
        ) from None

    # Replay returns the persisted attempt's CURRENT state.
    # It never creates another attempt or calls a gateway.
    attempt = CreatedSandboxPaymentAttempt(
        id=original.id,
        organization_id=original.organization_id,
        order_id=original.order_id,
        attempt_number=original.attempt_number,
        amount=amount,
        provider_code=original.provider_code,
        state=state,
    )

    return IdempotentSandboxAttemptResult(
        attempt=attempt,
        replayed=True,
    )


def create_sandbox_payment_attempt_idempotent(
    db: Session,
    *,
    actor_user_id: uuid.UUID,
    intent: CreateAttemptIntent,
) -> IdempotentSandboxAttemptResult:
    """Create or replay a sandbox attempt in one caller-owned txn.

    The caller must commit on success and rollback on errors.
    Do not use outside the development environment.
    """

    if not isinstance(intent, CreateAttemptIntent):
        raise TypeError("Expected CreateAttemptIntent")

    order = _authorize_and_lock_order(
        db,
        actor_user_id=actor_user_id,
        organization_id=intent.organization_id,
        order_id=intent.order_id,
    )

    fingerprint = fingerprint_create_attempt_intent(intent)

    # PostgreSQL's unique-key arbitration ensures that a
    # concurrent request with the same tenant/key waits for
    # the first transaction to commit or rollback.
    statement = (
        pg_insert(PaymentAttemptIdempotencyRecord)
        .values(
            id=uuid.uuid4(),
            organization_id=intent.organization_id,
            order_id=intent.order_id,
            idempotency_key=intent.idempotency_key,
            request_fingerprint=fingerprint,
            attempt_number=None,
            status="reserved",
        )
        .on_conflict_do_nothing(
            constraint=KEY_CONSTRAINT
        )
        .returning(PaymentAttemptIdempotencyRecord.id)
    )

    claimed_id = db.execute(
        statement
    ).scalar_one_or_none()

    if claimed_id is None:
        return _replay_original(
            db,
            intent=intent,
            fingerprint=fingerprint,
            order=order,
        )

    created = create_sandbox_payment_attempt(
        db,
        actor_user_id=actor_user_id,
        organization_id=intent.organization_id,
        order_id=intent.order_id,
    )

    completed = db.execute(
        update(PaymentAttemptIdempotencyRecord)
        .where(
            PaymentAttemptIdempotencyRecord.id == claimed_id,
            PaymentAttemptIdempotencyRecord.organization_id
            == intent.organization_id,
            PaymentAttemptIdempotencyRecord.order_id
            == intent.order_id,
            PaymentAttemptIdempotencyRecord.status
            == "reserved",
        )
        .values(
            status="completed",
            attempt_number=created.attempt_number,
        )
    )

    if completed.rowcount != 1:
        raise AttemptIdempotencyStateUnavailable(
            "Original attempt mapping could not be completed"
        )

    # The reservation, attempt and mapping are still
    # uncommitted. The caller commits all three together.
    return IdempotentSandboxAttemptResult(
        attempt=created,
        replayed=False,
    )
