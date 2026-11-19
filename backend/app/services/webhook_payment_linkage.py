"""Read-only, tenant-scoped local payment-reference linkage.

This is NOT provider reconciliation or payment confirmation.

A match means an existing local payment-attempt record contains
the exact sandbox provider reference from a verified inbox event.

Local payment state is NOT authoritative provider state.

No HTTP routes, refunds, provider calls, financial mutations,
transaction commits, retry authorization or inbox transitions.

The caller must already own a PostgreSQL transaction and
establish a trusted tenant context. This service is not an
independent public authorization boundary.

Only sandbox_sim provider references can match.
Legacy attempt rows with provider_code='sandbox' or
provider_payment_id=NULL remain unlinked.

Refund events are explicitly unsupported because no durable
refund-object linkage model has been established yet.
"""

from dataclasses import dataclass
from enum import Enum
from uuid import UUID

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.payments import PaymentAttempt, PaymentOrder
from app.models.webhooks import VerifiedProviderEvent
from app.payments.contracts import Money, PaymentState
from app.payments.webhook_contracts import SandboxEventType
from app.payments.webhook_processing_policy import (
    InboxLifecycle,
    ProviderObjectKind,
    StoredInboxEventSnapshot,
)
from app.services.webhook_triage import _advisory_lock_key


class PaymentLinkUnavailable(Exception):
    """Sandbox-only linkage disabled or unsafe DB context."""


class PaymentLinkNotFound(Exception):
    """Inbox record not visible in the tenant scope."""


class PaymentLinkInvalidRecord(Exception):
    """Stored inbox record cannot be safely interpreted."""


class PaymentLinkIntegrityError(Exception):
    """Stored local payment reference is inconsistent."""


class PaymentLinkKind(str, Enum):
    LOCAL_REFERENCE = "local_reference"
    UNLINKED = "unlinked"
    REFUND_UNSUPPORTED = "refund_unsupported"
    ALREADY_RESOLVED = "already_resolved"


@dataclass(frozen=True, slots=True)
class PaymentLinkInspection:
    organization_id: UUID
    record_id: UUID
    event_id: str
    kind: PaymentLinkKind
    attempt_id: UUID | None = None
    order_id: UUID | None = None
    local_attempt_state: PaymentState | None = None
    local_order_status: str | None = None

    # This result deliberately has no:
    # provider_confirmed, settlement_confirmed,
    # amount_to_capture, retry_authorized or payment_state.


def _valid_uuid(value: UUID) -> bool:
    return isinstance(value, UUID) and value.int != 0


def _valid_environment() -> None:
    settings = get_settings()

    if (
        settings.app_env != "development"
        or settings.sandbox_payment_attempts_enabled is not True
    ):
        raise PaymentLinkUnavailable(
            "Sandbox payment-reference linkage disabled"
        )


def _validate_db(db: Session) -> None:
    if not db.in_transaction():
        raise PaymentLinkUnavailable(
            "Active caller-owned transaction required"
        )

    bind = db.get_bind()

    if bind is None or bind.dialect.name != "postgresql":
        raise PaymentLinkUnavailable(
            "PostgreSQL transaction required"
        )


def _result(
    event: StoredInboxEventSnapshot,
    record_id: UUID,
    kind: PaymentLinkKind,
    *,
    attempt_id: UUID | None = None,
    order_id: UUID | None = None,
    local_attempt_state: PaymentState | None = None,
    local_order_status: str | None = None,
) -> PaymentLinkInspection:
    return PaymentLinkInspection(
        organization_id=event.organization_id,
        record_id=record_id,
        event_id=event.event_id,
        kind=kind,
        attempt_id=attempt_id,
        order_id=order_id,
        local_attempt_state=local_attempt_state,
        local_order_status=local_order_status,
    )


def inspect_local_payment_reference(
    db: Session,
    *,
    organization_id: UUID,
    record_id: UUID,
) -> PaymentLinkInspection:
    """Inspect an already-stored sandbox event and local references.

    Acquires the same cooperative transaction advisory lock used
    by the read-only webhook triage inspector.

    The event is selected by both organization and inbox ID.
    Payment attempts are selected by tenant, provider code and
    EXACT provider payment ID, never by an approximate reference.

    The associated order must also match tenant, ID, amount and
    currency. This is attribution evidence only.

    Even a local_attempt_state of SUCCEEDED never means an
    external provider confirmed settlement.
    """

    if not _valid_uuid(organization_id):
        raise ValueError("Valid organization UUID required")

    if not _valid_uuid(record_id):
        raise ValueError("Valid inbox record UUID required")

    _valid_environment()
    _validate_db(db)

    db.execute(
        text("SELECT pg_advisory_xact_lock(:lock_key)"),
        {
            "lock_key": _advisory_lock_key(
                organization_id,
                record_id,
            ),
        },
    )

    stored = db.scalar(
        select(VerifiedProviderEvent).where(
            VerifiedProviderEvent.organization_id
            == organization_id,
            VerifiedProviderEvent.id == record_id,
        )
    )

    if stored is None:
        raise PaymentLinkNotFound(
            "Webhook inbox record not found"
        )

    if (
        stored.id != record_id
        or stored.organization_id != organization_id
    ):
        raise PaymentLinkNotFound(
            "Webhook inbox record not found"
        )

    try:
        event = StoredInboxEventSnapshot(
            organization_id=stored.organization_id,
            provider_code=stored.provider_code,
            event_id=stored.event_id,
            event_type=SandboxEventType(stored.event_type),
            provider_object_id=stored.provider_object_id,
            occurred_at=stored.occurred_at,
            lifecycle=InboxLifecycle(stored.status),
        )
    except (ValueError, TypeError, AttributeError):
        raise PaymentLinkInvalidRecord(
            "Stored webhook event is invalid"
        ) from None

    if event.lifecycle is not InboxLifecycle.RECEIVED:
        return _result(
            event,
            record_id,
            PaymentLinkKind.ALREADY_RESOLVED,
        )

    if event.object_kind is ProviderObjectKind.REFUND:
        return _result(
            event,
            record_id,
            PaymentLinkKind.REFUND_UNSUPPORTED,
        )

    attempt = db.scalar(
        select(PaymentAttempt).where(
            PaymentAttempt.organization_id
            == organization_id,
            PaymentAttempt.provider_code
            == event.provider_code,
            PaymentAttempt.provider_payment_id
            == event.provider_object_id,
        )
    )

    if attempt is None:
        return _result(
            event,
            record_id,
            PaymentLinkKind.UNLINKED,
        )

    if (
        not _valid_uuid(attempt.id)
        or not _valid_uuid(attempt.order_id)
        or attempt.organization_id != organization_id
        or attempt.provider_code != event.provider_code
        or attempt.provider_payment_id
        != event.provider_object_id
    ):
        raise PaymentLinkIntegrityError(
            "Local payment reference integrity check failed"
        )

    try:
        local_state = PaymentState(attempt.status)

        # Validate the stored amount without accepting
        # any amount from the webhook event.
        Money(
            minor_units=attempt.amount_minor_units,
            currency=attempt.currency,
        )

        if (
            type(attempt.attempt_number) is not int
            or attempt.attempt_number < 1
        ):
            raise ValueError("Invalid attempt number")

    except (ValueError, TypeError, AttributeError):
        raise PaymentLinkIntegrityError(
            "Local payment attempt is invalid"
        ) from None

    order = db.scalar(
        select(PaymentOrder).where(
            PaymentOrder.organization_id
            == organization_id,
            PaymentOrder.id == attempt.order_id,
            PaymentOrder.amount_minor_units
            == attempt.amount_minor_units,
            PaymentOrder.currency == attempt.currency,
        )
    )

    if order is None:
        raise PaymentLinkIntegrityError(
            "Matching payment order unavailable"
        )

    if (
        order.organization_id != organization_id
        or order.id != attempt.order_id
        or order.amount_minor_units
        != attempt.amount_minor_units
        or order.currency != attempt.currency
        or order.status not in (
            "open",
            "paid",
            "cancelled",
        )
    ):
        raise PaymentLinkIntegrityError(
            "Local payment order integrity check failed"
        )

    return _result(
        event,
        record_id,
        PaymentLinkKind.LOCAL_REFERENCE,
        attempt_id=attempt.id,
        order_id=order.id,
        local_attempt_state=local_state,
        local_order_status=order.status,
    )
