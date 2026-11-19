"""Tenant-scoped, read-only inspection of sandbox webhook inbox records.

Development-only. No public endpoints, gateway operations,
payment writes, commits, event status updates, or refunds.

The caller owns an active PostgreSQL transaction.

Transaction advisory locks coordinate cooperating triage
inspectors for the same tenant and inbox record. They do NOT
constitute a durable processing claim or protect against
writers that do not participate in the locking protocol.

Until trusted provider-object linkage is implemented,
unresolved records require quarantine review. The recommendation
is NOT automatically persisted or marked processed.

Recorded inbox rows are trusted only within the ingestion
and database-permission boundaries. This service does not
perform signature verification again.
"""

import hashlib
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.webhooks import VerifiedProviderEvent
from app.payments.webhook_contracts import SandboxEventType
from app.payments.webhook_processing_policy import (
    InboxLifecycle,
    StoredInboxEventSnapshot,
    TriageAction,
    TriageReason,
    plan_webhook_triage,
)


class WebhookTriageUnavailable(Exception):
    """Triage is disabled or an unsafe environment was detected."""


class WebhookTriageNotFound(Exception):
    """No inbox record visible in the trusted tenant scope."""


class WebhookTriageInvalidRecord(Exception):
    """Stored data could not be safely interpreted."""


@dataclass(frozen=True, slots=True)
class WebhookTriageInspection:
    record_id: UUID
    organization_id: UUID
    event_id: str
    action: TriageAction
    reason: TriageReason
    persisted: bool = False


def _valid_uuid(value: UUID) -> bool:
    return isinstance(value, UUID) and value.int != 0


def _advisory_lock_key(
    organization_id: UUID,
    record_id: UUID,
) -> int:
    # Signed int64; deterministic across processes.
    # Lock collisions only reduce concurrency.
    # Tenant authorization must never depend on this key.
    material = (
        b"payflow.webhook.triage.v1:"
        + organization_id.bytes
        + record_id.bytes
    )

    digest = hashlib.sha256(material).digest()

    return int.from_bytes(
        digest[:8],
        byteorder="big",
        signed=True,
    )


def inspect_sandbox_webhook(
    db: Session,
    *,
    organization_id: UUID,
    record_id: UUID,
) -> WebhookTriageInspection:
    """Inspect one trusted tenant's recorded webhook event.

    An existing caller-owned transaction is required.

    No untrusted linked-object snapshot is accepted. Until
    trusted linkage is implemented, the pure policy receives
    linked_object=None and recommends manual quarantine review.

    This method does not commit, rollback, update, or persist
    any status. It holds a cooperative advisory lock until the
    caller ends the transaction.
    """

    if not _valid_uuid(organization_id):
        raise ValueError("Valid organization UUID required")

    if not _valid_uuid(record_id):
        raise ValueError("Valid inbox record UUID required")

    settings = get_settings()

    if (
        settings.app_env != "development"
        or settings.sandbox_payment_attempts_enabled is not True
    ):
        raise WebhookTriageUnavailable(
            "Sandbox webhook triage disabled"
        )

    if not db.in_transaction():
        raise WebhookTriageUnavailable(
            "An active caller-owned transaction is required"
        )

    bind = db.get_bind()

    if (
        bind is None
        or bind.dialect.name != "postgresql"
    ):
        raise WebhookTriageUnavailable(
            "PostgreSQL transaction required"
        )

    lock_key = _advisory_lock_key(
        organization_id,
        record_id,
    )

    # PostgreSQL transaction-scoped cooperative lock.
    # No persistent database modification.
    db.execute(
        text("SELECT pg_advisory_xact_lock(:lock_key)"),
        {"lock_key": lock_key},
    )

    # Tenant is included in the SQL predicate, not checked
    # only after fetching a record.
    stored = db.scalar(
        select(VerifiedProviderEvent).where(
            VerifiedProviderEvent.organization_id
            == organization_id,
            VerifiedProviderEvent.id
            == record_id,
        )
    )

    if stored is None:
        raise WebhookTriageNotFound(
            "Webhook inbox record not found"
        )

    # Defense in depth against incorrect repositories/mocks.
    if (
        stored.id != record_id
        or stored.organization_id != organization_id
    ):
        raise WebhookTriageNotFound(
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
        raise WebhookTriageInvalidRecord(
            "Stored webhook event is invalid"
        ) from None

    # No authoritative provider-object linkage exists yet.
    # Do not accept a supplied object snapshot as proof.
    plan = plan_webhook_triage(
        event=event,
        linked_object=None,
    )

    return WebhookTriageInspection(
        record_id=stored.id,
        organization_id=stored.organization_id,
        event_id=stored.event_id,
        action=plan.action,
        reason=plan.reason,
        persisted=False,
    )
