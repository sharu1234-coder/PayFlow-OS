"""Read-only coordination of sandbox inbox triage and local linkage.

This internal service combines two existing, tenant-scoped
PostgreSQL inspection services under one caller-owned transaction.

Local provider-reference matching is NOT provider confirmation.

Only an exact existing local payment reference may produce a
recommendation to consider a separate read-only reconciliation.

Unlinked payments and unsupported refunds remain recommended
for manual quarantine review, not automatically quarantined.

No HTTP routes, payment mutations, refund processing, provider
calls, event status updates, transaction commits or retries.

An authenticated/authorized internal caller must supply the
trusted tenant identity. This service is not an independent
merchant-facing authorization boundary.

The cooperative advisory lock is acquired by both underlying
services, for the same transaction and event identity.
"""

from dataclasses import dataclass
from uuid import UUID

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.payments.contracts import PaymentState
from app.payments.webhook_processing_policy import (
    TriageAction,
    TriageReason,
)
from app.services import webhook_payment_linkage as linkage
from app.services import webhook_triage as triage


class LinkedWebhookTriageUnavailable(Exception):
    """Integrated sandbox triage is disabled."""


class LinkedWebhookTriageInconsistent(Exception):
    """Independent read-only observations disagree."""


@dataclass(frozen=True, slots=True)
class LinkedWebhookTriageInspection:
    organization_id: UUID
    record_id: UUID
    event_id: str
    action: TriageAction
    reason: TriageReason
    linkage_kind: linkage.PaymentLinkKind | None
    local_attempt_id: UUID | None = None
    local_order_id: UUID | None = None
    persisted: bool = False

    # No provider_confirmed, settlement_confirmed,
    # mutation_authorized or retry_payment properties.


def _valid_uuid(value: UUID) -> bool:
    return isinstance(value, UUID) and value.int != 0


def _check_runtime(db: Session) -> None:
    settings = get_settings()

    if (
        settings.app_env != "development"
        or settings.sandbox_payment_attempts_enabled is not True
    ):
        raise LinkedWebhookTriageUnavailable(
            "Integrated sandbox webhook triage disabled"
        )

    if not db.in_transaction():
        raise LinkedWebhookTriageUnavailable(
            "Caller-owned transaction required"
        )

    bind = db.get_bind()

    if bind is None or bind.dialect.name != "postgresql":
        raise LinkedWebhookTriageUnavailable(
            "PostgreSQL transaction required"
        )


def _check_base(
    base: triage.WebhookTriageInspection,
    *,
    organization_id: UUID,
    record_id: UUID,
) -> None:
    if (
        not isinstance(base, triage.WebhookTriageInspection)
        or base.organization_id != organization_id
        or base.record_id != record_id
        or not isinstance(base.event_id, str)
        or not base.event_id
        or not isinstance(base.action, TriageAction)
        or not isinstance(base.reason, TriageReason)
        or base.persisted is not False
    ):
        raise LinkedWebhookTriageInconsistent(
            "Base webhook triage observation is invalid"
        )


def _check_linkage(
    local: linkage.PaymentLinkInspection,
    *,
    base: triage.WebhookTriageInspection,
) -> None:
    if (
        not isinstance(local, linkage.PaymentLinkInspection)
        or local.organization_id != base.organization_id
        or local.record_id != base.record_id
        or local.event_id != base.event_id
        or not isinstance(local.kind, linkage.PaymentLinkKind)
    ):
        raise LinkedWebhookTriageInconsistent(
            "Webhook and local payment identities disagree"
        )


def inspect_linked_sandbox_webhook(
    db: Session,
    *,
    organization_id: UUID,
    record_id: UUID,
) -> LinkedWebhookTriageInspection:
    """Return a conservative, non-persisted triage recommendation.

    Both underlying services inspect the same tenant-scoped
    stored event using the same active SQLAlchemy transaction.

    This service intentionally DOES NOT pass local attempt state
    into LinkedProviderObjectSnapshot.confirmed_state.
    A local row is not independently confirmed by the provider.
    """

    if not _valid_uuid(organization_id):
        raise ValueError("Valid organization UUID required")

    if not _valid_uuid(record_id):
        raise ValueError("Valid inbox record UUID required")

    _check_runtime(db)

    base = triage.inspect_sandbox_webhook(
        db,
        organization_id=organization_id,
        record_id=record_id,
    )

    _check_base(
        base,
        organization_id=organization_id,
        record_id=record_id,
    )

    if base.action is TriageAction.NO_ACTION:
        if base.reason is not TriageReason.ALREADY_RESOLVED:
            raise LinkedWebhookTriageInconsistent(
                "Resolved event has unexpected triage reason"
            )

        # No need for another DB lookup on resolved events.
        return LinkedWebhookTriageInspection(
            organization_id=organization_id,
            record_id=record_id,
            event_id=base.event_id,
            action=TriageAction.NO_ACTION,
            reason=TriageReason.ALREADY_RESOLVED,
            linkage_kind=None,
        )

    # Existing base inspector must recommend manual review
    # because it has no trusted provider-object linkage.
    if (
        base.action is not TriageAction.QUARANTINE
        or base.reason is not TriageReason.UNKNOWN_OBJECT
    ):
        raise LinkedWebhookTriageInconsistent(
            "Unexpected base triage decision"
        )

    local = linkage.inspect_local_payment_reference(
        db,
        organization_id=organization_id,
        record_id=record_id,
    )

    _check_linkage(local, base=base)

    if local.kind is linkage.PaymentLinkKind.ALREADY_RESOLVED:
        raise LinkedWebhookTriageInconsistent(
            "Inbox lifecycle changed during inspection"
        )

    if local.kind is linkage.PaymentLinkKind.LOCAL_REFERENCE:
        if (
            not _valid_uuid(local.attempt_id)
            or not _valid_uuid(local.order_id)
            or not isinstance(
                local.local_attempt_state,
                PaymentState,
            )
            or local.local_order_status not in (
                "open",
                "paid",
                "cancelled",
            )
        ):
            raise LinkedWebhookTriageInconsistent(
                "Linked local payment reference is incomplete"
            )

        # This is only a recommendation for a future,
        # separately authorized READ-ONLY provider check.
        # It does not confirm success or authorize any retry.
        return LinkedWebhookTriageInspection(
            organization_id=organization_id,
            record_id=record_id,
            event_id=base.event_id,
            action=TriageAction.RECONCILE,
            reason=TriageReason.READ_CONFIRMATION_REQUIRED,
            linkage_kind=local.kind,
            local_attempt_id=local.attempt_id,
            local_order_id=local.order_id,
        )

    if local.kind in (
        linkage.PaymentLinkKind.UNLINKED,
        linkage.PaymentLinkKind.REFUND_UNSUPPORTED,
    ):
        if (
            local.attempt_id is not None
            or local.order_id is not None
            or local.local_attempt_state is not None
            or local.local_order_status is not None
        ):
            raise LinkedWebhookTriageInconsistent(
                "Unsupported event unexpectedly exposes local linkage"
            )

        return LinkedWebhookTriageInspection(
            organization_id=organization_id,
            record_id=record_id,
            event_id=base.event_id,
            action=TriageAction.QUARANTINE,
            reason=TriageReason.UNKNOWN_OBJECT,
            linkage_kind=local.kind,
        )

    raise LinkedWebhookTriageInconsistent(
        "Unsupported payment linkage decision"
    )
