"""Conservative, pure sandbox webhook triage policy.

This module DOES NOT:
- Verify signatures
- Read or write the database
- Resolve provider object ownership
- Call a payment provider
- Process refunds
- Change payment or refund statuses
- Mark inbox events processed
- Trigger financial retries

All event snapshots must originate from previously verified,
durably stored inbox records. Linked-object snapshots must
come from trusted, tenant-scoped persistence/reconciliation.

A matching event is evidence requiring read-only provider
confirmation, never proof that payment state should change.

A RECONCILE decision does not authorize retrying payment or
refund creation.
"""

import re
from dataclasses import dataclass
from enum import Enum
from uuid import UUID

from app.payments.contracts import (
    PaymentState,
    RefundState,
)
from app.payments.webhook_contracts import (
    SANDBOX_PROVIDER_CODE,
    SandboxEventType,
)


_EVENT_ID_PATTERN = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z",
    flags=re.ASCII,
)

_OBJECT_ID_PATTERN = re.compile(
    r"sim_(?:pay|ref)_[0-9a-f]{32}\Z",
    flags=re.ASCII,
)

_PROVIDER_PATTERN = re.compile(
    r"[a-z][a-z0-9_]{1,31}\Z",
    flags=re.ASCII,
)


class InboxLifecycle(str, Enum):
    RECEIVED = "received"
    PROCESSED = "processed"
    QUARANTINED = "quarantined"


class ProviderObjectKind(str, Enum):
    PAYMENT = "payment"
    REFUND = "refund"


class TriageAction(str, Enum):
    NO_ACTION = "no_action"
    QUARANTINE = "quarantine"
    RECONCILE = "reconcile"


class TriageReason(str, Enum):
    ALREADY_RESOLVED = "already_resolved"
    UNKNOWN_OBJECT = "unknown_object"
    TENANT_MISMATCH = "tenant_mismatch"
    PROVIDER_MISMATCH = "provider_mismatch"
    OBJECT_KIND_MISMATCH = "object_kind_mismatch"
    OBJECT_ID_MISMATCH = "object_id_mismatch"
    STALE_EVENT = "stale_event"
    TERMINAL_STATE_CONFLICT = "terminal_state_conflict"
    STATE_REGRESSION = "state_regression"
    READ_CONFIRMATION_REQUIRED = "read_confirmation_required"


def _check_uuid(value: UUID) -> None:
    if not isinstance(value, UUID) or value.int == 0:
        raise ValueError("Valid organization UUID required")


def _check_object_id(value: str) -> None:
    if (
        type(value) is not str
        or _OBJECT_ID_PATTERN.fullmatch(value) is None
    ):
        raise ValueError("Invalid synthetic provider object ID")


def _event_kind(event_type: SandboxEventType) -> ProviderObjectKind:
    if event_type.value.startswith("payment."):
        return ProviderObjectKind.PAYMENT

    return ProviderObjectKind.REFUND


@dataclass(frozen=True, slots=True)
class StoredInboxEventSnapshot:
    """Validated read-only view of one stored inbox event."""

    organization_id: UUID
    provider_code: str
    event_id: str
    event_type: SandboxEventType
    provider_object_id: str
    occurred_at: int
    lifecycle: InboxLifecycle

    def __post_init__(self) -> None:
        _check_uuid(self.organization_id)

        if self.provider_code != SANDBOX_PROVIDER_CODE:
            raise ValueError("Only synthetic sandbox events supported")

        if (
            type(self.event_id) is not str
            or _EVENT_ID_PATTERN.fullmatch(self.event_id) is None
        ):
            raise ValueError("Invalid event ID")

        if not isinstance(self.event_type, SandboxEventType):
            raise TypeError("Invalid sandbox event type")

        _check_object_id(self.provider_object_id)

        prefix = (
            "sim_pay_"
            if self.object_kind is ProviderObjectKind.PAYMENT
            else "sim_ref_"
        )

        if not self.provider_object_id.startswith(prefix):
            raise ValueError("Event and object type mismatch")

        if (
            type(self.occurred_at) is not int
            or not 0 < self.occurred_at < 1_000_000_000_000
        ):
            raise ValueError("Invalid event occurrence timestamp")

        if not isinstance(self.lifecycle, InboxLifecycle):
            raise TypeError("Invalid inbox lifecycle")

    @property
    def object_kind(self) -> ProviderObjectKind:
        return _event_kind(self.event_type)


@dataclass(frozen=True, slots=True)
class LinkedProviderObjectSnapshot:
    """Trusted provider-object association and last known state.

    last_confirmed_at represents a trusted reconciliation
    observation time, not an unverified webhook timestamp.
    """

    organization_id: UUID
    provider_code: str
    provider_object_id: str
    object_kind: ProviderObjectKind
    confirmed_state: PaymentState | RefundState
    last_confirmed_at: int | None = None

    def __post_init__(self) -> None:
        _check_uuid(self.organization_id)

        if (
            type(self.provider_code) is not str
            or _PROVIDER_PATTERN.fullmatch(self.provider_code) is None
        ):
            raise ValueError("Invalid linked provider code")

        _check_object_id(self.provider_object_id)

        if not isinstance(self.object_kind, ProviderObjectKind):
            raise TypeError("Invalid linked object kind")

        prefix = (
            "sim_pay_"
            if self.object_kind is ProviderObjectKind.PAYMENT
            else "sim_ref_"
        )

        if not self.provider_object_id.startswith(prefix):
            raise ValueError("Linked object type mismatch")

        if self.object_kind is ProviderObjectKind.PAYMENT:
            if not isinstance(self.confirmed_state, PaymentState):
                raise TypeError("Payment requires PaymentState")
        else:
            if not isinstance(self.confirmed_state, RefundState):
                raise TypeError("Refund requires RefundState")

        if self.last_confirmed_at is not None:
            if (
                type(self.last_confirmed_at) is not int
                or not 0 < self.last_confirmed_at < 1_000_000_000_000
            ):
                raise ValueError(
                    "Invalid authoritative observation timestamp"
                )


@dataclass(frozen=True, slots=True)
class WebhookTriagePlan:
    action: TriageAction
    reason: TriageReason


_EVENT_TO_STATE = {
    SandboxEventType.PAYMENT_PROCESSING: PaymentState.PROCESSING,
    SandboxEventType.PAYMENT_SUCCEEDED: PaymentState.SUCCEEDED,
    SandboxEventType.PAYMENT_FAILED: PaymentState.FAILED,
    SandboxEventType.REFUND_PENDING: RefundState.PENDING,
    SandboxEventType.REFUND_SUCCEEDED: RefundState.SUCCEEDED,
    SandboxEventType.REFUND_FAILED: RefundState.FAILED,
}

_TERMINAL_PAYMENT = frozenset({
    PaymentState.SUCCEEDED,
    PaymentState.FAILED,
    PaymentState.CANCELLED,
})

_TERMINAL_REFUND = frozenset({
    RefundState.SUCCEEDED,
    RefundState.FAILED,
})


def plan_webhook_triage(
    *,
    event: StoredInboxEventSnapshot,
    linked_object: LinkedProviderObjectSnapshot | None,
) -> WebhookTriagePlan:
    """Plan a safe next action without financial state mutation.

    RECONCILE means a separate authorized component should
    consider a bounded READ-ONLY provider check.

    QUARANTINE means automatic processing is unsafe.

    NO_ACTION means the inbox event was already resolved.

    This plan does not claim a work item, establish locks,
    prove delivery authorization, or update inbox status.
    """

    if not isinstance(event, StoredInboxEventSnapshot):
        raise TypeError("Expected stored inbox event snapshot")

    if (
        linked_object is not None
        and not isinstance(linked_object, LinkedProviderObjectSnapshot)
    ):
        raise TypeError("Invalid linked provider object snapshot")

    if event.lifecycle is not InboxLifecycle.RECEIVED:
        return WebhookTriagePlan(
            TriageAction.NO_ACTION,
            TriageReason.ALREADY_RESOLVED,
        )

    if linked_object is None:
        return WebhookTriagePlan(
            TriageAction.QUARANTINE,
            TriageReason.UNKNOWN_OBJECT,
        )

    if event.organization_id != linked_object.organization_id:
        return WebhookTriagePlan(
            TriageAction.QUARANTINE,
            TriageReason.TENANT_MISMATCH,
        )

    if event.provider_code != linked_object.provider_code:
        return WebhookTriagePlan(
            TriageAction.QUARANTINE,
            TriageReason.PROVIDER_MISMATCH,
        )

    if event.object_kind is not linked_object.object_kind:
        return WebhookTriagePlan(
            TriageAction.QUARANTINE,
            TriageReason.OBJECT_KIND_MISMATCH,
        )

    if event.provider_object_id != linked_object.provider_object_id:
        return WebhookTriagePlan(
            TriageAction.QUARANTINE,
            TriageReason.OBJECT_ID_MISMATCH,
        )

    if (
        linked_object.last_confirmed_at is not None
        and event.occurred_at < linked_object.last_confirmed_at
    ):
        return WebhookTriagePlan(
            TriageAction.RECONCILE,
            TriageReason.STALE_EVENT,
        )

    incoming_state = _EVENT_TO_STATE[event.event_type]
    current_state = linked_object.confirmed_state

    terminal_states = (
        _TERMINAL_PAYMENT
        if event.object_kind is ProviderObjectKind.PAYMENT
        else _TERMINAL_REFUND
    )

    if (
        current_state in terminal_states
        and incoming_state != current_state
    ):
        return WebhookTriagePlan(
            TriageAction.RECONCILE,
            TriageReason.TERMINAL_STATE_CONFLICT,
        )

    if (
        event.object_kind is ProviderObjectKind.PAYMENT
        and current_state is PaymentState.AUTHORIZED
        and incoming_state is PaymentState.PROCESSING
    ):
        return WebhookTriagePlan(
            TriageAction.RECONCILE,
            TriageReason.STATE_REGRESSION,
        )

    return WebhookTriagePlan(
        TriageAction.RECONCILE,
        TriageReason.READ_CONFIRMATION_REQUIRED,
    )
