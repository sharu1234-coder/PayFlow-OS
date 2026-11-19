"""Pure policy tests for conservative webhook processing."""

from dataclasses import FrozenInstanceError, replace
from uuid import UUID

import pytest

from app.payments.contracts import PaymentState, RefundState
from app.payments.webhook_contracts import SandboxEventType
from app.payments.webhook_processing_policy import (
    InboxLifecycle,
    LinkedProviderObjectSnapshot,
    ProviderObjectKind,
    StoredInboxEventSnapshot,
    TriageAction,
    TriageReason,
    plan_webhook_triage,
)


ORG_A = UUID("11111111-1111-4111-8111-111111111111")
ORG_B = UUID("22222222-2222-4222-8222-222222222222")

PAYMENT_ID = "sim_pay_" + "a" * 32
OTHER_PAYMENT_ID = "sim_pay_" + "b" * 32
REFUND_ID = "sim_ref_" + "c" * 32


def make_event(
    event_type=SandboxEventType.PAYMENT_PROCESSING,
    **changes,
):
    kind = (
        ProviderObjectKind.PAYMENT
        if event_type.value.startswith("payment.")
        else ProviderObjectKind.REFUND
    )

    values = {
        "organization_id": ORG_A,
        "provider_code": "sandbox_sim",
        "event_id": "evt_processing_001",
        "event_type": event_type,
        "provider_object_id": (
            PAYMENT_ID
            if kind is ProviderObjectKind.PAYMENT
            else REFUND_ID
        ),
        "occurred_at": 2_000_000_000,
        "lifecycle": InboxLifecycle.RECEIVED,
    }

    values.update(changes)

    return StoredInboxEventSnapshot(**values)


def make_link(event, **changes):
    kind = event.object_kind

    values = {
        "organization_id": event.organization_id,
        "provider_code": event.provider_code,
        "provider_object_id": event.provider_object_id,
        "object_kind": kind,
        "confirmed_state": (
            PaymentState.PROCESSING
            if kind is ProviderObjectKind.PAYMENT
            else RefundState.PENDING
        ),
        "last_confirmed_at": None,
    }

    values.update(changes)

    return LinkedProviderObjectSnapshot(**values)


@pytest.mark.parametrize(
    "event_type",
    list(SandboxEventType),
)
def test_all_supported_events_require_confirmation(event_type):
    event = make_event(event_type)
    linked = make_link(event)

    result = plan_webhook_triage(
        event=event,
        linked_object=linked,
    )

    assert result.action is TriageAction.RECONCILE
    assert result.reason is TriageReason.READ_CONFIRMATION_REQUIRED


def test_unlinked_event_is_quarantined():
    result = plan_webhook_triage(
        event=make_event(),
        linked_object=None,
    )

    assert result.action is TriageAction.QUARANTINE
    assert result.reason is TriageReason.UNKNOWN_OBJECT


def test_cross_tenant_link_is_quarantined():
    event = make_event()

    result = plan_webhook_triage(
        event=event,
        linked_object=make_link(
            event, organization_id=ORG_B
        ),
    )

    assert result.action is TriageAction.QUARANTINE
    assert result.reason is TriageReason.TENANT_MISMATCH


def test_provider_mismatch_is_quarantined():
    event = make_event()

    result = plan_webhook_triage(
        event=event,
        linked_object=make_link(
            event, provider_code="sandbox"
        ),
    )

    assert result.action is TriageAction.QUARANTINE
    assert result.reason is TriageReason.PROVIDER_MISMATCH


def test_payment_refund_kind_mismatch_is_quarantined():
    event = make_event()

    linked = make_link(
        event,
        object_kind=ProviderObjectKind.REFUND,
        provider_object_id=REFUND_ID,
        confirmed_state=RefundState.PENDING,
    )

    result = plan_webhook_triage(
        event=event,
        linked_object=linked,
    )

    assert result.action is TriageAction.QUARANTINE
    assert result.reason is TriageReason.OBJECT_KIND_MISMATCH


def test_provider_object_id_mismatch_is_quarantined():
    event = make_event()

    result = plan_webhook_triage(
        event=event,
        linked_object=make_link(
            event,
            provider_object_id=OTHER_PAYMENT_ID,
        ),
    )

    assert result.action is TriageAction.QUARANTINE
    assert result.reason is TriageReason.OBJECT_ID_MISMATCH


@pytest.mark.parametrize(
    "lifecycle",
    [
        InboxLifecycle.PROCESSED,
        InboxLifecycle.QUARANTINED,
    ],
)
def test_resolved_inbox_events_are_not_reprocessed(lifecycle):
    event = make_event(lifecycle=lifecycle)

    result = plan_webhook_triage(
        event=event,
        linked_object=None,
    )

    assert result.action is TriageAction.NO_ACTION
    assert result.reason is TriageReason.ALREADY_RESOLVED


def test_old_event_requires_reconciliation_not_status_change():
    event = make_event(occurred_at=2_000_000_000)

    linked = make_link(
        event,
        last_confirmed_at=2_000_000_100,
    )

    result = plan_webhook_triage(
        event=event,
        linked_object=linked,
    )

    assert result.action is TriageAction.RECONCILE
    assert result.reason is TriageReason.STALE_EVENT


@pytest.mark.parametrize(
    "current,event_type",
    [
        (
            PaymentState.SUCCEEDED,
            SandboxEventType.PAYMENT_FAILED,
        ),
        (
            PaymentState.SUCCEEDED,
            SandboxEventType.PAYMENT_PROCESSING,
        ),
        (
            PaymentState.FAILED,
            SandboxEventType.PAYMENT_SUCCEEDED,
        ),
        (
            PaymentState.CANCELLED,
            SandboxEventType.PAYMENT_SUCCEEDED,
        ),
        (
            PaymentState.CANCELLED,
            SandboxEventType.PAYMENT_PROCESSING,
        ),
    ],
)
def test_payment_terminal_conflicts_only_reconcile(
    current,
    event_type,
):
    event = make_event(event_type)

    plan = plan_webhook_triage(
        event=event,
        linked_object=make_link(
            event, confirmed_state=current
        ),
    )

    assert plan.action is TriageAction.RECONCILE
    assert plan.reason is TriageReason.TERMINAL_STATE_CONFLICT


@pytest.mark.parametrize(
    "current,event_type",
    [
        (
            RefundState.SUCCEEDED,
            SandboxEventType.REFUND_FAILED,
        ),
        (
            RefundState.SUCCEEDED,
            SandboxEventType.REFUND_PENDING,
        ),
        (
            RefundState.FAILED,
            SandboxEventType.REFUND_SUCCEEDED,
        ),
    ],
)
def test_refund_terminal_conflicts_only_reconcile(
    current,
    event_type,
):
    event = make_event(event_type)

    plan = plan_webhook_triage(
        event=event,
        linked_object=make_link(
            event, confirmed_state=current
        ),
    )

    assert plan.action is TriageAction.RECONCILE
    assert plan.reason is TriageReason.TERMINAL_STATE_CONFLICT


def test_authorized_to_processing_regression_is_detected():
    event = make_event(
        SandboxEventType.PAYMENT_PROCESSING
    )

    plan = plan_webhook_triage(
        event=event,
        linked_object=make_link(
            event,
            confirmed_state=PaymentState.AUTHORIZED,
        ),
    )

    assert plan.action is TriageAction.RECONCILE
    assert plan.reason is TriageReason.STATE_REGRESSION


def test_same_terminal_state_still_requires_confirmation():
    event = make_event(
        SandboxEventType.PAYMENT_SUCCEEDED
    )

    plan = plan_webhook_triage(
        event=event,
        linked_object=make_link(
            event,
            confirmed_state=PaymentState.SUCCEEDED,
        ),
    )

    assert plan.action is TriageAction.RECONCILE
    assert plan.reason is TriageReason.READ_CONFIRMATION_REQUIRED


@pytest.mark.parametrize(
    "bad_org",
    [None, "merchant", UUID(int=0)],
)
def test_invalid_event_organization_rejected(bad_org):
    with pytest.raises(ValueError):
        make_event(organization_id=bad_org)


@pytest.mark.parametrize(
    "bad_status",
    ["received", "unknown", None],
)
def test_untyped_or_invalid_lifecycle_rejected(bad_status):
    with pytest.raises(TypeError):
        make_event(lifecycle=bad_status)


@pytest.mark.parametrize(
    "bad_type",
    ["payment.succeeded", None, 1],
)
def test_untyped_event_type_rejected(bad_type):
    event = make_event()

    with pytest.raises(TypeError):
        replace(event, event_type=bad_type)


@pytest.mark.parametrize(
    "bad_time",
    [0, -1, True, None, "2000000000"],
)
def test_invalid_event_time_rejected(bad_time):
    with pytest.raises(ValueError):
        make_event(occurred_at=bad_time)


def test_invalid_event_object_kind_rejected():
    with pytest.raises(ValueError):
        make_event(provider_object_id=REFUND_ID)


def test_invalid_linked_payment_state_rejected():
    event = make_event()

    with pytest.raises(TypeError):
        make_link(
            event,
            confirmed_state=RefundState.SUCCEEDED,
        )


def test_invalid_linked_refund_state_rejected():
    event = make_event(
        SandboxEventType.REFUND_PENDING
    )

    with pytest.raises(TypeError):
        make_link(
            event,
            confirmed_state=PaymentState.PROCESSING,
        )


@pytest.mark.parametrize(
    "timestamp",
    [0, -1, True, "2000000000"],
)
def test_invalid_authoritative_time_rejected(timestamp):
    event = make_event()

    with pytest.raises(ValueError):
        make_link(
            event,
            last_confirmed_at=timestamp,
        )


def test_invalid_linked_provider_code_rejected():
    event = make_event()

    with pytest.raises(ValueError):
        make_link(
            event,
            provider_code="Unknown Provider!",
        )


@pytest.mark.parametrize(
    "event,linked",
    [
        (None, None),
        ("event", None),
        (make_event(), "provider"),
    ],
)
def test_invalid_policy_inputs_fail_closed(event, linked):
    with pytest.raises(TypeError):
        plan_webhook_triage(
            event=event,
            linked_object=linked,
        )


def test_triage_plan_is_immutable():
    event = make_event()

    result = plan_webhook_triage(
        event=event,
        linked_object=make_link(event),
    )

    with pytest.raises(FrozenInstanceError):
        result.action = TriageAction.NO_ACTION


def test_triage_never_authorizes_financial_mutation():
    event = make_event(
        SandboxEventType.PAYMENT_SUCCEEDED
    )

    result = plan_webhook_triage(
        event=event,
        linked_object=make_link(event),
    )

    assert result.action is TriageAction.RECONCILE
    assert not hasattr(result, "payment_state")
    assert not hasattr(result, "refund_state")
    assert not hasattr(result, "retry_payment")
    assert not hasattr(result, "settlement_confirmed")
