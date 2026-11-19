"""Tests for read-only integrated sandbox webhook triage."""

from dataclasses import FrozenInstanceError, replace
from types import SimpleNamespace
from uuid import UUID

import pytest

import app.services.webhook_linked_triage as combined

from app.payments.contracts import PaymentState
from app.payments.webhook_processing_policy import (
    TriageAction,
    TriageReason,
)
from app.services.webhook_payment_linkage import (
    PaymentLinkInspection,
    PaymentLinkIntegrityError,
    PaymentLinkKind,
)
from app.services.webhook_triage import (
    WebhookTriageInspection,
    WebhookTriageNotFound,
)


ORG = UUID("11111111-1111-4111-8111-111111111111")
OTHER_ORG = UUID("22222222-2222-4222-8222-222222222222")
RECORD = UUID("33333333-3333-4333-8333-333333333333")
ATTEMPT = UUID("44444444-4444-4444-8444-444444444444")
ORDER = UUID("55555555-5555-4555-8555-555555555555")


class FakeSession:
    def __init__(self, *, active=True, dialect="postgresql"):
        self.active = active
        self.dialect = dialect

    def in_transaction(self):
        return self.active

    def get_bind(self):
        return SimpleNamespace(
            dialect=SimpleNamespace(name=self.dialect)
        )

    def commit(self):
        raise AssertionError("Must not commit")

    def rollback(self):
        raise AssertionError("Must not roll back")

    def flush(self):
        raise AssertionError("Must not flush")


def base_result(
    *,
    action=TriageAction.QUARANTINE,
    reason=TriageReason.UNKNOWN_OBJECT,
    **changes,
):
    values = {
        "organization_id": ORG,
        "record_id": RECORD,
        "event_id": "evt_linked_triage_001",
        "action": action,
        "reason": reason,
        "persisted": False,
    }

    values.update(changes)

    return WebhookTriageInspection(**values)


def local_result(kind=PaymentLinkKind.LOCAL_REFERENCE, **changes):
    values = {
        "organization_id": ORG,
        "record_id": RECORD,
        "event_id": "evt_linked_triage_001",
        "kind": kind,
        "attempt_id": ATTEMPT if kind is PaymentLinkKind.LOCAL_REFERENCE else None,
        "order_id": ORDER if kind is PaymentLinkKind.LOCAL_REFERENCE else None,
        "local_attempt_state": (
            PaymentState.PROCESSING
            if kind is PaymentLinkKind.LOCAL_REFERENCE
            else None
        ),
        "local_order_status": (
            "open"
            if kind is PaymentLinkKind.LOCAL_REFERENCE
            else None
        ),
    }

    values.update(changes)

    return PaymentLinkInspection(**values)


def install(monkeypatch, *, base=None, local=None):
    monkeypatch.setattr(
        combined,
        "get_settings",
        lambda: SimpleNamespace(
            app_env="development",
            sandbox_payment_attempts_enabled=True,
        ),
    )

    calls = []

    if base is None:
        base = base_result()

    if local is None:
        local = local_result()

    def inspect_base(db, *, organization_id, record_id):
        calls.append(("base", db, organization_id, record_id))

        if isinstance(base, Exception):
            raise base

        return base

    def inspect_local(db, *, organization_id, record_id):
        calls.append(("local", db, organization_id, record_id))

        if isinstance(local, Exception):
            raise local

        return local

    monkeypatch.setattr(
        combined.triage,
        "inspect_sandbox_webhook",
        inspect_base,
    )

    monkeypatch.setattr(
        combined.linkage,
        "inspect_local_payment_reference",
        inspect_local,
    )

    return calls


def inspect(db=None, **changes):
    if db is None:
        db = FakeSession()

    values = {
        "organization_id": ORG,
        "record_id": RECORD,
    }

    values.update(changes)

    return combined.inspect_linked_sandbox_webhook(
        db,
        **values,
    )


def test_matched_local_payment_recommends_read_only_reconciliation(
    monkeypatch
):
    calls = install(monkeypatch)
    db = FakeSession()

    result = inspect(db)

    assert result.action is TriageAction.RECONCILE
    assert result.reason is TriageReason.READ_CONFIRMATION_REQUIRED
    assert result.linkage_kind is PaymentLinkKind.LOCAL_REFERENCE
    assert result.local_attempt_id == ATTEMPT
    assert result.local_order_id == ORDER
    assert result.persisted is False

    assert calls == [
        ("base", db, ORG, RECORD),
        ("local", db, ORG, RECORD),
    ]


@pytest.mark.parametrize(
    "state",
    [
        PaymentState.CREATED,
        PaymentState.PROCESSING,
        PaymentState.AUTHORIZED,
        PaymentState.SUCCEEDED,
        PaymentState.FAILED,
        PaymentState.CANCELLED,
    ],
)
def test_local_state_never_confirms_payment(monkeypatch, state):
    install(
        monkeypatch,
        local=local_result(
            local_attempt_state=state,
        ),
    )

    result = inspect()

    assert result.action is TriageAction.RECONCILE
    assert result.reason is TriageReason.READ_CONFIRMATION_REQUIRED

    for forbidden in (
        "provider_confirmed",
        "settlement_confirmed",
        "payment_state",
        "retry_payment",
        "mutation_authorized",
    ):
        assert not hasattr(result, forbidden)


@pytest.mark.parametrize(
    "kind",
    [
        PaymentLinkKind.UNLINKED,
        PaymentLinkKind.REFUND_UNSUPPORTED,
    ],
)
def test_unlinked_and_refund_remain_manual_review(
    monkeypatch, kind
):
    install(
        monkeypatch,
        local=local_result(kind),
    )

    result = inspect()

    assert result.action is TriageAction.QUARANTINE
    assert result.reason is TriageReason.UNKNOWN_OBJECT
    assert result.linkage_kind is kind
    assert result.local_attempt_id is None
    assert result.local_order_id is None
    assert result.persisted is False


@pytest.mark.parametrize(
    "status",
    ["processed", "quarantined"],
)
def test_resolved_event_skips_payment_linkage(monkeypatch, status):
    calls = install(
        monkeypatch,
        base=base_result(
            action=TriageAction.NO_ACTION,
            reason=TriageReason.ALREADY_RESOLVED,
        ),
        local=AssertionError(
            "Resolved events must not perform linkage"
        ),
    )

    result = inspect()

    assert result.action is TriageAction.NO_ACTION
    assert result.reason is TriageReason.ALREADY_RESOLVED
    assert result.linkage_kind is None
    assert result.persisted is False
    assert [entry[0] for entry in calls] == ["base"]


@pytest.mark.parametrize(
    "bad_organization",
    [None, "tenant", UUID(int=0)],
)
def test_invalid_organization_rejected_before_inspection(
    monkeypatch, bad_organization
):
    calls = install(monkeypatch)

    with pytest.raises(ValueError):
        inspect(organization_id=bad_organization)

    assert calls == []


@pytest.mark.parametrize(
    "bad_record",
    [None, "inbox", UUID(int=0)],
)
def test_invalid_record_rejected_before_inspection(
    monkeypatch, bad_record
):
    calls = install(monkeypatch)

    with pytest.raises(ValueError):
        inspect(record_id=bad_record)

    assert calls == []


@pytest.mark.parametrize(
    "environment,enabled",
    [
        ("development", False),
        ("staging", False),
        ("staging", True),
        ("production", False),
        ("production", True),
    ],
)
def test_disabled_environment_prevents_inspection(
    monkeypatch, environment, enabled
):
    calls = install(monkeypatch)

    monkeypatch.setattr(
        combined,
        "get_settings",
        lambda: SimpleNamespace(
            app_env=environment,
            sandbox_payment_attempts_enabled=enabled,
        ),
    )

    with pytest.raises(combined.LinkedWebhookTriageUnavailable):
        inspect()

    assert calls == []


def test_caller_owned_transaction_required(monkeypatch):
    calls = install(monkeypatch)

    with pytest.raises(combined.LinkedWebhookTriageUnavailable):
        inspect(FakeSession(active=False))

    assert calls == []


def test_postgresql_required(monkeypatch):
    calls = install(monkeypatch)

    with pytest.raises(combined.LinkedWebhookTriageUnavailable):
        inspect(FakeSession(dialect="sqlite"))

    assert calls == []


def test_cross_tenant_event_not_found_propagates(monkeypatch):
    calls = install(
        monkeypatch,
        base=WebhookTriageNotFound(
            "Webhook inbox record not found"
        ),
    )

    with pytest.raises(WebhookTriageNotFound):
        inspect()

    assert [entry[0] for entry in calls] == ["base"]


def test_local_reference_integrity_failure_propagates(monkeypatch):
    install(
        monkeypatch,
        local=PaymentLinkIntegrityError(
            "Local payment reference integrity check failed"
        ),
    )

    with pytest.raises(PaymentLinkIntegrityError):
        inspect()


@pytest.mark.parametrize(
    "changes",
    [
        {"organization_id": OTHER_ORG},
        {"record_id": UUID("66666666-6666-4666-8666-666666666666")},
        {"event_id": "evt_wrong"},
    ],
)
def test_inconsistent_linked_identity_fails_closed(
    monkeypatch, changes
):
    install(
        monkeypatch,
        local=local_result(**changes),
    )

    with pytest.raises(
        combined.LinkedWebhookTriageInconsistent
    ):
        inspect()


@pytest.mark.parametrize(
    "changes",
    [
        {"organization_id": OTHER_ORG},
        {"record_id": UUID("66666666-6666-4666-8666-666666666666")},
        {"persisted": True},
        {"event_id": ""},
    ],
)
def test_inconsistent_base_result_fails_closed(
    monkeypatch, changes
):
    install(
        monkeypatch,
        base=base_result(**changes),
    )

    with pytest.raises(
        combined.LinkedWebhookTriageInconsistent
    ):
        inspect()


def test_already_resolved_linkage_conflict_fails_closed(monkeypatch):
    install(
        monkeypatch,
        local=local_result(
            PaymentLinkKind.ALREADY_RESOLVED,
        ),
    )

    with pytest.raises(
        combined.LinkedWebhookTriageInconsistent
    ):
        inspect()


@pytest.mark.parametrize(
    "changes",
    [
        {"attempt_id": None},
        {"order_id": None},
        {"local_attempt_state": None},
        {"local_order_status": None},
        {"local_order_status": "unknown"},
    ],
)
def test_incomplete_local_linkage_fails_closed(
    monkeypatch, changes
):
    install(
        monkeypatch,
        local=local_result(**changes),
    )

    with pytest.raises(
        combined.LinkedWebhookTriageInconsistent
    ):
        inspect()


@pytest.mark.parametrize(
    "kind",
    [
        PaymentLinkKind.UNLINKED,
        PaymentLinkKind.REFUND_UNSUPPORTED,
    ],
)
def test_unsupported_linkage_cannot_expose_payment_ids(
    monkeypatch, kind
):
    install(
        monkeypatch,
        local=local_result(
            kind,
            attempt_id=ATTEMPT,
        ),
    )

    with pytest.raises(
        combined.LinkedWebhookTriageInconsistent
    ):
        inspect()


def test_unexpected_base_decision_fails_closed(monkeypatch):
    install(
        monkeypatch,
        base=base_result(
            action=TriageAction.RECONCILE,
            reason=TriageReason.READ_CONFIRMATION_REQUIRED,
        ),
    )

    with pytest.raises(
        combined.LinkedWebhookTriageInconsistent
    ):
        inspect()


def test_incorrect_resolved_reason_fails_closed(monkeypatch):
    install(
        monkeypatch,
        base=base_result(
            action=TriageAction.NO_ACTION,
            reason=TriageReason.UNKNOWN_OBJECT,
        ),
    )

    with pytest.raises(
        combined.LinkedWebhookTriageInconsistent
    ):
        inspect()


def test_result_is_immutable(monkeypatch):
    install(monkeypatch)

    result = inspect()

    with pytest.raises(FrozenInstanceError):
        result.action = TriageAction.NO_ACTION


def test_no_financial_state_authorization(monkeypatch):
    install(monkeypatch)

    result = inspect()

    assert result.persisted is False
    assert result.action is TriageAction.RECONCILE
    assert not hasattr(result, "provider_confirmed")
    assert not hasattr(result, "settlement_confirmed")
    assert not hasattr(result, "payment_state")
    assert not hasattr(result, "retry_payment")
    assert not hasattr(result, "mutation_authorized")
