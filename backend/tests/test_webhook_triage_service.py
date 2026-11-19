"""Database-independent tests of the webhook triage boundary."""

from dataclasses import FrozenInstanceError
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest

import app.services.webhook_triage as triage
from app.payments.webhook_processing_policy import (
    TriageAction,
    TriageReason,
)


ORG = UUID("11111111-1111-4111-8111-111111111111")
OTHER_ORG = UUID("22222222-2222-4222-8222-222222222222")
RECORD = UUID("33333333-3333-4333-8333-333333333333")


def make_record(**changes):
    values = {
        "id": RECORD,
        "organization_id": ORG,
        "provider_code": "sandbox_sim",
        "event_id": "evt_triage_001",
        "event_type": "payment.succeeded",
        "provider_object_id": "sim_pay_" + "a" * 32,
        "occurred_at": 2_000_000_000,
        "status": "received",
    }

    values.update(changes)

    return SimpleNamespace(**values)


class FakeSession:
    def __init__(
        self,
        row=None,
        *,
        active=True,
        dialect="postgresql",
    ):
        self.row = row
        self.active = active
        self.dialect = dialect
        self.calls = []

    def in_transaction(self):
        return self.active

    def get_bind(self):
        return SimpleNamespace(
            dialect=SimpleNamespace(name=self.dialect)
        )

    def execute(self, statement, parameters=None):
        self.calls.append(("lock", str(statement), parameters))
        assert "pg_advisory_xact_lock" in str(statement)
        assert isinstance(parameters["lock_key"], int)
        return None

    def scalar(self, statement):
        self.calls.append(("lookup", str(statement), None))

        # Both tenant and inbox record must be SQL predicates.
        query = str(statement)
        assert "organization_id" in query
        assert "provider_event_inbox.id" in query

        return self.row

    def commit(self):
        raise AssertionError("Triage must not commit")

    def rollback(self):
        raise AssertionError("Triage must not roll back")

    def flush(self):
        raise AssertionError("Triage must not flush")


def enable_development(monkeypatch):
    monkeypatch.setattr(
        triage,
        "get_settings",
        lambda: SimpleNamespace(
            app_env="development",
            sandbox_payment_attempts_enabled=True,
        ),
    )


def inspect(db, **changes):
    args = {
        "organization_id": ORG,
        "record_id": RECORD,
    }

    args.update(changes)

    return triage.inspect_sandbox_webhook(db, **args)


def test_valid_received_event_is_review_only(monkeypatch):
    enable_development(monkeypatch)

    db = FakeSession(make_record())
    result = inspect(db)

    assert result.record_id == RECORD
    assert result.organization_id == ORG
    assert result.action is TriageAction.QUARANTINE
    assert result.reason is TriageReason.UNKNOWN_OBJECT
    assert result.persisted is False

    assert [item[0] for item in db.calls] == [
        "lock",
        "lookup",
    ]


@pytest.mark.parametrize(
    "status",
    ["processed", "quarantined"],
)
def test_resolved_records_do_not_trigger_processing(
    monkeypatch, status
):
    enable_development(monkeypatch)

    result = inspect(
        FakeSession(make_record(status=status))
    )

    assert result.action is TriageAction.NO_ACTION
    assert result.reason is TriageReason.ALREADY_RESOLVED
    assert result.persisted is False


@pytest.mark.parametrize(
    "environment,enabled",
    [
        ("development", False),
        ("staging", True),
        ("staging", False),
        ("production", True),
        ("production", False),
    ],
)
def test_disabled_environment_does_not_touch_database(
    monkeypatch, environment, enabled
):
    monkeypatch.setattr(
        triage,
        "get_settings",
        lambda: SimpleNamespace(
            app_env=environment,
            sandbox_payment_attempts_enabled=enabled,
        ),
    )

    db = FakeSession(make_record())

    with pytest.raises(triage.WebhookTriageUnavailable):
        inspect(db)

    assert db.calls == []


@pytest.mark.parametrize(
    "bad_value",
    [None, "org", UUID(int=0)],
)
def test_invalid_organization_rejected_before_database(
    monkeypatch, bad_value
):
    enable_development(monkeypatch)

    db = FakeSession(make_record())

    with pytest.raises(ValueError):
        inspect(db, organization_id=bad_value)

    assert db.calls == []


@pytest.mark.parametrize(
    "bad_value",
    [None, "record", UUID(int=0)],
)
def test_invalid_record_id_rejected_before_database(
    monkeypatch, bad_value
):
    enable_development(monkeypatch)

    db = FakeSession(make_record())

    with pytest.raises(ValueError):
        inspect(db, record_id=bad_value)

    assert db.calls == []


def test_transaction_is_required(monkeypatch):
    enable_development(monkeypatch)

    db = FakeSession(make_record(), active=False)

    with pytest.raises(triage.WebhookTriageUnavailable):
        inspect(db)

    assert db.calls == []


def test_non_postgres_session_is_rejected(monkeypatch):
    enable_development(monkeypatch)

    db = FakeSession(make_record(), dialect="sqlite")

    with pytest.raises(triage.WebhookTriageUnavailable):
        inspect(db)

    assert db.calls == []


def test_missing_record_does_not_create_data(monkeypatch):
    enable_development(monkeypatch)

    db = FakeSession()

    with pytest.raises(triage.WebhookTriageNotFound):
        inspect(db)

    assert [item[0] for item in db.calls] == [
        "lock",
        "lookup",
    ]


def test_cross_tenant_record_is_not_disclosed(monkeypatch):
    enable_development(monkeypatch)

    db = FakeSession(make_record(organization_id=OTHER_ORG))

    with pytest.raises(triage.WebhookTriageNotFound):
        inspect(db)


def test_wrong_record_id_is_not_disclosed(monkeypatch):
    enable_development(monkeypatch)

    db = FakeSession(make_record(id=uuid4()))

    with pytest.raises(triage.WebhookTriageNotFound):
        inspect(db)


@pytest.mark.parametrize(
    "bad_type",
    ["payment.unknown", "refund.succeeded", None],
)
def test_invalid_event_type_or_object_mapping_fails_closed(
    monkeypatch, bad_type
):
    enable_development(monkeypatch)

    db = FakeSession(make_record(event_type=bad_type))

    with pytest.raises(triage.WebhookTriageInvalidRecord):
        inspect(db)


@pytest.mark.parametrize(
    "invalid_status",
    ["waiting", "", None],
)
def test_invalid_stored_lifecycle_fails_closed(
    monkeypatch, invalid_status
):
    enable_development(monkeypatch)

    with pytest.raises(triage.WebhookTriageInvalidRecord):
        inspect(FakeSession(make_record(status=invalid_status)))


def test_invalid_stored_provider_fails_closed(monkeypatch):
    enable_development(monkeypatch)

    db = FakeSession(make_record(provider_code="real_gateway"))

    with pytest.raises(triage.WebhookTriageInvalidRecord):
        inspect(db)


def test_advisory_lock_is_stable_and_tenant_scoped():
    first = triage._advisory_lock_key(ORG, RECORD)
    second = triage._advisory_lock_key(ORG, RECORD)
    different_tenant = triage._advisory_lock_key(
        OTHER_ORG, RECORD
    )
    different_record = triage._advisory_lock_key(
        ORG, uuid4()
    )

    assert first == second
    assert first != different_tenant
    assert first != different_record

    assert -(2**63) <= first < 2**63


def test_inspection_result_cannot_be_mutated(monkeypatch):
    enable_development(monkeypatch)

    result = inspect(FakeSession(make_record()))

    with pytest.raises(FrozenInstanceError):
        result.persisted = True


def test_inspection_does_not_authorize_money_movement(
    monkeypatch
):
    enable_development(monkeypatch)

    result = inspect(FakeSession(make_record()))

    assert not hasattr(result, "payment_state")
    assert not hasattr(result, "refund_state")
    assert not hasattr(result, "retry_payment")
    assert not hasattr(result, "settlement_confirmed")
