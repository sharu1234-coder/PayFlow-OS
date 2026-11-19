"""Read-only sandbox webhook payment linkage security tests."""

from dataclasses import FrozenInstanceError
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest

import app.services.webhook_payment_linkage as linkage

from app.payments.contracts import PaymentState


ORG_A = UUID("11111111-1111-4111-8111-111111111111")
ORG_B = UUID("22222222-2222-4222-8222-222222222222")

RECORD_ID = UUID("33333333-3333-4333-8333-333333333333")
ATTEMPT_ID = UUID("44444444-4444-4444-8444-444444444444")
ORDER_ID = UUID("55555555-5555-4555-8555-555555555555")

PAYMENT_ID = "sim_pay_" + "a" * 32
REFUND_ID = "sim_ref_" + "b" * 32


def event_row(**changes):
    values = {
        "id": RECORD_ID,
        "organization_id": ORG_A,
        "provider_code": "sandbox_sim",
        "event_id": "evt_local_link_001",
        "event_type": "payment.succeeded",
        "provider_object_id": PAYMENT_ID,
        "occurred_at": 2_000_000_000,
        "status": "received",
    }

    values.update(changes)
    return SimpleNamespace(**values)


def attempt_row(**changes):
    values = {
        "id": ATTEMPT_ID,
        "organization_id": ORG_A,
        "order_id": ORDER_ID,
        "attempt_number": 1,
        "provider_code": "sandbox_sim",
        "provider_payment_id": PAYMENT_ID,
        "amount_minor_units": 12500,
        "currency": "INR",
        "status": "processing",
    }

    values.update(changes)
    return SimpleNamespace(**values)


def order_row(**changes):
    values = {
        "id": ORDER_ID,
        "organization_id": ORG_A,
        "amount_minor_units": 12500,
        "currency": "INR",
        "status": "open",
    }

    values.update(changes)
    return SimpleNamespace(**values)


class FakeSession:
    def __init__(
        self,
        rows=(),
        *,
        transaction=True,
        dialect="postgresql",
    ):
        self.rows = list(rows)
        self.transaction = transaction
        self.dialect = dialect
        self.calls = []

    def in_transaction(self):
        return self.transaction

    def get_bind(self):
        return SimpleNamespace(
            dialect=SimpleNamespace(name=self.dialect)
        )

    def execute(self, statement, parameters=None):
        query = str(statement)
        self.calls.append(("lock", query))

        assert "pg_advisory_xact_lock" in query
        assert isinstance(parameters["lock_key"], int)

        return None

    def scalar(self, statement):
        query = str(statement)
        self.calls.append(("lookup", query))

        assert self.rows, "Unexpected additional database read"

        position = len([
            call for call in self.calls
            if call[0] == "lookup"
        ])

        if position == 1:
            assert "provider_event_inbox.organization_id" in query
            assert "provider_event_inbox.id" in query

        elif position == 2:
            assert "payment_attempts.organization_id" in query
            assert "payment_attempts.provider_code" in query
            assert "payment_attempts.provider_payment_id" in query

        elif position == 3:
            assert "payment_orders.organization_id" in query
            assert "payment_orders.id" in query
            assert "payment_orders.amount_minor_units" in query
            assert "payment_orders.currency" in query

        else:
            raise AssertionError("Unexpected SQL lookup")

        return self.rows.pop(0)

    def flush(self):
        raise AssertionError("Linkage must not flush")

    def commit(self):
        raise AssertionError("Linkage must not commit")

    def rollback(self):
        raise AssertionError("Linkage must not rollback")

    def add(self, value):
        raise AssertionError("Linkage must not add records")


def enable(monkeypatch):
    monkeypatch.setattr(
        linkage,
        "get_settings",
        lambda: SimpleNamespace(
            app_env="development",
            sandbox_payment_attempts_enabled=True,
        ),
    )


def inspect(db, **changes):
    values = {
        "organization_id": ORG_A,
        "record_id": RECORD_ID,
    }

    values.update(changes)

    return linkage.inspect_local_payment_reference(
        db,
        **values,
    )


def test_matching_local_payment_reference(monkeypatch):
    enable(monkeypatch)

    db = FakeSession([
        event_row(),
        attempt_row(),
        order_row(),
    ])

    result = inspect(db)

    assert result.kind is linkage.PaymentLinkKind.LOCAL_REFERENCE
    assert result.organization_id == ORG_A
    assert result.record_id == RECORD_ID
    assert result.attempt_id == ATTEMPT_ID
    assert result.order_id == ORDER_ID
    assert result.local_attempt_state is PaymentState.PROCESSING
    assert result.local_order_status == "open"

    assert [x[0] for x in db.calls] == [
        "lock",
        "lookup",
        "lookup",
        "lookup",
    ]


def test_local_success_does_not_confirm_settlement(monkeypatch):
    enable(monkeypatch)

    result = inspect(FakeSession([
        event_row(),
        attempt_row(status="succeeded"),
        order_row(status="paid"),
    ]))

    assert result.kind is linkage.PaymentLinkKind.LOCAL_REFERENCE
    assert result.local_attempt_state is PaymentState.SUCCEEDED

    for forbidden in (
        "provider_confirmed",
        "settlement_confirmed",
        "retry_authorized",
        "amount_to_capture",
        "payment_state",
    ):
        assert not hasattr(result, forbidden)


def test_missing_local_reference_fails_closed(monkeypatch):
    enable(monkeypatch)

    db = FakeSession([
        event_row(),
        None,
    ])

    result = inspect(db)

    assert result.kind is linkage.PaymentLinkKind.UNLINKED
    assert result.attempt_id is None
    assert result.order_id is None
    assert len(db.calls) == 3


def test_legacy_sandbox_attempt_is_not_implicitly_linked(
    monkeypatch
):
    enable(monkeypatch)

    # Exact SQL provider_code + provider_payment_id matching
    # must not return historical "sandbox" / NULL attempts.
    db = FakeSession([
        event_row(),
        None,
    ])

    result = inspect(db)

    assert result.kind is linkage.PaymentLinkKind.UNLINKED

    lookup = db.calls[-1][1]

    assert "payment_attempts.provider_code" in lookup
    assert "payment_attempts.provider_payment_id" in lookup


def test_refund_linkage_is_not_invented(monkeypatch):
    enable(monkeypatch)

    db = FakeSession([
        event_row(
            event_type="refund.succeeded",
            provider_object_id=REFUND_ID,
        ),
    ])

    result = inspect(db)

    assert result.kind is linkage.PaymentLinkKind.REFUND_UNSUPPORTED
    assert result.attempt_id is None
    assert len(db.calls) == 2


@pytest.mark.parametrize(
    "status",
    ["processed", "quarantined"],
)
def test_resolved_event_skips_payment_lookup(
    monkeypatch,
    status,
):
    enable(monkeypatch)

    db = FakeSession([
        event_row(status=status),
    ])

    result = inspect(db)

    assert result.kind is linkage.PaymentLinkKind.ALREADY_RESOLVED
    assert len(db.calls) == 2


def test_event_is_missing(monkeypatch):
    enable(monkeypatch)

    with pytest.raises(linkage.PaymentLinkNotFound):
        inspect(FakeSession([None]))


def test_cross_tenant_event_is_not_returned(monkeypatch):
    enable(monkeypatch)

    with pytest.raises(linkage.PaymentLinkNotFound):
        inspect(FakeSession([
            event_row(organization_id=ORG_B),
        ]))


def test_wrong_event_id_is_not_returned(monkeypatch):
    enable(monkeypatch)

    with pytest.raises(linkage.PaymentLinkNotFound):
        inspect(FakeSession([
            event_row(id=uuid4()),
        ]))


def test_wrong_tenant_attempt_is_rejected(monkeypatch):
    enable(monkeypatch)

    with pytest.raises(linkage.PaymentLinkIntegrityError):
        inspect(FakeSession([
            event_row(),
            attempt_row(organization_id=ORG_B),
        ]))


def test_mismatched_provider_attempt_is_rejected(monkeypatch):
    enable(monkeypatch)

    with pytest.raises(linkage.PaymentLinkIntegrityError):
        inspect(FakeSession([
            event_row(),
            attempt_row(provider_code="sandbox"),
        ]))


def test_mismatched_provider_payment_id_is_rejected(
    monkeypatch
):
    enable(monkeypatch)

    with pytest.raises(linkage.PaymentLinkIntegrityError):
        inspect(FakeSession([
            event_row(),
            attempt_row(
                provider_payment_id="sim_pay_" + "c" * 32
            ),
        ]))


@pytest.mark.parametrize(
    "bad_status",
    ["unknown", "", None],
)
def test_invalid_payment_attempt_state_fails_closed(
    monkeypatch,
    bad_status,
):
    enable(monkeypatch)

    with pytest.raises(linkage.PaymentLinkIntegrityError):
        inspect(FakeSession([
            event_row(),
            attempt_row(status=bad_status),
        ]))


@pytest.mark.parametrize(
    "bad_amount",
    [0, -1, True],
)
def test_invalid_local_amount_fails_closed(
    monkeypatch,
    bad_amount,
):
    enable(monkeypatch)

    with pytest.raises(linkage.PaymentLinkIntegrityError):
        inspect(FakeSession([
            event_row(),
            attempt_row(amount_minor_units=bad_amount),
        ]))


def test_missing_order_fails_closed(monkeypatch):
    enable(monkeypatch)

    with pytest.raises(linkage.PaymentLinkIntegrityError):
        inspect(FakeSession([
            event_row(),
            attempt_row(),
            None,
        ]))


def test_cross_tenant_order_fails_closed(monkeypatch):
    enable(monkeypatch)

    with pytest.raises(linkage.PaymentLinkIntegrityError):
        inspect(FakeSession([
            event_row(),
            attempt_row(),
            order_row(organization_id=ORG_B),
        ]))


def test_order_amount_mismatch_fails_closed(monkeypatch):
    enable(monkeypatch)

    with pytest.raises(linkage.PaymentLinkIntegrityError):
        inspect(FakeSession([
            event_row(),
            attempt_row(),
            order_row(amount_minor_units=100),
        ]))


def test_order_currency_mismatch_fails_closed(monkeypatch):
    enable(monkeypatch)

    with pytest.raises(linkage.PaymentLinkIntegrityError):
        inspect(FakeSession([
            event_row(),
            attempt_row(),
            order_row(currency="USD"),
        ]))


def test_invalid_event_type_fails_closed(monkeypatch):
    enable(monkeypatch)

    with pytest.raises(linkage.PaymentLinkInvalidRecord):
        inspect(FakeSession([
            event_row(event_type="payment.unknown"),
        ]))


def test_event_provider_mismatch_fails_closed(monkeypatch):
    enable(monkeypatch)

    with pytest.raises(linkage.PaymentLinkInvalidRecord):
        inspect(FakeSession([
            event_row(provider_code="real_gateway"),
        ]))


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
def test_disabled_environment_has_no_database_access(
    monkeypatch,
    environment,
    enabled,
):
    monkeypatch.setattr(
        linkage,
        "get_settings",
        lambda: SimpleNamespace(
            app_env=environment,
            sandbox_payment_attempts_enabled=enabled,
        ),
    )

    db = FakeSession([
        event_row(),
    ])

    with pytest.raises(linkage.PaymentLinkUnavailable):
        inspect(db)

    assert db.calls == []


@pytest.mark.parametrize(
    "bad_value",
    [None, "organization", UUID(int=0)],
)
def test_invalid_organization_rejected_before_db(
    monkeypatch,
    bad_value,
):
    enable(monkeypatch)

    db = FakeSession([])

    with pytest.raises(ValueError):
        inspect(db, organization_id=bad_value)

    assert db.calls == []


@pytest.mark.parametrize(
    "bad_value",
    [None, "record", UUID(int=0)],
)
def test_invalid_record_id_rejected_before_db(
    monkeypatch,
    bad_value,
):
    enable(monkeypatch)

    db = FakeSession([])

    with pytest.raises(ValueError):
        inspect(db, record_id=bad_value)

    assert db.calls == []


def test_active_transaction_required(monkeypatch):
    enable(monkeypatch)

    db = FakeSession([], transaction=False)

    with pytest.raises(linkage.PaymentLinkUnavailable):
        inspect(db)

    assert db.calls == []


def test_postgresql_required(monkeypatch):
    enable(monkeypatch)

    db = FakeSession([], dialect="sqlite")

    with pytest.raises(linkage.PaymentLinkUnavailable):
        inspect(db)

    assert db.calls == []


def test_result_is_immutable(monkeypatch):
    enable(monkeypatch)

    result = inspect(FakeSession([
        event_row(),
        attempt_row(),
        order_row(),
    ]))

    with pytest.raises(FrozenInstanceError):
        result.kind = linkage.PaymentLinkKind.UNLINKED


def test_local_linkage_never_authorizes_money_movement(monkeypatch):
    enable(monkeypatch)

    result = inspect(FakeSession([
        event_row(),
        attempt_row(),
        order_row(),
    ]))

    assert result.kind is linkage.PaymentLinkKind.LOCAL_REFERENCE
    assert not hasattr(result, "retry_payment")
    assert not hasattr(result, "settlement_confirmed")
    assert not hasattr(result, "refund_status")
