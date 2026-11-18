"""Database-independent idempotent attempt service tests."""

import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy.dialects import postgresql
from sqlalchemy.sql.dml import Insert, Update

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
from app.services import payment_attempt_idempotency as service
from app.services.payment_attempts import (
    CreatedSandboxPaymentAttempt,
    PaymentAttemptAccessDenied,
    PaymentAttemptOrderNotFound,
)


ACTOR = uuid.UUID("1a43188b-f293-4a1f-9f8c-95d23606c928")
ORG = uuid.UUID("bfed88b3-edeb-48d0-b671-9406a689daba")
ORDER = uuid.UUID("945e6aae-75b4-455b-bb23-a76b9d974b76")
OTHER_ORDER = uuid.UUID(
    "2a38ff5e-ec37-4e1f-b96d-98ffba19984e"
)
ATTEMPT = uuid.UUID(
    "fa027ff0-0376-4291-bf5f-06179fe44301"
)
KEY = "ATTEMPT_KEY_0001"


def make_intent(order=ORDER):
    return CreateAttemptIntent(
        organization_id=ORG,
        order_id=order,
        idempotency_key=KEY,
    )


class FakeSession:
    def __init__(self):
        self.order = SimpleNamespace(
            organization_id=ORG,
            id=ORDER,
            amount_minor_units=149900,
            currency="INR",
            status="open",
        )
        self.claimed_id = uuid.uuid4()
        self.record = None
        self.original_attempt = None
        self.update_rowcount = 1
        self.executed = []
        self.selected = []
        self.created_calls = []
        self.commits = 0
        self.rollbacks = 0

    def scalar(self, statement):
        self.selected.append(statement)

        entity = statement.column_descriptions[0]["entity"]

        if entity is PaymentOrder:
            return self.order

        if entity is PaymentAttemptIdempotencyRecord:
            return self.record

        if entity is PaymentAttempt:
            return self.original_attempt

        raise AssertionError(
            "Unexpected SELECT statement"
        )

    def execute(self, statement):
        self.executed.append(statement)

        if isinstance(statement, Insert):
            return SimpleNamespace(
                scalar_one_or_none=lambda: self.claimed_id
            )

        if isinstance(statement, Update):
            return SimpleNamespace(
                rowcount=self.update_rowcount
            )

        raise AssertionError(
            "Unexpected database statement"
        )

    def commit(self):
        self.commits += 1
        raise AssertionError("Service must never commit")

    def rollback(self):
        self.rollbacks += 1
        raise AssertionError("Service must never rollback")


@pytest.fixture
def db(monkeypatch):
    instance = FakeSession()

    monkeypatch.setattr(
        service,
        "get_settings",
        lambda: SimpleNamespace(app_env="development"),
    )

    monkeypatch.setattr(
        service,
        "get_accessible_organization",
        lambda *_: (object(), "owner"),
    )

    def fake_create(session, **kwargs):
        session.created_calls.append(kwargs)

        return CreatedSandboxPaymentAttempt(
            id=ATTEMPT,
            organization_id=ORG,
            order_id=ORDER,
            attempt_number=1,
            amount=Money(
                minor_units=149900,
                currency="INR",
            ),
            provider_code="sandbox",
            state=PaymentState.CREATED,
        )

    monkeypatch.setattr(
        service,
        "create_sandbox_payment_attempt",
        fake_create,
    )

    return instance


def call(db, intent=None):
    return service.create_sandbox_payment_attempt_idempotent(
        db,
        actor_user_id=ACTOR,
        intent=intent or make_intent(),
    )


def prepare_replay(db, *, status="failed"):
    db.claimed_id = None

    intent = make_intent()

    db.record = SimpleNamespace(
        organization_id=ORG,
        order_id=ORDER,
        idempotency_key=KEY,
        request_fingerprint=(
            fingerprint_create_attempt_intent(intent)
        ),
        attempt_number=1,
        status="completed",
    )

    db.original_attempt = SimpleNamespace(
        id=ATTEMPT,
        organization_id=ORG,
        order_id=ORDER,
        attempt_number=1,
        amount_minor_units=149900,
        currency="INR",
        provider_code="sandbox",
        provider_payment_id=None,
        status=status,
    )


def test_new_key_creates_once_without_commit(db):
    result = call(db)

    assert result.replayed is False
    assert result.attempt.id == ATTEMPT
    assert result.attempt.attempt_number == 1
    assert result.attempt.state is PaymentState.CREATED

    assert len(db.created_calls) == 1
    assert len(db.executed) == 2

    assert isinstance(db.executed[0], Insert)
    assert isinstance(db.executed[1], Update)

    assert db.commits == 0
    assert db.rollbacks == 0


def test_claim_uses_postgres_unique_key_arbitration(db):
    call(db)

    statement = db.executed[0]

    compiled = statement.compile(
        dialect=postgresql.dialect()
    )

    sql = str(compiled)

    assert (
        "ON CONFLICT ON CONSTRAINT "
        "uq_attempt_idem_tenant_key"
    ) in sql

    assert "DO NOTHING" in sql
    assert "RETURNING" in sql
    assert "payment_attempt_idempotency_records" in sql

    params = compiled.params

    assert ORG in params.values()
    assert ORDER in params.values()
    assert KEY in params.values()

    assert params.get("status") == "reserved"


def test_parent_order_locked_before_key_reservation(db):
    call(db)

    assert len(db.selected) == 1

    query = db.selected[0]

    compiled = query.compile(
        dialect=postgresql.dialect()
    )

    sql = str(compiled)

    assert "FOR UPDATE" in sql
    assert "payment_orders" in sql
    assert ORG in compiled.params.values()
    assert ORDER in compiled.params.values()


def test_mapping_update_scoped_to_reserved_claim(db):
    call(db)

    statement = db.executed[1]

    compiled = statement.compile(
        dialect=postgresql.dialect()
    )

    sql = str(compiled)

    assert "UPDATE payflow.payment_attempt_idempotency_records" in sql
    assert "status" in sql
    assert "attempt_number" in sql
    assert ORG in compiled.params.values()
    assert ORDER in compiled.params.values()
    assert db.claimed_id in compiled.params.values()
    assert "reserved" in compiled.params.values()
    assert "completed" in compiled.params.values()


@pytest.mark.parametrize(
    "state",
    ["created", "failed", "cancelled", "succeeded"],
)
def test_same_key_replays_original_current_state(db, state):
    prepare_replay(db, status=state)

    result = call(db)

    assert result.replayed is True
    assert result.attempt.id == ATTEMPT
    assert result.attempt.attempt_number == 1
    assert result.attempt.state is PaymentState(state)

    assert db.created_calls == []
    assert len(db.executed) == 1
    assert db.commits == 0


def test_same_key_different_order_conflicts(db):
    prepare_replay(db)

    with pytest.raises(
        service.AttemptIdempotencyKeyConflict
    ):
        call(db, make_intent(order=OTHER_ORDER))

    assert db.created_calls == []


def test_unfinished_reservation_fails_closed(db):
    prepare_replay(db)
    db.record.status = "reserved"
    db.record.attempt_number = None

    with pytest.raises(
        service.AttemptIdempotencyStateUnavailable
    ):
        call(db)

    assert db.created_calls == []


def test_missing_replay_record_fails_closed(db):
    db.claimed_id = None

    with pytest.raises(
        service.AttemptIdempotencyStateUnavailable
    ):
        call(db)

    assert db.created_calls == []


def test_missing_original_attempt_fails_closed(db):
    prepare_replay(db)
    db.original_attempt = None

    with pytest.raises(
        service.AttemptIdempotencyStateUnavailable
    ):
        call(db)


@pytest.mark.parametrize(
    "field,value",
    [
        ("organization_id", uuid.uuid4()),
        ("order_id", uuid.uuid4()),
    ],
)
def test_untrusted_attempt_mapping_rejected(db, field, value):
    prepare_replay(db)
    setattr(db.original_attempt, field, value)

    with pytest.raises(
        service.AttemptIdempotencyStateUnavailable
    ):
        call(db)


def test_untrusted_provider_rejected(db):
    prepare_replay(db)
    db.original_attempt.provider_code = "other_provider"

    with pytest.raises(
        service.AttemptIdempotencyStateUnavailable
    ):
        call(db)


def test_amount_mismatch_fails_closed(db):
    prepare_replay(db)
    db.original_attempt.amount_minor_units = 150000

    with pytest.raises(
        service.AttemptIdempotencyStateUnavailable
    ):
        call(db)


def test_invalid_replay_state_fails_closed(db):
    prepare_replay(db)
    db.original_attempt.status = "unrecognized"

    with pytest.raises(
        service.AttemptIdempotencyStateUnavailable
    ):
        call(db)


def test_incomplete_mapping_update_requires_rollback(db):
    db.update_rowcount = 0

    with pytest.raises(
        service.AttemptIdempotencyStateUnavailable
    ):
        call(db)

    assert len(db.created_calls) == 1
    assert db.commits == 0


def test_creation_error_propagates_without_commit(db, monkeypatch):
    def fail_create(*args, **kwargs):
        raise RuntimeError("synthetic creation failure")

    monkeypatch.setattr(
        service,
        "create_sandbox_payment_attempt",
        fail_create,
    )

    with pytest.raises(
        RuntimeError,
        match="synthetic creation failure",
    ):
        call(db)

    assert db.commits == 0


def test_unknown_order_rejected_before_key_claim(db):
    db.order = None

    with pytest.raises(
        PaymentAttemptOrderNotFound
    ):
        call(db)

    assert db.executed == []


@pytest.mark.parametrize(
    "role",
    ["viewer", "finance", "developer"],
)
def test_unauthorized_roles_blocked_before_claim(
    db,
    monkeypatch,
    role,
):
    monkeypatch.setattr(
        service,
        "get_accessible_organization",
        lambda *_: (object(), role),
    )

    with pytest.raises(
        PaymentAttemptAccessDenied
    ):
        call(db)

    assert db.selected == []
    assert db.executed == []


def test_missing_membership_blocked_before_claim(
    db,
    monkeypatch,
):
    monkeypatch.setattr(
        service,
        "get_accessible_organization",
        lambda *_: None,
    )

    with pytest.raises(
        PaymentAttemptAccessDenied
    ):
        call(db)

    assert db.selected == []
    assert db.executed == []


def test_production_environment_blocked(db, monkeypatch):
    monkeypatch.setattr(
        service,
        "get_settings",
        lambda: SimpleNamespace(app_env="production"),
    )

    with pytest.raises(
        PaymentAttemptAccessDenied
    ):
        call(db)

    assert db.selected == []
    assert db.executed == []


@pytest.mark.parametrize(
    "actor",
    [uuid.UUID(int=0), "not-a-uuid"],
)
def test_invalid_actor_blocked_before_queries(db, actor):
    with pytest.raises(ValueError):
        service.create_sandbox_payment_attempt_idempotent(
            db,
            actor_user_id=actor,
            intent=make_intent(),
        )

    assert db.selected == []
    assert db.executed == []


def test_invalid_intent_rejected_before_queries(db):
    with pytest.raises(TypeError):
        call(db, intent={"order_id": str(ORDER)})

    assert db.selected == []
    assert db.executed == []


def test_result_is_immutable(db):
    from dataclasses import FrozenInstanceError

    result = call(db)

    with pytest.raises(FrozenInstanceError):
        result.replayed = True

@pytest.mark.parametrize("replay", [False, True])
@pytest.mark.parametrize(
    "after_lock_role",
    [None, "viewer", "finance", "developer"],
)
def test_permission_change_during_order_lock_fails_closed(
    db,
    monkeypatch,
    replay,
    after_lock_role,
):
    """A role change during the order-lock wait prevents use."""

    if replay:
        prepare_replay(db)

    authorization_steps = []

    def changing_access(*args):
        authorization_steps.append(len(db.selected))

        if len(authorization_steps) == 1:
            return (object(), "owner")

        if len(authorization_steps) == 2:
            if after_lock_role is None:
                return None

            return (object(), after_lock_role)

        raise AssertionError(
            "Unexpected third authorization check"
        )

    monkeypatch.setattr(
        service,
        "get_accessible_organization",
        changing_access,
    )

    with pytest.raises(PaymentAttemptAccessDenied):
        call(db)

    # One check before locking, then another after.
    assert authorization_steps == [0, 1]

    # The payment order lock was requested.
    assert len(db.selected) == 1

    # No key reservation, original replay, or attempt write.
    assert db.executed == []
    assert db.created_calls == []

    assert db.commits == 0
    assert db.rollbacks == 0


@pytest.mark.parametrize("replay", [False, True])
@pytest.mark.parametrize("final_role", ["owner", "admin"])
def test_authorized_role_survives_post_lock_recheck(
    db,
    monkeypatch,
    replay,
    final_role,
):
    """An authorized role still creates or replays normally."""

    if replay:
        prepare_replay(db)

    authorization_steps = []

    def changing_access(*args):
        authorization_steps.append(len(db.selected))

        if len(authorization_steps) == 1:
            return (object(), "owner")

        if len(authorization_steps) == 2:
            return (object(), final_role)

        raise AssertionError(
            "Unexpected third authorization check"
        )

    monkeypatch.setattr(
        service,
        "get_accessible_organization",
        changing_access,
    )

    result = call(db)

    assert authorization_steps == [0, 1]

    # New requests select the order once.
    # Replays also fetch the key mapping and original attempt.
    assert len(db.selected) == (3 if replay else 1)
    assert db.selected[0].column_descriptions[0]["entity"] is PaymentOrder

    assert result.replayed is replay

    if replay:
        assert result.attempt.id == ATTEMPT
        assert db.created_calls == []
        assert len(db.executed) == 1
    else:
        assert result.attempt.attempt_number == 1
        assert len(db.created_calls) == 1
        assert len(db.executed) == 2

    assert db.commits == 0
    assert db.rollbacks == 0
