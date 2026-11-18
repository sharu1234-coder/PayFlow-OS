"""Unit tests for sandbox attempt creation; no database connection."""

import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy.dialects import postgresql
from sqlalchemy.exc import IntegrityError

from app.payments.contracts import PaymentState
from app.services import payment_attempts as service


ACTOR_ID = uuid.UUID("dc0bdb75-8056-4435-a76e-bfcebc7466a7")
ORG_ID = uuid.UUID("27701d67-6347-480a-b02d-1d1e71347bda")
ORDER_ID = uuid.UUID("0b502740-bc5c-4e0e-b8f8-96190b1003ca")


class FakeSession:
    def __init__(self):
        self.order = SimpleNamespace(
            id=ORDER_ID,
            organization_id=ORG_ID,
            status="open",
            amount_minor_units=149900,
            currency="INR",
        )
        self.attempts = []
        self.statements = []
        self.added = []
        self.flushes = 0
        self.commits = 0
        self.rollbacks = 0
        self.flush_error = None

    def scalar(self, statement):
        self.statements.append(("order", statement))
        return self.order

    def scalars(self, statement):
        self.statements.append(("attempts", statement))
        return SimpleNamespace(
            all=lambda: list(self.attempts)
        )

    def add(self, entity):
        self.added.append(entity)

    def flush(self):
        self.flushes += 1

        if self.flush_error is not None:
            raise self.flush_error


def stored_attempt(number, status):
    return SimpleNamespace(
        attempt_number=number,
        status=status,
    )


@pytest.fixture
def db(monkeypatch):
    monkeypatch.setattr(
        service,
        "get_settings",
        lambda: SimpleNamespace(app_env="development"),
    )

    monkeypatch.setattr(
        service,
        "get_accessible_organization",
        lambda session, actor, organization: (
            object(),
            "owner",
        ),
    )

    return FakeSession()


def create(db):
    return service.create_sandbox_payment_attempt(
        db,
        actor_user_id=ACTOR_ID,
        organization_id=ORG_ID,
        order_id=ORDER_ID,
    )


def test_first_attempt_inherits_order_amount_and_no_commit(db):
    result = create(db)

    assert result.id == db.added[0].id
    assert result.organization_id == ORG_ID
    assert result.order_id == ORDER_ID
    assert result.attempt_number == 1
    assert result.amount.minor_units == 149900
    assert result.amount.currency == "INR"
    assert result.provider_code == "sandbox"
    assert result.state is PaymentState.CREATED

    attempt = db.added[0]

    assert attempt.status == "created"
    assert attempt.provider_payment_id is None
    assert db.flushes == 1
    assert db.commits == 0
    assert db.rollbacks == 0


def test_parent_order_is_locked_before_attempt_query(db):
    create(db)

    assert [kind for kind, _ in db.statements] == [
        "order",
        "attempts",
    ]

    order_statement = db.statements[0][1]

    compiled = order_statement.compile(
        dialect=postgresql.dialect()
    )

    assert "FOR UPDATE" in str(compiled)
    assert ORG_ID in compiled.params.values()
    assert ORDER_ID in compiled.params.values()

    attempts_statement = db.statements[1][1]

    attempts_sql = attempts_statement.compile(
        dialect=postgresql.dialect()
    )

    assert ORG_ID in attempts_sql.params.values()
    assert ORDER_ID in attempts_sql.params.values()


@pytest.mark.parametrize(
    "state",
    ["failed", "cancelled"],
)
def test_retry_after_terminal_attempt(db, state):
    db.attempts = [stored_attempt(1, state)]

    assert create(db).attempt_number == 2


def test_retry_uses_highest_terminal_attempt_number(db):
    db.attempts = [
        stored_attempt(3, "failed"),
        stored_attempt(1, "cancelled"),
    ]

    assert create(db).attempt_number == 4


@pytest.mark.parametrize(
    "state",
    [
        "created",
        "requires_action",
        "processing",
        "authorized",
        "succeeded",
    ],
)
def test_active_or_successful_attempt_blocks_retry(db, state):
    db.attempts = [stored_attempt(1, state)]

    with pytest.raises(service.PaymentAttemptConflict):
        create(db)

    assert db.added == []
    assert db.flushes == 0


@pytest.mark.parametrize(
    "state",
    ["paid", "cancelled"],
)
def test_non_open_order_rejected(db, state):
    db.order.status = state

    with pytest.raises(service.PaymentAttemptConflict):
        create(db)

    assert db.added == []


def test_unknown_existing_attempt_state_fails_closed(db):
    db.attempts = [
        stored_attempt(1, "unexpected"),
    ]

    with pytest.raises(service.PaymentAttemptConflict):
        create(db)

    assert db.added == []


def test_duplicate_attempt_numbers_fail_closed(db):
    db.attempts = [
        stored_attempt(1, "failed"),
        stored_attempt(1, "cancelled"),
    ]

    with pytest.raises(service.PaymentAttemptConflict):
        create(db)

    assert db.added == []


def test_missing_order_rejected(db):
    db.order = None

    with pytest.raises(service.PaymentAttemptOrderNotFound):
        create(db)

    assert db.added == []
    assert len(db.statements) == 1


@pytest.mark.parametrize(
    "role",
    ["viewer", "finance", "developer"],
)
def test_non_writer_role_rejected(db, monkeypatch, role):
    monkeypatch.setattr(
        service,
        "get_accessible_organization",
        lambda *args: (object(), role),
    )

    with pytest.raises(service.PaymentAttemptAccessDenied):
        create(db)

    assert db.statements == []


def test_missing_membership_rejected(db, monkeypatch):
    monkeypatch.setattr(
        service,
        "get_accessible_organization",
        lambda *args: None,
    )

    with pytest.raises(service.PaymentAttemptAccessDenied):
        create(db)

    assert db.statements == []


def test_production_environment_rejected(db, monkeypatch):
    monkeypatch.setattr(
        service,
        "get_settings",
        lambda: SimpleNamespace(app_env="production"),
    )

    with pytest.raises(service.PaymentAttemptAccessDenied):
        create(db)

    assert db.statements == []


@pytest.mark.parametrize(
    "field",
    ["actor_user_id", "organization_id", "order_id"],
)
@pytest.mark.parametrize(
    "value",
    [uuid.UUID(int=0), "not-a-uuid"],
)
def test_invalid_uuid_rejected_before_queries(db, field, value):
    arguments = {
        "actor_user_id": ACTOR_ID,
        "organization_id": ORG_ID,
        "order_id": ORDER_ID,
    }

    arguments[field] = value

    with pytest.raises(ValueError):
        service.create_sandbox_payment_attempt(
            db,
            **arguments,
        )

    assert db.statements == []


class FakePostgresError(Exception):
    sqlstate = "23505"

    diag = SimpleNamespace(
        constraint_name="uq_payment_attempts_order_number"
    )


def test_duplicate_attempt_database_error_normalized(db):
    db.flush_error = IntegrityError(
        "INSERT",
        {},
        FakePostgresError(),
    )

    with pytest.raises(service.PaymentAttemptConflict):
        create(db)

    assert db.flushes == 1
    assert db.commits == 0


def test_unrelated_database_integrity_error_propagates(db):
    db.flush_error = IntegrityError(
        "INSERT",
        {},
        Exception("other constraint"),
    )

    with pytest.raises(IntegrityError):
        create(db)

    assert db.commits == 0


def test_no_gateway_result_or_successful_state(db):
    create(db)

    attempt = db.added[0]

    assert attempt.status == "created"
    assert attempt.provider_payment_id is None
    assert attempt.provider_code == (
        service.SANDBOX_PROVIDER_CODE
    )

    assert db.commits == 0


# PHASE_2B4B6A_UNIQUENESS_TESTS


class FakeLiveAttemptIndexError(Exception):
    sqlstate = "23505"
    diag = SimpleNamespace(
        constraint_name=(
            "ux_payment_attempts_one_live_or_successful"
        )
    )


class FakeOtherUniqueIndexError(Exception):
    sqlstate = "23505"
    diag = SimpleNamespace(
        constraint_name=(
            "uq_payment_attempts_provider_payment"
        )
    )


class FakeWrongSqlstateError(Exception):
    sqlstate = "23503"
    diag = SimpleNamespace(
        constraint_name=(
            "ux_payment_attempts_one_live_or_successful"
        )
    )


def test_active_attempt_partial_index_error_is_normalized(db):
    db.flush_error = IntegrityError(
        "INSERT",
        {},
        FakeLiveAttemptIndexError(),
    )

    with pytest.raises(
        service.PaymentAttemptConflict,
        match="Payment attempt already exists",
    ):
        create(db)

    assert db.flushes == 1
    assert db.commits == 0


def test_other_unique_constraint_is_not_misclassified(db):
    db.flush_error = IntegrityError(
        "INSERT",
        {},
        FakeOtherUniqueIndexError(),
    )

    with pytest.raises(IntegrityError):
        create(db)

    assert db.flushes == 1
    assert db.commits == 0


def test_non_unique_sqlstate_is_not_misclassified(db):
    db.flush_error = IntegrityError(
        "INSERT",
        {},
        FakeWrongSqlstateError(),
    )

    with pytest.raises(IntegrityError):
        create(db)

    assert db.flushes == 1
    assert db.commits == 0
