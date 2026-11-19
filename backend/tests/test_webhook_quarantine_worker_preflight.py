"""Tests for the inactive quarantine-worker security preflight."""

from dataclasses import FrozenInstanceError
from types import SimpleNamespace

import pytest

import app.services.webhook_quarantine_worker_preflight as preflight


class FakeResult:
    def __init__(self, value):
        self.value = value

    def one(self):
        return self.value

    def scalar_one(self):
        return self.value


class FakeSession:
    def __init__(
        self,
        *,
        role=preflight.EXPECTED_ROLE,
        login_role=None,
        read_only="off",
        isolation="read committed",
        transaction=True,
        dialect="postgresql",
        permitted=None,
    ):
        self.role = role
        self.login_role = role if login_role is None else login_role
        self.read_only = read_only
        self.isolation = isolation
        self.transaction = transaction
        self.dialect = dialect
        self.permitted = permitted or {}
        self.calls = []

    def in_transaction(self):
        return self.transaction

    def get_bind(self):
        return SimpleNamespace(
            dialect=SimpleNamespace(name=self.dialect)
        )

    def execute(self, statement, parameters=None):
        query = str(statement)
        self.calls.append((query, parameters))

        if "current_setting('transaction_read_only')" in query:
            return FakeResult((
                self.role,
                self.login_role,
                self.read_only,
                self.isolation,
            ))

        assert "has_table_privilege" in query
        assert parameters["relation"] in preflight.PROTECTED_RELATIONS
        assert parameters["privilege"] in preflight.DIRECT_PRIVILEGES

        value = self.permitted.get((
            parameters["relation"],
            parameters["privilege"],
        ), False)

        return FakeResult(value)

    def add(self, value):
        raise AssertionError("Must not add records")

    def flush(self):
        raise AssertionError("Must not flush")

    def commit(self):
        raise AssertionError("Must not commit")

    def rollback(self):
        raise AssertionError("Must not rollback")


def enable(monkeypatch):
    monkeypatch.setattr(
        preflight,
        "get_settings",
        lambda: SimpleNamespace(
            app_env="development",
            sandbox_payment_attempts_enabled=True,
        ),
    )


def test_diagnostic_only_with_no_direct_permissions(monkeypatch):
    enable(monkeypatch)

    db = FakeSession()
    result = preflight.inspect_quarantine_worker_privileges(db)

    assert result.database_role == preflight.EXPECTED_ROLE
    assert result.direct_table_permissions_absent is True
    assert result.diagnostic_only is True

    privilege_calls = [
        call
        for call in db.calls
        if "has_table_privilege" in call[0]
    ]

    assert len(privilege_calls) == (
        len(preflight.PROTECTED_RELATIONS)
        * len(preflight.DIRECT_PRIVILEGES)
    )

    for forbidden in (
        "authorized",
        "organization_id",
        "record_id",
        "mutation_authorized",
        "payment_state",
        "retry_payment",
        "execute",
        "commit",
    ):
        assert not hasattr(result, forbidden)


@pytest.mark.parametrize(
    "role",
    [
        "payflow_runtime",
        "payflow_migrator",
        "postgres",
        "public",
        "payflow_quarantine_worker_fake",
        "",
    ],
)
def test_wrong_database_role_rejected(monkeypatch, role):
    enable(monkeypatch)

    with pytest.raises(
        preflight.QuarantineWorkerPreflightUnavailable
    ):
        preflight.inspect_quarantine_worker_privileges(
            FakeSession(role=role)
        )


def test_session_role_switching_rejected(monkeypatch):
    enable(monkeypatch)

    with pytest.raises(
        preflight.QuarantineWorkerPreflightUnavailable
    ):
        preflight.inspect_quarantine_worker_privileges(
            FakeSession(login_role="payflow_runtime")
        )


@pytest.mark.parametrize(
    "read_only",
    ["on", "", None],
)
def test_unexpected_transaction_mode_rejected(
    monkeypatch, read_only
):
    enable(monkeypatch)

    with pytest.raises(
        preflight.QuarantineWorkerPreflightUnavailable
    ):
        preflight.inspect_quarantine_worker_privileges(
            FakeSession(read_only=read_only)
        )


@pytest.mark.parametrize(
    "isolation",
    [
        "serializable",
        "repeatable read",
        "read uncommitted",
        None,
    ],
)
def test_unexpected_isolation_rejected(
    monkeypatch, isolation
):
    enable(monkeypatch)

    with pytest.raises(
        preflight.QuarantineWorkerPreflightUnavailable
    ):
        preflight.inspect_quarantine_worker_privileges(
            FakeSession(isolation=isolation)
        )


def test_transaction_required(monkeypatch):
    enable(monkeypatch)

    db = FakeSession(transaction=False)

    with pytest.raises(
        preflight.QuarantineWorkerPreflightUnavailable
    ):
        preflight.inspect_quarantine_worker_privileges(db)

    assert db.calls == []


def test_postgresql_required(monkeypatch):
    enable(monkeypatch)

    db = FakeSession(dialect="sqlite")

    with pytest.raises(
        preflight.QuarantineWorkerPreflightUnavailable
    ):
        preflight.inspect_quarantine_worker_privileges(db)

    assert db.calls == []


@pytest.mark.parametrize(
    "environment,enabled",
    [
        ("production", True),
        ("production", False),
        ("staging", True),
        ("development", False),
    ],
)
def test_disabled_environment_prevents_database_access(
    monkeypatch,
    environment,
    enabled,
):
    monkeypatch.setattr(
        preflight,
        "get_settings",
        lambda: SimpleNamespace(
            app_env=environment,
            sandbox_payment_attempts_enabled=enabled,
        ),
    )

    db = FakeSession()

    with pytest.raises(
        preflight.QuarantineWorkerPreflightUnavailable
    ):
        preflight.inspect_quarantine_worker_privileges(db)

    assert db.calls == []


@pytest.mark.parametrize(
    "relation",
    preflight.PROTECTED_RELATIONS,
)
@pytest.mark.parametrize(
    "privilege",
    preflight.DIRECT_PRIVILEGES,
)
def test_each_direct_privilege_fails_closed(
    monkeypatch, relation, privilege
):
    enable(monkeypatch)

    db = FakeSession(
        permitted={(relation, privilege): True}
    )

    with pytest.raises(
        preflight.QuarantineWorkerPreflightUnavailable
    ):
        preflight.inspect_quarantine_worker_privileges(db)


def test_ambiguous_privilege_result_fails_closed(monkeypatch):
    enable(monkeypatch)

    db = FakeSession(
        permitted={
            (
                "payflow.provider_event_inbox",
                "SELECT",
            ): None,
        }
    )

    with pytest.raises(
        preflight.QuarantineWorkerPreflightUnavailable
    ):
        preflight.inspect_quarantine_worker_privileges(db)


def test_diagnostic_result_is_immutable(monkeypatch):
    enable(monkeypatch)

    result = preflight.inspect_quarantine_worker_privileges(
        FakeSession()
    )

    with pytest.raises(FrozenInstanceError):
        result.diagnostic_only = False


def test_all_sql_operations_are_read_only(monkeypatch):
    enable(monkeypatch)

    db = FakeSession()

    preflight.inspect_quarantine_worker_privileges(db)

    assert db.calls

    for query, parameters in db.calls:
        normalized = query.lstrip().upper()

        assert normalized.startswith("SELECT")
        assert "UPDATE " not in normalized
        assert "DELETE FROM" not in normalized
        assert "INSERT INTO" not in normalized
        assert "CREATE ROLE" not in normalized
        assert "GRANT " not in normalized
