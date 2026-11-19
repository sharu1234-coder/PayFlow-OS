"""Offline guards for isolated PostgreSQL test connections."""

import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest


TARGET = "payflow_payment_drill_20261117_020846_9fbac781"
START = "1795000000.123456"


def harness():
    path = Path(__file__).with_name(
        "test_webhook_inbox_concurrency_postgres.py"
    )

    spec = importlib.util.spec_from_file_location(
        "isolated_harness_guard_tests",
        path,
    )

    assert spec is not None
    assert spec.loader is not None

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return module


def settings(
    port=55432,
    database=TARGET,
    host="127.0.0.1",
    environment="development",
):
    return SimpleNamespace(
        app_env=environment,
        database_url=(
            f"postgresql+psycopg://payflow_runtime:"
            f"synthetic@{host}:{port}/{database}"
        ),
        migration_database_url=(
            f"postgresql+psycopg://payflow_migrator:"
            f"synthetic@{host}:{port}/{database}"
        ),
    )


def isolated(monkeypatch, module, **kwargs):
    monkeypatch.setenv(
        "PAYFLOW_ISOLATED_TEST_DB",
        TARGET,
    )

    monkeypatch.setattr(
        module,
        "get_settings",
        lambda: settings(**kwargs),
    )


def test_explicit_lab_selection(monkeypatch):
    module = harness()
    isolated(monkeypatch, module)

    runtime, migrator = module.approved_urls()

    assert runtime.database == TARGET
    assert migrator.database == TARGET
    assert runtime.port == 55432
    assert migrator.port == 55432


@pytest.mark.parametrize(
    "port,database,host",
    [
        (5432, TARGET, "127.0.0.1"),
        (55433, TARGET, "127.0.0.1"),
        (55432, "payflow_db", "127.0.0.1"),
        (55432, "postgres", "127.0.0.1"),
        (55432, TARGET, "localhost"),
    ],
)
def test_wrong_lab_connection_rejected(
    monkeypatch,
    port,
    database,
    host,
):
    module = harness()

    isolated(
        monkeypatch,
        module,
        port=port,
        database=database,
        host=host,
    )

    with pytest.raises(AssertionError):
        module.approved_urls()


def test_legacy_connection_selection_preserved(monkeypatch):
    module = harness()

    monkeypatch.delenv(
        "PAYFLOW_ISOLATED_TEST_DB",
        raising=False,
    )

    monkeypatch.setattr(
        module,
        "get_settings",
        lambda: settings(
            port=5432,
            database="payflow_db",
        ),
    )

    runtime, migrator = module.approved_urls()

    assert runtime.database == TARGET
    assert migrator.database == TARGET
    assert runtime.port == 5432
    assert migrator.port == 5432


def test_unknown_selector_rejected(monkeypatch):
    module = harness()

    monkeypatch.setenv(
        "PAYFLOW_ISOLATED_TEST_DB",
        "wrong_database",
    )

    monkeypatch.setattr(
        module,
        "get_settings",
        lambda: settings(
            port=5432,
            database="payflow_db",
        ),
    )

    with pytest.raises(AssertionError):
        module.approved_urls()


def test_production_environment_rejected(monkeypatch):
    module = harness()

    isolated(
        monkeypatch,
        module,
        environment="production",
    )

    with pytest.raises(AssertionError):
        module.approved_urls()


class FakeConnection:
    def __init__(
        self,
        address="127.0.0.1",
        port=55432,
        version=180004,
        started_at=START,
    ):
        self.address = address
        self.port = port
        self.version = version
        self.started_at = started_at

    def execute(self, statement):
        sql = str(statement)

        if "current_database()" in sql:
            return SimpleNamespace(
                one=lambda: (
                    TARGET,
                    "payflow_migrator",
                )
            )

        assert "pg_postmaster_start_time()" in sql
        assert "data_directory" not in sql

        return SimpleNamespace(
            one=lambda: (
                self.address,
                self.port,
                self.version,
                self.started_at,
            )
        )


def test_attested_lab_connection_accepted(monkeypatch):
    module = harness()

    isolated(monkeypatch, module)

    monkeypatch.setenv(
        "PAYFLOW_LAB_ATTESTED_START_EPOCH",
        START,
    )

    module.verify_identity(
        FakeConnection(),
        "payflow_migrator",
    )


def test_missing_admin_attestation_rejected(monkeypatch):
    module = harness()

    isolated(monkeypatch, module)

    monkeypatch.delenv(
        "PAYFLOW_LAB_ATTESTED_START_EPOCH",
        raising=False,
    )

    with pytest.raises(AssertionError):
        module.verify_identity(
            FakeConnection(),
            "payflow_migrator",
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("address", "192.0.2.1"),
        ("port", 5432),
        ("version", 170000),
        ("started_at", "1795000001.123456"),
    ],
)
def test_wrong_server_identity_rejected(
    monkeypatch,
    field,
    value,
):
    module = harness()

    isolated(monkeypatch, module)

    monkeypatch.setenv(
        "PAYFLOW_LAB_ATTESTED_START_EPOCH",
        START,
    )

    parameters = {
        field: value,
    }

    with pytest.raises(AssertionError):
        module.verify_identity(
            FakeConnection(**parameters),
            "payflow_migrator",
        )


def test_incorrect_attestation_rejected(monkeypatch):
    module = harness()

    isolated(monkeypatch, module)

    monkeypatch.setenv(
        "PAYFLOW_LAB_ATTESTED_START_EPOCH",
        "1795000999.000000",
    )

    with pytest.raises(AssertionError):
        module.verify_identity(
            FakeConnection(),
            "payflow_migrator",
        )
