"""Offline tests for the isolated dormant quarantine worker.

No database connections, grants, migrations or worker activation.
"""

import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest


def module():
    path = Path(__file__).with_name(
        "test_dormant_quarantine_function_postgres.py"
    )

    spec = importlib.util.spec_from_file_location(
        "isolated_dormant_worker_offline",
        path,
    )

    assert spec is not None
    assert spec.loader is not None

    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)

    return result


def restricted_role():
    return {
        "rolcanlogin": True,
        "rolinherit": False,
        "rolsuper": False,
        "rolcreatedb": False,
        "rolcreaterole": False,
        "rolreplication": False,
        "rolbypassrls": False,
        "rolconnlimit": 2,
    }


class FakeConnection:
    def __init__(
        self,
        role=None,
        database_connect=False,
        schema_usage=False,
        membership=False,
    ):
        self.role = role
        self.permissions = (
            database_connect,
            schema_usage,
            membership,
        )

    def execute(self, statement):
        query = str(statement)

        if "FROM pg_catalog.pg_roles" in query:
            return SimpleNamespace(
                mappings=lambda: SimpleNamespace(
                    one_or_none=lambda: self.role
                )
            )

        assert "has_database_privilege" in query
        assert "has_schema_privilege" in query

        return SimpleNamespace(
            one=lambda: self.permissions,
        )


def harness(isolated):
    return SimpleNamespace(
        _isolated_lab_mode=lambda: isolated,
    )


def test_isolated_dormant_worker_accepted():
    module().verify_worker_role_preflight(
        FakeConnection(role=restricted_role()),
        harness(True),
    )


def test_legacy_cluster_without_worker_accepted():
    module().verify_worker_role_preflight(
        FakeConnection(),
        harness(False),
    )


def test_legacy_worker_presence_rejected():
    with pytest.raises(AssertionError):
        module().verify_worker_role_preflight(
            FakeConnection(role=restricted_role()),
            harness(False),
        )


def test_isolated_missing_worker_rejected():
    with pytest.raises(AssertionError):
        module().verify_worker_role_preflight(
            FakeConnection(),
            harness(True),
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("rolcanlogin", False),
        ("rolinherit", True),
        ("rolsuper", True),
        ("rolcreatedb", True),
        ("rolcreaterole", True),
        ("rolreplication", True),
        ("rolbypassrls", True),
        ("rolconnlimit", 5),
    ],
)
def test_unexpected_worker_role_attributes_rejected(
    field,
    value,
):
    role = restricted_role()
    role[field] = value

    with pytest.raises(AssertionError):
        module().verify_worker_role_preflight(
            FakeConnection(role=role),
            harness(True),
        )


@pytest.mark.parametrize(
    "permission",
    [
        "database_connect",
        "schema_usage",
        "membership",
    ],
)
def test_unexpected_worker_access_rejected(permission):
    kwargs = {
        "role": restricted_role(),
        permission: True,
    }

    with pytest.raises(AssertionError):
        module().verify_worker_role_preflight(
            FakeConnection(**kwargs),
            harness(True),
        )
