"""Offline checks for the test-only reference lock prototype.

No PostgreSQL or payment processing required.
"""

import importlib.util
from pathlib import Path
from uuid import UUID

import pytest


def contract():
    path = (
        Path(__file__).parent
        / "fixtures"
        / "reference_serialization_contract.py"
    )

    spec = importlib.util.spec_from_file_location(
        "payflow_reference_lock_test_prototype",
        path,
    )

    assert spec is not None
    assert spec.loader is not None

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return module


ORG_A = UUID("11111111-1111-4111-8111-111111111111")
ORG_B = UUID("22222222-2222-4222-8222-222222222222")

REF_A = "sim_pay_" + ("a" * 32)
REF_B = "sim_pay_" + ("b" * 32)
REF_C = "sim_pay_" + ("c" * 32)


def key(organization, reference):
    return contract().payment_reference_lock_key(
        organization,
        "sandbox_sim",
        reference,
    )


def change(previous, new, organization=ORG_A):
    return contract().reference_change_lock_keys(
        organization,
        "sandbox_sim",
        previous,
        new,
    )


def test_lock_key_is_deterministic():
    assert key(ORG_A, REF_A) == key(ORG_A, REF_A)


def test_lock_key_is_signed_64_bit_integer():
    result = key(ORG_A, REF_A)

    assert type(result) is int
    assert -(2**63) <= result < 2**63


def test_different_tenants_have_different_sample_keys():
    assert key(ORG_A, REF_A) != key(ORG_B, REF_A)


def test_different_references_have_different_sample_keys():
    assert key(ORG_A, REF_A) != key(ORG_A, REF_B)


def test_reference_identity_is_not_event_identity():
    assert "event_id" not in (
        contract().payment_reference_lock_key.__code__.co_varnames
    )


def test_new_reference_requests_one_key():
    assert change(None, REF_A) == (
        key(ORG_A, REF_A),
    )


def test_removed_reference_requests_old_key():
    assert change(REF_A, None) == (
        key(ORG_A, REF_A),
    )


def test_unchanged_reference_requests_one_key():
    assert change(REF_A, REF_A) == (
        key(ORG_A, REF_A),
    )


def test_null_to_null_requires_no_reference_key():
    assert change(None, None) == ()


def test_reference_replacement_requests_both_keys():
    expected = tuple(sorted({
        key(ORG_A, REF_A),
        key(ORG_A, REF_B),
    }))

    assert change(REF_A, REF_B) == expected


def test_reverse_replacement_has_same_lock_set():
    assert change(REF_A, REF_B) == change(REF_B, REF_A)


def test_three_sample_keys_are_distinct():
    assert len({
        key(ORG_A, REF_A),
        key(ORG_A, REF_B),
        key(ORG_A, REF_C),
    }) == 3


def test_lock_keys_are_always_sorted():
    result = change(REF_A, REF_B)

    assert result == tuple(sorted(result))


@pytest.mark.parametrize(
    "organization",
    [
        None,
        "",
        "11111111-1111-4111-8111-111111111111",
        UUID(int=0),
        42,
    ],
)
def test_invalid_organization_rejected(organization):
    with pytest.raises(ValueError):
        contract().payment_reference_lock_key(
            organization,
            "sandbox_sim",
            REF_A,
        )


@pytest.mark.parametrize(
    "provider",
    [
        None,
        "",
        "sandbox",
        "SANDBOX_SIM",
        "sandbox_sim ",
        17,
    ],
)
def test_unsupported_provider_rejected(provider):
    with pytest.raises(ValueError):
        contract().payment_reference_lock_key(
            ORG_A,
            provider,
            REF_A,
        )


@pytest.mark.parametrize(
    "reference",
    [
        None,
        "",
        "sim_pay_",
        "sim_ref_" + ("a" * 32),
        "sim_pay_" + ("A" * 32),
        "sim_pay_" + ("a" * 31),
        "sim_pay_" + ("a" * 33),
        "sim_pay_" + ("a" * 32) + " ",
        "sim_pay_" + ("g" * 32),
        12,
        True,
    ],
)
def test_invalid_reference_rejected(reference):
    with pytest.raises(ValueError):
        contract().payment_reference_lock_key(
            ORG_A,
            "sandbox_sim",
            reference,
        )


@pytest.mark.parametrize(
    "previous,new",
    [
        ("invalid", None),
        (None, "invalid"),
        (REF_A, "invalid"),
        ("invalid", REF_B),
    ],
)
def test_reference_change_rejects_invalid_values(previous, new):
    with pytest.raises(ValueError):
        change(previous, new)


def test_no_sql_or_database_dependencies():
    source = (
        Path(__file__).parent
        / "fixtures"
        / "reference_serialization_contract.py"
    ).read_text(encoding="utf-8")

    for prohibited in (
        "create_engine",
        "psycopg",
        "pg_advisory_xact_lock(",
        "GRANT EXECUTE",
        "CREATE ROLE",
        "ALTER ROLE",
        "UPDATE payflow.",
        "INSERT INTO payflow.",
    ):
        assert prohibited not in source


def test_prototype_does_not_claim_authorization():
    source = (
        Path(__file__).parent
        / "fixtures"
        / "reference_serialization_contract.py"
    ).read_text(encoding="utf-8")

    assert "NOT a deployed reference writer" in source
    assert "does not authorize" in source
    assert "late-arriving payment references" in source
