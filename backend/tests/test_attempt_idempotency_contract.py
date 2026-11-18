"""Database-independent attempt-idempotency contract tests."""

import hashlib
import json
import re
import uuid
from dataclasses import FrozenInstanceError

import pytest

from app.payments.attempt_idempotency import (
    REQUEST_SCHEMA,
    CreateAttemptIntent,
    fingerprint_create_attempt_intent,
)


ORG_A = uuid.UUID("27701d67-6347-480a-b02d-1d1e71347bda")
ORG_B = uuid.UUID("a4c936f1-e2cd-4a1f-9cb5-8790420a8e25")
ORDER_A = uuid.UUID("0b502740-bc5c-4e0e-b8f8-96190b1003ca")
ORDER_B = uuid.UUID("8c26bc49-3514-4bd2-82a1-bf2aa786c145")

KEY_A = "ATTEMPT_KEY_0001"
KEY_B = "ATTEMPT_KEY_0002"


def intent(
    *,
    organization_id=ORG_A,
    order_id=ORDER_A,
    key=KEY_A,
):
    return CreateAttemptIntent(
        organization_id=organization_id,
        order_id=order_id,
        idempotency_key=key,
    )


def test_valid_intent_keeps_original_values():
    value = intent()

    assert value.organization_id == ORG_A
    assert value.order_id == ORDER_A
    assert value.idempotency_key == KEY_A


def test_intent_is_immutable():
    value = intent()

    with pytest.raises(FrozenInstanceError):
        value.order_id = ORDER_B


@pytest.mark.parametrize("length", [10, 128])
def test_valid_key_length_boundaries(length):
    value = intent(key="A" * length)

    assert len(value.idempotency_key) == length


@pytest.mark.parametrize(
    "bad_key",
    [
        None,
        123,
        "",
        "short",
        "A" * 129,
        "bad key 0000",
        "bad/key_0000",
        "bad.key_0000",
        "abcdefghij\n",
        "é" * 10,
    ],
)
def test_invalid_idempotency_keys_rejected(bad_key):
    with pytest.raises(ValueError):
        intent(key=bad_key)


@pytest.mark.parametrize(
    "bad_id",
    [
        None,
        "not-a-uuid",
        uuid.UUID(int=0),
        123,
    ],
)
@pytest.mark.parametrize(
    "field",
    ["organization_id", "order_id"],
)
def test_invalid_organization_or_order_rejected(field, bad_id):
    arguments = {
        "organization_id": ORG_A,
        "order_id": ORDER_A,
        "key": KEY_A,
    }

    arguments[field] = bad_id

    with pytest.raises(ValueError):
        intent(**arguments)


def test_fingerprint_is_stable():
    first = fingerprint_create_attempt_intent(
        intent()
    )

    second = fingerprint_create_attempt_intent(
        intent()
    )

    assert first == second
    assert re.fullmatch(r"[0-9a-f]{64}", first)


def test_order_change_changes_fingerprint():
    first = fingerprint_create_attempt_intent(
        intent(order_id=ORDER_A)
    )

    second = fingerprint_create_attempt_intent(
        intent(order_id=ORDER_B)
    )

    assert first != second


def test_organization_change_changes_fingerprint():
    first = fingerprint_create_attempt_intent(
        intent(organization_id=ORG_A)
    )

    second = fingerprint_create_attempt_intent(
        intent(organization_id=ORG_B)
    )

    assert first != second


def test_key_is_separate_from_request_fingerprint():
    first = fingerprint_create_attempt_intent(
        intent(key=KEY_A)
    )

    second = fingerprint_create_attempt_intent(
        intent(key=KEY_B)
    )

    assert first == second


def test_fingerprint_uses_versioned_canonical_payload():
    value = intent()

    canonical = json.dumps(
        {
            "schema": REQUEST_SCHEMA,
            "organization_id": str(ORG_A),
            "order_id": str(ORDER_A),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")

    expected = hashlib.sha256(
        canonical
    ).hexdigest()

    assert (
        fingerprint_create_attempt_intent(value)
        == expected
    )


def test_non_intent_input_is_rejected():
    with pytest.raises(TypeError):
        fingerprint_create_attempt_intent(
            {"organization_id": str(ORG_A)}
        )


def test_fingerprint_is_not_affected_by_actor_identity():
    # Actor identity is intentionally absent from the
    # request contract. Authorization is separate.
    fields = set(
        CreateAttemptIntent.__dataclass_fields__
    )

    assert fields == {
        "organization_id",
        "order_id",
        "idempotency_key",
    }
    assert "actor_user_id" not in fields


def test_contract_does_not_claim_payment_success():
    value = intent()

    assert not hasattr(value, "payment_status")
    assert not hasattr(value, "provider_payment_id")
    assert not hasattr(value, "attempt_number")
