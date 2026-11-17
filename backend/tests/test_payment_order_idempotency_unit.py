"""Unit tests for deterministic payment-order idempotency."""

import re
import uuid
from dataclasses import FrozenInstanceError

import pytest

from app.payments.contracts import CreatePaymentCommand, Money
from app.services.payment_order_idempotency import (
    IdempotentPaymentOrderResult,
    fingerprint_create_payment_command,
)
from app.services.payment_orders import CreatedPaymentOrder


ORG = uuid.uuid4()


def make_command(
    organization_id=ORG,
    reference="merchant_order_001",
    amount=12500,
    currency="INR",
    key="idempotency_key_001",
):
    return CreatePaymentCommand(
        organization_id=organization_id,
        order_reference=reference,
        amount=Money(amount, currency),
        idempotency_key=key,
    )


def test_fingerprint_is_stable():
    first = fingerprint_create_payment_command(make_command())
    second = fingerprint_create_payment_command(make_command())

    assert first == second
    assert re.fullmatch(r"[0-9a-f]{64}", first)


def test_idempotency_key_not_in_fingerprint():
    first = fingerprint_create_payment_command(
        make_command(key="idempotency_key_001")
    )
    second = fingerprint_create_payment_command(
        make_command(key="idempotency_key_002")
    )

    assert first == second


@pytest.mark.parametrize(
    "change",
    [
        {"organization_id": uuid.uuid4()},
        {"reference": "merchant_order_002"},
        {"amount": 12501},
        {"currency": "USD"},
    ],
)
def test_changed_request_changes_fingerprint(change):
    original = fingerprint_create_payment_command(make_command())
    changed = fingerprint_create_payment_command(
        make_command(**change)
    )

    assert original != changed


def test_invalid_command_rejected():
    with pytest.raises(TypeError):
        fingerprint_create_payment_command(None)


def test_result_is_immutable():
    order = CreatedPaymentOrder(
        id=uuid.uuid4(),
        organization_id=ORG,
        merchant_order_reference="merchant_order_001",
        amount=Money(12500, "INR"),
        status="open",
    )

    result = IdempotentPaymentOrderResult(
        order=order,
        replayed=False,
    )

    with pytest.raises(FrozenInstanceError):
        result.replayed = True
