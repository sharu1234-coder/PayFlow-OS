from dataclasses import FrozenInstanceError
from uuid import UUID, uuid4

import pytest

from app.payments.contracts import (
    CreatePaymentCommand,
    CreateRefundCommand,
    FetchPaymentCommand,
    Money,
    PaymentResult,
    PaymentState,
    ProviderError,
    ProviderErrorKind,
    RefundResult,
    RefundState,
)
from app.payments.ports import PaymentProvider


ORGANIZATION_ID = uuid4()


def payment_command(**overrides):
    values = {
        "organization_id": ORGANIZATION_ID,
        "order_reference": "order_example_001",
        "amount": Money(12500, "INR"),
        "idempotency_key": "operation_key_001",
    }
    values.update(overrides)
    return CreatePaymentCommand(**values)


def test_money_stores_integer_minor_units():
    value = Money(12500, "INR")
    assert value.minor_units == 12500
    assert value.currency == "INR"


@pytest.mark.parametrize(
    "amount",
    [0, -1, True, 1.5, "12500", 2**63],
)
def test_invalid_amounts_rejected(amount):
    with pytest.raises(ValueError):
        Money(amount, "INR")


@pytest.mark.parametrize(
    "currency",
    ["inr", "IN", "INRR", "IN1", "", None],
)
def test_invalid_currency_format_rejected(currency):
    with pytest.raises(ValueError):
        Money(100, currency)


def test_money_is_immutable():
    value = Money(100, "INR")
    with pytest.raises(FrozenInstanceError):
        value.minor_units = 200


def test_payment_command_preserves_tenant_and_order():
    request = payment_command()
    assert request.organization_id == ORGANIZATION_ID
    assert request.order_reference == "order_example_001"


@pytest.mark.parametrize(
    "organization_id",
    ["tenant_1", UUID(int=0), None],
)
def test_invalid_organization_rejected(organization_id):
    with pytest.raises(ValueError):
        payment_command(organization_id=organization_id)


@pytest.mark.parametrize(
    "key",
    ["", "short", "contains spaces", "abc/def_12345"],
)
def test_invalid_idempotency_key_rejected(key):
    with pytest.raises(ValueError):
        payment_command(idempotency_key=key)


def test_payment_command_requires_money():
    with pytest.raises(TypeError):
        payment_command(amount=12500)


def test_fetch_command_requires_valid_reference():
    with pytest.raises(ValueError):
        FetchPaymentCommand(
            organization_id=ORGANIZATION_ID,
            provider_payment_id="../other_tenant",
        )


def test_refund_requires_valid_money_and_key():
    with pytest.raises(TypeError):
        CreateRefundCommand(
            organization_id=ORGANIZATION_ID,
            provider_payment_id="fake_pay_1",
            amount=100,
            idempotency_key="operation_key_002",
        )


def test_invalid_normalized_payment_state_rejected():
    with pytest.raises(TypeError):
        PaymentResult(
            provider_payment_id="fake_pay_1",
            state="succeeded",
        )


def test_invalid_normalized_refund_state_rejected():
    with pytest.raises(TypeError):
        RefundResult(
            provider_refund_id="fake_ref_1",
            state="succeeded",
        )


@pytest.mark.parametrize(
    "kind",
    [
        ProviderErrorKind.TIMEOUT,
        ProviderErrorKind.UNAVAILABLE,
        ProviderErrorKind.RATE_LIMITED,
    ],
)
def test_transient_provider_failures_are_retryable(kind):
    assert ProviderError(kind).retryable is True


@pytest.mark.parametrize(
    "kind",
    [
        ProviderErrorKind.INVALID_REQUEST,
        ProviderErrorKind.AUTHENTICATION,
        ProviderErrorKind.DECLINED,
        ProviderErrorKind.CONFLICT,
        ProviderErrorKind.INVALID_RESPONSE,
    ],
)
def test_other_provider_failures_are_not_auto_retryable(kind):
    assert ProviderError(kind).retryable is False


def test_provider_errors_use_sanitized_categories():
    error = ProviderError(ProviderErrorKind.TIMEOUT)
    assert "timeout" in str(error)
    assert error.kind is ProviderErrorKind.TIMEOUT


class FakeProvider:
    provider_code = "fake"

    def create_payment(
        self,
        command: CreatePaymentCommand,
    ) -> PaymentResult:
        assert command.organization_id == ORGANIZATION_ID
        return PaymentResult(
            provider_payment_id="fake_pay_1",
            state=PaymentState.PROCESSING,
        )

    def fetch_payment(
        self,
        command: FetchPaymentCommand,
    ) -> PaymentResult:
        assert command.organization_id == ORGANIZATION_ID
        return PaymentResult(
            provider_payment_id=command.provider_payment_id,
            state=PaymentState.SUCCEEDED,
        )

    def create_refund(
        self,
        command: CreateRefundCommand,
    ) -> RefundResult:
        assert command.organization_id == ORGANIZATION_ID
        return RefundResult(
            provider_refund_id="fake_ref_1",
            state=RefundState.PENDING,
        )


def test_fake_provider_implements_payment_port():
    provider: PaymentProvider = FakeProvider()

    created = provider.create_payment(payment_command())
    assert created.state is PaymentState.PROCESSING

    fetched = provider.fetch_payment(
        FetchPaymentCommand(
            organization_id=ORGANIZATION_ID,
            provider_payment_id=created.provider_payment_id,
        )
    )
    assert fetched.state is PaymentState.SUCCEEDED

    refund = provider.create_refund(
        CreateRefundCommand(
            organization_id=ORGANIZATION_ID,
            provider_payment_id=created.provider_payment_id,
            amount=Money(100, "INR"),
            idempotency_key="operation_key_002",
        )
    )
    assert refund.state is RefundState.PENDING
