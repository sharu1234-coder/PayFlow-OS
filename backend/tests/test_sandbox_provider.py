"""Deterministic, database-free sandbox provider tests."""

from concurrent.futures import ThreadPoolExecutor
from uuid import UUID

import pytest

from app.payments.contracts import (
    CreatePaymentCommand,
    CreateRefundCommand,
    FetchPaymentCommand,
    Money,
    PaymentState,
    ProviderError,
    ProviderErrorKind,
    RefundState,
)

from app.payments.ports import PaymentProvider

from app.payments.sandbox_provider import (
    SandboxPaymentProvider,
    SandboxScenario,
)


ORG_A = UUID("11111111-1111-4111-8111-111111111111")
ORG_B = UUID("22222222-2222-4222-8222-222222222222")


def payment(
    organization_id=ORG_A,
    order_reference="order_sim_001",
    idempotency_key="payment_key_001",
):
    return CreatePaymentCommand(
        organization_id=organization_id,
        order_reference=order_reference,
        amount=Money(12500, "INR"),
        idempotency_key=idempotency_key,
    )


def refund(
    payment_id,
    organization_id=ORG_A,
    amount=2500,
    idempotency_key="refund_key_001",
    currency="INR",
):
    return CreateRefundCommand(
        organization_id=organization_id,
        provider_payment_id=payment_id,
        amount=Money(amount, currency),
        idempotency_key=idempotency_key,
    )


def test_implements_existing_provider_interface():
    provider: PaymentProvider = SandboxPaymentProvider()

    created = provider.create_payment(payment())

    assert created.state is PaymentState.SUCCEEDED
    assert created.provider_payment_id.startswith("sim_pay_")

    fetched = provider.fetch_payment(
        FetchPaymentCommand(
            organization_id=ORG_A,
            provider_payment_id=created.provider_payment_id,
        )
    )

    assert fetched == created


def test_payment_replay_returns_original_result():
    provider = SandboxPaymentProvider()
    command = payment()

    first = provider.create_payment(command)
    second = provider.create_payment(command)

    assert first == second
    assert len(provider._payments_by_key) == 1


def test_simulated_ids_are_deterministic_across_instances():
    first = SandboxPaymentProvider().create_payment(payment())
    second = SandboxPaymentProvider().create_payment(payment())

    assert first == second


def test_same_tenant_key_cannot_change_order():
    provider = SandboxPaymentProvider()
    provider.create_payment(payment())

    with pytest.raises(ProviderError) as error:
        provider.create_payment(
            payment(order_reference="order_sim_002")
        )

    assert error.value.kind is ProviderErrorKind.CONFLICT


def test_payment_keys_are_tenant_scoped():
    provider = SandboxPaymentProvider()

    a = provider.create_payment(payment(ORG_A))
    b = provider.create_payment(payment(ORG_B))

    assert a.provider_payment_id != b.provider_payment_id


def test_cross_tenant_payment_fetch_is_rejected():
    provider = SandboxPaymentProvider()
    result = provider.create_payment(payment(ORG_A))

    with pytest.raises(ProviderError) as error:
        provider.fetch_payment(
            FetchPaymentCommand(
                organization_id=ORG_B,
                provider_payment_id=result.provider_payment_id,
            )
        )

    assert error.value.kind is ProviderErrorKind.INVALID_REQUEST


def test_unknown_payment_fetch_is_rejected():
    provider = SandboxPaymentProvider()

    with pytest.raises(ProviderError) as error:
        provider.fetch_payment(
            FetchPaymentCommand(
                organization_id=ORG_A,
                provider_payment_id="sim_pay_unknown",
            )
        )

    assert error.value.kind is ProviderErrorKind.INVALID_REQUEST


@pytest.mark.parametrize(
    "scenario,expected_state",
    [
        (SandboxScenario.SUCCESS, PaymentState.SUCCEEDED),
        (SandboxScenario.PENDING, PaymentState.PROCESSING),
    ],
)
def test_normal_payment_outcomes(scenario, expected_state):
    provider = SandboxPaymentProvider(
        payment_scenario=scenario,
    )

    result = provider.create_payment(payment())

    assert result.state is expected_state
    assert provider.reconcile_payment(payment()) == result


def test_declined_payment_is_recorded_as_failed():
    provider = SandboxPaymentProvider(
        payment_scenario=SandboxScenario.DECLINED,
    )

    with pytest.raises(ProviderError) as error:
        provider.create_payment(payment())

    assert error.value.kind is ProviderErrorKind.DECLINED

    stored = provider.reconcile_payment(payment())

    assert stored is not None
    assert stored.state is PaymentState.FAILED
    assert provider.create_payment(payment()) == stored


def test_timeout_after_accept_retains_payment():
    provider = SandboxPaymentProvider(
        payment_scenario=SandboxScenario.TIMEOUT_AFTER_ACCEPT,
    )

    with pytest.raises(ProviderError) as error:
        provider.create_payment(payment())

    assert error.value.kind is ProviderErrorKind.TIMEOUT

    stored = provider.reconcile_payment(payment())

    assert stored is not None
    assert stored.state is PaymentState.PROCESSING
    assert provider.create_payment(payment()) == stored
    assert len(provider._payments_by_key) == 1


def test_unavailable_before_accept_has_no_record():
    provider = SandboxPaymentProvider(
        payment_scenario=SandboxScenario.UNAVAILABLE_BEFORE_ACCEPT,
    )

    with pytest.raises(ProviderError) as error:
        provider.create_payment(payment())

    assert error.value.kind is ProviderErrorKind.UNAVAILABLE
    assert provider.reconcile_payment(payment()) is None


def test_refund_success_and_replay():
    provider = SandboxPaymentProvider()
    created = provider.create_payment(payment())

    command = refund(created.provider_payment_id)

    first = provider.create_refund(command)
    replay = provider.create_refund(command)

    assert first == replay
    assert first.state is RefundState.SUCCEEDED
    assert first.provider_refund_id.startswith("sim_ref_")
    assert len(provider._refunds_by_key) == 1


def test_refund_idempotency_conflict():
    provider = SandboxPaymentProvider()
    created = provider.create_payment(payment())

    provider.create_refund(refund(created.provider_payment_id))

    with pytest.raises(ProviderError) as error:
        provider.create_refund(
            refund(
                created.provider_payment_id,
                amount=3500,
            )
        )

    assert error.value.kind is ProviderErrorKind.CONFLICT


def test_refund_cannot_exceed_remaining_amount():
    provider = SandboxPaymentProvider()
    created = provider.create_payment(payment())

    provider.create_refund(
        refund(
            created.provider_payment_id,
            amount=10000,
        )
    )

    with pytest.raises(ProviderError) as error:
        provider.create_refund(
            refund(
                created.provider_payment_id,
                amount=3000,
                idempotency_key="refund_key_002",
            )
        )

    assert error.value.kind is ProviderErrorKind.CONFLICT
    assert len(provider._refunds_by_key) == 1


def test_cross_tenant_refund_is_rejected():
    provider = SandboxPaymentProvider()
    created = provider.create_payment(payment(ORG_A))

    with pytest.raises(ProviderError) as error:
        provider.create_refund(
            refund(
                created.provider_payment_id,
                organization_id=ORG_B,
            )
        )

    assert error.value.kind is ProviderErrorKind.INVALID_REQUEST


def test_refund_currency_must_match_payment():
    provider = SandboxPaymentProvider()
    created = provider.create_payment(payment())

    with pytest.raises(ProviderError) as error:
        provider.create_refund(
            refund(
                created.provider_payment_id,
                currency="USD",
            )
        )

    assert error.value.kind is ProviderErrorKind.INVALID_REQUEST


def test_refund_requires_successful_payment():
    provider = SandboxPaymentProvider(
        payment_scenario=SandboxScenario.PENDING,
    )

    created = provider.create_payment(payment())

    with pytest.raises(ProviderError) as error:
        provider.create_refund(
            refund(created.provider_payment_id)
        )

    assert error.value.kind is ProviderErrorKind.CONFLICT


def test_pending_refunds_reserve_balance():
    provider = SandboxPaymentProvider(
        refund_scenario=SandboxScenario.PENDING,
    )

    created = provider.create_payment(payment())

    first = provider.create_refund(
        refund(
            created.provider_payment_id,
            amount=11000,
        )
    )

    assert first.state is RefundState.PENDING

    with pytest.raises(ProviderError) as error:
        provider.create_refund(
            refund(
                created.provider_payment_id,
                amount=2000,
                idempotency_key="refund_key_002",
            )
        )

    assert error.value.kind is ProviderErrorKind.CONFLICT


def test_refund_timeout_after_accept_is_reconcilable():
    provider = SandboxPaymentProvider(
        refund_scenario=SandboxScenario.TIMEOUT_AFTER_ACCEPT,
    )

    created = provider.create_payment(payment())
    command = refund(created.provider_payment_id)

    with pytest.raises(ProviderError) as error:
        provider.create_refund(command)

    assert error.value.kind is ProviderErrorKind.TIMEOUT

    original = provider.reconcile_refund(command)

    assert original is not None
    assert original.state is RefundState.PENDING
    assert provider.create_refund(command) == original


def test_refund_unavailable_before_accept():
    provider = SandboxPaymentProvider(
        refund_scenario=SandboxScenario.UNAVAILABLE_BEFORE_ACCEPT,
    )

    created = provider.create_payment(payment())
    command = refund(created.provider_payment_id)

    with pytest.raises(ProviderError) as error:
        provider.create_refund(command)

    assert error.value.kind is ProviderErrorKind.UNAVAILABLE
    assert provider.reconcile_refund(command) is None


def test_refund_decline_has_no_successful_record():
    provider = SandboxPaymentProvider(
        refund_scenario=SandboxScenario.DECLINED,
    )

    created = provider.create_payment(payment())
    command = refund(created.provider_payment_id)

    with pytest.raises(ProviderError) as error:
        provider.create_refund(command)

    assert error.value.kind is ProviderErrorKind.DECLINED
    assert provider.reconcile_refund(command) is None


def test_reconciliation_rejects_changed_request():
    provider = SandboxPaymentProvider()
    provider.create_payment(payment())

    with pytest.raises(ProviderError) as error:
        provider.reconcile_payment(
            payment(order_reference="order_sim_002")
        )

    assert error.value.kind is ProviderErrorKind.CONFLICT


def test_refund_reconciliation_rejects_changed_request():
    provider = SandboxPaymentProvider()
    created = provider.create_payment(payment())

    provider.create_refund(refund(created.provider_payment_id))

    with pytest.raises(ProviderError) as error:
        provider.reconcile_refund(
            refund(
                created.provider_payment_id,
                amount=1000,
            )
        )

    assert error.value.kind is ProviderErrorKind.CONFLICT


def test_concurrent_same_key_creates_one_payment():
    provider = SandboxPaymentProvider()
    command = payment()

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(
            pool.map(
                lambda _: provider.create_payment(command),
                range(20),
            )
        )

    assert len({
        result.provider_payment_id
        for result in results
    }) == 1

    assert len(provider._payments_by_key) == 1


def test_concurrent_distinct_refunds_respect_balance():
    provider = SandboxPaymentProvider()
    created = provider.create_payment(payment())

    commands = [
        refund(
            created.provider_payment_id,
            amount=8000,
            idempotency_key="refund_key_A001",
        ),
        refund(
            created.provider_payment_id,
            amount=8000,
            idempotency_key="refund_key_B001",
        ),
    ]

    def execute(command):
        try:
            return provider.create_refund(command)
        except ProviderError as error:
            return error.kind

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(execute, commands))

    assert sum(
        isinstance(result, RefundState)
        or (
            hasattr(result, "state")
            and result.state is RefundState.SUCCEEDED
        )
        for result in results
    ) == 1

    assert results.count(ProviderErrorKind.CONFLICT) == 1
    assert len(provider._refunds_by_key) == 1


@pytest.mark.parametrize(
    "payment_scenario,refund_scenario",
    [
        ("success", SandboxScenario.SUCCESS),
        (SandboxScenario.SUCCESS, "success"),
        (None, SandboxScenario.SUCCESS),
        (SandboxScenario.SUCCESS, None),
    ],
)
def test_invalid_scenario_types_rejected(
    payment_scenario,
    refund_scenario,
):
    with pytest.raises(TypeError):
        SandboxPaymentProvider(
            payment_scenario=payment_scenario,
            refund_scenario=refund_scenario,
        )


@pytest.mark.parametrize(
    "method,arg",
    [
        ("create_payment", None),
        ("create_payment", "invalid"),
        ("fetch_payment", None),
        ("create_refund", None),
        ("reconcile_payment", None),
        ("reconcile_refund", None),
    ],
)
def test_invalid_command_types_rejected(method, arg):
    provider = SandboxPaymentProvider()

    with pytest.raises(TypeError):
        getattr(provider, method)(arg)


def test_no_real_gateway_configuration_needed():
    provider = SandboxPaymentProvider()

    assert provider.provider_code == "sandbox_sim"
    assert provider.reconcile_payment(payment()) is None
