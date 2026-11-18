"""Isolated tenant-provider registry security tests."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
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
)
from app.payments.ports import PaymentProvider
from app.payments.provider_registry import (
    ProviderAlreadyRegistered,
    ProviderNotAvailable,
    ProviderRegistry,
    RegistryPolicy,
)
from app.payments.sandbox_provider import SandboxScenario


ORG_A = UUID("11111111-1111-4111-8111-111111111111")
ORG_B = UUID("22222222-2222-4222-8222-222222222222")


def enabled_registry():
    return ProviderRegistry(
        policy=RegistryPolicy(
            environment="development",
            sandbox_enabled=True,
        ),
    )


def command(
    organization_id=ORG_A,
    key="payment_key_001",
):
    return CreatePaymentCommand(
        organization_id=organization_id,
        order_reference="order_reg_001",
        amount=Money(12000, "INR"),
        idempotency_key=key,
    )


def fetch(organization_id, provider_payment_id):
    return FetchPaymentCommand(
        organization_id=organization_id,
        provider_payment_id=provider_payment_id,
    )


def refund(organization_id, provider_payment_id):
    return CreateRefundCommand(
        organization_id=organization_id,
        provider_payment_id=provider_payment_id,
        amount=Money(1000, "INR"),
        idempotency_key="refund_key_001",
    )


def resolved(registry, organization_id=ORG_A):
    return registry.resolve(
        organization_id=organization_id,
        provider_code="sandbox_sim",
    )


def test_explicit_development_policy_allows_sandbox():
    registry = enabled_registry()
    registry.register_sandbox(organization_id=ORG_A)

    provider: PaymentProvider = resolved(registry)

    result = provider.create_payment(command())

    assert result.state is PaymentState.SUCCEEDED
    assert provider.provider_code == "sandbox_sim"


@pytest.mark.parametrize(
    "environment,enabled",
    [
        ("development", False),
        ("staging", False),
        ("staging", True),
        ("production", False),
        ("production", True),
    ],
)
def test_disabled_environment_rejects_registration_and_selection(
    environment,
    enabled,
):
    registry = ProviderRegistry(
        policy=RegistryPolicy(
            environment=environment,
            sandbox_enabled=enabled,
        )
    )

    with pytest.raises(ProviderNotAvailable):
        registry.register_sandbox(organization_id=ORG_A)

    with pytest.raises(ProviderNotAvailable):
        resolved(registry)


@pytest.mark.parametrize(
    "environment",
    ["Development", "dev", "test", "", None, 1],
)
def test_invalid_environment_rejected(environment):
    with pytest.raises(ValueError):
        RegistryPolicy(
            environment=environment,
            sandbox_enabled=True,
        )


@pytest.mark.parametrize(
    "flag",
    ["true", 1, None, [], 0],
)
def test_non_boolean_flags_rejected(flag):
    with pytest.raises(TypeError):
        RegistryPolicy(
            environment="development",
            sandbox_enabled=flag,
        )


def test_registry_policy_is_immutable():
    policy = RegistryPolicy(
        environment="development",
        sandbox_enabled=True,
    )

    with pytest.raises(FrozenInstanceError):
        policy.environment = "production"


def test_invalid_registry_policy_rejected():
    with pytest.raises(TypeError):
        ProviderRegistry(policy=None)


@pytest.mark.parametrize(
    "organization_id",
    [None, "tenant", UUID(int=0), 123],
)
def test_invalid_organization_rejected(organization_id):
    registry = enabled_registry()

    with pytest.raises(ValueError):
        registry.register_sandbox(
            organization_id=organization_id
        )

    with pytest.raises(ValueError):
        registry.resolve(
            organization_id=organization_id,
            provider_code="sandbox_sim",
        )


def test_provider_requires_explicit_registration():
    with pytest.raises(ProviderNotAvailable):
        resolved(enabled_registry())


@pytest.mark.parametrize(
    "provider_code",
    ["razorpay", "juspay", "sandbox", "", None, 1],
)
def test_unknown_provider_codes_fail_closed(provider_code):
    registry = enabled_registry()
    registry.register_sandbox(organization_id=ORG_A)

    with pytest.raises(ProviderNotAvailable):
        registry.resolve(
            organization_id=ORG_A,
            provider_code=provider_code,
        )


def test_duplicate_registration_is_rejected():
    registry = enabled_registry()
    registry.register_sandbox(organization_id=ORG_A)

    with pytest.raises(ProviderAlreadyRegistered):
        registry.register_sandbox(
            organization_id=ORG_A,
            payment_scenario=SandboxScenario.DECLINED,
        )


def test_registration_failure_does_not_store_partial_binding():
    registry = enabled_registry()

    with pytest.raises(TypeError):
        registry.register_sandbox(
            organization_id=ORG_A,
            payment_scenario="success",
        )

    registry.register_sandbox(organization_id=ORG_A)
    assert resolved(registry) is not None


def test_registered_provider_instance_is_stable():
    registry = enabled_registry()
    registry.register_sandbox(organization_id=ORG_A)

    assert resolved(registry) is resolved(registry)


def test_each_tenant_has_independent_provider_instance():
    registry = enabled_registry()

    registry.register_sandbox(organization_id=ORG_A)
    registry.register_sandbox(organization_id=ORG_B)

    a = resolved(registry, ORG_A)
    b = resolved(registry, ORG_B)

    assert a is not b

    payment_a = a.create_payment(command(ORG_A))
    payment_b = b.create_payment(command(ORG_B))

    assert (
        payment_a.provider_payment_id
        != payment_b.provider_payment_id
    )


def test_other_tenant_cannot_resolve_organization_binding():
    registry = enabled_registry()
    registry.register_sandbox(organization_id=ORG_A)

    with pytest.raises(ProviderNotAvailable):
        resolved(registry, ORG_B)


def test_create_payment_rejects_cross_tenant_command():
    registry = enabled_registry()
    registry.register_sandbox(organization_id=ORG_A)

    provider = resolved(registry)

    with pytest.raises(ProviderNotAvailable):
        provider.create_payment(command(ORG_B))

    assert provider.reconcile_payment(command(ORG_A)) is None


def test_fetch_and_refund_reject_cross_tenant_commands():
    registry = enabled_registry()
    registry.register_sandbox(organization_id=ORG_A)

    provider = resolved(registry)
    created = provider.create_payment(command(ORG_A))

    with pytest.raises(ProviderNotAvailable):
        provider.fetch_payment(
            fetch(ORG_B, created.provider_payment_id)
        )

    with pytest.raises(ProviderNotAvailable):
        provider.create_refund(
            refund(ORG_B, created.provider_payment_id)
        )


def test_reconciliation_rejects_cross_tenant_commands():
    registry = enabled_registry()
    registry.register_sandbox(organization_id=ORG_A)

    provider = resolved(registry)
    created = provider.create_payment(command(ORG_A))

    with pytest.raises(ProviderNotAvailable):
        provider.reconcile_payment(command(ORG_B))

    with pytest.raises(ProviderNotAvailable):
        provider.reconcile_refund(
            refund(ORG_B, created.provider_payment_id)
        )


def test_valid_refund_and_reconciliation_work():
    registry = enabled_registry()
    registry.register_sandbox(organization_id=ORG_A)

    provider = resolved(registry)
    created = provider.create_payment(command())

    refunded = provider.create_refund(
        refund(ORG_A, created.provider_payment_id)
    )

    assert refunded.provider_refund_id.startswith("sim_ref_")
    assert provider.reconcile_payment(command()) == created
    assert provider.reconcile_refund(
        refund(ORG_A, created.provider_payment_id)
    ) == refunded


def test_scenarios_are_separate_per_tenant():
    registry = enabled_registry()

    registry.register_sandbox(
        organization_id=ORG_A,
        payment_scenario=SandboxScenario.SUCCESS,
    )

    registry.register_sandbox(
        organization_id=ORG_B,
        payment_scenario=SandboxScenario.DECLINED,
    )

    assert (
        resolved(registry, ORG_A)
        .create_payment(command(ORG_A))
        .state is PaymentState.SUCCEEDED
    )

    with pytest.raises(ProviderError) as exc:
        resolved(registry, ORG_B).create_payment(command(ORG_B))

    assert exc.value.kind is ProviderErrorKind.DECLINED


def test_concurrent_duplicate_registration_has_one_winner():
    registry = enabled_registry()

    def register(_):
        try:
            registry.register_sandbox(organization_id=ORG_A)
            return "registered"
        except ProviderAlreadyRegistered:
            return "duplicate"

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(register, range(20)))

    assert results.count("registered") == 1
    assert results.count("duplicate") == 19


def test_bound_provider_rejects_invalid_commands():
    registry = enabled_registry()
    registry.register_sandbox(organization_id=ORG_A)
    provider = resolved(registry)

    for method in (
        provider.create_payment,
        provider.fetch_payment,
        provider.create_refund,
        provider.reconcile_payment,
        provider.reconcile_refund,
    ):
        with pytest.raises(TypeError):
            method(None)


def test_no_production_provider_or_credential_storage():
    registry = enabled_registry()
    registry.register_sandbox(organization_id=ORG_A)

    provider = resolved(registry)

    assert provider.provider_code == "sandbox_sim"
    assert not hasattr(registry, "credentials")
    assert not hasattr(provider, "api_key")
    assert not hasattr(provider, "secret_key")
