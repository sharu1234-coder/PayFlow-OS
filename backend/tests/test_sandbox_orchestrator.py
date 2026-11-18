"""Authorization and recovery tests for sandbox orchestration.

These are isolated tests with a controlled permission stub.
Actual PostgreSQL authorization integration remains a
separate required milestone.
"""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
from types import SimpleNamespace
from uuid import UUID

import pytest

import app.payments.sandbox_orchestrator as module

from app.payments.contracts import (
    CreatePaymentCommand,
    CreateRefundCommand,
    FetchPaymentCommand,
    Money,
    PaymentState,
    ProviderErrorKind,
    RefundState,
)
from app.payments.provider_recovery import (
    ProviderOperation,
    RecoveryAction,
)
from app.payments.provider_registry import (
    ProviderRegistry,
    RegistryPolicy,
)
from app.payments.sandbox_orchestrator import (
    SandboxOrchestrationAccessDenied,
    SandboxOrchestrationUnavailable,
    SandboxPaymentOrchestrator,
)
from app.payments.sandbox_provider import SandboxScenario
from app.services.organization_rbac import (
    OrganizationUnavailable,
    PermissionDenied,
    permissions_for_role,
)


ORG_A = UUID("11111111-1111-4111-8111-111111111111")
ORG_B = UUID("22222222-2222-4222-8222-222222222222")

OWNER = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
VIEWER = UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
FINANCE = UUID("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
OTHER_OWNER = UUID("dddddddd-dddd-4ddd-8ddd-dddddddddddd")

DB = object()


def payment(organization_id=ORG_A):
    return CreatePaymentCommand(
        organization_id=organization_id,
        order_reference="order_orch_001",
        amount=Money(12000, "INR"),
        idempotency_key="payment_key_001",
    )


def refund(provider_payment_id, organization_id=ORG_A):
    return CreateRefundCommand(
        organization_id=organization_id,
        provider_payment_id=provider_payment_id,
        amount=Money(2000, "INR"),
        idempotency_key="refund_key_001",
    )


@pytest.fixture
def setup(monkeypatch):
    monkeypatch.setattr(
        module,
        "get_settings",
        lambda: SimpleNamespace(
            app_env="development",
            sandbox_payment_attempts_enabled=True,
        ),
    )

    grants = {
        (OWNER, ORG_A): "owner",
        (VIEWER, ORG_A): "viewer",
        (FINANCE, ORG_A): "finance",
        (OTHER_OWNER, ORG_B): "owner",
    }

    def check_permission(db, actor, organization_id, permission):
        role = grants.get((actor, organization_id))

        if role is None:
            raise OrganizationUnavailable()

        if permission not in permissions_for_role(role):
            raise PermissionDenied()

        return role

    monkeypatch.setattr(
        module,
        "require_organization_permission",
        check_permission,
    )

    registry = ProviderRegistry(
        policy=RegistryPolicy(
            environment="development",
            sandbox_enabled=True,
        )
    )

    registry.register_sandbox(organization_id=ORG_A)
    registry.register_sandbox(organization_id=ORG_B)

    return SandboxPaymentOrchestrator(registry=registry), grants, registry


def test_authorized_payment_creation(setup):
    orchestrator, _, _ = setup

    outcome = orchestrator.create_payment(
        DB,
        actor_user_id=OWNER,
        command=payment(),
    )

    assert outcome.operation is ProviderOperation.CREATE_PAYMENT
    assert outcome.result is not None
    assert outcome.result.state is PaymentState.SUCCEEDED
    assert outcome.provider_error is None
    assert outcome.next_action is None


def test_payment_replay_returns_same_simulated_result(setup):
    orchestrator, _, _ = setup

    first = orchestrator.create_payment(
        DB, actor_user_id=OWNER, command=payment()
    )
    second = orchestrator.create_payment(
        DB, actor_user_id=OWNER, command=payment()
    )

    assert first == second


def test_payment_status_is_readable_by_viewer(setup):
    orchestrator, _, _ = setup

    created = orchestrator.create_payment(
        DB, actor_user_id=OWNER, command=payment()
    )

    outcome = orchestrator.fetch_payment(
        DB,
        actor_user_id=VIEWER,
        command=FetchPaymentCommand(
            organization_id=ORG_A,
            provider_payment_id=created.result.provider_payment_id,
        ),
    )

    assert outcome.result == created.result


def test_viewer_cannot_create_payment(setup):
    orchestrator, _, registry = setup

    with pytest.raises(SandboxOrchestrationAccessDenied):
        orchestrator.create_payment(
            DB, actor_user_id=VIEWER, command=payment()
        )

    provider = registry.resolve(
        organization_id=ORG_A,
        provider_code="sandbox_sim",
    )

    assert provider.reconcile_payment(payment()) is None


def test_viewer_cannot_create_refund(setup):
    orchestrator, _, _ = setup

    created = orchestrator.create_payment(
        DB, actor_user_id=OWNER, command=payment()
    )

    command = refund(created.result.provider_payment_id)

    with pytest.raises(SandboxOrchestrationAccessDenied):
        orchestrator.create_refund(
            DB, actor_user_id=VIEWER, command=command
        )

    assert orchestrator.reconcile_refund(
        DB, actor_user_id=OWNER, command=command
    ) is None


def test_finance_can_request_refund(setup):
    orchestrator, _, _ = setup

    created = orchestrator.create_payment(
        DB, actor_user_id=OWNER, command=payment()
    )

    refunded = orchestrator.create_refund(
        DB,
        actor_user_id=FINANCE,
        command=refund(created.result.provider_payment_id),
    )

    assert refunded.result.state is RefundState.SUCCEEDED


def test_unknown_membership_is_denied(setup):
    orchestrator, _, _ = setup

    with pytest.raises(SandboxOrchestrationAccessDenied):
        orchestrator.create_payment(
            DB, actor_user_id=OTHER_OWNER, command=payment()
        )


def test_cross_tenant_payment_is_denied(setup):
    orchestrator, _, registry = setup

    with pytest.raises(SandboxOrchestrationAccessDenied):
        orchestrator.create_payment(
            DB,
            actor_user_id=OWNER,
            command=payment(ORG_B),
        )

    provider_b = registry.resolve(
        organization_id=ORG_B,
        provider_code="sandbox_sim",
    )

    assert provider_b.reconcile_payment(payment(ORG_B)) is None


def test_membership_revocation_blocks_original_replay(setup):
    orchestrator, grants, _ = setup

    created = orchestrator.create_payment(
        DB, actor_user_id=OWNER, command=payment()
    )

    assert created.result is not None

    grants.pop((OWNER, ORG_A))

    with pytest.raises(SandboxOrchestrationAccessDenied):
        orchestrator.create_payment(
            DB, actor_user_id=OWNER, command=payment()
        )

    with pytest.raises(SandboxOrchestrationAccessDenied):
        orchestrator.reconcile_payment(
            DB, actor_user_id=OWNER, command=payment()
        )


def test_permission_downgrade_blocks_refund(setup):
    orchestrator, grants, _ = setup

    created = orchestrator.create_payment(
        DB, actor_user_id=OWNER, command=payment()
    )

    grants[(OWNER, ORG_A)] = "viewer"

    with pytest.raises(SandboxOrchestrationAccessDenied):
        orchestrator.create_refund(
            DB,
            actor_user_id=OWNER,
            command=refund(created.result.provider_payment_id),
        )


@pytest.mark.parametrize(
    "environment,enabled",
    [
        ("development", False),
        ("staging", True),
        ("staging", False),
        ("production", True),
        ("production", False),
    ],
)
def test_runtime_environment_blocks_sandbox(
    setup, monkeypatch, environment, enabled
):
    orchestrator, _, registry = setup

    monkeypatch.setattr(
        module,
        "get_settings",
        lambda: SimpleNamespace(
            app_env=environment,
            sandbox_payment_attempts_enabled=enabled,
        ),
    )

    with pytest.raises(SandboxOrchestrationUnavailable):
        orchestrator.create_payment(
            DB, actor_user_id=OWNER, command=payment()
        )

    provider = registry.resolve(
        organization_id=ORG_A,
        provider_code="sandbox_sim",
    )

    assert provider.reconcile_payment(payment()) is None


def test_timeout_after_accept_requires_reconciliation(
    setup,
):
    _, _, _ = setup

    registry = ProviderRegistry(
        policy=RegistryPolicy(
            environment="development",
            sandbox_enabled=True,
        ),
    )

    registry.register_sandbox(
        organization_id=ORG_A,
        payment_scenario=SandboxScenario.TIMEOUT_AFTER_ACCEPT,
    )

    orchestrator = SandboxPaymentOrchestrator(
        registry=registry
    )

    outcome = orchestrator.create_payment(
        DB, actor_user_id=OWNER, command=payment()
    )

    assert outcome.result is None
    assert outcome.provider_error is ProviderErrorKind.TIMEOUT
    assert outcome.next_action is RecoveryAction.RECONCILE

    original = orchestrator.reconcile_payment(
        DB, actor_user_id=OWNER, command=payment()
    )

    assert original is not None
    assert original.state is PaymentState.PROCESSING


def test_unavailable_payment_remains_unresolved(setup):
    registry = ProviderRegistry(
        policy=RegistryPolicy(
            environment="development",
            sandbox_enabled=True,
        )
    )
    registry.register_sandbox(
        organization_id=ORG_A,
        payment_scenario=SandboxScenario.UNAVAILABLE_BEFORE_ACCEPT,
    )

    orchestrator = SandboxPaymentOrchestrator(
        registry=registry
    )

    outcome = orchestrator.create_payment(
        DB, actor_user_id=OWNER, command=payment()
    )

    assert outcome.result is None
    assert outcome.next_action is RecoveryAction.RECONCILE

    # Absence of a local simulation record is not proof
    # that a live gateway did not accept a payment.
    assert orchestrator.reconcile_payment(
        DB, actor_user_id=OWNER, command=payment()
    ) is None


def test_unknown_payment_fetch_returns_sanitized_error(setup):
    orchestrator, _, _ = setup

    outcome = orchestrator.fetch_payment(
        DB,
        actor_user_id=VIEWER,
        command=FetchPaymentCommand(
            organization_id=ORG_A,
            provider_payment_id="sim_pay_unknown",
        ),
    )

    assert outcome.result is None
    assert outcome.provider_error is ProviderErrorKind.INVALID_REQUEST
    assert outcome.next_action is RecoveryAction.REJECT


def test_refund_timeout_does_not_retry(setup):
    registry = ProviderRegistry(
        policy=RegistryPolicy(
            environment="development",
            sandbox_enabled=True,
        )
    )

    registry.register_sandbox(
        organization_id=ORG_A,
        refund_scenario=SandboxScenario.TIMEOUT_AFTER_ACCEPT,
    )

    orchestrator = SandboxPaymentOrchestrator(
        registry=registry
    )

    created = orchestrator.create_payment(
        DB, actor_user_id=OWNER, command=payment()
    )

    refund_command = refund(created.result.provider_payment_id)

    outcome = orchestrator.create_refund(
        DB, actor_user_id=FINANCE, command=refund_command
    )

    assert outcome.result is None
    assert outcome.provider_error is ProviderErrorKind.TIMEOUT
    assert outcome.next_action is RecoveryAction.RECONCILE

    original = orchestrator.reconcile_refund(
        DB,
        actor_user_id=FINANCE,
        command=refund_command,
    )

    assert original is not None
    assert original.state is RefundState.PENDING


def test_refund_replay_is_idempotent(setup):
    orchestrator, _, _ = setup

    created = orchestrator.create_payment(
        DB, actor_user_id=OWNER, command=payment()
    )

    command = refund(created.result.provider_payment_id)

    first = orchestrator.create_refund(
        DB, actor_user_id=FINANCE, command=command
    )
    second = orchestrator.create_refund(
        DB, actor_user_id=FINANCE, command=command
    )

    assert first == second


def test_concurrent_payment_replay_is_stable(setup):
    orchestrator, _, _ = setup

    def invoke(_):
        return orchestrator.create_payment(
            DB, actor_user_id=OWNER, command=payment()
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(invoke, range(20)))

    assert all(result == results[0] for result in results)
    assert results[0].result is not None


@pytest.mark.parametrize(
    "method",
    [
        "create_payment",
        "fetch_payment",
        "create_refund",
        "reconcile_payment",
        "reconcile_refund",
    ],
)
def test_invalid_commands_rejected(setup, method):
    orchestrator, _, _ = setup

    with pytest.raises(TypeError):
        getattr(orchestrator, method)(
            DB,
            actor_user_id=OWNER,
            command=None,
        )


@pytest.mark.parametrize(
    "actor",
    [None, "owner", UUID(int=0)],
)
def test_invalid_authenticated_actor_rejected(setup, actor):
    orchestrator, _, _ = setup

    with pytest.raises(ValueError):
        orchestrator.create_payment(
            DB, actor_user_id=actor, command=payment()
        )


def test_orchestrator_requires_registry():
    with pytest.raises(TypeError):
        SandboxPaymentOrchestrator(registry=None)


def test_execution_record_is_immutable(setup):
    orchestrator, _, _ = setup

    outcome = orchestrator.create_payment(
        DB, actor_user_id=OWNER, command=payment()
    )

    with pytest.raises(FrozenInstanceError):
        outcome.result = None
