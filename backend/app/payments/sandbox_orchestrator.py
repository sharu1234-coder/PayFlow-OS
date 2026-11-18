"""Authorization-aware sandbox payment orchestration.

This is a non-persistent, development-only simulation component.

It does not expose HTTP routes, process real money, contact
providers, modify payment orders, or write payment state.

The caller must supply an actor identity obtained from a
verified session, never from untrusted request input.

Durable provider operations, concurrency across processes,
reconciliation workers and real-money integrations are out
of scope for this implementation.
"""

from dataclasses import dataclass
from typing import Callable, TypeVar
from uuid import UUID

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.payments.contracts import (
    CreatePaymentCommand,
    CreateRefundCommand,
    FetchPaymentCommand,
    PaymentResult,
    RefundResult,
    ProviderError,
    ProviderErrorKind,
)
from app.payments.provider_recovery import (
    ProviderOperation,
    RecoveryAction,
    choose_provider_recovery,
)
from app.payments.provider_registry import ProviderRegistry
from app.services.organization_rbac import (
    OrganizationUnavailable,
    PermissionDenied,
    require_organization_permission,
)


class SandboxOrchestrationUnavailable(Exception):
    """Sandbox operation disabled by deployment policy."""


class SandboxOrchestrationAccessDenied(Exception):
    """Actor lacks permission for this organization."""


@dataclass(frozen=True, slots=True)
class SandboxExecution:
    """Synthetic provider result or sanitized failure.

    A missing result is not proof that money did not move.
    An action of RECONCILE does not authorize another mutation.
    """

    operation: ProviderOperation
    result: PaymentResult | RefundResult | None
    provider_error: ProviderErrorKind | None
    next_action: RecoveryAction | None


_Result = TypeVar("_Result", PaymentResult, RefundResult)


class SandboxPaymentOrchestrator:
    """Fail-closed sandbox orchestration boundary.

    All operations recheck server-side environment settings,
    organization membership and operation-specific permission.
    Provider registration must already be performed by trusted
    application setup; this class never registers providers.
    """

    def __init__(self, *, registry: ProviderRegistry) -> None:
        if not isinstance(registry, ProviderRegistry):
            raise TypeError("Expected ProviderRegistry")

        self._registry = registry

    @staticmethod
    def _authorize(
        db: Session,
        *,
        actor_user_id: UUID,
        organization_id: UUID,
        permission: str,
    ) -> None:
        if (
            not isinstance(actor_user_id, UUID)
            or actor_user_id.int == 0
        ):
            raise ValueError("Valid authenticated actor required")

        settings = get_settings()

        if (
            settings.app_env != "development"
            or settings.sandbox_payment_attempts_enabled is not True
        ):
            raise SandboxOrchestrationUnavailable(
                "Sandbox orchestration disabled"
            )

        try:
            require_organization_permission(
                db,
                actor_user_id,
                organization_id,
                permission,
            )
        except (OrganizationUnavailable, PermissionDenied):
            raise SandboxOrchestrationAccessDenied(
                "Payment operation is not permitted"
            ) from None

    def _provider(self, organization_id: UUID):
        # No dynamic gateway selection or arbitrary provider codes.
        return self._registry.resolve(
            organization_id=organization_id,
            provider_code=ProviderRegistry.SANDBOX_CODE,
        )

    @staticmethod
    def _execute(
        operation: ProviderOperation,
        action: Callable[[], _Result],
    ) -> SandboxExecution:
        try:
            result = action()
        except ProviderError as error:
            recovery = choose_provider_recovery(
                operation,
                error,
            )

            return SandboxExecution(
                operation=operation,
                result=None,
                provider_error=error.kind,
                next_action=recovery.action,
            )

        return SandboxExecution(
            operation=operation,
            result=result,
            provider_error=None,
            next_action=None,
        )

    def create_payment(
        self,
        db: Session,
        *,
        actor_user_id: UUID,
        command: CreatePaymentCommand,
    ) -> SandboxExecution:
        if not isinstance(command, CreatePaymentCommand):
            raise TypeError("Expected CreatePaymentCommand")

        self._authorize(
            db,
            actor_user_id=actor_user_id,
            organization_id=command.organization_id,
            permission="payments.create",
        )

        provider = self._provider(command.organization_id)

        return self._execute(
            ProviderOperation.CREATE_PAYMENT,
            lambda: provider.create_payment(command),
        )

    def fetch_payment(
        self,
        db: Session,
        *,
        actor_user_id: UUID,
        command: FetchPaymentCommand,
    ) -> SandboxExecution:
        if not isinstance(command, FetchPaymentCommand):
            raise TypeError("Expected FetchPaymentCommand")

        self._authorize(
            db,
            actor_user_id=actor_user_id,
            organization_id=command.organization_id,
            permission="payments.read",
        )

        provider = self._provider(command.organization_id)

        return self._execute(
            ProviderOperation.FETCH_PAYMENT,
            lambda: provider.fetch_payment(command),
        )

    def create_refund(
        self,
        db: Session,
        *,
        actor_user_id: UUID,
        command: CreateRefundCommand,
    ) -> SandboxExecution:
        if not isinstance(command, CreateRefundCommand):
            raise TypeError("Expected CreateRefundCommand")

        self._authorize(
            db,
            actor_user_id=actor_user_id,
            organization_id=command.organization_id,
            permission="refunds.request",
        )

        provider = self._provider(command.organization_id)

        return self._execute(
            ProviderOperation.CREATE_REFUND,
            lambda: provider.create_refund(command),
        )

    def reconcile_payment(
        self,
        db: Session,
        *,
        actor_user_id: UUID,
        command: CreatePaymentCommand,
    ) -> PaymentResult | None:
        """Read original simulated result without retrying create."""
        if not isinstance(command, CreatePaymentCommand):
            raise TypeError("Expected CreatePaymentCommand")

        self._authorize(
            db,
            actor_user_id=actor_user_id,
            organization_id=command.organization_id,
            permission="payments.read",
        )

        return self._provider(
            command.organization_id
        ).reconcile_payment(command)

    def reconcile_refund(
        self,
        db: Session,
        *,
        actor_user_id: UUID,
        command: CreateRefundCommand,
    ) -> RefundResult | None:
        """Read original simulated refund without retrying create."""
        if not isinstance(command, CreateRefundCommand):
            raise TypeError("Expected CreateRefundCommand")

        self._authorize(
            db,
            actor_user_id=actor_user_id,
            organization_id=command.organization_id,
            permission="payments.read",
        )

        return self._provider(
            command.organization_id
        ).reconcile_refund(command)
