"""Explicit sandbox-only, tenant-bound provider selection.

This registry is an in-memory test component, not an
authorization service or production credential store.

Callers must perform authenticated tenant membership and
RBAC checks before selecting or invoking any provider.

Never construct RegistryPolicy from untrusted request input.
Use authoritative server-side configuration when integrating.
No API registration, database, gateway or network operations.
"""

from dataclasses import dataclass
from threading import RLock
from uuid import UUID

from app.payments.contracts import (
    CreatePaymentCommand,
    CreateRefundCommand,
    FetchPaymentCommand,
    PaymentResult,
    RefundResult,
)
from app.payments.sandbox_provider import (
    SandboxPaymentProvider,
    SandboxScenario,
)


class ProviderRegistryError(Exception):
    """Base for sanitized registry errors."""


class ProviderNotAvailable(ProviderRegistryError):
    """Provider unavailable or not permitted by registry policy."""


class ProviderAlreadyRegistered(ProviderRegistryError):
    """Duplicate provider binding was rejected."""


@dataclass(frozen=True, slots=True)
class RegistryPolicy:
    environment: str
    sandbox_enabled: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.environment) is not str
            or self.environment not in (
                "development",
                "staging",
                "production",
            )
        ):
            raise ValueError("Invalid registry environment")

        if type(self.sandbox_enabled) is not bool:
            raise TypeError("Sandbox enabled must be boolean")

    @property
    def allows_sandbox(self) -> bool:
        return (
            self.environment == "development"
            and self.sandbox_enabled is True
        )


def _validate_organization(value: UUID) -> None:
    if not isinstance(value, UUID) or value.int == 0:
        raise ValueError("Valid organization UUID required")


class _TenantBoundSandboxProvider:
    """Enforces a single tenant for every delegated operation.

    This defense-in-depth wrapper is not a substitute for
    authentication, authorization or durable tenant isolation.
    """

    provider_code = SandboxPaymentProvider.provider_code

    __slots__ = ("_organization_id", "_delegate")

    def __init__(
        self,
        organization_id: UUID,
        delegate: SandboxPaymentProvider,
    ) -> None:
        self._organization_id = organization_id
        self._delegate = delegate

    def _check_command(self, command: object) -> None:
        if not isinstance(
            command,
            (
                CreatePaymentCommand,
                FetchPaymentCommand,
                CreateRefundCommand,
            ),
        ):
            raise TypeError("Invalid provider command")

        if command.organization_id != self._organization_id:
            raise ProviderNotAvailable(
                "Provider not available for organization"
            )

    def create_payment(
        self,
        command: CreatePaymentCommand,
    ) -> PaymentResult:
        self._check_command(command)
        return self._delegate.create_payment(command)

    def fetch_payment(
        self,
        command: FetchPaymentCommand,
    ) -> PaymentResult:
        self._check_command(command)
        return self._delegate.fetch_payment(command)

    def create_refund(
        self,
        command: CreateRefundCommand,
    ) -> RefundResult:
        self._check_command(command)
        return self._delegate.create_refund(command)

    def reconcile_payment(
        self,
        command: CreatePaymentCommand,
    ) -> PaymentResult | None:
        self._check_command(command)
        return self._delegate.reconcile_payment(command)

    def reconcile_refund(
        self,
        command: CreateRefundCommand,
    ) -> RefundResult | None:
        self._check_command(command)
        return self._delegate.reconcile_refund(command)


class ProviderRegistry:
    """Fail-closed, process-local sandbox provider registry.

    Each organization receives a separate sandbox instance.
    Unknown providers, absent bindings, disabled sandbox, and
    cross-tenant commands are rejected.

    The registry does not authenticate callers and must not
    be wired directly to publicly accessible payment routes.
    """

    SANDBOX_CODE = "sandbox_sim"

    def __init__(self, *, policy: RegistryPolicy) -> None:
        if not isinstance(policy, RegistryPolicy):
            raise TypeError("Expected RegistryPolicy")

        self._policy = policy
        self._lock = RLock()
        self._bindings: dict[
            UUID, _TenantBoundSandboxProvider
        ] = {}

    def _require_sandbox_allowed(self) -> None:
        if not self._policy.allows_sandbox:
            raise ProviderNotAvailable(
                "Sandbox provider is disabled"
            )

    def register_sandbox(
        self,
        *,
        organization_id: UUID,
        payment_scenario: SandboxScenario = SandboxScenario.SUCCESS,
        refund_scenario: SandboxScenario = SandboxScenario.SUCCESS,
    ) -> None:
        _validate_organization(organization_id)
        self._require_sandbox_allowed()

        with self._lock:
            if organization_id in self._bindings:
                raise ProviderAlreadyRegistered(
                    "Provider binding already exists"
                )

            # Construct before storing to avoid partially
            # registered configurations on invalid scenarios.
            delegate = SandboxPaymentProvider(
                payment_scenario=payment_scenario,
                refund_scenario=refund_scenario,
            )

            self._bindings[organization_id] = (
                _TenantBoundSandboxProvider(
                    organization_id,
                    delegate,
                )
            )

    def resolve(
        self,
        *,
        organization_id: UUID,
        provider_code: str,
    ) -> _TenantBoundSandboxProvider:
        _validate_organization(organization_id)
        self._require_sandbox_allowed()

        if (
            type(provider_code) is not str
            or provider_code != self.SANDBOX_CODE
        ):
            raise ProviderNotAvailable(
                "Provider not available for organization"
            )

        with self._lock:
            provider = self._bindings.get(organization_id)

            if provider is None:
                raise ProviderNotAvailable(
                    "Provider not available for organization"
                )

            return provider
