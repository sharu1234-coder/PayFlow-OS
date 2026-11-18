"""In-memory deterministic payment provider for isolated tests.

No network, database, external gateway, or actual money movement.

Records are scoped to one provider instance and are not durable.
Never use this as a production idempotency or reconciliation store.
Never automatically register it as a real payment provider.
"""

from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
from threading import RLock
from uuid import UUID

from app.payments.contracts import (
    CreatePaymentCommand,
    CreateRefundCommand,
    FetchPaymentCommand,
    PaymentResult,
    PaymentState,
    ProviderError,
    ProviderErrorKind,
    RefundResult,
    RefundState,
)


class SandboxScenario(str, Enum):
    SUCCESS = "success"
    PENDING = "pending"
    DECLINED = "declined"
    TIMEOUT_AFTER_ACCEPT = "timeout_after_accept"
    UNAVAILABLE_BEFORE_ACCEPT = "unavailable_before_accept"


@dataclass(frozen=True, slots=True)
class _StoredPayment:
    command: CreatePaymentCommand
    result: PaymentResult


@dataclass(frozen=True, slots=True)
class _StoredRefund:
    command: CreateRefundCommand
    result: RefundResult


def _simulation_id(
    prefix: str,
    organization_id: UUID,
    key: str,
) -> str:
    """Generate a stable, obviously synthetic reference."""
    value = (
        prefix + ":" + organization_id.hex + ":" + key
    ).encode("ascii")

    digest = sha256(value).hexdigest()[:32]

    return f"sim_{prefix}_{digest}"


class SandboxPaymentProvider:
    """Thread-safe, process-local provider simulator.

    Scenarios are fixed at construction to make tests repeatable.

    An accepted request can time out without losing its simulated
    record. Reconciliation can then locate the original result.

    A simulated pre-accept failure has no stored result. A future
    production orchestrator must not interpret that absence as
    proof that retrying a real financial operation is safe.
    """

    provider_code = "sandbox_sim"

    def __init__(
        self,
        *,
        payment_scenario: SandboxScenario = SandboxScenario.SUCCESS,
        refund_scenario: SandboxScenario = SandboxScenario.SUCCESS,
    ) -> None:
        if not isinstance(payment_scenario, SandboxScenario):
            raise TypeError("Invalid payment scenario")

        if not isinstance(refund_scenario, SandboxScenario):
            raise TypeError("Invalid refund scenario")

        self._payment_scenario = payment_scenario
        self._refund_scenario = refund_scenario

        self._lock = RLock()

        self._payments_by_key: dict[
            tuple[UUID, str], _StoredPayment
        ] = {}

        self._payments_by_id: dict[
            tuple[UUID, str], _StoredPayment
        ] = {}

        self._refunds_by_key: dict[
            tuple[UUID, str], _StoredRefund
        ] = {}

    def create_payment(
        self,
        command: CreatePaymentCommand,
    ) -> PaymentResult:
        if not isinstance(command, CreatePaymentCommand):
            raise TypeError("Expected CreatePaymentCommand")

        key = (
            command.organization_id,
            command.idempotency_key,
        )

        with self._lock:
            original = self._payments_by_key.get(key)

            if original is not None:
                if original.command != command:
                    raise ProviderError(
                        ProviderErrorKind.CONFLICT
                    )
                return original.result

            scenario = self._payment_scenario

            if scenario is SandboxScenario.UNAVAILABLE_BEFORE_ACCEPT:
                raise ProviderError(
                    ProviderErrorKind.UNAVAILABLE
                )

            state = {
                SandboxScenario.SUCCESS: PaymentState.SUCCEEDED,
                SandboxScenario.PENDING: PaymentState.PROCESSING,
                SandboxScenario.DECLINED: PaymentState.FAILED,
                SandboxScenario.TIMEOUT_AFTER_ACCEPT: PaymentState.PROCESSING,
            }[scenario]

            result = PaymentResult(
                provider_payment_id=_simulation_id(
                    "pay",
                    command.organization_id,
                    command.idempotency_key,
                ),
                state=state,
            )

            record = _StoredPayment(
                command=command,
                result=result,
            )

            self._payments_by_key[key] = record

            self._payments_by_id[
                (
                    command.organization_id,
                    result.provider_payment_id,
                )
            ] = record

            if scenario is SandboxScenario.DECLINED:
                raise ProviderError(
                    ProviderErrorKind.DECLINED
                )

            if scenario is SandboxScenario.TIMEOUT_AFTER_ACCEPT:
                raise ProviderError(
                    ProviderErrorKind.TIMEOUT
                )

            return result

    def fetch_payment(
        self,
        command: FetchPaymentCommand,
    ) -> PaymentResult:
        if not isinstance(command, FetchPaymentCommand):
            raise TypeError("Expected FetchPaymentCommand")

        with self._lock:
            record = self._payments_by_id.get(
                (
                    command.organization_id,
                    command.provider_payment_id,
                )
            )

            if record is None:
                raise ProviderError(
                    ProviderErrorKind.INVALID_REQUEST
                )

            return record.result

    def reconcile_payment(
        self,
        command: CreatePaymentCommand,
    ) -> PaymentResult | None:
        """Inspect the simulated original request by tenant/key.

        None means no local simulated record was found.
        It never authorizes a real payment retry.
        """
        if not isinstance(command, CreatePaymentCommand):
            raise TypeError("Expected CreatePaymentCommand")

        key = (
            command.organization_id,
            command.idempotency_key,
        )

        with self._lock:
            record = self._payments_by_key.get(key)

            if record is None:
                return None

            if record.command != command:
                raise ProviderError(
                    ProviderErrorKind.CONFLICT
                )

            return record.result

    def create_refund(
        self,
        command: CreateRefundCommand,
    ) -> RefundResult:
        if not isinstance(command, CreateRefundCommand):
            raise TypeError("Expected CreateRefundCommand")

        key = (
            command.organization_id,
            command.idempotency_key,
        )

        with self._lock:
            original = self._refunds_by_key.get(key)

            if original is not None:
                if original.command != command:
                    raise ProviderError(
                        ProviderErrorKind.CONFLICT
                    )
                return original.result

            payment = self._payments_by_id.get(
                (
                    command.organization_id,
                    command.provider_payment_id,
                )
            )

            if payment is None:
                raise ProviderError(
                    ProviderErrorKind.INVALID_REQUEST
                )

            if payment.result.state is not PaymentState.SUCCEEDED:
                raise ProviderError(
                    ProviderErrorKind.CONFLICT
                )

            if (
                payment.command.amount.currency
                != command.amount.currency
            ):
                raise ProviderError(
                    ProviderErrorKind.INVALID_REQUEST
                )

            reserved = sum(
                item.command.amount.minor_units
                for item in self._refunds_by_key.values()
                if (
                    item.command.organization_id
                    == command.organization_id
                    and item.command.provider_payment_id
                    == command.provider_payment_id
                    and item.result.state in (
                        RefundState.PENDING,
                        RefundState.SUCCEEDED,
                    )
                )
            )

            remaining = (
                payment.command.amount.minor_units - reserved
            )

            if command.amount.minor_units > remaining:
                raise ProviderError(
                    ProviderErrorKind.CONFLICT
                )

            scenario = self._refund_scenario

            if scenario is SandboxScenario.UNAVAILABLE_BEFORE_ACCEPT:
                raise ProviderError(
                    ProviderErrorKind.UNAVAILABLE
                )

            if scenario is SandboxScenario.DECLINED:
                raise ProviderError(
                    ProviderErrorKind.DECLINED
                )

            state = (
                RefundState.SUCCEEDED
                if scenario is SandboxScenario.SUCCESS
                else RefundState.PENDING
            )

            result = RefundResult(
                provider_refund_id=_simulation_id(
                    "ref",
                    command.organization_id,
                    command.idempotency_key,
                ),
                state=state,
            )

            self._refunds_by_key[key] = _StoredRefund(
                command=command,
                result=result,
            )

            if scenario is SandboxScenario.TIMEOUT_AFTER_ACCEPT:
                raise ProviderError(
                    ProviderErrorKind.TIMEOUT
                )

            return result

    def reconcile_refund(
        self,
        command: CreateRefundCommand,
    ) -> RefundResult | None:
        """Inspect an original synthetic refund by tenant/key."""
        if not isinstance(command, CreateRefundCommand):
            raise TypeError("Expected CreateRefundCommand")

        key = (
            command.organization_id,
            command.idempotency_key,
        )

        with self._lock:
            record = self._refunds_by_key.get(key)

            if record is None:
                return None

            if record.command != command:
                raise ProviderError(
                    ProviderErrorKind.CONFLICT
                )

            return record.result
