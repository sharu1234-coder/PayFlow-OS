"""Immutable provider-neutral payment command and result types.

These contracts do not process payments, persist records, or
establish authorization. Those controls belong to orchestration
services implemented in later phases.
"""

import re
from dataclasses import dataclass
from enum import Enum
from uuid import UUID


MAX_MINOR_UNITS = 2**63 - 1

_REFERENCE_PATTERN = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z"
)

_IDEMPOTENCY_PATTERN = re.compile(
    r"[A-Za-z0-9_-]{10,128}\Z"
)


def _validate_organization(value: UUID) -> None:
    if not isinstance(value, UUID) or value.int == 0:
        raise ValueError("Valid organization UUID required")


def _validate_reference(value: str, label: str) -> None:
    if (
        not isinstance(value, str)
        or _REFERENCE_PATTERN.fullmatch(value) is None
    ):
        raise ValueError(f"Invalid {label}")


def _validate_idempotency_key(value: str) -> None:
    if (
        not isinstance(value, str)
        or _IDEMPOTENCY_PATTERN.fullmatch(value) is None
    ):
        raise ValueError("Invalid idempotency key")


@dataclass(frozen=True, slots=True)
class Money:
    minor_units: int
    currency: str

    def __post_init__(self) -> None:
        if (
            type(self.minor_units) is not int
            or not 1 <= self.minor_units <= MAX_MINOR_UNITS
        ):
            raise ValueError(
                "Amount must be a positive signed-64-bit integer"
            )

        if (
            not isinstance(self.currency, str)
            or re.fullmatch(r"[A-Z]{3}", self.currency) is None
        ):
            raise ValueError(
                "Currency must use a three-letter uppercase code"
            )


class PaymentState(str, Enum):
    CREATED = "created"
    REQUIRES_ACTION = "requires_action"
    PROCESSING = "processing"
    AUTHORIZED = "authorized"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class RefundState(str, Enum):
    PENDING = "pending"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class CreatePaymentCommand:
    organization_id: UUID
    order_reference: str
    amount: Money
    idempotency_key: str

    def __post_init__(self) -> None:
        _validate_organization(self.organization_id)
        _validate_reference(self.order_reference, "order reference")
        _validate_idempotency_key(self.idempotency_key)

        if not isinstance(self.amount, Money):
            raise TypeError("Payment amount must be Money")


@dataclass(frozen=True, slots=True)
class FetchPaymentCommand:
    organization_id: UUID
    provider_payment_id: str

    def __post_init__(self) -> None:
        _validate_organization(self.organization_id)
        _validate_reference(
            self.provider_payment_id,
            "provider payment ID",
        )


@dataclass(frozen=True, slots=True)
class CreateRefundCommand:
    organization_id: UUID
    provider_payment_id: str
    amount: Money
    idempotency_key: str

    def __post_init__(self) -> None:
        _validate_organization(self.organization_id)
        _validate_reference(
            self.provider_payment_id,
            "provider payment ID",
        )
        _validate_idempotency_key(self.idempotency_key)

        if not isinstance(self.amount, Money):
            raise TypeError("Refund amount must be Money")


@dataclass(frozen=True, slots=True)
class PaymentResult:
    provider_payment_id: str
    state: PaymentState

    def __post_init__(self) -> None:
        _validate_reference(
            self.provider_payment_id,
            "provider payment ID",
        )

        if not isinstance(self.state, PaymentState):
            raise TypeError("Invalid normalized payment state")


@dataclass(frozen=True, slots=True)
class RefundResult:
    provider_refund_id: str
    state: RefundState

    def __post_init__(self) -> None:
        _validate_reference(
            self.provider_refund_id,
            "provider refund ID",
        )

        if not isinstance(self.state, RefundState):
            raise TypeError("Invalid normalized refund state")


class ProviderErrorKind(str, Enum):
    INVALID_REQUEST = "invalid_request"
    AUTHENTICATION = "authentication"
    DECLINED = "declined"
    CONFLICT = "conflict"
    RATE_LIMITED = "rate_limited"
    TIMEOUT = "timeout"
    UNAVAILABLE = "unavailable"
    INVALID_RESPONSE = "invalid_response"


class ProviderError(Exception):
    """Sanitized provider error; never stores raw gateway responses."""

    def __init__(self, kind: ProviderErrorKind) -> None:
        if not isinstance(kind, ProviderErrorKind):
            raise TypeError("Invalid provider error category")

        self.kind = kind
        super().__init__(
            f"Payment provider operation failed: {kind.value}"
        )

    @property
    def retryable(self) -> bool:
        return self.kind in {
            ProviderErrorKind.RATE_LIMITED,
            ProviderErrorKind.TIMEOUT,
            ProviderErrorKind.UNAVAILABLE,
        }
