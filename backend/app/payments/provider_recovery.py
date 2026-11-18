"""Provider-neutral failure recovery decisions.

Pure policy only. No gateway calls, database writes, retries,
payment-state updates, or network operations.

A retryable transport error does not imply that retrying a
money-moving operation is safe. Ambiguous outcomes require
reconciliation before another mutation is considered.
"""

from dataclasses import dataclass
from enum import Enum

from app.payments.contracts import (
    ProviderError,
    ProviderErrorKind,
)


class ProviderOperation(str, Enum):
    CREATE_PAYMENT = "create_payment"
    FETCH_PAYMENT = "fetch_payment"
    CREATE_REFUND = "create_refund"


class RecoveryAction(str, Enum):
    REJECT = "reject"
    STOP_AND_ALERT = "stop_and_alert"
    RECONCILE = "reconcile"
    RETRY_READ_WITH_BACKOFF = "retry_read_with_backoff"


@dataclass(frozen=True, slots=True)
class RecoveryDecision:
    operation: ProviderOperation
    error_kind: ProviderErrorKind
    action: RecoveryAction


_TRANSIENT_ERRORS = frozenset({
    ProviderErrorKind.TIMEOUT,
    ProviderErrorKind.UNAVAILABLE,
    ProviderErrorKind.RATE_LIMITED,
})

_DEFINITE_REJECTIONS = frozenset({
    ProviderErrorKind.INVALID_REQUEST,
    ProviderErrorKind.DECLINED,
})


def choose_provider_recovery(
    operation: ProviderOperation,
    error: ProviderError | ProviderErrorKind,
) -> RecoveryDecision:
    """Choose a conservative action for a provider error.

    RECONCILE does not authorize another payment request.

    RETRY_READ_WITH_BACKOFF requires a future orchestrator
    to enforce strict retry limits, timeouts, and rate limits.

    This function never changes payment or refund state.
    """

    if not isinstance(operation, ProviderOperation):
        raise TypeError("Invalid provider operation")

    if isinstance(error, ProviderError):
        kind = error.kind
    elif isinstance(error, ProviderErrorKind):
        kind = error
    else:
        raise TypeError("Expected sanitized provider error")

    if operation is ProviderOperation.FETCH_PAYMENT:
        if kind in _TRANSIENT_ERRORS:
            action = RecoveryAction.RETRY_READ_WITH_BACKOFF
        elif kind in _DEFINITE_REJECTIONS:
            action = RecoveryAction.REJECT
        else:
            action = RecoveryAction.STOP_AND_ALERT

    else:
        # Creating payments and refunds may move money.
        # Never blindly retry an ambiguous provider response.
        if kind in _DEFINITE_REJECTIONS:
            action = RecoveryAction.REJECT
        elif kind is ProviderErrorKind.AUTHENTICATION:
            action = RecoveryAction.STOP_AND_ALERT
        else:
            action = RecoveryAction.RECONCILE

    return RecoveryDecision(
        operation=operation,
        error_kind=kind,
        action=action,
    )
