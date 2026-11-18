"""Database-independent provider recovery tests."""

from dataclasses import FrozenInstanceError

import pytest

from app.payments.contracts import (
    ProviderError,
    ProviderErrorKind,
)

from app.payments.provider_recovery import (
    ProviderOperation,
    RecoveryAction,
    choose_provider_recovery,
)


MUTATING_OPERATIONS = (
    ProviderOperation.CREATE_PAYMENT,
    ProviderOperation.CREATE_REFUND,
)


@pytest.mark.parametrize(
    "operation",
    MUTATING_OPERATIONS,
)
@pytest.mark.parametrize(
    "kind,expected",
    [
        (
            ProviderErrorKind.TIMEOUT,
            RecoveryAction.RECONCILE,
        ),
        (
            ProviderErrorKind.UNAVAILABLE,
            RecoveryAction.RECONCILE,
        ),
        (
            ProviderErrorKind.RATE_LIMITED,
            RecoveryAction.RECONCILE,
        ),
        (
            ProviderErrorKind.INVALID_RESPONSE,
            RecoveryAction.RECONCILE,
        ),
        (
            ProviderErrorKind.CONFLICT,
            RecoveryAction.RECONCILE,
        ),
        (
            ProviderErrorKind.AUTHENTICATION,
            RecoveryAction.STOP_AND_ALERT,
        ),
        (
            ProviderErrorKind.INVALID_REQUEST,
            RecoveryAction.REJECT,
        ),
        (
            ProviderErrorKind.DECLINED,
            RecoveryAction.REJECT,
        ),
    ],
)
def test_money_moving_operation_never_blindly_retries(
    operation,
    kind,
    expected,
):
    result = choose_provider_recovery(
        operation,
        ProviderError(kind),
    )

    assert result.action is expected
    assert result.operation is operation
    assert result.error_kind is kind

    assert result.action is not (
        RecoveryAction.RETRY_READ_WITH_BACKOFF
    )


@pytest.mark.parametrize(
    "kind,expected",
    [
        (
            ProviderErrorKind.TIMEOUT,
            RecoveryAction.RETRY_READ_WITH_BACKOFF,
        ),
        (
            ProviderErrorKind.UNAVAILABLE,
            RecoveryAction.RETRY_READ_WITH_BACKOFF,
        ),
        (
            ProviderErrorKind.RATE_LIMITED,
            RecoveryAction.RETRY_READ_WITH_BACKOFF,
        ),
        (
            ProviderErrorKind.INVALID_RESPONSE,
            RecoveryAction.STOP_AND_ALERT,
        ),
        (
            ProviderErrorKind.CONFLICT,
            RecoveryAction.STOP_AND_ALERT,
        ),
        (
            ProviderErrorKind.AUTHENTICATION,
            RecoveryAction.STOP_AND_ALERT,
        ),
        (
            ProviderErrorKind.INVALID_REQUEST,
            RecoveryAction.REJECT,
        ),
        (
            ProviderErrorKind.DECLINED,
            RecoveryAction.REJECT,
        ),
    ],
)
def test_read_only_payment_lookup_recovery(
    kind,
    expected,
):
    result = choose_provider_recovery(
        ProviderOperation.FETCH_PAYMENT,
        kind,
    )

    assert result.action is expected


def test_timeout_is_not_permission_to_retry_payment():
    error = ProviderError(ProviderErrorKind.TIMEOUT)

    assert error.retryable is True

    decision = choose_provider_recovery(
        ProviderOperation.CREATE_PAYMENT,
        error,
    )

    assert decision.action is RecoveryAction.RECONCILE


def test_timeout_is_not_permission_to_retry_refund():
    decision = choose_provider_recovery(
        ProviderOperation.CREATE_REFUND,
        ProviderErrorKind.TIMEOUT,
    )

    assert decision.action is RecoveryAction.RECONCILE


@pytest.mark.parametrize(
    "operation,error",
    [
        (
            "create_payment",
            ProviderErrorKind.TIMEOUT,
        ),
        (
            None,
            ProviderErrorKind.TIMEOUT,
        ),
        (
            ProviderOperation.CREATE_PAYMENT,
            "timeout",
        ),
        (
            ProviderOperation.CREATE_PAYMENT,
            None,
        ),
    ],
)
def test_invalid_inputs_fail_closed(
    operation,
    error,
):
    with pytest.raises(TypeError):
        choose_provider_recovery(
            operation,
            error,
        )


def test_recovery_decision_is_immutable():
    decision = choose_provider_recovery(
        ProviderOperation.CREATE_PAYMENT,
        ProviderErrorKind.TIMEOUT,
    )

    with pytest.raises(FrozenInstanceError):
        decision.action = RecoveryAction.REJECT


def test_policy_does_not_claim_payment_success_or_failure():
    decision = choose_provider_recovery(
        ProviderOperation.CREATE_PAYMENT,
        ProviderErrorKind.INVALID_RESPONSE,
    )

    assert decision.action is RecoveryAction.RECONCILE

    assert not hasattr(
        decision,
        "payment_state",
    )
