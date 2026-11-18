"""Database-independent payment attempt policy tests."""

import pytest

from app.payments.attempt_policy import (
    MAX_ATTEMPT_NUMBER,
    AttemptCreationBlocked,
    AttemptSnapshot,
    plan_next_attempt_number,
)
from app.payments.contracts import PaymentState


def snapshot(number, state):
    return AttemptSnapshot(number=number, state=state)


def test_first_attempt_number_is_one():
    result = plan_next_attempt_number(
        order_status="open",
        attempts=[],
    )

    assert result == 1


def test_retry_after_failed_attempt():
    result = plan_next_attempt_number(
        order_status="open",
        attempts=[
            snapshot(1, PaymentState.FAILED),
        ],
    )

    assert result == 2


def test_retry_after_cancelled_attempt():
    result = plan_next_attempt_number(
        order_status="open",
        attempts=[
            snapshot(1, PaymentState.CANCELLED),
        ],
    )

    assert result == 2


def test_multiple_terminal_attempts_increment_number():
    result = plan_next_attempt_number(
        order_status="open",
        attempts=[
            snapshot(1, PaymentState.FAILED),
            snapshot(2, PaymentState.CANCELLED),
            snapshot(3, PaymentState.FAILED),
        ],
    )

    assert result == 4


@pytest.mark.parametrize(
    "state",
    [
        PaymentState.CREATED,
        PaymentState.REQUIRES_ACTION,
        PaymentState.PROCESSING,
        PaymentState.AUTHORIZED,
        PaymentState.SUCCEEDED,
    ],
)
def test_active_or_successful_attempt_blocks_retry(state):
    with pytest.raises(AttemptCreationBlocked):
        plan_next_attempt_number(
            order_status="open",
            attempts=[snapshot(1, state)],
        )


@pytest.mark.parametrize(
    "order_status",
    ["paid", "cancelled", "unknown", ""],
)
def test_non_open_order_blocks_attempt_creation(order_status):
    with pytest.raises(AttemptCreationBlocked):
        plan_next_attempt_number(
            order_status=order_status,
            attempts=[],
        )


def test_duplicate_attempt_numbers_are_rejected():
    with pytest.raises(AttemptCreationBlocked):
        plan_next_attempt_number(
            order_status="open",
            attempts=[
                snapshot(1, PaymentState.FAILED),
                snapshot(1, PaymentState.CANCELLED),
            ],
        )


@pytest.mark.parametrize(
    "number",
    [0, -1, True, MAX_ATTEMPT_NUMBER + 1],
)
def test_invalid_attempt_numbers_are_rejected(number):
    with pytest.raises(ValueError):
        snapshot(number, PaymentState.FAILED)


def test_untyped_attempt_state_is_rejected():
    with pytest.raises(TypeError):
        snapshot(1, "failed")


def test_invalid_snapshot_input_is_rejected():
    with pytest.raises(TypeError):
        plan_next_attempt_number(
            order_status="open",
            attempts=[object()],
        )


def test_attempt_number_overflow_is_blocked():
    with pytest.raises(AttemptCreationBlocked):
        plan_next_attempt_number(
            order_status="open",
            attempts=[
                snapshot(
                    MAX_ATTEMPT_NUMBER,
                    PaymentState.FAILED,
                ),
            ],
        )


def test_pending_attempt_blocks_retry_even_after_failure():
    with pytest.raises(AttemptCreationBlocked):
        plan_next_attempt_number(
            order_status="open",
            attempts=[
                snapshot(1, PaymentState.FAILED),
                snapshot(2, PaymentState.PROCESSING),
            ],
        )


def test_policy_does_not_mutate_attempt_snapshots():
    attempts = [
        snapshot(1, PaymentState.FAILED),
    ]

    assert plan_next_attempt_number(
        order_status="open",
        attempts=attempts,
    ) == 2

    assert attempts == [
        snapshot(1, PaymentState.FAILED),
    ]
