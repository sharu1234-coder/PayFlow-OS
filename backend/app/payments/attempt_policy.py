"""Pure policy for planning a payment attempt number.

No database access, gateway operations, payment-state mutation,
or transaction commits occur here.

A persistence service must separately enforce tenant authorization,
order row locking, and uniqueness inside one transaction.
"""

from dataclasses import dataclass
from typing import Iterable

from app.payments.contracts import PaymentState


MAX_ATTEMPT_NUMBER = 2_147_483_647

RETRYABLE_TERMINAL_STATES = frozenset({
    PaymentState.FAILED,
    PaymentState.CANCELLED,
})


class AttemptCreationBlocked(Exception):
    """Creating another attempt would violate lifecycle policy."""


@dataclass(frozen=True, slots=True)
class AttemptSnapshot:
    number: int
    state: PaymentState

    def __post_init__(self) -> None:
        if (
            type(self.number) is not int
            or not 1 <= self.number <= MAX_ATTEMPT_NUMBER
        ):
            raise ValueError("Invalid payment attempt number")

        if not isinstance(self.state, PaymentState):
            raise TypeError("Invalid payment attempt state")


def plan_next_attempt_number(
    *,
    order_status: str,
    attempts: Iterable[AttemptSnapshot],
) -> int:
    """Plan a retry without modifying any payment records.

    Only an open order with no active or successful attempt
    can receive another attempt.

    The caller must not treat this pure calculation as a
    concurrency guarantee.
    """

    if order_status != "open":
        raise AttemptCreationBlocked(
            "Payment order must be open"
        )

    highest_number = 0
    seen_numbers = set()

    for attempt in attempts:
        if not isinstance(attempt, AttemptSnapshot):
            raise TypeError("Expected AttemptSnapshot")

        if attempt.number in seen_numbers:
            raise AttemptCreationBlocked(
                "Duplicate payment attempt number"
            )

        seen_numbers.add(attempt.number)

        if attempt.state not in RETRYABLE_TERMINAL_STATES:
            raise AttemptCreationBlocked(
                "Another attempt is active or successful"
            )

        highest_number = max(
            highest_number,
            attempt.number,
        )

    if highest_number >= MAX_ATTEMPT_NUMBER:
        raise AttemptCreationBlocked(
            "Payment attempt numbering exhausted"
        )

    return highest_number + 1
