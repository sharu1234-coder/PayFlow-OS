"""Pure payment-attempt idempotency request contract.

This module does not use a database, payment gateway or API.

Future persistence semantics:
- An idempotency key is unique per organization for attempt creation.
- Same organization/key/order replays the original attempt.
- Reusing the same organization/key for another order conflicts.
- A new attempt after failure/cancellation requires a new key.
- Authorization must be rechecked before every replay.
- Request fingerprint and attempt mapping must be committed atomically.
- Never treat an attempt replay as permission to invoke a gateway.
"""

import hashlib
import json
import re
import uuid
from dataclasses import dataclass


REQUEST_SCHEMA = "payflow.payment-attempt.create.v1"

KEY_PATTERN = re.compile(
    r"[A-Za-z0-9_-]{10,128}\Z",
    flags=re.ASCII,
)


@dataclass(frozen=True, slots=True)
class CreateAttemptIntent:
    organization_id: uuid.UUID
    order_id: uuid.UUID
    idempotency_key: str

    def __post_init__(self) -> None:
        for label, value in (
            ("organization", self.organization_id),
            ("order", self.order_id),
        ):
            if (
                not isinstance(value, uuid.UUID)
                or value.int == 0
            ):
                raise ValueError(
                    f"Valid {label} UUID required"
                )

        if (
            type(self.idempotency_key) is not str
            or KEY_PATTERN.fullmatch(
                self.idempotency_key
            ) is None
        ):
            raise ValueError(
                "Invalid attempt idempotency key"
            )


def fingerprint_create_attempt_intent(
    intent: CreateAttemptIntent,
) -> str:
    """Compute the stable fingerprint of an attempt request.

    The key is excluded because it identifies the idempotency
    record separately. The actor is excluded because permissions
    must be revalidated on every request.

    The attempt number and amount are server-derived, not
    client-controlled inputs.
    """

    if not isinstance(intent, CreateAttemptIntent):
        raise TypeError(
            "Expected CreateAttemptIntent"
        )

    payload = {
        "schema": REQUEST_SCHEMA,
        "organization_id": str(
            intent.organization_id
        ),
        "order_id": str(
            intent.order_id
        ),
    }

    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")

    return hashlib.sha256(canonical).hexdigest()
