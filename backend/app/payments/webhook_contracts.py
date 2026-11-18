"""Verified event contracts for the PayFlow sandbox simulator.

This verifier is ONLY for our synthetic sandbox provider.
Real gateways require their own documented signature formats.

No HTTP endpoints, provider calls, credentials storage, database
writes, deduplication, refunds, or payment-state transitions.

The expected tenant identity, signing key, and current time
must come from trusted server-side sources.

Signature verification and timestamp checks alone do not
prevent replay inside the acceptance window. Durable event
deduplication must be added before webhook processing.
"""

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from enum import Enum
from uuid import UUID


MAX_EVENT_BYTES = 16 * 1024
MAX_EVENT_AGE_SECONDS = 300
MAX_FUTURE_SKEW_SECONDS = 30

SANDBOX_PROVIDER_CODE = "sandbox_sim"

_EVENT_ID_PATTERN = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z",
    flags=re.ASCII,
)

_OBJECT_ID_PATTERN = re.compile(
    r"sim_(?:pay|ref)_[0-9a-f]{32}\Z",
    flags=re.ASCII,
)

_TIMESTAMP_PATTERN = re.compile(
    r"[1-9][0-9]{9,11}\Z",
    flags=re.ASCII,
)

_SIGNATURE_PATTERN = re.compile(
    r"v1=[0-9a-f]{64}\Z",
    flags=re.ASCII,
)

_REQUIRED_FIELDS = frozenset({
    "event_id",
    "organization_id",
    "provider_code",
    "event_type",
    "provider_object_id",
    "occurred_at",
})


class WebhookVerificationError(ValueError):
    """Sanitized verification failure."""


class SandboxEventType(str, Enum):
    PAYMENT_PROCESSING = "payment.processing"
    PAYMENT_SUCCEEDED = "payment.succeeded"
    PAYMENT_FAILED = "payment.failed"
    REFUND_PENDING = "refund.pending"
    REFUND_SUCCEEDED = "refund.succeeded"
    REFUND_FAILED = "refund.failed"


@dataclass(frozen=True, slots=True)
class VerifiedSandboxEvent:
    organization_id: UUID
    provider_code: str
    event_id: str
    event_type: SandboxEventType
    provider_object_id: str
    occurred_at: int
    signed_at: int
    payload_sha256: str

    @property
    def deduplication_identity(self) -> tuple[UUID, str, str]:
        """Identity to enforce durably in a later DB phase."""
        return (
            self.organization_id,
            self.provider_code,
            self.event_id,
        )


def _reject_duplicates(pairs):
    result = {}

    for key, value in pairs:
        if key in result:
            raise WebhookVerificationError(
                "Duplicate event JSON field"
            )

        result[key] = value

    return result


def _reject_nonfinite(value):
    raise WebhookVerificationError("Invalid event JSON")


def verify_sandbox_webhook(
    *,
    expected_organization_id: UUID,
    signing_secret: bytes,
    timestamp: str,
    signature: str,
    raw_body: bytes,
    now: int,
) -> VerifiedSandboxEvent:
    """Verify an isolated sandbox event without processing it.

    Synthetic signing format:

        HMAC_SHA256(
            secret,
            b"v1." + timestamp + b"." + raw_body
        )

    Signature header is lowercase "v1=<64 hex characters>".

    The organization ID comes from trusted server routing and
    must match the authenticated event envelope.

    Return is verification evidence, not permission to mutate
    financial state or to accept event delivery as unique.
    """

    if (
        not isinstance(expected_organization_id, UUID)
        or expected_organization_id.int == 0
    ):
        raise ValueError("Valid expected organization required")

    if type(signing_secret) is not bytes:
        raise TypeError("Signing secret must be bytes")

    if len(signing_secret) < 32:
        raise ValueError("Signing secret is too short")

    if type(now) is not int or now <= 0:
        raise ValueError("Invalid trusted current timestamp")

    if (
        type(raw_body) is not bytes
        or not 0 < len(raw_body) <= MAX_EVENT_BYTES
    ):
        raise WebhookVerificationError(
            "Invalid webhook body size"
        )

    if (
        type(timestamp) is not str
        or _TIMESTAMP_PATTERN.fullmatch(timestamp) is None
    ):
        raise WebhookVerificationError(
            "Invalid webhook timestamp"
        )

    if (
        type(signature) is not str
        or _SIGNATURE_PATTERN.fullmatch(signature) is None
    ):
        raise WebhookVerificationError(
            "Invalid webhook signature"
        )

    issued_at = int(timestamp)

    if not (
        now - MAX_EVENT_AGE_SECONDS
        <= issued_at
        <= now + MAX_FUTURE_SKEW_SECONDS
    ):
        raise WebhookVerificationError(
            "Webhook timestamp outside acceptance window"
        )

    signed_message = (
        b"v1."
        + timestamp.encode("ascii")
        + b"."
        + raw_body
    )

    expected_signature = hmac.new(
        signing_secret,
        signed_message,
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(
        expected_signature,
        signature[3:],
    ):
        raise WebhookVerificationError(
            "Webhook signature verification failed"
        )

    # Decode only after verifying the authentic raw bytes.
    try:
        payload = json.loads(
            raw_body.decode("utf-8"),
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise WebhookVerificationError(
            "Invalid authenticated event JSON"
        ) from None

    if (
        type(payload) is not dict
        or frozenset(payload) != _REQUIRED_FIELDS
    ):
        raise WebhookVerificationError(
            "Invalid authenticated event schema"
        )

    if (
        type(payload["organization_id"]) is not str
        or payload["organization_id"]
        != str(expected_organization_id)
    ):
        raise WebhookVerificationError(
            "Webhook organization mismatch"
        )

    if payload["provider_code"] != SANDBOX_PROVIDER_CODE:
        raise WebhookVerificationError(
            "Unsupported sandbox provider"
        )

    event_id = payload["event_id"]

    if (
        type(event_id) is not str
        or _EVENT_ID_PATTERN.fullmatch(event_id) is None
    ):
        raise WebhookVerificationError(
            "Invalid event identifier"
        )

    try:
        event_type = SandboxEventType(payload["event_type"])
    except (ValueError, TypeError):
        raise WebhookVerificationError(
            "Unsupported event type"
        ) from None

    provider_object_id = payload["provider_object_id"]

    if (
        type(provider_object_id) is not str
        or _OBJECT_ID_PATTERN.fullmatch(
            provider_object_id
        ) is None
    ):
        raise WebhookVerificationError(
            "Invalid provider object identifier"
        )

    prefix = (
        "sim_pay_"
        if event_type.value.startswith("payment.")
        else "sim_ref_"
    )

    if not provider_object_id.startswith(prefix):
        raise WebhookVerificationError(
            "Event object type mismatch"
        )

    occurred_at = payload["occurred_at"]

    if (
        type(occurred_at) is not int
        or occurred_at <= 0
        or occurred_at > issued_at + MAX_FUTURE_SKEW_SECONDS
    ):
        raise WebhookVerificationError(
            "Invalid event occurrence time"
        )

    return VerifiedSandboxEvent(
        organization_id=expected_organization_id,
        provider_code=SANDBOX_PROVIDER_CODE,
        event_id=event_id,
        event_type=event_type,
        provider_object_id=provider_object_id,
        occurred_at=occurred_at,
        signed_at=issued_at,
        payload_sha256=hashlib.sha256(
            raw_body
        ).hexdigest(),
    )
