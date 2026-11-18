"""Isolated security tests for synthetic sandbox webhooks."""

import hashlib
import hmac
import json
from dataclasses import FrozenInstanceError
from uuid import UUID

import pytest

from app.payments.webhook_contracts import (
    MAX_EVENT_BYTES,
    SandboxEventType,
    WebhookVerificationError,
    verify_sandbox_webhook,
)


ORG_A = UUID("11111111-1111-4111-8111-111111111111")
ORG_B = UUID("22222222-2222-4222-8222-222222222222")

SECRET = b"synthetic-test-key-" + b"x" * 32

NOW = 2_000_000_000

PAYMENT_ID = "sim_pay_" + "a" * 32
REFUND_ID = "sim_ref_" + "b" * 32


def event_payload(**changes):
    payload = {
        "event_id": "evt_test_001",
        "organization_id": str(ORG_A),
        "provider_code": "sandbox_sim",
        "event_type": "payment.succeeded",
        "provider_object_id": PAYMENT_ID,
        "occurred_at": NOW - 10,
    }
    payload.update(changes)
    return payload


def encode(payload):
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sign(body, timestamp=str(NOW), secret=SECRET):
    message = (
        b"v1."
        + timestamp.encode("ascii")
        + b"."
        + body
    )

    return "v1=" + hmac.new(
        secret,
        message,
        hashlib.sha256,
    ).hexdigest()


def verify(
    payload=None,
    *,
    raw_body=None,
    organization_id=ORG_A,
    secret=SECRET,
    timestamp=str(NOW),
    signature=None,
    now=NOW,
):
    body = (
        encode(event_payload() if payload is None else payload)
        if raw_body is None
        else raw_body
    )

    return verify_sandbox_webhook(
        expected_organization_id=organization_id,
        signing_secret=secret,
        timestamp=timestamp,
        signature=(
            sign(body, timestamp, secret)
            if signature is None
            else signature
        ),
        raw_body=body,
        now=now,
    )


def test_valid_payment_webhook_verifies():
    event = verify()

    assert event.organization_id == ORG_A
    assert event.provider_code == "sandbox_sim"
    assert event.event_id == "evt_test_001"
    assert event.event_type is SandboxEventType.PAYMENT_SUCCEEDED
    assert event.provider_object_id == PAYMENT_ID
    assert event.occurred_at == NOW - 10
    assert event.signed_at == NOW

    assert len(event.payload_sha256) == 64

    assert event.deduplication_identity == (
        ORG_A,
        "sandbox_sim",
        "evt_test_001",
    )


@pytest.mark.parametrize(
    "event_type,object_id",
    [
        ("payment.processing", PAYMENT_ID),
        ("payment.succeeded", PAYMENT_ID),
        ("payment.failed", PAYMENT_ID),
        ("refund.pending", REFUND_ID),
        ("refund.succeeded", REFUND_ID),
        ("refund.failed", REFUND_ID),
    ],
)
def test_supported_event_types(event_type, object_id):
    event = verify(
        event_payload(
            event_type=event_type,
            provider_object_id=object_id,
        )
    )

    assert event.event_type.value == event_type


def test_identical_payload_has_stable_fingerprint():
    first = verify()
    second = verify()

    assert first == second


def test_different_content_has_different_fingerprint():
    first = verify()
    second = verify(event_payload(event_id="evt_test_002"))

    assert first.payload_sha256 != second.payload_sha256


def test_tampered_body_fails_signature():
    original = encode(event_payload())
    signature = sign(original)

    changed = encode(
        event_payload(event_type="payment.failed")
    )

    with pytest.raises(WebhookVerificationError):
        verify(raw_body=changed, signature=signature)


def test_wrong_signing_key_rejected():
    original = encode(event_payload())

    with pytest.raises(WebhookVerificationError):
        verify(
            signature=sign(original, secret=b"z" * 40)
        )


@pytest.mark.parametrize(
    "signature",
    [
        "",
        "invalid",
        "v1=wrong",
        "v1=" + "A" * 64,
        "v2=" + "a" * 64,
        None,
    ],
)
def test_invalid_signature_formats(signature):
    if signature is None:
        with pytest.raises(WebhookVerificationError):
            verify_sandbox_webhook(
                expected_organization_id=ORG_A,
                signing_secret=SECRET,
                timestamp=str(NOW),
                signature=None,
                raw_body=encode(event_payload()),
                now=NOW,
            )
    else:
        with pytest.raises(WebhookVerificationError):
            verify(signature=signature)


@pytest.mark.parametrize(
    "age",
    [301, 500, 10000],
)
def test_old_delivery_is_rejected(age):
    timestamp = str(NOW - age)

    with pytest.raises(WebhookVerificationError):
        verify(timestamp=timestamp)


def test_old_delivery_at_limit_is_accepted():
    signed_at = NOW - 300

    assert verify(
        event_payload(occurred_at=signed_at),
        timestamp=str(signed_at),
    ).event_id == "evt_test_001"


def test_future_delivery_at_limit_is_accepted():
    assert verify(
        timestamp=str(NOW + 30)
    ).event_id == "evt_test_001"


def test_delivery_too_far_in_future_rejected():
    with pytest.raises(WebhookVerificationError):
        verify(timestamp=str(NOW + 31))


@pytest.mark.parametrize(
    "timestamp",
    ["", "2000000000.0", "-1", "abc", "02000000000"],
)
def test_invalid_timestamp_format(timestamp):
    with pytest.raises(WebhookVerificationError):
        verify(timestamp=timestamp)


def test_timestamp_tampering_is_detected():
    body = encode(event_payload())
    original_signature = sign(body, str(NOW))

    with pytest.raises(WebhookVerificationError):
        verify(
            raw_body=body,
            timestamp=str(NOW + 1),
            signature=original_signature,
        )


def test_cross_tenant_event_rejected():
    with pytest.raises(WebhookVerificationError):
        verify(organization_id=ORG_B)


def test_signed_cross_tenant_payload_rejected():
    with pytest.raises(WebhookVerificationError):
        verify(
            event_payload(organization_id=str(ORG_B))
        )


@pytest.mark.parametrize(
    "provider",
    ["razorpay", "sandbox", "", None, 100],
)
def test_unknown_provider_rejected(provider):
    with pytest.raises(WebhookVerificationError):
        verify(event_payload(provider_code=provider))


@pytest.mark.parametrize(
    "event_type",
    ["payment.unknown", "", None, 2],
)
def test_unsupported_event_types_rejected(event_type):
    with pytest.raises(WebhookVerificationError):
        verify(event_payload(event_type=event_type))


def test_payment_event_cannot_reference_refund():
    with pytest.raises(WebhookVerificationError):
        verify(
            event_payload(provider_object_id=REFUND_ID)
        )


def test_refund_event_cannot_reference_payment():
    with pytest.raises(WebhookVerificationError):
        verify(
            event_payload(
                event_type="refund.succeeded",
                provider_object_id=PAYMENT_ID,
            )
        )


@pytest.mark.parametrize(
    "event_id",
    ["", "../invalid", "bad key", None, 99, "x" * 129],
)
def test_invalid_event_id_rejected(event_id):
    with pytest.raises(WebhookVerificationError):
        verify(event_payload(event_id=event_id))


@pytest.mark.parametrize(
    "occurred_at",
    [None, "2000000000", True, 0, -1, NOW + 31],
)
def test_invalid_occurrence_timestamp_rejected(
    occurred_at,
):
    with pytest.raises(WebhookVerificationError):
        verify(event_payload(occurred_at=occurred_at))


def test_duplicate_json_fields_rejected():
    body = (
        b'{"event_id":"a","event_id":"b",'
        b'"organization_id":"' + str(ORG_A).encode() + b'"}'
    )

    with pytest.raises(WebhookVerificationError):
        verify(raw_body=body)


@pytest.mark.parametrize(
    "raw",
    [
        b"not json",
        b"[]",
        b"null",
        b'{"event_id":NaN}',
        b"\xff\xfe",
        b"{}",
    ],
)
def test_invalid_authenticated_json_rejected(raw):
    with pytest.raises(WebhookVerificationError):
        verify(raw_body=raw)


def test_unexpected_extra_field_rejected():
    payload = event_payload()
    payload["sensitive_extra"] = "must-reject"

    with pytest.raises(WebhookVerificationError):
        verify(payload)


def test_missing_required_field_rejected():
    payload = event_payload()
    del payload["event_id"]

    with pytest.raises(WebhookVerificationError):
        verify(payload)


def test_oversized_event_rejected():
    with pytest.raises(WebhookVerificationError):
        verify(raw_body=b"x" * (MAX_EVENT_BYTES + 1))


def test_empty_event_rejected():
    with pytest.raises(WebhookVerificationError):
        verify(raw_body=b"")


@pytest.mark.parametrize(
    "secret",
    [b"short", None, "a" * 40, bytearray(40)],
)
def test_invalid_signing_key_rejected(secret):
    with pytest.raises((TypeError, ValueError)):
        verify_sandbox_webhook(
            expected_organization_id=ORG_A,
            signing_secret=secret,
            timestamp=str(NOW),
            signature="v1=" + "a" * 64,
            raw_body=encode(event_payload()),
            now=NOW,
        )


@pytest.mark.parametrize(
    "organization",
    [None, "tenant", UUID(int=0)],
)
def test_invalid_expected_organization_rejected(organization):
    with pytest.raises(ValueError):
        verify_sandbox_webhook(
            expected_organization_id=organization,
            signing_secret=SECRET,
            timestamp=str(NOW),
            signature="v1=" + "a" * 64,
            raw_body=encode(event_payload()),
            now=NOW,
        )


@pytest.mark.parametrize(
    "now",
    [None, "2000000000", True, 0, -1],
)
def test_invalid_trusted_clock_rejected(now):
    with pytest.raises(ValueError):
        verify_sandbox_webhook(
            expected_organization_id=ORG_A,
            signing_secret=SECRET,
            timestamp=str(NOW),
            signature="v1=" + "a" * 64,
            raw_body=encode(event_payload()),
            now=now,
        )


def test_verified_event_is_immutable():
    result = verify()

    with pytest.raises(FrozenInstanceError):
        result.event_id = "changed"


def test_verification_never_changes_payment_state():
    result = verify()

    assert not hasattr(result, "payment_state")
    assert not hasattr(result, "settlement_status")
