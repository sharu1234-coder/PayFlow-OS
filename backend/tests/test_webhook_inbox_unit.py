"""Isolated fail-closed tests for the sandbox inbox boundary."""

import hashlib
import hmac
import json
from dataclasses import FrozenInstanceError
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest

import app.services.webhook_inbox as inbox

from app.payments.webhook_contracts import (
    WebhookVerificationError,
)


ORG = UUID("11111111-1111-4111-8111-111111111111")
OTHER = UUID("22222222-2222-4222-8222-222222222222")

SECRET = b"synthetic-inbox-unit-key-" + b"x" * 32
NOW = 2_000_000_000


class NoDatabaseAccess:
    """Any database call is a test failure."""

    def execute(self, *args, **kwargs):
        raise AssertionError("Unverified event accessed database")

    def scalar(self, *args, **kwargs):
        raise AssertionError("Unverified event accessed database")


def delivery(organization_id=ORG):
    payload = {
        "event_id": "evt_inbox_test_001",
        "organization_id": str(organization_id),
        "provider_code": "sandbox_sim",
        "event_type": "payment.succeeded",
        "provider_object_id": "sim_pay_" + "a" * 32,
        "occurred_at": NOW - 5,
    }

    body = json.dumps(
        payload,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()

    timestamp = str(NOW)

    signed = (
        b"v1."
        + timestamp.encode()
        + b"."
        + body
    )

    signature = "v1=" + hmac.new(
        SECRET, signed, hashlib.sha256
    ).hexdigest()

    return {
        "expected_organization_id": organization_id,
        "signing_secret": SECRET,
        "timestamp": timestamp,
        "signature": signature,
        "raw_body": body,
        "now": NOW,
    }


def allow_development(monkeypatch):
    monkeypatch.setattr(
        inbox,
        "get_settings",
        lambda: SimpleNamespace(
            app_env="development",
            sandbox_payment_attempts_enabled=True,
        ),
    )


@pytest.mark.parametrize(
    "environment,enabled",
    [
        ("development", False),
        ("staging", False),
        ("staging", True),
        ("production", False),
        ("production", True),
    ],
)
def test_disabled_environment_never_accesses_database(
    monkeypatch, environment, enabled
):
    monkeypatch.setattr(
        inbox,
        "get_settings",
        lambda: SimpleNamespace(
            app_env=environment,
            sandbox_payment_attempts_enabled=enabled,
        ),
    )

    with pytest.raises(inbox.WebhookInboxDisabled):
        inbox.receive_sandbox_webhook(
            NoDatabaseAccess(),
            **delivery(),
        )


def test_tampered_signature_never_reaches_database(monkeypatch):
    allow_development(monkeypatch)

    request = delivery()
    request["signature"] = "v1=" + "0" * 64

    with pytest.raises(WebhookVerificationError):
        inbox.receive_sandbox_webhook(
            NoDatabaseAccess(),
            **request,
        )


def test_cross_tenant_event_never_reaches_database(monkeypatch):
    allow_development(monkeypatch)

    request = delivery()
    request["expected_organization_id"] = OTHER

    with pytest.raises(WebhookVerificationError):
        inbox.receive_sandbox_webhook(
            NoDatabaseAccess(),
            **request,
        )


def test_stale_timestamp_never_reaches_database(monkeypatch):
    allow_development(monkeypatch)

    request = delivery()
    request["now"] = NOW + 301

    with pytest.raises(WebhookVerificationError):
        inbox.receive_sandbox_webhook(
            NoDatabaseAccess(),
            **request,
        )


def test_missing_signature_never_reaches_database(monkeypatch):
    allow_development(monkeypatch)

    request = delivery()
    request["signature"] = None

    with pytest.raises(WebhookVerificationError):
        inbox.receive_sandbox_webhook(
            NoDatabaseAccess(),
            **request,
        )


def test_receipt_is_immutable():
    result = inbox.WebhookInboxResult(
        record_id=uuid4(),
        organization_id=ORG,
        provider_code="sandbox_sim",
        event_id="evt_inbox_test_001",
        status="received",
        replayed=False,
    )

    with pytest.raises(FrozenInstanceError):
        result.replayed = True


def test_service_uses_database_identity_constraint():
    assert (
        inbox.IDENTITY_CONSTRAINT
        == "uq_provider_event_inbox_identity"
    )
