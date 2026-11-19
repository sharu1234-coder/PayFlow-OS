"""Security tests for pure sandbox quarantine review policy."""

from dataclasses import FrozenInstanceError, replace
from uuid import UUID

import pytest

from app.payments.webhook_processing_policy import (
    TriageAction,
    TriageReason,
)
from app.payments.webhook_quarantine_policy import (
    QuarantinePolicyError,
    QuarantineReviewDisposition,
    QuarantineReviewReason,
    propose_quarantine_review,
)
from app.services.webhook_linked_triage import (
    LinkedWebhookTriageInspection,
)
from app.services.webhook_payment_linkage import (
    PaymentLinkKind,
)


ORG = UUID("11111111-1111-4111-8111-111111111111")
RECORD = UUID("22222222-2222-4222-8222-222222222222")
ATTEMPT = UUID("33333333-3333-4333-8333-333333333333")
ORDER = UUID("44444444-4444-4444-8444-444444444444")


def make_inspection(**changes):
    values = {
        "organization_id": ORG,
        "record_id": RECORD,
        "event_id": "evt_quarantine_review_001",
        "action": TriageAction.QUARANTINE,
        "reason": TriageReason.UNKNOWN_OBJECT,
        "linkage_kind": PaymentLinkKind.UNLINKED,
        "local_attempt_id": None,
        "local_order_id": None,
        "persisted": False,
    }

    values.update(changes)

    return LinkedWebhookTriageInspection(**values)


def test_unlinked_payment_requires_manual_quarantine_review():
    proposal = propose_quarantine_review(
        make_inspection()
    )

    assert proposal.disposition is (
        QuarantineReviewDisposition.REVIEW_QUARANTINE
    )
    assert proposal.reason is (
        QuarantineReviewReason.UNLINKED_PAYMENT
    )
    assert proposal.persisted is False
    assert proposal.organization_id == ORG
    assert proposal.record_id == RECORD


def test_refund_without_linkage_requires_review():
    proposal = propose_quarantine_review(
        make_inspection(
            linkage_kind=PaymentLinkKind.REFUND_UNSUPPORTED,
        )
    )

    assert proposal.disposition is (
        QuarantineReviewDisposition.REVIEW_QUARANTINE
    )
    assert proposal.reason is (
        QuarantineReviewReason.REFUND_LINKAGE_UNAVAILABLE
    )


def test_linked_payment_is_held_for_read_only_confirmation():
    proposal = propose_quarantine_review(
        make_inspection(
            action=TriageAction.RECONCILE,
            reason=TriageReason.READ_CONFIRMATION_REQUIRED,
            linkage_kind=PaymentLinkKind.LOCAL_REFERENCE,
            local_attempt_id=ATTEMPT,
            local_order_id=ORDER,
        )
    )

    assert proposal.disposition is (
        QuarantineReviewDisposition.HOLD_FOR_RECONCILIATION
    )
    assert proposal.reason is (
        QuarantineReviewReason.PROVIDER_READ_REQUIRED
    )
    assert proposal.persisted is False


def test_already_resolved_inbox_is_not_reprocessed():
    proposal = propose_quarantine_review(
        make_inspection(
            action=TriageAction.NO_ACTION,
            reason=TriageReason.ALREADY_RESOLVED,
            linkage_kind=None,
        )
    )

    assert proposal.disposition is (
        QuarantineReviewDisposition.NO_CHANGE
    )
    assert proposal.reason is (
        QuarantineReviewReason.ALREADY_RESOLVED
    )


def test_proposal_is_immutable():
    proposal = propose_quarantine_review(
        make_inspection()
    )

    with pytest.raises(FrozenInstanceError):
        proposal.persisted = True


def test_proposal_cannot_authorize_financial_mutations():
    proposal = propose_quarantine_review(
        make_inspection()
    )

    for forbidden in (
        "payment_state",
        "refund_state",
        "provider_confirmed",
        "settlement_confirmed",
        "retry_payment",
        "mutation_authorized",
        "new_inbox_status",
        "database_role",
        "commit",
        "execute",
    ):
        assert not hasattr(proposal, forbidden)


@pytest.mark.parametrize(
    "bad_value",
    [None, "tenant", UUID(int=0)],
)
def test_invalid_organization_rejected(bad_value):
    with pytest.raises(QuarantinePolicyError):
        propose_quarantine_review(
            make_inspection(organization_id=bad_value)
        )


@pytest.mark.parametrize(
    "bad_value",
    [None, "record", UUID(int=0)],
)
def test_invalid_record_identity_rejected(bad_value):
    with pytest.raises(QuarantinePolicyError):
        propose_quarantine_review(
            make_inspection(record_id=bad_value)
        )


@pytest.mark.parametrize(
    "bad_event",
    [
        None,
        "",
        " ",
        "evt with spaces",
        "evt_💳",
        "a" * 129,
    ],
)
def test_invalid_event_identity_rejected(bad_event):
    with pytest.raises(QuarantinePolicyError):
        propose_quarantine_review(
            make_inspection(event_id=bad_event)
        )


@pytest.mark.parametrize(
    "bad_value",
    [
        "quarantine",
        None,
        True,
    ],
)
def test_untyped_triage_action_rejected(bad_value):
    with pytest.raises(QuarantinePolicyError):
        propose_quarantine_review(
            make_inspection(action=bad_value)
        )


@pytest.mark.parametrize(
    "bad_value",
    [
        "unknown_object",
        None,
        1,
    ],
)
def test_untyped_triage_reason_rejected(bad_value):
    with pytest.raises(QuarantinePolicyError):
        propose_quarantine_review(
            make_inspection(reason=bad_value)
        )


@pytest.mark.parametrize(
    "bad_kind",
    [
        "unlinked",
        "local_reference",
        True,
    ],
)
def test_untyped_linkage_category_rejected(bad_kind):
    with pytest.raises(QuarantinePolicyError):
        propose_quarantine_review(
            make_inspection(linkage_kind=bad_kind)
        )


def test_persisted_input_rejected():
    with pytest.raises(QuarantinePolicyError):
        propose_quarantine_review(
            make_inspection(persisted=True)
        )


@pytest.mark.parametrize(
    "changes",
    [
        {"local_attempt_id": ATTEMPT},
        {"local_order_id": ORDER},
        {"local_attempt_id": UUID(int=0), "local_order_id": ORDER},
        {"local_attempt_id": ATTEMPT, "local_order_id": UUID(int=0)},
    ],
)
def test_incomplete_local_identity_rejected(changes):
    with pytest.raises(QuarantinePolicyError):
        propose_quarantine_review(
            make_inspection(**changes)
        )


@pytest.mark.parametrize(
    "changes",
    [
        {
            "action": TriageAction.RECONCILE,
            "reason": TriageReason.READ_CONFIRMATION_REQUIRED,
        },
        {
            "action": TriageAction.NO_ACTION,
            "reason": TriageReason.ALREADY_RESOLVED,
        },
        {
            "linkage_kind": PaymentLinkKind.LOCAL_REFERENCE,
        },
        {
            "reason": TriageReason.STALE_EVENT,
        },
        {
            "reason": TriageReason.TERMINAL_STATE_CONFLICT,
        },
        {
            "reason": TriageReason.READ_CONFIRMATION_REQUIRED,
        },
        {
            "action": TriageAction.RECONCILE,
        },
        {
            "action": TriageAction.NO_ACTION,
        },
        {
            "action": TriageAction.QUARANTINE,
            "linkage_kind": None,
        },
        {
            "action": TriageAction.NO_ACTION,
            "reason": TriageReason.ALREADY_RESOLVED,
            "linkage_kind": None,
            "local_attempt_id": ATTEMPT,
            "local_order_id": ORDER,
        },
    ],
)
def test_conflicting_decision_combinations_fail_closed(changes):
    with pytest.raises(QuarantinePolicyError):
        propose_quarantine_review(
            make_inspection(**changes)
        )


def test_fake_caller_supplied_object_rejected():
    with pytest.raises(TypeError):
        propose_quarantine_review({
            "organization_id": str(ORG),
            "record_id": str(RECORD),
            "action": "quarantine",
        })


def test_repeated_review_proposal_is_deterministic():
    inspection = make_inspection()

    first = propose_quarantine_review(inspection)
    second = propose_quarantine_review(inspection)

    assert first == second
    assert first is not second
    assert first.persisted is False


def test_input_inspection_is_not_modified():
    inspection = make_inspection()

    before = replace(inspection)

    propose_quarantine_review(inspection)

    assert inspection == before
