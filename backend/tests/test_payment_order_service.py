"""Offline tests for provider-neutral payment-order creation."""

import uuid
from dataclasses import FrozenInstanceError
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.payments.contracts import Money
from app.services import payment_orders as service


ACTOR = uuid.uuid4()
ORGANIZATION = uuid.uuid4()


@pytest.fixture
def db():
    return Mock(spec=Session)


@pytest.fixture
def access(monkeypatch):
    checker = Mock(
        return_value=(object(), "owner", object())
    )
    monkeypatch.setattr(
        service,
        "get_accessible_organization",
        checker,
    )
    return checker


def order_request(**changes):
    data = {
        "organization_id": ORGANIZATION,
        "merchant_order_reference": "order_001",
        "amount": Money(12500, "INR"),
    }
    data.update(changes)
    return service.CreatePaymentOrderInput(**data)


def create(db, request=None, actor=ACTOR):
    return service.create_payment_order(
        db,
        actor_user_id=actor,
        request=request or order_request(),
    )


def make_integrity_error(
    *,
    sqlstate="23505",
    constraint="uq_payment_orders_tenant_reference",
):
    original = Exception("simulated database failure")
    original.sqlstate = sqlstate
    original.diag = SimpleNamespace(
        constraint_name=constraint
    )
    return IntegrityError(
        "INSERT simulated",
        {},
        original,
    )


def test_owner_creates_order_without_committing(db, access):
    result = create(db)

    access.assert_called_once_with(
        db,
        ACTOR,
        ORGANIZATION,
    )

    db.add.assert_called_once()
    db.flush.assert_called_once()

    db.commit.assert_not_called()
    db.rollback.assert_not_called()

    inserted = db.add.call_args.args[0]

    assert isinstance(inserted.id, uuid.UUID)
    assert inserted.organization_id == ORGANIZATION
    assert inserted.merchant_order_reference == "order_001"
    assert inserted.amount_minor_units == 12500
    assert inserted.currency == "INR"
    assert inserted.status == "open"

    assert result.id == inserted.id
    assert result.amount == Money(12500, "INR")
    assert result.status == "open"


def test_created_result_is_immutable(db, access):
    result = create(db)

    with pytest.raises(FrozenInstanceError):
        result.status = "paid"


def test_admin_can_create_order(db, access):
    access.return_value = (
        object(),
        "admin",
        object(),
    )

    result = create(db)

    assert result.status == "open"
    db.flush.assert_called_once()


@pytest.mark.parametrize(
    "role",
    [
        "viewer",
        "member",
        "operator",
        "OWNER",
        "",
        None,
        123,
    ],
)
def test_unapproved_roles_cannot_create(db, access, role):
    access.return_value = (
        object(),
        role,
        object(),
    )

    with pytest.raises(
        service.PaymentOrderAccessDenied
    ):
        create(db)

    db.add.assert_not_called()
    db.flush.assert_not_called()


def test_no_active_membership_blocks_creation(db, access):
    access.return_value = None

    with pytest.raises(
        service.PaymentOrderAccessDenied
    ):
        create(db)

    db.add.assert_not_called()
    db.flush.assert_not_called()


def test_actor_is_used_in_tenant_access_query(db, access):
    other_actor = uuid.uuid4()
    other_tenant = uuid.uuid4()

    create(
        db,
        actor=other_actor,
        request=order_request(
            organization_id=other_tenant
        ),
    )

    access.assert_called_once_with(
        db,
        other_actor,
        other_tenant,
    )


@pytest.mark.parametrize(
    "actor",
    [
        None,
        "not-a-uuid",
        uuid.UUID(int=0),
    ],
)
def test_invalid_actor_rejected_before_database_access(
    db,
    access,
    actor,
):
    with pytest.raises(ValueError):
        create(db, actor=actor)

    access.assert_not_called()
    db.add.assert_not_called()


@pytest.mark.parametrize(
    "organization_id",
    [
        None,
        "org1",
        uuid.UUID(int=0),
    ],
)
def test_invalid_organization_rejected(organization_id):
    with pytest.raises(ValueError):
        order_request(organization_id=organization_id)


@pytest.mark.parametrize(
    "reference",
    [
        "",
        "_invalid_first_character",
        "contains spaces",
        "../cross-tenant",
        "a" * 129,
    ],
)
def test_invalid_order_reference_rejected(reference):
    with pytest.raises(ValueError):
        order_request(
            merchant_order_reference=reference
        )


def test_maximum_length_reference_is_accepted():
    request = order_request(
        merchant_order_reference="A" * 128
    )
    assert len(request.merchant_order_reference) == 128


@pytest.mark.parametrize("amount", [None, 12500, "12500"])
def test_input_requires_valid_money_type(amount):
    with pytest.raises(TypeError):
        order_request(amount=amount)


def test_duplicate_reference_maps_exact_constraint(db, access):
    db.flush.side_effect = make_integrity_error()

    with pytest.raises(
        service.PaymentOrderReferenceConflict,
        match="Merchant order reference already exists",
    ):
        create(db)

    db.add.assert_called_once()
    db.flush.assert_called_once()

    # Rollback belongs to the transaction owner.
    db.commit.assert_not_called()
    db.rollback.assert_not_called()


@pytest.mark.parametrize(
    "sqlstate,constraint",
    [
        ("23503", "fk_payment_orders_organization"),
        ("23505", "different_unique_constraint"),
        ("23514", "ck_payment_orders_amount_positive"),
    ],
)
def test_other_integrity_errors_are_not_misclassified(
    db,
    access,
    sqlstate,
    constraint,
):
    original = make_integrity_error(
        sqlstate=sqlstate,
        constraint=constraint,
    )

    db.flush.side_effect = original

    with pytest.raises(IntegrityError) as captured:
        create(db)

    assert captured.value is original


def test_unexpected_database_error_propagates(db, access):
    db.flush.side_effect = RuntimeError(
        "simulated database unavailability"
    )

    with pytest.raises(
        RuntimeError,
        match="simulated database unavailability",
    ):
        create(db)

    db.commit.assert_not_called()


def test_request_must_be_order_input(db, access):
    with pytest.raises(TypeError):
        service.create_payment_order(
            db,
            actor_user_id=ACTOR,
            request=None,
        )

    access.assert_not_called()
    db.add.assert_not_called()


def test_service_never_invokes_payment_provider(db, access):
    result = create(db)

    assert result.status == "open"

    # Order creation only creates a database record.
    # It does not mark a payment succeeded or invoke
    # a provider without a separate orchestration step.
    assert db.add.call_count == 1
    assert db.flush.call_count == 1
    db.commit.assert_not_called()
