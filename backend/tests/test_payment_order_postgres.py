"""Rollback-only PostgreSQL integration tests for payment orders."""

import uuid

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import engine
from app.models import (
    User,
    Organization,
    OrganizationMembership,
    MerchantProfile,
)
from app.models.payments import PaymentOrder
from app.payments.contracts import Money
from app.services.organization_rbac import permissions_for_role
from app.services.payment_orders import (
    CreatePaymentOrderInput,
    PaymentOrderAccessDenied,
    PaymentOrderReferenceConflict,
    create_payment_order,
)


def session_for(connection):
    return Session(
        bind=connection,
        expire_on_commit=False,
        join_transaction_mode="create_savepoint",
    )


def make_request(organization_id, reference):
    return CreatePaymentOrderInput(
        organization_id=organization_id,
        merchant_order_reference=reference,
        amount=Money(12500, "INR"),
    )


def create_order(db, user_id, organization_id, reference):
    return create_payment_order(
        db,
        actor_user_id=user_id,
        request=make_request(
            organization_id,
            reference,
        ),
    )


def count_orders(db, organization_id):
    return db.scalar(
        select(func.count())
        .select_from(PaymentOrder)
        .where(
            PaymentOrder.organization_id == organization_id
        )
    )


@pytest.fixture
def sandbox():
    settings = get_settings()
    url = make_url(settings.database_url)

    if (
        settings.app_env != "development"
        or url.database != "payflow_db"
        or url.username != "payflow_runtime"
        or url.host not in (
            "localhost",
            "127.0.0.1",
            "::1",
        )
        or url.port not in (None, 5432)
    ):
        raise RuntimeError(
            "Refusing integration test outside "
            "the established development/CI database."
        )

    with engine.connect() as connection:
        outer = connection.begin()

        try:
            database, role = connection.execute(
                text(
                    "SELECT current_database(), current_user"
                )
            ).one()

            assert database == "payflow_db"
            assert role == "payflow_runtime"

            with session_for(connection) as db:
                with db.begin():
                    names = (
                        "owner",
                        "admin",
                        "developer",
                        "finance",
                        "viewer",
                        "other_owner",
                        "revoked",
                    )

                    actors = {}

                    for name in names:
                        actor = User(
                            email=(
                                "payment-"
                                + name
                                + "-"
                                + uuid.uuid4().hex
                                + "@example.invalid"
                            ),
                            password_hash=(
                                "!synthetic-test-login-disabled!"
                            ),
                            is_active=True,
                        )

                        db.add(actor)
                        actors[name] = actor

                    db.flush()

                    org_a = Organization(
                        name="Integration Merchant Alpha",
                        slug=(
                            "payment-alpha-"
                            + uuid.uuid4().hex[:16]
                        ),
                        status="active",
                    )

                    org_b = Organization(
                        name="Integration Merchant Beta",
                        slug=(
                            "payment-beta-"
                            + uuid.uuid4().hex[:16]
                        ),
                        status="active",
                    )

                    db.add_all([org_a, org_b])
                    db.flush()

                    db.add_all([
                        MerchantProfile(
                            organization_id=org_a.id,
                            business_name="Test Merchant Alpha",
                            onboarding_status="approved",
                        ),
                        MerchantProfile(
                            organization_id=org_b.id,
                            business_name="Test Merchant Beta",
                            onboarding_status="approved",
                        ),
                    ])

                    for role_name in (
                        "owner",
                        "admin",
                        "developer",
                        "finance",
                        "viewer",
                    ):
                        db.add(
                            OrganizationMembership(
                                organization_id=org_a.id,
                                user_id=actors[role_name].id,
                                role=role_name,
                                status="active",
                            )
                        )

                    db.add_all([
                        OrganizationMembership(
                            organization_id=org_b.id,
                            user_id=actors["other_owner"].id,
                            role="owner",
                            status="active",
                        ),
                        OrganizationMembership(
                            organization_id=org_a.id,
                            user_id=actors["revoked"].id,
                            role="owner",
                            status="revoked",
                        ),
                    ])

                    db.flush()

                    data = {
                        "users": {
                            name: actor.id
                            for name, actor in actors.items()
                        },
                        "org_a": org_a.id,
                        "org_b": org_b.id,
                    }

            yield connection, data

        finally:
            # No synthetic identity or payment records
            # are permanently committed.
            if outer.is_active:
                outer.rollback()


@pytest.mark.parametrize(
    ("role", "allowed"),
    [
        ("owner", True),
        ("admin", True),
        ("developer", False),
        ("finance", False),
        ("viewer", False),
        ("unknown", False),
    ],
)
def test_payment_create_rbac(role, allowed):
    assert (
        "payments.create" in permissions_for_role(role)
    ) is allowed


def test_owner_and_admin_can_create_orders(sandbox):
    connection, data = sandbox

    with session_for(connection) as db:
        with db.begin():
            first = create_order(
                db,
                data["users"]["owner"],
                data["org_a"],
                "owner-" + uuid.uuid4().hex,
            )

            second = create_order(
                db,
                data["users"]["admin"],
                data["org_a"],
                "admin-" + uuid.uuid4().hex,
            )

            assert first.organization_id == data["org_a"]
            assert first.amount == Money(12500, "INR")
            assert first.status == "open"

            assert second.organization_id == data["org_a"]

            assert db.get(PaymentOrder, first.id) is not None
            assert db.get(PaymentOrder, second.id) is not None

            assert count_orders(db, data["org_a"]) == 2


@pytest.mark.parametrize(
    "role",
    ["developer", "finance", "viewer"],
)
def test_restricted_roles_cannot_create_orders(sandbox, role):
    connection, data = sandbox

    with session_for(connection) as db:
        with db.begin():
            with pytest.raises(PaymentOrderAccessDenied):
                create_order(
                    db,
                    data["users"][role],
                    data["org_a"],
                    "blocked-" + uuid.uuid4().hex,
                )

            assert count_orders(db, data["org_a"]) == 0


def test_cross_tenant_creation_is_denied(sandbox):
    connection, data = sandbox

    with session_for(connection) as db:
        with db.begin():
            with pytest.raises(PaymentOrderAccessDenied):
                create_order(
                    db,
                    data["users"]["owner"],
                    data["org_b"],
                    "cross-" + uuid.uuid4().hex,
                )

            assert count_orders(db, data["org_b"]) == 0


def test_unknown_user_cannot_create_order(sandbox):
    connection, data = sandbox

    with session_for(connection) as db:
        with db.begin():
            with pytest.raises(PaymentOrderAccessDenied):
                create_order(
                    db,
                    uuid.uuid4(),
                    data["org_a"],
                    "unknown-" + uuid.uuid4().hex,
                )


def test_revoked_membership_cannot_create_order(sandbox):
    connection, data = sandbox

    with session_for(connection) as db:
        with db.begin():
            with pytest.raises(PaymentOrderAccessDenied):
                create_order(
                    db,
                    data["users"]["revoked"],
                    data["org_a"],
                    "revoked-" + uuid.uuid4().hex,
                )


def test_suspended_organization_cannot_create_order(sandbox):
    connection, data = sandbox

    with session_for(connection) as db:
        with db.begin():
            organization = db.get(
                Organization,
                data["org_a"],
            )

            organization.status = "suspended"
            db.flush()

            with pytest.raises(PaymentOrderAccessDenied):
                create_order(
                    db,
                    data["users"]["owner"],
                    data["org_a"],
                    "suspended-" + uuid.uuid4().hex,
                )


def test_duplicate_reference_and_tenant_isolation(sandbox):
    connection, data = sandbox

    reference = "shared-" + uuid.uuid4().hex

    with session_for(connection) as db:
        with db.begin():
            first = create_order(
                db,
                data["users"]["owner"],
                data["org_a"],
                reference,
            )

            # Isolate the expected unique-constraint
            # failure in a PostgreSQL savepoint.
            with pytest.raises(
                PaymentOrderReferenceConflict
            ):
                with db.begin_nested():
                    create_order(
                        db,
                        data["users"]["admin"],
                        data["org_a"],
                        reference,
                    )

            second = create_order(
                db,
                data["users"]["other_owner"],
                data["org_b"],
                reference,
            )

            assert first.id != second.id
            assert count_orders(db, data["org_a"]) == 1
            assert count_orders(db, data["org_b"]) == 1


def test_payment_order_transaction_rollback(sandbox):
    connection, data = sandbox
    reference = "rollback-" + uuid.uuid4().hex

    with session_for(connection) as db:
        transaction = db.begin()

        try:
            created = create_order(
                db,
                data["users"]["owner"],
                data["org_a"],
                reference,
            )

            assert db.get(PaymentOrder, created.id) is not None

        finally:
            if transaction.is_active:
                transaction.rollback()

    with session_for(connection) as db:
        remaining = db.scalar(
            select(func.count())
            .select_from(PaymentOrder)
            .where(
                PaymentOrder.organization_id
                == data["org_a"],
                PaymentOrder.merchant_order_reference
                == reference,
            )
        )

        assert remaining == 0
