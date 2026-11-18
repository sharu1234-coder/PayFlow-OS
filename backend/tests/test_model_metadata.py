import app.models
from app.core.model_base import Base


EXPECTED_TABLES = {
    "payflow.users",
    "payflow.organizations",
    "payflow.organization_memberships",
    "payflow.merchant_profiles",
    "payflow.audit_events",
    "payflow.user_sessions",
    "payflow.auth_tokens",
    "payflow.organization_invitations",
}


def test_identity_tables_are_registered():
    # Payment and webhook tables share Base.metadata.
    # Exclude them when checking identity tables.
    non_identity_tables = {
        "payflow.payment_orders",
        "payflow.payment_attempts",
        "payflow.payment_idempotency_records",
        "payflow.payment_attempt_idempotency_records",
        "payflow.provider_event_inbox",
    }
    identity_tables = set(Base.metadata.tables) - non_identity_tables
    assert identity_tables == EXPECTED_TABLES


def test_all_tables_use_payflow_schema():
    assert all(
        table.schema == "payflow"
        for table in Base.metadata.tables.values()
    )


def test_membership_has_unique_pair_constraint():
    table = Base.metadata.tables[
        "payflow.organization_memberships"
    ]

    unique_pairs = {
        tuple(column.name for column in constraint.columns)
        for constraint in table.constraints
        if constraint.__class__.__name__ == "UniqueConstraint"
    }

    assert (
        "organization_id",
        "user_id",
    ) in unique_pairs
