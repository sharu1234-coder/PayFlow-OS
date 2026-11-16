import app.models

from sqlalchemy import CheckConstraint, UniqueConstraint

from app.core.model_base import Base
from app.models.invitations import OrganizationInvitation


def test_invitation_table_is_registered():
    table = Base.metadata.tables[
        "payflow.organization_invitations"
    ]

    assert table.schema == "payflow"
    assert table.name == "organization_invitations"


def test_invitation_references_correct_identities():
    table = OrganizationInvitation.__table__

    foreign_keys = {
        fk.target_fullname
        for fk in table.foreign_keys
    }

    assert foreign_keys == {
        "payflow.organizations.id",
        "payflow.users.id",
    }

    assert not table.c.organization_id.nullable
    assert not table.c.invited_by_user_id.nullable


def test_raw_invitation_token_is_not_stored():
    table = OrganizationInvitation.__table__

    assert "token_hash" in table.c
    assert "token" not in table.c
    assert "raw_token" not in table.c

    unique_columns = {
        tuple(column.name for column in constraint.columns)
        for constraint in table.constraints
        if isinstance(constraint, UniqueConstraint)
    }

    assert ("token_hash",) in unique_columns


def test_invitation_state_constraints_exist():
    table = OrganizationInvitation.__table__

    names = {
        constraint.name
        for constraint in table.constraints
        if isinstance(constraint, CheckConstraint)
    }

    assert names == {
        "ck_organization_invitations_email_lowercase",
        "ck_organization_invitations_role_valid",
        "ck_organization_invitations_token_hash_length",
        "ck_organization_invitations_expiry_after_creation",
        "ck_organization_invitations_acceptance_fields_match",
        "ck_organization_invitations_terminal_states_exclusive",
    }

    assert table.c.accepted_at.nullable
    assert table.c.accepted_user_id.nullable
    assert table.c.revoked_at.nullable


def test_pending_invitations_have_partial_unique_index():
    table = OrganizationInvitation.__table__

    indexes = {
        index.name: index
        for index in table.indexes
    }

    pending = indexes["uq_organization_invitations_pending"]

    assert pending.unique is True

    assert {
        column.name for column in pending.columns
    } == {"organization_id", "email"}

    predicate = str(
        pending.dialect_options["postgresql"]["where"]
    )

    assert "accepted_at IS NULL" in predicate
    assert "revoked_at IS NULL" in predicate
