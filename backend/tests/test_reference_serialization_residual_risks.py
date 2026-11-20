"""Offline reproductions of reference serialization limitations.

These tests intentionally demonstrate UNSAFE interleavings.

A passing test does NOT prove that PayFlow's concurrency
vulnerability has been fixed.

No database connections, SQL, worker execution, gateway access,
payment mutation, or production processing.

The timeline is an illustrative model, not application code.
"""

from pathlib import Path

import pytest


DOCUMENT = (
    Path(__file__).resolve().parents[2]
    / "docs"
    / "REFERENCE_SERIALIZATION_RESIDUAL_RISKS.md"
)


class ReferenceTimeline:
    """Deterministic model of an advisory lock and reference state.

    Not a PostgreSQL implementation.

    The advisory lock is cooperative: a writer that ignores
    it can still create a matching reference.
    """

    def __init__(self):
        self.lock_owner = None
        self.reference_linked = False
        self.observed_reference = None
        self.decision = None

    def acquire_lock(self, actor):
        if self.lock_owner not in (None, actor):
            return False

        self.lock_owner = actor
        return True

    def release_lock(self, actor):
        if self.lock_owner != actor:
            raise ValueError("Lock ownership mismatch")

        self.lock_owner = None

    def observe_reference(self):
        self.observed_reference = self.reference_linked
        return self.observed_reference

    def write_reference(self, actor, *, cooperating):
        if (
            cooperating
            and self.lock_owner not in (None, actor)
        ):
            return False

        self.reference_linked = True
        return True

    def unsafe_cached_classification(self):
        if self.observed_reference is None:
            raise ValueError("No reference observation")

        return (
            "linked"
            if self.observed_reference
            else "orphan"
        )

    def safe_review_disposition(self):
        # Illustrative safe default only.
        # No actual inbox or payment state is persisted.
        self.decision = "review_pending"
        return self.decision


def test_cooperating_writer_respects_existing_lock():
    timeline = ReferenceTimeline()

    assert timeline.acquire_lock("inspector") is True

    assert timeline.write_reference(
        "writer",
        cooperating=True,
    ) is False

    assert timeline.reference_linked is False


def test_noncooperating_writer_bypasses_advisory_lock():
    timeline = ReferenceTimeline()

    assert timeline.acquire_lock("inspector") is True

    assert timeline.observe_reference() is False

    # Deliberately bypasses the cooperative lock protocol.
    assert timeline.write_reference(
        "raw_sql_writer",
        cooperating=False,
    ) is True

    assert timeline.reference_linked is True

    # This is the unsafe, stale classification.
    assert timeline.unsafe_cached_classification() == "orphan"


def test_fresh_observation_differs_from_stale_observation():
    timeline = ReferenceTimeline()

    assert timeline.acquire_lock("inspector") is True
    assert timeline.observe_reference() is False

    assert timeline.write_reference(
        "raw_sql_writer",
        cooperating=False,
    ) is True

    assert timeline.unsafe_cached_classification() == "orphan"

    # A fresh read in this model sees the new reference.
    assert timeline.observe_reference() is True
    assert timeline.unsafe_cached_classification() == "linked"


def test_reference_can_arrive_after_decision_commit():
    timeline = ReferenceTimeline()

    assert timeline.acquire_lock("inspector") is True
    assert timeline.observe_reference() is False

    # A conservative decision does not declare payment
    # permanently invalid or settled.
    assert timeline.safe_review_disposition() == "review_pending"

    timeline.release_lock("inspector")

    # A fully cooperating writer can now proceed.
    assert timeline.write_reference(
        "writer",
        cooperating=True,
    ) is True

    assert timeline.reference_linked is True
    assert timeline.decision == "review_pending"


def test_lock_recheck_alone_does_not_solve_late_linkage():
    timeline = ReferenceTimeline()

    assert timeline.acquire_lock("inspector") is True

    # Even a fresh lookup immediately before the decision
    # cannot prove no reference will ever be created later.
    assert timeline.observe_reference() is False
    assert timeline.safe_review_disposition() == "review_pending"

    timeline.release_lock("inspector")

    assert timeline.write_reference(
        "writer",
        cooperating=True,
    ) is True

    assert timeline.reference_linked is True


def test_cooperative_writer_proceeds_after_lock_release():
    timeline = ReferenceTimeline()

    assert timeline.acquire_lock("inspector") is True

    assert timeline.write_reference(
        "writer",
        cooperating=True,
    ) is False

    timeline.release_lock("inspector")

    assert timeline.write_reference(
        "writer",
        cooperating=True,
    ) is True


def test_wrong_actor_cannot_release_modeled_lock():
    timeline = ReferenceTimeline()

    assert timeline.acquire_lock("inspector") is True

    with pytest.raises(ValueError):
        timeline.release_lock("another_actor")

    assert timeline.lock_owner == "inspector"


def test_safe_review_never_implies_payment_finality():
    timeline = ReferenceTimeline()

    assert timeline.observe_reference() is False

    disposition = timeline.safe_review_disposition()

    assert disposition == "review_pending"
    assert disposition not in (
        "settled",
        "paid",
        "refunded",
        "permanently_invalid",
    )


def test_security_document_names_both_unresolved_risks():
    content = DOCUMENT.read_text(encoding="utf-8")

    required = (
        "NON-COOPERATING WRITERS",
        "LATE-ARRIVING REFERENCES",
        "DATABASE-ENFORCED BOUNDARY",
        "TRUSTED-JOB AUTHORIZATION",
        "NO-GO",
        "review_pending",
        "PostgreSQL",
        "commit",
        "rollback",
    )

    for item in required:
        assert item in content


def test_document_requires_writer_inventory():
    content = DOCUMENT.read_text(encoding="utf-8")

    for writer in (
        "Application services",
        "Administrative SQL",
        "Data repairs",
        "Background jobs",
        "Migration scripts",
        "Future provider integrations",
    ):
        assert writer in content


def test_document_explicitly_rejects_activation():
    content = DOCUMENT.read_text(encoding="utf-8")

    assert "Worker activation remains BLOCKED" in content
    assert "No worker EXECUTE grants" in content
    assert "No production deployment approval" in content


def test_model_has_no_database_or_payment_dependencies():
    import ast

    tree = ast.parse(
        Path(__file__).read_text(encoding="utf-8")
    )

    prohibited_modules = {
        "sqlalchemy",
        "psycopg",
        "psycopg2",
        "asyncpg",
    }

    prohibited_calls = {
        "create_engine",
        "create_async_engine",
        "connect",
        "execute",
        "exec_driver_sql",
        "exec",
        "eval",
    }

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                assert root not in prohibited_modules

        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            assert root not in prohibited_modules

        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                name = node.func.attr
            else:
                continue

            assert name not in prohibited_calls
