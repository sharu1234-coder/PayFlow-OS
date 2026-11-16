from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"

REQUIRED = {
    "DATABASE_RECOVERY.md": [
        "## Recovery objectives",
        "## Backup strategy",
        "## Safe restore drill",
        "## Evidence and sign-off",
        "## Open blockers",
    ],
    "INCIDENT_RESPONSE.md": [
        "## Severity",
        "## First response",
        "## Containment",
        "## Recovery",
        "## Evidence and sign-off",
    ],
    "DEPLOYMENT_RUNBOOK.md": [
        "## Pre-deployment",
        "## Procedure",
        "## Rollback",
        "## Evidence and sign-off",
    ],
    "RELEASE_SECURITY.md": [
        "## Verified development controls",
        "## Required before production approval",
        "## Evidence and sign-off",
        "## Open blockers",
    ],
}


@pytest.mark.parametrize("filename", sorted(REQUIRED))
def test_operational_runbook_exists_and_is_structured(filename):
    path = DOCS / filename

    assert path.is_file(), filename

    content = path.read_text(encoding="utf-8")

    for heading in REQUIRED[filename]:
        assert heading in content, (filename, heading)

    assert "Production launch approval: NOT GRANTED." in content


def test_backup_runbook_does_not_claim_pitr_is_ready():
    content = (
        DOCS / "DATABASE_RECOVERY.md"
    ).read_text(encoding="utf-8")

    assert "NOT point-in-time recovery backups" in content
    assert "No verified production PITR mechanism" in content


def test_release_checklist_requires_recovery_evidence():
    content = (
        DOCS / "RELEASE_SECURITY.md"
    ).read_text(encoding="utf-8")

    assert "restore testing" in content
    assert "passing test suite" in content
