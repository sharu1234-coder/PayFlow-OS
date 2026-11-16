# PayFlow OS ? Release Security Checklist

## Status
PRELAUNCH ? production launch approval: NOT GRANTED.

A successful unit or CI test run does not grant production
approval or establish regulatory compliance.

## Verified development controls
- Private GitHub repository was verified.
- CI tests on commit d358ae4 passed on GitHub.
- PostgreSQL migrations and runtime privilege checks passed in CI.
- Explicit APP_ENV requirement is implemented.
- Prelaunch API lockdown is implemented and tested.
- Authentication and tenant RBAC tests exist.
- Source secret-pattern and pinned dependency audits run in CI.

These are development and CI findings, not production controls
proven in a live environment.

## Required before production approval
- [ ] Production threat model and independent security review.
- [ ] Enforced branch protection or approved compensating controls.
- [ ] Production secrets manager and secret rotation procedure.
- [ ] Verified TLS, network isolation and trusted proxy policy.
- [ ] Production database backup, retention and restore testing.
- [ ] Approved RPO/RTO supported by recovery drills.
- [ ] Centralized redacted logs, monitoring and alerting.
- [ ] Incident response contacts and exercised runbook.
- [ ] Staging deployment and rollback rehearsal.
- [ ] Live payment provider contracts and credential boundaries.
- [ ] Webhook verification, replay defense and idempotency tests.
- [ ] Reconciliation, ledger integrity and operational controls.
- [ ] Privacy, regulatory and contractual requirements review.
- [ ] Production acceptance by the designated release authority.

## Source-control governance
Branch protection was not enabled during initial setup because
GitHub returned HTTP 403 to the current credentials.

Until enforcement is available, use feature branches, pull
requests and passing CI before merging. Direct pushes remain a
governance risk and are not automatically blocked.

## Payment and data boundaries
PayFlow is intended as an orchestration and merchant operations
service, not as a holder of merchant or customer funds.

Do not store raw cardholder credentials or introduce real-money
processing without separately approved provider integration,
data minimization, applicable compliance review and operations.

Do not infer payment regulatory approval from a passing test suite.

## Evidence and sign-off
The release authority must record each verified control, the
supporting evidence, any approved exception, and sign-off date.

No checklist item should be marked complete solely because a
document describing the intended process exists.

## Open blockers
Production infrastructure, recovery, monitoring, provider
operations and release authorization remain unverified.

Production launch approval: NOT GRANTED.
