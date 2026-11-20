# PayFlow OS - Reference Serialization Residual Risks

Status: SECURITY DESIGN ONLY - NO-GO

Worker activation remains BLOCKED.

This document follows the isolated PostgreSQL reference-race
reproduction and advisory-lock contention drill.

The earlier drill confirmed cooperative transaction-scoped
advisory-lock contention and release.

It did not establish a database-enforced serialization rule.

No production deployment approval is granted.

## 1. NON-COOPERATING WRITERS

PostgreSQL advisory locks are cooperative.

If transaction A acquires a reference advisory lock,
transaction B can still write to the payment_attempts table
without acquiring that same advisory lock.

Therefore, the existence of a reference lock does not
prevent arbitrary permitted database writers from
creating or changing provider_payment_id.

The offline tests reproduce this limitation using a
deterministic state-transition model.

This is a model, not a successful PostgreSQL safety proof.

## 2. Required writer inventory

The implementation must inventory every path capable of
creating, assigning, updating, clearing or replacing a
payment reference.

Review at least:

- Application services
- Administrative SQL
- Data repairs
- Background jobs
- Migration scripts
- Future provider integrations

Also inspect database role privileges, internal tooling,
legacy code and direct database maintenance procedures.

No path may silently bypass the reviewed consistency
boundary.

## 3. DATABASE-ENFORCED BOUNDARY

A shared application helper alone is insufficient.

Before worker activation, evaluate a database-enforced
reference ownership mechanism.

Potential designs include:

- A tenant/provider/reference registry with durable
  ownership and uniqueness constraints.
- Restricted and reviewed reference-write interfaces.
- Database-side enforcement preventing bypass by
  ordinary runtime roles.
- Clearly defined ordering across reference, order
  and inbox locks.

These are architectural options, not approved changes.

A database trigger, stored procedure, privilege change,
registry migration or role change requires separate
review and isolated PostgreSQL tests.

The design must prevent conflicting association of one
provider reference to multiple attempts.

It must also define reference replacement and revocation.

## 4. LATE-ARRIVING REFERENCES

A reference may become linked after a quarantine decision
has committed.

Even if all writers cooperate with an advisory lock,
that lock does not prevent a later transaction from
linking the same reference after lock release.

A fresh check inside one transaction proves only what
was visible under that transaction's isolation rules.

Absence now does not prove permanent invalidity.

## 5. Conservative lifecycle handling

For an unresolved reference, use the conceptual disposition:

review_pending

This is a design label, not an approved database status.

The existing inbox schema has its own lifecycle values.
This phase does not change them.

An unlinked payment event must not, solely because of
reference absence, authorize:

- A final payment failure
- A successful settlement
- A refund
- A ledger mutation
- Irreversible rejection of legitimate linkage

Late references require an explicitly designed way to
trigger or schedule safe reconciliation.

No scheduler or background worker is started here.

## 6. TRUSTED-JOB AUTHORIZATION

Correct reference coordination is not sufficient to
authorize an internal processing job.

A future worker must establish trusted, tenant-bound,
durable work-item authorization.

The job must not be authorized merely by knowing a
tenant UUID and inbox record UUID.

Authorization must be validated atomically with any
approved protected transition.

## 7. Required future PostgreSQL experiments

Before choosing a database design, run isolated
experiments including:

1. A non-cooperating INSERT during an advisory lock.
2. A non-cooperating UPDATE during an advisory lock.
3. A cooperating INSERT waiting for lock release.
4. Concurrent commit and rollback ordering.
5. Reference replacement under conflicting writers.
6. Tenant-scoped uniqueness and isolation.
7. A late reference arriving after a decision commit.
8. Retries after a late reference appears.
9. Deadlock and lock-timeout recovery.
10. Independent verification of a clean database baseline.

Each experiment must use the isolated PostgreSQL lab,
synthetic identities and explicit execution opt-ins.

A successful race reproduction is not evidence that the
production race has been fixed.

## 8. Current prohibited actions

- No worker EXECUTE grants.
- No worker password or database CONNECT grants.
- No privileged quarantine function activation.
- No production migrations.
- No public processing endpoints.
- No payment, refund or settlement transitions.
- No background processors.
- No production deployment approval.

## 9. Decision

NO-GO: The quarantine worker remains dormant.

Both non-cooperating writers and late-arriving references
remain unresolved architectural security risks.

Completion of the offline scenarios does not close
either blocker.
