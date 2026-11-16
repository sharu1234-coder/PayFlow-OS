# PayFlow OS ? Deployment and Rollback

## Status
PLANNED ? production infrastructure has not been approved or
validated. This procedure must be tested in staging first.

## Runbook owner
Release manager: to be assigned.
Migration reviewer: to be assigned.
Security reviewer: to be assigned.

## Pre-deployment
1. Confirm the intended repository, commit SHA and environment.
2. Confirm successful GitHub CI for the exact commit.
3. Review the source diff and all database migrations.
4. Verify APP_ENV is explicitly set.
5. Verify runtime and migration database roles are distinct.
6. Verify TLS, secrets management and network restrictions.
7. Check recent backup status and restore readiness.
8. Confirm alerts, log retention and incident contacts.
9. Obtain release authorization.

The runtime application must not use migration credentials.

## Procedure
1. Prepare an isolated staging deployment.
2. Verify the deployment is configured to fail closed.
3. Verify health probes and observability.
4. Validate migration scripts against staging data.
5. Review expected locks, operation duration and failure modes.
6. Run migrations using the dedicated migration role.
7. Start application processes using the restricted runtime role.
8. Run smoke tests without real payment transactions.
9. Confirm the production API release gate remains locked.

Do not enable live payment handling by changing APP_ENV.
PayFlow's release gate requires a separate, reviewed activation
change after all launch conditions are satisfied.

## Rollback
Classify the failed deployment before acting:
- Application-only regression: restore the last known-good
  application image or immutable deployment revision.
- Additive database migration: consider a compatible application
  rollback only after confirming schema compatibility.
- Destructive or incompatible migration: use a reviewed
  forward-fix or formal disaster-recovery procedure.

Never assume `alembic downgrade` is safe or reversible.
Never restore a database backup into production without an
explicit incident and data-loss impact assessment.

## Post-deployment
1. Verify health and critical authorization paths.
2. Verify no unexpected tenant data access.
3. Monitor error rate, latency, database health and audit logs.
4. Record deployment SHA, migration revision and operator.
5. Obtain operational acceptance.

## Evidence and sign-off
Record:
- Release and rollback plan identifiers.
- Tested build artifact and immutable SHA.
- CI run and staging validation evidence.
- Migration approval and backup evidence.
- Change approval and post-release monitoring result.

## Open blockers
- No production hosting and networking verification.
- No completed staging deployment rehearsal.
- No proven production backup and rollback drill.
- No production alerting validation.
- No approved change-control process.

Production launch approval: NOT GRANTED.
