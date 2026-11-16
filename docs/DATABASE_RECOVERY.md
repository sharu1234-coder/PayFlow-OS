# PayFlow OS ? Database Backup and Recovery

## Status
PLANNED ? production backup automation, retention and restoration
have not yet been verified. This document is not evidence of
recoverability.

## Runbook owner
Database operations owner: to be assigned before launch.
Security reviewer: to be assigned before launch.

## Recovery objectives
- Recovery Point Objective (RPO): to be approved.
- Recovery Time Objective (RTO): to be approved.
- Backup retention period: to be approved.
- Backup storage region and encryption: to be approved.
- Restore testing frequency: to be approved.

Do not claim that any recovery target is achievable until a
timed restoration drill has demonstrated it.

## Backup strategy
1. Use encrypted, access-controlled, offsite backup storage.
2. Keep database runtime credentials separate from privileged
   backup and migration credentials.
3. Monitor backup success, age, storage capacity and failures.
4. Preserve the ability to reconstruct required database roles,
   extensions, ownership and grants.
5. Record PostgreSQL major version and schema migration revision.
6. Do not place real database dumps in Git or CI artifacts.

Logical backups created by pg_dump are useful for data export and
isolated restoration. They are NOT point-in-time recovery backups.

Production PITR requires an appropriate base backup and continuous
WAL archiving, or an independently verified managed service
offering equivalent recovery capabilities.

Reference:
https://www.postgresql.org/docs/18/continuous-archiving.html

## Safe restore drill
A restore drill must use a disposable, isolated database that is
not connected to production applications, workers or webhooks.

Before running a drill:
- Confirm the exact source and target database identifiers.
- Confirm the target contains no valuable data.
- Confirm available storage and appropriate access controls.
- Confirm that the archive can be inspected with pg_restore --list.
- Use no production notification, payment or email delivery paths.

A local logical-backup example, for future supervised use:

```powershell
$backupDir = Join-Path $HOME "PayFlowLocalBackups"
New-Item -ItemType Directory -Force -Path $backupDir | Out-Null

$archive = Join-Path $backupDir "payflow-local.dump"

pg_dump -h localhost -p 5432 -U payflow_migrator `
    -d payflow_db -n payflow -Fc -f $archive

if ($LASTEXITCODE -ne 0) {
    throw "Backup failed."
}

pg_restore --list $archive | Out-Null

if ($LASTEXITCODE -ne 0) {
    throw "Backup archive inspection failed."
}
```

The example requires suitable PostgreSQL permissions and the
client tools on PATH. It does not perform a restore.

For a full restore drill:
1. Provision a new isolated database.
2. Restore into that database using reviewed role and grant rules.
3. Run integrity checks, row-count comparisons and application
   read-only tests.
4. Verify migration revision and expected access restrictions.
5. Record duration, data consistency and any missing objects.
6. Destroy the disposable environment after approved cleanup.

Never restore over payflow_db during a test.

## Evidence and sign-off
Capture:
- Backup job identity and completion time.
- Backup object identifier and integrity evidence.
- Restore environment identifier.
- Restore duration and validation results.
- RPO/RTO measured against approved targets.
- Reviewer identity and approval date.

Do not put secrets or customer data in evidence reports.

## Open blockers
- No verified production backup schedule.
- No verified offsite retention and encryption controls.
- No completed isolated restore drill.
- No approved RPO or RTO.
- No verified production PITR mechanism.

Production launch approval: NOT GRANTED.
