# Database development and upgrades

The [versioned database contract](../contracts/v0.2/database.md) defines service ownership and data invariants. The [migration directory policy](../../migrations/README.md) defines file identities and runner requirements. This document describes how developers and operators apply that policy; it does not replace contract tables with a second schema specification.

## Current commands and scope

Follow [getting started](getting-started.md) to configure Docker Compose and generated local credentials, then run:

```sh
make bootstrap
make infra-up
make db-version
make migration-status
make build
make database-status
make migration-up
make database-status
make check
```

`db-version` checks the PostgreSQL **server** version. `migration-status` reports the repository's available forward files, currently level **5**. `database-status` reads the actual native version/dirty state and validates applied checksums. `migration-up` uses the pinned native runner and embedded SQL. Supply `JUDGE_MIGRATION_DATABASE_URL` privately; build and apply are separate operations. Follow [role provisioning](database-provisioning.md) before `migration-up`, then apply the explicit runtime grants afterward. [The migration runbook](migrations.md) contains direct executable commands, PostgreSQL tests and failure behavior.

Local infrastructure administration credentials are generated for a disposable development database. They are not application or migration credentials. The runner requires a non-administrative owner of `judge`; runtime uses a separate identity with explicit business-table privileges and read-only migration tracking. A running PostgreSQL server or an available SQL file alone does not prove an applied business schema or production access control.

## Database and credential boundaries

PostgreSQL infrastructure can be shared with other services, but the service only owns `judge`. There are no cross-schema foreign keys for backend `submissionId` or administrator identifiers; those are logical references verified through the trusted API boundary. The API/worker must not possess backend or algorithm database credentials. The sandbox process must not possess any business database credential.

Provisioning must establish a separate migration identity that owns/changes `judge` and a runtime identity with only the required table/sequence privileges in `judge`. Runtime credentials cannot perform DDL, create roles/databases, or read/write another service's schema. Do not rely on a connection's `search_path` as an access-control boundary. Review database defaults and `PUBLIC` grants as part of provisioning, and verify denied cross-schema access with the actual runtime role. Keep provisioning automation versioned and reviewed; do not perform undocumented production SQL.

Use schema-qualified object names. Keep the migration tool's tracking table in `judge`. Keep connection secrets out of command logs, shell tracing, Issue bodies, database dumps in the repository, and application logs. Production connections use authenticated transport with certificate verification where the database is reached over a network; local-only Compose settings are not production defaults.

## Development migration workflow

For each new forward schema change:

1. Read the active contract, accepted ADRs, previous migrations, and the implementation Issue. Resolve any contract conflict in the [question register](../contracts/open-questions.md) before encoding a competing interpretation.
2. Ask the migration coordinator for the next identity. Add forward SQL and its explanation; do not use ORM auto-sync or amend a previously shared file. Follow the initial dependency order in database contract section 14, including deferred local compound foreign keys for circular artifact/version/validation references.
3. Review schema constraints, grants, indexes, lock duration, transaction boundaries, and compatibility with both the current and next application release. CHECK constraints cannot be declared deferrable in PostgreSQL. Where the contract requires deferred cross-row/terminal-state enforcement, use supported database mechanisms such as deferred constraint triggers; owner-layer validation and transaction tests supplement required database constraints rather than replacing them.
4. Apply all migrations to a fresh disposable database, then upgrade a database initialized at the previous released level with representative historical records. Repeat the forward command, check actual version/dirty state, compare checksums, and run repository/API integration tests. Test new constraints with invalid rows, not only happy-path inserts.
5. Record the validation and operational evidence in the Issue/PR. Update the release's supported schema range and migration metadata. Integrate into `dev` after review and checks.

Run the [database-backed migration checks](migrations.md#postgresql-validation) with an isolated PostgreSQL administrator connection. The suite creates disposable databases and roles, tests retained previous-level records and verifies native locking, dirty failure, checksum changes/missing history, circular relationships, immutable facts and runtime privilege denials. If its required test connection is absent, database tests explicitly skip; ordinary unit success is not database acceptance evidence. Use the separate [backup and restore rehearsal](db-recovery.md) to verify native migration history and coordinated private objects in fresh restored databases. Historical Phase 0 reports retain their original scope.

## Historical records and data conversions

Preserve the identity and traceability of problem versions, artifacts, license evidence, validation runs, language configurations, JudgeTasks, results, and published contracts. Migration-level conversions must preserve old value semantics, original hashes, upstream provenance, image/toolchain digests, and object references. New problem/execution meaning is a new immutable version, not an overwrite of a historical record.

Review any lifecycle update against the contract's permitted exceptions, such as first publication, active language selection, and task/outbox state before terminal commitment. The [published clarifications](../contracts/v0.2/clarifications.md) freeze source/content identities and evidence variants, permit one exact-context selected validation pointer, and define the bounded recovery reservation graph. New license approval inserts evidence; it never edits an old record. Source cleanup changes only the private transient key and preserves public task timestamps/revisions. Expired catalog snapshots are cleaned as whole snapshots; neither cleanup permits deleting immutable packages/results. Never cascade a historical problem/task deletion to its dependants.

For an evolving table, prefer **expand → backfill → verify → switch readers/writers → remove obsolete structure in a later migration**. Backfills must be bounded, restartable, and observable. Keep old application binaries compatible during the intended deployment overlap. Removing a column or constraint requires an explicit compatibility plan and evidence that supported readers no longer need it. Do not make immutable historical rows masquerade as records created under the new contract.

## Production upgrade procedure

Production schema changes are controlled deployment steps, not an automatic side effect of every API replica starting.

1. Select a reviewed release commit/tag and image digest. Verify migration checksums against the previous deployment record and release manifest; inspect the actual database version/dirty state. Confirm the release's supported schema range, database engine version, required storage capacity, and rollback-compatible application binary.
2. Arrange a verified, recoverable database backup/PITR point and confirm restore procedures before destructive or substantial changes. Protect backup access and coordinate private artifact storage retention: restoring relational metadata without its referenced immutable objects is insufficient. Record expected lock time, statement timeout, and the chosen maintenance or rolling-upgrade window.
3. Run one migration job using the migration credential and native database lock. Pause or drain work if the change cannot safely coexist with running API/worker instances; do not lose in-flight JudgeTasks or outbox events. Apply only the intended release's forward ceiling.
4. Verify actual clean database version, grants, constraints, indexes, retained record readability, representative queries, and contract integration checks. Start/roll the compatible application and check readiness. Readiness must reject dirty or unsupported schema states once the service exists.
5. Record commit/tag, contract version, before/after migration level, SQL checksums, image digest, test results, operator, and time with the deployment evidence. Keep this evidence access-controlled if it contains infrastructure details.

## Failure and recovery

On a migration failure, stop the upgrade and retain logs, actual version, dirty state, and database/object-store evidence. Do not run `down`, reset a shared database, alter the old SQL file, or blindly force a version. Inspect which transaction committed and whether nontransactional operations left objects behind; involve the database owner and use a reviewed forward repair when feasible. A dirty-state repair may require a carefully justified tool-specific operation after the schema is verified, with its SQL and evidence recorded in the incident/deployment record. It is never a routine bootstrap step.

Revert the application binary only when it remains compatible with the expanded schema. If it is not, pause/drain the service and execute the documented recovery plan. Restoring a backup is a deliberate incident action: reconcile tasks, accepted requests, results, and outbox deliveries that occurred after the restore point so committed facts or accepted work are not silently lost or replayed inconsistently.

## Version visibility

Repository file numbers describe available migrations; the tool's database tracking table describes the applied version and dirty state; neither is the PostgreSQL engine version. Future operational startup diagnostics and the release manifest must expose the supported schema range, while deployment evidence records the actual applied level and file checksums. This does not change the contracted public health DTO. API contract versions, migration levels, application releases, and package-manifest versions are distinct identifiers; do not equate them.
