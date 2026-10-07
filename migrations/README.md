# Database migrations

This directory owns forward changes to the service's PostgreSQL `judge` schema. The [active database contract](../docs/contracts/v0.2/database.md) defines the initial model; [database development and operations](../docs/development/database.md) defines the workflow.

## Current state

The repository supplies **migration level 1** in `000001_judge_v02_baseline.up.sql`. It implements the judge-owned V0.2 tables and the [published clarifications](../docs/contracts/v0.2/clarifications.md), including source/content/evidence identities, immutable history and deferred task/result/outbox checks. This file ceiling does not declare any production database migrated.

The [golang-migrate](https://github.com/golang-migrate/migrate) engine and pgx v5 driver are pinned in [go.mod](../go.mod) and [go.sum](../go.sum). The project-owned `judge-migrate` wrapper embeds reviewed SQL, provides only `up` and read-only `status`, and verifies an immutable checksum ledger under the native advisory lock. [Executable commands and recovery](../docs/development/migrations.md) describe its transaction/dirty-state behavior. [Role provisioning](../docs/development/database-provisioning.md) remains a separate operator step.

`make migration-status` reports repository files only. `make database-status` inspects actual database tracking/checksums. `make migration-up` applies forward files with the separately scoped migration identity supplied through `JUDGE_MIGRATION_DATABASE_URL`. The PostgreSQL server version is separately available through `make db-version`.

## File and ownership rules

- Name files `000001_descriptive_name.up.sql`, `000002_descriptive_name.up.sql`, and so on, with six digits and lowercase snake_case names. Start at 1, assign consecutive identities, and keep one forward file per identity. Do not add `.down.sql` files.
- One coordinator assigns migration numbers before parallel work is integrated into `dev`. Contributors may prepare SQL together, but must resolve number collisions before integration. A migration used in a shared environment keeps its original number, name, order, and bytes forever.
- Migrations must explicitly target `judge` objects. Never modify backend/algorithm schemas, add cross-service foreign keys, or use shared business credentials. Database/role/schema provisioning is separate, reviewed infrastructure automation; it must exist before the runner creates its tracking table in `judge`.
- Every migration identifies its Issue, purpose, transaction behavior, application compatibility, and any operational requirements in SQL comments. A migration that changes historical interpretation also links the contract/ADR and explains how old records remain readable.
- Use explicit `BEGIN`/`COMMIT` for atomic SQL. The current wrapper accepts atomic files only and places its checksum insertion before their final `COMMIT`. Operations that cannot run in a transaction, such as `CREATE INDEX CONCURRENTLY`, require a separately reviewed runner extension and cleanup/retry procedure before adding a migration. Never assume arbitrary SQL is transactional.
- New schema changes and corrections use new forward migrations. Once applied in shared development, staging, or production, do not edit, delete, reorder, or squash history. Disposable private databases may be recreated; shared databases may not be reset to disguise a migration failure.

## Runner acceptance requirements

Every native-tool release must retain these acceptance properties:

1. Pin the tool and driver, support the file convention above, and run with only the migration identity. Expose forward application and read-only status commands. Reject `down`, `drop`, negative steps, and routine `force` operations. **Missing down files do not provide this protection**: a tool can still change its recorded version without reversing schema changes.
2. Use PostgreSQL migration locking so only one runner applies changes. Place the tracking table in `judge`; report actual database version and dirty/in-progress state separately from PostgreSQL server version and repository's highest file number. Read-only status must not initialize a missing tracking table.
3. Verify file checksums against the immutable record from previous shared deployments/releases before applying new files. Native golang-migrate version/dirty tracking does not by itself prove that old SQL bytes have not changed.
4. Fail on unknown schema versions, dirty state, checksum drift, insufficient privileges, and SQL errors. Do not automatically erase dirty state or claim an incomplete migration succeeded.
5. Demonstrate fresh installation, upgrade from the previous released schema using representative retained data, repeat application with no changes, concurrent-runner locking, least-privilege boundaries, and failure recovery on disposable PostgreSQL databases.

Each release records its migration ceiling and the SHA-256 of each original SQL file. Each shared deployment records the actual before/after database version and matching checksums. `judge.schema_migrations` records native version/dirty state, while `judge.migration_checksums` records each immutable applied file; read-only status initializes neither. PostgreSQL integration tests create isolated databases and exercise installation, upgrade/repeat, locking, dirty failure, checksum drift/history loss and privilege/integrity denials. See the [release process](../docs/releases/process.md) for evidence ownership.
