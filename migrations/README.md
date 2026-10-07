# Database migrations

This directory owns forward changes to the service's PostgreSQL `judge` schema. The [active database contract](../docs/contracts/v0.2/database.md) defines the initial model; [database development and operations](../docs/development/database.md) defines the workflow.

## Current state

Phase 0 has **migration level 0: no numbered SQL migrations, no migration runner, and no deployed schema declared by this repository**. A running development PostgreSQL server is infrastructure, not an initialized judge database. `make migration-status` reports repository files; it does not inspect a deployed database or prove its schema version.

The first schema implementation Issue must install and pin a maintained native migration tool, provision schema-scoped identities, add the first SQL migrations, and provide database-backed migration checks. The selected integration direction is [golang-migrate](https://github.com/golang-migrate/migrate), using its PostgreSQL driver and forward files. Its exact release, checksum/module lock, license inventory, and executable wrapper belong to that Issue; no unpinned migration binary is required in Phase 0.

## File and ownership rules

- Name files `000001_descriptive_name.up.sql`, `000002_descriptive_name.up.sql`, and so on, with six digits and lowercase snake_case names. Start at 1, assign consecutive identities, and keep one forward file per identity. Do not add `.down.sql` files.
- One coordinator assigns migration numbers before parallel work is integrated into `dev`. Contributors may prepare SQL together, but must resolve number collisions before integration. A migration used in a shared environment keeps its original number, name, order, and bytes forever.
- Migrations must explicitly target `judge` objects. Never modify backend/algorithm schemas, add cross-service foreign keys, or use shared business credentials. Database/role/schema provisioning is separate, reviewed infrastructure automation; it must exist before the runner creates its tracking table in `judge`.
- Every migration identifies its Issue, purpose, transaction behavior, application compatibility, and any operational requirements in SQL comments. A migration that changes historical interpretation also links the contract/ADR and explains how old records remain readable.
- Use explicit `BEGIN`/`COMMIT` for a migration intended to be atomic. Isolate operations that cannot run in a transaction, such as `CREATE INDEX CONCURRENTLY`, into reviewed files with cleanup/retry instructions. Never assume a runner makes arbitrary SQL transactional.
- New schema changes and corrections use new forward migrations. Once applied in shared development, staging, or production, do not edit, delete, reorder, or squash history. Disposable private databases may be recreated; shared databases may not be reset to disguise a migration failure.

## Runner acceptance requirements

Before the first schema migration is considered complete, the native tool integration must:

1. Pin the tool and driver, support the file convention above, and run with only the migration identity. Expose forward application and read-only status commands. Reject `down`, `drop`, negative steps, and routine `force` operations. **Missing down files do not provide this protection**: a tool can still change its recorded version without reversing schema changes.
2. Use PostgreSQL migration locking so only one runner applies changes. Place the tracking table in `judge`; report actual database version and dirty/in-progress state separately from PostgreSQL server version and repository's highest file number. Read-only status must not initialize a missing tracking table.
3. Verify file checksums against the immutable record from previous shared deployments/releases before applying new files. Native golang-migrate version/dirty tracking does not by itself prove that old SQL bytes have not changed.
4. Fail on unknown schema versions, dirty state, checksum drift, insufficient privileges, and SQL errors. Do not automatically erase dirty state or claim an incomplete migration succeeded.
5. Demonstrate fresh installation, upgrade from the previous released schema using representative retained data, repeat application with no changes, concurrent-runner locking, least-privilege boundaries, and failure recovery on disposable PostgreSQL databases.

Each release records its migration ceiling and the SHA-256 of each SQL file. Each shared deployment records the actual before/after database version and matching checksums. There is no shipped checksum ledger to populate at level 0. See the [release process](../docs/releases/process.md) for evidence ownership.
