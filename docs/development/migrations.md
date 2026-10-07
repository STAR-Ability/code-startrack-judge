# Applying the V0.2 judge schema

Issue [#6](https://github.com/STAR-Ability/code-startrack-judge/issues/6) introduces the first forward schema. The [database contract](../contracts/v0.2/database.md) and [published clarifications](../contracts/v0.2/clarifications.md) remain authoritative. Migration `000001_judge_v02_baseline.up.sql` supplies the owned tables, immutable history, deferred local identities, qualified publication, task/result/case/outbox integrity and catalog transaction checks.

## Executable commands

Build with the locked Go toolchain and module checksums:

```sh
make toolchain build
build/judge-migrate status
build/judge-migrate up -ceiling 1
build/judge-migrate status
make check
```

The command reads `JUDGE_MIGRATION_DATABASE_URL` from a private environment, never an argument. Supply the separately provisioned migration identity for `up`. A status-only identity may have `SELECT` on the tracking tables; `status` does not initialize a missing table. Keep credentials out of shell tracing, terminal output and repository files. Production connections require authenticated TLS with certificate verification according to the [database operations policy](database.md).

The executable embeds reviewed forward files at build time. It accepts `up`, `status` and a nonnegative release ceiling only. It has no runtime SQL path, SQL URL, `down`, `drop`, negative steps or `force` interface. A ceiling below the applied level fails. The JSON status distinguishes the applied database level from the highest available release file and whether tracking has been initialized. Dirty, unknown, missing or changed historical state fails instead of returning a healthy status.

## Native execution and checksum history

The pinned `golang-migrate` engine and PostgreSQL pgx v5 driver in [go.mod](../../go.mod) own migration execution, the database advisory lock and native `judge.schema_migrations(version,dirty)` tracking. The project wrapper checks six-digit contiguous forward identities and original file SHA-256 values before execution.

Under the native lock, the wrapper compares every applied file's number, name and original bytes with `judge.migration_checksums`. It rejects a missing row, renamed file, changed checksum, unknown migration version or disagreement with native tracking. It uses the native lock once; acquiring it again on another connection would deadlock. Both tracking-table initialization and migration lock waits have a server-side 15-second lock timeout. Statements have a five-minute timeout.

Each initial migration contains explicit `BEGIN` and `COMMIT`. The wrapper places a checksum-ledger insertion immediately before that file's final `COMMIT`, preserving the checksum of the original reviewed file. SQL and its immutable checksum therefore commit together. Native dirty marking occurs before SQL execution and clean marking occurs afterward. A crash after SQL commitment but before clean marking retains both the applied checksum and a dirty native version; it requires an incident review. The wrapper never guesses that such a crash is safe to repair.

This release supports atomic migrations only. A future nontransactional operation, including `CREATE INDEX CONCURRENTLY`, requires a separately reviewed runner extension and failure procedure before its migration is accepted. Do not disguise it inside this wrapper.

## Privileges and invariant boundaries

Provision the `judge` schema and identities separately. The migration identity must own `judge` and must lack superuser, `CREATEROLE` and `CREATEDB`. The runner deliberately rejects an infrastructure administrator for application migration. Grant the runtime identity schema usage, required application table/sequence privileges and required function/domain usage. Grant tracking-table `SELECT` only. Do not grant runtime DDL or checksum/native-version mutation. Review database and `public` schema defaults as well as cross-service schemas; `search_path` provides no isolation.

SQL enforces text enums, safe resource integers, same-problem/version/artifact/test relationships, approved package evidence, exact frozen selected-validation identities, and append-only licenses/source/content/artifacts/results. Successful terminal package validations must contain all five checkpoint booleans and bounded evidence matching the [validation results schema](../contracts/v0.2/validation-results-schema.json). Publication stamps a version once and advances the catalog in the same transaction. Task result, case aggregates and current callback revision are deferred until commitment, permitting correct circular insertion order while rejecting incomplete terminal facts. A qualified artifact's member registration locks its artifact row to serialize with one-time validation selection.

Owner code still validates canonical JSON hashes, full manifests, DTOs, sample schemas, authorization, staging/object checksums, private storage paths and the contents of actual validation evidence. A database record cannot prove a compiler, reference solution or sandbox ran. Qualification must retain the real tool/image/config/log evidence, and readiness must not infer execution safety from a successful schema migration.

## PostgreSQL validation

Tests create a newly named disposable database and independently scoped migration/runtime roles. They never reset the supplied administrator database. Provide an authenticated PostgreSQL administrator URL through a private file or environment variable; the test file path must be absolute because Go runs each package from its source directory:

```sh
JUDGE_TEST_ADMIN_DSN_FILE=/absolute/private/postgres-admin.dsn GOTOOLCHAIN=local .local/toolchains/go1.26.8/go/bin/go test ./internal/persistence/migrate -count=1 -v
```

Without `JUDGE_TEST_ADMIN_DSN_FILE` or `JUDGE_TEST_ADMIN_DATABASE_URL`, database tests explicitly skip; unit test success then proves no applied schema. Portable PostgreSQL testing covers installation, repeat/upgrade, native locking, dirty SQL failure, checksum drift/missing history, cross-schema privilege denials, immutable history, circular ownership, task/result/outbox atomicity and catalog integrity. It does not qualify Linux sandbox execution or the public-production host.

## Upgrade and incident procedure

1. Select the reviewed release commit/image and its migration ceiling and original SQL checksums. Inspect the actual server version, native version/dirty state and checksum ledger. Confirm application compatibility, bounded lock/statement time and the maintenance window.
2. Verify a restorable backup/PITR point and the matching private artifact store before changing a shared database. Retain a compatible previous application binary. Drain admission/workers when required by the particular migration; preserve accepted tasks and callbacks.
3. Run one migration job with the migration identity. Repeat `status` and verify constraints, grants, previous retained records and representative operations. Re-running the same forward ceiling must be a no-op.
4. Record before/after levels, checksums, release/image identities, operator/time and validation evidence in the [release/deployment records](../releases/process.md).

On failure, stop rollout. Preserve native dirty state, checksum rows and private diagnostics. An explicit transaction failure rolls back its schema and checksum row, while dirty tracking persists. A crash between SQL commitment and clean marking may already have committed both. Inspect both states before a database-owner-reviewed repair. The ordinary executable cannot clear dirty state or force a version. Never change old SQL bytes, reset a shared database, run down migrations or blindly replay a dirty file.

Application rollback is permitted only while the previous binary supports the expanded schema. Otherwise follow the reviewed incident recovery plan; a backup restore must reconcile accepted tasks, results and outbox events after the restore point, together with private artifact retention.
