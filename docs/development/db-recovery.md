# Disposable database recovery rehearsal

Refs #24. [`scripts/qualify-db-recovery.py`](../../scripts/qualify-db-recovery.py)
rehearses a quiescent synthetic backup and recovery of the V0.2 migration ceiling
5. It creates a new, network-isolated PostgreSQL container and fresh databases;
it accepts no connection string or existing database. Follow the
[database policy](database.md), [native migration procedure](migrations.md), and
[private-storage ownership rules](private-storage.md) for actual operations.

## Run

Prepare the reviewed service vendor inputs with
[`prepare-image-context.py`](../../scripts/prepare-image-context.py). Use a Docker context
reserved for this rehearsal, with the exact local PostgreSQL 17.10 Linux amd64
image already present. The output directory must be new and below `.local/`.

```sh
python3 scripts/qualify-db-recovery.py \
  --context colima-startrack-v02 \
  --image sha256:9b18b78397054fce88a9552e9d5a3ad5bb7fd258c5b3cc1c5028e46373d6ea8f \
  --output .local/v02-db-recovery-9
```

The runner compiles the actual `judge-migrate` command inside the exact Linux
Go 1.26.8 compiler image from `docker/image.lock.json`, with network access
disabled and prepared vendor inputs. It records the binary and copied source
inventory hashes, compiler image identity, PostgreSQL version/image identity,
and every shipped migration/operator-script checksum. The measured executable
and per-input source inventory are retained in the evidence directory for audit.
Temporary build and PostgreSQL containers
are removed on success and failure. It never prints credentials, private object
contents, SQL diagnostics, or server logs.

## Checks

1. Apply migration 1 through the native command. In one guarded transaction,
   retain synthetic automatic license evidence requiring offline review,
   package-source identity, a failed import with rejected-package evidence,
   and a frozen failed publish request. Repeat migration 1, upgrade forward to
   5, and repeat 5. Require the original six tables' rows to remain identical.
2. Register three checksum-addressed private source, normalized-package, and
   rejection-log objects with their real rejected-evidence owner references.
   The bytes are inert authored fixtures; they represent no upstream package
   or legal approval. Stop all fixture writes, produce `pg_dump --format=custom`
   and a coordinated private-object tar archive, and retain both privately.
3. Restore the dump into four new databases with `pg_restore --single-transaction
   --exit-on-error`. Apply the exact provisioning and runtime grant scripts.
   Require native status, all retained rows, ledger/checksums, immutable trigger
   definitions and enabled state, normalized schema/relation/function ownership
   and ACLs, and role/database settings to equal the original snapshot.
4. Corrupt a checksum in one disposable clone and set the dirty flag in another.
   Native `status` and `up` must fail without changing either clone. The original
   database and a separate healthy restore must remain identical. This rehearses
   isolated failure diagnosis and restoration; no failed ledger is repaired.
5. Use working restricted runtime connections, verify the complete private SQL
   logging policy, and reject ledger writes, forged approval, attempt-evidence
   updates/deletes, and DDL. Test restored immutable-row triggers as the schema
   owner and confirm the migration/runtime roles have no administrative powers.
6. Extract the private archive into new directories with fixed content-addressed
   member paths, regular-file checks, exclusive creation, and size limits.
   Require every database object key to resolve to the exact restored SHA-256
   and byte count. Reject a separately corrupted copy and recheck the intact copy.
7. With PostgreSQL statement/duration/transaction logging enabled globally,
   require credential and private-evidence canaries to be absent from server logs.

`report.json` is the bounded shareable result. `database.dump`,
`private-objects.tar`, restored private bytes, the measured executable/source
inventory, and any native/SQL failure logs remain
under the mode-0700 ignored evidence directory; individual backups/diagnostics
are mode 0600. Do not attach them to ordinary Issues, CI logs, or release records.
The separate [offline review ACL qualification](license-review.md) proves a live
fenced migration-5 attempt append and reviewer/runtime mutation denials.

## Recorded development execution

On 2026-10-08, the command above passed in the dedicated `colima-startrack-v02`
Linux VM, driven from the macOS development host. PostgreSQL reported
`17.10 (Debian 17.10-1.pgdg12+1)`; the native compiler reported
`go1.26.8 linux/amd64`. All recovery, immutable history, owner/ACL, private-byte
binding, corruption/dirty refusal, and credential/evidence log-canary checks
passed. The measured native executable SHA-256 was
`52bd9284562b5ce696641669d73ded3fec84ea0a30407b8a9e36b8eec14285fe`.
The bounded report and private audit inputs remain in
`.local/v02-db-recovery-9/`. This is development evidence for the current source
workspace; official release provenance still requires an exact reviewed source
commit and the separate release gates.

## Qualification scope

This finite rehearsal covers native migration upgrade/idempotency and a
coordinated quiescent restore with synthetic private objects. It does not qualify
live service writes, production database recovery, PITR/WAL archiving, a standby,
external SQL proxies/auditors, Backend integration, actual legal judgment, or
Linux sandbox execution. Production backup consistency, encryption/access,
retention, recovery-point/time objectives, and owner-approved incident procedures
remain separate deployment gates in [production guidance](../deployment/production.md)
and [release evidence](../releases/process.md).
