# Disposable synthetic API import capacity

The fixed `startrack-import-capacity` binary supports the authorized V0.2 Linux
qualification task. It exercises the production import Service and Worker,
ImportPipeline, real adaptation and archives, private Store/Registry, PostgreSQL
problem registration, and production validation coordinator through the private
authenticated scheduler. Its sole source seam creates authored inert byte
snapshots for three fixed cases. Neither the pinned repository identifiers required by the production
adapter nor a successful run establishes Git acquisition or upstream provenance
for these synthetic packages.

The supervisor may launch only these fixed commands under qualification mode:

```text
/opt/startrack/bin/startrack-import-capacity --phase reject
/opt/startrack/bin/startrack-import-capacity --phase validate
```

No stdin, package selector, caller path, command, execution profile, callback,
proxy, or publication option exists. The binary requires Linux UID/GID 20000,
supplementary scheduling group 20002, and the actual `0::/service` cgroup. Its
environment permits only `JUDGE_QUALIFICATION_ONLY=true`, `JUDGE_DATABASE_URL`,
`JUDGE_SCHEDULER_TOKEN`, `JUDGE_PRIVATE_STORAGE_DIR=/var/lib/startrack/private`,
and `PATH`, `LANG`, `TZ`, `HOME`, `TMPDIR`. It rejects other environment keys,
duplicate keys, reviewer credentials, runtime credentials and Backend credentials.
The URL and actual session must identify `judge_runtime` in a disposable database
whose name matches `judge_capacity_[a-z0-9_]+`; embedded migration history must be
clean and exactly level 5. The scheduler client uses the fixed authenticated Unix
socket. Judger and untrusted execution roles receive no database/reviewer keys.

Run the trusted Linux harness from the clean reviewed repository in the reserved
qualification VM. `QUALIFIED_IMAGE` is the measured immutable image reference
and `QUALIFIED_COMMIT` is its clean reviewed source commit:

```sh
sudo python3 scripts/linux-import-capacity.py \
  --image "$QUALIFIED_IMAGE" --expected-commit "$QUALIFIED_COMMIT" \
  --docker-context colima-startrack-v02 \
  --runtime-dsn-file /root/startrack-capacity/secrets/runtime.dsn \
  --reviewer-dsn-file /root/startrack-capacity/secrets/reviewer.dsn \
  --database-ca-file /root/startrack-capacity/secrets/db-ca.crt \
  --evidence /root/startrack-capacity/evidence
```

The database fixture uses an isolated, exact PostgreSQL 17.10 image on the
qualification network, with a fresh `judge_capacity_*` database and separately
provisioned runtime and offline-reviewer roles. Both trusted DSN files are
root-owned `0400`, single-link regular files under immutable trusted parents.
They require `sslmode=verify-full` and the fixed public CA path
`/opt/startrack/db-ca.crt`; client-certificate/key options are rejected. The
harness verifies the root-owned `0444` public CA file and binds it read-only to
that path for the capacity and offline-reviewer containers. The server private
key and CA private key remain in separate operator/database facilities and are
never mounted to API, judger, or untrusted execution processes. Database
provisioning receipts record actual TLS sessions and role privilege denials;
they do not qualify final-image capacity execution.

The three source-authored fixtures have a 2 second CPU limit, 4 second wall limit,
256 MiB memory limit, and the adapter's unchanged execution profiles:

| Case | Actual acceptance target |
| --- | --- |
| `MEMBER_PAYLOAD` | 65,534 original regular files; generated TeX and reserved manifest bring the normalized USTAR to exactly 65,536 regular members and 512 MiB regular payload, including the manifest. Distinct large asset buffers are committed page by page and have distinct checksums. Empty files retain their real metadata and storage registration costs. |
| `SAMPLE_SUPPORTED` | Tiny sample 1 and secret case 2, plus sample 10 with a separately authored 15 MiB input and 15 MiB answer. Both public sample pairs survive adaptation and participate in real validator/reference checks. Persisted public samples and the full normal version-detail HTTP envelope must remain under the 32 MiB response limit. |
| `SAMPLE_HEAVY` | The original 32 MiB sample 10 input and 32 MiB answer remain immutable. After rights approval, the normal pipeline must reject the oversized public projection before technical validation or DRAFT registration, retaining source/normalized archives and structured failure evidence. This is an expected rejection, not supported detail API capacity. |

All fixtures retain a C++ and a Python accepted reference. The Python reference
uses `read().split()`; qualification must establish whether its actual admitted
256 MiB limit suffices. Fixtures also retain authored wrong-answer, time-limit,
and runtime-error examples for mature validation. Limits may not be changed after
admission to obtain a pass. The pinned statement template renders samples 1–9;
sample 10 measures public-view transport/extraction, not rendering large text.

The first phase requires an empty disposable business database, submits one real
job per fixture, and requires three durable automatic `REVIEW_REQUIRED` rights
rejections. Source and normalized archives remain owned by their rejected
evidence. It must invoke no technical validator. The report supplies bounded
receipt identifiers and hashes for a separate trusted operator.

The operator then invokes the existing `judge-admin license-review -config ...
-review ...` interface using root-owned ADMIN configuration and receipts and the
dedicated narrow `judge_license_reviewer` role. Approval must explicitly describe
the authored synthetic fixture and all included assets; it must not claim the
synthetic bytes were acquired from upstream. Exact package/license/archive hashes
and previous/rejected evidence identify the immutable facts being approved. The
API runner cannot insert reviewed approvals or impersonate this operator.

The second phase requires all three retained rights rejections and all three
offline approvals, submits fresh real jobs, and requires `VALIDATED` outcomes
for `MEMBER_PAYLOAD` and `SAMPLE_SUPPORTED`, with selected
`PASSED` validation runs, all five checkpoints, and privately retained exact
program evidence. It streams archive counting and hashing from retained objects;
it verifies distinct durable artifact and validation objects and their owner
references. Successful registration must leave both problems DRAFT, no current
public version, no publication timestamp, catalog version 1, and no snapshot.
The original `SAMPLE_HEAVY` must fail with `PACKAGE_UNSUPPORTED` at `UNSUPPORTED`,
retain the exact approved license and both archives under the new rejection owner,
and have zero technical-validator calls, validation runs, artifacts, or
problem/version registration. The report preserves the original rights-rejection
receipt and `approvedLicenseEvidenceId` separately from `oversizeRejectedEvidenceId`, `rejectionStage`, and
`rejectionCode`. Actual persisted Version DTOs and the authenticated
normal version HTTP route/encoder are measured in process for the two successful
cases, using a generated synthetic request token with no external Backend keys,
listener, or network request. The 30 MiB supported sample view must return HTTP
200 within the complete response budget. This is not network HTTP admission or
the original `judge-service` PID; cgroup accounting describes the occupied API
role budget during this separate fixed qualification process.
The binary never publishes a problem.

The disposable private facility must persist or be completely restored between
phases. A fresh empty tmpfs cannot stand in for retained historical objects.
Qualification uses the supervisor-owned 6 GiB service and 4 GiB runtime cgroups,
10 GiB outer budget, bounded 2 GiB private ext4 facility, and the candidate 2 GiB
workspace with 262,144 inodes. Their actual accounting is collected by the Linux
harness; the binary's archive statistics are not memory or filesystem peaks.

Each phase writes one JSON object of at most 64 KiB to stdout. Schema version 1
has scope `DISPOSABLE_SYNTHETIC_API_IMPORT_CAPACITY`, `syntheticFixture: true`,
fixed phase, pass/failure code, measured role/cgroup, declared limits, and three
bounded case records. Cases contain fixed package identifiers, archive/member/
payload measurements and hashes, receipt identifiers, and validation/DRAFT
evidence, supported detail response measurements, and an explicit expected
oversize-rejection flag. They exclude raw source, hidden data, private object keys, raw tool/SQL
logs, database URLs and credentials. A failed phase exits nonzero with a fixed
code. Startup readiness is bounded to 5 minutes, each job to 30 minutes, and the
whole phase to a 70 minute cancellation context; the supervisor applies a 75
minute external watchdog, because synchronous Adapt and worker drain may extend
beyond context cancellation. Qualification must record watchdog/cleanup failure
as failure rather than treating the context deadline as a measured wall bound.

Focused portable checks cover rejection of broader operator/environment/database
scope and archive corruption, links, duplicate members, cancellation, and byte
size mismatches. They do not establish Linux isolation or real validation. Record
the actual final image, source inventory, environment, phase reports, accounting,
offline receipts and failure evidence with the Linux qualification results. A
capacity pass is narrow synthetic evidence; it does not qualify real upstream
acquisition, live production workload, Backend callbacks, release publication, or
four-service interoperability.
