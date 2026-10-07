# Independent Judge control-flow acceptance

Refs [#22](https://github.com/STAR-Ability/code-startrack-judge/issues/22). The
[published API](../contracts/v0.2/api.md),
[database contract](../contracts/v0.2/database.md), and
[accepted clarifications](../contracts/v0.2/clarifications.md) govern the tests.

`cmd/judge-service/acceptance*_test.go` combines actual authenticated HTTP routes,
domain services, private filesystem storage and its PostgreSQL object registry,
import/task repositories and workers, catalog snapshots, and the transactional
outbox dispatcher. Each fixture creates a disposable database, applies the
complete shipped migration chain, and uses an isolated runtime role. No external
Backend tables, submitted-code execution, or algorithm service is used.

## Reproduce

Provision the disposable development PostgreSQL described in
[getting started](getting-started.md). Store its administrator DSN in a private
file and supply an **absolute** filename; do not print the DSN or put credentials
in command arguments. The administrator connection is used only to create and
remove isolated test databases/roles and inject explicit operator faults.

```sh
JUDGE_TEST_ADMIN_DSN_FILE="$PWD/.local/v02-postgres-admin.dsn" \
GOTOOLCHAIN=local .local/toolchains/go1.26.8/go/bin/go test -race \
  ./cmd/judge-service -run TestPortableAcceptance -count=1 -v

GOTOOLCHAIN=local PATH="$PWD/.local/toolchains/go1.26.8/go/bin:$PATH" make check
```

Without a private administrator connection the PostgreSQL acceptance tests skip;
a skipped test is not acceptance evidence. Ordinary portable checks remain useful
but must be reported separately from the actual database run.

## Covered flows

| Fixture | Actual behavior exercised |
| --- | --- |
| Import and publication | Fixed-source import retains automatic `REVIEW_REQUIRED` evidence without running programs; runtime credentials cannot forge approval; a dedicated narrow offline reviewer appends trusted `ADMIN` evidence; a new request reuses exact approved bytes, runs the real validation coordinator/journal, registers `DRAFT`, explicitly publishes, snapshots the version, and judges a task from it. The original failed import remains unchanged. |
| Lost POST and verdicts | The admission response is lost after commit and a callback arrives before response binding; by-request recovers the one task and replay preserves it. AC/WA/TLE/MLE/RE/CE/OLE/IE facts pass through the real worker and atomic result transaction. Reversed, duplicate and older callbacks preserve the latest mock projection; same-revision conflicts are rejected. |
| Frozen history and recovery | Metadata publication and withdrawal preserve an accepted version and its snapshot/history; fresh withdrawn admission fails. An ambiguous executor failure leaves recoverable work; a restarted worker receives a new lease and identical frozen source/identity/limits/cases. Stale heartbeat and completion fail; immediate cleanup preserves in-flight and newly terminal source. Accepted replay survives runtime unavailability. |
| Callback failures and reconciliation | Unknown mapping, authentication failure, conflict, invalid ACK, delayed ACK and lost ACK retain the original event/hash. Restart and stale completion are fenced. Delivered events cannot regress. Manual replay rejects a younger event; a separately seeded historical task/event is inserted once with its old timestamps, using actual Registry source attachment and all immutable triggers. Automatic expiry and audited manual delivery preserve that original event. |
| Final transaction failure | Revoking case-result insertion from the isolated runtime role rolls back result, case facts, terminal task state and terminal event together. Restored privileges and fresh fenced recovery complete the same task. |

Public response/event/error and normal-log checks reject synthetic source, hidden
input/answer/reference, private tool-log/path/object-address and credential
canaries. Public statement, sample, attribution and complete `license.sourceUrl`
remain available. A definitive infrastructure IE overrides earlier WA while
retaining observed case facts; CE and other verdicts follow their own result
invariants.

## Mock boundaries and independent evidence

The package source, mature verifier, execution engine and Backend inbox are
explicit test-only mocks. Synthetic validation `PASSED` rows belong only to the
disposable database; they qualify coordinator persistence/control flow and do
not grant legal rights or production runtime qualification. Verdict fixtures do
not prove compiler, checker, Linux isolation or real sandbox behavior.

The Backend fixture stores only expected dispatch references and public callback
projections. Its sender invokes an HTTP handler through a test recorder; this
integrated suite does not use the production `callbacks.Client`. Its fixed URL,
authentication and ACK behavior complement the production transport/worker
tests in `internal/callbacks`. Real PostgreSQL original-deadline/backoff,
operator-role privilege denial and interrupted replay tests are in
`internal/persistence/outbox`; expired terminal-source cleanup and GC ownership
races are in `internal/storage`. See [callback delivery](callbacks.md),
[task persistence](tasks.md), [private storage](private-storage.md), and
[offline license review](license-review.md).

Actual Linux qualification must follow [the Linux sandbox guide](linux-sandbox.md)
and be linked to its exact environment/image in the
[compatibility record](../upstream/compatibility-matrix.md). Portable acceptance
does not satisfy that gate. Real Backend integration and final image/release
acceptance remain [#23](https://github.com/STAR-Ability/code-startrack-judge/issues/23)
and [#24](https://github.com/STAR-Ability/code-startrack-judge/issues/24).

On 2026-10-08, all five `TestPortableAcceptance` tests passed with Go 1.26.8
`-race` in 16.387 seconds, driven from macOS x86_64 against PostgreSQL 17.10 in
the isolated `colima-startrack-v02` development environment. This records the
actual database/control-flow run; it is not a deployment or Linux sandbox
qualification record.

At clean Backend commit `318b84170860b6e4ca6931712554474a531acfcb`, its existing
`SubmissionPipelineTest` and `JcsTest` also passed on 2026-10-08: 12 tests,
zero failures/errors/skips, using Java21.0.4, Maven3.9.16 and disposable embedded
PostgreSQL16.2. The four handler fixtures run real session/callback filters,
Submission persistence, dispatch, inbox/projection, training and analysis enqueue
through Spring MockMvc. Judge and Algorithm clients are Mockito substitutions.
This separate consumer test does not supply live-service integration or owner
approval; the precise canonical divergences and remaining gates are recorded in
the [compatibility matrix](../upstream/compatibility-matrix.md#real-backend-consumer-evidence).
