# Durable JudgeTasks and recovery

Issues #18 and #17 implement JudgeTask persistence in `internal/persistence/tasks`
and the bounded scheduler in `internal/tasks`. The active
[task contract](../contracts/v0.2/clarifications.md#q-004-initial-execution-recovery-and-fencing)
governs the state machine; [database policy](database.md) governs retained facts.

Admission serializes request and submission identities, resolves an accepted
replay before mutable eligibility checks, locks the current published problem,
qualified version/license and active language configuration, then consumes a
verified private source registration. QUEUED, the frozen execution configuration,
the source owner reference and the complete revision-one callback commit together.
Rejected admission reserves no request/submission identity. Execution templates,
compiler limits and source filename must equal the pinned runtime profile.

Each scheduler slot reserves one task in a short `FOR UPDATE SKIP LOCKED`
transaction. Initial dispatch has recovery count zero. Expired DISPATCHING or
RUNNING reservations receive a fresh token and counts one through three. Recovery
retains the first start and all accepted inputs, and creates another visible
revision and callback even for DISPATCHING to DISPATCHING. Exhaustion atomically
produces FAILED/IE with nonretryable `JUDGE_INTERRUPTED` and its final event.
Deadlines, final timestamps and expiry checks use PostgreSQL time.

RUNNING is persisted through the runtime's error-returning acknowledgement before
compilation. Heartbeats renew a strictly live matching token every 30 seconds to
180 seconds without changing public timestamps/revision. Every write locks the
task before evaluating its deadline; expiry during a lock wait cannot resurrect
an owner. Ambiguous runtime transport failures stop heartbeat and await a fresh
counted reservation. The runtime's persistent dispatch ledger independently
rejects duplicate execution of one token. Ordinary TLE is a completed user result.

Case facts remain private attempt data until the final transaction. The reducer
verifies frozen order and identities, computes actual AC count, frozen total and
maximum executed-case CPU/memory, uses ceiling nanoseconds-to-milliseconds, and
selects the first user failure in manifest order. Definitive infrastructure failure
produces FAILED/IE while preserving available case facts. CE has null resources;
unexecuted cases are SKIPPED. Score stays null. Public compilation/error messages
are generated from bounded diagnostics and never copy raw tool logs.

Final task, immutable result, immutable cases, JCS result hash and exact callback
snapshot/hash commit together. Migration `000002` checks each case against the
original result transaction and frozen artifact/ordinal with indexed lookups,
preventing late appends while avoiding a full case scan per insertion. Full
aggregate constraints still run for task/result/event changes. Result insertion
uses the same top-level SQL transaction as cases; result creation inside an
independent SQL savepoint is not an adapter API.

Shutdown stops acquisition immediately and drains accepted attempts for a bounded
grace period before cancelling their runtime requests. Source cleanup is owned by
the private-object registry: only terminal, expired copies are released; public
task timestamps/revision and retained hashes/results/events stay unchanged.
An internal task-worker panic instead stops acquisition and cancels peer attempts
immediately. Their uncertain leases remain available only for counted recovery;
the healthy operator-stop grace period never delays this abort. The application
retains a fixed worker failure even when operator cancellation occurs concurrently,
and waits for workers before deciding its final exit status or closing resources.
A true fault or panic in another application worker closes a private fatal-stop
gate, which stops task acquisition and cancels detached attempts even during
operator grace. A lease reserved before that gate closes remains for natural
counted recovery. Guards reject late source, execution and progress responses
before starting new persistence calls; progress writes also retain the attempt's
cancellation when the runtime supplies a detached context. In-flight database
work still follows context handling and the live-token/deadline fences; the gate
does not undo committed transactions. Expected operator cancellation leaves this
gate open and preserves healthy drain. This does not establish the live
supervisor drain; that requires separate Linux validation.

Portable verification uses mocks for runtime execution. Actual PostgreSQL suites
require a private `JUDGE_TEST_ADMIN_DSN_FILE` and create disposable scoped databases
through `internal/testutil/postgres`; they test admission races, atomic source
pin/outbox, replay after withdrawal, invalid-case rollback, ordinary TLE,
initial-plus-three recovery, stale/expired owners including lock waits, late CE
case rejection, case-before-result commitment and a 4,096-case batch. Synthetic
qualified package fixtures are explicitly repository transaction evidence. They
do not qualify a Linux sandbox, compiler image, private IPC boundary or adversarial
execution profile; those remain separate runtime acceptance evidence.
