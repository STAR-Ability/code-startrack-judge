# Persistent synthetic Linux service-flow qualification

The fixed [host harness](../../scripts/qualify-linux-service-flow.py) supplies the
remaining real-runtime seam for Issues [#17](https://github.com/STAR-Ability/code-startrack-judge/issues/17)
and [#22](https://github.com/STAR-Ability/code-startrack-judge/issues/22). It runs the
unchanged normal supervisor, API, persistent workers, authenticated private
scheduler, judger and pinned sandbox in the same reviewed immutable image.
Only a fixed synthetic callback ACK receiver substitutes for an external service.

Run it after the complete reviewed Linux matrix and all three
[import-capacity cases](import-capacity.md) succeed against that exact clean
commit/image. The release/environment owner executes Docker and lifecycle work
on the reserved trusted Linux VM; no parallel image/context owner is introduced.
This is disposable qualification, not production deployment or real Backend
acceptance. Its public report always retains `qualified:false` and
`realBackendAccepted:false`.

```sh
sudo python3 scripts/qualify-linux-service-flow.py \
  --image "$QUALIFIED_IMAGE" --expected-commit "$QUALIFIED_COMMIT" \
  --docker-context default \
  --capacity-evidence /root/startrack-capacity/evidence \
  --runtime-dsn-file /root/startrack-capacity/secrets/runtime.dsn \
  --database-ca-file /root/startrack-capacity/secrets/db-ca.crt \
  --evidence /root/startrack-capacity/service-flow
```

The source checkout and image source inventory must be clean and match the
expected commit. `default` selects the reviewed Linux host's local Docker daemon
and accepts only the official repository's immutable image reference. The dedicated
`colima-startrack-v02` diagnostic context also accepts `startrack-qualified-candidate`;
both contexts require the same clean source, exact image, cgroup v2, four CPUs and
at least 15 GiB daemon memory. A context selection supplies no host eligibility
or security approval. The fixed `startrack-v02-integration_default` network,
retained capacity database and private bridge port 8081 must already belong to
the isolated qualification facility. Capacity receipts must record success, cleanup and the retained
root-owned 2 GiB ext4 backing file. The harness copies and verifies that detached
file into its new private facility before mounting it with `nosuid,nodev,noexec`;
the original capacity filesystem remains unchanged. It continues the same
disposable `judge_capacity_*` database and never reruns migrations or accepted
backup/restore drills. The initial database must still have six import jobs,
two unpublished versions and no JudgeTasks/results/outbox rows. It is a one-shot
continuation; a failed attempt requires an explicit fixture recovery decision.

Runtime credentials retain the reviewed root-owned `0400` file policy and
`sslmode=verify-full` with the fixed public CA. No reviewer/administrator credential
is supplied to any service or SQL client. A transient utility container uses the
already reviewed exact PostgreSQL 17.10 digest and runtime role for bounded
read-only queries. Its DSN crosses stdin into a scoped process environment, never
command arguments, Docker configuration, public JSON or normal diagnostics.
All workload/container settings preserve the reviewed Linux profile.

The fixed ACK receiver listens only on the private qualification bridge gateway
at port 8081. The Judge container maps the fixed `backend` name to that facility;
the production callback URL and `callbacks.Client` remain unchanged. The receiver
authenticates its independent synthetic token, validates complete event/task
identity and canonical fixture bytes, preserves duplicate identities and rejects
conflicts. It follows the current Judge ACK request-ID echo profile. Q-010 and real
Backend canonical/inbox/projection acceptance remain joint owner gates under
[#19](https://github.com/STAR-Ability/code-startrack-judge/issues/19) and
[#23](https://github.com/STAR-Ability/code-startrack-judge/issues/23).

The harness first reads the actual approved `MEMBER_PAYLOAD` DRAFT through normal
authenticated HTTP, then explicitly publishes that version and obtains its full
`PLATFORM/startrack` ProblemRef from the response. It creates a normal catalog
snapshot. Offline ADMIN rights approval remains the separate preceding capacity
operator action; publication supplies no new legal rights.

Fourteen persistent tasks exercise these finite cases:

| Cases | Required observed facts |
| --- | --- |
| AC, WA, CE, CPU TLE, wall TLE, MLE, OLE, RE | Normal HTTP admission, production task worker/scheduler/judger execution, expected actual verdict, frozen image/source/version, two ordered original case rows with stopping/SKIPPED semantics, resource aggregation, result hash, terminal task/result/case transaction and matching terminal event. |
| Three concurrent bounded AC programs | Exactly two RUNNING tasks and one QUEUED task at the production two-slot worker boundary, followed by three complete results. This is a scoped worker observation, not four-service host-capacity qualification. |
| One interrupted AC program | Stable actual contestant-process observation, abrupt whole-container stop, original process generations gone, retained source and nonterminal task without partial result/cases, natural lease expiry, new counted fence, unchanged source/version/configuration/first start, actual recovered execution and one terminal result. |
| Four interrupted attempts | The initial reservation and exactly three recovery executions receive distinct observed fences and greater revisions. After the last natural expiry, the unchanged worker finalizes FAILED/IE with nonretryable `JUDGE_INTERRUPTED`, without a fifth dispatch. All original case rows are SKIPPED. |
| One task during graceful stop | A stable native contestant and live unchanged task fence are observed before `SIGTERM`. The normal supervisor must exit0 within the 120-second external stop budget, revoke qualification and settle all observed original process generations and the held original cgroup. The task either completes AC during drain or retains its unchanged nonterminal fence/source for one natural counted recovery. A seventh normal start must preserve the original frozen task facts and deliver the retained event identities. |

CPU, wall, memory and output limits stay frozen at the authored package profile.
The memory fixture commits shared file mappings in three separate 128 MiB files,
each below the inherited file-size ceiling; it must produce actual MLE without
raising any limit. Every interruption follows a stable actual `main` process
witness rather than treating the earlier Compiling/RUNNING acknowledgement as
proof of contestant execution. Database clocks/lease deadlines are never edited.
The one-hour harness watchdog interrupts work into cleanup; individual HTTP,
utility, readiness and task waits also have finite limits.

Every normal start binds the root-owned structural `process-boundary.json` to
the exact image and current host boot, alongside the runtime measurement and
isolation observation hashes. Its API/judger denial/control facts must match the
supervisor's actual report. The trusted Linux host then maps the two fixed roles
through Docker's host PID list, exact UID/GID tuples, container `NSpid`, start ticks,
process name and PID namespace. API supplementary groups must be exactly `20002`;
judger supplementary groups must be empty. Both must retain zero effective,
permitted, inheritable and ambient capabilities and `NoNewPrivs=1`. These numerical
credential facts are rechecked with every sample and retained in each receipt.
Held `/proc` directory descriptors preserve the
observed generations; missing, changed or unreadable required facts fail the run.

The host observer samples only numerical `status` and `smaps_rollup` RSS/PSS,
high-water RSS and swap fields at 250 ms intervals throughout the normal task
load, concurrent tasks and natural recovery waits. It never reads process
environments, command lines, memory or credential-bearing FD targets. It discards
the `smaps_rollup` address header and records only numerical fields.
Root privileges belong to the external qualification observer; no container
capability, image binary, process credentials or workload limit changes.

The inspected supervisor belongs to the `service` leaf. The observer derives its
outer parent and holds the original outer/service/runtime cgroup directory
descriptors before load. It verifies service membership and fixed 10/6/4 GiB
memory budgets with zero swap, then records bounded before/after current/peak
memory, hierarchical and local event counters and nonnegative event deltas through
those same descriptors. Service OOM events and parent local OOM events fail the
run; hierarchical runtime/outer events may contain the authored contestant MLE.
Each of the seven container generations ends with a live sample before its authored
kill or graceful stop and a hashed private memory receipt. Per-process HWM is
per generation; kernel peaks cover the original cgroup lifetime, including
startup. Sampled RSS/PSS maxima describe the observed load and are not absolute
peaks or four-service co-location evidence.

For each task, a duplicate POST and by-request lookup preserve the one accepted
identity. The AC terminal callback loses one ACK; the WA terminal callback receives
one invalid correlated ACK. Both must retry the exact event/hash and become
DELIVERED through the real dispatcher. Every revision has the expected persisted
state sequence and a matching acknowledged event. Success has exactly 14 tasks,
14 original results and 64 retained delivered events when the live task completes
during drain, or 66 when it uses one fresh counted recovery. The recovery path
uses the authoritative post-stop lease expiry; healthy drain may have renewed its
private heartbeat without changing the visible revision. Original result/case
transaction IDs match; accepted database constraints and the reused failure tests
establish the atomic outbox boundary rather than a new destructive SQL fault.
Judger spool directories must be empty after completed groups.

The normal withdrawal endpoint then rejects fresh admission without creating a
task, preserves complete historical statement/samples/license content, and permits
accepted-request replay. A normal fresh publication restores the unchanged
approved version for later external integration. No immutable facts are rewritten.

The sixth normal generation receives the live task and stops through Docker's
fixed `SIGTERM`/120-second budget. A trusted host witness positively binds the
supervisor, runtime manager, API and judger process generations before signalling,
and holds the original outer cgroup directory until settlement. Exit status must
be exactly0, with no OOM flag; both the qualification record and its temporary
record must be absent, including symlinks. All observed generations must be gone
and the original cgroup empty or removed. A forced stop, deadline, denied kernel
read or retained process fails the gate. Forced resource removal in final cleanup
cannot supply successful shutdown evidence.

After restart, the completed task's terminal revision/result/cases cannot change.
An incomplete task retains its original source and fence until natural lease
expiry, then requires one fresh recovery fence and actual contestant execution.
Both outcomes finish AC under the unchanged limits. Post-stop outbox identities,
hashes and statuses are retained, then checked against delivered events after
restart. `pendingEventsObserved` reports whether any delivery was actually pending
across stop; a zero count supplies no such pending-delivery claim. The seventh
generation then performs a separate quiescent graceful stop with the same exit,
revocation and cleanup proof. Neither shutdown fixture claims a positively
witnessed in-flight recurring qualification probe; that overlap remains a
separate Linux acceptance gate.

These fixtures are authored requirements, pending execution against an eligible
Linux host and the exact final image. Portable receipt/refusal tests provide no
evidence that the 120-second budget, live drain or natural recovery has passed.

Combined acceptance reuses all five actual-PostgreSQL
[portable acceptance fixtures](acceptance.md), including lost POST/by-request,
callback-before-binding, reordered/conflicting events, frozen publication/history,
stale-owner writes, transaction failure, source cleanup and operator replay.
The report binds those fixture source hashes to the image commit. It does not
rerun their accepted PG scenarios, 24-hour retry clock, migrations or four
quiescent restores. The real matrix/capacity reports, this receipt, exact-source
portable/PG checks and independent review must be assessed together; this harness
alone does not close all #17/#22 criteria. New source-canary and exact public DTO
allowlists complement the broader reused portable privacy fixtures.

Public `service-flow.json` is at most 64 KiB and contains only structural facts,
public task/receipt IDs, hashes and bounded measurements. It excludes source,
hidden bytes, object keys, raw SQL/tool logs, DSNs and credentials. The new private
facility, generated root-owned secrets and runtime evidence remain under the
root-only `private/` directory for controlled continuation/evidence review.
Container, receiver, mount and loop-device cleanup is mandatory; any failure
keeps `serviceFlowPassed:false`. Original capacity backing bytes and the retained
PostgreSQL instance remain available. The receipt supplies normal service-process
memory evidence for independent final review; real Backend #23 and four-service
release #24 remain separate gates. Production
publication and deployment remain deliberate future operator actions.
