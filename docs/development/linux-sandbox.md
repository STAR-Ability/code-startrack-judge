# Real Linux sandbox validation

Portable development uses PostgreSQL, mocks, DTO/package parsing, and ordinary tests. Docker Desktop runs a VM; its availability does not certify the host or deployment sandbox. macOS cannot directly qualify Linux isolation. Do not execute submissions, validators, checkers, reference programs, or unreviewed package hooks through an unrestricted portable fallback.

Phase 0 provides a read-only eligibility command:

```sh
./scripts/sandbox-preflight.sh
```

It rejects non-Linux or missing visible production-profile features, checks cgroup v2 `cpu`, `memory`, and `pids` controllers, namespace interfaces, and kernel seccomp metadata. Exit 0 means only that those interfaces are visible. It does not create namespaces/cgroups, install filters, launch go-judge, test delegation, or authorize execution. A restrictive environment can fail inspection even if an operator could later configure it; fix the environment and validate rather than bypassing the gate. Actual isolation verification is planned for the runtime implementation Issues and is not completed in Phase 0.

## Qualification host

Use a dedicated disposable modern Linux host/VM with cgroup v2, supported namespaces/seccomp, controlled toolchain, and operator-reviewed cgroup delegation/capabilities/mounts. Record kernel, architecture, distribution, container runtime, cgroup layout, actual deployment privileges, and image digest. Run the exact pinned go-judge build and server-owned templates used in production, with `--no-fallback` and seccomp enabled. Consult the pinned source/configuration rather than obsolete README claims about defaults; see the [upstream compatibility matrix](../upstream/compatibility-matrix.md).

The V0.2 deployment requires API/persistent worker, supervised demo judger, and go-judge inside the same judge business container. Keep the low-level service on `127.0.0.1:5050` with its own token, without a published host port. Determine a restricted production host/container profile through real tests; Phase 0 does not invent a safe capability set. Upstream privileged quick-start can help characterize behavior on a disposable host but cannot qualify a different unprivileged production profile.

## Required behavioral evidence

Implement tests with synthetic fixtures and expected assertions, then execute them against the actual deployment profile. A checklist or preflight output is insufficient. Preserve a sanitized report tied to the tested commit/image and store sensitive raw logs privately.

| Property | Required test and observation |
| --- | --- |
| Initialization and fail-closed behavior | Missing cgroup delegation, blocked namespace creation, or unavailable seccomp yields unavailable readiness and rejects new execution; no unrestricted fallback |
| cgroups and processes | Confirm each job's effective cgroup and limits, fork/process-tree bounds, and all descendants are accounted and killed; missing controllers cannot be ignored |
| seccomp | Inspect the effective filter mode and attempt controlled prohibited operations; prove denial while required compiler/runtime operations work |
| Namespaces | Verify host processes, IPC, mounts, and adjacent jobs cannot be enumerated or controlled; namespace visibility alone is not proof |
| Filesystem and secrets | Attempts to read host root, sibling job files, private buckets, Docker socket, DB/S2S/cloud tokens, and hidden answers fail; only approved files are visible |
| Network | Attempts to reach loopback API/go-judge, backend/algorithm, host gateway, DNS, metadata and external hosts fail for contestant/validator/checker execution |
| CPU and wall time | Busy loops and sleeping/blocking programs hit distinct limits; process-tree CPU is measured; CPU-ms aggregation follows the contract |
| Memory | Allocation and child-process fixtures hit the frozen limit with correct MLE/IE classification; no host-wide OOM or unrelated-service eviction |
| Output | Infinite stdout/stderr and generated files remain bounded; contestant output excess maps to OLE; raw output stays private |
| Compiler/runtime | Compiler resource abuse is bounded, only advertised installed languages execute, compiler errors map to CE, version/template/digest are captured |
| Validators/checkers/reference solutions | Each runs isolated with explicit limits; checker timeout/crash maps to infrastructure failure, never user WA; preserve expected token/float/case semantics |
| Cleanup and recovery | Consecutive tasks cannot share files/processes; interrupted workers use new fenced attempts; stale processes cannot publish results; final facts never regress |
| Shared-host pressure | At configured concurrency, pathological fixtures cannot starve backend/algorithm; overload rejects safely and preserves persisted tasks |
| Contract acceptance | Real cpp17 AC/WA/TLE/MLE/RE/CE/OLE/IE, callback/restart/idempotency, immutable version execution, and no private-data DTO/log leaks |

Rerun qualification after changes to go-judge, toolchains, kernel/container runtime, capability/mount/delegation settings, limits, or the execution adapter. Keep historical validated profiles and the dates/releases they cover. Readiness must run implementation-specific isolation self-checks and continually detect lost dependencies; the Phase 0 script must never be substituted for them.

## CI separation

Ordinary PR CI runs without privileged access or production secrets. Real sandbox jobs are an explicitly selected trusted commit on an isolated Linux runner, invoked by a maintainer after review; prefer disposable hosts. Do not use `pull_request_target` to execute PR code, and do not let fork PRs or arbitrary branch input reach a privileged self-hosted runner. Pin checkout/action/tool dependencies, give minimal token permissions, remove secrets, retain sanitized evidence, and destroy the test host after qualification. A future qualification workflow must enforce these boundaries before being enabled; no privileged automated workflow is supplied in Phase 0.
