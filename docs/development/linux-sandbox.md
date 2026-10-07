# Real Linux sandbox validation

Portable development uses PostgreSQL, mocks, DTO/package parsing, and ordinary tests. Docker Desktop runs a VM; its availability does not certify the host or deployment sandbox. macOS cannot directly qualify Linux isolation. Do not execute submissions, validators, checkers, reference programs, or unreviewed package hooks through an unrestricted portable fallback.

The read-only eligibility command remains available:

```sh
./scripts/sandbox-preflight.sh
```

It rejects non-Linux or missing visible production-profile features, checks cgroup v2 `cpu`, `memory`, and `pids` controllers, namespace interfaces, and kernel seccomp metadata. Exit 0 means only that those interfaces are visible. It does not create namespaces/cgroups, install filters, launch go-judge, test delegation, or authorize execution. A restrictive environment can fail inspection even if an operator could later configure it; fix the environment and validate rather than bypassing the gate.

Issues #20/#21 add the fixed supervisor, actual sandbox measurement producer, offline image builder and synthetic Linux qualification launcher. Their presence does not establish production qualification. The candidate profile in [ADR0007](../adr/0007-supervised-process-and-cgroup-boundaries.md) remains proposed until the complete behavioral, capacity and independent review gates pass.

On a trusted Linux amd64 root runner, with the reviewed repository and an already verified immutable image available, run:

```sh
python3 scripts/linux-qualify.py \
  --image ghcr.io/star-ability/code-startrack-judge@sha256:<digest> \
  --expected-commit <40-hex-reviewed-commit> \
  --docker-context default \
  --evidence artifacts/linux-qualification/<fresh-run>
```

The launcher verifies the actual image digest/platform and clean release source inventory, loads the exact AppArmor policy and checks its bytes against the image, supplies independent synthetic root0400 credentials, and tests the no-capability failure baseline before the explicit candidate profile. The supervisor measures the actual sandbox and starts only the fixed matrix binary as UID20001 in its service cgroup. Matrix credentials use stdin; the process inherits a scoped environment. Retained cgroup directory descriptors remain root-only and CLOEXEC so accounting covers the actual service/runtime/outer limits and peaks. The matrix has a finite fifteen-minute bound. Bounded raw synthetic diagnostics are retained separately under the root0700 `private/` evidence directory; public JSON contains structural observations and artifact digests.

The candidate requires cgroup v2, at least four visible CPUs and at least15GiB measured host memory. The configured maxima are10GiB outer,6GiB service,4GiB runtime, swap0, and2GiB `/run` and `/w` tmpfs. Maximum-package and parallel-statement measurements must demonstrate these budgets before they become qualified capacity. The launcher reports `qualified:false` while any acceptance gate remains outstanding, even when its runtime checks pass. Local diagnostic candidates may use only the dedicated `colima-startrack-v02` context; dirty diagnostic source and edited binaries must never be presented as release provenance.

## Qualification host

Use a dedicated disposable modern Linux host/VM with cgroup v2, supported namespaces/seccomp, controlled toolchain, and operator-reviewed cgroup delegation/capabilities/mounts. Record kernel, architecture, distribution, container runtime, cgroup layout, actual deployment privileges, and image digest. Run the exact pinned go-judge build and server-owned templates used in production, with `--no-fallback` and seccomp enabled. Consult the pinned source/configuration rather than obsolete README claims about defaults; see the [upstream compatibility matrix](../upstream/compatibility-matrix.md).

The V0.2 deployment requires API/persistent worker, supervised judger, and go-judge inside the same judge business container. Keep the low-level service on `127.0.0.1:5050` with its own token, without a published host port. Qualify the exact restricted candidate profile through real tests. A different privileged profile provides no acceptance evidence for this candidate.

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

Ordinary PR CI runs without privileged access or production secrets. The [Linux qualification workflow](../../.github/workflows/linux-qualification.yml) selects a reviewed immutable commit/image on an isolated trusted runner. Do not use `pull_request_target` to execute PR code, and do not let fork PRs or arbitrary branch input reach a privileged self-hosted runner. Pin checkout/action/tool dependencies, give minimal token permissions, remove secrets, retain sanitized evidence, and destroy disposable test hosts after qualification. Ordinary checks and image publication do not satisfy the production qualification gates.
