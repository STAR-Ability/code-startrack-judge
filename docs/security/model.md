# Security model

The [active contracts](../contracts/README.md) define protocol details. These invariants apply across releases. The service owns platform problem packages, private tests, package validation, JudgeTasks, and original results. The backend owns users, authorization, business submissions, permanent source code, and public result projections. Judge never receives backend/algorithm database credentials or reads their tables. Backend performs user/role/resource authorization before calling judge; bearer authentication of backend does not make source code or package content safe.

## Trust boundaries

| Boundary | Permitted access | Required protection |
| --- | --- | --- |
| Backend → internal API | Contract DTOs and frozen source copy | Dedicated incoming S2S token, strict schema/size/hash checks, request identity and durable idempotency |
| API/persistent worker → go-judge | Server-owned commands, limits, and minimal per-execution files | Loopback-only low-level endpoint, separate token, process credential separation |
| Root supervisor → trusted service roles | Fixed bootstrap, secrets and component lifecycle | Root0400 fixed secret files, explicit child environments/FDs, immutable ancestors, distinct outer UIDs and final executable nondumpability |
| Nested runtime manager → service roles | No business credential, private file or ancestor-cgroup access | Parent-created locked proc/mask mounts, bounded delegated cgroup mount, independent user/mount namespaces and actual manager escape probes |
| Judge → backend | Existing-task result events | Fixed deployment-owned receiver, distinct outgoing S2S token, durable outbox, no caller URL or redirects to other origins |
| Import acquisition → validation | Pinned permitted repository content | Fixed repository and full commit, checksums, bounded extraction, no network during validation |
| Untrusted executable → host | Per-run input and controlled toolchain | Real Linux namespaces, cgroups, seccomp, filesystem and network isolation, bounded resources |
| Private storage → public DTO | Explicit statement/sample/result fields | Allowlisted projections, never direct package links or hidden-data logs |

The current callback receiver is fixed by the API contract. Deployments use private service networking; no internal API or go-judge port is published to the Internet. The contract uses internal HTTP: traffic crossing an untrusted network needs authenticated encrypted transport at the infrastructure layer and an explicit deployment review, rather than treating bearer tokens as transport encryption.

## Execution

- Treat submissions, reference solutions, input/output validators, checkers, package build steps, and the data they parse as untrusted. Package parsing is bounded and non-executing; execution happens through the reviewed sandbox path. Do not run upstream verification tools on hostile packages in the API process or portable developer environment.
- Use the pinned go-judge runtime and reviewed adapters. Do not replace isolation with ordinary `exec`, rlimits alone, or a handwritten sandbox. Linux execution uses `--no-fallback`; seccomp remains enabled. A failed initialization or failed required isolation probe disables new execution and fails readiness.
- Users choose a supported `languageId`, never shell commands, environment variables, toolchain paths, tests, or limits. Commands and argv come from immutable service-owned templates; do not interpolate user values into a shell. Compiler invocations need isolation and independent CPU/wall/memory/output limits too.
- Each execution sees only its input, work directory, and approved compiler/runtime files. Hidden expected answers are supplied to the isolated checker, not mounted into the contestant process. Deny host root, Docker/container-runtime sockets, host devices, other task directories, host process visibility, and backend source buckets. Prevent child processes and leftovers surviving cleanup.
- Deny contestant network access, including loopback services, other containers, host gateway, DNS, metadata services, and external destinations. Apply resource/concurrency limits to the entire process tree so hostile code cannot exhaust the shared backend/algorithm host.
- The non-root API and persistent worker use only judge-schema/private-storage credentials. go-judge and sandbox children receive no business DB, storage, S2S, SMTP, or cloud credentials; the supervisor must explicitly construct per-process environments and restricted file permissions. Clearing environment variables alone does not protect credentials if sandbox files or host processes remain visible.
- Enumerate actual process listeners and routes. Upstream demo metrics/pprof and runtime diagnostic/configuration routes require an explicit reviewed access policy or removal; the pinned runtime token does not protect all routes. Never expose default debug surfaces in production or assume loopback defeats sandbox network escape. See the [known upstream gates](../upstream/dependencies.md).
- Production does not default to `privileged: true`. Required capabilities and cgroup delegation need a tested host/container profile. Upstream privileged quick-start is permitted only on an isolated disposable qualification host with synthetic data and no production secrets. Never attach an unreviewed PR to a privileged runner.

The implemented supervision boundary and candidate profile are documented in [ADR0007](../adr/0007-supervised-process-and-cgroup-boundaries.md). Startup probes attempt manager-root unmount/proc/private-file/ancestor-control escape in the same nested namespaces before launching go-judge. Sandbox probes measure unique identities, simultaneous PID/network namespaces, private descriptors and files, actual compiler cgroup/seccomp/privilege state, network enforcement, resource limits and cleanup. These produce live-instance readiness evidence; complete release acceptance additionally requires the exact-image verdict/role/adversarial matrix, independent review and recorded host evidence. A supplied image digest is checked against the actual image by the external trusted harness, not self-attested by the container.

The [candidate outer seccomp filter](../../docker/startrack-v02.seccomp.json) is the exact pinned Moby default plus the single `pivot_root` rule required for upstream sandbox initialization. Its [lock](../../docker/security-profile.lock.json) and [license/source evidence](../licenses/moby-seccomp/README.md) distinguish source from derived policy. The capability condition selects the rule when Docker constructs the filter; child executions inherit the outer allow. They must still lack all effective/permitted/inheritable/ambient capabilities and receive the unchanged mature inner filter, with actual prohibited pivot-root/unshare denial. No unconfined seccomp or privileged fallback is permitted.

## Data and imports

Hidden inputs/answers, user stdout/stderr, reference code, checker paths, private object keys, raw execution logs, and credentials never enter public DTOs, ordinary logs, traces, or unrestricted CI artifacts. The public compile-log exception is explicitly bounded, redacted, and authorized by the contract. Keep restricted diagnostics private with access control and a documented retention policy; prefer task/request IDs and diagnostic codes in ordinary logs. Sanitize diagnostic messages from upstream tools before returning them.

Reject archive traversal, absolute paths, escaping symlinks/hardlinks, device files, decompression bombs, excess file counts/sizes, and unexpected executable entrypoints. Preserve immutable original/normalized artifacts and their hashes. Only declared format adaptations are permitted; checker crashes and technical validation failures block publication. A repository license does not grant blanket rights to every imported problem; technical validation and package license evidence are separate publication gates.

Source copies are temporary execution artifacts, not the permanent backend source of truth. Follow the active contract's cleanup policy, protect in-flight tasks, and preserve historical source hashes, task context, package versions, validation evidence, and original results. Retain enough frozen compiler/runtime/template/image metadata to understand past judgments; reproducing source execution also requires the authorized backend source to remain available.

## Credentials and change review

Commit examples with placeholders only. Keep real `.env` files, tokens, credentials, private keys, source dumps, and hidden test corpora out of Git. Inject runtime secrets through operator-controlled secret facilities, scope them per process, redact them from logs, and rotate incoming/outgoing/low-level tokens independently. Never source a caller-supplied environment file in a worker.

Execution-path, privilege/mount, callback/authentication, private-data projection, package extraction, and sandbox dependency changes require an independent security/runtime reviewer plus real Linux regression evidence. A portable green CI run provides no sandbox certification. [Linux validation](../development/linux-sandbox.md) defines the qualification evidence; [release records](../releases/process.md) retain it.
