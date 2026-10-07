# ADR 0007: Supervised process credentials and delegated runtime namespaces

- Status: Proposed
- Date: 2026-10-08
- Accountable roles: Judge service owner; independent security/runtime reviewer
- Related contract/Issue: [v0.2 contracts](../contracts/README.md), implementation Issues #20 and #21
- Supersedes / superseded by: none

## Context

The platform allows one judge business container. The non-root API/worker owns private judge storage and business credentials; the judger adapter owns dispatch and low-level runtime credentials. Untrusted compilers, submissions, validators, checkers, reference solutions and statement renderers must execute through pinned go-judge. Sharing the outer container filesystem and process environment without an enforced boundary would expose private files or service process memory.

The tested baseline private Docker cgroup namespace reports `/`; pinned go-judge rejects an empty cgroup prefix. An outer root helper is needed for container-local cgroup delegation and upstream namespace setup. A supervisor's pre-exec nondumpability does not protect final executables because exec resets that setting. The selected AppArmor-enabled Linux guest also rejects upstream read-only remount flags containing propagation flags, requiring the independently reviewed narrow go-sandbox patch.

## Decision

Use a fixed root PID1 supervisor for bootstrap and component supervision only. API/worker runs as UID20000, judger as UID20001, with scheduling socket group20002. Fixed root-owned0400 secret files have independent credentials. Root PID1 rejects ambient credential variables and constructs each child's environment explicitly. Final credential-bearing executables set and verify Linux nondumpability before consuming credentials.

Inside the private container cgroup root create separate service and runtime subtrees. Keep runtime ancestor resource maxima root-owned; delegate only the bounded runtime subtree to outerUID30000. Bind that subtree over `/sys/fs/cgroup` before entering a new user namespace, preventing the manager from unmounting it to reveal the service sibling. The trusted runtime-init PID1 helper enters user/PID/mount namespaces, waits until the supervisor assigns its cgroup, creates a cgroup namespace and a nonempty `/manager` subgroup, then mounts its private proc view and masks business facilities.

Launch actual pinned go-judge inside a second user and mount namespace with an identity mapping relative to the helper. Proc and masks created by the more privileged parent become inherited locked mounts. The helper receives only the runtime token and supervises go-judge; it never runs package or submitted code. A fixed trusted startup fixture attempts manager-privilege unmount, proc, secret and cgroup-control escape before go-judge starts. Pinned go-judge alone creates the mature inner sandbox and executes all untrusted programs.

Across the trusted inner init's exec retain namespace-scoped `CAP_SETPCAP` in addition to upstream's `SYS_ADMIN` and `SYS_RESOURCE`, through an exact [vendored patch](../../patches/go-sandbox/0002-namespace-init-securebits-capability.patch). This permits upstream's existing securebits transition under inherited `no_new_privs`; it does not expand the eight outer capabilities or AppArmor policy. Keep mature child `DropCaps`: zero effective/permitted/inheritable/ambient sets, securebits locked at47, and `no_new_privs`1, with the namespace-scoped bounding set measured. Qualification must prove capability regain, securebits unlock, mount, pivot-root and new user/network namespaces are denied. A separate [Linux ABI correction](../../patches/go-sandbox/0003-complete-capability-v3-buffer.patch) supplies both zero words required by capability ABI v3 at each existing capability-removal syscall; it preserves that policy.

Use no fallback, enabled seccomp, private runtime REST on127.0.0.1:5050, no host port, a read-only outer filesystem, explicit writable facilities, no privileged mode and exactly the reviewed outer capability set in the [candidate AppArmor profile](../../docker/startrack-v02.apparmor). Linux grants full capabilities within the manager's nested user namespace, mapped to outerUID30000; empirical ancestor/mask denial must prove that these confer no parent authority. Docker29.5.2's measured Moby seccompv0.2.3 default denies the mature sandbox's required `pivot_root` before installing its inner filter. The [derived candidate outer filter](../../docker/startrack-v02.seccomp.json) retains all33 original rules and appends only `pivot_root` allow when Docker constructs the profile with outerCAP_SYS_ADMIN; that condition is evaluated at construction, not on each syscall. The [lock and exact provenance](../../docker/security-profile.lock.json) bind its source and sole delta. Untrusted child pivot-root denial by the unchanged inner filter and kernel remains mandatory.

A root producer performs actual sandbox probes and publishes a bounded structural measurement bound to actual go-judge PID/start ticks, boot ID, image identity, toolchain/checker bytes and enforced profile. Readiness consumes fresh evidence and fails closed on missing, stale, mismatched or failed evidence. Component or qualification failure clears evidence and stops the container. The candidate finite budgets are4GiB runtime,6GiB service,10GiB container,2GiB `/run` and2GiB per sandbox workspace; actual maximum-package/live-copy/materialization and parallel-statement accounting must pass before capacity is qualified.

The explicit synthetic qualification mode starts only a fixed matrix executable as UID20001 after the first fresh measurement. It inherits the supervisor's service cgroup, scoped environment and a bounded stdin credential envelope. Root keeps CLOEXEC accounting directory descriptors across the runtime bind and records actual outer/service/runtime resource maxima, peaks and events. A finite fifteen-minute matrix bound and separate root-only bounded diagnostic retention make failed qualification reviewable. The trusted launcher loads the exact reviewed AppArmor policy, verifies image equality, and records host eligibility; an enforce-mode policy name alone cannot establish loaded-policy provenance.

## Reasons

Distinct outer identities and immutable parent-owned masks protect business facilities even under manager compromise. Namespace ownership prevents the nested manager from mounting an outer proc view. The delegated mount and root-owned maxima prevent the manager from widening its resource budget or controlling service cgroups. Explicit environments, descriptors and final executable hardening complement filesystem protection.

## Consequences

The profile needs modern Linux, cgroupv2, namespaces, seccomp, a named AppArmor policy and empirical qualification. SYS_ADMIN remains an outer bootstrap capability and is not a blanket production security approval. Container/image/kernel/runtime changes require new qualification. OCI image equality must be established externally; a process cannot independently prove the digest of its containing image. Ordinary CI and successful image builds do not provide security acceptance. The profile remains proposed until the complete adversarial matrix and independent findings pass; no production release or deployment is implied.

## Alternatives

Privileged default, an unrestricted fallback, a fifth business container, and rewriting mature sandbox execution violate the established boundaries. A single manager user namespace leaves helper-created masks removable by manager root. A supervisor-only pre-exec dumpability setting fails across exec. Ambient shared-container secrets expose credentials to unrelated processes.

## Revisit / upgrade conditions

Revisit with the service/security owners when upstream no longer requires root mapping or outer bootstrap capabilities, when hosting supports narrower native delegation, or when the platform business-container contract changes. Preserve upstream patch provenance and rerun mount/write-denial, namespace, process-memory, descriptor, network, limits, cleanup and actual runtime verdict tests before accepting an upgrade.
