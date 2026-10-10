# ADR 0005: Reuse the pinned sandbox and qualify security on Linux

- Status: Accepted
- Date: 2026-10-07
- Accountable roles: repository lead; judge/runtime, security and deployment owners
- Evidence: [API contract](../contracts/v0.2/api.md) §8; [database contract](../contracts/v0.2/database.md) §§10/12/14

## Context

Submitted code and imported execution tools are untrusted. Portable developer environments and ordinary Docker containers do not prove cgroup/seccomp/namespace isolation. Rewriting security-critical isolation or exposing the demo's raw commands/answers would add avoidable risk.

## Decision

Reuse pinned go-judge `v1.13.0` and the pinned demo's execution/progress protocol behind Code Startrack-owned safe adapters. Separate upstream source/provenance from owned integration. Real execution uses Linux with verified cgroups, enabled seccomp, namespaces and resource/filesystem/network isolation; require `--no-fallback`. Use explicit mocks for portable work. Missing security capability fails readiness and stops new execution.

V0.2 has one judge business container with supervised runtime components, a nonroot API/worker, and localhost-only bottom-level execution API using its own token. The production profile must prove restricted capabilities/mounts and credential separation on the actual Linux target; privileged Docker is only an isolated upstream test method, not a production default.

## Reasons

Mature upstream isolation reduces the amount of security-critical code the team owns. Distinct portable and Linux validation gates keep development convenient without turning incomplete isolation into accepted production behavior.

## Consequences

Sandbox tests must include CPU/wall/memory/output limits, compiler/runtime separation, no network, no hidden filesystem access and cleanup. Validators/checkers/reference programs follow the same untrusted-code model. No Docker socket, host-root mount, backend-source credentials, business database credentials or S2S secrets enter execution. Process supervision/environment separation within the single container requires measured proof; documentation alone does not establish readiness.

The demo's default gRPC endpoint differs from the contract binding; settle [Q-008](../contracts/open-questions.md#q-008--bottom-level-transport-and-binding-reconciliation) before runtime wiring. Audit upstream logging as well: pinned go-judge startup configuration/auth logging can disclose its token. Verify safe logging configuration or a minimal provenance-tracked redaction patch before real deployment.

## Alternatives

Unrestricted `exec`, rlimit-only fallback, custom isolation, or generic hosted CI as security proof are not authorized. Replacing the sandbox requires explicit architectural/security review, not a convenience refactor.

## Revisit / upgrade conditions

Upstream sandbox/security updates, host-kernel changes, deployment capability changes or new languages require renewed security/license review and real Linux regression. Preserve task/runtime version provenance and never roll a floating `latest` image into historical execution.
