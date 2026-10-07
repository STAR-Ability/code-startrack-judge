# Implementation workstreams

Phase 0 stops at an engineering foundation. This plan organizes the first implementation milestone, **V0.2 Judge & Problem Service**, under the [active contract](../contracts/README.md). It is not evidence that business functionality exists. GitHub Issues are the work tracker; [issue-plan.json](issue-plan.json) records the canonical P01–P20 scopes and dependency DAG. IDs are stable workstream references, not an execution order. Each Issue names its owner, contract sections, dependencies and acceptance evidence.

## Shared interface gate

Before parallel owners implement dependent interfaces, resolve the relevant [open questions](../contracts/open-questions.md), review shared DTO/hash/manifest fixtures, and agree transaction/repository seams. Reuse exact contract DTOs rather than designing conflicting local variants. Build backend mock fixtures early so later work can be verified without waiting for the real backend.

Dependencies identify required artifacts/checkpoints rather than requiring every predecessor Issue to be closed. Build inactive language configuration, a controlled adapter and candidate image first; qualify their primitive isolation in P17 before enabling capabilities or executing imported code. Later repeat qualification against the final release digest and four-service deployment in P20. No staged checkpoint is permission to weaken isolation or publish an unvalidated capability.

| ID | Workstream / deliverable | Depends on | Required acceptance evidence |
|---|---|---|---|
| [P01 #5](https://github.com/STAR-Ability/code-startrack-judge/issues/5) | Service configuration and strict internal HTTP contracts | Phase 0 | Exact language/toolchain lock, reproducible build, DTO/auth/request identity/limits, conservative capability-aware health |
| [P02 #6](https://github.com/STAR-Ability/code-startrack-judge/issues/6) | Initial judge schema and forward-only migrations | [P01 #5](https://github.com/STAR-Ability/code-startrack-judge/issues/5) | Contract constraints, circular DEFERRABLE local FKs, judge-only privileges, fresh/reapply/upgrade checks; Q-005 gates affected schema |
| [P03 #7](https://github.com/STAR-Ability/code-startrack-judge/issues/7) | Immutable problem/version/artifact repositories and private storage | [P02 #6](https://github.com/STAR-Ability/code-startrack-judge/issues/6) | Same-problem references, immutable bytes/checksums, metadata sharing, safe transient/orphan cleanup |
| [P04 #8](https://github.com/STAR-Ability/code-startrack-judge/issues/8) | Per-package license evidence and publication eligibility | P02, P03 | Reviewed per-package rights/provenance, independent technical/legal gates; Q-003/Q-005 |
| [P05 #9](https://github.com/STAR-Ability/code-startrack-judge/issues/9) | Versioned OJ-Lab-to-Kattis compatibility adapter | [P03 #7](https://github.com/STAR-Ability/code-startrack-judge/issues/7) | Fixed original packages, typed manifest, deterministic conversions and checker semantics; Q-007 |
| [P06 #10](https://github.com/STAR-Ability/code-startrack-judge/issues/10) | Isolated problemtools validation and reproducible records | P02, P03, P05, P10, P11, P17 | Isolated validators/reference programs, technical failures retained, real toolchain/image/checksum evidence |
| [P07 #11](https://github.com/STAR-Ability/code-startrack-judge/issues/11) | Persistent asynchronous OJ-Lab import jobs | P01, P02, P03, P04, P05, P06 | Fixed source/path allowlist, idempotent ordered items, partial-success drafts, fenced recovery, no auto-publish; Q-003/Q-004/Q-006 |
| [P08 #12](https://github.com/STAR-Ability/code-startrack-judge/issues/12) | Metadata versions, publication/withdrawal and problem queries | P01, P02, P03, P04, P06 | Atomic public updates, historical versions, mutation replay and no hidden DTO fields; Q-006 |
| [P09 #13](https://github.com/STAR-Ability/code-startrack-judge/issues/13) | Consistent catalog snapshots and protected cursors | P01, P02, P08 | Tombstones, protected cursor/expiry, full version-consistent backend cache swap |
| [P10 #14](https://github.com/STAR-Ability/code-startrack-judge/issues/14) | Versioned server-controlled language capabilities/toolchains | P01, P02 | Actual cpp17 capability, immutable templates/limits/digests, no caller commands |
| [P11 #15](https://github.com/STAR-Ability/code-startrack-judge/issues/15) | Provenance-preserving go-judge/demo runtime adapter | P01, P03, P10 | Reviewed protocol/binding, safe bottom-level API, resource/verdict/checker mapping and safe logs; Q-007/Q-008 |
| [P12 #16](https://github.com/STAR-Ability/code-startrack-judge/issues/16) | Durable JudgeTask admission and query/recovery APIs | P01, P02, P03, P08, P10, P14 | Durable task/source/initial event, unique submission/request, frozen context, by-request recovery; Q-002/Q-006 |
| [P13 #17](https://github.com/STAR-Ability/code-startrack-judge/issues/17) | Persistent task scheduler, leases and fenced crash recovery | P11, P12, P14 | Short claims, confirmed dispatch, stale-owner rejection, bounded recovery and no terminal regression; Q-004 |
| [P14 #18](https://github.com/STAR-Ability/code-startrack-judge/issues/18) | Atomic task transitions, raw/case results and outbox snapshots | P01, P02, P03 | Shared transaction core, immutable results, safe aggregation and exact callback snapshot at every revision; Q-002/Q-004 |
| [P15 #19](https://github.com/STAR-Ability/code-startrack-judge/issues/19) | Durable callback delivery, dead letters and reconciliation | P01, P14 | Stable retries/events, duplicate/out-of-order convergence, failures retained, restart recovery |
| [P16 #20](https://github.com/STAR-Ability/code-startrack-judge/issues/20) | Production image, supervision and deployment operations | P01, P10, P11, U01 | One business container, restricted process secrets/mounts/capabilities, actual image/SBOM and operator evidence |
| [P17 #21](https://github.com/STAR-Ability/code-startrack-judge/issues/21) | Real Linux adversarial sandbox verification and readiness | P10, P11, P16 | Baseline cgroup/seccomp/namespaces/network/filesystem/resource/cleanup proof on the candidate image; no fallback; final digest/co-location repeated in P20 |
| [P18 #22](https://github.com/STAR-Ability/code-startrack-judge/issues/22) | Backend mock and independent contract acceptance | P07, P08, P09, P12, P13, P14, P15, P17 | Complete owner acceptance and fault-injection matrix; mock controls separated from real sandbox proof |
| [P19 #23](https://github.com/STAR-Ability/code-startrack-judge/issues/23) | Real backend consumer compatibility and integration handoff | [P18 #22](https://github.com/STAR-Ability/code-startrack-judge/issues/22) | Named backend/judge builds, callback/polling/catalog/projection evidence and external owner sign-off; Q-001 |
| [P20 #24](https://github.com/STAR-Ability/code-startrack-judge/issues/24) | Final acceptance, release evidence and deployment rehearsal | Q01, P07, P08, P09, P13, P15, P16, P17, P18, P19, U01 | Full four-service contract acceptance, migration/backup drills, actual release/image/provenance and owner license gates |

P10/P11/P16/P17 start early alongside the problem model: the ability to isolate validators/checkers/reference solutions is a prerequisite for trusted package validation, not a last-minute deployment test. P06 depends on P17 for completion; records and mocked control-flow fixtures can be prepared earlier, but real untrusted execution requires the appropriate qualified Linux environment and no production validation/publication claim precedes P17. P18's final harness depends on completed workstreams, but owners should start its shared DTO/backend-mock fixtures during P01 and use them continuously. P14 is foundational before P12 because acceptance already requires the initial durable event; P15 retry transport can proceed in parallel once that transaction interface is frozen.

## Suggested execution order

Start **P01**, while resolving Q01's applicable questions and the owner license decision separately. P02 enables P03 and P10 in parallel. Build P04/P05 on the problem track and P11/P16/P17 on the runtime track, while P14 establishes atomic task/result/outbox transactions and P15 develops delivery fixtures. P06/P07/P08/P09 and P12/P13 then converge on validated packages, consistent catalogs and durable safe judging. Complete independent mock acceptance P18, real backend coordination P19, and release acceptance P20. Resolve only the relevant contract gate before a workstream's affected design; there is no need to block all bootstrap work on every Q01 question.

Keep security qualification as an ongoing gate. Passing unit tests with mocks does not permit real untrusted execution, and generic hosted CI cannot stand in for Linux sandbox evidence. If the required environment is unavailable, report the exact unmet capability and continue portable work using explicit mocks.

## Parallel ownership and completion

Each Issue should name the directories it owns and the shared artifacts it proposes to change. Coordinate migration number reservation and shared DTO/manifest changes before writing. Changes crossing a contract seam need the neighboring owner's review; source ownership does not grant permission to alter another service's responsibilities.

All workstreams require contract-correct tests, necessary documentation/ADR changes, provenance and licensing updates where applicable, and a clean reviewed diff. A service release requires the [contract compatibility evidence](../contracts/README.md#backendjudge-compatibility-evidence), real sandbox validation, immutable migration history, actual image digests, release notes, and operator instructions. No final `dev -> main` release PR, release tag, or production deployment belongs to Phase 0.

## Decision and foundation trackers

- [F00 #1 — Phase 0: establish and verify the repository engineering foundation](https://github.com/STAR-Ability/code-startrack-judge/issues/1)
- [Q01 #2 — Resolve V0.2 contract clarifications before affected implementation](https://github.com/STAR-Ability/code-startrack-judge/issues/2)
- [L01 #3 — Owner decision: choose the Code Startrack project license](https://github.com/STAR-Ability/code-startrack-judge/issues/3)
- [U01 #4 — Resolve problemtools nested VIVA binary provenance before image redistribution](https://github.com/STAR-Ability/code-startrack-judge/issues/4)
