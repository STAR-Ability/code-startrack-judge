# Upstream dependency ownership

The active contract pins four source baselines in [upstream.lock.json](../../upstream.lock.json). The lock records repository URLs, full commits, release names where specified, license evidence and hashes, selected source metadata hashes, and an explicit patch list. A resolved commit proves source identity; it does not prove API compatibility, package validity, or sandbox isolation. The [compatibility matrix](compatibility-matrix.md) records those distinctions.

## Integration mechanisms

| Component | Mechanism | Code Startrack ownership |
|---|---|---|
| go-judge-demo | Retain the exact reviewed scheduling reference and hardened judger build inputs/provenance; owned private scheduling uses typed Unix-socket operations. | PostgreSQL repository, durable scheduling, authenticated contract DTOs, leases and callbacks. The upstream bare submit/shell endpoints, MongoDB demo storage and frontend are not exposed or adopted. |
| go-judge | Build the Linux execution binary from the exact source baseline; supervise it privately inside the service image. Native Go module dependencies may be used for generated protocol/client packages with their own version locks. | Translation from fixed server-side language templates and frozen package manifests to execution requests, result mapping and capability checks. Namespace/cgroup/seccomp implementations remain upstream-owned. |
| oj-lab/problem-packages | Fetch an immutable source tree, then import selected packages into private immutable artifacts through the importer. No upstream tools or reference solutions execute during bootstrap. | Per-package license review, input/path safety, original hashes, independently versioned normalization and validation evidence. |
| problemtools | Build a pinned tool environment from source with locked Python/build/OS dependencies; call through the isolated package-validation adapter. | `ojlab-kattis-v0.2.1` normalization and the legacy validation view specified by the contract, error interpretation, isolation and provenance. No blanket suppression of upstream errors. |

Upstream source is retrieved into ignored `.cache/upstream/` storage. Owned adapters belong in the service code; [reviewed source changes](patches.md) remain separate patch series and retain upstream notices. The bootstrap retrieves and verifies source without executing these components. Image preparation exports only approved source inputs, verifies the module vendor graph and retains patch inventories. Follow [getting started](../development/getting-started.md) for commands.

## Toolchain and inventory limits

Both pinned Go repositories declare `go 1.26.0`. This is a minimum toolchain requirement, not a requirement to stay on an insecure patch release. The implementation build must select and lock an approved compatible patched toolchain, record its actual version, and verify it. Demo's `go.mod` declares `go-judge/pb v1.3.4` and `go-judge-client v0.1.4`; runtime's `go.mod` declares `go-judge/pb v1.4.0`. Their coexistence requires protocol regression tests, not an assumption that matching repository names imply compatibility.

Pinned problemtools requires Python >=3.11. Its `requirements.txt` declares `colorlog`, `nh3`, `PyYAML`, `plasTeX>=3.0`, `pydantic>=2.11`, and `checktestdata>=2026.7.1`; its build requirements include setuptools >=77 and setuptools-scm. These are not a reproducible full dependency lock. Before a validation image is released, resolve and lock Python packages and their hashes, native support programs, compilers, TeX/rendering dependencies actually included, and base OS packages. Do not install the floating `problemtools/icpc` example image as the production baseline.

The demo includes a frontend `package-lock.json`, but Code Startrack does not build or distribute that frontend. OJ-Lab has Node development tools; the importer consumes package data without adopting or executing those tools. Scope the artifact inventory to what is actually built and distributed, and retain separate build-tool inventory when relevant.

The [native Go inventory](../licenses/go-service-dependencies.json) verifies the actual owned-command dependency closure on Linux/macOS amd64/arm64 and retains exact module/license provenance. This does not replace a complete final-image SBOM. The source lock includes the four baselines, Moby's seccomp profile and selected security-critical runtime dependencies. The release image must additionally inventory upstream Go modules, Python/native/TeX dependencies and base OS packages, reconcile required notices, and inspect the actual distributed layers.

## Known integration gates

1. The pinned runtime embeds an Apache-2.0 Moby seccomp derivative. Preserve its [NOTICE](../licenses/go-judge-seccomp-NOTICE), Apache license and upstream change attribution. Upstream's NOTICE links Moby `main` without an original snapshot revision. The exact redistributed snapshot is pinned by the go-judge commit and `seccomp/moby-default.json` hash; the supplemental Moby commit identifies the copied license text only. Do not claim it is the snapshot's origin commit or refresh the profile from `main`.
2. Original problemtools installs VIVA with nested MiGLayout and Eclipse loader bytes whose complete redistribution provenance was not established. The [reviewed omission](patches.md) removes VIVA before source/build inputs are assembled and classifies `.viva` packages as unsupported. Source-staging regressions pass; final distribution/layer inspection and required checker/package execution are still mandatory.
3. The owned judger translates typed authenticated Unix-socket operations to the contract's fixed private REST endpoint `127.0.0.1:5050`. It has an independent low-level token; the API does not. [Transport evidence](rest-transport.md) records byte preservation and route boundaries. Final Linux listener/process isolation must be measured.
4. Reviewed go-judge patches remove full configuration/token/raw execution logging and request-dumping recovery. Actual HTTP canary regressions pass; final-image startup/error logs must also be checked.
5. Reviewed patches remove the demo's `:2112` diagnostics, runtime `/config` and WebSocket execution routes, and authenticate `/version`. Prove the actual final-image listener/route allowlist before release; an unpublished host port alone does not establish authentication or process privacy.
6. Full Linux sandbox and mature package-validation qualification remain mandatory. Final credential-bearing executables measure nondumpability after exec; launcher-only hardening cannot prove this boundary. The supplemental go-sandbox remount patch requires actual read-only, inherited-mask and nested-submount adversarial verification.

Each [current patch record](patches.md) contains its upstream commit, reason, changed files/diff, compatibility and security impact, license/change notices, regression evidence, and upgrade/rebase instructions. Track the owning Issue and accepted ADR when the boundary changes. See [upgrade policy](upgrade-policy.md).

## Imported content is a separate license domain

The initial OJ-Lab tree has 14 package directories. Their root software license is MIT, but **no package has been approved for publication by this source audit**. Review each problem's statement, illustrations, test data, solutions, validators and checker sources, including third-party origins, attribution and root-license coverage. Preserve the exact original license files with path/hash, fixed-commit source URLs, reviewer identity/time and evidence required by the database contract. Missing or uncertain permissions block publication. Record SPDX only when the actual terms can be identified; a valid custom permission may have a null identifier and complete notice/evidence.

Software/image notices and problem-content evidence have different owners and retention. An image SBOM cannot replace per-package evidence, and a package license row cannot replace image attribution. Withdrawal, artifact normalization or a software upgrade must not erase prior evidence or overwrite historical artifacts.
