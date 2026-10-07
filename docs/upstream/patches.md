# Controlled upstream build patches

These patch series implement source hardening for [#4](https://github.com/STAR-Ability/code-startrack-judge/issues/4) and [#15](https://github.com/STAR-Ability/code-startrack-judge/issues/15). They supplement the [source lock](../../upstream.lock.json) without changing contractual upstream commits or published contracts. Patches are project-owned integration changes; modified upstream files keep their original licensing and prominent modification notices.

## Exact series and scope

| Component | Base commit | Patch metadata | Result |
|---|---|---|---|
| problemtools v1.20260907 | `6010cbaa37a1612117f49566b2fff8646d53faa2` | [series](../../patches/problemtools/series.json), [diff](../../patches/problemtools/0001-startrack-distribution-hardening.patch) | Removes VIVA install commands. Build-input allowlist excludes the entire `support/viva/` directory before wheel, sdist or image construction. |
| go-judge v1.13.0 | `e9d70a0d9a3df0c62182a6e7090d7af650a1d5f8` | [series](../../patches/go-judge/series.json), [diff](../../patches/go-judge/0001-startrack-distribution-hardening.patch) | Removes full-config/token and raw execution logs, replaces request-dumping panic recovery with bounded logging, authenticates `/version`, removes `/config` and WebSocket execution routes, adds HTTP route/log regression tests. Sandbox isolation source stays unchanged. |
| go-judge-demo | `ed6cc756082ee9f7d792238185dc3e6a47c84b52` | [series](../../patches/go-judge-demo/series.json), [diff](../../patches/go-judge-demo/0001-startrack-distribution-hardening.patch) | Removes judger's unconditional `:2112` metrics/pprof listener and submitted-source/test/result logging. Excludes demo server, gateway, MongoDB example and frontend from build inputs. |

Each `series.json` declares repository/base identity, ordered patch paths and SHA-256, exact before/after hashes for modified files, reason, license impact, upgrade conditions and the build source allowlist. Original upstream root LICENSE and applicable NOTICE files remain byte-identical. New Code Startrack regression test code states Apache-2.0 separately; it does not relicense upstream source.

## Reproducible preparation

Fetch and verify immutable sources first using the existing [development commands](../development/getting-started.md). Preparation uses only verified Git objects and never runs upstream programs or downloads dependencies:

```sh
make upstream-fetch
make upstream-verify
python3 scripts/apply-upstream-patches.py problemtools --destination .cache/build-inputs/problemtools
python3 scripts/apply-upstream-patches.py go-judge --destination .cache/build-inputs/go-judge
python3 scripts/apply-upstream-patches.py go-judge-demo --destination .cache/build-inputs/go-judge-demo
python3 -m unittest discover -s tests -p 'test_upstream_patches.py' -v
```

The [preparer](../../scripts/apply-upstream-patches.py) refuses an existing destination, unsafe paths, symbolic links, special files, submodules, mismatched cache origins/commits, modified patch bytes, changed base files, missing notices and unrecorded source or permission changes. It rejects nonregular files before reading content and preserves exact `100644`/`100755` modes. Destinations must be fresh directories below ignored `.cache/` or `.local/`. Git patch application is isolated from the enclosing project worktree. Partial preparation is cleaned up; it never replaces existing user work.

Every prepared directory contains `.startrack-upstream-build.json` with source identity, patch metadata, exclusions, unsupported extensions and an inventory of actual staged file hashes/sizes. This record states `BUILD_INPUTS_ONLY`: preparation proves a selected, patched source tree, not an installed tool, redistributable image or safe runtime.

Builders must consume this prepared directory as their sole upstream source input. Do not copy the bare cache, unfiltered upstream archive or complete checkout into a build stage and remove excluded files later: excluded bytes would still be present in distributed layers. Preserve the generated provenance record with the actual build/release evidence. Package-version generation from the Git-free problemtools staging tree must use the exact reviewed `SETUPTOOLS_SCM_PRETEND_VERSION_FOR_PROBLEMTOOLS` value associated with `v1.20260907`; it must not infer a version from the enclosing Code Startrack Git repository. Resolve/lock build dependencies separately before building a release artifact.

## VIVA omission and compatibility

Pinned Kattis Debian metadata declares VIVA MIT, Copyright 2010–2018 David van Brackle. Both VIVA JARs also contain MiGLayout declaring version 3.7.4 and Eclipse JDT loader classes without embedded license/NOTICE. Static forensic evidence matches all six loader classes exactly to [Eclipse JDT UI commit 6e2438da0f4abb65874faa0eaa7870c1a56d1c23](https://github.com/eclipse-jdt/eclipse.jdt.ui/tree/6e2438da0f4abb65874faa0eaa7870c1a56d1c23), whose historical terms are EPL-1.0. MiGLayout's released Maven binary differs in seven class files from the bundled binary. Its manifest alone does not establish exact redistribution provenance. Current Eclipse license headers do not substitute for the historical binary's terms.

The authorized omission route removes this unnecessary bundled component rather than guessing rights. The two VIVA installation commands are removed from `support/Makefile`, and the preparation allowlist omits both JARs, wrapper and guide. Required default-validator, default-grader and interactive support source remains present. The allowed legacy batch fixtures and all 24 upstream default-validator regression fixtures remain available; unsupported scoring/interactive example fixtures are omitted from this build-input profile.

The importer must classify any `.viva` validator as `PACKAGE_UNSUPPORTED`, retain its original evidence and refuse technical success/publication. Missing engines or input validators must never be silently skipped. The unchanged problemtools Python VIVA wrapper reports a missing engine if called; it does not include the omitted JARs. Detection/admission belongs to the owned compatibility adapter and is a required gate before enabling imports.

The pinned OJ-Lab corpus has 14 problem packages, no VIVA/JAR/custom output-validator files, 14 C++ reference sources and one Python reference source. Only `hello-world` includes an input validator; the other 13 packages must retain upstream's `No input format validators found` error. Omission therefore removes no existing VIVA dependency, while full package technical acceptance remains subject to real validation.

Before closing #4 or declaring a redistributable image, inspect actual wheel/sdist, installed filesystem and exported image layers/SBOM for all excluded components, then run the pinned default-checker fixtures and real package-validation regressions under the qualified Linux runtime. A prepared source inventory or absence of a runtime import is insufficient evidence for that release gate.

## Private runtime hardening and remaining wiring

The go-judge patch protects version diagnostics with the same token middleware as execution/file routes and removes internal configuration disclosure. It removes raw request/result logs in REST and gRPC execution paths. Its bounded HTTP recovery emits only a fixed diagnostic and an empty 500 response; the inherited Gin/Zap request dump could otherwise expose Authorization headers on panic. It changes no files under `env/`, `envexec/` or `seccomp/`; portable staging regressions verify those files retain their original hashes.

This source patch does not start or configure a service. The owned launcher must require an independent nonempty runtime token, bind REST to exactly `127.0.0.1:5050`, disable gRPC/metrics/debug TCP listeners, enable `--no-fallback`, preserve seccomp and inject no business/S2S credentials into go-judge. The demo stream uses the approved private Unix socket through the owned scheduler/launcher; its inherited gRPC defaults and hardcoded demo limits are not an accepted production execution profile. Frozen manifest/checker/limits, REST byte-preserving transport, leases/fencing and graceful cancellation remain separate adapter work.

Run native regression tests in the prepared Go trees using the exact locked SDK, with `GOTOOLCHAIN=local` and readonly module resolution:

```sh
GOTOOLCHAIN=local go test -mod=readonly ./cmd/go-judge -run TestStartrackPrivateHTTPRoutes -count=1
GOTOOLCHAIN=local go test -mod=readonly ./judger -run '^$'
```

Run each command from its corresponding prepared source directory. The first test exercises actual HTTP middleware with a canary token, including an authenticated panic containing header/query/panic canaries, and asserts authenticated version access, missing config/WebSocket routes and absent default monitoring. The second compiles the patched judger without running it. Neither executes submitted programs or qualifies Linux isolation. Final-image tests must measure listeners, sibling-process credential boundaries, startup/failure logs and sandbox denial of network/management access.

On 2026-10-08, exact-source preparation for all three components and eight portable staging/provenance/path/permission/special-file regressions passed on macOS. The actual hardened go-judge HTTP middleware test passed with Go `1.26.8 darwin/amd64`; the patched demo judger compiled. Independent review identified and resolved request-dumping recovery and mode-only tampering defects. No C++ checker/reference/validator execution, wheel/image distribution audit or Linux sandbox qualification was performed by these checks. Those remain the #4/#15/P06/P16/P17 acceptance gates.

## Upgrade/rebase conditions

An upstream upgrade follows the [upgrade policy](upgrade-policy.md) and an Issue. Export the proposed exact commit into a fresh ignored directory; inspect upstream changes to patched functions, listener defaults, LICENSE/NOTICE and bundled components. Rebase the separate patch diff deliberately, regenerate before/after/patch hashes, run staging negative tests and affected native/contract/Linux regressions, and obtain independent review. Never apply fuzzed patches, change the contracted commit silently or preserve an old hash merely to satisfy checks.

Removal of an exclusion requires authoritative rights/provenance evidence and actual artifact/compliance regression. Removal of a hardening hunk requires proof the new upstream baseline already enforces the required boundary. Historical release locks, build inventories and patch series remain traceable; format/execution semantics changing an adapter require new immutable artifacts/versions.
