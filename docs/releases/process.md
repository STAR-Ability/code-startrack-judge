# Releases and historical traceability

No production release is published. V0.2 is the current implementation target, with contract release `0.2.0`; contract publication does not mean runnable release readiness. [Versioned contracts](../contracts/README.md) and immutable release records make later V0.3/V0.4/V1.0 development independent of previous conversations.

Use tags `vMAJOR.MINOR.PATCH` with a practical compatibility policy: patches preserve supported consumers and historical semantics, minors add compatible capability, and majors signal significant incompatibility. Pre-1.0 minor versions may deliberately introduce breaking behavior only with explicit release notes and consumer migration. API generations and contract versions evolve by their own compatibility rules; changing the release number never licenses an undocumented change to `/internal/v2`.

## Release sequence

1. Implement scoped Issues on `dev` (later `feature/*` → PR → `dev`). Record changes in [CHANGELOG.md](../../CHANGELOG.md), update contract/backend/upstream compatibility and accepted ADRs as necessary, and settle release blockers.
2. Validate the candidate commit with portable CI, migration/schema/DTO/integration tests, dependency and license checks, container build, mock and real backend acceptance, and real Linux sandbox qualification. Use actual job names/results; portable CI cannot substitute for isolation tests. The [portable acceptance suite](../development/acceptance.md) checks actual PostgreSQL control flow with mock acquisition, Backend and execution; full Linux and real Backend acceptance require separate evidence.
3. Prepare `dev` → `main` PR with exact release scope, source contract paths, compatibility/migration notes and test evidence. Review security-sensitive changes independently. Main remains the stable/release branch; normal development does not push directly.
4. Validate the exact merged `main` commit. If merge results changed the tested tree, rerun affected checks against that commit before tagging. Create an immutable release tag from it; never move a shipped tag. Record the full commit and actual CI run URLs.
5. Use the audited commit artifact described below, or build/publish the container from the tag with the same pinned build inputs and distribution gates. The [project license decision](../licenses/project-license-decision.md) is accepted; that decision does not approve unreviewed third-party dependencies. Attach provenance, actual dependency/license inventory and SBOMs, and the complete corresponding-source artifact. Record the resulting immutable image digest; do not guess it or use `latest`. If the final digest differs from the qualified candidate, rerun image-bound integration and Linux isolation tests against that final digest before declaring the release validated or deploying it. Preserve upstream LICENSE/NOTICE in source/binary distribution as required.
6. Complete a record based on the [release template](template.md), with no placeholders masquerading as evidence. Publish release notes and link the record, tag, changelog, qualified environment and upgrade instructions. Release-specific evidence belongs under `docs/releases/<version>.md` or linked immutable release attachments; later deployment appendices may record real rollout results without rewriting historical release facts.
7. Follow the [production runbook](../deployment/production.md), record deployment evidence, monitor, and update the supported release/security policy and current-production pointer in repository documentation. Never mark a target release as production until it has actually deployed and been accepted.

Keep an immutable association among commit/tag, contract/API generation, migration level/checksums, backend tested version, upstream/adapters/toolchain versions, package and validation context, image digest, and verification evidence. Deployment-specific secret values are never published; record nonsecret configuration versions/hashes. Preserve released contracts, shipped migrations, package/version artifacts, license evidence, validation runs, JudgeTasks and results across upgrades. Historical execution needs the frozen image/template/sandbox context plus authorized backend source; a checksum alone is not executable source.

## Protected-main artifact automation

[Publish immutable artifacts](../../.github/workflows/publish-artifacts.yml) runs only after a successful canonical-repository `Foundation` push or manual run on protected `main`. It checks out the exact tested commit, requires a clean tree and ancestry on `origin/main`, and uses job-scoped GHCR write access. It creates no Git tag, GitHub release, deployment or production pointer.

The workflow first publishes `ghcr.io/star-ability/code-startrack-judge-sources:git-<full-commit>` as a data-only OCI image. This carrier is never started. It includes the complete byte-inventoried build context, project/upstream/vendor source and patches, original legal evidence, and the exact archives named by [validation-sources.lock.json](../../validation-sources.lock.json). Linux `gpgv` verification of the retained Debian signatures, full signed-index matching and every archive checksum must pass. The publisher audits the carrier by streaming its actual filesystem bytes, then measures the registry digest before any service image publication.

The service image is `ghcr.io/star-ability/code-startrack-judge:git-<full-commit>`, built for Linux amd64 with network disabled during build steps. Actual extracted licenses, source/context locks, installed OS/Python inventories, migrations and executable checksums are checked before push. Extracted prebuilt provenance files must match their context-entry hashes and sizes. The [wheel auditor](../../scripts/problemtools-wheel-audit.py) captures the actual problemtools wheel's checksum, complete member hashes and original RECORD. The original wheel is retained at `/opt/startrack/provenance/problemtools-1.20260907-py3-none-any.whl`; the publisher independently remeasures its strict ZIP32 envelope, every compressed stream and member, rejecting prefixes, trailers, unmeasured comments/extras and unused compressed data. Pinned metadata and entry points, excluded VIVA/nested archive payloads and installed bytes are checked against that raw artifact. Installation uses `--no-compile`; generated problemtools bytecode is rejected. The publisher independently remeasures the fixed installed package, metadata and three entry-point paths against this receipt. The Dockerfile builds no sdist; the receipt records `sdistBuilt: false`.

The [go-judge auditor](../../scripts/check-go-judge-licenses.py) verifies the actual linked binary against the reviewed legal inventory and emits SPDX and CycloneDX records scoped to that binary. `release-artifacts.json` states the scope of measured OS/Python/executable inventories, wheel evidence, the separately installed pinned checker and original two-example qualification corpora, and `BUILD_INPUTS_ONLY` dependency inputs. Every extracted qualification-carrier byte must match its upstream context entry. The [runtime matrix](../development/runtime-adapter.md) separately records all 24 original checker vectors, the declared original-byte `hello` projection and expected unsupported examples; it never claims the full original package suite passed. Preserve the [example-content notice](../licenses/problemtools-example-notice.txt) alongside the software notices. Runtime migration payload contains exactly the numbered SQL files; `migrations/source.go` remains a source/build input. These records do not assert a complete image SBOM or inspect every distributed layer; retain separate complete-image inventory/SBOM and service/source-carrier layer-exclusion evidence before accepting the distribution gates. The service and source artifacts must share the exact build-context inventory. Existing commit tags are resolved to digests, re-audited and reused; the workflow refuses to replace an existing tag.

`release-artifacts.json` binds the tested source commit, contract/API identities, migration checksums, source-manifest and context-inventory hashes, source and service registry digests, actual linked dependency records, builder identity and CI URLs. It explicitly records `UNQUALIFIED` and `NOT_DEPLOYED`. The uniquely named Actions evidence artifact contains this record, extracted provenance/legal evidence, SBOMs, checksums and, for a fresh build, the prepared build-context archive. Automatic artifact publication is implemented; its first successful official run and resulting digests must be recorded from actual GitHub evidence.

Keep the corresponding-source GHCR artifact accessible to every recipient of its binary image. Preserve both immutable digests and their evidence for as long as the binaries are offered and for the applicable historical/license retention period. Grant source access before widening binary access; package visibility and organization retention policies are operator responsibilities. Actions attachments have a 90-day retention window, so the release owner must copy release evidence into durable release attachments or approved archival storage before it expires. Do not treat an expiring CI attachment or an upstream download URL as durable corresponding-source distribution. Never delete or retag an offered source/image pair.

## Local candidate artifact inspection

The [artifact auditor](../../scripts/release-artifacts.py) also provides
`candidate-sources-prepare`, `candidate-sources-audit` and `candidate-audit` for
clean candidates before the protected-main release. Each requires an explicit
full `--source-commit` equal to the current clean Git HEAD; the auditor checks
this again before emitting evidence. These commands never query a registry,
push, pull, finalize an official artifact, start a container or change Git.
Official commands retain the protected-main guard and require the published
immutable source digest.

Prepare a fresh context with `scripts/prepare-image-context.py prepare
.local/candidate-context --release-commit <full-commit>` and verify it. On Linux,
verify the signed corresponding-source bundle and prepare the data-only carrier:

```sh
JUDGE_CANDIDATE_COMMIT=$(git rev-parse HEAD)
JUDGE_SOURCE_LOCK_SHA=$(sha256sum validation-sources.lock.json | cut -d ' ' -f 1)
python3 scripts/validation-sources.py verify-signatures
python3 scripts/validation-sources.py verify
python3 scripts/release-artifacts.py candidate-sources-prepare \
  --source-commit "$JUDGE_CANDIDATE_COMMIT" \
  --context .local/candidate-context \
  --bundle ".cache/validation-sources/$JUDGE_SOURCE_LOCK_SHA" \
  --output .local/candidate-source-context
```

Build the service and scratch carrier offline from those contexts with explicit
host-specific CPU, memory, process, storage and duration limits. Use dedicated
local tags. Both images need the exact commit revision, canonical GitHub source
URL and `Apache-2.0` OCI labels; the carrier also needs
`io.startrack.artifact=corresponding-source`. Resolve each local tag to its full
`sha256:` **Docker image ID** through `docker image inspect`; the candidate
commands accept only that ID, avoiding mutable-tag races. With Docker's
containerd image store this ID can identify an OCI index; it must not be described
as an OCI configuration digest. Capture `--metadata-file` from each candidate
build to record its separate `containerimage.config.digest`, when emitted, and
build digest. Current BuildKit can omit the configuration key; the auditor also
accepts Docker's measured `Descriptor.annotations["config.digest"]` when that
descriptor binds the exact inspected Docker ID.

```sh
python3 scripts/release-artifacts.py candidate-sources-audit \
  --source-commit "$JUDGE_CANDIDATE_COMMIT" \
  --image "$JUDGE_SOURCE_DOCKER_ID" --output .local/candidate-source-evidence \
  --build-metadata .local/candidate-source-build-metadata.json
python3 scripts/release-artifacts.py candidate-audit \
  --source-commit "$JUDGE_CANDIDATE_COMMIT" \
  --image "$JUDGE_SERVICE_DOCKER_ID" --output .local/candidate-service-evidence \
  --sources .local/candidate-source-evidence \
  --build-metadata .local/candidate-build-metadata.json
```

Source auditing retains the official signed-index and full archive checks. Service
auditing retains installed legal/package/wheel/executable/migration checks and the
actual linked go-judge audit. The source and service context inventories must
match; supplied build metadata must bind the inspected Docker image ID to its
recorded configuration or exported build digest. The receipt keeps `imageDockerID`
separate from `imageConfigID`, whose recorded origin is BuildKit metadata or
Docker's descriptor; actual configuration bytes and
the complete layer graph still require independent archive verification. Without
build metadata or a bound Docker descriptor, the configuration digest remains
null. The source carrier must
still exist under its recorded local Docker image ID
when service evidence is checked. Auditor-created containers are never started
and only those temporary containers are removed.

Receipts are `candidate-artifacts.json` plus `SHA256SUMS`, explicitly
`LOCAL_CANDIDATE`, `UNQUALIFIED`, `NOT_DEPLOYED` and `NOT_PUBLISHED`. They contain no
official CI-run claim or immutable registry reference and are rejected by the
official source-evidence verifier. Complete-image SBOM, all distributed layer
inspection, source-recipient access/retention, Linux execution and real Backend
acceptance remain separately evidenced gates. A successful candidate artifact
audit does not make PR #25 ready for merge.

## Bounded static archive companions

The [gzip companion](../../scripts/audit-image-gzip.py) measures selected compressed
documentation, man and info payloads. The [Rust source companion](../../scripts/audit-image-crates.py)
measures the gzip/TAR contents of locked `.crate` archives shared by the service
and source-carrier physical inventories. These are separate static measurements;
they preserve the original receipts and do not grant legal, distribution or
sandbox qualification approval.

The Rust companion requires explicit hashes for the source archive, both physical
receipts, image configurations/manifests and validation-tool lock. It remeasures the
source archive and affected layer, then associates identical service payloads
through their existing physical name/size/content-hash evidence. This is not a
new measurement of the service archive. Every supported gzip/TAR header,
metadata value, member and padding byte is inspected or structurally verified;
unsupported profiles and nested gaps remain unresolved. Use `--help` for the
complete input interface.

Run these tools in dedicated, bounded static-audit processes with read-only
inputs, disabled networking, explicit CPU/memory/PID/time limits and private
output directories. They never extract or execute the archived files. Preserve
each exact helper/input/output hash and actual limits/cleanup evidence. When
combining supplements, derive the union of their resolved original gap locations
against the same immutable physical receipt; do not subtract counts without
checking the location sets and retained nested gaps.
Carry forward new companion gaps and excluded-payload findings; successful static
measurement does not close the exclusion gate.

An additional content association may bind unresolved original locations to
previously measured identical compressed bytes. Require the unchanged receipt
hashes, unique original gap locations, regular-file types, sizes and content
hashes, and a complete measured origin without retained findings or gaps.
Preserve the location-set union and describe this as receipt association;
it does not remeasure the target image or decide its license terms.

## Trusted Linux evidence

[Trusted Linux image qualification](../../.github/workflows/linux-qualification.yml) is a manual protected-main workflow on the dedicated `judge-sandbox-qualification` Linux runner/environment. It accepts only a fixed-repository manifest digest and checks the image's source commit against the checked-out `main` commit. Operators must first configure the reviewed dedicated runner, noninteractive root launcher and the profiles in the [production runbook](../deployment/production.md). The workflow authenticates job-scoped registry read access through a temporary private Docker configuration, pulls the exact digest through the trusted root Docker context, and removes the credentials after the job. The launcher verifies the actual local `RepoDigest` rather than accepting a mutable tag.

The launcher creates only disposable synthetic containers, exercises the denied baseline and reviewed capability/cgroup/AppArmor/seccomp profile, runs the native runtime matrix, verifies cleanup and uploads bounded sanitized evidence. A zero exit status means the recorded synthetic runtime checks passed. The report keeps `qualified: false` while mature-role/statement, maximum-package/parallel-budget, final service-process-memory or independent-security-review acceptance remains outstanding. This workflow does not deploy the service or substitute for those gates or real Backend acceptance. Record actual evidence and its scope before declaring a release qualified.

Deprecation follows introduce → migrate consumers → verify → deprecate → remove, with named owners and explicit support windows. Removal requires evidence that supported consumers and still-active frozen work no longer depend on the old behavior. Do not retain obsolete versions indefinitely without reason; preserve archived evidence even after runtime support ends.

Upstream/runtime upgrades follow the [upstream upgrade policy](../upstream/upgrade-policy.md). Emergency security fixes may use an administrator's documented branch-protection exception; record the reason, commit, review, tests and subsequent reconciliation to `dev`. A break-glass path is never the ordinary release workflow.
