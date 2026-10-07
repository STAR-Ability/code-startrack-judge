# Pinned package adaptation and validation

Issues #9 and #10 implement the byte adaptation and validation control flow governed by [package protocol 0.2.0](../contracts/v0.2/package-protocol.md), [ADR 0004](../adr/0004-explicit-package-compatibility.md), and [ADR 0005](../adr/0005-mature-linux-sandbox.md). These implementation notes do not amend the contract or qualify a runtime.

`internal/packages.Adapt` accepts an inert, bounded snapshot from the exact reviewed OJ-Lab commit. It does no fetching, extraction, compilation, execution, license approval, registration, or publication. It preserves original Markdown/YAML/test/program bytes, source file modes, tags, source difficulty, and unknown metadata. The original statement path may be `problem_statement/problem.md` or `problem_statement/problem.en.md`; two candidates or additional language statements are unsupported. The derived validation statement is always the escaped literal TeX view defined by the protocol. Public sample projection reads only SAMPLE cases; source difficulty does not become a platform or Codeforces rating.

Source metadata lives in `manifest.sourceMetadata.originalMetadata`; `sourceFileModes` and `timeLimitLexeme` preserve additional provenance. Consumers must use that wrapper instead of assuming original fields remain at the top level. CPU/MiB conversion, applied defaults, shortname mapping, TeX generation, and controlled legacy metadata conversion are recorded as typed adaptations. Nested sample/secret directory names may be retained as labels, without adding grading, ordering, limit, or validator semantics. Unsupported execution flags and nonempty group configuration fail rather than disappearing from the validation view.

`ManifestReady` means structural conformity only. Acceptance still requires approved license evidence, actual qualified technical validation, verified object bytes, and immutable registration. A package without a real input validator returns `INPUT_VALIDATOR_MISSING`, retains both original and derived archives/manifest, and has `ManifestReady=false`. Bounded unsafe original paths remain inert private snapshots; they are never extracted into a filesystem. The reserved source manifest path is unsupported. Other early failures retain the original canonical archive when it can safely be constructed.

The canonical archive builder/parser uses the complete independent [archive vectors](../../testdata/archive-golden.json). Regular-file unused device fields are all-zero bytes exactly as frozen by those vectors. The parser rejects alternate metadata, links, PAX/GNU extensions, padding/data after the two end blocks, path collisions, and size/count violations. Filesystem extraction belongs to the private storage boundary, not this parser.

Sealed-candidate verification uses `VerifyArchive` to stream the same canonical writer's headers, borrowed snapshot data, padding and exact two-block trailer directly against the existing archive bytes. It preserves all canonical ordering/path/bounds checks without decoding another archive buffer or copying member data. `ReadArchive` remains available for callers that need decoded inert snapshots. Portable tamper and allocation regressions exercise the verification path against independent golden bytes.

Run focused portable tests with the verified SDK:

```sh
GOTOOLCHAIN=local .local/toolchains/go1.26.8/go/bin/go test -race ./internal/packages ./internal/validation
make check
```

After the owner fetches the reviewed Git cache using the repository upstream workflow, reproduce all fourteen source/normalized/manifest hashes without executing imported source:

```sh
STARTRACK_PACKAGE_GIT_DIR="$PWD/.cache/upstream/problem-packages.git" \
  GOTOOLCHAIN=local .local/toolchains/go1.26.8/go/bin/go test \
  ./internal/packages -run TestPinnedCorpusGolden -v
```

The checksum-only [corpus fixture](../../internal/packages/testdata/pinned-corpus.json) contains no test or program bytes. All fourteen packages adapt reproducibly; hello-world is structurally ready and thirteen retain missing-validator failure. This corpus test does not establish license permission, accepted-reference correctness, mature-tool success, or Linux isolation. It skips when the explicitly configured cache is absent and never fetches a branch or new revision.

`internal/validation.Validator` combines every mature verification checkpoint with independently executed exact-profile validators and all ACCEPTED references on every case. Its request binds the owning import job, durable item, and current fencing token. Named mature and exact-program steps consume distinct reservations; transport ambiguity does not authorize a retry under the same reservation. Each exact program/case event is checked and forwarded to the caller's private evidence journal outside SQL transactions. The report retains the exact NDJSON digest/count and bounded checkpoint summaries; the caller must retain all journal chunks and bind the sealed report/log into the live fenced commit.

The production default `UnavailableMatureVerifier` fails closed. The concrete [role-separated problemtools bridge](../upstream/problemtools-bridge.md) preserves pinned mature verification and delegates compilation, reference programs, validators, checkers, the default grader, and whole statement conversions to reviewed sandbox operations. Its existence alone does not qualify a runtime: the application must explicitly wire a measured matching helper. Incomplete upstream steps retain NOT_RUN evidence even when their error counter is zero.

A real PASSED report requires measured, matching Linux/helper/image identity before and after the run, complete mature checkpoints, every exact program/case event retained, and no errors. A failed mature check stays failed; skipped exact checks explicitly carry NOT_RUN. Journal failures and uncertain transport return unfinished errors for counted recovery. Portable mock construction forces `PORTABLE_ONLY`, leaves the execution context empty, and cannot be saved as a package validation run or authorize publication. Portable tests cover these control-flow invariants; they claim no untrusted execution qualification.
