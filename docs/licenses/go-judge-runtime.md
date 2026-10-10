# Measured go-judge binary legal inventory

Refs [#20](https://github.com/STAR-Ability/code-startrack-judge/issues/20).
[go-judge-runtime-dependencies.json](go-judge-runtime-dependencies.json) records
the exact patched upstream `./cmd/go-judge` target for Go 1.26.8, Linux amd64,
`CGO_ENABLED=0`, empty `GOEXPERIMENT`, `GOAMD64=v1`, vendored imports, `-trimpath`
and `-buildvcs=false`. It complements the
[owned command inventory](go-service-dependencies.json) and the separate
[validation-tool inventory](../../validation-tools.lock.json).

The measured target has 496 dependency packages and 48 runtime modules. Its
distributed vendor tree also contains 14 source-only modules. Another 73 modules
in the selected graph are absent from both that vendor distribution and binary.
Each row states its scope; presence in `go.mod` is not evidence of linkage.

The records bind module version, Go module and go.mod checksums, exact downloaded
archive SHA-256, source go.mod SHA-256, legal-text SHA-256, and compiled Go,
assembly, header and embedded-data file hashes. The module archive is the
checksum-verified source reference; an absent Git origin is recorded as null
rather than inventing a commit. Source-only rows retain their archive legal texts
as well. Original license, NOTICE, COPYING, COPYRIGHT and PATENTS files are
retained in [go-judge-runtime](go-judge-runtime/); compiled source header bundles
preserve original copyright/grant comments and identify each exact source file.
The image also retains the unmodified legal texts copied from its actual vendor
tree. Nested module ownership is kept separate.

The main source record includes the upstream MIT text, reviewed Apache-2.0
project patches, and the embedded Moby seccomp configuration's Apache-2.0
license and NOTICE. It records the upstream build and go-sandbox vendor patch
provenance hashes. The pinned Go SDK's existing reviewed BSD-3-Clause evidence
includes its standard library/vendor licenses and PATENTS. CGO is disabled and
no external C/C++ object or BoringSSL alternative is linked by this target;
compiler, checker, Python and OS packages require their separate inventories.

## Verify and assemble image evidence

After preparing exact upstream sources and applying the reviewed vendor patch:

```sh
python3 scripts/check-go-judge-licenses.py prepare \
  --source .local/v02-qualified-candidate-context/upstream/go-judge \
  --output .local/v02-qualified-candidate-context/provenance

python3 scripts/check-go-judge-licenses.py legal
```

`prepare` independently remeasures the package/file closure and compares it to
the reviewed repository record; it never silently updates an approved module,
license or source hash. `capture` is the explicit maintainer operation for
recording a newly reviewed source candidate, followed by independent review.
Legal evidence and the generated inventory must enter the prepared context
before its final byte/mode inventory is sealed.

After extracting the actual immutable image's binary, legal and provenance
directories, audit the shipped binary without executing it:

```sh
python3 scripts/check-go-judge-licenses.py verify \
  --binary .local/release-evidence/bin/go-judge \
  --legal-root .local/release-evidence/legal \
  --inventory .local/release-evidence/provenance/go-judge-runtime-dependencies.json \
  --output .local/release-evidence/provenance
```

The auditor requires the embedded inventory to equal the independently reviewed
repository inventory, checks every retained legal hash, requires a Linux amd64
ELF and the exact Go build profile, and compares the actual `go version -m`
module/version closure. It emits:

- `go-judge-binary-dependencies.json`: actual binary SHA-256, size, build settings,
  module versions and the reviewed inventory checksum.
- `go-judge.spdx.json`: SPDX 2.3 packages, dependency relationships, binary/source
  hashes, and verbatim extracted `LicenseRef` terms.
- `go-judge.cdx.json`: CycloneDX 1.6 components, package URLs, dependency edges,
  hashes, exact retained terms and explicit binary/source-only scope.

The SBOMs use extracted LicenseRef terms for module grants and preserve
`NOASSERTION` conclusions; they do not guess standard license identifiers from
project names or substitute a summary for the original grant. The SDK's standard
identifier comes from its existing independently reviewed evidence. The SPDX
document metadata uses SPDX's required CC0 data license.

On 2026-10-08 the exact source/legal comparison and actual cross-compiled Linux
amd64 binary audit passed with the locked macOS Go 1.26.8 SDK. That proves the
measured build/legal closure; the final-image audit must repeat against the
extracted binary. These records do not certify sandbox isolation or deployment.
