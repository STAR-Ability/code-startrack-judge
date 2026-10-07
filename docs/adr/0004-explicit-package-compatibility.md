# ADR 0004: Preserve originals and adapt packages explicitly

- Status: Accepted
- Date: 2026-10-07
- Accountable roles: repository lead; import, judge/runtime and compliance owners
- Evidence: [API contract](../contracts/v0.2/api.md) §§7/8; [database contract](../contracts/v0.2/database.md) §§4–8

## Context

Pinned OJ-Lab packages use Markdown, metadata extensions, shortnames and resource formats that do not directly match the pinned problemtools legacy format. Treating conversion as invisible or accepting root licensing globally would lose both technical and licensing evidence.

## Decision

Keep original package bytes/source metadata and separately generate a platform manifest plus legacy verification view through pinned `ojlab-kattis-v0.2.1`. Record path/name mappings, escaped validation statements, allowed format adaptations, checksums and explicit unit conversions. Preserve source checker token/float/case semantics. Use pinned problemtools for technical validation, isolate all reference solutions/validators/checkers, and gate publication on technical PASSED plus independent per-package license VERIFIED. Initially publish only supported batch/pass-fail problems; retain unsupported packages and report `PACKAGE_UNSUPPORTED`.

## Reasons

An explicit adapter lets future maintainers distinguish a registered source-format difference from a real tool/reference-solution failure. Separate evidence avoids assuming software repository licensing covers imported problem content.

## Consequences

The adapter needs a typed manifest and reviewed bounded defaults before importer/runtime parallel work; see [Q-007](../contracts/open-questions.md#q-007--shared-manifest-and-conversion-profile). License-review intake and rejected-source retention need [Q-003](../contracts/open-questions.md#q-003--license-evidence-intake-and-review-workflow). Errors cannot be removed or downgraded to claim success. Format/execution adapter upgrades create new artifacts/versions; new validation-tool runs retain prior evidence.

## Alternatives

Silently rewriting originals, using naive trimmed string equality, or skipping technical failures are forbidden by the contract. The incompletely supported `2023-07-draft` format is not a production shortcut.

## Revisit / upgrade conditions

New package modes, adapter versions or problemtools releases require diff/license review and full package regression before switching. Keep historical adapter/schema and source bytes interpretable; do not normalize old archives in place.
