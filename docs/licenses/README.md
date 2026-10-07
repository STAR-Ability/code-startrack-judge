# License evidence and distribution responsibilities

Files in this directory are verbatim upstream license/notice evidence. [upstream.lock.json](../../upstream.lock.json) identifies the source repository, immutable revision, original path and SHA-256 of each copy. Do not edit the text to match Code Startrack preferences. Refresh evidence only as a reviewed dependency change; older release locks and distributed bundles remain historical records.

The [third-party notices](../../THIRD_PARTY_NOTICES.md) describe inspected components and remaining scope. [NOTICE](../../NOTICE) preserves known notice attribution. No Code Startrack project license has been selected; the [owner comparison](project-license-decision.md) records the pending decision. Carrying upstream license texts does not license Code Startrack-owned code.

Before distributing a service/validation image, the release owner must inventory what the image actually includes, resolve unknown licensing, include required original LICENSE/NOTICE and modification notices in a readable location (for example `/usr/share/licenses/code-startrack/`), and verify their presence in the built artifact. This Phase 0 evidence bundle is not a declaration that every future transitive dependency, compiler, font, OS package, or bundled binary has been audited.

The problemtools Debian copyright file is retained as declared licensing evidence; it contains a historical `support/checktestdata/*` entry although that path is absent from the pinned tree. The current Python `checktestdata` dependency must be audited at its actual resolved version. VIVA's own MIT declaration does not identify the licensing/version of the nested MigLayout jar or Eclipse loader classes. See [dependency gates](../upstream/dependencies.md).

Imported problem content has independent evidence and publication review under the database contract. Do not put problem-specific permissions into the software SBOM as a substitute for retaining each package's provenance, notices, license file hashes and review record.
