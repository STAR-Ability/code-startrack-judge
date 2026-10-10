# Validation tools and corresponding source

`validation-tools.lock.json` pins the Linux amd64/Python 3.11.15 validation
bundle: 18 wheels, 54 Debian packages, and 173 conservative Cargo source
records supplied by the native wheels' original CycloneDX SBOMs. The Cargo
inventory includes target-specific and build dependencies; presence in that
inventory does not assert linkage into the Linux wheel. Original notices and
SBOMs are retained byte for byte with checksums. Published license metadata is
retained as evidence, without converting an ambiguous label into an inferred
SPDX expression.

The base image also supplies CPython 3.11.15 and pip 24.0. Their original
notices, exact source archives, and all 24 versions in pip's original vendor
inventory are retained. The vendored chardet and certifi sources and notices
are included along with the other vendors. The pip source distribution retains
its own vendor changes. webencodings 0.5.1 omits its license from its source
distribution; the original grant is retained from its exact release commit
`fa2cb5d75ab41e63ace691bc0825d3432ba7d694`, after byte comparison of the
release's implementation with the selected source distribution.

The installer verifies every artifact and notice, checks all 429 packages in
the frozen base image and inherited pip version before and after installation,
unpacks only the locked
local Debian files, and installs every wheel with no index, no dependency
resolver, and mandatory hashes. It records measured versions in
`installed-inventory.json`. LuaLaTeX, the original problemtools PDF sanitation
through Ghostscript, and plasTeX's dvisvgm support use this exact closure.

## Corresponding source delivery

`validation-sources.lock.json` records 233 exact Debian source versions covering
all baseline and added OS packages, plus 19 exact Python source distributions
for the 18 selected wheels and inherited pip, 24 original pip vendor sources,
CPython's original source, and the native FreeType source. Its 791 archives
include upstream source, Debian patches, descriptors, and original build
scripts. The separate source bundle is approximately 3.99 GB; source is not
omitted merely because a package
was inherited from the base image. The 173 Cargo source archives remain pinned
in the validation tool bundle. Reviewed problemtools source and local patch
provenance are additionally retained through `upstream.lock.json` and the image
context's source records.

The GPL notice shipped by Unidecode and the LGPL notices shipped with Pillow's
FriBiDi shim require corresponding source to accompany redistribution. The
exact Unidecode and Pillow source distributions are included. Pillow's shim
loads the base image's FriBiDi 1.0.8; that Debian package's exact patched source
is also included. The wheel's published broad SBOM lists libimagequant, but the
Linux wheel feature inspection reports that support absent; the SBOM is not
used to assert that GPL-covered component is linked. Debian packages, including
Ghostscript, retain their original per-file copyright and license records;
all their corresponding source versions are included rather than relying on a
new written source-offer promise. Baseline notices remain available in the
image's `/usr/share/doc` and `/usr/share/common-licenses`.

Pillow's FreeType 2.14.3 uses the original FreeType License (FTL), whose original
text and dual-license explanation are retained along with the exact FreeType
source. The original public header identifies the 1996–2026 copyright period.
Portions of this software are copyright © 2026 The FreeType Project
(https://freetype.org). All rights reserved. This attribution follows the
original FTL wording; retaining the alternative GPL text does not replace the
selected FTL terms. Pillow's original combined notice also retains the grants
for its bundled native libraries, including XAU, and the exact source retains
FreeType's separately licensed files.

Prepare and verify the companion source artifact before redistribution:

```sh
python3 scripts/validation-sources.py check
python3 scripts/validation-sources.py fetch
python3 scripts/validation-sources.py verify
python3 scripts/validation-tools.py fetch
python3 scripts/validation-tools.py verify
```

Publish the verified source bundle, including the Cargo source directory and
source/patch records, alongside the image through the same distribution
channel. Keep the original notices and manifest with it. The manifest is an
exact source locator and inventory; it is not itself a substitute for delivery
of the corresponding source archives. No written source offer is claimed.

## Signed Debian evidence

Four original signed `InRelease` files, the exact archive keyring from the
pinned base image, and selected verbatim `Sources` paragraphs are retained
under `debian-metadata/`. Full index URLs, sizes, and SHA-256 values are pinned
in the source manifest. The verifier downloads the full immutable indexes,
checks their signed-release hashes, and compares each retained paragraph to
its full index. Source archive hashes and URLs must match those paragraphs.
The additional 2026-08-05 security snapshot supplies the base image's
`linux-libc-dev` 6.1.180-1 source, published after the validation dependency
snapshot of 2026-08-03; it does not change any installed binary package.

In the pinned Linux environment, verify the original archive signatures with:

```sh
python3 scripts/validation-sources.py verify-signatures
```

Neither the portable integrity checks nor this dependency installation smoke
qualifies execution of untrusted packages. Linux runtime isolation and
adversarial acceptance remain separate release evidence.
