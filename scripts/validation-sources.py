#!/usr/bin/env python3
"""Verify or fetch exact corresponding source; never resolve package versions.

Source bundles are distribution artifacts separate from the runtime image.
The retained signed Debian metadata binds each source archive and build patch;
Python sdists and native Cargo source records identify the selected wheels.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import lzma
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from urllib.parse import urlparse
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parent.parent
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
FILENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+~%-]*\Z")
HOSTS = {"files.pythonhosted.org", "snapshot.debian.org", "www.python.org", "download-mirror.savannah.gnu.org"}


def fail(message):
    raise ValueError(message)


def sha_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for data in iter(lambda: stream.read(1 << 20), b""):
            digest.update(data)
    return digest.hexdigest()


def read_lock(path):
    raw = path.read_bytes()
    lock = json.loads(raw)
    if lock.get("schemaVersion") != 1 or lock.get("platform") != "linux/amd64":
        fail("Unsupported corresponding-source identity")
    names = set()
    for item in lock["sourceArchives"] + [meta["sourceIndex"] for meta in lock["signedMetadata"]]:
        name = item["filename"]
        if not FILENAME.fullmatch(name) or name in names:
            fail("Unsafe or duplicate corresponding-source filename")
        names.add(name)
        url = urlparse(item["url"])
        if url.scheme != "https" or url.hostname not in HOSTS or url.username or url.password or url.port not in (None, 443) or url.fragment:
            fail("Unapproved corresponding-source origin")
        if not DIGEST.fullmatch(item["sha256"]) or type(item["sizeBytes"]) is not int or not 0 < item["sizeBytes"] <= 8 << 30:
            fail("Invalid corresponding-source checksum or bound")
    return lock, hashlib.sha256(raw).hexdigest()


def evidence(lock):
    yield lock["debianKeyring"]
    for meta in lock["signedMetadata"]:
        yield meta["inRelease"]
        yield meta["selectedParagraphs"]


def legal_file(entry, legal_root):
    relative = Path(entry["path"])
    if relative.is_absolute() or ".." in relative.parts or relative.parts[:3] != ("docs", "licenses", "validation-tools"):
        fail("Unsafe corresponding-source evidence path")
    path = legal_root / relative
    if path.is_symlink() or not path.is_file() or not DIGEST.fullmatch(entry["sha256"]) or sha_file(path) != entry["sha256"]:
        fail("Corresponding-source evidence mismatch")
    return path


def paragraphs(raw):
    for text in raw.decode("utf-8").split("\n\n"):
        if not text.strip():
            continue
        value = {}
        field = None
        for line in text.splitlines():
            if line.startswith(" ") and field:
                value[field] += "\n" + line[1:]
            elif ":" in line:
                field, content = line.split(":", 1)
                value[field] = content.lstrip(" ")
        yield value, (text + "\n\n").encode("utf-8")


def check(lock, legal_root, tools_lock, lock_digest):
    tools = json.loads(tools_lock.read_bytes())
    source_manifest = tools.get("correspondingSourceManifest")
    if not isinstance(source_manifest, dict) or not isinstance(lock_digest, str) or not DIGEST.fullmatch(lock_digest) or source_manifest.get("sha256") != lock_digest:
        fail("Corresponding-source manifest differs from the frozen tools identity")
    for entry in evidence(lock):
        legal_file(entry, legal_root)
    archives = {item["filename"]: item for item in lock["sourceArchives"]}
    indexed = {}
    for meta in lock["signedMetadata"]:
        release = legal_file(meta["inRelease"], legal_root).read_text()
        record = meta["sourceIndex"]
        expected = f'{record["sha256"]} {record["sizeBytes"]} main/source/Sources.xz'
        if expected not in {" ".join(line.split()) for line in release.splitlines()}:
            fail("Source index differs from its retained signed release")
        for section, raw in paragraphs(legal_file(meta["selectedParagraphs"], legal_root).read_bytes()):
            identity = (section["Package"], section["Version"])
            if identity in indexed:
                fail("Duplicate selected source paragraph")
            indexed[identity] = (section, hashlib.sha256(raw).hexdigest(), meta)
    covered = set()
    for source in lock["debianSources"]:
        identity = (source["name"], source["version"])
        section, digest, meta = indexed[identity]
        if digest != source["paragraphSha256"] or source["sourceIndexSha256"] != meta["sourceIndex"]["sha256"] or (source["repository"], source["suite"], source["snapshot"]) != (meta["repository"], meta["suite"], meta["snapshot"]):
            fail("Selected corresponding-source identity mismatch")
        expected = []
        for line in section["Checksums-Sha256"].splitlines():
            if not line.strip():
                continue
            digest, size, filename = line.split()
            record = archives[filename]
            origin = f'https://snapshot.debian.org/archive/{source["repository"]}/{source["snapshot"]}/{section["Directory"]}/{filename}'
            if (record["sha256"], record["sizeBytes"], record["url"], record["name"], record["version"]) != (digest, int(size), origin, source["name"], source["version"]):
                fail("Source archive differs from its signed index paragraph")
            expected.append(filename)
        if expected != source["archives"]:
            fail("Corresponding-source archive closure is incomplete")
        covered.update(tuple(item) for item in source["binaryPackages"])
    if len(indexed) != len(lock["debianSources"]):
        fail("Unreferenced selected source paragraph")
    required = {(entry["name"], entry["version"]) for entry in tools["baselineAnchors"] + tools["debs"]}
    if required != covered or tools["baseImage"] != lock["baseImage"]:
        fail("Corresponding source does not cover the exact installed OS inventory")
    wheels = {(item["name"].lower(), item["version"]) for item in tools["wheels"] + tools["baselinePythonPackages"]}
    sdists = {(item["name"].lower(), item["version"]) for item in lock["pythonSources"]}
    if wheels != sdists or any(archives[item["filename"]] != item for item in lock["pythonSources"]):
        fail("Corresponding Python source does not cover the exact wheels")
    vendors = {(item["name"].lower(), item["version"]) for package in tools["baselinePythonPackages"] for item in package["vendoredPackages"]}
    sources = {(item["name"].lower(), item["version"]) for item in lock["pythonVendorSources"]}
    if vendors != sources or any(archives[item["filename"]] != item for item in lock["pythonVendorSources"]):
        fail("Corresponding source does not cover the frozen pip vendor inventory")
    if lock["pythonRuntimeSources"] != [tools["pythonRuntimeSource"]] or any(archives[item["filename"]] != item for item in lock["pythonRuntimeSources"]):
        fail("Corresponding source does not cover the frozen CPython runtime")
    if lock["pythonNativeVendorSources"] != tools["pythonNativeVendorSources"] or any(archives[item["filename"]] != item for item in lock["pythonNativeVendorSources"]):
        fail("Corresponding source does not cover the frozen native Python vendors")
    wheel_records = {(entry["name"].lower(), entry["version"]): entry for entry in tools["wheels"]}
    wheel_versions = {entry["name"].lower(): entry["version"] for entry in tools["wheels"]}
    for item in lock["pythonNativeVendorSources"]:
        if wheel_versions.get(item["ownerPackageName"]) != item["ownerPackageVersion"] or not item.get("licenses"):
            fail("Native Python source owner or original grant is incomplete")
    for group in ("pythonSources", "pythonVendorSources", "pythonRuntimeSources", "pythonNativeVendorSources"):
        for item in lock[group]:
            licenses = item.get("licenses")
            # Ordinary sdists retain their program's notices in the exact
            # matching wheel. Baseline pip and the other source groups carry
            # their own lists. An explicit empty list never falls back.
            if group == "pythonSources" and "licenses" not in item:
                licenses = wheel_records.get((item["name"].lower(), item["version"]), {}).get("licenses")
            if not isinstance(licenses, list) or not licenses:
                fail("Original Python source grant is incomplete")
            for entry in licenses:
                legal_file(entry, legal_root)


def artifact_groups(lock):
    for meta in lock["signedMetadata"]:
        yield "indexes", meta["sourceIndex"]
    for item in lock["sourceArchives"]:
        yield "archives", item


def verify_file(path, entry):
    if path.is_symlink() or not path.is_file() or path.stat().st_size != entry["sizeBytes"] or sha_file(path) != entry["sha256"]:
        fail("Corresponding-source artifact mismatch")


def fetch(lock, bundle, digest):
    def fetch_one(item):
        directory, entry = item
        target = bundle / directory / entry["filename"]
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            verify_file(target, entry)
            return
        descriptor, temporary = tempfile.mkstemp(prefix=".source-", dir=target.parent)
        try:
            with os.fdopen(descriptor, "wb") as output, urlopen(entry["url"], timeout=90) as response:
                final = urlparse(response.geturl())
                if final.scheme != "https" or final.hostname not in HOSTS:
                    fail("Unapproved corresponding-source redirect")
                remaining = entry["sizeBytes"]
                while remaining:
                    data = response.read(min(1 << 20, remaining))
                    if not data:
                        fail("Incomplete corresponding-source download")
                    output.write(data)
                    remaining -= len(data)
                if response.read(1):
                    fail("Corresponding-source size exceeded")
                output.flush()
                os.fsync(output.fileno())
            verify_file(Path(temporary), entry)
            Path(temporary).replace(target)
        finally:
            Path(temporary).unlink(missing_ok=True)
    # Start the large TeX source archives promptly while smaller archives fill
    # the remaining bounded download slots.
    with ThreadPoolExecutor(max_workers=8) as workers:
        list(workers.map(fetch_one, sorted(artifact_groups(lock), key=lambda item: -item[1]["sizeBytes"])))
    (bundle / "inventory.json").write_text(json.dumps({"schemaVersion": 1, "lockSha256": digest, "platform": lock["platform"]}, indent=2) + "\n")


def verify(lock, bundle, digest, legal_root):
    for directory, entry in artifact_groups(lock):
        verify_file(bundle / directory / entry["filename"], entry)
    if json.loads((bundle / "inventory.json").read_text()) != {"schemaVersion": 1, "lockSha256": digest, "platform": lock["platform"]}:
        fail("Corresponding-source bundle identity mismatch")
    for meta in lock["signedMetadata"]:
        full = {(item["Package"], item["Version"]): raw for item, raw in paragraphs(lzma.decompress((bundle / "indexes" / meta["sourceIndex"]["filename"]).read_bytes()))}
        for section, raw in paragraphs(legal_file(meta["selectedParagraphs"], legal_root).read_bytes()):
            if full.get((section["Package"], section["Version"])) != raw:
                fail("Selected source paragraph differs from the full signed index")


def signatures(lock, legal_root):
    for meta in lock["signedMetadata"]:
        subprocess.run(["gpgv", "--keyring", str(legal_file(lock["debianKeyring"], legal_root)), str(legal_file(meta["inRelease"], legal_root))], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "fetch", "verify", "verify-signatures"))
    parser.add_argument("--lock", type=Path, default=ROOT / "validation-sources.lock.json")
    parser.add_argument("--tools-lock", type=Path, default=ROOT / "validation-tools.lock.json")
    parser.add_argument("--legal-root", type=Path, default=ROOT)
    parser.add_argument("--bundle", type=Path)
    args = parser.parse_args()
    lock, digest = read_lock(args.lock)
    check(lock, args.legal_root, args.tools_lock, digest)
    bundle = args.bundle or ROOT / ".cache/validation-sources" / digest
    if args.action == "fetch":
        fetch(lock, bundle, digest)
        verify(lock, bundle, digest, args.legal_root)
    elif args.action == "verify":
        verify(lock, bundle, digest, args.legal_root)
    elif args.action == "verify-signatures":
        signatures(lock, args.legal_root)
    print(f'Corresponding source {args.action} passed: {len(lock["debianSources"])} Debian source versions, {len(lock["pythonSources"])} Python sdists, {len(lock["sourceArchives"])} archives')


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError, json.JSONDecodeError, lzma.LZMAError) as error:
        print(f"Corresponding-source operation failed: {type(error).__name__}", file=sys.stderr)
        sys.exit(1)
