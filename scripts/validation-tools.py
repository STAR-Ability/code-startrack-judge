#!/usr/bin/env python3
"""Fetch/verify the exact trusted validation-tool bundle; never resolve versions.

Image builds consume pre-fetched files offline. This operator script is not a
judge API, and it never accepts caller URLs or execution commands.
"""
import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile
from urllib.parse import urlparse
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parent.parent
LOCK = ROOT / "validation-tools.lock.json"
ALLOWED_HOSTS = {"files.pythonhosted.org", "static.crates.io", "snapshot.debian.org", "raw.githubusercontent.com"}
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
FILENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+~%-]*\Z")


def fail(message):
    raise ValueError(message)


def read_lock(path):
    raw = path.read_bytes()
    value = json.loads(raw)
    if value.get("schemaVersion") != 1 or value.get("platform") != "linux/amd64" or value.get("pythonVersion") != "3.11.15":
        fail("Unsupported validation bundle identity")
    identities = set()
    source_manifest = value.get("correspondingSourceManifest", {})
    if not FILENAME.fullmatch(source_manifest.get("filename", "")) or not DIGEST.fullmatch(source_manifest.get("sha256", "")) or type(source_manifest.get("sizeBytes")) is not int or not 0 < source_manifest["sizeBytes"] <= 16 << 20:
        fail("Missing corresponding-source manifest identity")
    for group in ("wheels", "debs", "crateSources"):
        if not isinstance(value.get(group), list):
            fail("Missing locked artifact inventory")
        for entry in value[group]:
            filename = entry.get("filename", "")
            if not FILENAME.fullmatch(filename) or (group, filename) in identities:
                fail("Unsafe or duplicate artifact identity")
            identities.add((group, filename))
            if not DIGEST.fullmatch(entry.get("sha256", "")) or type(entry.get("sizeBytes")) is not int or not 0 < entry["sizeBytes"] <= 1 << 30:
                fail("Invalid locked checksum or size")
            address = urlparse(entry.get("url", ""))
            if address.scheme != "https" or address.hostname not in ALLOWED_HOSTS or address.username or address.password or address.port not in (None, 443) or address.fragment:
                fail("Unapproved locked artifact origin")
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", entry.get("name", "")) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:+!~-]*", entry.get("version", "")):
                fail("Invalid locked package identity")
            if not entry.get("licenses"):
                fail("Artifact license evidence is incomplete")
    if {entry.get("name"): entry.get("version") for entry in value.get("baselinePythonPackages", [])} != {"pip": "24.0"}:
        fail("Frozen base Python package inventory changed")
    runtime = value.get("pythonRuntimeSource", {})
    if runtime.get("name") != "CPython" or runtime.get("version") != value["pythonVersion"] or not runtime.get("licenses"):
        fail("Frozen CPython source identity is incomplete")
    for entry in value["baselinePythonPackages"]:
        if not entry.get("licenses") or not entry.get("vendoredPackages"):
            fail("Frozen base Python source/license inventory is incomplete")
    if not value.get("pythonNativeVendorSources"):
        fail("Native Python source/license inventory is incomplete")
    return value, hashlib.sha256(raw).hexdigest()


def sha_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for data in iter(lambda: stream.read(1 << 20), b""):
            digest.update(data)
    return digest.hexdigest()


def verify_file(path, entry):
    if path.is_symlink() or not path.is_file() or path.stat().st_size != entry["sizeBytes"] or sha_file(path) != entry["sha256"]:
        fail("Locked validation artifact mismatch")


def license_entries(lock):
    for group in ("wheels", "debs", "crateSources"):
        for artifact in lock[group]:
            yield from artifact["licenses"]
            yield from artifact.get("sboms", [])
    yield from lock.get("commonLicenses", [])
    yield from lock.get("sourceMetadataEvidence", [])
    for entry in lock["baselinePythonPackages"]:
        yield from entry["licenses"]
    yield from lock["pythonRuntimeSource"]["licenses"]
    for entry in lock["pythonNativeVendorSources"]:
        yield from entry["licenses"]


def verify_legal(lock, legal_root):
    for entry in license_entries(lock):
        relative = Path(entry["path"])
        if relative.is_absolute() or ".." in relative.parts or relative.parts[:3] != ("docs", "licenses", "validation-tools"):
            fail("Unsafe license evidence identity")
        path = legal_root / relative
        if path.is_symlink() or not path.is_file() or not DIGEST.fullmatch(entry["sha256"]) or sha_file(path) != entry["sha256"]:
            fail("Validation license evidence mismatch")
    for package in lock["baselinePythonPackages"]:
        inventory = [entry for entry in package["licenses"] if entry.get("sourcePath") == "pip/_vendor/vendor.txt"]
        if len(inventory) != 1:
            fail("Frozen pip vendor source inventory is absent")
        published = set()
        for line in (legal_root / inventory[0]["path"]).read_text().splitlines():
            match = re.match(r"\s*([\w.-]+)==([^\s#]+)", line)
            if match:
                published.add((match.group(1).lower(), match.group(2)))
        recorded = {(entry["name"].lower(), entry["version"]) for entry in package["vendoredPackages"]}
        if published != recorded or len(recorded) != len(package["vendoredPackages"]):
            fail("Frozen pip vendor inventory differs from its original notice")


def artifact_groups(lock):
    for group, directory in (("wheels", "wheels"), ("debs", "debs"), ("crateSources", "crate-sources")):
        for entry in lock[group]:
            yield directory, entry


def requirements(lock):
    return "".join(f'{entry["name"]}=={entry["version"]} --hash=sha256:{entry["sha256"]}\n' for entry in sorted(lock["wheels"], key=lambda value: value["name"].lower()))


def verify_bundle(lock, bundle, digest):
    for directory, entry in artifact_groups(lock):
        verify_file(bundle / directory / entry["filename"], entry)
    if (bundle / "requirements.txt").read_text() != requirements(lock):
        fail("Locked Python requirement projection mismatch")
    if json.loads((bundle / "inventory.json").read_text()) != {"schemaVersion": 1, "lockSha256": digest, "platform": lock["platform"]}:
        fail("Locked validation inventory projection mismatch")


def fetch(lock, bundle, digest):
    for directory, entry in artifact_groups(lock):
        path = bundle / directory / entry["filename"]
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            verify_file(path, entry)
            continue
        descriptor, temporary = tempfile.mkstemp(prefix=".fetch-", dir=path.parent)
        try:
            with os.fdopen(descriptor, "wb") as output, urlopen(entry["url"], timeout=60) as response:
                final = urlparse(response.geturl())
                if final.scheme != "https" or final.hostname not in ALLOWED_HOSTS:
                    fail("Unapproved artifact redirect")
                remaining = entry["sizeBytes"]
                while remaining:
                    data = response.read(min(1 << 20, remaining))
                    if not data:
                        fail("Incomplete locked artifact download")
                    output.write(data)
                    remaining -= len(data)
                if response.read(1):
                    fail("Locked artifact size exceeded")
                output.flush()
                os.fsync(output.fileno())
            temporary_path = Path(temporary)
            verify_file(temporary_path, entry)
            temporary_path.replace(path)
        finally:
            Path(temporary).unlink(missing_ok=True)
    (bundle / "requirements.txt").write_text(requirements(lock))
    (bundle / "inventory.json").write_text(json.dumps({"schemaVersion": 1, "lockSha256": digest, "platform": lock["platform"]}, indent=2) + "\n")
    verify_bundle(lock, bundle, digest)


def package_version(name):
    result = subprocess.run(["dpkg-query", "-W", "-f=${Version}", name], capture_output=True, text=True, check=False)
    return result.stdout if result.returncode == 0 else None


def install(lock, bundle, digest):
    if platform.system() != "Linux" or platform.machine() != "x86_64" or platform.python_version() != lock["pythonVersion"]:
        fail("Validation tool installation requires the pinned Linux/Python base")
    for entry in lock["baselineAnchors"]:
        if package_version(entry["name"]) != entry["version"]:
            fail("Frozen base package identity changed")
    for entry in lock["baselinePythonPackages"]:
        if importlib.metadata.version(entry["name"]) != entry["version"]:
            fail("Frozen base Python package identity changed")
    paths = [str((bundle / "debs" / entry["filename"]).resolve()) for entry in lock["debs"]]
    environment = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
    # The complete dependency closure was resolved against signed snapshot
    # indexes when this lock was reviewed. Install exactly those files without
    # involving apt sources, indexes, recommendations, or network resolution.
    subprocess.run(["dpkg", "--unpack"] + paths, env=environment, check=True)
    subprocess.run(["dpkg", "--configure", "--pending"], env=environment, check=True)
    subprocess.run([sys.executable, "-m", "pip", "install", "--disable-pip-version-check", "--no-index", "--no-deps", "--force-reinstall", "--require-hashes", "--find-links", str(bundle / "wheels"), "-r", str(bundle / "requirements.txt")], check=True)
    subprocess.run([sys.executable, "-m", "pip", "check"], check=True)
    for entry in lock["baselineAnchors"] + lock["debs"]:
        if package_version(entry["name"]) != entry["version"]:
            fail("Installed package identity does not match the frozen inventory")
    for entry in lock["wheels"] + lock["baselinePythonPackages"]:
        if importlib.metadata.version(entry["name"]) != entry["version"]:
            fail("Installed Python package identity does not match the frozen inventory")
    (bundle / "installed-inventory.json").write_text(json.dumps({
        "schemaVersion": 1,
        "lockSha256": digest,
        "platform": lock["platform"],
        "pythonVersion": platform.python_version(),
        "debianPackages": [{"name": entry["name"], "version": package_version(entry["name"])} for entry in lock["baselineAnchors"] + lock["debs"]],
        "pythonPackages": [{"name": entry["name"], "version": importlib.metadata.version(entry["name"])} for entry in lock["wheels"] + lock["baselinePythonPackages"]],
    }, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("fetch", "verify", "install", "check"))
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--lock", type=Path, default=LOCK)
    parser.add_argument("--legal-root", type=Path, default=ROOT)
    args = parser.parse_args()
    lock, digest = read_lock(args.lock)
    verify_file(args.lock.parent / lock["correspondingSourceManifest"]["filename"], lock["correspondingSourceManifest"])
    verify_legal(lock,args.legal_root)
    bundle = args.bundle or ROOT / ".cache" / "validation-tools" / digest
    if args.action == "fetch":
        fetch(lock, bundle,digest)
    elif args.action in ("verify", "install"):
        verify_bundle(lock, bundle, digest)
        if args.action == "install":
            install(lock, bundle, digest)
    print(f'Validation tool {args.action} passed: {len(lock["wheels"])} wheels, {len(lock["debs"])} Debian packages, {len(lock["crateSources"])} native source records')


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError, json.JSONDecodeError, importlib.metadata.PackageNotFoundError) as error:
        print(f"Validation tool operation failed: {type(error).__name__}", file=sys.stderr)
        sys.exit(1)
