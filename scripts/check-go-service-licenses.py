#!/usr/bin/env python3
"""Verify legal evidence and the exact native Go command dependency closure.

Default mode is read-only. --refresh-closure updates measured reachability after
source edits, but never approves a new module/version or assigns license terms.
The owned native binaries are distinct from the sandbox/compiler/OS image SBOM.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "docs/licenses/go-service-dependencies.json"
PROFILES = (("linux", "amd64"), ("linux", "arm64"), ("darwin", "amd64"), ("darwin", "arm64"))


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def stream_json(raw: str) -> list[dict]:
    decoder = json.JSONDecoder()
    values = []
    offset = 0
    while offset < len(raw):
        while offset < len(raw) and raw[offset].isspace():
            offset += 1
        if offset == len(raw):
            break
        value, offset = decoder.raw_decode(raw, offset)
        values.append(value)
    return values


def go_command(go: str, *args: str, goos: str | None = None, goarch: str | None = None) -> str:
    env = dict(os.environ, GOTOOLCHAIN="local", CGO_ENABLED="0", GOEXPERIMENT="", GOFLAGS="")
    if goos is not None:
        env["GOOS"] = goos
    if goarch is not None:
        env["GOARCH"] = goarch
    result = subprocess.run([go, *args], cwd=ROOT, env=env, text=True, capture_output=True, check=False)
    if result.returncode:
        # A configured module proxy could contain a credential. Do not echo its
        # URL or subprocess diagnostics through repository validation output.
        raise ValueError(f"Go dependency inspection failed (exit {result.returncode})")
    return result.stdout


def legal_evidence(record: dict, source_root: Path | None = None) -> None:
    # Source URLs identify immutable reviewed revisions, never moving tags.
    origin = record["source"]
    if not re.fullmatch(r"[0-9a-f]{40}", origin["revision"]):
        raise ValueError("license source revision must be an immutable Git commit")
    prefix = origin["repositoryUrl"] + "/blob/" + origin["revision"] + "/"
    for evidence in record["licenseEvidence"]:
        if evidence["sourceUrl"] != prefix + evidence["upstreamPath"]:
            raise ValueError("license evidence URL does not identify its retained source revision")
        local = ROOT / evidence["localPath"]
        if not local.resolve().is_relative_to(ROOT) or not local.is_file():
            raise ValueError("missing or out-of-repository license evidence")
        if digest(local) != evidence["sha256"]:
            raise ValueError(f"license evidence checksum changed: {evidence['localPath']}")
        if source_root is None:
            continue
        upstream = source_root / evidence["upstreamPath"]
        if evidence.get("kind") == "verbatim-source-license-header":
            if digest(upstream) != evidence["sourceSha256"]:
                raise ValueError("canonicalizer license-header source checksum changed")
            lines = upstream.read_bytes().splitlines(keepends=True)
            retained = b"".join(lines[evidence["firstLine"] - 1:evidence["lastLine"]])
            if retained != local.read_bytes():
                raise ValueError("retained canonicalizer copyright header differs from upstream")
        elif upstream.read_bytes() != local.read_bytes():
            raise ValueError(f"retained license differs from selected dependency: {evidence['localPath']}")


def measure(go: str, inventory: dict, modules: list[dict]) -> dict:
    known = {item["modulePath"]: item for item in inventory["modules"]}
    selected = {item["Path"]: item for item in modules if not item.get("Main")}
    profiles = []
    shipped = set()
    reachable = set()
    packages_by_module: dict[str, set[str]] = {}
    for goos, goarch in PROFILES:
        targets = []
        for target in inventory["entrypoints"]:
            packages = stream_json(go_command(go, "list", "-mod=readonly", "-deps", "-json", target, goos=goos, goarch=goarch))
            paths = sorted({package["Module"]["Path"] for package in packages if package.get("Module") and not package["Module"].get("Main")})
            shipped.update(paths)
            for package in packages:
                module = package.get("Module", {})
                if module.get("Path") in paths:
                    packages_by_module.setdefault(module["Path"], set()).add(package["ImportPath"])
            targets.append({"entrypoint": target, "dependencyPackageCount": len(packages), "modulePaths": paths})
        profiles.append({"goos": goos, "goarch": goarch, "cgoEnabled": False, "goExperiment": "", "targets": targets})
    tests = stream_json(go_command(go, "list", "-mod=readonly", "-deps", "-test", "-json", "./..."))
    for package in tests:
        module = package.get("Module", {})
        if module and not module.get("Main"):
            reachable.add(module["Path"])
            packages_by_module.setdefault(module["Path"], set()).add(package["ImportPath"])
    covered = shipped | reachable
    refreshed = []
    for path in sorted(covered):
        module = selected[path]
        if path not in known or known[path]["version"] != module["Version"]:
            raise ValueError(f"new module/version requires reviewed license evidence: {path}@{module['Version']}")
        record = dict(known[path])
        if record["moduleSum"] != module.get("Sum") or record["goModSum"] != module.get("GoModSum"):
            raise ValueError(f"module checksum differs from retained provenance: {path}")
        record["direct"] = not module.get("Indirect", False)
        record["linkScope"] = "NATIVE_COMMAND_RUNTIME" if path in shipped else "OWNED_PACKAGE_TESTS_ONLY"
        record["importedPackages"] = sorted(packages_by_module[path])
        refreshed.append(record)
    if covered != set(known):
        raise ValueError("inventory contains a module no longer imported by the native commands or owned-package tests")
    return {
        "toolchainLockSha256": digest(ROOT / "toolchain.lock.json"),
        "goModSha256": digest(ROOT / "go.mod"),
        "goSumSha256": digest(ROOT / "go.sum"),
        "modules": refreshed,
        "buildProfiles": profiles,
        "testOnlyModules": sorted(reachable - shipped),
        "excludedModuleGraph": [{
            "modulePath": path,
            "version": selected[path]["Version"],
            "reason": "NOT_IMPORTED_BY_OWNED_COMMANDS_OR_PACKAGE_TESTS",
        } for path in sorted(set(selected) - covered)],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--refresh-closure", action="store_true")
    parser.add_argument("--go", default=str(ROOT / ".local/toolchains/go1.26.8/go/bin/go"))
    args = parser.parse_args()
    try:
        inventory = json.loads(INVENTORY.read_text())
        locked = json.loads((ROOT / "toolchain.lock.json").read_text())
        version = inventory["goToolchain"]["version"]
        if locked["goVersion"] != version or f"go{version} " not in go_command(args.go, "version"):
            raise ValueError("license inventory must use the exact locked Go SDK")
        goroot = Path(go_command(args.go, "env", "GOROOT").strip())
        legal_evidence(inventory["goToolchain"], goroot)
        modules = stream_json(go_command(args.go, "list", "-mod=readonly", "-m", "-json", "all"))
        selected = {item["Path"]: item for item in modules if not item.get("Main")}
        for record in inventory["modules"]:
            module = selected.get(record["modulePath"])
            if module is None or module.get("Version") != record["version"] or not module.get("Dir"):
                raise ValueError("licensed module/version is absent from the local selected module cache")
            legal_evidence(record, Path(module["Dir"]))
        measured = measure(args.go, inventory, modules)
        if args.refresh_closure:
            inventory.update(measured)
            INVENTORY.write_text(json.dumps(inventory, ensure_ascii=False, indent=2) + "\n")
        elif any(inventory.get(key) != value for key, value in measured.items()):
            raise ValueError("native Go license dependency closure is stale; review and run --refresh-closure")
        runtime = sum(module["linkScope"] == "NATIVE_COMMAND_RUNTIME" for module in measured["modules"])
        print(f"Native Go license/provenance inventory verified: {runtime} runtime modules, {len(measured['testOnlyModules'])} test-only modules, {len(PROFILES)} build profiles")
        return 0
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
