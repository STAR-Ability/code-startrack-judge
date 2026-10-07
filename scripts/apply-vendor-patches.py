#!/usr/bin/env python3
"""Apply exact reviewed patches to a freshly verified go-judge vendor tree."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def regular(path: Path) -> bytes:
    if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
        raise ValueError("Vendor input must be a regular file")
    return path.read_bytes()


def digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def apply(directory: Path) -> dict:
    directory = directory.absolute()
    relative = directory.relative_to(ROOT)
    if relative.parts[0] not in (".local", ".cache") or directory.resolve() != directory:
        raise ValueError("Vendor patches require an ignored, nonsymlink staging directory")
    if (directory / ".startrack-vendor-patches.json").exists():
        raise ValueError("Vendor patches already applied")
    series = json.loads(regular(ROOT / "patches/go-sandbox/series.json"))
    lock = json.loads(regular(ROOT / "upstream.lock.json"))
    component = next(item for item in lock["supplemental_licenses"] if item["name"] == "go-sandbox")
    if component.get("patches") != series.get("patches") or component.get("source_assembly") != {"policy": "verified-go-module-vendor", "descriptor": "patches/go-sandbox/series.json"}:
        raise ValueError("Vendor patch inventory differs from the reviewed lock")
    if series["schemaVersion"] != 1 or series["component"] != component["name"] or series["repository"] != component["repository"] or series["baseCommit"] != component["commit"] or series["baseVersion"] != component["version"] or series["module"] != "github.com/criyle/go-sandbox":
        raise ValueError("Vendor patch does not match locked source identity")
    modules = regular(directory / "vendor/modules.txt").decode().splitlines()
    if modules.count("# " + series["module"] + " " + series["baseVersion"]) != 1:
        raise ValueError("Vendor selected an unexpected go-sandbox version")
    source = directory / "vendor" / series["module"]
    if not source.is_dir() or source.resolve() != source:
        raise ValueError("Vendor module or its ancestors must not be symbolic links")
    before = {}
    for path in source.rglob("*"):
        if path.is_symlink() or not path.is_dir() and not stat.S_ISREG(path.stat().st_mode):
            raise ValueError("Vendor tree contains an unsafe input")
        if path.is_file():
            before[path.relative_to(source).as_posix()] = (digest(regular(path)), stat.S_IMODE(path.stat().st_mode))
    allowed = {}
    for patch in series["patches"]:
        path = Path(patch["path"])
        if path.parts[:2] != ("patches", "go-sandbox") or path.is_absolute() or ".." in path.parts or digest(regular(ROOT / path)) != patch["sha256"]:
            raise ValueError("Vendor patch bytes or path differ")
        for record in patch["files"]:
            name = record["path"]
            if Path(name).is_absolute() or ".." in Path(name).parts or before.get(name) != (record["baseSha256"], int(record["mode"], 8) & 0o777):
                raise ValueError("Vendor base bytes or mode differ")
            allowed[name] = (record["patchedSha256"], int(record["mode"], 8) & 0o777)
    for item in component["license"]["evidence"]:
        if digest(regular(ROOT / item["local_path"])) != item["sha256"]:
            raise ValueError("Locked vendor license differs")
    spec = importlib.util.spec_from_file_location("startrack_patches", ROOT / "scripts/apply-upstream-patches.py")
    module = importlib.util.module_from_spec(spec)
    # Resolve its trusted sibling module even when this preparer is imported
    # through importlib rather than launched as a script.
    saved_path = list(sys.path)
    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path[:] = saved_path
    module.apply_patches(series, source)
    after = {}
    for path in source.rglob("*"):
        if path.is_symlink() or not path.is_dir() and not stat.S_ISREG(path.stat().st_mode):
            raise ValueError("Patched vendor tree contains an unsafe input")
        if path.is_file():
            after[path.relative_to(source).as_posix()] = (digest(regular(path)), stat.S_IMODE(path.stat().st_mode))
    expected = dict(before)
    expected.update(allowed)
    if after != expected:
        raise ValueError("Vendor patch changed an unrecorded source or mode")
    record = {"schemaVersion": 1, "scope": "BUILD_INPUTS_ONLY", "source": component,
              "patches": series["patches"], "files": [{"path": path, "sha256": values[0], "mode": f"{values[1]:04o}"} for path, values in sorted(after.items())]}
    (directory / ".startrack-vendor-patches.json").write_text(json.dumps(record, indent=2) + "\n")
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    apply(args.directory)
    print("Exact go-sandbox vendor patch applied; Linux qualification remains separate")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, StopIteration, subprocess.SubprocessError):
        print("vendor-patches: source/patch verification failed", file=sys.stderr)
        sys.exit(1)
