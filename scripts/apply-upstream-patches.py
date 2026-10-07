#!/usr/bin/env python3
"""Export allowlisted pinned sources and apply verified Code Startrack patches.

This prepares build inputs; it never executes upstream programs or downloads
dependencies. Source caches are populated by scripts/upstream.py separately.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import tempfile

import upstream

ROOT = Path(__file__).resolve().parents[1]
COMPONENTS = ("problemtools", "go-judge", "go-judge-demo")
PROVENANCE_NAME = ".startrack-upstream-build.json"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_relative(value: str) -> PurePosixPath:
    """Reject ambiguous Git/build paths rather than normalize unsafe input."""
    path = PurePosixPath(value)
    if (
        not value or not path.parts or value != path.as_posix() or path.is_absolute()
        or ".." in path.parts or ".git" in path.parts
        or "\\" in value or ":" in value
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise ValueError("Unsafe relative build path")
    return path


def matches(path: str, rule: str) -> bool:
    return path.startswith(rule) if rule.endswith("/") else path == rule


def selected(path: str, series: dict) -> bool:
    return (
        any(matches(path, rule) for rule in series["includePaths"])
        and not any(matches(path, rule) for rule in series["excludePaths"])
    )


def load_series(component: dict) -> dict:
    path = ROOT / "patches" / component["name"] / "series.json"
    series = json.loads(path.read_text(encoding="utf-8"))
    if (
        series.get("schemaVersion") != 1
        or series.get("component") != component["name"]
        or series.get("repository") != component["repository"]
        or series.get("baseCommit") != component["commit"]
    ):
        raise ValueError("Patch series does not match the locked upstream identity")
    for key in ("includePaths", "excludePaths"):
        if not isinstance(series.get(key), list):
            raise ValueError("Patch series lacks explicit source allowlist/exclusions")
        for rule in series[key]:
            safe_relative(rule.removesuffix("/"))
    if not series["includePaths"] or not isinstance(series.get("patches"), list) or not series["patches"]:
        raise ValueError("Patch series is empty")
    if component["name"] == "problemtools":
        if "support/viva/" not in series["excludePaths"]:
            raise ValueError("problemtools build must exclude the complete VIVA directory")
        if series.get("unsupportedPackageExtensions") != [".viva"]:
            raise ValueError("VIVA package classification must be explicitly unsupported")
    files = set()
    for patch in series["patches"]:
        relative = safe_relative(patch["path"])
        if relative.parts[:2] != ("patches", component["name"]):
            raise ValueError("Patch is outside its owned component directory")
        source = ROOT / relative
        if source.is_symlink() or sha256(source.read_bytes()) != patch["sha256"]:
            raise ValueError("Patch checksum mismatch")
        if not all(patch.get(key) for key in ("reason", "licenseImpact", "upgradeCondition", "files")):
            raise ValueError("Patch provenance is incomplete")
        for record in patch["files"]:
            safe_relative(record["path"])
            if record["path"] in files or not selected(record["path"], series):
                raise ValueError("Patch modifies a duplicate or excluded source path")
            files.add(record["path"])
    return series


def destination_path(value: str) -> Path:
    destination = Path(os.path.abspath(value))
    try:
        relative = destination.relative_to(ROOT)
    except ValueError as exc:
        raise ValueError("Build destination must be inside the repository's ignored .cache/.local directories") from exc
    if len(relative.parts) < 2 or relative.parts[0] not in (".cache", ".local"):
        raise ValueError("Build destination must be below .cache/ or .local/")
    current = ROOT
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("Build destination contains a symbolic link")
    if destination.exists():
        raise ValueError("Build destination already exists; choose a fresh destination")
    return destination


def export_sources(component: dict, series: dict, repository: Path, stage: Path) -> list[dict]:
    records = []
    tree = upstream.git(["ls-tree", "-r", "-z", component["commit"]], repository=repository)
    for entry in tree.split(b"\0"):
        if not entry:
            continue
        metadata, name = entry.split(b"\t", 1)
        relative = name.decode("utf-8", "strict")
        safe_relative(relative)
        if not selected(relative, series):
            continue
        mode, kind, object_id = metadata.decode("ascii").split()
        if kind != "blob" or mode not in ("100644", "100755"):
            raise ValueError("Selected upstream build input must be a regular Git blob")
        data = upstream.git(["cat-file", "blob", object_id], repository=repository)
        output = stage / relative
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(data)
        output.chmod(0o755 if mode == "100755" else 0o644)
        records.append({"path": relative, "mode": mode, "sourceSha256": sha256(data)})
    if not records:
        raise ValueError("Source allowlist selected no build inputs")
    return records


def apply_patches(series: dict, stage: Path) -> None:
    environment = dict(os.environ)
    for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"):
        environment.pop(name, None)
    environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    # The staging directory is under this repository, but patches target the
    # exported source tree, never the enclosing Code Startrack worktree.
    environment["GIT_CEILING_DIRECTORIES"] = str(stage.parent)
    for patch in series["patches"]:
        for record in patch["files"]:
            file = stage / record["path"]
            if record["baseSha256"] is None:
                if file.exists():
                    raise ValueError("Patch addition unexpectedly exists in the upstream baseline")
            elif not file.is_file() or sha256(file.read_bytes()) != record["baseSha256"]:
                raise ValueError("Patch base-file checksum mismatch")
        arguments = ["git", "-c", f"core.hooksPath={os.devnull}", "apply", "--whitespace=error"]
        patch_path = str(ROOT / patch["path"])
        subprocess.run([*arguments, "--check", patch_path], cwd=stage, env=environment, check=True, capture_output=True)
        subprocess.run([*arguments, patch_path], cwd=stage, env=environment, check=True, capture_output=True)
        for record in patch["files"]:
            file = stage / record["path"]
            if file.is_symlink() or not file.is_file() or sha256(file.read_bytes()) != record["patchedSha256"]:
                raise ValueError("Patched source checksum mismatch")


def audit_inputs(stage: Path, component: dict, series: dict, records: list[dict]) -> list[dict]:
    """Verify the actual staging tree and unchanged license/NOTICE payloads."""
    expected = {record["path"] for record in records}
    expected.update(record["path"] for patch in series["patches"] for record in patch["files"])
    actual = set()
    for directory, names, files in os.walk(stage, followlinks=False):
        for name in names + files:
            path = Path(directory) / name
            if path.is_symlink():
                raise ValueError("Prepared build input contains a symbolic link")
        for name in files:
            path = Path(directory) / name
            # Reject FIFOs/devices/sockets before reading or hashing content.
            if not stat.S_ISREG(path.stat().st_mode):
                raise ValueError("Prepared build input is not a regular file")
            relative = path.relative_to(stage).as_posix()
            if not selected(relative, series):
                raise ValueError("Prepared build input is outside its source allowlist")
            actual.add(relative)
    if actual != expected:
        raise ValueError("Prepared source inventory differs from selected and patched inputs")
    for evidence in component["license"]["evidence"]:
        file = stage / evidence["upstream_path"]
        if not file.is_file() or sha256(file.read_bytes()) != evidence["sha256"]:
            raise ValueError("Upstream license/NOTICE payload was omitted or changed")
    source_records = {record["path"]: record for record in records}
    patch_records = {record["path"]: record for patch in series["patches"] for record in patch["files"]}
    result = []
    for relative in sorted(actual):
        file = stage / relative
        source_record = source_records.get(relative)
        expected_hash = patch_records.get(relative, {}).get("patchedSha256")
        if expected_hash is None:
            expected_hash = source_record["sourceSha256"]
        if sha256(file.read_bytes()) != expected_hash:
            raise ValueError("Prepared source changed outside the recorded patch series")
        expected_mode = patch_records.get(relative, {}).get("mode")
        if expected_mode is None:
            expected_mode = source_record["mode"]
        if expected_mode not in ("100644", "100755"):
            raise ValueError("Prepared source has an unsupported recorded file mode")
        actual_mode = file.stat().st_mode
        if not stat.S_ISREG(actual_mode) or stat.S_IMODE(actual_mode) != int(expected_mode[-3:], 8):
            raise ValueError("Prepared source file mode differs from recorded provenance")
        result.append({"path": relative, "sizeBytes": file.stat().st_size, "sha256": expected_hash,
                       "sourceSha256": source_record["sourceSha256"] if source_record else None,
                       "mode": expected_mode})
    return result


def prepare(name: str, value: str) -> Path:
    component = next(item for item in upstream.load_components() if item["name"] == name)
    series = load_series(component)
    repository = upstream.cache_path(name)
    upstream.verify(component, repository)
    destination = destination_path(value)
    destination.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=f".{name}-prepare-", dir=destination.parent))
    try:
        records = export_sources(component, series, repository, stage)
        apply_patches(series, stage)
        inventory = audit_inputs(stage, component, series, records)
        provenance = {
            "schemaVersion": 1, "component": name, "repository": component["repository"],
            "baseCommit": component["commit"], "patches": series["patches"],
            "includePaths": series["includePaths"], "excludePaths": series["excludePaths"],
            "unsupportedPackageExtensions": series.get("unsupportedPackageExtensions", []),
            "inventory": inventory, "qualification": "BUILD_INPUTS_ONLY",
        }
        (stage / PROVENANCE_NAME).write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
        # Recheck immediately before publication. Never overwrite an existing path.
        destination_path(value)
        stage.rename(destination)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    return destination


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("component", choices=COMPONENTS)
    parser.add_argument("--destination", required=True, help="Fresh directory below .cache/ or .local/")
    options = parser.parse_args()
    output = prepare(options.component, options.destination)
    print(f"Prepared {options.component}: {output.relative_to(ROOT)}; no upstream execution or image qualification")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, KeyError, StopIteration, subprocess.CalledProcessError) as exc:
        # Git diagnostics may contain source paths/configuration; keep output bounded.
        print(f"Upstream preparation failed ({type(exc).__name__}); no build inputs published.", file=sys.stderr)
        raise SystemExit(1) from None
