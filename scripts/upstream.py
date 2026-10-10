#!/usr/bin/env python3
"""Fetch and verify locked upstream Git objects; never build or execute source."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / ".cache" / "upstream"


def git(arguments: list[str], *, repository: Path | None = None) -> bytes:
    environment = dict(os.environ)
    environment.update(GIT_TERMINAL_PROMPT="0", GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    command = ["git", "-c", f"core.hooksPath={os.devnull}", "-c", "submodule.recurse=false", "-c", "protocol.file.allow=never"]
    if repository is not None:
        command.extend(["--git-dir", str(repository)])
    completed = subprocess.run([*command, *arguments], cwd=ROOT, env=environment, capture_output=True, check=True)
    return completed.stdout


def load_components() -> list[dict]:
    lock = json.loads((ROOT / "upstream.lock.json").read_text(encoding="utf-8"))
    if lock.get("schema_version") != 1 or not isinstance(lock.get("components"), list) or not lock["components"]:
        raise RuntimeError("Unsupported or empty upstream.lock.json.")
    names: set[str] = set()
    for component in lock["components"]:
        name = component.get("name", "")
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", name) or name in names:
            raise RuntimeError("Invalid or duplicate component name in upstream.lock.json.")
        names.add(name)
        if not re.fullmatch(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\.git", component.get("repository", "")):
            raise RuntimeError(f"Invalid fixed GitHub repository for {name}.")
        if not re.fullmatch(r"[a-f0-9]{40}", component.get("commit", "")):
            raise RuntimeError(f"Invalid full commit for {name}.")
    return lock["components"]


def cache_path(name: str) -> Path:
    for directory in (ROOT / ".cache", CACHE):
        if directory.is_symlink() or (directory.exists() and not directory.is_dir()):
            raise RuntimeError(f"Cache directory must be a regular directory: {directory.relative_to(ROOT)}")
    path = CACHE / f"{name}.git"
    if path.is_symlink():
        raise RuntimeError(f"Refusing symlink cache for {name}.")
    return path


def check_repository(component: dict, repository: Path) -> None:
    if not repository.is_dir():
        raise RuntimeError(f"Missing {component['name']} cache; run make upstream-fetch.")
    if git(["rev-parse", "--is-bare-repository"], repository=repository).strip() != b"true":
        raise RuntimeError(f"Expected a bare Git object cache for {component['name']}.")
    origin = git(["remote", "get-url", "origin"], repository=repository).decode().strip()
    if origin != component["repository"]:
        raise RuntimeError(f"Unexpected cache origin for {component['name']}; preserve it and investigate rather than overwriting it.")


def verify(component: dict, repository: Path) -> None:
    check_repository(component, repository)
    commit = component["commit"]
    actual = git(["rev-parse", "--verify", f"{commit}^{{commit}}"], repository=repository).decode().strip()
    if actual != commit:
        raise RuntimeError(f"Commit mismatch for {component['name']}.")
    git(["fsck", "--full", "--no-reflogs"], repository=repository)
    for evidence in component.get("license", {}).get("evidence", []):
        source = PurePosixPath(evidence["upstream_path"])
        local = PurePosixPath(evidence["local_path"])
        if source.is_absolute() or local.is_absolute() or ".." in source.parts or ".." in local.parts:
            raise RuntimeError(f"Unsafe evidence path for {component['name']}.")
        expected = evidence["sha256"]
        if not re.fullmatch(r"[a-f0-9]{64}", expected):
            raise RuntimeError(f"Invalid evidence checksum for {component['name']}.")
        upstream_bytes = git(["show", f"{commit}:{source.as_posix()}"], repository=repository)
        if hashlib.sha256(upstream_bytes).hexdigest() != expected:
            raise RuntimeError(f"Upstream license checksum mismatch for {component['name']}: {source}")
        local_file = ROOT / local
        if local_file.is_symlink() or not local_file.is_file() or hashlib.sha256(local_file.read_bytes()).hexdigest() != expected:
            raise RuntimeError(f"Local license checksum mismatch for {component['name']}: {local}")
    print(f"Verified {component['name']} {commit} and its retained license evidence.")


def fetch(component: dict, repository: Path) -> None:
    CACHE.mkdir(parents=True, exist_ok=True)
    if not repository.exists():
        git(["init", "--bare", "--template=", str(repository)])
        git(["remote", "add", "origin", component["repository"]], repository=repository)
    check_repository(component, repository)
    git(["fetch", "--no-tags", "--no-recurse-submodules", "--depth=1", "origin", component["commit"]], repository=repository)
    git(["update-ref", f"refs/locked/{component['commit']}", component["commit"]], repository=repository)
    verify(component, repository)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("fetch", "verify"))
    parser.add_argument("--component", help="One component name from upstream.lock.json (default: all)")
    options = parser.parse_args()
    components = load_components()
    if options.component:
        components = [component for component in components if component["name"] == options.component]
        if not components:
            raise RuntimeError("Unknown component name.")
    for component in components:
        repository = cache_path(component["name"])
        if options.command == "fetch":
            print(f"Fetching locked {component['name']} Git objects; no source execution.", flush=True)
            fetch(component, repository)
        else:
            verify(component, repository)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        print("Upstream command failed; cache retained. Git reported:", file=sys.stderr)
        print(error.stderr.decode(errors="replace").strip(), file=sys.stderr)
        sys.exit(1)
    except (RuntimeError, OSError, KeyError, TypeError, ValueError) as error:
        print(f"Upstream command failed: {error}", file=sys.stderr)
        sys.exit(1)
