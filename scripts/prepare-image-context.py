#!/usr/bin/env python3
"""Prepare a verified, secret-free offline Linux image context; never publish it."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = "provenance/context-inventory.json"
PATCH_COMPONENTS = ("go-judge", "problemtools", "go-sandbox")


def digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def regular(path: Path) -> bytes:
    if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
        raise ValueError("Image input must be a regular file")
    return path.read_bytes()


def copy_file(source: Path, destination: Path) -> None:
    body = regular(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(body)
    destination.chmod(stat.S_IMODE(source.stat().st_mode))


def patch_inputs(root: Path, lock_path: Path) -> dict[str, tuple[bytes, int]]:
    """Retain only the reviewed diff/series bytes used by this image build."""
    lock = json.loads(regular(lock_path))
    components = lock["components"] + lock["supplemental_licenses"]
    result = {}

    def read(relative: str) -> tuple[bytes, int]:
        source = root / relative
        if source.resolve() != source.absolute():
            raise ValueError("Patch input and its ancestors must not be symbolic links")
        body = regular(source)
        return body, stat.S_IMODE(source.stat().st_mode)

    for name in PATCH_COMPONENTS:
        matching = [component for component in components if component.get("name") == name]
        if len(matching) != 1:
            raise ValueError("Image patch component is not uniquely locked")
        component = matching[0]
        descriptor = f"patches/{name}/series.json"
        body, mode = read(descriptor)
        series = json.loads(body)
        if (series.get("schemaVersion") != 1 or series.get("component") != name
                or series.get("repository") != component["repository"]
                or series.get("baseCommit") != component["commit"]
                or not isinstance(series.get("patches"), list) or not series["patches"]
                or series["patches"] != component.get("patches")):
            raise ValueError("Image patch series differs from the reviewed upstream lock")
        if name == "go-sandbox" and (
                series.get("module") != "github.com/criyle/go-sandbox"
                or series.get("baseVersion") != component["version"]
                or component.get("source_assembly") != {
                    "policy": "verified-go-module-vendor", "descriptor": descriptor}):
            raise ValueError("Image vendor patch series differs from the reviewed source identity")
        result[descriptor] = (body, mode)
        for patch in series["patches"]:
            relative = patch["path"]
            path = PurePosixPath(relative)
            if (relative != path.as_posix() or len(path.parts) != 3
                    or path.parts[:2] != ("patches", name) or path.suffix != ".patch"
                    or ".." in path.parts or "\\" in relative or ":" in relative
                    or any(ord(char) < 32 or ord(char) == 127 for char in relative)
                    or relative in result):
                raise ValueError("Image patch is outside its explicit owned file allowlist")
            patch_body, patch_mode = read(relative)
            if digest(patch_body) != patch["sha256"]:
                raise ValueError("Image patch checksum differs from the reviewed series")
            result[relative] = (patch_body, patch_mode)
    return result


def copy_patch_inputs(destination: Path) -> None:
    # Validate a complete snapshot before writing any patch payload. Do not copy
    # an unrestricted patches directory or re-read diffs after their SHA check.
    for relative, (body, mode) in patch_inputs(ROOT, ROOT / "upstream.lock.json").items():
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
        target.chmod(mode)


def inventory(directory: Path) -> list[dict]:
    records = []
    for parent, directories, files in os.walk(directory, followlinks=False):
        for name in directories:
            if (Path(parent) / name).is_symlink():
                raise ValueError("Image input directory must not be a symlink")
        for name in sorted(files):
            path = Path(parent) / name
            relative = path.relative_to(directory).as_posix()
            if relative == INVENTORY:
                continue
            body = regular(path)
            records.append({"path": relative, "sizeBytes": len(body), "sha256": digest(body),
                            "mode": f"{stat.S_IMODE(path.stat().st_mode):04o}"})
    return sorted(records, key=lambda item: item["path"])


def go_inputs(directory: Path, go: Path) -> dict:
    environment = {"PATH": os.environ.get("PATH", ""), "HOME": os.environ["HOME"],
                   "GOTOOLCHAIN": "local", "GOENV":"off", "GOOS": "linux", "GOARCH": "amd64", "CGO_ENABLED": "0"}
    version = subprocess.check_output([str(go), "version"], env=environment, stderr=subprocess.PIPE,text=True).strip()
    if not version.startswith("go version go1.26.8 "):
        raise ValueError("Image preparation requires the locked Go SDK")
    subprocess.run([str(go), "mod", "download"], cwd=directory, env=environment, capture_output=True,check=True)
    subprocess.run([str(go), "mod", "verify"], cwd=directory, env=environment, capture_output=True,check=True)
    subprocess.run([str(go), "mod", "vendor"], cwd=directory, env=environment, capture_output=True,check=True)
    selected = subprocess.check_output([str(go), "list", "-m", "-mod=mod", "-json", "all"],
                                       cwd=directory, env=environment, stderr=subprocess.PIPE,text=True)
    return {"producer": version, "target": "linux/amd64", "modulesJSONStream": selected,
            "vendorInventory": inventory(directory / "vendor")}


def service_go_inputs(directory: Path, go: Path) -> dict:
    # Module resolution may expand go.sum. Preserve the original owned source
    # and retain the generated checksums as a separate, inventoried build input.
    original = {name: (regular(directory / name), stat.S_IMODE((directory / name).stat().st_mode))
                for name in ("go.mod", "go.sum")}
    try:
        generated = go_inputs(directory, go)
        if regular(directory / "go.mod") != original["go.mod"][0]:
            raise ValueError("Image preparation must not change owned module requirements")
        destination = directory.parent / "provenance/service-generated.go.sum"
        copy_file(directory / "go.sum", destination)
        body = regular(destination)
        generated["generatedGoSum"] = {"path": "provenance/service-generated.go.sum",
            "sizeBytes": len(body), "sha256": digest(body),
            "mode": f"{stat.S_IMODE(destination.stat().st_mode):04o}"}
        return generated
    finally:
        for name, (body, mode) in original.items():
            # Atomic replacement also avoids following a replaced module-file
            # symlink when restoring after a failed preparation command.
            descriptor, temporary = tempfile.mkstemp(prefix=".startrack-module-", dir=directory)
            try:
                with os.fdopen(descriptor, "wb") as output:
                    output.write(body)
                    os.fchmod(output.fileno(), mode)
                os.replace(temporary, directory / name)
            finally:
                Path(temporary).unlink(missing_ok=True)


def prepare(value: str, release_commit: str | None = None) -> Path:
    spec = importlib.util.spec_from_file_location("startrack_patches", ROOT / "scripts/apply-upstream-patches.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    working_tree = subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=all"], cwd=ROOT, text=True)
    if release_commit is not None and (release_commit != head or working_tree):
        raise ValueError("Official image preparation requires a clean exact source commit")
    destination = module.destination_path(value)
    destination.mkdir(parents=True)
    go = ROOT / ".local/toolchains/go1.26.8/go/bin/go"
    source_names = subprocess.check_output(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=ROOT).split(b"\0")
    # Never send an unfiltered repository, caches, credentials, fetched archives,
    # VIVA, Git metadata, or the operator's unrelated work to Docker.
    for raw in sorted(set(source_names)):
        if not raw:
            continue
        relative = raw.decode("utf-8")
        source = ROOT / relative
        parts = Path(relative).parts
        include = relative in ("go.mod", "go.sum", "scripts/problemtools-bridge.py", "scripts/problemtools-wheel-audit.py", "scripts/validation-tools.py") or (
            parts[0] in ("cmd", "internal", "migrations") and source.suffix in (".go", ".cc", ".h", ".py", ".sql")
        )
        if include:
            copy_file(source, destination / "service" / relative)
        if relative in ("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md") or relative.startswith("docs/licenses/"):
            copy_file(source, destination / "legal" / relative)
    for name in ("Dockerfile", "mount.yaml", "image.lock.json", "startrack-v02.apparmor", "seccomp-source.json", "startrack-v02.seccomp.json", "security-profile.lock.json", "startrack-workload-seccomp.yaml", "workload-security-profile.lock.json"):
        copy_file(ROOT / "docker" / name, destination / "docker" / name)
    copy_file(ROOT / "docker/Dockerfile", destination / "Dockerfile")
    for name in ("upstream.lock.json", "toolchain.lock.json", "validation-tools.lock.json", "validation-sources.lock.json"):
        copy_file(ROOT / name, destination / "provenance" / name)
    copy_patch_inputs(destination)
    validation_spec = importlib.util.spec_from_file_location("startrack_validation_tools", ROOT / "scripts/validation-tools.py")
    validation = importlib.util.module_from_spec(validation_spec)
    validation_spec.loader.exec_module(validation)
    validation_lock, validation_sha = validation.read_lock(ROOT / "validation-tools.lock.json")
    validation.verify_legal(validation_lock, ROOT)
    bundle = ROOT / ".cache/validation-tools" / validation_sha
    validation.verify_bundle(validation_lock, bundle, validation_sha)
    for directory, entry in validation.artifact_groups(validation_lock):
        copy_file(bundle / directory / entry["filename"], destination / "validation-tools" / directory / entry["filename"])
    for name in ("requirements.txt", "inventory.json"):
        copy_file(bundle / name, destination / "validation-tools" / name)
    generated = {"service": service_go_inputs(destination / "service", go)}
    for name in ("go-judge", "problemtools"):
        prepared = module.prepare(name, str(destination / "upstream" / name))
        copy_file(prepared / module.PROVENANCE_NAME, destination / "provenance" / f"{name}-sources.json")
        if name == "go-judge":
            generated[name] = go_inputs(prepared, go)
            vendor_spec = importlib.util.spec_from_file_location("startrack_vendor_patches", ROOT / "scripts/apply-vendor-patches.py")
            vendor_module = importlib.util.module_from_spec(vendor_spec)
            vendor_spec.loader.exec_module(vendor_module)
            vendor_module.apply(prepared)
            generated[name]["vendorInventory"] = inventory(prepared / "vendor")
            copy_file(prepared / ".startrack-vendor-patches.json", destination / "provenance/go-sandbox-vendor-patches.json")
            workload_spec = importlib.util.spec_from_file_location("startrack_workload_seccomp", ROOT / "scripts/workload-seccomp.py")
            workload_module = importlib.util.module_from_spec(workload_spec)
            workload_spec.loader.exec_module(workload_module)
            workload_module.verify(ROOT, prepared)
    for name, directory in (("service", destination / "service/vendor"), ("go-judge", destination / "upstream/go-judge/vendor")):
        for path in directory.rglob("*"):
            if path.is_file() and path.name.upper().startswith(("LICENSE", "LICENCE", "COPYING", "COPYRIGHT", "NOTICE", "PATENTS")):
                copy_file(path, destination / "legal" / (name + "-vendor") / path.relative_to(directory))
    subprocess.run([sys.executable, str(ROOT / "scripts/check-go-judge-licenses.py"), "prepare",
                    "--source", str(destination / "upstream/go-judge"), "--output", str(destination / "provenance"), "--go", str(go)],check=True)
    record = {"schemaVersion": 1, "scope": "BUILD_INPUTS_ONLY", "generatedDependencyInputs": generated}
    (destination / "provenance/generated-dependencies.json").write_text(json.dumps(record, indent=2) + "\n")
    final_head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    final_tree = subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=all"], cwd=ROOT, text=True)
    if release_commit is not None and (final_head != release_commit or final_tree):
        raise ValueError("Official source changed during image preparation")
    context = {"schemaVersion": 1, "gitHead": head, "sourceState": "DIRTY" if working_tree else "CLEAN",
               "workingTreeStatus": working_tree, "finalGitHead":final_head,"finalWorkingTreeStatus":final_tree,"releaseCommit": release_commit,
               "qualification": "UNQUALIFIED", "inventory": inventory(destination)}
    (destination / INVENTORY).write_text(json.dumps(context, indent=2) + "\n")
    verify(destination)
    return destination


def verify(directory: Path) -> None:
    expected = json.loads(regular(directory / INVENTORY))
    if expected.get("schemaVersion") != 1 or expected.get("inventory") != inventory(directory):
        raise ValueError("Prepared context differs from its recorded bytes or modes")
    patches = patch_inputs(directory, directory / "provenance/upstream.lock.json")
    recorded = {record["path"] for record in expected["inventory"] if record["path"].startswith("patches/")}
    if recorded != set(patches):
        raise ValueError("Prepared context patch inventory differs from its reviewed allowlist")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "verify"))
    parser.add_argument("destination")
    parser.add_argument("--release-commit", help="Require clean source at this exact reviewed commit")
    args = parser.parse_args()
    if args.command == "prepare":
        print(prepare(args.destination, args.release_commit).relative_to(ROOT))
    else:
        verify(Path(args.destination))
        print("Image context byte/mode inventory verified; no runtime qualification claimed")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        print("image-context: preparation/verification failed; preserve local evidence for review", file=sys.stderr)
        sys.exit(1)
