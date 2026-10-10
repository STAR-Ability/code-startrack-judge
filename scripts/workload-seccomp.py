#!/usr/bin/env python3
"""Bind the fixed additive workload profile to reviewed source; never execute it."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import stat


def regular(path: Path) -> bytes:
    if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
        raise ValueError("Workload seccomp evidence must be a regular file")
    return path.read_bytes()


def digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def verify(root: Path, prepared: Path | None = None) -> dict:
    """Check source identities and optional actual staged bytes, not isolation."""
    profile = json.loads(regular(root / "docker/workload-security-profile.lock.json"))
    lock = json.loads(regular(root / "upstream.lock.json"))
    components = {item["name"]: item for item in lock["components"] + lock["supplemental_licenses"]}
    required = {
        "schemaVersion": 1, "status": "PROPOSED_UNQUALIFIED", "scope": "STACKED_WORKLOAD_ONLY_GUARD",
        "architecture": "linux/amd64", "profilePath": "docker/startrack-workload-seccomp.yaml",
        "embeddedPath": "seccomp/startrack-workload.yaml",
        "loading": "FIXED_EMBEDDED_NO_CALLER_PROFILE_OR_DISABLE",
        "installation": "EXISTING_FORKEXEC_AFTER_TRUSTED_SETUP_AND_CAPABILITY_DROP_BEFORE_EXEC",
        "minimumWorkloadFilterCount": 3,
        "qualification": "REQUIRED_EXACT_IMAGE_LINUX_MATRIX_NO_PORTABLE_ACCEPTANCE",
    }
    if any(profile.get(key) != value for key, value in required.items()):
        raise ValueError("Workload seccomp scope/loading/qualification differs")
    policy = {
        "defaultAction": "ALLOW_NEUTRAL_WHEN_STACKED", "unshare": "EPERM", "setns": "EPERM",
        "cloneNamespaceMask": "0x7e020000", "cloneNamespaceAction": "EPERM", "clone3": "ENOSYS",
        "clone3Errno": 38, "conditionalCloneGroup": "TERMINAL", "foreignArchitecture": "INHERITED_INIT_EPERM",
        "x32": "ENOSYS", "legacyCloneNewtimeExcluded": True,
    }
    if profile.get("policy") != policy:
        raise ValueError("Workload seccomp policy differs")
    assembler = components["go-seccomp-bpf"]
    if profile.get("assembler") != {
        "component": assembler["name"], "module": "github.com/elastic/go-seccomp-bpf",
        "version": assembler["version"], "commit": assembler["commit"], "customBPF": False,
    }:
        raise ValueError("Workload seccomp assembler identity differs")
    baseline = next(item for item in components["go-judge"]["source_evidence"] if item["upstream_path"] == "seccomp/moby.yaml")
    if profile.get("initProfile") != {
        "component": "go-judge", "path": baseline["upstream_path"], "sha256": baseline["sha256"], "mustRemainUnchanged": True,
    }:
        raise ValueError("Workload seccomp inherited init identity differs")
    expected_paths = {
        "go-judge": {"env/env_linux.go", "env/linuxcontainer/environment_linux.go", "seccomp/startrack_workload.go",
                     "seccomp/startrack-workload.yaml", "seccomp/startrack_workload_test.go"},
        "go-sandbox": {"container/container_exec_linux.go"},
    }
    sources = []
    for name, paths in expected_paths.items():
        records = [record for patch in components[name]["patches"] for record in patch["files"]]
        if any(record["path"] == baseline["upstream_path"] for record in records):
            raise ValueError("Workload seccomp must preserve the inherited init profile")
        selected = [record for record in records if record["path"] in paths]
        if len(selected) != len(paths) or {record["path"] for record in selected} != paths:
            raise ValueError("Workload seccomp source inventory differs")
        sources.extend({"component": name, "path": record["path"], "sha256": record["patchedSha256"]} for record in selected)
    if profile.get("sources") != sources:
        raise ValueError("Workload seccomp source hashes differ")
    body = regular(root / profile["profilePath"])
    embedded = next(item for item in sources if item["path"] == profile["embeddedPath"])
    if digest(body) != profile.get("profileSha256") or embedded["sha256"] != profile.get("profileSha256"):
        raise ValueError("Workload seccomp embedded/profile bytes differ")
    if prepared is not None:
        for record in sources:
            source = prepared / record["path"] if record["component"] == "go-judge" else prepared / "vendor/github.com/criyle/go-sandbox" / record["path"]
            if digest(regular(source)) != record["sha256"]:
                raise ValueError("Workload seccomp actual prepared source differs")
        if digest(regular(prepared / baseline["upstream_path"])) != baseline["sha256"]:
            raise ValueError("Workload seccomp actual init profile differs")
    return profile
