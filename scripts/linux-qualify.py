#!/usr/bin/env python3
"""Run the exact synthetic-only Linux image qualification profile; never deploy."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import stat
import subprocess
import tempfile
import time

OFFICIAL = "ghcr.io/star-ability/code-startrack-judge"
ROOT=Path(__file__).resolve().parent.parent
CAPABILITIES = ("CHOWN", "FOWNER", "KILL", "SETUID", "SETGID", "SYS_ADMIN", "SYS_RESOURCE", "SETFCAP")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
REQUIRED_CHECKS = {"seccomp", "namespaces", "network_denied", "filesystem_isolation", "credential_isolation", "sibling_proc_denied", "unique_execution_uids", "cpu_limits", "wall_limits", "memory_limits", "output_limits", "process_limits", "cgroup_cpu", "cgroup_memory", "cgroup_pids", "compiler_isolation", "cleanup", "cache_cleanup"}


def run(prefix, args, *, check=True, stdin=None, timeout=240):
    result = subprocess.run(prefix + args, input=stdin, capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        raise ValueError("docker_" + args[0] + "_failed")
    return result


def regular_json(path, limit=65536):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise ValueError("evidence_file_invalid")
    return json.loads(path.read_bytes())


def retain_private(runtime_evidence, evidence):
    destination = evidence / "private"
    destination.mkdir(mode=0o700)
    candidates = [(runtime_evidence / name, name) for name in ("runtime-private.log", "qualification-private.log", "matrix-private.log", "matrix-report-private.json")]
    matrix_directory = runtime_evidence / "private-matrix"
    if matrix_directory.is_dir() and not matrix_directory.is_symlink():
        entries = list(matrix_directory.iterdir())
        if len(entries) <= 8:
            candidates.extend((path, "matrix-" + path.name) for path in entries if re.fullmatch(r"(?:ALL_PARTS|VALIDATOR_EXIT_ZERO|ACCEPTED_REFERENCE_WRONG|STATEMENT_ARTIFACTS|MAXIMUM_PACKAGE)-[A-Za-z0-9]+\.log", path.name))
    retained = 0
    for source, name in candidates:
        try:
            descriptor = os.open(source, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        except OSError:
            continue
        with os.fdopen(descriptor, "rb") as source_file:
            facts = os.fstat(source_file.fileno())
            if not stat.S_ISREG(facts.st_mode) or stat.S_IMODE(facts.st_mode) != 0o600 or facts.st_uid != 0 or facts.st_nlink != 1 or facts.st_size > 65536:
                continue
            data = source_file.read(65537)
            if len(data) > 65536:
                continue
        output_descriptor = os.open(destination / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(output_descriptor, "wb") as output:
            output.write(data)
        retained += 1
    return retained


def isolation_observations(runtime_evidence, measurement, digest):
    observations = regular_json(runtime_evidence / "runtime-isolation-observations.json", 8192)
    if observations.get("version") != 1 or observations.get("workerImageDigest") != digest or any(observations.get(key) != measurement.get(key) for key in ("pid", "startTicks", "bootId")):
        raise ValueError("runtime_observations_identity_invalid")
    values = observations.get("observations", [])
    if len(values) != 2 or any(value.get("seccompFilters", 0) < 3 or value.get("securebits") != 47 or value.get("denialFailure") != "" or any(value.get(key) != 0 for key in ("capabilityEffectiveBits", "capabilityPermittedBits", "capabilityInheritableBits", "capabilityAmbientBits")) or not isinstance(value.get("capabilityBoundingBits"), int) or not 0 <= value["capabilityBoundingBits"] < 1 << 53 for value in values):
        raise ValueError("runtime_observations_incomplete")
    for value in values:
        counters = [value.get(name) for name in ("readonlyEROFSCount", "readonlyEACCESCount", "readonlyEPERMCount")]
        if value.get("readonly") is not True or value.get("readonlyFailure") != "" or value.get("readonlyMountCount") != 9 or value.get("readonlyWriteDeniedCount") != 9 or any(type(count) is not int or not 0 <= count <= 9 for count in counters) or sum(counters) != 9:
            raise ValueError("runtime_readonly_observations_incomplete")
    cleanup = observations.get("cleanupObservations", {})
    if any(type(cleanup.get(name)) is not int or not lower <= cleanup[name] <= upper for name, lower, upper in (
        ("ownedModesObserved", 10, 10), ("ownedGroupsObserved", 10, 32),
        ("ownedProcessesObserved", 10, 1024), ("forkWitnessProcesses", 2, 8),
    )) or cleanup.get("ownedProcessesReaped") is not True or cleanup.get("ownedGroupsDrained") is not True or type(cleanup.get("startupGlobalIdle")) is not bool:
        raise ValueError("runtime_cleanup_observations_incomplete")
    return observations


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--docker-context", required=True, choices=("default", "colima-startrack-v02"))
    parser.add_argument("--evidence", required=True, type=Path)
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "amd64") or os.geteuid() != 0:
        raise ValueError("trusted_linux_root_runner_required")
    repository, separator, digest = args.image.partition("@")
    if not separator or not DIGEST.fullmatch(digest) or not COMMIT.fullmatch(args.expected_commit):
        raise ValueError("immutable_image_commit_required")
    if repository != OFFICIAL and not (args.docker_context == "colima-startrack-v02" and repository == "startrack-qualified-candidate"):
        raise ValueError("image_repository_not_allowed")
    evidence = args.evidence.absolute()
    if evidence.exists() or evidence.is_symlink():
        raise ValueError("fresh_evidence_directory_required")
    evidence.mkdir(parents=True, mode=0o755)
    evidence.chmod(0o755)
    prefix = ["docker", "--context", args.docker_context]
    daemon = json.loads(run(prefix, ["info", "--format", "{{json .}}"]).stdout)
    if daemon.get("CgroupVersion") != "2" or daemon.get("MemTotal", 0) < 15 << 30 or daemon.get("NCPU", 0) < 4:
        raise ValueError("qualification_daemon_capacity_insufficient")
    image = json.loads(run(prefix, ["image", "inspect", args.image]).stdout)[0]
    if image.get("Os") != "linux" or image.get("Architecture") != "amd64" or args.image not in image.get("RepoDigests", []):
        raise ValueError("actual_image_identity_invalid")
    profile_lock=regular_json(ROOT/"docker/security-profile.lock.json")
    profile=ROOT/"docker/startrack-v02.seccomp.json"
    if hashlib.sha256(profile.read_bytes()).hexdigest()!=profile_lock["profileSha256"]:
        raise ValueError("seccomp_profile_checksum_invalid")
    apparmor = ROOT / "docker/startrack-v02.apparmor"
    apparmor_hash = hashlib.sha256(apparmor.read_bytes()).hexdigest()
    parser_version = subprocess.run(["apparmor_parser", "--version"], capture_output=True, text=True, timeout=10, check=True).stdout.splitlines()[0]
    subprocess.run(["apparmor_parser", "--replace", str(apparmor)], capture_output=True, timeout=30, check=True)
    identifier = "startrack-qualification-" + secrets.token_hex(8)
    containers = []
    report = {"schemaVersion": 1, "scope":"LINUX_RUNTIME_SYNTHETIC", "qualified": False,"runtimeChecksPassed":False,"requiredAcceptanceGates":{"matureRolesAndStatements":False,"maximumPackageAndParallelStatements":False,"finalServiceProcessMemory":False,"independentSecurityReview":False},"sourceCommit": args.expected_commit,
              "imageReference": args.image, "imageID": image["Id"], "failureCode": "incomplete"}
    report["trustedHost"] = {"memoryBytes": daemon["MemTotal"], "cpuCount": daemon["NCPU"], "cgroupVersion": daemon["CgroupVersion"], "apparmorSha256": apparmor_hash, "apparmorParserVersion": parser_version}
    facilities = runtime_evidence = None
    try:
        with contextlib.nullcontext(tempfile.mkdtemp(prefix="startrack-qualification-")) as temporary:
            facilities = Path(temporary)
            extract = identifier + "-extract"
            run(prefix, ["create", "--name", extract, "--entrypoint", "/bin/true", args.image])
            containers.append(extract)
            for name in ("context-inventory.json", "binaries.sha256"):
                run(prefix, ["cp", extract + ":/opt/startrack/provenance/" + name, str(facilities / name)])
            for name in ("startrack-v02.apparmor", "startrack-v02.seccomp.json", "startrack-workload-seccomp.yaml", "workload-security-profile.lock.json"):
                run(prefix, ["cp", extract + ":/opt/startrack/" + name, str(facilities / name)])
                if (facilities / name).read_bytes() != (ROOT / "docker" / name).read_bytes():
                    raise ValueError("image_security_profile_mismatch")
            context = regular_json(facilities / "context-inventory.json", 32 << 20)
            if context.get("gitHead") != args.expected_commit:
                raise ValueError("image_source_commit_mismatch")
            if repository == OFFICIAL and (context.get("sourceState") != "CLEAN" or context.get("releaseCommit") != args.expected_commit or context.get("workingTreeStatus")):
                raise ValueError("image_source_not_clean_release")
            binaries = {}
            for line in (facilities / "binaries.sha256").read_text().splitlines():
                checksum, filename = line.split(None, 1)
                if not re.fullmatch(r"[0-9a-f]{64}", checksum):
                    raise ValueError("binary_inventory_invalid")
                binaries[filename] = checksum
            checker = binaries["/opt/startrack/libexec/default_validator"]
            bridge = binaries["/opt/startrack/libexec/problemtools-bridge.py"]
            secret_directory, runtime_evidence = facilities / "secrets", facilities / "runtime"
            secret_directory.mkdir(mode=0o700)
            runtime_evidence.mkdir(mode=0o755)
            runtime_token = secrets.token_hex(32)
            values = {name: secrets.token_hex(32) for name in ("backend-judge-token", "judge-backend-token", "scheduler-token", "catalog-cursor-key")}
            values.update({"runtime-token": runtime_token, "database-url": "postgres://synthetic:qualification-only@127.0.0.1/judge?sslmode=disable"})
            for name, value in values.items():
                descriptor = os.open(secret_directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
                with os.fdopen(descriptor, "w") as output:
                    output.write(value)
            common = ["--read-only", "--cgroupns", "private", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                      "--security-opt", "apparmor=startrack-v02", "--security-opt","seccomp="+str(profile),"--pids-limit", "512", "--memory", "10g", "--memory-swap", "10g", "--cpus", "3",
                      "--tmpfs", "/run:rw,nosuid,nodev,size=2g,nr_inodes=262144,mode=755", "--tmpfs", "/var/lib/startrack:rw,nosuid,nodev,size=64m,mode=755",
                      "--tmpfs", "/var/lib/startrack-judger:rw,nosuid,nodev,size=64m,mode=755",
                      "--mount", "type=bind,source=" + str(secret_directory) + ",target=/run/secrets/startrack,readonly",
                      "--mount", "type=bind,source=" + str(runtime_evidence) + ",target=/run/startrack-supervisor",
                      "--env", "JUDGE_QUALIFICATION_ONLY=true", "--env", "JUDGE_WORKER_IMAGE_DIGEST=" + digest,
                      "--env", "JUDGE_CHECKER_SHA256=" + checker, "--env", "JUDGE_MATURE_BRIDGE_SHA256=" + bridge]
            denied = identifier + "-denied"
            containers.append(denied)
            run(prefix, ["run", "--name", denied, "--detach", *common, args.image])
            denied_exit = run(prefix, ["wait", denied]).stdout.strip()
            if denied_exit != "1" or (runtime_evidence / "runtime-measurement.json").exists():
                raise ValueError("denied_baseline_failed_open")
            report["deniedBaseline"] = "PASS"
            active = identifier + "-active"
            containers.append(active)
            granted = [item for capability in CAPABILITIES for item in ("--cap-add", capability)]
            run(prefix, ["run", "--name", active, "--detach", *common, *granted, args.image])
            measurement_path = runtime_evidence / "runtime-measurement.json"
            deadline = time.monotonic() + 90
            while not measurement_path.exists():
                running = run(prefix, ["inspect", active, "--format", "{{.State.Running}}"])
                if running.stdout.strip() != "true" or time.monotonic() > deadline:
                    raise ValueError("runtime_measurement_unavailable")
                time.sleep(0.25)
            measurement = regular_json(measurement_path)
            if measurement.get("identity", {}).get("workerImageDigest") != digest or not all(measurement.get("checks", {}).get(key) is True for key in REQUIRED_CHECKS):
                raise ValueError("runtime_measurement_incomplete")
            observations = isolation_observations(runtime_evidence, measurement, digest)
            matrix_path = runtime_evidence / "runtime-matrix.json"
            deadline = time.monotonic() + 930
            while not matrix_path.exists():
                running = run(prefix, ["inspect", active, "--format", "{{.State.Running}}"])
                if running.stdout.strip() != "true" or time.monotonic() > deadline:
                    raise ValueError("runtime_matrix_unavailable")
                time.sleep(0.25)
            matrix_report = regular_json(matrix_path)
            if matrix_report.get("workerImageDigest") != digest or matrix_report.get("matrixCgroup") != "/service" or matrix_report.get("matrixUID") != 20001:
                raise ValueError("runtime_matrix_identity_invalid")
            matrix = matrix_report["matrix"]
            if matrix.get("passed") is not True:
                raise ValueError("runtime_matrix_failed")
            report.update({"runtimeChecksPassed": True, "failureCode": "", "measurement": measurement, "isolationObservations": observations, "matrix": matrix, "cgroupsBefore": matrix_report["cgroupsBefore"], "cgroupsAfter": matrix_report["cgroupsAfter"]})
    except (ValueError, OSError, KeyError, json.JSONDecodeError, subprocess.SubprocessError) as error:
        report["failureCode"] = str(error) if isinstance(error, ValueError) and re.fullmatch(r"[a-z_]+", str(error)) else type(error).__name__
    finally:
        if runtime_evidence is not None:
            try:
                report["privateDiagnosticsRetained"] = retain_private(runtime_evidence, evidence)
            except OSError:
                report.update({"qualified": False, "runtimeChecksPassed": False, "failureCode": "private_evidence_retention_failed"})
        cleanup=True
        for container in reversed(containers):
            try:
                removed=run(prefix,["rm","--force",container],check=False)
                remains=run(prefix,["inspect",container],check=False)
                cleanup=cleanup and removed.returncode==0 and remains.returncode!=0
            except (ValueError,OSError,subprocess.SubprocessError):cleanup=False
        report["containerCleanupPassed"]=cleanup
        if not cleanup:report.update({"qualified":False,"runtimeChecksPassed":False,"failureCode":"container_cleanup_failed"})
        if facilities is not None:
            shutil.rmtree(facilities)
        (evidence / "qualification.json").write_text(json.dumps(report, indent=2) + "\n")
        (evidence / "qualification.json").chmod(0o644)
    print("Linux synthetic runtime checks " + ("passed; full acceptance pending" if report["runtimeChecksPassed"] else "failed: " + report["failureCode"]))
    return 0 if report["runtimeChecksPassed"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, KeyError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        print("Linux qualification setup failed: " + type(error).__name__)
        raise SystemExit(1)
