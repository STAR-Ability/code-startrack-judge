#!/usr/bin/env python3
"""Run the exact synthetic-only Linux image qualification profile; never deploy."""

from __future__ import annotations

import argparse
import contextlib
import errno
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
MANAGER_KILL_PROBE = """import json, os, signal, sys
from pathlib import Path
pid, ticks, boot = int(sys.argv[1]), sys.argv[2], sys.argv[3]
if pid <= 1 or not ticks.isdecimal():
    raise SystemExit(1)
descriptor = os.pidfd_open(pid, 0)
try:
    raw = Path('/proc/' + str(pid) + '/stat').read_text()
    fields = raw[raw.rindex(')') + 1:].split()
    if (len(fields) < 20 or fields[0] == 'Z' or fields[19] != ticks
            or Path('/proc/' + str(pid) + '/comm').read_text().strip() != 'go-judge'
            or Path('/proc/sys/kernel/random/boot_id').read_text().strip() != boot):
        raise SystemExit(1)
    signal.pidfd_send_signal(descriptor, signal.SIGKILL)
    print(json.dumps({'killSent': True, 'pid': pid, 'startTicks': ticks, 'bootId': boot}))
finally:
    os.close(descriptor)
"""


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
            candidates.extend((path, "matrix-" + path.name) for path in entries if re.fullmatch(r"(?:ALL_PARTS|VALIDATOR_EXIT_ZERO|ACCEPTED_REFERENCE_WRONG|STATEMENT_ARTIFACTS|LARGE_STATEMENT|WORKSPACE|DEFAULT_CHECKER_REGRESSIONS)-[A-Za-z0-9]+\.log", path.name))
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


def require_failed_closed(state, measurement_path):
    if (state.get("Running") is not False or state.get("Status") != "exited"
            or type(state.get("ExitCode")) is not int or state["ExitCode"] != 1
            or type(state.get("Pid")) is not int or state["Pid"] != 0
            or measurement_path.exists() or measurement_path.is_symlink()):
        raise ValueError("runtime_crash_failed_open")


def process_start_ticks(pid):
    raw = Path("/proc", str(pid), "stat").read_text()
    fields = raw[raw.rindex(")") + 1:].split()
    if len(fields) < 20 or not fields[19].isdecimal():
        raise ValueError("runtime_crash_process_identity_invalid")
    return fields[19]


def process_snapshot(pid):
    directory = os.open(Path("/proc", str(pid)), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        values = {}
        for name in ("stat", "status", "cgroup"):
            descriptor = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory)
            with os.fdopen(descriptor, "rb") as source:
                data = source.read(8193)
            if len(data) > 8192:
                raise ValueError("runtime_crash_process_metadata_bounds")
            values[name] = data.decode("ascii")
        fields = values["stat"][values["stat"].rindex(")") + 1:].split()
        if len(fields) < 20 or not fields[19].isdecimal():
            raise ValueError("runtime_crash_process_identity_invalid")
        return fields[19], values["status"].splitlines(), values["cgroup"].splitlines()
    finally:
        os.close(directory)


def capture_execution_drain(prefix, active, measurement):
    state = json.loads(run(prefix, ["inspect", active, "--format", "{{json .State}}"], timeout=10).stdout)
    identifier = run(prefix, ["inspect", active, "--format", "{{.Id}}"], timeout=10).stdout.strip()
    init = state.get("Pid")
    if state.get("Running") is not True or type(init) is not int or init <= 1 or not re.fullmatch(r"[0-9a-f]{64}", identifier):
        raise ValueError("runtime_crash_host_identity_invalid")
    cgroups = Path("/proc", str(init), "cgroup").read_text().splitlines()
    if len(cgroups) != 1 or not cgroups[0].startswith("0::/"):
        raise ValueError("runtime_crash_host_cgroup_invalid")
    relative = Path(cgroups[0][4:])
    if relative.is_absolute() or ".." in relative.parts or relative.name != "service":
        raise ValueError("runtime_crash_host_cgroup_invalid")
    relative = relative.parent  # PID1 is in /service; /runtime is its sibling.
    if not any(part in (identifier, "docker-" + identifier + ".scope") for part in relative.parts):
        raise ValueError("runtime_crash_host_cgroup_invalid")
    outer_membership = "0::/" + relative.as_posix()
    descriptor = os.open(Path("/sys/fs/cgroup") / relative, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        facts = os.fstat(descriptor)
        rows = run(prefix, ["top", active, "-eo", "pid"], timeout=10).stdout.splitlines()
        if not rows or rows[0].strip() != "PID" or not 2 <= len(rows) <= 513:
            raise ValueError("runtime_crash_host_roster_invalid")
        pids = [int(row.strip()) for row in rows[1:] if re.fullmatch(r"[1-9][0-9]{0,9}", row.strip())]
        if len(pids) != len(rows) - 1 or len(set(pids)) != len(pids) or init not in pids:
            raise ValueError("runtime_crash_host_roster_invalid")
        originals, manager_seen = {}, False
        for pid in pids:
            try:
                ticks, status, membership = process_snapshot(pid)
            except FileNotFoundError:
                continue  # A short-lived completed probe is already gone.
            if len(membership) != 1 or not (membership[0] == outer_membership or membership[0].startswith(outer_membership + "/")):
                continue  # A reused PID belonging to another workload is excluded.
            originals[pid] = ticks
            nspid = next((line.split()[1:] for line in status if line.startswith("NSpid:")), [])
            if len(nspid) >= 2 and nspid[1] == str(measurement["pid"]) and ticks == measurement["startTicks"]:
                manager_seen = True
        if init not in originals or not manager_seen:
            raise ValueError("runtime_crash_host_positive_coverage_missing")
        return {"descriptor": descriptor, "device": facts.st_dev, "inode": facts.st_ino, "processes": originals}
    except BaseException:
        os.close(descriptor)
        raise


def execution_drained(witness):
    facts = os.fstat(witness["descriptor"])
    if (facts.st_dev, facts.st_ino) != (witness["device"], witness["inode"]):
        raise ValueError("runtime_crash_cgroup_identity_changed")
    for pid, ticks in witness["processes"].items():
        try:
            if process_start_ticks(pid) == ticks:
                return False
        except FileNotFoundError:
            pass
    try:
        descriptor = os.open("pids.current", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=witness["descriptor"])
    except OSError as error:
        if error.errno in (errno.ENOENT, errno.ENODEV):
            return True  # The original kernel cgroup has been removed.
        raise
    with os.fdopen(descriptor, "rb") as counter:
        value = counter.read(128).strip()
    if not re.fullmatch(rb"[0-9]{1,20}", value):
        raise ValueError("runtime_crash_cgroup_counter_invalid")
    return int(value) == 0


def require_fresh_restart(previous, current, observations):
    if (type(current.get("pid")) is not int or current["pid"] <= 1
            or current.get("identity") != previous.get("identity")
            or current.get("bootId") != previous.get("bootId")
            or not re.fullmatch(r"[0-9a-f]{64}", previous.get("securityProfileSha256", ""))
            or current.get("securityProfileSha256") != previous["securityProfileSha256"]
            or not isinstance(current.get("startTicks"), str)
            or not re.fullmatch(r"[0-9]{1,20}", current["startTicks"])
            or int(current["startTicks"]) <= int(previous["startTicks"])
            or any(current.get("checks", {}).get(key) is not True for key in REQUIRED_CHECKS)
            or observations.get("cleanupObservations", {}).get("startupGlobalIdle") is not True):
        raise ValueError("runtime_restart_measurement_invalid")


def matrix_log_facts(matrix):
    mature = matrix.get("mature", [])
    names = {"ALL_PARTS", "VALIDATOR_EXIT_ZERO", "ACCEPTED_REFERENCE_WRONG"}
    if len(mature) != 3 or {entry.get("name") for entry in mature} != names:
        raise ValueError("matrix_private_diagnostics_invalid")
    facts = {entry["name"]: entry["privateLog"] for entry in mature}
    facts.update({"STATEMENT_ARTIFACTS": matrix["statement"]["privateLog"],
                  "LARGE_STATEMENT": matrix["largeStatement"]["statement"]["privateLog"],
                  "WORKSPACE": matrix["workspace"]["privateLog"],
                  "DEFAULT_CHECKER_REGRESSIONS": matrix["defaultChecker"]["privateLog"]})
    return facts


def verify_preserved_matrix(private, matrix):
    if regular_json(private / "matrix-report-private.json") != matrix:
        raise ValueError("matrix_private_report_mismatch")
    facts = matrix_log_facts(matrix)
    retained = []
    for name, expected in sorted(facts.items()):
        matches = [path for path in private.iterdir()
                   if re.fullmatch(r"matrix-" + name + r"-[A-Za-z0-9]+\.log", path.name)]
        if (len(matches) != 1 or matches[0].is_symlink() or not matches[0].is_file()
                or type(expected.get("retainedBytes")) is not int or not 0 <= expected["retainedBytes"] <= 65536
                or matches[0].stat().st_size != expected["retainedBytes"]
                or not re.fullmatch(r"[0-9a-f]{64}", expected.get("retainedSha256", ""))
                or hashlib.sha256(matches[0].read_bytes()).hexdigest() != expected["retainedSha256"]):
            raise ValueError("matrix_private_log_mismatch")
        retained.append({"fixture": name, "retainedSha256": expected["retainedSha256"],
                         "retainedBytes": expected["retainedBytes"]})
    return {"matrixReportSha256": hashlib.sha256((private / "matrix-report-private.json").read_bytes()).hexdigest(),
            "fixtureLogs": retained}


def preserve_completed_matrix(runtime_evidence, evidence, matrix):
    # The public matrix is written just before its deferred private exporter.
    # Wait for complete, digest-bound export rather than racing that transfer.
    deadline = time.monotonic() + 10
    facts = matrix_log_facts(matrix)
    source = runtime_evidence / "private-matrix"
    while True:
        complete = source.is_dir() and not source.is_symlink()
        entries = list(source.iterdir()) if complete else []
        complete = complete and len(entries) <= 8
        for name, expected in facts.items():
            matches = [path for path in entries if re.fullmatch(name + r"-[A-Za-z0-9]+\.log", path.name)]
            complete = complete and len(matches) == 1
            if len(matches) == 1:
                path = matches[0]
                complete = (complete and not path.is_symlink() and path.is_file()
                            and path.stat().st_size == expected["retainedBytes"] <= 65536
                            and hashlib.sha256(path.read_bytes()).hexdigest() == expected["retainedSha256"])
        if complete:
            break
        if time.monotonic() >= deadline:
            raise ValueError("matrix_private_export_incomplete")
        time.sleep(0.025)
    pre_crash = evidence / "pre-crash"
    pre_crash.mkdir(mode=0o700)
    count = retain_private(runtime_evidence, pre_crash)
    binding = verify_preserved_matrix(pre_crash / "private", matrix)
    return {"filesRetained": count, **binding}


def crash_restart(prefix, active, runtime_evidence, previous, digest):
    pid, ticks, boot = (previous.get(key) for key in ("pid", "startTicks", "bootId"))
    if (type(pid) is not int or pid <= 1 or not isinstance(ticks, str) or not re.fullmatch(r"[0-9]{1,20}", ticks)
            or not isinstance(boot, str) or not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot)):
        raise ValueError("runtime_crash_identity_invalid")
    witness = capture_execution_drain(prefix, active, previous)
    try:
        return measured_crash_restart(prefix, active, runtime_evidence, previous, digest, witness)
    finally:
        os.close(witness["descriptor"])


def measured_crash_restart(prefix, active, runtime_evidence, previous, digest, witness):
    pid, ticks, boot = (previous[key] for key in ("pid", "startTicks", "bootId"))
    killed = run(prefix, ["exec", "--user", "0", active, "/usr/bin/python3", "-c",
                         MANAGER_KILL_PROBE, str(pid), ticks, boot], timeout=30)
    if json.loads(killed.stdout) != {"killSent": True, "pid": pid, "startTicks": ticks, "bootId": boot}:
        raise ValueError("runtime_crash_signal_unconfirmed")
    deadline = time.monotonic() + 75
    while True:
        state = json.loads(run(prefix, ["inspect", active, "--format", "{{json .State}}"], timeout=10).stdout)
        if state.get("Running") is False:
            break
        if time.monotonic() >= deadline:
            raise ValueError("runtime_crash_shutdown_timeout")
        time.sleep(0.25)
    measurement_path = runtime_evidence / "runtime-measurement.json"
    require_failed_closed(state, measurement_path)
    deadline = time.monotonic() + 15
    while not execution_drained(witness):
        if time.monotonic() >= deadline:
            raise ValueError("runtime_crash_original_execution_retained")
        time.sleep(0.025)
    run(prefix, ["restart", active], timeout=30)
    deadline = time.monotonic() + 90
    while not measurement_path.exists() or not (runtime_evidence / "runtime-isolation-observations.json").exists():
        running = run(prefix, ["inspect", active, "--format", "{{.State.Running}}"], timeout=10)
        if running.stdout.strip() != "true" or time.monotonic() >= deadline:
            raise ValueError("runtime_restart_measurement_unavailable")
        time.sleep(0.25)
    current = regular_json(measurement_path)
    observations = isolation_observations(runtime_evidence, current, digest)
    require_fresh_restart(previous, current, observations)
    return {"passed": True, "managerSignal": "SIGKILL", "signalBoundToPIDFD": True,
            "originalHostProcessesObserved": len(witness["processes"]), "originalHostProcessesGone": True,
            "originalCgroupDrainedOrRemoved": True, "originalCgroupIdentityHeld": True,
            "failedContainerExitCode": state["ExitCode"], "dockerOOMKilled": state.get("OOMKilled"),
            "oldQualificationRemoved": True, "restartInitialMeasurement": current,
            "restartInitialObservations": observations,
            "restartedMatrixUsedForAcceptance": False,
            "scope": "Manager death and same-image/profile restart; business task recovery is a separate gate"}


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
    report = {"schemaVersion": 1, "scope":"LINUX_RUNTIME_SYNTHETIC", "qualified": False,"runtimeChecksPassed":False,"requiredAcceptanceGates":{"matureRolesAndStatements":False,"maximumPackageAndParallelStatements":False,"runtimeCrashRestart":False,"finalServiceProcessMemory":False,"independentSecurityReview":False},"sourceCommit": args.expected_commit,
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
            # A restart truncates fixed private logs. Preserve completed matrix
            # diagnostics before deliberately crashing the measured manager.
            report["preCrashPrivateDiagnostics"] = preserve_completed_matrix(runtime_evidence, evidence, matrix)
            report["runtimeCrashRestart"] = crash_restart(prefix, active, runtime_evidence, measurement, digest)
            report["requiredAcceptanceGates"]["runtimeCrashRestart"] = True
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
