#!/usr/bin/env python3
"""Test normal startup and small API probes on a capped shared Linux host.

This never runs the qualification matrix, capacity fixtures, or crash injection.
The ordinary supervisor's mandatory bounded isolation checks remain enabled.
Provision a disposable migrated least-privilege PostgreSQL database separately.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parent.parent
MEMORY_BYTES = 3 << 30
MIN_HEADROOM_BYTES = 1 << 30
NETWORK = re.compile(r"startrack-v02-(?:smoke-[a-z0-9-]+|integration_default)\Z")
OWNER_LABEL = "io.startrack.bounded-smoke.owner"


def module(name, filename):
    specification = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    loaded = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(loaded)
    return loaded


QUALIFY = module("startrack_bounded_qualification", "linux-qualify.py")
CAPACITY = module("startrack_bounded_credentials", "linux-import-capacity.py")


def require(condition, code):
    if not condition:
        raise ValueError(code)


def available_memory():
    fields = dict(line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())
    value, unit = fields["MemAvailable"].split()
    require(unit == "kB" and value.isdecimal(), "host_memory_observation_invalid")
    return int(value) * 1024


def check_headroom(startup=False):
    free = available_memory()
    require(free >= MIN_HEADROOM_BYTES + (MEMORY_BYTES if startup else 0), "host_memory_headroom_insufficient")
    return free


def scoped_apparmor(source, name):
    require(re.fullmatch(r"startrack-v02-smoke-[0-9a-f]{16}", name), "apparmor_name_invalid")
    require(source.count("profile startrack-v02 ") == 1 and source.count("peer=startrack-v02,") == 2, "apparmor_source_invalid")
    return source.replace("profile startrack-v02 ", "profile " + name + " ").replace("peer=startrack-v02,", "peer=" + name + ",")


def image_identity(image, reference):
    require(image.get("Os") == "linux" and image.get("Architecture") == "amd64", "image_platform_invalid")
    identifier = image.get("Id", "")
    require(QUALIFY.DIGEST.fullmatch(identifier), "image_id_invalid")
    if QUALIFY.DIGEST.fullmatch(reference):
        require(reference == identifier, "image_id_mismatch")
        return identifier, "DOCKER_IMAGE_ID"
    repository, separator, digest = reference.partition("@")
    require(separator and repository in (QUALIFY.OFFICIAL, "startrack-qualified-candidate") and QUALIFY.DIGEST.fullmatch(digest)
            and reference in image.get("RepoDigests", []), "immutable_image_reference_invalid")
    return digest, "OCI_MANIFEST_DIGEST"


def docker_limits(profile, apparmor, port):
    return ["--read-only", "--cgroupns", "private", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--security-opt", "apparmor=" + apparmor,
            "--security-opt", "seccomp=" + str(profile), "--pids-limit", "256",
            "--memory", "3g", "--memory-swap", "3g", "--cpus", "1",
            "--tmpfs", "/run:rw,nosuid,nodev,size=512m,nr_inodes=65536,mode=755",
            "--tmpfs", "/var/lib/startrack:rw,nosuid,nodev,noexec,size=64m,mode=755",
            "--tmpfs", "/var/lib/startrack-judger:rw,nosuid,nodev,noexec,size=64m,mode=755",
            "--publish", "127.0.0.1:" + (str(port) if port else "") + ":8082",
            *[item for capability in QUALIFY.CAPABILITIES for item in ("--cap-add", capability)]]


def enforced_limits(configuration, apparmor):
    capabilities = {value.removeprefix("CAP_") for value in configuration.get("CapAdd", [])}
    require(configuration.get("Privileged") is False and configuration.get("ReadonlyRootfs") is True
            and configuration.get("CgroupnsMode") == "private" and capabilities == set(QUALIFY.CAPABILITIES)
            and configuration.get("CapDrop") == ["ALL"] and configuration.get("Memory") == MEMORY_BYTES
            and configuration.get("MemorySwap") == MEMORY_BYTES and configuration.get("NanoCpus") == 1_000_000_000
            and configuration.get("PidsLimit") == 256, "docker_enforced_limits_invalid")
    options = configuration.get("SecurityOpt", [])
    require("apparmor=" + apparmor in options and any(value in ("no-new-privileges", "no-new-privileges=true") for value in options)
            and any(value.startswith("seccomp=") and value != "seccomp=unconfined" for value in options), "docker_security_policy_invalid")
    return {"memoryBytes": configuration["Memory"], "memoryAndSwapBytes": configuration["MemorySwap"],
            "nanoCPUs": configuration["NanoCpus"], "pids": configuration["PidsLimit"], "readOnlyRoot": True, "privateCgroupNamespace": True}


def request(port, path, token=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        correlation = str(uuid.uuid4())
        headers = {"X-Request-Id": correlation}
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        body = response.read(65537)
        require(len(body) <= 65536, "api_response_bounds_invalid")
        decoded = json.loads(body)
        if path.startswith("/internal/v2/"):
            require(decoded.get("requestId") == correlation and response.getheader("X-Request-Id") == correlation,
                    "api_request_correlation_invalid")
        return response.status, decoded
    finally:
        connection.close()


def state(prefix, container):
    return json.loads(QUALIFY.run(prefix, ["inspect", container, "--format", "{{json .State}}"], timeout=10).stdout)


def healthy_docker_probe(observed_state):
    health = observed_state.get("Health", {})
    return health.get("Status") == "healthy" and any(entry.get("ExitCode") == 0 for entry in health.get("Log", []))


def wait_ready(prefix, container, directory, digest, port):
    deadline = time.monotonic() + 120
    startup_measurement = startup_observations = None
    while True:
        check_headroom()
        observed_state = state(prefix, container)
        require(observed_state.get("Running") is True, "service_stopped_before_readiness")
        path = directory / "runtime-measurement.json"
        if path.exists():
            measurement = QUALIFY.regular_json(path)
            require(measurement.get("identity", {}).get("workerImageDigest") == digest
                    and all(measurement.get("checks", {}).get(key) is True for key in QUALIFY.REQUIRED_CHECKS), "runtime_measurement_incomplete")
            if startup_measurement is None:
                startup_observations = QUALIFY.isolation_observations(directory, measurement, digest)
                require(startup_observations.get("cleanupObservations", {}).get("startupGlobalIdle") is True,
                        "startup_global_idle_evidence_missing")
                startup_measurement = measurement
            try:
                status, health = request(port, "/health")
                if status == 200 and healthy_docker_probe(observed_state):
                    require(health == {"status": "ok", "service": "judge-problem-service", "contractVersion": "0.2.0",
                                       "capabilities": {"catalog": True, "judge": True, "imports": True}}, "health_response_invalid")
                    return startup_measurement, health, startup_observations
            except (OSError, json.JSONDecodeError):
                pass
        require(time.monotonic() < deadline, "service_readiness_deadline")
        time.sleep(1)


def api_checks(port, token):
    statuses = {}
    for description, credential, expected in (("missing", None, 401), ("wrong", secrets.token_hex(32), 401)):
        status, _ = request(port, "/internal/v2/languages", credential)
        require(status == expected, "api_authorization_failed")
        statuses[description] = status
    status, languages = request(port, "/internal/v2/languages", token)
    require(status == 200 and isinstance(languages.get("data"), dict), "languages_probe_failed")
    values = languages["data"].get("languages", [])
    require(len(values) == 1 and values[0].get("languageId") == "cpp17", "languages_capability_invalid")
    status, catalog = request(port, "/internal/v2/problems", token)
    require(status == 200 and catalog.get("data") == [] and catalog.get("meta", {}).get("total") == 0
            and catalog.get("meta", {}).get("hasNext") is False, "disposable_catalog_not_empty")
    return {"authorizationHTTP": statuses, "languages": languages["data"], "emptyCatalogHTTP": status}


def stop(prefix, container, directory):
    QUALIFY.run(prefix, ["stop", "--time", "120", container], timeout=150)
    ended = state(prefix, container)
    require(ended.get("Running") is False and ended.get("ExitCode") == 0 and ended.get("OOMKilled") is False,
            "graceful_shutdown_failed")
    require(not (directory / "runtime-measurement.json").exists(), "shutdown_measurement_not_revoked")
    return {"exitCode": ended["ExitCode"], "oomKilled": ended["OOMKilled"], "measurementRevoked": True}


def interrupted(_kind, _frame):
    raise ValueError("operator_or_watchdog_interrupted")


def cleanup_owned(prefix, containers, apparmor, profile_loaded, owner):
    cleanup = True
    for container in reversed(containers):
        try:
            inspection = QUALIFY.run(prefix, ["inspect", container, "--format", "{{.Id}} {{json .Config.Labels}}"], check=False, timeout=10)
            if inspection.returncode != 0:
                remaining = QUALIFY.run(prefix, ["container", "ls", "--all", "--filter", "name=^/" + container + "$",
                                                "--format", "{{.Names}}"], check=False, timeout=10)
                cleanup = cleanup and remaining.returncode == 0 and not remaining.stdout.strip()
                continue
            identifier, separator, encoded_labels = inspection.stdout.partition(" ")
            labels = json.loads(encoded_labels) if separator else None
            if not re.fullmatch(r"[0-9a-f]{64}", identifier) or not isinstance(labels, dict) or labels.get(OWNER_LABEL) != owner:
                cleanup = False
                continue
            # Bind deletion to the inspected owned object, so a concurrent name
            # replacement cannot redirect cleanup to another container.
            removed = QUALIFY.run(prefix, ["rm", "--force", identifier], check=False, timeout=30)
            remaining = QUALIFY.run(prefix, ["container", "ls", "--all", "--filter", "id=" + identifier,
                                            "--format", "{{.ID}}"], check=False, timeout=10)
            cleanup = cleanup and removed.returncode == 0 and remaining.returncode == 0 and not remaining.stdout.strip()
        except (ValueError, OSError, subprocess.SubprocessError):
            cleanup = False
    # Removing a profile from a possibly live container would remove protection.
    if profile_loaded and cleanup:
        try:
            subprocess.run(["apparmor_parser", "--remove", str(apparmor)], capture_output=True, timeout=30, check=True)
        except (OSError, subprocess.SubprocessError):
            cleanup = False
    return cleanup


def retain_and_cleanup(prefix, containers, apparmor, profile_loaded, runtime, evidence, report, owner):
    try:
        report["privateDiagnosticsRetained"] = QUALIFY.retain_private(runtime, evidence)
    except (OSError, ValueError):
        report.update({"passed": False, "failureCode": "private_evidence_retention_failed"})
    finally:
        cleanup = cleanup_owned(prefix, containers, apparmor, profile_loaded, owner)
    return cleanup


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="immutable OCI reference or exact Docker sha256 image ID")
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--runtime-dsn-file", type=Path, required=True)
    parser.add_argument("--database-ca-file", type=Path, required=True)
    parser.add_argument("--network", required=True)
    parser.add_argument("--host-port", type=int, default=0, help="loopback port; default allocates an unused ephemeral port")
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    require(platform.system() == "Linux" and platform.machine() in ("x86_64", "amd64") and os.geteuid() == 0, "trusted_linux_root_runner_required")
    require(QUALIFY.COMMIT.fullmatch(args.expected_commit) and NETWORK.fullmatch(args.network)
            and 0 <= args.host_port <= 65535, "smoke_arguments_invalid")
    dsn, _ = CAPACITY.trusted_dsn(args.runtime_dsn_file, "judge_runtime")
    ca, ca_hash = CAPACITY.trusted_public_ca(args.database_ca_file)
    if args.host_port:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", args.host_port))
    initial_headroom = check_headroom(startup=True)
    prefix = ["docker", "--context", "default"]
    daemon = json.loads(QUALIFY.run(prefix, ["info", "--format", "{{json .}}"], timeout=10).stdout)
    require(daemon.get("CgroupVersion") == "2", "cgroup_v2_required")
    image = json.loads(QUALIFY.run(prefix, ["image", "inspect", args.image], timeout=10).stdout)[0]
    digest, identity_kind = image_identity(image, args.image)
    require(image.get("Config", {}).get("Healthcheck", {}).get("Test", ["NONE"])[0] != "NONE", "image_healthcheck_required")
    network = json.loads(QUALIFY.run(prefix, ["network", "inspect", args.network], timeout=10).stdout)[0]
    require(network.get("Driver") == "bridge", "dedicated_bridge_network_required")
    evidence = args.evidence.absolute()
    require(not evidence.exists() and not evidence.is_symlink(), "fresh_evidence_directory_required")
    evidence.mkdir(mode=0o755, parents=True)
    identifier = "startrack-v02-smoke-" + secrets.token_hex(8)
    facilities = Path(tempfile.mkdtemp(prefix="facility-", dir=evidence))
    facilities.chmod(0o755)
    containers, profile_loaded = [], False
    profile = ROOT / "docker/startrack-v02.seccomp.json"
    apparmor = facilities / "apparmor.profile"
    runtime = facilities / "runtime"
    runtime.mkdir(mode=0o755)
    report = {"schemaVersion": 1, "scope": "SHARED_HOST_BOUNDED_STARTUP_AND_API_SMOKE", "passed": False,
              "qualified": False, "productionQualified": False, "sourceCommit": args.expected_commit,
              "imageReference": args.image, "imageID": image["Id"], "runtimeDigest": digest, "runtimeDigestKind": identity_kind,
              "limits": {"memoryBytes": MEMORY_BYTES, "swapBytes": 0, "cpus": 1, "pids": 256, "runTmpfsBytes": 512 << 20},
              "host": {"kernel": platform.release(), "memoryBytes": daemon.get("MemTotal"), "availableBeforeBytes": initial_headroom},
              "databaseCaSha256": ca_hash, "failureCode": "incomplete", "limitations": ["FULL_ADVERSARIAL_QUALIFICATION_NOT_RUN",
              "MAXIMUM_PACKAGE_AND_PARALLEL_STATEMENT_CAPACITY_NOT_RUN", "REAL_BACKEND_INTEGRATION_NOT_RUN", "TASK_EXECUTION_AND_RECOVERY_NOT_RUN"]}
    try:
        signal.signal(signal.SIGINT, interrupted)
        signal.signal(signal.SIGTERM, interrupted)
        signal.signal(signal.SIGALRM, interrupted)
        signal.alarm(540)
        extract = identifier + "-extract"
        containers.append(extract)
        QUALIFY.run(prefix, ["create", "--name", extract, "--label", OWNER_LABEL + "=" + identifier,
                            "--entrypoint", "/bin/true", image["Id"]], timeout=15)
        for name in ("context-inventory.json", "binaries.sha256"):
            QUALIFY.run(prefix, ["cp", extract + ":/opt/startrack/provenance/" + name, str(facilities / name)], timeout=15)
        context = QUALIFY.regular_json(facilities / "context-inventory.json", 32 << 20)
        require(context.get("gitHead") == args.expected_commit and context.get("sourceState") == "CLEAN"
                and not context.get("workingTreeStatus"), "image_clean_source_commit_mismatch")
        for name in ("startrack-v02.apparmor", "startrack-v02.seccomp.json", "startrack-workload-seccomp.yaml", "workload-security-profile.lock.json"):
            target = facilities / name
            QUALIFY.run(prefix, ["cp", extract + ":/opt/startrack/" + name, str(target)], timeout=15)
            require(target.read_bytes() == (ROOT / "docker" / name).read_bytes(), "image_security_profile_mismatch")
        require(hashlib.sha256(profile.read_bytes()).hexdigest() == QUALIFY.regular_json(ROOT / "docker/security-profile.lock.json")["profileSha256"], "seccomp_profile_checksum_invalid")
        apparmor.write_text(scoped_apparmor((ROOT / "docker/startrack-v02.apparmor").read_text(), identifier))
        subprocess.run(["apparmor_parser", "--add", str(apparmor)], capture_output=True, timeout=30, check=True)
        profile_loaded = True
        report["apparmor"] = {"name": identifier, "sourceSha256": hashlib.sha256((ROOT / "docker/startrack-v02.apparmor").read_bytes()).hexdigest(),
                               "scopedSha256": hashlib.sha256(apparmor.read_bytes()).hexdigest(), "change": "PROFILE_AND_SELF_PEER_NAME_ONLY"}
        binaries = dict((filename, checksum) for checksum, filename in (line.split(None, 1) for line in (facilities / "binaries.sha256").read_text().splitlines()))
        secret_directory = facilities / "secrets"
        secret_directory.mkdir(mode=0o700)
        values = {name: secrets.token_hex(32) for name in ("backend-judge-token", "judge-backend-token", "runtime-token", "scheduler-token", "catalog-cursor-key")}
        values["database-url"] = dsn
        for name, value in values.items():
            CAPACITY.secret_file(secret_directory / name, value)
        active = identifier + "-active"
        report["ownedContainer"] = active
        containers.append(active)
        command = ["run", "--name", active, "--label", OWNER_LABEL + "=" + identifier,
                   "--detach", "--network", args.network, *docker_limits(profile, identifier, args.host_port),
                   "--mount", "type=bind,source=" + str(secret_directory) + ",target=/run/secrets/startrack,readonly",
                   "--mount", "type=bind,source=" + str(runtime) + ",target=/run/startrack-supervisor",
                   "--mount", "type=bind,source=" + str(ca) + ",target=" + CAPACITY.DATABASE_CA_PATH + ",readonly",
                   "--env", "JUDGE_APPARMOR_PROFILE=" + identifier,
                   "--env", "JUDGE_WORKER_IMAGE_DIGEST=" + digest,
                   "--env", "JUDGE_CHECKER_SHA256=" + binaries["/opt/startrack/libexec/default_validator"],
                   "--env", "JUDGE_MATURE_BRIDGE_SHA256=" + binaries["/opt/startrack/libexec/problemtools-bridge.py"], image["Id"]]
        QUALIFY.run(prefix, command, timeout=30)
        configuration = json.loads(QUALIFY.run(prefix, ["inspect", active, "--format", "{{json .HostConfig}}"], timeout=10).stdout)
        report["enforcedDockerLimits"] = enforced_limits(configuration, identifier)
        port_output = QUALIFY.run(prefix, ["port", active, "8082/tcp"], timeout=10).stdout.strip()
        require(re.fullmatch(r"127\.0\.0\.1:[1-9][0-9]{0,4}", port_output), "loopback_publication_invalid")
        port = int(port_output.split(":")[1])
        first, report["health"], report["initialIsolationObservations"] = wait_ready(prefix, active, runtime, digest, port)
        report["initialMeasurement"] = first
        report["initialDockerHealthcheckPassed"] = healthy_docker_probe(state(prefix, active))
        report["api"] = api_checks(port, values["backend-judge-token"])
        report["firstStop"] = stop(prefix, active, runtime)
        check_headroom(startup=True)
        QUALIFY.run(prefix, ["start", active], timeout=15)
        port_output = QUALIFY.run(prefix, ["port", active, "8082/tcp"], timeout=10).stdout.strip()
        require(re.fullmatch(r"127\.0\.0\.1:[1-9][0-9]{0,4}", port_output), "loopback_publication_invalid")
        port = int(port_output.split(":")[1])
        second, _, report["restartIsolationObservations"] = wait_ready(prefix, active, runtime, digest, port)
        QUALIFY.require_fresh_restart(first, second, report["restartIsolationObservations"])
        report["restartMeasurement"] = second
        report["restartDockerHealthcheckPassed"] = healthy_docker_probe(state(prefix, active))
        report["restartAPI"] = api_checks(port, values["backend-judge-token"])
        report["finalStop"] = stop(prefix, active, runtime)
        report.update({"passed": True, "failureCode": ""})
    except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError, subprocess.SubprocessError) as error:
        report["failureCode"] = str(error) if isinstance(error, ValueError) and re.fullmatch(r"[a-z_]+", str(error)) else type(error).__name__
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        cleanup = retain_and_cleanup(prefix, containers, apparmor, profile_loaded, runtime, evidence, report, identifier)
        report["cleanupPassed"] = cleanup
        if not cleanup:
            report.update({"passed": False, "failureCode": "owned_resource_cleanup_failed"})
        if cleanup:
            shutil.rmtree(facilities)
        else:
            # A failed removal can leave a bind mount live. Retain its root-only
            # credential facility for explicit cleanup rather than losing it.
            facilities.chmod(0o700)
            report["retainedOwnedFacility"] = str(facilities)
        (evidence / "smoke.json").write_text(json.dumps(report, indent=2) + "\n")
        (evidence / "smoke.json").chmod(0o644)
    print("Bounded Linux smoke " + ("passed; release qualification remains separate" if report["passed"] else "failed: " + report["failureCode"]))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, KeyError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        print("Bounded Linux smoke setup failed: " + type(error).__name__)
        raise SystemExit(1)
