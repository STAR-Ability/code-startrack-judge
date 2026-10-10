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
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import secrets
import selectors
import shutil
import signal
import socket
import stat
import subprocess
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parent.parent
MEMORY_BYTES = 3 << 30
MIN_HEADROOM_BYTES = 1 << 30
NETWORK = re.compile(r"startrack-v02-(?:smoke-[a-z0-9-]+|integration_default)\Z")
OWNER_LABEL = "io.startrack.bounded-smoke.owner"
DOCKER_STREAM_BYTES = 65536
MAX_DOCKER_DIAGNOSTIC_STREAMS = 16
ENDPOINT_INSPECTION = ('{"Id":{{json .Id}},"Labels":{{json .Config.Labels}},"State":{{json .State}},'
                       '"Networks":{{json .NetworkSettings.Networks}},"Ports":{{json .NetworkSettings.Ports}},'
                       '"PortBindings":{{json .HostConfig.PortBindings}}}')


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


def docker_limits(profile, apparmor, port, internal=False):
    return ["--read-only", "--cgroupns", "private", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--security-opt", "apparmor=" + apparmor,
            "--security-opt", "seccomp=" + str(profile), "--pids-limit", "256",
            "--memory", "3g", "--memory-swap", "3g", "--cpus", "1",
            "--tmpfs", "/run:rw,nosuid,nodev,size=512m,nr_inodes=65536,mode=755",
            "--tmpfs", "/var/lib/startrack:rw,nosuid,nodev,noexec,size=64m,mode=755",
            "--tmpfs", "/var/lib/startrack-judger:rw,nosuid,nodev,noexec,size=64m,mode=755",
            *([] if internal else ["--publish", "127.0.0.1:" + (str(port) if port else "") + ":8082"]),
            *[item for capability in QUALIFY.CAPABILITIES for item in ("--cap-add", capability)]]


def bounded_docker(prefix, args, timeout=10):
    """Drain both CLI streams with fixed memory and time bounds; never print them."""
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    truncated = {name: False for name in buffers}
    timed_out = False
    deadline = time.monotonic() + timeout
    process = subprocess.Popen(prefix + args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        with selectors.DefaultSelector() as selected:
            for name in buffers:
                selected.register(getattr(process, name), selectors.EVENT_READ, name)
            while selected.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    break
                for key, _ in selected.select(min(1, remaining)):
                    chunk = os.read(key.fd, 16384)
                    if not chunk:
                        selected.unregister(key.fileobj)
                        continue
                    name = key.data
                    remaining_bytes = DOCKER_STREAM_BYTES - len(buffers[name])
                    buffers[name].extend(chunk[:remaining_bytes])
                    truncated[name] = truncated[name] or len(chunk) > remaining_bytes
            if not timed_out:
                try:
                    process.wait(timeout=max(0.01, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    timed_out = True
    finally:
        try:
            if process.poll() is None:
                process.kill()
            # Do not use Popen.__exit__: it waits without a deadline if reaping
            # fails, which could postpone cleanup of the owned container.
            process.wait(timeout=5)
        finally:
            process.stdout.close()
            process.stderr.close()
    result = subprocess.CompletedProcess(prefix + args, process.returncode, bytes(buffers["stdout"]), bytes(buffers["stderr"]))
    result.timed_out = timed_out
    result.truncated = truncated
    return result


def retain_docker_output(evidence, name, result):
    require(re.fullmatch(r"(?:initial|restart|failure)-(?:run|start|inspect|port|logs)", name), "docker_diagnostic_name_invalid")
    destination = evidence / "docker-private"
    if not destination.exists():
        destination.mkdir(mode=0o700)
    facts = destination.lstat()
    require(stat.S_ISDIR(facts.st_mode) and stat.S_IMODE(facts.st_mode) == 0o700 and facts.st_uid == os.geteuid(),
            "docker_private_directory_invalid")
    entries = list(destination.iterdir())
    require(len(entries) <= MAX_DOCKER_DIAGNOSTIC_STREAMS - 2, "docker_diagnostic_global_bound_exceeded")
    for stream in ("stdout", "stderr"):
        data = getattr(result, stream)
        require(isinstance(data, bytes) and len(data) <= DOCKER_STREAM_BYTES, "docker_diagnostic_stream_bound_exceeded")
        descriptor = os.open(destination / (name + "." + stream), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)


def observed_docker(prefix, args, evidence, report, name, timeout=10, check=True):
    result = bounded_docker(prefix, args, timeout)
    retained = False
    try:
        retain_docker_output(evidence, name, result)
        retained = True
    except (OSError, ValueError):
        report["privateDockerDiagnosticsRetentionFailed"] = True
    report.setdefault("dockerDiagnostics", []).append({"stage": name, "operation": args[0], "exitCode": result.returncode,
        "timedOut": result.timed_out, "stdoutTruncated": result.truncated["stdout"], "stderrTruncated": result.truncated["stderr"],
        "privateRetained": retained})
    if check:
        require(result.returncode == 0 and not result.timed_out, "docker_" + args[0] + "_failed")
        require(not any(result.truncated.values()), "docker_output_bound_exceeded")
        require(retained, "private_docker_evidence_retention_failed")
    return result


def sanitized_state(value):
    require(isinstance(value, dict), "container_state_invalid")
    status = value.get("Status")
    require(status in ("created", "running", "paused", "restarting", "removing", "exited", "dead")
            and type(value.get("Running")) is bool and type(value.get("OOMKilled")) is bool
            and type(value.get("ExitCode")) is int and 0 <= value["ExitCode"] <= 255, "container_state_invalid")
    return {"status": status, "running": value["Running"], "exitCode": value["ExitCode"], "oomKilled": value["OOMKilled"]}


def owned_inspection(value, container_id, owner):
    require(isinstance(value, dict) and re.fullmatch(r"[0-9a-f]{64}", value.get("Id", ""))
            and (container_id is None or value["Id"] == container_id)
            and isinstance(value.get("Labels"), dict) and value["Labels"].get(OWNER_LABEL) == owner,
            "container_endpoint_ownership_invalid")
    return value["Id"]


def service_endpoint(prefix, container_id, network, owner, evidence, report, stage):
    result = observed_docker(prefix, ["inspect", container_id, "--format", ENDPOINT_INSPECTION], evidence, report, stage + "-inspect")
    value = json.loads(result.stdout)
    owned_inspection(value, container_id, owner)
    report[stage + "ContainerState"] = sanitized_state(value["State"])
    require(value["State"]["Running"] is True, "service_stopped_before_readiness")
    attached = value.get("Networks")
    require(isinstance(attached, dict) and set(attached) == {network["Name"]}
            and attached[network["Name"]].get("NetworkID") == network["Id"], "container_network_identity_invalid")
    if network.get("Internal") is True:
        address = ipaddress.IPv4Address(attached[network["Name"]].get("IPAddress", ""))
        subnets = [ipaddress.ip_network(item["Subnet"]) for item in network.get("IPAM", {}).get("Config", []) if item.get("Subnet")]
        require(address.is_private and not any((address.is_loopback, address.is_link_local, address.is_unspecified, address.is_reserved))
                and any(isinstance(subnet, ipaddress.IPv4Network) and subnet.is_private and address in subnet for subnet in subnets),
                "private_bridge_address_invalid")
        require(value.get("PortBindings") in (None, {}) and isinstance(value.get("Ports"), dict)
                and all(binding is None for binding in value["Ports"].values()), "internal_bridge_publication_forbidden")
        report["endpoint"] = {"scope": "PRIVATE_BRIDGE_FROM_HOST", "port": 8082, "hostPublished": False}
        return str(address), 8082
    result = observed_docker(prefix, ["port", container_id, "8082/tcp"], evidence, report, stage + "-port")
    publication = result.stdout.decode("utf-8", errors="strict").strip()
    require(re.fullmatch(r"127\.0\.0\.1:[1-9][0-9]{0,4}", publication), "loopback_publication_invalid")
    port = int(publication.split(":")[1])
    require(port <= 65535, "loopback_publication_invalid")
    report["endpoint"] = {"scope": "LOOPBACK_HOST_PUBLICATION", "port": port, "hostPublished": True}
    return "127.0.0.1", port


def failure_diagnostics(prefix, active, container_id, owner, evidence, report):
    result = observed_docker(prefix, ["inspect", container_id or active, "--format", ENDPOINT_INSPECTION], evidence, report,
                             "failure-inspect", check=False)
    if result.returncode != 0 or result.timed_out or any(result.truncated.values()):
        report["failureContainerDiagnosticsAvailable"] = False
        return
    value = json.loads(result.stdout)
    identifier = owned_inspection(value, container_id, owner)
    report["failureContainerState"] = sanitized_state(value["State"])
    logs = observed_docker(prefix, ["logs", "--tail", "200", identifier], evidence, report, "failure-logs", check=False)
    report["failureContainerDiagnosticsAvailable"] = (logs.returncode == 0 and not logs.timed_out
                                                      and not report.get("privateDockerDiagnosticsRetentionFailed", False))


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


def request(port, path, token=None, host="127.0.0.1"):
    connection = http.client.HTTPConnection(host, port, timeout=5)
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


def wait_ready(prefix, container, directory, digest, port, host="127.0.0.1"):
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
                status, health = request(port, "/health", host=host)
                if status == 200 and healthy_docker_probe(observed_state):
                    require(health == {"status": "ok", "service": "judge-problem-service", "contractVersion": "0.2.0",
                                       "capabilities": {"catalog": True, "judge": True, "imports": True}}, "health_response_invalid")
                    return startup_measurement, health, startup_observations
            except (OSError, json.JSONDecodeError):
                pass
        require(time.monotonic() < deadline, "service_readiness_deadline")
        time.sleep(1)


def api_checks(port, token, host="127.0.0.1"):
    statuses = {}
    for description, credential, expected in (("missing", None, 401), ("wrong", secrets.token_hex(32), 401)):
        status, _ = request(port, "/internal/v2/languages", credential, host)
        require(status == expected, "api_authorization_failed")
        statuses[description] = status
    status, languages = request(port, "/internal/v2/languages", token, host)
    require(status == 200 and isinstance(languages.get("data"), dict), "languages_probe_failed")
    values = languages["data"].get("languages", [])
    require(len(values) == 1 and values[0].get("languageId") == "cpp17", "languages_capability_invalid")
    status, catalog = request(port, "/internal/v2/problems", token, host)
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


def retain_and_cleanup(prefix, containers, apparmor, profile_loaded, runtime, evidence, report, owner, active=None, container_id=None):
    try:
        if not report["passed"] and active is not None:
            try:
                failure_diagnostics(prefix, active, container_id, owner, evidence, report)
            except Exception as error:
                report["failureContainerDiagnosticsAvailable"] = False
                report["failureContainerDiagnosticErrorClass"] = type(error).__name__
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
    parser.add_argument("--host-port", type=int, default=0, help="non-internal bridge loopback port; default allocates an ephemeral port; omit for internal bridges")
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    require(platform.system() == "Linux" and platform.machine() in ("x86_64", "amd64") and os.geteuid() == 0, "trusted_linux_root_runner_required")
    require(QUALIFY.COMMIT.fullmatch(args.expected_commit) and NETWORK.fullmatch(args.network)
            and 0 <= args.host_port <= 65535, "smoke_arguments_invalid")
    dsn, _ = CAPACITY.trusted_dsn(args.runtime_dsn_file, "judge_runtime")
    ca, ca_hash = CAPACITY.trusted_public_ca(args.database_ca_file)
    initial_headroom = check_headroom(startup=True)
    prefix = ["docker", "--context", "default"]
    daemon = json.loads(QUALIFY.run(prefix, ["info", "--format", "{{json .}}"], timeout=10).stdout)
    require(daemon.get("CgroupVersion") == "2", "cgroup_v2_required")
    image = json.loads(QUALIFY.run(prefix, ["image", "inspect", args.image], timeout=10).stdout)[0]
    digest, identity_kind = image_identity(image, args.image)
    require(image.get("Config", {}).get("Healthcheck", {}).get("Test", ["NONE"])[0] != "NONE", "image_healthcheck_required")
    network = json.loads(QUALIFY.run(prefix, ["network", "inspect", args.network], timeout=10).stdout)[0]
    require(network.get("Driver") == "bridge" and network.get("Name") == args.network
            and re.fullmatch(r"[0-9a-f]{64}", network.get("Id", "")) and type(network.get("Internal")) is bool,
            "dedicated_bridge_network_required")
    require(not (network["Internal"] and args.host_port), "host_port_not_applicable_to_internal_network")
    if args.host_port:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", args.host_port))
    evidence = args.evidence.absolute()
    require(not evidence.exists() and not evidence.is_symlink(), "fresh_evidence_directory_required")
    evidence.mkdir(mode=0o755, parents=True)
    identifier = "startrack-v02-smoke-" + secrets.token_hex(8)
    facilities = Path(tempfile.mkdtemp(prefix="facility-", dir=evidence))
    facilities.chmod(0o755)
    containers, profile_loaded = [], False
    active = container_id = None
    profile = ROOT / "docker/startrack-v02.seccomp.json"
    apparmor = facilities / "apparmor.profile"
    runtime = facilities / "runtime"
    runtime.mkdir(mode=0o755)
    report = {"schemaVersion": 1, "scope": "SHARED_HOST_BOUNDED_STARTUP_AND_API_SMOKE", "passed": False,
              "qualified": False, "productionQualified": False, "sourceCommit": args.expected_commit,
              "runnerSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
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
                   "--detach", "--network", args.network, *docker_limits(profile, identifier, args.host_port, network["Internal"]),
                   "--mount", "type=bind,source=" + str(secret_directory) + ",target=/run/secrets/startrack,readonly",
                   "--mount", "type=bind,source=" + str(runtime) + ",target=/run/startrack-supervisor",
                   "--mount", "type=bind,source=" + str(ca) + ",target=" + CAPACITY.DATABASE_CA_PATH + ",readonly",
                   "--env", "JUDGE_APPARMOR_PROFILE=" + identifier,
                   "--env", "JUDGE_WORKER_IMAGE_DIGEST=" + digest,
                   "--env", "JUDGE_CHECKER_SHA256=" + binaries["/opt/startrack/libexec/default_validator"],
                   "--env", "JUDGE_MATURE_BRIDGE_SHA256=" + binaries["/opt/startrack/libexec/problemtools-bridge.py"], image["Id"]]
        launched = observed_docker(prefix, command, evidence, report, "initial-run", timeout=30)
        container_id = launched.stdout.decode("utf-8", errors="strict").strip()
        require(re.fullmatch(r"[0-9a-f]{64}", container_id), "owned_container_id_invalid")
        configuration = json.loads(QUALIFY.run(prefix, ["inspect", container_id, "--format", "{{json .HostConfig}}"], timeout=10).stdout)
        report["enforcedDockerLimits"] = enforced_limits(configuration, identifier)
        host, port = service_endpoint(prefix, container_id, network, identifier, evidence, report, "initial")
        first, report["health"], report["initialIsolationObservations"] = wait_ready(prefix, container_id, runtime, digest, port, host)
        report["initialMeasurement"] = first
        report["initialDockerHealthcheckPassed"] = healthy_docker_probe(state(prefix, container_id))
        report["api"] = api_checks(port, values["backend-judge-token"], host)
        report["firstStop"] = stop(prefix, container_id, runtime)
        check_headroom(startup=True)
        observed_docker(prefix, ["start", container_id], evidence, report, "restart-start", timeout=15)
        host, port = service_endpoint(prefix, container_id, network, identifier, evidence, report, "restart")
        second, _, report["restartIsolationObservations"] = wait_ready(prefix, container_id, runtime, digest, port, host)
        QUALIFY.require_fresh_restart(first, second, report["restartIsolationObservations"])
        report["restartMeasurement"] = second
        report["restartDockerHealthcheckPassed"] = healthy_docker_probe(state(prefix, container_id))
        report["restartAPI"] = api_checks(port, values["backend-judge-token"], host)
        report["finalStop"] = stop(prefix, container_id, runtime)
        report.update({"passed": True, "failureCode": ""})
    except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError, subprocess.SubprocessError) as error:
        report["failureCode"] = str(error) if isinstance(error, ValueError) and re.fullmatch(r"[a-z_]+", str(error)) else type(error).__name__
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        cleanup = retain_and_cleanup(prefix, containers, apparmor, profile_loaded, runtime, evidence, report, identifier, active, container_id)
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
