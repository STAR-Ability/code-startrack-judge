#!/usr/bin/env python3
"""Qualify authored API imports and oversize rejection in a capped Linux facility."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import secrets
import ssl
import shutil
import stat
import subprocess
import tempfile
import time
from urllib.parse import parse_qs, urlparse
import uuid

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("startrack_linux_qualify", ROOT / "scripts/linux-qualify.py")
QUALIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(QUALIFY)
FACILITY_BYTES = 2 << 30
SYNTHETIC = "SYNTHETIC_QUALIFICATION_NO_UPSTREAM_PROVENANCE"
REPOSITORY = "https://github.com/oj-lab/problem-packages"
REVISION = "a4e1d6f106879043eb30af640ba46d0fcbf8053f"
LICENSE_SHA = "de52ee4ed262f4e6df22186e5f7f219cac3bae60cf1edfbb7e5dbd8f71a9323e"
CASES = ("problems/synthetic-api-member-payload", "problems/synthetic-api-sample-supported", "problems/synthetic-api-sample-heavy")
DATABASE_CA_PATH = "/opt/startrack/db-ca.crt"


def host(args, *, timeout=60):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise ValueError("private_facility_operation_failed")
    return result.stdout.strip()


def trusted_dsn(path, role):
    path = path.absolute()
    current = path
    before = path.lstat()
    while True:
        facts = current.lstat()
        if current.is_symlink() or facts.st_uid != 0 or stat.S_IMODE(facts.st_mode) & 0o022:
            raise ValueError("root_secret_facility_invalid")
        if current == path:
            if not stat.S_ISREG(facts.st_mode) or stat.S_IMODE(facts.st_mode) != 0o400 or facts.st_nlink != 1 or not 0 < facts.st_size <= 4096:
                raise ValueError("root_secret_facility_invalid")
        elif not stat.S_ISDIR(facts.st_mode):
            raise ValueError("root_secret_facility_invalid")
        if current == current.parent:
            break
        current = current.parent
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "r") as source:
        if not os.path.samestat(before, os.fstat(source.fileno())):
            raise ValueError("root_secret_facility_invalid")
        value = source.read(4097)
    parsed = urlparse(value)
    if len(value) > 4096 or any(character in value for character in "\x00\r\n") or parsed.scheme not in ("postgres", "postgresql") or parsed.username != role or not parsed.password or not re.fullmatch(r"/judge_capacity_[a-z0-9_]+", parsed.path):
        raise ValueError("disposable_database_identity_invalid")
    parameters = parse_qs(parsed.query, strict_parsing=True, keep_blank_values=True)
    if parameters.get("sslmode") != ["verify-full"] or parameters.get("sslrootcert") != [DATABASE_CA_PATH] or any(name in parameters for name in ("sslcert", "sslkey")):
        raise ValueError("disposable_database_transport_invalid")
    return value, parsed.path


def trusted_public_ca(path):
    path = path.absolute()
    before = path.lstat()
    current = path
    while True:
        facts = current.lstat()
        if current.is_symlink() or facts.st_uid != 0 or stat.S_IMODE(facts.st_mode) & 0o022:
            raise ValueError("root_public_ca_facility_invalid")
        if current == path:
            if not stat.S_ISREG(facts.st_mode) or stat.S_IMODE(facts.st_mode) != 0o444 or facts.st_nlink != 1 or not 0 < facts.st_size <= 65536:
                raise ValueError("root_public_ca_facility_invalid")
        elif not stat.S_ISDIR(facts.st_mode):
            raise ValueError("root_public_ca_facility_invalid")
        if current == current.parent:
            break
        current = current.parent
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as source:
        if not os.path.samestat(before, os.fstat(source.fileno())):
            raise ValueError("root_public_ca_facility_invalid")
        contents = source.read(65537)
    if not re.fullmatch(rb"-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\r\n]+\n-----END CERTIFICATE-----\n?", contents):
        raise ValueError("public_ca_certificate_required")
    try:
        ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata=contents.decode("ascii"))
    except (UnicodeDecodeError, ssl.SSLError):
        raise ValueError("public_ca_certificate_required") from None
    return path, hashlib.sha256(contents).hexdigest()


def secret_file(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(descriptor, "w") as output:
        os.fchmod(output.fileno(), 0o400)
        output.write(value)


def create_facility(base, resources):
    backing, mount = base / "private.ext4", base / "storage"
    resources.update({"backing": backing, "mount": mount})
    descriptor = os.open(backing, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.truncate(FACILITY_BYTES)
    host(["mkfs.ext4", "-q", "-F", "-m", "0", "-O", "^has_journal", str(backing)])
    device = host(["losetup", "--find", "--show", "--nooverlap", str(backing)])
    if not re.fullmatch(r"/dev/loop[0-9]+", device):
        raise ValueError("private_facility_device_invalid")
    resources["device"] = device
    mount.mkdir(mode=0o755)
    host(["mount", "-t", "ext4", "-o", "nosuid,nodev,noexec", device, str(mount)])
    resources["mounted"] = True
    mount.chmod(0o755)
    (mount / "private").mkdir(mode=0o700)
    os.chown(mount / "private", 20000, 20000)
    facts = os.statvfs(mount)
    if backing.stat().st_size != FACILITY_BYTES or facts.f_blocks * facts.f_frsize > FACILITY_BYTES:
        raise ValueError("private_facility_capacity_invalid")
    return {"backingBytes": FACILITY_BYTES, "filesystemBytes": facts.f_blocks * facts.f_frsize, "filesystem": "ext4", "options": ["nosuid", "nodev", "noexec"]}


def retain_logs(runtime_evidence, private, phase):
    for name in ("capacity-private.log", "runtime-private.log", "qualification-private.log"):
        source = runtime_evidence / name
        try:
            descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            continue
        with os.fdopen(descriptor, "rb") as source_file:
            facts = os.fstat(source_file.fileno())
            if not stat.S_ISREG(facts.st_mode) or facts.st_uid != 0 or stat.S_IMODE(facts.st_mode) != 0o600 or facts.st_nlink != 1 or facts.st_size > 65536:
                raise ValueError("private_evidence_invalid")
            contents = source_file.read(65537)
            if len(contents) > 65536:
                raise ValueError("private_evidence_invalid")
        descriptor = os.open(private / (phase + "-" + name), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(contents)


def receipt(case):
    if case["packagePath"] not in CASES or case["licenseTextSha256"] != LICENSE_SHA:
        raise ValueError("synthetic_receipt_source_invalid")
    return {"evidenceId": str(uuid.uuid4()), "rejectedEvidenceId": case["rejectedEvidenceId"], "previousEvidenceId": case["previousLicenseEvidenceId"], "repositoryUrl": REPOSITORY, "sourceRevision": REVISION, "packagePath": case["packagePath"], "sourceSha256": case["sourceSha256"], "normalizedSha256": case["normalizedSha256"], "scope": "PACKAGE", "spdxId": "Apache-2.0", "notice": SYNTHETIC, "sourceUrl": REPOSITORY + "/tree/" + REVISION + "/" + case["packagePath"], "licenseFiles": [{"path": "LICENSE", "sha256": LICENSE_SHA, "spdxId": "Apache-2.0"}], "repositoryLicenseTexts": {}, "coverage": SYNTHETIC, "thirdPartyReview": SYNTHETIC, "approvalEvidence": SYNTHETIC}


def wait_report(prefix, container, path, timeout):
    deadline = time.monotonic() + timeout
    while not path.exists():
        state = QUALIFY.run(prefix, ["inspect", container, "--format", "{{.State.Running}}"]).stdout.strip()
        if state != "true" or time.monotonic() > deadline:
            raise ValueError("capacity_phase_evidence_unavailable")
        time.sleep(0.25)
    return QUALIFY.regular_json(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--docker-context", required=True, choices=("default", "colima-startrack-v02"))
    parser.add_argument("--runtime-dsn-file", type=Path, required=True)
    parser.add_argument("--reviewer-dsn-file", type=Path, required=True)
    parser.add_argument("--database-ca-file", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--network", choices=("startrack-v02-integration_default",), default="startrack-v02-integration_default")
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "amd64") or os.geteuid() != 0:
        raise ValueError("trusted_linux_root_runner_required")
    repository, separator, digest = args.image.partition("@")
    if not separator or not QUALIFY.DIGEST.fullmatch(digest) or not QUALIFY.COMMIT.fullmatch(args.expected_commit) or repository not in (QUALIFY.OFFICIAL, "startrack-qualified-candidate"):
        raise ValueError("immutable_image_commit_required")
    runtime_dsn, database = trusted_dsn(args.runtime_dsn_file, "judge_runtime")
    reviewer_dsn, reviewer_database = trusted_dsn(args.reviewer_dsn_file, "judge_license_reviewer")
    database_ca, database_ca_sha = trusted_public_ca(args.database_ca_file)
    if database != reviewer_database or runtime_dsn == reviewer_dsn:
        raise ValueError("disposable_database_identity_invalid")
    evidence = args.evidence.absolute()
    evidence.mkdir(mode=0o755)
    evidence.chmod(0o755)
    private = evidence / "private"
    private.mkdir(mode=0o700)
    prefix = ["docker", "--context", args.docker_context]
    daemon = json.loads(QUALIFY.run(prefix, ["info", "--format", "{{json .}}"]).stdout)
    if daemon.get("CgroupVersion") != "2" or daemon.get("MemTotal", 0) < 15 << 30 or daemon.get("NCPU", 0) < 4:
        raise ValueError("qualification_daemon_capacity_insufficient")
    image = json.loads(QUALIFY.run(prefix, ["image", "inspect", args.image]).stdout)[0]
    if image.get("Os") != "linux" or image.get("Architecture") != "amd64" or args.image not in image.get("RepoDigests", []):
        raise ValueError("actual_image_identity_invalid")
    profile = ROOT / "docker/startrack-v02.seccomp.json"
    if hashlib.sha256(profile.read_bytes()).hexdigest() != QUALIFY.regular_json(ROOT / "docker/security-profile.lock.json")["profileSha256"]:
        raise ValueError("seccomp_profile_checksum_invalid")
    apparmor = ROOT / "docker/startrack-v02.apparmor"
    host(["apparmor_parser", "--replace", str(apparmor)])
    identifier = "startrack-capacity-" + secrets.token_hex(8)
    report = {"schemaVersion": 1, "scope": "DISPOSABLE_SYNTHETIC_API_IMPORT_CAPACITY", "syntheticFixture": True, "qualified": False, "capacityPassed": False, "sourceCommit": args.expected_commit, "imageReference": args.image, "imageID": image["Id"], "databaseTransport": "VERIFY_FULL_FIXED_PUBLIC_CA", "databaseCaSha256": database_ca_sha, "failureCode": "incomplete", "phases": [], "approvals": []}
    base = Path(tempfile.mkdtemp(prefix="facility-", dir=private))
    containers, resources = [], {}
    try:
        report["privateFacility"] = create_facility(base, resources)
        mount = resources["mount"]
        extract = identifier + "-extract"
        containers.append(extract)
        QUALIFY.run(prefix, ["create", "--name", extract, "--entrypoint", "/bin/true", args.image])
        for name in ("context-inventory.json", "binaries.sha256"):
            QUALIFY.run(prefix, ["cp", extract + ":/opt/startrack/provenance/" + name, str(base / name)])
        for name in ("startrack-v02.apparmor", "startrack-v02.seccomp.json", "startrack-workload-seccomp.yaml", "workload-security-profile.lock.json"):
            QUALIFY.run(prefix, ["cp", extract + ":/opt/startrack/" + name, str(base / name)])
            if (base / name).read_bytes() != (ROOT / "docker" / name).read_bytes():
                raise ValueError("image_security_profile_mismatch")
        context = QUALIFY.regular_json(base / "context-inventory.json", 32 << 20)
        if context.get("gitHead") != args.expected_commit or repository == QUALIFY.OFFICIAL and (context.get("sourceState") != "CLEAN" or context.get("releaseCommit") != args.expected_commit or context.get("workingTreeStatus")):
            raise ValueError("image_source_commit_mismatch")
        binaries = {name: checksum for checksum, name in (line.split(None, 1) for line in (base / "binaries.sha256").read_text().splitlines())}
        secrets_dir = base / "secrets"
        secrets_dir.mkdir(mode=0o700)
        for name in ("backend-judge-token", "judge-backend-token", "runtime-token", "scheduler-token", "catalog-cursor-key"):
            secret_file(secrets_dir / name, secrets.token_hex(32))
        secret_file(secrets_dir / "database-url", runtime_dsn)
        operator = base / "operator"
        operator.mkdir(mode=0o700)
        secret_file(operator / "config.json", json.dumps({"databaseUrl": reviewer_dsn, "privateStorageRoot": "/var/lib/startrack/private", "reviewerId": SYNTHETIC, "authority": "ADMIN"}))
        for phase in ("reject", "validate"):
            runtime_evidence = base / phase
            runtime_evidence.mkdir(mode=0o755)
            active = identifier + "-" + phase
            containers.append(active)
            common = ["run", "--name", active, "--detach", "--network", args.network, "--read-only", "--cgroupns", "private", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--security-opt", "apparmor=startrack-v02", "--security-opt", "seccomp=" + str(profile), "--pids-limit", "512", "--memory", "10g", "--memory-swap", "10g", "--cpus", "3", "--tmpfs", "/run:rw,nosuid,nodev,size=2g,nr_inodes=262144,mode=755", "--tmpfs", "/var/lib/startrack-judger:rw,nosuid,nodev,size=64m,mode=755", "--mount", "type=bind,source=" + str(mount) + ",target=/var/lib/startrack", "--mount", "type=bind,source=" + str(secrets_dir) + ",target=/run/secrets/startrack,readonly", "--mount", "type=bind,source=" + str(runtime_evidence) + ",target=/run/startrack-supervisor", "--env", "JUDGE_QUALIFICATION_ONLY=true", "--env", "JUDGE_QUALIFICATION_CAPACITY_PHASE=" + phase, "--env", "JUDGE_WORKER_IMAGE_DIGEST=" + digest, "--env", "JUDGE_CHECKER_SHA256=" + binaries["/opt/startrack/libexec/default_validator"], "--env", "JUDGE_MATURE_BRIDGE_SHA256=" + binaries["/opt/startrack/libexec/problemtools-bridge.py"]]
            common += [item for capability in QUALIFY.CAPABILITIES for item in ("--cap-add", capability)]
            common += ["--mount", "type=bind,source=" + str(database_ca) + ",target=" + DATABASE_CA_PATH + ",readonly"]
            QUALIFY.run(prefix, common + [args.image])
            current = wait_report(prefix, active, runtime_evidence / "import-capacity.json", 75 * 60 + 120)
            measurement = QUALIFY.regular_json(runtime_evidence / "runtime-measurement.json")
            observations = QUALIFY.isolation_observations(runtime_evidence, measurement, digest)
            if current.get("executionPassed") is not True or current.get("workerImageDigest") != digest or current.get("capacityUID") != 20000 or current.get("capacityCgroup") != "/service" or current.get("outcome", {}).get("passed") is not True or current["outcome"].get("phase") != phase:
                raise ValueError("capacity_phase_failed")
            current["isolationObservations"] = observations
            report["phases"].append(current)
            QUALIFY.run(prefix, ["stop", "--time", "15", active])
            if phase == "reject":
                for index, case in enumerate(current["outcome"]["cases"]):
                    secret_file(operator / "review.json", json.dumps(receipt(case)))
                    reviewer = identifier + "-review-" + str(index)
                    containers.append(reviewer)
                    command = ["run", "--name", reviewer, "--network", args.network, "--read-only", "--cap-drop", "ALL", "--cap-add", "DAC_READ_SEARCH", "--security-opt", "no-new-privileges", "--memory", "2g", "--memory-swap", "2g", "--pids-limit", "64", "--cpus", "1", "--mount", "type=bind,source=" + str(mount) + ",target=/var/lib/startrack,readonly", "--mount", "type=bind,source=" + str(operator) + ",target=/operator,readonly", "--entrypoint", "/usr/local/libexec/startrack/judge-admin", args.image, "license-review", "-config", "/operator/config.json", "-review", "/operator/review.json"]
                    command[1:1] = ["--mount", "type=bind,source=" + str(database_ca) + ",target=" + DATABASE_CA_PATH + ",readonly"]
                    result = QUALIFY.run(prefix, command, check=False, timeout=180)
                    if result.returncode:
                        raise ValueError("synthetic_offline_review_failed")
                    approval = json.loads(result.stdout)
                    if approval.get("status") != "VERIFIED" or not re.fullmatch(r"[0-9a-f-]{36}", approval.get("evidenceId", "")):
                        raise ValueError("synthetic_offline_review_failed")
                    report["approvals"].append(approval)
                    (operator / "review.json").unlink()
        report.update({"capacityPassed": True, "failureCode": ""})
    except (ValueError, OSError, KeyError, json.JSONDecodeError, subprocess.SubprocessError) as error:
        report["failureCode"] = str(error) if isinstance(error, ValueError) and re.fullmatch(r"[a-z_]+", str(error)) else type(error).__name__
    finally:
        cleanup = True
        for container in reversed(containers):
            try:
                removed = QUALIFY.run(prefix, ["rm", "--force", container], check=False)
                remains = QUALIFY.run(prefix, ["inspect", container], check=False)
                cleanup = cleanup and removed.returncode == 0 and remains.returncode != 0
            except (ValueError, OSError, subprocess.SubprocessError):
                cleanup = False
        for phase in ("reject", "validate"):
            if (base / phase).is_dir():
                try:
                    retain_logs(base / phase, private, phase)
                except (ValueError, OSError):
                    cleanup = False
        if resources.get("device") is not None:
            try:
                if os.path.ismount(resources["mount"]):
                    host(["umount", str(resources["mount"])])
                if os.path.ismount(resources["mount"]):
                    raise ValueError("private_facility_still_mounted")
                host(["losetup", "--detach", resources["device"]])
                os.rename(resources["backing"], private / "synthetic-private.ext4")
                (private / "synthetic-private.ext4").chmod(0o600)
                report["privateFacilityRetained"] = True
            except (ValueError, OSError, subprocess.SubprocessError):
                cleanup = False
        report["cleanupPassed"] = cleanup
        if not cleanup:
            report.update({"capacityPassed": False, "failureCode": "capacity_cleanup_failed"})
        elif not resources.get("mount") or not os.path.ismount(resources["mount"]):
            shutil.rmtree(base)
        (evidence / "capacity.json").write_text(json.dumps(report, indent=2) + "\n")
        (evidence / "capacity.json").chmod(0o644)
    print("Linux synthetic API import capacity " + ("passed; full acceptance pending" if report["capacityPassed"] else "failed: " + report["failureCode"]))
    return 0 if report["capacityPassed"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, KeyError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        print("Linux capacity setup failed: " + type(error).__name__)
        raise SystemExit(1)
