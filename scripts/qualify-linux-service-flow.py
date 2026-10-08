#!/usr/bin/env python3
"""Qualify fixed synthetic persistent service flows on the reviewed Linux image.

This operator harness is never a deployment or a real Backend acceptance test.
It continues a successful capacity fixture through ordinary authenticated HTTP.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import secrets
import signal
import shutil
import socket
import stat
import subprocess
import threading
import time
from urllib.parse import parse_qs, unquote, urlparse
import uuid

ROOT = Path(__file__).resolve().parent.parent


def module(name, filename):
    specification = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    loaded = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(loaded)
    return loaded


QUALIFY = module("startrack_service_linux", "linux-qualify.py")
CAPACITY = module("startrack_service_capacity", "linux-import-capacity.py")
POSTGRES = "postgres:17.10-bookworm@sha256:9b18b78397054fce88a9552e9d5a3ad5bb7fd258c5b3cc1c5028e46373d6ea8f"
NETWORK = "startrack-v02-integration_default"
MAX_PUBLIC = 32 << 20
PRIVATE_CANARY = "SYNTHETIC_SERVICE_FLOW_PRIVATE_SOURCE"
ID = re.compile(r"[1-9][0-9]{0,18}\Z")
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
TASK_FIELDS = {"requestId", "revision", "status", "error", "createdAt", "updatedAt", "finishedAt", "judgeTaskId", "submissionId", "result"}
RESULT_FIELDS = {"verdict", "timeMs", "memoryBytes", "passedTestCount", "totalTestCount", "score", "compileLog", "diagnosticCode", "judgedAt"}
SUM = '#include <cstdio>\nint main(){int a,b;if(std::scanf("%d %d",&a,&b)!=2)return 1;std::printf("%d\\n",a+b);}\n'
SLEEP_SUM = '#include <unistd.h>\n' + SUM.replace("int main(){", "int main(){sleep(3);")
FIXTURES = (
    ("AC", "AC", SUM),
    ("WA", "WA", '#include <cstdio>\nint main(){std::puts("6");}\n'),
    ("CE", "CE", "int main( {\n"),
    ("CPU_TLE", "TLE", "int main(){volatile unsigned long long x=0;for(;;){x=x+1;}}\n"),
    ("WALL_TLE", "TLE", "#include <unistd.h>\nint main(){sleep(10);}\n"),
    ("MLE", "MLE", '#include <cstdio>\n#include <fcntl.h>\n#include <sys/mman.h>\n#include <unistd.h>\nint main(){const int n=128<<20;for(int k=0;k<3;k++){char name[64];std::snprintf(name,sizeof(name),"/w/service-memory-%d",k);int fd=open(name,O_RDWR|O_CREAT|O_EXCL,0600);if(fd<0)return 71;if(ftruncate(fd,n)!=0)return 72;void* m=mmap(nullptr,n,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);if(m==MAP_FAILED)return 73;close(fd);volatile char* p=(volatile char*)m;for(int i=0;i<n;i+=4096)p[i]=1;}}\n'),
    ("OLE", "OLE", "#include <unistd.h>\nint main(){char p[8192]={};for(;;)if(write(1,p,sizeof(p))<0)return 0;}\n"),
    ("RE", "RE", "#include <csignal>\nint main(){std::raise(SIGSEGV);}\n"),
)
DATABASE_ENVIRONMENT = ("PGHOST", "PGPORT", "PGUSER", "PGPASSWORD", "PGDATABASE", "PGSSLMODE", "PGSSLROOTCERT")
PSQL = " && ".join("IFS= read -r " + name for name in DATABASE_ENVIRONMENT) + " && export " + " ".join(DATABASE_ENVIRONMENT) + " && exec psql -X -qAt --no-password -v ON_ERROR_STOP=1"
SPOOL = 'import json,os; p="/run/startrack-judger/tmp"; print(json.dumps({"entries":len(os.listdir(p))}))'


def require(condition, code):
    if not condition:
        raise ValueError(code)


def abort(_signal, _frame):
    signal.alarm(0)
    raise ValueError("service_flow_operator_or_watchdog_interrupt")


def cleanup_signals():
    # The first signal enters cleanup. Later operator signals must not skip it.
    signal.alarm(0)
    for kind in (signal.SIGINT, signal.SIGTERM):
        signal.signal(kind, signal.SIG_IGN)


def remove_container(prefix, name):
    removed = QUALIFY.run(prefix, ["rm", "--force", name], check=False, timeout=30)
    listed = QUALIFY.run(prefix, ["container", "ls", "--all", "--format", "{{.Names}}"], check=False, timeout=30)
    require(len(listed.stdout.encode()) <= 1 << 20, "container_cleanup_listing_bounds_invalid")
    return removed.returncode == 0 and listed.returncode == 0 and name not in listed.stdout.splitlines()


def strict_json(raw, limit=MAX_PUBLIC):
    require(len(raw) <= limit and PRIVATE_CANARY.encode() not in raw, "public_response_bounds_or_privacy_failed")

    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate_json_member")
            result[key] = value
        return result

    def invalid(_):
        raise ValueError("invalid_json_number")

    return json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=pairs, parse_constant=invalid)


def canonical_fixture(value):
    # Task/event fixtures contain only fixed ASCII property names, strict UTF-8,
    # safe integers and null numeric score. This is not a generic JCS engine.
    def validate(item):
        if isinstance(item, dict):
            require(all(key.isascii() for key in item), "fixture_property_domain_invalid")
            for child in item.values():
                validate(child)
        elif isinstance(item, list):
            for child in item:
                validate(child)
        elif type(item) is int:
            require(abs(item) <= (1 << 53) - 1, "fixture_integer_domain_invalid")
        elif type(item) is float:
            raise ValueError("fixture_float_domain_invalid")
    validate(value)
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def public_task(task):
    require(isinstance(task, dict) and set(task) == TASK_FIELDS, "public_task_fields_invalid")
    require(UUID.fullmatch(task.get("judgeTaskId", "")) and UUID.fullmatch(task.get("requestId", "")) and ID.fullmatch(task.get("submissionId", "")), "public_task_identity_invalid")
    result = task.get("result")
    if result is not None:
        require(isinstance(result, dict) and set(result) == RESULT_FIELDS and result.get("score") is None, "public_result_fields_invalid")
        require(result.get("compileLog") is None or isinstance(result["compileLog"], str) and len(result["compileLog"].encode()) <= 16384, "public_compile_diagnostic_invalid")
    error = task.get("error")
    require(error is None or isinstance(error, dict) and set(error) == {"code", "message", "retryable"} and type(error["retryable"]) is bool, "public_task_error_fields_invalid")
    return task


def trusted_file(path, mode, exact_size=None):
    path = path.absolute()
    current = path
    before = path.lstat()
    while True:
        facts = current.lstat()
        require(not current.is_symlink() and facts.st_uid == 0 and not stat.S_IMODE(facts.st_mode) & 0o022, "trusted_fixture_facility_invalid")
        if current == path:
            require(stat.S_ISREG(facts.st_mode) and stat.S_IMODE(facts.st_mode) == mode and facts.st_nlink == 1, "trusted_fixture_file_invalid")
            require(exact_size is None or facts.st_size == exact_size, "trusted_fixture_size_invalid")
        else:
            require(stat.S_ISDIR(facts.st_mode), "trusted_fixture_parent_invalid")
        if current == current.parent:
            break
        current = current.parent
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    require(os.path.samestat(before, os.fstat(descriptor)), "trusted_fixture_identity_changed")
    return path, descriptor


def file_sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def capacity_seed(capacity, image, commit):
    require(capacity.get("scope") == "DISPOSABLE_SYNTHETIC_API_IMPORT_CAPACITY" and capacity.get("syntheticFixture") is True and capacity.get("capacityPassed") is True and capacity.get("cleanupPassed") is True and capacity.get("privateFacilityRetained") is True, "successful_capacity_receipt_required")
    require(capacity.get("sourceCommit") == commit and capacity.get("imageReference") == image, "capacity_image_identity_mismatch")
    phases = capacity.get("phases", [])
    require(len(phases) == 2 and [phase.get("outcome", {}).get("phase") for phase in phases] == ["reject", "validate"], "capacity_phase_identity_invalid")
    require(all(phase.get("executionPassed") is True and phase.get("outcome", {}).get("passed") is True for phase in phases), "capacity_phase_not_accepted")
    cases = phases[1]["outcome"].get("cases", [])
    require([case.get("name") for case in cases] == ["MEMBER_PAYLOAD", "SAMPLE_SUPPORTED", "SAMPLE_HEAVY"], "capacity_case_order_invalid")
    seed = cases[0]
    require(seed.get("status") == "SUCCEEDED" and seed.get("checkpointsPassed") == 5 and seed.get("noPublication") is True and seed.get("detailHTTPStatus") == 200 and bool(seed.get("approvedLicenseEvidenceId")), "capacity_seed_not_validated_draft")
    require(ID.fullmatch(seed.get("problemId", "")) and UUID.fullmatch(seed.get("problemVersionId", "")), "capacity_seed_identity_invalid")
    return seed


class FixtureReceiver:
    """A fixed mock ACK facility, never Backend business implementation."""

    def __init__(self, token):
        self.token = token
        self.lock = threading.Lock()
        self.expected = {}
        self.events = {}
        self.latest = {}
        self.failures = 0
        self.duplicates = 0
        self.drop_once = set()
        self.dropped = set()
        self.invalid_once = set()
        self.invalidated = set()

    def expect(self, request):
        with self.lock:
            self.expected[request["requestId"]] = request["submissionId"]

    def receive(self, headers, raw):
        event = strict_json(raw)
        require(headers.get("Authorization") == "Bearer " + self.token and headers.get("X-Request-Id") == event.get("requestId"), "mock_callback_auth_or_identity_invalid")
        require(set(event) == {"eventId", "eventType", "occurredAt", "requestId", "aggregateId", "revision", "payload"} and event.get("eventType") == "JUDGE_TASK_UPDATED", "mock_callback_contract_invalid")
        require(UUID.fullmatch(event.get("eventId", "")) and UUID.fullmatch(event.get("aggregateId", "")), "mock_callback_uuid_invalid")
        payload = event.get("payload", {})
        public_task(payload)
        require(payload.get("judgeTaskId") == event["aggregateId"] and payload.get("requestId") == event["requestId"] and payload.get("revision") == event.get("revision"), "mock_callback_payload_binding_invalid")
        require(type(event["revision"]) is int and event["revision"] > 0 and canonical_fixture(event) == raw, "mock_callback_canonical_invalid")
        digest = hashlib.sha256(raw).hexdigest()
        with self.lock:
            require(self.expected.get(event["requestId"]) == payload.get("submissionId"), "mock_callback_submission_invalid")
            prior = self.events.get(event["eventId"])
            require(prior is None or prior["hash"] == digest, "mock_callback_event_conflict")
            revision_key = (event["aggregateId"], event["revision"])
            for known in self.events.values():
                require(known["revisionKey"] != revision_key or known["hash"] == digest, "mock_callback_revision_conflict")
            duplicate = prior is not None or self.latest.get(event["aggregateId"], 0) >= event["revision"]
            self.latest[event["aggregateId"]] = max(self.latest.get(event["aggregateId"], 0), event["revision"])
            self.events[event["eventId"]] = {"hash": digest, "revisionKey": revision_key, "payload": payload}
            self.duplicates += int(duplicate)
            drop = payload.get("status") in ("COMPLETED", "FAILED") and event["requestId"] in self.drop_once and event["requestId"] not in self.dropped
            if drop:
                self.dropped.add(event["requestId"])
            invalid = payload.get("status") in ("COMPLETED", "FAILED") and event["requestId"] in self.invalid_once and event["requestId"] not in self.invalidated
            if invalid:
                self.invalidated.add(event["requestId"])
        return {"data": {"accepted": True, "duplicate": duplicate}, "requestId": str(uuid.uuid4()) if invalid else event["requestId"]}, "drop" if drop else "invalid" if invalid else "normal"

    def handler(self):
        receiver = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_):
                pass

            def do_POST(self):
                try:
                    length = self.headers.get("Content-Length", "")
                    require(self.path == "/internal/v2/events/judge" and length.isdigit() and 0 < int(length) <= MAX_PUBLIC and self.headers.get("Transfer-Encoding") is None, "mock_callback_request_invalid")
                    self.connection.settimeout(10)
                    raw = self.rfile.read(int(length))
                    require(len(raw) == int(length), "mock_callback_body_incomplete")
                    ack, mode = receiver.receive(self.headers, raw)
                    if mode == "drop":
                        self.close_connection = True
                        self.connection.shutdown(socket.SHUT_RDWR)
                        self.connection.close()
                        return
                    encoded = canonical_fixture(ack)
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(encoded)))
                    self.end_headers()
                    self.wfile.write(encoded)
                except (ValueError, KeyError, TypeError, UnicodeError, OSError):
                    with receiver.lock:
                        receiver.failures += 1
                    self.close_connection = True
                    try:
                        self.send_error(400)
                    except OSError:
                        pass

        return Handler


def database_parameters(dsn):
    # PGDATABASE alone does not expand a URI in psql's default connection path.
    # Explicit libpq environment fields keep credentials out of command argv.
    try:
        uri = urlparse(dsn)
        options = parse_qs(uri.query, strict_parsing=True)
        require(uri.scheme == "postgres" and uri.hostname == "startrack-capacity-postgres"
                and uri.port == 5432 and uri.username == "judge_runtime"
                and uri.password is not None and not uri.fragment
                and re.fullmatch(r"/judge_capacity_[a-z0-9_]+", uri.path)
                and options == {"sslmode": ["verify-full"], "sslrootcert": [CAPACITY.DATABASE_CA_PATH]},
                "database_connection_parameters_invalid")
        values = [uri.hostname, str(uri.port), uri.username,
                  unquote(uri.password, encoding="utf-8", errors="strict"), uri.path[1:],
                  "verify-full", CAPACITY.DATABASE_CA_PATH]
        require(all(value and len(value) <= 1024 and not any(ord(char) < 32 or ord(char) == 127 for char in value)
                    for value in values), "database_connection_parameters_invalid")
        return values
    except (ValueError, UnicodeError):
        raise ValueError("database_connection_parameters_invalid") from None


class Database:
    def __init__(self, prefix, dsn, ca, clients):
        self.prefix, self.dsn, self.ca, self.clients = prefix, dsn, ca, clients

    def query(self, sql):
        # The only SQL callers are fixed read-only expressions in this module.
        require(sql.startswith("SELECT ") and ";" not in sql, "fixed_read_only_query_required")
        parameters = database_parameters(self.dsn)
        name = "startrack-flow-db-" + secrets.token_hex(8)
        self.clients.append(name)
        command = ["run", "--name", name, "--rm", "--interactive", "--network", NETWORK, "--read-only", "--user", "65534:65534", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--memory", "128m", "--memory-swap", "128m", "--pids-limit", "16", "--cpus", "0.5", "--mount", "type=bind,source=" + str(self.ca) + ",target=/opt/startrack/db-ca.crt,readonly", "--entrypoint", "/bin/sh", POSTGRES, "-c", PSQL]
        result = QUALIFY.run(self.prefix, command, stdin="\n".join(parameters) + "\nBEGIN READ ONLY; SET LOCAL statement_timeout='10s'; " + sql + "; COMMIT;\n", timeout=30)
        self.clients.remove(name)  # --rm completed; only uncertain clients need cleanup.
        require(len(result.stdout.encode()) <= 1 << 20, "database_fact_bounds_invalid")
        return strict_json(result.stdout.encode(), 1 << 20)

    def scope(self):
        return self.query("SELECT json_build_object('runtimeRole',current_user='judge_runtime' AND session_user=current_user,'database',current_database(),'tls',coalesce((SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()),false),'tasks',(SELECT count(*) FROM judge.judge_tasks),'results',(SELECT count(*) FROM judge.judge_results),'outbox',(SELECT count(*) FROM judge.callback_outbox),'active',(SELECT count(*) FROM judge.judge_tasks WHERE status IN('DISPATCHING','RUNNING')),'imports',(SELECT count(*) FROM judge.import_jobs),'versions',(SELECT count(*) FROM judge.problem_versions),'published',(SELECT count(*) FROM judge.platform_problems WHERE status='PUBLISHED'))")

    def task(self, identifier):
        require(UUID.fullmatch(identifier), "task_query_identity_invalid")
        return self.query("SELECT json_build_object('taskId',t.id,'requestId',t.request_id,'submissionId',t.submission_id::text,'problemId',t.problem_id::text,'versionId',t.problem_version_id,'status',t.status,'revision',t.revision,'attempt',t.attempt_count,'startedAt',t.started_at,'leaseExpiresAt',t.lease_expires_at,'databaseNow',clock_timestamp(),'sourceHash',t.source_sha256,'sourceRetained',t.transient_source_key IS NOT NULL,'lease',t.lease_owner,'frozen',t.execution_limits,'image',t.worker_image_digest,'result',CASE WHEN r.judge_task_id IS NULL THEN NULL ELSE to_jsonb(r)-ARRAY['raw_execution_log_key','compile_log'] END,'sameResultCaseTransaction',r.judge_task_id IS NOT NULL AND t.xmin=r.xmin AND NOT EXISTS(SELECT 1 FROM judge.judge_case_results c WHERE c.judge_task_id=t.id AND c.xmin<>r.xmin),'cases',(SELECT coalesce(json_agg(json_build_object('ordinal',c.ordinal,'verdict',c.verdict,'cpu',c.cpu_time_ms,'wall',c.wall_time_ms,'memory',c.memory_bytes) ORDER BY c.ordinal),'[]'::json) FROM judge.judge_case_results c WHERE c.judge_task_id=t.id),'events',(SELECT coalesce(json_agg(json_build_object('eventId',o.event_id,'revision',o.revision,'status',o.status,'hash',o.payload_hash,'attempts',o.attempt_count,'terminal',o.payload->'payload'->>'status' IN('COMPLETED','FAILED'),'payload',o.payload->'payload') ORDER BY o.revision),'[]'::json) FROM judge.callback_outbox o WHERE o.judge_task_id=t.id)) FROM judge.judge_tasks t LEFT JOIN judge.judge_results r ON r.judge_task_id=t.id WHERE t.id='" + identifier + "'")


class Service:
    def __init__(self, address, token):
        self.address, self.token = address, token
        self.health = None

    def call(self, method, path, request_id=None, body=None):
        if self.health is not None:
            self.health()
        request_id = request_id or str(uuid.uuid4())
        require(UUID.fullmatch(request_id) and path.startswith("/internal/v2/"), "fixed_http_request_invalid")
        connection = http.client.HTTPConnection(self.address, 8082, timeout=15)
        try:
            encoded = canonical_fixture(body) if body is not None else None
            connection.request(method, path, body=encoded, headers={"Authorization": "Bearer " + self.token, "X-Request-Id": request_id, "Content-Type": "application/json"})
            response = connection.getresponse()
            raw = response.read(MAX_PUBLIC + 1)
            parsed = strict_json(raw)
            require(parsed.get("requestId") == request_id, "http_response_correlation_invalid")
            return response.status, parsed
        finally:
            connection.close()

    def accepted(self, method, path, body=None, statuses=(200,)):
        status, envelope = self.call(method, path, body.get("requestId") if body and "requestId" in body else None, body)
        require(status in statuses and "data" in envelope, "normal_api_operation_failed")
        return envelope["data"]

    def wait(self, identifier, predicate, timeout=300):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            task = self.accepted("GET", "/internal/v2/judge-tasks/" + identifier)
            public_task(task)
            if predicate(task):
                return task
            require(task.get("status") not in ("COMPLETED", "FAILED", "CANCELLED"), "unexpected_terminal_before_witness")
            time.sleep(0.05)
        raise ValueError("persistent_task_deadline_exceeded")


def assert_terminal(task, facts, expected):
    public_task(task)
    result = task.get("result") or {}
    require(task.get("status") == ("FAILED" if expected == "IE" else "COMPLETED") and result.get("verdict") == expected and task.get("finishedAt") is not None, "persistent_verdict_mismatch")
    require(facts.get("sameResultCaseTransaction") is True and facts.get("taskId") == task["judgeTaskId"] and facts.get("revision") == task["revision"], "terminal_transaction_facts_invalid")
    require(len(facts.get("cases", [])) == 2 and [case.get("ordinal") for case in facts["cases"]] == [1, 2] and result.get("totalTestCount") == 2, "terminal_case_order_or_count_invalid")
    stored = facts.get("result") or {}
    require(stored.get("verdict") == expected and stored.get("result_hash") == hashlib.sha256(canonical_fixture(result)).hexdigest(), "terminal_result_hash_invalid")
    if expected == "AC":
        require(result.get("passedTestCount") == 2 and [case["verdict"] for case in facts["cases"]] == ["AC", "AC"], "accepted_cases_invalid")
    elif expected in ("CE", "IE"):
        require(result.get("passedTestCount") == 0 and all(case["verdict"] == "SKIPPED" for case in facts["cases"]), "unexecuted_case_facts_invalid")
    else:
        require(result.get("passedTestCount") == 0 and [case["verdict"] for case in facts["cases"]] == [expected, "SKIPPED"], "first_failure_stop_invalid")
    if expected == "CE":
        require(result.get("timeMs") is None and result.get("memoryBytes") is None, "compile_error_resources_invalid")
    else:
        executed = [case for case in facts["cases"] if case["verdict"] != "SKIPPED"]
        require(result.get("timeMs") == max((case["cpu"] for case in executed), default=None) and result.get("memoryBytes") == max((case["memory"] for case in executed), default=None), "terminal_resource_aggregation_invalid")
    terminal = [event for event in facts.get("events", []) if event.get("revision") == task["revision"]]
    require(len(terminal) == 1 and terminal[0].get("terminal") is True and terminal[0].get("payload") == task, "terminal_event_projection_invalid")
    return {"taskId": task["judgeTaskId"], "requestId": task["requestId"], "status": task["status"], "revision": task["revision"], "verdict": expected, "resultHash": stored["result_hash"], "caseCount": 2, "resultCaseTransactionMatched": True, "terminalEventMatched": True, "timeMs": result.get("timeMs"), "memoryBytes": result.get("memoryBytes")}


def process_identity(pid):
    try:
        contents = Path("/proc") / str(pid) / "stat"
        return contents.read_text().rsplit(")", 1)[1].split()[19]
    except (OSError, IndexError):
        return None


def boundary_report(value, measurement, digest):
    require(isinstance(value, dict) and set(value) == {"version", "imageDigest", "bootId", "measuredAt", "observations"}, "normal_process_boundary_shape_invalid")
    require(type(value["version"]) is int and value["version"] == 1 and value["imageDigest"] == digest and value["bootId"] == measurement.get("bootId") and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value["bootId"]), "normal_process_boundary_identity_invalid")
    measured = datetime.fromisoformat(value["measuredAt"].replace("Z", "+00:00"))
    require(measured.utcoffset() is not None and measured.utcoffset().total_seconds() == 0, "normal_process_boundary_time_invalid")
    observations = value["observations"]
    require(isinstance(observations, list) and len(observations) == 2, "normal_process_boundary_roles_invalid")
    for observed, role, uid in zip(observations, ("api", "judger"), (20000, 20001)):
        require(isinstance(observed, dict) and set(observed) == {"role", "uid", "pid", "startTicks", "controlMem", "controlVMRead", "controlPtrace", "denied"}, "normal_process_boundary_observation_invalid")
        require(observed["role"] == role and type(observed["uid"]) is int and observed["uid"] == uid and type(observed["pid"]) is int and observed["pid"] > 1 and type(observed["startTicks"]) is int and observed["startTicks"] > 0 and observed["denied"] is True and all(observed[key] in ("allowed", "permission_denied") for key in ("controlMem", "controlVMRead", "controlPtrace")), "normal_process_boundary_denial_invalid")
    require(observations[0]["pid"] != observations[1]["pid"], "normal_process_boundary_distinct_roles_required")
    return observations


def read_fd(directory, name, limit=16384):
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
    with os.fdopen(descriptor, "rb") as source:
        raw = source.read(limit + 1)
    require(len(raw) <= limit, "host_observation_bounds_invalid")
    return raw.decode("ascii", errors="strict")


def proc_start(raw, pid):
    opening, closing = raw.find(" ("), raw.rfind(") ")
    require(opening > 0 and closing > opening and raw[:opening] == str(pid), "host_process_stat_identity_invalid")
    fields = raw[closing + 2:].split()
    require(len(fields) >= 20 and fields[0] in ("R", "S", "D", "T", "t", "I", "W", "P", "K") and fields[19].isdigit() and int(fields[19]) > 0, "host_process_generation_invalid")
    return int(fields[19])


def proc_status(raw, uid, pid, container_pid):
    wanted = {"Uid", "Gid", "Groups", "NSpid", "CapEff", "CapPrm", "CapInh", "CapAmb", "NoNewPrivs", "VmRSS", "VmHWM", "VmSwap"}
    result = {}
    for line in raw.splitlines():
        key, colon, rest = line.partition(":")
        if not colon or key not in wanted:
            continue
        require(key not in result, "host_process_duplicate_fact")
        fields = rest.split()
        if key in ("Uid", "Gid"):
            require(len(fields) == 4 and all(value == str(uid) for value in fields), "host_process_role_credentials_invalid")
            result[key] = [uid] * 4
        elif key == "NSpid":
            require(len(fields) == 2 and all(value.isdigit() for value in fields) and int(fields[0]) == pid and int(fields[-1]) == container_pid, "host_process_namespace_identity_invalid")
            result[key] = [int(value) for value in fields]
        elif key == "Groups":
            expected = ["20002"] if uid == 20000 else []
            require(fields == expected, "host_process_supplementary_groups_invalid")
            result[key] = [int(value) for value in fields]
        elif key.startswith("Cap"):
            require(len(fields) == 1 and re.fullmatch(r"[0-9a-f]{16}", fields[0]) and int(fields[0], 16) == 0, "host_process_capabilities_invalid")
            result[key] = 0
        elif key == "NoNewPrivs":
            require(fields == ["1"], "host_process_no_new_privileges_invalid")
            result[key] = 1
        else:
            require(len(fields) == 2 and fields[0].isdigit() and fields[1] == "kB", "host_process_memory_unit_invalid")
            result[key] = int(fields[0]) * 1024
    require(set(result) == wanted, "host_process_required_fact_missing")
    return result


def proc_rollup(raw):
    # Skip the address header and all nonnumeric fields; retain no address rows.
    result = {}
    for line in raw.splitlines():
        key, colon, rest = line.partition(":")
        if key not in ("Rss", "Pss", "Swap") or not colon:
            continue
        fields = rest.split()
        require(key not in result and len(fields) == 2 and fields[0].isdigit() and fields[1] == "kB", "host_process_rollup_fact_invalid")
        result[key] = int(fields[0]) * 1024
    require(set(result) == {"Rss", "Pss", "Swap"} and result["Pss"] <= result["Rss"], "host_process_rollup_required_fact_missing")
    return result


def unified_group(raw):
    require(raw.endswith("\n") and raw.count("\n") == 1 and raw.startswith("0::/"), "host_unified_cgroup_required")
    components = raw[4:].strip().split("/")
    require(components and all(re.fullmatch(r"[A-Za-z0-9_.:-]+", part) and part not in (".", "..") for part in components), "host_cgroup_path_invalid")
    return components


def event_counts(raw):
    result = {}
    for line in raw.splitlines():
        fields = line.split()
        require(len(fields) == 2 and re.fullmatch(r"[a-z_]+", fields[0]) and fields[1].isdigit() and fields[0] not in result, "host_cgroup_event_fact_invalid")
        result[fields[0]] = int(fields[1])
    require({"low", "high", "max", "oom", "oom_kill", "oom_group_kill"} <= set(result), "host_cgroup_required_event_missing")
    return result


class MemoryWindow:
    """Fixed trusted-host numerical observer; no image privileges or secrets."""

    def __init__(self, prefix, name, inspection, boundary, output):
        self.roles, self.groups, self.closed = {}, {}, False
        self.stop = threading.Event()
        self.thread, self.error = None, None
        self.count, self.maxima, self.digest = 0, {}, hashlib.sha256()
        self.output = output
        self.started = time.monotonic()
        try:
            require(inspection["State"].get("Running") is True and re.fullmatch(r"[0-9a-f]{64}", inspection["Id"]), "host_running_container_identity_required")
            self.container_id = inspection["Id"]
            outer_pid = inspection["State"]["Pid"]
            require(type(outer_pid) is int and outer_pid > 1, "host_supervisor_pid_required")
            supervisor = os.open("/proc/" + str(outer_pid), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                start = proc_start(read_fd(supervisor, "stat"), outer_pid)
                namespace = os.stat("ns/pid", dir_fd=supervisor).st_ino
                service_path = unified_group(read_fd(supervisor, "cgroup"))
                require(service_path[-1] == "service" and len(service_path) > 1, "host_supervisor_service_group_required")
                require(start == proc_start(read_fd(supervisor, "stat"), outer_pid), "host_supervisor_generation_changed")
            finally:
                os.close(supervisor)
            self.supervisor = {"hostPID": outer_pid, "startTicks": start, "pidNamespaceInode": namespace}
            directory = os.open("/sys/fs/cgroup", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                for part in service_path[:-1]:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
                    os.close(directory)
                    directory = child
                self.groups["outer"] = os.dup(directory)
                for role in ("service", "runtime"):
                    self.groups[role] = os.open(role, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            finally:
                os.close(directory)
            top = QUALIFY.run(prefix, ["top", name, "-eo", "pid,comm"], timeout=15).stdout
            require(len(top.encode()) <= 65536, "host_role_listing_bounds_invalid")
            candidates = [(int(fields[0]), fields[1]) for fields in (line.split() for line in top.splitlines()[1:]) if len(fields) == 2 and fields[0].isdigit()]
            for observation in boundary:
                role = observation["role"]
                expected_comm = "judge-service" if role == "api" else "startrack-judge"
                for pid, comm in candidates:
                    if comm != expected_comm:
                        continue
                    descriptor = os.open("/proc/" + str(pid), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                    keep = False
                    try:
                        # Non-role candidates are inspected only for NSpid, never memory.
                        status = read_fd(descriptor, "status")
                        match = re.search(r"^NSpid:\s*([0-9]+)\s+([0-9]+)\s*$", status, re.M)
                        if match is None or int(match[2]) != observation["pid"]:
                            continue
                        require(role not in self.roles, "host_role_mapping_ambiguous")
                        credential_facts = proc_status(status, observation["uid"], pid, observation["pid"])
                        require(proc_start(read_fd(descriptor, "stat"), pid) == observation["startTicks"] and os.stat("ns/pid", dir_fd=descriptor).st_ino == namespace and read_fd(descriptor, "comm").strip() == expected_comm and unified_group(read_fd(descriptor, "cgroup")) == service_path, "host_role_generation_or_membership_invalid")
                        self.roles[role] = {"descriptor": descriptor, "hostPID": pid, "observation": observation, "namespace": namespace, "comm": expected_comm, "group": service_path, "credentials": {key: credential_facts[key] for key in ("Uid", "Gid", "Groups", "CapEff", "CapPrm", "CapInh", "CapAmb", "NoNewPrivs")}}
                        keep = True
                    finally:
                        if not keep:
                            os.close(descriptor)
            require(set(self.roles) == {"api", "judger"}, "host_role_mapping_missing")
            self.before = self.cgroups()
            self.sample()
            self.thread = threading.Thread(target=self.observe, daemon=True)
            self.thread.start()
        except BaseException:
            self.close()
            raise

    def cgroups(self):
        result = {}
        for label, descriptor in self.groups.items():
            facts = {}
            for name in ("memory.current", "memory.peak", "memory.max", "memory.swap.max"):
                raw = read_fd(descriptor, name, 64).strip()
                require(raw.isdigit(), "host_cgroup_numeric_limit_required")
                facts[name] = int(raw)
            require(facts["memory.max"] == {"outer": 10 << 30, "service": 6 << 30, "runtime": 4 << 30}[label] and facts["memory.swap.max"] == 0 and facts["memory.current"] <= facts["memory.peak"] <= facts["memory.max"], "host_cgroup_budget_invalid")
            for name in ("memory.events", "memory.events.local"):
                facts[name] = event_counts(read_fd(descriptor, name, 4096))
            directory = os.fstat(descriptor)
            require(directory.st_nlink > 0, "host_cgroup_original_directory_removed")
            facts["directoryInode"] = directory.st_ino
            result[label] = facts
        members = read_fd(self.groups["service"], "cgroup.procs").splitlines()
        require(members and len(members) <= 512 and all(value.isdigit() for value in members) and str(self.supervisor["hostPID"]) in members and all(str(role["hostPID"]) in members for role in self.roles.values()), "host_service_cgroup_membership_invalid")
        return result

    def role_memory(self, role):
        descriptor, observation, pid = role["descriptor"], role["observation"], role["hostPID"]
        before = proc_start(read_fd(descriptor, "stat"), pid)
        status = proc_status(read_fd(descriptor, "status"), observation["uid"], pid, observation["pid"])
        rollup = proc_rollup(read_fd(descriptor, "smaps_rollup"))
        after = proc_status(read_fd(descriptor, "status"), observation["uid"], pid, observation["pid"])
        require(before == proc_start(read_fd(descriptor, "stat"), pid) == observation["startTicks"] and status["Uid"] == after["Uid"] and status["Gid"] == after["Gid"] and status["NSpid"] == after["NSpid"] and os.stat("ns/pid", dir_fd=descriptor).st_ino == role["namespace"] and read_fd(descriptor, "comm").strip() == role["comm"] and unified_group(read_fd(descriptor, "cgroup")) == role["group"], "host_role_sample_generation_changed")
        return {"rssBytes": rollup["Rss"], "pssBytes": rollup["Pss"], "hwmBytes": max(status["VmHWM"], after["VmHWM"]), "statusRSSBytes": max(status["VmRSS"], after["VmRSS"]), "swapBytes": max(rollup["Swap"], status["VmSwap"], after["VmSwap"])}

    def sample(self):
        sample = {role: self.role_memory(facts) for role, facts in self.roles.items()}
        groups = self.cgroups()
        self.digest.update(canonical_fixture({"ordinal": self.count + 1, "roles": sample, "cgroups": groups}))
        self.count += 1
        for role, values in sample.items():
            self.maxima[role] = {key: max(value, self.maxima.get(role, {}).get(key, 0)) for key, value in values.items()}

    def observe(self):
        while not self.stop.wait(0.25):
            try:
                self.sample()
            except Exception as error:
                self.error = type(error).__name__
                self.stop.set()

    def check(self):
        require(self.error is None and not self.closed and self.thread is not None and self.thread.is_alive(), "host_memory_sampler_failed")

    def finish(self, reason):
        require(not self.closed, "host_memory_window_already_closed")
        try:
            self.stop.set()
            if self.thread is not None:
                self.thread.join(timeout=5)
                require(not self.thread.is_alive(), "host_memory_sampler_did_not_stop")
            require(self.error is None, "host_memory_sampler_failed")
            self.sample()
            after = self.cgroups()
            deltas = {}
            for role in self.groups:
                require(after[role]["directoryInode"] == self.before[role]["directoryInode"] and after[role]["memory.peak"] >= self.before[role]["memory.peak"], "host_cgroup_generation_or_peak_changed")
                deltas[role] = {}
                for name in ("memory.events", "memory.events.local"):
                    initial, final = self.before[role][name], after[role][name]
                    require(set(initial) == set(final) and all(final[key] >= initial[key] for key in initial), "host_cgroup_event_counter_regressed")
                    deltas[role][name] = {key: final[key] - initial[key] for key in initial}
                require(all(deltas[role]["memory.events.local"][key] == 0 for key in ("oom", "oom_kill", "oom_group_kill")), "host_parent_or_service_local_oom")
            require(all(deltas["service"]["memory.events"][key] == 0 for key in ("oom", "oom_kill", "oom_group_kill")), "host_service_group_oom")
            receipt = {"scope": "NORMAL_SERVICE_HOST_NUMERIC_MEMORY", "passed": True, "endReason": reason, "containerID": self.container_id, "sampleIntervalMs": 250, "samples": self.count, "elapsedMs": int((time.monotonic() - self.started) * 1000), "sampleStreamSha256": self.digest.hexdigest(), "supervisor": self.supervisor, "roles": [{"role": name, "uid": facts["observation"]["uid"], "containerPID": facts["observation"]["pid"], "hostPID": facts["hostPID"], "startTicks": facts["observation"]["startTicks"], "credentials": facts["credentials"], "boundaryDenied": True, "maximumObserved": self.maxima[name]} for name, facts in self.roles.items()], "before": self.before, "after": after, "eventDeltas": deltas, "hwmScope": "PER_SERVICE_PROCESS_GENERATION", "kernelPeakScope": "ORIGINAL_CONTAINER_CGROUP_LIFETIME_INCLUDES_STARTUP"}
            raw = json.dumps(receipt, indent=2).encode() + b"\n"
            require(len(raw) <= 16384, "host_memory_receipt_bounds_invalid")
            self.output.write_bytes(raw)
            self.output.chmod(0o600)
            return {"receiptSha256": hashlib.sha256(raw).hexdigest(), "passed": True, "samples": self.count, "roles": receipt["roles"], "cgroupEventDeltas": deltas, "kernelPeaksBytes": {role: facts["memory.peak"] for role, facts in after.items()}}
        finally:
            self.close()

    def close(self):
        if self.closed:
            return
        self.stop.set()
        if self.thread is not None:
            self.thread.join(timeout=5)
            # An uncertain observer keeps its FDs until process exit. Closing
            # them while it reads could redirect a reused FD to another file.
            require(not self.thread.is_alive(), "host_memory_sampler_did_not_stop")
        for facts in self.roles.values():
            os.close(facts["descriptor"])
        for descriptor in self.groups.values():
            os.close(descriptor)
        self.roles, self.groups, self.closed = {}, {}, True


class Lifecycle:
    def __init__(self, prefix, image, digest, ca, mounted, secret_dir, gateway, binaries, evidence):
        self.prefix, self.image, self.digest, self.ca, self.mounted = prefix, image, digest, ca, mounted
        self.secret_dir, self.gateway, self.binaries, self.evidence = secret_dir, gateway, binaries, evidence
        self.containers = []
        self.active = None
        self.starts = []
        self.memory = None

    def start(self):
        name = "startrack-flow-" + secrets.token_hex(8)
        self.containers.append(name)
        current = self.evidence / ("normal-" + str(len(self.containers)))
        current.mkdir(mode=0o755)
        command = ["run", "--name", name, "--detach", "--network", NETWORK, "--add-host", "backend:" + self.gateway, "--read-only", "--cgroupns", "private", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--security-opt", "apparmor=startrack-v02", "--security-opt", "seccomp=" + str(ROOT / "docker/startrack-v02.seccomp.json"), "--pids-limit", "512", "--memory", "10g", "--memory-swap", "10g", "--cpus", "3", "--tmpfs", "/run:rw,nosuid,nodev,size=2g,nr_inodes=262144,mode=755", "--tmpfs", "/var/lib/startrack-judger:rw,nosuid,nodev,size=64m,mode=755", "--mount", "type=bind,source=" + str(self.mounted) + ",target=/var/lib/startrack", "--mount", "type=bind,source=" + str(self.secret_dir) + ",target=/run/secrets/startrack,readonly", "--mount", "type=bind,source=" + str(current) + ",target=/run/startrack-supervisor", "--mount", "type=bind,source=" + str(self.ca) + ",target=/opt/startrack/db-ca.crt,readonly", "--env", "JUDGE_WORKER_IMAGE_DIGEST=" + self.digest, "--env", "JUDGE_CHECKER_SHA256=" + self.binaries["/opt/startrack/libexec/default_validator"], "--env", "JUDGE_MATURE_BRIDGE_SHA256=" + self.binaries["/opt/startrack/libexec/problemtools-bridge.py"]]
        command += [entry for capability in QUALIFY.CAPABILITIES for entry in ("--cap-add", capability)]
        QUALIFY.run(self.prefix, command + [self.image])
        self.active = name
        inspection = json.loads(QUALIFY.run(self.prefix, ["inspect", name]).stdout)[0]
        address = inspection["NetworkSettings"]["Networks"][NETWORK]["IPAddress"]
        require(ipaddress.ip_address(address).is_private, "private_service_address_required")
        service = Service(address, (self.secret_dir / "backend-judge-token").read_text())
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            inspection = json.loads(QUALIFY.run(self.prefix, ["inspect", name]).stdout)[0]
            require(inspection["State"].get("Running") is True, "normal_service_start_failed")
            try:
                languages = service.accepted("GET", "/internal/v2/languages")
                require(len(languages.get("languages", [])) == 1 and languages["languages"][0].get("languageId") == "cpp17", "normal_capabilities_invalid")
                measurement = QUALIFY.regular_json(current / "runtime-measurement.json")
                require(measurement.get("identity", {}).get("workerImageDigest") == self.digest and all(measurement.get("checks", {}).get(key) is True for key in QUALIFY.REQUIRED_CHECKS), "normal_measurement_invalid")
                observations = QUALIFY.isolation_observations(current, measurement, self.digest)
                _, descriptor = trusted_file(current / "process-boundary.json", 0o644)
                with os.fdopen(descriptor, "rb") as source:
                    boundary_raw = source.read(4097)
                roles = boundary_report(strict_json(boundary_raw, 4096), measurement, self.digest)
                require((Path("/proc/sys/kernel/random/boot_id").read_text().strip()) == measurement["bootId"] and inspection["Config"]["Image"] == self.image, "normal_local_host_boot_or_image_mismatch")
                break
            except (ValueError, OSError, KeyError, http.client.HTTPException):
                time.sleep(0.2)
        else:
            raise ValueError("normal_service_readiness_deadline_exceeded")
        self.starts.append({"ordinal": len(self.containers), "runtimeMeasurementSha256": file_sha(current / "runtime-measurement.json"), "isolationObservationsSha256": file_sha(current / "runtime-isolation-observations.json"), "processBoundarySha256": hashlib.sha256(boundary_raw).hexdigest(), "processBoundaryImageBootMatched": True, "runtimeCleanupMeasured": observations["cleanupObservations"]["ownedGroupsDrained"]})
        require(self.memory is None, "previous_memory_window_not_finished")
        self.memory = MemoryWindow(self.prefix, name, inspection, roles, current / "host-service-memory.json")
        service.health = self.memory.check
        return service

    def finish_memory(self, reason):
        require(self.memory is not None, "normal_memory_window_missing")
        self.starts[-1]["serviceMemory"] = self.memory.finish(reason)
        self.memory = None

    def kill(self):
        rows = QUALIFY.run(self.prefix, ["top", self.active, "-eo", "pid"]).stdout.splitlines()[1:]
        identities = {int(row.strip()): process_identity(int(row.strip())) for row in rows if row.strip().isdigit()}
        require(bool(identities) and all(value is not None for value in identities.values()), "interrupted_process_witness_missing")
        self.finish_memory("BEFORE_AUTHORED_CONTAINER_KILL")
        QUALIFY.run(self.prefix, ["kill", "--signal", "KILL", self.active])
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if all(process_identity(pid) != identity for pid, identity in identities.items()):
                inspection = json.loads(QUALIFY.run(self.prefix, ["inspect", self.active]).stdout)[0]
                require(inspection["State"].get("Running") is False, "interrupted_container_still_running")
                return {"signal": "KILL", "observedProcesses": len(identities), "originalProcessGenerationsGone": True}
            time.sleep(0.1)
        raise ValueError("interrupted_process_cleanup_failed")

    def executing(self):
        # RUNNING starts at the compile acknowledgement. Require a stable real
        # contestant executable witness before the authored interruption.
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            rows = QUALIFY.run(self.prefix, ["top", self.active, "-eo", "pid,comm"]).stdout.splitlines()[1:]
            witnesses = {int(fields[0]): process_identity(int(fields[0])) for fields in (row.split() for row in rows) if len(fields) == 2 and fields[0].isdigit() and fields[1] == "main"}
            if witnesses and all(value is not None for value in witnesses.values()):
                time.sleep(0.15)
                if all(process_identity(pid) == identity for pid, identity in witnesses.items()):
                    return len(witnesses)
            time.sleep(0.05)
        raise ValueError("actual_contestant_process_witness_missing")

    def spool_empty(self):
        facts = strict_json(QUALIFY.run(self.prefix, ["exec", "--user", "0", self.active, "/usr/bin/python3", "-I", "-c", SPOOL], timeout=15).stdout.encode(), 4096)
        require(facts.get("entries") == 0, "normal_judger_spool_retained")


def request(problem_ref, source, submission):
    source = "// " + PRIVATE_CANARY + "\n" + source
    return {"requestId": str(uuid.uuid4()), "submissionId": str(submission), "problemRef": problem_ref, "languageId": "cpp17", "sourceCode": source, "sourceSha256": hashlib.sha256(source.encode()).hexdigest()}


def assert_frozen(facts, original, digest):
    frozen = facts.get("frozen", {})
    require(facts.get("sourceHash") == original["sourceSha256"] and facts.get("versionId") == original["problemRef"]["problemVersionId"] and facts.get("problemId") == original["problemRef"]["problemId"] and facts.get("image") == digest, "normal_task_frozen_identity_invalid")
    require(frozen.get("limits") == {"cpuTimeNS": 2_000_000_000, "wallTimeNS": 4_000_000_000, "memoryBytes": 256 << 20, "outputBytes": 8 << 20, "processes": 32} and frozen.get("sourceSizeBytes") == len(original["sourceCode"].encode()) and frozen.get("sourceFilename") == "main.cpp" and frozen.get("identity", {}).get("workerImageDigest") == digest, "normal_task_frozen_configuration_invalid")


def all_delivered(db, receiver, identifier, timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        facts = db.task(identifier)
        events = facts.get("events", [])
        with receiver.lock:
            require(receiver.failures == 0, "mock_receiver_validation_failed")
            accepted = all(event.get("status") == "DELIVERED" and receiver.events.get(event["eventId"], {}).get("hash") == event.get("hash") for event in events)
        if events and accepted:
            return facts
        time.sleep(1)
    raise ValueError("callback_delivery_deadline_exceeded")


def replay_checks(service, original, task_id):
    replay = service.accepted("POST", "/internal/v2/judge-tasks", original)
    found = service.accepted("POST", "/internal/v2/judge-tasks/by-request", {"requestIds": [original["requestId"]]})
    require(replay.get("judgeTaskId") == task_id and len(found.get("tasks", [])) == 1 and found["tasks"][0].get("judgeTaskId") == task_id and found.get("missingRequestIds") == [], "persistent_request_replay_failed")


def assert_event_sequence(facts, kills):
    expected = ["QUEUED", "DISPATCHING", "RUNNING"]
    for _ in range(3 if kills == 4 else kills):
        expected += ["DISPATCHING", "RUNNING"]
    expected += ["FAILED" if kills == 4 else "COMPLETED"]
    events = facts.get("events", [])
    require([event.get("revision") for event in events] == list(range(1, len(expected) + 1)) and [event.get("payload", {}).get("status") for event in events] == expected, "persistent_event_revision_sequence_invalid")


def concurrency(service, lifecycle, db, receiver, problem_ref, submission, report):
    originals = [request(problem_ref, SLEEP_SUM, submission + offset) for offset in range(3)]
    identifiers = []
    for original in originals:
        receiver.expect(original)
        identifiers.append(service.accepted("POST", "/internal/v2/judge-tasks", original, (202,))["judgeTaskId"])
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        states = [service.accepted("GET", "/internal/v2/judge-tasks/" + identifier)["status"] for identifier in identifiers]
        require(sum(state in ("DISPATCHING", "RUNNING") for state in states) <= 2, "persistent_worker_concurrency_exceeded")
        if states.count("RUNNING") == 2 and states.count("QUEUED") == 1:
            require(db.scope().get("active") == 2, "concurrent_database_witness_missing")
            report["concurrency"] = {"admittedTasks": 3, "observedRunning": 2, "observedQueued": 1, "productionWorkerSlots": 2}
            break
        time.sleep(0.05)
    require("concurrency" in report, "bounded_concurrent_execution_witness_missing")
    for index, (original, identifier) in enumerate(zip(originals, identifiers)):
        final = service.wait(identifier, lambda task: task.get("status") == "COMPLETED", timeout=60)
        facts = all_delivered(db, receiver, identifier)
        assert_event_sequence(facts, 0)
        assert_frozen(facts, original, lifecycle.digest)
        replay_checks(service, original, identifier)
        require(facts["attempt"] == 0, "concurrent_task_unexpected_recovery")
        record = assert_terminal(final, facts, "AC")
        record.update({"name": "CONCURRENT_AC_" + str(index + 1), "sourceSha256": original["sourceSha256"], "callbackEvents": len(facts["events"]), "allEventsDelivered": True, "normalRequestReplay": True})
        report["cases"].append(record)
    lifecycle.spool_empty()


def recovery(service, lifecycle, db, receiver, problem_ref, submission, kills, report):
    original = request(problem_ref, SLEEP_SUM, submission)
    receiver.expect(original)
    accepted = service.accepted("POST", "/internal/v2/judge-tasks", original, (202,))
    task_id = accepted["judgeTaskId"]
    first, tokens, witnesses, observations = None, [], [], []
    prior_revision, previous_expiry = 0, None
    for attempt in range(kills):
        running = service.wait(task_id, lambda task: task.get("status") == "RUNNING" and task.get("revision", 0) > prior_revision, timeout=260)
        facts = db.task(task_id)
        assert_frozen(facts, original, lifecycle.digest)
        require(facts.get("status") == "RUNNING" and facts.get("attempt") == attempt and UUID.fullmatch(facts.get("lease") or "") and facts.get("sourceRetained") is True and facts.get("image") == lifecycle.digest, "natural_recovery_attempt_invalid")
        frozen = canonical_fixture(facts["frozen"])
        identity = (facts["versionId"], facts["sourceHash"], frozen, facts["startedAt"])
        if first is None:
            first = identity
        require(identity == first and facts["lease"] not in tokens and (not tokens or running["revision"] > prior_revision), "recovery_changed_frozen_inputs_or_fence")
        tokens.append(facts["lease"])
        database_now = datetime.fromisoformat(facts["databaseNow"])
        expires = datetime.fromisoformat(facts["leaseExpiresAt"])
        require(0 < (expires - database_now).total_seconds() <= 180 and (previous_expiry is None or database_now >= previous_expiry), "natural_database_lease_clock_invalid")
        observations.append({"recoveryCount": attempt, "revision": facts["revision"], "leaseRemainingMs": int((expires - database_now).total_seconds() * 1000), "afterPreviousLeaseExpiry": previous_expiry is not None})
        previous_expiry = expires
        prior_revision = running["revision"]
        executing = lifecycle.executing()
        witness = lifecycle.kill()
        witness["stableContestantProcessesObserved"] = executing
        witnesses.append(witness)
        after = db.task(task_id)
        require(after.get("status") == "RUNNING" and after.get("attempt") == attempt and after.get("result") is None and not after.get("cases") and after.get("sourceRetained") is True, "interrupted_task_not_recoverable")
        service = lifecycle.start()
        replay_checks(service, original, task_id)
    expected = "IE" if kills == 4 else "AC"
    if kills == 1:
        service.wait(task_id, lambda task: task.get("status") == "RUNNING" and task.get("revision", 0) > prior_revision, timeout=260)
        recovered = db.task(task_id)
        require(recovered.get("attempt") == 1 and UUID.fullmatch(recovered.get("lease") or "") and recovered["lease"] not in tokens and datetime.fromisoformat(recovered["databaseNow"]) >= previous_expiry and (recovered["versionId"], recovered["sourceHash"], canonical_fixture(recovered["frozen"]), recovered["startedAt"]) == first, "recovered_execution_fence_invalid")
        tokens.append(recovered["lease"])
        require(lifecycle.executing() > 0, "recovered_execution_witness_missing")
        observations.append({"recoveryCount": 1, "revision": recovered["revision"], "afterPreviousLeaseExpiry": True})
    final = service.wait(task_id, lambda task: task.get("status") in ("COMPLETED", "FAILED"), timeout=280)
    facts = all_delivered(db, receiver, task_id)
    assert_frozen(facts, original, lifecycle.digest)
    replay_checks(service, original, task_id)
    assert_event_sequence(facts, kills)
    require(facts.get("attempt") == (3 if kills == 4 else 1) and (facts["versionId"], facts["sourceHash"], canonical_fixture(facts["frozen"]), facts["startedAt"]) == first, "final_recovery_identity_invalid")
    if expected == "IE":
        require((final.get("error") or {}).get("code") == "JUDGE_INTERRUPTED" and (final.get("error") or {}).get("retryable") is False, "recovery_exhaustion_error_invalid")
    lifecycle.spool_empty()
    record = assert_terminal(final, facts, expected)
    record.update({"name": "RECOVERY_EXHAUSTED" if kills == 4 else "RECOVERY_ONCE", "interruptions": kills, "recoveryCount": facts["attempt"], "distinctObservedFences": len(set(tokens)), "frozenInputsPreserved": True, "sourceRetained": True, "frozenInputSha256": hashlib.sha256(first[2]).hexdigest(), "processCleanup": witnesses, "attemptObservations": observations, "leaseClock": "UNMODIFIED_POSTGRESQL_180_SECONDS", "normalRequestReplay": True})
    report["cases"].append(record)
    return service


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--docker-context", required=True, choices=("colima-startrack-v02",))
    parser.add_argument("--capacity-evidence", type=Path, required=True)
    parser.add_argument("--runtime-dsn-file", type=Path, required=True)
    parser.add_argument("--database-ca-file", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    require(platform.system() == "Linux" and platform.machine() in ("amd64", "x86_64") and os.geteuid() == 0, "trusted_linux_root_runner_required")
    signal.signal(signal.SIGINT, abort)
    signal.signal(signal.SIGTERM, abort)
    signal.signal(signal.SIGALRM, abort)
    repository, separator, digest = args.image.partition("@")
    require(separator and repository in (QUALIFY.OFFICIAL, "startrack-qualified-candidate") and QUALIFY.DIGEST.fullmatch(digest) and QUALIFY.COMMIT.fullmatch(args.expected_commit), "immutable_image_commit_required")
    require(CAPACITY.host(["git", "-C", str(ROOT), "rev-parse", "HEAD"]) == args.expected_commit and not CAPACITY.host(["git", "-C", str(ROOT), "status", "--porcelain", "--untracked-files=all"]), "clean_host_source_required")
    dsn, database = CAPACITY.trusted_dsn(args.runtime_dsn_file, "judge_runtime")
    ca, ca_sha = CAPACITY.trusted_public_ca(args.database_ca_file)
    capacity_path, descriptor = trusted_file(args.capacity_evidence.absolute() / "capacity.json", 0o644)
    with os.fdopen(descriptor, "rb") as source:
        capacity = strict_json(source.read((1 << 20) + 1), 1 << 20)
    seed = capacity_seed(capacity, args.image, args.expected_commit)
    require(capacity.get("databaseCaSha256") == ca_sha, "capacity_database_ca_mismatch")
    original, descriptor = trusted_file(args.capacity_evidence.absolute() / "private/synthetic-private.ext4", 0o600, 2 << 30)
    os.close(descriptor)
    evidence = args.evidence.absolute()
    require(not evidence.exists() and not evidence.is_symlink(), "fresh_evidence_directory_required")
    evidence.mkdir(mode=0o755)
    private = evidence / "private"
    private.mkdir(mode=0o700)
    prefix = ["docker", "--context", args.docker_context]
    clients, extraction, device, mounted, receiver_server, lifecycle = [], None, None, None, None, None
    report = {"schemaVersion": 1, "scope": "DISPOSABLE_SYNTHETIC_PERSISTENT_SERVICE_FLOW", "syntheticFixture": True, "qualified": False, "serviceFlowPassed": False, "realBackendAccepted": False, "productionDeployment": "NOT_PERFORMED_FUTURE_OPERATOR_ACTION", "sourceCommit": args.expected_commit, "imageReference": args.image, "capacityReceiptSha256": file_sha(capacity_path), "databaseCaSha256": ca_sha, "cases": [], "failureCode": "incomplete", "reusedEvidence": ["accepted migration5 and runtime-role ACL", "accepted PostgreSQL stale-owner and transaction-failure tests", "accepted disposable quiescent restores"], "externalGates": ["Q-010 joint ACK correlation and shared Backend canonical vectors", "real Backend #23", "four-service release acceptance #24"]}
    report["portableAcceptance"] = {"scope": "REUSED_ACTUAL_POSTGRESQL_CONTROL_FLOW_ACCEPTANCE", "documentation": "docs/development/acceptance.md", "fixtures": ["TestPortableAcceptanceImportRightsValidationPublishAndSnapshot", "TestPortableAcceptanceLostPOSTVerdictsAndReorderedEvents", "TestPortableAcceptanceFrozenVersionWithdrawalAndFreshFenceRecovery", "TestPortableAcceptanceCallbackFaultsRestartAndReconciliation", "TestPortableAcceptanceFinalTransactionFailureRetainsRecoverableTask"], "sourceSHA256": {str(path.relative_to(ROOT)): file_sha(path) for path in sorted((ROOT / "cmd/judge-service").glob("acceptance*_test.go"))}}
    try:
        signal.alarm(60 * 60)
        image = json.loads(QUALIFY.run(prefix, ["image", "inspect", args.image]).stdout)[0]
        require(image.get("Os") == "linux" and image.get("Architecture") == "amd64" and args.image in image.get("RepoDigests", []), "actual_image_identity_invalid")
        report["imageID"] = image["Id"]
        daemon = json.loads(QUALIFY.run(prefix, ["info", "--format", "{{json .}}"]).stdout)
        require(daemon.get("CgroupVersion") == "2" and daemon.get("MemTotal", 0) >= 15 << 30 and daemon.get("NCPU", 0) >= 4, "qualification_daemon_capacity_insufficient")
        network = json.loads(QUALIFY.run(prefix, ["network", "inspect", NETWORK]).stdout)[0]
        gateway = network["IPAM"]["Config"][0]["Gateway"]
        require(ipaddress.ip_address(gateway).is_private, "private_fixture_gateway_required")
        extraction = "startrack-flow-extract-" + secrets.token_hex(8)
        QUALIFY.run(prefix, ["create", "--name", extraction, "--entrypoint", "/bin/true", args.image])
        for name in ("context-inventory.json", "binaries.sha256"):
            QUALIFY.run(prefix, ["cp", extraction + ":/opt/startrack/provenance/" + name, str(private / name)])
        inventory = QUALIFY.regular_json(private / "context-inventory.json", 32 << 20)
        require(inventory.get("gitHead") == args.expected_commit and inventory.get("sourceState") == "CLEAN" and inventory.get("releaseCommit") == args.expected_commit and not inventory.get("workingTreeStatus"), "clean_image_source_required")
        binaries = {name: checksum for checksum, name in (line.split(None, 1) for line in (private / "binaries.sha256").read_text().splitlines())}
        for name in ("startrack-v02.apparmor", "startrack-v02.seccomp.json", "startrack-workload-seccomp.yaml", "workload-security-profile.lock.json"):
            QUALIFY.run(prefix, ["cp", extraction + ":/opt/startrack/" + name, str(private / name)])
            require((private / name).read_bytes() == (ROOT / "docker" / name).read_bytes(), "image_security_profile_mismatch")
        CAPACITY.host(["apparmor_parser", "--replace", str(ROOT / "docker/startrack-v02.apparmor")])
        backing = private / "continuation.ext4"
        shutil.copyfile(original, backing)
        backing.chmod(0o600)
        require(file_sha(original) == file_sha(backing), "private_facility_copy_mismatch")
        report["capacityPrivateFacilitySha256"] = file_sha(original)
        device = CAPACITY.host(["losetup", "--find", "--show", "--nooverlap", str(backing)])
        require(re.fullmatch(r"/dev/loop[0-9]+", device), "private_facility_device_invalid")
        mounted = private / "storage"
        mounted.mkdir(mode=0o755)
        CAPACITY.host(["mount", "-t", "ext4", "-o", "nosuid,nodev,noexec", device, str(mounted)])
        require(os.path.ismount(mounted), "private_facility_mount_failed")
        secret_dir = private / "secrets"
        secret_dir.mkdir(mode=0o700)
        for name in ("backend-judge-token", "judge-backend-token", "runtime-token", "scheduler-token", "catalog-cursor-key"):
            CAPACITY.secret_file(secret_dir / name, secrets.token_hex(32))
        CAPACITY.secret_file(secret_dir / "database-url", dsn)
        receiver = FixtureReceiver((secret_dir / "judge-backend-token").read_text())
        receiver_server = ThreadingHTTPServer((gateway, 8081), receiver.handler())
        receiver_server.daemon_threads = True
        receiver_thread = threading.Thread(target=receiver_server.serve_forever, daemon=True)
        receiver_thread.start()
        db = Database(prefix, dsn, ca, clients)
        scope = db.scope()
        require(scope.get("runtimeRole") is True and scope.get("tls") is True and scope.get("database") == database[1:] and scope.get("tasks") == 0 and scope.get("results") == 0 and scope.get("outbox") == 0 and scope.get("published") == 0 and scope.get("versions") == 2 and scope.get("imports") == 6, "capacity_database_continuation_scope_invalid")
        lifecycle = Lifecycle(prefix, args.image, digest, ca, mounted, secret_dir, gateway, binaries, private)
        service = lifecycle.start()
        detail = service.accepted("GET", "/internal/v2/problems/" + seed["problemId"] + "/versions/" + seed["problemVersionId"])
        require(detail.get("status") == "DRAFT" and detail.get("problemRef", {}).get("problemVersionId") == seed["problemVersionId"], "normal_draft_detail_invalid")
        publication = {"requestId": str(uuid.uuid4()), "problemVersionId": seed["problemVersionId"]}
        published = service.accepted("POST", "/internal/v2/problems/" + seed["problemId"] + "/publish", publication)
        problem_ref = published.get("problemRef")
        require(published.get("status") == "PUBLISHED" and problem_ref == detail["problemRef"] and set(problem_ref) == {"source", "platform", "problemId", "problemVersionId"} and problem_ref.get("source") == "PLATFORM" and problem_ref.get("platform") == "startrack" and problem_ref.get("problemId") == seed["problemId"] and problem_ref.get("problemVersionId") == seed["problemVersionId"], "normal_publication_reference_invalid")
        snapshot = service.accepted("GET", "/internal/v2/catalog-snapshots?limit=10")
        require(len(snapshot.get("items", [])) == 1, "published_catalog_snapshot_invalid")
        report["publication"] = {"problemId": seed["problemId"], "problemVersionId": seed["problemVersionId"], "requestId": publication["requestId"], "approvedLicenseEvidenceId": seed["approvedLicenseEvidenceId"], "snapshotId": snapshot["snapshotId"], "normalHTTP": True}
        base_submission = 700000000000000000 + secrets.randbelow(1000000) * 100
        for index, (name, expected, source) in enumerate(FIXTURES):
            original_request = request(problem_ref, source, base_submission + index)
            receiver.expect(original_request)
            if name == "AC":
                receiver.drop_once.add(original_request["requestId"])
            if name == "WA":
                receiver.invalid_once.add(original_request["requestId"])
            accepted = service.accepted("POST", "/internal/v2/judge-tasks", original_request, (202,))
            final = service.wait(accepted["judgeTaskId"], lambda task: task.get("status") in ("COMPLETED", "FAILED"), timeout=180)
            facts = all_delivered(db, receiver, final["judgeTaskId"])
            assert_event_sequence(facts, 0)
            require(facts.get("attempt") == 0, "normal_task_unexpected_recovery")
            assert_frozen(facts, original_request, digest)
            replay_checks(service, original_request, final["judgeTaskId"])
            lifecycle.spool_empty()
            record = assert_terminal(final, facts, expected)
            record.update({"name": name, "sourceSha256": original_request["sourceSha256"], "frozenInputSha256": hashlib.sha256(canonical_fixture(facts["frozen"])).hexdigest(), "callbackEvents": len(facts["events"]), "allEventsDelivered": True, "normalRequestReplay": True, "judgerSpoolEmpty": True})
            if name == "AC":
                require(original_request["requestId"] in receiver.dropped and any(event["terminal"] and event["attempts"] >= 2 for event in facts["events"]), "lost_ack_durable_retry_missing")
                record["lostAckSameEventRetried"] = True
                completed_request, completed_id = original_request, final["judgeTaskId"]
            if name == "WA":
                require(original_request["requestId"] in receiver.invalidated and any(event["terminal"] and event["attempts"] >= 2 for event in facts["events"]), "invalid_ack_durable_retry_missing")
                record["invalidAckSameEventRetried"] = True
            report["cases"].append(record)
        concurrency(service, lifecycle, db, receiver, problem_ref, base_submission + 30, report)
        service = recovery(service, lifecycle, db, receiver, problem_ref, base_submission + 20, 1, report)
        service = recovery(service, lifecycle, db, receiver, problem_ref, base_submission + 21, 4, report)
        withdraw = {"requestId": str(uuid.uuid4()), "reason": "Authored disposable service-flow qualification"}
        withdrawn = service.accepted("POST", "/internal/v2/problems/" + seed["problemId"] + "/withdraw", withdraw)
        require(withdrawn.get("status") == "WITHDRAWN", "normal_withdrawal_failed")
        rejected = request(problem_ref, SUM, base_submission + 40)
        status, rejection = service.call("POST", "/internal/v2/judge-tasks", rejected["requestId"], rejected)
        require(status == 409 and rejection.get("error", {}).get("code") == "PROBLEM_NOT_SUBMITTABLE", "withdrawn_fresh_admission_not_rejected")
        history = service.accepted("GET", "/internal/v2/problems/" + seed["problemId"] + "/versions/" + seed["problemVersionId"])
        require(history.get("problemRef") == problem_ref and all(history.get(field) == detail.get(field) for field in ("statement", "samples", "license")), "withdrawal_changed_historical_content")
        replay_checks(service, completed_request, completed_id)
        continuation_publish = {"requestId": str(uuid.uuid4()), "problemVersionId": seed["problemVersionId"]}
        continuation = service.accepted("POST", "/internal/v2/problems/" + seed["problemId"] + "/publish", continuation_publish)
        require(continuation.get("status") == "PUBLISHED" and continuation.get("problemRef") == problem_ref, "normal_continuation_republication_failed")
        report["withdrawal"] = {"freshAdmissionRejected": True, "noRemoteTaskCreated": True, "historicalContentPreserved": True, "acceptedRequestReplayPreserved": True, "normallyRepublishedForContinuation": True}
        final_scope = db.scope()
        require(final_scope.get("tasks") == 13 and final_scope.get("results") == 13 and final_scope.get("outbox") == 60 and final_scope.get("active") == 0 and final_scope.get("published") == 1 and final_scope.get("imports") == scope["imports"] and final_scope.get("versions") == scope["versions"] and receiver.failures == 0, "final_service_flow_scope_invalid")
        lifecycle.finish_memory("COMPLETED_FIXED_THIRTEEN_TASK_LOAD")
        require(len(lifecycle.starts) == 6 and all(start.get("serviceMemory", {}).get("passed") is True for start in lifecycle.starts), "normal_service_memory_generations_incomplete")
        report.update({"serviceFlowPassed": True, "serviceProcessMemoryPassed": True, "failureCode": "", "normalStarts": lifecycle.starts, "mockCallbacks": {"scope": "FIXED_SYNTHETIC_ACK_ONLY", "correlation": "CURRENT_JUDGE_ECHO_PROFILE_Q010_EXTERNALLY_PENDING", "validatedEvents": len(receiver.events), "duplicates": receiver.duplicates, "validationFailures": receiver.failures}, "databaseFacts": {"tasks": 13, "results": 13, "outboxEvents": 60, "runtimeRole": True, "verifyFullTLS": True}})
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, json.JSONDecodeError, http.client.HTTPException, subprocess.SubprocessError) as error:
        report["failureCode"] = str(error) if isinstance(error, ValueError) and re.fullmatch(r"[a-z0-9_]+", str(error)) else type(error).__name__
    finally:
        cleanup_signals()
        cleanup = True
        if lifecycle is not None:
            report["normalStarts"] = lifecycle.starts
            if lifecycle.memory is not None:
                try:
                    lifecycle.memory.close()
                except (ValueError, OSError):
                    cleanup = False
        if receiver_server is not None:
            receiver_server.shutdown()
            receiver_server.server_close()
        containers = (lifecycle.containers if lifecycle else []) + clients + ([extraction] if extraction else [])
        for name in reversed(containers):
            try:
                removed = remove_container(prefix, name)
                cleanup = cleanup and removed
            except (ValueError, OSError, subprocess.SubprocessError):
                cleanup = False
        if mounted is not None and os.path.ismount(mounted):
            try:
                CAPACITY.host(["umount", str(mounted)])
            except (ValueError, OSError, subprocess.SubprocessError):
                cleanup = False
        if device is not None:
            try:
                require(mounted is None or not os.path.ismount(mounted), "private_facility_still_mounted")
                CAPACITY.host(["losetup", "--detach", device])
            except (ValueError, OSError, subprocess.SubprocessError):
                cleanup = False
        report["cleanupPassed"] = cleanup
        if not cleanup:
            report.update({"serviceFlowPassed": False, "failureCode": "service_flow_cleanup_failed"})
        public = json.dumps(report, indent=2).encode() + b"\n"
        require(len(public) <= 65536 and PRIVATE_CANARY.encode() not in public and dsn.encode() not in public, "service_flow_report_invalid")
        (evidence / "service-flow.json").write_bytes(public)
        (evidence / "service-flow.json").chmod(0o644)
    print("Linux persistent synthetic service flow " + ("passed; external acceptance pending" if report["serviceFlowPassed"] else "failed: " + report["failureCode"]))
    return 0 if report["serviceFlowPassed"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, subprocess.SubprocessError):
        print("Linux persistent synthetic service flow failed: fixture_prerequisite_invalid")
        raise SystemExit(1)
