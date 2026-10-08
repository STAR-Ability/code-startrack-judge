"""Portable refusal/receipt tests; these do not execute or qualify a sandbox."""

import copy
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from urllib.parse import quote
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("linux_service_flow", ROOT / "scripts/qualify-linux-service-flow.py")
FLOW = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FLOW)
REQUEST = "00000000-0000-4000-8000-000000000001"
TASK = "00000000-0000-4000-8000-000000000002"
EVENT = "00000000-0000-4000-8000-000000000003"
VERSION = "00000000-0000-4000-8000-000000000004"
IMAGE = "startrack-qualified-candidate@sha256:" + "a" * 64
COMMIT = "b" * 40


def task(verdict=None):
    result = None
    if verdict is not None:
        result = {"verdict": verdict, "timeMs": 2 if verdict not in ("CE", "IE") else None, "memoryBytes": 4096 if verdict not in ("CE", "IE") else None, "passedTestCount": 2 if verdict == "AC" else 0, "totalTestCount": 2, "score": None, "compileLog": "Compilation failed" if verdict == "CE" else None, "diagnosticCode": "JUDGE_INTERRUPTED" if verdict == "IE" else None, "judgedAt": "2026-10-08T00:00:00Z"}
    return {"requestId": REQUEST, "revision": 4, "status": "FAILED" if verdict == "IE" else "COMPLETED" if verdict else "RUNNING", "error": {"code": "JUDGE_INTERRUPTED", "message": "Controlled execution failed", "retryable": False} if verdict == "IE" else None, "createdAt": "2026-10-08T00:00:00Z", "updatedAt": "2026-10-08T00:00:00Z", "finishedAt": "2026-10-08T00:00:00Z" if verdict else None, "judgeTaskId": TASK, "submissionId": "7", "result": result}


def event(payload=None):
    payload = payload or task("AC")
    return {"eventId": EVENT, "eventType": "JUDGE_TASK_UPDATED", "occurredAt": "2026-10-08T00:00:00Z", "requestId": REQUEST, "aggregateId": TASK, "revision": payload["revision"], "payload": payload}


def facts(public):
    verdict = public["result"]["verdict"]
    cases = []
    for ordinal in (1, 2):
        observed = "AC" if verdict == "AC" else verdict if ordinal == 1 and verdict not in ("CE", "IE") else "SKIPPED"
        cases.append({"ordinal": ordinal, "verdict": observed, "cpu": 2 if observed != "SKIPPED" else None, "wall": 3 if observed != "SKIPPED" else None, "memory": 4096 if observed != "SKIPPED" else None})
    return {"taskId": TASK, "revision": public["revision"], "sameResultCaseTransaction": True, "cases": cases, "result": {"verdict": verdict, "result_hash": hashlib.sha256(FLOW.canonical_fixture(public["result"])).hexdigest()}, "events": [{"revision": public["revision"], "terminal": True, "payload": public}]}


def capacity():
    cases = [{"name": name} for name in ("MEMBER_PAYLOAD", "SAMPLE_SUPPORTED", "SAMPLE_HEAVY")]
    cases[0].update({"status": "SUCCEEDED", "checkpointsPassed": 5, "noPublication": True, "detailHTTPStatus": 200, "approvedLicenseEvidenceId": EVENT, "problemId": "7", "problemVersionId": VERSION})
    return {"scope": "DISPOSABLE_SYNTHETIC_API_IMPORT_CAPACITY", "syntheticFixture": True, "capacityPassed": True, "cleanupPassed": True, "privateFacilityRetained": True, "sourceCommit": COMMIT, "imageReference": IMAGE, "phases": [{"executionPassed": True, "outcome": {"phase": "reject", "passed": True}}, {"executionPassed": True, "outcome": {"phase": "validate", "passed": True, "cases": cases}}]}


def boundary():
    return {"version": 1, "imageDigest": IMAGE.split("@")[1], "bootId": VERSION, "measuredAt": "2026-10-08T00:00:00Z", "observations": [{"role": role, "uid": uid, "pid": pid, "startTicks": 123, "controlMem": "allowed", "controlVMRead": "permission_denied", "controlPtrace": "allowed", "denied": True} for role, uid, pid in (("api", 20000, 25), ("judger", 20001, 26))]}


def worker_snapshot():
    return {"databaseNow": "2026-10-08T00:00:00+00:00", "active": 2, "tasks": [
        {"taskId": TASK, "status": "RUNNING", "lease": REQUEST, "leaseExpiresAt": "2026-10-08T00:03:00+00:00"},
        {"taskId": EVENT, "status": "RUNNING", "lease": VERSION, "leaseExpiresAt": "2026-10-08T00:03:00+00:00"},
        {"taskId": VERSION, "status": "QUEUED", "lease": None, "leaseExpiresAt": None},
    ]}


STATUS = "Uid:\t20000\t20000\t20000\t20000\nGid:\t20000\t20000\t20000\t20000\nGroups:\t20002\nCapEff:\t0000000000000000\nCapPrm:\t0000000000000000\nCapInh:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\nNSpid:\t1025\t25\nVmRSS:\t80 kB\nVmHWM:\t100 kB\nVmSwap:\t0 kB\n"
STAT = "1025 (judge-service) S " + "0 " * 18 + "123 0\n"
EVENTS = "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom_group_kill 0\n"


class LinuxServiceFlowTests(unittest.TestCase):
    def test_graceful_exit_requires_clean_wait_and_both_records_revoked(self):
        state = {"Running": False, "Status": "exited", "ExitCode": 0, "Pid": 0, "OOMKilled": False}
        with tempfile.TemporaryDirectory() as temporary:
            measurement = Path(temporary) / "runtime-measurement.json"
            FLOW.require_graceful_exit(state, measurement)
            for key, value in (("Running", True), ("Status", "dead"), ("ExitCode", 137), ("ExitCode", False),
                               ("Pid", False), ("Pid", 1), ("OOMKilled", True), ("OOMKilled", None)):
                with self.subTest(key=key, value=value), self.assertRaisesRegex(ValueError, "graceful_container_exit_invalid"):
                    FLOW.require_graceful_exit(dict(state, **{key: value}), measurement)
            for path in (measurement, Path(str(measurement) + ".tmp")):
                for symlink in (False, True):
                    path.symlink_to(Path(temporary) / "absent") if symlink else path.write_text("{}")
                    with self.subTest(path=path.name, symlink=symlink), self.assertRaisesRegex(ValueError, "graceful_qualification_not_revoked"):
                        FLOW.require_graceful_exit(state, measurement)
                    path.unlink()

    def test_graceful_stop_keeps_original_witness_and_rejects_failed_settlement(self):
        for outcome in ("clean", "forced", "retained", "role_missing", "contestant_changed", "stop_error"):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as temporary:
                lifecycle = FLOW.Lifecycle.__new__(FLOW.Lifecycle)
                lifecycle.prefix, lifecycle.active = ["docker", "--context", "default"], "startrack-flow-fixture"
                lifecycle.evidence, lifecycle.digest = Path(temporary), IMAGE.split("@")[1]
                lifecycle.containers, lifecycle.starts = [lifecycle.active], [{}]
                measurement = {"identity": {"workerImageDigest": lifecycle.digest}, "bootId": VERSION,
                               "checks": {key: True for key in FLOW.QUALIFY.REQUIRED_CHECKS}}
                descriptor = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY)
                witness = {"descriptor": descriptor, "processes": {1001: "123", 1002: "456", 1003: "789"}}
                if outcome == "role_missing":
                    witness["processes"].pop(1002)
                observed = []

                def observe():
                    observed.append(True)
                    return {1003: "different" if outcome == "contestant_changed" else "789"}

                def capture(*_):
                    self.assertEqual(observed, [True], "native execution must be observed before capturing cleanup generations")
                    return witness

                def finish(reason):
                    self.assertEqual(reason, "BEFORE_AUTHORED_GRACEFUL_STOP")
                    lifecycle.starts[-1]["serviceMemory"] = {"roles": [{"role": "api", "hostPID": 1001, "startTicks": 123},
                                                                         {"role": "judger", "hostPID": 1002, "startTicks": 456}]}

                state = {"Running": False, "Status": "exited", "ExitCode": 137 if outcome == "forced" else 0, "Pid": 0, "OOMKilled": False}

                def docker(_prefix, arguments, **options):
                    if arguments[0] == "stop":
                        self.assertEqual(arguments, ["stop", "--signal", "SIGTERM", "--timeout", "120", lifecycle.active])
                        self.assertEqual(options["timeout"], 150)
                        if outcome == "stop_error":
                            raise subprocess.TimeoutExpired("synthetic-stop", 150)
                        return SimpleNamespace(stdout="")
                    self.assertEqual(arguments[0], "inspect")
                    return SimpleNamespace(stdout=json.dumps(state))

                with patch.object(lifecycle, "finish_memory", side_effect=finish), \
                        patch.object(FLOW.QUALIFY, "regular_json", return_value=measurement), \
                        patch.object(FLOW.QUALIFY, "capture_execution_drain", side_effect=capture), \
                        patch.object(FLOW.QUALIFY, "execution_drained", return_value=outcome != "retained"), \
                        patch.object(FLOW.QUALIFY, "run", side_effect=docker), \
                        patch.object(Path, "read_text", return_value=VERSION), \
                        patch.object(FLOW.time, "monotonic", side_effect=[0, 1, 2, 20] if outcome == "retained" else [0, 1, 2, 3]):
                    if outcome == "clean":
                        receipt = lifecycle.graceful_stop(observe)
                        self.assertTrue(receipt["passed"])
                        self.assertEqual(receipt["scope"], "LIVE_NORMAL_SERVICE_TASK_DRAIN")
                        self.assertEqual(receipt["stableContestantProcessesBeforeTERM"], 1)
                        self.assertFalse(receipt["inFlightQualificationProbeWitnessed"])
                    else:
                        with self.assertRaises((ValueError, subprocess.TimeoutExpired)):
                            lifecycle.graceful_stop(observe)
                        self.assertNotIn("gracefulShutdown", lifecycle.starts[-1])
                with self.assertRaises(OSError):
                    os.fstat(descriptor)

    def live_drain_fixture(self, completed, failure=None):
        original = FLOW.request({"problemId": "7", "problemVersionId": VERSION}, FLOW.SLEEP_SUM, 7)
        original["requestId"] = REQUEST
        frozen = {"limits": {"cpuTimeNS": 2_000_000_000, "wallTimeNS": 4_000_000_000, "memoryBytes": 256 << 20,
                              "outputBytes": 8 << 20, "processes": 32}, "sourceSizeBytes": len(original["sourceCode"].encode()),
                  "sourceFilename": "main.cpp", "identity": {"workerImageDigest": IMAGE.split("@")[1]}}
        running = {"taskId": TASK, "versionId": VERSION, "problemId": "7", "sourceHash": original["sourceSha256"],
                   "frozen": frozen, "image": IMAGE.split("@")[1], "startedAt": "2026-10-08T00:00:00Z",
                   "sourceRetained": True, "status": "RUNNING", "revision": 3, "attempt": 0, "lease": EVENT,
                   "result": None, "cases": [], "databaseNow": "2026-10-08T00:00:00+00:00",
                   "leaseExpiresAt": "2026-10-08T00:03:00+00:00"}
        states = ["QUEUED", "DISPATCHING", "RUNNING"] + ([] if completed else ["DISPATCHING", "RUNNING"]) + ["COMPLETED"]
        public = task("AC")
        public["revision"] = len(states)
        final = dict(running, **facts(public), status="COMPLETED", attempt=0 if completed else 1, lease=None)
        final["events"] = [{"eventId": "00000000-0000-4000-8000-%012x" % revision, "revision": revision,
                             "hash": "%064x" % revision, "status": "DELIVERED",
                             "terminal": status == "COMPLETED", "payload": public if status == "COMPLETED" else {"status": status}}
                            for revision, status in enumerate(states, 1)]
        after = copy.deepcopy(final if completed else running)
        if not completed:
            after["leaseExpiresAt"] = "2026-10-08T00:03:30+00:00"
            after["events"] = copy.deepcopy(final["events"][:3])
        after["events"][-1]["status"] = "PENDING"
        recovered = dict(running, attempt=1, revision=5, lease=VERSION,
                         databaseNow="2026-10-08T00:03:30+00:00")
        if failure == "clock":
            recovered["databaseNow"] = "2026-10-08T00:03:29+00:00"
        elif failure == "fence":
            recovered["lease"] = EVENT
        live = copy.deepcopy(running)
        if failure == "expired":
            live["databaseNow"] = live["leaseExpiresAt"]
        snapshots = [running, live, after] + ([] if completed else [recovered])
        return original, public, final, snapshots

    def test_live_drain_preserves_completed_or_naturally_recovered_task_and_events(self):
        for completed, failure in ((True, None), (False, None), (False, "clock"), (False, "fence"), (False, "expired")):
            with self.subTest(completed=completed, failure=failure):
                original, public, final, snapshots = self.live_drain_fixture(completed, failure)
                service, lifecycle, database, receiver = (unittest.mock.Mock() for _ in range(4))
                lifecycle.digest = IMAGE.split("@")[1]
                lifecycle.executing.side_effect = lambda identities=False: {1003: "789"} if identities else 1
                lifecycle.start.return_value = service
                lifecycle.graceful_stop.side_effect = lambda observer: {"passed": True, "stableContestantProcessesBeforeTERM": len(observer())}
                service.accepted.return_value = {"judgeTaskId": TASK}
                service.wait.return_value = public
                database.task.side_effect = snapshots
                report = {"cases": []}
                with patch.object(FLOW, "request", return_value=original), \
                        patch.object(FLOW, "all_delivered", return_value=final), \
                        patch.object(FLOW, "replay_checks") as replay:
                    if failure is not None:
                        with self.assertRaisesRegex(ValueError, "graceful_task_lease_not_live" if failure == "expired" else "graceful_recovery_fence_or_clock_invalid"):
                            FLOW.graceful_live_drain(service, lifecycle, database, receiver, {}, 7, report)
                        self.assertEqual(report["cases"], [])
                        replay.assert_not_called()
                    else:
                        restarted, count = FLOW.graceful_live_drain(service, lifecycle, database, receiver, {}, 7, report)
                        self.assertIs(restarted, service)
                        self.assertEqual(count, 64 if completed else 66)
                        self.assertEqual(report["cases"][0]["recoveryCount"], 0 if completed else 1)
                        self.assertTrue(report["gracefulShutdown"]["pendingEventsObserved"])
                        self.assertTrue(report["gracefulShutdown"]["retainedEventIdentitiesDeliveredAfterRestart"])
                        self.assertEqual(report["gracefulShutdown"]["sameTaskRecoveredAfterNaturalLeaseExpiry"], not completed)
                        replay.assert_called_once_with(service, original, TASK)

    def launcher_arguments(self, context, image):
        return ["qualify-linux-service-flow.py", "--image", image, "--expected-commit", COMMIT,
                "--docker-context", context, "--capacity-evidence", "/synthetic/capacity",
                "--runtime-dsn-file", "/synthetic/runtime.dsn", "--database-ca-file", "/synthetic/ca.crt",
                "--evidence", "/synthetic/evidence"]

    def test_supported_contexts_keep_dirty_source_refusal_before_credentials_or_docker(self):
        official = FLOW.QUALIFY.OFFICIAL + "@sha256:" + "a" * 64
        for context, image in (("default", official), ("colima-startrack-v02", official),
                               ("colima-startrack-v02", IMAGE)):
            with self.subTest(context=context, image=image), \
                    patch.object(sys, "argv", self.launcher_arguments(context, image)), \
                    patch.object(FLOW.platform, "system", return_value="Linux"), \
                    patch.object(FLOW.platform, "machine", return_value="amd64"), \
                    patch.object(FLOW.os, "geteuid", return_value=0), \
                    patch.object(FLOW.signal, "signal"), \
                    patch.object(FLOW.CAPACITY, "host", side_effect=[COMMIT, " M synthetic-file"]), \
                    patch.object(FLOW.CAPACITY, "trusted_dsn") as credentials, \
                    patch.object(FLOW.QUALIFY, "run") as docker:
                with self.assertRaisesRegex(ValueError, "^clean_host_source_required$"):
                    FLOW.main()
                credentials.assert_not_called()
                docker.assert_not_called()

    def test_default_context_refuses_diagnostic_image_before_host_or_docker_access(self):
        with patch.object(sys, "argv", self.launcher_arguments("default", IMAGE)), \
                patch.object(FLOW.platform, "system", return_value="Linux"), \
                patch.object(FLOW.platform, "machine", return_value="amd64"), \
                patch.object(FLOW.os, "geteuid", return_value=0), \
                patch.object(FLOW.signal, "signal"), \
                patch.object(FLOW.CAPACITY, "host") as host, \
                patch.object(FLOW.QUALIFY, "run") as docker:
            with self.assertRaisesRegex(ValueError, "^image_repository_not_allowed$"):
                FLOW.main()
            host.assert_not_called()
            docker.assert_not_called()

    def test_arbitrary_docker_context_is_refused_before_any_host_action(self):
        with patch.object(sys, "argv", self.launcher_arguments("production", IMAGE)), \
                patch.object(FLOW.CAPACITY, "host") as host, \
                patch.object(FLOW.QUALIFY, "run") as docker, contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as refused:
                FLOW.main()
            self.assertEqual(refused.exception.code, 2)
            host.assert_not_called()
            docker.assert_not_called()

    def receiver(self):
        receiver = FLOW.FixtureReceiver("synthetic-fixed-outbound-token")
        receiver.expect({"requestId": REQUEST, "submissionId": "7"})
        return receiver, {"Authorization": "Bearer " + receiver.token, "X-Request-Id": REQUEST}

    def test_actual_callback_shape_is_accepted_and_invented_fields_refused(self):
        receiver, headers = self.receiver()
        ack, mode = receiver.receive(headers, FLOW.canonical_fixture(event()))
        self.assertEqual(ack, {"data": {"accepted": True, "duplicate": False}, "requestId": REQUEST})
        self.assertEqual(mode, "normal")
        for field in ("aggregateType", "contractVersion", "hiddenAnswer", "sourceCode"):
            altered = event()
            altered[field] = "forbidden"
            with self.subTest(field=field), self.assertRaises(ValueError):
                receiver.receive(headers, FLOW.canonical_fixture(altered))

    def test_callback_auth_envelope_payload_and_duplicate_conflicts_fail(self):
        receiver, headers = self.receiver()
        receiver.receive(headers, FLOW.canonical_fixture(event()))
        mutations = (
            lambda value: value.update(requestId=VERSION),
            lambda value: value.update(aggregateId=VERSION),
            lambda value: value["payload"].update(submissionId="8"),
            lambda value: value["payload"].update(revision=9),
            lambda value: value["payload"].update(sourceCode="forbidden"),
            lambda value: value["payload"]["result"].update(compileLog="different same event"),
        )
        for mutate in mutations:
            altered = event()
            mutate(altered)
            with self.subTest(mutation=mutations.index(mutate)), self.assertRaises(ValueError):
                receiver.receive(headers, FLOW.canonical_fixture(altered))
        with self.assertRaises(ValueError):
            receiver.receive({**headers, "Authorization": "Bearer wrong"}, FLOW.canonical_fixture(event()))

    def test_lost_and_invalid_ack_keep_exact_event_hash_and_duplicate_identity(self):
        for failure in ("drop", "invalid"):
            receiver, headers = self.receiver()
            getattr(receiver, "drop_once" if failure == "drop" else "invalid_once").add(REQUEST)
            raw = FLOW.canonical_fixture(event())
            initial, mode = receiver.receive(headers, raw)
            self.assertEqual(mode, failure)
            if failure == "invalid":
                self.assertNotEqual(initial["requestId"], REQUEST)
            retry, mode = receiver.receive(headers, raw)
            self.assertEqual(mode, "normal")
            self.assertTrue(retry["data"]["duplicate"])
            self.assertEqual(retry["requestId"], REQUEST)
            self.assertEqual(receiver.events[EVENT]["hash"], hashlib.sha256(raw).hexdigest())
            self.assertEqual(receiver.failures, 0)

    def test_public_json_bounds_utf8_duplicate_and_private_canary_refusals(self):
        invalid = (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":"\xff"}', b'"' + FLOW.PRIVATE_CANARY.encode() + b'"')
        for index, raw in enumerate(invalid):
            with self.subTest(case=index), self.assertRaises((ValueError, UnicodeError)):
                FLOW.strict_json(raw)
        with self.assertRaises(ValueError):
            FLOW.strict_json(b"{}", 1)
        for invalid in (1.0, 1 << 53, {"nonascii\u00e9": 1}):
            with self.assertRaises(ValueError):
                FLOW.canonical_fixture(invalid)

    def test_supported_seed_requires_success_clean_phase_and_publication_separation(self):
        self.assertEqual(FLOW.capacity_seed(capacity(), IMAGE, COMMIT)["problemVersionId"], VERSION)
        alterations = (
            lambda value: value.update(cleanupPassed=False),
            lambda value: value.update(privateFacilityRetained=False),
            lambda value: value.update(imageReference=IMAGE + "0"),
            lambda value: value["phases"][1]["outcome"]["cases"][0].update(name="SAMPLE_HEAVY"),
            lambda value: value["phases"][1]["outcome"]["cases"][0].update(noPublication=False),
            lambda value: value["phases"][1]["outcome"]["cases"][0].update(checkpointsPassed=4),
            lambda value: value["phases"][1]["outcome"]["cases"][0].update(approvedLicenseEvidenceId=""),
        )
        for index, alter in enumerate(alterations):
            changed = capacity()
            alter(changed)
            with self.subTest(case=index), self.assertRaises(ValueError):
                FLOW.capacity_seed(changed, IMAGE, COMMIT)

    def test_all_verdict_receipts_require_real_coherent_terminal_facts(self):
        for verdict in ("AC", "WA", "CE", "TLE", "MLE", "OLE", "RE", "IE"):
            public = task(verdict)
            self.assertEqual(FLOW.assert_terminal(public, facts(public), verdict)["verdict"], verdict)
        public = task("AC")
        changes = (
            lambda value: value.update(sameResultCaseTransaction=False),
            lambda value: value["result"].update(result_hash="a" * 64),
            lambda value: value["cases"].pop(),
            lambda value: value["cases"][1].update(ordinal=3),
            lambda value: value["cases"][0].update(cpu=4),
            lambda value: value["events"][0].update(payload=task("WA")),
        )
        for index, alter in enumerate(changes):
            changed = facts(public)
            alter(changed)
            with self.subTest(case=index), self.assertRaises(ValueError):
                FLOW.assert_terminal(public, changed, "AC")

    def test_recovery_events_require_initial_plus_three_and_no_fifth_dispatch(self):
        statuses = ["QUEUED", "DISPATCHING", "RUNNING", "DISPATCHING", "RUNNING", "DISPATCHING", "RUNNING", "DISPATCHING", "RUNNING", "FAILED"]
        value = {"events": [{"revision": index + 1, "payload": {"status": status}} for index, status in enumerate(statuses)]}
        FLOW.assert_event_sequence(value, 4)
        for altered in (value["events"][:-1], value["events"] + [{"revision": 11, "payload": {"status": "DISPATCHING"}}]):
            with self.assertRaises(ValueError):
                FLOW.assert_event_sequence({"events": altered}, 4)
        changed = copy.deepcopy(value)
        changed["events"][4]["revision"] = 8
        with self.assertRaises(ValueError):
            FLOW.assert_event_sequence(changed, 4)

    def test_database_mutations_and_identity_injection_never_reach_docker(self):
        database = FLOW.Database(["docker"], "synthetic-not-real", Path("synthetic-ca"), [])
        with patch.object(FLOW.QUALIFY, "run") as run:
            for sql in ("UPDATE judge.judge_tasks SET status='FAILED'", "SELECT 1; DELETE FROM judge.judge_tasks", "DROP TABLE judge.judge_tasks"):
                with self.assertRaises(ValueError):
                    database.query(sql)
            with self.assertRaises(ValueError):
                database.task(TASK + "' OR true")
            for identifiers in ([TASK, EVENT, TASK], [TASK, EVENT], [TASK, EVENT, VERSION + "' OR true"],
                                [TASK, EVENT, None], TASK):
                with self.subTest(identifiers=identifiers), self.assertRaises(ValueError):
                    database.concurrency_snapshot(identifiers)
            run.assert_not_called()

    def test_concurrency_query_reads_exact_tasks_and_clock_in_one_statement(self):
        database = FLOW.Database([], "synthetic-not-real", Path("synthetic-ca"), [])
        snapshots, queries = worker_snapshot(), []

        def query(sql):
            queries.append(sql)
            return snapshots

        with patch.object(database, "query", side_effect=query):
            self.assertIs(database.concurrency_snapshot([VERSION, TASK, EVENT]), snapshots)
        self.assertEqual(len(queries), 1)
        self.assertTrue(queries[0].startswith("SELECT "))
        self.assertNotIn(";", queries[0])
        self.assertEqual(queries[0].count("statement_timestamp()"), 1)
        for identifier in (TASK, EVENT, VERSION):
            self.assertEqual(queries[0].count("'" + identifier + "'"), 1)

    def test_concurrency_witness_requires_coexisting_states_and_live_exact_fences(self):
        identifiers = [TASK, EVENT, VERSION]
        self.assertTrue(FLOW.concurrent_worker_witness(worker_snapshot(), identifiers))
        pending = worker_snapshot()
        pending["tasks"][1]["status"] = "DISPATCHING"
        self.assertFalse(FLOW.concurrent_worker_witness(pending, identifiers))
        changes = (
            lambda value: value["tasks"].pop(),
            lambda value: value["tasks"][2].update(taskId=REQUEST),
            lambda value: value["tasks"][2].update(taskId=TASK),
            lambda value: value["tasks"][0].update(lease=None),
            lambda value: value["tasks"][1].update(lease=REQUEST),
            lambda value: value["tasks"][0].update(leaseExpiresAt="2026-10-08T00:00:00+00:00"),
            lambda value: value["tasks"][0].update(leaseExpiresAt="2026-10-07T23:59:59+00:00"),
            lambda value: value["tasks"][0].update(leaseExpiresAt="2026-10-08T00:03:00"),
            lambda value: value["tasks"][2].update(lease=REQUEST),
            lambda value: value["tasks"][2].pop("leaseExpiresAt"),
            lambda value: value.update(databaseNow="2026-10-08T00:00:00"),
            lambda value: value.update(databaseNow="invalid"),
            lambda value: value.update(active=1),
            lambda value: value.update(active=3),
            lambda value: value.update(active=True),
        )
        for index, change in enumerate(changes):
            invalid = worker_snapshot()
            change(invalid)
            with self.subTest(case=index), self.assertRaises(ValueError):
                FLOW.concurrent_worker_witness(invalid, identifiers)

    def test_concurrency_rejects_cross_time_http_states_and_unrelated_active_count(self):
        # A finishes before B starts; C is claimed after its earlier QUEUED read.
        # Old sequential HTTP observations look like two RUNNING plus one QUEUED,
        # while the later aggregate counts B and C. No snapshot has that roster.
        identifiers = [TASK, EVENT, VERSION]
        http_states = dict(zip(identifiers, ("RUNNING", "RUNNING", "QUEUED")))
        snapshot = worker_snapshot()
        snapshot["tasks"][0].update(status="COMPLETED", lease=None, leaseExpiresAt=None)
        snapshot["tasks"][2].update(status="DISPATCHING", lease=EVENT,
                                    leaseExpiresAt="2026-10-08T00:03:00+00:00")
        admissions, gets, reads, aggregates = [], [], [], []

        def accepted(method, path, *_):
            if method == "POST":
                identifier = identifiers[len(admissions)]
                admissions.append(identifier)
                return {"judgeTaskId": identifier}
            gets.append(path)
            return {"status": http_states[path.rsplit("/", 1)[-1]]}

        def read(selected):
            reads.append(list(selected))
            return snapshot

        def scope():
            aggregates.append(True)
            return {"active": 2}

        service = SimpleNamespace(accepted=accepted, wait=lambda *_args, **_kwargs: self.fail("skew reached finalization"))
        database = SimpleNamespace(concurrency_snapshot=read, scope=scope)
        receiver = SimpleNamespace(expect=lambda *_: None)
        report = {"cases": []}
        with patch.object(FLOW.time, "monotonic", side_effect=(0, 0, 16)), \
                patch.object(FLOW.time, "sleep"), self.assertRaisesRegex(ValueError, "bounded_concurrent_execution_witness_missing"):
            FLOW.concurrency(service, None, database, receiver, {}, 7, report)
        self.assertEqual(reads, [identifiers])
        self.assertEqual(gets, [])
        self.assertEqual(aggregates, [])
        self.assertNotIn("concurrency", report)

    def test_concurrency_keeps_terminal_checks_and_emits_only_bounded_witness(self):
        identifiers, admitted, final_rows = [TASK, EVENT, VERSION], {}, {}
        digest = IMAGE.split("@")[1]

        def accepted(method, path, original, *_):
            self.assertEqual(method, "POST", "worker coexistence must come from the database snapshot")
            if path.endswith("/by-request"):
                return {"tasks": [{"judgeTaskId": admitted[original["requestIds"][0]]}], "missingRequestIds": []}
            if original["requestId"] not in admitted:
                identifier = identifiers[len(admitted)]
                admitted[original["requestId"]] = identifier
                public = dict(task("AC"), judgeTaskId=identifier, requestId=original["requestId"],
                              submissionId=original["submissionId"])
                stored = dict(facts(public), taskId=identifier, attempt=0, image=digest,
                              sourceHash=original["sourceSha256"], versionId=VERSION, problemId="7",
                              frozen={"limits": {"cpuTimeNS": 2_000_000_000, "wallTimeNS": 4_000_000_000,
                                                 "memoryBytes": 256 << 20, "outputBytes": 8 << 20, "processes": 32},
                                      "sourceSizeBytes": len(original["sourceCode"].encode()),
                                      "sourceFilename": "main.cpp", "identity": {"workerImageDigest": digest}})
                stored["events"] = [{"revision": revision, "terminal": status == "COMPLETED",
                                      "payload": public if status == "COMPLETED" else {"status": status}}
                                     for revision, status in enumerate(("QUEUED", "DISPATCHING", "RUNNING", "COMPLETED"), 1)]
                final_rows[identifier] = (public, stored)
            return {"judgeTaskId": admitted[original["requestId"]]}

        def wait(identifier, predicate, **_):
            public = final_rows[identifier][0]
            self.assertTrue(predicate(public))
            return public

        service = SimpleNamespace(accepted=accepted, wait=wait)
        database = SimpleNamespace(concurrency_snapshot=lambda selected: worker_snapshot())
        receiver = SimpleNamespace(expect=lambda *_: None)
        lifecycle = SimpleNamespace(digest=digest, spool_empty=lambda: None)
        report = {"cases": []}
        with patch.object(FLOW, "all_delivered", side_effect=lambda _db, _receiver, identifier: final_rows[identifier][1]):
            FLOW.concurrency(service, lifecycle, database, receiver,
                             {"problemId": "7", "problemVersionId": VERSION}, 7, report)
        witness = report["concurrency"]
        self.assertEqual((witness["observedRunning"], witness["observedQueued"], witness["productionWorkerSlots"]), (2, 1, 2))
        self.assertTrue(witness["atomicDatabaseSnapshot"])
        self.assertEqual(witness["liveRunningLeases"], 2)
        self.assertLess(len(json.dumps(witness)), 256)
        self.assertEqual({record["taskId"] for record in report["cases"]}, set(identifiers))
        self.assertTrue(all(record["verdict"] == "AC" and record["resultCaseTransactionMatched"]
                            and record["terminalEventMatched"] for record in report["cases"]))
        self.assertFalse(any(key in json.dumps(report) for key in ("leaseExpiresAt", '"lease"', "sourceCode", "frozen")))

    def test_libpq_environment_preserves_uri_password_without_secret_arguments(self):
        password = "EXAMPLE_FIXTURE :#%\\ Unicode-雪"
        dsn = "postgres://judge_runtime:" + quote(password, safe="") + "@startrack-capacity-postgres:5432/judge_capacity_fixture?sslmode=verify-full&sslrootcert=%2Fopt%2Fstartrack%2Fdb-ca.crt"
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "psql"
            executable.write_text("#!" + sys.executable + "\nimport json,os,sys\nprint(json.dumps({'argv':sys.argv[1:],'connection':{name:os.environ[name] for name in " + repr(FLOW.DATABASE_ENVIRONMENT) + "},'sql':sys.stdin.read()}))\n")
            executable.chmod(0o700)
            parameters = FLOW.database_parameters(dsn)
            sql = "BEGIN READ ONLY; SELECT 1; COMMIT;\n"
            environment = dict(os.environ, PATH=directory + os.pathsep + os.environ.get("PATH", ""))
            result = subprocess.run(["/bin/sh", "-c", FLOW.PSQL], input="\n".join(parameters) + "\n" + sql,
                                    text=True, capture_output=True, check=True, timeout=10, env=environment)
        observed = json.loads(result.stdout)
        self.assertEqual(observed["connection"]["PGPASSWORD"], password)
        self.assertEqual(observed["connection"]["PGDATABASE"], "judge_capacity_fixture")
        self.assertEqual(observed["connection"]["PGHOST"], "startrack-capacity-postgres")
        self.assertEqual(observed["connection"]["PGSSLMODE"], "verify-full")
        self.assertEqual(observed["connection"]["PGSSLROOTCERT"], "/opt/startrack/db-ca.crt")
        self.assertEqual(observed["sql"], sql)
        self.assertNotIn(dsn, " ".join(observed["argv"]))
        self.assertNotIn(password, " ".join(observed["argv"]))

    def test_database_parameter_frames_and_tls_downgrades_are_refused(self):
        base = "postgres://judge_runtime:fixture@startrack-capacity-postgres:5432/judge_capacity_fixture?sslmode=verify-full&sslrootcert=%2Fopt%2Fstartrack%2Fdb-ca.crt"
        for changed in (base.replace("fixture@", "fixture%0Ainjected@"), base.replace("fixture@", "fixture%00@"),
                        base.replace("verify-full", "disable"), base + "&sslmode=disable", base + "&host=elsewhere",
                        base.replace("judge_runtime:", "admin:"), base.replace(":5432/", ":5433/"),
                        base.replace("startrack-capacity-postgres", "elsewhere"), base.replace("%2Fopt%2Fstartrack%2Fdb-ca.crt", "other")):
            with self.subTest(uri=changed.replace("fixture", "synthetic")), self.assertRaisesRegex(ValueError, "^database_connection_parameters_invalid$"):
                FLOW.database_parameters(changed)

    def test_cleanup_requires_successful_removal_and_positive_daemon_absence(self):
        name = "startrack-flow-aabb"
        for removed, listed, names, expected in ((0, 0, "other\n", True), (1, 0, "other\n", False), (0, 1, "", False), (1, 1, "", False), (0, 0, name + "\n", False), (0, 0, name + "-other\n", True)):
            with self.subTest(removed=removed, listed=listed, names=names):
                returns = [SimpleNamespace(returncode=removed), SimpleNamespace(returncode=listed, stdout=names)]
                with patch.object(FLOW.QUALIFY, "run", side_effect=returns):
                    self.assertEqual(FLOW.remove_container(["docker"], name), expected)

    def test_repeated_real_operator_signals_do_not_interrupt_cleanup(self):
        program = "import importlib.util,os,signal; spec=importlib.util.spec_from_file_location('flow'," + repr(str(ROOT / "scripts/qualify-linux-service-flow.py")) + "); flow=importlib.util.module_from_spec(spec); spec.loader.exec_module(flow)\nsignal.signal(signal.SIGTERM,flow.abort)\ntry:\n os.kill(os.getpid(),signal.SIGTERM)\nexcept ValueError:\n flow.cleanup_signals(); os.kill(os.getpid(),signal.SIGINT); os.kill(os.getpid(),signal.SIGTERM); print('cleanup_completed')\n"
        result = subprocess.run([sys.executable, "-c", program], text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "cleanup_completed\n")

    def test_actual_boundary_schema_image_boot_and_denials_are_required(self):
        measurement = {"identity": {"workerImageDigest": IMAGE.split("@")[1]}, "bootId": VERSION}
        self.assertEqual(len(FLOW.boundary_report(boundary(), measurement, IMAGE.split("@")[1])), 2)
        changes = (
            lambda value: value.update(imageDigest="sha256:" + "c" * 64),
            lambda value: value.update(bootId=TASK),
            lambda value: value.update(version=True),
            lambda value: value.update(qualified=True),
            lambda value: value.update(measuredAt="2026-10-08T00:00:00"),
            lambda value: value["observations"][0].update(denied=False),
            lambda value: value["observations"][0].update(uid=0),
            lambda value: value["observations"][0].update(controlMem="missing"),
            lambda value: value["observations"][1].update(pid=25),
            lambda value: value["observations"].reverse(),
        )
        for index, change in enumerate(changes):
            value = boundary()
            change(value)
            with self.subTest(case=index), self.assertRaises(ValueError):
                FLOW.boundary_report(value, measurement, IMAGE.split("@")[1])

    def test_host_status_requires_all_role_credentials_namespace_and_memory_facts(self):
        value = FLOW.proc_status(STATUS, 20000, 1025, 25)
        self.assertEqual(value["VmRSS"], 80 * 1024)
        altered = (
            STATUS.replace("Uid:\t20000\t20000\t20000\t20000", "Uid:\t20000\t20000\t0\t20000"),
            STATUS.replace("Gid:\t20000\t20000\t20000\t20000", "Gid:\t20000\t20000\t20000\t0"),
            STATUS.replace("1025\t25", "1025\t26"),
            STATUS.replace("1025\t25", "1025\t20\t25"),
            STATUS.replace("VmSwap:\t0 kB\n", ""),
            STATUS + "VmRSS:\t80 kB\n",
            STATUS.replace("80 kB", "80 MB"),
            STATUS.replace("Groups:\t20002", "Groups:\t0 20002"),
            STATUS.replace("Groups:\t20002", "Groups:"),
            STATUS.replace("CapEff:\t0000000000000000", "CapEff:\t0000000000080000"),
            STATUS.replace("CapPrm:\t0000000000000000", "CapPrm:\t0000000000000001"),
            STATUS.replace("CapInh:\t0000000000000000", "CapInh:\t0000000000000001"),
            STATUS.replace("CapAmb:\t0000000000000000", "CapAmb:\t0000000000000001"),
            STATUS.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0"),
        )
        for index, raw in enumerate(altered):
            with self.subTest(case=index), self.assertRaises(ValueError):
                FLOW.proc_status(raw, 20000, 1025, 25)
        judger = STATUS.replace("20000", "20001").replace("Groups:\t20002", "Groups:")
        self.assertEqual(FLOW.proc_status(judger, 20001, 1025, 25)["Groups"], [])
        with self.assertRaises(ValueError):
            FLOW.proc_status(judger.replace("Groups:", "Groups:\t20002"), 20001, 1025, 25)

    def test_host_rollup_and_live_process_generation_fail_closed(self):
        self.assertEqual(FLOW.proc_start(STAT, 1025), 123)
        self.assertEqual(FLOW.proc_rollup("00000000-ffffffff ---p 00000000 00:00 0 [rollup]\nRss: 80 kB\nPss: 60 kB\nSwap: 0 kB\n"), {"Rss": 80 * 1024, "Pss": 60 * 1024, "Swap": 0})
        for raw in (STAT.replace("1025 (", "1026 ("), STAT.replace(") S ", ") Z "), STAT.replace("123 0", "0 0")):
            with self.assertRaises(ValueError):
                FLOW.proc_start(raw, 1025)
        for raw in ("Rss: 80 kB\nSwap: 0 kB\n", "Rss: 80 kB\nPss: 90 kB\nSwap: 0 kB\n", "Rss: 80 kB\nPss: 60 kB\nPss: 60 kB\nSwap: 0 kB\n", "Rss: 80 bytes\nPss: 60 kB\nSwap: 0 kB\n"):
            with self.assertRaises(ValueError):
                FLOW.proc_rollup(raw)

    def test_per_sample_pid_generation_namespace_comm_and_cgroup_are_rechecked(self):
        window = FLOW.MemoryWindow.__new__(FLOW.MemoryWindow)
        role = {"descriptor": 91, "hostPID": 1025, "observation": boundary()["observations"][0], "namespace": 42, "comm": "judge-service", "group": ["docker", "fixture", "service"]}
        data = {"stat": STAT, "status": STATUS, "smaps_rollup": "Rss: 80 kB\nPss: 60 kB\nSwap: 0 kB\n", "comm": "judge-service\n", "cgroup": "0::/docker/fixture/service\n"}
        with patch.object(FLOW, "read_fd", side_effect=lambda _, name, *args: data[name]), patch.object(FLOW.os, "stat", return_value=SimpleNamespace(st_ino=42)):
            self.assertEqual(window.role_memory(role)["pssBytes"], 60 * 1024)
            for name, value in (("stat", STAT.replace("123 0", "124 0")), ("comm", "unexpected\n"), ("cgroup", "0::/docker/other/service\n")):
                old = data[name]
                data[name] = value
                with self.subTest(fact=name), self.assertRaises(ValueError):
                    window.role_memory(role)
                data[name] = old
        with patch.object(FLOW, "read_fd", side_effect=lambda _, name, *args: data[name]), patch.object(FLOW.os, "stat", return_value=SimpleNamespace(st_ino=43)):
            with self.assertRaises(ValueError):
                window.role_memory(role)
        with patch.object(FLOW, "read_fd", side_effect=FileNotFoundError):
            with self.assertRaises(OSError):
                window.role_memory(role)

    def test_host_cgroup_paths_and_events_refuse_unbounded_or_ambiguous_facts(self):
        self.assertEqual(FLOW.unified_group("0::/docker/fixture/service\n"), ["docker", "fixture", "service"])
        self.assertEqual(FLOW.event_counts(EVENTS)["oom_kill"], 0)
        for raw in ("0::/docker/../service\n", "0::/docker//service\n", "0::/docker/service\n1:cpu:/service\n", "0::/docker/service"):
            with self.assertRaises(ValueError):
                FLOW.unified_group(raw)
        for raw in (EVENTS + "oom 0\n", EVENTS.replace("oom_group_kill 0\n", ""), EVENTS.replace("oom 0", "oom -1")):
            with self.assertRaises(ValueError):
                FLOW.event_counts(raw)

    def test_sampler_error_prevents_health_and_success_receipt(self):
        window = FLOW.MemoryWindow.__new__(FLOW.MemoryWindow)
        window.error, window.closed = "PermissionError", False
        window.thread = None
        window.stop = threading.Event()
        with self.assertRaises(ValueError):
            window.check()
        with patch.object(window, "close") as close, patch.object(window, "sample") as sample:
            with self.assertRaises(ValueError):
                window.finish("COMPLETED")
            close.assert_called_once()
            sample.assert_not_called()

    def test_blocked_sampler_retains_fds_and_lifecycle_cleanup_owner(self):
        window = FLOW.MemoryWindow.__new__(FLOW.MemoryWindow)
        window.closed, window.error = False, None
        window.stop = threading.Event()
        window.thread = SimpleNamespace(join=lambda timeout: None, is_alive=lambda: True)
        window.roles = {"api": {"descriptor": 91}}
        window.groups = {"service": 92}
        lifecycle = FLOW.Lifecycle.__new__(FLOW.Lifecycle)
        lifecycle.memory, lifecycle.starts = window, [{}]
        with patch.object(FLOW.os, "close") as close:
            with self.assertRaisesRegex(ValueError, "host_memory_sampler_did_not_stop"):
                lifecycle.finish_memory("COMPLETED")
            self.assertIs(lifecycle.memory, window)
            self.assertFalse(window.closed)
            close.assert_not_called()
            with self.assertRaisesRegex(ValueError, "host_memory_sampler_did_not_stop"):
                window.close()
            close.assert_not_called()
            window.thread = SimpleNamespace(join=lambda timeout: None, is_alive=lambda: False)
            window.close()
            self.assertTrue(window.closed)
            self.assertEqual(close.call_count, 2)
            window.close()
            self.assertEqual(close.call_count, 2)

    def test_cgroup_reads_keep_original_directory_and_reject_budget_membership_drift(self):
        window = FLOW.MemoryWindow.__new__(FLOW.MemoryWindow)
        window.groups = {}
        window.supervisor = {"hostPID": 1000}
        window.roles = {"api": {"hostPID": 1025}, "judger": {"hostPID": 1026}}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            try:
                for role, limit in (("outer", 10 << 30), ("service", 6 << 30), ("runtime", 4 << 30)):
                    directory = root / role
                    directory.mkdir()
                    for name, value in {"memory.current": "65536\n", "memory.peak": "131072\n", "memory.max": str(limit) + "\n", "memory.swap.max": "0\n", "memory.events": EVENTS, "memory.events.local": EVENTS, "cgroup.procs": "1000\n1025\n1026\n"}.items():
                        (directory / name).write_text(value)
                    window.groups[role] = FLOW.os.open(directory, FLOW.os.O_RDONLY | FLOW.os.O_DIRECTORY)
                before = window.cgroups()
                (root / "outer").rename(root / "original-outer")
                (root / "outer").mkdir()
                (root / "outer/memory.max").write_text("1\n")
                self.assertEqual(window.cgroups(), before)
                (root / "service/cgroup.procs").write_text("1000\n1025\n")
                with self.assertRaises(ValueError):
                    window.cgroups()
                (root / "service/cgroup.procs").write_text("1000\n1025\n1026\n")
                (root / "runtime/memory.max").write_text(str(8 << 30) + "\n")
                with self.assertRaises(ValueError):
                    window.cgroups()
            finally:
                for descriptor in window.groups.values():
                    FLOW.os.close(descriptor)

    def test_memory_receipt_accepts_descendant_mle_and_refuses_service_or_local_oom(self):
        initial = {role: {"directoryInode": inode, "memory.peak": 100, "memory.events": FLOW.event_counts(EVENTS), "memory.events.local": FLOW.event_counts(EVENTS)} for role, inode in (("outer", 1), ("service", 2), ("runtime", 3))}
        for target, local, accepted in (("runtime", False, True), ("outer", False, True), ("service", False, False), ("runtime", True, False), ("outer", True, False), ("service", True, False)):
            with self.subTest(target=target, local=local):
                window = FLOW.MemoryWindow.__new__(FLOW.MemoryWindow)
                window.closed, window.error, window.thread = False, None, None
                window.stop = threading.Event()
                window.groups, window.roles = {role: inode for role, inode in (("outer", 1), ("service", 2), ("runtime", 3))}, {}
                window.before, window.maxima = copy.deepcopy(initial), {}
                window.count, window.started = 2, FLOW.time.monotonic()
                window.digest = hashlib.sha256(b"synthetic-numerical-sample")
                window.container_id, window.supervisor = "a" * 64, {"hostPID": 1000}
                final = copy.deepcopy(initial)
                final[target]["memory.events.local" if local else "memory.events"]["oom_kill"] = 1
                with tempfile.TemporaryDirectory() as temporary:
                    window.output = Path(temporary) / "memory.json"
                    with patch.object(window, "sample"), patch.object(window, "cgroups", return_value=final), patch.object(window, "close"):
                        if accepted:
                            receipt = window.finish("COMPLETED")
                            self.assertTrue(receipt["passed"])
                            self.assertEqual(receipt["receiptSha256"], hashlib.sha256(window.output.read_bytes()).hexdigest())
                        else:
                            with self.assertRaises(ValueError):
                                window.finish("COMPLETED")
                            self.assertFalse(window.output.exists())

    def test_frozen_limits_source_identity_and_size_are_explicit(self):
        original = FLOW.request({"problemId": "7", "problemVersionId": VERSION}, FLOW.SUM, 7)
        value = {"sourceHash": original["sourceSha256"], "versionId": VERSION, "problemId": "7", "image": IMAGE.split("@")[1], "frozen": {"limits": {"cpuTimeNS": 2_000_000_000, "wallTimeNS": 4_000_000_000, "memoryBytes": 256 << 20, "outputBytes": 8 << 20, "processes": 32}, "sourceSizeBytes": len(original["sourceCode"].encode()), "sourceFilename": "main.cpp", "identity": {"workerImageDigest": IMAGE.split("@")[1]}}}
        FLOW.assert_frozen(value, original, IMAGE.split("@")[1])
        changes = (
            lambda changed: changed["frozen"]["limits"].update(memoryBytes=1 << 30),
            lambda changed: changed["frozen"]["limits"].update(cpuTimeNs=2_000_000_000),
            lambda changed: changed["frozen"].update(sourceSizeBytes=1),
            lambda changed: changed["frozen"].update(sourceFilename="caller-path"),
            lambda changed: changed["frozen"]["identity"].update(workerImageDigest="sha256:" + "c" * 64),
        )
        for index, change in enumerate(changes):
            altered = copy.deepcopy(value)
            change(altered)
            with self.subTest(case=index), self.assertRaises(ValueError):
                FLOW.assert_frozen(altered, original, IMAGE.split("@")[1])


if __name__ == "__main__":
    unittest.main()
