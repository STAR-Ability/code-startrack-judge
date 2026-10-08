"""Fail-closed qualification and actual Linux pidfd identity checks."""

import importlib.util
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("linux_qualification", ROOT / "scripts/linux-qualify.py")
QUALIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(QUALIFY)


class CrashEvidenceTests(unittest.TestCase):
    def test_shutdown_requires_exit_one_and_absent_qualification(self):
        state = {"Running": False, "Status": "exited", "ExitCode": 1, "Pid": 0, "OOMKilled": True}
        with tempfile.TemporaryDirectory() as directory:
            proof = Path(directory) / "runtime-measurement.json"
            QUALIFY.require_failed_closed(state, proof)
            for key, value in (("ExitCode", 0), ("ExitCode", True), ("Running", True), ("Pid", False)):
                invalid = dict(state, **{key: value})
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    QUALIFY.require_failed_closed(invalid, proof)
            proof.write_text("{}")
            with self.assertRaises(ValueError):
                QUALIFY.require_failed_closed(state, proof)
            proof.unlink()
            proof.symlink_to(Path(directory) / "absent")
            with self.assertRaises(ValueError):
                QUALIFY.require_failed_closed(state, proof)

    def test_restart_requires_new_process_same_environment_and_all_initial_checks(self):
        previous = {"pid": 29, "startTicks": "100", "bootId": "same-boot", "securityProfileSha256": "a" * 64,
                    "identity": {"workerImageDigest": "same-image"}}
        current = dict(previous, startTicks="200", checks={key: True for key in QUALIFY.REQUIRED_CHECKS})
        observations = {"cleanupObservations": {"startupGlobalIdle": True}}
        QUALIFY.require_fresh_restart(previous, current, observations)
        invalid_values = [("startTicks", "100"), ("startTicks", "99"), ("bootId", "another-boot"),
                          ("identity", {"workerImageDigest": "another-image"}), ("pid", True),
                          ("securityProfileSha256", "b" * 64),
                          ("checks", {key: key != "cleanup" for key in QUALIFY.REQUIRED_CHECKS})]
        for key, value in invalid_values:
            with self.subTest(key=key), self.assertRaises(ValueError):
                QUALIFY.require_fresh_restart(previous, dict(current, **{key: value}), observations)
        with self.assertRaises(ValueError):
            QUALIFY.require_fresh_restart(previous, current, {"cleanupObservations": {"startupGlobalIdle": False}})

    def test_invalid_manager_identity_is_rejected_before_docker_operation(self):
        with mock.patch.object(QUALIFY, "run", side_effect=AssertionError("unexpected Docker operation")) as operation:
            for pid in (1, 0, -1, True, "29"):
                with self.subTest(pid=pid), self.assertRaises(ValueError):
                    QUALIFY.crash_restart([], "unused", Path("unused"),
                                          {"pid": pid, "startTicks": "123", "bootId": "11111111-1111-1111-1111-111111111111"}, "unused")
            operation.assert_not_called()

    def preserved(self, directory):
        names = ("ALL_PARTS", "VALIDATOR_EXIT_ZERO", "ACCEPTED_REFERENCE_WRONG", "STATEMENT_ARTIFACTS",
                 "LARGE_STATEMENT", "WORKSPACE", "DEFAULT_CHECKER_REGRESSIONS")
        facts = {}
        for name in names:
            data = ("bounded " + name).encode()
            (directory / ("matrix-" + name + "-A.log")).write_bytes(data)
            facts[name] = {"retainedBytes": len(data), "retainedSha256": QUALIFY.hashlib.sha256(data).hexdigest()}
        matrix = {"mature": [{"name": name, "privateLog": facts[name]} for name in names[:3]],
                  "statement": {"privateLog": facts["STATEMENT_ARTIFACTS"]},
                  "largeStatement": {"statement": {"privateLog": facts["LARGE_STATEMENT"]}},
                  "workspace": {"privateLog": facts["WORKSPACE"]},
                  "defaultChecker": {"privateLog": facts["DEFAULT_CHECKER_REGRESSIONS"]}, "passed": True}
        (directory / "matrix-report-private.json").write_text(json.dumps(matrix))
        return matrix

    def test_preservation_binds_all_seven_logs_and_completed_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            private = Path(directory)
            matrix = self.preserved(private)
            binding = QUALIFY.verify_preserved_matrix(private, matrix)
            self.assertEqual(len(binding["fixtureLogs"]), 7)
            self.assertEqual(binding["matrixReportSha256"], QUALIFY.hashlib.sha256((private / "matrix-report-private.json").read_bytes()).hexdigest())

    def test_missing_or_corrupt_original_log_cannot_pass_preservation(self):
        for corruption in ("absent", "wrong bytes", "duplicate"):
            with self.subTest(corruption=corruption), tempfile.TemporaryDirectory() as directory:
                private = Path(directory)
                matrix = self.preserved(private)
                target = private / "matrix-LARGE_STATEMENT-A.log"
                if corruption == "absent":
                    target.unlink()
                elif corruption == "duplicate":
                    (private / "matrix-LARGE_STATEMENT-B.log").write_bytes(target.read_bytes())
                else:
                    target.write_bytes(b"X" * target.stat().st_size)
                with self.assertRaises(ValueError):
                    QUALIFY.verify_preserved_matrix(private, matrix)

    def test_private_matrix_report_must_match_completed_original(self):
        with tempfile.TemporaryDirectory() as directory:
            private = Path(directory)
            matrix = self.preserved(private)
            (private / "matrix-report-private.json").write_text(json.dumps(dict(matrix, passed=False)))
            with self.assertRaises(ValueError):
                QUALIFY.verify_preserved_matrix(private, matrix)

    def test_capture_binds_outer_group_and_both_service_runtime_branches(self):
        identifier = "a" * 64
        outer = "system.slice/docker-" + identifier + ".scope"
        state = {"Running": True, "Pid": 1000}
        responses = [SimpleNamespace(stdout=json.dumps(state)), SimpleNamespace(stdout=identifier),
                     SimpleNamespace(stdout="PID\n1000\n1001\n")]
        snapshots = [("10", ["NSpid:\t1000\t1"], ["0::/" + outer + "/service"]),
                     ("100", ["NSpid:\t1001\t29\t2"], ["0::/" + outer + "/runtime/manager"])]
        with tempfile.TemporaryDirectory() as directory:
            descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with mock.patch.object(QUALIFY, "run", side_effect=responses), \
                        mock.patch.object(QUALIFY.Path, "read_text", return_value="0::/" + outer + "/service\n"), \
                        mock.patch.object(QUALIFY, "process_snapshot", side_effect=snapshots), \
                        mock.patch.object(QUALIFY.os, "open", return_value=descriptor) as opened:
                    witness = QUALIFY.capture_execution_drain([], "fixed", {"pid": 29, "startTicks": "100"})
                self.assertEqual(witness["processes"], {1000: "10", 1001: "100"})
                self.assertEqual(opened.call_args.args[0], Path("/sys/fs/cgroup") / outer)
                self.assertTrue(opened.call_args.args[1] & os.O_CLOEXEC)
            finally:
                os.close(descriptor)

    def test_capture_rejects_wrong_container_topology_before_opening_group(self):
        identifier = "a" * 64
        for suffix in ("runtime", "service/child", ""):
            responses = [SimpleNamespace(stdout=json.dumps({"Running": True, "Pid": 1000})), SimpleNamespace(stdout=identifier)]
            cgroup = "0::/system.slice/docker-" + identifier + ".scope/" + suffix
            with self.subTest(suffix=suffix), \
                    mock.patch.object(QUALIFY, "run", side_effect=responses), \
                    mock.patch.object(QUALIFY.Path, "read_text", return_value=cgroup + "\n"), \
                    mock.patch.object(QUALIFY.os, "open", side_effect=AssertionError("unexpected cgroup open")) as opened:
                with self.assertRaises(ValueError):
                    QUALIFY.capture_execution_drain([], "fixed", {"pid": 29, "startTicks": "100"})
                opened.assert_not_called()


@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "pidfd_open")
                     and hasattr(signal, "pidfd_send_signal"), "requires actual Linux pidfd support")
class LinuxManagerSignalTests(unittest.TestCase):
    def child(self, name="go-judge"):
        code = "import ctypes,sys; assert ctypes.CDLL(None).prctl(15,sys.argv[1].encode(),0,0,0)==0; print('ready',flush=True); sys.stdin.buffer.read(1)"
        child = subprocess.Popen([sys.executable, "-c", code, name], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        self.addCleanup(self.reap, child)
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            self.assertTrue(selector.select(timeout=5))
        self.assertEqual(child.stdout.readline(), b"ready\n")
        raw = Path(f"/proc/{child.pid}/stat").read_text()
        ticks = raw[raw.rindex(")") + 1:].split()[19]
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        return child, ticks, boot

    @staticmethod
    def reap(child):
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)
        child.stdin.close()
        child.stdout.close()

    def invoke(self, child, ticks, boot):
        return subprocess.run([sys.executable, "-c", QUALIFY.MANAGER_KILL_PROBE,
                               str(child.pid), ticks, boot], capture_output=True, timeout=5)

    def test_wrong_start_or_boot_does_not_signal_existing_child(self):
        child, ticks, boot = self.child()
        for wrong_ticks, wrong_boot in ((str(int(ticks) + 1), boot), (ticks, "another-boot")):
            with self.subTest(ticks=wrong_ticks, boot=wrong_boot):
                self.assertNotEqual(self.invoke(child, wrong_ticks, wrong_boot).returncode, 0)
                self.assertIsNone(child.poll())

    def test_exact_identity_signals_and_reaps_original_child(self):
        child, ticks, boot = self.child()
        result = self.invoke(child, ticks, boot)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout), {"killSent": True, "pid": child.pid,
                                                   "startTicks": ticks, "bootId": boot})
        self.assertEqual(child.wait(timeout=5), -signal.SIGKILL)

    def test_other_component_is_not_signaled(self):
        child, ticks, boot = self.child("runtime-init")
        self.assertNotEqual(self.invoke(child, ticks, boot).returncode, 0)
        self.assertIsNone(child.poll())

    def witness(self, directory, processes):
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.addCleanup(os.close, descriptor)
        facts = os.fstat(descriptor)
        return {"descriptor": descriptor, "device": facts.st_dev, "inode": facts.st_ino, "processes": processes}

    def test_drain_requires_original_process_reaped_and_zero_original_group(self):
        child, ticks, _boot = self.child()
        with tempfile.TemporaryDirectory() as directory:
            group = Path(directory)
            (group / "pids.current").write_text("0\n")
            witness = self.witness(group, {child.pid: ticks})
            self.assertFalse(QUALIFY.execution_drained(witness))
            child.kill()
            child.wait(timeout=5)
            self.assertTrue(QUALIFY.execution_drained(witness))
            (group / "pids.current").write_text("1\n")
            self.assertFalse(QUALIFY.execution_drained(witness))

    def test_renamed_original_group_does_not_accept_empty_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            original = Path(directory) / "group"
            original.mkdir()
            (original / "pids.current").write_text("1\n")
            witness = self.witness(original, {})
            held = Path(directory) / "renamed"
            original.rename(held)
            original.mkdir()
            (original / "pids.current").write_text("0\n")
            self.assertFalse(QUALIFY.execution_drained(witness))
            (held / "pids.current").write_text("0\n")
            self.assertTrue(QUALIFY.execution_drained(witness))

    def test_snapshot_binds_actual_process_metadata_and_closes_descriptor(self):
        child, ticks, _boot = self.child()
        expected_descriptors = len(list(Path("/proc/self/fd").iterdir()))
        captured, status, membership = QUALIFY.process_snapshot(child.pid)
        self.assertEqual(captured, ticks)
        self.assertTrue(any(line.startswith("NSpid:") for line in status))
        self.assertTrue(membership)
        self.assertEqual(len(list(Path("/proc/self/fd").iterdir())), expected_descriptors)


if __name__ == "__main__":
    unittest.main()
