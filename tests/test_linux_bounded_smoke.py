"""Portable rejection checks for the shared-host smoke launcher; no Linux claim."""

import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import threading
import unittest
import uuid
from unittest.mock import MagicMock, patch
from contextlib import redirect_stdout

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("bounded_smoke", ROOT / "scripts/linux-bounded-smoke.py")
SMOKE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SMOKE)


class BoundedSmokeTests(unittest.TestCase):
    def endpoint_fixture(self):
        name = "startrack-v02-smoke-" + "c" * 16
        network = {"Name": name, "Id": "b" * 64, "Internal": True, "IPAM": {"Config": [{"Subnet": "172.19.0.0/16"}]}}
        value = {"Id": "a" * 64, "Labels": {SMOKE.OWNER_LABEL: name},
                 "State": {"Status": "running", "Running": True, "ExitCode": 0, "OOMKilled": False,
                           "Error": "PRIVATE_STATE_ERROR", "Health": {"Log": [{"Output": "PRIVATE_HEALTH_LOG"}]}},
                 "Networks": {name: {"NetworkID": network["Id"], "IPAddress": "172.19.0.3"}},
                 "Ports": {"8082/tcp": None}, "PortBindings": {}}
        return name, network, value

    def test_internal_bridge_uses_owned_private_endpoint_without_publication(self):
        owner, network, value = self.endpoint_fixture()
        report = {}
        with patch.object(SMOKE, "observed_docker", return_value=SimpleNamespace(stdout=json.dumps(value).encode())) as docker:
            self.assertEqual(SMOKE.service_endpoint(["docker"], value["Id"], network, owner, Path("evidence"), report, "initial"),
                             ("172.19.0.3", 8082))
        self.assertEqual(len(docker.call_args_list), 1)
        self.assertEqual(docker.call_args.args[1][:2], ["inspect", value["Id"]])
        self.assertEqual(report["endpoint"], {"scope": "PRIVATE_BRIDGE_FROM_HOST", "port": 8082, "hostPublished": False})
        public = json.dumps(report)
        for private in ("172.19.0.3", "PRIVATE_STATE_ERROR", "PRIVATE_HEALTH_LOG"):
            self.assertNotIn(private, public)
        self.assertNotIn("--publish", SMOKE.docker_limits(Path("profile"), owner, 0, internal=True))
        self.assertIn("--publish", SMOKE.docker_limits(Path("profile"), owner, 0))

    def test_internal_endpoint_rejects_foreign_identity_network_address_and_publication(self):
        owner, network, accepted = self.endpoint_fixture()
        changes = (
            (lambda value: value.update(Id="d" * 64), "container_endpoint_ownership_invalid"),
            (lambda value: value["Labels"].update({SMOKE.OWNER_LABEL: "other-owner"}), "container_endpoint_ownership_invalid"),
            (lambda value: value["Networks"][owner].update(NetworkID="d" * 64), "container_network_identity_invalid"),
            (lambda value: value["Networks"].update(other={}), "container_network_identity_invalid"),
            (lambda value: value["Networks"][owner].update(IPAddress="10.0.0.1"), "private_bridge_address_invalid"),
            (lambda value: value["Networks"][owner].update(IPAddress="8.8.8.8"), "private_bridge_address_invalid"),
            (lambda value: value.update(PortBindings={"8082/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8082"}]}), "internal_bridge_publication_forbidden"),
            (lambda value: value.update(Ports={"8082/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8082"}]}), "internal_bridge_publication_forbidden"),
        )
        for mutate, code in changes:
            value = copy.deepcopy(accepted)
            mutate(value)
            with self.subTest(code=code), patch.object(SMOKE, "observed_docker", return_value=SimpleNamespace(stdout=json.dumps(value).encode())):
                with self.assertRaisesRegex(ValueError, code):
                    SMOKE.service_endpoint(["docker"], accepted["Id"], network, owner, Path("evidence"), {}, "initial")

    def test_stopped_service_records_exit_and_oom_before_port_query(self):
        owner, network, value = self.endpoint_fixture()
        value["State"].update(Status="exited", Running=False, ExitCode=137, OOMKilled=True)
        report = {}
        with patch.object(SMOKE, "observed_docker", return_value=SimpleNamespace(stdout=json.dumps(value).encode())) as docker:
            with self.assertRaisesRegex(ValueError, "service_stopped_before_readiness"):
                SMOKE.service_endpoint(["docker"], value["Id"], dict(network, Internal=False), owner, Path("evidence"), report, "initial")
        self.assertEqual(len(docker.call_args_list), 1)
        self.assertEqual(report["initialContainerState"], {"status": "exited", "running": False, "exitCode": 137, "oomKilled": True})

    def test_docker_capture_enforces_independent_byte_bounds_and_timeout(self):
        program = 'import os; os.write(1, b"A" * 262144); os.write(2, b"B" * 262144)'
        result = SMOKE.bounded_docker([sys.executable], ["-c", program], timeout=5)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(len(result.stdout), SMOKE.DOCKER_STREAM_BYTES)
        self.assertEqual(len(result.stderr), SMOKE.DOCKER_STREAM_BYTES)
        self.assertEqual(result.truncated, {"stdout": True, "stderr": True})
        self.assertFalse(result.timed_out)
        result = SMOKE.bounded_docker([sys.executable], ["-c", "import time; time.sleep(5)"], timeout=0.1)
        self.assertTrue(result.timed_out)
        self.assertNotEqual(result.returncode, 0)

    def test_unreapable_docker_client_never_enters_an_unbounded_context_wait(self):
        process = MagicMock()
        process.stdout = io.BytesIO()
        process.stderr = io.BytesIO()
        process.poll.return_value = None
        process.wait.side_effect = SMOKE.subprocess.TimeoutExpired("docker", 5)
        selected = MagicMock()
        selected.__enter__.return_value = selected
        selected.get_map.return_value = {}
        with patch.object(SMOKE.subprocess, "Popen", return_value=process), \
             patch.object(SMOKE.selectors, "DefaultSelector", return_value=selected):
            with self.assertRaises(SMOKE.subprocess.TimeoutExpired):
                SMOKE.bounded_docker(["docker"], ["logs", "owned"], timeout=0.1)
        process.__enter__.assert_not_called()
        process.__exit__.assert_not_called()
        process.kill.assert_called_once()
        self.assertTrue(all(call.kwargs.get("timeout") is not None for call in process.wait.call_args_list))
        self.assertTrue(process.stdout.closed)
        self.assertTrue(process.stderr.closed)

    def test_failed_docker_output_is_private_bounded_and_never_printed(self):
        result = SimpleNamespace(returncode=1, stdout=b"PRIVATE_STDOUT", stderr=b"PRIVATE_STDERR", timed_out=False,
                                 truncated={"stdout": False, "stderr": False})
        public = io.StringIO()
        report = {}
        with tempfile.TemporaryDirectory() as directory, patch.object(SMOKE, "bounded_docker", return_value=result), redirect_stdout(public):
            evidence = Path(directory)
            with self.assertRaisesRegex(ValueError, "docker_port_failed"):
                SMOKE.observed_docker(["docker"], ["port", "owned", "8082/tcp"], evidence, report, "initial-port")
            private = evidence / "docker-private"
            self.assertEqual(stat.S_IMODE(private.stat().st_mode), 0o700)
            for stream in ("stdout", "stderr"):
                path = private / ("initial-port." + stream)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertEqual(path.stat().st_uid, os.geteuid())
                self.assertEqual(path.read_bytes(), getattr(result, stream))
        self.assertEqual(public.getvalue(), "")
        self.assertNotIn("PRIVATE_", json.dumps(report))

    def test_docker_retention_rejects_symlinks_and_global_file_overflow(self):
        result = SimpleNamespace(stdout=b"bounded", stderr=b"bounded")
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            private = evidence / "docker-private"
            private.mkdir(mode=0o700)
            target = evidence / "other"
            target.write_bytes(b"original")
            (private / "initial-port.stdout").symlink_to(target)
            with self.assertRaises(OSError):
                SMOKE.retain_docker_output(evidence, "initial-port", result)
            self.assertEqual(target.read_bytes(), b"original")
            (private / "initial-port.stdout").unlink()
            for number in range(SMOKE.MAX_DOCKER_DIAGNOSTIC_STREAMS - 1):
                (private / str(number)).touch(mode=0o600)
            with self.assertRaisesRegex(ValueError, "docker_diagnostic_global_bound_exceeded"):
                SMOKE.retain_docker_output(evidence, "initial-port", result)

    def test_failure_diagnostics_never_read_an_unowned_containers_logs(self):
        owner, _, value = self.endpoint_fixture()
        value["Labels"][SMOKE.OWNER_LABEL] = "other-owner"
        result = SimpleNamespace(returncode=0, stdout=json.dumps(value).encode(), timed_out=False,
                                 truncated={"stdout": False, "stderr": False})
        with patch.object(SMOKE, "observed_docker", return_value=result) as docker:
            with self.assertRaisesRegex(ValueError, "container_endpoint_ownership_invalid"):
                SMOKE.failure_diagnostics(["docker"], "active", value["Id"], owner, Path("evidence"), {})
        self.assertEqual(len(docker.call_args_list), 1)

    def test_mutable_reference_and_wrong_platform_rejected(self):
        identifier = "sha256:" + "a" * 64
        image = {"Id": identifier, "Os": "linux", "Architecture": "amd64", "RepoDigests": []}
        with self.assertRaisesRegex(ValueError, "immutable_image_reference_invalid"):
            SMOKE.image_identity(image, "startrack-qualified-candidate:dev")
        with self.assertRaisesRegex(ValueError, "image_id_mismatch"):
            SMOKE.image_identity(image, "sha256:" + "b" * 64)
        with self.assertRaisesRegex(ValueError, "image_platform_invalid"):
            SMOKE.image_identity(dict(image, Architecture="arm64"), identifier)
        self.assertEqual(SMOKE.image_identity(image, identifier), (identifier, "DOCKER_IMAGE_ID"))

    def test_oci_reference_must_exist_in_actual_image_inventory(self):
        identifier = "sha256:" + "a" * 64
        reference = SMOKE.QUALIFY.OFFICIAL + "@sha256:" + "b" * 64
        image = {"Id": identifier, "Os": "linux", "Architecture": "amd64", "RepoDigests": []}
        with self.assertRaisesRegex(ValueError, "immutable_image_reference_invalid"):
            SMOKE.image_identity(image, reference)
        self.assertEqual(SMOKE.image_identity(dict(image, RepoDigests=[reference]), reference)[1], "OCI_MANIFEST_DIGEST")

    def test_host_pressure_aborts_before_and_during_execution(self):
        with patch.object(SMOKE, "available_memory", return_value=SMOKE.MEMORY_BYTES):
            with self.assertRaisesRegex(ValueError, "host_memory_headroom_insufficient"):
                SMOKE.check_headroom(startup=True)
        with patch.object(SMOKE, "available_memory", return_value=SMOKE.MIN_HEADROOM_BYTES - 1):
            with self.assertRaisesRegex(ValueError, "host_memory_headroom_insufficient"):
                SMOKE.check_headroom()

    def test_docker_health_requires_an_actual_successful_probe(self):
        self.assertFalse(SMOKE.healthy_docker_probe({"Health": {"Status": "healthy", "Log": []}}))
        self.assertFalse(SMOKE.healthy_docker_probe({"Health": {"Status": "healthy", "Log": [{"ExitCode": 1}]}}))
        self.assertFalse(SMOKE.healthy_docker_probe({"Health": {"Status": "unhealthy", "Log": [{"ExitCode": 0}]}}))
        self.assertTrue(SMOKE.healthy_docker_probe({"Health": {"Status": "healthy", "Log": [{"ExitCode": 0}]}}))

    def test_existing_apparmor_profile_is_only_renamed_with_self_peers(self):
        source = (ROOT / "docker/startrack-v02.apparmor").read_text()
        name = "startrack-v02-smoke-" + "c" * 16
        generated = SMOKE.scoped_apparmor(source, name)
        self.assertEqual(generated.replace("profile " + name + " ", "profile startrack-v02 ")
                         .replace("peer=" + name + ",", "peer=startrack-v02,"), source)
        with self.assertRaisesRegex(ValueError, "apparmor_name_invalid"):
            SMOKE.scoped_apparmor(source, "startrack-v02")
        with self.assertRaisesRegex(ValueError, "apparmor_source_invalid"):
            SMOKE.scoped_apparmor(source.replace("peer=startrack-v02,", "peer=unconfined,"), name)

    def test_unsafe_actual_docker_settings_are_rejected(self):
        name = "startrack-v02-smoke-" + "c" * 16
        accepted = {"Privileged": False, "ReadonlyRootfs": True, "CgroupnsMode": "private", "CapAdd": list(SMOKE.QUALIFY.CAPABILITIES),
                    "CapDrop": ["ALL"], "Memory": SMOKE.MEMORY_BYTES, "MemorySwap": SMOKE.MEMORY_BYTES,
                    "NanoCpus": 1_000_000_000, "PidsLimit": 256,
                    "SecurityOpt": ["apparmor=" + name, "no-new-privileges", "seccomp=/reviewed/profile.json"]}
        SMOKE.enforced_limits(accepted, name)
        for key, value in (("Privileged", True), ("ReadonlyRootfs", False), ("CgroupnsMode", "host"),
                           ("Memory", 0), ("MemorySwap", -1), ("NanoCpus", 0), ("PidsLimit", 0),
                           ("CapAdd", list(SMOKE.QUALIFY.CAPABILITIES) + ["NET_ADMIN"])):
            with self.subTest(key=key):
                changed = copy.deepcopy(accepted)
                changed[key] = value
                with self.assertRaisesRegex(ValueError, "docker_enforced_limits_invalid"):
                    SMOKE.enforced_limits(changed, name)
        changed = copy.deepcopy(accepted)
        changed["SecurityOpt"][-1] = "seccomp=unconfined"
        with self.assertRaisesRegex(ValueError, "docker_security_policy_invalid"):
            SMOKE.enforced_limits(changed, name)

    def test_failed_diagnostic_retention_still_cleans_owned_resources(self):
        report = {"passed": True}
        with patch.object(SMOKE.QUALIFY, "retain_private", side_effect=OSError), patch.object(SMOKE, "cleanup_owned", return_value=True) as cleanup:
            self.assertTrue(SMOKE.retain_and_cleanup(["docker"], ["owned"], Path("profile"), True, Path("runtime"), Path("evidence"), report, "task-owner"))
        cleanup.assert_called_once()
        self.assertFalse(report["passed"])
        self.assertEqual(report["failureCode"], "private_evidence_retention_failed")

    def test_failure_snapshot_errors_cannot_skip_owned_cleanup(self):
        for error in (OSError, RuntimeError):
            report = {"passed": False, "failureCode": "service_stopped_before_readiness"}
            with self.subTest(error=error), patch.object(SMOKE, "failure_diagnostics", side_effect=error), \
                 patch.object(SMOKE.QUALIFY, "retain_private", return_value=0), patch.object(SMOKE, "cleanup_owned", return_value=True) as cleanup:
                self.assertTrue(SMOKE.retain_and_cleanup(["docker"], ["owned"], Path("profile"), True, Path("runtime"), Path("evidence"),
                                                        report, "task-owner", "owned", "a" * 64))
                self.assertFalse(report["failureContainerDiagnosticsAvailable"])
                self.assertEqual(report["failureContainerDiagnosticErrorClass"], error.__name__)
                cleanup.assert_called_once()
                self.assertEqual(report["failureCode"], "service_stopped_before_readiness")

    def test_uncertain_container_cleanup_keeps_profile_enforced(self):
        success = SimpleNamespace(returncode=0, stdout="")
        owned = SimpleNamespace(returncode=0, stdout="a" * 64 + " " + json.dumps({SMOKE.OWNER_LABEL: "task-owner"}))
        uncertain = SimpleNamespace(returncode=1, stdout="")
        for listing in (uncertain, SimpleNamespace(returncode=0, stdout="owned\n")):
            with self.subTest(listing=listing), patch.object(SMOKE.QUALIFY, "run", side_effect=[owned, success, listing]), patch.object(SMOKE.subprocess, "run") as parser:
                self.assertFalse(SMOKE.cleanup_owned(["docker"], ["owned"], Path("profile"), True, "task-owner"))
                parser.assert_not_called()

    def test_name_collision_never_removes_an_unowned_container(self):
        for labels in ({}, {SMOKE.OWNER_LABEL: "another-task"}, None):
            inspection = SimpleNamespace(returncode=0, stdout="a" * 64 + " " + json.dumps(labels))
            with self.subTest(labels=labels), patch.object(SMOKE.QUALIFY, "run", return_value=inspection) as docker, patch.object(SMOKE.subprocess, "run") as parser:
                self.assertFalse(SMOKE.cleanup_owned(["docker"], ["collision"], Path("profile"), True, "task-owner"))
                self.assertEqual(len(docker.call_args_list), 1)
                self.assertEqual(docker.call_args.args[1][0], "inspect")
                parser.assert_not_called()

    def test_uncertain_owner_inspection_never_sends_remove(self):
        unavailable = SimpleNamespace(returncode=1, stdout="")
        with patch.object(SMOKE.QUALIFY, "run", return_value=unavailable) as docker, patch.object(SMOKE.subprocess, "run") as parser:
            self.assertFalse(SMOKE.cleanup_owned(["docker"], ["uncertain"], Path("profile"), True, "task-owner"))
            self.assertFalse(any(call.args[1][0] == "rm" for call in docker.call_args_list))
            parser.assert_not_called()

    def test_api_probes_use_contract_envelopes_and_correlated_uuid_headers(self):
        accepted = SMOKE.secrets.token_hex(32)
        requests = []

        class ContractHandler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                correlation = self.headers.get("X-Request-Id")
                try:
                    uuid.UUID(correlation)
                except (ValueError, AttributeError, TypeError):
                    self.send_error(400)
                    return
                requests.append((self.path, correlation))
                if self.headers.get("Authorization") != "Bearer " + accepted:
                    status, body = 401, {"error": {"code": "SERVICE_UNAUTHORIZED", "message": "Unauthorized", "details": {}}, "requestId": correlation}
                elif self.path == "/internal/v2/languages":
                    status, body = 200, {"data": {"capabilityVersion": "fixture", "languages": [{"languageId": "cpp17"}]}, "requestId": correlation}
                else:
                    # Published PageResponse<PlatformProblemSummary> places
                    # data[] and meta beside one another, without an items key.
                    status, body = 200, {"data": [], "meta": {"page": 1, "pageSize": 20, "total": 0, "hasNext": False}, "requestId": correlation}
                encoded = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("X-Request-Id", correlation)
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

        server = ThreadingHTTPServer(("127.0.0.1", 0), ContractHandler)
        thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True)
        thread.start()
        try:
            result = SMOKE.api_checks(server.server_port, accepted, host="localhost")
            self.assertEqual(result["authorizationHTTP"], {"missing": 401, "wrong": 401})
            self.assertEqual(result["emptyCatalogHTTP"], 200)
            self.assertEqual(len(requests), 4)
            self.assertEqual(len({correlation for _, correlation in requests}), 4)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=1)


if __name__ == "__main__":
    unittest.main()
