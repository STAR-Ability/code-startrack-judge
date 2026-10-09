"""Portable rejection checks for the shared-host smoke launcher; no Linux claim."""

import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import threading
import unittest
import uuid
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("bounded_smoke", ROOT / "scripts/linux-bounded-smoke.py")
SMOKE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SMOKE)


class BoundedSmokeTests(unittest.TestCase):
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
            result = SMOKE.api_checks(server.server_port, accepted)
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
