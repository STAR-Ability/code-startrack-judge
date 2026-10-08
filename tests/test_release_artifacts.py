"""Reject unsafe official publication and tampered distribution evidence."""

import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import tarfile
import tempfile
import types
import unittest
from unittest.mock import patch
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("release_artifacts", ROOT / "scripts/release-artifacts.py")
RELEASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RELEASE)
COMMIT = "a" * 40


def checksum(body):
    return hashlib.sha256(body).hexdigest()


def response(body, headers=None):
    value = io.BytesIO(body)
    value.headers = headers or {}
    return value


class ReleaseArtifactTests(unittest.TestCase):
    def test_official_guard_requires_clean_exact_protected_main(self):
        valid = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": RELEASE.REPOSITORY,
                 "GITHUB_REF": "refs/heads/main", "GITHUB_REF_PROTECTED": "true",
                 "RELEASE_SOURCE_COMMIT": COMMIT}
        self.assertEqual(RELEASE.guard(valid, COMMIT, ""), COMMIT)
        for key, value in (("GITHUB_ACTIONS", "false"), ("GITHUB_REPOSITORY", "fork/repo"),
                           ("GITHUB_REF", "refs/heads/dev"), ("GITHUB_REF_PROTECTED", "false"),
                           ("RELEASE_SOURCE_COMMIT", "a" * 39), ("RELEASE_SOURCE_COMMIT", "b" * 40)):
            with self.subTest(key=key), self.assertRaises(RELEASE.Failure):
                RELEASE.guard({**valid, key: value}, COMMIT, "")
        with self.assertRaises(RELEASE.Failure):
            RELEASE.guard(valid, COMMIT, " M source.go")

    def test_registry_only_manifest_404_means_absent(self):
        credentials = {"GITHUB_ACTOR": "fixture", "REGISTRY_TOKEN": "EXAMPLE_TEST_ONLY_TOKEN"}
        body = b'{"schemaVersion":2}'
        digest = "sha256:" + checksum(body)
        opener = types.SimpleNamespace(open=unittest.mock.Mock(side_effect=[response(b'{"token":"fixture"}'), response(body, {"Docker-Content-Digest": digest})]))
        with patch.dict(os.environ, credentials), patch.object(RELEASE.urllib.request, "build_opener", return_value=opener):
            self.assertEqual(RELEASE.registry_digest(COMMIT, RELEASE.SOURCES), digest)
        self.assertIn("code-startrack-judge-sources", opener.open.call_args.args[0].full_url)
        for code in (401, 403, 429, 500):
            opener.open.side_effect = [response(b'{"token":"fixture"}'), urllib.error.HTTPError("https://ghcr.io", code, "fixture", {}, None)]
            with self.subTest(code=code), patch.dict(os.environ, credentials), patch.object(RELEASE.urllib.request, "build_opener", return_value=opener), self.assertRaises(RELEASE.Failure):
                RELEASE.registry_digest(COMMIT)
        opener.open.side_effect = [response(b'{"token":"fixture"}'), urllib.error.HTTPError("https://ghcr.io", 404, "fixture", {}, None)]
        with patch.dict(os.environ, credentials), patch.object(RELEASE.urllib.request, "build_opener", return_value=opener):
            self.assertIsNone(RELEASE.registry_digest(COMMIT))
        opener.open.side_effect = [urllib.error.HTTPError("https://ghcr.io", 404, "fixture", {}, None)]
        with patch.dict(os.environ, credentials), patch.object(RELEASE.urllib.request, "build_opener", return_value=opener), self.assertRaises(urllib.error.HTTPError):
            RELEASE.registry_digest(COMMIT)

    def test_registry_rejects_digest_mismatch_redirects_and_other_hosts(self):
        opener = types.SimpleNamespace(open=unittest.mock.Mock(side_effect=[response(b'{"token":"fixture"}'), response(b"tampered", {"Docker-Content-Digest": "sha256:" + "0" * 64})]))
        with patch.dict(os.environ, {"GITHUB_ACTOR": "fixture", "REGISTRY_TOKEN": "EXAMPLE_TEST_ONLY_TOKEN"}), patch.object(RELEASE.urllib.request, "build_opener", return_value=opener), self.assertRaises(RELEASE.Failure):
            RELEASE.registry_digest(COMMIT)
        with self.assertRaises(RELEASE.Failure):
            RELEASE.NoRedirect().redirect_request(None, None, 307, "fixture", {}, "https://other.example")
        with self.assertRaises(RELEASE.Failure):
            RELEASE.registry_digest(COMMIT, "ghcr.io/other/repo")

    def test_outputs_cannot_escape_or_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(RELEASE, "ROOT", Path(temporary).resolve()):
            root = Path(temporary).resolve()
            (root / ".local").mkdir()
            fresh = RELEASE.output_path(".local/evidence", fresh=True)
            self.assertTrue(fresh.is_dir())
            with self.assertRaises(RELEASE.Failure):
                RELEASE.output_path(".local/evidence", fresh=True)
            with self.assertRaises(RELEASE.Failure):
                RELEASE.output_path("docs/evidence", fresh=True)
            (root / ".local/link").symlink_to(root / ".local/evidence")
            with self.assertRaises(RELEASE.Failure):
                RELEASE.output_path(".local/link")
            (fresh / "secret").symlink_to(root / "missing")
            with self.assertRaises(RELEASE.Failure):
                RELEASE.files(fresh)

    def test_image_identity_and_source_artifact_labels(self):
        image = {"Os": "linux", "Architecture": "amd64", "Id": "sha256:" + "b" * 64,
                 "Config": {"Labels": {"org.opencontainers.image.revision": COMMIT,
                             "org.opencontainers.image.source": "https://github.com/" + RELEASE.REPOSITORY,
                             "org.opencontainers.image.licenses": "Apache-2.0", "io.startrack.artifact": "corresponding-source"}}}
        with patch.object(RELEASE, "command", return_value=json.dumps([image])):
            self.assertEqual(RELEASE.inspect_image(RELEASE.SOURCES + ":git-" + COMMIT, COMMIT, RELEASE.SOURCES)["Id"], image["Id"])
        for value in ({**image, "Architecture": "arm64"}, {**image, "Config": {"Labels": {}}}):
            with patch.object(RELEASE, "command", return_value=json.dumps([value])), self.assertRaises(RELEASE.Failure):
                RELEASE.inspect_image(RELEASE.IMAGE + ":git-" + COMMIT, COMMIT)
        with self.assertRaises(RELEASE.Failure):
            RELEASE.inspect_image("example.org/repo:git-" + COMMIT, COMMIT)

    def test_source_tar_rejects_links_traversal_and_special_files(self):
        for name, kind in (("../escape", tarfile.REGTYPE), ("/absolute", tarfile.REGTYPE),
                           ("context/link", tarfile.SYMTYPE), ("context/link", tarfile.LNKTYPE),
                           ("context/fifo", tarfile.FIFOTYPE)):
            body = io.BytesIO()
            with tarfile.open(fileobj=body, mode="w") as archive:
                member = tarfile.TarInfo(name)
                member.type = kind
                archive.addfile(member)
            process = types.SimpleNamespace(stdout=io.BytesIO(body.getvalue()), wait=lambda **kwargs: 0, poll=lambda: 0)
            with self.subTest(name=name, kind=kind), patch.object(RELEASE.subprocess, "Popen", return_value=process), self.assertRaises(RELEASE.Failure):
                RELEASE.read_source_archive("c" * 64)

    def source_fixture(self, root):
        bodies = {}
        def add(name, body):
            bodies[name] = body
        for name in ("upstream.lock.json", "toolchain.lock.json", "validation-tools.lock.json", "validation-sources.lock.json"):
            (root / name).write_bytes(b"{}")
            add("context/provenance/" + name, b"{}")
        for name in ("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md"):
            (root / name).write_bytes(name.encode())
            add("context/legal/" + name, name.encode())
        def records(values):
            return [{"path": name, "sizeBytes": len(body), "sha256": checksum(body), "mode": "0644"} for name, body in sorted(values.items())]
        context = {"schemaVersion": 1, "gitHead": COMMIT, "releaseCommit": COMMIT, "sourceState": "CLEAN", "workingTreeStatus": "", "qualification": "UNQUALIFIED",
                   "inventory": records({name.removeprefix("context/"): body for name, body in bodies.items()})}
        add("context/provenance/context-inventory.json", json.dumps(context).encode())
        source_lock_digest = checksum(b"{}")
        add("validation-sources/archives/fixture.tar.gz", b"corresponding source")
        add("validation-sources/inventory.json", (json.dumps({"schemaVersion": 1, "lockSha256": source_lock_digest, "platform": "linux/amd64"}, indent=2) + "\n").encode())
        source_inventory = {"schemaVersion": 1, "sourceCommit": COMMIT, "sourceManifestSHA256": source_lock_digest, "inventory": records(bodies)}
        add("source-inventory.json", json.dumps(source_inventory).encode())
        lock = {"platform": "linux/amd64", "sourceArchives": [{"filename": "fixture.tar.gz", "sizeBytes": len(b"corresponding source"), "sha256": checksum(b"corresponding source")}], "signedMetadata": []}
        module = types.SimpleNamespace(artifact_groups=lambda lock: [("archives", lock["sourceArchives"][0])])
        actual = {entry["path"]: entry for entry in records(bodies)}
        retained = {name: bodies[name] for name in ("source-inventory.json", "context/provenance/context-inventory.json")}
        return actual, retained, module, lock, source_lock_digest

    def test_source_archive_requires_complete_exact_bound_inventories(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(RELEASE, "ROOT", Path(temporary)):
            actual, retained, module, lock, digest = self.source_fixture(Path(temporary))
            verified = RELEASE.verify_source_archive(actual, retained, COMMIT, module, lock, digest)
            self.assertEqual(verified["archiveCount"], 1)
            for variant in ("missing", "tampered", "extra", "dirty", "wrong_commit", "wrong_lock"):
                changed, held = copy.deepcopy(actual), copy.deepcopy(retained)
                if variant == "missing":
                    del changed["validation-sources/archives/fixture.tar.gz"]
                elif variant == "tampered":
                    changed["validation-sources/archives/fixture.tar.gz"]["sha256"] = "0" * 64
                elif variant == "extra":
                    changed["unexpected"] = {"path": "unexpected", "sha256": "0" * 64, "sizeBytes": 0, "mode": "0644"}
                elif variant == "wrong_lock":
                    digest = "0" * 64
                else:
                    context = json.loads(held["context/provenance/context-inventory.json"])
                    context["sourceState" if variant == "dirty" else "gitHead"] = "DIRTY" if variant == "dirty" else "b" * 40
                    held["context/provenance/context-inventory.json"] = json.dumps(context).encode()
                with self.subTest(variant=variant), self.assertRaises(RELEASE.Failure):
                    RELEASE.verify_source_archive(changed, held, COMMIT, module, lock, digest)

    def test_signature_failure_stops_official_source_preparation(self):
        module = types.SimpleNamespace(read_lock=lambda path: ({}, "a" * 64), check=lambda *args: None,
                                       signatures=unittest.mock.Mock(side_effect=ValueError("bad signature")))
        with patch.object(RELEASE, "sources_module", return_value=module), patch.object(RELEASE.sys, "platform", "linux"), self.assertRaises(ValueError):
            RELEASE.source_inputs()
        module.signatures.assert_called_once()

    def image_fixture(self, root):
        directory = root / ".local/evidence"
        def write(path, body):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
        for name in RELEASE.PROVENANCE:
            write(directory / "provenance" / name, b"{}")
        entries = []
        for name in ("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md"):
            body = name.encode()
            write(root / name, body)
            write(directory / "legal" / name, body)
            entries.append({"path": "legal/" + name, "sizeBytes": len(body), "sha256": checksum(body), "mode": "0644"})
        for name in RELEASE.CONFIGS:
            body = name.encode()
            write(root / "docker" / name, body)
            write(directory / name, body)
            entries.append({"path": "docker/" + name, "sizeBytes": len(body), "sha256": checksum(body), "mode": "0644"})
        tools = {"platform": "linux/amd64", "pythonVersion": "3.11.15", "baselineAnchors": [{"name": "libbase:amd64", "version": "1", "architecture": "amd64"}], "debs": [],
                 "wheels": [{"name": "fixture-lib", "version": "2"}], "baselinePythonPackages": [{"name": "pip", "version": "3"}]}
        for name in ("upstream.lock.json", "toolchain.lock.json", "validation-tools.lock.json", "validation-sources.lock.json"):
            body = json.dumps(tools).encode() if name == "validation-tools.lock.json" else b"{}"
            write(root / name, body)
            write(directory / "provenance" / name, body)
        write(directory / "provenance/generated-dependencies.json", json.dumps({"schemaVersion": 1, "scope": "BUILD_INPUTS_ONLY", "generatedDependencyInputs": {"service": {}, "go-judge": {}}}).encode())
        from test_problemtools_wheel_audit import WheelEvidenceTests
        wheel = WheelEvidenceTests().fixture(root)
        write(directory / "provenance/problemtools-sources.json", (root / "opt/startrack/provenance/problemtools-sources.json").read_bytes())
        for name in RELEASE.PROVENANCE:
            if name not in RELEASE.BUILD_OUTPUT_PROVENANCE:
                body = (directory / "provenance" / name).read_bytes()
                entries.append({"path": "provenance/" + name, "sizeBytes": len(body), "sha256": checksum(body), "mode": "0644"})
        fixture_body = b"inert original fixture bytes\n"
        fixture_name = "test_simple_ac/user.out"
        write(directory / "qualification/default_validator_tests" / fixture_name, fixture_body)
        entries.append({"path": "upstream/problemtools/tests/default_validator_tests/" + fixture_name,
                        "sizeBytes": len(fixture_body), "sha256": checksum(fixture_body), "mode": "0644"})
        for package in ("hello", "different"):
            body = ("inert original " + package + " metadata\n").encode()
            write(directory / "qualification/upstream_examples" / package / "problem.yaml", body)
            entries.append({"path": "upstream/problemtools/examples/" + package + "/problem.yaml",
                            "sizeBytes": len(body), "sha256": checksum(body), "mode": "0644"})
        context = {"schemaVersion": 1, "gitHead": COMMIT, "releaseCommit": COMMIT, "sourceState": "CLEAN", "workingTreeStatus": "", "qualification": "UNQUALIFIED", "inventory": entries}
        write(directory / "provenance/context-inventory.json", json.dumps(context).encode())
        write(root / "opt/startrack/provenance/context-inventory.json", json.dumps(context).encode())
        write(directory / "provenance/problemtools-wheel.sha256", (checksum(wheel.read_bytes()) + "  /build/dist/" + wheel.name + "\n").encode())
        write(directory / "provenance/problemtools-wheel-audit.json", json.dumps(RELEASE.wheel_audit_module().capture(wheel, root)).encode())
        shutil.copytree(root / "usr", directory / "installed/usr")
        write(directory / "provenance/validation-tools-installed.json", json.dumps({"schemaVersion": 1, "lockSha256": RELEASE.sha_file(root / "validation-tools.lock.json"), "platform": "linux/amd64", "pythonVersion": "3.11.15", "debianPackages": tools["baselineAnchors"], "pythonPackages": tools["wheels"] + tools["baselinePythonPackages"]}).encode())
        write(directory / "provenance/python-packages.json", json.dumps([{"name": "fixture_lib", "version": "2"}, {"name": "pip", "version": "3"}, {"name": "problemtools", "version": "1.20260907"}]).encode())
        write(directory / "provenance/os-packages.tsv", b"libbase:amd64\t1\tamd64\n")
        binaries = {"/usr/local/libexec/startrack/" + name: directory / "bin" / name for name in RELEASE.BINARIES if name not in ("default_validator", "startrack-checker-launcher")}
        binaries.update({"/opt/startrack/libexec/" + name: directory / "helpers" / name for name in ("default_validator", "default_grader", "problemtools-bridge.py")})
        binaries["/opt/startrack/bin/startrack-runtime-matrix"] = directory / "tools/startrack-runtime-matrix"
        binaries["/opt/startrack/bin/startrack-import-capacity"] = directory / "tools/startrack-import-capacity"
        binaries["/usr/local/bin/startrack-checker-launcher"] = directory / "bin/startrack-checker-launcher"
        for name, path in binaries.items():
            write(path, path.name.encode())
        write(directory / "provenance/binaries.sha256", "".join(checksum(path.name.encode()) + "  " + name + "\n" for name, path in binaries.items()).encode())
        write(root / "migrations/000001_initial.up.sql", b"fixture migration")
        write(directory / "migrations/000001_initial.up.sql", b"fixture migration")
        write(root / "docs/contracts/v0.2/manifest.json", b"{}")
        write(root / "docs/releases/state.json", json.dumps({"repositoryMigrationLevel": 1, "contractVersion": "0.2.0", "apiGeneration": "/internal/v2", "contractPath": "docs/contracts/v0.2"}).encode())
        return directory

    def test_actual_image_audit_rejects_legal_security_inventory_binary_and_history_drift(self):
        for variant in ("valid", "license", "extra_legal", "profile", "python", "os", "binary", "missing_binary",
                        "capacity_libexec", "capacity_tool", "missing_capacity_libexec", "missing_capacity_tool", "missing_capacity_checksum", "diverged_capacity",
                        "migration", "dirty_context", "provenance_generated", "provenance_source", "provenance_vendor", "missing_provenance_entry", "wheel_receipt", "installed_payload", "checker_fixture_changed", "checker_fixture_extra", "checker_fixture_missing",
                        "installed_missing_baseline", "installed_changed_baseline", "installed_extra", "installed_duplicate_baseline", "installed_duplicate_os"):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as temporary, patch.object(RELEASE, "ROOT", Path(temporary).resolve()):
                directory = self.image_fixture(Path(temporary).resolve())
                if variant == "valid":
                    self.assertEqual(RELEASE.verify_extracted(directory, COMMIT)["migrationLevel"], 1)
                    continue
                if variant == "license":
                    (directory / "legal/LICENSE").write_bytes(b"different license")
                elif variant == "extra_legal":
                    (directory / "legal/unrecorded").write_bytes(b"extra")
                elif variant == "profile":
                    (directory / "startrack-v02.seccomp.json").write_bytes(b"unreviewed")
                elif variant == "python":
                    value = json.loads((directory / "provenance/python-packages.json").read_bytes())
                    value.append({"name": "unreviewed", "version": "1"})
                    (directory / "provenance/python-packages.json").write_text(json.dumps(value))
                elif variant == "os":
                    (directory / "provenance/os-packages.tsv").write_bytes(b"libbase:amd64\t2\tamd64\n")
                elif variant == "binary":
                    (directory / "tools/startrack-runtime-matrix").write_bytes(b"changed second copy")
                elif variant == "missing_binary":
                    (directory / "bin/go-judge").unlink()
                elif variant in ("capacity_libexec", "capacity_tool"):
                    branch = "bin" if variant == "capacity_libexec" else "tools"
                    (directory / branch / "startrack-import-capacity").write_bytes(b"changed capacity binary")
                elif variant in ("missing_capacity_libexec", "missing_capacity_tool"):
                    branch = "bin" if variant == "missing_capacity_libexec" else "tools"
                    (directory / branch / "startrack-import-capacity").unlink()
                elif variant == "missing_capacity_checksum":
                    path = directory / "provenance/binaries.sha256"
                    path.write_text("".join(line for line in path.read_text().splitlines(keepends=True)
                                            if "/opt/startrack/bin/startrack-import-capacity" not in line))
                elif variant == "diverged_capacity":
                    body = b"self-consistent different capacity binary"
                    (directory / "tools/startrack-import-capacity").write_bytes(body)
                    path = directory / "provenance/binaries.sha256"
                    path.write_text("".join(checksum(body) + "  /opt/startrack/bin/startrack-import-capacity\n"
                                            if "/opt/startrack/bin/startrack-import-capacity" in line else line
                                            for line in path.read_text().splitlines(keepends=True)))
                elif variant == "migration":
                    (directory / "migrations/000001_initial.up.sql").write_bytes(b"rewrite")
                elif variant.startswith("provenance_"):
                    name = {"provenance_generated": "generated-dependencies.json", "provenance_source": "problemtools-sources.json", "provenance_vendor": "go-sandbox-vendor-patches.json"}[variant]
                    (directory / "provenance" / name).write_text('{"tampered":true}')
                elif variant == "missing_provenance_entry":
                    path = directory / "provenance/context-inventory.json"
                    context = json.loads(path.read_bytes())
                    context["inventory"] = [entry for entry in context["inventory"] if entry["path"] != "provenance/generated-dependencies.json"]
                    path.write_text(json.dumps(context))
                elif variant == "wheel_receipt":
                    path = directory / "provenance/problemtools-wheel-audit.json"
                    receipt = json.loads(path.read_bytes())
                    receipt["wheelSHA256"] = "0" * 64
                    path.write_text(json.dumps(receipt))
                elif variant == "installed_payload":
                    (directory / "installed/usr/local/lib/python3.11/site-packages/problemtools/__init__.py").write_bytes(b"tampered")
                elif variant.startswith("checker_fixture_"):
                    path = directory / "qualification/default_validator_tests/test_simple_ac/user.out"
                    if variant == "checker_fixture_changed":
                        path.write_bytes(b"changed fixture")
                    elif variant == "checker_fixture_extra":
                        (path.parent / "unexpected").write_bytes(b"extra fixture")
                    else:
                        path.unlink()
                elif variant.startswith("installed_"):
                    path = directory / "provenance/validation-tools-installed.json"
                    value = json.loads(path.read_bytes())
                    if variant == "installed_missing_baseline":
                        value["pythonPackages"] = [entry for entry in value["pythonPackages"] if entry["name"] != "pip"]
                    elif variant == "installed_changed_baseline":
                        value["pythonPackages"][-1]["version"] = "unreviewed"
                    elif variant == "installed_extra":
                        value["pythonPackages"].append({"name": "unreviewed", "version": "1"})
                    elif variant == "installed_duplicate_baseline":
                        value["pythonPackages"].append({"name": "PIP", "version": "3"})
                    else:
                        value["debianPackages"].append(dict(value["debianPackages"][0]))
                    path.write_text(json.dumps(value))
                else:
                    context = json.loads((directory / "provenance/context-inventory.json").read_bytes())
                    context["sourceState"] = "DIRTY"
                    (directory / "provenance/context-inventory.json").write_text(json.dumps(context))
                with self.assertRaises(RELEASE.Failure):
                    RELEASE.verify_extracted(directory, COMMIT)

    def test_image_push_requires_existing_source_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            identity = "sha256:" + "b" * 64
            (directory / "release-artifacts.json").write_text(json.dumps({"sourceCommit": COMMIT, "imageRepository": RELEASE.IMAGE, "imageConfigID": identity}))
            with patch.object(RELEASE, "official_commit", return_value=COMMIT), patch.object(RELEASE, "registry_digest", return_value=None), patch.object(RELEASE, "output_path", return_value=directory), patch.object(RELEASE, "inspect_image", return_value={"Id": identity}), patch.object(RELEASE, "verify_extracted"), patch.object(RELEASE, "command") as command, patch.object(RELEASE.sys, "argv", ["release-artifacts.py", "push", "--image", RELEASE.IMAGE + ":git-" + COMMIT, "--output", ".local/evidence"]), self.assertRaises(RELEASE.Failure):
                RELEASE.main()
            command.assert_not_called()

    def test_existing_commit_tag_cannot_be_overwritten(self):
        with patch.object(RELEASE, "official_commit", return_value=COMMIT), patch.object(RELEASE, "registry_digest", return_value="sha256:" + "b" * 64), patch.object(RELEASE, "command") as command, patch.object(RELEASE.sys, "argv", ["release-artifacts.py", "sources-push", "--image", RELEASE.SOURCES + ":git-" + COMMIT, "--output", ".local/evidence"]), self.assertRaises(RELEASE.Failure):
            RELEASE.main()
        command.assert_not_called()


if __name__ == "__main__":
    unittest.main()
