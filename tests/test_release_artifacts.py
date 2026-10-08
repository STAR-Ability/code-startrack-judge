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
    def test_candidate_guard_checks_actual_clean_git_identity(self):
        import subprocess
        with tempfile.TemporaryDirectory() as temporary, patch.object(RELEASE, "ROOT", Path(temporary).resolve()):
            root = Path(temporary).resolve()
            subprocess.run(["git", "init", "-q", str(root)], check=True, capture_output=True)
            subprocess.run(["git", "-C", str(root), "-c", "user.name=Candidate Test", "-c", "user.email=candidate@example.invalid",
                            "commit", "--allow-empty", "-qm", "synthetic candidate"], check=True, capture_output=True)
            commit = RELEASE.command(["git", "rev-parse", "HEAD"])
            self.assertEqual(RELEASE.candidate_commit(commit), commit)
            for value in (None, "a" * 39, "b" * 40):
                with self.subTest(value=value), self.assertRaises(RELEASE.Failure):
                    RELEASE.candidate_commit(value)
            (root / "unreviewed-source").write_text("synthetic dirty input")
            with self.assertRaises(RELEASE.Failure):
                RELEASE.candidate_commit(commit)

    def test_candidate_image_requires_exact_local_docker_id(self):
        identity = "sha256:" + "b" * 64
        image = {"Os": "linux", "Architecture": "amd64", "Id": identity,
                 "Config": {"Labels": {"org.opencontainers.image.revision": COMMIT,
                             "org.opencontainers.image.source": "https://github.com/" + RELEASE.REPOSITORY,
                             "org.opencontainers.image.licenses": "Apache-2.0"}}}
        with patch.object(RELEASE, "command", return_value=json.dumps([image])) as command:
            self.assertEqual(RELEASE.inspect_image(identity, COMMIT, candidate=True)["Id"], identity)
            command.assert_called_once_with(["docker", "image", "inspect", identity])
        for reference in ("startrack-candidate:local", RELEASE.IMAGE + "@" + identity, identity[:-1], None):
            with self.subTest(reference=reference), self.assertRaises(RELEASE.Failure):
                RELEASE.inspect_image(reference, COMMIT, candidate=True)
        for changed in ({**image, "Id": "sha256:" + "c" * 64}, {**image, "Architecture": "arm64"},
                        {**image, "Config": {"Labels": {"org.opencontainers.image.revision": "c" * 40}}}):
            with patch.object(RELEASE, "command", return_value=json.dumps([changed])), self.assertRaises(RELEASE.Failure):
                RELEASE.inspect_image(identity, COMMIT, candidate=True)

    def test_candidate_routing_has_no_official_or_registry_access(self):
        with tempfile.TemporaryDirectory() as temporary:
            arguments = ["release-artifacts.py", "candidate-sources-prepare", "--source-commit", COMMIT,
                         "--context", ".local/context", "--bundle", ".cache/sources", "--output", ".local/source-context"]
            with patch.object(RELEASE.sys, "argv", arguments), patch.object(RELEASE, "candidate_commit", return_value=COMMIT) as guard, \
                 patch.object(RELEASE, "official_commit") as official, patch.object(RELEASE, "registry_digest") as registry, \
                 patch.object(RELEASE, "output_path", return_value=Path(temporary)), patch.object(RELEASE, "prepare_sources") as prepare:
                self.assertEqual(RELEASE.main(), 0)
            self.assertEqual(guard.call_count, 2)
            official.assert_not_called()
            registry.assert_not_called()
            prepare.assert_called_once_with(".local/context", ".cache/sources", Path(temporary), COMMIT)
        for operation in ("target", "audit", "push", "finalize", "sources-prepare", "sources-audit", "sources-push", "sources-finalize"):
            with self.subTest(operation=operation), patch.object(RELEASE.sys, "argv", ["release-artifacts.py", operation]), \
                 patch.object(RELEASE, "official_commit", side_effect=RELEASE.Failure) as official, \
                 patch.object(RELEASE, "candidate_commit") as candidate, self.assertRaises(RELEASE.Failure):
                RELEASE.main()
            official.assert_called_once()
            candidate.assert_not_called()

    def test_candidate_identity_distinguishes_docker_index_from_oci_config(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            docker_id = "sha256:" + "b" * 64
            config_id = "sha256:" + "c" * 64
            metadata = directory / "input.json"
            metadata.write_text(json.dumps({"containerimage.config.digest": config_id, "containerimage.digest": docker_id}))
            result = RELEASE.candidate_image_identity({"Id": docker_id}, metadata, directory)
            self.assertEqual(result["imageDockerID"], docker_id)
            self.assertEqual(result["imageConfigID"], config_id)
            self.assertEqual(result["imageBuildDigest"], docker_id)
            self.assertEqual(result["imageConfigIdentity"], "BUILDKIT_METADATA_REQUIRES_LAYER_VERIFICATION")
            self.assertEqual(RELEASE.candidate_image_identity({"Id": docker_id}, None, None)["imageConfigID"], None)
            descriptor = {"digest": docker_id, "annotations": {"config.digest": config_id}}
            metadata.write_text(json.dumps({"containerimage.digest": docker_id}))
            result = RELEASE.candidate_image_identity({"Id": docker_id, "Descriptor": descriptor}, metadata, directory)
            self.assertEqual(result["imageConfigID"], config_id)
            self.assertEqual(result["imageConfigIdentity"], "DOCKER_DESCRIPTOR_REQUIRES_LAYER_VERIFICATION")
            with self.assertRaises(RELEASE.Failure):
                RELEASE.candidate_image_identity({"Id": docker_id, "Descriptor": {"digest": "sha256:" + "d" * 64}}, metadata, None)
            for value in ({"containerimage.config.digest": config_id},
                          {"containerimage.config.digest": config_id, "containerimage.digest": "sha256:" + "d" * 64},
                          {"containerimage.config.digest": config_id, "containerimage.digest": "unmeasured"}):
                metadata.write_text(json.dumps(value))
                with self.subTest(value=value), self.assertRaises(RELEASE.Failure):
                    RELEASE.candidate_image_identity({"Id": docker_id}, metadata, None)

    def test_candidate_source_evidence_cannot_be_promoted_or_mixed(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(RELEASE, "ROOT", Path(temporary).resolve()):
            root = Path(temporary).resolve()
            directory = root / ".local/sources"
            directory.mkdir(parents=True)
            (root / "validation-sources.lock.json").write_bytes(b"{}")
            (directory / "source-inventory.json").write_bytes(b"synthetic source inventory")
            (directory / "context-inventory.json").write_bytes(b"synthetic context inventory")
            context_sha = RELEASE.sha_file(directory / "context-inventory.json")
            record = {"schemaVersion": 1, "sourceRepository": RELEASE.REPOSITORY, "sourceCommit": COMMIT,
                      "imageRepository": None, "imageDockerID": "sha256:" + "b" * 64,
                      "imageConfigID": None, "imageConfigIdentity": "SEPARATE_LAYER_EVIDENCE_REQUIRED",
                      "artifactType": "corresponding-source", "imageDigest": None,
                      "sourceManifestSHA256": RELEASE.sha_file(root / "validation-sources.lock.json"),
                      "sourceInputInventorySHA256": RELEASE.sha_file(directory / "source-inventory.json"),
                      "contextInventorySHA256": context_sha, **RELEASE.candidate_status()}
            path = directory / "candidate-artifacts.json"
            path.write_text(json.dumps(record))
            with patch.object(RELEASE, "inspect_image", return_value={"Id": record["imageDockerID"]}) as inspect:
                self.assertEqual(RELEASE.verified_candidate_source_record(".local/sources", COMMIT, context_sha), record)
                inspect.assert_called_once_with(record["imageDockerID"], COMMIT, RELEASE.SOURCES, candidate=True)
            for name, value in (("sourceCommit", "c" * 40), ("imageRepository", RELEASE.SOURCES),
                                ("imageDigest", "sha256:" + "d" * 64), ("immutableImage", "synthetic"),
                                ("evidenceType", "OFFICIAL"), ("qualification", "QUALIFIED"),
                                ("deployment", "DEPLOYED"), ("publication", "PUBLISHED"),
                                ("artifactType", "service"), ("sourceManifestSHA256", "0" * 64),
                                ("contextInventorySHA256", "0" * 64), ("sourceInputInventorySHA256", "0" * 64)):
                path.write_text(json.dumps({**record, name: value}))
                with self.subTest(name=name), self.assertRaises(RELEASE.Failure):
                    RELEASE.verified_candidate_source_record(".local/sources", COMMIT, context_sha)
            path.write_text(json.dumps(record))
            with patch.object(RELEASE, "inspect_image", side_effect=RELEASE.Failure), self.assertRaises(RELEASE.Failure):
                RELEASE.verified_candidate_source_record(".local/sources", COMMIT, context_sha)
            (directory / "release-artifacts.json").write_text(json.dumps(record))
            with self.assertRaises(RELEASE.Failure):
                RELEASE.verified_source_record(".local/sources", COMMIT, context_sha)

    def test_candidate_source_audit_never_starts_or_publishes_carrier(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(RELEASE, "ROOT", Path(temporary).resolve()):
            root = Path(temporary).resolve()
            directory = root / ".local/evidence"
            directory.mkdir(parents=True)
            actual, retained, module, lock, digest = self.source_fixture(root)
            image = "sha256:" + "b" * 64
            container = "c" * 64
            with patch.object(RELEASE, "source_inputs", return_value=(module, lock, digest)), \
                 patch.object(RELEASE, "inspect_image", return_value={"Id": image}), \
                 patch.object(RELEASE, "command", side_effect=[container, ""]) as commands, \
                 patch.object(RELEASE, "read_source_archive", return_value=(actual, retained)), \
                 patch.object(RELEASE, "candidate_commit", return_value=COMMIT):
                RELEASE.audit_sources(image, directory, COMMIT, candidate=True)
            self.assertEqual(commands.call_args_list[0].args[0], ["docker", "create", "--network", "none", "--entrypoint", "/never-run", image])
            self.assertEqual(commands.call_args_list[1].args[0], ["docker", "rm", "--volumes", container])
            record = json.loads((directory / "candidate-artifacts.json").read_bytes())
            self.assertTrue(all(record[name] == value for name, value in RELEASE.candidate_status().items()))
            self.assertEqual(record["imageDockerID"], image)
            self.assertIsNone(record["imageConfigID"])
            self.assertIsNone(record["imageDigest"])
            self.assertFalse((directory / "release-artifacts.json").exists())
            self.assertIn("candidate-artifacts.json", (directory / "SHA256SUMS").read_text())

    def test_candidate_service_audit_binds_metadata_and_emits_no_ci_claim(self):
        for variant in ("valid", "metadata_drift", "source_changed"):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as temporary, \
                 patch.object(RELEASE, "ROOT", Path(temporary).resolve()):
                root = Path(temporary).resolve()
                directory = self.image_fixture(root)
                sources = root / ".local/sources"
                sources.mkdir()
                source_record = {"imageConfigID": "sha256:" + "c" * 64, **RELEASE.candidate_status()}
                image = "sha256:" + "b" * 64
                metadata = root / ".local/build.json"
                metadata.write_text(json.dumps({"containerimage.config.digest": image if variant != "metadata_drift" else "sha256:" + "d" * 64}))
                def command(arguments, **kwargs):
                    if arguments[:2] == ["docker", "create"]:
                        return "e" * 64
                    return "synthetic build observation"
                with patch.object(RELEASE, "inspect_image", return_value={"Id": image}), \
                     patch.object(RELEASE, "command", side_effect=command), \
                     patch.object(RELEASE, "verified_candidate_source_record", return_value=source_record) as verifier, \
                     patch.object(RELEASE, "candidate_commit", side_effect=RELEASE.Failure if variant == "source_changed" else None, return_value=COMMIT), \
                     patch.dict(os.environ, {"GITHUB_RUN_ID": "synthetic-ci", "RELEASE_VALIDATION_RUN": "synthetic-validation", "GITHUB_SHA": "f" * 40}):
                    if variant == "valid":
                        RELEASE.audit(image, directory, COMMIT, metadata, ".local/sources", candidate=True)
                    else:
                        with self.assertRaises(RELEASE.Failure):
                            RELEASE.audit(image, directory, COMMIT, metadata, ".local/sources", candidate=True)
                if variant != "valid":
                    self.assertFalse((directory / "candidate-artifacts.json").exists())
                    continue
                verifier.assert_called_once_with(".local/sources", COMMIT, RELEASE.sha_file(directory / "provenance/context-inventory.json"))
                record = json.loads((directory / "candidate-artifacts.json").read_bytes())
                self.assertTrue(all(record[name] == value for name, value in RELEASE.candidate_status().items()))
                self.assertIsNone(record["ciRun"])
                self.assertIsNone(record["sourceValidationRun"])
                self.assertIsNone(record["workflowDefinitionCommit"])
                self.assertEqual(record["correspondingSource"], source_record)
                self.assertEqual(record["inventoryScopes"]["wholeImageSBOM"], "SEPARATE_EVIDENCE_REQUIRED")
                self.assertFalse((directory / "release-artifacts.json").exists())

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
        lock = {"components": [], "supplemental_licenses": []}
        for name in ("go-judge", "problemtools", "go-sandbox"):
            patch_path = f"patches/{name}/0001-inert.patch"
            descriptor = f"patches/{name}/series.json"
            patch_body = ("synthetic inert " + name + " diff\n").encode()
            patch = {"path": patch_path, "sha256": checksum(patch_body)}
            component = {"name": name, "repository": "https://example.invalid/" + name,
                         "commit": "a" * 40, "patches": [patch]}
            series = {"schemaVersion": 1, "component": name, "repository": component["repository"],
                      "baseCommit": component["commit"], "patches": component["patches"]}
            if name == "go-sandbox":
                component.update({"version": "v0.0.1", "source_assembly": {"policy": "verified-go-module-vendor", "descriptor": descriptor}})
                series.update({"module": "github.com/criyle/go-sandbox", "baseVersion": component["version"]})
                lock["supplemental_licenses"].append(component)
            else:
                lock["components"].append(component)
            for relative, body in ((patch_path, patch_body), (descriptor, json.dumps(series).encode())):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(body)
                path.chmod(0o644)
                add("context/" + relative, body)
        (root / "upstream.lock.json").write_bytes(json.dumps(lock).encode())
        add("context/provenance/upstream.lock.json", (root / "upstream.lock.json").read_bytes())
        for name in ("toolchain.lock.json", "validation-tools.lock.json", "validation-sources.lock.json"):
            (root / name).write_bytes(b"{}")
            add("context/provenance/" + name, b"{}")
        for name in ("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md"):
            (root / name).write_bytes(name.encode())
            add("context/legal/" + name, name.encode())
        def records(values):
            return [{"path": name, "sizeBytes": len(body), "sha256": checksum(body), "mode": "0644"} for name, body in sorted(values.items())]
        context = {"schemaVersion": 1, "gitHead": COMMIT, "releaseCommit": COMMIT, "sourceState": "CLEAN", "workingTreeStatus": "", "qualification": "UNQUALIFIED",
                   "finalGitHead": COMMIT, "finalWorkingTreeStatus": "",
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
        with tempfile.TemporaryDirectory() as temporary, patch.object(RELEASE, "ROOT", Path(temporary).resolve()):
            actual, retained, module, lock, digest = self.source_fixture(Path(temporary).resolve())
            verified = RELEASE.verify_source_archive(actual, retained, COMMIT, module, lock, digest)
            self.assertEqual(verified["archiveCount"], 1)
            for variant in ("missing", "tampered", "extra", "dirty", "wrong_commit", "wrong_lock", "missing_patch", "changed_patch_descriptor"):
                changed, held = copy.deepcopy(actual), copy.deepcopy(retained)
                if variant == "missing":
                    del changed["validation-sources/archives/fixture.tar.gz"]
                elif variant == "tampered":
                    changed["validation-sources/archives/fixture.tar.gz"]["sha256"] = "0" * 64
                elif variant == "extra":
                    changed["unexpected"] = {"path": "unexpected", "sha256": "0" * 64, "sizeBytes": 0, "mode": "0644"}
                elif variant == "wrong_lock":
                    digest = "0" * 64
                elif variant in ("missing_patch", "changed_patch_descriptor"):
                    context = json.loads(held["context/provenance/context-inventory.json"])
                    name = "patches/problemtools/series.json"
                    if variant == "missing_patch":
                        context["inventory"] = [entry for entry in context["inventory"] if entry["path"] != name]
                        del changed["context/" + name]
                    else:
                        for entry in context["inventory"]:
                            if entry["path"] == name:
                                entry["sha256"] = "0" * 64
                        changed["context/" + name]["sha256"] = "0" * 64
                    held["context/provenance/context-inventory.json"] = json.dumps(context).encode()
                    # Keep the outer source inventory internally consistent;
                    # only the independently reviewed ROOT patch set can reject it.
                    changed["context/provenance/context-inventory.json"].update({"sha256": checksum(held["context/provenance/context-inventory.json"]),
                                                                             "sizeBytes": len(held["context/provenance/context-inventory.json"])})
                    source_inventory = json.loads(held["source-inventory.json"])
                    source_inventory["inventory"] = [entry for key, entry in sorted(changed.items()) if key != "source-inventory.json"]
                    held["source-inventory.json"] = json.dumps(source_inventory).encode()
                else:
                    context = json.loads(held["context/provenance/context-inventory.json"])
                    context["sourceState" if variant == "dirty" else "gitHead"] = "DIRTY" if variant == "dirty" else "b" * 40
                    held["context/provenance/context-inventory.json"] = json.dumps(context).encode()
                with self.subTest(variant=variant), self.assertRaises(RELEASE.Failure):
                    RELEASE.verify_source_archive(changed, held, COMMIT, module, lock, digest)

    def test_source_archive_rejects_self_consistent_forged_owned_source(self):
        for variant in ("valid", "changed", "missing", "extra", "wrong_final_head", "dirty_final_tree"):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as temporary, \
                 patch.object(RELEASE, "ROOT", Path(temporary).resolve()):
                root = Path(temporary).resolve()
                actual, retained, module, lock, digest = self.source_fixture(root)
                source = root / "cmd/judge-service/main.go"
                source.parent.mkdir(parents=True)
                source.write_bytes(b"synthetic reviewed source")
                source.chmod(0o644)
                name = "service/cmd/judge-service/main.go"
                body = b"synthetic forged source" if variant == "changed" else source.read_bytes()
                context = json.loads(retained["context/provenance/context-inventory.json"])
                if variant != "missing":
                    entry = {"path": name, "sha256": checksum(body), "sizeBytes": len(body), "mode": "0644"}
                    context["inventory"].append(entry)
                    actual["context/" + name] = {**entry, "path": "context/" + name}
                if variant == "extra":
                    entry = {"path": "service/unreviewed.go", "sha256": checksum(b"extra"), "sizeBytes": 5, "mode": "0644"}
                    context["inventory"].append(entry)
                    actual["context/" + entry["path"]] = {**entry, "path": "context/" + entry["path"]}
                if variant == "wrong_final_head":
                    context["finalGitHead"] = "b" * 40
                if variant == "dirty_final_tree":
                    context["finalWorkingTreeStatus"] = " M synthetic.go"
                retained["context/provenance/context-inventory.json"] = json.dumps(context).encode()
                actual["context/provenance/context-inventory.json"].update({"sha256": checksum(retained["context/provenance/context-inventory.json"]),
                                                                         "sizeBytes": len(retained["context/provenance/context-inventory.json"])})
                inventory = json.loads(retained["source-inventory.json"])
                inventory["inventory"] = [entry for key, entry in sorted(actual.items()) if key != "source-inventory.json"]
                retained["source-inventory.json"] = json.dumps(inventory).encode()
                actual["source-inventory.json"].update({"sha256": checksum(retained["source-inventory.json"]), "sizeBytes": len(retained["source-inventory.json"])})
                if variant == "valid":
                    self.assertEqual(RELEASE.verify_source_archive(actual, retained, COMMIT, module, lock, digest)["archiveCount"], 1)
                else:
                    with self.assertRaises(RELEASE.Failure):
                        RELEASE.verify_source_archive(actual, retained, COMMIT, module, lock, digest)

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
        context = {"schemaVersion": 1, "gitHead": COMMIT, "releaseCommit": COMMIT, "sourceState": "CLEAN", "workingTreeStatus": "", "qualification": "UNQUALIFIED", "inventory": entries,
                   "finalGitHead": COMMIT, "finalWorkingTreeStatus": ""}
        write(directory / "provenance/context-inventory.json", json.dumps(context).encode())
        write(root / "opt/startrack/provenance/context-inventory.json", json.dumps(context).encode())
        write(directory / "provenance/problemtools-wheel.sha256", (checksum(wheel.read_bytes()) + "  /build/dist/" + wheel.name + "\n").encode())
        write(directory / "provenance/problemtools-wheel-audit.json", json.dumps(RELEASE.wheel_audit_module().capture(wheel, root)).encode())
        write(directory / "provenance" / RELEASE.wheel_audit_module().WHEEL_NAME, wheel.read_bytes())
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
