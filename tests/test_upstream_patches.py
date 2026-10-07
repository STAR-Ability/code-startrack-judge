"""Actual pinned-source staging and negative provenance/safety regressions."""

import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("upstream_patches", ROOT / "scripts/apply-upstream-patches.py")
PREPARER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREPARER)


class UpstreamPatchTests(unittest.TestCase):
    def setUp(self):
        (ROOT / ".local").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="upstream-patches-test-", dir=ROOT / ".local")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def test_unsafe_paths_are_rejected_before_export(self):
        for value in ("", ".", "../escape", "/absolute", "a/../b", "a//b", "a\\b", "https://host", ".git/config", "line\nfeed"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                PREPARER.safe_relative(value)

    def test_destination_cannot_overwrite_or_follow_symlink(self):
        existing = self.directory / "existing"
        existing.mkdir()
        with self.assertRaises(ValueError):
            PREPARER.destination_path(str(existing))
        link = self.directory / "link"
        link.symlink_to(self.directory, target_is_directory=True)
        with self.assertRaises(ValueError):
            PREPARER.destination_path(str(link / "new"))
        with self.assertRaises(ValueError):
            PREPARER.destination_path(str(ROOT / "tracked-build-output"))

    def test_changed_base_identity_is_rejected(self):
        component = next(item for item in PREPARER.upstream.load_components() if item["name"] == "go-judge")
        series = json.loads((ROOT / "patches/go-judge/series.json").read_text())
        series["baseCommit"] = "0" * 40
        with patch.object(PREPARER.json, "loads", return_value=series), self.assertRaises(ValueError):
            PREPARER.load_series(component)

    def test_changed_patch_bytes_are_rejected(self):
        component = next(item for item in PREPARER.upstream.load_components() if item["name"] == "go-judge")
        series = json.loads((ROOT / "patches/go-judge/series.json").read_text())
        series["patches"][0]["sha256"] = "0" * 64
        with patch.object(PREPARER.json, "loads", return_value=series), self.assertRaises(ValueError):
            PREPARER.load_series(component)

    def test_real_pinned_sources_have_required_exclusions_and_notices(self):
        # Offline cache availability is a deliberate prerequisite, never a
        # silent test skip or a moving-branch fetch inside validation.
        for name in PREPARER.COMPONENTS:
            with self.subTest(component=name):
                output = PREPARER.prepare(name, str(self.directory / name))
                evidence = json.loads((output / PREPARER.PROVENANCE_NAME).read_text())
                self.assertEqual(evidence["qualification"], "BUILD_INPUTS_ONLY")
                self.assertTrue((output / "LICENSE").is_file())
                self.assertFalse((output / ".git").exists())
                for record in evidence["inventory"]:
                    self.assertEqual(PREPARER.sha256((output / record["path"]).read_bytes()), record["sha256"])
                if name == "problemtools":
                    self.assertFalse((output / "support/viva").exists())
                    self.assertFalse(any(output.rglob("*.jar")))
                    self.assertEqual(evidence["unsupportedPackageExtensions"], [".viva"])
                    self.assertTrue((output / "support/default_validator/default_validator.cc").is_file())
                    fixture_count = len(list((output / "tests/default_validator_tests").glob("test_*")))
                    self.assertEqual(fixture_count, 24)
                    validator_checks = (output / "problemtools/checks/validators.py").read_text()
                    self.assertIn("No input format validators found", validator_checks)
                if name == "go-judge":
                    self.assertTrue((output / "seccomp/NOTICE").is_file())
                    workload_changes = {record["path"] for patch in evidence["patches"] if patch["path"].endswith("0003-workload-namespace-seccomp.patch") for record in patch["files"]}
                    for record in evidence["inventory"]:
                        if record["path"].startswith(("env/", "envexec/", "seccomp/")) and record["path"] not in workload_changes:
                            self.assertEqual(record["sha256"], record["sourceSha256"])
                    self.assertEqual((output / "seccomp/startrack-workload.yaml").read_bytes(), (ROOT / "docker/startrack-workload-seccomp.yaml").read_bytes())
                    main = (output / "cmd/go-judge/main.go").read_text()
                    self.assertNotIn('r.GET("/config"', main)
                    self.assertLess(main.index("r.Use(tokenAuth"), main.index('r.GET("/version"'))
                    self.assertNotIn('zap.String("token"', main)
                    self.assertNotIn('fmt.Sprintf("%+v", conf)', main)
                    self.assertNotIn("wsHandle.Register", main)
                if name == "go-judge-demo":
                    main = (output / "judger/main.go").read_text()
                    self.assertNotIn("ListenAndServe", main)
                    self.assertNotIn("net/http/pprof", main)
                    self.assertNotIn("zap.Any", (output / "judger/grpc.go").read_text())
                    for excluded in ("apigateway", "demoserver", "src", "package-lock.json"):
                        self.assertFalse((output / excluded).exists())

    def test_unrecorded_source_modification_fails_inventory(self):
        component = next(item for item in PREPARER.upstream.load_components() if item["name"] == "problemtools")
        series = PREPARER.load_series(component)
        stage = self.directory / "tampered"
        stage.mkdir()
        records = PREPARER.export_sources(component, series, PREPARER.upstream.cache_path("problemtools"), stage)
        PREPARER.apply_patches(series, stage)
        source = stage / "support/default_validator/default_validator.cc"
        source.write_bytes(source.read_bytes() + b"\n// unexpected mutation\n")
        with self.assertRaises(ValueError):
            PREPARER.audit_inputs(stage, component, series, records)

    def test_mode_only_source_modification_fails_inventory(self):
        component = next(item for item in PREPARER.upstream.load_components() if item["name"] == "problemtools")
        series = PREPARER.load_series(component)
        stage = self.directory / "mode-tampered"
        stage.mkdir()
        records = PREPARER.export_sources(component, series, PREPARER.upstream.cache_path("problemtools"), stage)
        PREPARER.apply_patches(series, stage)
        (stage / "support/default_grader/default_grader").chmod(0o644)
        with self.assertRaises(ValueError):
            PREPARER.audit_inputs(stage, component, series, records)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX FIFO support")
    def test_special_file_is_rejected_without_reading_content(self):
        stage = self.directory / "special-file"
        stage.mkdir()
        os.mkfifo(stage / "LICENSE")
        component = {"license": {"evidence": []}}
        series = {"includePaths": ["LICENSE"], "excludePaths": [], "patches": []}
        records = [{"path": "LICENSE", "sourceSha256": "0" * 64, "mode": "100644"}]
        with patch.object(Path, "read_bytes", side_effect=AssertionError("special file must not be read")):
            with self.assertRaises(ValueError):
                PREPARER.audit_inputs(stage, component, series, records)


if __name__ == "__main__":
    unittest.main()
