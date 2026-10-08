"""Image source carriers retain locked diffs without unrelated operator files."""

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location("image_context", ROOT / "scripts/prepare-image-context.py")
CONTEXT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTEXT)
COMPONENTS = ("go-judge", "problemtools", "go-sandbox")


class ImageContextModuleTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="image-context-modules-")
        self.addCleanup(temporary.cleanup)
        self.context = Path(temporary.name).resolve() / "context"
        self.service = self.context / "service"
        self.service.mkdir(parents=True)
        self.original = {"go.mod": (b"module example.test/service\n\ngo 1.26.0\n", 0o644),
                         "go.sum": (b"example.test/module v1.0.0 h1:original\n", 0o640)}
        for name, (body, mode) in self.original.items():
            (self.service / name).write_bytes(body)
            (self.service / name).chmod(mode)
        self.download_sum = self.original["go.sum"][0] + b"example.test/module v1.0.0/go.mod h1:download\n"
        self.final_sum = self.download_sum + b"example.test/transitive v1.0.0/go.mod h1:list\n"
        self.go = Path("/reviewed/go1.26.8/bin/go")

    def prepare(self, fail=None, change_module=False, sum_symlink=None):
        def output(arguments, **kwargs):
            if arguments[1:] == ["version"]:
                return "go version go1.26.8 test/host\n"
            self.assertEqual(arguments[1:], ["list", "-m", "-mod=mod", "-json", "all"])
            self.assertEqual(kwargs["cwd"], self.service)
            if fail == "list":
                raise subprocess.CalledProcessError(1, arguments)
            if sum_symlink:
                (self.service / "go.sum").unlink()
                (self.service / "go.sum").symlink_to(sum_symlink)
            else:
                (self.service / "go.sum").write_bytes(self.final_sum)
            return '{"Path":"example.test/service","Main":true}\n'

        def run(arguments, **kwargs):
            self.assertEqual(arguments[:2], [str(self.go), "mod"])
            command = arguments[2]
            self.assertIn(command, ("download", "verify", "vendor"))
            self.assertEqual(kwargs["cwd"], self.service)
            if command == "download":
                (self.service / "go.sum").write_bytes(self.download_sum)
                (self.service / "go.sum").chmod(0o644)
                if change_module:
                    (self.service / "go.mod").write_bytes(b"module substituted.test/service\n")
            if command == fail:
                raise subprocess.CalledProcessError(1, arguments)
            if command == "vendor":
                vendor = self.service / "vendor"
                vendor.mkdir()
                (vendor / "modules.txt").write_bytes(b"# example.test/module v1.0.0\n")

        with patch.object(CONTEXT.subprocess, "check_output", side_effect=output), patch.object(
                CONTEXT.subprocess, "run", side_effect=run):
            return CONTEXT.service_go_inputs(self.service, self.go)

    def assert_original_sources(self):
        for name, (body, mode) in self.original.items():
            self.assertEqual((self.service / name).read_bytes(), body)
            self.assertEqual((self.service / name).stat().st_mode & 0o777, mode)
        self.assertEqual(list(self.service.glob(".startrack-module-*")), [])

    def test_resolution_retains_final_generated_checksums_without_rewriting_owned_sources(self):
        generated = self.prepare()
        self.assert_original_sources()
        retained = self.context / "provenance/service-generated.go.sum"
        self.assertEqual(retained.read_bytes(), self.final_sum)
        records = {entry["path"]: entry for entry in CONTEXT.inventory(self.context)}
        self.assertEqual(generated["generatedGoSum"], records["provenance/service-generated.go.sum"])
        self.assertEqual(generated["vendorInventory"], CONTEXT.inventory(self.service / "vendor"))
        retained.write_bytes(b"rewritten checksum evidence")
        self.assertNotEqual(generated["generatedGoSum"],
                            next(entry for entry in CONTEXT.inventory(self.context)
                                 if entry["path"] == "provenance/service-generated.go.sum"))

    def test_preserved_context_passes_unchanged_owned_source_auditor(self):
        self.prepare()
        authority = self.context.parent / "authority"
        authority.mkdir()
        for name, (body, mode) in self.original.items():
            (authority / name).write_bytes(body)
            (authority / name).chmod(mode)
        for name in ("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md"):
            (authority / name).write_bytes(b"owned legal evidence\n")
            CONTEXT.copy_file(authority / name, self.context / "legal" / name)
        spec = importlib.util.spec_from_file_location("image_context_release", ROOT / "scripts/release-artifacts.py")
        release = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(release)
        with patch.object(release, "ROOT", authority):
            release.verify_context_owned_sources({entry["path"]: entry for entry in CONTEXT.inventory(self.context)})
            (self.service / "go.sum").write_bytes(self.final_sum)
            with self.assertRaises(release.Failure):
                release.verify_context_owned_sources({entry["path"]: entry for entry in CONTEXT.inventory(self.context)})

    def test_failed_go_command_restores_original_bytes_and_modes(self):
        for command in ("download", "verify", "vendor", "list"):
            with self.subTest(command=command), self.assertRaises(subprocess.CalledProcessError):
                self.prepare(fail=command)
            self.assert_original_sources()
            self.assertFalse((self.context / "provenance/service-generated.go.sum").exists())

    def test_resolution_cannot_silently_change_owned_module_requirements(self):
        with self.assertRaisesRegex(ValueError, "module requirements"):
            self.prepare(change_module=True)
        self.assert_original_sources()
        self.assertFalse((self.context / "provenance/service-generated.go.sum").exists())

    def test_generated_checksum_symlink_is_rejected_without_touching_its_target(self):
        outside = self.context.parent / "outside"
        outside.write_bytes(b"external file canary")
        with self.assertRaisesRegex(ValueError, "regular file"):
            self.prepare(sum_symlink=outside)
        self.assert_original_sources()
        self.assertEqual(outside.read_bytes(), b"external file canary")
        self.assertFalse((self.context / "provenance/service-generated.go.sum").exists())


class ImageContextPatchTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="image-context-patches-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        self.source = self.directory / "source"
        self.source.mkdir()
        self.context = self.directory / "context"
        self.context.mkdir()
        shutil.copyfile(ROOT / "upstream.lock.json", self.source / "upstream.lock.json")
        for name in COMPONENTS:
            series_path = ROOT / "patches" / name / "series.json"
            series = json.loads(series_path.read_bytes())
            paths = [f"patches/{name}/series.json"] + [record["path"] for record in series["patches"]]
            for relative in paths:
                target = self.source / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, target)
                target.chmod((ROOT / relative).stat().st_mode & 0o777)

    def copy(self):
        with patch.object(CONTEXT, "ROOT", self.source):
            CONTEXT.copy_patch_inputs(self.context)

    def record_context(self):
        target = self.context / CONTEXT.INVENTORY
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps({"schemaVersion": 1, "inventory": CONTEXT.inventory(self.context)}))

    def prepare_context(self):
        self.copy()
        (self.context / "provenance").mkdir()
        shutil.copyfile(self.source / "upstream.lock.json", self.context / "provenance/upstream.lock.json")
        self.record_context()

    def change_patch_record(self, name, change):
        series_path = self.source / "patches" / name / "series.json"
        series = json.loads(series_path.read_bytes())
        change(series["patches"])
        series_path.write_text(json.dumps(series))
        lock_path = self.source / "upstream.lock.json"
        lock = json.loads(lock_path.read_bytes())
        component = next(item for item in lock["components"] + lock["supplemental_licenses"] if item["name"] == name)
        component["patches"] = series["patches"]
        lock_path.write_text(json.dumps(lock))

    def test_actual_locked_bytes_and_metadata_are_retained_without_unlisted_files(self):
        for relative in ("patches/.env", "patches/go-judge/operator-private.patch", "patches/go-judge-demo/private.patch"):
            target = self.source / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b"operator_private_canary")
        self.copy()
        expected = set()
        for name in COMPONENTS:
            descriptor = f"patches/{name}/series.json"
            series = json.loads((ROOT / descriptor).read_bytes())
            for relative in [descriptor] + [record["path"] for record in series["patches"]]:
                expected.add(relative)
                self.assertEqual((self.context / relative).read_bytes(), (ROOT / relative).read_bytes())
        self.assertEqual({record["path"] for record in CONTEXT.inventory(self.context)}, expected)
        self.assertFalse(any(b"operator_private_canary" in path.read_bytes() for path in self.context.rglob("*") if path.is_file()))

    def test_changed_patch_bytes_are_rejected_before_any_copy(self):
        for name in COMPONENTS:
            with self.subTest(component=name):
                series = json.loads((self.source / "patches" / name / "series.json").read_bytes())
                target = self.source / series["patches"][0]["path"]
                original = target.read_bytes()
                target.write_bytes(original + b"\nchanged diff\n")
                with self.assertRaisesRegex(ValueError, "checksum"):
                    self.copy()
                self.assertEqual(list(self.context.iterdir()), [])
                target.write_bytes(original)

    def test_metadata_and_source_identity_must_match_upstream_lock(self):
        for name in COMPONENTS:
            target = self.source / "patches" / name / "series.json"
            original = target.read_bytes()
            for key, value in (("baseCommit", "0" * 40), ("repository", "https://invalid.example/")):
                with self.subTest(component=name, field=key):
                    series = json.loads(original)
                    series[key] = value
                    target.write_text(json.dumps(series))
                    with self.assertRaisesRegex(ValueError, "upstream lock"):
                        self.copy()
            series = json.loads(original)
            series["patches"][0]["reason"] = "unreviewed provenance change"
            target.write_text(json.dumps(series))
            with self.assertRaisesRegex(ValueError, "upstream lock"):
                self.copy()
            target.write_bytes(original)
        self.assertEqual(list(self.context.iterdir()), [])

    def test_locked_paths_cannot_escape_or_admit_arbitrary_files(self):
        for value in ("../private.patch", "/absolute.patch", "patches/problemtools/private.patch",
                      "patches/go-judge/../private.patch", "patches/go-judge//private.patch",
                      "patches/go-judge/nested/private.patch", "patches/go-judge/.env",
                      "patches/go-judge/back\\slash.patch", "patches/go-judge/control\n.patch"):
            with self.subTest(path=value):
                self.change_patch_record("go-judge", lambda patches: patches[0].update(path=value))
                with self.assertRaisesRegex(ValueError, "allowlist"):
                    self.copy()
                self.assertEqual(list(self.context.iterdir()), [])

    def test_duplicate_locked_patch_paths_are_rejected(self):
        self.change_patch_record("go-judge", lambda patches: patches.append(dict(patches[0])))
        with self.assertRaisesRegex(ValueError, "allowlist"):
            self.copy()

    def test_patch_and_series_symlinks_are_rejected(self):
        series = json.loads((self.source / "patches/go-judge/series.json").read_bytes())
        for relative in ("patches/go-judge/series.json", series["patches"][0]["path"]):
            with self.subTest(path=relative):
                target = self.source / relative
                outside = self.directory / "outside"
                target.rename(outside)
                target.symlink_to(outside)
                with self.assertRaisesRegex(ValueError, "symbolic links"):
                    self.copy()
                target.unlink()
                outside.rename(target)

    def test_symlink_ancestor_is_rejected(self):
        target = self.source / "patches/go-sandbox"
        outside = self.directory / "outside"
        target.rename(outside)
        target.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symbolic links"):
            self.copy()

    def test_special_patch_file_is_rejected_before_reading(self):
        series = json.loads((self.source / "patches/go-judge/series.json").read_bytes())
        target = self.source / series["patches"][0]["path"]
        target.unlink()
        os.mkfifo(target)
        with self.assertRaisesRegex(ValueError, "regular file"):
            self.copy()

    def test_context_verifies_without_access_to_source_worktree(self):
        self.prepare_context()
        shutil.rmtree(self.source)
        CONTEXT.verify(self.context)

    def test_inventory_rewrite_cannot_hide_corrupt_or_missing_locked_diffs(self):
        self.prepare_context()
        series = json.loads((self.context / "patches/go-judge/series.json").read_bytes())
        target = self.context / series["patches"][0]["path"]
        target.write_bytes(b"substituted diff")
        self.record_context()
        with self.assertRaisesRegex(ValueError, "checksum"):
            CONTEXT.verify(self.context)
        target.unlink()
        self.record_context()
        with self.assertRaises(FileNotFoundError):
            CONTEXT.verify(self.context)

    def test_inventory_rewrite_cannot_admit_unlisted_patch_files(self):
        self.prepare_context()
        (self.context / "patches/go-judge/private.patch").write_bytes(b"unlisted operator file")
        self.record_context()
        with self.assertRaisesRegex(ValueError, "allowlist"):
            CONTEXT.verify(self.context)

    def test_recorded_modes_bind_patch_payloads(self):
        self.prepare_context()
        (self.context / "patches/go-judge/series.json").chmod(0o600)
        with self.assertRaisesRegex(ValueError, "bytes or modes"):
            CONTEXT.verify(self.context)

    def test_official_preparation_still_requires_clean_exact_commit(self):
        for commit, status in (("a" * 40, " M operator-change\n"), ("b" * 40, "")):
            with self.subTest(commit=commit, dirty=bool(status)), patch.object(
                    CONTEXT.subprocess, "check_output", side_effect=[commit, status]):
                with self.assertRaisesRegex(ValueError, "clean exact source commit"):
                    CONTEXT.prepare(str(self.context / "official"), release_commit="a" * 40)
                self.assertFalse((self.context / "official").exists())


if __name__ == "__main__":
    unittest.main()
