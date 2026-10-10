"""Rejection tests for release-time binary and private legal evidence auditing."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("go_judge_licenses", ROOT / "scripts/check-go-judge-licenses.py")
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


class GoJudgeLicenseReviewTests(unittest.TestCase):
    def setUp(self):
        self.inventory = json.loads((ROOT / "docs/licenses/go-judge-runtime-dependencies.json").read_text())

    def test_binary_module_or_build_profile_drift_cannot_generate_sbom(self):
        profile = {"GOOS": "linux", "GOARCH": "amd64", "GOAMD64": "v1", "CGO_ENABLED": "0", "-trimpath": "true", "-compiler": "gc", "-buildmode": "exe"}
        dependencies = {m["modulePath"]: m["version"] for m in self.inventory["modules"] if m["linkScope"] == "BINARY_RUNTIME"}
        module = self.inventory["source"]["modulePath"]

        def metadata(deps, settings):
            return "binary: go1.26.8\n\tpath\t" + module + "/cmd/go-judge\n\tmod\t" + module + "\t(devel)\n" + "".join("\tdep\t" + path + "\t" + version + "\n" for path, version in deps.items()) + "".join("\tbuild\t" + key + "=" + value + "\n" for key, value in settings.items())

        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "binary"
            elf = bytearray(64)
            elf[:6] = b"\x7fELF\x02\x01"
            elf[18:20] = (62).to_bytes(2, "little")
            binary.write_bytes(elf)
            with patch.object(AUDIT, "go_command", return_value=metadata(dependencies, profile)):
                self.assertEqual(len(AUDIT.binary_info(Path("go"), binary, self.inventory)["moduleVersions"]), 48)
            modified = dict(dependencies)
            modified[next(iter(modified))] = "v0.0.0-unreviewed"
            for deps, settings in ((modified, profile), (dependencies, dict(profile, CGO_ENABLED="1")), (dependencies, dict(profile, GOAMD64="v3")), (dependencies, dict(profile, **{"vcs.revision": "unreviewed"}))):
                with patch.object(AUDIT, "go_command", return_value=metadata(deps, settings)):
                    with self.assertRaises(ValueError):
                        AUDIT.binary_info(Path("go"), binary, self.inventory)
            elf[18:20] = (183).to_bytes(2, "little")
            binary.write_bytes(elf)
            with self.assertRaises(ValueError):
                AUDIT.binary_info(Path("go"), binary, self.inventory)

    def test_legal_mutation_and_path_escape_fail_before_artifact_emission(self):
        with tempfile.TemporaryDirectory() as directory:
            legal = Path(directory)
            path = legal / "LICENSE"
            path.write_bytes(b"Exact copyright and grant.\n")
            record = {"licenseEvidence": [{"localPath": "LICENSE", "sha256": AUDIT.sha(path.read_bytes()), "sizeBytes": path.stat().st_size}]}
            inventory = {"source": record, "goToolchain": {"licenseEvidence": []}, "modules": []}
            AUDIT.legal_check(inventory, legal)
            path.write_bytes(b"Omitted copyright.\n")
            with self.assertRaises(ValueError):
                AUDIT.legal_check(inventory, legal)
            with self.assertRaises(ValueError):
                AUDIT.legal_path(legal, "../outside-license")

    def test_link_and_extracted_license_identifiers_preserve_distinct_module_scopes(self):
        runtime = [m for m in self.inventory["modules"] if m["linkScope"] == "BINARY_RUNTIME"]
        source_only = [m for m in self.inventory["modules"] if m["linkScope"] == "VENDORED_SOURCE_ONLY"]
        self.assertEqual(len(runtime), 48)
        self.assertEqual(len(source_only), 14)
        refs = [m["licenseRef"] for m in self.inventory["modules"]]
        self.assertEqual(len(refs), len(set(refs)))
        for record in self.inventory["modules"]:
            self.assertRegex(record["licenseRef"], r"^LicenseRef-[A-Za-z0-9.-]+$")
            self.assertTrue(record["licenseEvidence"])
            if record["linkScope"] == "VENDORED_SOURCE_ONLY":
                self.assertEqual(record["compiledSourceFiles"], [])
                self.assertEqual(record["importedPackages"], [])


if __name__ == "__main__":
    unittest.main()
