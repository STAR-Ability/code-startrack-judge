"""Fail closed when standalone source identity or original grant evidence changes."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("validation_sources", ROOT / "scripts/validation-sources.py")
SOURCES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SOURCES)


class ValidationSourcesReviewTests(unittest.TestCase):
    def setUp(self):
        self.source_path = ROOT / "validation-sources.lock.json"
        self.tools_path = ROOT / "validation-tools.lock.json"
        self.lock, self.digest = SOURCES.read_lock(self.source_path)
        self.tools = json.loads(self.tools_path.read_bytes())

    def test_canonical_standalone_source_closure_passes(self):
        SOURCES.check(self.lock, ROOT, self.tools_path, self.digest)

    def test_original_source_bytes_must_match_frozen_tools_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            changed = Path(temporary) / "validation-sources.lock.json"
            # Even semantically identical JSON has a different exact-byte identity.
            changed.write_bytes(self.source_path.read_bytes() + b"\n")
            lock, digest = SOURCES.read_lock(changed)
            self.assertNotEqual(digest, self.digest)
            with self.assertRaisesRegex(ValueError, "frozen tools identity"):
                SOURCES.check(lock, ROOT, self.tools_path, digest)
        for digest in ("0" * 64, "", None):
            with self.subTest(digest=digest), self.assertRaisesRegex(ValueError, "frozen tools identity"):
                SOURCES.check(self.lock, ROOT, self.tools_path, digest)

    def test_tools_manifest_cannot_rebind_an_unrelated_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            tools = copy.deepcopy(self.tools)
            tools["correspondingSourceManifest"]["sha256"] = "0" * 64
            path = Path(temporary) / "validation-tools.lock.json"
            path.write_text(json.dumps(tools))
            with self.assertRaisesRegex(ValueError, "frozen tools identity"):
                SOURCES.check(self.lock, ROOT, path, self.digest)

    def test_python_grants_remain_required_after_consistent_manifest_rebinding(self):
        for group in ("pythonSources", "pythonVendorSources", "pythonRuntimeSources", "pythonNativeVendorSources"):
            for missing in (False, True):
                with self.subTest(group=group, missing=missing), tempfile.TemporaryDirectory() as temporary:
                    lock, tools = copy.deepcopy(self.lock), copy.deepcopy(self.tools)
                    source = next(item for item in lock[group] if item["name"].lower() == "pip") if group == "pythonSources" else lock[group][0]
                    if missing:
                        source.pop("licenses")
                    else:
                        source["licenses"] = []
                    lock["sourceArchives"] = [source if item["filename"] == source["filename"] else item for item in lock["sourceArchives"]]
                    # Preserve duplicate identity/owner records so a distinct
                    # coverage mismatch cannot mask the missing original grant.
                    if group == "pythonRuntimeSources":
                        tools["pythonRuntimeSource"] = source
                    elif group == "pythonNativeVendorSources":
                        tools["pythonNativeVendorSources"] = lock[group]
                    raw = (json.dumps(lock, indent=2) + "\n").encode()
                    digest = hashlib.sha256(raw).hexdigest()
                    tools["correspondingSourceManifest"].update(sha256=digest, sizeBytes=len(raw))
                    source_path = Path(temporary) / "validation-sources.lock.json"
                    tools_path = Path(temporary) / "validation-tools.lock.json"
                    source_path.write_bytes(raw)
                    tools_path.write_text(json.dumps(tools))
                    parsed, actual_digest = SOURCES.read_lock(source_path)
                    with self.assertRaises(ValueError):
                        SOURCES.check(parsed, ROOT, tools_path, actual_digest)

    def test_ordinary_sdist_requires_matching_retained_wheel_grants(self):
        self.assertNotIn("licenses", self.lock["pythonSources"][0])
        for missing in (False, True):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as temporary:
                tools = copy.deepcopy(self.tools)
                wheel = next(item for item in tools["wheels"] if item["name"].lower() == self.lock["pythonSources"][0]["name"].lower())
                if missing:
                    wheel.pop("licenses")
                else:
                    wheel["licenses"] = []
                path = Path(temporary) / "validation-tools.lock.json"
                path.write_text(json.dumps(tools))
                with self.assertRaisesRegex(ValueError, "Original Python source grant is incomplete"):
                    SOURCES.check(self.lock, ROOT, path, self.digest)


if __name__ == "__main__":
    unittest.main()
