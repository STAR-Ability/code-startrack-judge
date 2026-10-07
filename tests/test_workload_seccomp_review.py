"""The additive guard must remain bound to its inherited policy and exact source."""

import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("workload_seccomp", ROOT / "scripts/workload-seccomp.py")
PROFILE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROFILE)


class WorkloadSeccompTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for relative in ("upstream.lock.json", "docker/workload-security-profile.lock.json", "docker/startrack-workload-seccomp.yaml"):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, path)
        self.profile_path = self.root / "docker/workload-security-profile.lock.json"
        self.profile = json.loads(self.profile_path.read_bytes())

    def change_profile(self):
        self.profile_path.write_text(json.dumps(self.profile))

    def test_reviewed_source_binding_is_valid(self):
        self.assertEqual(PROFILE.verify(self.root), self.profile)

    def test_profile_byte_drift_is_rejected(self):
        path = self.root / "docker/startrack-workload-seccomp.yaml"
        path.write_bytes(path.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "bytes differ"):
            PROFILE.verify(self.root)

    def test_standalone_or_reordered_policy_is_rejected(self):
        for field, value in (("defaultAction", "STANDALONE_ALLOW"), ("conditionalCloneGroup", "FIRST"), ("cloneNamespaceMask", "0x7e020080")):
            original = self.profile["policy"][field]
            self.profile["policy"][field] = value
            self.change_profile()
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "policy differs"):
                PROFILE.verify(self.root)
            self.profile["policy"][field] = original

    def test_inherited_policy_and_source_drift_are_rejected(self):
        self.profile["initProfile"]["sha256"] = "0" * 64
        self.change_profile()
        with self.assertRaisesRegex(ValueError, "init identity"):
            PROFILE.verify(self.root)
        self.profile = json.loads((ROOT / "docker/workload-security-profile.lock.json").read_bytes())
        self.profile["sources"][0]["sha256"] = "0" * 64
        self.change_profile()
        with self.assertRaisesRegex(ValueError, "source hashes"):
            PROFILE.verify(self.root)


if __name__ == "__main__":
    unittest.main()
