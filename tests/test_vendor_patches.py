"""Vendor mutation gates reject unsafe inputs before altering any source."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("vendor_patches", ROOT / "scripts/apply-vendor-patches.py")
PREPARER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREPARER)


class VendorPatchTests(unittest.TestCase):
    def setUp(self):
        (ROOT / ".local").mkdir(exist_ok=True)
        temporary = tempfile.TemporaryDirectory(prefix="vendor-patches-test-", dir=ROOT / ".local")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.source = self.directory / "vendor/github.com/criyle/go-sandbox"
        self.source.mkdir(parents=True)
        (self.directory / "vendor/modules.txt").write_text("# github.com/criyle/go-sandbox v0.14.0\n")
        target = self.source / "pkg/mount/mount_linux.go"
        target.parent.mkdir(parents=True)
        target.write_text("corrupted source fixture\n")

    def test_changed_selected_version_is_rejected(self):
        (self.directory / "vendor/modules.txt").write_text("# github.com/criyle/go-sandbox v0.14.1\n")
        with self.assertRaisesRegex(ValueError, "version"):
            PREPARER.apply(self.directory)

    def test_unreviewed_patch_inventory_is_rejected(self):
        original = PREPARER.regular
        def altered(path):
            body = original(path)
            if path == ROOT / "patches/go-sandbox/series.json":
                record = json.loads(body)
                record["patches"][0]["sha256"] = "0" * 64
                return json.dumps(record).encode()
            return body
        with patch.object(PREPARER, "regular", side_effect=altered), self.assertRaisesRegex(ValueError, "review"):
            PREPARER.apply(self.directory)

    def test_changed_base_bytes_are_rejected_without_mutation(self):
        target = self.source / "pkg/mount/mount_linux.go"
        before = target.read_bytes()
        with self.assertRaisesRegex(ValueError, "base bytes or mode"):
            PREPARER.apply(self.directory)
        self.assertEqual(target.read_bytes(), before)
        self.assertFalse((self.directory / ".startrack-vendor-patches.json").exists())

    def test_module_ancestor_symlink_is_rejected(self):
        actual = self.directory / "outside-module"
        self.source.rename(actual)
        self.source.symlink_to(actual, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symbolic links"):
            PREPARER.apply(self.directory)

    def test_special_file_is_rejected_before_reading(self):
        import os
        os.mkfifo(self.source / "named-pipe")
        with self.assertRaisesRegex(ValueError, "unsafe input"):
            PREPARER.apply(self.directory)


if __name__ == "__main__":
    unittest.main()
