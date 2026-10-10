# SPDX-License-Identifier: Apache-2.0
"""Independent inert statement-transport regressions; no converter is run."""

import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("reviewed_bridge", ROOT / "scripts/problemtools-bridge.py")
bridge = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bridge)


class StatementTransportReviewTests(unittest.TestCase):
    def archive(self, additional=()):
        value = io.BytesIO()
        with tarfile.open(fileobj=value, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for path, raw in (("problem/problem.yaml", b"name: fixture\n"),
                              ("problem/problem_statement/problem.en.tex", b"inert statement\n")):
                member = tarfile.TarInfo(path)
                member.size = len(raw)
                archive.addfile(member, io.BytesIO(raw))
            for member, raw in additional:
                archive.addfile(member, io.BytesIO(raw))
        return value.getvalue()

    def unpack(self, raw, split=None):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        work = Path(temporary.name).resolve()
        if split is None:
            (work / "statement.000001.tarpart").write_bytes(raw)
        else:
            (work / "statement.000001.tarpart").write_bytes(raw[:split])
            (work / "statement.000002.tarpart").write_bytes(raw[split:])
        bridge.unpack_statement(work)
        return work

    def test_pax_names_are_checked_after_decoding_and_cannot_duplicate(self):
        for effective in ("problem/data/secret/1.in", "problem/../escape", "problem/problem.yaml"):
            with self.subTest(effective=effective):
                member = tarfile.TarInfo("problem/problem_statement/apparently-safe.txt")
                member.size = 1
                member.pax_headers = {"path": effective}
                with self.assertRaises(bridge.BridgeAbort):
                    self.unpack(self.archive(((member, b"x"),)))

    def test_long_pax_public_paths_survive_header_and_body_splits(self):
        path = "problem/problem_statement/" + "asset/" * 25 + "图像.txt"
        member = tarfile.TarInfo(path)
        raw = b"inert public asset"
        member.size = len(raw)
        archive = self.archive(((member, raw),))
        for split in (511, 1025, 2047, 3073):
            with self.subTest(split=split):
                work = self.unpack(archive, split)
                self.assertEqual((work / path).read_bytes(), raw)

    def test_nonzero_trailing_bytes_inside_tarfile_buffer_are_rejected(self):
        raw = bytearray(self.archive())
        # Two short regular members consume four blocks; the next block is EOS.
        # tarfile's streaming buffer already holds this following payload.
        raw[4 * tarfile.BLOCKSIZE + 2 * tarfile.BLOCKSIZE + 17] = 1
        with self.assertRaises(bridge.BridgeAbort):
            self.unpack(bytes(raw))

    def test_existing_parent_symlink_cannot_redirect_public_extraction(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name).resolve()
        work, outside = base / "work", base / "outside"
        work.mkdir()
        outside.mkdir()
        (work / "problem").symlink_to(outside, target_is_directory=True)
        (work / "statement.000001.tarpart").write_bytes(self.archive())
        with self.assertRaises(bridge.BridgeAbort):
            bridge.unpack_statement(work)
        self.assertEqual(list(outside.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
