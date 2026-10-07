# SPDX-License-Identifier: Apache-2.0
"""Portable inert workspace facts; no imported source or converter executes."""
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("workspace_bridge", ROOT / "scripts/problemtools-bridge.py")
bridge = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bridge)


class StatementWorkspaceTests(unittest.TestCase):
    def test_public_transport_counts_are_actual_extracted_regular_files(self):
        archive = io.BytesIO()
        files = {"problem/problem.yaml": b"name: Fixture\n",
                 "problem/problem_statement/problem.en.tex": b"text\n",
                 "problem/problem_statement/unused.bin": b""}
        with tarfile.open(fileobj=archive, mode="w") as tar:
            for name, data in files.items():
                member = tarfile.TarInfo(name)
                member.size = len(data)
                tar.addfile(member, io.BytesIO(data))
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            (work / "statement.000001.tarpart").write_bytes(archive.getvalue())
            facts = bridge.unpack_statement(work)
            self.assertEqual(facts, {"transportBytes": len(archive.getvalue()),
                                     "regularBytes": sum(map(len, files.values())), "regularFiles": 3})
            for name, data in files.items():
                self.assertEqual((work / name).read_bytes(), data)

    def test_workspace_facts_measure_kernel_units_without_mutating_transport(self):
        transport = {"transportBytes": 10240, "regularBytes": 18, "regularFiles": 3}
        fs = SimpleNamespace(f_blocks=524288, f_bfree=524278, f_frsize=4096,
                             f_files=262144, f_ffree=262130)
        with patch.object(bridge.os, "statvfs", return_value=fs):
            facts = bridge.statement_workspace(transport)
        self.assertEqual(facts["totalBytes"], 2 << 30)
        self.assertEqual(facts["totalInodes"], 262144)
        self.assertEqual(facts["peakObservedUsedBytes"], 40960)
        self.assertEqual(facts["peakObservedUsedInodes"], 14)
        self.assertEqual(set(transport), {"transportBytes", "regularBytes", "regularFiles"})
        self.assertFalse(any(isinstance(value, str) for value in facts.values()))

    def test_impossible_kernel_workspace_facts_fail(self):
        for fs in (SimpleNamespace(f_blocks=1, f_bfree=2, f_files=3, f_ffree=3),
                   SimpleNamespace(f_blocks=1, f_bfree=1, f_files=3, f_ffree=4)):
            with patch.object(bridge.os, "statvfs", return_value=fs):
                with self.assertRaises(bridge.BridgeAbort):
                    bridge.statement_workspace({"transportBytes": 10240, "regularBytes": 18, "regularFiles": 3})


if __name__ == "__main__":
    unittest.main()
