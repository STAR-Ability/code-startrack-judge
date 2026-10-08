"""Canonical wheel evidence rejects mismatched and unapproved installed bytes."""

import base64
import copy
import csv
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("wheel_audit", ROOT / "scripts/problemtools-wheel-audit.py")
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


def digest(body):
    return hashlib.sha256(body).hexdigest()


def record(bodies, self_name):
    stream = io.StringIO()
    writer = csv.writer(stream, lineterminator="\n")
    for name, body in sorted(bodies.items()):
        writer.writerow((name, "sha256=" + base64.urlsafe_b64encode(bytes.fromhex(digest(body))).decode().rstrip("="), len(body)))
    writer.writerow((self_name, "", ""))
    return stream.getvalue().encode()


class WheelEvidenceTests(unittest.TestCase):
    def fixture(self, root, extra=None, mutate_record=None, duplicate=False, special=None):
        dist = AUDIT.DIST_INFO
        bodies = {"problemtools/__init__.py": b"# package\n", "problemtools/run/viva.py": b"# retained wrapper\n",
                  f"{dist}/METADATA": f"Metadata-Version: 2.4\nName: problemtools\nVersion: {AUDIT.VERSION}\n".encode(),
                  f"{dist}/WHEEL": b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
                  f"{dist}/entry_points.txt": b"[console_scripts]\nproblem2html = problemtools.problem2html:main\nproblem2pdf = problemtools.problem2pdf:main\nverifyproblem = problemtools.verifyproblem:main\n"}
        bodies.update(extra or {})
        original_record = record(bodies, f"{dist}/RECORD")
        if mutate_record:
            original_record = mutate_record(original_record)
        bodies[f"{dist}/RECORD"] = original_record
        wheel = root / f"problemtools-{AUDIT.VERSION}-py3-none-any.whl"
        with zipfile.ZipFile(wheel, "w") as archive:
            for name, body in bodies.items():
                info = zipfile.ZipInfo(name)
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                if name == special:
                    info.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(info, body)
            if duplicate:
                archive.writestr("problemtools/__init__.py", b"second")
        site = root / AUDIT.SITE.lstrip("/")
        installed = {}
        for name, body in bodies.items():
            if name == f"{dist}/RECORD" or ".." in Path(name).parts or name.startswith("/"):
                continue
            target = site / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(body)
            installed[name] = body
        for name in ("verifyproblem", "problem2html", "problem2pdf"):
            body = f"#!/usr/local/bin/python3\nfrom problemtools.{name} import main\n".encode()
            target = root / "usr/local/bin" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(body)
            installed[f"../../../bin/{name}"] = body
        generated = {f"{dist}/INSTALLER": b"pip\n", f"{dist}/REQUESTED": b"",
                     f"{dist}/direct_url.json": json.dumps({"url": f"file:///build/dist/{wheel.name}",
                     "archive_info": {"hash": "sha256=" + digest(wheel.read_bytes()), "hashes": {"sha256": digest(wheel.read_bytes())}}}).encode()}
        for name, body in generated.items():
            (site / name).write_bytes(body)
            installed[name] = body
        (site / dist / "RECORD").write_bytes(record(installed, f"{dist}/RECORD"))
        provenance = root / "opt/startrack/provenance"
        provenance.mkdir(parents=True)
        (provenance / "problemtools-sources.json").write_text(json.dumps({"baseCommit": AUDIT.REVISION}))
        (provenance / "context-inventory.json").write_text("{}")
        return wheel

    def verify(self, receipt, wheel, root):
        source = root / "opt/startrack/provenance/problemtools-sources.json"
        context = root / "opt/startrack/provenance/context-inventory.json"
        AUDIT.verify(receipt, digest(wheel.read_bytes()) + "  /build/dist/" + wheel.name + "\n", root,
                     digest(source.read_bytes()), digest(context.read_bytes()))

    def test_actual_zip_and_installed_record_bind_payloads_and_allow_wrapper(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            wheel = self.fixture(root)
            receipt = AUDIT.capture(wheel, root)
            self.verify(receipt, wheel, root)
            self.assertFalse(receipt["sdistBuilt"])
            self.assertIn("problemtools/run/viva.py", {value["path"] for value in receipt["wheelMembers"]})

    def test_wheel_rejects_record_archive_identity_and_omission_failures(self):
        nested = io.BytesIO()
        with zipfile.ZipFile(nested, "w") as archive:
            archive.writestr("hidden.class", b"class")
        cases = [
            {"mutate_record": lambda body: body.replace(b"sha256=", b"sha512=", 1)},
            {"mutate_record": lambda body: body + body.splitlines(keepends=True)[0]},
            {"mutate_record": lambda body: b"\n".join(body.splitlines()[1:]) + b"\n"},
            {"duplicate": True}, {"extra": {"../escape": b"bad"}}, {"extra": {"problemtools/link": b"target"}, "special": "problemtools/link"},
            {"extra": {"problemtools/hidden.dat": nested.getvalue()}}, {"extra": {"problemtools/support/viva/viva.sh": b"engine"}},
            {"extra": {f"{AUDIT.DIST_INFO}/METADATA": b"Name: problemtools\nVersion: 2\n"}},
            {"extra": {f"{AUDIT.DIST_INFO}/entry_points.txt": b"[console_scripts]\nevil = evil:main\n"}},
        ]
        for case in cases:
            with self.subTest(case=tuple(case)), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                wheel = self.fixture(root, **case)
                with self.assertRaises(ValueError):
                    AUDIT.capture(wheel, root)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            wheel = self.fixture(root, extra={"problemtools/renamed.dat": b"forbidden"})
            with patch.object(AUDIT, "FORBIDDEN_HASHES", {digest(b"forbidden")}), self.assertRaises(ValueError):
                AUDIT.capture(wheel, root)

    def test_publisher_remeasures_files_and_rejects_receipt_or_provenance_drift(self):
        for case in ("payload", "extra", "extra_cache", "wrapper", "symlink", "receipt_hash", "receipt_missing_member", "receipt_record", "source_hash", "context_hash", "direct_url"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                wheel = self.fixture(root)
                receipt = copy.deepcopy(AUDIT.capture(wheel, root))
                site = root / AUDIT.SITE.lstrip("/")
                if case == "payload":
                    (site / "problemtools/__init__.py").write_bytes(b"changed")
                elif case in ("extra", "extra_cache"):
                    target = site / ("problemtools/extra.py" if case == "extra" else "problemtools/__pycache__/extra.cpython-311.pyc")
                    target.parent.mkdir(exist_ok=True)
                    target.write_bytes(b"extra")
                elif case == "wrapper":
                    (root / "usr/local/bin/verifyproblem").write_bytes(b"changed wrapper")
                elif case == "symlink":
                    target = site / "problemtools/__init__.py"
                    target.unlink()
                    target.symlink_to(site / "problemtools/run/viva.py")
                elif case == "receipt_hash":
                    receipt["wheelSHA256"] = "0" * 64
                elif case == "receipt_missing_member":
                    receipt["wheelMembers"] = receipt["wheelMembers"][1:]
                elif case == "receipt_record":
                    receipt["wheelRecordBase64"] = base64.b64encode(b"wrong record").decode()
                elif case in ("source_hash", "context_hash"):
                    field = "problemtoolsSourceProvenanceSHA256" if case == "source_hash" else "contextInventorySHA256"
                    receipt[field] = "0" * 64
                else:
                    (site / AUDIT.DIST_INFO / "direct_url.json").write_text('{"url":"https://unreviewed.example/"}')
                with self.assertRaises(ValueError):
                    self.verify(receipt, wheel, root)


if __name__ == "__main__":
    unittest.main()
