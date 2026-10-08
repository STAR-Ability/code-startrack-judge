"""Inert fixtures exercise input binding, gzip envelopes and retained gaps."""

import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GZIP = load("image_gzip", ROOT / "scripts/audit-image-gzip.py")
FIXTURE = load("image_gzip_fixture", ROOT / "tests/test_image_layers.py")


def compressed(body, filename=""):
    output = io.BytesIO()
    with gzip.GzipFile(filename=filename, fileobj=output, mode="wb", mtime=0) as stream:
        stream.write(body)
    return output.getvalue()


class ImageGzipTests(unittest.TestCase):
    def test_regular_file_preserves_size_and_link_boundaries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "regular"
            body = b"inert fixture"
            path.write_bytes(body)
            with GZIP.regular_file(path, len(body)) as stream:
                self.assertEqual(stream.read(), body)
            with self.assertRaisesRegex(GZIP.LAYERS.Failure, "bounded regular single-link input required"):
                GZIP.regular_file(path, len(body) - 1)
            alias = root / "hardlink"
            os.link(path, alias)
            for candidate in (path, alias):
                with self.subTest(path=candidate), self.assertRaisesRegex(
                        GZIP.LAYERS.Failure, "bounded regular single-link input required"):
                    GZIP.regular_file(candidate, len(body))
            alias.unlink()
            alias.symlink_to(path)
            with self.assertRaises(OSError):
                GZIP.regular_file(alias, len(body))

    @unittest.skipUnless(hasattr(os, "mkfifo") and hasattr(os, "O_NONBLOCK"), "requires POSIX FIFO")
    def test_writerless_fifo_is_rejected_without_waiting_and_descriptor_is_closed(self):
        probe = """import errno, importlib.util, os, sys
from pathlib import Path
from unittest.mock import patch
spec = importlib.util.spec_from_file_location("fifo_gzip", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
opened = []
real_open = os.open
def tracked_open(*args, **kwargs):
    descriptor = real_open(*args, **kwargs)
    opened.append(descriptor)
    return descriptor
with patch.object(module.os, "open", side_effect=tracked_open):
    try:
        stream = module.regular_file(Path(sys.argv[2]), 1)
    except module.LAYERS.Failure as error:
        if str(error) != "bounded regular single-link input required":
            raise AssertionError("unexpected FIFO rejection") from error
    else:
        stream.close()
        raise AssertionError("FIFO input accepted")
if len(opened) != 1:
    raise AssertionError("FIFO open descriptor not observed")
try:
    os.fstat(opened[0])
except OSError as error:
    if error.errno != errno.EBADF:
        raise AssertionError("unexpected rejected-descriptor error") from error
else:
    raise AssertionError("rejected FIFO descriptor remains open")
"""
        with tempfile.TemporaryDirectory() as directory:
            fifo = Path(directory) / "writerless"
            os.mkfifo(fifo, 0o600)
            # A parent timeout also kills and reaps the child if open blocks.
            result = subprocess.run([sys.executable, "-c", probe,
                                     str(ROOT / "scripts/audit-image-gzip.py"), str(fifo)],
                                    stdin=subprocess.DEVNULL, capture_output=True, timeout=3)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))

    def report(self, entries, *, oci=False, receipt_change=None, call_change=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            layers = [FIXTURE.tar_bytes(entries)]
            if oci:
                archive, config, _ = FIXTURE.saved_oci_image(root, layers, filename="rootfs.tar")
            else:
                archive, config = FIXTURE.saved_image(root, layers)
            physical = FIXTURE.LAYERS.audit(archive, config)
            if receipt_change:
                receipt_change(physical)
            receipt = root / "physical.json"
            receipt.write_text(json.dumps(physical))
            args = [archive, FIXTURE.sha(archive.read_bytes()), receipt, FIXTURE.sha(receipt.read_bytes()), config]
            if call_change:
                call_change(args)
            return GZIP.audit(*args)

    def test_plain_docs_measure_actual_expanded_hash_without_full_gate(self):
        text = b"documented upstream license and manual\n"
        report = self.report([("usr/share/doc/package/license.gz", compressed(text)),
                              ("usr/share/man/man1/program.1.gz", compressed(text)),
                              ("usr/share/info/package.info.gz", compressed(text))])
        self.assertEqual(report["selectedPayloadCount"], 3)
        self.assertEqual(report["measuredPayloadCount"], 3)
        self.assertEqual(report["originalUnresolvedGapRows"], 0)
        self.assertTrue(all(item["expandedSHA256"] == hashlib.sha256(text).hexdigest()
                            and item["expandedSizeBytes"] == len(text) for item in report["inventory"]))
        self.assertFalse(report["qualified"])
        self.assertFalse(report["originalReceiptReplaced"])
        self.assertEqual(report["exclusionGate"], "PENDING_OTHER_PHYSICAL_GAPS_AND_LEGAL_RECONCILIATION")

    def test_docker29_gzip_layer_is_content_bound(self):
        report = self.report([("usr/share/man/man1/doc.1.gz", compressed(b"manual"))], oci=True)
        self.assertEqual(report["measuredPayloadCount"], 1)
        self.assertIsNotNone(report["ociImageManifestID"])
        self.assertEqual(len(report["affectedLayers"]), 1)

    def test_bounded_filename_header_has_measured_identity(self):
        value = compressed(b"manual", "doc.1")
        report = self.report([("usr/share/man/man1/doc.1.gz", value)])
        entry = report["inventory"][0]
        self.assertEqual(entry["headerSizeBytes"], 16)
        self.assertEqual(entry["headerSHA256"], FIXTURE.sha(value[:16]))
        self.assertEqual(entry["headerProfile"], "BOUNDED_INSPECTED_FILENAME")
        self.assertEqual(entry["status"], "MEASURED")

    def test_scope_does_not_waive_non_doc_gzip_or_other_archives(self):
        report = self.report([("usr/share/doc/package/doc.gz", compressed(b"manual")),
                              ("opt/package/private.gz", compressed(b"outside selected scope")),
                              ("usr/share/doc/package/source.tar", b"inert source archive hint")])
        self.assertEqual(report["selectedPayloadCount"], 1)
        self.assertEqual(report["originalUnresolvedGapRows"], 2)

    def test_bad_crc_truncated_concatenated_and_trailing_keep_gap(self):
        good = compressed(b"manual")
        bad_crc = good[:-8] + bytes([good[-8] ^ 1]) + good[-7:]
        for value, reason in [(bad_crc, "GZIP_INVALID_MEMBER_OR_CRC_ISIZE"),
                              (good[:-1], "GZIP_TRUNCATED_MEMBER"),
                              (good + good, "GZIP_CONCATENATED_OR_TRAILING_BYTES"),
                              (good + b"\0", "GZIP_CONCATENATED_OR_TRAILING_BYTES")]:
            with self.subTest(reason=reason):
                report = self.report([("usr/share/doc/package/doc.gz", value)])
                self.assertEqual(report["measuredPayloadCount"], 0)
                self.assertEqual(report["archiveInspectionGaps"][0]["reason"], reason)
                self.assertEqual(report["originalUnresolvedGapRows"], 1)

    def test_other_header_profiles_are_not_silently_discarded(self):
        good = compressed(b"manual")
        value = good[:3] + b"\x04" + good[4:10] + b"\x04\0data" + good[10:]
        report = self.report([("usr/share/doc/package/doc.gz", value)])
        self.assertEqual(report["archiveInspectionGaps"][0]["reason"], "GZIP_HEADER_PROFILE_UNSUPPORTED")
        self.assertEqual(report["measuredPayloadCount"], 0)

    def test_missing_or_overlong_filename_is_a_gap(self):
        good = compressed(b"manual")
        value = good[:3] + b"\x08" + good[4:10] + b"a" * 4097 + b"\0" + good[10:]
        report = self.report([("usr/share/doc/package/doc.gz", value)])
        self.assertEqual(report["archiveInspectionGaps"][0]["reason"], "GZIP_FILENAME_UNTERMINATED_OR_BOUND")

    def test_declared_filename_cannot_hide_excluded_or_archive_hint(self):
        report = self.report([("usr/share/doc/package/doc.gz", compressed(b"manual", "viva.jar"))])
        self.assertEqual(report["exclusionGate"], "FAILED")
        self.assertEqual(report["measuredPayloadCount"], 0)
        self.assertTrue(report["excludedPayloadFindings"])
        archive_hint = self.report([("usr/share/doc/package/doc.gz", compressed(b"manual", "doc.tar"))])
        self.assertEqual(archive_hint["measuredPayloadCount"], 0)
        self.assertTrue(archive_hint["archiveInspectionGaps"])

    def test_expanded_zip_and_excluded_filename_are_inspected(self):
        jar = FIXTURE.zip_bytes("Viva/excluded.class", b"inert fixture")
        report = self.report([("usr/share/doc/package/doc.gz", compressed(jar)),
                              ("usr/share/doc/package/viva.sh.gz", compressed(b"inert fixture"))])
        self.assertEqual(report["exclusionGate"], "FAILED")
        self.assertEqual(report["measuredPayloadCount"], 0)
        self.assertTrue(any(item["reason"] == "EXCLUDED_VIVA_OR_NESTED_CLASS_PATH"
                            for item in report["excludedPayloadFindings"]))

    def test_expanded_other_archive_remains_gap(self):
        inner = compressed(b"nested gzip remains unsupported")
        report = self.report([("usr/share/doc/package/doc.gz", compressed(inner))])
        self.assertEqual(report["measuredPayloadCount"], 0)
        self.assertEqual(report["archiveInspectionGaps"][0]["reason"], GZIP.ORIGINAL_GAP)

    def test_expanded_filename_archive_hint_keeps_invalid_zip_gap(self):
        report = self.report([("usr/share/doc/package/renamed.jar.gz", compressed(b"invalid jar without magic")),
                              ("usr/share/doc/package/renamed.tar.gz", compressed(b"tar hint without ustar magic"))])
        self.assertEqual(report["measuredPayloadCount"], 0)
        self.assertEqual({item["reason"] for item in report["archiveInspectionGaps"]},
                         {"ZIP_FORMAT_UNSUPPORTED_OR_INVALID", GZIP.ORIGINAL_GAP})

    def test_payload_expansion_and_compressed_bound_preserve_gaps(self):
        with patch.object(GZIP, "MAX_EXPANDED_BYTES", 8):
            report = self.report([("usr/share/doc/package/doc.gz", compressed(b"x" * 1000))])
            self.assertEqual(report["archiveInspectionGaps"][0]["reason"], "GZIP_PAYLOAD_EXPANSION_BOUND")
        with patch.object(GZIP, "MAX_COMPRESSED_BYTES", 8):
            report = self.report([("usr/share/doc/package/doc.gz", compressed(b"manual"))])
            self.assertEqual(report["archiveInspectionGaps"][0]["reason"], "GZIP_COMPRESSED_PAYLOAD_BOUND")

    def test_aggregate_and_deadline_abort_instead_of_claiming_scope(self):
        entries = [("usr/share/doc/package/doc.gz", compressed(b"x" * 100))]
        with patch.object(GZIP, "MAX_TOTAL_EXPANDED_BYTES", 8):
            with self.assertRaisesRegex(ValueError, "aggregate expansion bound"):
                self.report(entries)
        with patch.object(GZIP, "MAX_TOTAL_COMPRESSED_BYTES", 8):
            with self.assertRaisesRegex(ValueError, "compressed aggregate bound"):
                self.report(entries)
        with patch.object(GZIP, "DEADLINE_SECONDS", -1):
            with self.assertRaisesRegex(ValueError, "deadline"):
                self.report(entries)

    def test_wrong_archive_receipt_and_config_fingerprints_fail(self):
        entries = [("usr/share/doc/package/doc.gz", compressed(b"manual"))]
        for index, value in [(1, "0" * 64), (3, "0" * 64), (4, "sha256:" + "0" * 64)]:
            with self.subTest(index=index):
                with self.assertRaises(ValueError):
                    self.report(entries, call_change=lambda args: args.__setitem__(index, value))

    def test_self_inventory_affected_layer_and_selected_payload_bindings_fail(self):
        entries = [("usr/share/doc/package/doc.gz", compressed(b"manual"))]
        def bad_inventory(receipt):
            receipt["layers"][0]["inventory"][0]["sha256"] = "0" * 64
        def bad_layer(receipt):
            receipt["layers"][0]["diffID"] = "sha256:" + "0" * 64
        def bad_payload(receipt):
            layer = receipt["layers"][0]
            layer["inventory"][0]["sha256"] = "0" * 64
            layer["inventorySHA256"] = FIXTURE.sha(json.dumps(layer["inventory"], sort_keys=True, separators=(",", ":")).encode())
        for change in [bad_inventory, bad_layer, bad_payload]:
            with self.subTest(change=change.__name__):
                with self.assertRaises(ValueError):
                    self.report(entries, receipt_change=change)

    def test_prior_excluded_findings_remain_failed(self):
        report = self.report([("usr/share/doc/package/doc.gz", compressed(b"manual"))],
                             receipt_change=lambda receipt: receipt["excludedPayloadFindings"].append({"reason": "EXACT_EXCLUDED_BINARY_SHA256"}))
        self.assertEqual(report["exclusionGate"], "FAILED")
        self.assertEqual(report["originalExcludedPayloadFindingCount"], 1)


if __name__ == "__main__":
    unittest.main()
