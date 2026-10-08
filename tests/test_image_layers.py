"""Measure physical image evidence, including historic and nested payloads."""

import hashlib
from contextlib import nullcontext
import importlib.util
import io
import json
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("image_layers", ROOT / "scripts/audit-image-layers.py")
LAYERS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAYERS)


def sha(body):
    return hashlib.sha256(body).hexdigest()


def tar_bytes(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name, body in entries:
            member = tarfile.TarInfo(name)
            member.size = len(body)
            member.mode = 0o644
            archive.addfile(member, io.BytesIO(body))
    return output.getvalue()


def zip_bytes(name, body):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr(name, body)
    return output.getvalue()


def saved_image(root, layer_bodies, config_change=None, layer_change=None):
    config = {"os": "linux", "architecture": "amd64", "rootfs": {
        "type": "layers", "diff_ids": ["sha256:" + sha(body) for body in layer_bodies]}}
    if config_change:
        config_change(config)
    config_body = json.dumps(config).encode()
    config_id = "sha256:" + sha(config_body)
    entries = [("config.json", config_body), ("manifest.json", json.dumps([
        {"Config": "config.json", "RepoTags": ["fixture:local"],
         "Layers": [f"layer-{index}/layer.tar" for index in range(len(layer_bodies))]}]).encode())]
    for index, body in enumerate(layer_bodies):
        entries.append((f"layer-{index}/layer.tar", layer_change(body) if layer_change else body))
    path = root / "image.tar"
    path.write_bytes(tar_bytes(entries))
    return path, config_id


class ImageLayerTests(unittest.TestCase):
    def test_config_and_each_physical_layer_are_bound_to_content(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path, identity = saved_image(root, [tar_bytes([("usr/file", b"first")]), tar_bytes([("usr/file", b"second")])])
            report = LAYERS.audit(path, identity)
            self.assertTrue(report["completePhysicalLayerInventory"])
            self.assertEqual(len(report["layers"]), 2)
            self.assertEqual(report["layers"][0]["inventory"][0]["sha256"], sha(b"first"))
            self.assertEqual(report["layers"][1]["inventory"][0]["sha256"], sha(b"second"))
            self.assertFalse(report["qualified"])
            with self.assertRaises(LAYERS.Failure):
                LAYERS.audit(path, "sha256:" + "0" * 64)
            path, identity = saved_image(root, [tar_bytes([("usr/file", b"first")])], layer_change=lambda body: body + b"tampered")
            with self.assertRaises(LAYERS.Failure):
                LAYERS.audit(path, identity)

    def test_whiteout_does_not_hide_excluded_previous_layer(self):
        with tempfile.TemporaryDirectory() as temporary:
            path, identity = saved_image(Path(temporary), [
                tar_bytes([("build/problemtools/support/viva/payload", b"excluded")]),
                tar_bytes([("build/problemtools/support/.wh.viva", b"")])])
            report = LAYERS.audit(path, identity)
            self.assertEqual(report["exclusionGate"], "FAILED")
            self.assertIn("layer[0]", report["excludedPayloadFindings"][0]["location"])

    def test_nested_and_prepended_jars_cannot_hide_excluded_class_paths(self):
        jar = zip_bytes("org/eclipse/jdt/internal/jarinjarloader/JarRsrcLoader.class", b"class")
        wheel = zip_bytes("package/module.py", b"pass\n")
        for payload in (zip_bytes("renamed.data", jar), jar + wheel):
            with self.subTest(payload_size=len(payload)), tempfile.TemporaryDirectory() as temporary:
                path, identity = saved_image(Path(temporary), [tar_bytes([("usr/renamed", payload)])])
                report = LAYERS.audit(path, identity)
                self.assertTrue(report["excludedPayloadFindings"])
                self.assertEqual(report["exclusionGate"], "FAILED")

    def test_renamed_exact_binary_hash_is_detected(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(LAYERS, "BLOCKED_DIGESTS", frozenset([sha(b"excluded bytes")])):
            path, identity = saved_image(Path(temporary), [tar_bytes([("usr/renamed", b"excluded bytes")])])
            report = LAYERS.audit(path, identity)
            self.assertEqual(report["excludedPayloadFindings"][0]["reason"], "EXACT_EXCLUDED_BINARY_SHA256")

    def test_renamed_java_class_definition_is_distinct_from_reference(self):
        blocked = b"org/eclipse/jdt/internal/jarinjarloader/JarRsrcLoader"
        allowed = b"example/Allowed"
        prefix = b"\xca\xfe\xba\xbe" + struct.pack(">HHH", 0, 52, 5)
        pool = (b"\x01" + struct.pack(">H", len(blocked)) + blocked + b"\x07\x00\x01"
                + b"\x01" + struct.pack(">H", len(allowed)) + allowed + b"\x07\x00\x03")
        for definition, expected in ((2, True), (4, False)):
            body = prefix + pool + struct.pack(">HHH", 0x21, definition, 0)
            with self.subTest(definition=definition), tempfile.TemporaryDirectory() as temporary:
                path, identity = saved_image(Path(temporary), [tar_bytes([("usr/renamed", body)])])
                report = LAYERS.audit(path, identity)
                self.assertEqual(bool(report["excludedPayloadFindings"]), expected)

    def test_layer_paths_reject_traversal_absolute_and_duplicate_entries(self):
        for entries in ([('../escape', b'x')], [('/absolute', b'x')], [('safe', b'x'), ('safe', b'y')]):
            with self.subTest(entries=entries), tempfile.TemporaryDirectory() as temporary:
                path, identity = saved_image(Path(temporary), [tar_bytes(entries)])
                with self.assertRaises(LAYERS.Failure):
                    LAYERS.audit(path, identity)

    def test_payload_after_tar_end_cannot_escape_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            path, identity = saved_image(Path(temporary), [tar_bytes([("usr/file", b"safe")]) + b"unmeasured binary"])
            with self.assertRaises(LAYERS.Failure):
                LAYERS.audit(path, identity)

    def test_nonzero_regular_metadata_and_outer_member_padding_is_refused(self):
        regular = bytearray(tar_bytes([("usr/file", b"x")]))
        regular[513:520] = b"PADDING"
        metadata = io.BytesIO()
        with tarfile.open(fileobj=metadata, mode="w", format=tarfile.PAX_FORMAT) as archive:
            member = tarfile.TarInfo("usr/file")
            member.pax_headers = {"audit-metadata": "ordinary metadata"}
            member.size = 1
            archive.addfile(member, io.BytesIO(b"x"))
        padded_metadata = bytearray(metadata.getvalue())
        header = tarfile.TarInfo.frombuf(padded_metadata[:512], "utf-8", "surrogateescape")
        padded_metadata[512 + header.size:519 + header.size] = b"PADDING"
        for layer in (bytes(regular), bytes(padded_metadata)):
            with self.subTest(layer_type="regular" if layer == bytes(regular) else "metadata"), tempfile.TemporaryDirectory() as temporary:
                path, identity = saved_image(Path(temporary), [layer])
                with self.assertRaisesRegex(LAYERS.Failure, "member padding"):
                    LAYERS.audit(path, identity)
        with tempfile.TemporaryDirectory() as temporary:
            path, identity = saved_image(Path(temporary), [tar_bytes([("usr/file", b"x")])])
            outer = bytearray(path.read_bytes())
            header = tarfile.TarInfo.frombuf(outer[:512], "utf-8", "surrogateescape")
            outer[512 + header.size:519 + header.size] = b"PADDING"
            path.write_bytes(outer)
            with self.assertRaisesRegex(LAYERS.Failure, "member padding"):
                LAYERS.audit(path, identity)

    def test_nonregular_payload_and_outer_archive_tail_are_refused(self):
        body = io.BytesIO()
        with tarfile.open(fileobj=body, mode="w") as archive:
            member = tarfile.TarInfo("usr/link")
            member.type = tarfile.SYMTYPE
            member.linkname = "target"
            member.size = 14
            archive.addfile(member, io.BytesIO(b"excluded bytes"))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path, identity = saved_image(root, [body.getvalue()])
            with self.assertRaises(LAYERS.Failure):
                LAYERS.audit(path, identity)
            path, identity = saved_image(root, [tar_bytes([("usr/file", b"safe")])])
            path.write_bytes(path.read_bytes() + b"unmeasured outer payload")
            with self.assertRaises(LAYERS.Failure):
                LAYERS.audit(path, identity)

    def test_pax_payloads_are_measured_and_inspected(self):
        jar = zip_bytes("org/eclipse/jdt/internal/jarinjarloader/JarRsrcLoader.class", b"class")
        for value in ("excluded bytes", jar.decode("utf-8", errors="surrogateescape")):
            body = io.BytesIO()
            with tarfile.open(fileobj=body, mode="w", format=tarfile.PAX_FORMAT) as archive:
                member = tarfile.TarInfo("usr/allowed")
                member.pax_headers = {"audit-payload": value}
                archive.addfile(member)
            with self.subTest(value_size=len(value)), tempfile.TemporaryDirectory() as temporary, \
                 patch.object(LAYERS, "BLOCKED_DIGESTS", frozenset([sha(b"excluded bytes")])):
                path, identity = saved_image(Path(temporary), [body.getvalue()])
                report = LAYERS.audit(path, identity)
                self.assertTrue(report["layers"][0]["metadataPayloads"])
                self.assertTrue(report["excludedPayloadFindings"])
                self.assertEqual(report["exclusionGate"], "FAILED")

    def test_orphan_zip_local_payload_keeps_exclusion_gate_pending(self):
        jar = zip_bytes("org/eclipse/jdt/internal/jarinjarloader/JarRsrcLoader.class", b"class")
        orphan = jar[:jar.index(b"PK\x01\x02")]
        with tempfile.TemporaryDirectory() as temporary:
            path, identity = saved_image(Path(temporary), [tar_bytes([("usr/renamed.whl", orphan + zip_bytes("module.py", b"pass\n"))])])
            report = LAYERS.audit(path, identity)
            self.assertTrue(report["archiveInspectionGaps"])
            self.assertEqual(report["exclusionGate"], "PENDING_ARCHIVE_COVERAGE")

    def test_compressed_zip_directory_payload_is_not_skipped(self):
        jar = zip_bytes("org/eclipse/jdt/internal/jarinjarloader/JarRsrcLoader.class", b"class")
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("allowed/", jar)
        with tempfile.TemporaryDirectory() as temporary:
            path, identity = saved_image(Path(temporary), [tar_bytes([("usr/renamed.whl", output.getvalue())])])
            report = LAYERS.audit(path, identity)
            self.assertTrue(report["excludedPayloadFindings"])
            self.assertEqual(report["exclusionGate"], "FAILED")

    def test_false_empty_stored_directory_and_member_comment_remain_pending(self):
        stored = bytearray(zip_bytes("allowed/", b"unmeasured bytes"))
        central = stored.index(b"PK\x01\x02")
        struct.pack_into("<I", stored, 22, 0)
        struct.pack_into("<I", stored, central + 24, 0)
        commented = io.BytesIO()
        with zipfile.ZipFile(commented, "w") as archive:
            member = zipfile.ZipInfo("allowed.py")
            member.comment = b"opaque member metadata"
            archive.writestr(member, b"pass\n")
        for payload in (bytes(stored), commented.getvalue()):
            with self.subTest(payload_size=len(payload)), tempfile.TemporaryDirectory() as temporary:
                path, identity = saved_image(Path(temporary), [tar_bytes([("usr/renamed.whl", payload)])])
                report = LAYERS.audit(path, identity)
                self.assertTrue(report["archiveInspectionGaps"])
                self.assertEqual(report["exclusionGate"], "PENDING_ARCHIVE_COVERAGE")

    def test_tar_extension_size_is_bounded_before_parser_allocation(self):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as archive:
            member = tarfile.TarInfo("usr/allowed")
            member.pax_headers = {"audit-payload": "oversized metadata"}
            archive.addfile(member)
        with tempfile.TemporaryDirectory() as temporary, patch.object(LAYERS, "MAX_METADATA_BYTES", 8):
            path, identity = saved_image(Path(temporary), [output.getvalue()])
            # Manifest size exceeds this synthetic low bound too; the direct
            # layer call isolates the extension parser's allocation boundary.
            counters = {"payloadBytes": 0, "metadataBytes": 0, "layerMembers": 0, "zipArchives": 0, "zipMembers": 0, "zipExpandedBytes": 0}
            with self.assertRaises(LAYERS.Failure):
                LAYERS.layer_inventory(io.BytesIO(output.getvalue()), 0, [], [], counters)

    def test_source_carrier_exact_inventory_and_outer_root_boundary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = b"source bytes"
            receipt = json.dumps({"schemaVersion": 1, "inventory": [{"path": "context/source.go", "sizeBytes": len(payload), "sha256": sha(payload), "mode": "0644"}]}).encode()
            inventory = root / "source-inventory.json"
            inventory.write_bytes(receipt)
            entries = [("corresponding-source/context/source.go", payload), ("corresponding-source/source-inventory.json", receipt)]
            path, identity = saved_image(root, [tar_bytes(entries)])
            self.assertTrue(LAYERS.audit(path, identity, inventory)["sourceCarrierInventoryVerified"])
            for changed in (entries + [("outside", b"unexpected")], [entries[0], (entries[1][0], b"tampered")]):
                path, identity = saved_image(root, [tar_bytes(changed)])
                with self.assertRaises(LAYERS.Failure):
                    LAYERS.audit(path, identity, inventory)
            path, identity = saved_image(root, [tar_bytes(entries), tar_bytes([("corresponding-source/extra", b"x")])])
            with self.assertRaises(LAYERS.Failure):
                LAYERS.audit(path, identity, inventory)

    def test_uninspected_archive_and_size_bounds_remain_pending(self):
        for payload, options in ((b"\x1f\x8bnot inspected", {}), (b"oversized", {"MAX_ZIP_BYTES": 4})):
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as temporary, patch.multiple(LAYERS, **options) if options else nullcontext():
                path, identity = saved_image(Path(temporary), [tar_bytes([("usr/archive", payload)])])
                report = LAYERS.audit(path, identity)
                self.assertTrue(report["archiveInspectionGaps"])
                self.assertEqual(report["exclusionGate"], "PENDING_ARCHIVE_COVERAGE")
                self.assertEqual(report["wholeImageSBOM"], "SEPARATE_EVIDENCE_REQUIRED")


if __name__ == "__main__":
    unittest.main()
