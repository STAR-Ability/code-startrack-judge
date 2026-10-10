"""Inert fixtures verify crate envelopes, physical headers and receipt bindings."""

import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CRATES = load("image_crates", ROOT / "scripts/audit-image-crates.py")
FIXTURE = load("image_crates_fixture", ROOT / "tests/test_image_layers.py")
FILENAME = "example-1.0.0.crate"
CRATE_ROOT = "example-1.0.0"


def compressed(body, filename=FILENAME):
    output = io.BytesIO()
    with gzip.GzipFile(filename=filename, fileobj=output, mode="wb", mtime=0) as stream:
        stream.write(body)
    return output.getvalue()


def crate_tar(entries=((CRATE_ROOT + "/src/lib.rs", b"pub fn fixture() {}\n"),), *, format=tarfile.GNU_FORMAT):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=format) as archive:
        for name, body in entries:
            member = name if isinstance(name, tarfile.TarInfo) else tarfile.TarInfo(name)
            member.size = len(body)
            member.mode = 0o644
            archive.addfile(member, io.BytesIO(body))
    return output.getvalue()


def checked_header(header):
    header = bytearray(header)
    header[148:156] = b"        "
    checksum = sum(header)
    header[148:156] = f"{checksum:06o}\0 ".encode()
    return bytes(header)


def replace_header(body, start, finish, replacement):
    header = bytearray(body[:512])
    header[start:finish] = replacement
    return checked_header(header) + body[512:]


def inventory_hashes(receipt):
    for layer in receipt["layers"]:
        for rows, key in ((layer["inventory"], "inventorySHA256"), (layer["metadataPayloads"], "metadataInventorySHA256")):
            layer[key] = FIXTURE.sha(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode())
        layer["memberCount"] = len(layer["inventory"])


class ImageCrateTests(unittest.TestCase):
    def report(self, value=None, *, source_change=None, service_change=None, lock_change=None, call_change=None,
               source_extra=(), service_extra=()):
        value = compressed(crate_tar()) if value is None else value
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_root, service_root = root / "source", root / "service"
            source_root.mkdir()
            service_root.mkdir()
            lock_data = {"crateSources": [{"name": "example", "version": "1.0.0", "filename": FILENAME,
                                           "sizeBytes": len(value), "sha256": FIXTURE.sha(value)}]}
            if lock_change:
                lock_change(lock_data)
            lock_body = json.dumps(lock_data).encode()
            lock = root / "lock.json"
            lock.write_bytes(lock_body)
            source_layer = FIXTURE.tar_bytes([(CRATES.SOURCE_PREFIX + FILENAME, value), (CRATES.LOCK_PATH, lock_body), *source_extra])
            service_layer = FIXTURE.tar_bytes([(CRATES.SERVICE_PREFIX + FILENAME, value), *service_extra])
            source, source_id, source_manifest = FIXTURE.saved_oci_image(source_root, [source_layer], filename="rootfs.tar")
            service, service_id, service_manifest = FIXTURE.saved_oci_image(service_root, [service_layer])
            source_receipt = FIXTURE.LAYERS.audit(source, source_id)
            # Fixture stands in for an already verified original carrier receipt.
            source_receipt["sourceCarrierInventoryVerified"] = True
            service_receipt = FIXTURE.LAYERS.audit(service, service_id)
            if source_change:
                source_change(source_receipt)
            if service_change:
                service_change(service_receipt)
            source_physical, service_physical = root / "source.json", root / "service.json"
            source_physical.write_text(json.dumps(source_receipt))
            service_physical.write_text(json.dumps(service_receipt))
            args = {"source_archive": source, "source_archive_sha256": FIXTURE.sha(source.read_bytes()),
                    "source_image_config_id": source_id, "source_image_manifest_id": source_manifest,
                    "source_physical_receipt": source_physical, "source_physical_receipt_sha256": FIXTURE.sha(source_physical.read_bytes()),
                    "service_archive_sha256": FIXTURE.sha(service.read_bytes()), "service_image_config_id": service_id,
                    "service_image_manifest_id": service_manifest, "service_physical_receipt": service_physical,
                    "service_physical_receipt_sha256": FIXTURE.sha(service_physical.read_bytes()), "lock": lock,
                    "lock_sha256": FIXTURE.sha(lock_body)}
            if call_change:
                call_change(args)
            with patch.object(CRATES, "EXPECTED_CRATES", 1):
                return CRATES.audit(**args)

    def assert_gap(self, value, reason):
        report = self.report(value)
        self.assertEqual(report["measuredCrateCount"], 0)
        self.assertIn(reason, {row["reason"] for row in report["archiveInspectionGaps"]})
        for accounting in report["gapAccounting"].values():
            self.assertEqual(accounting["resolvedOriginalCrateGapRows"], 0)
            self.assertEqual(accounting["originalUnresolvedGapRows"], 1)
        return report

    def test_full_hashes_envelope_members_and_original_gate_accounting(self):
        payload = b"pub fn fixture() {}\n"
        for format in (tarfile.GNU_FORMAT, tarfile.USTAR_FORMAT):
            tar_body = crate_tar(format=format)
            value = compressed(tar_body)
            report = self.report(value)
            row = report["inventory"][0]
            self.assertEqual(report["measuredCrateCount"], 1)
            self.assertEqual(row["status"], "MEASURED")
            self.assertEqual(row["compressedSHA256"], FIXTURE.sha(value))
            self.assertEqual(row["expandedSHA256"], FIXTURE.sha(tar_body))
            self.assertEqual(row["gzipHeaderSHA256"], FIXTURE.sha(value[:10 + len(FILENAME) + 1]))
            self.assertEqual(row["members"][0]["rawHeaderSHA256"], FIXTURE.sha(tar_body[:512]))
            self.assertEqual(row["members"][0]["sha256"], FIXTURE.sha(payload))
            self.assertEqual(report["measurement"]["physicalCrateHeaders"], 1)
            self.assertTrue(report["sourceLayerMeasurement"]["sourceSaveSHA256BeforeAndAfterVerified"])
            for accounting in report["gapAccounting"].values():
                self.assertEqual(accounting["resolvedOriginalCrateGapRows"], 1)
                self.assertEqual(accounting["originalUnresolvedGapRows"], 0)
            self.assertFalse(report["qualified"])
            self.assertFalse(report["legalAccepted"])
            self.assertFalse(report["originalReceiptReplaced"])
            self.assertIn("NO_SERVICE_ARCHIVE_OR_CURRENT_DOCKER_REMEASUREMENT", report["serviceAssociation"])
            self.assertEqual(report["exclusionGate"], "PENDING_OTHER_PHYSICAL_GAPS_AND_LEGAL_RECONCILIATION")

    def test_gnu_long_name_header_payload_and_association_are_measured(self):
        path = CRATE_ROOT + "/" + "nested/" * 20 + "lib.rs"
        tar_body = crate_tar([(path, b"inert source")])
        report = self.report(compressed(tar_body))
        row = report["inventory"][0]
        self.assertEqual(row["status"], "MEASURED")
        self.assertEqual(row["memberCount"], 1)
        self.assertEqual(row["physicalHeaderCount"], 2)
        meta = row["gnuLongNameMetadata"][0]
        self.assertEqual(meta["associatedPath"], path)
        self.assertEqual(meta["sha256"], FIXTURE.sha(path.encode() + b"\0"))
        self.assertEqual(meta["rawHeaderSHA256"], FIXTURE.sha(tar_body[:512]))
        self.assertEqual(row["members"][0]["path"], path)

    def test_bad_gzip_crc_isize_truncation_concatenation_and_trailing_bytes(self):
        good = compressed(crate_tar())
        for value, reason in ((good[:-8] + bytes([good[-8] ^ 1]) + good[-7:], "CRATE_GZIP_INVALID_CRC_ISIZE_OR_MEMBER"),
                              (good[:-1] + bytes([good[-1] ^ 1]), "CRATE_GZIP_INVALID_CRC_ISIZE_OR_MEMBER"),
                              (good[:-1], "CRATE_GZIP_TRUNCATED_MEMBER"),
                              (good + good, "CRATE_GZIP_CONCATENATED_OR_TRAILING_BYTES"),
                              (good + b"\0", "CRATE_GZIP_CONCATENATED_OR_TRAILING_BYTES")):
            with self.subTest(reason=reason):
                self.assert_gap(value, reason)

    def test_gzip_optional_profiles_and_filename_are_not_discarded(self):
        self.assert_gap(compressed(crate_tar(), "other.crate"), "CRATE_GZIP_FILENAME_DIFFERS_FROM_LOCK")
        self.assert_gap(compressed(crate_tar(), ""), "CRATE_GZIP_HEADER_PROFILE_UNSUPPORTED")
        good = compressed(crate_tar())
        for flags in (9, 12, 24, 40):
            self.assert_gap(good[:3] + bytes([flags]) + good[4:], "CRATE_GZIP_HEADER_PROFILE_UNSUPPORTED")
        no_name = good[:10] + b"a" * 4097 + good[10 + len(FILENAME):]
        self.assert_gap(no_name, "CRATE_GZIP_FILENAME_UNTERMINATED_OR_BOUND")

    def test_path_scope_duplicates_and_nonnormalized_paths_remain_gaps(self):
        for name, reason in (("../escape", "TAR_UNSAFE_OR_INVALID_PATH"),
                             ("/absolute", "TAR_UNSAFE_OR_INVALID_PATH"),
                             ("other-1.0.0/file", "TAR_PATH_OUTSIDE_LOCKED_CRATE_ROOT"),
                             (CRATE_ROOT, "TAR_PATH_OUTSIDE_LOCKED_CRATE_ROOT"),
                             ("./" + CRATE_ROOT + "/file", "TAR_PATH_OUTSIDE_LOCKED_CRATE_ROOT"),
                             (CRATE_ROOT + "/file//", "TAR_PATH_OUTSIDE_LOCKED_CRATE_ROOT")):
            self.assert_gap(compressed(crate_tar([(name, b"inert")])), reason)
        path = CRATE_ROOT + "/file"
        self.assert_gap(compressed(crate_tar([(path, b"one"), (path, b"two")])), "TAR_DUPLICATE_PATH")

    def test_links_sparse_devices_fifo_pax_and_unrecognized_types_keep_gap(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE,
                     tarfile.FIFOTYPE, tarfile.GNUTYPE_SPARSE, tarfile.XHDTYPE, tarfile.XGLTYPE, b"Z"):
            member = tarfile.TarInfo(CRATE_ROOT + "/unsupported")
            member.type = kind
            member.linkname = CRATE_ROOT + "/target" if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE) else ""
            with self.subTest(kind=kind):
                self.assert_gap(compressed(crate_tar([(member, b"")])), "TAR_ENTRY_TYPE_UNSUPPORTED")

    def test_bad_headers_numeric_suffix_reserved_fields_and_normalization(self):
        good = crate_tar()
        damaged = bytearray(good)
        damaged[10] ^= 1
        self.assert_gap(compressed(bytes(damaged)), "TAR_RAW_HEADER_INVALID")
        for start, finish, replacement, reason in ((257, 265, b"junkjunk", "TAR_HEADER_PROFILE_UNSUPPORTED"),
                                                    (108, 116, b"\xff" * 8, "TAR_NUMERIC_FIELD_PROFILE_UNSUPPORTED"),
                                                    (124, 136, b"0000000\0ZIP!", "TAR_NUMERIC_FIELD_PROFILE_UNSUPPORTED"),
                                                    (124, 136, b"0000000\x000123", "TAR_NUMERIC_FIELD_PROFILE_UNSUPPORTED"),
                                                    (500, 512, b"hidden-bytes", "TAR_GNU_EXTENSION_UNSUPPORTED")):
            self.assert_gap(compressed(replace_header(good, start, finish, replacement)), reason)
        member = tarfile.TarInfo(CRATE_ROOT + "/directory/")
        member.type = tarfile.AREGTYPE
        self.assert_gap(compressed(crate_tar([(member, b"")])), "TAR_HEADER_NORMALIZATION_UNSUPPORTED")

    def test_legacy_mode_type_bits_must_match_entry_type_and_remain_recorded(self):
        good = crate_tar()
        legacy_regular = replace_header(good, 100, 108, b"0100644\0")
        report = self.report(compressed(legacy_regular))
        self.assertEqual(report["measuredCrateCount"], 1)
        member = report["inventory"][0]["members"][0]
        self.assertEqual(member["rawModeOctal"], "100644")
        self.assertEqual(member["permissionModeOctal"], "0644")
        self.assertEqual(member["rawHeaderSHA256"], FIXTURE.sha(legacy_regular[:512]))
        for mode in (b"0040644\0", b"0120644\0", b"0200644\0"):
            self.assert_gap(compressed(replace_header(good, 100, 108, mode)), "TAR_MODE_TYPE_BITS_UNSUPPORTED")
        directory = tarfile.TarInfo(CRATE_ROOT + "/directory/")
        directory.type = tarfile.DIRTYPE
        tar_body = crate_tar([(directory, b"")])
        report = self.report(compressed(replace_header(tar_body, 100, 108, b"0040755\0")))
        self.assertEqual(report["measuredCrateCount"], 1)
        self.assert_gap(compressed(replace_header(tar_body, 100, 108, b"0100755\0")), "TAR_MODE_TYPE_BITS_UNSUPPORTED")

    def test_tar_padding_two_end_blocks_length_and_full_trailer(self):
        good = crate_tar([(CRATE_ROOT + "/file", b"x")])
        bad_padding = good[:513] + b"x" + good[514:]
        self.assert_gap(compressed(bad_padding), "TAR_NONZERO_MEMBER_PADDING")
        self.assert_gap(compressed(good[:1024 + 512]), "TAR_TWO_END_BLOCKS_REQUIRED")
        self.assert_gap(compressed(good[:-1]), "TAR_BLOCK_LENGTH_INVALID")
        self.assert_gap(compressed(good + b"x" * 512), "TAR_NONZERO_TRAILING_BYTES")
        self.assert_gap(compressed(good + good), "TAR_NONZERO_TRAILING_BYTES")

    def test_gnu_long_name_chained_dangling_and_unsafe_associations(self):
        path = CRATE_ROOT + "/" + "long/" * 30 + "file"
        good = crate_tar([(path, b"x")])
        metadata_end = 512 + ((len(path.encode()) + 1 + 511) // 512) * 512
        self.assert_gap(compressed(good[:metadata_end] + b"\0" * 1024), "TAR_DANGLING_GNU_LONGNAME")
        self.assert_gap(compressed(good[:metadata_end] + good), "TAR_GNU_LONGNAME_PROFILE_UNSUPPORTED")
        unsafe = "../" + "x/" * 70 + "file"
        self.assert_gap(compressed(crate_tar([(unsafe, b"x")])), "TAR_UNSAFE_OR_INVALID_PATH")

    def test_every_gnu_metadata_and_regular_header_has_a_unique_inspection_location(self):
        path = CRATE_ROOT + "/" + "long/" * 30 + "file"
        observed = []
        original = CRATES.Budget.inspect
        def inspected(budget, body, head, location, findings, gaps):
            if "!tar-header[" in location and "!gnu-longname" not in location:
                observed.append(location)
            return original(budget, body, head, location, findings, gaps)
        with patch.object(CRATES.Budget, "inspect", inspected):
            report = self.report(compressed(crate_tar([(path, b"x")])))
        self.assertEqual(report["measuredCrateCount"], 1)
        self.assertEqual(len(observed), 2)
        self.assertEqual(len(set(observed)), 2)
        self.assertEqual([value.rsplit("[", 1)[-1] for value in observed], ["0]", "1]"])

    def test_nested_archives_findings_class_and_exact_digests_are_retained(self):
        nested_gzip = compressed(b"unsupported nested gzip")
        self.assert_gap(compressed(crate_tar([(CRATE_ROOT + "/asset", nested_gzip)])), CRATES.ORIGINAL_GAP)
        jar = FIXTURE.zip_bytes("Viva/excluded.class", b"inert")
        report = self.report(compressed(crate_tar([(CRATE_ROOT + "/asset", jar)])))
        self.assertEqual(report["exclusionGate"], "FAILED")
        self.assertEqual(report["measuredCrateCount"], 0)
        self.assertTrue(report["excludedPayloadFindings"])
        name = b"org/eclipse/jdt/internal/jarinjarloader/JarRsrcLoader"
        java = (b"\xca\xfe\xba\xbe" + struct.pack(">HHH", 0, 52, 3) + b"\x01" + struct.pack(">H", len(name))
                + name + b"\x07\x00\x01" + struct.pack(">HHH", 0x21, 2, 0))
        report = self.report(compressed(crate_tar([(CRATE_ROOT + "/renamed", java)])))
        self.assertIn("EXCLUDED_JAVA_CLASS_DEFINITION", {row["reason"] for row in report["excludedPayloadFindings"]})
        with patch.object(CRATES.LAYERS, "BLOCKED_DIGESTS", frozenset([FIXTURE.sha(b"excluded fixture")])):
            report = self.report(compressed(crate_tar([(CRATE_ROOT + "/renamed", b"excluded fixture")])))
        self.assertEqual(report["exclusionGate"], "FAILED")
        self.assertEqual(report["measuredCrateCount"], 0)

    def test_valid_nested_zip_does_not_create_a_structural_tar_gap(self):
        jar = FIXTURE.zip_bytes("allowed/file.txt", b"inert")
        report = self.report(compressed(crate_tar([(CRATE_ROOT + "/asset", jar)])))
        self.assertEqual(report["measuredCrateCount"], 1)
        self.assertEqual(report["measurement"]["zipArchives"], 1)

    def test_embedded_zip_in_raw_header_and_metadata_is_inspected_before_refusal(self):
        jar = FIXTURE.zip_bytes("Viva/x.class", b"x")
        good = crate_tar()
        header = bytearray(good[:512])
        header[265:265 + len(jar)] = jar
        report = self.report(compressed(checked_header(header) + good[512:]))
        self.assertTrue(report["excludedPayloadFindings"])
        self.assertEqual(report["measuredCrateCount"], 0)
        metadata = tarfile.TarInfo("././@LongLink")
        metadata.type = tarfile.GNUTYPE_LONGNAME
        report = self.report(compressed(crate_tar([(metadata, jar + b"\0")])))
        self.assertTrue(report["excludedPayloadFindings"])
        self.assertEqual(report["measuredCrateCount"], 0)

    def test_mismatched_all_explicit_hashes_and_image_ids_refuse_receipt(self):
        for key in ("source_archive_sha256", "source_physical_receipt_sha256", "service_archive_sha256",
                    "service_physical_receipt_sha256", "lock_sha256", "source_image_config_id",
                    "source_image_manifest_id", "service_image_config_id", "service_image_manifest_id"):
            value = ("sha256:" if key.endswith("_id") else "") + "0" * 64
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.report(call_change=lambda args: args.__setitem__(key, value))

    def test_receipt_inventory_scope_count_and_source_verification_are_required(self):
        changes = [lambda receipt: receipt.__setitem__("completePhysicalLayerInventory", False),
                   lambda receipt: receipt.__setitem__("scope", "MERGED_ROOTFS"),
                   lambda receipt: receipt["layers"][0].__setitem__("memberCount", True),
                   lambda receipt: receipt["layers"][0].__setitem__("inventorySHA256", "0" * 64),
                   lambda receipt: receipt["layers"][0].__setitem__("metadataInventorySHA256", "0" * 64)]
        for role in ("source_change", "service_change"):
            for change in changes:
                with self.subTest(role=role, change=change), self.assertRaises(ValueError):
                    self.report(**{role: change})
        with self.assertRaises(ValueError):
            self.report(source_change=lambda receipt: receipt.__setitem__("sourceCarrierInventoryVerified", False))

    def test_exact_lock_and_physical_sets_cannot_omit_add_or_rebind_a_crate(self):
        for change in (lambda lock: lock["crateSources"].clear(),
                       lambda lock: lock["crateSources"].append(dict(lock["crateSources"][0])),
                       lambda lock: lock["crateSources"][0].__setitem__("filename", "different.crate"),
                       lambda lock: lock["crateSources"][0].__setitem__("sizeBytes", True)):
            with self.assertRaises(ValueError):
                self.report(lock_change=change)
        for role, prefix in (("source_extra", CRATES.SOURCE_PREFIX), ("service_extra", CRATES.SERVICE_PREFIX)):
            with self.assertRaises(ValueError):
                self.report(**{role: [(prefix + "extra.crate", compressed(crate_tar()))]})
        def omitted(receipt):
            receipt["layers"][0]["inventory"] = [row for row in receipt["layers"][0]["inventory"] if not row["path"].endswith(FILENAME)]
            inventory_hashes(receipt)
        def rebound(receipt):
            row = next(row for row in receipt["layers"][0]["inventory"] if row["path"].endswith(FILENAME))
            row["sha256"] = "0" * 64
            inventory_hashes(receipt)
        def duplicate_gap(receipt):
            receipt["archiveInspectionGaps"].append(dict(receipt["archiveInspectionGaps"][0]))
        for role in ("source_change", "service_change"):
            for change in (omitted, rebound, duplicate_gap):
                with self.assertRaises(ValueError):
                    self.report(**{role: change})

    def test_only_selected_rows_resolve_and_original_findings_stay_failed(self):
        other = compressed(b"outside locked crate scope", "other")
        report = self.report(source_extra=[("corresponding-source/context/other.gz", other)],
                             service_extra=[("opt/other.gz", other)])
        for accounting in report["gapAccounting"].values():
            self.assertEqual(accounting["resolvedOriginalCrateGapRows"], 1)
            self.assertEqual(accounting["originalUnresolvedGapRows"], 1)
        report = self.report(service_change=lambda receipt: receipt["excludedPayloadFindings"].append({"location": "prior", "reason": "prior"}))
        self.assertEqual(report["exclusionGate"], "FAILED")

    def test_distributed_lock_layer_hash_size_count_and_save_bytes_are_bound(self):
        def different_lock(args):
            body = args["lock"].read_bytes() + b" "
            args["lock"].write_bytes(body)
            args["lock_sha256"] = FIXTURE.sha(body)
        with self.assertRaises(ValueError):
            self.report(call_change=different_lock)
        for field, value in (("diffID", "sha256:" + "0" * 64), ("storedBlobSHA256", "0" * 64),
                             ("storedBlobSizeBytes", 1), ("tarSizeBytes", 512)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.report(source_change=lambda receipt: receipt["layers"][0].__setitem__(field, value))
        def appended_save(args):
            with args["source_archive"].open("ab") as stream:
                stream.write(b"unbound")
        with self.assertRaises(ValueError):
            self.report(call_change=appended_save)

    def test_single_link_nofollow_nonblocking_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            file = root / "file"
            file.write_bytes(b"inert")
            symlink = root / "symlink"
            symlink.symlink_to(file)
            with self.assertRaises(OSError):
                CRATES.regular_file(symlink, 100)
            os.link(file, root / "hardlink")
            with self.assertRaises(ValueError):
                CRATES.regular_file(file, 100)
            fifo = root / "fifo"
            os.mkfifo(fifo)
            with self.assertRaises(ValueError):
                CRATES.regular_file(fifo, 100)

    def test_per_crate_and_aggregate_bounds_deadline_and_report_accumulation(self):
        with patch.object(CRATES, "MAX_EXPANDED_BYTES", 512):
            self.assert_gap(compressed(crate_tar()), "CRATE_GZIP_EXPANSION_BOUND")
        for constant, maximum in (("MAX_TOTAL_EXPANDED_BYTES", 512), ("MAX_TOTAL_COMPRESSED_BYTES", 1),
                                  ("MAX_COMPRESSED_BYTES", 1), ("MAX_PHYSICAL_HEADERS", 0),
                                  ("MAX_REPORT_BYTES", 4097), ("DEADLINE_SECONDS", -1)):
            with self.subTest(constant=constant), patch.object(CRATES, constant, maximum), self.assertRaises(ValueError):
                self.report()
        with patch.object(CRATES, "MAX_MEMBER_BYTES", 1):
            self.assert_gap(compressed(crate_tar()), "TAR_MEMBER_BOUNDS_UNSUPPORTED")

    def test_output_is_fresh_and_beneath_task_owned_repository_directories(self):
        with tempfile.TemporaryDirectory(dir=ROOT / ".local") as temporary:
            root = Path(temporary)
            destination = root / "fresh.json"
            self.assertEqual(CRATES.destination_path(destination), destination)
            destination.write_bytes(b"preserved")
            with self.assertRaises(ValueError):
                CRATES.destination_path(destination)
            link = root / "link"
            link.symlink_to(destination)
            with self.assertRaises(ValueError):
                CRATES.destination_path(link)
            self.assertEqual(destination.read_bytes(), b"preserved")
        with self.assertRaises(ValueError):
            CRATES.destination_path(ROOT / "unowned-output.json")
        with self.assertRaises(ValueError):
            CRATES.destination_path(Path("/tmp/outside-crate-receipt.json"))


if __name__ == "__main__":
    unittest.main()
