"""Inert byte fixtures exercise full-input ar structure and excluded ZIPs."""

import importlib.util
import io
from pathlib import Path
import struct
import unittest
from unittest.mock import patch
import zipfile
import zlib


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("image_ar", ROOT / "scripts/audit-image-ar.py")
AR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AR)


def header(name, size, *, mtime=b"0", uid=b"0", gid=b"0", mode=b"644"):
    field = name if isinstance(name, bytes) else (name + "/").encode()
    return (field.ljust(16, b" ") + mtime.ljust(12, b" ") + uid.ljust(6, b" ")
            + gid.ljust(6, b" ") + mode.ljust(8, b" ") + str(size).encode().ljust(10, b" ") + b"`\n")


def member(name, payload=b"", **fields):
    return header(name, len(payload), **fields) + payload + (b"\n" if len(payload) % 2 else b"")


def indexed(symbols=(b"cabi_realloc",), *, suffix=None, offset_delta=0):
    names = b"".join(value + b"\0" for value in symbols)
    core = struct.pack(">I", len(symbols)) + b"\0" * (4 * len(symbols)) + names
    pad = b"\0" if len(core) % 2 else b""
    payload = core + (pad if suffix is None else suffix)
    ordinary_offset = 8 + 60 + len(payload) + len(payload) % 2
    payload = struct.pack(">I", len(symbols)) + b"".join(struct.pack(">I", ordinary_offset + offset_delta)
                                                        for _ in symbols) + names + (pad if suffix is None else suffix)
    return AR.MAGIC + member(b"/", payload, mode=b"0") + member("cabi_realloc.o", b"object-fixture")


def zipped(name="viva.jar", payload=b"inert", *, compression=zipfile.ZIP_STORED):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=compression) as archive:
        info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
        info.compress_type = compression
        archive.writestr(info, payload)
    return output.getvalue()


class ImageArTests(unittest.TestCase):
    def report(self, body):
        return AR.audit(body, "fixture.a")

    def assert_gap(self, body, reason):
        report = self.report(body)
        self.assertEqual(report["status"], "GAP")
        self.assertIn(reason, [row["reason"] for row in report["archiveInspectionGaps"]])
        self.assertFalse(report["qualified"])
        self.assertFalse(report["legalAccepted"])
        return report

    def test_empty_archive_is_fully_consumed_without_outer_archive_gap(self):
        report = self.report(AR.MAGIC)
        self.assertEqual(report["status"], "MEASURED")
        self.assertEqual(report["memberCount"], 0)
        self.assertTrue(report["fullInputConsumed"])
        self.assertFalse(report["qualified"])
        self.assertFalse(report["legalAccepted"])
        self.assertFalse(report["originalReceiptReplaced"])

    def test_even_and_odd_members_record_all_padding(self):
        report = self.report(AR.MAGIC + member("even.o", b"AB") + member("odd.o", b"C"))
        self.assertEqual(report["status"], "MEASURED")
        self.assertEqual([row["headerOffsetBytes"] for row in report["members"]], [8, 70])
        self.assertEqual([row["paddingSizeBytes"] for row in report["members"]], [0, 1])
        self.assertEqual(report["members"][1]["paddingSHA256"], AR.LAYERS.sha(b"\n"))

    def test_index_header_offsets_names_and_internal_zero_padding(self):
        report = self.report(indexed())
        self.assertEqual(report["status"], "MEASURED")
        index = report["members"][0]
        self.assertEqual(index["symbolCount"], 1)
        self.assertEqual(index["indexPaddingSizeBytes"], 1)
        self.assertEqual(index["indexPaddingSHA256"], AR.LAYERS.sha(b"\0"))
        self.assertEqual(index["symbols"][0]["memberHeaderOffsetBytes"], report["members"][1]["headerOffsetBytes"])

    def test_multiple_symbols_may_reference_one_member(self):
        report = self.report(indexed((b"first", b"second")))
        self.assertEqual(report["status"], "MEASURED")
        self.assertEqual(report["members"][0]["symbolCount"], 2)

    def test_unindexed_ordinary_members_are_allowed(self):
        report = self.report(indexed() + member("other.o", b"other"))
        self.assertEqual(report["status"], "MEASURED")

    def test_exact_512_byte_boundary(self):
        body = AR.MAGIC + member("max.o", b"x" * 444)
        self.assertEqual(len(body), 512)
        self.assertEqual(self.report(body)["status"], "MEASURED")
        self.assert_gap(body + b"x", "AR_INPUT_BYTES_BOUND")

    def test_eight_physical_entries_include_index(self):
        body = AR.MAGIC + member(b"/", struct.pack(">I", 0), mode=b"0")
        body += b"".join(member(f"m{i}.o") for i in range(7))
        self.assertEqual(self.report(body)["memberCount"], 8)
        self.assert_gap(AR.MAGIC + b"".join(member(f"m{i}.o") for i in range(8)) + b"x", "AR_MEMBER_COUNT_BOUND")

    def test_short_name_uses_all_fifteen_available_characters(self):
        self.assertEqual(self.report(AR.MAGIC + member("abcdefghijklmno"))["status"], "MEASURED")

    def test_thin_bsd_long_name_gnu64_and_unsafe_names_remain_gaps(self):
        self.assert_gap(b"!<thin>\n", "AR_MAGIC_OR_VARIANT_UNSUPPORTED")
        for name in (b"#1/4", b"__.SYMDEF/", b"//", b"/0", b"/SYM64/", b"../bad/", b"/absolute/", b"no-slash", b"bad name/", b"a\\b/"):
            with self.subTest(name=name):
                self.assert_gap(AR.MAGIC + member(name), "AR_MEMBER_NAME_PROFILE_UNSUPPORTED")

    def test_duplicate_short_names_remain_gaps(self):
        self.assert_gap(AR.MAGIC + member("same.o") * 2, "AR_DUPLICATE_MEMBER_NAME")

    def test_index_must_be_first_and_unique(self):
        index = member(b"/", struct.pack(">I", 0), mode=b"0")
        for body in (AR.MAGIC + member("a.o") + index, AR.MAGIC + index * 2):
            self.assert_gap(body, "AR_GNU32_INDEX_NOT_UNIQUE_FIRST_MEMBER")

    def test_bad_numeric_fields_fail_closed(self):
        for fields in ({"mtime": b" 1"}, {"uid": b"-1"}, {"gid": b"+1"}, {"mode": b"888"}, {"uid": b""}, {"mtime": b"1\0"}):
            with self.subTest(fields=fields):
                self.assert_gap(AR.MAGIC + member("a.o", **fields), "AR_NUMERIC_FIELD_PROFILE_UNSUPPORTED")

    def test_numeric_member_size_bound(self):
        self.assert_gap(AR.MAGIC + header("a.o", 513), "AR_NUMERIC_FIELD_BOUND")

    def test_nonregular_mode_type_is_rejected(self):
        self.assert_gap(AR.MAGIC + member("a.o", mode=b"120644"), "AR_MODE_TYPE_UNSUPPORTED")

    def test_index_attributes_may_be_blank(self):
        report = self.report(AR.MAGIC + member(b"/", struct.pack(">I", 0), mtime=b"", uid=b"", gid=b"", mode=b""))
        self.assertEqual(report["status"], "MEASURED")
        self.assertIsNone(report["members"][0]["mtime"])

    def test_invalid_header_terminator(self):
        self.assert_gap(AR.MAGIC + header("a.o", 0)[:-2] + b"xx", "AR_HEADER_TERMINATOR_INVALID")

    def test_header_payload_padding_and_trailer_truncations(self):
        for body, reason in ((AR.MAGIC + b"short", "AR_TRUNCATED_HEADER_OR_TRAILING_BYTES"),
                             (AR.MAGIC + header("a.o", 2) + b"x", "AR_TRUNCATED_PAYLOAD_OR_PADDING"),
                             ((AR.MAGIC + member("a.o", b"x"))[:-1], "AR_TRUNCATED_PAYLOAD_OR_PADDING"),
                             (AR.MAGIC + member("a.o") + b"\0\0", "AR_TRUNCATED_HEADER_OR_TRAILING_BYTES")):
            with self.subTest(reason=reason):
                self.assert_gap(body, reason)

    def test_non_newline_odd_padding_is_retained_gap(self):
        self.assert_gap((AR.MAGIC + member("a.o", b"x"))[:-1] + b"\0", "AR_ODD_PADDING_NOT_NEWLINE")

    def test_index_offsets_reject_index_header_payload_interiors_and_outside(self):
        body = indexed()
        actual = self.report(body)["members"][1]["headerOffsetBytes"]
        for offset in (8, actual + 1, actual + 60, 0, 999):
            changed = body[:72] + struct.pack(">I", offset) + body[76:]
            with self.subTest(offset=offset):
                self.assert_gap(changed, "AR_GNU32_SYMBOL_OFFSET_NOT_MEMBER_HEADER")

    def test_index_count_is_big_endian_and_bounded(self):
        body = indexed()
        self.assert_gap(body[:68] + b"\x01\0\0\0" + body[72:], "AR_GNU32_SYMBOL_COUNT_BOUND")

    def test_index_truncated_offsets_and_names(self):
        self.assert_gap(AR.MAGIC + member(b"/", b"\0\0\0", mode=b"0"), "AR_GNU32_INDEX_TRUNCATED")
        self.assert_gap(AR.MAGIC + member(b"/", struct.pack(">I", 1), mode=b"0"), "AR_GNU32_INDEX_TRUNCATED")
        self.assert_gap(indexed((b"",)), "AR_GNU32_SYMBOL_STRING_INVALID_OR_BOUND")

    def test_index_extra_strings_and_padding_are_not_ignored(self):
        self.assert_gap(indexed(suffix=b"extra\0"), "AR_GNU32_INDEX_UNBOUND_SUFFIX")
        self.assert_gap(indexed(suffix=b"\0\0"), "AR_GNU32_INDEX_UNBOUND_SUFFIX")

    def test_index_control_symbol_is_rejected(self):
        self.assert_gap(indexed((b"bad\nname",)), "AR_GNU32_SYMBOL_ENCODING_UNSUPPORTED")

    def test_excluded_member_path_and_exact_digest_survive(self):
        body = AR.MAGIC + member("viva.jar", b"excluded-fixture")
        with patch.object(AR.LAYERS, "BLOCKED_DIGESTS", frozenset((AR.LAYERS.sha(b"excluded-fixture"),))):
            report = self.report(body)
        reasons = {row["reason"] for row in report["excludedPayloadFindings"]}
        self.assertIn("EXACT_EXCLUDED_BINARY_SHA256", reasons)
        self.assertIn("EXCLUDED_VIVA_OR_NESTED_CLASS_PATH", reasons)
        self.assertEqual(report["exclusionGate"], "FAILED")

    def test_nested_nonzip_archives_keep_their_gap(self):
        report = self.report(AR.MAGIC + member("nested.a", AR.MAGIC))
        self.assertEqual(report["status"], "NESTED_FINDING_OR_GAP")
        self.assertIn({"location": "fixture.a!/nested.a", "reason": "NON_ZIP_ARCHIVE_NOT_RECURSIVELY_INSPECTED"},
                      report["archiveInspectionGaps"])

    def test_zip_expansion_bound_and_envelope_gap_are_retained(self):
        report = self.report(AR.MAGIC + member("nested.zip", zipped("plain", b"x" * (AR.LAYERS.MAX_ZIP_BYTES + 1), compression=zipfile.ZIP_DEFLATED)))
        self.assertEqual(report["status"], "NESTED_FINDING_OR_GAP")
        self.assertIn("ZIP_ENCRYPTION_OR_EXPANSION_BOUND", {row["reason"] for row in report["archiveInspectionGaps"]})

    def test_unsupported_zip_codecs_cannot_expand_forged_small_sizes(self):
        for compression in (zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA):
            with self.subTest(compression=compression):
                payload = bytearray(zipped("tiny", b"X" * (128 << 10), compression=compression))
                central = payload.index(b"PK\x01\x02")
                for offset in (14, central + 16):
                    struct.pack_into("<I", payload, offset, zlib.crc32(b"X"))
                for offset in (22, central + 24):
                    struct.pack_into("<I", payload, offset, 1)
                body = AR.MAGIC + member("tiny.zip", bytes(payload))
                self.assertLessEqual(len(body), AR.MAX_AR_BYTES)
                with patch.object(zipfile, "_get_decompressor", side_effect=AssertionError("unsupported codec invoked")):
                    report = self.report(body)
                self.assertEqual(report["status"], "NESTED_FINDING_OR_GAP")
                self.assertEqual(report["measurement"]["zipExpandedBytes"], 0)
                self.assertIn("ZIP_FORMAT_UNSUPPORTED_OR_INVALID",
                              {row["reason"] for row in report["archiveInspectionGaps"]})
                self.assertFalse(report["qualified"])
                self.assertFalse(report["legalAccepted"])

    def test_forged_deflate_sizes_cannot_bypass_aggregate_expansion_bound(self):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for index in range(24):
                archive.writestr(str(index), b"X" * (16 << 10))
        inner = bytearray(output.getvalue())
        with zipfile.ZipFile(io.BytesIO(inner)) as archive:
            for info in archive.infolist():
                struct.pack_into("<I", inner, info.header_offset + 14, zlib.crc32(b"X"))
                struct.pack_into("<I", inner, info.header_offset + 22, 1)
        cursor = 0
        while True:
            central = inner.find(b"PK\x01\x02", cursor)
            if central < 0:
                break
            struct.pack_into("<I", inner, central + 16, zlib.crc32(b"X"))
            struct.pack_into("<I", inner, central + 24, 1)
            cursor = central + 4
        body = AR.MAGIC + member("nested.zip", zipped("inner.zip", bytes(inner), compression=zipfile.ZIP_DEFLATED))
        self.assertLessEqual(len(body), AR.MAX_AR_BYTES)
        original = zipfile._get_decompressor
        opened = []
        def observe(compression):
            opened.append(compression)
            return original(compression)
        with patch.object(zipfile, "_get_decompressor", side_effect=observe):
            report = self.report(body)
        # Only the valid outer ZIP may open: malformed inner envelopes are
        # diagnosed by bounded zlib validation and never reach ZipExtFile.
        self.assertEqual(opened, [zipfile.ZIP_DEFLATED])
        self.assertEqual(report["status"], "NESTED_FINDING_OR_GAP")
        self.assertEqual(report["measurement"]["zipExpandedBytes"], len(inner))
        self.assertIn("ZIP_ENVELOPE_BYTES_NOT_FULLY_MEMBER_BOUND",
                      {row["reason"] for row in report["archiveInspectionGaps"]})

    def test_full_raw_scan_detects_zip_spanning_ar_payload_padding_and_next_header(self):
        # This valid outer ar interleaves its second header into a stored ZIP's
        # data. Neither separately scanned member contains a complete ZIP.
        second_header = header("second.o", 78)
        value = zipped("viva.jar", b"X\n" + second_header + b"YZ")
        split = 30 + len("viva.jar") + 1
        self.assertEqual(len(value[split + 1 + 60:]), 78)
        body = AR.MAGIC + header("first.o", split) + value
        report = self.report(body)
        self.assertEqual(report["memberCount"], 2)
        self.assertTrue(report["fullInputConsumed"])
        self.assertTrue(any("!ar-raw!/viva.jar" in row["location"] for row in report["excludedPayloadFindings"]))

    def test_whole_input_finding_survives_later_structural_failure(self):
        report = self.assert_gap(AR.MAGIC + zipped(), "AR_HEADER_TERMINATOR_INVALID")
        self.assertTrue(report["excludedPayloadFindings"])

    def test_complete_signature_header_name_index_payload_and_padding_views_are_scanned(self):
        body = indexed((b"symbol",)) + member("odd.o", b"x")
        seen = []
        original = AR.LAYERS.inspect_payload
        def observe(payload, head, name, *args, **kwargs):
            seen.append((payload, head, name))
            return original(payload, head, name, *args, **kwargs)
        with patch.object(AR.LAYERS, "inspect_payload", side_effect=observe):
            report = self.report(body)
        self.assertEqual(report["status"], "MEASURED")
        self.assertIn((body, b"", "fixture.a!ar-raw"), seen)
        for suffix in ("!ar-signature", "!ar-header[0]", "!ar-header[0]!name-field", "!gnu32-index",
                       "!gnu32-index!offset-table", "!gnu32-index!symbol[0]", "!gnu32-index!index-zero-padding",
                       "!ar-name/odd.o", "!/odd.o", "!/odd.o!ar-odd-padding"):
            self.assertTrue(any(name.endswith(suffix) for _, _, name in seen), suffix)

    def test_deadline_failure_is_fatal(self):
        with patch.object(AR.time, "monotonic", side_effect=(0, 11)):
            with self.assertRaisesRegex(AR.LAYERS.Failure, "deadline exceeded"):
                self.report(AR.MAGIC)


if __name__ == "__main__":
    unittest.main()
