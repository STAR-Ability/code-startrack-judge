#!/usr/bin/env python3
"""Bounded, non-executing inspection of a narrow full-input GNU ar profile.

Supports short basename members and an optional first GNU 32-bit symbol index.
Thin/BSD/long-name/GNU64 archives remain gaps. This supplement grants neither
whole-image qualification nor legal acceptance. Callers must provide a hard
outer timeout and enforce or explicitly disclose CPU/memory/PID limits.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import re
import stat
import time


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("ar_physical_layers", ROOT / "scripts/audit-image-layers.py")
LAYERS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAYERS)
# Private import: bounds do not alter any other inspector instance.
LAYERS.MAX_ZIP_BYTES = 4 << 10
LAYERS.MAX_ZIP_EXPANDED_BYTES = 64 << 10
LAYERS.MAX_ZIP_MEMBERS = 32
LAYERS.MAX_ZIP_DEPTH = 2
LAYERS.MAX_ZIP_ENVELOPES = 4
MAGIC = b"!<arch>\n"
MAX_AR_BYTES = 512
MAX_AR_MEMBERS = 8
MAX_SYMBOLS = 32
MAX_SYMBOL_BYTES = 128
MAX_SCANNED_BYTES = 8 << 10
DEADLINE_SECONDS = 10
PROFILE = "GNU_AR_SHORT_BASENAMES_OPTIONAL_FIRST_GNU32_INDEX_FULL_INPUT"


class CoverageGap(ValueError):
    """The complete bytes do not fit this deliberately narrow profile."""


def profile(condition, reason):
    if not condition:
        raise CoverageGap(reason)


class Budget:
    def __init__(self):
        self.deadline = time.monotonic() + DEADLINE_SECONDS
        self.scanned = 0
        self.inspection = {"zipArchives": 0, "zipMembers": 0, "zipExpandedBytes": 0}

    def check(self):
        LAYERS.require(time.monotonic() < self.deadline, "ar companion deadline exceeded")

    def scan(self, body, location, findings, gaps, *, structural=False):
        self.check()
        self.scanned += len(body)
        LAYERS.require(self.scanned <= MAX_SCANNED_BYTES, "ar scan aggregate bound exceeded")
        try:
            LAYERS.inspect_payload(body, b"" if structural else body[:512], location,
                                   LAYERS.sha(body), findings, gaps, self.inspection)
        except LAYERS.Failure:
            raise
        except ValueError:
            # A component may contain a ZIP directory whose local header lies
            # in a preceding ar component. The raw view still gets inspected;
            # retain the component's rejected view without hiding any findings.
            gaps.append({"location": location, "reason": "AR_NESTED_DETECTOR_REJECTED_VALUE"})
        self.check()


def number(field, base, maximum, *, blank=False):
    token = field.rstrip(b" ")
    if blank and not token:
        return None
    pattern = rb"[0-9]+" if base == 10 else rb"[0-7]+"
    profile(re.fullmatch(pattern, token) is not None, "AR_NUMERIC_FIELD_PROFILE_UNSUPPORTED")
    value = int(token, base)
    profile(value <= maximum, "AR_NUMERIC_FIELD_BOUND")
    return value


def short_name(field):
    token = field.rstrip(b" ")
    profile(re.fullmatch(rb"[A-Za-z0-9_][A-Za-z0-9_.+-]{0,14}/", token) is not None
            and not token.startswith(b"__.SYMDEF"), "AR_MEMBER_NAME_PROFILE_UNSUPPORTED")
    return token[:-1].decode("ascii")


def symbol_index(payload, regular_offsets, budget, location, findings, gaps):
    profile(len(payload) >= 4, "AR_GNU32_INDEX_TRUNCATED")
    count = int.from_bytes(payload[:4], "big")
    profile(count <= MAX_SYMBOLS, "AR_GNU32_SYMBOL_COUNT_BOUND")
    names_start = 4 + count * 4
    profile(names_start <= len(payload), "AR_GNU32_INDEX_TRUNCATED")
    budget.scan(payload[:names_start], location + "!offset-table", findings, gaps)
    offsets = [int.from_bytes(payload[4 + i * 4:8 + i * 4], "big") for i in range(count)]
    profile(all(value in regular_offsets for value in offsets), "AR_GNU32_SYMBOL_OFFSET_NOT_MEMBER_HEADER")
    cursor, symbols = names_start, []
    for index in range(count):
        budget.check()
        end = payload.find(b"\0", cursor, min(len(payload), cursor + MAX_SYMBOL_BYTES + 1))
        profile(end > cursor, "AR_GNU32_SYMBOL_STRING_INVALID_OR_BOUND")
        value = payload[cursor:end]
        profile(all(33 <= byte <= 126 for byte in value), "AR_GNU32_SYMBOL_ENCODING_UNSUPPORTED")
        budget.scan(payload[cursor:end + 1], location + f"!symbol[{index}]", findings, gaps)
        symbols.append({"memberHeaderOffsetBytes": offsets[index], "nameSizeBytes": len(value),
                        "nameSHA256": LAYERS.sha(value)})
        cursor = end + 1
    # GNU/LLVM may include one terminal NUL within the declared index size to
    # make an odd string table even. Account for it independently of ar's LF pad.
    padding = payload[cursor:]
    profile(not padding or cursor % 2 == 1 and padding == b"\0", "AR_GNU32_INDEX_UNBOUND_SUFFIX")
    budget.scan(padding, location + "!index-zero-padding", findings, gaps)
    return {"symbolCount": count, "symbols": symbols, "indexPaddingSizeBytes": len(padding),
            "indexPaddingSHA256": LAYERS.sha(padding), "indexProfile": "GNU32_BIG_ENDIAN_EXACT_HEADER_REFERENCES_AND_COUNTED_NAMES"}


def inspect_ar(body, location, budget, findings, gaps):
    """Inspect all bytes or raise CoverageGap, retaining findings already seen."""
    profile(type(body) is bytes and len(body) <= MAX_AR_BYTES, "AR_INPUT_BYTES_BOUND")
    # Do not remove the raw body: ZIP envelopes may cross ar component boundaries.
    # Empty head suppresses only this outer ar signature, whose grammar follows.
    # Use a neutral location for raw scanning so a caller's .deb suffix cannot
    # manufacture a second outer-format gap. Member names use their real paths.
    budget.scan(body, location + "!ar-raw", findings, gaps, structural=True)
    profile(body.startswith(MAGIC), "AR_MAGIC_OR_VARIANT_UNSUPPORTED")
    budget.scan(MAGIC, location + "!ar-signature", findings, gaps, structural=True)
    cursor, rows, names, indexes = len(MAGIC), [], set(), []
    while cursor < len(body):
        budget.check()
        profile(len(rows) < MAX_AR_MEMBERS, "AR_MEMBER_COUNT_BOUND")
        profile(cursor + 60 <= len(body), "AR_TRUNCATED_HEADER_OR_TRAILING_BYTES")
        header = body[cursor:cursor + 60]
        header_location = location + f"!ar-header[{len(rows)}]"
        budget.scan(header, header_location, findings, gaps, structural=True)
        budget.scan(header[:16], header_location + "!name-field", findings, gaps)
        profile(header[58:] == b"`\n", "AR_HEADER_TERMINATOR_INVALID")
        index_member = header[:16] == b"/               "
        if index_member:
            profile(not rows and not indexes, "AR_GNU32_INDEX_NOT_UNIQUE_FIRST_MEMBER")
            name = "/"
        else:
            name = short_name(header[:16])
            profile(name not in names, "AR_DUPLICATE_MEMBER_NAME")
            names.add(name)
            budget.scan(name.encode(), location + "!ar-name/" + name, findings, gaps)
        mtime = number(header[16:28], 10, (1 << 63) - 1, blank=index_member)
        uid = number(header[28:34], 10, (1 << 32) - 1, blank=index_member)
        gid = number(header[34:40], 10, (1 << 32) - 1, blank=index_member)
        mode = number(header[40:48], 8, 0o177777, blank=index_member)
        profile(mode is None or mode & ~(0o7777 | stat.S_IFREG) == 0
                and stat.S_IFMT(mode) in (0, stat.S_IFREG), "AR_MODE_TYPE_UNSUPPORTED")
        size = number(header[48:58], 10, MAX_AR_BYTES)
        start, finish = cursor + 60, cursor + 60 + size
        next_cursor = finish + size % 2
        profile(next_cursor <= len(body), "AR_TRUNCATED_PAYLOAD_OR_PADDING")
        payload, padding = body[start:finish], body[finish:next_cursor]
        payload_location = location + ("!gnu32-index" if index_member else "!/" + name)
        budget.scan(payload, payload_location, findings, gaps)
        budget.scan(padding, payload_location + "!ar-odd-padding", findings, gaps)
        profile(not padding or padding == b"\n", "AR_ODD_PADDING_NOT_NEWLINE")
        row = {"headerOffsetBytes": cursor, "rawHeaderSHA256": LAYERS.sha(header), "name": name,
               "kind": "GNU32_SYMBOL_INDEX" if index_member else "SHORT_NAME_MEMBER",
               "mtime": mtime, "uid": uid, "gid": gid, "rawModeOctal": None if mode is None else format(mode, "o"),
               "sizeBytes": size, "sha256": LAYERS.sha(payload), "paddingSizeBytes": len(padding),
               "paddingSHA256": LAYERS.sha(padding)}
        rows.append(row)
        if index_member:
            indexes.append((row, payload, payload_location))
        cursor = next_cursor
    regular_offsets = {row["headerOffsetBytes"] for row in rows if row["kind"] == "SHORT_NAME_MEMBER"}
    for row, payload, index_location in indexes:
        row.update(symbol_index(payload, regular_offsets, budget, index_location, findings, gaps))
    budget.check()
    return {"arProfile": PROFILE, "sizeBytes": len(body), "sha256": LAYERS.sha(body),
            "signatureSHA256": LAYERS.sha(MAGIC), "memberCount": len(rows), "members": rows,
            "fullInputConsumed": cursor == len(body)}


def audit(body, location):
    """Return bounded evidence; unsupported structures stay explicit gaps."""
    budget, findings, gaps = Budget(), [], []
    result = {"schemaVersion": 1, "scope": "NARROW_STATIC_AR_PAYLOAD_COMPANION", "location": location,
              "qualified": False, "legalAccepted": False, "originalReceiptReplaced": False}
    try:
        result.update(inspect_ar(body, location, budget, findings, gaps))
        result["status"] = "MEASURED" if not findings and not gaps else "NESTED_FINDING_OR_GAP"
    except CoverageGap as exc:
        gaps.append({"location": location, "reason": str(exc)})
        result["status"] = "GAP"
    result.update({"excludedPayloadFindings": findings, "archiveInspectionGaps": gaps,
                   "exclusionGate": "FAILED" if findings else "PENDING_OTHER_PHYSICAL_GAPS_AND_LEGAL_RECONCILIATION",
                   "measurement": {"scannedBytesIncludingRepeatedViews": budget.scanned, **budget.inspection},
                   "limits": {"maximumArBytes": MAX_AR_BYTES, "maximumPhysicalArMembers": MAX_AR_MEMBERS,
                              "maximumSymbols": MAX_SYMBOLS, "maximumSymbolBytes": MAX_SYMBOL_BYTES,
                              "maximumScannedBytesIncludingRepeatedViews": MAX_SCANNED_BYTES,
                              "maximumNestedZipMemberBytes": LAYERS.MAX_ZIP_BYTES,
                              "maximumNestedZipExpandedAggregateBytes": LAYERS.MAX_ZIP_EXPANDED_BYTES,
                              "maximumNestedZipMembers": LAYERS.MAX_ZIP_MEMBERS,
                              "maximumNestedZipEnvelopesPerView": LAYERS.MAX_ZIP_ENVELOPES,
                              "maximumNestedZipDepth": LAYERS.MAX_ZIP_DEPTH,
                              "cooperativeDeadlineSeconds": DEADLINE_SECONDS, "hardOuterUnitRequired": True}})
    return result
