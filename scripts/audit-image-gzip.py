#!/usr/bin/env python3
"""Issue #4: bounded companion evidence for physical doc/man/info gzip gaps.

This reads inert candidate bytes only. It neither executes image contents nor
replaces the original physical receipt, legal reconciliation or qualification.
Run real candidates only inside a separately reviewed resource/deadline unit.
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
import time
import zlib


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("gzip_physical_layers", ROOT / "scripts/audit-image-layers.py")
LAYERS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAYERS)
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
PREFIXES = ("usr/share/doc/", "usr/share/man/", "usr/share/info/")
MAX_ARCHIVE_BYTES = 8 << 30
MAX_RECEIPT_BYTES = 32 << 20
MAX_SELECTED_FILES = 20_000
MAX_COMPRESSED_BYTES = 4 << 20
MAX_TOTAL_COMPRESSED_BYTES = 128 << 20
MAX_EXPANDED_BYTES = 32 << 20
MAX_TOTAL_EXPANDED_BYTES = 512 << 20
MAX_LAYER_BYTES = 16 << 30
MAX_FILENAME_BYTES = 4096
MAX_REPORT_BYTES = 16 << 20
DEADLINE_SECONDS = 300
ORIGINAL_GAP = "NON_ZIP_ARCHIVE_NOT_RECURSIVELY_INSPECTED"


class CoverageGap(ValueError):
    """A selected payload remains unmeasured within this supported profile."""


class Budget:
    def __init__(self):
        self.deadline = time.monotonic() + DEADLINE_SECONDS
        self.expanded = 0
        self.compressed = 0
        self.layer_counters = {"expandedLayerBytes": 0}
        self.inspection = {"zipArchives": 0, "zipMembers": 0, "zipExpandedBytes": 0}

    def check(self):
        LAYERS.require(time.monotonic() < self.deadline, "companion deadline exceeded")


def regular_file(path, maximum):
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    stream = os.fdopen(descriptor, "rb")
    info = os.fstat(stream.fileno())
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > maximum:
        stream.close()
        raise LAYERS.Failure("bounded regular single-link input required")
    return stream


def file_hash(stream, budget):
    digest = hashlib.sha256()
    stream.seek(0)
    for chunk in iter(lambda: stream.read(1 << 20), b""):
        budget.check()
        digest.update(chunk)
    stream.seek(0)
    return digest.hexdigest()


def selected_inputs(receipt, config_id, archive_hash):
    LAYERS.require(type(receipt.get("schemaVersion")) is int and receipt["schemaVersion"] == 1
                   and receipt.get("imageConfigID") == config_id
                   and receipt.get("dockerSaveSHA256") == archive_hash
                   and receipt.get("completePhysicalLayerInventory") is True
                   and receipt.get("scope") == "ALL_DISTRIBUTED_FILESYSTEM_LAYERS_INCLUDING_DELETED_PAYLOADS",
                   "physical receipt identity/scope differs")
    layers = receipt["layers"]
    LAYERS.require(isinstance(layers, list) and 0 < len(layers) <= LAYERS.MAX_LAYERS, "invalid physical layers")
    original_gaps = receipt["archiveInspectionGaps"]
    LAYERS.require(isinstance(original_gaps, list) and len(original_gaps) <= LAYERS.MAX_LAYER_MEMBERS,
                   "invalid original gaps")
    gap_locations = {item["location"] for item in original_gaps if item["reason"] == ORIGINAL_GAP}
    selected, archives = {}, set()
    for index, layer in enumerate(layers):
        records = layer["inventory"]
        archive_name = LAYERS.canonical(layer["archivePath"])
        LAYERS.require(type(layer["index"]) is int and layer["index"] == index
                       and archive_name not in archives
                       and LAYERS.DIGEST.fullmatch(layer["diffID"]) is not None
                       and SHA256.fullmatch(layer["storedBlobSHA256"]) is not None
                       and type(layer["storedBlobSizeBytes"]) is int
                       and 0 <= layer["storedBlobSizeBytes"] <= MAX_ARCHIVE_BYTES
                       and layer["compression"] in ("none", "gzip")
                       and isinstance(records, list) and len(records) == layer["memberCount"]
                       and len(records) <= LAYERS.MAX_LAYER_MEMBERS,
                       "invalid physical layer inventory")
        archives.add(archive_name)
        encoded = json.dumps(records, sort_keys=True, separators=(",", ":")).encode()
        LAYERS.require(LAYERS.sha(encoded) == layer["inventorySHA256"], "physical inventory hash differs")
        names = set()
        for item in records:
            name = LAYERS.canonical(item["path"])
            LAYERS.require(name not in names, "duplicate physical inventory path")
            names.add(name)
            if item["type"] not in ("0", "\0") or not name.startswith(PREFIXES) or not name.endswith(".gz"):
                continue
            location = f"layer[{index}]/" + name
            LAYERS.require(location in gap_locations and type(item["sizeBytes"]) is int
                           and 0 <= item["sizeBytes"] <= LAYERS.MAX_FILE_BYTES
                           and SHA256.fullmatch(item["sha256"]) is not None,
                           "selected physical gap binding absent")
            selected[location] = item
            LAYERS.require(len(selected) <= MAX_SELECTED_FILES, "selected file bound exceeded")
    return selected


def inspect_gzip(body, location, budget, findings, gaps):
    budget.check()
    if len(body) < 18 or body[:3] != b"\x1f\x8b\x08" or body[3] not in (0, 8):
        raise CoverageGap("GZIP_HEADER_PROFILE_UNSUPPORTED")
    header_end = 10
    if body[3] == 8:
        terminator = body.find(b"\0", 10, 10 + MAX_FILENAME_BYTES + 1)
        if terminator < 0:
            raise CoverageGap("GZIP_FILENAME_UNTERMINATED_OR_BOUND")
        filename = body[10:terminator]
        if filename:
            try:
                declared_name = LAYERS.canonical(filename.decode("utf-8", "strict"))
            except (UnicodeError, ValueError):
                raise CoverageGap("GZIP_FILENAME_PROFILE_UNSUPPORTED") from None
            LAYERS.inspect_payload(filename, filename[:512], location + "!gzip-filename/" + declared_name,
                                   LAYERS.sha(filename), findings, gaps, budget.inspection)
        header_end = terminator + 1
    header = body[:header_end]
    # The structural magic was parsed above. Scan the complete recorded header
    # for appended/embedded ZIP envelopes as well as its filename metadata.
    LAYERS.inspect_payload(header, b"", location + "!gzip-header", LAYERS.sha(header),
                           findings, gaps, budget.inspection)
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    expanded = bytearray()
    pending, offset = b"", 0
    try:
        while not decoder.eof:
            budget.check()
            if not pending:
                pending = body[offset:offset + (64 << 10)]
                offset += len(pending)
            if not pending:
                raise CoverageGap("GZIP_TRUNCATED_MEMBER")
            remaining = min(MAX_EXPANDED_BYTES - len(expanded), MAX_TOTAL_EXPANDED_BYTES - budget.expanded)
            chunk = decoder.decompress(pending, min(64 << 10, max(0, remaining) + 1))
            pending = decoder.unconsumed_tail
            budget.expanded += len(chunk)
            if budget.expanded > MAX_TOTAL_EXPANDED_BYTES:
                raise LAYERS.Failure("gzip aggregate expansion bound exceeded")
            if len(expanded) + len(chunk) > MAX_EXPANDED_BYTES:
                raise CoverageGap("GZIP_PAYLOAD_EXPANSION_BOUND")
            expanded.extend(chunk)
        if decoder.unused_data or pending or offset != len(body):
            raise CoverageGap("GZIP_CONCATENATED_OR_TRAILING_BYTES")
    except zlib.error:
        raise CoverageGap("GZIP_INVALID_MEMBER_OR_CRC_ISIZE") from None
    value = bytes(expanded)
    expanded_location = location + "!gzip-expanded/" + location.rsplit("/", 1)[-1][:-3]
    LAYERS.inspect_payload(value, value[:512], expanded_location, LAYERS.sha(value),
                           findings, gaps, budget.inspection)
    budget.check()
    return {"headerSizeBytes": header_end, "headerSHA256": LAYERS.sha(body[:header_end]),
            "headerProfile": "NONE" if body[3] == 0 else "BOUNDED_INSPECTED_FILENAME",
            "expandedSizeBytes": len(value), "expandedSHA256": LAYERS.sha(value),
            "gzipProfile": "SINGLE_MEMBER_FULL_INPUT_CRC_ISIZE_VERIFIED"}


class LayerReader:
    def __init__(self, stream, compressed, budget):
        self.stream = LAYERS.ExpandedGzip(stream, budget.layer_counters) if compressed else stream
        self.compressed, self.budget = compressed, budget
        self.digest, self.size = hashlib.sha256(), 0

    def read(self, size):
        self.budget.check()
        LAYERS.require(type(size) is int and 0 <= size <= 1 << 20, "bounded layer read required")
        chunk = self.stream.read(size)
        self.digest.update(chunk)
        self.size += len(chunk)
        if not self.compressed:
            self.budget.layer_counters["expandedLayerBytes"] += len(chunk)
        LAYERS.require(self.budget.layer_counters["expandedLayerBytes"] <= MAX_LAYER_BYTES,
                       "affected layer expansion bound exceeded")
        return chunk


def audit(archive_path, archive_hash, physical_path, physical_hash, config_id):
    LAYERS.require(SHA256.fullmatch(archive_hash) is not None and SHA256.fullmatch(physical_hash) is not None
                   and LAYERS.DIGEST.fullmatch(config_id) is not None, "explicit full input identities required")
    budget = Budget()
    with regular_file(physical_path, MAX_RECEIPT_BYTES) as stream:
        raw_receipt = stream.read(MAX_RECEIPT_BYTES + 1)
    LAYERS.require(LAYERS.sha(raw_receipt) == physical_hash, "physical receipt checksum differs")
    receipt = json.loads(raw_receipt)
    selected = selected_inputs(receipt, config_id, archive_hash)
    records, affected, findings, gaps, seen = [], [], [], [], set()
    with regular_file(archive_path, MAX_ARCHIVE_BYTES) as stream:
        before = os.fstat(stream.fileno())
        LAYERS.require(file_hash(stream, budget) == archive_hash, "candidate archive checksum differs")
        with tarfile.open(fileobj=stream, mode="r:", tarinfo=LAYERS.BoundedMetadataInfo) as saved:
            outer = {}
            for member in saved:
                budget.check()
                name = LAYERS.canonical(member.name)
                LAYERS.require(name not in outer and len(outer) < LAYERS.MAX_OUTER_MEMBERS
                               and (member.isfile() or member.isdir()) and not member.issparse(),
                               "unsupported outer archive inventory")
                outer[name] = member
            for index, layer in enumerate(receipt["layers"]):
                wanted = {location: item for location, item in selected.items() if location.startswith(f"layer[{index}]/")}
                if not wanted:
                    continue
                blob = outer[LAYERS.canonical(layer["archivePath"])]
                LAYERS.require(blob.isfile() and blob.size == layer["storedBlobSizeBytes"], "affected layer stored size differs")
                digest = hashlib.sha256()
                head = b""
                with saved.extractfile(blob) as payload:
                    for chunk in iter(lambda: payload.read(1 << 20), b""):
                        budget.check()
                        head = head or chunk[:32]
                        digest.update(chunk)
                LAYERS.require(digest.hexdigest() == layer["storedBlobSHA256"], "affected stored layer checksum differs")
                if layer["compression"] == "gzip":
                    LAYERS.require(LAYERS.gzip_envelope(head) == layer["gzipEnvelope"], "affected layer gzip envelope differs")
                with saved.extractfile(blob) as payload:
                    reader = LayerReader(payload, layer["compression"] == "gzip", budget)
                    count, names = 0, set()
                    with tarfile.open(fileobj=reader, mode="r|", tarinfo=LAYERS.BoundedMetadataInfo) as tar:
                        for member in tar:
                            budget.check()
                            name = LAYERS.canonical(member.name)
                            count += 1
                            LAYERS.require(name not in names and count <= LAYERS.MAX_LAYER_MEMBERS
                                           and not member.issparse(), "unsupported affected layer inventory")
                            names.add(name)
                            location = f"layer[{index}]/" + name
                            if location not in wanted:
                                continue
                            expected = wanted[location]
                            LAYERS.require(member.isfile() and member.size == expected["sizeBytes"], "selected payload type/size differs")
                            value, digest = bytearray(), hashlib.sha256()
                            LAYERS.require(budget.compressed + member.size <= MAX_TOTAL_COMPRESSED_BYTES,
                                           "selected compressed aggregate bound exceeded")
                            retain = member.size <= MAX_COMPRESSED_BYTES
                            observed = 0
                            with tar.extractfile(member) as source:
                                for chunk in iter(lambda: source.read(64 << 10), b""):
                                    budget.check()
                                    digest.update(chunk)
                                    observed += len(chunk)
                                    if retain:
                                        value.extend(chunk)
                            budget.compressed += member.size
                            LAYERS.require(observed == member.size and digest.hexdigest() == expected["sha256"],
                                           "selected compressed payload checksum/size differs")
                            entry = {"location": location, "compressedSizeBytes": member.size,
                                     "compressedSHA256": digest.hexdigest(), "status": "GAP"}
                            start_findings, start_gaps = len(findings), len(gaps)
                            try:
                                if not retain:
                                    raise CoverageGap("GZIP_COMPRESSED_PAYLOAD_BOUND")
                                entry.update(inspect_gzip(bytes(value), location, budget, findings, gaps))
                                entry["status"] = "MEASURED" if len(findings) == start_findings and len(gaps) == start_gaps else "NESTED_FINDING_OR_GAP"
                            except CoverageGap as exc:
                                gaps.append({"location": location, "reason": str(exc)})
                            records.append(entry)
                            seen.add(location)
                        for padding in iter(lambda: tar.fileobj.read(1 << 20), b""):
                            budget.check()
                            LAYERS.require(not padding.strip(b"\0"), "affected layer has nonzero trailing bytes")
                    LAYERS.require(count == layer["memberCount"] and reader.size == layer["tarSizeBytes"]
                                   and "sha256:" + reader.digest.hexdigest() == layer["diffID"]
                                   and (not reader.compressed or reader.stream.finished), "affected layer diffID/size/count differs")
                    affected.append({"index": index, "diffID": layer["diffID"], "tarSizeBytes": reader.size,
                                     "storedBlobSHA256": layer["storedBlobSHA256"], "selectedPayloadCount": len(wanted)})
        after = os.fstat(stream.fileno())
        LAYERS.require((before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                       (after.st_size, after.st_mtime_ns, after.st_ctime_ns), "archive changed during measurement")
    LAYERS.require(seen == set(selected), "selected payload coverage differs")
    resolved = {entry["location"] for entry in records if entry["status"] == "MEASURED"}
    unresolved = sum(not (item["reason"] == ORIGINAL_GAP and item["location"] in resolved)
                     for item in receipt["archiveInspectionGaps"])
    budget.check()
    return {"schemaVersion": 1, "scope": "SELECTED_DOC_MAN_INFO_GZIP_PAYLOAD_COMPANION",
            "imageConfigID": config_id, "dockerSaveSHA256": archive_hash, "physicalReceiptSHA256": physical_hash,
            "ociImageManifestID": receipt.get("ociImageManifestID"), "selectedPathPrefixes": list(PREFIXES),
            "selectedSuffix": ".gz", "affectedLayers": affected, "inventory": records,
            "selectedPayloadCount": len(selected), "measuredPayloadCount": len(resolved),
            "originalGapRows": len(receipt["archiveInspectionGaps"]), "originalUnresolvedGapRows": unresolved,
            "originalExcludedPayloadFindingCount": len(receipt["excludedPayloadFindings"]),
            "excludedPayloadFindings": findings, "archiveInspectionGaps": gaps,
            "exclusionGate": "FAILED" if findings or receipt["excludedPayloadFindings"] else "PENDING_OTHER_PHYSICAL_GAPS_AND_LEGAL_RECONCILIATION",
            "qualified": False, "originalReceiptReplaced": False,
            "measurement": {"compressedBytesObserved": budget.compressed, "gzipExpandedBytesObserved": budget.expanded,
                            "affectedLayerBytesObserved": budget.layer_counters["expandedLayerBytes"], **budget.inspection},
            "limits": {"maximumCompressedPayloadBytes": MAX_COMPRESSED_BYTES, "maximumCompressedAggregateBytes": MAX_TOTAL_COMPRESSED_BYTES,
                       "maximumExpandedPayloadBytes": MAX_EXPANDED_BYTES, "maximumExpandedAggregateBytes": MAX_TOTAL_EXPANDED_BYTES,
                       "maximumFilenameBytes": MAX_FILENAME_BYTES, "maximumSelectedFiles": MAX_SELECTED_FILES,
                       "cooperativeDeadlineSeconds": DEADLINE_SECONDS, "hardOuterUnitRequired": True},
            "tools": {"companionSHA256": LAYERS.sha(Path(__file__).read_bytes()),
                      "physicalInspectorSHA256": LAYERS.sha((ROOT / "scripts/audit-image-layers.py").read_bytes()),
                      "pythonVersion": sys.version.split()[0], "zlibRuntimeVersion": zlib.ZLIB_RUNTIME_VERSION}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--archive-sha256", required=True)
    parser.add_argument("--physical-receipt", type=Path, required=True)
    parser.add_argument("--physical-receipt-sha256", required=True)
    parser.add_argument("--image-config-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    destination = args.output.absolute()
    LAYERS.require(not destination.exists() and not destination.is_symlink()
                   and destination.resolve().is_relative_to(ROOT), "fresh output below repository required")
    relative = destination.resolve().relative_to(ROOT)
    LAYERS.require(len(relative.parts) > 1 and relative.parts[0] in (".local", "artifacts"), "fresh task-owned evidence output required")
    report = audit(args.archive, args.archive_sha256, args.physical_receipt, args.physical_receipt_sha256, args.image_config_id)
    body = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
    LAYERS.require(len(body) <= MAX_REPORT_BYTES, "companion receipt size exceeded")
    with destination.open("xb") as stream:
        stream.write(body)
    print("Selected gzip companion measured; remaining physical and legal gates stay pending")
    return 1 if report["exclusionGate"] == "FAILED" else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError, AttributeError, tarfile.TarError):
        print("image-gzip-audit: invalid, unsupported or over-limit evidence; no gate claimed", file=sys.stderr)
        raise SystemExit(1)
