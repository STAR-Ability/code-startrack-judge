#!/usr/bin/env python3
"""Issue #4: bounded static companion for the 173 locked Rust crate archives.

Read retained source-carrier bytes without extraction or execution. Service
association uses unchanged original physical receipt content hashes; it is not
a current service-image measurement, qualification, SBOM or legal acceptance.
Run candidate inputs only in a separately reviewed hard resource/deadline unit.
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
SPEC = importlib.util.spec_from_file_location("crate_physical_layers", ROOT / "scripts/audit-image-layers.py")
LAYERS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAYERS)
# This private import has narrower nested inspection budgets than the original.
LAYERS.MAX_ZIP_BYTES = 4 << 20
LAYERS.MAX_ZIP_EXPANDED_BYTES = 64 << 20
LAYERS.MAX_ZIP_MEMBERS = 20_000
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
CRATE_PART = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]*\Z")
SOURCE_PREFIX = "corresponding-source/context/validation-tools/crate-sources/"
SERVICE_PREFIX = "build/validation-tools/crate-sources/"
LOCK_PATH = "corresponding-source/context/provenance/validation-tools.lock.json"
EXPECTED_CRATES = 173
MAX_ARCHIVE_BYTES = 8 << 30
MAX_RECEIPT_BYTES = 32 << 20
MAX_LOCK_BYTES = 2 << 20
MAX_COMPRESSED_BYTES = 4 << 20
MAX_TOTAL_COMPRESSED_BYTES = 32 << 20
MAX_EXPANDED_BYTES = 8 << 20
MAX_TOTAL_EXPANDED_BYTES = 128 << 20
MAX_MEMBER_BYTES = 4 << 20
MAX_PHYSICAL_HEADERS = 20_000
MAX_METADATA_BYTES = 4096
MAX_LAYER_BYTES = 8 << 30
MAX_REPORT_BYTES = 16 << 20
DEADLINE_SECONDS = 300
ORIGINAL_GAP = "NON_ZIP_ARCHIVE_NOT_RECURSIVELY_INSPECTED"


class CoverageGap(ValueError):
    """A crate remains outside the completely inspected supported profile."""


def profile(condition, reason):
    if not condition:
        raise CoverageGap(reason)


class Budget:
    def __init__(self):
        self.deadline = time.monotonic() + DEADLINE_SECONDS
        self.compressed = self.expanded = self.headers = 0
        self.report_bytes = 4096
        self.layer_counters = {"expandedLayerBytes": 0}
        self.inspection = {"zipArchives": 0, "zipMembers": 0, "zipExpandedBytes": 0}

    def check(self):
        LAYERS.require(time.monotonic() < self.deadline, "crate companion deadline exceeded")

    def charge_report(self, value):
        self.check()
        # Charge each retained row as pretty JSON plus nesting/format overhead.
        # Nested member rows are charged again when their crate row is retained.
        self.report_bytes += len(json.dumps(value, sort_keys=True, indent=2).encode()) + 256
        LAYERS.require(self.report_bytes <= MAX_REPORT_BYTES, "crate report accumulation bound exceeded")

    def inspect(self, body, head, location, findings, gaps):
        self.check()
        LAYERS.inspect_payload(body, head, location, LAYERS.sha(body), findings, gaps, self.inspection)
        self.check()


class BoundedRows(list):
    def __init__(self, budget):
        super().__init__()
        self.budget = budget

    def append(self, value):
        self.budget.charge_report(value)
        super().append(value)


def fingerprint(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def regular_file(path, maximum):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    stream = os.fdopen(descriptor, "rb")
    info = os.fstat(stream.fileno())
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 <= info.st_size <= maximum:
        stream.close()
        raise LAYERS.Failure("bounded regular single-link input required")
    return stream


def unchanged(stream, path, before):
    LAYERS.require(fingerprint(before) == fingerprint(os.fstat(stream.fileno()))
                   == fingerprint(os.stat(path, follow_symlinks=False)), "input changed during measurement")


def file_hash(stream, budget):
    digest = hashlib.sha256()
    stream.seek(0)
    for chunk in iter(lambda: stream.read(1 << 20), b""):
        budget.check()
        digest.update(chunk)
    stream.seek(0)
    return digest.hexdigest()


def bound_input(path, expected, maximum, budget):
    with regular_file(path, maximum) as stream:
        before = os.fstat(stream.fileno())
        body = stream.read(maximum + 1)
        budget.check()
        LAYERS.require(len(body) <= maximum and LAYERS.sha(body) == expected, "bound input checksum differs")
        unchanged(stream, path, before)
    return body


def locked_crates(body):
    lock = json.loads(body)
    rows = lock.get("crateSources")
    LAYERS.require(isinstance(rows, list) and len(rows) == EXPECTED_CRATES, "exact locked crate set required")
    result, identities = {}, set()
    for row in rows:
        name, version, filename = row["name"], row["version"], row["filename"]
        LAYERS.require(isinstance(name, str) and CRATE_PART.fullmatch(name) is not None
                       and isinstance(version, str) and CRATE_PART.fullmatch(version) is not None
                       and filename == f"{name}-{version}.crate" and len(filename.encode()) <= MAX_METADATA_BYTES
                       and filename not in result and (name, version) not in identities
                       and type(row["sizeBytes"]) is int and 0 < row["sizeBytes"] <= MAX_COMPRESSED_BYTES
                       and isinstance(row["sha256"], str) and SHA256.fullmatch(row["sha256"]) is not None,
                       "invalid or duplicate locked crate identity")
        result[filename] = {key: row[key] for key in ("name", "version", "filename", "sizeBytes", "sha256")}
        identities.add((name, version))
    LAYERS.require(sum(row["sizeBytes"] for row in result.values()) <= MAX_TOTAL_COMPRESSED_BYTES,
                   "locked compressed aggregate bound exceeded")
    return result


def receipt_inputs(receipt, config_id, manifest_id, archive_hash, prefix, locked, budget, *, source=False):
    LAYERS.require(type(receipt.get("schemaVersion")) is int and receipt["schemaVersion"] == 1
                   and receipt.get("imageConfigID") == config_id
                   and receipt.get("ociImageManifestID") == manifest_id
                   and receipt.get("dockerSaveSHA256") == archive_hash
                   and receipt.get("completePhysicalLayerInventory") is True
                   and receipt.get("scope") == "ALL_DISTRIBUTED_FILESYSTEM_LAYERS_INCLUDING_DELETED_PAYLOADS",
                   "physical receipt identity/scope differs")
    layers, original_gaps = receipt["layers"], receipt["archiveInspectionGaps"]
    LAYERS.require(isinstance(layers, list) and 0 < len(layers) <= LAYERS.MAX_LAYERS
                   and isinstance(original_gaps, list) and len(original_gaps) <= LAYERS.MAX_LAYER_MEMBERS
                   and isinstance(receipt["excludedPayloadFindings"], list), "invalid original physical receipt")
    if source:
        LAYERS.require(receipt.get("sourceCarrierInventoryVerified") is True and len(layers) == 1,
                       "verified single-layer source carrier required")
    gap_counts = {}
    for item in original_gaps:
        LAYERS.require(isinstance(item["location"], str) and isinstance(item["reason"], str), "invalid original gap row")
        if item["reason"] == ORIGINAL_GAP:
            gap_counts[item["location"]] = gap_counts.get(item["location"], 0) + 1
    selected, archives, total_members = {}, set(), 0
    for index, layer in enumerate(layers):
        budget.check()
        records, metadata = layer["inventory"], layer["metadataPayloads"]
        archive_name = LAYERS.canonical(layer["archivePath"])
        LAYERS.require(type(layer["index"]) is int and layer["index"] == index and archive_name not in archives
                       and isinstance(layer["diffID"], str) and LAYERS.DIGEST.fullmatch(layer["diffID"]) is not None
                       and isinstance(layer["storedBlobSHA256"], str) and SHA256.fullmatch(layer["storedBlobSHA256"]) is not None
                       and type(layer["storedBlobSizeBytes"]) is int and 0 < layer["storedBlobSizeBytes"] <= MAX_ARCHIVE_BYTES
                       and type(layer["tarSizeBytes"]) is int and 0 < layer["tarSizeBytes"] <= MAX_LAYER_BYTES
                       and layer["compression"] in ("none", "gzip")
                       and type(layer["memberCount"]) is int and isinstance(records, list)
                       and len(records) == layer["memberCount"] and isinstance(metadata, list), "invalid physical layer")
        archives.add(archive_name)
        total_members += len(records)
        LAYERS.require(total_members <= LAYERS.MAX_LAYER_MEMBERS, "physical member bound exceeded")
        for rows, field in ((records, "inventorySHA256"), (metadata, "metadataInventorySHA256")):
            encoded = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()
            LAYERS.require(LAYERS.sha(encoded) == layer[field], "physical inventory hash differs")
        names = set()
        for row in records:
            path = LAYERS.canonical(row["path"])
            LAYERS.require(path == row["path"] and path not in names, "duplicate or noncanonical physical path")
            names.add(path)
            if not path.startswith(prefix):
                continue
            if row["type"] == "5" and row["sizeBytes"] == 0:
                continue
            filename = path.removeprefix(prefix)
            LAYERS.require(filename in locked and filename not in selected and row["type"] in ("0", "\0")
                           and type(row["sizeBytes"]) is int
                           and row["sizeBytes"] == locked[filename]["sizeBytes"]
                           and row["sha256"] == locked[filename]["sha256"], "physical locked crate association differs")
            location = f"layer[{index}]/" + path
            LAYERS.require(gap_counts.get(location) == 1, "exact original crate gap binding required")
            selected[filename] = {"location": location, "path": path, "layerIndex": index, **locked[filename]}
    LAYERS.require(set(selected) == set(locked), "physical locked crate set differs")
    return selected


def crate_path(name, root, *, directory=False):
    try:
        canonical = LAYERS.canonical(name)
    except (ValueError, TypeError):
        raise CoverageGap("TAR_UNSAFE_OR_INVALID_PATH") from None
    profile((name == canonical or directory and name == canonical + "/")
            and (directory and canonical == root or canonical.startswith(root + "/")),
            "TAR_PATH_OUTSIDE_LOCKED_CRATE_ROOT")
    return canonical


def cstring(field):
    value, separator, tail = field.partition(b"\0")
    profile(not separator or not tail.strip(b"\0"), "TAR_STRING_FIELD_NONZERO_SUFFIX")
    try:
        return value.decode("utf-8", "strict")
    except UnicodeError:
        raise CoverageGap("TAR_STRING_ENCODING_UNSUPPORTED") from None


def raw_header(header):
    profile(header[257:265] in (b"ustar\x0000", b"ustar  \x00"), "TAR_HEADER_PROFILE_UNSUPPORTED")
    profile(header[156:157] in (b"0", b"\0", b"5", b"L"), "TAR_ENTRY_TYPE_UNSUPPORTED")
    for start, end in ((100, 108), (108, 116), (116, 124), (124, 136), (136, 148),
                       (148, 156), (329, 337), (337, 345)):
        token, terminator, padding = header[start:end].partition(b"\0")
        profile(re.fullmatch(rb" *[0-7]* *", token) is not None
                and (not terminator or not padding.strip(b"\0 ")), "TAR_NUMERIC_FIELD_PROFILE_UNSUPPORTED")
    name, link = cstring(header[:100]), cstring(header[157:257])
    cstring(header[265:297])
    cstring(header[297:329])
    profile(not link, "TAR_LINK_FIELD_UNSUPPORTED")
    if header[257:265] == b"ustar\x0000":
        prefix = cstring(header[345:500])
        name = prefix + "/" + name if prefix else name
        profile(not header[500:].strip(b"\0"), "TAR_RESERVED_BYTES_UNSUPPORTED")
    else:
        profile(not header[345:].strip(b"\0"), "TAR_GNU_EXTENSION_UNSUPPORTED")
    try:
        info = tarfile.TarInfo.frombuf(header, "utf-8", "strict")
    except (tarfile.TarError, UnicodeError, ValueError):
        raise CoverageGap("TAR_RAW_HEADER_INVALID") from None
    profile(info.name.rstrip("/") == name.rstrip("/") and info.type == header[156:157],
            "TAR_HEADER_NORMALIZATION_UNSUPPORTED")
    allowed_mode_type = stat.S_IFDIR if info.type == b"5" else stat.S_IFREG if info.type in (b"0", b"\0") else 0
    profile(info.mode >= 0 and not info.mode & ~(0o7777 | allowed_mode_type)
            and stat.S_IFMT(info.mode) in (0, allowed_mode_type), "TAR_MODE_TYPE_BITS_UNSUPPORTED")
    profile(0 <= info.uid < 1 << 32 and 0 <= info.gid < 1 << 32
            and 0 <= info.size <= MAX_MEMBER_BYTES and 0 <= info.mtime < 1 << 63
            and info.devmajor == info.devminor == 0, "TAR_MEMBER_BOUNDS_UNSUPPORTED")
    return info, name


def inspect_tar(body, location, locked, budget, findings, gaps):
    profile(len(body) % 512 == 0, "TAR_BLOCK_LENGTH_INVALID")
    root = f"{locked['name']}-{locked['version']}"
    rows, metadata, seen = BoundedRows(budget), BoundedRows(budget), set()
    offset, pending, header_count = 0, None, 0
    while True:
        budget.check()
        profile(offset + 512 <= len(body), "TAR_TWO_END_BLOCKS_REQUIRED")
        header = body[offset:offset + 512]
        if not header.strip(b"\0"):
            profile(pending is None, "TAR_DANGLING_GNU_LONGNAME")
            profile(offset + 1024 <= len(body) and not body[offset + 512:offset + 1024].strip(b"\0"),
                    "TAR_TWO_END_BLOCKS_REQUIRED")
            trailer = body[offset:]
            profile(not trailer.strip(b"\0"), "TAR_NONZERO_TRAILING_BYTES")
            return {"members": rows, "gnuLongNameMetadata": metadata, "memberCount": len(rows),
                    "physicalHeaderCount": len(rows) + len(metadata), "trailerSizeBytes": len(trailer),
                    "trailerSHA256": LAYERS.sha(trailer), "tarProfile": "PHYSICAL_GNU_OR_POSIX_USTAR_HEADERS_FULL_PAYLOAD_PADDING_AND_ZERO_TRAILER"}
        budget.headers += 1
        LAYERS.require(budget.headers <= MAX_PHYSICAL_HEADERS, "physical header aggregate bound exceeded")
        header_location = location + f"!tar-header[{header_count}]"
        header_count += 1
        # Structural TAR magic is checked separately; retain ZIP inspection of
        # every complete physical header, including ignored non-path fields.
        budget.inspect(header, b"", header_location, findings, gaps)
        info, name = raw_header(header)
        start, finish = offset + 512, offset + 512 + info.size
        next_offset = finish + (-info.size % 512)
        profile(next_offset <= len(body), "TAR_TRUNCATED_PAYLOAD_OR_PADDING")
        payload, padding = body[start:finish], body[finish:next_offset]
        profile(not padding.strip(b"\0"), "TAR_NONZERO_MEMBER_PADDING")
        row = {"headerOffsetBytes": offset, "rawHeaderSHA256": LAYERS.sha(header),
               "type": info.type.decode("ascii"), "sizeBytes": info.size, "sha256": LAYERS.sha(payload),
               "rawModeOctal": format(info.mode, "04o"), "permissionModeOctal": format(info.mode & 0o7777, "04o"),
               "paddingSizeBytes": len(padding), "paddingSHA256": LAYERS.sha(padding)}
        offset = next_offset
        if info.type == b"L":
            profile(pending is None and name == "././@LongLink" and 0 < info.size <= MAX_METADATA_BYTES,
                    "TAR_GNU_LONGNAME_PROFILE_UNSUPPORTED")
            budget.inspect(payload, payload[:512], header_location + "!gnu-longname", findings, gaps)
            profile(payload.endswith(b"\0") and b"\0" not in payload[:-1], "TAR_GNU_LONGNAME_TERMINATOR_INVALID")
            try:
                long_name = payload[:-1].decode("utf-8", "strict")
            except UnicodeError:
                raise CoverageGap("TAR_GNU_LONGNAME_ENCODING_UNSUPPORTED") from None
            pending = {**row, "headerPath": name, "declaredPath": long_name,
                       "associatedPath": crate_path(long_name, root, directory=True)}
            continue
        path = crate_path(name if pending is None else pending["declaredPath"], root, directory=info.type == b"5")
        # Even when GNU metadata supplies the full path, bind the ordinary raw
        # header's path to the same root; never hide an unsafe truncated name.
        crate_path(name, root, directory=info.type == b"5")
        profile(path not in seen, "TAR_DUPLICATE_PATH")
        seen.add(path)
        if pending is not None:
            profile(info.type in (b"0", b"\0", b"5"), "TAR_GNU_LONGNAME_ASSOCIATION_UNSUPPORTED")
            metadata.append(pending)
            pending = None
        if info.type == b"5":
            profile(info.size == 0, "TAR_DIRECTORY_PAYLOAD_UNSUPPORTED")
        else:
            budget.inspect(payload, payload[:512], location + "!/" + path, findings, gaps)
        rows.append({**row, "path": path})


def inspect_crate(body, location, locked, budget, findings, gaps):
    budget.check()
    profile(len(body) >= 18 and body[:4] == b"\x1f\x8b\x08\x08", "CRATE_GZIP_HEADER_PROFILE_UNSUPPORTED")
    end = body.find(b"\0", 10, 10 + MAX_METADATA_BYTES + 1)
    profile(end >= 0, "CRATE_GZIP_FILENAME_UNTERMINATED_OR_BOUND")
    filename = body[10:end]
    profile(filename == locked["filename"].encode(), "CRATE_GZIP_FILENAME_DIFFERS_FROM_LOCK")
    header = body[:end + 1]
    budget.inspect(filename, filename[:512], location + "!gzip-filename/" + locked["filename"], findings, gaps)
    budget.inspect(header, b"", location + "!gzip-header", findings, gaps)
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    expanded, pending, offset = bytearray(), b"", 0
    try:
        while not decoder.eof:
            budget.check()
            if not pending:
                pending = body[offset:offset + (64 << 10)]
                offset += len(pending)
            profile(bool(pending), "CRATE_GZIP_TRUNCATED_MEMBER")
            remaining = min(MAX_EXPANDED_BYTES - len(expanded), MAX_TOTAL_EXPANDED_BYTES - budget.expanded)
            chunk = decoder.decompress(pending, min(64 << 10, max(0, remaining) + 1))
            pending = decoder.unconsumed_tail
            budget.expanded += len(chunk)
            LAYERS.require(budget.expanded <= MAX_TOTAL_EXPANDED_BYTES, "crate expansion aggregate bound exceeded")
            profile(len(expanded) + len(chunk) <= MAX_EXPANDED_BYTES, "CRATE_GZIP_EXPANSION_BOUND")
            expanded.extend(chunk)
        profile(not decoder.unused_data and not pending and offset == len(body), "CRATE_GZIP_CONCATENATED_OR_TRAILING_BYTES")
    except zlib.error:
        raise CoverageGap("CRATE_GZIP_INVALID_CRC_ISIZE_OR_MEMBER") from None
    value = bytes(expanded)
    return {"gzipHeaderSizeBytes": len(header), "gzipHeaderSHA256": LAYERS.sha(header),
            "gzipFilename": locked["filename"], "gzipProfile": "SINGLE_MEMBER_FULL_INPUT_CRC_ISIZE_VERIFIED_EXACT_LOCKED_FILENAME",
            "expandedSizeBytes": len(value), "expandedSHA256": LAYERS.sha(value),
            **inspect_tar(value, location, locked, budget, findings, gaps)}


class LayerReader:
    def __init__(self, stream, compressed, budget):
        self.stream = LAYERS.ExpandedGzip(stream, budget.layer_counters) if compressed else stream
        self.compressed, self.budget = compressed, budget
        self.digest, self.size = hashlib.sha256(), 0

    def read(self, size):
        self.budget.check()
        LAYERS.require(type(size) is int and 0 <= size <= 1 << 20, "bounded source layer read required")
        chunk = self.stream.read(size)
        self.digest.update(chunk)
        self.size += len(chunk)
        if not self.compressed:
            self.budget.layer_counters["expandedLayerBytes"] += len(chunk)
        LAYERS.require(self.budget.layer_counters["expandedLayerBytes"] <= MAX_LAYER_BYTES, "source layer expansion bound exceeded")
        return chunk


def measure_source(path, archive_hash, receipt, selected, lock_body, budget, findings, gaps):
    layer = receipt["layers"][0]
    rows, seen = BoundedRows(budget), set()
    with regular_file(path, MAX_ARCHIVE_BYTES) as stream:
        before = os.fstat(stream.fileno())
        LAYERS.require(file_hash(stream, budget) == archive_hash, "source archive checksum differs")
        with tarfile.open(fileobj=stream, mode="r:", tarinfo=LAYERS.BoundedMetadataInfo) as saved:
            outer = {}
            for member in saved:
                budget.check()
                name = LAYERS.canonical(member.name)
                LAYERS.require(name not in outer and len(outer) < LAYERS.MAX_OUTER_MEMBERS
                               and (member.isfile() or member.isdir()) and not member.issparse()
                               and (member.isfile() or member.size == 0), "unsupported source save inventory")
                LAYERS.check_member_padding(saved, member, streaming=False)
                outer[name] = member
            for padding in iter(lambda: saved.fileobj.read(1 << 20), b""):
                budget.check()
                LAYERS.require(not padding.strip(b"\0"), "nonzero source save trailing bytes")

            def metadata(name):
                member = outer[LAYERS.canonical(name)]
                LAYERS.require(member.isfile() and 0 <= member.size <= MAX_LOCK_BYTES, "invalid source save metadata")
                with saved.extractfile(member) as source:
                    body = source.read(member.size + 1)
                LAYERS.require(len(body) == member.size, "truncated source save metadata")
                return body

            manifests = json.loads(metadata("manifest.json"))
            LAYERS.require(isinstance(manifests, list) and len(manifests) == 1, "single source saved image required")
            manifest = manifests[0]
            config_body = metadata(manifest["Config"])
            LAYERS.require("sha256:" + LAYERS.sha(config_body) == receipt["imageConfigID"], "source config checksum differs")
            config = json.loads(config_body)
            LAYERS.require(config.get("os") == "linux" and config.get("architecture") == "amd64"
                           and config.get("rootfs") == {"type": "layers", "diff_ids": [layer["diffID"]]}
                           and manifest["Layers"] == [layer["archivePath"]], "source saved layer identity differs")
            manifest_id, descriptors = LAYERS.oci_graph(outer, metadata, manifest, config_body)
            LAYERS.require(manifest_id == receipt["ociImageManifestID"] and descriptors is not None
                           and (descriptors[0]["mediaType"] == LAYERS.OCI_GZIP_LAYER) == (layer["compression"] == "gzip"),
                           "source OCI manifest/compression identity differs")
            blob = outer[LAYERS.canonical(layer["archivePath"])]
            LAYERS.require(blob.isfile() and blob.size == layer["storedBlobSizeBytes"], "stored source layer size differs")
            stored_hash, stored_size, head = hashlib.sha256(), 0, b""
            with saved.extractfile(blob) as source:
                for chunk in iter(lambda: source.read(1 << 20), b""):
                    budget.check()
                    stored_hash.update(chunk)
                    stored_size += len(chunk)
                    head = head or chunk[:32]
            LAYERS.require(stored_size == blob.size and stored_hash.hexdigest() == layer["storedBlobSHA256"], "stored source layer checksum differs")
            if layer["compression"] == "gzip":
                LAYERS.require(LAYERS.gzip_envelope(head) == layer["gzipEnvelope"], "source layer gzip envelope differs")
            lock_seen = False
            with saved.extractfile(blob) as source:
                reader = LayerReader(source, layer["compression"] == "gzip", budget)
                count, names = 0, set()
                wanted = {item["path"]: item for item in selected.values()}
                with tarfile.open(fileobj=reader, mode="r|", tarinfo=LAYERS.BoundedMetadataInfo) as tar:
                    for member in tar:
                        budget.check()
                        name = LAYERS.canonical(member.name)
                        count += 1
                        LAYERS.require(name not in names and count <= LAYERS.MAX_LAYER_MEMBERS and not member.issparse(), "invalid source layer member")
                        names.add(name)
                        if name not in wanted and name != LOCK_PATH:
                            continue
                        expected = wanted.get(name)
                        size = len(lock_body) if name == LOCK_PATH else expected["sizeBytes"]
                        LAYERS.require(member.isfile() and member.size == size, "selected source member type/size differs")
                        with tar.extractfile(member) as payload:
                            value = payload.read(size + 1)
                        LAYERS.require(len(value) == size, "selected source payload length differs")
                        LAYERS.check_member_padding(tar, member, streaming=True)
                        if name == LOCK_PATH:
                            LAYERS.require(value == lock_body and not lock_seen, "distributed lock bytes differ")
                            lock_seen = True
                            continue
                        LAYERS.require(LAYERS.sha(value) == expected["sha256"], "selected source crate checksum differs")
                        budget.compressed += size
                        LAYERS.require(budget.compressed <= MAX_TOTAL_COMPRESSED_BYTES, "crate compressed aggregate bound exceeded")
                        row = {"filename": expected["filename"], "name": expected["name"], "version": expected["version"],
                               "sourceLocation": expected["location"], "compressedSizeBytes": size,
                               "compressedSHA256": expected["sha256"], "status": "GAP"}
                        start_findings, start_gaps = len(findings), len(gaps)
                        try:
                            row.update(inspect_crate(value, expected["location"], expected, budget, findings, gaps))
                            row["status"] = "MEASURED" if len(findings) == start_findings and len(gaps) == start_gaps else "NESTED_FINDING_OR_GAP"
                        except CoverageGap as exc:
                            gaps.append({"location": expected["location"], "reason": str(exc)})
                        rows.append(row)
                        seen.add(expected["filename"])
                    for padding in iter(lambda: tar.fileobj.read(1 << 20), b""):
                        budget.check()
                        LAYERS.require(not padding.strip(b"\0"), "nonzero source layer trailing bytes")
                LAYERS.require(lock_seen and count == layer["memberCount"] and reader.size == layer["tarSizeBytes"]
                               and "sha256:" + reader.digest.hexdigest() == layer["diffID"]
                               and (not reader.compressed or reader.stream.finished), "source layer diffID/size/count/lock differs")
        LAYERS.require(file_hash(stream, budget) == archive_hash, "source archive final checksum differs")
        unchanged(stream, path, before)
    LAYERS.require(seen == set(selected), "source crate measurement coverage differs")
    return rows, {"index": 0, "diffID": layer["diffID"], "storedBlobSHA256": stored_hash.hexdigest(),
                  "storedBlobSizeBytes": stored_size, "tarSizeBytes": reader.size, "memberCount": count,
                  "distributedLockSHA256": LAYERS.sha(lock_body), "sourceSaveSHA256BeforeAndAfterVerified": True}


def audit(*, source_archive, source_archive_sha256, source_image_config_id, source_image_manifest_id,
          source_physical_receipt, source_physical_receipt_sha256, service_archive_sha256,
          service_image_config_id, service_image_manifest_id, service_physical_receipt,
          service_physical_receipt_sha256, lock, lock_sha256):
    hashes = (source_archive_sha256, source_physical_receipt_sha256, service_archive_sha256,
              service_physical_receipt_sha256, lock_sha256)
    ids = (source_image_config_id, source_image_manifest_id, service_image_config_id, service_image_manifest_id)
    LAYERS.require(all(isinstance(value, str) and SHA256.fullmatch(value) is not None for value in hashes)
                   and all(isinstance(value, str) and LAYERS.DIGEST.fullmatch(value) is not None for value in ids),
                   "explicit full input identities required")
    budget = Budget()
    lock_body = bound_input(lock, lock_sha256, MAX_LOCK_BYTES, budget)
    locked = locked_crates(lock_body)
    source_receipt = json.loads(bound_input(source_physical_receipt, source_physical_receipt_sha256, MAX_RECEIPT_BYTES, budget))
    service_receipt = json.loads(bound_input(service_physical_receipt, service_physical_receipt_sha256, MAX_RECEIPT_BYTES, budget))
    source_selected = receipt_inputs(source_receipt, source_image_config_id, source_image_manifest_id,
                                     source_archive_sha256, SOURCE_PREFIX, locked, budget, source=True)
    service_selected = receipt_inputs(service_receipt, service_image_config_id, service_image_manifest_id,
                                      service_archive_sha256, SERVICE_PREFIX, locked, budget)
    findings, gaps = BoundedRows(budget), BoundedRows(budget)
    rows, measured_layer = measure_source(source_archive, source_archive_sha256, source_receipt,
                                          source_selected, lock_body, budget, findings, gaps)
    for row in rows:
        row["serviceLocation"] = service_selected[row["filename"]]["location"]
    resolved = {row["filename"] for row in rows if row["status"] == "MEASURED"}
    accounting = {}
    for role, receipt, selected in (("source", source_receipt, source_selected), ("service", service_receipt, service_selected)):
        resolved_locations = {selected[filename]["location"] for filename in resolved}
        unresolved = sum(not (row["reason"] == ORIGINAL_GAP and row["location"] in resolved_locations)
                         for row in receipt["archiveInspectionGaps"])
        accounting[role] = {"originalGapRows": len(receipt["archiveInspectionGaps"]),
                            "resolvedOriginalCrateGapRows": len(resolved_locations), "originalUnresolvedGapRows": unresolved,
                            "originalExcludedPayloadFindingCount": len(receipt["excludedPayloadFindings"])}
    budget.check()
    report = {"schemaVersion": 1, "scope": "EXACT_LOCKED_CRATE_SOURCE_GZIP_TAR_COMPANION",
              "sourceArchiveSHA256": source_archive_sha256, "sourceImageConfigID": source_image_config_id,
              "sourceImageManifestID": source_image_manifest_id, "sourcePhysicalReceiptSHA256": source_physical_receipt_sha256,
              "serviceArchiveSHA256": service_archive_sha256, "serviceImageConfigID": service_image_config_id,
              "serviceImageManifestID": service_image_manifest_id, "servicePhysicalReceiptSHA256": service_physical_receipt_sha256,
              "serviceAssociation": "ORIGINAL_PHYSICAL_RECEIPT_FILENAME_SIZE_SHA256_ASSOCIATION_NO_SERVICE_ARCHIVE_OR_CURRENT_DOCKER_REMEASUREMENT",
              "lockSHA256": lock_sha256, "sourcePathPrefix": SOURCE_PREFIX, "servicePathPrefix": SERVICE_PREFIX,
              "sourceLayerMeasurement": measured_layer, "inventory": rows, "selectedCrateCount": len(locked),
              "measuredCrateCount": len(resolved), "gapAccounting": accounting,
              "excludedPayloadFindings": findings, "archiveInspectionGaps": gaps,
              "exclusionGate": "FAILED" if findings or source_receipt["excludedPayloadFindings"] or service_receipt["excludedPayloadFindings"]
                  else "PENDING_OTHER_PHYSICAL_GAPS_AND_LEGAL_RECONCILIATION",
              "qualified": False, "legalAccepted": False, "originalReceiptReplaced": False,
              "measurement": {"compressedCrateBytes": budget.compressed, "expandedCrateTarBytes": budget.expanded,
                              "physicalCrateHeaders": budget.headers, "expandedSourceLayerBytes": budget.layer_counters["expandedLayerBytes"],
                              **budget.inspection},
              "limits": {"exactLockedCrateCount": EXPECTED_CRATES, "maximumCompressedCrateBytes": MAX_COMPRESSED_BYTES,
                         "maximumCompressedAggregateBytes": MAX_TOTAL_COMPRESSED_BYTES, "maximumExpandedCrateTarBytes": MAX_EXPANDED_BYTES,
                         "maximumExpandedAggregateBytes": MAX_TOTAL_EXPANDED_BYTES, "maximumMemberBytes": MAX_MEMBER_BYTES,
                         "maximumPhysicalHeaders": MAX_PHYSICAL_HEADERS, "maximumFilenameMetadataBytes": MAX_METADATA_BYTES,
                         "maximumReportBytes": MAX_REPORT_BYTES, "maximumNestedZipMemberBytes": LAYERS.MAX_ZIP_BYTES,
                         "maximumNestedZipAggregateBytes": LAYERS.MAX_ZIP_EXPANDED_BYTES, "maximumNestedZipMembers": LAYERS.MAX_ZIP_MEMBERS,
                         "cooperativeDeadlineSeconds": DEADLINE_SECONDS, "hardOuterUnitRequired": True},
              "tools": {"companionSHA256": LAYERS.sha(Path(__file__).read_bytes()),
                        "physicalInspectorSHA256": LAYERS.sha((ROOT / "scripts/audit-image-layers.py").read_bytes()),
                        "pythonVersion": sys.version.split()[0], "zlibRuntimeVersion": zlib.ZLIB_RUNTIME_VERSION}}
    LAYERS.require(len((json.dumps(report, sort_keys=True, indent=2) + "\n").encode()) <= MAX_REPORT_BYTES,
                   "crate receipt size exceeded")
    return report


def destination_path(path):
    destination = path.absolute()
    LAYERS.require(not destination.exists() and not destination.is_symlink()
                   and destination.resolve().is_relative_to(ROOT), "fresh output below repository required")
    relative = destination.resolve().relative_to(ROOT)
    LAYERS.require(len(relative.parts) > 1 and relative.parts[0] in (".local", "artifacts"), "fresh task-owned evidence output required")
    return destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source-archive", "source-physical-receipt", "service-physical-receipt", "lock", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("source-archive-sha256", "source-image-config-id", "source-image-manifest-id",
                 "source-physical-receipt-sha256", "service-archive-sha256", "service-image-config-id",
                 "service-image-manifest-id", "service-physical-receipt-sha256", "lock-sha256"):
        parser.add_argument("--" + name, required=True)
    args = vars(parser.parse_args())
    destination = destination_path(args.pop("output"))
    report = audit(**args)
    body = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
    with destination.open("xb") as stream:
        stream.write(body)
    print("Locked crate companion measured; remaining physical and legal gates stay pending")
    return 1 if report["exclusionGate"] == "FAILED" else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError, AttributeError, tarfile.TarError):
        print("image-crate-audit: invalid, unsupported or over-limit evidence; no gate claimed", file=sys.stderr)
        raise SystemExit(1)
