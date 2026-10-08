#!/usr/bin/env python3
"""Measure a saved image without extraction or execution; this is not an SBOM.

Every distributed filesystem layer is hashed and inventoried, including payloads
subsequently removed by whiteouts. ZIP/JAR inspection has explicit bounds; other
archive formats are recorded as uninspected rather than declared redistributable.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import sys
import tarfile
import zipfile
import zlib

ROOT = Path(__file__).resolve().parents[1]
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
BLOCKED_DIGESTS = frozenset((
    "6590cf1bcea23e27bc4c0ca86ca365343ee85a19671b42ef9815aaaa451b8aa9",
    "79db2dea6c4f024285a648c51be82c333345b82958e14f7fb5f6920f0b455d85",
    "65e7a791bcb39437ef98562f29fa098124ae81736d9376296e95d6afedac6ba7",
))
MAX_OUTER_MEMBERS = 4096
MAX_LAYER_MEMBERS = 1_000_000
MAX_LAYERS = 128
MAX_FILE_BYTES = 16 << 30
MAX_TOTAL_BYTES = 64 << 30
MAX_METADATA_BYTES = 32 << 20
MAX_ZIP_BYTES = 32 << 20
MAX_ZIP_EXPANDED_BYTES = 256 << 20
MAX_ZIP_MEMBERS = 40_000
MAX_ZIP_DEPTH = 4
MAX_ZIP_ENVELOPES = 32


class Failure(ValueError):
    """Invalid or unsupported physical-image evidence."""


class BoundedMetadataInfo(tarfile.TarInfo):
    def metadata_with_padding(self, archive, processor):
        require(0 <= self.size <= MAX_METADATA_BYTES, "tar metadata payload bound exceeded")
        original = archive.fileobj.read
        first = True
        def checked_read(size):
            nonlocal first
            body = original(size)
            if first:
                first = False
                padded_size = (self.size + tarfile.BLOCKSIZE - 1) // tarfile.BLOCKSIZE * tarfile.BLOCKSIZE
                require(len(body) == padded_size, "truncated tar metadata payload or padding")
                require(not body[self.size:].strip(b"\0"), "nonzero tar metadata member padding")
            return body
        archive.fileobj.read = checked_read
        try:
            return processor(archive)
        finally:
            archive.fileobj.read = original

    def _proc_pax(self, archive):
        require(not any(key.startswith("GNU.sparse") for key in archive.pax_headers), "sparse tar metadata unsupported")
        return self.metadata_with_padding(archive, super()._proc_pax)

    def _proc_gnulong(self, archive):
        return self.metadata_with_padding(archive, super()._proc_gnulong)

    def _proc_sparse(self, archive):
        raise Failure("sparse tar metadata unsupported")

    def _proc_gnusparse_10(self, next_member, pax_headers, archive):
        raise Failure("sparse tar metadata unsupported")


def require(value: bool, message: str) -> None:
    if not value:
        raise Failure(message)


def sha(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def check_member_padding(archive, member, *, streaming: bool) -> None:
    start = member.offset_data + member.size
    if streaming:
        require(archive.fileobj.tell() == start, "tar payload position differs from declared member size")
    else:
        archive.fileobj.seek(start)
    padding_size = -member.size % tarfile.BLOCKSIZE
    padding = archive.fileobj.read(padding_size)
    require(len(padding) == padding_size, "truncated tar member padding")
    require(not padding.strip(b"\0"), "nonzero tar member padding")


def canonical(name: str) -> str:
    require(isinstance(name, str) and 0 < len(name) <= 4096, "invalid archive path")
    require(not any(ord(char) < 32 or ord(char) == 127 for char in name)
            and "\\" not in name, "invalid archive path")
    while name.startswith("./"):
        name = name[2:]
    name = name.rstrip("/")
    if not name:
        name = "."
    path = PurePosixPath(name)
    require(bool(name) and not path.is_absolute() and ".." not in path.parts
            and path.as_posix() == name, "unsafe archive path")
    return name


def blocked_name(name: str) -> bool:
    parts = PurePosixPath(name.lower()).parts
    return ("viva" in parts or parts[-1] in ("viva.jar", "viva.sh", "viva user's guide.pdf")
            or parts[-1].endswith(".class") and (
                parts[-1] == "jarrsrcloader.class" or "jarinjarloader" in parts
                or "miginfocom" in parts or "miglayout" in parts))


def java_class_name(body: bytes) -> str | None:
    """Read this_class, rather than treating a reference as a class definition."""
    if not body.startswith(b"\xca\xfe\xba\xbe"):
        return None
    try:
        count = struct.unpack_from(">H", body, 8)[0]
        offset, index, pool = 10, 1, {}
        while index < count:
            tag = body[offset]
            offset += 1
            if tag == 1:
                length = struct.unpack_from(">H", body, offset)[0]
                offset += 2
                pool[index] = body[offset:offset + length].decode("utf-8", errors="replace")
                require(offset + length <= len(body), "truncated Java class")
                offset += length
            elif tag == 7:
                pool[index] = struct.unpack_from(">H", body, offset)[0]
                offset += 2
            elif tag in (3, 4, 9, 10, 11, 12, 17, 18):
                offset += 4
            elif tag in (5, 6):
                offset += 8
                index += 1
            elif tag in (8, 16, 19, 20):
                offset += 2
            elif tag == 15:
                offset += 3
            else:
                return None
            require(offset <= len(body), "truncated Java class")
            index += 1
        this_class = struct.unpack_from(">H", body, offset + 2)[0]
        name = pool[pool[this_class]]
        return name if isinstance(name, str) else None
    except (IndexError, KeyError, struct.error, Failure):
        return None


def other_archive(body: bytes, name: str) -> bool:
    lower = name.lower()
    return (body.startswith((b"\x1f\x8b", b"\x1f\x9d", b"BZh", b"\xfd7zXZ\x00", b"LZIP", b"\x28\xb5\x2f\xfd",
                             b"!<arch>\n", b"7z\xbc\xaf\x27\x1c", b"Rar!"))
            or len(body) > 262 and body[257:262] == b"ustar"
            or lower.endswith((".tar", ".tar.gz", ".tgz", ".tar.xz", ".tar.bz2", ".deb", ".7z", ".rar", ".zst")))


def zip_envelope_gaps(body: bytes, end: int, archive, infos: list, name: str, gaps: list[dict], counters: dict) -> None:
    """Account for raw bytes outside the central directory's member view."""
    cursor = 0
    incomplete = end != len(body) or bool(archive.comment)
    try:
        for info in sorted(infos, key=lambda entry: entry.header_offset):
            if info.header_offset != cursor:
                incomplete = True
            fields = struct.unpack_from("<4s5H3I2H", body, info.header_offset)
            require(fields[0] == b"PK\x03\x04", "invalid ZIP local header")
            flags, method, name_size, extra_size = fields[2], fields[3], fields[-2], fields[-1]
            start = info.header_offset + 30 + name_size + extra_size
            finish = start + info.compress_size
            require(finish <= archive.start_dir, "ZIP local payload exceeds directory")
            if extra_size or info.extra or info.comment or flags != info.flag_bits or method != info.compress_type:
                incomplete = True
            if not flags & 8 and fields[6:9] != (info.CRC, info.compress_size, info.file_size):
                incomplete = True
            if method == zipfile.ZIP_DEFLATED:
                # zlib may accept unused bytes after a valid compressed stream;
                # those bytes are absent from archive.read(member).
                already_expanded = counters.setdefault("zipEnvelopeExpandedBytes", 0)
                if info.file_size <= MAX_ZIP_BYTES and already_expanded + info.file_size <= MAX_ZIP_EXPANDED_BYTES:
                    decompressor = zlib.decompressobj(-15)
                    value = decompressor.decompress(body[start:finish], info.file_size + 1)
                    counters["zipEnvelopeExpandedBytes"] += len(value)
                    if (not decompressor.eof or decompressor.unused_data or decompressor.unconsumed_tail
                            or len(value) != info.file_size or zlib.crc32(value) & 0xffffffff != info.CRC):
                        incomplete = True
                else:
                    incomplete = True
            elif method == zipfile.ZIP_STORED:
                if info.compress_size != info.file_size or zlib.crc32(body[start:finish]) & 0xffffffff != info.CRC:
                    incomplete = True
            else:
                incomplete = True
            cursor = finish
            if flags & 8:
                if body[cursor:cursor + 4] == b"PK\x07\x08":
                    cursor += 4
                descriptor = struct.unpack_from("<III", body, cursor)
                if descriptor != (info.CRC, info.compress_size, info.file_size):
                    incomplete = True
                cursor += 12
        if cursor != archive.start_dir:
            incomplete = True
    except (Failure, struct.error, zlib.error):
        incomplete = True
    if incomplete:
        gaps.append({"location": name, "reason": "ZIP_ENVELOPE_BYTES_NOT_FULLY_MEMBER_BOUND"})


def inspect_payload(body: bytes | None, head: bytes, name: str, digest: str,
                    findings: list[dict], gaps: list[dict], counters: dict, depth: int = 0) -> None:
    if blocked_name(name):
        findings.append({"location": name, "reason": "EXCLUDED_VIVA_OR_NESTED_CLASS_PATH"})
    if digest in BLOCKED_DIGESTS:
        findings.append({"location": name, "reason": "EXACT_EXCLUDED_BINARY_SHA256", "sha256": digest})
    if body is not None:
        class_name = java_class_name(body)
        if class_name is not None and blocked_name(class_name + ".class"):
            findings.append({"location": name, "reason": "EXCLUDED_JAVA_CLASS_DEFINITION", "className": class_name})
    if other_archive(head, name):
        gaps.append({"location": name, "reason": "NON_ZIP_ARCHIVE_NOT_RECURSIVELY_INSPECTED"})
    zip_hint = head.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")) or name.lower().endswith((".zip", ".jar", ".whl"))
    if body is None:
        # A large, renamed concatenated ZIP cannot be excluded by a leading
        # magic check. Preserve this limitation for every oversized payload.
        gaps.append({"location": name, "reason": "PAYLOAD_EXCEEDS_NESTED_INSPECTION_BOUND"})
        return
    # Inspect each valid ZIP end record, including a JAR prepended to another
    # archive. zipfile alone selects only the last end record in such a file.
    endings = []
    start = 0
    while True:
        position = body.find(b"PK\x05\x06", start)
        if position < 0:
            break
        start = position + 4
        if len(body) >= position + 22:
            end = position + 22 + int.from_bytes(body[position + 20:position + 22], "little")
            if end <= len(body):
                endings.append(end)
        if len(endings) > MAX_ZIP_ENVELOPES:
            gaps.append({"location": name, "reason": "ZIP_ENVELOPE_COUNT_BOUND"})
            return
    if not endings:
        if zip_hint:
            gaps.append({"location": name, "reason": "ZIP_FORMAT_UNSUPPORTED_OR_INVALID"})
        return
    if depth >= MAX_ZIP_DEPTH:
        gaps.append({"location": name, "reason": "ZIP_RECURSION_DEPTH_BOUND"})
        return
    valid = False
    for end in endings:
        try:
            with zipfile.ZipFile(io.BytesIO(body[:end])) as archive:
                infos = archive.infolist()
                if len(infos) + counters["zipMembers"] > MAX_ZIP_MEMBERS:
                    gaps.append({"location": name, "reason": "ZIP_MEMBER_COUNT_BOUND"})
                    continue
                valid = True
                zip_envelope_gaps(body, end, archive, infos, name, gaps, counters)
                counters["zipArchives"] += 1
                counters["zipMembers"] += len(infos)
                seen = set()
                for info in infos:
                    member = canonical(info.filename)
                    require(member not in seen, "duplicate ZIP member")
                    seen.add(member)
                    location = name + "!/" + member
                    if info.is_dir() and info.file_size == 0:
                        continue
                    if info.is_dir():
                        gaps.append({"location": location, "reason": "ZIP_DIRECTORY_CONTAINS_PAYLOAD"})
                    if blocked_name(member):
                        findings.append({"location": location, "reason": "EXCLUDED_VIVA_OR_NESTED_CLASS_PATH"})
                    if info.flag_bits & 1 or info.file_size > MAX_ZIP_BYTES or counters["zipExpandedBytes"] + info.file_size > MAX_ZIP_EXPANDED_BYTES:
                        gaps.append({"location": location, "reason": "ZIP_ENCRYPTION_OR_EXPANSION_BOUND"})
                        continue
                    require(not stat.S_ISLNK(info.external_attr >> 16), "ZIP link payload unsupported")
                    with archive.open(info) as stream:
                        value = stream.read(info.file_size + 1)
                    require(len(value) == info.file_size, "ZIP member length mismatch")
                    counters["zipExpandedBytes"] += len(value)
                    inspect_payload(value, value[:512], location, sha(value), findings, gaps, counters, depth + 1)
        except (zipfile.BadZipFile, NotImplementedError, RuntimeError, Failure, OSError):
            gaps.append({"location": name, "reason": "ZIP_FORMAT_UNSUPPORTED_OR_INVALID"})
    if zip_hint and not valid:
        gaps.append({"location": name, "reason": "ZIP_FORMAT_UNSUPPORTED_OR_INVALID"})


def layer_inventory(stream, layer_index: int, findings: list[dict], gaps: list[dict], counters: dict) -> tuple[list[dict], list[dict]]:
    records, seen, metadata = [], set(), []

    class BoundedInfo(BoundedMetadataInfo):
        def metadata_header(self, archive, method):
            require(0 <= self.size <= MAX_METADATA_BYTES, "tar metadata payload bound exceeded")
            original = archive.fileobj.read
            first = True
            def capture(size):
                nonlocal first
                body = original(size)
                if first:
                    first = False
                    require(len(body) >= self.size, "truncated tar metadata payload")
                    payload = body[:self.size]
                    counters["metadataBytes"] += len(payload)
                    require(counters["metadataBytes"] <= MAX_TOTAL_BYTES and len(metadata) < MAX_LAYER_MEMBERS,
                            "tar metadata inventory bound exceeded")
                    name = canonical(self.name)
                    digest = sha(payload)
                    metadata.append({"headerPath": name, "type": self.type.decode("ascii"), "sizeBytes": len(payload), "sha256": digest})
                    inspect_payload(payload, payload[:512], f"layer[{layer_index}]/tar-metadata/" + name,
                                    digest, findings, gaps, counters)
                return body
            archive.fileobj.read = capture
            try:
                return method(archive)
            finally:
                archive.fileobj.read = original

        def _proc_pax(self, archive):
            return self.metadata_header(archive, super()._proc_pax)

        def _proc_gnulong(self, archive):
            return self.metadata_header(archive, super()._proc_gnulong)

    inspected_pax_values = set()
    with tarfile.open(fileobj=stream, mode="r|", tarinfo=BoundedInfo) as layer:
        for member in layer:
            require(len(records) < MAX_LAYER_MEMBERS, "layer member count bound exceeded")
            counters["layerMembers"] += 1
            require(counters["layerMembers"] <= MAX_LAYER_MEMBERS, "total layer member count bound exceeded")
            name = canonical(member.name)
            require(not member.issparse(), "sparse tar metadata unsupported")
            require(name not in seen, "duplicate layer member")
            seen.add(name)
            require(0 <= member.size <= MAX_FILE_BYTES and 0 <= member.mode <= 0o7777
                    and 0 <= member.uid < 1 << 32 and 0 <= member.gid < 1 << 32, "invalid layer member bounds")
            record = {"path": name, "type": member.type.decode("ascii"), "mode": format(member.mode, "04o"),
                      "uid": member.uid, "gid": member.gid, "sizeBytes": member.size}
            if member.pax_headers:
                record["paxHeaderValues"] = []
                require(len(member.pax_headers) <= MAX_OUTER_MEMBERS, "PAX field count bound exceeded")
                for index, (key, value) in enumerate(sorted(member.pax_headers.items())):
                    body = value.encode("utf-8", errors="surrogateescape")
                    require(len(body) <= MAX_METADATA_BYTES, "PAX value bound exceeded")
                    identity = (sha(key.encode("utf-8", errors="surrogateescape")), sha(body))
                    record["paxHeaderValues"].append({"keySHA256": identity[0], "valueSHA256": identity[1], "sizeBytes": len(body)})
                    if identity not in inspected_pax_values:
                        inspected_pax_values.add(identity)
                        inspect_payload(body, body[:512], f"layer[{layer_index}]/" + name + f"!PAX[{index}]",
                                        identity[1], findings, gaps, counters)
            if member.isfile():
                counters["payloadBytes"] += member.size
                require(counters["payloadBytes"] <= MAX_TOTAL_BYTES, "total payload size bound exceeded")
                value, head, hasher, size = bytearray(), b"", hashlib.sha256(), 0
                with layer.extractfile(member) as payload:
                    for chunk in iter(lambda: payload.read(1 << 20), b""):
                        if not head:
                            head = chunk[:512]
                        hasher.update(chunk)
                        size += len(chunk)
                        if member.size <= MAX_ZIP_BYTES:
                            value.extend(chunk)
                require(size == member.size, "layer payload length mismatch")
                record["sha256"] = hasher.hexdigest()
                inspect_payload(bytes(value) if member.size <= MAX_ZIP_BYTES else None, head,
                                f"layer[{layer_index}]/" + name, record["sha256"], findings, gaps, counters)
            elif member.issym() or member.islnk():
                require(member.size == 0, "nonregular layer member contains payload")
                require(len(member.linkname) <= 4096 and not any(ord(c) < 32 or ord(c) == 127 for c in member.linkname), "invalid layer link")
                record["linkTarget"] = member.linkname
            elif member.ischr() or member.isblk():
                require(member.size == 0, "nonregular layer member contains payload")
                record.update({"deviceMajor": member.devmajor, "deviceMinor": member.devminor})
            else:
                require(member.isdir() or member.isfifo(), "unsupported layer entry type")
                require(member.size == 0, "nonregular layer member contains payload")
            check_member_padding(layer, member, streaming=True)
            records.append(record)
        # Standard tar padding is zero-filled. A second archive or binary
        # appended after the end marker is distributed but invisible to the
        # member iterator, so refuse that unmeasured envelope payload.
        for padding in iter(lambda: layer.fileobj.read(1 << 20), b""):
            require(not padding.strip(b"\0"), "nonzero layer data after tar end marker")
    return records, metadata


def verify_source_carrier(layers: list[dict], source_inventory: Path) -> None:
    require(len(layers) == 1, "source carrier must have exactly one filesystem layer")
    regular = {}
    for item in layers[0]["inventory"]:
        name = item["path"]
        if name == "." and item["type"] == tarfile.DIRTYPE.decode():
            continue
        require(name == "corresponding-source" or name.startswith("corresponding-source/"), "source carrier has payload outside corresponding-source")
        if item["type"] == tarfile.DIRTYPE.decode():
            continue
        require(item["type"] in (tarfile.REGTYPE.decode(), tarfile.AREGTYPE.decode()), "source carrier contains nonregular payload")
        require(item["mode"][:1] == "0", "source carrier has special permission bits")
        relative = name.removeprefix("corresponding-source/")
        regular[relative] = {"path": relative, "mode": item["mode"], "sizeBytes": item["sizeBytes"], "sha256": item["sha256"]}
    require(source_inventory.is_file() and not source_inventory.is_symlink() and source_inventory.stat().st_size <= MAX_METADATA_BYTES,
            "regular source inventory required")
    body = source_inventory.read_bytes()
    inventory = json.loads(body)
    require(inventory.get("schemaVersion") == 1 and isinstance(inventory.get("inventory"), list), "invalid source inventory")
    entries = inventory["inventory"]
    expected = {canonical(item["path"]): item for item in entries}
    require(len(expected) == len(entries), "duplicate source inventory entry")
    receipt = regular.pop("source-inventory.json", None)
    require(receipt is not None and receipt["sizeBytes"] == len(body) and receipt["sha256"] == sha(body),
            "source inventory differs from distributed bytes")
    require(regular == expected, "source carrier bytes differ from source inventory")


def audit(archive_path: Path, image_config_id: str, source_inventory: Path | None = None) -> dict:
    require(DIGEST.fullmatch(image_config_id) is not None, "explicit full image config ID required")
    require(archive_path.is_file() and not archive_path.is_symlink() and archive_path.stat().st_size <= MAX_TOTAL_BYTES,
            "bounded regular docker-save archive required")
    findings, gaps, layers = [], [], []
    counters = {"payloadBytes": 0, "metadataBytes": 0, "layerMembers": 0, "zipArchives": 0, "zipMembers": 0, "zipExpandedBytes": 0}
    with tarfile.open(archive_path, mode="r:", tarinfo=BoundedMetadataInfo) as saved:
        members = {}
        for item in saved:
            require(len(members) < MAX_OUTER_MEMBERS, "docker-save member count bound exceeded")
            name = canonical(item.name)
            require(not item.issparse(), "sparse docker-save member unsupported")
            require(name not in members and (item.isfile() or item.isdir()), "invalid docker-save archive member")
            require(0 <= item.size <= MAX_TOTAL_BYTES, "docker-save member size bound exceeded")
            check_member_padding(saved, item, streaming=False)
            members[name] = item
        for padding in iter(lambda: saved.fileobj.read(1 << 20), b""):
            require(not padding.strip(b"\0"), "nonzero docker-save data after tar end marker")
        def metadata(name):
            item = members[canonical(name)]
            require(item.isfile() and item.size <= MAX_METADATA_BYTES, "metadata size or type invalid")
            with saved.extractfile(item) as stream:
                body = stream.read(item.size + 1)
            require(len(body) == item.size, "metadata length mismatch")
            return body
        manifest = json.loads(metadata("manifest.json"))
        require(isinstance(manifest, list) and len(manifest) == 1, "exactly one saved image required")
        selected = manifest[0]
        config_body = metadata(selected["Config"])
        require("sha256:" + sha(config_body) == image_config_id, "image config checksum mismatch")
        config = json.loads(config_body)
        require(config.get("os") == "linux" and config.get("architecture") == "amd64", "Linux amd64 image required")
        diff_ids = config.get("rootfs", {}).get("diff_ids")
        names = selected.get("Layers")
        require(config.get("rootfs", {}).get("type") == "layers" and isinstance(names, list)
                and isinstance(diff_ids, list) and 0 < len(names) == len(diff_ids) <= MAX_LAYERS
                and len(set(names)) == len(names), "invalid saved layer identity")
        for index, (name, expected) in enumerate(zip(names, diff_ids)):
            require(isinstance(expected, str) and DIGEST.fullmatch(expected) is not None, "invalid layer diffID")
            member = members[canonical(name)]
            require(member.isfile(), "regular uncompressed layer required")
            digest, size = hashlib.sha256(), 0
            with saved.extractfile(member) as stream:
                for chunk in iter(lambda: stream.read(1 << 20), b""):
                    digest.update(chunk)
                    size += len(chunk)
            require(size == member.size and "sha256:" + digest.hexdigest() == expected, "layer diffID checksum mismatch")
            with saved.extractfile(member) as stream:
                records, metadata_records = layer_inventory(stream, index, findings, gaps, counters)
            encoded = json.dumps(records, sort_keys=True, separators=(",", ":")).encode()
            layers.append({"index": index, "archivePath": name, "diffID": expected, "tarSizeBytes": size,
                           "inventorySHA256": sha(encoded), "memberCount": len(records), "inventory": records,
                           "metadataPayloads": metadata_records,
                           "metadataInventorySHA256": sha(json.dumps(metadata_records, sort_keys=True, separators=(",", ":")).encode())})
    if source_inventory is not None:
        verify_source_carrier(layers, source_inventory)
    archive_digest = hashlib.sha256()
    with archive_path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            archive_digest.update(chunk)
    return {"schemaVersion": 1, "imageConfigID": image_config_id, "dockerSaveSHA256": archive_digest.hexdigest(),
            "scope": "ALL_DISTRIBUTED_FILESYSTEM_LAYERS_INCLUDING_DELETED_PAYLOADS", "completePhysicalLayerInventory": True,
            "sourceCarrierInventoryVerified": source_inventory is not None, "layers": layers, "measurement": counters,
            "dockerSaveEnvelopeScope": "SELECTED_CONFIG_AND_LAYER_BYTES_BOUND_NONZERO_MEMBER_PADDING_AND_TRAILER_REJECTED_OUTER_PAX_NOT_PAYLOAD_AUDIT",
            "excludedPayloadFindings": findings, "archiveInspectionGaps": gaps,
            "exclusionGate": "FAILED" if findings else "PENDING_ARCHIVE_COVERAGE" if gaps else "MEASURED_SCOPE_PASSED",
            "wholeImageSBOM": "SEPARATE_EVIDENCE_REQUIRED", "qualified": False,
            "nestedInspectionLimits": {"maximumPayloadBytes": MAX_ZIP_BYTES, "maximumExpandedBytes": MAX_ZIP_EXPANDED_BYTES,
                                       "maximumMembers": MAX_ZIP_MEMBERS, "maximumDepth": MAX_ZIP_DEPTH,
                                       "formats": ["ZIP", "JAR", "WHEEL"], "otherFormats": "NOT_RECURSIVELY_INSPECTED"}}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--image-config-id", required=True)
    parser.add_argument("--source-inventory", type=Path, help="Verify scratch source-carrier bytes against this audited receipt")
    parser.add_argument("--output", required=True, type=Path, help="Fresh JSON file below .local/ or artifacts/")
    args = parser.parse_args()
    report = audit(args.archive, args.image_config_id, args.source_inventory)
    destination = args.output.absolute()
    require(not destination.is_symlink() and destination.resolve().is_relative_to(ROOT), "output escapes repository")
    relative = destination.resolve().relative_to(ROOT)
    require(len(relative.parts) > 1 and relative.parts[0] in (".local", "artifacts"), "output must be task-owned local evidence")
    with destination.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print("Physical layers measured; archive coverage and SBOM scope remain explicit in evidence")
    return 1 if report["excludedPayloadFindings"] else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError, AttributeError, tarfile.TarError):
        print("image-layer-audit: invalid or unsupported archive; no exclusion gate claimed", file=sys.stderr)
        raise SystemExit(1)
