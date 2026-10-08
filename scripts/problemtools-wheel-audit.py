#!/usr/bin/env python3
"""Capture canonical problemtools wheel evidence before its build inputs disappear."""

from __future__ import annotations

import argparse
import base64
import configparser
import csv
import hashlib
import io
import json
import os
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import zipfile
import zlib

VERSION = "1.20260907"
REVISION = "6010cbaa37a1612117f49566b2fff8646d53faa2"
DIST_INFO = f"problemtools-{VERSION}.dist-info"
WHEEL_NAME = f"problemtools-{VERSION}-py3-none-any.whl"
SITE = "/usr/local/lib/python3.11/site-packages"
INSTALLED_PATHS = (f"{SITE}/problemtools", f"{SITE}/{DIST_INFO}",
                   "/usr/local/bin/verifyproblem", "/usr/local/bin/problem2html", "/usr/local/bin/problem2pdf")
FORBIDDEN_HASHES = frozenset((
    "6590cf1bcea23e27bc4c0ca86ca365343ee85a19671b42ef9815aaaa451b8aa9",
    "79db2dea6c4f024285a648c51be82c333345b82958e14f7fb5f6920f0b455d85",
    "65e7a791bcb39437ef98562f29fa098124ae81736d9376296e95d6afedac6ba7",
))
SHA = re.compile(r"[0-9a-f]{64}\Z")
MAX_MEMBER = 64 << 20
MAX_TOTAL = 256 << 20


def require(condition: bool) -> None:
    if not condition:
        raise ValueError("Problemtools wheel/install evidence invalid")


def sha(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def safe_name(name: str) -> str:
    path = PurePosixPath(name)
    require(bool(path.parts) and name == path.as_posix() and not path.is_absolute()
            and ".." not in path.parts and "\\" not in name and "\x00" not in name)
    return name


def checked_body(name: str, body: bytes) -> dict:
    safe_name(name)
    lowered = PurePosixPath(name.lower())
    digest = sha(body)
    require("viva" not in lowered.parts and lowered.name not in ("viva.sh", "viva user's guide.pdf")
            and lowered.suffix not in (".jar", ".class", ".zip", ".pyc", ".pyo")
            and digest not in FORBIDDEN_HASHES and len(body) <= MAX_MEMBER)
    # No nested ZIP payload is approved in this pinned Python distribution.
    require(not zipfile.is_zipfile(io.BytesIO(body)))
    return {"path": name, "sizeBytes": len(body), "sha256": digest}


def regular(path: Path) -> bytes:
    require(not path.is_symlink())
    info = path.stat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= MAX_MEMBER)
    for parent in path.parents:
        require(not parent.is_symlink())
    return path.read_bytes()


def installed(root: Path) -> dict[str, dict]:
    records = {}
    for name in INSTALLED_PATHS:
        path = root / name.lstrip("/")
        require(path.exists() and not path.is_symlink())
        if path.is_dir():
            members = []
            for parent, directories, files in os.walk(path, followlinks=False):
                require(all(not (Path(parent) / value).is_symlink() for value in directories))
                members.extend(Path(parent) / value for value in files)
        else:
            members = [path]
        for member in members:
            relative = member.relative_to(root).as_posix()
            require(relative not in records)
            records[relative] = checked_body(relative, regular(member))
    require(bool(records) and sum(value["sizeBytes"] for value in records.values()) <= MAX_TOTAL)
    return records


def record_rows(body: bytes) -> dict[str, tuple[str, str]]:
    rows = {}
    for row in csv.reader(io.StringIO(body.decode("utf-8"))):
        require(len(row) == 3 and row[0] not in rows)
        rows[row[0]] = (row[1], row[2])
    require(bool(rows))
    return rows


def check_record_hash(record: dict, declared: tuple[str, str], unhashed: bool = False) -> None:
    checksum, size = declared
    if unhashed:
        require(checksum == "" and size == "")
        return
    encoded = base64.urlsafe_b64encode(bytes.fromhex(record["sha256"])).decode().rstrip("=")
    require(checksum == "sha256=" + encoded and size == str(record["sizeBytes"]))


def installed_record(root: Path, records: dict[str, dict]) -> None:
    name = f"{SITE.lstrip('/')}/{DIST_INFO}/RECORD"
    rows = record_rows(regular(root / name))
    declared = {}
    for entry, value in rows.items():
        # pip's three fixed entry-point wrappers use ../../../bin paths.
        path = PurePosixPath(SITE, entry)
        canonical = os.path.normpath(str(path)).lstrip("/")
        require(canonical in records and canonical not in declared and "\\" not in entry and "\x00" not in entry)
        declared[canonical] = value
        check_record_hash(records[canonical], value, canonical == name)
    require(set(declared) == set(records))


def wheel_envelope(wheel_body: bytes, archive: zipfile.ZipFile) -> dict:
    """Account for every ZIP byte under the pinned seekable ZIP32 builder profile.

    zipfile deliberately tolerates prefixes, comments and unused compressed
    bytes. Those are additional payload carriers, so this profile rejects them
    rather than treating the member list as a complete archive inventory.
    """
    require(22 <= len(wheel_body) <= MAX_MEMBER and not archive.comment)
    ending = struct.unpack("<4s4H2IH", wheel_body[-22:])
    signature, disk, directory_disk, disk_count, count, directory_size, directory_offset, comment_size = ending
    members = archive.infolist()
    require(signature == b"PK\x05\x06" and disk == directory_disk == comment_size == 0
            and disk_count == count == len(members) and 0 < count <= 10000
            and directory_offset + directory_size + 22 == len(wheel_body))
    cursor, headers, compressed_members = 0, [], []
    for member in members:
        require(member.header_offset == cursor and cursor + 30 <= directory_offset
                and member.orig_filename == member.filename and not member.extra and not member.comment
                and member.flag_bits in (0, 0x800) and member.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                and member.file_size <= MAX_MEMBER and member.compress_size <= MAX_MEMBER)
        local = struct.unpack_from("<4s5H3I2H", wheel_body, cursor)
        marker, version, flags, method, _, _, crc, compressed_size, size, name_size, extra_size = local
        raw_name = member.filename.encode("utf-8" if flags & 0x800 else "cp437")
        require(marker == b"PK\x03\x04" and version == member.extract_version and flags == member.flag_bits
                and method == member.compress_type and crc == member.CRC
                and compressed_size == member.compress_size and size == member.file_size
                and name_size == len(raw_name) and extra_size == 0)
        payload_offset = cursor + 30 + name_size
        end = payload_offset + compressed_size
        require(end <= directory_offset and wheel_body[cursor + 30:payload_offset] == raw_name)
        compressed = wheel_body[payload_offset:end]
        if method == zipfile.ZIP_DEFLATED:
            inflater = zlib.decompressobj(-15)
            try:
                decoded = inflater.decompress(compressed, size + 1)
            except zlib.error:
                raise ValueError("Problemtools wheel/install evidence invalid") from None
            require(inflater.eof and not inflater.unused_data and not inflater.unconsumed_tail and len(decoded) == size)
        else:
            decoded = compressed
            require(compressed_size == size)
        require(decoded == archive.read(member))
        headers.append(wheel_body[cursor:payload_offset])
        compressed_members.append({"path": member.filename, "sizeBytes": compressed_size, "sha256": sha(compressed)})
        cursor = end
    require(cursor == directory_offset)
    for member in members:
        require(cursor + 46 <= len(wheel_body) - 22)
        central = struct.unpack_from("<4s6H3I5H2I", wheel_body, cursor)
        (marker, made_by, needed, flags, method, _, _, crc, compressed_size, size,
         name_size, extra_size, member_comment_size, start_disk, internal, external, local_offset) = central
        raw_name = member.filename.encode("utf-8" if flags & 0x800 else "cp437")
        end = cursor + 46 + name_size
        require(marker == b"PK\x01\x02" and made_by == (member.create_system << 8) | member.create_version
                and needed == member.extract_version and flags == member.flag_bits and method == member.compress_type
                and crc == member.CRC and compressed_size == member.compress_size and size == member.file_size
                and name_size == len(raw_name) and extra_size == member_comment_size == start_disk == 0
                and internal == member.internal_attr and external == member.external_attr and local_offset == member.header_offset
                and end <= len(wheel_body) - 22 and wheel_body[cursor + 46:end] == raw_name)
        headers.append(wheel_body[cursor:end])
        cursor = end
    require(cursor == len(wheel_body) - 22)
    headers.append(wheel_body[-22:])
    envelope = b"".join(headers)
    require(len(envelope) + sum(record["sizeBytes"] for record in compressed_members) == len(wheel_body))
    return {"format": "STRICT_ZIP32", "sizeBytes": len(wheel_body), "headerBytes": len(envelope),
            "headerSHA256": sha(envelope), "compressedMembers": compressed_members}


def wheel_records(wheel_name: str, wheel_body: bytes) -> dict[str, dict]:
    require(wheel_name == WHEEL_NAME)
    records, bodies = {}, {}
    with zipfile.ZipFile(io.BytesIO(wheel_body)) as archive:
        wheel_envelope(wheel_body, archive)
        require(len(archive.infolist()) <= 10000)
        for member in archive.infolist():
            name = member.filename
            # The pinned setuptools wheel writes payload files only. Reject
            # directory markers too, rather than omit unmeasured ZIP entries.
            require(not member.is_dir())
            safe_name(name)
            require(name not in records and name.split("/")[0] in ("problemtools", DIST_INFO)
                    and member.file_size <= MAX_MEMBER and not member.flag_bits & 1
                    and stat.S_IFMT(member.external_attr >> 16) in (0, stat.S_IFREG))
            body = archive.read(member)
            require(len(body) == member.file_size)
            records[name] = checked_body(name, body)
            bodies[name] = body
            require(sum(value["sizeBytes"] for value in records.values()) <= MAX_TOTAL)
    record_name = f"{DIST_INFO}/RECORD"
    require(all(f"{DIST_INFO}/{name}" in bodies for name in ("RECORD", "METADATA", "entry_points.txt")))
    metadata = BytesParser().parsebytes(bodies[f"{DIST_INFO}/METADATA"])
    require(metadata.get_all("Name") == ["problemtools"] and metadata.get_all("Version") == [VERSION])
    entry_points = configparser.ConfigParser(interpolation=None)
    entry_points.read_string(bodies[f"{DIST_INFO}/entry_points.txt"].decode("utf-8"))
    require(entry_points.sections() == ["console_scripts"] and dict(entry_points["console_scripts"]) == {
        "verifyproblem": "problemtools.verifyproblem:main", "problem2html": "problemtools.problem2html:main",
        "problem2pdf": "problemtools.problem2pdf:main"})
    rows = record_rows(bodies[record_name])
    require(set(rows) == set(records))
    for name, value in records.items():
        check_record_hash(value, rows[name], name == record_name)
    return records


def bind_installed(wheel: dict[str, dict], distribution: dict[str, dict], root: Path, wheel_sha: str) -> None:
    required = {f"{SITE.lstrip('/')}/{name}" for name in wheel}
    required.update(name.lstrip("/") for name in INSTALLED_PATHS[2:])
    required.add(f"{SITE.lstrip('/')}/{DIST_INFO}/INSTALLER")
    allowed = required | {f"{SITE.lstrip('/')}/{DIST_INFO}/{name}" for name in ("REQUESTED", "direct_url.json")}
    require(required <= set(distribution) <= allowed)
    require(regular(root / SITE.lstrip("/") / DIST_INFO / "INSTALLER") == b"pip\n")
    requested = root / SITE.lstrip("/") / DIST_INFO / "REQUESTED"
    require(not requested.exists() or regular(requested) == b"")
    direct_url = root / SITE.lstrip("/") / DIST_INFO / "direct_url.json"
    if direct_url.exists():
        value = json.loads(regular(direct_url))
        require(value.get("url") == f"file:///build/dist/problemtools-{VERSION}-py3-none-any.whl"
                and value.get("archive_info", {}).get("hashes") == {"sha256": wheel_sha}
                and value.get("archive_info", {}).get("hash", "sha256=" + wheel_sha) == "sha256=" + wheel_sha)
    for name, record in wheel.items():
        if name == f"{DIST_INFO}/RECORD":
            continue  # pip rewrites RECORD to include the generated scripts.
        target = f"{SITE.lstrip('/')}/{name}"
        require(target in distribution and all(distribution[target][key] == record[key] for key in ("sha256", "sizeBytes")))


def capture(wheel: Path, root: Path) -> dict:
    wheel_body = regular(wheel)
    wheel_members = wheel_records(wheel.name, wheel_body)
    distribution = installed(root)
    installed_record(root, distribution)
    bind_installed(wheel_members, distribution, root, sha(wheel_body))
    source = regular(root / "opt/startrack/provenance/problemtools-sources.json")
    require(json.loads(source).get("baseCommit") == REVISION)
    context = regular(root / "opt/startrack/provenance/context-inventory.json")
    with zipfile.ZipFile(io.BytesIO(wheel_body)) as archive:
        original_record = archive.read(f"{DIST_INFO}/RECORD")
        envelope = wheel_envelope(wheel_body, archive)
    return {"schemaVersion": 1, "scope": "CANONICAL_WHEEL_AND_INSTALLED_DISTRIBUTION",
            "problemtoolsVersion": VERSION, "problemtoolsRevision": REVISION, "sdistBuilt": False,
            "problemtoolsSourceProvenanceSHA256": sha(source), "contextInventorySHA256": sha(context),
            "wheelFileName": wheel.name, "wheelSHA256": sha(wheel_body),
            "wheelEnvelope": envelope,
            "wheelRecordBase64": base64.b64encode(original_record).decode(),
            "wheelMembers": sorted(wheel_members.values(), key=lambda item: item["path"]),
            "installedMembers": sorted(distribution.values(), key=lambda item: item["path"]),
            "layerExclusion": "REQUIRES_SEPARATE_DISTRIBUTED_LAYER_AUDIT"}


def declared_records(values: list[dict]) -> dict[str, dict]:
    require(isinstance(values, list) and bool(values) and len(values) <= 10000)
    result = {}
    for record in values:
        require(isinstance(record, dict) and set(record) == {"path", "sizeBytes", "sha256"})
        name = safe_name(record["path"])
        require(name not in result and type(record["sizeBytes"]) is int and 0 <= record["sizeBytes"] <= MAX_MEMBER
                and isinstance(record["sha256"], str) and SHA.fullmatch(record["sha256"]) is not None)
        require(record["sha256"] not in FORBIDDEN_HASHES and "viva" not in PurePosixPath(name.lower()).parts
                and PurePosixPath(name.lower()).name not in ("viva.sh", "viva user's guide.pdf")
                and PurePosixPath(name.lower()).suffix not in (".jar", ".class", ".zip", ".pyc", ".pyo"))
        result[name] = record
    require(sum(value["sizeBytes"] for value in result.values()) <= MAX_TOTAL)
    return result


def verify(receipt: dict, checksum: str, root: Path, source_sha: str, context_sha: str, wheel_body: bytes) -> None:
    require(receipt.get("schemaVersion") == 1 and receipt.get("scope") == "CANONICAL_WHEEL_AND_INSTALLED_DISTRIBUTION"
            and receipt.get("problemtoolsVersion") == VERSION and receipt.get("problemtoolsRevision") == REVISION
            and receipt.get("sdistBuilt") is False and receipt.get("problemtoolsSourceProvenanceSHA256") == source_sha
            and receipt.get("contextInventorySHA256") == context_sha
            and receipt.get("layerExclusion") == "REQUIRES_SEPARATE_DISTRIBUTED_LAYER_AUDIT")
    rows = checksum.splitlines()
    require(len(rows) == 1)
    digest, name = rows[0].split(maxsplit=1)
    require(SHA.fullmatch(digest) is not None and name == f"/build/dist/problemtools-{VERSION}-py3-none-any.whl"
            and receipt.get("wheelFileName") == PurePosixPath(name).name and receipt.get("wheelSHA256") == digest)
    require(isinstance(wheel_body, bytes) and sha(wheel_body) == digest)
    wheel = declared_records(receipt.get("wheelMembers"))
    require(wheel_records(WHEEL_NAME, wheel_body) == wheel)
    with zipfile.ZipFile(io.BytesIO(wheel_body)) as archive:
        require(receipt.get("wheelEnvelope") == wheel_envelope(wheel_body, archive))
    require(all(name.split("/")[0] in ("problemtools", DIST_INFO) for name in wheel)
            and f"{DIST_INFO}/RECORD" in wheel)
    encoded_record = receipt.get("wheelRecordBase64")
    require(isinstance(encoded_record, str) and len(encoded_record) <= MAX_MEMBER)
    record_body = base64.b64decode(encoded_record, validate=True)
    record_name = f"{DIST_INFO}/RECORD"
    require(checked_body(record_name, record_body) == wheel[record_name])
    original_rows = record_rows(record_body)
    require(set(original_rows) == set(wheel))
    for name, record in wheel.items():
        check_record_hash(record, original_rows[name], name == record_name)
    distribution = installed(root)
    require(distribution == declared_records(receipt.get("installedMembers")))
    installed_record(root, distribution)
    bind_installed(wheel, distribution, root, digest)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    require(not args.output.exists())
    args.output.write_text(json.dumps(capture(args.wheel, Path("/")), indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
