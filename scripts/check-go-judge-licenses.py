#!/usr/bin/env python3
"""Measure and verify the pinned go-judge binary and its exact legal evidence.

capture records reviewed source bytes; prepare requires that record to match.
verify audits an actual extracted binary without executing it and emits SPDX 2.3
and CycloneDX 1.6. LicenseRef terms are verbatim grants, never guessed SPDX IDs.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "docs/licenses/go-judge-runtime-dependencies.json"
LEGAL_PREFIX = "docs/licenses/go-judge-runtime"
ENTRYPOINT = "./cmd/go-judge"
LEGAL_NAME = re.compile(r"^(?:license|licence|copying|notice|patents|copyright)(?:[._-]|$)", re.I)
SOURCE_FIELDS = ("GoFiles", "SFiles", "CFiles", "CXXFiles", "HFiles", "SysoFiles", "EmbedFiles")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sha(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def read(path: Path) -> bytes:
    require(path.is_file() and not path.is_symlink(), "regular evidence file required")
    return path.read_bytes()


def objects(raw: str) -> list[dict]:
    decoder, offset, result = json.JSONDecoder(), 0, []
    while offset < len(raw):
        while offset < len(raw) and raw[offset].isspace():
            offset += 1
        if offset == len(raw):
            break
        item, offset = decoder.raw_decode(raw, offset)
        require(isinstance(item, dict), "invalid Go JSON object")
        result.append(item)
    return result


def go_command(go: Path, source: Path | None, *args: str) -> str:
    environment = dict(os.environ, GOTOOLCHAIN="local", GOOS="linux", GOARCH="amd64",
                       CGO_ENABLED="0", GOEXPERIMENT="", GOFLAGS="", GOWORK="off", GOAMD64="v1")
    result = subprocess.run([str(go), *args], cwd=source, env=environment,
                            capture_output=True, text=True, timeout=300)
    # Configured proxies can carry secrets; no raw subprocess diagnostics escape.
    require(result.returncode == 0, "Go dependency or binary inspection failed")
    return result.stdout


def key(module: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", module)


def header(body: bytes) -> bytes:
    lines = body.splitlines(keepends=True)
    result, in_block = [], False
    for line in lines:
        stripped = line.lstrip()
        if in_block:
            result.append(line)
            if b"*/" in stripped:
                in_block = False
        elif not stripped.strip() or stripped.startswith((b"//", b"#", b";")):
            result.append(line)
        elif stripped.startswith(b"/*"):
            result.append(line)
            in_block = b"*/" not in stripped
        else:
            break
    value = b"".join(result)
    return value if re.search(rb"copyright|licen[sc]e|permission|redistribution", value, re.I) else b""


def store_evidence(relative: str, body: bytes, capture: bool) -> dict:
    destination = ROOT / relative
    require(destination.resolve().is_relative_to(ROOT / "docs/licenses"), "invalid retained evidence path")
    if capture:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(body)
    else:
        require(read(destination) == body, "retained legal evidence differs from exact source")
    return {"localPath": relative, "sha256": sha(body), "sizeBytes": len(body)}


def collect(go: Path, source: Path, capture: bool = False) -> dict:
    require("go version go1.26.8 " in go_command(go, source, "version"), "locked Go 1.26.8 required")
    require(read(source / "LICENSE") == read(ROOT / "docs/licenses/go-judge-LICENSE"), "main upstream license differs from retained pin")
    packages = objects(go_command(go, source, "list", "-mod=vendor", "-deps", "-json", ENTRYPOINT))
    selected = {m["Path"]: m for m in objects(go_command(go, source, "list", "-mod=mod", "-m", "-json", "all")) if not m.get("Main")}
    vendor = source / "vendor"
    vendored = {}
    for line in read(vendor / "modules.txt").decode().splitlines():
        if line.startswith("# "):
            fields = line.split()
            require(len(fields) == 3 and fields[2].startswith("v"), "module replacements require separate legal review")
            vendored[fields[1]] = fields[2]
    downloaded = objects(go_command(go, source, "mod", "download", "-json",
                                   *[path + "@" + version for path, version in sorted(vendored.items())]))
    origins = {item["Path"]: item for item in downloaded}
    package_modules = {p["ImportPath"]: p.get("Module", {}).get("Path", "go-toolchain") for p in packages}
    main = "github.com/criyle/go-judge"
    linked = {m for m in package_modules.values() if m not in (main, "go-toolchain")}
    require(linked <= set(vendored), "linked module is absent from reviewed vendor input")
    records = []
    for module, version in sorted(vendored.items()):
        downloaded_module = origins[module]
        require(downloaded_module.get("Version") == version and not downloaded_module.get("Error"), "module archive missing")
        original = Path(downloaded_module["Dir"])
        source_legal = sorted(p for p in original.rglob("*") if p.is_file() and LEGAL_NAME.match(p.name))
        require(any(p.parent == original and LEGAL_NAME.match(p.name) for p in source_legal), "module root license evidence missing")
        legal = []
        for path in source_legal:
            relative = path.relative_to(original).as_posix()
            evidence = store_evidence(LEGAL_PREFIX + "/" + key(module) + "/" + relative, read(path), capture)
            evidence.update({"upstreamPath": relative, "kind": "verbatim-module-archive-legal-text"})
            legal.append(evidence)
        used_packages, compiled, header_blocks = [], [], []
        dependencies = set()
        for package in packages:
            if package.get("Module", {}).get("Path") != module:
                continue
            used_packages.append(package["ImportPath"])
            require(not package.get("CgoFiles"), "unreviewed CGO payload in locked CGO-disabled target")
            for imported in package.get("Imports", []):
                dep = package_modules.get(imported, "go-toolchain")
                if dep != module:
                    dependencies.add(dep)
            for name in sorted({n for field in SOURCE_FIELDS for n in package.get(field, [])}):
                path = Path(package["Dir"]) / name
                relative = path.relative_to(vendor / module).as_posix()
                body = read(path)
                compiled.append({"path": relative, "sha256": sha(body), "sizeBytes": len(body)})
                value = header(body)
                if value:
                    header_blocks.append((relative, sha(body), value))
        if header_blocks:
            blocks = b"".join(("===== " + path + " sha256:" + digest + " =====\n").encode() + body + b"\n" for path, digest, body in sorted(header_blocks))
            evidence = store_evidence(LEGAL_PREFIX + "/" + key(module) + "/COMPILED-SOURCE-HEADERS.txt", blocks, capture)
            evidence.update({"kind": "verbatim-compiled-source-header-bundle", "sourceFiles": [path for path, _, _ in sorted(header_blocks)]})
            legal.append(evidence)
        vendor_legal = []
        module_root = vendor / module
        for path in sorted(p for p in module_root.rglob("*") if p.is_file() and LEGAL_NAME.match(p.name)):
            # Nested Go submodules have their own separate rows.
            owning = max((m for m in vendored if path.is_relative_to(vendor / m)), key=len)
            if owning != module:
                continue
            relative = path.relative_to(module_root).as_posix()
            require(read(path) == read(original / relative), "vendored legal text differs from pinned module archive")
            vendor_legal.append({"path": "go-judge-vendor/" + module + "/" + relative,
                                 "sha256": sha(read(path)), "sizeBytes": path.stat().st_size})
        records.append({"modulePath": module, "version": version,
                        "linkScope": "BINARY_RUNTIME" if module in linked else "VENDORED_SOURCE_ONLY",
                        "moduleSum": downloaded_module["Sum"], "goModSum": downloaded_module["GoModSum"],
                        "source": {"kind": "checksum-verified-Go-module-archive",
                                   "downloadUrl": "https://proxy.golang.org/" + module_proxy_path(module) + "/@v/" + quote(version, safe="") + ".zip",
                                   "archiveSha256": sha(read(Path(downloaded_module["Zip"]))),
                                   "goModSha256": sha(read(Path(downloaded_module["GoMod"]))),
                                   "origin": downloaded_module.get("Origin")},
                        "licenseRef": "LicenseRef-" + key(module).replace("_", "-"), "licenseEvidence": legal,
                        "retainedVendorLegal": vendor_legal, "importedPackages": sorted(used_packages),
                        "compiledSourceFiles": sorted(compiled, key=lambda entry: entry["path"]),
                        "dependsOn": sorted(dependencies)})
    own_files, own_headers, own_imports = [], [], set()
    for package in packages:
        if not package.get("Module", {}).get("Main"):
            continue
        for imported in package.get("Imports", []):
            dep = package_modules.get(imported, "go-toolchain")
            if dep != main:
                own_imports.add(dep)
        for name in sorted({n for field in SOURCE_FIELDS for n in package.get(field, [])}):
            path = Path(package["Dir"]) / name
            relative, body = path.relative_to(source).as_posix(), read(path)
            own_files.append({"path": relative, "sha256": sha(body), "sizeBytes": len(body)})
            value = header(body)
            if value:
                own_headers.append((relative, sha(body), value))
    own_legal = []
    for local in ("docs/licenses/go-judge-LICENSE", "docs/licenses/moby-profiles-Apache-2.0-LICENSE",
                  "docs/licenses/go-judge-seccomp-NOTICE", "LICENSE", "NOTICE"):
        own_legal.append({"localPath": local, "sha256": sha(read(ROOT / local)), "sizeBytes": (ROOT / local).stat().st_size})
    blocks = b"".join(("===== " + path + " sha256:" + digest + " =====\n").encode() + body + b"\n" for path, digest, body in sorted(own_headers))
    own_legal.append(store_evidence(LEGAL_PREFIX + "/go-judge/COMPILED-SOURCE-HEADERS.txt", blocks, capture))
    toolchain = json.loads(read(ROOT / "docs/licenses/go-service-dependencies.json"))["goToolchain"]
    goroot = Path(go_command(go, source, "env", "GOROOT").strip())
    for evidence in toolchain["licenseEvidence"]:
        require(read(goroot / evidence["upstreamPath"]) == read(ROOT / evidence["localPath"]), "locked SDK legal evidence differs from source")
    return {"schemaVersion": 1, "inventoryDate": "2026-10-08", "scope": "PINNED_GO_JUDGE_LINUX_AMD64_BINARY_AND_VENDORED_SOURCE_LEGAL_EVIDENCE",
            "target": {"entrypoint": ENTRYPOINT, "goos": "linux", "goarch": "amd64", "goVersion": "go1.26.8", "cgoEnabled": False,
                       "goExperiment": "", "goamd64": "v1", "buildFlags": ["-mod=vendor", "-trimpath", "-buildvcs=false"]},
            "source": {"modulePath": main, "version": "v1.13.0", "baseCommit": "e9d70a0d9a3df0c62182a6e7090d7af650a1d5f8",
                       "goModSha256": sha(read(source / "go.mod")), "goSumSha256": sha(read(source / "go.sum")),
                       "upstreamBuildProvenanceSha256": sha(read(source / ".startrack-upstream-build.json")),
                       "vendorPatchProvenanceSha256": sha(read(source / ".startrack-vendor-patches.json")),
                       "compiledSourceFiles": sorted(own_files, key=lambda item: item["path"]),
                       "licenseRef": "LicenseRef-go-judge-and-reviewed-patches", "licenseEvidence": own_legal,
                       "dependsOn": sorted(own_imports)},
            "goToolchain": toolchain, "dependencyPackageCount": len(packages), "modules": records,
            "selectedButNotVendored": [{"modulePath": path, "version": module["Version"], "scope": "NOT_IN_DISTRIBUTED_VENDOR_OR_BINARY"}
                                      for path, module in sorted(selected.items()) if path not in vendored],
            "qualification": "LEGAL_AND_BUILD_CLOSURE_ONLY_NOT_LINUX_ISOLATION"}


def module_proxy_path(module: str) -> str:
    return "".join("!" + char.lower() if char.isupper() else char for char in module)


def legal_path(legal_root: Path, relative: str) -> Path:
    path = legal_root / relative
    require(path.resolve().is_relative_to(legal_root.resolve()), "legal evidence escapes retained root")
    return path


def legal_check(inventory: dict, legal_root: Path) -> None:
    for record in [inventory["source"], inventory["goToolchain"], *inventory["modules"]]:
        for item in record["licenseEvidence"]:
            body = read(legal_path(legal_root, item["localPath"]))
            require(sha(body) == item["sha256"], "retained license or copyright evidence checksum mismatch")
            if "sizeBytes" in item:
                require(len(body) == item["sizeBytes"], "retained legal evidence length mismatch")
        # Repository mode has no image-only vendor directory.
        if legal_root.resolve() != ROOT.resolve():
            for item in record.get("retainedVendorLegal", []):
                body = read(legal_path(legal_root, item["path"]))
                require(sha(body) == item["sha256"] and len(body) == item["sizeBytes"], "image vendor legal evidence changed")


def binary_info(go: Path, binary: Path, inventory: dict) -> dict:
    body = read(binary)
    require(body[:6] == b"\x7fELF\x02\x01" and int.from_bytes(body[18:20], "little") == 62, "Linux amd64 ELF binary required")
    lines = go_command(go, None, "version", "-m", str(binary)).splitlines()
    require(bool(lines) and lines[0].endswith(": go1.26.8"), "binary Go toolchain differs from lock")
    dependencies, settings, main, path = {}, {}, None, None
    for line in lines[1:]:
        parts = line.strip().split("\t")
        if parts[0] == "dep":
            require(len(parts) >= 3 and parts[1] not in dependencies, "invalid binary dependency metadata")
            dependencies[parts[1]] = parts[2]
        elif parts[0] == "build":
            setting, value = parts[1].split("=", 1)
            settings[setting] = value
        elif parts[0] == "mod":
            main = parts[1]
        elif parts[0] == "path":
            path = parts[1]
        elif parts[0] == "=>":
            raise ValueError("binary module replacement requires review")
    expected = {record["modulePath"]: record["version"] for record in inventory["modules"] if record["linkScope"] == "BINARY_RUNTIME"}
    require(dependencies == expected, "actual binary module closure differs from reviewed inventory")
    require(main == inventory["source"]["modulePath"] and path == main + "/cmd/go-judge", "unexpected binary entrypoint")
    for setting, expected_value in {"GOOS": "linux", "GOARCH": "amd64", "GOAMD64": "v1", "CGO_ENABLED": "0", "-trimpath": "true", "-compiler": "gc", "-buildmode": "exe"}.items():
        require(settings.get(setting) == expected_value, "binary build profile differs from reviewed target")
    require(settings.get("GOEXPERIMENT", "") == "" and not any(name.startswith("vcs") for name in settings), "unexpected experimental or VCS build inputs")
    return {"sha256": sha(body), "sizeBytes": len(body), "moduleVersions": dependencies, "buildSettings": settings}


def license_text(record: dict, legal_root: Path) -> str:
    return "\n\n".join("===== " + evidence["localPath"] + " =====\n" + read(legal_path(legal_root, evidence["localPath"])).decode("utf-8", errors="strict")
                        for evidence in record["licenseEvidence"] if "COMPILED-SOURCE-HEADERS" not in evidence["localPath"])


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def emit(inventory: dict, info: dict, legal_root: Path, output: Path) -> None:
    binary_id = "SPDXRef-go-judge-binary"
    binary_component = {"SPDXID": binary_id, "name": "go-judge", "versionInfo": "v1.13.0-with-reviewed-startrack-patches", "downloadLocation": "NONE", "filesAnalyzed": False,
                        "checksums": [{"algorithm": "SHA256", "checksumValue": info["sha256"]}], "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION", "copyrightText": "NOASSERTION"}
    packages, extracted, relationships = [binary_component], [], [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": binary_id}]
    components, dependencies = [], []
    records = [dict(inventory["source"], linkScope="BINARY_RUNTIME"), *inventory["modules"]]
    id_by_module = {record["modulePath"]: "SPDXRef-" + key(record["modulePath"]).replace("_", "-") for record in records}
    id_by_module["go-toolchain"] = "SPDXRef-go-toolchain"
    for record in records:
        module, version = record["modulePath"], record["version"]
        identifier, ref = id_by_module[module], record["licenseRef"]
        text = license_text(record, legal_root)
        extracted.append({"licenseId": ref, "name": "Exact retained terms for " + module + "@" + version, "extractedText": text})
        package = {"SPDXID": identifier, "name": module, "versionInfo": version, "downloadLocation": record.get("source", {}).get("downloadUrl", "NOASSERTION"), "filesAnalyzed": False,
                   "licenseConcluded": "NOASSERTION", "licenseDeclared": ref, "copyrightText": "NOASSERTION", "comment": "Link scope: " + record["linkScope"]}
        if "source" in record:
            package["checksums"] = [{"algorithm": "SHA256", "checksumValue": record["source"]["archiveSha256"]}]
        packages.append(package)
        relationships.append({"spdxElementId": binary_id if record["linkScope"] == "BINARY_RUNTIME" else "SPDXRef-DOCUMENT",
                              "relationshipType": "CONTAINS" if record["linkScope"] == "BINARY_RUNTIME" else "DESCRIBES", "relatedSpdxElement": identifier})
        if record["linkScope"] == "BINARY_RUNTIME":
            for dependency in record["dependsOn"]:
                relationships.append({"spdxElementId": identifier, "relationshipType": "DEPENDS_ON", "relatedSpdxElement": id_by_module[dependency]})
        component = {"type": "library", "bom-ref": identifier, "name": module, "version": version,
                     "purl": "pkg:golang/" + quote(module, safe="/") + "@" + quote(version, safe=""),
                     "licenses": [{"license": {"name": ref, "text": {"contentType": "text/plain", "content": text}}}],
                     "properties": [{"name": "startrack:linkScope", "value": record["linkScope"]}]}
        if "source" in record:
            component["hashes"] = [{"alg": "SHA-256", "content": record["source"]["archiveSha256"]}]
        components.append(component)
        dependencies.append({"ref": identifier, "dependsOn": [id_by_module[dep] for dep in record["dependsOn"]]})
    sdk = inventory["goToolchain"]
    packages.append({"SPDXID": "SPDXRef-go-toolchain", "name": "Go standard library and runtime", "versionInfo": sdk["version"], "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
                     "licenseConcluded": "NOASSERTION", "licenseDeclared": sdk["spdxExpression"], "copyrightText": "NOASSERTION"})
    relationships.append({"spdxElementId": binary_id, "relationshipType": "CONTAINS", "relatedSpdxElement": "SPDXRef-go-toolchain"})
    components.append({"type": "library", "bom-ref": "SPDXRef-go-toolchain", "name": "Go standard library and runtime", "version": sdk["version"], "licenses": [{"license": {"id": sdk["spdxExpression"]}}]})
    dependencies.append({"ref": "SPDXRef-go-toolchain", "dependsOn": []})
    dependencies.append({"ref": binary_id, "dependsOn": [id_by_module[record["modulePath"]] for record in records if record["linkScope"] == "BINARY_RUNTIME"] + ["SPDXRef-go-toolchain"]})
    spdx = {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT", "name": "Pinned go-judge actual Linux amd64 binary closure",
            "documentNamespace": "https://github.com/STAR-Ability/code-startrack-judge/sbom/go-judge/" + info["sha256"],
            "creationInfo": {"created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "creators": ["Tool: startrack-check-go-judge-licenses-1"]},
            "packages": packages, "relationships": relationships, "hasExtractedLicensingInfos": extracted}
    cdx = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
           "metadata": {"component": {"type": "application", "bom-ref": binary_id, "name": "go-judge", "version": "v1.13.0-with-reviewed-startrack-patches", "hashes": [{"alg": "SHA-256", "content": info["sha256"]}]}},
           "components": components, "dependencies": dependencies}
    write_json(output / "go-judge.spdx.json", spdx)
    write_json(output / "go-judge.cdx.json", cdx)
    write_json(output / "go-judge-binary-dependencies.json", {"schemaVersion": 1, "inventorySha256": sha(json.dumps(inventory, ensure_ascii=False, indent=2).encode() + b"\n"), "binary": info, "qualification": inventory["qualification"]})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("capture", "prepare", "verify", "legal"))
    parser.add_argument("--source", type=Path)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--inventory", type=Path, default=INVENTORY)
    parser.add_argument("--legal-root", type=Path, default=ROOT)
    parser.add_argument("--go", type=Path, default=ROOT / ".local/toolchains/go1.26.8/go/bin/go")
    args = parser.parse_args()
    try:
        if args.command in ("capture", "prepare"):
            require(args.source is not None, "prepared upstream source required")
            measured = collect(args.go.resolve(), args.source.resolve(), args.command == "capture")
            if args.command == "capture":
                write_json(args.inventory, measured)
            else:
                require(json.loads(read(args.inventory)) == measured, "go-judge source closure or legal provenance changed; independent review required")
                require(args.output is not None, "provenance output required")
                write_json(args.output / "go-judge-runtime-dependencies.json", measured)
            legal_check(measured, ROOT)
            runtime = sum(record["linkScope"] == "BINARY_RUNTIME" for record in measured["modules"])
            print(f"go-judge exact legal/source closure verified: {runtime} binary modules, {len(measured['modules']) - runtime} source-only vendor modules")
        else:
            inventory = json.loads(read(args.inventory))
            require(inventory.get("schemaVersion") == 1 and inventory.get("target", {}).get("goVersion") == "go1.26.8", "invalid reviewed go-judge inventory")
            require(inventory == json.loads(read(INVENTORY)), "embedded go-judge inventory differs from independently reviewed source record")
            legal_check(inventory, args.legal_root)
            if args.command == "verify":
                require(args.binary is not None and args.output is not None, "actual binary and provenance output required")
                info = binary_info(args.go.resolve(), args.binary.resolve(), inventory)
                emit(inventory, info, args.legal_root, args.output)
                print(f"Actual go-judge Linux amd64 binary verified: {len(info['moduleVersions'])} linked modules; SPDX/CycloneDX emitted")
            else:
                print("go-judge retained license, notice, patent and compiled-source copyright evidence verified")
        return 0
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        print("ERROR: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
