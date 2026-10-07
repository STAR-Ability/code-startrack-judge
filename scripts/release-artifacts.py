#!/usr/bin/env python3
"""Audit and record official immutable image artifacts; never deploy or tag Git."""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "STAR-Ability/code-startrack-judge"
IMAGE = "ghcr.io/star-ability/code-startrack-judge"
SOURCES = "ghcr.io/star-ability/code-startrack-judge-sources"
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
PROVENANCE = (
    "binaries.sha256", "os-packages.tsv", "python-packages.json", "problemtools-wheel.sha256",
    "context-inventory.json", "generated-dependencies.json",
    "go-judge-sources.json", "problemtools-sources.json",
    "go-sandbox-vendor-patches.json", "upstream.lock.json",
    "toolchain.lock.json", "validation-tools.lock.json", "validation-sources.lock.json", "validation-tools-installed.json",
    "go-judge-runtime-dependencies.json",
)
BINARIES = ("judge-service", "startrack-judger", "supervisor", "runtime-init",
            "judge-migrate", "judge-admin", "judge-outbox", "startrack-runtime-matrix", "startrack-import-capacity", "go-judge",
            "default_validator", "startrack-checker-launcher")
CONFIGS = ("image.lock.json", "mount.yaml", "startrack-v02.apparmor",
           "startrack-v02.seccomp.json", "security-profile.lock.json",
           "startrack-workload-seccomp.yaml", "workload-security-profile.lock.json")


class Failure(Exception):
    pass


def require(value: bool) -> None:
    if not value:
        raise Failure("release artifact verification failed")


def sha_file(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            value.update(chunk)
    return value.hexdigest()


def command(arguments: list[str], timeout: int = 180) -> str:
    result = subprocess.run(arguments, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
    require(result.returncode == 0)
    return result.stdout.strip()


def guard(environment: dict[str, str], head: str, dirty: str) -> str:
    commit = environment.get("RELEASE_SOURCE_COMMIT", "")
    require(environment.get("GITHUB_ACTIONS") == "true")
    require(environment.get("GITHUB_REPOSITORY") == REPOSITORY)
    require(environment.get("GITHUB_REF") == "refs/heads/main")
    require(environment.get("GITHUB_REF_PROTECTED") == "true")
    require(COMMIT.fullmatch(commit) is not None and commit == head and not dirty)
    return commit


def official_commit() -> str:
    commit = guard(dict(os.environ), command(["git", "rev-parse", "HEAD"]),
                   command(["git", "status", "--porcelain", "--untracked-files=all"]))
    command(["git", "merge-base", "--is-ancestor", commit, "origin/main"])
    return commit


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        raise Failure("registry redirect prohibited")


def registry_digest(commit: str, repository: str = IMAGE) -> str | None:
    require(repository in (IMAGE, SOURCES))
    actor, credential = os.environ.get("GITHUB_ACTOR", ""), os.environ.get("REGISTRY_TOKEN", "")
    require(bool(actor) and bool(credential) and COMMIT.fullmatch(commit) is not None)
    opener = urllib.request.build_opener(NoRedirect)
    authorization = base64.b64encode((actor + ":" + credential).encode()).decode()
    token_request = urllib.request.Request(
        "https://ghcr.io/token?service=ghcr.io&scope=repository:" + repository.removeprefix("ghcr.io/") + ":pull,push",
        headers={"Authorization": "Basic " + authorization})
    with opener.open(token_request, timeout=30) as response:
        body = response.read(65537)
        require(len(body) <= 65536)
    token = json.loads(body).get("token")
    require(isinstance(token, str) and bool(token))
    request = urllib.request.Request(
        "https://ghcr.io/v2/" + repository.removeprefix("ghcr.io/") + "/manifests/git-" + commit,
        headers={"Authorization": "Bearer " + token,
                 "Accept": "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"})
    try:
        with opener.open(request, timeout=30) as response:
            body = response.read((8 << 20) + 1)
            require(len(body) <= 8 << 20)
            digest = response.headers.get("Docker-Content-Digest", "")
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise Failure("registry unavailable") from None
    require(SHA256.fullmatch(digest) is not None)
    require(digest == "sha256:" + hashlib.sha256(body).hexdigest())
    return digest


def output_path(value: str, *, fresh: bool = False) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = ROOT / path
    require(not path.is_symlink())
    path = path.resolve()
    relative = path.relative_to(ROOT)
    require(relative.parts[0] in (".local", "artifacts") and len(relative.parts) > 1)
    if fresh:
        require(not path.exists())
        path.mkdir(parents=True, mode=0o700)
    else:
        require(path.is_dir())
    return path


def files(directory: Path) -> list[Path]:
    result = []
    for parent, directories, names in os.walk(directory, followlinks=False):
        for name in directories:
            require(not (Path(parent) / name).is_symlink())
        for name in names:
            path = Path(parent) / name
            require(path.is_file() and not path.is_symlink())
            result.append(path)
    return sorted(result)


def inspect_image(image: str, commit: str, repository: str = IMAGE) -> dict:
    require(repository in (IMAGE, SOURCES))
    require(image == repository + ":git-" + commit or
            image.startswith(repository + "@") and SHA256.fullmatch(image[len(repository) + 1:]) is not None)
    values = json.loads(command(["docker", "image", "inspect", image]))
    require(isinstance(values, list) and len(values) == 1)
    value = values[0]
    require(value.get("Os") == "linux" and value.get("Architecture") == "amd64")
    require(SHA256.fullmatch(value.get("Id", "")) is not None)
    labels = value.get("Config", {}).get("Labels", {})
    require(labels.get("org.opencontainers.image.revision") == commit)
    require(labels.get("org.opencontainers.image.source") == "https://github.com/" + REPOSITORY)
    require(labels.get("org.opencontainers.image.licenses") == "Apache-2.0")
    if repository == SOURCES:
        require(labels.get("io.startrack.artifact") == "corresponding-source")
    return value


def verify_extracted(directory: Path, commit: str) -> dict:
    inventory = files(directory)
    require(bool(inventory))
    for name in ("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md"):
        path = directory / "legal" / name
        require(path.is_file() and sha_file(path) == sha_file(ROOT / name))
    for name in PROVENANCE:
        path = directory / "provenance" / name
        require(path.is_file() and path.stat().st_size > 0)
    context = json.loads((directory / "provenance/context-inventory.json").read_bytes())
    require(isinstance(context, dict))
    context_records(context, commit)
    require(context.get("schemaVersion") == 1 and context.get("gitHead") == commit)
    require(context.get("sourceState") == "CLEAN" and context.get("workingTreeStatus") == "")
    require(context.get("releaseCommit") == commit and context.get("qualification") == "UNQUALIFIED")
    entries = context.get("inventory", [])
    require(isinstance(entries, list) and bool(entries))
    legal = {}
    for entry in entries:
        require(isinstance(entry, dict))
        name = entry.get("path", "")
        relative = PurePosixPath(name)
        require(bool(relative.parts) and name == relative.as_posix() and not relative.is_absolute() and ".." not in relative.parts)
        if relative.parts[0] != "legal":
            continue
        path = directory / name
        require(path.is_file() and not path.is_symlink())
        require(entry.get("sha256") == sha_file(path) and entry.get("sizeBytes") == path.stat().st_size)
        legal[name] = entry["sha256"]
    actual_legal = {path.relative_to(directory).as_posix(): sha_file(path) for path in files(directory / "legal")}
    require(legal == actual_legal)
    for name in ("upstream.lock.json", "toolchain.lock.json", "validation-tools.lock.json", "validation-sources.lock.json"):
        require(sha_file(directory / "provenance" / name) == sha_file(ROOT / name))
    for name in CONFIGS:
        path = directory / name
        require(path.is_file() and not path.is_symlink() and sha_file(path) == sha_file(ROOT / "docker" / name))
        matching = [entry for entry in entries if entry["path"] == "docker/" + name]
        require(len(matching) == 1 and matching[0]["sha256"] == sha_file(path) and matching[0]["sizeBytes"] == path.stat().st_size)
    migrations = sorted((ROOT / "migrations").glob("*.up.sql"))
    require(bool(migrations))
    for migration in migrations:
        require(sha_file(directory / "migrations" / migration.name) == sha_file(migration))
    require({path.name for path in files(directory / "migrations")} == {path.name for path in migrations})
    tools = json.loads((ROOT / "validation-tools.lock.json").read_bytes())
    expected_os = {entry["name"].removesuffix(":" + entry["architecture"]): (entry["version"], entry["architecture"])
                   for entry in tools["baselineAnchors"] + tools["debs"]}
    actual_os = {}
    for line in (directory / "provenance/os-packages.tsv").read_text().splitlines():
        name, version, architecture = line.split("\t")
        name = name.removesuffix(":" + architecture)
        require(name not in actual_os)
        actual_os[name] = (version, architecture)
    require(actual_os == expected_os)
    installed = json.loads((directory / "provenance/validation-tools-installed.json").read_bytes())
    require(installed.get("schemaVersion") == 1 and installed.get("lockSha256") == sha_file(ROOT / "validation-tools.lock.json"))
    require(installed.get("platform") == tools["platform"] and installed.get("pythonVersion") == tools["pythonVersion"])
    expected_installed_os = {entry["name"]: entry["version"] for entry in tools["baselineAnchors"] + tools["debs"]}
    installed_os = {entry["name"]: entry["version"] for entry in installed.get("debianPackages", [])}
    require(len(installed_os) == len(installed.get("debianPackages", [])) and installed_os == expected_installed_os)
    def normalized(name):
        return re.sub(r"[-_.]+", "-", name).lower()
    python = json.loads((directory / "provenance/python-packages.json").read_bytes())
    expected_python = {normalized(entry["name"]): entry["version"]
                       for entry in tools["wheels"] + tools["baselinePythonPackages"]}
    installed_python = {normalized(entry["name"]): entry["version"] for entry in installed.get("pythonPackages", [])}
    require(len(installed_python) == len(installed.get("pythonPackages", [])) and installed_python == expected_python)
    expected_python["problemtools"] = "1.20260907"
    actual_python = {normalized(entry["name"]): entry["version"] for entry in python}
    require(len(actual_python) == len(python) and actual_python == expected_python)
    json.loads((directory / "provenance/generated-dependencies.json").read_bytes())
    binaries = {}
    binary_paths = {"/usr/local/libexec/startrack/" + name: directory / "bin" / name
                    for name in BINARIES if name not in ("default_validator", "startrack-checker-launcher")}
    binary_paths.update({"/opt/startrack/libexec/" + name: directory / "helpers" / name
                         for name in ("default_validator", "default_grader", "problemtools-bridge.py")})
    binary_paths["/opt/startrack/bin/startrack-runtime-matrix"] = directory / "tools/startrack-runtime-matrix"
    binary_paths["/opt/startrack/bin/startrack-import-capacity"] = directory / "tools/startrack-import-capacity"
    binary_paths["/usr/local/bin/startrack-checker-launcher"] = directory / "bin/startrack-checker-launcher"
    for line in (directory / "provenance/binaries.sha256").read_text().splitlines():
        checksum, name = line.split(maxsplit=1)
        name = name.lstrip(" *")
        require(name not in binaries and re.fullmatch(r"[0-9a-f]{64}", checksum) is not None)
        binaries[name] = checksum
    require(set(binaries) == set(binary_paths))
    for name, path in binary_paths.items():
        require(path.is_file() and not path.is_symlink() and binaries[name] == sha_file(path))
    require(binaries["/usr/local/libexec/startrack/startrack-import-capacity"] ==
            binaries["/opt/startrack/bin/startrack-import-capacity"])
    state = json.loads((ROOT / "docs/releases/state.json").read_bytes())
    require(state["repositoryMigrationLevel"] == len(migrations))
    return {"contractVersion": state["contractVersion"], "apiGeneration": state["apiGeneration"],
            "contractManifestSHA256": sha_file(ROOT / state["contractPath"] / "manifest.json"),
            "migrationLevel": len(migrations),
            "migrationChecksums": {path.name: sha_file(path) for path in migrations},
            "securityConfigChecksums": {name: sha_file(directory / name) for name in CONFIGS}}


def write_record(directory: Path, record: dict) -> None:
    (directory / "release-artifacts.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    checksums = [sha_file(path) + "  " + path.relative_to(directory).as_posix()
                 for path in files(directory) if path.name != "SHA256SUMS"]
    (directory / "SHA256SUMS").write_text("\n".join(checksums) + "\n")


def sources_module():
    spec = importlib.util.spec_from_file_location("startrack_validation_sources", ROOT / "scripts/validation-sources.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def source_inputs() -> tuple[object, dict, str]:
    module = sources_module()
    lock, digest = module.read_lock(ROOT / "validation-sources.lock.json")
    module.check(lock, ROOT, ROOT / "validation-tools.lock.json", digest)
    # Required official publisher runs on Linux. Signature verification is a
    # distribution gate, independent of the portable foundation check.
    require(sys.platform == "linux")
    module.signatures(lock, ROOT)
    return module, lock, digest


def context_records(context: dict, commit: str) -> dict[str, dict]:
    require(context.get("schemaVersion") == 1 and context.get("gitHead") == commit)
    require(context.get("sourceState") == "CLEAN" and context.get("workingTreeStatus") == "")
    require(context.get("releaseCommit") == commit and context.get("qualification") == "UNQUALIFIED")
    entries = context.get("inventory", [])
    require(isinstance(entries, list) and bool(entries))
    result = {}
    for entry in entries:
        require(isinstance(entry, dict))
        name = entry.get("path", "")
        relative = PurePosixPath(name)
        require(bool(relative.parts) and name == relative.as_posix() and not relative.is_absolute() and ".." not in relative.parts)
        require(name not in result and re.fullmatch(r"[0-9a-f]{64}", entry.get("sha256", "")) is not None)
        require(type(entry.get("sizeBytes")) is int and entry["sizeBytes"] >= 0)
        require(re.fullmatch(r"0[0-7]{3}", entry.get("mode", "")) is not None)
        result[name] = entry
    return result


def prepare_sources(context_path: str, bundle_path: str, directory: Path, commit: str) -> None:
    context = output_path(context_path)
    module, lock, digest = source_inputs()
    bundle = Path(bundle_path).resolve()
    require(bundle == (ROOT / ".cache/validation-sources" / digest).resolve())
    module.verify(lock, bundle, digest, ROOT)
    context_inventory = json.loads((context / "provenance/context-inventory.json").read_bytes())
    expected = context_records(context_inventory, commit)
    actual = {path.relative_to(context).as_posix(): {"path": path.relative_to(context).as_posix(),
              "sha256": sha_file(path), "sizeBytes": path.stat().st_size,
              "mode": format(path.stat().st_mode & 0o777, "04o")}
              for path in files(context) if path.relative_to(context).as_posix() != "provenance/context-inventory.json"}
    require(actual == expected)
    distribution = directory / "distribution"
    for prefix, source in (("context", context), ("validation-sources", bundle)):
        for path in files(source):
            destination = distribution / prefix / path.relative_to(source)
            destination.parent.mkdir(parents=True, exist_ok=True)
            # Same-device hard links avoid another multi-GB copy. Docker is
            # given only these already-verified distribution inputs.
            os.link(path, destination)
    inventory = [{"path": path.relative_to(distribution).as_posix(), "sizeBytes": path.stat().st_size,
                  "sha256": sha_file(path), "mode": format(path.stat().st_mode & 0o777, "04o")}
                 for path in files(distribution)]
    (distribution / "source-inventory.json").write_text(json.dumps({"schemaVersion": 1, "sourceCommit": commit,
        "sourceManifestSHA256": digest, "inventory": inventory}, indent=2, sort_keys=True) + "\n")
    (directory / "Dockerfile").write_text("FROM scratch\nCOPY distribution/ /corresponding-source/\n")


def read_source_archive(container: str) -> tuple[dict[str, dict], dict[str, bytes]]:
    actual, retained = {}, {}
    process = subprocess.Popen(["docker", "cp", container + ":/corresponding-source/.", "-"],
                               cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        with tarfile.open(fileobj=process.stdout, mode="r|") as archive:
            for member in archive:
                relative = PurePosixPath(member.name)
                require(not relative.is_absolute() and ".." not in relative.parts)
                name = relative.as_posix()
                if member.isdir():
                    continue
                require(member.isfile() and name not in actual and not member.issym() and not member.islnk())
                require(member.mode & 0o7000 == 0)
                digest = hashlib.sha256()
                keep = name in ("source-inventory.json", "context/provenance/context-inventory.json") or name.startswith("validation-sources/indexes/")
                require(not keep or member.size <= 32 << 20)
                data = bytearray()
                size = 0
                with archive.extractfile(member) as stream:
                    for chunk in iter(lambda: stream.read(1 << 20), b""):
                        digest.update(chunk)
                        size += len(chunk)
                        if keep:
                            data.extend(chunk)
                require(size == member.size)
                actual[name] = {"path": name, "sizeBytes": size, "sha256": digest.hexdigest(), "mode": format(member.mode & 0o777, "04o")}
                if keep:
                    retained[name] = bytes(data)
        require(process.wait(timeout=60) == 0)
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdout.close()
    return actual, retained


def verify_source_archive(actual: dict, retained: dict, commit: str, module, lock: dict, digest: str) -> dict:
    inventory = json.loads(retained["source-inventory.json"])
    require(inventory.get("schemaVersion") == 1 and inventory.get("sourceCommit") == commit and inventory.get("sourceManifestSHA256") == digest)
    declared = inventory.get("inventory", [])
    require(isinstance(declared, list) and len(declared) == len(actual) - 1)
    expected = {entry["path"]: entry for entry in declared}
    require(len(expected) == len(declared) and expected == {name: entry for name, entry in actual.items() if name != "source-inventory.json"})
    context = json.loads(retained["context/provenance/context-inventory.json"])
    records = context_records(context, commit)
    expected_context = {"context/" + name: {**entry, "path": "context/" + name} for name, entry in records.items()}
    require(expected_context == {name: entry for name, entry in actual.items() if name.startswith("context/") and name != "context/provenance/context-inventory.json"})
    expected_bundle = {"validation-sources/" + directory + "/" + entry["filename"]: (entry["sha256"], entry["sizeBytes"])
                       for directory, entry in module.artifact_groups(lock)}
    require(expected_bundle == {name: (entry["sha256"], entry["sizeBytes"]) for name, entry in actual.items() if name.startswith("validation-sources/") and name != "validation-sources/inventory.json"})
    bundle_inventory = (json.dumps({"schemaVersion": 1, "lockSha256": digest, "platform": lock["platform"]}, indent=2) + "\n").encode()
    require(actual["validation-sources/inventory.json"]["sha256"] == hashlib.sha256(bundle_inventory).hexdigest())
    require(set(actual) == set(expected_context) | set(expected_bundle) | {"source-inventory.json", "context/provenance/context-inventory.json", "validation-sources/inventory.json"})
    for name in ("upstream.lock.json", "toolchain.lock.json", "validation-tools.lock.json", "validation-sources.lock.json"):
        require(actual["context/provenance/" + name]["sha256"] == sha_file(ROOT / name))
    for name in ("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md"):
        require(actual["context/legal/" + name]["sha256"] == sha_file(ROOT / name))
    import lzma
    for meta in lock["signedMetadata"]:
        full = {(item["Package"], item["Version"]): raw for item, raw in module.paragraphs(lzma.decompress(retained["validation-sources/indexes/" + meta["sourceIndex"]["filename"]]))}
        for section, raw in module.paragraphs(module.legal_file(meta["selectedParagraphs"], ROOT).read_bytes()):
            require(full.get((section["Package"], section["Version"])) == raw)
    return {"sourceManifestSHA256": digest,
            "sourceInputInventorySHA256": actual["source-inventory.json"]["sha256"],
            "contextInventorySHA256": actual["context/provenance/context-inventory.json"]["sha256"],
            "archiveCount": len(lock["sourceArchives"])}


def audit_sources(image: str, directory: Path, commit: str) -> None:
    module, lock, digest = source_inputs()
    image_data = inspect_image(image, commit, SOURCES)
    # The scratch source carrier contains data only and is never started.
    container = command(["docker", "create", "--network", "none", "--entrypoint", "/never-run", image])
    require(re.fullmatch(r"[0-9a-f]{64}", container) is not None)
    try:
        actual, retained = read_source_archive(container)
    finally:
        command(["docker", "rm", "--volumes", container])
    identities = verify_source_archive(actual, retained, commit, module, lock, digest)
    for name in ("source-inventory.json", "context/provenance/context-inventory.json"):
        (directory / PurePosixPath(name).name).write_bytes(retained[name])
    write_record(directory, {"schemaVersion": 1, "sourceRepository": REPOSITORY, "sourceCommit": commit,
                 "imageRepository": SOURCES, "imageConfigID": image_data["Id"],
                 "artifactType": "corresponding-source", "imageDigest": None, **identities})


def verified_source_record(path: str, commit: str, context_sha: str | None = None) -> dict:
    directory = output_path(path)
    record = json.loads((directory / "release-artifacts.json").read_bytes())
    require(record.get("sourceCommit") == commit and record.get("imageRepository") == SOURCES)
    require(record.get("artifactType") == "corresponding-source" and record.get("sourceManifestSHA256") == sha_file(ROOT / "validation-sources.lock.json"))
    require(SHA256.fullmatch(record.get("imageDigest", "")) is not None)
    require(record.get("immutableImage") == SOURCES + "@" + record["imageDigest"])
    require(sha_file(directory / "source-inventory.json") == record.get("sourceInputInventorySHA256"))
    require(sha_file(directory / "context-inventory.json") == record.get("contextInventorySHA256"))
    if context_sha is not None:
        require(record["contextInventorySHA256"] == context_sha)
    return record


def audit(image: str, directory: Path, commit: str, metadata: Path | None, sources: str) -> None:
    image_data = inspect_image(image, commit)
    container = command(["docker", "create", "--network", "none", image])
    require(re.fullmatch(r"[0-9a-f]{64}", container) is not None)
    try:
        for name in ("legal", "provenance", "migrations", *CONFIGS):
            command(["docker", "cp", container + ":/opt/startrack/" + name, str(directory / name)])
        command(["docker", "cp", container + ":/usr/local/libexec/startrack", str(directory / "bin")])
        command(["docker", "cp", container + ":/opt/startrack/libexec", str(directory / "helpers")])
        command(["docker", "cp", container + ":/opt/startrack/bin", str(directory / "tools")])
        command(["docker", "cp", container + ":/usr/local/bin/startrack-checker-launcher", str(directory / "bin/startrack-checker-launcher")])
    finally:
        command(["docker", "rm", "--volumes", container])
    identities = verify_extracted(directory, commit)
    source_record = verified_source_record(sources, commit, sha_file(directory / "provenance/context-inventory.json"))
    command([sys.executable, "scripts/check-go-judge-licenses.py", "verify", "--binary", str(directory / "bin/go-judge"),
             "--legal-root", str(directory / "legal"), "--inventory", str(directory / "provenance/go-judge-runtime-dependencies.json"),
             "--output", str(directory / "provenance"), "--go", str(ROOT / ".local/toolchains/go1.26.8/go/bin/go")])
    if metadata is not None:
        require(metadata.is_file() and not metadata.is_symlink())
        value = json.loads(metadata.read_bytes())
        (directory / "build-metadata.json").write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    record = {"schemaVersion": 1, "sourceRepository": REPOSITORY, "sourceCommit": commit,
              "imageRepository": IMAGE, "imageConfigID": image_data["Id"], "platform": "linux/amd64",
              "qualification": "UNQUALIFIED", "deployment": "NOT_DEPLOYED", **identities,
              "ciRun": "https://github.com/" + REPOSITORY + "/actions/runs/" + os.environ["GITHUB_RUN_ID"],
              "sourceValidationRun": os.environ.get("RELEASE_VALIDATION_RUN", ""),
              "workflowDefinitionCommit": os.environ.get("GITHUB_SHA", ""),
              "imageDigest": None, "correspondingSource": source_record,
              "builder": {"docker": command(["docker", "version", "--format", "{{json .}}"]),
                          "buildx": command(["docker", "buildx", "version"])}}
    shutil.copytree(output_path(sources), directory / "corresponding-source")
    write_record(directory, record)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("target", "audit", "push", "finalize", "sources-prepare", "sources-audit", "sources-push", "sources-finalize"))
    parser.add_argument("--kind", choices=("image", "sources"), default="image")
    parser.add_argument("--image")
    parser.add_argument("--output")
    parser.add_argument("--build-metadata", type=Path)
    parser.add_argument("--context")
    parser.add_argument("--bundle")
    parser.add_argument("--sources")
    args = parser.parse_args()
    commit = official_commit()
    repository = SOURCES if args.command.startswith("sources-") or args.command == "target" and args.kind == "sources" else IMAGE
    tag = repository + ":git-" + commit
    if args.command == "target":
        digest = registry_digest(commit, repository)
        require(bool(args.output))
        # Only validated constants/digests enter the Actions step-output file.
        with Path(args.output).open("a") as output:
            output.write("exists=" + ("true" if digest else "false") + "\n")
            output.write("image=" + (repository + "@" + digest if digest else tag) + "\n")
        return 0
    if args.command == "sources-prepare":
        require(bool(args.context) and bool(args.bundle) and bool(args.output))
        prepare_sources(args.context, args.bundle, output_path(args.output, fresh=True), commit)
        require(official_commit() == commit)
        return 0
    require(bool(args.image))
    if args.command in ("audit", "sources-audit"):
        require(bool(args.output))
        directory = output_path(args.output, fresh=True)
        if repository == SOURCES:
            audit_sources(args.image, directory, commit)
        else:
            require(bool(args.sources))
            audit(args.image, directory, commit, args.build_metadata, args.sources)
    elif args.command in ("push", "sources-push"):
        require(args.image == tag and registry_digest(commit, repository) is None)
        # Audit is a prerequisite; publishing cannot operate on an unverified image.
        require(bool(args.output))
        directory = output_path(args.output)
        record = json.loads((directory / "release-artifacts.json").read_bytes())
        require(record.get("sourceCommit") == commit and record.get("imageRepository") == repository)
        require(inspect_image(tag, commit, repository)["Id"] == record["imageConfigID"])
        if repository == SOURCES:
            source_inputs()
            require(sha_file(directory / "source-inventory.json") == record.get("sourceInputInventorySHA256"))
            require(sha_file(directory / "context-inventory.json") == record.get("contextInventorySHA256"))
            require(record.get("sourceManifestSHA256") == sha_file(ROOT / "validation-sources.lock.json"))
        else:
            verify_extracted(directory, commit)
            require(bool(args.sources))
            source_record = verified_source_record(args.sources, commit, sha_file(directory / "provenance/context-inventory.json"))
            require(record.get("correspondingSource") == source_record)
            require(registry_digest(commit, SOURCES) == source_record["imageDigest"])
            for name in ("go-judge.spdx.json", "go-judge.cdx.json", "go-judge-binary-dependencies.json"):
                require((directory / "provenance" / name).is_file())
        command(["docker", "push", tag], timeout=900)
    else:
        require(bool(args.output))
        directory = output_path(args.output)
        if repository == IMAGE:
            verify_extracted(directory, commit)
        digest = registry_digest(commit, repository)
        require(digest is not None)
        reference = repository + "@" + digest
        command(["docker", "pull", reference], timeout=900)
        record = json.loads((directory / "release-artifacts.json").read_bytes())
        require(record.get("sourceCommit") == commit and record.get("imageRepository") == repository)
        require(inspect_image(reference, commit, repository)["Id"] == record["imageConfigID"])
        if repository == IMAGE:
            require(bool(args.sources))
            require(record.get("correspondingSource") == verified_source_record(args.sources, commit, sha_file(directory / "provenance/context-inventory.json")))
        record["imageDigest"] = digest
        record["immutableImage"] = reference
        write_record(directory, record)
    print("release artifacts verified; no runtime qualification or deployment claimed")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (Failure, OSError, ValueError, KeyError, TypeError, AttributeError, IndexError, subprocess.SubprocessError, urllib.error.URLError):
        print("release-artifacts: operation failed; publication remains unqualified", file=sys.stderr)
        sys.exit(1)
