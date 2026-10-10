#!/usr/bin/env python3
"""Portable, offline checks for repository metadata; not a sandbox/security audit.

Uses Python's standard library and Git/Bash. CI separately parses YAML with
Ruby/Psych and Compose with Docker. Only Git-visible files are scanned, so an
ignored local .env or downloaded upstream tree is never read or printed.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
HISTORICAL_MISSING_REFERENCE = "V0.2-整体架构与联调说明.md"
# These byte-identical baseline documents already referenced an absent file.
# Never expand this exception to a directory or arbitrary missing links.
HISTORICAL_REFERENCE_SOURCES = {
    "判题题库api文档.md",
    "判题题库数据库文档.md",
    "docs/contracts/v0.2/api.md",
    "docs/contracts/v0.2/database.md",
}
REQUIRED_FILES = (
    "AGENTS.md", "README.md", "CONTRIBUTING.md", "SECURITY.md", "CHANGELOG.md",
    "NOTICE", "THIRD_PARTY_NOTICES.md", ".env.example", "Makefile", "compose.yaml",
    "upstream.lock.json", "docs/contracts/README.md", "docs/adr/README.md",
    "docs/releases/state.json", "migrations/README.md",
    ".github/workflows/foundation.yml",
)
MIGRATION_NAME = re.compile(r"([0-9]{6})_[a-z][a-z0-9_]*\.up\.sql\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
SECRET_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b"),
    re.compile(r"\bAKIA[A-Z0-9]{16}\b"),
    re.compile(r"\b(?:sk-proj|sk)-[A-Za-z0-9_-]{32,}\b"),
)


def within_root(root: Path, path: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git_files(root: Path) -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root, check=True, stdout=subprocess.PIPE,
    )
    return sorted({root / name.decode("utf-8") for name in result.stdout.split(b"\0") if name})


def markdown_prose(content: str, *, keep_inline_text: bool = False) -> str:
    """Remove fenced blocks and inline code before examining documentation links."""
    lines = []
    fence = None
    for line in content.splitlines():
        match = re.match(r"^\s{0,3}(`{3,}|~{3,})", line)
        if match:
            marker = match.group(1)
            if fence is None:
                fence = marker
            elif marker[0] == fence[0] and len(marker) >= len(fence):
                fence = None
            lines.append("")
        elif fence is None:
            lines.append(line)
        else:
            lines.append("")
    prose = "\n".join(lines)
    if keep_inline_text:
        return re.sub(r"(`+)(.*?)\1", r"\2", prose)
    return re.sub(r"(`+).*?\1", "", prose)


def markdown_targets(content: str) -> list[str]:
    prose = markdown_prose(content)
    inline = re.findall(r"!?\[[^\]\n]*\]\(\s*(<[^>\n]+>|[^\s)]+)(?:\s+[^)]*)?\)", prose)
    references = re.findall(r"^\s{0,3}\[[^\]\n]+\]:\s*(<[^>\n]+>|\S+)", prose, re.MULTILINE)
    return [target.strip("<>") for target in inline + references]


def markdown_anchors(content: str) -> set[str]:
    anchors = set()
    counts: dict[str, int] = {}
    for line in markdown_prose(content, keep_inline_text=True).splitlines():
        match = re.match(r"^\s{0,3}#{1,6}\s+(.+?)\s*#*\s*$", line)
        if match:
            heading = re.sub(r"\[([^]]+)\]\([^)]*\)", r"\1", match.group(1))
            heading = re.sub(r"<[^>]+>", "", heading)
            slug = re.sub(r"[^\w\- ]", "", heading.lower(), flags=re.UNICODE).replace(" ", "-")
            count = counts.get(slug, 0)
            counts[slug] = count + 1
            anchors.add(slug if count == 0 else f"{slug}-{count}")
    anchors.update(re.findall(r'<(?:a|[a-z][a-z0-9]*)\b[^>]*\bid=["\']([^"\']+)', content, re.IGNORECASE))
    return anchors


def check_links(root: Path, path: Path, content: str) -> tuple[list[str], int]:
    errors = []
    historical = 0
    relative = path.relative_to(root).as_posix()
    for target in markdown_targets(content):
        url = urlsplit(target)
        if url.scheme or url.netloc:
            continue
        decoded = unquote(url.path)
        if relative in HISTORICAL_REFERENCE_SOURCES and decoded == HISTORICAL_MISSING_REFERENCE:
            candidate = path.parent / decoded
            if not candidate.exists():
                historical += 1
                continue
        candidate = root / decoded.lstrip("/") if decoded.startswith("/") else path.parent / decoded
        if not decoded:
            candidate = path
        if not within_root(root, candidate):
            errors.append(f"{relative}: link leaves repository: {target}")
        elif not candidate.exists():
            errors.append(f"{relative}: missing relative link: {target}")
        elif url.fragment and candidate.is_file() and candidate.suffix.lower() == ".md":
            fragment = unquote(url.fragment)
            if fragment not in markdown_anchors(candidate.read_text(encoding="utf-8")):
                errors.append(f"{relative}: missing Markdown anchor: {target}")
    return errors, historical


def check_migrations(names: list[str]) -> list[str]:
    errors = []
    numbers = []
    for name in names:
        match = MIGRATION_NAME.fullmatch(name)
        if not match or int(match.group(1)) == 0:
            errors.append(f"migrations/{name}: expected NNNNNN_description.up.sql; forward-only")
        else:
            numbers.append(int(match.group(1)))
    if sorted(numbers) != list(range(1, len(numbers) + 1)):
        errors.append("migrations: identities must be unique, contiguous, and start at 000001")
    return errors


def check_hash(root: Path, record: dict, path_key: str, context: str) -> list[str]:
    local = record.get(path_key)
    expected = record.get("sha256")
    if not isinstance(local, str) or not isinstance(expected, str) or not SHA256.fullmatch(expected):
        return [f"{context}: expected local path and lowercase SHA-256"]
    path = root / local
    if not within_root(root, path) or not path.is_file():
        return [f"{context}: missing or out-of-repository evidence file: {local}"]
    if digest(path) != expected:
        return [f"{context}: checksum mismatch: {local}"]
    return []


def check_contracts(root: Path) -> tuple[list[str], str, dict, dict]:
    errors = []
    active_text = []
    active_manifest = {}
    state = {}
    try:
        state = json.loads((root / "docs/releases/state.json").read_text(encoding="utf-8"))
        current = root / state["contractPath"] / "manifest.json"
        if not within_root(root / "docs/contracts", current):
            errors.append("release state: active contract must be inside docs/contracts")
        manifests = sorted((root / "docs/contracts").glob("*/manifest.json"))
        if current not in manifests:
            errors.append("release state: active contract manifest is missing")
        versions = []
        for manifest_path in manifests:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            version = manifest.get("contractVersion")
            if not isinstance(version, str) or not manifest.get("apiGeneration"):
                errors.append(f"{manifest_path.relative_to(root)}: missing contract version/API generation")
            versions.append(version)
            records = manifest.get("files", [])
            if not records:
                errors.append(f"{manifest_path.relative_to(root)}: no contract files recorded")
            paths = [record.get("path") for record in records]
            if len(paths) != len(set(paths)):
                errors.append(f"{manifest_path.relative_to(root)}: duplicate contract file identities")
            for record in records:
                context = f"contract {record.get('path')}"
                errors.extend(check_hash(root, record, "path", context))
                if "source" in record:
                    errors.extend(check_hash(root, record, "source", context))
                path = root / record["path"]
                if not within_root(manifest_path.parent, path):
                    errors.append(f"{context}: snapshot path is outside its version directory")
                if manifest_path == current and path.is_file():
                    active_text.append(path.read_text(encoding="utf-8"))
            # Clarifications are additive publications, never edits to the frozen
            # baseline. Verify their own immutable evidence independently.
            amendment_paths = []
            for amendment in manifest.get("amendments", []):
                context = f"contract amendment {amendment.get('path')}"
                errors.extend(check_hash(root, amendment, "path", context))
                amendment_path = root / amendment["path"]
                if not within_root(manifest_path.parent, amendment_path):
                    errors.append(f"{context}: amendment is outside its version directory")
                amendment_paths.append(amendment["path"])
            if len(amendment_paths) != len(set(amendment_paths)):
                errors.append(f"{manifest_path.relative_to(root)}: duplicate amendment paths")
            for reference in manifest.get("supplementaryReferences", []):
                context = f"supplementary contract reference {reference.get('path')}"
                errors.extend(check_hash(root, reference, "path", context))
                if not within_root(manifest_path.parent, root / reference["path"]):
                    errors.append(f"{context}: reference is outside its version directory")
            if manifest_path == current:
                active_manifest = manifest
                for key in ("contractVersion", "apiGeneration"):
                    if state.get(key) != manifest.get(key):
                        errors.append(f"release state: active {key} differs from its manifest")
                components = manifest.get("upstreamComponents")
                if not isinstance(components, list) or not components or any(not isinstance(c, str) for c in components) or len(components) != len(set(components)):
                    errors.append("active contract manifest: upstreamComponents must declare unique component names")
        if len(versions) != len(set(versions)):
            errors.append("contract manifests: duplicate version identities")
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        errors.append(f"contract/release metadata: {exc}")
    return errors, "\n".join(active_text), active_manifest, state


def check_evidence(root: Path, component: dict, context: str) -> list[str]:
    errors = []
    repository = component.get("repository", "")
    commit = component.get("commit", "")
    if not isinstance(repository, str) or not re.fullmatch(r"https://github\.com/[\w.-]+/[\w.-]+(?:\.git)?", repository):
        errors.append(f"{context}: expected an HTTPS GitHub repository")
        return errors
    if not isinstance(commit, str) or not COMMIT.fullmatch(commit):
        errors.append(f"{context}: expected an immutable lowercase 40-hex commit")
        return errors
    prefix = repository.removesuffix(".git") + f"/blob/{commit}/"
    license_record = component.get("license", component)
    evidence = license_record.get("evidence", [])
    if not evidence:
        errors.append(f"{context}: no license evidence")
    for record in evidence:
        errors.extend(check_hash(root, record, "local_path", context))
        upstream_path = record.get("upstream_path")
        if not isinstance(upstream_path, str) or record.get("source_url") != prefix + upstream_path:
            errors.append(f"{context}: evidence URL must identify its exact commit and upstream path")
    for record in component.get("source_evidence", []):
        upstream_path = record.get("upstream_path")
        if not isinstance(upstream_path, str) or record.get("source_url") != prefix + upstream_path:
            errors.append(f"{context}: source evidence URL is not pinned to this component")
        if not isinstance(record.get("sha256"), str) or not SHA256.fullmatch(record["sha256"]):
            errors.append(f"{context}: source evidence lacks lowercase SHA-256")
    return errors


def check_upstream(root: Path, contract_text: str, active_manifest: dict) -> list[str]:
    errors = []
    try:
        lock = json.loads((root / "upstream.lock.json").read_text(encoding="utf-8"))
        if lock.get("schema_version") != 1 or lock.get("contract_version") != active_manifest.get("contractVersion"):
            errors.append("upstream.lock.json: unknown schema or incorrect contract version")
        components = lock.get("components", [])
        names = [c.get("name") for c in components]
        if set(names) != set(active_manifest.get("upstreamComponents", [])) or len(names) != len(set(names)):
            errors.append("upstream.lock.json: component identities differ from the active contract manifest")
        for component in components:
            context = f"upstream {component.get('name')}"
            errors.extend(check_evidence(root, component, context))
            repository = component.get("repository", "").removesuffix(".git")
            commit = component.get("commit", "")
            # Pins are authoritative contract data, rather than permanent code constants.
            row = next((line for line in contract_text.splitlines() if line.startswith("|") and repository in line and commit in line), "")
            if not row:
                errors.append(f"{context}: repository/commit not present together in the contract baseline")
            version = component.get("version")
            if version is not None and (not isinstance(version, str) or version not in row):
                errors.append(f"{context}: release version differs from the contract baseline")
            for key in ("role", "integration"):
                if not component.get(key):
                    errors.append(f"{context}: missing {key}")
            if not component.get("license", {}).get("spdx_expression") or not component.get("license", {}).get("scope"):
                errors.append(f"{context}: missing audited license expression/scope")
            if not isinstance(component.get("patches"), list):
                errors.append(f"{context}: missing explicit patch inventory")
            elif component["patches"]:
                series_path = root / "patches" / component["name"] / "series.json"
                if not series_path.is_file():
                    errors.append(f"{context}: missing patch-series provenance")
                else:
                    series = json.loads(series_path.read_text(encoding="utf-8"))
                    if series.get("baseCommit") != commit or series.get("repository") != component["repository"]:
                        errors.append(f"{context}: patch series does not match its locked origin/commit")
                    if series.get("patches") != component["patches"]:
                        errors.append(f"{context}: locked patch inventory differs from reviewed series")
                for patch in component["patches"]:
                    errors.extend(check_hash(root, patch, "path", context))
        for component in lock.get("supplemental_licenses", []):
            context = f"supplemental {component.get('name')}"
            errors.extend(check_evidence(root, component, context))
            patches = component.get("patches", [])
            if not isinstance(patches, list):
                errors.append(f"{context}: invalid patch inventory")
            elif patches:
                descriptor = f"patches/{component['name']}/series.json"
                if component.get("source_assembly") != {"policy": "verified-go-module-vendor", "descriptor": descriptor}:
                    errors.append(f"{context}: missing verified vendor assembly policy")
                series = json.loads((root / descriptor).read_text(encoding="utf-8"))
                if series.get("schemaVersion") != 1 or series.get("component") != component["name"] or series.get("baseCommit") != component["commit"] or series.get("baseVersion") != component.get("version") or series.get("repository") != component["repository"]:
                    errors.append(f"{context}: vendor series does not match locked source identity")
                if series.get("patches") != patches:
                    errors.append(f"{context}: locked patch inventory differs from reviewed vendor series")
                for patch in patches:
                    errors.extend(check_hash(root, patch, "path", context))
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        errors.append(f"upstream.lock.json: {exc}")
    return errors


def check_security_profile(root: Path) -> list[str]:
    """Bind the outer filter to reviewed upstream bytes and the sole delta.

    This validates source assembly, never Linux execution or qualification.
    """
    errors = []
    context = "outer seccomp profile"
    try:
        lock = json.loads((root / "docker/security-profile.lock.json").read_text())
        if lock.get("schemaVersion") != 1 or lock.get("module") != "github.com/moby/profiles/seccomp" or lock.get("repository") != "https://github.com/moby/profiles":
            errors.append(f"{context}: invalid source identity")
        commit, version = lock.get("commit", ""), lock.get("version", "")
        if not COMMIT.fullmatch(commit) or not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", version) or lock.get("tag") != "seccomp/" + version:
            errors.append(f"{context}: exact reviewed source revision/release required")
        prefix = "https://raw.githubusercontent.com/moby/profiles/" + commit
        if lock.get("sourcePath") != "seccomp/default.json" or lock.get("profileSourceURL") != prefix + "/seccomp/default.json" or lock.get("licenseSourceURL") != prefix + "/LICENSE":
            errors.append(f"{context}: source URLs must bind the exact revision")
        if not SHA256.fullmatch(lock.get("moduleArchiveSha256", "")) or any(not re.fullmatch(r"h1:[A-Za-z0-9+/]{43}=", lock.get(field, "")) for field in ("moduleSum", "goModSum")):
            errors.append(f"{context}: missing exact module archive provenance")
        for relative, field in (("docker/seccomp-source.json", "upstreamProfileSha256"),
                                ("docker/startrack-v02.seccomp.json", "profileSha256"),
                                ("docs/licenses/moby-seccomp/LICENSE", "licenseSha256")):
            path = root / relative
            if path.is_symlink() or not path.is_file():
                errors.append(f"{context}: regular retained evidence required: {relative}")
            else:
                errors.extend(check_hash(root, {"local_path": relative, "sha256": lock.get(field)}, "local_path", context))
        delta = {"addedSyscalls": ["pivot_root"], "action": "SCMP_ACT_ALLOW", "requiresOuterCapability": "CAP_SYS_ADMIN"}
        if lock.get("delta") != delta:
            errors.append(f"{context}: only the reviewed capability-conditioned pivot_root delta is allowed")
        original = json.loads((root / "docker/seccomp-source.json").read_text())
        candidate = json.loads((root / "docker/startrack-v02.seccomp.json").read_text())
        expected = json.loads(json.dumps(original))
        expected["syscalls"].append({"names": ["pivot_root"], "action": "SCMP_ACT_ALLOW", "includes": {"caps": ["CAP_SYS_ADMIN"]}})
        if candidate != expected:
            errors.append(f"{context}: profile differs from the reviewed upstream plus sole delta")
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        errors.append(f"{context}: invalid retained source/lock ({type(exc).__name__})")
    return errors


def check_workload_profile(root: Path) -> list[str]:
    """Check the fixed stacked workload guard's source identity, not execution."""
    try:
        spec = importlib.util.spec_from_file_location("startrack_workload_seccomp", ROOT / "scripts/workload-seccomp.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.verify(root)
    except (OSError, ValueError, TypeError, KeyError, StopIteration, AttributeError) as exc:
        return [f"workload seccomp profile: invalid retained source/lock ({type(exc).__name__})"]
    return []


def check_workflow(content: str, relative: str) -> list[str]:
    errors = []
    for action in re.findall(r"^\s*-?\s*uses:\s*([^\s#]+)", content, flags=re.MULTILINE):
        if action.startswith("./"):
            continue
        if "@" not in action or not COMMIT.fullmatch(action.rsplit("@", 1)[1]):
            errors.append(f"{relative}: action must use an immutable commit: {action}")
    if relative == ".github/workflows/foundation.yml":
        if "secrets." in content or re.search(r"\b(?:write-all|contents:\s*write|pull_request_target)\b", content):
            errors.append(f"{relative}: portable foundation must not access secrets, write permissions, or privileged PR triggers")
    return errors


def check_secrets(content: str, relative: str) -> list[str]:
    # Output only the location, never a detected value.
    detected = any(pattern.search(content) for pattern in SECRET_PATTERNS)
    config_like = Path(relative).suffix in {".md", ".yml", ".yaml", ".env", ".example", ".ini", ".toml", ".conf"}
    assignments = re.findall(
        r"^\s*(?:[A-Z_]*(?:PASSWORD|TOKEN|SECRET|PRIVATE_KEY)[A-Z_]*|password|token|secret)\s*[:=]\s*([^\n#]+)",
        content, flags=re.MULTILINE,
    ) if config_like else []
    for assignment in assignments:
        value = assignment.strip().strip("\"'")
        placeholder = (
            not value or value.startswith(("$", "<"))
            or value.upper().startswith(("GENERATED_", "REPLACE_", "EXAMPLE_", "PLACEHOLDER"))
            or value in {"null", "None"}
        )
        detected = detected or not placeholder
    return [f"{relative}: possible credential/private key; remove and investigate"] if detected else []


def check_python(content: str, relative: str) -> list[str]:
    """Parse source without importing it; inspect explicit credential literals."""
    try:
        tree = ast.parse(content, filename=relative)
    except SyntaxError as exc:
        return [f"{relative}:{exc.lineno}: invalid Python syntax"]
    errors = []

    def inspect_literal(name: object, value: ast.AST, line: int) -> None:
        if not isinstance(name, str) or not re.fullmatch(r"(?:[A-Z_]*(?:PASSWORD|TOKEN|SECRET|PRIVATE_KEY)|password|token|secret|private_key)", name):
            return
        if isinstance(value, ast.Constant) and isinstance(value.value, str) and value.value:
            if not value.value.startswith(("$", "<", "GENERATED_", "REPLACE_", "EXAMPLE_", "PLACEHOLDER")):
                errors.append(f"{relative}:{line}: possible literal credential; remove and investigate")

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                name = target.id if isinstance(target, ast.Name) else None
                if isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Constant):
                    name = target.slice.value
                inspect_literal(name, node.value, node.lineno)
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if isinstance(key, ast.Constant):
                    inspect_literal(key.value, value, key.lineno)
    return errors


def validate(root: Path) -> tuple[list[str], list[str]]:
    errors = []
    notes = []
    for required in REQUIRED_FILES:
        if not (root / required).is_file():
            errors.append(f"missing required foundation file: {required}")
    files = git_files(root)
    historical = 0
    prose = []
    for path in files:
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            if not path.exists() or not within_root(root, path):
                errors.append(f"{relative}: dangling or out-of-repository symlink")
            continue
        if not path.is_file():
            errors.append(f"{relative}: tracked file is missing")
            continue
        if path.name == ".env" or path.suffix in {".pem", ".key", ".p12", ".pfx"}:
            errors.append(f"{relative}: local credentials/key material must not be tracked")
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        errors.extend(check_secrets(content, relative))
        if path.suffix == ".py":
            errors.extend(check_python(content, relative))
        if path.suffix.lower() == ".md":
            link_errors, count = check_links(root, path, content)
            errors.extend(link_errors)
            historical += count
            prose.append(content)
        if path.suffix == ".json":
            try:
                json.loads(content)
            except ValueError as exc:
                errors.append(f"{relative}: invalid JSON: {exc}")
        if path.suffix == ".sh":
            result = subprocess.run(["bash", "-n", str(path)], capture_output=True, text=True)
            if result.returncode:
                errors.append(f"{relative}: shell syntax invalid: {result.stderr.strip()}")
        if relative.startswith(".github/workflows/") and path.suffix in {".yml", ".yaml"}:
            errors.extend(check_workflow(content, relative))
    if historical:
        notes.append(f"{historical} bounded historical links still reference the absent {HISTORICAL_MISSING_REFERENCE}; see docs/contracts/open-questions.md")
    migration_files = [path.name for path in files if path.parent == root / "migrations" and path.suffix == ".sql"]
    errors.extend(check_migrations(migration_files))
    contract_errors, contract_text, active_manifest, state = check_contracts(root)
    errors.extend(contract_errors)
    errors.extend(check_upstream(root, contract_text, active_manifest))
    errors.extend(check_security_profile(root))
    errors.extend(check_workload_profile(root))
    level = state.get("repositoryMigrationLevel")
    if not isinstance(level, int) or isinstance(level, bool) or level < 0 or level != len(migration_files):
        errors.append("release state: repositoryMigrationLevel must match the numbered repository migration files")
    example = root / ".env.example"
    if example.is_file():
        documentation = "\n".join(prose)
        for key in re.findall(r"^([A-Z][A-Z0-9_]*)=", example.read_text(encoding="utf-8"), flags=re.MULTILINE):
            if not re.search(r"\b" + re.escape(key) + r"\b", documentation):
                errors.append(f".env.example: {key} is not documented in Markdown")
    notes.append(f"checked {len(files)} Git-visible files; no judge execution, external URLs, transitive license audit, or production sandbox validation performed")
    return errors, notes


class ValidatorTests(unittest.TestCase):
    def test_outer_seccomp_source_and_sole_delta_are_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = ("docker/security-profile.lock.json", "docker/seccomp-source.json",
                     "docker/startrack-v02.seccomp.json", "docs/licenses/moby-seccomp/LICENSE")
            for relative in paths:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((ROOT / relative).read_bytes())
            self.assertEqual(check_security_profile(root), [])
            profile = root / "docker/startrack-v02.seccomp.json"
            baseline = profile.read_bytes()
            candidate = json.loads(baseline)
            candidate["syscalls"][-1].pop("includes")
            profile.write_text(json.dumps(candidate))
            lock_path = root / "docker/security-profile.lock.json"
            lock = json.loads(lock_path.read_text())
            lock["profileSha256"] = digest(profile)
            lock_path.write_text(json.dumps(lock))
            self.assertTrue(any("sole delta" in error for error in check_security_profile(root)))
            profile.write_bytes(baseline)
            lock["profileSha256"] = digest(profile)
            lock["profileSourceURL"] = "https://raw.githubusercontent.com/moby/profiles/main/seccomp/default.json"
            lock_path.write_text(json.dumps(lock))
            self.assertTrue(any("exact revision" in error for error in check_security_profile(root)))
            license_path = root / "docs/licenses/moby-seccomp/LICENSE"
            license_path.write_text("modified retained license")
            self.assertTrue(any("checksum mismatch" in error for error in check_security_profile(root)))

    def test_links_and_fences(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "README.md"
            target = root / "another file.md"
            target.write_text("# Known heading\n# Known heading\n# `Command` reference\n", encoding="utf-8")
            content = '[OK](another%20file.md#known-heading-1) [remote](https://example.org/missing)\n```md\n[fake](missing.md)\n```\n`[code](missing.md)`'
            self.assertEqual(check_links(root, path, content), ([], 0))
            self.assertTrue(check_links(root, path, "[bad](another%20file.md#absent)")[0])
            self.assertTrue(check_links(root, path, "[reference]: missing.md")[0])
            self.assertTrue(check_links(root, path, "[escape](../outside.md)")[0])
            self.assertEqual(check_links(root, path, "[inline heading](another%20file.md#command-reference)"), ([], 0))

    def test_historical_exception_is_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            content = f"[historical]({HISTORICAL_MISSING_REFERENCE})"
            self.assertEqual(check_links(root, root / "判题题库api文档.md", content), ([], 1))
            self.assertTrue(check_links(root, root / "README.md", content)[0])
            self.assertTrue(check_links(root, root / "判题题库api文档.md", "[other](missing.md)")[0])

    def test_migration_names(self):
        self.assertEqual(check_migrations([]), [])
        self.assertEqual(check_migrations(["000001_initial.up.sql", "000002_outbox.up.sql"]), [])
        for names in (["000001_initial.down.sql"], ["000002_initial.up.sql"], ["000001_a.up.sql", "000001_b.up.sql"]):
            self.assertTrue(check_migrations(names))

    def test_checksum_and_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "LICENSE"
            evidence.write_text("license evidence", encoding="utf-8")
            component = {"repository": "https://github.com/example/project.git", "commit": "a" * 40, "evidence": [{"local_path": "LICENSE", "sha256": digest(evidence), "upstream_path": "LICENSE", "source_url": "https://github.com/example/project/blob/" + "a" * 40 + "/LICENSE"}]}
            self.assertEqual(check_evidence(root, component, "test"), [])
            component["evidence"][0]["source_url"] = "https://github.com/example/project/blob/main/LICENSE"
            self.assertTrue(check_evidence(root, component, "test"))
            component["evidence"][0]["sha256"] = "0" * 64
            self.assertTrue(check_evidence(root, component, "test"))

    def test_contract_evolution_preserves_old_snapshots(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "docs/releases").mkdir(parents=True)
            state = {"contractPath": "docs/contracts/v0.3", "contractVersion": "0.3.0", "apiGeneration": "/internal/v3", "repositoryMigrationLevel": 0}
            (root / "docs/releases/state.json").write_text(json.dumps(state), encoding="utf-8")
            for version in ("0.2", "0.3"):
                folder = root / f"docs/contracts/v{version}"
                folder.mkdir(parents=True)
                path = folder / "api.md"
                path.write_text(f"contract {version}", encoding="utf-8")
                manifest = {"contractVersion": f"{version}.0", "apiGeneration": f"/internal/v{version[-1]}", "upstreamComponents": ["new-tool"], "files": [{"path": path.relative_to(root).as_posix(), "sha256": digest(path)}]}
                (folder / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            errors, text, manifest, _ = check_contracts(root)
            self.assertEqual(errors, [])
            self.assertEqual(text, "contract 0.3")
            self.assertEqual(manifest["upstreamComponents"], ["new-tool"])
            (root / "docs/contracts/v0.2/api.md").write_text("rewritten old contract", encoding="utf-8")
            self.assertTrue(any("checksum mismatch" in error for error in check_contracts(root)[0]))

    def test_supplemental_patch_lock_rejects_identity_inventory_and_byte_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            folder = root / "patches/sandbox"
            folder.mkdir(parents=True)
            evidence = root / "LICENSE"
            evidence.write_text("retained license", encoding="utf-8")
            patch_file = folder / "0001-reviewed.patch"
            patch_file.write_text("reviewed patch bytes", encoding="utf-8")
            component = {
                "name": "sandbox", "repository": "https://github.com/example/sandbox.git",
                "commit": "a" * 40, "version": "v1.0.0",
                "evidence": [{"local_path": "LICENSE", "sha256": digest(evidence),
                              "upstream_path": "LICENSE", "source_url": "https://github.com/example/sandbox/blob/" + "a" * 40 + "/LICENSE"}],
                "patches": [{"path": "patches/sandbox/0001-reviewed.patch", "sha256": digest(patch_file)}],
                "source_assembly": {"policy": "verified-go-module-vendor", "descriptor": "patches/sandbox/series.json"},
            }
            lock = {"schema_version": 1, "contract_version": "0.2.0", "components": [], "supplemental_licenses": [component]}
            series = {"schemaVersion": 1, "component": "sandbox", "repository": component["repository"],
                      "baseCommit": component["commit"], "baseVersion": component["version"], "patches": component["patches"]}
            (root / "upstream.lock.json").write_text(json.dumps(lock), encoding="utf-8")
            descriptor = folder / "series.json"
            descriptor.write_text(json.dumps(series), encoding="utf-8")
            manifest = {"contractVersion": "0.2.0", "upstreamComponents": []}
            self.assertEqual(check_upstream(root, "", manifest), [])
            for field, changed in (("baseCommit", "b" * 40), ("baseVersion", "v2.0.0"), ("patches", [])):
                with self.subTest(field=field):
                    descriptor.write_text(json.dumps(dict(series, **{field: changed})), encoding="utf-8")
                    self.assertTrue(check_upstream(root, "", manifest))
            descriptor.write_text(json.dumps(series), encoding="utf-8")
            patch_file.write_text("unreviewed patch bytes", encoding="utf-8")
            self.assertTrue(any("checksum mismatch" in error for error in check_upstream(root, "", manifest)))
            patch_file.write_text("reviewed patch bytes", encoding="utf-8")
            component["source_assembly"]["policy"] = "unverified-vendor"
            (root / "upstream.lock.json").write_text(json.dumps(lock), encoding="utf-8")
            self.assertTrue(check_upstream(root, "", manifest))

    def test_python_credential_literals_and_syntax(self):
        self.assertEqual(check_python('password = values["POSTGRES_PASSWORD"]\nconfig = {"POSTGRES_PASSWORD": ""}\n', "test.py"), [])
        self.assertTrue(check_python('config = {"POSTGRES_PASSWORD": "' + 'literal-value"}', "test.py"))
        self.assertTrue(check_python('token = "' + 'literal-value"', "test.py"))
        self.assertTrue(check_python("def broken(:", "test.py"))

    def test_actions_and_secret_detection(self):
        self.assertTrue(check_workflow("- uses: actions/checkout@v4", "workflow.yml"))
        self.assertEqual(check_workflow("- uses: actions/checkout@" + "a" * 40, "workflow.yml"), [])
        self.assertTrue(check_workflow("on: pull_request_target", ".github/workflows/foundation.yml"))
        credential = "gh" + "p_" + "a" * 36
        self.assertTrue(check_secrets(credential, "test"))
        self.assertNotIn(credential, check_secrets(credential, "test")[0])
        self.assertEqual(check_secrets("BACKEND_JUDGE_TOKEN=<generated-local-token>", "test"), [])
        self.assertEqual(check_secrets("POSTGRES_PASSWORD=GENERATED_BY_MAKE_BOOTSTRAP_ONLY", "test"), [])
        self.assertEqual(check_secrets("POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?required}", "test"), [])
        self.assertTrue(check_secrets("POSTGRES_PASSWORD=" + "accidentally-committed", "test.env"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="test failure detection with isolated fixtures")
    args = parser.parse_args()
    if args.self_test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(ValidatorTests)
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
    try:
        errors, notes = validate(ROOT)
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"Foundation validation could not run: {exc}", file=sys.stderr)
        return 1
    for note in notes:
        print(f"NOTE: {note}")
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        print(f"Foundation validation failed: {len(errors)} finding(s)", file=sys.stderr)
        return 1
    print("Foundation validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
