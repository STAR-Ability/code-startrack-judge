#!/usr/bin/env python3
"""Validate typed private contract schemas with meaningful negative fixtures.

Install the exact test-only engine with scripts/requirements-contract-tests.txt.
These fixtures are synthetic and prove shape/range rejection, not execution.
"""

from copy import deepcopy
from decimal import Decimal, InvalidOperation
import base64
import hashlib
import importlib.metadata
import io
import json
from pathlib import Path
import sys
import tarfile

try:
    from jsonschema import Draft202012Validator, FormatChecker
except ImportError:
    sys.exit("Install scripts/requirements-contract-tests.txt before schema tests")

ROOT = Path(__file__).resolve().parents[1]
CHECKER = FormatChecker()


@CHECKER.checks("unit-interval-decimal")
def unit_decimal(value):
    if not isinstance(value, str):
        return True
    try:
        parsed = Decimal(value)
    except InvalidOperation:
        return False
    return parsed.is_finite() and Decimal(0) <= parsed <= Decimal(1)


@CHECKER.checks("ustar-relative-path")
def ustar_path(value):
    if not isinstance(value, str):
        return True
    try:
        raw = value.encode("utf-8", errors="strict")
    except UnicodeError:
        return False
    if len(raw) <= 100:
        return True
    for split in range(len(raw) - 1, -1, -1):
        if raw[split : split + 1] == b"/":
            prefix, name = raw[:split], raw[split + 1 :]
            if 0 < len(name) <= 100 and 0 < len(prefix) <= 155:
                return True
    return False


def load(relative):
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


def validator(name):
    schema = load("docs/contracts/v0.2/" + name)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=CHECKER)


def rejected(engine, original, label, mutate):
    candidate = deepcopy(original)
    mutate(candidate)
    if engine.is_valid(candidate):
        raise AssertionError("schema accepted invalid fixture: " + label)


def verify_archive_vectors():
    vectors = load("testdata/archive-golden.json")
    if vectors["profile"] != "startrack-ustar-v1":
        raise AssertionError("wrong golden archive profile")
    for vector in vectors["vectors"]:
        raw = base64.b64decode(vector["archiveBytesBase64"], validate=True)
        if len(raw) != vector["archiveSizeBytes"] or hashlib.sha256(raw).hexdigest() != vector["sha256"]:
            raise AssertionError("archive fixture integrity")
        expected = {f["path"]: base64.b64decode(f["bytesBase64"], validate=True) for f in vector["inputFiles"]}
        names = sorted(expected, key=lambda name: name.encode("utf-8"))
        if names != vector["orderedPaths"] or not raw.endswith(bytes(1024)):
            raise AssertionError("archive ordering/footer")
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:", encoding="utf-8", errors="strict") as archive:
            members = archive.getmembers()
            if [member.name for member in members] != names:
                raise AssertionError("archive member order")
            for member in members:
                if not member.isfile() or member.mode != 0o644 or member.uid != 0 or member.gid != 0 or member.mtime != 0 or member.uname or member.gname:
                    raise AssertionError("archive metadata")
                if archive.extractfile(member).read() != expected[member.name]:
                    raise AssertionError("archive binary fidelity")
        if len(raw) != 1024 + sum(512 + ((len(body) + 511) // 512) * 512 for body in expected.values()):
            raise AssertionError("archive extra padding")
    return len(vectors["vectors"])


def main():
    if importlib.metadata.version("jsonschema") != "4.26.0":
        raise AssertionError("schema test engine must be exactly jsonschema 4.26.0")
    manifest = load("testdata/manifest-valid.json")
    results = load("testdata/validation-results-valid.json")
    m = validator("manifest-schema.json")
    r = validator("validation-results-schema.json")
    m.validate(manifest)
    r.validate(results)
    negative = [
        ("unknown manifest member", lambda x: x.update(command="arbitrary")),
        ("missing required checker", lambda x: x.pop("checker")),
        ("unsupported judge mode", lambda x: x.update(judgeMode="INTERACTIVE")),
        ("public Python capability", lambda x: x.update(languageIds=["python3"])),
        ("moving upstream branch", lambda x: x["source"].update(revision="main")),
        ("arbitrary fetch URL", lambda x: x["source"].update(repositoryUrl="https://example.invalid")),
        ("source path traversal", lambda x: x["source"].update(packagePath="problems/../escape")),
        ("negative resource", lambda x: x["limits"].update(timeLimitMs=-1)),
        ("CPU cap", lambda x: x["limits"].update(timeLimitMs=60001)),
        ("memory cap", lambda x: x["limits"].update(memoryLimitBytes=2147483649)),
        ("output cap", lambda x: x["limits"].update(outputLimitBytes=67108865)),
        ("controlled compiler profile", lambda x: x["executionProfiles"]["compile"].update(processLimit=129)),
        ("no input validator", lambda x: x.update(inputValidators=[])),
        ("no accepted reference", lambda x: x["referenceSolutions"][0].update(role="WRONG_ANSWER")),
        ("no secret case", lambda x: x["tests"][1].update(visibility="SAMPLE")),
        ("no sample case", lambda x: x["tests"][0].update(visibility="SECRET")),
        ("unknown checker flag", lambda x: x["checker"].update(argv=["shell"])),
        ("floating tolerance cap", lambda x: x["checker"].update(floatAbsoluteTolerance="2")),
        ("nonfinite tolerance", lambda x: x["checker"].update(floatRelativeTolerance="NaN")),
        ("negative tolerance", lambda x: x["checker"].update(floatRelativeTolerance="-0.1")),
        ("generated mapping fabricated source", lambda x: next(v for v in x["files"] if v["originalPath"] is None).update(sourceSha256="0" * 64)),
        ("file cap", lambda x: x["tests"][0]["input"].update(sizeBytes=67108865)),
    ]
    for path in ["/etc/passwd", "a/../b", "a/./b", "a//b", "a/", "a\\b", "a/%2e%2e/b", "a/\x00b", "a:b", "a" * 101, "汉" * 90, "startrack-manifest.json"]:
        negative.append(("unsafe or unrepresentable file path", lambda x, path=path: x["tests"][0]["input"].update(path=path)))
    for label, mutate in negative:
        rejected(m, manifest, label, mutate)
    zero = deepcopy(manifest)
    zero["checker"]["floatAbsoluteTolerance"] = "0"
    m.validate(zero)
    maximum = deepcopy(manifest)
    maximum["limits"].update(timeLimitMs=60000, wallLimitMs=120000, memoryLimitBytes=2147483648, outputLimitBytes=67108864)
    m.validate(maximum)
    split_fallback = deepcopy(manifest)
    split_fallback["tests"][0]["input"]["path"] = "a" * 150 + "/" + "b" * 10 + "/c"
    m.validate(split_fallback)
    results_negative = [
        ("missing checkpoint", lambda x: x.pop("validators")),
        ("unknown checkpoint", lambda x: x.update(validator=True)),
        ("truthy string pass", lambda x: x["structure"].update(passed="true")),
        ("status alias", lambda x: x["statement"].update(status="ok")),
        ("empty proof", lambda x: x["testData"].update(evidence=[])),
        ("unbounded evidence summary", lambda x: x["referenceSolutions"]["evidence"][0].update(summary="x" * 501)),
    ]
    for label, mutate in results_negative:
        rejected(r, results, label, mutate)
    failure = deepcopy(results)
    failure["validators"]["passed"] = False
    r.validate(failure)
    archives = verify_archive_vectors()
    print(f"Typed schema tests passed: 2 schemas, 6 positive states, {len(negative) + len(results_negative)} negative fixtures, {archives} archive golden vectors; no execution qualification")


if __name__ == "__main__":
    main()
