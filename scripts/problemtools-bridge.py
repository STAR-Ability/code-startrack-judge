#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Trusted orchestration hooks for pinned problemtools, never an execution engine.

This service-owned wrapper targets upstream commit
6010cbaa37a1612117f49566b2fff8646d53faa2. The Go parent owns qualification,
fencing, sandbox profiles, source bytes, and every executable/cache identifier.
Only the fixed statement modes run native tooling, inside its private sandbox.
"""

from __future__ import annotations

import base64
import contextlib
import dataclasses
import hashlib
from html.parser import HTMLParser
import importlib.metadata
import json
import logging
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile
import tempfile

MAX_FRAME = 192 * 1024 * 1024
MAX_INPUT = 64 * 1024 * 1024
MAX_OUTPUT = 64 * 1024 * 1024
MAX_DIAGNOSTICS = 2 * 1024 * 1024
MAX_STATEMENT_ARCHIVE = 768 * 1024 * 1024
MAX_STATEMENT_DATA = 512 * 1024 * 1024
MAX_STATEMENT_ARTIFACTS = 256 * 1024 * 1024
PARTS = ("STRUCTURE", "STATEMENT", "TEST_DATA", "VALIDATORS", "REFERENCES")
STEP_PARTS = {
    "config": "STRUCTURE", "attachments": "STATEMENT",
    "statement": "STATEMENT", "input_validator": "VALIDATORS",
    "output_validator": "VALIDATORS", "grader": "STRUCTURE",
    "data": "TEST_DATA", "includes": "STRUCTURE", "submission": "REFERENCES",
}
REQUIRED_STEPS = {
    "STRUCTURE": {"package", "config", "grader", "includes"},
    "STATEMENT": {"statement", "attachments"}, "TEST_DATA": {"data"},
    "VALIDATORS": {"input_validator", "output_validator"}, "REFERENCES": {"submission"},
}
TOOLS = {
    "default_validator": Path("/opt/startrack/libexec/default_validator"),
    "default_grader": Path("/opt/startrack/libexec/default_grader"),
}
PROBLEMTOOLS_RELEASE = "v1.20260907"
PROBLEMTOOLS_REVISION = "6010cbaa37a1612117f49566b2fff8646d53faa2"
HELPER_PROFILE = "ROLE_SEPARATED_PROBLEMTOOLS_V1"
LANGUAGES = {
    "cpp": {"name": "C++17", "priority": 10, "files": "*.cpp *.cc *.cxx *.c++",
            "run": "{binary}"},
    "python3": {"name": "Python 3", "priority": 20, "files": "*.py", "run": "{mainfile}"},
}


class BridgeAbort(BaseException):
    """An infrastructure/protocol failure must escape upstream error catchers."""


def pairs_unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise BridgeAbort("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def read_frame(stream):
    raw = stream.readline(MAX_FRAME + 1)
    if not raw or len(raw) > MAX_FRAME or not raw.endswith(b"\n"):
        raise BridgeAbort("FRAME_INVALID")
    try:
        value = json.loads(raw, object_pairs_hook=pairs_unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(BridgeAbort("JSON_CONSTANT")))
    except (ValueError, UnicodeError, RecursionError):
        raise BridgeAbort("JSON_INVALID") from None
    if not isinstance(value, dict):
        raise BridgeAbort("FRAME_INVALID")
    return value


def decoded(value, maximum=MAX_OUTPUT):
    if not isinstance(value, str) or len(value) > ((maximum + 2) // 3) * 4:
        raise BridgeAbort("RESPONSE_BYTES_INVALID")
    try:
        raw = base64.b64decode(value, validate=True)
    except ValueError:
        raise BridgeAbort("RESPONSE_BYTES_INVALID") from None
    if len(raw) > maximum:
        raise BridgeAbort("RESPONSE_BYTES_INVALID")
    return raw


def encoded(raw):
    return base64.b64encode(raw).decode("ascii")


def integer(value, maximum):
    if type(value) is not int or value < 0 or value > maximum:
        raise BridgeAbort("RESPONSE_COUNTER_INVALID")
    return value


class Channel:
    def __init__(self, input_stream, output_stream):
        self.input = input_stream
        self.output = output_stream

    def send(self, frame):
        raw = json.dumps(frame, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode() + b"\n"
        if len(raw) > MAX_FRAME:
            raise BridgeAbort("FRAME_TOO_LARGE")
        self.output.write(raw)
        self.output.flush()

    def call(self, operation, **fields):
        self.send({"operation": operation, **fields})
        response = read_frame(self.input)
        expected = {"ok", "code", "compiled", "waitStatus", "cpuNs", "stdoutBase64",
                    "stderrBase64", "feedbackBase64", "errors", "warnings"}
        if set(response) != expected or type(response["ok"]) is not bool or type(response["compiled"]) is not bool:
            raise BridgeAbort("RESPONSE_INVALID")
        if not isinstance(response["code"], str) or not re.fullmatch(r"[A-Z0-9_]{0,80}", response["code"]):
            raise BridgeAbort("RESPONSE_CODE_INVALID")
        integer(response["waitStatus"], 65535)
        integer(response["cpuNs"], 10**15)
        integer(response["errors"], 1000000)
        integer(response["warnings"], 1000000)
        for key in ("stdoutBase64", "stderrBase64", "feedbackBase64"):
            decoded(response[key])
        if not response["ok"]:
            raise BridgeAbort("SANDBOX_OPERATION_FAILED")
        return response


def relative_path(value):
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise BridgeAbort("PATH_INVALID")
    path = Path(value)
    if path.is_absolute() or any(p in ("", ".", "..") for p in value.split("/")):
        raise BridgeAbort("PATH_INVALID")
    return value


class Bridge:
    def __init__(self, control, channel):
        if set(control) != {"packageDir", "manifest", "identity", "fixedTimeLimitSeconds"}:
            raise BridgeAbort("CONTROL_INVALID")
        self.root = Path(control["packageDir"]).resolve(strict=True)
        self.manifest = control["manifest"]
        self.channel = channel
        if not self.root.is_dir() or not isinstance(self.manifest, dict) or not isinstance(control["identity"], dict):
            raise BridgeAbort("CONTROL_INVALID")
        self.seconds = control["fixedTimeLimitSeconds"]
        if not isinstance(self.seconds, str) or not re.fullmatch(r"[0-9]+(?:\.[0-9]{1,3})?", self.seconds):
            raise BridgeAbort("TIME_INVALID")
        milliseconds = self.manifest["limits"]["timeLimitMs"]
        whole, _, fraction = self.seconds.partition(".")
        if int(whole) * 1000 + int((fraction + "000")[:3]) != milliseconds or milliseconds <= 0:
            raise BridgeAbort("TIME_INVALID")
        self.files = {}
        for file in self.manifest["files"]:
            path = relative_path(file["normalizedPath"])
            if path in self.files:
                raise BridgeAbort("FILES_INVALID")
            self.files[path] = file
        self.programs = {}
        for role, programs in (("VALIDATOR", self.manifest["inputValidators"]),
                               ("REFERENCE", self.manifest["referenceSolutions"])):
            for program in programs:
                path = relative_path(program["file"]["path"])
                if path in self.programs or program["languageId"] not in ("cpp17", "python3"):
                    raise BridgeAbort("PROGRAM_INVALID")
                self.programs[path] = (role, program["file"])
        self.cases = {}
        for case in self.manifest["tests"]:
            infile = relative_path(case["input"]["path"])
            if infile in self.cases:
                raise BridgeAbort("CASE_INVALID")
            self.cases[infile] = case
        self.completed = set()
        self.counts = {part: [0, 0] for part in PARTS}
        self.diagnostic_bytes = 0
        self.diagnostic_truncated = False
        self.scratch = None
        self.verify_files()

    def verify_files(self):
        found = set()
        for parent, dirs, files in os.walk(self.root, followlinks=False):
            for name in dirs + files:
                path = Path(parent) / name
                if path.is_symlink():
                    raise BridgeAbort("PACKAGE_LINK")
            for name in files:
                path = Path(parent) / name
                rel = path.relative_to(self.root).as_posix()
                if rel == "startrack-manifest.json":
                    continue  # Parent validates the sealed archive's manifest separately.
                found.add(rel)
                mapping = self.files.get(rel)
                if mapping is None or not stat.S_ISREG(path.stat().st_mode):
                    raise BridgeAbort("PACKAGE_FILE_INVALID")
                raw = self.read(path, MAX_INPUT)
                if len(raw) != mapping["normalizedSizeBytes"] or hashlib.sha256(raw).hexdigest() != mapping["normalizedSha256"]:
                    raise BridgeAbort("PACKAGE_HASH_INVALID")
        if found != set(self.files):
            raise BridgeAbort("PACKAGE_FILES_INCOMPLETE")

    def path(self, value, *, scratch=False):
        if value == "/dev/null":
            return Path(value)
        candidate = Path(value)
        if not candidate.is_absolute():
            raise BridgeAbort("IO_PATH_INVALID")
        resolved = candidate.resolve()
        allowed = resolved.is_relative_to(self.root) or scratch and self.scratch and resolved.is_relative_to(self.scratch)
        if not allowed or resolved != candidate:
            raise BridgeAbort("IO_PATH_INVALID")
        return resolved

    @staticmethod
    def read(path, maximum):
        with open(path, "rb") as stream:
            value = stream.read(maximum + 1)
        if len(value) > maximum:
            raise BridgeAbort("INPUT_TOO_LARGE")
        return value

    def write(self, path, raw):
        path = self.path(path, scratch=True)
        if path == Path("/dev/null"):
            return
        if not self.scratch or not path.is_relative_to(self.scratch):
            raise BridgeAbort("OUTPUT_PATH_INVALID")
        path.write_bytes(raw)

    def source(self, program):
        path = self.path(program._source_path)
        rel = path.relative_to(self.root).as_posix()
        if rel not in self.programs or not path.is_file() or program._includes.files or program._includes.mainfile is not None:
            raise BridgeAbort("PROGRAM_INVALID")
        role, ref = self.programs[rel]
        raw = self.read(path, MAX_INPUT)
        if len(raw) != ref["sizeBytes"] or hashlib.sha256(raw).hexdigest() != ref["sha256"]:
            raise BridgeAbort("PROGRAM_HASH_INVALID")
        return role, rel, ref["sha256"]

    def compile(self, program, work_dir, compile_result):
        _, path, sha = self.source(program)
        work = self.path(str(work_dir), scratch=True)
        if not work.is_relative_to(self.scratch):
            raise BridgeAbort("COMPILE_PATH_INVALID")
        program._path = work / ("virtual-" + sha)
        program._path.mkdir(exist_ok=True)
        response = self.channel.call("COMPILE", programPath=path)
        # Upstream check_output redirects stderr into stdout on compile failure.
        # Preserve both bounded channels rather than losing a stdout diagnostic.
        diagnostic = None
        if not response["compiled"]:
            streams = [decoded(response[key]) for key in ("stdoutBase64", "stderrBase64")]
            diagnostic = b"\n".join(raw for raw in streams if raw).decode("utf-8", "replace") or response["code"]
        return compile_result(response["compiled"], diagnostic, program._path)

    @staticmethod
    def flags(checker):
        flags = []
        for field, name in (("caseSensitive", "case_sensitive"), ("spaceChangeSensitive", "space_change_sensitive")):
            if checker[field]:
                flags.append(name)
        for field, name in (("floatAbsoluteTolerance", "float_absolute_tolerance"),
                            ("floatRelativeTolerance", "float_relative_tolerance")):
            if checker[field] is not None:
                flags.extend((name, checker[field]))
        return flags

    def run(self, program, infile="/dev/null", outfile="/dev/null", errfile="/dev/null",
            args=None, timelim=1000, memlim=1024, work_dir=None):
        del timelim, memlim, work_dir  # Parent always uses frozen profiles.
        args = [] if args is None else args
        if not isinstance(args, list) or any(not isinstance(arg, str) for arg in args):
            raise BridgeAbort("ARGS_INVALID")
        feedback = None
        if hasattr(program, "_source_path"):
            role, path, sha = self.source(program)
            if args:
                raise BridgeAbort("PROGRAM_ARGS_UNSUPPORTED")
            input_path = self.path(infile, scratch=True)
            if role == "REFERENCE":
                rel = input_path.relative_to(self.root).as_posix()
                case = self.cases.get(rel)
                if case is None:
                    raise BridgeAbort("REFERENCE_INPUT_INVALID")
                response = self.channel.call("RUN_REFERENCE", programPath=path, ordinal=case["ordinal"])
            else:
                response = self.channel.call("RUN_VALIDATOR", programPath=path,
                                             inputBase64=encoded(self.read(input_path, MAX_INPUT)))
        else:
            if getattr(program, "args", []):
                raise BridgeAbort("TOOL_ARGS_INVALID")
            tool = Path(program.path)
            if tool == TOOLS["default_validator"]:
                if len(args) < 3:
                    raise BridgeAbort("CHECKER_ARGS_INVALID")
                input_path = self.path(args[0])
                case = self.cases.get(input_path.relative_to(self.root).as_posix())
                if case is None or self.path(args[1]) != self.root / case["answer"]["path"] or args[3:] != self.flags(case["checker"]):
                    raise BridgeAbort("CHECKER_INPUT_INVALID")
                feedback = self.path(args[2].rstrip(os.sep), scratch=True)
                if not feedback.is_dir() or not feedback.is_relative_to(self.scratch):
                    raise BridgeAbort("FEEDBACK_PATH_INVALID")
                response = self.channel.call("CHECK_OUTPUT", ordinal=case["ordinal"],
                                             outputBase64=encoded(self.read(self.path(infile, scratch=True), MAX_OUTPUT)))
            elif tool == TOOLS["default_grader"]:
                if args:
                    raise BridgeAbort("GRADER_FLAGS_UNSUPPORTED")
                response = self.channel.call("GRADE", inputBase64=encoded(self.read(self.path(infile, scratch=True), MAX_INPUT)))
            else:
                raise BridgeAbort("TOOL_UNSUPPORTED")
        self.write(outfile, decoded(response["stdoutBase64"]))
        self.write(errfile, decoded(response["stderrBase64"]))
        if feedback is not None:
            self.write(str(feedback / "judgemessage.txt"), decoded(response["feedbackBase64"]))
        return response["waitStatus"], response["cpuNs"] / 1_000_000_000

    def statement(self, kind, options, file, diag=None):
        if options.language != "en" or self.path(str(file)) != self.root / self.manifest["statement"]["validationView"]["path"]:
            raise BridgeAbort("STATEMENT_INVALID")
        response = self.channel.call("STATEMENT_" + kind)
        raw_log = decoded(response["stderrBase64"])
        if raw_log:
            self.private_log(("ISOLATED_STATEMENT_" + kind + "_STDERR:\n").encode() + raw_log)
        if diag is not None:
            for _ in range(response["errors"]):
                diag.error("Isolated mature HTML statement conversion reported an error.")
            for _ in range(response["warnings"]):
                diag.warning("Isolated mature HTML statement conversion reported a warning.")
        return response["errors"] == 0

    def private_log(self, raw):
        marker = b"\n[private mature diagnostic log truncated at its bounded limit]\n"
        remaining = MAX_DIAGNOSTICS - self.diagnostic_bytes
        if remaining <= 0:
            return
        if len(raw) > remaining:
            raw = raw[:max(0, remaining - len(marker))] + marker[:remaining]
            self.diagnostic_truncated = True
        sys.stderr.buffer.write(raw)
        sys.stderr.buffer.flush()
        self.diagnostic_bytes += len(raw)

    def results(self):
        parts = []
        for part in PARTS:
            errors, warnings = self.counts[part]
            not_run = not REQUIRED_STEPS[part].issubset(self.completed)
            parts.append({"part": part, "passed": errors == 0 and not not_run,
                          "errors": errors, "warnings": warnings, "notRun": not_run})
        return {"operation": "RESULT", "completed": True, "parts": parts,
                "errors": sum(v[0] for v in self.counts.values()),
                "warnings": sum(v[1] for v in self.counts.values())}


class Diagnostics:
    """Private bounded messages with independent checkpoint counters."""
    def __init__(self, bridge, part="STRUCTURE"):
        self.bridge = bridge
        self.part = part

    @property
    def errors(self):
        return sum(value[0] for value in self.bridge.counts.values())

    @property
    def warnings(self):
        return sum(value[1] for value in self.bridge.counts.values())

    def child(self, name):
        return Diagnostics(self.bridge, STEP_PARTS.get(name, self.part))

    def emit(self, kind, msg, additional_info=None):
        text = f"{kind}: {msg}\n"
        if additional_info:
            text += str(additional_info)[:65536] + "\n"
        raw = text.encode("utf-8", "replace")[:65536]
        self.bridge.private_log(raw)

    def error(self, msg, additional_info=None):
        self.bridge.counts[self.part][0] += 1
        if self.bridge.counts[self.part][0] > 1000000:
            raise BridgeAbort("DIAGNOSTICS_COUNT_INVALID")
        self.emit("ERROR", msg, additional_info)

    def warning(self, msg, additional_info=None):
        self.bridge.counts[self.part][1] += 1
        if self.bridge.counts[self.part][1] > 1000000:
            raise BridgeAbort("DIAGNOSTICS_COUNT_INVALID")
        self.emit("WARNING", msg, additional_info)

    def fatal(self, msg, additional_info=None):
        from problemtools.diagnostics import VerifyError
        self.error(msg, additional_info)
        raise VerifyError(msg)

    def info(self, msg):
        self.emit("INFO", msg)

    def msg(self, msg):
        self.emit("INFO", msg)

    def debug(self, msg):
        pass

    def ttymsg(self, msg):
        pass


def bundled_config():
    """Remove /etc, HOME and adjacent package configuration search paths."""
    from problemtools import config
    import yaml
    directory = Path(config.__file__).parent / "config"

    def load(name, priority_dirs=()):
        del priority_dirs
        if name not in ("problem.yaml", "testdata.yaml", "languages.yaml"):
            raise BridgeAbort("CONFIG_UNSUPPORTED")
        if name == "languages.yaml":
            return LANGUAGES
        return yaml.safe_load((directory / name).read_text(encoding="utf-8"))
    config.load_config = load


def block_native_execution():
    def blocked(*args, **kwargs):
        raise BridgeAbort("NATIVE_EXECUTION_FORBIDDEN")

    def audit(event, args):
        del args
        if event in ("subprocess.Popen", "os.system", "os.fork", "os.forkpty", "os.exec", "os.posix_spawn", "pty.spawn", "ctypes.dlopen", "ctypes.dlsym", "socket.__new__"):
            blocked()
    sys.addaudithook(audit)
    subprocess.Popen = blocked
    for name in ("fork", "forkpty", "system", "popen", "posix_spawn", "posix_spawnp",
                 "execl", "execle", "execlp", "execlpe", "execv", "execve", "execvp", "execvpe",
                 "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe"):
        if hasattr(os, name):
            setattr(os, name, blocked)


def install_hooks(bridge):
    # Import configuration before metadata/model globals freeze defaults.
    bundled_config()
    from problemtools import languages, run
    from problemtools.run import tools
    from problemtools.run.executable import Executable
    from problemtools.run.program import CompileResult, Program

    def get_tool(name):
        if name not in TOOLS:
            raise BridgeAbort("TOOL_UNSUPPORTED")
        return Executable(str(TOOLS[name]))
    tools.get_tool = get_tool
    run.get_tool = get_tool
    languages.load_language_config = lambda _: languages.Languages(LANGUAGES)

    def forbidden(*args, **kwargs):
        raise BridgeAbort("EXECUTION_FORMAT_UNSUPPORTED")
    for kind in (run.BuildRun, run.Viva, run.Checktestdata):
        kind.__init__ = forbidden
        kind.do_compile = forbidden
        kind.get_runcmd = forbidden
    run.SourceCode.do_compile = lambda program, work: bridge.compile(program, work, CompileResult)
    run.SourceCode.get_runcmd = forbidden
    Executable.get_runcmd = forbidden
    Program.run = lambda program, *args, **kwargs: bridge.run(program, *args, **kwargs)

    from problemtools import problem2html, problem2pdf, verifyproblem
    problem2pdf.convert = lambda options, file=None: bridge.statement("PDF", options, file)
    problem2html.convert = lambda options, diag, file=None: bridge.statement("HTML", options, file, diag)
    original = verifyproblem.ProblemVerifier._build_steps

    def steps(verifier, *args, **kwargs):
        result = original(verifier, *args, **kwargs)
        if {step.name for step in result} != set(STEP_PARTS):
            raise BridgeAbort("UPSTREAM_STEP_DRIFT")
        bridge.completed.add("package")
        wrapped = []
        for step in result:
            def check(diag, step=step):
                step.run(diag)
                bridge.completed.add(step.name)
            wrapped.append(dataclasses.replace(step, run=check))
        return wrapped
    verifyproblem.ProblemVerifier._build_steps = steps
    block_native_execution()


def statement_processes():
    """Retain upstream native calls, with explicit TeX shell escape disabled."""
    original = subprocess.Popen

    def launch(args, *positional, **options):
        if options.get("shell", False) or not isinstance(args, (list, tuple)) or not args:
            raise BridgeAbort("STATEMENT_COMMAND_INVALID")
        argv = list(args)
        engine = Path(argv[0]).name
        if engine in ("latex", "pdflatex", "xelatex", "lualatex", "tex", "pdftex", "xetex", "luatex"):
            if any("shell-escape" in str(arg) and str(arg) not in ("-no-shell-escape", "--no-shell-escape") for arg in argv[1:]):
                raise BridgeAbort("STATEMENT_SHELL_ESCAPE_FORBIDDEN")
            argv.insert(1, "-no-shell-escape")
        return original(argv, *positional, **options)
    subprocess.Popen = launch


class ChunkReader:
    """Bounded sequential reads across the parent's fixed tar transport chunks."""
    def __init__(self, streams):
        self.streams = iter(streams)
        self.current = next(self.streams, None)

    def read(self, size):
        if type(size) is not int or size < 0 or size > 1024 * 1024:
            raise BridgeAbort("STATEMENT_ARCHIVE_READ_INVALID")
        pieces = []
        remaining = size
        while remaining and self.current is not None:
            data = self.current.read(remaining)
            if data:
                pieces.append(data)
                remaining -= len(data)
            else:
                self.current = next(self.streams, None)
        return b"".join(pieces)


def unpack_statement(work=Path("/w")):
    """Extract only the Go parent's bounded public statement tar transport."""
    work = work.resolve(strict=True)
    chunks = sorted(path for path in work.iterdir() if path.name.startswith("statement."))
    if not 1 <= len(chunks) <= 12:
        raise BridgeAbort("STATEMENT_CHUNKS_INVALID")
    archive_bytes = 0
    for ordinal, path in enumerate(chunks, 1):
        if path.name != f"statement.{ordinal:06d}.tarpart" or path.is_symlink() or not path.is_file():
            raise BridgeAbort("STATEMENT_CHUNKS_INVALID")
        size = path.stat().st_size
        if size <= 0 or size > MAX_INPUT:
            raise BridgeAbort("STATEMENT_CHUNK_BOUNDS")
        archive_bytes += size
    if archive_bytes > MAX_STATEMENT_ARCHIVE:
        raise BridgeAbort("STATEMENT_ARCHIVE_BOUNDS")
    seen = set()
    total = 0
    regular_files = 0
    with contextlib.ExitStack() as stack:
        streams = [stack.enter_context(path.open("rb")) for path in chunks]
        reader = ChunkReader(streams)
        with tarfile.open(fileobj=reader, mode="r|", encoding="utf-8", errors="strict") as archive:
            for member in archive:
                path = relative_path(member.name.rstrip("/") if member.isdir() else member.name)
                parts = Path(path).parts
                allowed = path == "problem/problem.yaml" or len(parts) >= 3 and parts[:2] == ("problem", "problem_statement") or len(parts) >= 4 and parts[:3] == ("problem", "data", "sample") and Path(path).suffix in (".in", ".ans")
                directory = member.isdir() and (path in ("problem", "problem/problem_statement", "problem/data", "problem/data/sample") or allowed)
                if not (allowed or directory) or not (member.isfile() or member.isdir()) or path in seen:
                    raise BridgeAbort("STATEMENT_MEMBER_INVALID")
                seen.add(path)
                if len(seen) > 65536 or member.size < 0 or member.size > MAX_INPUT:
                    raise BridgeAbort("STATEMENT_MEMBER_BOUNDS")
                total += member.size
                if total > MAX_STATEMENT_DATA:
                    raise BridgeAbort("STATEMENT_DATA_BOUNDS")
                destination = work / path
                if destination.resolve() != destination or not destination.is_relative_to(work):
                    raise BridgeAbort("STATEMENT_PATH_INVALID")
                if directory:
                    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
                    continue
                regular_files += 1
                destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                source = archive.extractfile(member)
                if source is None:
                    raise BridgeAbort("STATEMENT_MEMBER_INVALID")
                # Never use tarfile.extract: every name/type/size is checked above.
                with source, destination.open("xb") as output:
                    remaining = member.size
                    while remaining:
                        data = source.read(min(remaining, 1024 * 1024))
                        if not data:
                            raise BridgeAbort("STATEMENT_DATA_INCOMPLETE")
                        output.write(data)
                        remaining -= len(data)
                destination.chmod(0o600)
            # tarfile buffers some end padding. Reject ignored payload after EOS.
            if any(archive.fileobj.buf):
                raise BridgeAbort("STATEMENT_ARCHIVE_TRAILING_DATA")
            while True:
                tail = reader.read(1024 * 1024)
                if not tail:
                    break
                if any(tail):
                    raise BridgeAbort("STATEMENT_ARCHIVE_TRAILING_DATA")
    if "problem/problem_statement/problem.en.tex" not in seen or "problem/problem.yaml" not in seen:
        raise BridgeAbort("STATEMENT_FILES_INCOMPLETE")
    return {"transportBytes": archive_bytes, "regularBytes": total, "regularFiles": regular_files}


def statement_workspace(transport, work=Path("/w")):
    """Bounded structural facts at extraction/converter observation points."""
    fs = os.statvfs(work)
    if fs.f_bfree > fs.f_blocks or fs.f_ffree > fs.f_files:
        raise BridgeAbort("STATEMENT_WORKSPACE_FACTS_INVALID")
    return dict(transport, totalBytes=fs.f_blocks * fs.f_frsize, totalInodes=fs.f_files,
                peakObservedUsedBytes=(fs.f_blocks - fs.f_bfree) * fs.f_frsize,
                peakObservedUsedInodes=fs.f_files - fs.f_ffree)


def installed_file(path):
    """The identity probe runs inside reviewed readonly sandbox bind mounts."""
    path = Path(path)
    if path.resolve(strict=True) != path or not path.is_relative_to(Path("/usr/local")) and not path.is_relative_to(Path("/opt/startrack")):
        raise BridgeAbort("INSTALLED_PATH_INVALID")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, 65534) or info.st_mode & 0o022 or not os.statvfs(path).f_flag & os.ST_RDONLY:
        raise BridgeAbort("INSTALLED_FILE_MUTABLE")
    for parent in path.parents:
        if parent == Path("/"):
            break
        info = parent.stat()
        if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022:
            raise BridgeAbort("INSTALLED_DIRECTORY_MUTABLE")


def identity_child():
    # This probe executes as a sandbox operation. It does not assert host
    # qualification: Go binds its result to the measured image/profile/hash.
    block_native_execution()
    # The parent verifies the root-owned original hash, then stages this one
    # private copy into a fresh sandbox. It is absent from general role mounts.
    if Path(__file__) != Path("/w/problemtools-bridge.py"):
        raise BridgeAbort("IDENTITY_BRIDGE_PATH_INVALID")
    distribution = importlib.metadata.distribution("problemtools")
    if distribution.version != PROBLEMTOOLS_RELEASE[1:] or not distribution.files:
        raise BridgeAbort("PROBLEMTOOLS_VERSION_INVALID")
    import problemtools
    from problemtools import _version
    root = Path(problemtools.__file__).parent
    if _version.version != distribution.version:
        raise BridgeAbort("PROBLEMTOOLS_VERSION_INVALID")
    for entry in distribution.files:
        installed_file(Path(os.path.abspath(distribution.locate_file(entry))))
    for path in (root / "__init__.py", root / "run/program.py",
                 root / "run/source.py", root / "verifyproblem.py", root / "problem2pdf.py",
                 root / "problem2html.py", root / "templates/latex/template.tex",
                 root / "templates/latex/problemset.cls", root / "config/problem.yaml",
                 root / "config/testdata.yaml"):
        installed_file(path)
    print(json.dumps({"problemtoolsVersion": "v" + distribution.version,
                      "problemtoolsRevision": PROBLEMTOOLS_REVISION, "helperProfile": HELPER_PROFILE}))
    return 0


def verify(control, channel):
    bridge = Bridge(control, channel)
    with tempfile.TemporaryDirectory(prefix="problemtools-bridge-") as scratch:
        bridge.scratch = Path(scratch).resolve()
        tempfile.tempdir = str(bridge.scratch)
        install_hooks(bridge)
        from problemtools import model, verifyproblem
        from problemtools.context import Context
        from problemtools.diagnostics import VerifyError
        diag = Diagnostics(bridge)
        try:
            problem = model.load_problem(bridge.root, diag)
        except VerifyError:
            pass
        else:
            context = Context(fixed_timelim=float(bridge.seconds), threads=1)
            with verifyproblem.ProblemVerifier(problem, diag) as verifier:
                verifier.check(context)
        channel.send(bridge.results())


def protect_statement_process():
    """Keep native children from changing the trusted parent's result channels."""
    if sys.platform != "linux":
        raise BridgeAbort("STATEMENT_PLATFORM_INVALID")
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    # Linux PR_SET_DUMPABLE / PR_GET_DUMPABLE. No package-provided ABI or input.
    if libc.prctl(4, 0, 0, 0, 0) != 0 or libc.prctl(3, 0, 0, 0, 0) != 0:
        raise BridgeAbort("STATEMENT_PROCESS_ISOLATION_FAILED")


def statement_parent_denied():
    """Measure same-UID native-child denial without reading any parent bytes."""
    probe = r'''
import errno, os, sys
denied = os.getppid() == int(sys.argv[1]) and os.getuid() == int(sys.argv[2])
for name in ("environ", "mem", "fd/0", "fd/1", "fd/2"):
    try:
        descriptor = os.open("/proc/" + sys.argv[1] + "/" + name, os.O_RDONLY | os.O_NONBLOCK)
    except OSError as error:
        denied = denied and error.errno in (errno.EACCES, errno.EPERM)
    else:
        os.close(descriptor)
        denied = False
print("true" if denied else "false")
raise SystemExit(0 if denied else 1)
'''
    result = subprocess.run([sys.executable, "-I", "-c", probe, str(os.getpid()), str(os.getuid())],
                            env={"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
                            capture_output=True, timeout=10, check=False)
    return result.returncode == 0 and result.stdout == b"true\n" and not result.stderr


def statement_artifacts(kind, work=Path("/w")):
    """Hash bounded converter output without exporting artifact bytes or names."""
    work = work.resolve(strict=True)
    primary = work / ("qualification.pdf" if kind == "pdf" else "html/index.html")
    root = work if kind == "pdf" else work / "html"
    if kind not in ("pdf", "html") or root.is_symlink() or root.resolve(strict=True) != root:
        raise BridgeAbort("STATEMENT_ARTIFACT_PATH_INVALID")
    paths = [primary] if kind == "pdf" else []
    if kind == "html":
        for parent, dirs, names in os.walk(root, followlinks=False):
            for name in dirs:
                path = Path(parent) / name
                if path.is_symlink() or not path.is_dir():
                    raise BridgeAbort("STATEMENT_ARTIFACT_PATH_INVALID")
            for name in names:
                paths.append(Path(parent) / name)
                if len(paths) > 4096:
                    raise BridgeAbort("STATEMENT_ARTIFACT_BOUNDS")
    records = []
    primary_raw = None
    total = 0
    for path in sorted(paths, key=lambda path: path.relative_to(root).as_posix().encode("utf-8")):
        if path.is_symlink() or path.resolve(strict=True) != path or not stat.S_ISREG(path.stat().st_mode):
            raise BridgeAbort("STATEMENT_ARTIFACT_PATH_INVALID")
        raw = Bridge.read(path, MAX_OUTPUT)
        total += len(raw)
        if total > MAX_STATEMENT_ARTIFACTS:
            raise BridgeAbort("STATEMENT_ARTIFACT_BOUNDS")
        records.append({"path": path.relative_to(root).as_posix(), "sizeBytes": len(raw),
                        "sha256": hashlib.sha256(raw).hexdigest()})
        if path == primary:
            primary_raw = raw
    if not records or not primary_raw:
        raise BridgeAbort("STATEMENT_ARTIFACT_MISSING")
    math_elements = 0
    if kind == "pdf":
        if not primary_raw.startswith(b"%PDF-") or not primary_raw.rstrip().endswith(b"%%EOF"):
            raise BridgeAbort("STATEMENT_ARTIFACT_INVALID")
    else:
        class Markup(HTMLParser):
            def __init__(self):
                super().__init__(convert_charrefs=True)
                self.html = False
                self.math = 0

            def handle_starttag(self, tag, attrs):
                self.html = self.html or tag == "html"
                if tag == "span" and any(name == "class" and value and "tex2jax_process" in value.split()
                                         for name, value in attrs):
                    self.math += 1
        markup = Markup()
        markup.feed(primary_raw.decode("utf-8", "strict"))
        markup.close()
        if not markup.html:
            raise BridgeAbort("STATEMENT_ARTIFACT_INVALID")
        math_elements = markup.math
    manifest = json.dumps(records, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    return {"kind": kind.upper(), "manifestSha256": hashlib.sha256(manifest).hexdigest(),
            "fileCount": len(records), "fileBytes": total,
            "primarySha256": hashlib.sha256(primary_raw).hexdigest(), "primaryBytes": len(primary_raw),
            "mathElements": math_elements}


def statement_child(kind, qualify=False):
    """Called only by fixed argv in the role-separated statement sandbox."""
    protect_statement_process()
    parent_denied = statement_parent_denied() if qualify else None
    if qualify and not parent_denied:
        raise BridgeAbort("STATEMENT_PROCESS_ISOLATION_FAILED")
    transport = unpack_statement()
    workspace = statement_workspace(transport) if qualify else None
    bundled_config()
    from problemtools import problem2html, problem2pdf, template
    from problemtools.diagnostics import LoggingDiagnostics
    statement_processes()
    original = template.Template.__init__

    def template_init(self, root, file, language, ignore_parent_cls=False):
        del ignore_parent_cls
        original(self, root, file, language, ignore_parent_cls=True)
    template.Template.__init__ = template_init
    root = Path("/w/problem")
    file = root / "problem_statement/problem.en.tex"
    ok = False
    artifacts = None
    # Preserve one JSON stdout frame even if a native image tool prints to fd 1.
    output_fd = os.dup(sys.stdout.fileno())
    os.dup2(sys.stderr.fileno(), sys.stdout.fileno())
    try:
        with contextlib.redirect_stdout(sys.stderr):
            diag = LoggingDiagnostics.create("statement", log_level=logging.WARNING, max_additional_info=0)
            try:
                if kind == "pdf":
                    options = problem2pdf.get_parser().parse_args([str(root)])
                    options.language, options.nopdf, options.quiet = "en", not qualify, True
                    if qualify:
                        options.destfile = "/w/qualification.pdf"
                    ok = problem2pdf.convert(options, file)
                else:
                    options = problem2html.get_parser().parse_args([str(root)])
                    options.language, options.quiet, options.destdir = "en", True, "/w/html"
                    problem2html.convert(options, diag, file)
                    ok = diag.errors == 0
                if qualify and ok:
                    artifacts = statement_artifacts(kind)
                    after = statement_workspace(transport)
                    for field in ("peakObservedUsedBytes", "peakObservedUsedInodes"):
                        workspace[field] = max(workspace[field], after[field])
            except Exception:
                ok = False
                diag.error("Isolated statement conversion raised an exception.")
    finally:
        sys.stdout.flush()
        os.dup2(output_fd, sys.stdout.fileno())
        os.close(output_fd)
    result = {"ok": bool(ok), "errors": diag.errors + int(not ok and diag.errors == 0), "warnings": diag.warnings}
    if qualify:
        result["artifacts"] = artifacts if ok else None
        result["parentProcessDenied"] = parent_denied
        result["workspace"] = workspace
    print(json.dumps(result))
    return 0 if ok else 1


def main():
    if len(sys.argv) == 2 and sys.argv[1] == "--identity":
        return identity_child()
    if len(sys.argv) == 3 and sys.argv[1] == "--statement" and sys.argv[2] in ("pdf", "html"):
        return statement_child(sys.argv[2])
    if len(sys.argv) == 3 and sys.argv[1] == "--qualify-statement" and sys.argv[2] in ("pdf", "html"):
        return statement_child(sys.argv[2], qualify=True)
    if len(sys.argv) != 1:
        raise BridgeAbort("ARGV_INVALID")
    channel = Channel(sys.stdin.buffer, sys.stdout.buffer)
    control = read_frame(channel.input)
    logging.disable(logging.CRITICAL)
    with contextlib.redirect_stdout(sys.stderr):
        verify(control, channel)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BridgeAbort as error:
        # Never print exception details supplied by packages or raw tool output.
        print("problemtools bridge stopped: " + str(error), file=sys.stderr)
        sys.exit(70)
