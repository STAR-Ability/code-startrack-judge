# SPDX-License-Identifier: Apache-2.0
"""Portable inert protocol tests; no imported program or statement is executed."""

import copy
import builtins
from contextlib import contextmanager
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("problemtools_bridge", ROOT / "scripts/problemtools-bridge.py")
bridge = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bridge)


def response(**values):
    result = {"ok": True, "code": "", "compiled": True, "waitStatus": 42 << 8,
              "cpuNs": 123456789, "stdoutBase64": "", "stderrBase64": "",
              "feedbackBase64": "", "errors": 0, "warnings": 0}
    result.update(values)
    return result


class MockChannel:
    def __init__(self):
        self.calls = []
        self.reply = response()

    def call(self, operation, **fields):
        self.calls.append((operation, fields))
        return self.reply


class InertConfigSection:
    """Match pinned PlasTeX's mapping API without importing its logging hooks."""
    def __init__(self, **values):
        self.options = {name: SimpleNamespace(value=value, metadata=object()) for name, value in values.items()}

    def __getitem__(self, name):
        return self.options[name].value

    def __setitem__(self, name, value):
        self.options[name].value = value


@contextmanager
def inert_html_imports(renderer, convert):
    """Provide inert modules and observe the delayed upstream import sequence."""
    problemtools = ModuleType("problemtools")
    problemtools.__path__ = []
    tex2html = ModuleType("problemtools.tex2html")
    tex2html.convert = convert
    problemtools.tex2html = tex2html
    renderers = ModuleType("problemtools.ProblemPlasTeX")
    renderers.ProblemRenderer = renderer
    plastex = ModuleType("plasTeX")
    plastex.__path__ = []
    plastex.Logging = ModuleType("plasTeX.Logging")
    plastex.TeX = ModuleType("plasTeX.TeX")
    modules = {"problemtools": problemtools, "problemtools.tex2html": tex2html,
               "problemtools.ProblemPlasTeX": renderers, "plasTeX": plastex,
               "plasTeX.Logging": plastex.Logging, "plasTeX.TeX": plastex.TeX}
    imported = []
    original_import = builtins.__import__

    def observe(name, *args, **kwargs):
        if name in ("plasTeX.Logging", "plasTeX.TeX", "problemtools.ProblemPlasTeX"):
            imported.append(name)
        return original_import(name, *args, **kwargs)

    with patch.dict(sys.modules, modules), patch.object(builtins, "__import__", observe):
        yield SimpleNamespace(tex2html=tex2html, imported=imported)


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.base = Path(self.directory.name).resolve()
        self.package = self.base / "fixture"
        self.package.mkdir()
        refs = {}
        mappings = []
        for path, content in {
            "input_validators/check.py": b"inert validator bytes",
            "submissions/accepted/main.cpp": b"inert reference bytes",
            "data/sample/1.in": b"input\n", "data/sample/1.ans": b"answer\n",
            "problem_statement/problem.en.tex": b"inert generated statement bytes",
        }.items():
            actual = self.package / path
            actual.parent.mkdir(parents=True, exist_ok=True)
            actual.write_bytes(content)
            sha = hashlib.sha256(content).hexdigest()
            refs[path] = {"path": path, "sha256": sha, "sizeBytes": len(content)}
            mappings.append({"normalizedPath": path, "normalizedSha256": sha, "normalizedSizeBytes": len(content)})
        checker = {"caseSensitive": True, "spaceChangeSensitive": False,
                   "floatAbsoluteTolerance": "0.1", "floatRelativeTolerance": None}
        self.control = {"packageDir": str(self.package), "identity": {}, "fixedTimeLimitSeconds": "1.25",
                        "manifest": {"limits": {"timeLimitMs": 1250}, "files": mappings,
                                     "inputValidators": [{"file": refs["input_validators/check.py"], "languageId": "python3"}],
                                     "referenceSolutions": [{"file": refs["submissions/accepted/main.cpp"], "languageId": "cpp17", "role": "ACCEPTED"}],
                                     "tests": [{"ordinal": 1, "input": refs["data/sample/1.in"], "answer": refs["data/sample/1.ans"], "checker": checker}],
                                     "statement": {"validationView": refs["problem_statement/problem.en.tex"]}}}
        self.channel = MockChannel()
        self.bridge = bridge.Bridge(self.control, self.channel)
        self.bridge.scratch = self.base / "scratch"
        self.bridge.scratch.mkdir()

    def program(self, path):
        return SimpleNamespace(_source_path=str(self.package / path), _includes=SimpleNamespace(files=[], mainfile=None))

    def test_exact_decimal_time_and_package_hash(self):
        for altered in ("1.251", "1e0", "NaN"):
            control = copy.deepcopy(self.control)
            control["fixedTimeLimitSeconds"] = altered
            with self.assertRaises(bridge.BridgeAbort):
                bridge.Bridge(control, self.channel)
        (self.package / "data/sample/1.in").write_bytes(b"changed")
        with self.assertRaises(bridge.BridgeAbort):
            bridge.Bridge(self.control, self.channel)

    def test_symlinks_and_extra_files_fail(self):
        outside = self.base / "outside"
        outside.write_bytes(b"secret")
        (self.package / "extra").symlink_to(outside)
        with self.assertRaises(bridge.BridgeAbort):
            bridge.Bridge(self.control, self.channel)
        (self.package / "extra").unlink()
        (self.package / "extra").write_bytes(b"extra")
        with self.assertRaises(bridge.BridgeAbort):
            bridge.Bridge(self.control, self.channel)

    def test_validator_mutation_is_bounded_and_role_selected(self):
        mutation = self.bridge.scratch / "mutation"
        mutation.write_bytes(b"mature generated junk")
        result = self.bridge.run(self.program("input_validators/check.py"), str(mutation))
        self.assertEqual(result, (42 << 8, 0.123456789))
        operation, fields = self.channel.calls[0]
        self.assertEqual(operation, "RUN_VALIDATOR")
        self.assertEqual(bridge.decoded(fields["inputBase64"]), b"mature generated junk")
        self.assertEqual(fields["programPath"], "input_validators/check.py")

    def test_reference_uses_only_sealed_ordinal(self):
        reference = self.program("submissions/accepted/main.cpp")
        self.bridge.run(reference, str(self.package / "data/sample/1.in"))
        self.assertEqual(self.channel.calls[0][0], "RUN_REFERENCE")
        self.assertEqual(self.channel.calls[0][1]["ordinal"], 1)
        self.assertNotIn("inputBase64", self.channel.calls[0][1])
        mutation = self.bridge.scratch / "mutation"
        mutation.write_bytes(b"junk")
        with self.assertRaises((bridge.BridgeAbort, ValueError)):
            self.bridge.run(reference, str(mutation))
        self.assertEqual(len(self.channel.calls), 1)

    def test_no_freeform_args_or_adjacent_sources(self):
        with self.assertRaises(bridge.BridgeAbort):
            self.bridge.run(self.program("input_validators/check.py"), args=["arbitrary"])
        with self.assertRaises(bridge.BridgeAbort):
            self.bridge.run(self.program("../outside"))
        self.assertEqual(self.channel.calls, [])

    def test_compile_returns_only_virtual_path(self):
        program = self.program("submissions/accepted/main.cpp")
        value = self.bridge.compile(program, self.bridge.scratch, lambda *args: args)
        self.assertTrue(value[0])
        self.assertTrue(value[2].is_relative_to(self.bridge.scratch))
        self.assertEqual(list(value[2].iterdir()), [])
        self.assertEqual(self.channel.calls[0][0], "COMPILE")
        program._includes.files = ["hidden include"]
        with self.assertRaises(bridge.BridgeAbort):
            self.bridge.compile(program, self.bridge.scratch, lambda *args: args)

    def test_failed_compile_retains_both_upstream_diagnostic_channels(self):
        self.channel.reply = response(compiled=False, stdoutBase64=bridge.encoded(b"compiler stdout"), stderrBase64=bridge.encoded(b"compiler stderr"))
        value = self.bridge.compile(self.program("submissions/accepted/main.cpp"), self.bridge.scratch, lambda *args: args)
        self.assertFalse(value[0])
        self.assertEqual(value[1], "compiler stdout\ncompiler stderr")

    def test_checker_paths_flags_and_feedback_are_controlled(self):
        tool = SimpleNamespace(path=bridge.TOOLS["default_validator"], args=[])
        feedback = self.bridge.scratch / "feedback"
        feedback.mkdir()
        output = self.bridge.scratch / "output"
        output.write_bytes(b"candidate output")
        args = [str(self.package / "data/sample/1.in"), str(self.package / "data/sample/1.ans"), str(feedback) + "/", "case_sensitive", "float_absolute_tolerance", "0.1"]
        self.channel.reply = response(feedbackBase64=bridge.encoded(b"private feedback"))
        self.bridge.run(tool, str(output), args=args)
        self.assertEqual(self.channel.calls[0][0], "CHECK_OUTPUT")
        self.assertEqual(self.channel.calls[0][1]["ordinal"], 1)
        self.assertEqual((feedback / "judgemessage.txt").read_bytes(), b"private feedback")
        for altered in (args + ["extra"], [args[0], args[0], *args[2:]], [*args[:2], str(self.package), *args[3:]]):
            with self.assertRaises(bridge.BridgeAbort):
                self.bridge.run(tool, str(output), args=altered)

    def test_output_cannot_overwrite_source_or_follow_link(self):
        with self.assertRaises(bridge.BridgeAbort):
            self.bridge.write(str(self.package / "data/sample/1.in"), b"overwrite")
        link = self.bridge.scratch / "link"
        link.symlink_to(self.package / "data/sample/1.in")
        with self.assertRaises(bridge.BridgeAbort):
            self.bridge.write(str(link), b"overwrite")
        self.assertEqual((self.package / "data/sample/1.in").read_bytes(), b"input\n")

    def test_default_grader_keeps_mature_input_without_flags(self):
        tool = SimpleNamespace(path=bridge.TOOLS["default_grader"], args=[])
        value = self.bridge.scratch / "grader-in"
        value.write_bytes(b"AC 1.0\nWA 0.0\n")
        self.bridge.run(tool, str(value))
        self.assertEqual(self.channel.calls[0][0], "GRADE")
        with self.assertRaises(bridge.BridgeAbort):
            self.bridge.run(tool, str(value), args=["sum"])

    def test_statement_can_only_request_fixed_generated_view(self):
        options = SimpleNamespace(language="en")
        self.assertTrue(self.bridge.statement("PDF", options, self.package / "problem_statement/problem.en.tex"))
        self.assertEqual(self.channel.calls, [("STATEMENT_PDF", {})])
        options.language = "other"
        with self.assertRaises(bridge.BridgeAbort):
            self.bridge.statement("PDF", options, self.package / "problem_statement/problem.en.tex")

    def test_statement_original_failure_diagnostics_remain_private_and_bounded(self):
        self.channel.reply = response(errors=1, stderrBase64=bridge.encoded(b"original converter failure"))
        private = io.BytesIO()
        stream = SimpleNamespace(buffer=private)
        with patch.object(bridge.sys, "stderr", stream):
            self.assertFalse(self.bridge.statement("PDF", SimpleNamespace(language="en"), self.package / "problem_statement/problem.en.tex"))
            self.bridge.private_log(b"x" * bridge.MAX_DIAGNOSTICS)
        self.assertIn(b"original converter failure", private.getvalue())
        self.assertEqual(len(private.getvalue()), bridge.MAX_DIAGNOSTICS)
        self.assertIn(b"truncated at its bounded limit", private.getvalue())

    def test_partial_and_fatal_steps_never_pass_on_zero_errors(self):
        self.bridge.completed.update({"package", "config", "grader", "includes", "statement"})
        self.bridge.counts["VALIDATORS"][0] = 1
        parts = {part["part"]: part for part in self.bridge.results()["parts"]}
        self.assertTrue(parts["STRUCTURE"]["passed"])
        self.assertFalse(parts["STATEMENT"]["passed"])
        self.assertTrue(parts["STATEMENT"]["notRun"])
        self.assertEqual(parts["STATEMENT"]["errors"], 0)
        self.assertTrue(parts["VALIDATORS"]["notRun"])

    def test_response_rejects_protocol_errors_before_data_is_used(self):
        for changed in ({"ok": False}, {"waitStatus": True}, {"cpuNs": -1}, {"stdoutBase64": "not base64"}, {"extra": "value"}):
            reply = response(**changed)
            channel = bridge.Channel(io.BytesIO(json.dumps(reply).encode() + b"\n"), io.BytesIO())
            with self.assertRaises(bridge.BridgeAbort):
                channel.call("GRADE", inputBase64="")

    def test_duplicate_keys_and_nonfinite_json_are_rejected(self):
        for raw in (b'{"ok":true,"ok":false}\n', b'{"value":NaN}\n', b'{"value":0}', b'[]\n'):
            with self.assertRaises(bridge.BridgeAbort):
                bridge.read_frame(io.BytesIO(raw))

    def test_native_execution_blocker_fails_without_running_commands(self):
        code = """
import importlib.util, os, subprocess, sys
spec = importlib.util.spec_from_file_location('bridge', sys.argv[1])
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)
b.block_native_execution()
for action in (lambda: os.system('should-not-execute'), lambda: os.fork(), lambda: subprocess.Popen(['should-not-execute'])):
    try:
        action()
    except b.BridgeAbort:
        continue
    raise SystemExit(1)
"""
        subprocess.run([sys.executable, "-I", "-c", code, str(ROOT / "scripts/problemtools-bridge.py")], check=True, capture_output=True)

    def test_statement_native_hook_disables_shell_escape_without_replacing_converter(self):
        launched = []
        with patch.object(bridge.subprocess, "Popen", lambda args, *rest, **kwargs: launched.append(args)):
            bridge.statement_processes()
            bridge.subprocess.Popen(["lualatex", "--interaction=nonstopmode", "--draftmode", "main.tex"])
            bridge.subprocess.Popen(["tidy", "-utf8", "-i", "-q", "-m", "index.html"])
            with self.assertRaises(bridge.BridgeAbort):
                bridge.subprocess.Popen(["lualatex", "--shell-escape", "main.tex"])
            with self.assertRaises(bridge.BridgeAbort):
                bridge.subprocess.Popen("lualatex main.tex", shell=True)
        self.assertEqual(launched, [["lualatex", "-no-shell-escape", "--interaction=nonstopmode", "--draftmode", "main.tex"],
                                    ["tidy", "-utf8", "-i", "-q", "-m", "index.html"]])

    def html_document(self, enabled=False, imager="none"):
        images = InertConfigSection(**{"enabled": enabled, "imager": imager,
                                     "vector-imager": "pdf2svg dvisvgm", "base-url": "images",
                                     "filenames": "img-$num(4)"})
        return SimpleNamespace(config={"images": images, "general": {"copy-theme-extras": False},
                                       "files": {"filename": "index.html"}},
                               userdata={"mathjax": {"configuration": "inert preserved math configuration"}})

    def test_html_image_hook_is_lazy_and_sets_only_fixed_vector_mode_before_original_render(self):
        document = self.html_document()
        images = document.config["images"]
        vector_option = images.options["vector-imager"]
        metadata = vector_option.metadata
        other_images = {name: option.value for name, option in images.options.items() if name != "vector-imager"}
        other_config = copy.deepcopy({name: value for name, value in document.config.items() if name != "images"})
        math = copy.deepcopy(document.userdata)
        custom_copier = object()
        render_calls, convert_calls = [], []
        result = object()

        class Renderer:
            def render(instance, doc, *args, **kwargs):
                render_calls.append((instance, doc, args, kwargs))
                self.assertEqual(doc.config["images"]["vector-imager"], "none")
                # The pinned original renderer installs its custom image copier.
                instance.imager = custom_copier
                return result

        renderer = Renderer()
        original_render = Renderer.render

        def convert(*args, **kwargs):
            convert_calls.append((args, kwargs))
            return renderer.render(document, "render-argument", preserve=True)

        with inert_html_imports(Renderer, convert) as modules:
            bridge.statement_html_configuration()
            self.assertEqual(modules.imported, [])
            self.assertIs(Renderer.render, original_render)
            self.assertIs(modules.tex2html.convert("convert-argument", preserve="value"), result)
            self.assertEqual(modules.imported, ["plasTeX.Logging", "plasTeX.TeX", "problemtools.ProblemPlasTeX"])
            self.assertIs(Renderer.render, original_render)
        self.assertEqual(convert_calls, [(("convert-argument",), {"preserve": "value"})])
        self.assertEqual(render_calls, [(renderer, document, ("render-argument",), {"preserve": True})])
        self.assertIs(renderer.imager, custom_copier)
        self.assertIs(document.config["images"], images)
        self.assertIs(images.options["vector-imager"], vector_option)
        self.assertIs(vector_option.metadata, metadata)
        self.assertEqual(other_images, {name: option.value for name, option in images.options.items() if name != "vector-imager"})
        self.assertEqual(other_config, {name: value for name, value in document.config.items() if name != "images"})
        self.assertEqual(document.userdata, math)

    def test_html_image_hook_rejects_upstream_profile_drift_and_restores_renderer(self):
        for enabled, imager in ((True, "none"), (0, "none"), (None, "none"), (False, "auto"), (False, "pdflatex")):
            with self.subTest(enabled=enabled, imager=imager):
                document = self.html_document(enabled, imager)
                called = []

                class Renderer:
                    def render(instance, doc):
                        called.append(doc)

                original_render = Renderer.render
                with inert_html_imports(Renderer, lambda: Renderer().render(document)) as modules:
                    bridge.statement_html_configuration()
                    with self.assertRaisesRegex(bridge.BridgeAbort, "STATEMENT_IMAGE_PROFILE_INVALID"):
                        modules.tex2html.convert()
                    self.assertIs(Renderer.render, original_render)
                self.assertEqual(called, [])
                self.assertEqual(document.config["images"]["vector-imager"], "pdf2svg dvisvgm")

    def test_html_image_hook_restores_renderer_after_original_conversion_and_render_failures(self):
        for failure in ("convert", "render"):
            with self.subTest(failure=failure):
                document = self.html_document()
                error = RuntimeError("inert original failure")

                class Renderer:
                    def render(instance, doc):
                        self.assertEqual(doc.config["images"]["vector-imager"], "none")
                        raise error

                def convert():
                    if failure == "convert":
                        raise error
                    return Renderer().render(document)

                original_render = Renderer.render
                with inert_html_imports(Renderer, convert) as modules:
                    bridge.statement_html_configuration()
                    with self.assertRaises(RuntimeError) as observed:
                        modules.tex2html.convert()
                    self.assertIs(observed.exception, error)
                    self.assertIs(Renderer.render, original_render)

    def statement_tar(self, extra=None):
        value = io.BytesIO()
        with tarfile.open(fileobj=value, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for path, raw in {"problem/problem.yaml": b"name: fixture\n",
                              "problem/problem_statement/problem.en.tex": b"inert tex\n",
                              "problem/data/sample/group/样例.in": b"public input\n",
                              "problem/data/sample/group/样例.ans": b"public answer\n"}.items():
                member = tarfile.TarInfo(path)
                member.size = len(raw)
                archive.addfile(member, io.BytesIO(raw))
            if extra:
                archive.addfile(extra, io.BytesIO(b"x") if extra.size else None)
        return value.getvalue()

    def test_statement_tar_is_streamed_across_contiguous_chunks_and_preserves_unicode(self):
        work = self.base / "statement-work"
        work.mkdir()
        raw = self.statement_tar()
        # A split inside a tar header exercises the actual streaming transport.
        (work / "statement.000001.tarpart").write_bytes(raw[:517])
        (work / "statement.000002.tarpart").write_bytes(raw[517:])
        bridge.unpack_statement(work)
        self.assertEqual((work / "problem/data/sample/group/样例.in").read_bytes(), b"public input\n")
        self.assertEqual((work / "problem/problem_statement/problem.en.tex").read_bytes(), b"inert tex\n")

    def test_statement_tar_rejects_links_special_paths_secret_cases_and_trailing_payload(self):
        for ordinal, (name, kind) in enumerate((("problem/../escape", tarfile.REGTYPE),
                                               ("problem/data/secret/1.in", tarfile.REGTYPE),
                                               ("problem/problem_statement/link", tarfile.SYMTYPE),
                                               ("problem/problem_statement/device", tarfile.CHRTYPE))):
            work = self.base / f"statement-invalid-{ordinal}"
            work.mkdir()
            extra = tarfile.TarInfo(name)
            extra.type = kind
            extra.size = 1 if kind == tarfile.REGTYPE else 0
            extra.linkname = "/etc/passwd" if kind == tarfile.SYMTYPE else ""
            (work / "statement.000001.tarpart").write_bytes(self.statement_tar(extra))
            with self.assertRaises(bridge.BridgeAbort):
                bridge.unpack_statement(work)
        work = self.base / "statement-trailing"
        work.mkdir()
        (work / "statement.000001.tarpart").write_bytes(self.statement_tar() + b"ignored malicious payload")
        with self.assertRaises(bridge.BridgeAbort):
            bridge.unpack_statement(work)

    def test_statement_tar_rejects_missing_chunks_and_files(self):
        work = self.base / "statement-missing"
        work.mkdir()
        (work / "statement.000002.tarpart").write_bytes(self.statement_tar())
        with self.assertRaises(bridge.BridgeAbort):
            bridge.unpack_statement(work)

    def test_qualification_artifacts_are_bounded_hashes_and_actual_math_markup_counts(self):
        work = self.base / "qualification"
        (work / "html").mkdir(parents=True)
        pdf = b"%PDF-1.7\ninert portable bytes\n%%EOF\n"
        (work / "qualification.pdf").write_bytes(pdf)
        evidence = bridge.statement_artifacts("pdf", work)
        self.assertEqual(evidence["primarySha256"], hashlib.sha256(pdf).hexdigest())
        self.assertEqual((evidence["fileCount"], evidence["fileBytes"], evidence["mathElements"]), (1, len(pdf), 0))
        html = b'<html><span class="tex2jax_process">\\(x^2\\)</span></html>'
        (work / "html/index.html").write_bytes(html)
        evidence = bridge.statement_artifacts("html", work)
        self.assertEqual((evidence["fileCount"], evidence["fileBytes"], evidence["mathElements"]), (1, len(html), 1))
        self.assertEqual(evidence["primarySha256"], hashlib.sha256(html).hexdigest())
        serialized = json.dumps(evidence)
        self.assertNotIn("index.html", serialized)
        self.assertNotIn("x^2", serialized)
        (work / "html/style.css").write_bytes(b"private inert CSS")
        additional = bridge.statement_artifacts("html", work)
        self.assertEqual(additional["fileCount"], 2)
        self.assertNotEqual(additional["manifestSha256"], evidence["manifestSha256"])
        self.assertEqual(additional["primarySha256"], evidence["primarySha256"])

    def test_qualification_artifacts_reject_missing_invalid_links_and_size_exhaustion(self):
        work = self.base / "qualification-invalid"
        (work / "html").mkdir(parents=True)
        for raw in (b"", b"not PDF", b"%PDF-incomplete"):
            (work / "qualification.pdf").write_bytes(raw)
            with self.assertRaises(bridge.BridgeAbort):
                bridge.statement_artifacts("pdf", work)
        with self.assertRaises(bridge.BridgeAbort):
            bridge.statement_artifacts("html", work)
        (work / "html/index.html").write_bytes(b"<html></html>")
        (work / "html/link").symlink_to(self.package / "data/sample/1.in")
        with self.assertRaises(bridge.BridgeAbort):
            bridge.statement_artifacts("html", work)
        (work / "html/link").unlink()
        with patch.object(bridge, "MAX_STATEMENT_ARTIFACTS", 1):
            with self.assertRaises(bridge.BridgeAbort):
                bridge.statement_artifacts("html", work)

    def test_qualification_statement_cli_has_only_fixed_modes_and_preserves_normal_dispatch(self):
        with patch.object(bridge, "statement_child", return_value=17) as child:
            with patch.object(bridge.sys, "argv", ["bridge", "--statement", "pdf"]):
                self.assertEqual(bridge.main(), 17)
            child.assert_called_once_with("pdf")
            child.reset_mock()
            with patch.object(bridge.sys, "argv", ["bridge", "--qualify-statement", "html"]):
                self.assertEqual(bridge.main(), 17)
            child.assert_called_once_with("html", qualify=True)
            for args in (["--qualify-statement", "svg"], ["--qualify-statement", "pdf", "/other"],
                         ["--qualify-statement", "pdf", "--shell-escape"]):
                with patch.object(bridge.sys, "argv", ["bridge", *args]):
                    with self.assertRaises(bridge.BridgeAbort):
                        bridge.main()

    def test_statement_process_protection_fails_closed_on_wrong_platform_or_failed_measurement(self):
        with patch.object(bridge.sys, "platform", "darwin"):
            with self.assertRaises(bridge.BridgeAbort):
                bridge.protect_statement_process()
        import ctypes
        for returns in ((-1,), (0, 1), (0, 0)):
            calls = []
            results = iter(returns)
            libc = SimpleNamespace(prctl=lambda *args: (calls.append(args), next(results))[1])
            with patch.object(bridge.sys, "platform", "linux"), patch.object(ctypes, "CDLL", return_value=libc):
                if returns == (0, 0):
                    bridge.protect_statement_process()
                    self.assertEqual(calls, [(4, 0, 0, 0, 0), (3, 0, 0, 0, 0)])
                else:
                    with self.assertRaises(bridge.BridgeAbort):
                        bridge.protect_statement_process()

    def test_statement_parent_denial_canary_requires_exact_bounded_native_result(self):
        for result, expected in ((SimpleNamespace(returncode=0, stdout=b"true\n", stderr=b""), True),
                                 (SimpleNamespace(returncode=1, stdout=b"false\n", stderr=b""), False),
                                 (SimpleNamespace(returncode=0, stdout=b"true\nextra", stderr=b""), False),
                                 (SimpleNamespace(returncode=0, stdout=b"true\n", stderr=b"error"), False)):
            with patch.object(bridge.subprocess, "run", return_value=result) as run:
                self.assertEqual(bridge.statement_parent_denied(), expected)
                arguments = run.call_args.args[0]
                self.assertEqual(arguments[:3], [sys.executable, "-I", "-c"])
                self.assertEqual(arguments[-2:], [str(os.getpid()), str(os.getuid())])
                self.assertEqual(run.call_args.kwargs["timeout"], 10)
                self.assertNotIn("O_NOFOLLOW", arguments[3])

    @unittest.skipUnless(os.environ.get("STARTRACK_PROBLEMTOOLS_SOURCE_DIR"), "exact pinned upstream source not configured")
    def test_pinned_upstream_static_hooks_intercept_every_native_role(self):
        # The upstream owner prepares this source from the reviewed Git pin.
        # It is trusted orchestration, while all package bytes remain inert.
        for path, raw in {"problem.yaml": json.dumps({"name": "Portable fixture", "type": "pass-fail", "validation": "default", "limits": {"memory": 1024, "output": 8}}).encode(),
                          "data/secret/2.in": b"input2\n", "data/secret/2.ans": b"answer\n"}.items():
            file = self.package / path
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(raw)
            sha = hashlib.sha256(raw).hexdigest()
            self.control["manifest"]["files"].append({"normalizedPath": path, "normalizedSha256": sha, "normalizedSizeBytes": len(raw)})
        first = self.control["manifest"]["tests"][0]
        first["checker"]["caseSensitive"] = False
        first["checker"]["floatAbsoluteTolerance"] = None
        self.control["manifest"]["tests"].append({"ordinal": 2, "input": {"path": "data/secret/2.in"}, "answer": {"path": "data/secret/2.ans"}, "checker": first["checker"]})
        source = Path(os.environ["STARTRACK_PROBLEMTOOLS_SOURCE_DIR"]).resolve(strict=True)
        completed = subprocess.run([sys.executable, "-I", str(ROOT / "tests/problemtools_static_driver.py"), str(source)], input=json.dumps(self.control), text=True, capture_output=True, check=True)
        evidence = json.loads(completed.stdout)
        self.assertTrue(evidence["portableOnly"])
        self.assertEqual({part["part"] for part in evidence["parts"]}, set(bridge.PARTS))
        self.assertTrue(all(part["passed"] and not part["notRun"] for part in evidence["parts"]))
        self.assertEqual(set(evidence["operations"]), {"COMPILE", "RUN_REFERENCE", "RUN_VALIDATOR", "CHECK_OUTPUT", "GRADE", "STATEMENT_PDF", "STATEMENT_HTML"})
        self.assertEqual(evidence["operations"]["COMPILE"], 2)
        self.assertEqual(evidence["operations"]["RUN_REFERENCE"], 2)


if __name__ == "__main__":
    unittest.main()
