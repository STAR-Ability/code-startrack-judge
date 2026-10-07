# SPDX-License-Identifier: Apache-2.0
"""Only for the opt-in pinned upstream static-hook compatibility regression.

No imported compiler, reference, validator, checker, grader or TeX is executed.
All execution is intercepted; this script cannot provide Linux qualification.
"""

import importlib.util
import json
import logging
from pathlib import Path
import sys
import tempfile
import types

source = Path(sys.argv[1]).resolve(strict=True)
sys.path.insert(0, str(source))
# These modules are imported by upstream but their only relevant native calls
# live inside statement conversion, which this test delegates to inert RPC.
colorlog = types.ModuleType("colorlog")
colorlog.basicConfig = logging.basicConfig
sys.modules["colorlog"] = colorlog
sys.modules["nh3"] = types.ModuleType("nh3")
spec = importlib.util.spec_from_file_location("bridge", Path(__file__).resolve().parents[1] / "scripts/problemtools-bridge.py")
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)
control = json.load(sys.stdin)


class MockRuntime:
    def __init__(self):
        self.operations = {}
        self.result = None

    def call(self, operation, **fields):
        self.operations[operation] = self.operations.get(operation, 0) + 1
        result = {"ok": True, "code": "", "compiled": True, "waitStatus": 0,
                  "cpuNs": 1000, "stdoutBase64": "", "stderrBase64": "",
                  "feedbackBase64": "", "errors": 0, "warnings": 0}
        if operation in ("RUN_VALIDATOR", "CHECK_OUTPUT"):
            result["waitStatus"] = 42 << 8
        if operation == "RUN_REFERENCE":
            result["stdoutBase64"] = bridge.encoded(b"answer\n")
        if operation == "GRADE":
            result["stdoutBase64"] = bridge.encoded(b"AC 2.000000\n")
        return result

    def send(self, result):
        self.result = result


with tempfile.TemporaryDirectory() as directory:
    for name in bridge.TOOLS:
        path = Path(directory).resolve() / name
        path.write_bytes(b"inert tool marker, never executed")
        path.chmod(0o700)
        bridge.TOOLS[name] = path
    runtime = MockRuntime()
    bridge.verify(control, runtime)
    print(json.dumps({"portableOnly": True, "parts": runtime.result["parts"], "operations": runtime.operations}))
