#!/usr/bin/env python3
"""Required native checks with the exact verified SDK and no automatic resolver."""

import json
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    subprocess.run([sys.executable, "scripts/toolchain.py", "verify"], cwd=ROOT, check=True)
    version = json.loads((ROOT / "toolchain.lock.json").read_text())["goVersion"]
    sdk = ROOT / ".local" / "toolchains" / f"go{version}" / "go" / "bin"
    env = dict(os.environ, GOTOOLCHAIN="local", GOWORK="off", GOFLAGS="", GOEXPERIMENT="")
    sources = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=ROOT,
    ).split(b"\0")
    files = sorted({os.fsdecode(p) for p in sources if p.endswith(b".go")})
    if files:
        formatted = subprocess.check_output([str(sdk / "gofmt"), "-l", *files], cwd=ROOT, env=env, text=True)
        if formatted:
            print("Go formatting required:\n" + formatted, file=sys.stderr)
            return 1
        for command in [["vet", "-mod=readonly", "./..."], ["test", "-mod=readonly", "-race", "-count=1", "./..."], ["build", "-mod=readonly", "-trimpath", "./..."]]:
            subprocess.run([str(sdk / "go"), *command], cwd=ROOT, env=env, check=True)
        subprocess.run([sys.executable, "scripts/check-go-service-licenses.py"], cwd=ROOT, env=env, check=True)
        subprocess.run([sys.executable, "scripts/check-go-judge-licenses.py", "legal"], cwd=ROOT, env=env, check=True)
        subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_go_judge_license_review.py", "-v"], cwd=ROOT, env=env, check=True)
        subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_release_artifacts.py", "-v"], cwd=ROOT, env=env, check=True)
        subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_image_context.py", "-v"], cwd=ROOT, env=env, check=True)
        subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_image_layers.py", "-v"], cwd=ROOT, env=env, check=True)
        subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_image_gzip.py", "-v"], cwd=ROOT, env=env, check=True)
        subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_problemtools_wheel_audit.py", "-v"], cwd=ROOT, env=env, check=True)
        subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_workload_seccomp_review.py", "-v"], cwd=ROOT, env=env, check=True)
        subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_linux_import_capacity.py", "-v"], cwd=ROOT, env=env, check=True)
        subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_linux_runtime_crash.py", "-v"], cwd=ROOT, env=env, check=True)
        subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_linux_service_flow.py", "-v"], cwd=ROOT, env=env, check=True)
        subprocess.run(["node", "scripts/verify-canonical-golden.mjs"], cwd=ROOT, env=env, check=True)
        schema_python = ROOT / ".local" / "contract-schema-tests" / "bin" / "python"
        if not schema_python.is_file():
            print("Schema test environment missing; run make contract-test-setup", file=sys.stderr)
            return 1
        subprocess.run([str(schema_python), "scripts/test-contract-schema.py"], cwd=ROOT, env=env, check=True)
        subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_problemtools_bridge*.py", "-v"], cwd=ROOT, env=env, check=True)
        subprocess.run([sys.executable, "scripts/validation-tools.py", "check"], cwd=ROOT, env=env, check=True)
        subprocess.run([sys.executable, "scripts/validation-sources.py", "check"], cwd=ROOT, env=env, check=True)
        subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_validation_sources_review.py", "-v"], cwd=ROOT, env=env, check=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.SubprocessError):
        print("native checks failed", file=sys.stderr)
        sys.exit(1)
