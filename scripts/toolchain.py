#!/usr/bin/env python3
"""Install only the repository's verified Go SDK; never use a floating resolver."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["install", "verify"])
    args = parser.parse_args()
    if not hasattr(tarfile, "data_filter"):
        raise ValueError("SDK extraction requires Python tarfile.data_filter (Python 3.11.8+)")
    lock = json.loads((ROOT / "toolchain.lock.json").read_text())
    version = lock["goVersion"]
    system = platform.system().lower()
    arch = {"x86_64": "amd64", "arm64": "arm64", "aarch64": "arm64"}.get(platform.machine())
    entry = lock["archives"].get(f"{system}-{arch}")
    if entry is None:
        raise ValueError("unsupported Go SDK platform")
    target = ROOT / ".local" / "toolchains" / f"go{version}"
    env = dict(os.environ, GOTOOLCHAIN="local")
    if not (target / "go" / "bin" / "go").exists():
        if args.command == "verify":
            raise ValueError("locked SDK missing; run make toolchain")
        target.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=target.parent) as staging:
            archive = Path(staging) / "sdk.tar.gz"
            with urllib.request.urlopen("https://go.dev/dl/" + entry["filename"], timeout=60) as response:
                with archive.open("wb") as output:
                    shutil.copyfileobj(response, output)
            if hashlib.sha256(archive.read_bytes()).hexdigest() != entry["sha256"]:
                raise ValueError("Go SDK checksum mismatch")
            unpacked = Path(staging) / "unpacked"
            unpacked.mkdir()
            # Archive identity is checked before extraction; data filter also rejects escapes.
            with tarfile.open(archive) as package:
                package.extractall(unpacked, filter="data")
            if target.exists():
                raise ValueError("SDK destination already exists; preserve it and inspect manually")
            unpacked.rename(target)
    actual = subprocess.check_output([str(target / "go" / "bin" / "go"), "version"], env=env, text=True).strip()
    if actual != f"go version go{version} {system}/{arch}":
        raise ValueError("installed Go SDK version does not match lock")
    print(actual)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, tarfile.TarError, subprocess.SubprocessError) as exc:
        print(f"toolchain: {type(exc).__name__}; installation/verification failed", file=sys.stderr)
        sys.exit(1)
