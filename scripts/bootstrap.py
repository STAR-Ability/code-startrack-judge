#!/usr/bin/env python3
"""Portable infrastructure helpers; no application or migration implementation."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
ENV_FILE = ROOT / ".env"
DEFAULTS = {
    "COMPOSE_PROJECT_NAME": "startrack-judge-dev",
    "POSTGRES_USER": "judge_dev",
    "POSTGRES_DB": "judge_dev",
    "POSTGRES_PASSWORD": "",
    "POSTGRES_PORT": "15432",
    "INFRA_WAIT_SECONDS": "90",
}


def fail(message: str) -> None:
    raise RuntimeError(message)


def run(arguments: list[str], *, environment: dict[str, str] | None = None) -> None:
    subprocess.run(arguments, cwd=ROOT, env=environment, check=True)


def check_tools() -> None:
    if sys.version_info < (3, 11):
        fail("Python >=3.11 is required for foundation tooling.")
    for executable in ("git", "make", "docker"):
        if shutil.which(executable) is None:
            fail(f"Missing {executable}; see docs/development/getting-started.md.")
    version = subprocess.run(
        ["docker", "compose", "version", "--short"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    match = re.match(r"v?(\d+)\.(\d+)", version)
    if match is None or tuple(map(int, match.groups())) < (2, 20):
        fail("Docker Compose >=2.20 is required for up --wait.")
    print(f"Python {sys.version_info.major}.{sys.version_info.minor}; git/make/Docker CLI available; Compose {version}.", flush=True)


def create_environment() -> None:
    if ENV_FILE.exists() or ENV_FILE.is_symlink():
        print("Existing .env retained.")
        return
    values = dict(DEFAULTS, POSTGRES_PASSWORD=secrets.token_urlsafe(32))
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(ENV_FILE, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        output.write("# Generated local development settings. Never commit this file.\n")
        output.write("".join(f"{key}={value}\n" for key, value in values.items()))
    print("Created .env with a generated local password and mode 0600.")


def read_environment() -> dict[str, str]:
    if ENV_FILE.is_symlink() or not ENV_FILE.is_file():
        fail("A regular local .env is required; run make bootstrap.")
    if stat.S_IMODE(ENV_FILE.stat().st_mode) & 0o077:
        fail(".env is readable by other users; run chmod 600 .env.")
    values: dict[str, str] = {}
    for line_number, line in enumerate(ENV_FILE.read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or key not in DEFAULTS or key in values:
            fail(f"Invalid or duplicate setting in .env line {line_number}; see .env.example.")
        if not re.fullmatch(r"[A-Za-z0-9_.:-]+", value):
            fail(f"Setting {key} must use simple unquoted characters; see the environment reference.")
        values[key] = value
    if set(values) != set(DEFAULTS):
        fail(".env must include every setting in .env.example.")
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", values["COMPOSE_PROJECT_NAME"]):
        fail("COMPOSE_PROJECT_NAME must be a lowercase Compose project name.")
    for key in ("POSTGRES_USER", "POSTGRES_DB"):
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,62}", values[key]):
            fail(f"{key} must be an identifier starting with a letter, up to 63 characters.")
    password = values["POSTGRES_PASSWORD"]
    if len(password) < 32 or password.startswith("GENERATED_"):
        fail("POSTGRES_PASSWORD must be a generated local secret of at least 32 characters; .env.example is not usable as credentials.")
    for key, minimum, maximum in (("POSTGRES_PORT", 1024, 65535), ("INFRA_WAIT_SECONDS", 1, 600)):
        if not values[key].isdigit() or not minimum <= int(values[key]) <= maximum:
            fail(f"{key} must be an integer in {minimum}..{maximum}.")
    return values


def compose(arguments: list[str], values: dict[str, str]) -> None:
    # Explicit local settings win over incidental parent-shell Compose variables.
    environment = dict(os.environ, **values)
    run(["docker", "compose", "--progress", "quiet", "--env-file", str(ENV_FILE), "--file", str(ROOT / "compose.yaml"), *arguments], environment=environment)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("bootstrap", "up", "down", "db-version", "migration-status"))
    command = parser.parse_args().command
    if command == "migration-status":
        migrations = sorted((ROOT / "migrations").glob("*.sql"))
        if migrations:
            # Repository availability is distinct from a connected database's
            # applied/checksummed history. The native runner owns that history.
            numbers = []
            for migration in migrations:
                match = re.fullmatch(r"([0-9]{6})_[a-z0-9_]+\.up\.sql", migration.name)
                if match is None:
                    fail("Repository migration filename is invalid; run make check.")
                numbers.append(int(match.group(1)))
            if numbers != list(range(1, len(numbers) + 1)):
                fail("Repository migration identities are not contiguous; run make check.")
            print(f"Repository migration level: {len(numbers)}. Available forward files only; use make database-status for applied history/checksums.")
            return
        print("Repository migration level: 0. No SQL migrations shipped; database tracking and the native runner are not implemented yet.")
        return
    check_tools()
    if command == "bootstrap":
        create_environment()
        values = read_environment()
        compose(["config", "--quiet"], values)
        print("Compose configuration valid. Start your Docker engine, then run make infra-up.")
        return
    values = read_environment()
    if command == "up":
        print("Starting PostgreSQL; the pinned image download and health check may take time.", flush=True)
        compose(["up", "--detach", "--wait", "--wait-timeout", values["INFRA_WAIT_SECONDS"]], values)
        print("PostgreSQL is healthy. No judge schema or business service is installed.")
    elif command == "down":
        compose(["down"], values)
        print("Infrastructure stopped; the named database volume was retained.")
    elif command == "db-version":
        compose(["exec", "--no-TTY", "postgres", "psql", "--username", values["POSTGRES_USER"], "--dbname", values["POSTGRES_DB"], "--tuples-only", "--no-align", "--command", "SELECT version();"], values)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, subprocess.CalledProcessError) as error:
        # No env values or rendered Compose configuration in errors.
        print(f"Infrastructure command failed: {error}", file=sys.stderr)
        sys.exit(1)
