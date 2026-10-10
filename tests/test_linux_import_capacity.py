"""Portable negative checks for the trusted capacity runner's TLS inputs."""

import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "linux_import_capacity", ROOT / "scripts/linux-import-capacity.py"
)
CAPACITY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CAPACITY)

# A synthetic public CA. Its ephemeral signing key was discarded at generation.
PUBLIC_CA = b"""-----BEGIN CERTIFICATE-----
MIIBtDCCAVugAwIBAgIUTrSdvRZZExuSThnU0qANEaYJ0fAwCgYIKoZIzj0EAwIw
LzEtMCsGA1UEAwwkU3RhcnRyYWNrIFN5bnRoZXRpYyBDYXBhY2l0eSBUZXN0IENB
MCAXDTI2MTAwNzIyMzAyM1oYDzIxMjYwOTEzMjIzMDIzWjAvMS0wKwYDVQQDDCRT
dGFydHJhY2sgU3ludGhldGljIENhcGFjaXR5IFRlc3QgQ0EwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAAS/82wjXFqCCEKbW75pwboGLjMVVWDL/p9Iue/nLez7vIZd
8eBGDs+Bu3q+tlMvjvaTM8M6u1M2ig40qQOQnNx2o1MwUTAdBgNVHQ4EFgQUG4hn
BrYiBZJHh0GnmTRLA93NjNMwHwYDVR0jBBgwFoAUG4hnBrYiBZJHh0GnmTRLA93N
jNMwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiB7mEq1rB4RUFwZ
64fNUIUH5pD8y6RS1bFJHDYc4juaOgIgUC0Jbz6hwy9qi5C8DQiZ0Y7BHsxpbfyb
3V+tLi5iH2E=
-----END CERTIFICATE-----
"""
TLS_QUERY = "sslmode=verify-full&sslrootcert=%2Fopt%2Fstartrack%2Fdb-ca.crt"


class CapacityTLSInputsTests(unittest.TestCase):
    def setUp(self):
        # Keep real permissions and inodes, including every ancestor's mode.
        # A checkout under /tmp would correctly fail the safe-parent requirement.
        self.temporary = tempfile.TemporaryDirectory(prefix="capacity-tls-", dir=ROOT)
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.owners = {}
        original_lstat = Path.lstat

        def portable_root_owner(path, *args, **kwargs):
            facts = original_lstat(path, *args, **kwargs)
            values = list(facts)
            values[stat.ST_UID] = self.owners.get(path, 0)
            return os.stat_result(values)

        ownership = patch.object(Path, "lstat", portable_root_owner)
        ownership.start()
        self.addCleanup(ownership.stop)

    def write(self, name, contents, mode):
        path = self.directory / name
        path.write_bytes(contents)
        path.chmod(mode)
        return path

    def dsn(self, query=TLS_QUERY, role="judge_runtime"):
        # Synthetic credentials are never printed by these tests.
        return (
            "postgresql://" + role + ":synthetic@startrack-capacity-postgres:5432/"
            "judge_capacity_tls_fixture?" + query
        ).encode()

    def test_each_role_accepts_only_the_fixed_verified_transport(self):
        for role in ("judge_runtime", "judge_license_reviewer"):
            with self.subTest(role=role):
                path = self.write(role + ".dsn", self.dsn(role=role), 0o400)
                value, database = CAPACITY.trusted_dsn(path, role)
                self.assertTrue(value.encode() == self.dsn(role=role))
                self.assertEqual(database, "/judge_capacity_tls_fixture")

    def test_tls_downgrades_duplicates_and_client_key_options_are_rejected(self):
        queries = (
            "sslrootcert=%2Fopt%2Fstartrack%2Fdb-ca.crt",
            "sslmode=disable&sslrootcert=%2Fopt%2Fstartrack%2Fdb-ca.crt",
            "sslmode=require&sslrootcert=%2Fopt%2Fstartrack%2Fdb-ca.crt",
            "sslmode=verify-ca&sslrootcert=%2Fopt%2Fstartrack%2Fdb-ca.crt",
            "sslmode=verify-full",
            "sslmode=verify-full&sslrootcert=%2Ftmp%2Fother-ca.crt",
            TLS_QUERY + "&sslmode=verify-full",
            TLS_QUERY + "&sslmode=",
            TLS_QUERY + "&sslrootcert=",
            TLS_QUERY + "&sslcert=%2Ftmp%2Fclient.crt",
            TLS_QUERY + "&sslkey=%2Ftmp%2Fclient.key",
            TLS_QUERY + "&sslcert=",
            TLS_QUERY + "&sslkey=",
        )
        for index, query in enumerate(queries):
            with self.subTest(case=index):
                path = self.write(str(index) + ".dsn", self.dsn(query), 0o400)
                with self.assertRaisesRegex(ValueError, "disposable_database_transport_invalid"):
                    CAPACITY.trusted_dsn(path, "judge_runtime")

    def test_ca_returns_only_the_public_file_identity_and_digest(self):
        path = self.write("ca.crt", PUBLIC_CA, 0o444)
        actual_path, digest = CAPACITY.trusted_public_ca(path)
        self.assertEqual(actual_path, path)
        self.assertEqual(digest, hashlib.sha256(PUBLIC_CA).hexdigest())

    def test_ca_rejects_private_keys_bundles_garbage_and_non_x509_pem(self):
        private_label = b" ".join((b"PRIVATE", b"KEY"))
        private_pem = b"-----BEGIN " + private_label + b"-----\nAAAA\n-----END " + private_label + b"-----\n"
        contents = (
            private_pem,
            PUBLIC_CA + PUBLIC_CA,
            PUBLIC_CA + b"unexpected trailing data\n",
            b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
            b"-----BEGIN CERTIFICATE-----\nA===\n-----END CERTIFICATE-----\n",
        )
        for index, body in enumerate(contents):
            with self.subTest(case=index):
                path = self.write(str(index) + ".crt", body, 0o444)
                with self.assertRaisesRegex(ValueError, "public_ca_certificate_required"):
                    CAPACITY.trusted_public_ca(path)

    def inputs(self):
        return (
            ("ca.crt", PUBLIC_CA, 0o444, CAPACITY.trusted_public_ca, "root_public_ca_facility_invalid"),
            ("runtime.dsn", self.dsn(), 0o400, lambda path: CAPACITY.trusted_dsn(path, "judge_runtime"), "root_secret_facility_invalid"),
        )

    def test_leaf_ownership_permissions_size_and_hard_links_are_real(self):
        for name, body, mode, verify, failure in self.inputs():
            for variant in ("owner", "writable", "private_ca", "empty", "oversize", "hardlink"):
                if variant == "private_ca" and name.endswith(".dsn"):
                    continue
                with self.subTest(input=name, variant=variant):
                    contents = b"" if variant == "empty" else b"x" * 65537 if variant == "oversize" else body
                    path = self.write(variant + "-" + name, contents, mode)
                    if variant == "owner":
                        self.owners[path] = 20000
                    elif variant == "writable":
                        path.chmod(mode | 0o200)
                    elif variant == "private_ca":
                        path.chmod(0o400)
                    elif variant == "hardlink":
                        os.link(path, path.with_name(path.name + ".link"))
                    with self.assertRaisesRegex(ValueError, failure):
                        verify(path)

    def test_unsafe_parent_owner_mode_and_symlink_are_rejected(self):
        for name, body, mode, verify, failure in self.inputs():
            path = self.write(name, body, mode)
            self.owners[self.directory] = 20000
            with self.subTest(input=name, variant="owner"), self.assertRaisesRegex(ValueError, failure):
                verify(path)
            self.owners.clear()
            self.directory.chmod(0o777)
            with self.subTest(input=name, variant="mode"), self.assertRaisesRegex(ValueError, failure):
                verify(path)
            self.directory.chmod(0o700)
            alias = self.directory / (name + ".symlink")
            alias.symlink_to(path)
            with self.subTest(input=name, variant="leaf-symlink"), self.assertRaisesRegex(ValueError, failure):
                verify(alias)
            parent_alias = self.directory / (name + ".parent-symlink")
            parent_alias.symlink_to(self.directory, target_is_directory=True)
            with self.subTest(input=name, variant="parent-symlink"), self.assertRaisesRegex(ValueError, failure):
                verify(parent_alias / name)

    def test_file_replacement_between_inspection_and_open_is_rejected(self):
        original_open = os.open
        for name, body, mode, verify, failure in self.inputs():
            path = self.write(name, body, mode)
            replacement = self.write(name + ".replacement", body, mode)

            def replace_then_open(candidate, flags, *args, **kwargs):
                if candidate == path:
                    os.replace(replacement, path)
                return original_open(candidate, flags, *args, **kwargs)

            with self.subTest(input=name), patch.object(CAPACITY.os, "open", replace_then_open):
                with self.assertRaisesRegex(ValueError, failure):
                    verify(path)


if __name__ == "__main__":
    unittest.main()
