#!/usr/bin/env python3
"""Qualify exact offline-review ACL scripts in a disposable pinned PG container.

No supplied database is reset; credentials and SQL diagnostics are never echoed.
This checks operator/database authority, not sandbox execution or legal judgment.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--context", required=True)
    parser.add_argument("--image", required=True, help="exact local sha256 image ID")
    args = parser.parse_args()
    if not args.image.startswith("sha256:") or len(args.image) != 71:
        raise RuntimeError("qualification requires an exact local image identity")
    root = Path(__file__).resolve().parents[1]
    docker = ["docker", "--context", args.context]
    container = "judge-license-acl-" + secrets.token_hex(6)
    canaries = ["license_credential_" + secrets.token_hex(24) for _ in range(4)]
    # Function-name errors must retain the entire canary under PostgreSQL's
    # 63-byte identifier limit, otherwise full-token log scans could miss leaks.
    receipt_canary = "private_receipt_" + secrets.token_hex(12)
    runtime_canary = "private_runtime_evidence_" + secrets.token_hex(12)
    results = []

    def invoke(command, label, data=None, success=True):
        result = subprocess.run(command, input=data, capture_output=True, text=True)
        if (result.returncode == 0) != success:
            raise RuntimeError(label + " failed")
        return result.stdout

    with tempfile.TemporaryDirectory(prefix="judge-license-acl-") as temporary:
        environment = Path(temporary) / "credentials"
        environment.write_text("\n".join([
            "POSTGRES_PASSWORD=" + canaries[0],
            "JUDGE_MIGRATION_PASSWORD=" + canaries[1],
            "JUDGE_RUNTIME_PASSWORD=" + canaries[2],
            "JUDGE_LICENSE_REVIEW_PASSWORD=" + canaries[3],
        ]) + "\n")
        environment.chmod(0o600)
        created = False
        try:
            invoke(docker + ["run", "--detach", "--name", container,
                            "--network", "none", "--env-file", str(environment),
                            args.image, "postgres", "-c", "log_statement=all",
                            "-c", "log_min_duration_statement=0",
                            "-c", "log_min_duration_sample=0",
                            "-c", "log_statement_sample_rate=1",
                            "-c", "log_transaction_sample_rate=1",
                            "-c", "log_duration=on",
                            "-c", "log_parameter_max_length=-1",
                            "-c", "log_parameter_max_length_on_error=-1",
                            "-c", "log_error_verbosity=verbose",
                            "-c", "log_min_error_statement=error"], "container start")
            created = True
            for _ in range(60):
                # The image's temporary initialization server accepts only Unix
                # sockets. Wait for the final TCP listener before bootstrap SQL.
                ready = subprocess.run(docker + ["exec", container, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"], capture_output=True)
                if ready.returncode == 0:
                    break
                time.sleep(0.5)
            else:
                raise RuntimeError("disposable PostgreSQL readiness failed")

            phase = "database bootstrap"

            def sql(body, role="postgres", success=True, database="judge_qualification"):
                prefix = ""
                if role == "postgres":
                    prefix = ("SET log_statement='none'; SET log_min_error_statement='panic'; "
                              "SET log_min_duration_statement=-1; SET log_min_duration_sample=-1; "
                              "SET log_duration=off; SET log_parameter_max_length=0; "
                              "SET log_parameter_max_length_on_error=0; SET log_transaction_sample_rate=0; "
                              "SET log_error_verbosity='terse'; SET log_min_messages='panic'; ")
                return invoke(docker + ["exec", "-i", container, "psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-U", role, "-d", database],
                              "bounded SQL authority check: " + phase + " / " + role, prefix + body, success)

            sql("CREATE DATABASE judge_qualification;", database="postgres")
            sql("REVOKE ALL ON DATABASE judge_qualification FROM PUBLIC; REVOKE ALL ON SCHEMA public FROM PUBLIC;")
            for name in ["provision-db.sql", "grant-runtime.sql", "grant-license-reviewer.sql"]:
                invoke(docker + ["cp", str(root / "scripts" / name), container + ":/tmp/" + name], "copy exact operator script")

            def script(name, success=True):
                return invoke(docker + ["exec", "--env-file", str(environment), container, "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "judge_qualification", "-f", "/tmp/" + name],
                              "exact operator script " + name, success=success)

            script("provision-db.sql")
            phase = "forward migration"
            for migration in sorted((root / "migrations").glob("[0-9]*.up.sql")):
                invoke(docker + ["cp", str(migration), container + ":/tmp/" + migration.name], "copy forward migration")
                sql("SET ROLE judge_migration; " + migration.read_text())
            # Native migration ledgers are created by judge-migrate, separately
            # from SQL files; create equivalent privilege targets for this ACL test.
            sql("SET ROLE judge_migration; CREATE TABLE judge.schema_migrations(version bigint,dirty boolean); CREATE TABLE judge.migration_checksums(version bigint,sha256 text);")
            script("grant-runtime.sql")
            script("grant-license-reviewer.sql")
            script("grant-runtime.sql")
            script("grant-license-reviewer.sql")
            results.append("fresh and repeated exact scripts")

            phase = "runtime automatic evidence"
            automatic = """INSERT INTO judge.license_evidence(id,repository_url,source_revision,package_path,status,license_scope,notice,source_url,license_files,evidence)
 VALUES('00000000-0000-0000-0000-000000000001','https://github.com/oj-lab/problem-packages',repeat('a',40),'problems/fixture','REVIEW_REQUIRED','UNKNOWN','RUNTIME_PRIVATE_NOTICE','','[]','{"automaticSuggestion":true}');""".replace("RUNTIME_PRIVATE_NOTICE", runtime_canary)
            sql(automatic, role="judge_runtime")
            phase = "runtime forged verified evidence"
            forged = automatic.replace("000000000001", "000000000002").replace("'REVIEW_REQUIRED'", "'VERIFIED'")
            sql(forged, role="judge_runtime", success=False)
            phase = "runtime actor column denial"
            actor_columns = """INSERT INTO judge.license_evidence(id,repository_url,source_revision,package_path,status,license_scope,notice,source_url,license_files,evidence,reviewed_by,reviewed_at)
 VALUES(gen_random_uuid(),'https://github.com/oj-lab/problem-packages',repeat('a',40),'problems/fixture','VERIFIED','PACKAGE','notice','source','[{"path":"LICENSE","sha256":"fixture","spdxId":null}]','{"review":true}','caller:ADMIN',now());"""
            sql(actor_columns, role="judge_runtime", success=False)
            phase = "runtime private invalid function denial"
            sql("SELECT nonexistent_" + runtime_canary + "();", role="judge_runtime", success=False)
            results.append("runtime automatic evidence allowed; VERIFIED and actor fields denied")

            approved = actor_columns.replace("gen_random_uuid()", "'00000000-0000-0000-0000-000000000003'").replace("'caller:ADMIN'", "'ADMIN:fixture'").replace(
                "'{\"review\":true}'", "'{\"review\":\"" + receipt_canary
                + "\",\"sourceSha256\":\"" + "a" * 64
                + "\",\"normalizedSha256\":\"" + "b" * 64 + "\"}'")
            phase = "reviewer approved receipt"
            sql(approved, role="judge_license_reviewer")

            # This is inert ACL data. Actual byte/archive binding is separately
            # checked by qualify-db-recovery.py and the storage integration suite.
            phase = "runtime append interrupted validation attempt"
            attempt = """BEGIN;
INSERT INTO judge.private_objects(object_key,sha256,size_bytes)
 VALUES('sha256/aa/'||repeat('a',64),repeat('a',64),1),
 ('sha256/bb/'||repeat('b',64),repeat('b',64),1),
 ('sha256/cc/'||repeat('c',64),repeat('c',64),1);
INSERT INTO judge.import_jobs(id,request_id,request_hash,source,repository_url,source_revision,status,
 package_count,completed_package_count,lease_owner,lease_expires_at,attempt_count,started_at)
 VALUES('00000000-0000-0000-0000-000000000004','00000000-0000-0000-0000-000000000005',repeat('d',64),
 'OJ_LAB','https://github.com/oj-lab/problem-packages',repeat('a',40),'RUNNING',1,0,
 '00000000-0000-0000-0000-000000000006',clock_timestamp()+interval '5 minutes',0,clock_timestamp());
INSERT INTO judge.import_items(id,import_job_id,ordinal,package_path,status,license_status,validation_status)
 VALUES('00000000-0000-0000-0000-000000000007','00000000-0000-0000-0000-000000000004',1,
 'problems/fixture','PENDING','VERIFIED','PENDING');
INSERT INTO judge.import_attempt_evidence(id,import_item_id,attempt_token,recovery_count,repository_url,
 source_revision,package_path,failure_stage,source_archive_key,source_sha256,normalized_archive_key,
 normalized_sha256,license_evidence_id,provenance,source_metadata,adaptations,errors,validation_log_key,evidence_sha256)
 VALUES('00000000-0000-0000-0000-000000000008','00000000-0000-0000-0000-000000000007',
 '00000000-0000-0000-0000-000000000006',0,'https://github.com/oj-lab/problem-packages',repeat('a',40),
 'problems/fixture','VALIDATION_FAILED','sha256/aa/'||repeat('a',64),repeat('a',64),
 'sha256/bb/'||repeat('b',64),repeat('b',64),'00000000-0000-0000-0000-000000000003',
 '{"complete":false,"validationEvidenceChunks":[],"fencingToken":"00000000-0000-0000-0000-000000000006","privateFixture":"RUNTIME_PRIVATE_NOTICE"}',
 '{"syntheticAclFixture":true}','[]','[{"code":"VALIDATION_FAILED","message":"Fixture interrupted","retryable":true}]',
 'sha256/cc/'||repeat('c',64),repeat('e',64));
INSERT INTO judge.private_object_references(object_key,owner_type,owner_id,role)
 VALUES('sha256/aa/'||repeat('a',64),'IMPORT_ATTEMPT','00000000-0000-0000-0000-000000000008','SOURCE'),
 ('sha256/bb/'||repeat('b',64),'IMPORT_ATTEMPT','00000000-0000-0000-0000-000000000008','NORMALIZED'),
 ('sha256/cc/'||repeat('c',64),'IMPORT_ATTEMPT','00000000-0000-0000-0000-000000000008','LOG');
COMMIT;""".replace("RUNTIME_PRIVATE_NOTICE", runtime_canary)
            sql(attempt, role="judge_runtime")
            if sql("SELECT count(*) FROM judge.import_attempt_evidence WHERE id='00000000-0000-0000-0000-000000000008';", role="judge_runtime").strip() != "1":
                raise RuntimeError("runtime append did not retain the attempt evidence")
            for role in ("judge_runtime", "judge_license_reviewer"):
                phase = "attempt evidence mutation authority denial"
                if sql("SELECT has_table_privilege(current_user,'judge.import_attempt_evidence','UPDATE') OR has_table_privilege(current_user,'judge.import_attempt_evidence','DELETE');", role=role).strip() != "f":
                    raise RuntimeError("attempt evidence mutation authority widened")
                sql("UPDATE judge.import_attempt_evidence SET source_metadata='{}' WHERE id='00000000-0000-0000-0000-000000000008';", role=role, success=False)
                sql("DELETE FROM judge.import_attempt_evidence WHERE id='00000000-0000-0000-0000-000000000008';", role=role, success=False)
            phase = "attempt evidence immutable retained row"
            if sql("SELECT count(*) FROM judge.import_attempt_evidence WHERE id='00000000-0000-0000-0000-000000000008' AND source_metadata='{" + '"syntheticAclFixture":true' + "}'::jsonb;").strip() != "1":
                raise RuntimeError("denied mutation changed immutable attempt evidence")
            results.append("runtime appends live fenced attempt evidence and owner references; runtime/reviewer UPDATE and DELETE denied")

            phase = "reviewer retained facts"
            sql("SELECT count(*) FROM judge.license_evidence;SELECT count(*) FROM judge.rejected_package_evidence;SELECT count(*) FROM judge.private_objects;", role="judge_license_reviewer")
            for denied in [
                "UPDATE judge.license_evidence SET notice='rewrite';",
                "UPDATE judge.catalog_state SET catalog_version=catalog_version+1;",
                "INSERT INTO judge.judge_tasks(id) VALUES(gen_random_uuid());",
                "UPDATE judge.schema_migrations SET version=999;",
                "CREATE TABLE judge.forbidden(id integer);",
            ]:
                phase = "reviewer forbidden write"
                sql(denied, role="judge_license_reviewer", success=False)
            # Failure diagnostics also must not reveal private receipt text.
            phase = "reviewer private invalid function denial"
            sql("SELECT nonexistent_" + receipt_canary + "();", role="judge_license_reviewer", success=False)
            phase = "reviewer private check violation denial"
            sql(approved.replace("'VERIFIED'", "'INVALID'"), role="judge_license_reviewer", success=False)
            results.append("reviewer inserts append-only evidence and reads retained facts; business/DDL/ledger writes denied")

            profiles = [
                ("ALTER ROLE judge_license_reviewer SUPERUSER;", "ALTER ROLE judge_license_reviewer NOSUPERUSER;"),
                ("CREATE ROLE license_unsafe;GRANT license_unsafe TO judge_license_reviewer;", "REVOKE license_unsafe FROM judge_license_reviewer;DROP ROLE license_unsafe;"),
                ("CREATE ROLE license_unsafe;GRANT judge_license_reviewer TO license_unsafe;", "REVOKE judge_license_reviewer FROM license_unsafe;DROP ROLE license_unsafe;"),
                ("GRANT UPDATE(catalog_version) ON judge.catalog_state TO judge_license_reviewer;", "REVOKE UPDATE(catalog_version) ON judge.catalog_state FROM judge_license_reviewer;"),
                ("ALTER TABLE judge.license_evidence OWNER TO judge_license_reviewer;", "ALTER TABLE judge.license_evidence OWNER TO judge_migration;"),
            ]
            for unsafe, restore in profiles:
                phase = "unsafe reviewer profile setup"
                sql(unsafe)
                script("grant-license-reviewer.sql", success=False)
                phase = "unsafe reviewer profile restoration"
                sql(restore)
                script("grant-license-reviewer.sql")
            results.append("five unsafe existing role profiles refused without accepting widened authority")

            logs = invoke(docker + ["logs", container], "read private qualification logs")
            # Docker may write logs on stderr as well. Never forward raw logs.
            captured = subprocess.run(docker + ["logs", container], capture_output=True, text=True)
            logs += captured.stdout + captured.stderr
            if any(value in logs for value in canaries + [receipt_canary, runtime_canary]):
                raise RuntimeError("private credential or receipt canary entered PostgreSQL logs")
            phase = "qualification server version"
            version = sql("SHOW server_version;").strip()
            results.append("credential, runtime private evidence, and successful/failed receipt canaries absent with server statement, duration, and transaction sampling enabled")
            print(json.dumps({"postgres": version, "imageId": args.image, "checks": results}, indent=2))
        finally:
            if created:
                subprocess.run(docker + ["rm", "--force", "--volumes", container], capture_output=True)


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as error:
        raise SystemExit("License reviewer ACL qualification failed: " + str(error))
    except OSError:
        raise SystemExit("License reviewer ACL qualification failed: local process or file unavailable")
