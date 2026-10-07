#!/usr/bin/env python3
"""Finite recovery rehearsal on a new, network-isolated pinned PG container.

Never connects to an existing database, rewinds a schema, or claims live/PITR
recovery. Only inert synthetic data is copied into fresh isolated databases.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import tarfile
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
POLICY = {"log_statement": "none", "log_min_error_statement": "panic",
          "log_min_duration_statement": "-1", "log_min_duration_sample": "-1",
          "log_transaction_sample_rate": "0", "log_duration": "off",
          "log_min_messages": "panic", "log_error_verbosity": "terse",
          "log_parameter_max_length": "0", "log_parameter_max_length_on_error": "0"}
TABLES = ("license_evidence", "package_source_identities", "import_jobs", "import_items",
          "rejected_package_evidence", "operation_requests", "private_objects",
          "private_object_references", "schema_migrations", "migration_checksums")


def require(value, message):
    if not value:
        raise RuntimeError(message)


def digest(body):
    return hashlib.sha256(body).hexdigest()


def literal(value):
    return "'" + str(value).replace("'", "''") + "'"


def invoke(command, label, data=None, success=True, timeout=180):
    result = subprocess.run(command, input=data, capture_output=True, timeout=timeout)
    require((result.returncode == 0) == success, label + " failed")
    # No raw SQL, credential, private bytes, or subprocess diagnostics escape.
    return result.stdout


def verify_objects(directory, records):
    for record in records:
        path = directory / record["object_key"]
        require(path.resolve().is_relative_to(directory.resolve()) and path.is_file()
                and not path.is_symlink(), "private restore object missing or unsafe")
        body = path.read_bytes()
        require(digest(body) == record["sha256"] and len(body) == record["size_bytes"],
                "private restored bytes differ from database identity")


def restore_objects(archive, directory):
    directory.mkdir(mode=0o700)
    with tarfile.open(archive, "r:") as source:
        for member in source:
            require(member.isfile() and re.fullmatch(r"sha256/[0-9a-f]{2}/[0-9a-f]{64}", member.name)
                    and member.name.split("/")[1] == member.name.split("/")[2][:2]
                    and member.size <= 1 << 20, "private archive member is invalid")
            destination = directory / member.name
            destination.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            with destination.open("xb") as output:
                output.write(source.extractfile(member).read((1 << 20) + 1))
            destination.chmod(0o600)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", required=True)
    parser.add_argument("--image", required=True, help="exact local PG 17.10 sha256 image ID")
    parser.add_argument("--vendor", type=Path, default=ROOT / ".local/v02-qualified-candidate-context/service/vendor")
    parser.add_argument("--output", type=Path, default=ROOT / ".local/v02-db-recovery")
    args = parser.parse_args()
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", args.image), "exact PostgreSQL image identity required")
    output = args.output.resolve()
    require(output.is_relative_to(ROOT / ".local") and not output.exists(), "fresh ignored local evidence directory required")
    require(args.vendor.is_dir() and not args.vendor.is_symlink(), "prepared verified service vendor inputs required")
    migrations = sorted((ROOT / "migrations").glob("[0-9]*.up.sql"))
    require(len(migrations) == 5, "rehearsal targets the reviewed five-migration release")
    output.mkdir(mode=0o700, parents=True)
    docker = ["docker", "--context", args.context]
    container = "judge-db-recovery-" + secrets.token_hex(6)
    pg_metadata = json.loads(invoke(docker + ["image", "inspect", args.image], "inspect PostgreSQL image"))[0]
    require(pg_metadata["Os"] == "linux" and pg_metadata["Architecture"] == "amd64", "pinned Linux amd64 PG image required")
    image_lock = json.loads((ROOT / "docker/image.lock.json").read_bytes())
    go_image = image_lock["goBuilder"]
    require(re.fullmatch(r"golang:1\.26\.8-bookworm@sha256:[0-9a-f]{64}", go_image), "exact locked Go compiler image required")
    require(invoke(docker + ["run", "--rm", "--network", "none", go_image, "go", "version"], "locked Linux Go version").strip() == b"go version go1.26.8 linux/amd64", "unexpected Linux compiler version")
    canaries = ["recovery_credential_" + secrets.token_hex(24) for _ in range(3)]
    private_canary = "synthetic_private_recovery_" + secrets.token_hex(12)
    checks = []
    created = False
    with tempfile.TemporaryDirectory(prefix="db-recovery-build-", dir=ROOT / ".local") as temporary:
        work = Path(temporary)
        source, binaries = work / "source", work / "bin"
        source.mkdir()
        binaries.mkdir()
        for relative in ("cmd/judge-migrate", "internal/config", "internal/processguard", "internal/persistence/migrate", "migrations"):
            for path in (ROOT / relative).rglob("*"):
                if path.is_file() and path.suffix in (".go", ".sql"):
                    destination = source / path.relative_to(ROOT)
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(path, destination)
        for name in ("go.mod", "go.sum"):
            shutil.copyfile(ROOT / name, source / name)
        shutil.copytree(args.vendor, source / "vendor", symlinks=False)
        source_inventory = {path.relative_to(source).as_posix(): digest(path.read_bytes())
                            for path in sorted(source.rglob("*")) if path.is_file()}
        source_inventory_body = json.dumps(source_inventory, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        source_inventory_sha = digest(source_inventory_body)
        (output / "native-source-inventory.json").write_bytes(source_inventory_body)
        (output / "native-source-inventory.json").chmod(0o600)
        builder = invoke(docker + ["create", "--network", "none", "--env", "GOTOOLCHAIN=local",
                                  "--env", "CGO_ENABLED=0", "--env", "GOEXPERIMENT=", "--env", "GOAMD64=v1",
                                  "--workdir", "/src", go_image, "go", "build", "-mod=vendor", "-trimpath", "-buildvcs=false",
                                  "-o", "/judge-migrate", "./cmd/judge-migrate"], "create locked Linux migration builder").strip().decode()
        require(re.fullmatch(r"[0-9a-f]{64}", builder), "invalid disposable builder identity")
        try:
            invoke(docker + ["cp", str(source) + "/.", builder + ":/src"], "copy credential-free native migration source")
            invoke(docker + ["start", "--attach", builder], "native locked Linux migration build", timeout=300)
            invoke(docker + ["cp", builder + ":/judge-migrate", str(binaries / "judge-migrate")], "retain native migration executable")
        finally:
            invoke(docker + ["rm", "--force", "--volumes", builder], "disposable compiler cleanup")
        binary_sha = digest((binaries / "judge-migrate").read_bytes())
        shutil.copyfile(binaries / "judge-migrate", output / "judge-migrate")
        (output / "judge-migrate").chmod(0o600)
        environment = work / "credentials"
        lines = ["POSTGRES_PASSWORD=" + canaries[0], "JUDGE_MIGRATION_PASSWORD=" + canaries[1], "JUDGE_RUNTIME_PASSWORD=" + canaries[2],
                 "PGOPTIONS=" + " ".join("-c " + key + "=" + value for key, value in POLICY.items())]
        environment.write_text("\n".join(lines) + "\n")
        environment.chmod(0o600)
        phase = "database bootstrap"

        def sql(body, database="recovery_source", role="postgres", success=True):
            policy = ";".join("SET " + name + "=" + literal(value) for name, value in POLICY.items()) + ";" if role == "postgres" else ""
            result = subprocess.run(docker + ["exec", "-i", "--env-file", str(environment), "--env", "PGOPTIONS=" if role != "postgres" else lines[-1], container, "psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-U", role, "-d", database],
                                    input=(policy + body).encode(), capture_output=True, timeout=180)
            if (result.returncode == 0) != success:
                private = output / "sql-failure.log"
                private.write_bytes(result.stdout + result.stderr)
                private.chmod(0o600)
                raise RuntimeError("bounded recovery SQL " + phase + " " + database + "/" + role + " failed")
            return result.stdout

        def operator_script(name, database):
            return invoke(docker + ["exec", "--env-file", str(environment), container, "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", database, "-f", "/tmp/" + name], "exact recovery operator script")

        def native(database, action, ceiling=None, success=True):
            migration_environment = work / "migration-credentials"
            migration_environment.write_text("JUDGE_MIGRATION_DATABASE_URL=postgres://judge_migration:" + canaries[1] + "@127.0.0.1:5432/" + database + "?sslmode=disable\n")
            migration_environment.chmod(0o600)
            arguments = [action] + ([] if ceiling is None else ["-ceiling", str(ceiling)])
            # The container's operator PGOPTIONS include superuser-only logging
            # settings. The actual restricted migration login must not inherit
            # them; the native command verifies its own dedicated authority.
            result = subprocess.run(docker + ["exec", "--env-file", str(migration_environment), "--env", "PGOPTIONS=", container, "/tmp/judge-migrate", *arguments], capture_output=True, timeout=180)
            if (result.returncode == 0) != success:
                # Native CLI diagnostics are bounded, but retain them privately
                # instead of assuming future changes preserve that property.
                private = output / "native-failure.log"
                private.write_bytes(result.stdout + result.stderr)
                private.chmod(0o600)
                raise RuntimeError("native recovery migration " + action + " " + database + " ceiling " + str(ceiling) + " failed")
            return json.loads(result.stdout) if success else None

        def create_database(database):
            require(re.fullmatch(r"recovery_[a-z]+", database), "fixed rehearsal database name required")
            sql("CREATE DATABASE " + database + ";", database="postgres")
            sql("REVOKE ALL ON DATABASE " + database + " FROM PUBLIC;REVOKE ALL ON SCHEMA public FROM PUBLIC;", database=database)

        def snapshot(database):
            facts = {table: json.loads(sql("SELECT coalesce(jsonb_agg(row_data ORDER BY row_data::text),'[]') FROM (SELECT to_jsonb(t) row_data FROM judge." + table + " t) rows;", database).decode()) for table in TABLES}
            facts["triggers"] = json.loads(sql("SELECT jsonb_agg(jsonb_build_object('table',c.relname,'name',t.tgname,'enabled',t.tgenabled,'definition',pg_get_triggerdef(t.oid)) ORDER BY c.relname,t.tgname) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='judge' AND NOT t.tgisinternal;", database).decode())
            # Normalize names rather than comparing database-specific OIDs.
            facts["authority"] = json.loads(sql("""SELECT jsonb_build_object(
 'schema',(SELECT jsonb_build_object('owner',pg_get_userbyid(nspowner),'acl',nspacl::text) FROM pg_namespace WHERE nspname='judge'),
 'relations',(SELECT jsonb_agg(jsonb_build_object('name',c.relname,'kind',c.relkind,'owner',pg_get_userbyid(c.relowner),'acl',c.relacl::text) ORDER BY c.relname) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='judge'),
 'functions',(SELECT jsonb_agg(jsonb_build_object('name',p.oid::regprocedure::text,'owner',pg_get_userbyid(p.proowner),'acl',p.proacl::text) ORDER BY p.oid::regprocedure::text) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='judge'),
 'loginDefaults',(SELECT jsonb_agg(jsonb_build_object('role',r.rolname,'settings',s.setconfig) ORDER BY r.rolname) FROM pg_db_role_setting s JOIN pg_roles r ON r.oid=s.setrole JOIN pg_database d ON d.oid=s.setdatabase WHERE d.datname=current_database() AND r.rolname IN ('judge_migration','judge_runtime')));""", database).decode())
            return facts

        def restored_database(database):
            create_database(database)
            invoke(docker + ["exec", "--env-file", str(environment), container, "pg_restore", "--exit-on-error", "--single-transaction", "-U", "postgres", "-d", database, "/tmp/recovery.dump"], "fresh isolated database restore")
            operator_script("provision-db.sql", database)
            operator_script("grant-runtime.sql", database)
            require(native(database, "status") == final_status, "restored native ledger status differs")
            require(snapshot(database) == final_facts, "restored immutable facts, ledger/checksums or triggers differ")

        try:
            invoke(docker + ["run", "--detach", "--network", "none", "--name", container, "--env-file", str(environment), args.image,
                             "postgres", "-c", "log_statement=all", "-c", "log_min_duration_statement=0", "-c", "log_transaction_sample_rate=1",
                             "-c", "log_duration=on", "-c", "log_parameter_max_length=-1", "-c", "log_parameter_max_length_on_error=-1"], "disposable recovery PostgreSQL start")
            created = True
            for _ in range(60):
                result = subprocess.run(docker + ["exec", container, "pg_isready", "-U", "postgres"], capture_output=True)
                if result.returncode == 0:
                    break
                time.sleep(0.5)
            else:
                raise RuntimeError("disposable recovery PostgreSQL never became ready")
            version = sql("SHOW server_version;", database="postgres").strip().decode()
            require(version.startswith("17.10"), "PostgreSQL 17.10 required")
            for name in ("provision-db.sql", "grant-runtime.sql"):
                invoke(docker + ["cp", str(ROOT / "scripts" / name), container + ":/tmp/" + name], "copy exact recovery operator script")
            invoke(docker + ["cp", str(binaries / "judge-migrate"), container + ":/tmp/judge-migrate"], "copy measured native migration executable")
            create_database("recovery_source")
            operator_script("provision-db.sql", "recovery_source")
            baseline_status = native("recovery_source", "up", ceiling=1)
            require(baseline_status == {"initialized": True, "applied": 1, "available": 5, "dirty": False}, "unexpected ceiling-one migration status")
            phase = "immutable baseline fixture"
            values = [("source", (private_canary + " original source archive\n").encode()),
                      ("normalized", (private_canary + " normalized package\n").encode()),
                      ("log", (private_canary + " bounded raw rejection evidence\n").encode())]
            objects = {name: {"object_key": "sha256/" + digest(body)[:2] + "/" + digest(body), "sha256": digest(body), "size_bytes": len(body), "body": body} for name, body in values}
            license_id, source_id, job_id, item_id, rejected_id, request_id = [str(uuid.uuid4()) for _ in range(6)]
            revision = "a4e1d6f106879043eb30af640ba46d0fcbf8053f"
            problem_path, repository = "problems/recovery", "https://github.com/oj-lab/problem-packages"
            errors = json.dumps([{"code": "LICENSE_REVIEW_REQUIRED", "message": "Offline review required", "retryable": False}])
            provenance = json.dumps({"syntheticFixture": True, "sourceSha256": objects["source"]["sha256"]})
            source_hash = objects["source"]["sha256"]
            seed = "BEGIN;SET ROLE judge_migration;" + f"""
INSERT INTO judge.license_evidence(id,repository_url,source_revision,package_path,status,license_scope,notice,source_url,license_files,evidence)
VALUES({literal(license_id)},{literal(repository)},{literal(revision)},{literal(problem_path)},'REVIEW_REQUIRED','UNKNOWN',{literal(private_canary)},'','[]',{literal(provenance)});
INSERT INTO judge.package_source_identities(id,repository_url,source_revision,package_path,source_sha256)
VALUES({literal(source_id)},{literal(repository)},{literal(revision)},{literal(problem_path)},{literal(source_hash)});
INSERT INTO judge.import_jobs(id,request_id,request_hash,source,repository_url,source_revision,status,package_count,completed_package_count,error,finished_at)
VALUES({literal(job_id)},{literal(request_id)},{literal(digest(b'inert original import request'))},'OJ_LAB',{literal(repository)},{literal(revision)},'FAILED',1,1,{literal(errors[1:-1])},clock_timestamp());
INSERT INTO judge.import_items(id,import_job_id,ordinal,package_path,status,license_status,validation_status,errors)
VALUES({literal(item_id)},{literal(job_id)},1,{literal(problem_path)},'REJECTED','REVIEW_REQUIRED','PENDING',{literal(errors)});
INSERT INTO judge.rejected_package_evidence(id,import_item_id,repository_url,source_revision,package_path,failure_stage,source_archive_key,source_sha256,normalized_archive_key,normalized_sha256,license_evidence_id,provenance,source_metadata,adaptations,errors,validation_log_key,evidence_sha256)
VALUES({literal(rejected_id)},{literal(item_id)},{literal(repository)},{literal(revision)},{literal(problem_path)},'LICENSE_REVIEW',{literal(objects['source']['object_key'])},{literal(source_hash)},{literal(objects['normalized']['object_key'])},{literal(objects['normalized']['sha256'])},{literal(license_id)},{literal(provenance)},'{{"syntheticFixture":true}}','[]',{literal(errors)},{literal(objects['log']['object_key'])},{literal(digest(b'inert rejected evidence'))});
INSERT INTO judge.operation_requests(operation,request_id,request_hash,status,error)
VALUES('PUBLISH',{literal(str(uuid.uuid4()))},{literal(digest(b'inert failed publish request'))},'FAILED','{{"code":"TASK_NOT_FOUND","message":"Problem unavailable"}}');
COMMIT;"""
            sql(seed)
            original_facts = {table: json.loads(sql("SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]') FROM judge." + table + " t;").decode()) for table in TABLES[:6]}
            require(native("recovery_source", "up", ceiling=1) == baseline_status, "repeated baseline migration changed ledger")
            final_status = native("recovery_source", "up", ceiling=5)
            require(final_status == {"initialized": True, "applied": 5, "available": 5, "dirty": False}, "unexpected upgraded migration status")
            require(native("recovery_source", "up") == final_status, "repeated final migration changed ledger")
            phase = "private object registration"
            registration = "BEGIN;SET ROLE judge_migration;"
            for name, record in objects.items():
                registration += "INSERT INTO judge.private_objects(object_key,sha256,size_bytes) VALUES(" + ",".join([literal(record["object_key"]), literal(record["sha256"]), str(record["size_bytes"])]) + ");"
                registration += "INSERT INTO judge.private_object_references(object_key,owner_type,owner_id,role) VALUES(" + ",".join([literal(record["object_key"]), "'REJECTED'", literal(rejected_id), literal({"source": "SOURCE", "normalized": "NORMALIZED", "log": "LOG"}[name])]) + ");"
            sql(registration + "COMMIT;")
            operator_script("grant-runtime.sql", "recovery_source")
            final_facts = snapshot("recovery_source")
            require(all(final_facts[table] == rows for table, rows in original_facts.items()), "forward upgrade altered immutable baseline facts")
            checks.append("native ceiling1 ->5 and repeated application preserve immutable baseline history")
            archive = output / "private-objects.tar"
            with tarfile.open(archive, "w:") as target:
                for record in objects.values():
                    member = tarfile.TarInfo(record["object_key"])
                    member.size, member.mode, member.mtime = record["size_bytes"], 0o600, 0
                    target.addfile(member, io.BytesIO(record["body"]))
            archive.chmod(0o600)
            invoke(docker + ["exec", "--env-file", str(environment), container, "pg_dump", "--format=custom", "-U", "postgres", "-d", "recovery_source", "-f", "/tmp/recovery.dump"], "coordinated quiescent custom backup")
            invoke(docker + ["cp", container + ":/tmp/recovery.dump", str(output / "database.dump")], "retain synthetic database backup")
            (output / "database.dump").chmod(0o600)
            for database in ("recovery_restored", "recovery_corrupt", "recovery_dirty", "recovery_recovered"):
                phase = "fresh isolated restore"
                restored_database(database)
            checks.append("custom backup restored into fresh databases with exact facts, triggers, native ledger/checksums and owners")
            phase = "isolated failure injection"
            sql("UPDATE judge.migration_checksums SET sha256=repeat('0',64) WHERE version=1;", "recovery_corrupt")
            sql("UPDATE judge.schema_migrations SET dirty=true;", "recovery_dirty")
            for database in ("recovery_corrupt", "recovery_dirty"):
                before = snapshot(database)
                native(database, "status", success=False)
                native(database, "up", success=False)
                require(snapshot(database) == before, "failed migration inspection modified corrupt/dirty database")
            require(snapshot("recovery_recovered") == final_facts and snapshot("recovery_source") == final_facts, "isolated failure injection touched retained source or fresh recovery")
            checks.append("corrupt-checksum and dirty isolated clones reject status/up without repair; fresh backup restore remains healthy")
            for database in ("recovery_restored", "recovery_recovered"):
                phase = "restored authority checks"
                require(sql("SELECT 1;", database, role="judge_runtime").strip() == b"1", "runtime privilege checks require a working non-admin connection")
                for setting, expected in POLICY.items():
                    require(sql("SHOW " + setting + ";", database, role="judge_runtime").strip().decode() == expected, "restored runtime private logging policy differs")
                for statement in ("UPDATE judge.license_evidence SET notice='rewrite';", "UPDATE judge.package_source_identities SET source_sha256=repeat('0',64);", "UPDATE judge.rejected_package_evidence SET source_metadata='{}';", "UPDATE judge.operation_requests SET error='{}';"):
                    sql("SET ROLE judge_migration;" + statement, database, success=False)
                for statement in ("UPDATE judge.schema_migrations SET dirty=true;", "UPDATE judge.migration_checksums SET sha256=repeat('0',64);", "UPDATE judge.import_attempt_evidence SET provenance='{}';", "DELETE FROM judge.import_attempt_evidence;", "CREATE TABLE judge.forbidden_restore(id int);", "INSERT INTO judge.license_evidence(id,reviewed_by) VALUES(gen_random_uuid(),'ADMIN:spoof');"):
                    sql(statement, database, role="judge_runtime", success=False)
                safe = sql("SELECT bool_and(rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolinherit AND NOT rolreplication AND NOT rolbypassrls) FROM pg_roles WHERE rolname IN ('judge_migration','judge_runtime');", database).strip()
                require(safe == b"t", "restored role attributes widened")
            checks.append("restored immutable triggers and exact runtime roles reject history, ledger, approval and DDL mutations")
            records = final_facts["private_objects"]
            restored = output / "restored-private"
            restore_objects(archive, restored)
            verify_objects(restored, records)
            corrupted = output / "corrupt-private"
            restore_objects(archive, corrupted)
            (corrupted / records[0]["object_key"]).write_bytes(b"corrupt synthetic bytes")
            try:
                verify_objects(corrupted, records)
            except RuntimeError:
                pass
            else:
                raise RuntimeError("corrupt private archive bytes were accepted")
            verify_objects(restored, records)
            checks.append("coordinated private archive restoration binds every database key to exact bytes/hash/size; corrupted copy rejected")
            logs = subprocess.run(docker + ["logs", container], capture_output=True)
            require(logs.returncode == 0 and not any(value.encode() in logs.stdout + logs.stderr for value in canaries + [private_canary]), "private credential or evidence canary entered PostgreSQL logs")
            report = {"schemaVersion": 1, "scope": "DISPOSABLE_SYNTHETIC_QUIESCENT_BACKUP_RESTORE_ONLY",
                      "postgres": version, "postgresImageId": args.image, "goBuilderImage": go_image,
                      "nativeMigrationBinarySha256": binary_sha, "nativeMigrationBinaryPath": "judge-migrate",
                      "nativeMigrationSourceInventorySha256": source_inventory_sha, "nativeMigrationSourceInventoryPath": "native-source-inventory.json",
                      "operatorScriptChecksums": {name: digest((ROOT / "scripts" / name).read_bytes()) for name in ("provision-db.sql", "grant-runtime.sql")},
                      "migrationChecksums": {path.name: digest(path.read_bytes()) for path in migrations},
                      "baselineStatus": baseline_status, "restoredStatus": final_status,
                      "databaseDumpSha256": digest((output / "database.dump").read_bytes()),
                      "privateArchiveSha256": digest(archive.read_bytes()), "privateObjectCount": len(records), "checks": checks,
                      "limitations": "No running service writes, backend integration, shared database repair, live restore, PITR, or sandbox qualification."}
            (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
            print(json.dumps(report, indent=2))
        finally:
            if created:
                cleanup = subprocess.run(docker + ["rm", "--force", "--volumes", container], capture_output=True)
                require(cleanup.returncode == 0, "disposable recovery container cleanup failed")


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as error:
        raise SystemExit("Disposable database recovery qualification failed: " + str(error))
    except (OSError, ValueError, subprocess.TimeoutExpired):
        raise SystemExit("Disposable database recovery qualification failed; private process/SQL diagnostics were suppressed")
