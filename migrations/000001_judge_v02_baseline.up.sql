-- Issue #6: V0.2 judge-owned schema, contract 0.2.0 and additive Q-005 clarification.
-- Atomic transaction; native runner inserts the immutable checksum before COMMIT.
-- Compatibility: first business schema; no previous application/schema exists.
-- Operational prerequisite: separately provisioned non-admin migration owner of
-- judge. Runtime grants are provisioned separately; no backend/algorithm access.
-- JSON deep schemas and canonical hashes remain owner-validated; SQL enforces
-- shape, local identity, terminal consistency and immutable historical facts.
BEGIN;

CREATE DOMAIN judge.sha256_hex AS char(64) CHECK (VALUE ~ '^[0-9a-f]{64}$');
CREATE DOMAIN judge.commit_hex AS char(40) CHECK (VALUE ~ '^[0-9a-f]{40}$');
CREATE DOMAIN judge.safe_nonnegative AS bigint CHECK (VALUE BETWEEN 0 AND 9007199254740991);

CREATE FUNCTION judge.valid_package_path(value text) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT AS $$
 SELECT value ~ '^problems/[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$'
 AND value !~ '(^|/)[.]{1,2}(/|$)'
$$;
CREATE FUNCTION judge.unique_nonnull_texts(value text[]) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT AS $$
 SELECT array_position(value,NULL) IS NULL
 AND cardinality(value) = (SELECT count(DISTINCT item) FROM unnest(value) item)
$$;
CREATE FUNCTION judge.valid_validation_results(value jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE STRICT AS $$
DECLARE checkpoint text; section jsonb; entry jsonb;
BEGIN
 IF jsonb_typeof(value)<>'object' THEN RETURN false; END IF;
 IF (SELECT count(*) FROM jsonb_object_keys(value))<>5 THEN RETURN false; END IF;
 FOREACH checkpoint IN ARRAY ARRAY['structure','statement','testData','validators','referenceSolutions'] LOOP
  section:=value->checkpoint;
  IF section IS NULL OR jsonb_typeof(section)<>'object' THEN RETURN false; END IF;
  IF (SELECT count(*) FROM jsonb_object_keys(section))<>2 OR jsonb_typeof(section->'passed') IS DISTINCT FROM 'boolean'
  OR jsonb_typeof(section->'evidence') IS DISTINCT FROM 'array' THEN RETURN false; END IF;
  IF jsonb_array_length(section->'evidence') NOT BETWEEN 1 AND 65536 THEN RETURN false; END IF;
  FOR entry IN SELECT item FROM jsonb_array_elements(section->'evidence') item LOOP
   IF jsonb_typeof(entry)<>'object' THEN RETURN false; END IF;
   IF (SELECT count(*) FROM jsonb_object_keys(entry))<>4 OR NOT (entry ?& ARRAY['check','subjectSha256','logObjectKey','summary'])
   OR jsonb_typeof(entry->'check')<>'string' OR entry->>'check' !~ '^[A-Z][A-Z0-9_]{0,63}$'
   OR (entry->'subjectSha256'<>'null'::jsonb AND (jsonb_typeof(entry->'subjectSha256')<>'string' OR entry->>'subjectSha256' !~ '^[0-9a-f]{64}$'))
   OR (entry->'logObjectKey'<>'null'::jsonb AND (jsonb_typeof(entry->'logObjectKey')<>'string' OR char_length(entry->>'logObjectKey') NOT BETWEEN 1 AND 1024))
   OR jsonb_typeof(entry->'summary')<>'string' OR char_length(entry->>'summary') NOT BETWEEN 1 AND 500 OR entry->>'summary' ~ '^[[:space:]]*$' THEN
    RETURN false;
   END IF;
  END LOOP;
 END LOOP;
 RETURN true;
END $$;

CREATE TABLE judge.platform_problems (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY CHECK (id > 0),
 source text NOT NULL CHECK (source = 'OJ_LAB'),
 repository_url text NOT NULL CHECK (repository_url = 'https://github.com/oj-lab/problem-packages'),
 package_path text NOT NULL CHECK (judge.valid_package_path(package_path)),
 status text NOT NULL CHECK (status IN ('DRAFT','PUBLISHED','WITHDRAWN')),
 current_version_id uuid, latest_version_id uuid,
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 public_updated_at timestamptz, withdrawn_at timestamptz, withdrawal_reason varchar(500),
 UNIQUE(source,repository_url,package_path),
 CHECK ((status = 'DRAFT' AND current_version_id IS NULL AND public_updated_at IS NULL AND withdrawn_at IS NULL)
 OR (status = 'PUBLISHED' AND current_version_id IS NOT NULL AND public_updated_at IS NOT NULL AND withdrawn_at IS NULL)
 OR (status = 'WITHDRAWN' AND current_version_id IS NOT NULL AND public_updated_at IS NOT NULL AND withdrawn_at IS NOT NULL))
);
CREATE INDEX platform_problems_public_order ON judge.platform_problems(status,public_updated_at DESC,id DESC);

CREATE TABLE judge.license_evidence (
 id uuid PRIMARY KEY,
 repository_url text NOT NULL CHECK (repository_url = 'https://github.com/oj-lab/problem-packages'),
 source_revision judge.commit_hex NOT NULL,
 package_path text NOT NULL CHECK (judge.valid_package_path(package_path)),
 previous_evidence_id uuid,
 status text NOT NULL CHECK (status IN ('PENDING','VERIFIED','MISSING','REVIEW_REQUIRED')),
 license_scope text NOT NULL CHECK (license_scope IN ('PACKAGE','REPOSITORY_INHERITED','UNKNOWN')),
 spdx_id varchar(128), notice text NOT NULL, source_url text NOT NULL,
 license_files jsonb NOT NULL CHECK (jsonb_typeof(license_files) = 'array'),
 evidence jsonb NOT NULL CHECK (jsonb_typeof(evidence) = 'object'),
 reviewed_by text, reviewed_at timestamptz, created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(id,repository_url,source_revision,package_path),
 FOREIGN KEY(previous_evidence_id,repository_url,source_revision,package_path)
 REFERENCES judge.license_evidence(id,repository_url,source_revision,package_path) ON DELETE RESTRICT ON UPDATE RESTRICT,
 CHECK (previous_evidence_id IS DISTINCT FROM id),
 CHECK (status <> 'VERIFIED' OR (reviewed_by IS NOT NULL AND btrim(reviewed_by) <> '' AND reviewed_at IS NOT NULL
 AND btrim(notice) <> '' AND btrim(source_url) <> '' AND jsonb_array_length(license_files) > 0 AND evidence <> '{}'::jsonb))
);
CREATE INDEX license_evidence_source ON judge.license_evidence(repository_url,source_revision,package_path);
CREATE INDEX license_evidence_status ON judge.license_evidence(status,created_at);

-- Source identity serializes first registration and freezes original bytes
-- across all adapters; content identity freezes normalization for one adapter.
CREATE TABLE judge.package_source_identities (
 id uuid PRIMARY KEY,
 repository_url text NOT NULL CHECK (repository_url = 'https://github.com/oj-lab/problem-packages'),
 source_revision judge.commit_hex NOT NULL,
 package_path text NOT NULL CHECK (judge.valid_package_path(package_path)),
 source_sha256 judge.sha256_hex NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(repository_url,source_revision,package_path), UNIQUE(id,source_sha256)
);
CREATE TABLE judge.package_content_identities (
 id uuid PRIMARY KEY,
 source_identity_id uuid NOT NULL REFERENCES judge.package_source_identities(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
 adapter_version varchar(64) NOT NULL CHECK (btrim(adapter_version) <> ''),
 source_format text NOT NULL CHECK (source_format = 'oj-lab-v1'),
 manifest_version text NOT NULL CHECK (manifest_version = '0.2.0'),
 normalized_sha256 judge.sha256_hex NOT NULL, manifest_sha256 judge.sha256_hex NOT NULL,
 manifest jsonb NOT NULL CHECK (jsonb_typeof(manifest) = 'object'),
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(source_identity_id,adapter_version)
);

CREATE TABLE judge.judge_language_configs (
 language_id text NOT NULL CHECK (btrim(language_id) <> ''), config_version text NOT NULL CHECK (btrim(config_version) <> ''),
 display_name text NOT NULL, language_family text NOT NULL, compiler_version text NOT NULL CHECK (btrim(compiler_version) <> ''),
 source_filename text NOT NULL, compile_template jsonb NOT NULL CHECK (jsonb_typeof(compile_template) = 'object'),
 run_template jsonb NOT NULL CHECK (jsonb_typeof(run_template) = 'object'),
 compile_limits jsonb NOT NULL CHECK (jsonb_typeof(compile_limits) = 'object'),
 toolchain_digest text NOT NULL CHECK (toolchain_digest ~ '^sha256:[0-9a-f]{64}$'),
 analysis_supported boolean NOT NULL, is_active boolean NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(language_id,config_version),
 CHECK (NOT is_active OR language_id = 'cpp17')
);
CREATE UNIQUE INDEX judge_language_configs_one_active ON judge.judge_language_configs(language_id) WHERE is_active;

CREATE TABLE judge.package_artifacts (
 id uuid PRIMARY KEY,
 problem_id bigint NOT NULL REFERENCES judge.platform_problems(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
 content_identity_id uuid NOT NULL REFERENCES judge.package_content_identities(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
 source text NOT NULL CHECK (source = 'OJ_LAB'),
 repository_url text NOT NULL CHECK (repository_url = 'https://github.com/oj-lab/problem-packages'),
 source_revision judge.commit_hex NOT NULL,
 package_path text NOT NULL CHECK (judge.valid_package_path(package_path)),
 source_format text NOT NULL CHECK (source_format = 'oj-lab-v1'), adapter_version varchar(64) NOT NULL,
 manifest_version text NOT NULL CHECK (manifest_version = '0.2.0'),
 source_archive_key text NOT NULL, source_sha256 judge.sha256_hex NOT NULL,
 normalized_archive_key text NOT NULL, normalized_sha256 judge.sha256_hex NOT NULL,
 manifest jsonb NOT NULL CHECK (jsonb_typeof(manifest) = 'object'),
 source_metadata jsonb NOT NULL CHECK (jsonb_typeof(source_metadata) = 'object'),
 license_evidence_id uuid NOT NULL, validation_run_id uuid,
 validation_context jsonb NOT NULL CHECK (jsonb_typeof(validation_context) = 'object'),
 evidence_set_hash judge.sha256_hex NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(problem_id,id),
 UNIQUE(repository_url,source_revision,package_path,adapter_version,evidence_set_hash),
 FOREIGN KEY(license_evidence_id,repository_url,source_revision,package_path)
 REFERENCES judge.license_evidence(id,repository_url,source_revision,package_path) ON DELETE RESTRICT ON UPDATE RESTRICT DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE judge.problem_versions (
 id uuid PRIMARY KEY,
 problem_id bigint NOT NULL REFERENCES judge.platform_problems(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
 version_number integer NOT NULL CHECK (version_number > 0), package_artifact_id uuid NOT NULL, base_version_id uuid,
 title varchar(256) NOT NULL CHECK (btrim(title) <> ''), statement_format text NOT NULL CHECK (statement_format = 'MARKDOWN'),
 statement_content text NOT NULL, statement_input text, statement_output text,
 samples jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(samples) = 'array'),
 tags text[] NOT NULL DEFAULT '{}' CHECK (judge.unique_nonnull_texts(tags) AND cardinality(tags) <= 32),
 difficulty integer CHECK (difficulty > 0), difficulty_scale text NOT NULL CHECK (difficulty_scale IN ('PLATFORM_RATING','UNRATED')),
 rating_basis text,
 time_limit_ms judge.safe_nonnegative NOT NULL CHECK (time_limit_ms > 0),
 wall_limit_ms judge.safe_nonnegative NOT NULL CHECK (wall_limit_ms >= time_limit_ms),
 memory_limit_bytes judge.safe_nonnegative NOT NULL CHECK (memory_limit_bytes > 0),
 output_limit_bytes judge.safe_nonnegative NOT NULL CHECK (output_limit_bytes > 0),
 language_ids text[] NOT NULL CHECK (cardinality(language_ids) > 0 AND judge.unique_nonnull_texts(language_ids)),
 judge_mode text NOT NULL CHECK (judge_mode = 'BATCH_PASS_FAIL'),
 checker_config jsonb NOT NULL CHECK (jsonb_typeof(checker_config) = 'object'),
 metadata_hash judge.sha256_hex NOT NULL, first_published_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(problem_id,id), UNIQUE(problem_id,version_number),
 FOREIGN KEY(problem_id,package_artifact_id) REFERENCES judge.package_artifacts(problem_id,id) ON DELETE RESTRICT ON UPDATE RESTRICT DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(problem_id,base_version_id) REFERENCES judge.problem_versions(problem_id,id) ON DELETE RESTRICT ON UPDATE RESTRICT DEFERRABLE INITIALLY DEFERRED,
 CHECK ((difficulty_scale = 'UNRATED' AND difficulty IS NULL) OR (difficulty_scale = 'PLATFORM_RATING' AND difficulty IS NOT NULL AND rating_basis IS NOT NULL AND btrim(rating_basis) <> ''))
);
ALTER TABLE judge.platform_problems ADD CONSTRAINT platform_current_version FOREIGN KEY(id,current_version_id)
 REFERENCES judge.problem_versions(problem_id,id) ON DELETE RESTRICT ON UPDATE RESTRICT DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE judge.platform_problems ADD CONSTRAINT platform_latest_version FOREIGN KEY(id,latest_version_id)
 REFERENCES judge.problem_versions(problem_id,id) ON DELETE RESTRICT ON UPDATE RESTRICT DEFERRABLE INITIALLY DEFERRED;
CREATE INDEX problem_versions_order ON judge.problem_versions(problem_id,version_number DESC);
CREATE INDEX problem_versions_tags ON judge.problem_versions USING gin(tags);
CREATE INDEX problem_versions_difficulty ON judge.problem_versions(difficulty_scale,difficulty);

CREATE TABLE judge.problem_test_cases (
 id uuid PRIMARY KEY,
 package_artifact_id uuid NOT NULL REFERENCES judge.package_artifacts(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
 ordinal integer NOT NULL CHECK (ordinal > 0), visibility text NOT NULL CHECK (visibility IN ('SAMPLE','SECRET')),
 input_object_key text NOT NULL, answer_object_key text NOT NULL,
 input_sha256 judge.sha256_hex NOT NULL, answer_sha256 judge.sha256_hex NOT NULL,
 input_size_bytes judge.safe_nonnegative NOT NULL, answer_size_bytes judge.safe_nonnegative NOT NULL,
 validation_group text, created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(package_artifact_id,ordinal)
);
CREATE TABLE judge.reference_solutions (
 id uuid PRIMARY KEY,
 package_artifact_id uuid NOT NULL REFERENCES judge.package_artifacts(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
 role text NOT NULL CHECK (role IN ('ACCEPTED','WRONG_ANSWER','TIME_LIMIT','RUNTIME_ERROR')),
 language_id text NOT NULL, source_object_key text NOT NULL, source_sha256 judge.sha256_hex NOT NULL,
 upstream_path text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(package_artifact_id,upstream_path)
);
CREATE INDEX reference_solutions_role ON judge.reference_solutions(package_artifact_id,role);

CREATE TABLE judge.package_validation_runs (
 id uuid PRIMARY KEY,
 package_artifact_id uuid NOT NULL REFERENCES judge.package_artifacts(id) ON DELETE RESTRICT ON UPDATE RESTRICT DEFERRABLE INITIALLY DEFERRED,
 status text NOT NULL CHECK (status IN ('PENDING','RUNNING','PASSED','FAILED')),
 problemtools_version text NOT NULL, adapter_version text NOT NULL, toolchain_version text NOT NULL,
 image_digest text NOT NULL CHECK (image_digest ~ '^sha256:[0-9a-f]{64}$'),
 config_sha256 judge.sha256_hex NOT NULL, source_sha256 judge.sha256_hex NOT NULL, normalized_sha256 judge.sha256_hex NOT NULL,
 results jsonb NOT NULL CHECK (jsonb_typeof(results) = 'object'),
 errors jsonb NOT NULL CHECK (jsonb_typeof(errors) = 'array'), adaptations jsonb NOT NULL CHECK (jsonb_typeof(adaptations) = 'array'),
 log_object_key text, started_at timestamptz, finished_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(id,package_artifact_id),
 CHECK ((status = 'PENDING' AND started_at IS NULL AND finished_at IS NULL)
 OR (status = 'RUNNING' AND started_at IS NOT NULL AND finished_at IS NULL)
 OR (status = 'PASSED' AND started_at IS NOT NULL AND finished_at IS NOT NULL AND errors = '[]'::jsonb)
 OR (status = 'FAILED' AND started_at IS NOT NULL AND finished_at IS NOT NULL AND jsonb_array_length(errors) > 0)),
 CHECK(status NOT IN ('PASSED','FAILED') OR judge.valid_validation_results(results)),
 CHECK(status<>'PASSED' OR results @> '{"structure":{"passed":true},"statement":{"passed":true},"testData":{"passed":true},"validators":{"passed":true},"referenceSolutions":{"passed":true}}'),
 CHECK(status<>'FAILED' OR NOT results @> '{"structure":{"passed":true},"statement":{"passed":true},"testData":{"passed":true},"validators":{"passed":true},"referenceSolutions":{"passed":true}}')
);
ALTER TABLE judge.package_artifacts ADD CONSTRAINT artifact_validation_run FOREIGN KEY(validation_run_id,id)
 REFERENCES judge.package_validation_runs(id,package_artifact_id) ON DELETE RESTRICT ON UPDATE RESTRICT DEFERRABLE INITIALLY DEFERRED;
CREATE INDEX package_validation_runs_history ON judge.package_validation_runs(package_artifact_id,created_at DESC);
CREATE INDEX package_validation_runs_status ON judge.package_validation_runs(status,created_at);

CREATE TABLE judge.import_jobs (
 id uuid PRIMARY KEY, request_id uuid NOT NULL UNIQUE, request_hash judge.sha256_hex NOT NULL,
 source text NOT NULL CHECK (source = 'OJ_LAB'), repository_url text NOT NULL CHECK (repository_url = 'https://github.com/oj-lab/problem-packages'),
 source_revision judge.commit_hex NOT NULL,
 status text NOT NULL CHECK (status IN ('QUEUED','RUNNING','SUCCEEDED','PARTIAL','FAILED')),
 revision integer NOT NULL DEFAULT 1 CHECK (revision >= 1),
 package_count integer NOT NULL CHECK (package_count >= 0), completed_package_count integer NOT NULL DEFAULT 0 CHECK (completed_package_count BETWEEN 0 AND package_count),
 error jsonb CHECK (jsonb_typeof(error) = 'object'), lease_owner uuid, lease_expires_at timestamptz,
 attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 3),
 started_at timestamptz, finished_at timestamptz, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 CHECK ((status = 'QUEUED' AND lease_owner IS NULL AND lease_expires_at IS NULL AND started_at IS NULL AND finished_at IS NULL AND error IS NULL)
 OR (status = 'RUNNING' AND lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL AND started_at IS NOT NULL AND finished_at IS NULL AND error IS NULL)
 OR (status IN ('SUCCEEDED','PARTIAL','FAILED') AND lease_owner IS NULL AND lease_expires_at IS NULL AND finished_at IS NOT NULL AND completed_package_count = package_count
 AND ((status = 'SUCCEEDED' AND error IS NULL) OR (status <> 'SUCCEEDED' AND error IS NOT NULL))))
);
CREATE INDEX import_jobs_queue ON judge.import_jobs(status,created_at);
CREATE INDEX import_jobs_lease ON judge.import_jobs(lease_expires_at) WHERE status = 'RUNNING';
CREATE TABLE judge.import_items (
 id uuid PRIMARY KEY,
 import_job_id uuid NOT NULL REFERENCES judge.import_jobs(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
 ordinal integer NOT NULL CHECK (ordinal > 0), package_path text NOT NULL CHECK (judge.valid_package_path(package_path)),
 status text NOT NULL CHECK (status IN ('PENDING','VALIDATED','REJECTED')), problem_id bigint REFERENCES judge.platform_problems(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
 problem_version_id uuid, license_status text NOT NULL CHECK (license_status IN ('PENDING','VERIFIED','MISSING','REVIEW_REQUIRED')),
 validation_status text NOT NULL CHECK (validation_status IN ('PENDING','PASSED','FAILED')),
 errors jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(errors) = 'array'),
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(import_job_id,ordinal), UNIQUE(import_job_id,package_path),
 FOREIGN KEY(problem_id,problem_version_id) REFERENCES judge.problem_versions(problem_id,id) ON DELETE RESTRICT ON UPDATE RESTRICT DEFERRABLE INITIALLY DEFERRED,
 CHECK ((problem_id IS NULL) = (problem_version_id IS NULL)),
 CHECK ((status = 'PENDING' AND problem_id IS NULL)
 OR (status = 'VALIDATED' AND problem_id IS NOT NULL AND license_status = 'VERIFIED' AND validation_status = 'PASSED' AND errors = '[]'::jsonb)
 OR (status = 'REJECTED' AND problem_id IS NULL AND jsonb_array_length(errors) > 0))
);
CREATE INDEX import_items_problem ON judge.import_items(problem_id);

-- Failed packages keep evidence without inventing problem/version identities.
CREATE TABLE judge.rejected_package_evidence (
 id uuid PRIMARY KEY,
 import_item_id uuid NOT NULL REFERENCES judge.import_items(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
 repository_url text NOT NULL CHECK(repository_url='https://github.com/oj-lab/problem-packages'),
 source_revision judge.commit_hex NOT NULL, package_path text NOT NULL CHECK(judge.valid_package_path(package_path)),
 failure_stage text NOT NULL CHECK(failure_stage IN ('SOURCE_UNAVAILABLE','INVALID_STRUCTURE','UNSUPPORTED','LICENSE_REVIEW','VALIDATION_FAILED')),
 source_archive_key text, source_sha256 judge.sha256_hex, normalized_archive_key text, normalized_sha256 judge.sha256_hex,
 license_evidence_id uuid REFERENCES judge.license_evidence(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
 provenance jsonb NOT NULL CHECK(jsonb_typeof(provenance)='object'), source_metadata jsonb NOT NULL CHECK(jsonb_typeof(source_metadata)='object'),
 adaptations jsonb NOT NULL CHECK(jsonb_typeof(adaptations)='array'), errors jsonb NOT NULL CHECK(jsonb_typeof(errors)='array' AND jsonb_array_length(errors)>0),
 validation_log_key text, evidence_sha256 judge.sha256_hex NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(import_item_id,evidence_sha256),
 CHECK((source_archive_key IS NULL)=(source_sha256 IS NULL)), CHECK((normalized_archive_key IS NULL)=(normalized_sha256 IS NULL))
);

CREATE TABLE judge.catalog_state (
 singleton_id smallint PRIMARY KEY CHECK (singleton_id = 1), catalog_version bigint NOT NULL DEFAULT 1 CHECK (catalog_version > 0), updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO judge.catalog_state(singleton_id) VALUES(1);
CREATE TABLE judge.catalog_snapshots (
 id uuid PRIMARY KEY, catalog_version bigint NOT NULL CHECK (catalog_version > 0), item_count integer NOT NULL CHECK (item_count >= 0),
 page_limit integer NOT NULL CHECK (page_limit BETWEEN 1 AND 1000), created_at timestamptz NOT NULL DEFAULT now(),
 expires_at timestamptz NOT NULL CHECK (expires_at > created_at)
);
CREATE INDEX catalog_snapshots_expiry ON judge.catalog_snapshots(expires_at);
CREATE TABLE judge.catalog_snapshot_items (
 snapshot_id uuid NOT NULL REFERENCES judge.catalog_snapshots(id) ON DELETE CASCADE ON UPDATE RESTRICT,
 ordinal integer NOT NULL CHECK (ordinal >= 0), problem_id bigint NOT NULL REFERENCES judge.platform_problems(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
 problem_version_id uuid NOT NULL, status text NOT NULL CHECK (status IN ('PUBLISHED','WITHDRAWN')),
 problem_summary jsonb NOT NULL CHECK (jsonb_typeof(problem_summary) = 'object'), PRIMARY KEY(snapshot_id,ordinal), UNIQUE(snapshot_id,problem_id),
 FOREIGN KEY(problem_id,problem_version_id) REFERENCES judge.problem_versions(problem_id,id) ON DELETE RESTRICT ON UPDATE RESTRICT DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE judge.judge_tasks (
 id uuid PRIMARY KEY, request_id uuid NOT NULL UNIQUE, request_hash judge.sha256_hex NOT NULL,
 submission_id bigint NOT NULL UNIQUE CHECK (submission_id > 0),
 problem_id bigint NOT NULL REFERENCES judge.platform_problems(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
 problem_version_id uuid NOT NULL,
 source_owner text NOT NULL CHECK (source_owner = 'backend'), source_sha256 judge.sha256_hex NOT NULL,
 transient_source_key text, source_expires_at timestamptz,
 language_id text NOT NULL, language_config_version text NOT NULL, sandbox_version text NOT NULL,
 worker_image_digest text NOT NULL CHECK (worker_image_digest ~ '^sha256:[0-9a-f]{64}$'),
 execution_limits jsonb NOT NULL CHECK (jsonb_typeof(execution_limits) = 'object'),
 status text NOT NULL CHECK (status IN ('QUEUED','DISPATCHING','RUNNING','COMPLETED','FAILED','CANCELLED')),
 revision integer NOT NULL DEFAULT 1 CHECK (revision >= 1), error jsonb CHECK (jsonb_typeof(error) = 'object'),
 lease_owner uuid, lease_expires_at timestamptz, attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 3),
 started_at timestamptz, finished_at timestamptz, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(problem_id,problem_version_id) REFERENCES judge.problem_versions(problem_id,id) ON DELETE RESTRICT ON UPDATE RESTRICT DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(language_id,language_config_version) REFERENCES judge.judge_language_configs(language_id,config_version) ON DELETE RESTRICT ON UPDATE RESTRICT,
 CHECK ((status = 'QUEUED' AND lease_owner IS NULL AND lease_expires_at IS NULL AND started_at IS NULL AND finished_at IS NULL AND error IS NULL)
 OR (status IN ('DISPATCHING','RUNNING') AND lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL AND started_at IS NOT NULL AND finished_at IS NULL AND error IS NULL)
 OR (status IN ('COMPLETED','FAILED','CANCELLED') AND lease_owner IS NULL AND lease_expires_at IS NULL AND finished_at IS NOT NULL
 AND ((status = 'COMPLETED' AND error IS NULL) OR (status <> 'COMPLETED' AND error IS NOT NULL)))),
 CHECK (status IN ('COMPLETED','FAILED','CANCELLED') OR (transient_source_key IS NOT NULL AND source_expires_at IS NULL)),
 CHECK (status NOT IN ('COMPLETED','FAILED','CANCELLED') OR (source_expires_at IS NOT NULL AND source_expires_at>=finished_at+interval '24 hours'))
);
CREATE INDEX judge_tasks_queue ON judge.judge_tasks(status,created_at);
CREATE INDEX judge_tasks_problem_history ON judge.judge_tasks(problem_id,created_at DESC);
CREATE INDEX judge_tasks_lease ON judge.judge_tasks(lease_expires_at) WHERE status IN ('DISPATCHING','RUNNING');

CREATE TABLE judge.judge_results (
 judge_task_id uuid PRIMARY KEY REFERENCES judge.judge_tasks(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
 verdict text NOT NULL CHECK (verdict IN ('AC','WA','TLE','MLE','RE','CE','OLE','IE')),
 time_ms judge.safe_nonnegative, memory_bytes judge.safe_nonnegative,
 passed_test_count integer NOT NULL CHECK (passed_test_count >= 0), total_test_count integer NOT NULL CHECK (total_test_count >= passed_test_count),
 score numeric(8,6) CHECK (score IS NULL), compile_log text CHECK (octet_length(compile_log) <= 16384), diagnostic_code varchar(64),
 judged_at timestamptz NOT NULL, result_hash judge.sha256_hex NOT NULL, raw_execution_log_key text,
 created_at timestamptz NOT NULL DEFAULT now(),
 CHECK (verdict <> 'CE' OR (passed_test_count = 0 AND time_ms IS NULL AND memory_bytes IS NULL))
);
CREATE TABLE judge.judge_case_results (
 judge_task_id uuid NOT NULL REFERENCES judge.judge_tasks(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
 test_case_id uuid NOT NULL REFERENCES judge.problem_test_cases(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
 ordinal integer NOT NULL CHECK (ordinal > 0), verdict text NOT NULL CHECK (verdict IN ('AC','WA','TLE','MLE','RE','OLE','IE','SKIPPED')),
 cpu_time_ms judge.safe_nonnegative, wall_time_ms judge.safe_nonnegative, memory_bytes judge.safe_nonnegative,
 exit_code integer, signal integer, sandbox_status text, checker_status text, private_log_key text,
 created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(judge_task_id,test_case_id), UNIQUE(judge_task_id,ordinal),
 CHECK (verdict <> 'SKIPPED' OR (cpu_time_ms IS NULL AND wall_time_ms IS NULL AND memory_bytes IS NULL))
);
CREATE INDEX judge_case_results_test ON judge.judge_case_results(test_case_id);

CREATE TABLE judge.callback_outbox (
 event_id uuid PRIMARY KEY, judge_task_id uuid NOT NULL REFERENCES judge.judge_tasks(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
 revision integer NOT NULL CHECK (revision >= 1), event_type text NOT NULL CHECK (event_type = 'JUDGE_TASK_UPDATED'), request_id uuid NOT NULL,
 payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'), payload_hash judge.sha256_hex NOT NULL,
 status text NOT NULL CHECK (status IN ('PENDING','SENDING','DELIVERED','DEAD_LETTER')),
 attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0), next_attempt_at timestamptz NOT NULL,
 lease_owner uuid, lease_expires_at timestamptz, last_error_code text,
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(), delivered_at timestamptz,
 UNIQUE(judge_task_id,revision),
 CHECK ((status = 'SENDING' AND lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL) OR (status <> 'SENDING' AND lease_owner IS NULL AND lease_expires_at IS NULL)),
 CHECK ((status = 'DELIVERED') = (delivered_at IS NOT NULL))
);
CREATE INDEX callback_outbox_queue ON judge.callback_outbox(status,next_attempt_at);
CREATE INDEX callback_outbox_lease ON judge.callback_outbox(lease_expires_at);
CREATE TABLE judge.operation_requests (
 operation text NOT NULL CHECK (operation IN ('PUBLISH','WITHDRAW','METADATA_VERSION')), request_id uuid NOT NULL,
 request_hash judge.sha256_hex NOT NULL, problem_id bigint REFERENCES judge.platform_problems(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
 result jsonb CHECK (jsonb_typeof(result) = 'object'), status text NOT NULL CHECK (status IN ('PROCESSING','SUCCEEDED','FAILED')),
 error jsonb CHECK (jsonb_typeof(error) = 'object'), created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(operation,request_id),
 CHECK ((status = 'PROCESSING' AND result IS NULL AND error IS NULL) OR (status = 'SUCCEEDED' AND result IS NOT NULL AND error IS NULL)
 OR (status = 'FAILED' AND result IS NULL AND error IS NOT NULL))
);

-- Historical rows are never deleted or silently rewritten. Only explicit
-- state/lifecycle fields below have mutation exceptions.
CREATE FUNCTION judge.immutable_row() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'immutable judge history'; END $$;
CREATE TRIGGER immutable_license BEFORE UPDATE OR DELETE ON judge.license_evidence FOR EACH ROW EXECUTE FUNCTION judge.immutable_row();
CREATE TRIGGER immutable_source BEFORE UPDATE OR DELETE ON judge.package_source_identities FOR EACH ROW EXECUTE FUNCTION judge.immutable_row();
CREATE TRIGGER immutable_content BEFORE UPDATE OR DELETE ON judge.package_content_identities FOR EACH ROW EXECUTE FUNCTION judge.immutable_row();
CREATE TRIGGER immutable_tests BEFORE UPDATE OR DELETE ON judge.problem_test_cases FOR EACH ROW EXECUTE FUNCTION judge.immutable_row();
CREATE TRIGGER immutable_references BEFORE UPDATE OR DELETE ON judge.reference_solutions FOR EACH ROW EXECUTE FUNCTION judge.immutable_row();
CREATE TRIGGER immutable_rejected_evidence BEFORE UPDATE OR DELETE ON judge.rejected_package_evidence FOR EACH ROW EXECUTE FUNCTION judge.immutable_row();
CREATE TRIGGER immutable_results BEFORE UPDATE OR DELETE ON judge.judge_results FOR EACH ROW EXECUTE FUNCTION judge.immutable_row();
CREATE TRIGGER immutable_case_results BEFORE UPDATE OR DELETE ON judge.judge_case_results FOR EACH ROW EXECUTE FUNCTION judge.immutable_row();
CREATE TRIGGER retain_problems BEFORE DELETE ON judge.platform_problems FOR EACH ROW EXECUTE FUNCTION judge.immutable_row();
CREATE TRIGGER retain_versions BEFORE DELETE ON judge.problem_versions FOR EACH ROW EXECUTE FUNCTION judge.immutable_row();
CREATE TRIGGER retain_artifacts BEFORE DELETE ON judge.package_artifacts FOR EACH ROW EXECUTE FUNCTION judge.immutable_row();
CREATE TRIGGER retain_validation BEFORE DELETE ON judge.package_validation_runs FOR EACH ROW EXECUTE FUNCTION judge.immutable_row();
CREATE TRIGGER retain_languages BEFORE DELETE ON judge.judge_language_configs FOR EACH ROW EXECUTE FUNCTION judge.immutable_row();
CREATE TRIGGER retain_tasks BEFORE DELETE ON judge.judge_tasks FOR EACH ROW EXECUTE FUNCTION judge.immutable_row();
CREATE TRIGGER retain_outbox BEFORE DELETE ON judge.callback_outbox FOR EACH ROW EXECUTE FUNCTION judge.immutable_row();
CREATE TRIGGER retain_operations BEFORE DELETE ON judge.operation_requests FOR EACH ROW EXECUTE FUNCTION judge.immutable_row();
CREATE TRIGGER retain_import_jobs BEFORE DELETE ON judge.import_jobs FOR EACH ROW EXECUTE FUNCTION judge.immutable_row();
CREATE TRIGGER retain_import_items BEFORE DELETE ON judge.import_items FOR EACH ROW EXECUTE FUNCTION judge.immutable_row();
CREATE TRIGGER retain_catalog_state BEFORE DELETE ON judge.catalog_state FOR EACH ROW EXECUTE FUNCTION judge.immutable_row();

CREATE FUNCTION judge.guard_problem() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (to_jsonb(NEW)-ARRAY['status','current_version_id','latest_version_id','updated_at','public_updated_at','withdrawn_at','withdrawal_reason'])
 IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['status','current_version_id','latest_version_id','updated_at','public_updated_at','withdrawn_at','withdrawal_reason']) THEN
  RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='immutable stable problem identity';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER guard_problem BEFORE UPDATE ON judge.platform_problems FOR EACH ROW EXECUTE FUNCTION judge.guard_problem();
CREATE FUNCTION judge.guard_catalog_version() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.singleton_id<>OLD.singleton_id OR NEW.catalog_version<=OLD.catalog_version THEN
  RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='catalog version must strictly advance';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER guard_catalog_version BEFORE UPDATE ON judge.catalog_state FOR EACH ROW EXECUTE FUNCTION judge.guard_catalog_version();
CREATE FUNCTION judge.check_catalog_transaction() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE changed_here boolean;
BEGIN
 IF NEW.status IS DISTINCT FROM OLD.status OR NEW.current_version_id IS DISTINCT FROM OLD.current_version_id
 OR NEW.withdrawn_at IS DISTINCT FROM OLD.withdrawn_at OR NEW.withdrawal_reason IS DISTINCT FROM OLD.withdrawal_reason THEN
  SELECT xmin::text::bigint=(pg_current_xact_id()::text::bigint % 4294967296) INTO changed_here FROM judge.catalog_state WHERE singleton_id=1;
  IF NOT coalesce(changed_here,false) OR NEW.public_updated_at IS NULL
  OR NEW.public_updated_at IS NOT DISTINCT FROM OLD.public_updated_at THEN
   RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='public problem change requires same-transaction catalog advance';
  END IF;
 END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER check_catalog_transaction AFTER UPDATE ON judge.platform_problems DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION judge.check_catalog_transaction();

CREATE FUNCTION judge.guard_package_member() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE selected uuid; registered_here boolean;
BEGIN
 SELECT validation_run_id,xmin::text::bigint=(pg_current_xact_id()::text::bigint % 4294967296) INTO selected,registered_here
 FROM judge.package_artifacts WHERE id=NEW.package_artifact_id FOR UPDATE;
 IF selected IS NOT NULL AND NOT registered_here THEN
  RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='qualified artifact members are immutable';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER guard_test_registration BEFORE INSERT ON judge.problem_test_cases FOR EACH ROW EXECUTE FUNCTION judge.guard_package_member();
CREATE TRIGGER guard_reference_registration BEFORE INSERT ON judge.reference_solutions FOR EACH ROW EXECUTE FUNCTION judge.guard_package_member();

CREATE FUNCTION judge.guard_version() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (to_jsonb(NEW)-'first_published_at') IS DISTINCT FROM (to_jsonb(OLD)-'first_published_at')
 OR OLD.first_published_at IS NOT NULL OR NEW.first_published_at IS NULL THEN
  RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='immutable problem version';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER guard_version BEFORE UPDATE ON judge.problem_versions FOR EACH ROW EXECUTE FUNCTION judge.guard_version();
CREATE FUNCTION judge.guard_language() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (to_jsonb(NEW)-'is_active') IS DISTINCT FROM (to_jsonb(OLD)-'is_active') THEN
  RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='immutable language configuration';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER guard_language BEFORE UPDATE ON judge.judge_language_configs FOR EACH ROW EXECUTE FUNCTION judge.guard_language();
CREATE FUNCTION judge.guard_artifact() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (to_jsonb(NEW)-'validation_run_id') IS DISTINCT FROM (to_jsonb(OLD)-'validation_run_id')
 OR OLD.validation_run_id IS NOT NULL OR NEW.validation_run_id IS NULL
 OR EXISTS(SELECT 1 FROM judge.problem_versions WHERE package_artifact_id=OLD.id AND first_published_at IS NOT NULL) THEN
  RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='immutable package artifact';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER guard_artifact BEFORE UPDATE ON judge.package_artifacts FOR EACH ROW EXECUTE FUNCTION judge.guard_artifact();
CREATE FUNCTION judge.guard_validation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.status IN ('PASSED','FAILED') OR (to_jsonb(NEW)-ARRAY['status','results','errors','adaptations','log_object_key','started_at','finished_at'])
 IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['status','results','errors','adaptations','log_object_key','started_at','finished_at']) THEN
  RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='immutable validation identity or terminal result';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER guard_validation BEFORE UPDATE ON judge.package_validation_runs FOR EACH ROW EXECUTE FUNCTION judge.guard_validation();

CREATE FUNCTION judge.check_artifact_identity() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE a judge.package_artifacts; c judge.package_content_identities; s judge.package_source_identities; r judge.package_validation_runs;
BEGIN
 SELECT * INTO a FROM judge.package_artifacts WHERE id=NEW.id;
 SELECT * INTO c FROM judge.package_content_identities WHERE id=a.content_identity_id;
 SELECT * INTO s FROM judge.package_source_identities WHERE id=c.source_identity_id;
 IF NOT FOUND OR a.repository_url<>s.repository_url OR a.source_revision<>s.source_revision OR a.package_path<>s.package_path
 OR a.source_sha256<>s.source_sha256 OR a.adapter_version<>c.adapter_version OR a.source_format<>c.source_format
 OR a.manifest_version<>c.manifest_version OR a.normalized_sha256<>c.normalized_sha256 OR a.manifest<>c.manifest
 OR NOT EXISTS(SELECT 1 FROM judge.platform_problems p WHERE p.id=a.problem_id AND p.source=a.source AND p.repository_url=a.repository_url AND p.package_path=a.package_path)
 OR NOT EXISTS(SELECT 1 FROM judge.license_evidence l WHERE l.id=a.license_evidence_id AND l.status='VERIFIED') THEN
  RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='artifact source, content or approved evidence mismatch';
 END IF;
 IF a.validation_context->>'adapterVersion' IS DISTINCT FROM a.adapter_version
 OR a.validation_context->>'sourceSha256' IS DISTINCT FROM a.source_sha256::text
 OR a.validation_context->>'normalizedSha256' IS DISTINCT FROM a.normalized_sha256::text
 OR NOT (a.validation_context ?& ARRAY['problemtoolsVersion','adapterVersion','toolchainVersion','imageDigest','configSha256','sourceSha256','normalizedSha256'])
 OR (SELECT count(*) FROM jsonb_object_keys(a.validation_context)) <> 7 THEN
  RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='invalid immutable validation context';
 END IF;
 IF a.validation_run_id IS NOT NULL THEN
  SELECT * INTO r FROM judge.package_validation_runs WHERE id=a.validation_run_id AND package_artifact_id=a.id;
  IF NOT FOUND OR r.status<>'PASSED' OR a.validation_context <> jsonb_build_object('problemtoolsVersion',r.problemtools_version,'adapterVersion',r.adapter_version,
   'toolchainVersion',r.toolchain_version,'imageDigest',r.image_digest,'configSha256',r.config_sha256,'sourceSha256',r.source_sha256,'normalizedSha256',r.normalized_sha256) THEN
   RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='selected validation must pass exact frozen artifact context';
  END IF;
  IF NOT (a.manifest ? 'testCount') OR (a.manifest->>'testCount')::integer <> (SELECT count(*) FROM judge.problem_test_cases WHERE package_artifact_id=a.id)
  OR (SELECT coalesce(max(ordinal),0) FROM judge.problem_test_cases WHERE package_artifact_id=a.id)<>(SELECT count(*) FROM judge.problem_test_cases WHERE package_artifact_id=a.id)
  OR NOT EXISTS(SELECT 1 FROM judge.reference_solutions WHERE package_artifact_id=a.id AND role='ACCEPTED') THEN
   RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='qualified artifact lacks complete frozen test/reference set';
  END IF;
 END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER check_artifact_identity AFTER INSERT OR UPDATE ON judge.package_artifacts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION judge.check_artifact_identity();

CREATE FUNCTION judge.check_validation_source() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM judge.package_artifacts a WHERE a.id=NEW.package_artifact_id AND a.adapter_version=NEW.adapter_version
 AND a.source_sha256=NEW.source_sha256 AND a.normalized_sha256=NEW.normalized_sha256) THEN
  RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='validation run cannot borrow or alter artifact source identity';
 END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER check_validation_source AFTER INSERT OR UPDATE ON judge.package_validation_runs DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION judge.check_validation_source();

CREATE FUNCTION judge.check_publication() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE p judge.platform_problems; v judge.problem_versions; a judge.package_artifacts;
BEGIN
 IF TG_TABLE_NAME='platform_problems' THEN SELECT * INTO p FROM judge.platform_problems WHERE id=NEW.id;
 ELSE SELECT * INTO p FROM judge.platform_problems WHERE id=NEW.problem_id; END IF;
 IF TG_TABLE_NAME='problem_versions' THEN
  IF NEW.first_published_at IS NOT NULL AND p.current_version_id IS DISTINCT FROM NEW.id THEN
   RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='first publication requires the selected current version';
  END IF;
 END IF;
 IF p.current_version_id IS NOT NULL THEN
  SELECT * INTO v FROM judge.problem_versions WHERE id=p.current_version_id AND problem_id=p.id;
  SELECT * INTO a FROM judge.package_artifacts WHERE id=v.package_artifact_id;
  IF v.first_published_at IS NULL OR a.validation_run_id IS NULL
  OR NOT EXISTS(SELECT 1 FROM judge.reference_solutions WHERE package_artifact_id=a.id AND role='ACCEPTED') THEN
   RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='publication lacks immutable qualified evidence';
  END IF;
 END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER check_problem_publication AFTER INSERT OR UPDATE ON judge.platform_problems DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION judge.check_publication();
CREATE CONSTRAINT TRIGGER check_version_publication AFTER INSERT OR UPDATE ON judge.problem_versions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION judge.check_publication();

CREATE FUNCTION judge.guard_task() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE mutable text[] := ARRAY['status','revision','error','lease_owner','lease_expires_at','attempt_count','started_at','finished_at','updated_at','transient_source_key','source_expires_at'];
BEGIN
 IF (to_jsonb(NEW)-mutable) IS DISTINCT FROM (to_jsonb(OLD)-mutable) OR NEW.revision<OLD.revision OR NEW.attempt_count<OLD.attempt_count THEN
  RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='immutable task admission or regressing revision';
 END IF;
 IF OLD.status IN ('COMPLETED','FAILED','CANCELLED') THEN
  IF (to_jsonb(NEW)-'transient_source_key') IS DISTINCT FROM (to_jsonb(OLD)-'transient_source_key')
  OR OLD.transient_source_key IS NULL OR NEW.transient_source_key IS NOT NULL OR OLD.source_expires_at>clock_timestamp() THEN
   RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='immutable terminal task';
  END IF;
 ELSE
  IF NEW.revision=OLD.revision AND NEW.updated_at IS DISTINCT FROM OLD.updated_at THEN
   RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='private heartbeat cannot change public task timestamp';
  END IF;
  IF (OLD.status='QUEUED' AND NEW.status NOT IN ('QUEUED','DISPATCHING','FAILED','CANCELLED'))
  OR (OLD.status='DISPATCHING' AND NEW.status NOT IN ('DISPATCHING','RUNNING','FAILED','CANCELLED'))
  OR (OLD.status='RUNNING' AND NEW.status NOT IN ('RUNNING','DISPATCHING','COMPLETED','FAILED','CANCELLED')) THEN
   RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='illegal task state transition';
  END IF;
  IF NEW.transient_source_key IS DISTINCT FROM OLD.transient_source_key THEN
   RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='in-flight source cannot change';
  END IF;
  IF NEW.status IS DISTINCT FROM OLD.status AND NEW.revision<>OLD.revision+1 THEN
   RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='visible task transition requires next revision';
  END IF;
  IF OLD.started_at IS NOT NULL AND NEW.started_at IS DISTINCT FROM OLD.started_at THEN
   RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='first execution timestamp is immutable';
  END IF;
  IF OLD.status='QUEUED' AND NEW.status='DISPATCHING' AND NEW.attempt_count<>0 THEN
   RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='initial execution must reserve recovery count zero';
  END IF;
  IF OLD.lease_owner IS NOT NULL AND NEW.lease_owner IS DISTINCT FROM OLD.lease_owner
  AND NEW.status NOT IN ('DISPATCHING','COMPLETED','FAILED','CANCELLED') THEN
   RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='lease owner changes only in recovery or terminal commitment';
  END IF;
  IF NEW.attempt_count<>OLD.attempt_count AND NOT (OLD.lease_owner IS NOT NULL AND NEW.status='DISPATCHING'
  AND NEW.lease_owner IS DISTINCT FROM OLD.lease_owner) THEN
   RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='recovery counter changes only at a fresh fenced reservation';
  END IF;
  IF NEW.status='DISPATCHING' AND OLD.status='RUNNING' AND NEW.lease_owner IS NOT DISTINCT FROM OLD.lease_owner THEN
   RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='recovery must fence the old worker';
  END IF;
  IF NEW.lease_owner IS DISTINCT FROM OLD.lease_owner AND OLD.lease_owner IS NOT NULL AND NEW.status='DISPATCHING'
  AND (OLD.lease_expires_at>clock_timestamp() OR NEW.lease_owner IS NULL OR NEW.attempt_count<>OLD.attempt_count+1 OR NEW.revision<>OLD.revision+1) THEN
   RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='invalid expired lease recovery reservation';
  END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER guard_task BEFORE UPDATE ON judge.judge_tasks FOR EACH ROW EXECUTE FUNCTION judge.guard_task();

CREATE FUNCTION judge.check_task_facts() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE task_id uuid; t judge.judge_tasks; r judge.judge_results; artifact_id uuid; expected_tests integer;
BEGIN
 IF TG_TABLE_NAME='judge_tasks' THEN task_id:=NEW.id; ELSE task_id:=NEW.judge_task_id; END IF;
 SELECT * INTO t FROM judge.judge_tasks WHERE id=task_id;
 SELECT * INTO r FROM judge.judge_results WHERE judge_task_id=task_id;
 SELECT package_artifact_id INTO artifact_id FROM judge.problem_versions WHERE id=t.problem_version_id;
 SELECT count(*) INTO expected_tests FROM judge.problem_test_cases WHERE package_artifact_id=artifact_id;
 IF (t.status='COMPLETED' AND (r.judge_task_id IS NULL OR r.verdict='IE'))
 OR (t.status='FAILED' AND (r.judge_task_id IS NULL OR r.verdict<>'IE'))
 OR (t.status IN ('QUEUED','DISPATCHING','RUNNING','CANCELLED') AND r.judge_task_id IS NOT NULL)
 OR (r.judge_task_id IS NOT NULL AND r.total_test_count<>expected_tests)
 OR (r.judge_task_id IS NOT NULL AND r.passed_test_count<>(SELECT count(*) FROM judge.judge_case_results WHERE judge_task_id=task_id AND verdict='AC'))
 OR (r.verdict='AC' AND r.passed_test_count<>expected_tests)
 OR (r.verdict='CE' AND EXISTS(SELECT 1 FROM judge.judge_case_results WHERE judge_task_id=task_id AND verdict<>'SKIPPED'))
 OR (r.judge_task_id IS NOT NULL AND r.time_ms IS DISTINCT FROM (SELECT max(cpu_time_ms) FROM judge.judge_case_results WHERE judge_task_id=task_id AND verdict<>'SKIPPED'))
 OR (r.judge_task_id IS NOT NULL AND r.memory_bytes IS DISTINCT FROM (SELECT max(memory_bytes) FROM judge.judge_case_results WHERE judge_task_id=task_id AND verdict<>'SKIPPED'))
 OR (t.status='COMPLETED' AND EXISTS(SELECT 1 FROM judge.judge_case_results WHERE judge_task_id=task_id AND verdict='IE'))
 OR EXISTS(SELECT 1 FROM judge.judge_case_results cr JOIN judge.problem_test_cases tc ON tc.id=cr.test_case_id
  WHERE cr.judge_task_id=task_id AND (tc.package_artifact_id<>artifact_id OR tc.ordinal<>cr.ordinal))
 OR (t.status IN ('QUEUED','DISPATCHING','RUNNING','CANCELLED') AND EXISTS(SELECT 1 FROM judge.judge_case_results WHERE judge_task_id=task_id))
 OR NOT EXISTS(SELECT 1 FROM judge.callback_outbox o WHERE o.judge_task_id=task_id AND o.revision=t.revision AND o.request_id=t.request_id) THEN
  RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='task, frozen cases, result and callback must commit consistently';
 END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER check_task_facts AFTER INSERT OR UPDATE ON judge.judge_tasks DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION judge.check_task_facts();
CREATE CONSTRAINT TRIGGER check_result_facts AFTER INSERT ON judge.judge_results DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION judge.check_task_facts();
CREATE CONSTRAINT TRIGGER check_case_facts AFTER INSERT ON judge.judge_case_results DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION judge.check_task_facts();
CREATE CONSTRAINT TRIGGER check_outbox_facts AFTER INSERT ON judge.callback_outbox DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION judge.check_task_facts();

CREATE FUNCTION judge.check_callback_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.payload->>'eventId' IS DISTINCT FROM NEW.event_id::text OR NEW.payload->>'requestId' IS DISTINCT FROM NEW.request_id::text
 OR NEW.payload->>'aggregateId' IS DISTINCT FROM NEW.judge_task_id::text OR NEW.payload->>'eventType' IS DISTINCT FROM NEW.event_type
 OR NEW.payload->>'revision' IS DISTINCT FROM NEW.revision::text OR NEW.payload->'payload'->>'revision' IS DISTINCT FROM NEW.revision::text
 OR NEW.payload->'payload'->>'requestId' IS DISTINCT FROM NEW.request_id::text
 OR NEW.payload->'payload'->>'judgeTaskId' IS DISTINCT FROM NEW.judge_task_id::text
 OR NOT EXISTS(SELECT 1 FROM judge.judge_tasks WHERE id=NEW.judge_task_id AND request_id=NEW.request_id AND revision>=NEW.revision
 AND NEW.payload->'payload'->>'submissionId'=submission_id::text
 AND (revision<>NEW.revision OR NEW.payload->'payload'->>'status'=status)) THEN
  RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='callback snapshot and durable task identity mismatch';
 END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER check_callback_identity AFTER INSERT ON judge.callback_outbox DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION judge.check_callback_identity();

CREATE FUNCTION judge.guard_outbox() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (to_jsonb(NEW)-ARRAY['status','attempt_count','next_attempt_at','lease_owner','lease_expires_at','last_error_code','updated_at','delivered_at'])
 IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['status','attempt_count','next_attempt_at','lease_owner','lease_expires_at','last_error_code','updated_at','delivered_at'])
 OR NEW.attempt_count<OLD.attempt_count OR (OLD.status='DELIVERED' AND NEW IS DISTINCT FROM OLD) THEN
  RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='immutable callback identity or delivered event';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER guard_outbox BEFORE UPDATE ON judge.callback_outbox FOR EACH ROW EXECUTE FUNCTION judge.guard_outbox();
CREATE FUNCTION judge.guard_operation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.status IN ('SUCCEEDED','FAILED') OR (to_jsonb(NEW)-ARRAY['status','result','error','updated_at'])
 IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['status','result','error','updated_at']) THEN
  RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='immutable management operation identity or result';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER guard_operation BEFORE UPDATE ON judge.operation_requests FOR EACH ROW EXECUTE FUNCTION judge.guard_operation();

CREATE FUNCTION judge.check_import_counts() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE job_id uuid; j judge.import_jobs; total integer; done integer; passed integer;
BEGIN
 IF TG_TABLE_NAME='import_jobs' THEN job_id:=NEW.id; ELSE job_id:=NEW.import_job_id; END IF;
 SELECT * INTO j FROM judge.import_jobs WHERE id=job_id;
 SELECT count(*),count(*) FILTER(WHERE status<>'PENDING'),count(*) FILTER(WHERE status='VALIDATED') INTO total,done,passed FROM judge.import_items WHERE import_job_id=job_id;
 IF total<>j.package_count OR done<>j.completed_package_count OR (total>0 AND (SELECT max(ordinal) FROM judge.import_items WHERE import_job_id=job_id)<>total)
 OR (j.status='SUCCEEDED' AND passed<>total) OR (j.status='PARTIAL' AND (passed=0 OR passed=total)) OR (j.status='FAILED' AND passed<>0) THEN
  RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='import counts and terminal summary mismatch';
 END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER check_import_job_counts AFTER INSERT OR UPDATE ON judge.import_jobs DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION judge.check_import_counts();
CREATE CONSTRAINT TRIGGER check_import_item_counts AFTER INSERT OR UPDATE ON judge.import_items DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION judge.check_import_counts();
CREATE FUNCTION judge.guard_import_job() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.status IN ('SUCCEEDED','PARTIAL','FAILED') OR NEW.revision<OLD.revision OR NEW.attempt_count<OLD.attempt_count
 OR (to_jsonb(NEW)-ARRAY['status','revision','completed_package_count','error','lease_owner','lease_expires_at','attempt_count','started_at','finished_at','updated_at'])
 IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['status','revision','completed_package_count','error','lease_owner','lease_expires_at','attempt_count','started_at','finished_at','updated_at']) THEN
  RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='immutable import identity or terminal result';
 END IF;
 IF NEW.status IS DISTINCT FROM OLD.status AND NEW.revision<>OLD.revision+1 THEN
  RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='import transition requires next revision';
 END IF;
 IF OLD.started_at IS NOT NULL AND NEW.started_at IS DISTINCT FROM OLD.started_at THEN
  RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='first import execution time is immutable';
 END IF;
 IF OLD.status='RUNNING' AND NEW.status='QUEUED' THEN
  RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='import recovery reserves a fresh running lease';
 END IF;
 IF OLD.status='QUEUED' AND NEW.status='RUNNING' AND NEW.attempt_count<>0 THEN
  RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='initial import recovery count must be zero';
 END IF;
 IF NEW.lease_owner IS DISTINCT FROM OLD.lease_owner AND OLD.lease_owner IS NOT NULL AND NEW.status='RUNNING'
 AND (OLD.lease_expires_at>clock_timestamp() OR NEW.lease_owner IS NULL OR NEW.attempt_count<>OLD.attempt_count+1 OR NEW.revision<>OLD.revision+1) THEN
  RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='invalid expired import lease recovery';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER guard_import_job BEFORE UPDATE ON judge.import_jobs FOR EACH ROW EXECUTE FUNCTION judge.guard_import_job();
CREATE FUNCTION judge.guard_import_item() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.status IN ('VALIDATED','REJECTED') OR (to_jsonb(NEW)-ARRAY['status','problem_id','problem_version_id','license_status','validation_status','errors','updated_at'])
 IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['status','problem_id','problem_version_id','license_status','validation_status','errors','updated_at']) THEN
  RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='immutable import item identity or terminal result';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER guard_import_item BEFORE UPDATE ON judge.import_items FOR EACH ROW EXECUTE FUNCTION judge.guard_import_item();
CREATE FUNCTION judge.check_rejected_evidence() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM judge.import_items i JOIN judge.import_jobs j ON j.id=i.import_job_id
 WHERE i.id=NEW.import_item_id AND i.status='REJECTED' AND i.package_path=NEW.package_path AND j.repository_url=NEW.repository_url AND j.source_revision=NEW.source_revision)
 OR (NEW.license_evidence_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM judge.license_evidence l WHERE l.id=NEW.license_evidence_id
 AND l.repository_url=NEW.repository_url AND l.source_revision=NEW.source_revision AND l.package_path=NEW.package_path)) THEN
  RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='rejected evidence source/item mismatch';
 END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER check_rejected_evidence AFTER INSERT ON judge.rejected_package_evidence DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION judge.check_rejected_evidence();
CREATE FUNCTION judge.check_snapshot_counts() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE snapshot uuid; expected integer; actual integer;
BEGIN
 IF TG_TABLE_NAME='catalog_snapshots' THEN snapshot:=NEW.id; ELSE snapshot:=NEW.snapshot_id; END IF;
 SELECT item_count INTO expected FROM judge.catalog_snapshots WHERE id=snapshot;
 IF NOT FOUND THEN RETURN NULL; END IF;
 SELECT count(*) INTO actual FROM judge.catalog_snapshot_items WHERE snapshot_id=snapshot;
 IF expected<>actual OR (actual>0 AND ((SELECT min(ordinal) FROM judge.catalog_snapshot_items WHERE snapshot_id=snapshot)<>0
 OR (SELECT max(ordinal) FROM judge.catalog_snapshot_items WHERE snapshot_id=snapshot)<>actual-1))
 OR EXISTS(SELECT 1 FROM judge.catalog_snapshot_items i JOIN judge.problem_versions v ON v.id=i.problem_version_id
 WHERE i.snapshot_id=snapshot AND v.first_published_at IS NULL) THEN
  RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='snapshot count or ordinal mismatch';
 END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER check_snapshot_counts AFTER INSERT OR UPDATE ON judge.catalog_snapshots DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION judge.check_snapshot_counts();
CREATE CONSTRAINT TRIGGER check_snapshot_item_counts AFTER INSERT OR UPDATE ON judge.catalog_snapshot_items DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION judge.check_snapshot_counts();

CREATE FUNCTION judge.guard_snapshot() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE expiry timestamptz;
BEGIN
 IF TG_OP='UPDATE' THEN RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='immutable catalog snapshot'; END IF;
 IF TG_TABLE_NAME='catalog_snapshots' THEN expiry:=OLD.expires_at;
 ELSE
  SELECT expires_at INTO expiry FROM judge.catalog_snapshots WHERE id=OLD.snapshot_id;
  IF FOUND THEN RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='clean snapshots as a whole'; END IF;
 END IF;
 IF expiry>clock_timestamp() THEN RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='unexpired snapshot cannot be cleaned'; END IF;
 RETURN OLD;
END $$;
CREATE TRIGGER guard_snapshot BEFORE UPDATE OR DELETE ON judge.catalog_snapshots FOR EACH ROW EXECUTE FUNCTION judge.guard_snapshot();
CREATE TRIGGER guard_snapshot_item BEFORE UPDATE OR DELETE ON judge.catalog_snapshot_items FOR EACH ROW EXECUTE FUNCTION judge.guard_snapshot();

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA judge FROM PUBLIC;
COMMIT;
