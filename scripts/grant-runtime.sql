-- Refs #6. Run as the database operator after the native forward migration.
\set ON_ERROR_STOP on
\set ECHO none
-- Private JSON/source evidence must stay out of ordinary statement, parameter,
-- duration, transaction-sample and database error-detail logs. These settings
-- affect this operator session and this role/database, never the whole server.
SET log_statement='none';
SET log_min_error_statement='panic';
SET log_min_duration_statement=-1;
SET log_min_duration_sample=-1;
SET log_duration=off;
SET log_parameter_max_length=0;
SET log_parameter_max_length_on_error=0;
SET log_transaction_sample_rate=0;
SET log_error_verbosity='terse';
SET log_min_messages='panic';
SELECT CASE WHEN EXISTS(SELECT 1 FROM pg_settings WHERE name='pgaudit.log')
  THEN set_config('pgaudit.log','none',false) ELSE 'none' END AS audit_policy \gset
SELECT CASE WHEN EXISTS(SELECT 1 FROM pg_settings WHERE name='pgaudit.role')
  THEN set_config('pgaudit.role','',false) ELSE '' END AS audit_object_role \gset
BEGIN;
SELECT pg_advisory_xact_lock(721035082);
SELECT current_database() AS judge_database \gset
ALTER ROLE judge_runtime IN DATABASE :"judge_database" SET log_statement='none';
ALTER ROLE judge_runtime IN DATABASE :"judge_database" SET log_min_error_statement='panic';
ALTER ROLE judge_runtime IN DATABASE :"judge_database" SET log_min_duration_statement=-1;
ALTER ROLE judge_runtime IN DATABASE :"judge_database" SET log_min_duration_sample=-1;
ALTER ROLE judge_runtime IN DATABASE :"judge_database" SET log_duration=off;
ALTER ROLE judge_runtime IN DATABASE :"judge_database" SET log_parameter_max_length=0;
ALTER ROLE judge_runtime IN DATABASE :"judge_database" SET log_parameter_max_length_on_error=0;
ALTER ROLE judge_runtime IN DATABASE :"judge_database" SET log_transaction_sample_rate=0;
ALTER ROLE judge_runtime IN DATABASE :"judge_database" SET log_error_verbosity='terse';
ALTER ROLE judge_runtime IN DATABASE :"judge_database" SET log_min_messages='panic';
SELECT EXISTS(SELECT 1 FROM pg_settings WHERE name='pgaudit.log') AS runtime_pgaudit \gset
\if :runtime_pgaudit
  ALTER ROLE judge_runtime IN DATABASE :"judge_database" SET pgaudit.log='none';
\endif
SELECT EXISTS(SELECT 1 FROM pg_settings WHERE name='pgaudit.role') AS runtime_pgaudit_role \gset
\if :runtime_pgaudit_role
  ALTER ROLE judge_runtime IN DATABASE :"judge_database" SET pgaudit.role='';
\endif
GRANT USAGE ON SCHEMA judge TO judge_runtime;
GRANT SELECT ON ALL TABLES IN SCHEMA judge TO judge_runtime;
-- Explicit list prevents writes to the native version/checksum tracking tables.
GRANT INSERT, UPDATE ON
  judge.platform_problems, judge.problem_versions, judge.package_artifacts,
  judge.package_source_identities, judge.package_content_identities,
  judge.package_validation_runs,
  judge.problem_test_cases, judge.reference_solutions,
  judge.import_jobs, judge.import_items, judge.rejected_package_evidence,
  judge.catalog_state, judge.catalog_snapshots, judge.catalog_snapshot_items,
  judge.judge_tasks, judge.judge_results, judge.judge_case_results,
  judge.judge_language_configs, judge.callback_outbox, judge.operation_requests
  TO judge_runtime;
-- Automatic collection cannot supply approval identity/time. VERIFIED requires
-- both columns, so only the offline reviewer credential can approve a package.
REVOKE INSERT, UPDATE ON judge.license_evidence FROM judge_runtime;
GRANT INSERT(id,repository_url,source_revision,package_path,previous_evidence_id,
  status,license_scope,spdx_id,notice,source_url,license_files,evidence,created_at)
  ON judge.license_evidence TO judge_runtime;
DO $$ BEGIN
  IF has_column_privilege('judge_runtime','judge.license_evidence','reviewed_by','INSERT')
    OR has_column_privilege('judge_runtime','judge.license_evidence','reviewed_at','INSERT') THEN
    RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='Runtime license approval privileges are unsafe';
  END IF;
END $$;
GRANT DELETE ON judge.catalog_snapshots, judge.catalog_snapshot_items TO judge_runtime;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA judge TO judge_runtime;
-- Dispatcher finishes/reaps append-only manual outcomes; it cannot authorize
-- a manual action by inserting callback_redelivery_requests.
GRANT INSERT ON judge.callback_redelivery_outcomes TO judge_runtime;
GRANT INSERT ON judge.import_attempt_evidence TO judge_runtime;
-- Private identity/reference rows are append-only; cleanup is constrained by
-- owner/retention triggers. Stages alone may be renewed while still active.
GRANT INSERT, DELETE ON judge.private_objects, judge.private_object_references TO judge_runtime;
GRANT INSERT, UPDATE, DELETE ON judge.private_object_stages TO judge_runtime;
-- Functions are schema-qualified, trigger functions and use invoker privileges.
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA judge TO judge_runtime;
COMMIT;
\echo Judge runtime grants applied; tracking tables remain read-only
