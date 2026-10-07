-- Refs #6. Run as the database operator after the native forward migration.
\set ON_ERROR_STOP on
BEGIN;
SELECT pg_advisory_xact_lock(721035082);
GRANT USAGE ON SCHEMA judge TO judge_runtime;
GRANT SELECT ON ALL TABLES IN SCHEMA judge TO judge_runtime;
-- Explicit list prevents writes to the native version/checksum tracking tables.
GRANT INSERT, UPDATE ON
  judge.platform_problems, judge.problem_versions, judge.package_artifacts,
  judge.package_source_identities, judge.package_content_identities,
  judge.license_evidence, judge.package_validation_runs,
  judge.problem_test_cases, judge.reference_solutions,
  judge.import_jobs, judge.import_items, judge.rejected_package_evidence,
  judge.catalog_state, judge.catalog_snapshots, judge.catalog_snapshot_items,
  judge.judge_tasks, judge.judge_results, judge.judge_case_results,
  judge.judge_language_configs, judge.callback_outbox, judge.operation_requests
  TO judge_runtime;
GRANT DELETE ON judge.catalog_snapshots, judge.catalog_snapshot_items TO judge_runtime;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA judge TO judge_runtime;
-- Functions are schema-qualified, trigger functions and use invoker privileges.
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA judge TO judge_runtime;
COMMIT;
\echo Judge runtime grants applied; tracking tables remain read-only
