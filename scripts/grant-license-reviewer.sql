-- Refs #8. Run as the database operator after all forward migrations.
-- This credential is private to the audited offline ADMIN command.
\set ON_ERROR_STOP on
\set ECHO none
SET log_statement = 'none';
SET log_min_error_statement = 'panic';
SET log_min_duration_statement = -1;
SET log_min_duration_sample = -1;
SET log_duration = off;
SET log_parameter_max_length = 0;
SET log_parameter_max_length_on_error = 0;
SET log_transaction_sample_rate = 0;
SET log_error_verbosity = 'terse';
SET log_min_messages = 'panic';
SELECT CASE WHEN EXISTS (SELECT 1 FROM pg_settings WHERE name='pgaudit.log')
       THEN set_config('pgaudit.log', 'none', false) ELSE 'none' END AS audit_policy \gset
SELECT CASE WHEN EXISTS (SELECT 1 FROM pg_settings WHERE name='pgaudit.role')
       THEN set_config('pgaudit.role', '', false) ELSE '' END AS object_audit_policy \gset
\getenv judge_license_password JUDGE_LICENSE_REVIEW_PASSWORD
\getenv judge_runtime_password JUDGE_RUNTIME_PASSWORD
\getenv judge_migration_password JUDGE_MIGRATION_PASSWORD
\if :{?judge_license_password}
\else
  DO $$ BEGIN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='License reviewer password is required'; END $$;
\endif
\if :{?judge_runtime_password}
\else
  DO $$ BEGIN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='Runtime credential is required for reviewer separation check'; END $$;
\endif
\if :{?judge_migration_password}
\else
  DO $$ BEGIN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='Migration credential is required for reviewer separation check'; END $$;
\endif
SELECT length(:'judge_license_password') >= 32
 AND :'judge_license_password'<>:'judge_runtime_password'
 AND :'judge_license_password'<>:'judge_migration_password' AS credential_valid \gset
\if :credential_valid
\else
  DO $$ BEGIN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='License reviewer credential must be independent and at least 32 characters'; END $$;
\endif
BEGIN;
SELECT pg_advisory_xact_lock(721035082);
SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='judge_license_reviewer') AS reviewer_exists \gset
\if :reviewer_exists
\else
  CREATE ROLE judge_license_reviewer LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD :'judge_license_password';
\endif
SELECT rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole
 AND NOT rolinherit AND NOT rolreplication AND NOT rolbypassrls
 AND NOT EXISTS(SELECT 1 FROM pg_auth_members WHERE member=r.oid OR roleid=r.oid)
 AND NOT EXISTS(SELECT 1 FROM pg_database WHERE datdba=r.oid)
 AND NOT EXISTS(SELECT 1 FROM pg_class WHERE relowner=r.oid)
 AND NOT EXISTS(SELECT 1 FROM pg_namespace WHERE nspowner=r.oid)
 AND NOT has_database_privilege(r.rolname,current_database(),'CREATE')
 AND NOT has_database_privilege(r.rolname,current_database(),'TEMPORARY')
 AND NOT EXISTS(SELECT 1 FROM pg_namespace n WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema' AND has_schema_privilege(r.rolname,n.oid,'CREATE'))
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema' AND c.relkind IN ('r','p','v','m','f')
   AND ((NOT(n.nspname='judge' AND c.relname IN ('license_evidence','rejected_package_evidence','private_objects'))
         AND (has_table_privilege(r.rolname,c.oid,'SELECT') OR has_any_column_privilege(r.rolname,c.oid,'SELECT')))
     OR (NOT(n.nspname='judge' AND c.relname='license_evidence') AND (has_table_privilege(r.rolname,c.oid,'INSERT') OR has_any_column_privilege(r.rolname,c.oid,'INSERT')))
     OR has_table_privilege(r.rolname,c.oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege(r.rolname,c.oid,'UPDATE,REFERENCES')))
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
   WHERE CASE WHEN c.relkind='S' AND n.nspname !~ '^pg_' THEN has_sequence_privilege(r.rolname,c.oid,'USAGE,UPDATE') ELSE false END)
 AS reviewer_safe FROM pg_roles r WHERE rolname='judge_license_reviewer' \gset
\if :reviewer_safe
\else
  DO $$ BEGIN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='Unsafe existing license reviewer authority requires operator remediation'; END $$;
\endif
SELECT current_database() AS judge_database \gset
GRANT CONNECT ON DATABASE :"judge_database" TO judge_license_reviewer;
GRANT USAGE ON SCHEMA judge TO judge_license_reviewer;
GRANT SELECT ON judge.license_evidence,judge.rejected_package_evidence,judge.private_objects TO judge_license_reviewer;
GRANT INSERT ON judge.license_evidence TO judge_license_reviewer;
GRANT EXECUTE ON FUNCTION judge.valid_package_path(text) TO judge_license_reviewer;
ALTER ROLE judge_license_reviewer IN DATABASE :"judge_database" SET search_path=pg_catalog,judge;
-- Receipt text and private source evidence must not enter ordinary SQL logs.
ALTER ROLE judge_license_reviewer IN DATABASE :"judge_database" SET log_statement='none';
ALTER ROLE judge_license_reviewer IN DATABASE :"judge_database" SET log_min_error_statement='panic';
ALTER ROLE judge_license_reviewer IN DATABASE :"judge_database" SET log_min_duration_statement=-1;
ALTER ROLE judge_license_reviewer IN DATABASE :"judge_database" SET log_min_duration_sample=-1;
ALTER ROLE judge_license_reviewer IN DATABASE :"judge_database" SET log_duration=off;
ALTER ROLE judge_license_reviewer IN DATABASE :"judge_database" SET log_parameter_max_length=0;
ALTER ROLE judge_license_reviewer IN DATABASE :"judge_database" SET log_parameter_max_length_on_error=0;
ALTER ROLE judge_license_reviewer IN DATABASE :"judge_database" SET log_transaction_sample_rate=0;
ALTER ROLE judge_license_reviewer IN DATABASE :"judge_database" SET log_error_verbosity='terse';
ALTER ROLE judge_license_reviewer IN DATABASE :"judge_database" SET log_min_messages='panic';
SELECT EXISTS(SELECT 1 FROM pg_settings WHERE name='pgaudit.log') AS reviewer_pgaudit \gset
\if :reviewer_pgaudit
  ALTER ROLE judge_license_reviewer IN DATABASE :"judge_database" SET pgaudit.log='none';
\endif
SELECT EXISTS(SELECT 1 FROM pg_settings WHERE name='pgaudit.role') AS reviewer_object_audit \gset
\if :reviewer_object_audit
  ALTER ROLE judge_license_reviewer IN DATABASE :"judge_database" SET pgaudit.role='';
\endif
COMMIT;
\echo Offline ADMIN license reviewer authority provisioned; existing password retained
