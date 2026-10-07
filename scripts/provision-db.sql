-- Refs #6. Run only as the database operator, before judge-migrate up.
-- Passwords come from the operator's environment, never command-line arguments.
-- This script refuses unsafe existing grants; it does not take over other roles.
\set ON_ERROR_STOP on
\set ECHO none
-- Fail before using passwords if the operator cannot suppress session SQL logs.
-- An external SQL proxy/auditor must separately have a reviewed secret policy.
SET log_statement = 'none';
SET log_min_error_statement = 'panic';
SET log_min_duration_statement = -1;
SET log_min_duration_sample = -1;
SET log_transaction_sample_rate = 0;
SET log_duration = off;
SET log_min_messages = 'panic';
SET log_error_verbosity = 'terse';
SET log_parameter_max_length = 0;
SET log_parameter_max_length_on_error = 0;
SELECT CASE WHEN EXISTS (SELECT 1 FROM pg_settings WHERE name='pgaudit.log')
       THEN set_config('pgaudit.log', 'none', false) ELSE 'none' END AS audit_policy \gset
SELECT CASE WHEN EXISTS (SELECT 1 FROM pg_settings WHERE name='pgaudit.role')
       THEN set_config('pgaudit.role', '', false) ELSE '' END AS object_audit_policy \gset
\getenv judge_migration_password JUDGE_MIGRATION_PASSWORD
\getenv judge_runtime_password JUDGE_RUNTIME_PASSWORD
\if :{?judge_migration_password}
\else
  \echo JUDGE_MIGRATION_PASSWORD is required
  DO $$ BEGIN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='Judge provisioning rejected'; END $$;
\endif
\if :{?judge_runtime_password}
\else
  \echo JUDGE_RUNTIME_PASSWORD is required
  DO $$ BEGIN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='Judge provisioning rejected'; END $$;
\endif
SELECT length(:'judge_migration_password') >= 32
   AND length(:'judge_runtime_password') >= 32
   AND :'judge_migration_password' <> :'judge_runtime_password' AS credentials_valid \gset
\if :credentials_valid
\else
  \echo Independent passwords of at least 32 characters are required
  DO $$ BEGIN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='Judge provisioning rejected'; END $$;
\endif

BEGIN;
SELECT pg_advisory_xact_lock(721035082);
SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'judge_migration') AS migration_exists \gset
\if :migration_exists
\else
  CREATE ROLE judge_migration LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD :'judge_migration_password';
\endif
SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'judge_runtime') AS runtime_exists \gset
\if :runtime_exists
\else
  CREATE ROLE judge_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD :'judge_runtime_password';
\endif
SELECT count(*) = 2 AND bool_and(rolcanlogin AND NOT rolsuper AND NOT rolcreatedb
       AND NOT rolcreaterole AND NOT rolinherit AND NOT rolreplication AND NOT rolbypassrls)
       AND NOT EXISTS (SELECT 1 FROM pg_auth_members WHERE member IN
          (SELECT oid FROM pg_roles WHERE rolname IN ('judge_migration','judge_runtime'))
          OR roleid IN (SELECT oid FROM pg_roles WHERE rolname IN ('judge_migration','judge_runtime')))
       AS roles_safe
  FROM pg_roles WHERE rolname IN ('judge_migration','judge_runtime') \gset
\if :roles_safe
\else
  \echo Existing Judge roles are unsafe; inspect their attributes and memberships
  DO $$ BEGIN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='Judge provisioning rejected'; END $$;
\endif
SELECT NOT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'judge'
         AND nspowner <> (SELECT oid FROM pg_roles WHERE rolname = 'judge_migration')) AS owner_safe \gset
\if :owner_safe
\else
  \echo Existing judge schema has a different owner; no ownership was changed
  DO $$ BEGIN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='Judge provisioning rejected'; END $$;
\endif

SELECT current_database() AS judge_database \gset
CREATE SCHEMA IF NOT EXISTS judge AUTHORIZATION judge_migration;
GRANT CONNECT ON DATABASE :"judge_database" TO judge_migration, judge_runtime;
GRANT USAGE ON SCHEMA judge TO judge_runtime;
ALTER ROLE judge_migration IN DATABASE :"judge_database" SET search_path = pg_catalog, judge;
ALTER ROLE judge_runtime IN DATABASE :"judge_database" SET search_path = pg_catalog, judge;

-- PUBLIC may grant privileges even to a NOINHERIT role. Refuse such a database
-- instead of altering the other services' privilege policy as a side effect.
SELECT NOT has_database_privilege('judge_runtime', current_database(), 'CREATE')
   AND NOT has_database_privilege('judge_runtime', current_database(), 'TEMPORARY')
   AND NOT has_schema_privilege('judge_runtime', 'judge', 'CREATE')
   AND NOT EXISTS (SELECT 1 FROM pg_namespace n,
          LATERAL aclexplode(COALESCE(n.nspacl, acldefault('n', n.nspowner))) a
          WHERE n.nspname='judge' AND a.privilege_type='CREATE' AND a.grantee<>n.nspowner)
   AND NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
          WHERE n.nspname='judge' AND c.relname IN ('schema_migrations','migration_checksums')
            AND has_table_privilege('judge_runtime', c.oid, 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'))
   AND NOT EXISTS (SELECT 1 FROM pg_namespace n
          WHERE n.nspname <> 'judge' AND n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
            AND (has_schema_privilege('judge_runtime', n.oid, 'CREATE')
              OR has_schema_privilege('judge_migration', n.oid, 'CREATE')))
   AND NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
          WHERE n.nspname <> 'judge' AND n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
            AND c.relkind IN ('r','p','v','m','f')
            AND (has_table_privilege('judge_runtime', c.oid, 'SELECT,INSERT,UPDATE,DELETE')
              OR has_table_privilege('judge_migration', c.oid, 'SELECT,INSERT,UPDATE,DELETE')))
   AS boundaries_safe \gset
\if :boundaries_safe
\else
  \echo Unsafe PUBLIC or cross-service grants detected; operator remediation is required
  DO $$ BEGIN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='Judge provisioning rejected'; END $$;
\endif
COMMIT;
\echo Judge roles and schema provisioned; existing passwords were retained
