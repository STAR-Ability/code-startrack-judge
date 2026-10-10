-- Refs #19. Provision the trusted reconciliation role after all migrations.
-- Use a direct operator PostgreSQL session with a reviewed proxy/audit policy.
\set ON_ERROR_STOP on
\set ECHO none
SET log_statement = 'none';
SET log_min_error_statement = 'panic';
SET log_min_duration_statement = -1;
SET log_min_duration_sample = -1;
SET log_duration = off;
SET log_parameter_max_length = 0;
SET log_parameter_max_length_on_error = 0;
SELECT CASE WHEN EXISTS (SELECT 1 FROM pg_settings WHERE name='pgaudit.log')
 THEN set_config('pgaudit.log','none',false) ELSE 'none' END AS audit_policy \gset
\getenv outbox_operator_password JUDGE_OUTBOX_OPERATOR_PASSWORD
\if :{?outbox_operator_password}
\else
 \echo JUDGE_OUTBOX_OPERATOR_PASSWORD is required
 DO $$ BEGIN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='Outbox operator provisioning rejected'; END $$;
\endif
SELECT length(:'outbox_operator_password')>=32 AS credentials_valid \gset
\if :credentials_valid
\else
 \echo Outbox operator password must have at least 32 characters
 DO $$ BEGIN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='Outbox operator provisioning rejected'; END $$;
\endif

BEGIN;
SELECT pg_advisory_xact_lock(721035082);
SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='judge_outbox_operator') AS operator_exists \gset
\if :operator_exists
\else
 CREATE ROLE judge_outbox_operator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD :'outbox_operator_password';
\endif
SELECT count(*)=1 AND bool_and(rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole
 AND NOT rolinherit AND NOT rolreplication AND NOT rolbypassrls)
 AND NOT EXISTS (SELECT 1 FROM pg_auth_members WHERE member IN (SELECT oid FROM pg_roles WHERE rolname='judge_outbox_operator')
 OR roleid IN (SELECT oid FROM pg_roles WHERE rolname='judge_outbox_operator')) AS role_safe
FROM pg_roles WHERE rolname='judge_outbox_operator' \gset
\if :role_safe
\else
 \echo Existing outbox operator role has unsafe attributes or memberships
 DO $$ BEGIN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='Outbox operator provisioning rejected'; END $$;
\endif

-- Refuse pre-existing broad privileges rather than silently removing them.
SELECT NOT has_database_privilege('judge_outbox_operator',current_database(),'CREATE,TEMPORARY')
 AND NOT EXISTS(SELECT 1 FROM pg_database WHERE datdba=(SELECT oid FROM pg_roles WHERE rolname='judge_outbox_operator'))
 AND NOT EXISTS(SELECT 1 FROM pg_namespace WHERE nspowner=(SELECT oid FROM pg_roles WHERE rolname='judge_outbox_operator')
 OR (nspname !~ '^pg_' AND nspname<>'information_schema' AND has_schema_privilege('judge_outbox_operator',oid,'CREATE')))
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE c.relowner=(SELECT oid FROM pg_roles WHERE rolname='judge_outbox_operator') OR
 (n.nspname !~ '^pg_' AND n.nspname<>'information_schema' AND c.relkind IN('r','p','v','m','f') AND (
  (NOT(n.nspname='judge' AND c.relname IN('callback_outbox','callback_redelivery_requests','callback_redelivery_outcomes'))
   AND has_table_privilege('judge_outbox_operator',c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'))
  OR (n.nspname='judge' AND c.relname IN('callback_outbox','callback_redelivery_requests','callback_redelivery_outcomes') AND (
   has_table_privilege('judge_outbox_operator',c.oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
   OR (c.relname='callback_outbox' AND has_table_privilege('judge_outbox_operator',c.oid,'INSERT')))))))
 AND NOT EXISTS(SELECT 1 FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE a.attnum>0 AND NOT a.attisdropped AND n.nspname !~ '^pg_' AND n.nspname<>'information_schema'
 AND ((has_column_privilege('judge_outbox_operator',c.oid,a.attnum,'SELECT') AND NOT(n.nspname='judge'
 AND c.relname IN('callback_outbox','callback_redelivery_requests','callback_redelivery_outcomes')))
 OR (has_column_privilege('judge_outbox_operator',c.oid,a.attnum,'UPDATE') AND NOT(n.nspname='judge' AND c.relname='callback_outbox'
 AND a.attname IN('status','attempt_count','next_attempt_at','lease_owner','lease_expires_at','last_error_code','updated_at','delivered_at')))
 OR (has_column_privilege('judge_outbox_operator',c.oid,a.attnum,'INSERT') AND NOT(n.nspname='judge'
 AND c.relname IN('callback_redelivery_requests','callback_redelivery_outcomes')))))
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE CASE WHEN c.relkind='S' AND n.nspname !~ '^pg_'
 THEN has_sequence_privilege('judge_outbox_operator',c.oid,'USAGE,UPDATE') ELSE false END)
 AS privileges_safe \gset
\if :privileges_safe
\else
 \echo Unsafe PUBLIC, ownership, or existing outbox operator grants detected
 DO $$ BEGIN RAISE EXCEPTION USING ERRCODE='42501', MESSAGE='Outbox operator provisioning rejected'; END $$;
\endif

SELECT current_database() AS outbox_database \gset
GRANT CONNECT ON DATABASE :"outbox_database" TO judge_outbox_operator;
GRANT USAGE ON SCHEMA judge TO judge_outbox_operator;
ALTER ROLE judge_outbox_operator IN DATABASE :"outbox_database" SET search_path=pg_catalog,judge;
GRANT SELECT ON judge.callback_outbox,judge.callback_redelivery_requests,judge.callback_redelivery_outcomes TO judge_outbox_operator;
GRANT UPDATE(status,attempt_count,next_attempt_at,lease_owner,lease_expires_at,last_error_code,updated_at,delivered_at)
 ON judge.callback_outbox TO judge_outbox_operator;
GRANT INSERT ON judge.callback_redelivery_requests,judge.callback_redelivery_outcomes TO judge_outbox_operator;
GRANT EXECUTE ON FUNCTION judge.guard_outbox(),judge.immutable_row(),judge.check_callback_redelivery_request(),judge.check_callback_redelivery_outcome()
 TO judge_outbox_operator;
COMMIT;
\echo Outbox operator grants applied; existing password was retained
