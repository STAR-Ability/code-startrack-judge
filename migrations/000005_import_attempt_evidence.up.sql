-- Refs #10/#11: retain interrupted validation evidence independently of final
-- rejected-item evidence. Existing rejected-item/qualification guards stay intact.
BEGIN;

CREATE TABLE judge.import_attempt_evidence (
 id uuid PRIMARY KEY,
 import_item_id uuid NOT NULL REFERENCES judge.import_items(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
 attempt_token uuid NOT NULL,
 recovery_count integer NOT NULL CHECK(recovery_count BETWEEN 0 AND 3),
 repository_url text NOT NULL CHECK(repository_url='https://github.com/oj-lab/problem-packages'),
 source_revision judge.commit_hex NOT NULL,
 package_path text NOT NULL CHECK(judge.valid_package_path(package_path)),
 failure_stage text NOT NULL CHECK(failure_stage='VALIDATION_FAILED'),
 source_archive_key text NOT NULL REFERENCES judge.private_objects(object_key) ON DELETE RESTRICT ON UPDATE RESTRICT,
 source_sha256 judge.sha256_hex NOT NULL,
 normalized_archive_key text NOT NULL REFERENCES judge.private_objects(object_key) ON DELETE RESTRICT ON UPDATE RESTRICT,
 normalized_sha256 judge.sha256_hex NOT NULL,
 license_evidence_id uuid NOT NULL REFERENCES judge.license_evidence(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
 provenance jsonb NOT NULL CHECK(jsonb_typeof(provenance)='object'
  AND provenance @> '{"complete":false}'::jsonb
  AND provenance ? 'validationEvidenceChunks' AND provenance ? 'fencingToken'
  AND jsonb_typeof(provenance->'validationEvidenceChunks')='array'
  AND jsonb_typeof(provenance->'fencingToken')='string'
  AND provenance->>'fencingToken'=attempt_token::text),
 source_metadata jsonb NOT NULL CHECK(jsonb_typeof(source_metadata)='object'),
 adaptations jsonb NOT NULL CHECK(jsonb_typeof(adaptations)='array'),
 errors jsonb NOT NULL CHECK(jsonb_typeof(errors)='array' AND jsonb_array_length(errors)>0),
 validation_log_key text NOT NULL REFERENCES judge.private_objects(object_key) ON DELETE RESTRICT ON UPDATE RESTRICT,
 evidence_sha256 judge.sha256_hex NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(import_item_id,attempt_token),
 CHECK(source_archive_key='sha256/'||left(source_sha256::text,2)||'/'||source_sha256::text),
 CHECK(normalized_archive_key='sha256/'||left(normalized_sha256::text,2)||'/'||normalized_sha256::text)
);
CREATE TRIGGER immutable_import_attempt_evidence BEFORE UPDATE OR DELETE ON judge.import_attempt_evidence
 FOR EACH ROW EXECUTE FUNCTION judge.immutable_row();

CREATE FUNCTION judge.check_import_attempt_evidence() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE job_id uuid;
BEGIN
 SELECT import_job_id INTO job_id FROM judge.import_items WHERE id=NEW.import_item_id;
 PERFORM 1 FROM judge.import_jobs WHERE id=job_id FOR UPDATE;
 -- Evaluate the clock after the potentially waiting job tuple lock.
 IF NOT EXISTS(SELECT 1 FROM judge.import_items i JOIN judge.import_jobs j ON j.id=i.import_job_id
  JOIN judge.license_evidence l ON l.id=NEW.license_evidence_id
  WHERE i.id=NEW.import_item_id AND i.status='PENDING' AND i.package_path=NEW.package_path
  AND j.repository_url=NEW.repository_url AND j.source_revision=NEW.source_revision
  AND j.status='RUNNING' AND j.lease_owner=NEW.attempt_token
  AND j.attempt_count=NEW.recovery_count AND j.lease_expires_at>clock_timestamp()
  AND l.repository_url=NEW.repository_url AND l.source_revision=NEW.source_revision
  AND l.package_path=NEW.package_path AND l.status='VERIFIED'
  AND l.evidence->>'sourceSha256'=NEW.source_sha256::text
  AND (l.evidence->>'normalizedSha256' IS NULL OR l.evidence->>'normalizedSha256'=NEW.normalized_sha256::text)) THEN
  RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='incomplete import evidence lacks live matching reservation';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER check_import_attempt_evidence_before BEFORE INSERT ON judge.import_attempt_evidence
 FOR EACH ROW EXECUTE FUNCTION judge.check_import_attempt_evidence();
CREATE CONSTRAINT TRIGGER check_import_attempt_evidence_commit AFTER INSERT ON judge.import_attempt_evidence
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION judge.check_import_attempt_evidence();

ALTER TABLE judge.private_object_references DROP CONSTRAINT private_object_references_owner_type_check;
ALTER TABLE judge.private_object_references ADD CONSTRAINT private_object_references_owner_type_check
 CHECK(owner_type IN ('ARTIFACT','TEST','REFERENCE','TASK','REJECTED','VALIDATION','RESULT','IMPORT_ATTEMPT'));

CREATE OR REPLACE FUNCTION judge.check_object_reference_owner() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE valid boolean := false;
BEGIN
 CASE NEW.owner_type
 WHEN 'ARTIFACT' THEN
  SELECT (NEW.role='SOURCE' AND source_archive_key=NEW.object_key)
   OR (NEW.role='NORMALIZED' AND normalized_archive_key=NEW.object_key)
   OR (NEW.role='FILE' AND EXISTS(SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(manifest->'files')='array' THEN manifest->'files' ELSE '[]'::jsonb END) item
       JOIN judge.private_objects o ON o.object_key=NEW.object_key WHERE item->>'normalizedSha256'=o.sha256::text))
  INTO valid FROM judge.package_artifacts WHERE id=NEW.owner_id;
 WHEN 'TEST' THEN
  SELECT (NEW.role='INPUT' AND input_object_key=NEW.object_key)
   OR (NEW.role='ANSWER' AND answer_object_key=NEW.object_key)
  INTO valid FROM judge.problem_test_cases WHERE id=NEW.owner_id;
 WHEN 'REFERENCE' THEN
  SELECT NEW.role='SOURCE' AND source_object_key=NEW.object_key INTO valid
  FROM judge.reference_solutions WHERE id=NEW.owner_id;
 WHEN 'TASK' THEN
  SELECT NEW.role='SOURCE' AND transient_source_key=NEW.object_key INTO valid
  FROM judge.judge_tasks WHERE id=NEW.owner_id;
 WHEN 'REJECTED' THEN
  SELECT (NEW.role='SOURCE' AND source_archive_key=NEW.object_key)
   OR (NEW.role='NORMALIZED' AND normalized_archive_key=NEW.object_key)
   OR (NEW.role='LOG' AND validation_log_key=NEW.object_key)
   OR (NEW.role='EVIDENCE_LOG' AND EXISTS(SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(provenance->'validationEvidenceChunks')='array' THEN provenance->'validationEvidenceChunks' ELSE '[]'::jsonb END) entry
       WHERE entry->>'objectKey'=NEW.object_key))
  INTO valid FROM judge.rejected_package_evidence WHERE id=NEW.owner_id;
 WHEN 'IMPORT_ATTEMPT' THEN
  SELECT (NEW.role='SOURCE' AND source_archive_key=NEW.object_key)
   OR (NEW.role='NORMALIZED' AND normalized_archive_key=NEW.object_key)
   OR (NEW.role='LOG' AND validation_log_key=NEW.object_key)
   OR (NEW.role='EVIDENCE_LOG' AND EXISTS(SELECT 1 FROM jsonb_array_elements(provenance->'validationEvidenceChunks') entry
       WHERE entry->>'objectKey'=NEW.object_key))
  INTO valid FROM judge.import_attempt_evidence WHERE id=NEW.owner_id;
 WHEN 'VALIDATION' THEN
  SELECT (NEW.role='LOG' AND log_object_key=NEW.object_key)
   OR (NEW.role='EVIDENCE_LOG' AND EXISTS(SELECT 1 FROM jsonb_each(results) section
      CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(section.value->'evidence')='array' THEN section.value->'evidence' ELSE '[]'::jsonb END) entry
      WHERE entry->>'logObjectKey'=NEW.object_key)) INTO valid
  FROM judge.package_validation_runs WHERE id=NEW.owner_id;
 WHEN 'RESULT' THEN
  SELECT (NEW.role='LOG' AND raw_execution_log_key=NEW.object_key)
   OR (NEW.role='CASE_LOG' AND EXISTS(SELECT 1 FROM judge.judge_case_results cr
      WHERE cr.judge_task_id=NEW.owner_id AND cr.private_log_key=NEW.object_key)) INTO valid
  FROM judge.judge_results WHERE judge_task_id=NEW.owner_id;
 END CASE;
 IF NOT coalesce(valid,false) THEN
  RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='private object reference lacks matching owner';
 END IF;
 RETURN NULL;
END $$;
-- Preserve the exact prior historical-owner search; add attempt history to it.
ALTER FUNCTION judge.private_object_has_business_owner(text) RENAME TO private_object_has_business_owner_v3;
CREATE FUNCTION judge.private_object_has_business_owner(candidate_key text)
RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT judge.private_object_has_business_owner_v3(candidate_key)
 OR EXISTS(SELECT 1 FROM judge.import_attempt_evidence a
  WHERE a.source_archive_key=candidate_key OR a.normalized_archive_key=candidate_key
  OR a.validation_log_key=candidate_key
  OR EXISTS(SELECT 1 FROM jsonb_array_elements(a.provenance->'validationEvidenceChunks') entry
    WHERE entry->>'objectKey'=candidate_key))
$$;
COMMIT;
