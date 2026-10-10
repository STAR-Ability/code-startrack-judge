-- Issue #7: private content-addressed bytes, staged pins and owner references.
-- Forward-only addition; does not rewrite previously accepted schema/history.
-- Filesystem writes cannot join PostgreSQL commits. Pins precede durable writes;
-- verified references commit with their real owner, and GC shares object locks.
BEGIN;

CREATE TABLE judge.private_objects (
 object_key text PRIMARY KEY,
 sha256 judge.sha256_hex NOT NULL,
 size_bytes judge.safe_nonnegative NOT NULL CHECK(size_bytes <= 1073741824),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK((object_key = 'sha256/' || left(sha256::text,2) || '/' || sha256::text)
 OR (object_key ~ '^sources/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/[0-9a-f]{64}$'
 AND split_part(object_key,'/',3)=sha256::text))
);
CREATE TRIGGER immutable_object_identity BEFORE UPDATE ON judge.private_objects
 FOR EACH ROW EXECUTE FUNCTION judge.immutable_row();

CREATE TABLE judge.private_object_stages (
 id uuid PRIMARY KEY,
 object_key text NOT NULL REFERENCES judge.private_objects(object_key) ON UPDATE RESTRICT ON DELETE RESTRICT,
 task_id uuid,
 expires_at timestamptz NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK(expires_at > created_at),
 CHECK((task_id IS NULL AND object_key LIKE 'sha256/%')
 OR (task_id IS NOT NULL AND object_key LIKE 'sources/' || task_id::text || '/%'))
);
CREATE INDEX private_object_stages_expiry ON judge.private_object_stages(expires_at,object_key);

CREATE TABLE judge.private_object_references (
 object_key text NOT NULL REFERENCES judge.private_objects(object_key) ON UPDATE RESTRICT ON DELETE RESTRICT,
 owner_type text NOT NULL CHECK(owner_type IN ('ARTIFACT','TEST','REFERENCE','TASK','REJECTED','VALIDATION','RESULT')),
 owner_id uuid NOT NULL,
 role varchar(32) NOT NULL CHECK(role ~ '^[A-Z][A-Z_]{0,31}$'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(object_key,owner_type,owner_id,role),
 CHECK((owner_type='TASK' AND role='SOURCE' AND object_key LIKE 'sources/' || owner_id::text || '/%')
 OR (owner_type<>'TASK' AND object_key LIKE 'sha256/%'))
);
CREATE UNIQUE INDEX private_object_task_source ON judge.private_object_references(owner_id)
 WHERE owner_type='TASK';
CREATE INDEX private_object_owner ON judge.private_object_references(owner_type,owner_id);
CREATE TRIGGER immutable_object_reference BEFORE UPDATE ON judge.private_object_references
 FOR EACH ROW EXECUTE FUNCTION judge.immutable_row();

CREATE FUNCTION judge.guard_object_reference_delete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.owner_type<>'TASK' OR OLD.role<>'SOURCE' OR NOT EXISTS(
  SELECT 1 FROM judge.judge_tasks WHERE id=OLD.owner_id
  AND status IN ('COMPLETED','FAILED','CANCELLED') AND transient_source_key IS NULL
  AND source_expires_at<=clock_timestamp() AND finished_at<=clock_timestamp()-interval '24 hours'
 ) THEN
  RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='private immutable reference cannot be removed';
 END IF;
 RETURN OLD;
END $$;
CREATE TRIGGER guard_object_reference_delete BEFORE DELETE ON judge.private_object_references
 FOR EACH ROW EXECUTE FUNCTION judge.guard_object_reference_delete();

CREATE FUNCTION judge.check_object_reference_owner() RETURNS trigger LANGUAGE plpgsql AS $$
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
CREATE CONSTRAINT TRIGGER check_object_reference_owner AFTER INSERT ON judge.private_object_references
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION judge.check_object_reference_owner();

-- Registration rows were introduced after immutable business records. Their
-- absence never authorizes GC to erase a historical object. This crosscheck is
-- also defense in depth against a future missing-pin implementation defect.
CREATE FUNCTION judge.private_object_has_business_owner(candidate_key text)
RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT EXISTS(SELECT 1 FROM judge.package_artifacts a
   WHERE a.source_archive_key=candidate_key OR a.normalized_archive_key=candidate_key
   OR (candidate_key LIKE 'sha256/%' AND EXISTS(
     SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(a.manifest->'files')='array' THEN a.manifest->'files' ELSE '[]'::jsonb END) item
     WHERE item->>'normalizedSha256'=split_part(candidate_key,'/',3))))
 OR EXISTS(SELECT 1 FROM judge.problem_test_cases WHERE input_object_key=candidate_key OR answer_object_key=candidate_key)
 OR EXISTS(SELECT 1 FROM judge.reference_solutions WHERE source_object_key=candidate_key)
 OR EXISTS(SELECT 1 FROM judge.rejected_package_evidence r WHERE r.source_archive_key=candidate_key OR r.normalized_archive_key=candidate_key OR r.validation_log_key=candidate_key
   OR EXISTS(SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(r.provenance->'validationEvidenceChunks')='array' THEN r.provenance->'validationEvidenceChunks' ELSE '[]'::jsonb END) entry
     WHERE entry->>'objectKey'=candidate_key))
 OR EXISTS(SELECT 1 FROM judge.package_validation_runs r WHERE r.log_object_key=candidate_key
   OR EXISTS(SELECT 1 FROM jsonb_each(r.results) section
     CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(section.value->'evidence')='array' THEN section.value->'evidence' ELSE '[]'::jsonb END) entry
     WHERE entry->>'logObjectKey'=candidate_key))
 OR EXISTS(SELECT 1 FROM judge.judge_results WHERE raw_execution_log_key=candidate_key)
 OR EXISTS(SELECT 1 FROM judge.judge_case_results WHERE private_log_key=candidate_key)
 OR EXISTS(SELECT 1 FROM judge.judge_tasks WHERE transient_source_key=candidate_key)
$$;

COMMIT;
