-- #18: each case belongs to the original final-result transaction. Per-case
-- indexed validation avoids rescanning all N cases for each of N inserts.
BEGIN;
DROP TRIGGER check_case_facts ON judge.judge_case_results;
CREATE FUNCTION judge.check_original_case_facts() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS (
  SELECT 1 FROM judge.judge_tasks t
  JOIN judge.problem_versions v ON v.id=t.problem_version_id AND v.problem_id=t.problem_id
  JOIN judge.problem_test_cases tc ON tc.id=NEW.test_case_id
  JOIN judge.judge_results r ON r.judge_task_id=t.id
  WHERE t.id=NEW.judge_task_id AND t.status IN ('COMPLETED','FAILED')
   AND tc.package_artifact_id=v.package_artifact_id AND tc.ordinal=NEW.ordinal
   AND r.xmin::text::bigint=(pg_current_xact_id()::text::bigint % 4294967296)
 ) THEN
  RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='case must commit with original frozen final result';
 END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER check_case_facts AFTER INSERT ON judge.judge_case_results
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION judge.check_original_case_facts();
COMMIT;
