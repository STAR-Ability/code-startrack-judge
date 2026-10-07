-- Refs #19. Copied with database owner authorization from migration contract fixture.
BEGIN;
INSERT INTO judge.platform_problems(source,repository_url,package_path,status) VALUES
 ('OJ_LAB','https://github.com/oj-lab/problem-packages','problems/alpha','DRAFT'),
 ('OJ_LAB','https://github.com/oj-lab/problem-packages','problems/beta','DRAFT');
INSERT INTO judge.license_evidence(id,repository_url,source_revision,package_path,status,license_scope,spdx_id,notice,source_url,license_files,evidence,reviewed_by,reviewed_at)
 VALUES('00000000-0000-0000-0000-000000000001','https://github.com/oj-lab/problem-packages',repeat('a',40),'problems/alpha','VERIFIED','PACKAGE','MIT','fixture license','https://github.com/oj-lab/problem-packages/blob/fixture/LICENSE','[{"path":"LICENSE","sha256":"fixture","spdxId":"MIT"}]','{"adminReview":true}','admin:fixture',now());
INSERT INTO judge.package_source_identities(id,repository_url,source_revision,package_path,source_sha256)
 VALUES('00000000-0000-0000-0000-000000000002','https://github.com/oj-lab/problem-packages',repeat('a',40),'problems/alpha',repeat('a',64));
INSERT INTO judge.package_content_identities(id,source_identity_id,adapter_version,source_format,manifest_version,normalized_sha256,manifest_sha256,manifest)
 VALUES('00000000-0000-0000-0000-000000000003','00000000-0000-0000-0000-000000000002','ojlab-kattis-v0.2.1','oj-lab-v1','0.2.0',repeat('a',64),repeat('a',64),'{"testCount":1}');
INSERT INTO judge.package_artifacts(id,problem_id,content_identity_id,source,repository_url,source_revision,package_path,source_format,adapter_version,manifest_version,source_archive_key,source_sha256,normalized_archive_key,normalized_sha256,manifest,source_metadata,license_evidence_id,validation_run_id,validation_context,evidence_set_hash)
 VALUES('00000000-0000-0000-0000-000000000010',1,'00000000-0000-0000-0000-000000000003','OJ_LAB','https://github.com/oj-lab/problem-packages',repeat('a',40),'problems/alpha','oj-lab-v1','ojlab-kattis-v0.2.1','0.2.0','private/source',repeat('a',64),'private/normalized',repeat('a',64),'{"testCount":1}','{"upstream":true}','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000004',jsonb_build_object('problemtoolsVersion','v1.20260907','adapterVersion','ojlab-kattis-v0.2.1','toolchainVersion','gcc-fixture','imageDigest','sha256:'||repeat('a',64),'configSha256',repeat('a',64),'sourceSha256',repeat('a',64),'normalizedSha256',repeat('a',64)),repeat('a',64));
INSERT INTO judge.package_validation_runs(id,package_artifact_id,status,problemtools_version,adapter_version,toolchain_version,image_digest,config_sha256,source_sha256,normalized_sha256,results,errors,adaptations,started_at,finished_at)
 VALUES('00000000-0000-0000-0000-000000000004','00000000-0000-0000-0000-000000000010','PASSED','v1.20260907','ojlab-kattis-v0.2.1','gcc-fixture','sha256:'||repeat('a',64),repeat('a',64),repeat('a',64),repeat('a',64),
 (SELECT jsonb_object_agg(name,jsonb_build_object('passed',true,'evidence',jsonb_build_array(jsonb_build_object('check','FIXTURE_VALIDATION','subjectSha256',repeat('a',64),'logObjectKey',NULL,'summary','Fixture checkpoint passed')))) FROM unnest(ARRAY['structure','statement','testData','validators','referenceSolutions']) name),'[]','[]',now(),now());
INSERT INTO judge.problem_versions(id,problem_id,version_number,package_artifact_id,title,statement_format,statement_content,difficulty_scale,time_limit_ms,wall_limit_ms,memory_limit_bytes,output_limit_bytes,language_ids,judge_mode,checker_config,metadata_hash)
 VALUES('00000000-0000-0000-0000-000000000011',1,1,'00000000-0000-0000-0000-000000000010','Alpha','MARKDOWN','fixture statement','UNRATED',1000,2000,10000,10000,ARRAY['cpp17'],'BATCH_PASS_FAIL','{}',repeat('a',64));
INSERT INTO judge.problem_test_cases(id,package_artifact_id,ordinal,visibility,input_object_key,answer_object_key,input_sha256,answer_sha256,input_size_bytes,answer_size_bytes)
 VALUES('00000000-0000-0000-0000-000000000020','00000000-0000-0000-0000-000000000010',1,'SECRET','private/input','private/answer',repeat('a',64),repeat('a',64),1,1);
INSERT INTO judge.reference_solutions(id,package_artifact_id,role,language_id,source_object_key,source_sha256,upstream_path)
 VALUES('00000000-0000-0000-0000-000000000021','00000000-0000-0000-0000-000000000010','ACCEPTED','cpp17','private/reference',repeat('a',64),'submissions/accepted/main.cpp');
INSERT INTO judge.judge_language_configs(language_id,config_version,display_name,language_family,compiler_version,source_filename,compile_template,run_template,compile_limits,toolchain_digest,analysis_supported,is_active)
 VALUES('cpp17','fixture-1','C++17','C++','gcc-fixture','main.cpp','{}','{}','{}','sha256:'||repeat('a',64),false,false);
UPDATE judge.platform_problems SET latest_version_id='00000000-0000-0000-0000-000000000011' WHERE id=1;
COMMIT;
