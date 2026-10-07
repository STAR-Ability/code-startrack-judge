# V0.2 判题与题库数据库契约

契约发布号 `0.2.0`。业务 owner 为 `judge-problem-service`；接口字段、异步状态和开源复用见 [判题题库 API 文档](判题题库api文档.md)，跨服务边界见 [整体架构与联调说明](V0.2-整体架构与联调说明.md)。本轮只规定实施所需数据模型，不新增业务代码或DDL文件。

## 1. 所有权、兼容与类型

已阅读 V0.1/V0.11/V0.12 相关后端、算法、API/数据库旧设计，CF 原始数据/字段分析与本次功能；未参考 `docs-fronted/`。现有 backend 的 `problems/submissions/oj_accounts` 非空外键及唯一键不改变，仍记录CF数据。本服务新增独立 `judge` schema，自己的迁移和数据库凭据，仅能写该schema。可共享PostgreSQL基础设施实例，禁止共用业务数据库账号或让其他服务直接UPDATE以下表。

| 主数据 | 唯一 owner | 本服务保存/读取方式 |
|---|---|---|
| 用户、RBAC、Session、团队、隐私 | backend | 不复制、不建用户表、不接收Cookie |
| CF目录、绑定、CF提交、Rating | backend | 不读取CF，不建CF目录 |
| 业务平台Submission、长期源码、训练记录 | backend | submissionId为逻辑引用；仅收到冻结源码副本供本次判题，非源码主数据 |
| 平台目录、题包、版本、测试/参考程序、许可证 | judge | 以下主表与私有对象桶，本服务唯一写入 |
| JudgeTask与原始判题事实 | judge | task与result主表；backend通过HTTP投影，不能修改事实 |
| 静态代码分析/工具原始结果与计算任务 | algorithm | 本服务不建分析主表，不调用算法 |
| 学习画像/交付推荐/结果公开投影 | backend | 本服务只供平台候选快照，无用户画像写权限 |

数据库snake_case，API camelCase；bigint identity主键正数，API为十进制字符串Id；版本/任务UUID；时间`timestamptz`写UTC；资源毫秒/字节，计数非负。枚举用text+CHECK，不用PG原生ENUM。以下表PK隐含NOT NULL/UNIQUE；标“空”才允许NULL；所有本地FK默认ON DELETE RESTRICT/ON UPDATE RESTRICT，历史不级联删；跨服务逻辑关联不建跨schema外键。created_at默认now()，updated_at只由owner更新。

## 2. judge.platform_problems：平台题目稳定身份

| 字段 | 类型 | 键/可空/约束 | 用途 |
|---|---|---|---|
| id | bigint identity | PK，>0 | 平台problemId，与CF命名空间分离 |
| source | text | 非空，OJ_LAB | 上游来源分类 |
| repository_url | text | 非空，固定官方GitHub URL | 来源身份，不接受任意网络地址 |
| package_path | text | 非空，规范problems/相对目录 | 题目原路径，重导入相同题保持id |
| status | text | 非空，DRAFT/PUBLISHED/WITHDRAWN | 当前题目的发布状态 |
| current_version_id | uuid | 空，FK→problem_versions.id；复合FK含id | 当前公开可提交版本；初始DRAFT空 |
| latest_version_id | uuid | 空，同题复合FK | 管理员预览最近版本；不替代公开current版本 |
| created_at | timestamptz | 非空 | 首次创建 |
| updated_at | timestamptz | 非空 | 最近管理变更 |
| public_updated_at | timestamptz | 空；有曾发布版本时非空 | 公开列表updatedAt与排序依据，创建草稿不更新 |
| withdrawn_at | timestamptz | 空 | 撤下时刻 |
| withdrawal_reason | varchar(500) | 空 | 管理员撤下原因 |

UNIQUE(source,repository_url,package_path)。PUBLISHED要求current_version_id非空、withdrawn_at空；WITHDRAWN要求current非空、withdrawn_at非空；DRAFT不能作为可提交题。当前可提交还要求提交 versionId=current_version_id。初始失败导入不创建虚假题目行；validated导入才建立/关联身份及latest版。创建新元数据版本不改变current/version公开状态，查询未发布版本的DTO.status=DRAFT。latest/current引用使用DEFERRABLE复合FK `(id,current_version_id)→problem_versions(problem_id,id)`，允许同事务先插身份再插版本；不能将别题版本设为current。

发布/撤下同时更新public_updated_at；公开Summary.updatedAt取public_updated_at，DRAFT预览取版本created_at，避免管理草稿使公开目录无版本变更而排序变化。索引 `(status,public_updated_at DESC,id DESC)`、source身份唯一索引。题名/标签/限制在版本表，避免在目录和版本分别维护一份权威值。查询经current版读取公开属性。

## 3. judge.problem_versions：不可变题面与元数据

| 字段 | 类型 | 键/可空/约束 | 用途 |
|---|---|---|---|
| id | uuid | PK | problemVersionId |
| problem_id | bigint | 非空FK→platform_problems.id | 稳定题身份 |
| version_number | integer | 非空>0，UNIQUE(problem_id,version_number) | 每题连续分配的展示版本号 |
| package_artifact_id | uuid | 非空FK→package_artifacts.id，复合FK含problem_id | 不可变原件/manifest/测试集引用 |
| base_version_id | uuid | 空，同题复合FK→problem_versions | 元数据二次版本来源；导入首版可空 |
| title | varchar(256) | 非空非空白 | 平台标题 |
| statement_format | text | 非空，MARKDOWN | 公开题面格式 |
| statement_content | text | 非空 | 完整原Markdown（经安全规范化，不去原题源） |
| statement_input | text | 空 | 可提取输入章节；缺失null |
| statement_output | text | 空 | 可提取输出章节；缺失null |
| samples | jsonb | 非空array，默认[] | 固定 `[{input:string,output:string}]` 公开样例 |
| tags | text[] | 非空默认{}，去重、无NULL元素 | 公开标签，metadata接口≤32项/每1..128 |
| difficulty | integer | 空，>0 | 本平台可信标定值 |
| difficulty_scale | text | 非空PLATFORM_RATING/UNRATED | 不冒充CF_RATING |
| rating_basis | text | 空 | 人工标定依据；ADMIN metadata请求记录MANUAL:<requestId>审核声明，非空评级须有依据 |
| time_limit_ms | bigint | 非空>0，安全整数 | 单测试CPU限制，秒转换后保存 |
| wall_limit_ms | bigint | 非空>=time_limit_ms | 沙箱实际墙钟限制，内部不用UI推导 |
| memory_limit_bytes | bigint | 非空>0，安全整数 | 单测试内存限制 |
| output_limit_bytes | bigint | 非空>0，安全整数 | 单测试输出限制 |
| language_ids | text[] | 非空、无NULL、非空数组 | 该题允许语言，动态有效能力取交集 |
| judge_mode | text | 非空，BATCH_PASS_FAIL | 首期仅支持该模式 |
| checker_config | jsonb | 非空object | checker类型/参数与版本；与manifest一致 |
| metadata_hash | char(64) | 非空，小写hex | 不可变公开/执行元数据摘要 |
| first_published_at | timestamptz | 空 | 首次发布标记，只能NULL→时间 |
| created_at | timestamptz | 非空 | 创建时间 |

UNIQUE(problem_id,id)，FK(package_artifact_id,problem_id)→package_artifacts(id,problem_id)。UNRATED当且仅当difficulty=NULL，PLATFORM_RATING要求difficulty>0和rating_basis非空；不能把上游1..10或CF points直接套本平台分数。base_version_id须同problem。JSON样例深层schema由owner校验；只从公开sample数据派生，不读隐藏测试作为sample。

版本创建后内容不UPDATE；first_published_at允许唯一一次登记。题面/限制/测试、checker、tags/难度任一变化产生新UUID，历史task引用不变。指定版本的first_published_at=NULL则DTO.status=DRAFT，否则取题目当前PUBLISHED/WITHDRAWN；catalogVersion始终当前目录版本。`metadata-versions` 创建新行复制基版本题面/限制/许可与同一只读package_artifact，只变tags/difficulty/difficulty_scale/rating_basis；返回未发布新版本DRAFT，后续publish原子切current。带版本号的题面不变，题目去重仍按ProblemRef去版本后的身份。

索引 `(problem_id,version_number DESC)`、GIN(tags)、`(difficulty_scale,difficulty)`；标题检索可使用pg_trgm或初期ILIKE，不强制新增扩展。发布事务校验技术/许可/模式及版本关联，再登记first_published_at、切current、推进catalog版本；撤下不删除此行。

## 4. judge.package_artifacts：不可变上游包与兼容产物

| 字段 | 类型 | 键/可空/约束 | 用途 |
|---|---|---|---|
| id | uuid | PK | 题包工件ID |
| problem_id | bigint | 非空FK→platform_problems.id | 所属题身份 |
| source | text | 非空OJ_LAB | 固定来源 |
| repository_url | text | 非空 | 原仓库完整来源 |
| source_revision | char(40) | 非空hex | 不可变commit，不保存漂移branch当版本 |
| package_path | text | 非空 | 原包路径 |
| source_format | text | 非空oj-lab-v1 | 原包格式 |
| adapter_version | varchar(64) | 非空 | ojlab-kattis-v0.2.1兼容策略版本 |
| manifest_version | text | 非空0.2.0 | 平台manifest schema |
| source_archive_key | text | 非空 | 私有原件桶对象key，不是公开URL |
| source_sha256 | char(64) | 非空 | 原包字节校验和 |
| normalized_archive_key | text | 非空 | 派生兼容验证包/manifest位置 |
| normalized_sha256 | char(64) | 非空 | 派生包checksum |
| manifest | jsonb | 非空object | 文件映射、单位转换、checker、测试顺序、语言/模式声明 |
| source_metadata | jsonb | 非空object | 原oj-lab难度/tags/.timelimit与未知扩展，不丢原值 |
| license_evidence_id | uuid | 非空FK→license_evidence.id | 逐包许可审核证据 |
| validation_run_id | uuid | 空FK→package_validation_runs.id | 发布必须指向本包成功校验记录 |
| created_at | timestamptz | 非空 | 入库时刻 |

UNIQUE(problem_id,id)，UNIQUE(repository_url,source_revision,package_path,adapter_version)。license_evidence_id与repository_url/source_revision/package_path使用复合FK匹配本包证据，许可证verified不能借别包记录。原包及normalized对象写入后不可覆盖；同源同checksum重导入复用包，不重写已有版本内容。validation_run_id关联用同包复合约束，不能借其他题校验通过。可重复升级校验产生新run；影响格式/执行语义的adapter升级产生新artifact/题版本。

manifest必须记录原路径→规范路径、shortname映射、Markdown→legacy验证题面转换、扩展字段迁移与秒/内存/输出单位转换。它不是后端推荐目录；不从CF补隐藏测试。归档路径、文件大小、解压总量及软链接越界检查在写对象前执行，私有对象不转公开签名链接。

## 5. judge.license_evidence：独立题包许可链

| 字段 | 类型 | 键/可空/约束 | 用途 |
|---|---|---|---|
| id | uuid | PK | 审核证据ID |
| repository_url | text | 非空 | 来源仓库 |
| source_revision | char(40) | 非空 | 审核对应commit |
| package_path | text | 非空 | 被审核包路径 |
| status | text | 非空PENDING/VERIFIED/MISSING/REVIEW_REQUIRED | 发布门禁 |
| license_scope | text | 非空PACKAGE/REPOSITORY_INHERITED/UNKNOWN | 区分题级与根继承 |
| spdx_id | varchar(128) | 空 | 真实可识别许可标识，不能臆填MIT |
| notice | text | 非空 | 对外许可/署名说明 |
| source_url | text | 非空 | 题源固定commit路径URL |
| license_files | jsonb | 非空array | `[{path,sha256,spdxId}]` 原许可文件清单 |
| evidence | jsonb | 非空object | 逐题出处、第三方内容检查、根许可适用范围/署名证据 |
| reviewed_by | text | 空 | 后端管理员publicId字符串或明确导入策略标识，非users FK |
| reviewed_at | timestamptz | 空 | 审核时刻 |
| created_at | timestamptz | 非空 | 创建时刻 |

VERIFIED要求reviewed_by/reviewed_at非空、notice/source_url完整且license_files至少一项；可接受有证据的repository继承。spdx_id可null用于不能用SPDX表达的有效许可，但必须完整notice/证据。MISSING/REVIEW_REQUIRED禁止publish；不是“有仓库根MIT就自动认可所有内容”。发布后证据不可改，重新审核追加新证据与新artifact/版本。

UNIQUE(id,repository_url,source_revision,package_path)供artifact复合FK。索引 `(repository_url,source_revision,package_path)`、`(status,created_at)`。镜像与题包分发必须保留原LICENSE/NOTICE，根MIT与题包许可分别记录；go-judge seccomp Moby Apache-2.0 NOTICE也纳入组件清单，不用题包表代替镜像SBOM。

## 6. judge.problem_test_cases 与 judge.reference_solutions

测试属于package_artifact，由所有使用该artifact的版本共享；不能把后台Submission结果写回标准答案。

| test_cases字段 | 类型 | 键/可空/约束 | 用途 |
|---|---|---|---|
| id | uuid | PK | 内部测试ID，不公开 |
| package_artifact_id | uuid | 非空FK→package_artifacts.id | 固定包关联 |
| ordinal | integer | 非空>0，UNIQUE(package_artifact_id,ordinal) | 稳定执行顺序 |
| visibility | text | 非空SAMPLE/SECRET | sample允许公开，secret禁止DTO输出 |
| input_object_key / answer_object_key | text | 非空 | 输入/期望输出私有key；默认pass-fail模式必需答案 |
| input_sha256 / answer_sha256 | char(64) | 非空 | 完整性 |
| input_size_bytes / answer_size_bytes | bigint | 非空>=0 | 读包限制与校验 |
| validation_group | text | 空 | 原包组信息，只内部 |
| created_at | timestamptz | 非空 | 写入时刻 |

reference_solutions字段：`id uuid PK`、`package_artifact_id uuid FK非空`、`role text CHECK ACCEPTED/WRONG_ANSWER/TIME_LIMIT/RUNTIME_ERROR非空`、`language_id text非空`、`source_object_key text非空`、`source_sha256 char(64)非空`、`upstream_path text非空`、`created_at timestamptz非空`。UNIQUE(package_artifact_id,upstream_path)，索引(package_artifact_id,role)。用于题包verifyproblem正负样本校验，源代码不走平台公开API；至少一个AC参考解通过全部测试才可发布。

两表内容不可变；测试序号连续与manifest testCount相同在包验收事务校验。checker/validator程序以manifest固定路径和checksum引用私有artifact，不提供编辑隐藏数据接口。新测试/参考解上传必须重新生成artifact、校验和version。

## 7. judge.package_validation_runs：可复现校验

| 字段 | 类型 | 键/可空/约束 | 用途 |
|---|---|---|---|
| id | uuid | PK | 校验运行ID |
| package_artifact_id | uuid | 非空FK→package_artifacts.id | 被校验包 |
| status | text | 非空PENDING/RUNNING/PASSED/FAILED | 技术状态，不等于许可状态 |
| problemtools_version | text | 非空 | 固定v1.20260907及commit |
| adapter_version | text | 非空 | 与artifact适配版本一致 |
| toolchain_version | text | 非空 | 参考解/checker编译器组合 |
| image_digest | text | 非空 | 实际sha256镜像digest，发布时记录不编造 |
| config_sha256 | char(64) | 非空 | 校验配置checksum |
| source_sha256 / normalized_sha256 | char(64) | 非空 | 所校验原包/派生包checksum |
| results | jsonb | 非空object | structure、statement、testData、validators、referenceSolutions各项结果 |
| errors | jsonb | 非空array | TaskError[]，工具真实错误 |
| adaptations | jsonb | 非空array | 格式差异白名单与处理证据，不吞技术错误 |
| log_object_key | text | 空 | 原始日志私有key，可能有路径/答案不得公开 |
| started_at / finished_at | timestamptz | 空 | 校验时间 |
| created_at | timestamptz | 非空 | 创建时间 |

UNIQUE(id,package_artifact_id)，artifact.validation_run_id通过复合FK回指本artifact；FK均延迟校验解决创建顺序。PASSED要求errors=[]、finished_at非空、各必需检查通过；FAILED要求错误非空。所有参考解/validator隔离执行，不在API进程运行。索引(package_artifact_id,created_at DESC)、(status,created_at)。新工具版本跑新run；旧run及日志只读保留。

## 8. judge.import_jobs 与 judge.import_items

| import_jobs字段 | 类型 | 键/可空/约束 | 用途 |
|---|---|---|---|
| id | uuid | PK | importJobId |
| request_id | uuid | 非空UNIQUE | 管理导入幂等请求 |
| request_hash | char(64) | 非空 | 固定来源/commit/paths规范化hash |
| source / repository_url | text | 非空 | OJ_LAB/固定仓库 |
| source_revision | char(40) | 非空 | 完整commit |
| status | text | 非空QUEUED/RUNNING/SUCCEEDED/PARTIAL/FAILED | 导入任务状态 |
| revision | integer | 非空>=1 | 可见结果版本 |
| package_count / completed_package_count | integer | 非空>=0，completed≤package | 总数/终结包数 |
| error | jsonb | 空或object | 终态部分失败/全失败摘要TaskError |
| lease_owner | uuid | 空 | 在途worker fencing token |
| lease_expires_at | timestamptz | 空 | 持久租约截止 |
| attempt_count | integer | 非空默认0，0..3 | 重启恢复领取次数 |
| started_at / finished_at | timestamptz | 空 | 执行/终态时刻 |
| created_at / updated_at | timestamptz | 非空 | TaskBase时间字段 |

import_items字段：`id uuid PK`、`import_job_id uuid FK非空`、`ordinal integer>0非空`、`package_path text非空`、`status text(PENDING/VALIDATED/REJECTED)非空`、`problem_id bigint FK→platform_problems空`、`problem_version_id uuid同题复合FK空`、`license_status text(PENDING/VERIFIED/MISSING/REVIEW_REQUIRED)非空`、`validation_status text(PENDING/PASSED/FAILED)非空`、`errors jsonb array非空默认[]`、`created_at/updated_at timestamptz非空`。UNIQUE(import_job_id,ordinal)、UNIQUE(import_job_id,package_path)。VALIDATED要求两引用非空/许可VERIFIED/技术PASSED/errors=[]；REJECTED至少一错误，失败源包不造已发布版本。

API.items按ordinal顺序映射，package_count等于明细数，completed_package_count=终态明细数。SUCCEEDED全VALIDATED、error=null；PARTIAL有成功亦有失败、error非空；FAILED无成功、error非空；终态completed=package_count且finished非空。租约/队列约束与judge_tasks相同。单包数据写入与item计数同事务，失败项独立提交，不能因为另一包失败撤销已VALIDATED草稿。导入不会推进公开catalog，不自动publish。

索引jobs(status,created_at)、(lease_expires_at) WHERE RUNNING；items(import_job_id,ordinal)、items(problem_id)。网络重试固定request_id，worker领取使用短事务SKIP LOCKED，无网络长事务。

## 9. judge.catalog_state、catalog_snapshots 与 catalog_snapshot_items

| 表 | 字段 / 类型与约束 | 用途 |
|---|---|---|
| catalog_state | `singleton_id smallint PK CHECK=1`；`catalog_version bigint非空>0默认1`；`updated_at timestamptz非空` | 全目录单调版本；公开属性变化同事务锁此行递增 |
| catalog_snapshots | `id uuid PK`；`catalog_version bigint非空>0`；`item_count integer非空>=0`；`page_limit integer非空1..1000`；`created_at timestamptz非空`；`expires_at timestamptz非空且>created_at` | 30分钟一致快照，非题目主数据 |
| catalog_snapshot_items | `snapshot_id uuid FK+复合PK`；`ordinal integer复合PK且>=0`；`problem_id bigint FK非空`；`problem_version_id uuid同题复合FK非空`；`status text(PUBLISHED/WITHDRAWN)非空`；`problem_summary jsonb object非空` | 冻结CatalogEntry，offset游标按ordinal读取 |

快照在REPEATABLE READ短事务取catalog状态、当前已发布及曾发布撤下题版本，冻结ProblemSummary/墓碑，排序problemId数值升序，ordinal从0连续；UNIQUE(snapshot_id,problem_id)。快照summary只含公开字段，不能夹隐藏数据、题包URL或源码。item_count与明细数一致；nextCursor为空当offset+page_limit≥item_count。空目录有效返回[]及版本。

快照期限后整份可清理（该快照两表FK允许仅对快照清理级联，业务题目不级联删）；索引(expires_at)、(snapshot_id,ordinal)。发布/撤下同一transaction更新platform_problems与catalog_state；纯DRAFT导入、新DRAFT标签版本创建及同值幂等publish不递增。backend缓存不是本表副本主数据，只保留sourceOwner/version/etag，通过快照整份切换。

## 10. judge.judge_tasks：持久调度任务

| 字段 | 类型 | 键/可空/约束 | 用途 |
|---|---|---|---|
| id | uuid | PK | judgeTaskId |
| request_id | uuid | 非空UNIQUE | 一次判题尝试幂等ID |
| request_hash | char(64) | 非空 | 原请求规范化hash |
| submission_id | bigint | 非空>0、UNIQUE，逻辑关联backend.platform_submissions | 原业务提交；v0.2不公开rejudge |
| problem_id | bigint | 非空FK→platform_problems | 平台题身份 |
| problem_version_id | uuid | 非空同题复合FK→problem_versions | 冻结判题版本 |
| source_owner | text | 非空固定backend | 长期源码owner标记 |
| source_sha256 | char(64) | 非空 | 输入源码字节hash |
| transient_source_key | text | 空 | 私有临时源码副本，终态后24h清理，非业务主源码 |
| source_expires_at | timestamptz | 空 | 临时副本清理时间 |
| language_id | text | 非空，与config_version复合FK | 已允许语言 |
| language_config_version | text | 非空，复合FK | 冻结服务端编译/执行模板 |
| sandbox_version | text | 非空 | go-judge版本/commit |
| worker_image_digest | text | 非空 | 实际工具链镜像digest |
| execution_limits | jsonb | 非空object | 冻结CPU/wall/memory/output/compile限制 |
| status | text | 非空JudgeStatus | QUEUED/DISPATCHING/RUNNING/COMPLETED/FAILED/CANCELLED |
| revision | integer | 非空默认1，>=1 | TaskBase对外单调修订号 |
| error | jsonb | 空或object | TaskError，终态基础设施原因 |
| lease_owner / lease_expires_at | uuid / timestamptz | 空 | 租约/fencing token |
| attempt_count | integer | 非空默认0，0..3 | 底层实际恢复执行次数 |
| started_at / finished_at | timestamptz | 空 | 开始/终态时刻 |
| created_at / updated_at | timestamptz | 非空 | TaskBase时间 |

FK(problem_id,problem_version_id)→problem_versions(problem_id,id)，冻结execution_limits来自已接受版本，不能在任务运行中JOIN新current版修改限制。submission_id无跨backend FK；API接收前backend已创建Submission并做授权，judge按受信调用校验全字段；绝不将“无FK”当成可以自己创建用户Submission。

QUEUED要求lease/started/finished空；DISPATCHING/RUNNING要求lease非空、started非空、finished空；终态finished非空、lease空。在途error=null，无原始result；COMPLETED要有完整非IE结果且error=null，FAILED要有IE+error，CANCELLED无result+error。通过延迟约束在task/result同事务提交时校验。

source临时副本创建、task与首个outbox事件同事务的数据库事实/对象登记完成才接受；对象写入与DB无法跨系统事务，先写checksum命名临时对象后短事务登记，失败对象按孤儿清理策略删除。task终态后24h清理源副本/工作目录，长期source_sha256与任务结果保留；在途不能因保留期清理。backend源码私有桶由backend维护，judge没有其读写凭据。

索引(status,created_at)、(submission_id)、(problem_id,created_at DESC)、(lease_expires_at) WHERE DISPATCHING/RUNNING。worker短事务SKIP LOCKED领task后调用上游，30秒续180秒；失效token禁止更新。租约恢复保留id/requestId/题版本，以新隔离工件重执行，最大3次；可见状态回退也使用更高revision，已提交终态永不回退。普通执行超时TLE是完成判定，不能按worker断线重试成新用户提交。

## 11. judge.judge_results 与 judge.judge_case_results：原始事实

| judge_results字段 | 类型 | 键/可空/约束 | 用途 |
|---|---|---|---|
| judge_task_id | uuid | PK+FK→judge_tasks.id | 每task一个最终原始结果 |
| verdict | text | 非空AC/WA/TLE/MLE/RE/CE/OLE/IE | 新短码；不混CF旧Verdict |
| time_ms / memory_bytes | bigint | 空，非负安全整数 | max单测试CPUms/峰值bytes，未运行null |
| passed_test_count / total_test_count | integer | 非空>=0，passed≤total | 实际通过/冻结总测试数 |
| score | numeric(8,6) | 空，0..1 | 首期pass-fail固定null，不拿资源值当分数 |
| compile_log | text | 空，UTF8≤16384bytes | 脱敏可公开编译日志；仅本人/管理员 |
| diagnostic_code | varchar(64) | 空 | 不含隐藏测试的结构化诊断 |
| judged_at | timestamptz | 非空 | 原始判题完成时刻 |
| result_hash | char(64) | 非空 | 原始JudgeResult规范JSONhash，投影校验依据 |
| raw_execution_log_key | text | 空 | 私有底层日志/统计，不进入API |
| created_at | timestamptz | 非空 | 结果落库时间 |

judge_case_results字段：`judge_task_id uuid FK+复合PK`、`test_case_id uuid FK→problem_test_cases+复合PK`、`ordinal integer>0非空`、`verdict text非空AC/WA/TLE/MLE/RE/OLE/IE/SKIPPED`、`cpu_time_ms bigint空>=0`、`wall_time_ms bigint空>=0`、`memory_bytes bigint空>=0`、`exit_code integer空`、`signal integer空`、`sandbox_status text空`、`checker_status text空`、`private_log_key text空`、`created_at timestamptz非空`。UNIQUE(judge_task_id,ordinal)，索引(test_case_id)。case必须来自task冻结版本的package_artifact，用事务/约束校验，不可挂别题case。

资源值聚合实际运行case；passed只数AC，总数=包全部测试数；编译失败CE=passed0且无运行资源。未执行case可不插明细或显式SKIPPED，但不充作AC。原始结果提交后不可UPDATE；内部日志限定读权限，隐藏输入/答案/stdout/stderr不投影。task状态+result+case+callback outbox同事务，backend只保存sourceOwner=judge-problem-service/sourceId=taskId/revision/hash的公开投影，不回写本表。

## 12. judge.judge_language_configs：服务端模板

字段：`language_id text复合PK`、`config_version text复合PK`、`display_name text非空`、`language_family text非空`、`compiler_version text非空`、`source_filename text非空`、`compile_template jsonb object非空`、`run_template jsonb object非空`、`compile_limits jsonb object非空`、`toolchain_digest text非空`、`analysis_supported boolean非空`、`is_active boolean非空`、`created_at timestamptz非空`。UNIQUE(language_id,config_version)，每language最多一is_active使用部分唯一索引。配置版本不可改，启用新配置仅切is_active；task固定旧版可读。

模板来自受控配置，不接收用户命令/环境变量；至少cpp17/main.cpp，c11选配，其他语言没有安装/隔离验证不能active。API仅输出LanguageCapability安全字段；内部analysisSupported是本服务允许分析声明；backend公开有效值取其与算法真实analysisLanguages交集，算法不可达false，judge不调用算法。内部capabilityVersion为排序后的活动配置及声明flag内容版本，变更才变化。

## 13. judge.callback_outbox 与 judge.operation_requests

| 表 | 字段 / 类型与约束 | 用途 |
|---|---|---|
| callback_outbox | `event_id uuid PK`；`judge_task_id uuid FK非空`；`revision integer非空>=1`；`event_type text非空JUDGE_TASK_UPDATED`；`request_id uuid非空`；`payload jsonb object非空`；`payload_hash char(64)非空`；`status text非空PENDING/SENDING/DELIVERED/DEAD_LETTER`；`attempt_count integer非空>=0`；`next_attempt_at timestamptz非空`；`lease_owner uuid空`；`lease_expires_at timestamptz空`；`last_error_code text空`；`created_at/updated_at timestamptz非空`；`delivered_at timestamptz空` | 持久CallbackEvent<JudgeTask>完整快照，固定backend接收地址 |
| operation_requests | `operation text复合PK`；`request_id uuid复合PK`；`request_hash char(64)非空`；`problem_id bigint FK空`；`result jsonb object空`；`status text非空PROCESSING/SUCCEEDED/FAILED`；`error jsonb object空`；`created_at/updated_at timestamptz非空` | publish/withdraw/metadata-versions管理幂等，与真实业务操作同事务 |

UNIQUE(callback_outbox.judge_task_id,revision)，payload.eventId=request_id之外独立event_id，payload.requestId等task原requestId，aggregateId=taskId。修订号相同不生成不同事件，重试eventId/payload_hash不变。outbox索引(status,next_attempt_at)、(lease_expires_at)；SENDING需要租约，DELIVERED需要delivered_at。1/2/4/8/16/30秒退避至24h，死信保留人工对账；回调ACK不会改变judge原始事实。

operation支持 `PUBLISH/WITHDRAW/METADATA_VERSION`；SUCCESS结果冻结完整DTO/目录版本，用原请求重放而不是重新读当前目录伪造同操作结果。异步IMPORT/JUDGE幂等已分别由任务表UNIQUE(request_id)完成，不另双写主结果。对同时在途同operation/requestId返回409 REQUEST_IN_PROGRESS+Retry-After2；DB唯一键兜底，同key不同hash为IDEMPOTENCY_CONFLICT。

## 14. 对象存储、开源升级与迁移验收

对象桶/卷由judge独占写权限，原包、规范包、隐藏tests/答案、参考代码、验证日志与执行日志均私有。公开题面与样例只通过API DTO由backend代理，不发整个题包下载链接。源码执行临时对象按task生命周期清理；不可变题包、许可证据和历史结果以业务历史保留，不因撤题删除。

上游锁定/许可证：go-judge-demo commit `ed6cc756082ee9f7d792238185dc3e6a47c84b52`（MIT）；go-judge v1.13.0 commit `e9d70a0d9a3df0c62182a6e7090d7af650a1d5f8`（MIT及Moby seccomp Apache-2.0 NOTICE）；oj-lab commit `a4e1d6f106879043eb30af640ba46d0fcbf8053f`（根MIT，逐包独立审核）；problemtools v1.20260907 commit `6010cbaa37a1612117f49566b2fff8646d53faa2`（MIT）。适配层与上游代码分开，固定源码依赖/补丁与SBOM，镜像保留LICENSE/NOTICE；升级只改锁定版本及适配层并回归，不复制成自研沙箱。

迁移：先建基础身份/许可/语言表，版本、artifact、validation间循环本地引用采用先表后DEFERRABLE FK；再测试/参考程序、import任务明细、catalog、judge任务/result/case、outbox/operation请求。所有FK循环仅为本服务完整性，不是跨服务调用循环；外部Submission/users无物理FK。数据库凭据只授予judge schema，本服务不持backend/algorithm schema权限。

验收要求：同源commit重复导入无重复原包；元数据新版本共享包且老版不改；不许可/题包错误禁止发布；同题current引用/本题test关联正确；新publish推进目录且旧task继续旧版；目录快照含撤题墓碑且不拼跨版本；同request只有一task；task终态/result/outbox原子；乱序重复回调不改变事实；进程重启恢复租约与投递；源码副本清理不删backend主源码；全部隐藏数据不公开；停止algorithm不影响判题与题库；四业务容器同机在cgroup/seccomp限制实测通过后形成最终训练闭环。
