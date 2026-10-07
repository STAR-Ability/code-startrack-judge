# V0.2 前端 API 文档

契约发布号：`0.2.0`。本文件与《前端需要知道的数据库.md》及《V0.2-整体架构与联调说明.md》组成前端独立实施依据。以下类型与端点是完整公开契约；历史类型集中在末尾，前端无需翻阅旧版文档。

## 1. 服务边界与兼容

浏览器只访问 frontend:80，同源 `/api/v1/**` 代理至 backend:8081。四个独立业务容器为 frontend、backend、algorithm:8000、judge-problem-service:8082。frontend 负责页面、编辑器、API Client、缓存与展示，只持有公开 DTO；服务令牌、数据库凭据、题包与隐藏测试均由对应服务持有。平台题目的题面由 backend 返回；外部推荐的 `url` 只用于浏览器导航。

V0.11 注册/登录/多 CF/账号级画像与推荐，V0.12 多 CF 用户画像/团队/隐私/报告/通知/教练全部保留原路径、原响应与原统计语义。`/me/analysis/**` 仍是 CF 汇总；新增 `/me/learning-profile/**` 表示平台与外部训练的综合学习画像。旧团队及报告仍使用 CF 画像，不自动纳入平台源码或静态分析。新平台 Submission 使用独立 `SubmissionView`，不能替换旧 `SubmissionDto`。新增接口仍属 `/api/v1`；`0.2.0` 是设计契约版本。

## 2. 统一公开协议

- JSON 使用 camelCase，`Content-Type: application/json`；未声明的请求字段返回 400。类型未写 `?` 的字段必须出现，只有 `| null` 可空；数组空值为 `[]`。
- `Id` 为正十进制字符串，`UUID` 为标准 UUID 字符串，均不转 JS number。`Instant` 为 RFC3339 UTC Z，例 `2026-10-07T02:30:00Z`；日期为 `YYYY-MM-DD`。时间用 timeMs 毫秒，内存用 memoryBytes 字节。
- `ApiResponse<T>` 是 `{data:T,requestId:UUID}`；`PageResponse<T>` 是 `{data:T[],meta:{page,pageSize,total,hasNext},requestId}`；表内写响应 T，表示已套上述 envelope。204 无 body。错误按 `ApiError.error.code` 判断。
- 分页默认 page=1、pageSize=20；page≥1，1≤pageSize≤100，total 为过滤后总条数，hasNext=page*pageSize<total；越界页返回 `[]`。每次分页请求内 total 与列表同快照；跨请求新增数据允许 total 变化。
- 认证用不透明 Session Cookie `cst_session`：HttpOnly、SameSite=Lax、Path=/，固定 7 天，生产 Secure。请求设置 `credentials: "include"`；所有写请求由后端校验 Origin 等于 PUBLIC_ORIGIN。登录/注册写 Cookie，退出/改密/重置/换邮箱按旧规则撤销。没有 refresh token。
- 除旧认证表明确开放的接口外全部登录；本轮题库也要求登录。个人操作需 STUDENT；管理导入、发布、撤题需 ADMIN。COACH 与 STUDENT 可同时存在，团队 OWNER 权限由 backend 逐次裁定。
- 新写接口必须 `Idempotency-Key: UUID`（提交、训练计划、分析重试、学习画像重建、综合推荐及题库管理）。一次操作的网络重试复用 key；成功后同 key 同参数 200 返回原对象，不同参数 409 IDEMPOTENCY_CONFLICT；在途若对象已持久化可 200 返回，否则 409 REQUEST_IN_PROGRESS + Retry-After:2。旧写接口只按其旧规则要求 key，不新增破坏性要求。

## 3. V0.2 工作区 DTO

此处复用末尾旧契约中的 Id、UUID、Instant、Summary、Period、TagStat、ActivityStat、DimensionScore、DimensionCode、ReasonCode、RecommendationMode；新类型不改变旧类型。

```ts
type ProblemSource = "PLATFORM" | "EXTERNAL";
type Platform = "startrack" | "codeforces";
type TrainingStatus = "PLANNED" | "IN_PROGRESS" | "COMPLETED";
type RecommendationSource = "ALL" | "PLATFORM" | "EXTERNAL";
type DifficultyScale = "CF_RATING" | "PLATFORM_RATING" | "UNRATED";
interface ProblemRef {
  source: ProblemSource; platform: Platform; problemId: Id; problemVersionId: UUID | null;
}
interface ProblemSummary {
  problemRef: ProblemRef; title: string | null; difficulty: number | null;
  difficultyScale: DifficultyScale; tags: string[]; url: string | null;
}
interface TaskError { code: string; message: string; retryable: boolean }
type JudgeStatus = "QUEUED" | "DISPATCHING" | "RUNNING" | "COMPLETED" | "FAILED" | "CANCELLED";
type JudgeVerdict = "AC" | "WA" | "TLE" | "MLE" | "RE" | "CE" | "OLE" | "IE";
type ProfileJobStatus = "QUEUED" | "RUNNING" | "SUCCEEDED" | "FAILED";
type AnalysisStatus = "NOT_REQUESTED" | "QUEUED" | "RUNNING" | "SUCCEEDED" | "PARTIAL" | "FAILED" | "SKIPPED";
interface JudgeResult {
  verdict: JudgeVerdict; timeMs: number | null; memoryBytes: number | null;
  passedTestCount: number; totalTestCount: number; score: number | null;
  compileLog: string | null; diagnosticCode: string | null; judgedAt: Instant;
}
interface SubmissionView {
  submissionId: Id; problem: ProblemSummary; languageId: string;
  judgeTaskId: UUID | null; judgeStatus: JudgeStatus; judgeRevision: number;
  judgeResult: JudgeResult | null; judgeError: TaskError | null; analysisId: UUID | null; analysisStatus: AnalysisStatus;
  analysisRevision: number; analysisError: TaskError | null;
  submittedAt: Instant; updatedAt: Instant;
}
interface LanguageCapability {
  languageId: string; displayName: string; languageFamily: string; compilerVersion: string;
  sourceFilename: string; analysisSupported: boolean;
}
interface AnalysisMetrics {
  sourceLines: number | null; functionCount: number | null;
  maxCyclomaticComplexity: number | null; meanCyclomaticComplexity: number | null;
  duplicateLines: number | null; maintainabilityIndex: number | null;
}
interface AnalysisFinding {
  findingId: string; tool: string; ruleId: string; severity: "INFO" | "WARNING" | "ERROR";
  category: "COMPLEXITY" | "BUG_RISK" | "STYLE" | "PERFORMANCE" | "DUPLICATION";
  message: string; file: string; startLine: number; endLine: number; column: number | null;
}
interface ToolRun {
  tool: string; version: string; configSha256: string;
  status: "SUCCEEDED" | "FAILED" | "SKIPPED"; durationMs: number; error: TaskError | null;
}
interface StaticAnalysisResult {
  schemaVersion: "0.2.0"; analysisId: UUID; submissionId: Id; sourceSha256: string;
  languageId: string; toolchainVersion: string; resultHash: string;
  metrics: AnalysisMetrics; findings: AnalysisFinding[]; tools: ToolRun[];
  reproducibility: { imageDigest: string; configSha256: string; sourceSha256: string };
  synthesis: {
    status: "NOT_REQUESTED" | "QUEUED" | "RUNNING" | "SUCCEEDED" | "FAILED" | "SKIPPED";
    provider: string | null; model: string | null; promptVersion: string | null;
    content: string | null; error: TaskError | null;
  };
}
interface SubmissionAnalysisView {
  analysisId: UUID | null; status: AnalysisStatus; revision: number;
  result: StaticAnalysisResult | null; error: TaskError | null;
}
interface TrainingRecord {
  trainingRecordId:UUID;problem:ProblemSummary;status:TrainingStatus;
  recommendationBatchId:UUID|null;firstSubmittedAt:Instant|null;lastSubmittedAt:Instant|null;
  attemptCount:number;acceptedSubmissionCount:number;lastSubmissionId:Id|null;
  completedAt:Instant|null;createdAt:Instant;updatedAt:Instant;
}
interface LearningDifficultyStat {
  difficulty: number | null; difficultyScale: DifficultyScale;
  attemptedProblemCount: number; solvedCount: number;
}
interface LearningProfileSources {
  platformSubmissionCount: number; externalSubmissionCount: number;
  codeAnalysisCount: number; sourceAccountIds: Id[];
}
interface CodeQuality {
  analyzedSubmissionCount: number; warningCount: number; errorCount: number;
  maxCyclomaticComplexity: number | null;
}
interface LearningAnalysisResult {
  window: AnalysisWindow; period: Period; summary: Summary;
  currentRating: number | null; maxRating: number | null;
  overallScore: number; dimensions: DimensionScore[]; weakestDimension: DimensionCode;
  tagStats: TagStat[]; difficultyStats: LearningDifficultyStat[];
  activityStats: ActivityStat[]; sources: LearningProfileSources; codeQuality: CodeQuality;
}
interface LearningProfile extends LearningAnalysisResult {
  publicId: UUID; snapshotId: UUID; profileJobId: UUID; sourceFingerprint: string;
  algorithmVersion: "learning-profile-v0.2.1"; mappingVersion: "mapping-v0.11.1";
  timezone: "Asia/Shanghai"; dataCutoffAt: Instant; createdAt: Instant; stale: boolean;
}
interface LearningProfileJob {
  jobId: UUID; status: ProfileJobStatus; sourceFingerprint: string;
  profileJobId: UUID | null; error: TaskError | null;
  createdAt: Instant; updatedAt: Instant; finishedAt: Instant | null;
}

interface LearningRecommendation {
  rank: number; problem: ProblemSummary; score: number; reasonCode: ReasonCode; reason: string;
  matchedDimension: DimensionCode | null; solvedSinceGeneration: boolean;
}
interface LearningRecommendationBatch {
  batchId:UUID;analysisSnapshotId:UUID;sourceFingerprint:string;source:RecommendationSource;
  mode:RecommendationMode;algorithmVersion:"learning-recommend-v0.2.1";mappingVersion:string;
  candidateCount:number;resultCount:number;recommendations:LearningRecommendation[];
  generatedAt:Instant;stale:boolean;
}
```

题目身份是 `(source,platform,problemId)`，版本不是题目去重键：PLATFORM 必须 `startrack` 且 problemVersionId 非空；EXTERNAL 必须 `codeforces` 且版本为 null。两个 owner 的题目 ID 空间可重叠，不能按裸 problemId 拼接缓存、统计或推荐。平台 url=null，前端用返回 problemId 导航；外部按 url 打开原站。difficultyScale 与 difficulty 同时展示，未评级为 null/UNRATED；不得把 points 当难度。

```ts
interface TaskBase {
  requestId: UUID; revision: number; status: string; error: TaskError | null;
  createdAt: Instant; updatedAt: Instant; finishedAt: Instant | null;
}
type PlatformProblemStatus = "DRAFT" | "PUBLISHED" | "WITHDRAWN";
interface PlatformProblemSummary extends ProblemSummary {
  problemRef: {source:"PLATFORM"; platform:"startrack"; problemId:Id; problemVersionId:UUID};
  status: PlatformProblemStatus;
  catalogVersion: Id;
  timeLimitMs: number;
  memoryLimitBytes: number;
  languageIds: string[];
  updatedAt: Instant;
}
interface PlatformProblemDetail extends PlatformProblemSummary {
  statement: {format:"MARKDOWN"; content:string; input:string|null; output:string|null};
  samples: Array<{input:string; output:string}>;
  license: {spdxId:string|null; notice:string; sourceUrl:string};
}
interface LanguageCapabilities { languages:LanguageCapability[]; capabilityVersion:string }
type ImportStatus = "QUEUED" | "RUNNING" | "SUCCEEDED" | "PARTIAL" | "FAILED";
interface ImportItem {
  packagePath:string;
  status:"PENDING"|"VALIDATED"|"REJECTED";
  problemId:Id|null;
  problemVersionId:UUID|null;
  licenseStatus:"PENDING"|"VERIFIED"|"MISSING"|"REVIEW_REQUIRED";
  validationStatus:"PENDING"|"PASSED"|"FAILED";
  errors:TaskError[];
}
interface ImportJob extends TaskBase {
  importJobId:UUID;
  status:ImportStatus;
  source:"OJ_LAB";
  repositoryUrl:"https://github.com/oj-lab/problem-packages";
  sourceRevision:string;
  packageCount:number;
  completedPackageCount:number;
  items:ImportItem[];
}
```

PlatformProblemSummary 是判题题库 owner 返回的只读题目视图。普通用户只读 PUBLISHED；ADMIN 的版本草稿可为 DRAFT。历史详情冻结题包字段；指定版本从未发布时status=DRAFT，曾发布时status为题目当前PUBLISHED/WITHDRAWN，catalogVersion始终为当前目录版本。目录版本、题目版本与 capabilityVersion 各有独立用途，不混作缓存同一版本。


新学习推荐的已解集合为平台全历史有效AC与当前未解绑CF账号全历史有效AC，按题目身份去重；已解绑账号的历史训练记录仍可查询，但不参与当前画像及新推荐过滤。

## 4. 平台题库与语言能力

所有调用方均为 frontend，实际接收服务均为 backend；以下及后续路径统一加 `/api/v1`。

| 方法与路径 | 参数 / 请求 | 成功响应 | 专属错误 |
|---|---|---|---|
| GET `/platform-problems` | q?、tag?、minDifficulty?、maxDifficulty?、status=PUBLISHED、分页 | 200 Page<PlatformProblemSummary> | 400 INVALID_ARGUMENT；503 JUDGE_UNAVAILABLE；504 JUDGE_TIMEOUT |
| GET `/platform-problems/{problemId}` | Id 路径 | 200 PlatformProblemDetail，当前已发布版 | 404 PROBLEM_NOT_FOUND |
| GET `/platform-problems/{problemId}/versions/{problemVersionId}` | Id + UUID | 200 PlatformProblemDetail，历史可读版 | 404 PROBLEM_NOT_FOUND |
| GET `/judge-languages` | 无 | 200 `{languages: LanguageCapability[], capabilityVersion: string}` | 503 JUDGE_UNAVAILABLE |

q trim 后 1..100 字符、模糊匹配题名；tag 精确匹配，1..128 字符；difficulty 边界为正整数且 min≤max，包含端点，只有PLATFORM_RATING参与，null 不匹配。普通用户 status 仅 PUBLISHED；列表按 updatedAt DESC、problemId 数值 DESC 排序，每次请求是同一目录快照，后续翻页目录更新可以变化，筛选变化重置 page。历史版仅曾发布或本人提交引用时可读；详情可读不代表该版本可新提交，以提交端点最终校验为准。题面为 Markdown，按前端安全渲染器显示；样例是公开测试，不能推断隐藏测试数和覆盖范围。

首发 cpp17 必须可用；c11 可选；Java/Python 只有实际配置后才在语言列表出现。编辑器 languageId 来自能力列表，不根据 CF programmingLanguage 自由文本猜编译器。analysisSupported 由backend取judge标记与algorithm真实analysisLanguages交集；algorithm暂不可达时false，仍可判题，UI解释为“当前分析暂不可用”，不由此推断永久不支持；具体原因以analysisError为准。公开capabilityVersion是backend对内部目录能力版本及按languageId排序的最终公开languages计算的SHA-256；analysisSupported交集变化会改变版本，客户端按此值刷新语言能力缓存。

## 5. 平台 Submission 与独立分析

| 方法与路径 | 参数 / 请求 | 成功响应 | 专属错误 |
|---|---|---|---|
| POST `/submissions` | `{problemRef: ProblemRef, languageId: string, sourceCode: string, trainingRecordId?: UUID}` + 幂等 key | 首次 202 SubmissionView，重放 200 原提交 | 400 INVALID_ARGUMENT/INVALID_PROBLEM_REF；404 PROBLEM_NOT_FOUND/TRAINING_RECORD_NOT_FOUND；409 PROBLEM_VERSION_CONFLICT/PROBLEM_NOT_SUBMITTABLE/LANGUAGE_NOT_SUPPORTED；413 SOURCE_TOO_LARGE |
| GET `/submissions` | problemId?、judgeStatus?、verdict: JudgeVerdict?、from/to?、分页 | 200 Page<SubmissionView>，仅本人平台提交 | 400 INVALID_ARGUMENT |
| GET `/submissions/{submissionId}` | Id | 200 SubmissionView | 404 SUBMISSION_NOT_FOUND |
| GET `/submissions/{submissionId}/source` | Id | 200 `{submissionId:Id, sourceCode:string, sourceSha256:string, languageId:string}` | 404 SUBMISSION_NOT_FOUND |
| GET `/submissions/{submissionId}/analysis` | Id | 200 SubmissionAnalysisView | 404 SUBMISSION_NOT_FOUND |
| POST `/submissions/{submissionId}/analysis/retry` | 无 body + 幂等 key | 首次 202 SubmissionAnalysisView；已有在途或重放 200 | 409 ANALYSIS_ALREADY_COMPLETE/ANALYSIS_NOT_RETRYABLE；503 ALGORITHM_UNAVAILABLE |

提交只接受 PLATFORM，不接受外部题伪造本地判题。sourceCode 是单文件 UTF-8 字符串，空白代码 400，最多 262144 字节（用 TextEncoder 字节数提示），普通写入/提交HTTP body最多2MiB；静态结果GET可达32MiB但不含raw工具报告，不把2MiB提交限制套到读结果。源码不 trim、不重写。传 trainingRecordId 时必须属于本人且指向同一题目身份；不传时 backend 自动关联或创建训练记录。题目版本变更返回 PROBLEM_VERSION_CONFLICT 时刷新详情并保留编辑器源码，由用户再次提交。不得把旧幂等 key 用于已经修改的源码。

本人源码响应是 private/no-store；编辑器内临时草稿按 publicId + ProblemRef + languageId 隔离，不默认把源码写入长期 localStorage。提交列表按 submittedAt DESC、submissionId 数值 DESC，from 包含/to 不包含，枚举过滤精确匹配。查询不存在或他人提交都返回同类 404。

判题主链：QUEUED → DISPATCHING → RUNNING → COMPLETED；依赖/执行基础设施错误进入 FAILED，取消进入 CANCELLED。回调或轮询可跳过中间状态，前端只按最新响应展示。COMPLETED 对应 AC/WA/TLE/MLE/RE/CE/OLE；已创建远程任务的 FAILED 对应真实 IE，不能显示“用户答错”；派发时题目撤下/版本冲突等明确拒绝或网络重试耗尽，也可本地 FAILED，此时 judgeTaskId/judgeResult 为 null，judgeError 是明确原因。前者刷新题目后发新提交，后者按 retryable 展示恢复提示，不能永久等QUEUED；接收不确定的可恢复本地FAILED仍由backend按原requestId对账，稍后可能恢复成真实RUNNING/COMPLETED状态，刷新提交历史读取，不生成重复Submission；CANCELLED 无判定。在途/成功 judgeError=null。judgeResult 未产生为 null。timeMs 是单测试最大 CPU 耗时，memoryBytes 是单测试峰值最大值，未运行为 null。二元 AC/WA 的 score=null；compileLog 仅本人/管理员可读，最多 16384 字节且已脱敏；不展示隐藏输入、期望输出、stdout/stderr 或测试路径。

代码分析与判题独立：判题完成先更新训练与基础画像，后台随后提交分析。QUEUED/RUNNING 显示分析中；SUCCEEDED 显示指标与诊断；PARTIAL 显示可用结果及失败工具；FAILED 显示不可用与可重试提示；SKIPPED 显示不支持或暂时无法运行；NOT_REQUESTED 显示尚未申请。FAILED/PARTIAL/暂不可用的 SKIPPED 可 retry；SUCCEEDED 不再重跑；未判题完成及不可分析语言返回 ANALYSIS_NOT_RETRYABLE。工具失败不把 AC 改成 IE，也不撤销训练完成。分析重试后当前 analysisId 变为新任务、result 暂为 null，但画像继续使用最近一次可用 SUCCEEDED/PARTIAL 证据；只有新的可用结果落库才推进特征版本，codeQuality 不因点击重试临时清零。

静态分析展示 Lizard 复杂度、clang-tidy/Infer 诊断、CPD 提交内重复；Python Radon、Java PMD/CPD 属能力扩展。字段缺失用 null，圈复杂度不能标成 Big-O，CPD 结果不能标成跨用户抄袭。findings 位置为 1-based 行，endLine≥startLine，column 为 1-based 或 null，file 是逻辑相对文件名。tools 明确每个工具版本、状态与配置摘要。v0.2 `synthesis.status=NOT_REQUESTED`，provider/model/promptVersion/content/error 为 null；界面先保留综合分析区的未来接口位置，不伪造 LLM 解释。

| 新 JudgeVerdict | 统一训练/旧 Verdict | 展示意义 |
|---|---|---|
| AC | ACCEPTED | 通过 |
| WA | WRONG_ANSWER | 答案错误 |
| TLE | TIME_LIMIT | 超时 |
| MLE | MEMORY_LIMIT | 超内存 |
| RE | RUNTIME_ERROR | 运行错误 |
| CE | COMPILE_ERROR | 编译错误 |
| OLE | OTHER | 输出超限，计训练失败 |
| IE | 不产生能力失败证据 | 判题基础设施错误 |
| 尚未完成 | PENDING | 不计训练失败 |
| CANCELLED | 不产生能力失败证据 | 已取消 |

前端显示短判定标签，后端提供统一统计；不得在旧 CF API 请求 verdict=AC。

## 6. 训练记录、综合画像与内外推荐

| 方法与路径 | 参数 / 请求 | 成功响应 | 专属错误 |
|---|---|---|---|
| POST `/me/training-records` | `{problemRef: ProblemRef, recommendationBatchId?: UUID}` + 幂等 key | 首次 201 TrainingRecord；重放 200 | 400 INVALID_PROBLEM_REF；404 RESOURCE_NOT_FOUND；409 IDEMPOTENCY_CONFLICT |
| GET `/me/training-records` | source?: ProblemSource、status?: PLANNED/IN_PROGRESS/COMPLETED、from/to?、分页 | 200 Page<TrainingRecord> | 400 INVALID_ARGUMENT |
| GET `/me/training-records/{trainingRecordId}` | UUID | 200 TrainingRecord | 404 TRAINING_RECORD_NOT_FOUND |
| GET `/me/learning-profile/latest` | window=ALL | 200 LearningProfile 或 null | 400 INVALID_ANALYSIS_WINDOW |
| GET `/me/learning-profile/history` | window=ALL + 分页 | 200 Page<LearningProfile> | 400 INVALID_ANALYSIS_WINDOW |
| GET `/me/learning-profile/{snapshotId}` | UUID | 200 LearningProfile | 404 RESOURCE_NOT_FOUND |
| POST `/me/learning-profile/rebuild` | 无 body + 幂等 key | 首次 202 LearningProfileJob；重放/已有任务 200 | 409 USER_SOURCE_NOT_READY；413 INPUT_TOO_LARGE；429 RATE_LIMITED |
| GET `/learning-profile-jobs/{jobId}` | UUID | 200 LearningProfileJob | 404 TASK_NOT_FOUND |
| POST `/me/recommendations/generate` | `{source?: "ALL"\|"PLATFORM"\|"EXTERNAL", mode?: RecommendationMode, limit?: number}`，默认 ALL/HYBRID/10，limit 整数1..50，幂等 key | 首次 201 LearningRecommendationBatch；重放 200 | 409 PROFILE_NOT_READY/DATA_CHANGED；502 ALGORITHM_BAD_RESPONSE；503 ALGORITHM_UNAVAILABLE；504 ALGORITHM_TIMEOUT |
| GET `/me/recommendations/latest` | source=ALL、mode=HYBRID | 200 LearningRecommendationBatch 或 null | 400 INVALID_ARGUMENT |
| GET `/me/recommendations/history` | source?/mode?，省略表示全部；分页 | 200 Page<LearningRecommendationBatch> | 400 INVALID_ARGUMENT |
| GET `/me/recommendations/{batchId}` | UUID | 200 LearningRecommendationBatch | 404 RESOURCE_NOT_FOUND |

训练记录唯一键是本人 + 题目身份；不同key重复计划也200返回既有记录，不新增计数；首次非空推荐归因冻结，后续推荐不重写。PLANNED 表示选题，IN_PROGRESS 表示有实际提交，COMPLETED 表示出现 AC。平台提交自动关联，外部只在绑定账号同步到真实结果后更新；跳转或手工点击不产生“通过”，外部记录没有源码分析。推荐关联只接受本轮 `/me/recommendations` 实际交付的本人批次且包含同一题目，不接旧CF单账号或团队batchId；前端传返回 batchId，不自行生成。训练列表按 updatedAt DESC、trainingRecordId DESC；from/to 过滤 lastSubmittedAt，from 包含/to 不包含，有边界时未提交计划不匹配。记录读取总是返回当前训练投影，不靠前端计数。CF重评若使有效AC全部撤销，记录可COMPLETED→IN_PROGRESS，以backend新事实响应为准。

综合画像允许纯平台数据和零画像，无需 CF 绑定才能使用；有未就绪 CF 时不悄悄漏掉该账号，任务返回 USER_SOURCE_NOT_READY，仍可看已有平台提交。来源计数区分平台、跨 CF 去重提交与可用代码分析。六维仍是判题训练熟练度 0..100；代码质量单独 codeQuality，不用 warning 数改变雷达轴。静态分析完成后 backend 推进特征版本、异步重建画像；未完成不阻塞基础画像。推荐必须基于最新未 stale 的 ALL 综合快照，不直接拿 `/me/analysis` 的旧 CF 快照。

新画像 summary 与 dimensions 的平均/最高难度、ratedSolvedCount 只按 CF_RATING；其他尺度计入 unratedSolvedCount，但分布按 `(difficultyScale,difficulty)` 独立桶保留。本地 PLATFORM_RATING 不能直接与 CF_RATING 比较；LEVEL 只接受可比较尺度候选，HYBRID 可按标签/新手规则纳入未评级本地题并在 reason 说明。ALL 排名按后端返回统一 score，前端不按原始 difficulty 混排。历史批次的题目/原因/rank 冻结，solvedSinceGeneration 单独标已完成，不改历史排名。

画像历史按 dataCutoffAt DESC、createdAt DESC、snapshotId DESC；推荐按 generatedAt DESC、batchId DESC。GET 不触发计算。null 是尚未生成，完整零画像是成功计算但无训练证据；recommendations=[] 是范围内无候选。stale 可以展示旧结果，但提示重建；版本/源数据变化或截止超过24小时由 backend 判定 stale，前端不自行推测。

## 6.1 保留管理员题库代理签名

前端本轮可只提供管理调用签名，不扩张完整 ADMIN 产品页面。调用方为带 ADMIN Session 的管理客户端，全部由 backend 代理到题库 owner，不直连下游或数据库。

| 方法与路径 | Request / 约束 | 成功响应 | 专属错误 |
|---|---|---|---|
| POST `/admin/problem-imports` | `{source:"OJ_LAB",repositoryUrl:"https://github.com/oj-lab/problem-packages",revision:string,packagePaths:string[]}` + 幂等 key | 首次202 ImportJob，重放200 | 400 INVALID_ARGUMENT；503 JUDGE_UNAVAILABLE |
| GET `/admin/problem-imports/{importJobId}` | UUID，无body | 200 ImportJob | 404 TASK_NOT_FOUND |
| POST `/admin/platform-problems/{problemId}/publish` | `{problemVersionId:UUID}` + 幂等 key | 200 PlatformProblemDetail | 409 PROBLEM_VERSION_CONFLICT；422 PACKAGE_INVALID/PACKAGE_LICENSE_MISSING |
| POST `/admin/platform-problems/{problemId}/withdraw` | `{reason:string}` + 幂等 key | 200 `{problemId:Id,status:"WITHDRAWN",catalogVersion:Id}` | 404 PROBLEM_NOT_FOUND |
| POST `/admin/platform-problems/{problemId}/metadata-versions` | `{baseProblemVersionId:UUID,tags:string[],difficulty:number\|null,difficultyScale:"PLATFORM_RATING"\|"UNRATED"}` + 幂等 key | 首次201 PlatformProblemDetail（DRAFT新版本），重放200 | 409 PROBLEM_VERSION_CONFLICT；400 INVALID_ARGUMENT |

revision 是完整40位不可变 commit；packagePaths 1..100项、唯一，必须是 `problems/` 下规范化相对目录，禁止URL、绝对路径或 `..`。题包工具校验成功仅产生 DRAFT，由管理员另行 publish。ImportJob 的 items 按请求顺序，completedPackageCount=VALIDATED+REJECTED；SUCCEEDED 全包有效，PARTIAL 部分有效、部分拒绝，FAILED 无有效包，轮询HTTP仍200。许可 MISSING/REVIEW_REQUIRED 不发布，repositoryUrl固定来源但仓库许可证不自动证明每题许可。

标签修改创建新不可变版本，不能原地改已发布题：tags≤32、每项1..128字符且去重，UNRATED要求difficulty=null，PLATFORM_RATING要求正整数与可信平台标定；随后publish切当前版。源码Submission与历史题目版本引用不改。


## 7. 页面与轮询流程

1. 应用初始化先 GET `/me`；401 清除所有私人缓存。主工作区读综合画像与综合推荐；CF 账号详情显式选择 accountId；团队仍按 teamId 路由与 backend 权限。
2. 题库列表 → 当前详情 → GET `/judge-languages` → 按 capability 选择 languageId → 编辑器 → POST `/me/training-records`（从推荐可带 batchId；直接提交可省略计划创建）→ POST `/submissions`。后台异步后仍留在提交详情。
3. 202 后每3秒 GET `/submissions/{id}`；judgeStatus 真实远程终态或确定拒绝后停止判题轮询；若本地FAILED且judgeTaskId=null、judgeError.retryable=true，继续每30秒低频刷新提交详情/历史，展示后台按原requestId对账恢复的结果，直至恢复后真实终态或离开页面；analysisStatus 未终态时继续 GET `/submissions/{id}/analysis`。PARTIAL/FAILED/SKIPPED 均为分析终态，需要人工 retry 才重新启动。页面隐藏暂停、恢复先查一次；网络错误指数退避至30秒，不重复 POST。
4. COMPLETED 立即显示判题结果并刷新训练记录，后台画像 job 完成后刷新综合画像、再由用户生成/读取新推荐。分析稍后完成可以再产生新综合快照；前端不等待分析才显示 AC。
5. 外部推荐 → 记录训练计划 → 打开后端 url → 完成原站训练 → CF同步 → 刷新训练和综合画像。没有CF源码时显示“外部训练不提供代码分析”。
6. SyncJob 的 SUCCESS/PARTIAL/FAILED、旧 AiJob 的 SUCCESS/FAILED、新 LearningProfileJob 的 SUCCEEDED/FAILED 分别处理，不能共用一个终态字符串判断。综合画像job轮询 `/learning-profile-jobs/{jobId}`，旧AI仍 `/ai-jobs/{jobId}`。

缓存键至少为 `[publicId, resource, ProblemRef身份/版本或submissionId/accountId/teamId, window/mode/source,分页与过滤]`。切账号/题/团队时取消旧请求或忽略迟到响应；退出清空。Submission 静态结果先比较当前 analysisId，再比较其 task 内 revision；重试产生新 analysisId 时，不用旧任务更大 revision 覆盖新任务。列表与详情以 backend 投影为准，不自行合并多个服务响应。

旧团队的 canManage/canLeave/myMembershipRole 和成员 dataAccess 是 UI 依据；角色仅控制导航，backend 始终最终授权。旧报告回看使用 report 冻结 statisticsSnapshot/profileSnapshot/recentTrainingSnapshot，不用当前画像替换。

## 8. HTTP 与错误行为

每个端点还适用401 SESSION_EXPIRED、403 ORIGIN_REJECTED/ROLE_REQUIRED（相应写入/角色），错误体均为 ApiError。任务失败轮询 HTTP 200，失败原因在 error 或旧 errors[] 内；不会把 GET 轮询用5xx表示业务终态。

| HTTP | code | 前端动作 |
|---|---|---|
| 400 | INVALID_ARGUMENT、INVALID_PROBLEM_REF、INVALID_ANALYSIS_WINDOW、INVALID_RECOMMENDATION_MODE | 修正参数；字段明细在 details.fields |
| 404 | PROBLEM_NOT_FOUND、SUBMISSION_NOT_FOUND、TASK_NOT_FOUND、TRAINING_RECORD_NOT_FOUND、RESOURCE_NOT_FOUND | 刷新列表；不存在与他人资源同类404 |
| 409 | IDEMPOTENCY_CONFLICT、REQUEST_IN_PROGRESS | 修正key或按Retry-After重试同操作 |
| 409 | PROBLEM_VERSION_CONFLICT、PROBLEM_NOT_SUBMITTABLE、LANGUAGE_NOT_SUPPORTED | 保留源码，刷新题目/语言能力 |
| 409 | PROFILE_NOT_READY、USER_SOURCE_NOT_READY、DATA_CHANGED | 保留旧结果，刷新源状态或重建 |
| 409 | ANALYSIS_ALREADY_COMPLETE、ANALYSIS_NOT_RETRYABLE | 刷新现有分析，不重复重试 |
| 413 | SOURCE_TOO_LARGE、INPUT_TOO_LARGE | 提示UTF-8大小或完整分析数据超限，不截断源码/历史 |
| 429 | RATE_LIMITED 及旧专有限流码 | 按Retry-After秒数倒计时 |
| 502 | JUDGE_BAD_RESPONSE、ALGORITHM_BAD_RESPONSE | 保留已创建对象与requestId，允许查询恢复 |
| 503 | JUDGE_UNAVAILABLE、ALGORITHM_UNAVAILABLE | 保留数据；已接受Submission等待恢复，勿重复生成新提交 |
| 504 | JUDGE_TIMEOUT、ALGORITHM_TIMEOUT | 用原key重试或查询，避免重复任务 |
| 500 | INTERNAL_ERROR | 展示requestId便于排查 |

旧认证/账号/团队错误码保持原含义，完整列在第10节。错误 message 用于展示，路由/权限/重试依 code；details 是object，无明细 `{}`；不展示SQL、堆栈、token或邮箱验证码。

## 9. 保留的 V0.11/V0.12 公共 DTO

以下合法字段与既有序列化保持一致，仅集中到本版作为兼容基线；新需求由独立类型承接。

```ts
type Id = string; // PostgreSQL bigint 的十进制正整数字符串；禁止转 JS number
type UUID = string; // 标准 UUID 字符串
type Instant = string; // ISO 8601 UTC，例 2026-10-02T02:30:00Z
type DateKey = string; // YYYY-MM-DD，按 timezone 的自然日
type AnalysisWindow = "7D" | "30D" | "365D" | "ALL";
type RecommendationMode = "LEVEL" | "WEAKNESS" | "HYBRID";
type Verdict = "ACCEPTED" | "PARTIAL" | "WRONG_ANSWER" | "TIME_LIMIT"
  | "MEMORY_LIMIT" | "RUNTIME_ERROR" | "COMPILE_ERROR" | "SKIPPED"
  | "CHALLENGED" | "IDLENESS_LIMIT" | "PRESENTATION_ERROR" | "PENDING" | "OTHER";
type DimensionCode = "IMPLEMENTATION" | "ALGORITHMS" | "DATA_STRUCTURES"
  | "DYNAMIC_PROGRAMMING" | "GRAPHS" | "MATH";
type ReasonCode = "WEAK_DIMENSION_MATCH" | "LEVEL_MATCH" | "SLIGHTLY_ABOVE_LEVEL"
  | "TAG_MATCH" | "BALANCED_PRACTICE" | "RECENT_WEAKNESS" | "LOW_ATTEMPT_COVERAGE"
  | "RATING_GROWTH_STEP" | "MIXED_SKILL_MATCH" | "DEFAULT_RECOMMENDATION";
interface Period { start: Instant | null; end: Instant }
interface Summary {
  attemptedProblemCount: number; solvedCount: number; unsolvedProblemCount: number;
  submissionCount: number; acceptedSubmissionCount: number;
  failedSubmissionCount: number; pendingSubmissionCount: number;
  ratedSolvedCount: number; unratedSolvedCount: number;
  averageSolvedDifficulty: number | null; maxSolvedDifficulty: number | null;
  activeDays: number;
}
interface TagStat {
  tag: string; attemptedProblemCount: number; solvedCount: number; submissionCount: number;
}
interface DifficultyStat {
  difficulty: number | null; attemptedProblemCount: number; solvedCount: number;
}
interface ActivityStat {
  date: DateKey; submissionCount: number; acceptedSubmissionCount: number;
  failedSubmissionCount: number; pendingSubmissionCount: number; solvedCount: number;
}
interface DimensionScore {
  code: DimensionCode; name: string; displayOrder: number; score: number;
  attemptedProblemCount: number; solvedCount: number; submissionCount: number;
  averageSolvedDifficulty: number | null; rankOrder: number;
}
interface AnalysisResult {
  window: AnalysisWindow; period: Period; summary: Summary;
  currentRating: number | null; maxRating: number | null;
  overallScore: number; dimensions: DimensionScore[];
  weakestDimension: DimensionCode;
  tagStats: TagStat[]; difficultyStats: DifficultyStat[]; activityStats: ActivityStat[];
}
type JobStatus = "QUEUED" | "RUNNING" | "SUCCESS" | "PARTIAL" | "FAILED";
type JobScope = "ACCOUNT_FULL" | "ANALYSIS_ONLY" | "PROBLEM_CATALOG";
type JobStage = "USER_INFO" | "SUBMISSIONS" | "RATING_HISTORY" | "PROBLEM_CATALOG" | "ANALYSIS" | "DONE";
interface UserDto {
  publicId: UUID; username: string; displayName: string | null; email: string;
  avatarUrl: string | null; emailVerified: boolean;
  accountStatus: "ACTIVE" | "LOCKED" | "DISABLED" | "DELETED";
  roles: string[]; primaryRole: string; locale: string; timezone: string;
}
interface OjAccountDto {
  accountId: Id; platform: "codeforces"; username: string;
  bindStatus: "ACTIVE" | "INVALID" | "UNBOUND";
  rating: number | null; maxRating: number | null; rank: string | null; maxRank: string | null;
  contribution: number | null; friendOfCount: number | null;
  firstName: string | null; lastName: string | null; country: string | null;
  city: string | null; organization: string | null; avatarUrl: string | null;
  titlePhotoUrl: string | null; registeredAt: Instant | null; lastOnlineAt: Instant | null;
  lastSyncedAt: Instant | null; lastSyncStatus: JobStatus | null;
  nextSyncAt: Instant | null; boundAt: Instant; unboundAt: Instant | null;
}
interface JobError { stage: JobStage; code: string; message: string; retryable: boolean }
interface SyncJobDto {
  jobId: UUID; accountId: Id | null; scope: JobScope;
  triggerType: "MANUAL" | "SCHEDULED" | "SYSTEM"; status: JobStatus;
  stage: JobStage | null; itemsFetched: number; itemsInserted: number; itemsUpdated: number;
  errors: JobError[]; requestedAt: Instant; startedAt: Instant | null; finishedAt: Instant | null;
}
interface SyncStatusDto {
  accountId: Id; lastSyncedAt: Instant | null; lastSyncStatus: JobStatus | null;
  nextSyncAt: Instant | null; latestJob: SyncJobDto | null;
}
interface ProblemDto {
  problemId: Id; platform: "codeforces"; externalProblemKey: string;
  title: string | null; difficulty: number | null; points: number | null;
  tags: string[]; solvedCount: number | null; url: string | null;
  isGym: boolean; catalogSource: "CATALOG" | "INFERRED";
}
interface ProblemProgressDto {
  accountId: Id; problem: ProblemDto;
  progress: { attemptCount: number; accepted: boolean; acceptedSubmissionCount: number;
    failedSubmissionCount: number; pendingSubmissionCount: number;
    firstSubmittedAt: Instant; lastSubmittedAt: Instant; acceptedAt: Instant | null };
}
interface SubmissionDto {
  submissionId: Id; accountId: Id; externalSubmissionId: Id; problem: ProblemDto;
  verdict: Verdict; verdictRaw: string | null; programmingLanguage: string | null;
  participantType: string | null; memberHandles: string[]; teamId: Id | null;
  teamName: string | null; testset: string | null; passedTestCount: number | null;
  timeMs: number | null; memoryBytes: number | null; submittedAt: Instant;
}
interface RatingChangeDto {
  accountId: Id; contestId: number; contestName: string; rank: number;
  oldRating: number; newRating: number; occurredAt: Instant;
}
interface AnalysisDto extends AnalysisResult {
  accountId: Id; snapshotId: UUID; algorithmVersion: string; mappingVersion: string;
  timezone: string; dataCutoffAt: Instant; sourceDataVersion: Id;
  createdAt: Instant; stale: boolean;
}
interface RecommendationDto {
  rank: number; problem: ProblemDto; score: number; reasonCode: ReasonCode; reason: string;
  matchedDimension: DimensionCode | null; solvedSinceGeneration: boolean;
}
interface RecommendationBatchDto {
  accountId: Id; batchId: UUID; analysisSnapshotId: UUID; mode: RecommendationMode;
  targetRating: number; targetDimension: DimensionCode | null;
  algorithmVersion: string; mappingVersion: string;
  candidateCount: number; resultCount: number; recommendations: RecommendationDto[];
  generatedAt: Instant; stale: boolean;
}
interface DashboardDto {
  accountId: Id; account: OjAccountDto; sync: SyncStatusDto;
  analysis: AnalysisDto | null; recommendationBatch: RecommendationBatchDto | null;
  nextAction: "SYNC" | "WAIT_SYNC" | "REBUILD_ANALYSIS" | "GENERATE_RECOMMENDATIONS" | "NONE";
}
interface ApiResponse<T> { data: T; requestId: UUID }
interface PageResponse<T> {
  data: T[]; meta: { page: number; pageSize: number; total: number; hasNext: boolean };
  requestId: UUID;
}
interface ApiError {
  error: { code: string; message: string; details: Record<string, unknown> }; requestId: UUID;
}

type TeamStatus = "ACTIVE" | "ARCHIVED" | "DISSOLVED";
type TeamMemberRole = "OWNER" | "MEMBER";
type TeamMemberStatus = "ACTIVE" | "LEFT" | "REMOVED";
type JoinApplicationStatus = "PENDING" | "APPROVED" | "REJECTED" | "CANCELLED";
type TeamInvitationStatus = "PENDING" | "ACCEPTED" | "REJECTED" | "EXPIRED" | "CANCELLED";
type PrivacyScope = "PRIVATE" | "TEAM_COACH" | "TEAM_MEMBER" | "PUBLIC";
type AiJobStatus = "QUEUED" | "RUNNING" | "SUCCESS" | "FAILED";
type AiJobType = "USER_ANALYSIS" | "PERSONAL_REPORT" | "TEAM_ANALYSIS" | "TEAM_RECOMMENDATION";
type AiJobTrigger = "MANUAL" | "SCHEDULED" | "SYSTEM";
type TeamAnalysisAudience = "COACH" | "MEMBER";
type TeamRecommendationMode = "WEAKNESS" | "HYBRID";

interface UserBriefDto {
  publicId: UUID;
  username: string;
  displayName: string | null;
  avatarUrl: string | null;
}

interface TeamSummaryDto {
  teamId: UUID;
  name: string;
  description: string | null;
  avatarUrl: string | null;
  status: TeamStatus;
  owner: UserBriefDto;
  memberCount: number;
  createdAt: Instant;
  updatedAt: Instant;
  myMembershipRole: TeamMemberRole | null;
  myJoinApplicationStatus: JoinApplicationStatus | null;
  myInvitationStatus: TeamInvitationStatus | null;
}

interface TeamDetailDto extends TeamSummaryDto {
  creator: UserBriefDto;
  canManage: boolean;
  canLeave: boolean;
  activeMemberCount: number;
}

interface TeamMemberDataAccessDto {
  basicTraining: boolean;
  abilityProfile: boolean;
  detailedSubmissions: boolean;
  analysisReport: boolean;
}

interface TeamMemberDto {
  membershipId: UUID;
  teamId: UUID;
  user: UserBriefDto;
  role: TeamMemberRole;
  status: TeamMemberStatus;
  joinedAt: Instant;
  endedAt: Instant | null;
  dataAccess: TeamMemberDataAccessDto;
}

interface JoinApplicationDto {
  applicationId: UUID;
  team: TeamSummaryDto;
  applicant: UserBriefDto;
  status: JoinApplicationStatus;
  message: string | null;
  decisionReason: string | null;
  createdAt: Instant;
  decidedAt: Instant | null;
  decidedBy: UserBriefDto | null;
}

interface TeamInvitationDto {
  invitationId: UUID;
  team: TeamSummaryDto;
  inviter: UserBriefDto;
  invitee: UserBriefDto | null;
  inviteeEmail: string | null;
  status: TeamInvitationStatus;
  createdAt: Instant;
  lastSentAt: Instant;
  expiresAt: Instant;
  respondedAt: Instant | null;
  emailDeliveryStatus: "PENDING" | "SENT" | "FAILED";
  emailDeliveryErrorCode: string | null;
}

interface PrivacySettingsDto {
  basicTraining: PrivacyScope;
  abilityProfile: PrivacyScope;
  detailedSubmissions: PrivacyScope;
  analysisReport: PrivacyScope;
  updatedAt: Instant;
}

interface UserRatingAccountDto {
  accountId: Id;
  platform: "codeforces";
  username: string;
  bindStatus: "ACTIVE" | "INVALID";
  currentRating: number | null;
  maxRating: number | null;
  lastSyncedAt: Instant;
}

// Summary/TagStat/DifficultyStat/ActivityStat/DimensionScore 复用 V0.11。
interface UserAnalysisDto {
  publicId: UUID;
  snapshotId: UUID;
  window: AnalysisWindow;
  period: {start: Instant | null; end: Instant};
  summary: Summary;
  currentRating: number | null;
  maxRating: number | null;
  ratingAccounts: UserRatingAccountDto[];
  overallScore: number;
  dimensions: DimensionScore[];
  weakestDimension: DimensionCode;
  tagStats: TagStat[];
  difficultyStats: DifficultyStat[];
  activityStats: ActivityStat[];
  sourceAccountCount: number;
  sourceAccountIds: Id[];
  sourceFingerprint: string;
  algorithmVersion: "user-profile-v0.12.1";
  mappingVersion: string;
  timezone: string;
  dataCutoffAt: Instant;
  createdAt: Instant;
  stale: boolean;
}

interface SharedTrainingOverviewDto {
  publicId: UUID;
  snapshotId: UUID;
  window: AnalysisWindow;
  period: {start: Instant | null; end: Instant};
  summary: Summary;
  currentRating: number | null;
  maxRating: number | null;
  tagStats: TagStat[];
  difficultyStats: DifficultyStat[];
  activityStats: ActivityStat[];
  sourceAccountCount: number;
  dataCutoffAt: Instant;
  stale: boolean;
}

interface SharedAbilityProfileDto {
  publicId: UUID;
  snapshotId: UUID;
  window: AnalysisWindow;
  overallScore: number;
  dimensions: DimensionScore[];
  weakestDimension: DimensionCode;
  dataCutoffAt: Instant;
  stale: boolean;
}

interface PersonalReportContentDto {
  overview: string;
  strengths: string[];
  weaknesses: string[];
  recentTrend: string;
  actionSuggestions: string[];
  caution: string | null;
}

interface ReportStatisticsSnapshotDto {
  summary: Summary;
  currentRating: number | null;
  maxRating: number | null;
  sourceAccountCount: number;
  dataCutoffAt: Instant;
}
interface ReportProfileSnapshotDto {
  overallScore: number;
  dimensions: DimensionScore[];
  weakestDimension: DimensionCode;
  tagStats: TagStat[];
  difficultyStats: DifficultyStat[];
}
interface ReportRecentTrainingSnapshotDto {
  period: {start: Instant | null; end: Instant};
  summary: Summary;
  tagStats: TagStat[];
  difficultyStats: DifficultyStat[];
  activityStats: ActivityStat[];
}
interface PersonalReportDto {
  reportId: UUID;
  analysisSnapshotId: UUID;
  recentAnalysisSnapshotId: UUID;
  sourceFingerprint: string;
  statisticsSnapshot: ReportStatisticsSnapshotDto;
  profileSnapshot: ReportProfileSnapshotDto;
  recentTrainingSnapshot: ReportRecentTrainingSnapshotDto;
  content: PersonalReportContentDto;
  reportVersion: "personal-report-v0.12.1";
  promptVersion: string;
  modelName: string;
  triggerType: "SCHEDULED" | "MANUAL";
  generatedAt: Instant;
}

interface AiJobErrorDto { code: string; message: string; retryable: boolean; }
interface AiJobDto {
  jobId: UUID;
  type: AiJobType;
  triggerType: AiJobTrigger;
  status: AiJobStatus;
  resultId: UUID | null;
  errors: AiJobErrorDto[];
  requestedAt: Instant;
  startedAt: Instant | null;
  finishedAt: Instant | null;
}

type NotificationType = "TEAM_INVITATION" | "TEAM_INVITATION_CANCELLED" | "JOIN_APPLICATION_CREATED"
  | "JOIN_APPLICATION_APPROVED" | "JOIN_APPLICATION_REJECTED" | "JOIN_APPLICATION_CANCELLED"
  | "MEMBER_JOINED" | "MEMBER_REMOVED";

interface NotificationDto {
  notificationId: UUID;
  type: NotificationType;
  title: string;
  body: string;
  teamId: UUID | null;
  actor: UserBriefDto | null;
  referenceType: "APPLICATION" | "INVITATION" | "MEMBERSHIP" | "TEAM" | null;
  referenceId: UUID | null;
  payload: Record<string, unknown>;
  read: boolean;
  createdAt: Instant;
}

interface TeamDimensionScoreDto {
  code: DimensionCode;
  name: string;
  displayOrder: number;
  score: number;
  memberSampleCount: number;
  rankOrder: number;
}

interface TeamActivityStatDto {
  date: string;
  submissionCount: number;
  acceptedSubmissionCount: number;
  activeMemberCount: number;
}

interface TeamAnalysisDto {
  snapshotId: UUID;
  teamId: UUID;
  audience: TeamAnalysisAudience;
  memberCount: number;
  includedMemberCount: number; // abilityProfile 样本数
  excludedMemberCount: number;
  trainingMemberCount: number; // basicTraining 活动样本数
  levelMemberCount: number; // 可提供 currentRating/averageSolvedDifficulty 的等级样本数
  overallScore: number;
  dimensions: TeamDimensionScoreDto[];
  weakestDimension: DimensionCode;
  activityStats: TeamActivityStatDto[];
  targetRating: number | null;
  sourceFingerprint: string;
  algorithmVersion: "team-profile-v0.12.1";
  mappingVersion: string;
  dataCutoffAt: Instant;
  createdAt: Instant;
  stale: boolean;
}

type TeamReasonCode = "TEAM_WEAKNESS_MATCH" | "TEAM_LEVEL_MATCH" | "TEAM_COVERAGE_GAP" | "TEAM_BALANCED_PRACTICE";
interface TeamRecommendationItemDto {
  rank: number;
  problem: ProblemDto;
  score: number;
  reasonCode: TeamReasonCode;
  reason: string;
}
interface TeamRecommendationBatchDto {
  batchId: UUID;
  teamId: UUID;
  analysisSnapshotId: UUID;
  mode: TeamRecommendationMode;
  targetRating: number;
  targetDimension: DimensionCode;
  candidateCount: number;
  resultCount: number;
  recommendations: TeamRecommendationItemDto[];
  algorithmVersion: "team-recommend-v0.12.1";
  mappingVersion: string;
  generatedAt: Instant;
  stale: boolean;
}

interface CoachDashboardDto {
  managedTeamCount: number;
  activeMemberCount: number;
  pendingApplicationCount: number;
  recentNotifications: NotificationDto[];
}

interface CoachInviteCodeDto {
  codeId: UUID; codePrefix: string; organization: string | null;
  maxUses: number; usedCount: number; expiresAt: Instant; enabled: boolean; createdAt: Instant;
}
interface UserSubmissionDto {
  sourceAccount: { accountId: Id; platform: "codeforces"; username: string };
  submission: SubmissionDto;
}
```

旧 UserSubmissionDto 是团队共享的 CF 提交元数据，跨账号相同 `platform+externalSubmissionId` 只返回一次，不含平台提交源码。此处补齐旧前端文档引用但缺失的类型，保持旧后端定义。roles 为系统角色字符串列表；rank/programmingLanguage/participantType/tags 为开放原始文本，不强制按 CF 样本数量封闭枚举。

## 10. 保留旧接口的完整签名

下表路径统一加 `/api/v1`；Query 未注明参数则不发送，Request 未注明则无body。`Page<T>` 表示 PageResponse<T>；其余成功响应套 ApiResponse<T>，204无body。

### 认证与安全

| 方法与路径                | Request                                                                                                                                                  | 成功状态及响应 T                                                                                                                  |
| ------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| POST /auth/captcha        | 无                                                                                                                                                       | 200`{challengeId: UUID, imageData: string, expiresInSeconds: number}`；imageData 为 PNG data URL（base64）；有效 180 秒，一次性 |
| POST /auth/email-codes    | `{email: string, purpose: "REGISTER"\|"PASSWORD_RESET"\|"EMAIL_CHANGE_OLD"\|"EMAIL_CHANGE_NEW", captchaChallengeId: UUID, captchaAnswer: string}`         | 202`{verificationId: UUID, cooldownSeconds: number, expiresInSeconds: number}`；60、600 秒                                      |
| POST /auth/register       | `{username: string, email: string, password: string, verificationId: UUID, emailCode: string}`                                                         | 201`{user: UserDto}`；验证邮箱、注册并登录，默认 STUDENT                                                                        |
| POST /auth/login          | `{account: string, password: string, captchaChallengeId: UUID, captchaAnswer: string}`                                                                 | 200`{user: UserDto, requiresOjBinding: boolean}`；account 为用户名或邮箱；无 ACTIVE/INVALID 绑定才需绑定                        |
| POST /auth/logout         | 无                                                                                                                                                       | 204；当前 Session 撤销，无有效会话也成功                                                                                          |
| POST /auth/logout-all     | 无                                                                                                                                                       | 200`{revokedSessions: number}`；所有设备下线                                                                                    |
| GET /me                   | 无                                                                                                                                                       | 200 UserDto                                                                                                                       |
| GET /me/roles             | 无                                                                                                                                                       | 200`{primaryRole: string, roles: Array<{code: string, name: string}>}`                                                          |
| POST /me/password/change  | `{currentPassword: string, newPassword: string}`                                                                                                       | 200`{changed: true, reauthRequired: true}`；全部会话撤销                                                                        |
| POST /auth/password/reset | `{email: string, verificationId: UUID, emailCode: string, newPassword: string}`                                                                        | 200`{reset: true}`；全部会话撤销                                                                                                |
| POST /me/email/change     | `{password: string, oldEmail: string, oldVerificationId: UUID, oldEmailCode: string, newEmail: string, newVerificationId: UUID, newEmailCode: string}` | 200`{email: string, emailVerified: true, reauthRequired: true}`；全部会话撤销                                                   |


### CF账号与同步

| 方法与路径                                     | Request / Query                                | 成功状态及响应 T                                                                            |
| ---------------------------------------------- | ---------------------------------------------- | ------------------------------------------------------------------------------------------- |
| POST /oj-accounts                              | `{platform: "codeforces", username: string}` | 201`{account: OjAccountDto, initialSync: SyncJobDto}`；绑定和创建 QUEUED 任务同一事务     |
| GET /oj-accounts                               | `includeUnbound=false`，boolean，分页参数    | 200 Page<OjAccountDto>；默认 ACTIVE/INVALID，按 boundAt DESC、accountId DESC |
| GET /oj-accounts/{accountId}                   | 无                                             | 200 OjAccountDto；可读自己 UNBOUND 历史                                                     |
| DELETE /oj-accounts/{accountId}                | 无                                             | 204；幂等软解绑；停止后续写入与定时同步                                                     |
| POST /oj-accounts/{accountId}/sync             | 无                                             | 202 SyncJobDto，ACCOUNT_FULL；已有 QUEUED/RUNNING 时返回同一任务                            |
| GET /sync-jobs/{jobId}                         | 无                                             | 200 SyncJobDto；普通用户仅能读取自己账号任务                                                |
| GET /oj-accounts/{accountId}/sync-status       | 无                                             | 200 SyncStatusDto                                                                           |
| POST /oj-accounts/{accountId}/analysis/rebuild | 无                                             | 202 SyncJobDto，ANALYSIS_ONLY；一次重建四个窗口，已有在途账号任务则返回该任务               |


### CF账号数据

| 方法与路径                                         | Query（均可省略）                                                                                                               | 成功状态及响应 T                                  |
| -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
| GET /oj-accounts/{accountId}/problems              | 分页；status=ALL（ALL/SOLVED/UNSOLVED），tag 精确匹配，minDifficulty/maxDifficulty 整数，sort=LAST_SUBMITTED_DESC（唯一排序值） | 200 Page<ProblemProgressDto> |
| GET /oj-accounts/{accountId}/submissions           | 分页；verdict: Verdict，problemId: Id，from/to: Instant                                                                         | 200 Page<SubmissionDto>           |
| GET /oj-accounts/{accountId}/rating-changes        | 分页                                                                                                                            | 200 Page<RatingChangeDto>       |
| GET /oj-accounts/{accountId}/training/overview     | window=30D（AnalysisWindow）                                                                                                    | 200 AnalysisDto 或 null                           |
| GET /oj-accounts/{accountId}/analysis/latest       | window=ALL（AnalysisWindow）                                                                                                    | 200 AnalysisDto 或 null                           |
| GET /oj-accounts/{accountId}/analysis/history      | window=ALL，分页                                                                                                                | 200 Page<AnalysisDto>               |
| GET /oj-accounts/{accountId}/analysis/{snapshotId} | 无                                                                                                                              | 200 AnalysisDto                                   |
| GET /oj-accounts/{accountId}/dashboard             | 无                                                                                                                              | 200 DashboardDto                                  |


### CF账号推荐

| 方法与路径                                             | Request / Query                                                                                                    | 成功状态及响应 T                                          |
| ------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------- |
| POST /oj-accounts/{accountId}/recommendations/generate | `{mode?: RecommendationMode, limit?: number}`；默认 HYBRID、10，limit 整数 1..50；必需 `Idempotency-Key: UUID` | 首次 201 RecommendationBatchDto；同 key 重放 200 原批次   |
| GET /oj-accounts/{accountId}/recommendations/latest    | mode=HYBRID                                                                                                        | 200 RecommendationBatchDto 或 null                        |
| GET /oj-accounts/{accountId}/recommendations/history   | mode 可省略（省略=所有模式），分页                                                                                 | 200 Page<RecommendationBatchDto> |
| GET /oj-accounts/{accountId}/recommendations/{batchId} | 无                                                                                                                 | 200 RecommendationBatchDto                                |


用户名3..32位ASCII字母/数字/下划线，大小写不敏感；密码12..128字符不trim；邮箱trim并小写用于唯一性，邮箱代码6位数字。图形验证码180秒/一次性，每次登录与发送邮件都需要；邮箱代码600秒/最多5次错误、同邮箱跨用途至少60秒，超限429+Retry-After。PASSWORD_RESET发送对不存在邮箱也同形202；EMAIL_CHANGE_OLD/NEW须登录。安全修改后reauthRequired清缓存回登录。

CF有效绑定为ACTIVE/INVALID，一个有效handle仅归一个用户，可绑定多个CF；handle只为显示和上游定位，accountId是稳定上下文。UNBOUND保留原用户历史，重新绑定总产生新accountId，不转移旧画像/任务/推荐；includeUnbound用于历史。INVALID可手动sync/解绑，UNBOUND不可sync/rebuild/generate。sync/rebuild有在途则返回同任务，否则至少60秒冷却；lastSyncedAt只表示三个CF数据阶段完整成功，算法失败可PARTIAL但不丢CF数据。

旧账号 problems 仅含有提交题，ALL/SOLVED/UNSOLVED按全历史AC定义，min/max含端点且null不匹配；排序lastSubmittedAt DESC、problemId数值DESC。submissions按submittedAt DESC、submissionId数值DESC，from含/to不含；rating-changes按occurredAt DESC、contestId DESC。分析latest/history按dataCutoffAt DESC、createdAt DESC、snapshotId DESC；training/overview与同window的latest取同快照。无快照data=null；无训练的成功分析是完整零画像。Dashboard nextAction仅指CF旧链路，不阻止平台做题。

旧CF推荐只基于本accountId最新完整未stale的ALL画像，默认HYBRID/10最大50，Idempotency-Key必填。首次201、成功重放200、在途409 REQUEST_IN_PROGRESS；同key参数冲突409；成功历史不可变，solvedSinceGeneration只追加展示标记；候选不足含0均成功。GET不触发计算。

### 身份与角色

| 方法与路径 | 权限 | Request | 成功响应 |
|---|---|---|---|
| PUT `/admin/users/{publicId}/roles/COACH` | ADMIN | 无 | 200 `{user: UserDto}` |
| DELETE `/admin/users/{publicId}/roles/COACH` | ADMIN | 无 | 204 |


| 方法与路径 | 权限 | Request / Query | 成功响应 |
|---|---|---|---|
| POST `/admin/coach-invite-codes` | ADMIN | `{organization: string\|null, maxUses: number, expiresAt: Instant}` | 201 `{codeId: UUID, code: string, organization: string\|null, maxUses: number, usedCount: 0, expiresAt: Instant, enabled: true}`；明文 code 仅此时返回 |
| GET `/admin/coach-invite-codes` | ADMIN | page/pageSize, enabled? | 200 Page<CoachInviteCodeDto> |
| PATCH `/admin/coach-invite-codes/{codeId}` | ADMIN | `{enabled: boolean}` | 200 CoachInviteCodeDto |
| POST `/coach-invite-codes/redeem` | 登录 | `{code: string}` | 200 `{user: UserDto}` |


### 团队基础

| 方法与路径 | 权限 | Request / Query | 成功响应 |
|---|---|---|---|
| POST `/teams` | COACH | `{name: string, description: string\|null, avatarUrl: string\|null}` | 201 TeamDetailDto |
| GET `/teams/mine` | 登录 | `scope=ALL\|JOINED\|MANAGED` 默认 ALL；分页 | 200 Page<TeamSummaryDto> |
| GET `/teams/search` | 登录 | `q` 必填 1..96；分页 | 200 Page<TeamSummaryDto> |
| GET `/teams/{teamId}` | 登录 | 无 | 200 TeamDetailDto |
| PATCH `/teams/{teamId}` | OWNER | `{name?: string, description?: string\|null, avatarUrl?: string\|null}` | 200 TeamDetailDto |
| POST `/teams/{teamId}/archive` | OWNER | 无 | 200 TeamDetailDto |
| POST `/teams/{teamId}/activate` | OWNER | 无 | 200 TeamDetailDto |
| POST `/teams/{teamId}/dissolve` | OWNER，P2 | `{confirmation: string}` | 200 TeamDetailDto |
| POST `/teams/{teamId}/transfer` | OWNER，P2 | `{newOwnerPublicId: UUID}` | 200 TeamDetailDto |


### 团队成员

| 方法与路径 | 权限 | Request / Query | 成功响应 |
|---|---|---|---|
| GET `/teams/{teamId}/members` | OWNER；P2 可开放普通成员 | status=ACTIVE 默认；分页 | 200 Page<TeamMemberDto> |
| DELETE `/teams/{teamId}/members/{memberPublicId}` | OWNER | `{reason?: string}` | 204 |
| POST `/teams/{teamId}/leave` | ACTIVE MEMBER（非 OWNER） | 无 | 204 |


### 加入申请

| 方法与路径 | Request | 成功响应 |
|---|---|---|
| POST `/teams/{teamId}/applications` | `{message?: string}` | 201 JoinApplicationDto |
| GET `/me/team-applications` | page/pageSize，status? | 200 Page<JoinApplicationDto> |
| POST `/team-applications/{applicationId}/cancel` | 无 | 200 JoinApplicationDto |


| 方法与路径 | 权限 | Request | 成功响应 |
|---|---|---|---|
| GET `/teams/{teamId}/applications` | OWNER | status=PENDING 默认；分页 | 200 Page<JoinApplicationDto> |
| POST `/team-applications/{applicationId}/approve` | 对应团队 OWNER | 无 | 200 JoinApplicationDto |
| POST `/team-applications/{applicationId}/reject` | 对应团队 OWNER | `{reason?: string}` | 200 JoinApplicationDto |


### 团队邀请

| 方法与路径 | Request | 成功响应 |
|---|---|---|
| POST `/teams/{teamId}/invitations` | `{email: string}` | 201 TeamInvitationDto |
| GET `/teams/{teamId}/invitations` | status?，分页 | 200 Page<TeamInvitationDto>；OWNER 视图包含 inviteeEmail |
| POST `/team-invitations/{invitationId}/cancel` | 无 | 200 TeamInvitationDto |
| POST `/team-invitations/{invitationId}/resend` | 无 | 200 TeamInvitationDto |


| 方法与路径 | Request | 成功响应 |
|---|---|---|
| GET `/me/team-invitations` | status=PENDING 默认；分页 | 200 Page<TeamInvitationDto>；`inviteeEmail=null` |
| POST `/team-invitations/{invitationId}/accept` | 无 | 200 TeamInvitationDto |
| POST `/team-invitations/{invitationId}/reject` | 无 | 200 TeamInvitationDto |


### 隐私及成员共享

| 方法与路径 | Request | 成功响应 |
|---|---|---|
| GET `/me/privacy` | 无 | 200 PrivacySettingsDto |
| PATCH `/me/privacy` | `{basicTraining?: PrivacyScope, abilityProfile?: PrivacyScope, detailedSubmissions?: PrivacyScope, analysisReport?: PrivacyScope}` | 200 PrivacySettingsDto |


| 方法与路径 | 权限项 | Query | 成功响应 |
|---|---|---|---|
| GET `/teams/{teamId}/members/{memberPublicId}/training/overview` | basicTraining | window=30D | 200 SharedTrainingOverviewDto 或 null |
| GET `/teams/{teamId}/members/{memberPublicId}/profile` | abilityProfile | window=ALL | 200 SharedAbilityProfileDto 或 null |
| GET `/teams/{teamId}/members/{memberPublicId}/submissions` | detailedSubmissions | V0.11 submission 过滤 + 分页 | 200 Page<UserSubmissionDto> |
| GET `/teams/{teamId}/members/{memberPublicId}/reports` | analysisReport | 分页 | 200 Page<PersonalReportDto> |
| GET `/teams/{teamId}/members/{memberPublicId}/reports/{reportId}` | analysisReport | 无 | 200 PersonalReportDto |


| scope | 自己 | 共享团队 OWNER/COACH | 共享团队普通成员 | 非共享成员 |
|---|---:|---:|---:|---:|
| PRIVATE | ✅ | ❌ | ❌ | ❌ |
| TEAM_COACH | ✅ | ✅ | ❌ | ❌ |
| TEAM_MEMBER | ✅ | ✅ | ✅ | ❌ |
| PUBLIC | ✅ | ✅ | ✅ | V0.12 可用于未来公开页 |


### CF用户级画像

| 方法与路径 | Query | 成功响应 |
|---|---|---|
| GET `/me/training/overview` | `window=30D` | 200 UserAnalysisDto 或 null |
| GET `/me/analysis/latest` | `window=ALL` | 200 UserAnalysisDto 或 null |
| GET `/me/analysis/history` | `window=ALL` + 分页 | 200 Page<UserAnalysisDto> |
| GET `/me/analysis/{snapshotId}` | 无 | 200 UserAnalysisDto |
| POST `/me/analysis/rebuild` | 无 | 202 AiJobDto |


### CF个人报告

| 方法与路径 | Query/Request | 成功响应 |
|---|---|---|
| GET `/me/reports/latest` | 无 | 200 PersonalReportDto 或 null |
| GET `/me/reports` | 分页 | 200 Page<PersonalReportDto> |
| GET `/me/reports/{reportId}` | 无 | 200 PersonalReportDto |
| POST `/me/reports/generate` | 无 | 202 AiJobDto；P2 手动生成 |


### 旧AI Job

| 方法与路径 | 成功响应 |
|---|---|
| GET `/ai-jobs/{jobId}` | 200 AiJobDto |


### 团队分析

| 方法与路径 | Query | 成功响应 |
|---|---|---|
| GET `/teams/{teamId}/analysis/latest` | 无 | 200 TeamAnalysisDto 或 null |
| GET `/teams/{teamId}/analysis/history` | 分页 | 200 Page<TeamAnalysisDto> |


| 方法与路径 | 成功响应 |
|---|---|
| POST `/teams/{teamId}/analysis/rebuild` | 202 AiJobDto |


### 团队推荐

| 方法与路径 | 权限 | Request / Query | 成功响应 |
|---|---|---|---|
| POST `/teams/{teamId}/recommendations/generate` | OWNER | `{mode?: "WEAKNESS"\|"HYBRID", limit?: number}` 默认 HYBRID/10 | 202 AiJobDto |
| GET `/teams/{teamId}/recommendations/latest` | ACTIVE member | mode=HYBRID | 200 TeamRecommendationBatchDto 或 null |
| GET `/teams/{teamId}/recommendations/history` | ACTIVE member | mode? + 分页 | 200 Page<TeamRecommendationBatchDto> |
| GET `/teams/{teamId}/recommendations/{batchId}` | ACTIVE member | 无 | 200 TeamRecommendationBatchDto |


| reasonCode | reason |
|---|---|
| `TEAM_WEAKNESS_MATCH` | 这道题覆盖团队当前相对薄弱的能力。 |
| `TEAM_LEVEL_MATCH` | 这道题的难度与团队当前训练水平接近。 |
| `TEAM_COVERAGE_GAP` | 在允许统计的成员中，这道题的训练覆盖较低。 |
| `TEAM_BALANCED_PRACTICE` | 这道题适合作为团队的综合训练题。 |


### 教练主页

| 方法与路径 | 权限 | 成功响应 |
|---|---|---|
| GET `/coach/dashboard` | COACH | 200 CoachDashboardDto |


### 通知

| 方法与路径 | Request / Query | 成功响应 |
|---|---|---|
| GET `/notifications` | `unreadOnly=false` + 分页 | 200 Page<NotificationDto> |
| GET `/notifications/unread-count` | 无 | 200 `{count: number}` |
| POST `/notifications/{notificationId}/read` | 无 | 200 NotificationDto |
| POST `/notifications/read-all` | 无 | 200 `{updated: number}` |


旧用户级source set包括全部未解绑ACTIVE/INVALID CF；每账号须已有完整同步且当前无该用户账号任务在途，否则USER_SOURCE_NOT_READY。提交按platform+externalSubmissionId去重、题按problemId去重；current/max Rating取各账号非null最大值，UI写“最高当前/历史Rating”，ratingAccounts展示独立账号值。旧/me/analysis可为零CF零画像，其sourceFingerprint涵盖CF源版本与CF题库版本，不包含平台数据。

团队创建需COACH，自动唯一ACTIVE OWNER；成员普通退出/移除不含OWNER；新入队产生新membershipId。ARCHIVED禁止加入且取消待处理申请/邀请，DISSOLVED不可恢复。transfer目标必须ACTIVE成员且有COACH；confirmation须等于团队名。申请PENDING→APPROVED/REJECTED/CANCELLED，邀请PENDING→ACCEPTED/REJECTED/EXPIRED/CANCELLED，终态重复操作409；邮箱未注册邀请由backend在验证邮箱后自动关联，不由frontend匹配。inviteeEmail仅owner管理列表返回，被邀请者视图null；SMTP发送失败通过emailDeliveryStatus展示，不等于取消邀请。

隐私默认四项PRIVATE；能力/基础训练/详细提交/报告分开授权，使用dataAccess控制入口。COACH身份不代表任意team OWNER；canManage为当前团队权限。共享training接口不含六维，profile接口不含提交统计；detailedSubmissions只CF元数据，不含平台源码。403 PRIVACY_DENIED提示未开放；资源不可见404。team analysis audience后端选择，能力、训练、level样本分别计数；includedMemberCount=0是无共享证据而非真实0水平，levelMemberCount=0时targetRating=null。coverage与included两个隐私集合独立，不强制coverage≤included。团队推荐不返回逐成员覆盖计数。

旧AI job收到202后3秒轮询，SUCCESS后刷新对应latest/history，FAILED保留旧结果。USER_ANALYSIS resultId指ALL快照，PERSONAL_REPORT指report，TEAM_ANALYSIS指team snapshot，TEAM_RECOMMENDATION指batch。历史报告用自己的冻结快照；旧P2手动报告冷却由backend配置，429 REPORT_RATE_LIMITED。通知不是业务状态源，点击用referenceType/referenceId/teamId后重读对象。

所有旧统计按Asia/Shanghai自然日：7D/30D/365D开始为cutoff所在日零点减N−1天，ALL start=null；[start,end)且end=cutoff。attempted/solved是题目去重，submission是次数；accepted+failed+pending=submission，rated+unrated=solved。未评级null；tag可多覆盖不能求和当题数；activity缺日期只显示补零。六维0..100、推荐0..1。CF solvedCount是公开通过人数，没有可靠分母，不展示全站通过率。

### 旧公共错误码

| HTTP | code                                                                                                              | 客户端行为                          |
| ---- | ----------------------------------------------------------------------------------------------------------------- | ----------------------------------- |
| 400  | INVALID_ARGUMENT、INVALID_ANALYSIS_WINDOW、INVALID_RECOMMENDATION_MODE、PLATFORM_NOT_SUPPORTED、PASSWORD_TOO_WEAK | 修正输入                            |
| 400  | CAPTCHA_INVALID、CAPTCHA_EXPIRED、EMAIL_CODE_INVALID、EMAIL_CODE_EXPIRED                                          | 刷新验证码或重新获取邮件代码        |
| 401  | INVALID_CREDENTIALS、SESSION_EXPIRED                                                                              | 登录失败提示或跳转登录              |
| 403  | ACCOUNT_LOCKED、ACCOUNT_DISABLED、FORBIDDEN、ORIGIN_REJECTED                                                      | 停止受限操作                        |
| 404  | OJ_ACCOUNT_NOT_FOUND、RESOURCE_NOT_FOUND、SYNC_JOB_NOT_FOUND、CF_ACCOUNT_NOT_FOUND                                | 刷新列表或核对 handle               |
| 409  | USERNAME_ALREADY_EXISTS、EMAIL_ALREADY_REGISTERED、OJ_ACCOUNT_ALREADY_BOUND、OJ_ACCOUNT_OWNERSHIP_CONFLICT        | 显示占用提示                        |
| 409  | OJ_ACCOUNT_UNBOUND、OJ_ACCOUNT_INVALID、PROFILE_NOT_READY、SYNC_REQUIRED、DATA_CHANGED                            | 刷新账号/同步状态，必要时同步或重建 |
| 409  | IDEMPOTENCY_CONFLICT、REQUEST_IN_PROGRESS                                                                         | 复用正确 key 或稍后重试             |
| 429  | EMAIL_CODE_RATE_LIMITED、SYNC_RATE_LIMITED、RATE_LIMITED                                                          | 按 Retry-After 秒数倒计时           |
| 502  | UPSTREAM_CODEFORCES_UNAVAILABLE、ALGORITHM_BAD_RESPONSE、ALGORITHM_VERSION_MISMATCH                               | 保留已有数据，允许重试              |
| 503  | ALGORITHM_UNAVAILABLE、EMAIL_DELIVERY_FAILED                                                                      | 保留已有数据，允许重试              |
| 504  | UPSTREAM_CODEFORCES_TIMEOUT、ALGORITHM_TIMEOUT                                                                    | 使用同一 key 重试生成               |
| 500  | INTERNAL_ERROR                                                                                                    | 展示 requestId，允许重试            |


| HTTP | code | 场景 |
|---|---|---|
| 403 | `ROLE_REQUIRED` | 缺少 COACH/ADMIN |
| 403 | `TEAM_FORBIDDEN` | 不是团队 owner/成员 |
| 403 | `PRIVACY_DENIED` | 隐私设置拒绝 |
| 404 | `TEAM_NOT_FOUND` | 团队不存在或不可见 |
| 404 | `TEAM_MEMBER_NOT_FOUND` | 成员关系不可见 |
| 404 | `APPLICATION_NOT_FOUND` | 申请不存在/不可见 |
| 404 | `INVITATION_NOT_FOUND` | 邀请不存在/不可见 |
| 404 | `REPORT_NOT_FOUND` | 报告不存在/不可见 |
| 404 | `AI_JOB_NOT_FOUND` | AI job 不存在/不可见 |
| 409 | `TEAM_ALREADY_MEMBER` | 已是 ACTIVE member |
| 409 | `TEAM_NOT_JOINABLE` | ARCHIVED/DISSOLVED |
| 409 | `APPLICATION_ALREADY_PENDING` | 已有 PENDING 申请 |
| 409 | `APPLICATION_ALREADY_PROCESSED` | 申请终态重复操作 |
| 409 | `INVITATION_ALREADY_PENDING` | 已有 PENDING 邀请 |
| 409 | `INVITATION_ALREADY_PROCESSED` | 邀请终态重复操作 |
| 409 | `INVITATION_EXPIRED` | 邀请已过期 |
| 409 | `TEAM_OWNER_CANNOT_LEAVE` | OWNER 试图退出/被移除 |
| 409 | `COACH_OWNS_TEAM` | 撤销仍持有团队的 COACH |
| 409 | `USER_SOURCE_NOT_READY` | 至少一个未解绑 CF 尚无完整成功同步，或当前有账号同步在途 |
| 409 | `USER_ANALYSIS_NOT_READY` | 用户聚合画像不存在/过期 |
| 409 | `USER_SOURCE_CONFLICT` | 跨账号同 submission 事件冲突 |
| 409 | `TEAM_ANALYSIS_NOT_READY` | 团队画像不存在/过期 |
| 409 | `TEAM_LEVEL_NOT_READY` | 团队画像存在但没有 basicTraining 样本，无法确定推荐难度 |
| 429 | `TEAM_INVITE_RATE_LIMITED` | 重发邀请过快 |
| 429 | `REPORT_RATE_LIMITED` | 手动报告过快 |
| 503 | `LLM_UNAVAILABLE` | LLM 依赖不可用；由 Algorithm 映射 |


## 11. 前端独立构建与验收

frontend 自己的 Dockerfile/锁文件构建静态资源，监听0.0.0.0:80，SPA回退index.html；只配置 `/api/v1/** → http://backend:8081`，保留路径、Origin、Cookie，30秒代理请求预算，源码body上限与backend一致2MiB。异步任务一律短轮询，不延长浏览器请求等待完整判题/工具/LLM。前端产物不含 INTERNAL_API_TOKEN、LLM key、数据库URL或judge内部地址。

Mock 至少覆盖：纯平台新用户、两个CF和同一团队提交跨账号去重、旧CF/旧团队CF-only、平台ID与CF ID相同但source不同、题目撤下/旧版、未评级本地题、cpp17能力、全部判题终态、编译错误、异步分析PARTIAL/FAILED/SKIPPED与新analysisId、综合零/stale画像、内外混合和空推荐、同key超时重试、他人资源404、PRIVATE团队隐私、历史报告冻结。

验收闭环：登录 → 内外推荐 → 平台题库/编辑提交 → AC及WA/CE展示 → 提交记录 → 静态分析可复现字段展示 → 训练完成 → 综合画像两阶段更新 → 新推荐；外部导航 → CF同步 → 训练记录更新；停止algorithm时判题与旧业务仍可读，停止judge后已接受提交保留QUEUED/恢复执行；旧注册/同步/团队/隐私/报告/通知全部回归。
