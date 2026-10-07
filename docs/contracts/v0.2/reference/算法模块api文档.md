# V0.2 算法模块 API 文档

> 契约发布号 `0.2.0`；算法容器 `algorithm:8000`。本文连同《算法模块数据库文档》和《V0.2-整体架构与联调说明》是算法负责人的实施契约。本轮只设计，不实施业务代码。

## 1. 职责、兼容和调用边界

四个独立业务容器为 `frontend`、`backend`、`algorithm`、`judge-problem-service`。算法只接受 backend 冻结并授权的数据；不访问 Codeforces、judge 题库或 backend 业务表，不接收浏览器 Cookie/密码/邮箱/handle，不决定成员隐私。源码仅通过单独代码分析任务进入算法，画像、推荐和旧个人报告不携带源码。算法回调仅回传已存在任务至固定 backend 事件端点；没有反向拉取业务数据。

backend 是全部用户画像业务快照、实际交付推荐批次及报告历史的唯一 owner；algorithm 保存异步任务、原始静态分析结果、版本配置及可复现计算工件。backend 保存静态结果只读展示投影，不能改算法事实。旧文档的“无数据库算法”升级为“拥有私有任务/计算工件 schema”，原因是静态分析耗时且必须重启恢复；绝不迁移旧画像/推荐主表或新增跨服务直接写表。

旧 `/internal/v1/analyze`、`/recommend`、`/user-analyze`、`/personal-report`、`/team-analyze`、`/team-recommend` 继续保留完整旧输入、裸响应和版本。旧 CF 单账号/多账号、团队、报告保持 CF-only；新增平台训练使用新 `/internal/v2/profile-jobs`，公开为 `/api/v1/me/learning-profile/**`。旧 `/me/analysis/**` 不悄悄改变来源和权限。

## 2. HTTP 公共规则

JSON camelCase，持久字段 snake_case。`Id` 是正十进制字符串、`UUID` 是 UUID 字符串、Instant 为 RFC3339 UTC `Z`；不得将 ID 转 number。统计自然日固定 `Asia/Shanghai`，数值计数为非负安全整数，毫秒/字节分别 `timeMs`/`memoryBytes`。nullable 字段显式 `null`、数组始终 `[]`，未声明输入拒绝。未知版本显式失败。

新 v2 内部全部成功套 `ApiResponse<T>={data:T,requestId:UUID}`；错误 `ApiError={error:{code,message,details:object},requestId}`。异步任务自身失败仍可 GET 200，错误位于 `error:TaskError|null`；`TaskError={code,message,retryable:boolean}`。v1 继续裸 DTO 和旧 AlgorithmError。请求带 `Content-Type:application/json`、`X-Request-Id:UUID`，POST body.requestId（有该字段时）等于请求头。查询 GET/by-request 每次用新的追踪 requestId，不修改原任务 requestId。

v2 `Authorization:Bearer <BACKEND_ALGORITHM_TOKEN>`；algorithm 回 backend 使用独立 `ALGORITHM_BACKEND_TOKEN`，固定 `http://backend:8081/internal/v2/events/algorithm`，禁止客户端传 callbackUrl。v1 仍用 `INTERNAL_API_TOKEN`。密钥仅配置于对应服务，不能转发用户 Session。

源码是单文件 UTF-8，限制 262144 bytes，空白拒绝，分析任务 HTTP body ≤2 MiB；profile 冻结输入以及v2完整查询响应/回调body ≤32 MiB（代码创建输入2MiB限额不套给结果/回调），超过 413 `INPUT_TOO_LARGE`，不得截取最近提交冒充 ALL。旧 v1 的 64 MiB 限制不变。sourceSha256 为请求源码 UTF-8 字节的 SHA-256（不统一换行、不 trim 后计算），非法 surrogate/编码拒绝。

新任务 requestId 是 backend 的一次逻辑任务幂等键，唯一约束保证重发同请求 200 原任务，初次 202；同 requestId 不同规范输入哈希 409 `IDEMPOTENCY_CONFLICT`。旧任务终态不复活，人工 retry 由 backend 创建新 requestId。profile只按requestId冻结唯一，sourceFingerprint不含cutoff，不得永久去重fingerprint；同主体在途可由backend合并，终态相同fingerprint的新cutoff必须允许新任务。DATA_CHANGED后新requestId与完整新输入一起生成，不能复用旧requestId换body。v2 任务首次 revision=1，仅提交状态变化时递增；失败重领仍同任务，不造成同 revision 不同内容。

## 3. 新接口一览

下表调用方均 backend。表中响应为 envelope 中 `data`。

| 方法、路径 | 用途和请求 | 成功状态及数据 | 主要错误 |
|---|---|---|---|
| POST `/internal/v2/analysis-jobs` | 非阻塞代码静态分析，AnalysisJobRequest | 初次202、重放200 AnalysisJob | 400参数；409幂等；413源码/输入；422版本；503过载 |
| GET `/internal/v2/analysis-jobs/{analysisId}` | 查询完整任务/结果，无body | 200 AnalysisJob | 404 TASK_NOT_FOUND |
| POST `/internal/v2/analysis-jobs/by-request` | 恢复POST超时未收到analysisId；`{requestIds:UUID[]}`，1..100且去重 | 200 `{tasks:AnalysisJob[],missingRequestIds:UUID[]}` | 400参数 |
| POST `/internal/v2/profile-jobs` | 完整训练与静态特征冻结分析，ProfileJobRequest | 初次202、重放200 ProfileJob | 400参数；409幂等；413输入；422版本/冲突；503过载 |
| GET `/internal/v2/profile-jobs/{profileJobId}` | 查询画像计算任务，无body | 200 ProfileJob | 404 TASK_NOT_FOUND |
| POST `/internal/v2/profile-jobs/by-request` | `{requestIds:UUID[]}`，1..100且去重 | 200 `{tasks:ProfileJob[],missingRequestIds:UUID[]}` | 400参数 |
| POST `/internal/v2/recommendations` | 当前新ALL画像及全部合法候选，LearningRecommendRequest | 200 LearningRecommendResponse，不生成公开batchId | 400参数；422版本/输入；503忙；504超时 |
| GET `/internal/v2/capabilities` | 部署的真实工具/语言/版本能力 | 200 AlgorithmCapabilities | 503配置未就绪 |
| GET `/health` | 私有探针，无认证 | 200 旧健康DTO（下节完整定义），基础依赖未就绪503同结构status=unavailable | 503 |


健康检查保留原字段并追加新契约信息，直接响应、不套data：

```ts
interface AlgorithmHealth {
  status: "ok" | "unavailable"; service: "algorithm"; contractVersion: "v1";
  algorithmVersions: string[]; mappingVersions: string[];
  apiContractVersion: "0.2.0"; capabilities: {llmReport:boolean; staticAnalysis:boolean};
}
```

algorithmVersions保留所有旧版本并可追加新画像/推荐版本；mappingVersions含mapping-v0.11.1。capabilities.llmReport表示旧报告能力已配置且可用，staticAnalysis表示至少一种已安装语言可静态分析；详细工具能力由/internal/v2/capabilities返回。只可选LLM不可用时保留纯计算健康，capabilities/报告能力明确不可用，不假装整个旧认证业务需要LLM。

by-request tasks 按 requestIds 顺序返回存在的任务；missingRequestIds 保持输入顺序。缺失不是自动新建，backend 原样重发原POST。不可使用此端点查询其他用户业务，backend 仍对其公开查询授权。

## 4. 统一题目、判题和静态结果 DTO

```ts
type Id=string; type UUID=string; type Instant=string; type DateKey=string;
type ProblemSource="PLATFORM"|"EXTERNAL";
type Platform="startrack"|"codeforces";
interface ProblemRef {
  source: ProblemSource; platform: Platform; problemId: Id; problemVersionId: UUID | null;
}
interface ProblemSummary {
  problemRef: ProblemRef; title: string | null; difficulty: number | null;
  difficultyScale: DifficultyScale; tags: string[]; url: string | null;
}
interface TaskError {code:string;message:string;retryable:boolean}
interface TaskBase {
  requestId:UUID;revision:number;status:string;error:TaskError|null;
  createdAt:Instant;updatedAt:Instant;finishedAt:Instant|null;
}
type JudgeVerdict="AC"|"WA"|"TLE"|"MLE"|"RE"|"CE"|"OLE"|"IE";
interface JudgeResult {
  verdict:JudgeVerdict;timeMs:number|null;memoryBytes:number|null;
  passedTestCount:number;totalTestCount:number;score:number|null;
  compileLog:string|null;diagnosticCode:string|null;judgedAt:Instant;
}
type AnalysisStatus="NOT_REQUESTED"|"QUEUED"|"RUNNING"|"SUCCEEDED"|"PARTIAL"|"FAILED"|"SKIPPED";
type ProfileJobStatus="QUEUED"|"RUNNING"|"SUCCEEDED"|"FAILED";
interface AnalysisMetrics {
  sourceLines:number|null;functionCount:number|null;maxCyclomaticComplexity:number|null;
  meanCyclomaticComplexity:number|null;duplicateLines:number|null;maintainabilityIndex:number|null;
}
interface AnalysisFinding {
  findingId:string;tool:string;ruleId:string;severity:"INFO"|"WARNING"|"ERROR";
  category:"COMPLEXITY"|"BUG_RISK"|"STYLE"|"PERFORMANCE"|"DUPLICATION";
  message:string;file:string;startLine:number;endLine:number;column:number|null;
}
interface ToolRun {
  tool:string;version:string;configSha256:string;status:"SUCCEEDED"|"FAILED"|"SKIPPED";
  durationMs:number;error:TaskError|null;
}
interface StaticAnalysisResult {
  schemaVersion:"0.2.0";analysisId:UUID;submissionId:Id;sourceSha256:string;
  languageId:string;toolchainVersion:string;resultHash:string;
  metrics:AnalysisMetrics;findings:AnalysisFinding[];tools:ToolRun[];
  reproducibility:{imageDigest:string;configSha256:string;sourceSha256:string};
  synthesis:{status:"NOT_REQUESTED"|"QUEUED"|"RUNNING"|"SUCCEEDED"|"FAILED"|"SKIPPED";
    provider:string|null;model:string|null;promptVersion:string|null;content:string|null;error:TaskError|null};
}
interface AnalysisJobRequest {
  requestId:UUID;submissionId:Id;problemRef:ProblemRef;languageId:string;
  sourceCode:string;sourceSha256:string;judgeResult:JudgeResult;toolchainVersion:"static-v0.2.1";
}
interface AnalysisJob extends TaskBase {
  analysisId:UUID;submissionId:Id;status:AnalysisStatus;result:StaticAnalysisResult|null;
}
interface CallbackEvent<T> {
  eventId:UUID;eventType:"JUDGE_TASK_UPDATED"|"ANALYSIS_JOB_UPDATED"|"PROFILE_JOB_UPDATED";
  occurredAt:Instant;requestId:UUID;aggregateId:UUID;revision:number;payload:T;
}
```

PLATFORM 只能 `startrack` 且非空版本；EXTERNAL 只能 `codeforces` 且 version=null。problemId 两个 owner 可同值，所有 join、去重、已AC排除必须使用 `(source,platform,problemId)`，不能裸 ID。平台静态分析输入只接受 PLATFORM；EXTERNAL 提交无公开源码，不能创建虚假分析任务。

JudgeVerdict→旧训练Verdict：AC→ACCEPTED、WA→WRONG_ANSWER、TLE→TIME_LIMIT、MLE→MEMORY_LIMIT、RE→RUNTIME_ERROR、CE→COMPILE_ERROR、OLE→OTHER（明确输出限制失败）；IE 和取消不进入能力失败，待判映射 PENDING。IE 不发静态分析，backend 投影SKIPPED；CE 可进行语法局部分析，不要求编译成功才能得到 Lizard 结果。算法不重新判题，也不依据静态规则把 WA 改 AC。

## 5. 静态分析适配层和结果语义

第一阶段默认 C++ `cpp17`，C `c11` 按部署 capabilities 可选。候选语言能力来自 judge-languages，是否能分析由算法 capabilities 独立决定，不要求 judge 支持的语言都已安装分析器。公开judge-languages.analysisSupported由backend取judge声明与algorithm.analysisLanguages真实能力交集；algorithm不可达则false。judge不调用algorithm，算法不可达不阻止可判语言执行。初版工作流固定：Lizard→clang-tidy/Infer→CPD→归一化输出；可并行运行彼此独立工具，最终一次提交完整结果。

| 工具标识 | 语言/用途 | 原始输出与边界 |
|---|---|---|
| LIZARD | C/C++、Java、Python适配；函数NLOC/CCN/参数数等 | Python API/CSV/XML适配；不展开宏，部分解析可能漏项；CCN不是Big-O |
| CLANG_TIDY | C/C++ Bug风险/性能/风格 | 固定编译模板/sysroot/头文件；`--export-fixes` YAML适配；不启用`--fix`或写回源码 |
| INFER | C/C++静态Bug分析；Java后续适配 | capture→analyze、`report.json`；仅固定编译器模板，不执行用户构建脚本/程序 |
| CPD | C/C++提交内重复片段；其他语言后续适配 | PMD发行件CPD子命令XML；C++使用CPD而非PMD规则；不做跨用户抄袭结论 |
| RADON | Python圈复杂度/行数/可维护性 | CLI JSON；C++任务SKIPPED，不是失败 |
| PMD | Java规则/代码质量 | JSON/XML适配；没有C++ PMD规则能力，不把CPD能力冒充PMD规则 |

工具对应原始发行版本、ruleset、适配器、编译模板、镜像digest固定于 `static-v0.2.1` manifest；内容变化发布新的toolchainVersion并回归，禁止同版本偷偷换二进制。见数据库文档发行基线与许可清单。capabilities.tools始终六项，enabled反映本部署配置；顶层analysisLanguages列实际可请求语言，不把Java/Python预留写成上线能力。

编译/解析用户文本本身也必须隔离：算法容器内受限工作进程、只读工具链、无网络/秘密/服务数据库凭据、仅临时源码目录可写、进程/CPU/内存/输出限额。HTTP/任务worker与工具进程分离凭据；不调用judge、go-judge或用户Makefile，不运行生成二进制。工具编译步骤允许产生中间表示，执行用户程序不允许。

默认每任务 wall-clock 120秒、总内存512MiB、子进程数32、每任务全部原始报告合计8MiB、每工具最长45秒；这些是计算边界而非用户判题限制，版本manifest固定，部署降低限额要发布相应配置版本。超时杀整个工具进程组并清理临时目录，不能无限积压。

`metrics` 来源固定：sourceLines使用Lizard NLOC（不含空白/纯注释）、functionCount为解析函数数、max CCN为函数最大值、mean CCN为各函数CCN算术均值round2；duplicateLines使用CPD对报告重复行区间求并集；maintainabilityIndex仅Radon（否则null）。无函数时functionCount=0、CCN均null，未知指标null而非0。重复片段内含多次区间不双计相同行。原始函数参数数/长度等完整报告存原始工件，API基础指标保持统一小集合。

findings ruleId保留工具原码；severity适配表锁定版本（clang诊断/Infer严重风险/PMD优先级分别映射，不把所有静态发现都写成已验证Bug）。文件仅受控相对路径 `main.cpp`/`main.c`，禁止宿主路径；行列1起，endLine>=startLine，<=源码总行数，行号校验按原文物理行数，不能用NLOC/sourceLines作行号上界；无法定位则标INFO工具摘要、file为受控源码文件、起止行1并明确消息“不定位具体行”。findingId为规范化工具/规则/位置/消息SHA-256，同语义重复诊断去重后按tool/file/startLine/ruleId排序。无发现返回[]。

工具正常报告包含问题也视为SUCCEEDED，ToolRun.error=null；跳过disabled/语言不支持为SKIPPED，error使用TOOL_DISABLED/TOOL_LANGUAGE_UNSUPPORTED且retryable=false。解析/编译无法分析/超时为FAILED（保留可校验部分报告），error分别TOOL_PARSE_FAILED/TOOL_COMPILE_CONTEXT_INVALID/TOOL_TIMEOUT。CPD退出4是正常重复结果；退出5有有效部分报告则该工具FAILED+可保留发现、总任务PARTIAL，不能将“检测到重复”当服务异常。

归一化StaticAnalysisResult连同v2任务envelope/回调完整payload最大32MiB；工具原始输出8MiB不等于HTTP仅2MiB。超过时任务FAILED `ANALYSIS_RESULT_TOO_LARGE`、result=null，明确超限而不截断后声称完整；原始报告仍私有，backend/前端不下载其内容。

AnalysisJob：QUEUED→RUNNING→SUCCEEDED/PARTIAL/FAILED/SKIPPED。SUCCEEDED=全部已启用且适用工具产生完整有效输出；PARTIAL=至少一份可用证据且适用工具有失败/不完整；FAILED=没有可用证据；SKIPPED=语言不支持或配置暂不可用。不适用工具SKIPPED不使本来完整C++任务PARTIAL。终态result：SUCCEEDED/PARTIAL必须完整StaticAnalysisResult，FAILED/SKIPPED为null；PARTIAL.error=ANALYSIS_PARTIAL，包含可读降级说明、可重试布尔值；没有源码/工具输出时不伪造空“成功分析”。

本轮 `synthesis={status:"NOT_REQUESTED",provider:null,model:null,promptVersion:null,content:null,error:null}` 恒定。未来Agent/LLM通过独立版本、触发API和证据引用补充，不能覆盖静态原始事实；旧 personal-report 已有LLM仅分析聚合统计，继续使用旧接口。Infer Cost 有限支持和未知成本不纳入本轮统一Big-O指标；原报告可保留，但不推断任意递归/未知库竞赛代码复杂度。

## 6. 综合画像、内外题推荐共享契约


此文件由算法负责人一次确定，后端/前端文档逐字使用。所有未标 ? 的字段必有；只有 `|null` 可空；所有内部 v2 成功套 ApiResponse，旧 v1 裸 DTO 不改。公共 ProblemRef/ProblemSummary/TaskBase/StaticAnalysisResult/AnalysisJob 等严格使用架构负责人契约。

```ts
type DifficultyScale = "CF_RATING" | "PLATFORM_RATING" | "UNRATED";
type RecommendationSource = "ALL" | "PLATFORM" | "EXTERNAL";
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
interface ProfileSourceAccount {
  accountId: Id; platform: "codeforces"; dataVersion: Id;
  currentRating: number | null; maxRating: number | null;
}
interface LearningSubmission {
  eventKey: string; submissionId: Id; accountId: Id | null;
  problemRef: ProblemRef; verdict: Verdict; submittedAt: Instant;
}
interface CodeAnalysisFeature {
  analysisId: UUID; submissionId: Id; revision: number; resultHash: string;
  status: "SUCCEEDED" | "PARTIAL"; metrics: AnalysisMetrics;
  findingCounts: { info: number; warning: number; error: number };
}
interface ProfileJobRequest {
  requestId: UUID; algorithmVersion: "learning-profile-v0.2.1";
  mappingVersion: "mapping-v0.11.1"; sourceFingerprint: string;
  dataCutoffAt: Instant; timezone: "Asia/Shanghai";
  windows: ["7D", "30D", "365D", "ALL"];
  accounts: ProfileSourceAccount[]; submissions: LearningSubmission[];
  problems: ProblemSummary[]; codeAnalysisFeatures: CodeAnalysisFeature[];
  dimensions: DimensionConfig[];
}
interface ProfileResult {
  requestId: UUID; algorithmVersion: "learning-profile-v0.2.1";
  mappingVersion: "mapping-v0.11.1"; sourceFingerprint: string;
  dataCutoffAt: Instant; timezone: "Asia/Shanghai";
  analyses: LearningAnalysisResult[];
}
interface ProfileJob extends TaskBase {
  profileJobId: UUID; status: ProfileJobStatus; result: ProfileResult | null;
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
interface LearningRecommendProfile {
  window: "ALL"; algorithmVersion: "learning-profile-v0.2.1";
  mappingVersion: "mapping-v0.11.1"; dataCutoffAt: Instant;
  overallScore: number; currentRating: number | null;
  averageSolvedDifficulty: number | null; maxSolvedDifficulty: number | null;
  weakestDimension: DimensionCode; dimensions: DimensionScore[];
  tagStats: TagStat[]; difficultyStats: LearningDifficultyStat[]; codeQuality: CodeQuality;
}
interface LearningRecommendRequest {
  requestId: UUID; algorithmVersion: "learning-recommend-v0.2.1";
  mappingVersion: "mapping-v0.11.1"; analysisSnapshotId: UUID;
  sourceFingerprint: string; source: RecommendationSource;
  mode: RecommendationMode; limit: number; profile: LearningRecommendProfile;
  candidateProblems: ProblemSummary[]; solvedProblemRefs: ProblemRef[];
  recentRecommendationRefs: ProblemRef[]; dimensions: DimensionConfig[];
}
interface LearningRecommendResponse {
  requestId: UUID; algorithmVersion: "learning-recommend-v0.2.1";
  mappingVersion: "mapping-v0.11.1"; analysisSnapshotId: UUID;
  sourceFingerprint: string; source: RecommendationSource;
  mode: RecommendationMode; candidateCount: number;
  recommendations: Array<{
    problemRef: ProblemRef; rank: number; score: number;
    reasonCode: ReasonCode; matchedDimension: DimensionCode | null;
  }>;
}
interface StaticToolCapability {
  tool: "LIZARD" | "CLANG_TIDY" | "INFER" | "RADON" | "PMD" | "CPD";
  version: string; enabled: boolean; languageIds: string[];
  features: Array<"SOURCE_METRICS" | "CYCLOMATIC_COMPLEXITY" | "BUG_RISK" | "STYLE" | "PERFORMANCE" | "DUPLICATION" | "MAINTAINABILITY">;
}
interface AlgorithmCapabilities {
  contractVersion: "0.2.0"; toolchainVersion: "static-v0.2.1";
  analysisLanguages: string[]; tools: StaticToolCapability[];
  profileVersions: string[]; recommendationVersions: string[];
}
```

## 输入和输出不变量

- Id 正十进制字符串，sourceFingerprint/resultHash/configSha256/sourceSha256 是64位小写hex；version不接受静默回退。
- `eventKey`：PLATFORM=`startrack:<submissionId>`、EXTERNAL=`codeforces:<externalSubmissionId>`，CF原提交ID由backend填入eventKey，本DTO不再重复发原字段。平台accountId=null；外部accountId必须在accounts中。跨CF重复eventKey仅在 problem身份、verdict、submittedAt一致时折叠，代表submissionId取数值最小值；冲突422 INVALID_INPUT。每window source计数使用折叠事件，不能把两个CF团队账号双计。
- 判题非终态QUEUED/DISPATCHING/RUNNING可作PENDING输入；COMPLETED映射旧Verdict。平台任意FAILED（包括未创建任务的本地拒绝）及CANCELLED不作为能力提交输入、不作为失败训练；源码仍可在提交历史读。训练记录planned不属于submission。
- Problem身份为(source,platform,problemId)；版本只影响冻结元数据。problems覆盖每个输入完整ProblemRef，PLATFORM多个历史版本可并存；同一窗口同题多个版本统计用该窗口最后提交 `(submittedAt,submissionId数值)` 的元数据，不合并成两题。AC去重不含version。externalRef version恒null。
- codeAnalysisFeatures每平台submission最多一份最近可用SUCCEEDED/PARTIAL可复现分析事实（backend usable_analysis_id/revision），只接受SUCCEEDED/PARTIAL，submission须在输入并属PLATFORM，计数非负。不传源码/完整finding消息进profile。warning/error不是已验证Bug事实。
- analyses恰好4项同请求顺序。sources计数每window去重后计算，platform+external=summary.submissionCount；sourceAccountIds为accounts全部ID按数字排序（四窗口一致）；codeAnalysisCount=codeQuality.analyzedSubmissionCount，为该window提交中有可用静态分析的去重次数。
- codeQuality计可用feature findingCounts.warning/error之和，maxCyclomaticComplexity取可用数值最大，无证据null。分析未就绪时codeQuality=零计数/null，不阻塞四窗口画像；之后backend featuresVersion变化重建。
- 新summary及dimensions中rating平均/最高只取difficultyScale=CF_RATING；其他尺度题按unratedSolvedCount计，不能把PLATFORM_RATING放入CF均分。difficultyStats按(scale,difficulty)独立分桶；UNRATED必须difficulty=null，其余必须正整数。currentRating/maxRating取accounts非null最大值，与旧多CF语义相同。
- LIZARD/CLANG_TIDY/INFER/CPD 为C/C++适配能力；RADON仅Python，PMD规则仅Java，CPD与PMD是分开能力。初版analysisLanguages必须含cpp17，c11可选；java/python未部署不可列入可用analysisLanguages。tools始终六项，enabled=false的version仍填发布清单锁定版本，不代表安装可运行，languageIds表示适配器支持范围，顶层analysisLanguages表示本部署真实可请求。disabled工具ToolRun=SKIPPED并给TOOL_DISABLED。

## 新六维确定公式（learning-profile-v0.2.1）

沿用旧映射：题对维度w为匹配tags的最大权重，同维度多个标签不累加。同window去重AC题：
`S=Σw`；CF_RATING `quality=clamp((difficulty-600)/2400,0,1)`；PLATFORM_RATING及UNRATED `quality=0`（本版仅贡献完成量，不伪造跨尺度难度）。`Q=S=0?0:Σ(w*quality)/S`；`coverage=min(S/20,1)`；`score=round2(100*(0.6*Q+0.4*coverage))`；overallScore=round2六分均值。纯CF输入和旧公式相同。codeQuality独立，不影响六维。rankOrder分数升序、displayOrder平局；空数据六维0且weakest=IMPLEMENTATION。

## 新推荐确定公式（learning-recommend-v0.2.1）

backend基础过滤全部合法目录，algorithm按source再次过滤，去除已AC Problem身份、*special/*broken，不自动造新题。难度目标按尺度独立：CF目标取profile.averageSolvedDifficulty??currentRating??800，roundHalfUp最近100再clamp[800,3500]；平台目标取ALL difficultyStats中PLATFORM_RATING已AC题按solvedCount加权平均（没有样本则null），roundHalfUp最近100且最低100，不凭CF目标推平台目标。

有同尺度目标的rated候选仅保留±200（闭区间），`D=1-abs(difficulty-target)/400`。LEVEL只接收有可比目标的rated候选；WEAKNESS/HYBRID在平台目标为null或UNRATED时可以保留，D固定0.5，并由固定reason文案注明未评级/平台评级不足。WEAKNESS仍仅保留最弱维度w>0。

`W=max_d(w_d*(1-profile.dimensions[d].score/100))`；`T=候选tags中未在profile.tagStats出现solvedCount>0的比例，空tags=0`；`R=同Problem身份最近7日推荐过?0.15:0`。LEVEL score=D；WEAKNESS score=0.6D+0.4w_weakest；HYBRID score=clamp(0.5D+0.35W+0.15T-R,0,1)。所有score先round6；跨source只比较归一化score，不比较原始rating。排序score DESC、同尺度目标绝对差ASC（无目标用固定200）、source PLATFORM在前、platform字典序、problemId数值ASC；rank连续1..N、N=min(limit,candidateCount)。无候选200空数组。

matchedDimension及reasonCode沿旧语义；无同尺度目标优先reasonCode=DEFAULT_RECOMMENDATION，backend按problem.difficultyScale输出固定补充说明，不宣称难度匹配。HYBRID codeQuality仅提供后续报告证据，本版不从静态warning自动推断知识点弱项或改变排名。数组顺序不影响结果，舍入使用十进制ROUND_HALF_UP。

## 7. 画像窗口、统计和训练闭环

每次request冻结cutoff；7D/30D/365D开始点为cutoff所在上海自然日零点向前N-1日，ALL.start=null，全部结束点为cutoff且不包含端点。活动统计按上海自然日；窗口题数是窗口内事件涉及/AC的去重题，不因同题曾在窗口外AC而忽略窗口再次训练。每日solvedCount是本窗口首次AC所在日，不是全历史首次AC；活动日期升序，只有活动日，缺日期前端补零。

Summary约束：solved≤attempted≤submission；unsolved=attempted−solved；accepted+failed+pending=submission；rated+unrated=solved。PENDING不能当失败；旧CF OTHER视为未知终态失败口径，平台IE已在输入排除。多标签一题可进入多项tagStat、各标签总数不要求等于题数；difficultyStats按尺度/值分桶，其solved之和必须等于总solved。无CF_RATING已AC样本时average/max=null，不填0。计数为整数，画像分数及均值round2、推荐分数round6，十进制ROUND_HALF_UP，禁止NaN/Infinity。

mapping-v0.11.1配置不变：

| order/code/name | tags（weight均1） |
|---|---|
| 1 IMPLEMENTATION / 编程实现 | implementation, strings, sortings |
| 2 ALGORITHMS / 算法策略 | greedy, binary search, brute force, two pointers, divide and conquer, constructive algorithms, meet-in-the-middle, ternary search, randomized |
| 3 DATA_STRUCTURES / 数据结构 | data structures, dsu, hashing, trees, string suffix structures |
| 4 DYNAMIC_PROGRAMMING / 动态规划 | dp, bitmasks |
| 5 GRAPHS / 图论 | graphs, dfs and similar, shortest paths, flows, matching, 2-sat, graph matchings |
| 6 MATH / 数学 | math, number theory, combinatorics, geometry, probabilities, games, matrices, fft, chinese remainder theorem, expression parsing |

tag仍自由文本；未映射tag保留统计不贡献六维。platform标签由题库owner管理，算法不擅自给题补标签；需要改映射时新mappingVersion。维度恰好六项，按displayOrder输出；rankOrder按score升序、displayOrder破平局，1最弱。

backend判题落有效投影后先更新platformTrainingVersion并发基础画像；分析无需等到全部工具完成才允许判题结果公开。analysis成功/PARTIAL投影到达后仅有实际特征变化才增加analysisFeaturesVersion，重新生成画像codeQuality。重复callback不会重复计算训练次数。人工retry中的QUEUED/FAILED/SKIPPED不删除旧可用特征、不推进featuresVersion；新SUCCEEDED/PARTIAL原子替换最近可用分析事实时才推进。feature.analysisId允许与submission当前分析尝试id不同，后台先核对任务身份，旧任务迟到不能覆盖新可用事实。CF同步完成→规范事件→新画像，没有源码不走代码分析。新画像成功后四窗口同一backend事务写入，旧快照不覆盖；后端重算fingerprint变化即丢弃并重新排队，算法不称其计算工件为当前用户最新画像。

学习fingerprint由backend唯一计算：SHA-256(JCS/RFC8785 JSON `{contractVersion,algorithmVersion,mappingVersion,accounts,externalCatalogVersion,platformCatalogVersion,platformTrainingVersion,analysisFeaturesVersion}`)，accounts按数值ID排序并含accountId/dataVersion/bindStatus。外部catalog计数Id是旧实际目录变更jobUUID的单调映射，不把UUID强转数字；未同步目录"0"、训练/分析版本初始"1"。algorithm只校验64hex并回显，不从自己任务库推导用户版本。cutoff导致日窗口变化另由24小时stale检测处理。

LearningRecommendRequest.profile必须ALL且新版本匹配；analysisSnapshotId由backend持有，algorithm不访问snapshot表。backend冻结当前合法平台目录快照（包括撤题目录版本）及完整CF候选，过滤非法URL/INFERRED/Gym/特殊题，避免只从用户已做题取候选；学习source ALL/PLATFORM/EXTERNAL是本次候选来源，旧account推荐仍CF-only。solvedProblemRefs包含平台全历史有效AC及当前未解绑CF账号的全历史有效AC（跨账号去重），与综合画像的授权源集一致，不纳入已解绑账号仅留作历史的训练记录；按身份去重，版本不参与已解决过滤；recentRecommendationRefs为最近7×24小时同用户所有新学习推荐模式/来源的去重身份。推荐不额外排除重复至空，HYBRID仅软降权；引用旧account推荐可由backend转换外部ProblemRef后加入新recent集合。

## 8. 可靠任务与回传接口

algorithm任务worker及分析器进程均在algorithm业务容器内，不要求新增业务worker容器。队列以持久数据库任务为准，Redis可作通知但不能是事实源。短事务领取后释放连接再计算，lease每15秒续120秒，lease_owner/fencing令牌防止旧worker回写；有效租约才能提交终态结果。重启扫描QUEUED及过期RUNNING，最多3次尝试，重试继续原requestId，预算耗尽为FAILED `TASK_INTERRUPTED`。静态指标内容确定性；实际durationMs和任务timestamp是运行事实，不要求跨重跑相等。

每次任务revision提交与CallbackEvent outbox同事务；payload是完整AnalysisJob或ProfileJob快照，eventType分别ANALYSIS_JOB_UPDATED/PROFILE_JOB_UPDATED，aggregateId为analysisId/profileJobId，requestId为原任务requestId，revision=payload.revision。algorithm不会发JUDGE事件。

`POST http://backend:8081/internal/v2/events/algorithm`：调用方algorithm，认证独立Bearer，X-Request-Id等于event.requestId；body为CallbackEvent，成功200 ApiResponse<{accepted:true,duplicate:boolean}>。401 SERVICE_UNAUTHORIZED；404 TASK_NOT_FOUND；409 EVENT_CONFLICT；413 INPUT_TOO_LARGE。backend以已派发逻辑任务/当前analysisId身份校验，未得到下游ID但POST超时的任务可经requestId匹配再绑定；不能接受任意submissionId结果。

eventId去重、旧revision或同内容重放200且不回退状态；同revision不同payloadHash返回409供告警。人工分析retry创建新analysisId，比较当前task身份后才比较revision，不能把旧task revision=99当作新task revision=1的更新。回传失败按1,2,4,8,16,30秒退避24小时后dead-letter；dead-letter保留重发能力，不丢原始任务/结果。backend每30秒轮询非终态，并对终态无ack/delivered对账。401/409告警且不忙重试；暂时404可能是派发映射提交竞态，按限次退避并用by-request恢复，持续未知任务入死信人工核查。

backend入口POST/GET网络预算连接2秒、单次5秒；网络/502/503/504最多重试一次复用原requestId/body，任务计算不会绑HTTP长连接。推荐预算算法8秒、backend10秒，连接2秒、公开请求25秒。四窗口计算预算55秒，静态分析120秒。v2计算异步，不受frontend30秒代理超时影响；回调客户端总超时5秒。数据校验/版本/幂等冲突不自动重试。backend明确收到400/409/413/422拒绝且未创建下游任务时，协调任务直接FAILED、GET仍200；网络/503/504结果未知先按requestId/by-request恢复后原样重派，不制造永久QUEUED。

## 9. 旧 v1 自包含兼容契约

下面定义旧纯计算/报告接口所需全部结构。旧Id、时间、统计口径与上文一致；旧problemId仅指backend CF问题表，旧DifficultyStat没有difficultyScale，禁止把新PLATFORM直接传旧端点。旧接口成功仍裸DTO，未知字段按旧schema规则返回400 INVALID_REQUEST，业务一致性422 INVALID_INPUT；旧Analyze/Recommend保持64MiB输入。

```ts
type AnalysisWindow="7D"|"30D"|"365D"|"ALL";
type RecommendationMode="LEVEL"|"WEAKNESS"|"HYBRID";
type Verdict="ACCEPTED"|"PARTIAL"|"WRONG_ANSWER"|"TIME_LIMIT"|"MEMORY_LIMIT"
 |"RUNTIME_ERROR"|"COMPILE_ERROR"|"SKIPPED"|"CHALLENGED"|"IDLENESS_LIMIT"
 |"PRESENTATION_ERROR"|"PENDING"|"OTHER";
type DimensionCode="IMPLEMENTATION"|"ALGORITHMS"|"DATA_STRUCTURES"|"DYNAMIC_PROGRAMMING"|"GRAPHS"|"MATH";
type ReasonCode="WEAK_DIMENSION_MATCH"|"LEVEL_MATCH"|"SLIGHTLY_ABOVE_LEVEL"|"TAG_MATCH"
 |"BALANCED_PRACTICE"|"RECENT_WEAKNESS"|"LOW_ATTEMPT_COVERAGE"|"RATING_GROWTH_STEP"
 |"MIXED_SKILL_MATCH"|"DEFAULT_RECOMMENDATION";
interface Period {start:Instant|null;end:Instant}
interface Summary {
 attemptedProblemCount:number;solvedCount:number;unsolvedProblemCount:number;
 submissionCount:number;acceptedSubmissionCount:number;failedSubmissionCount:number;
 pendingSubmissionCount:number;ratedSolvedCount:number;unratedSolvedCount:number;
 averageSolvedDifficulty:number|null;maxSolvedDifficulty:number|null;activeDays:number;
}
interface TagStat {tag:string;attemptedProblemCount:number;solvedCount:number;submissionCount:number}
interface DifficultyStat {difficulty:number|null;attemptedProblemCount:number;solvedCount:number}
interface ActivityStat {
 date:DateKey;submissionCount:number;acceptedSubmissionCount:number;
 failedSubmissionCount:number;pendingSubmissionCount:number;solvedCount:number;
}
interface DimensionScore {
 code:DimensionCode;name:string;displayOrder:number;score:number;
 attemptedProblemCount:number;solvedCount:number;submissionCount:number;
 averageSolvedDifficulty:number|null;rankOrder:number;
}
interface AnalysisResult {
 window:AnalysisWindow;period:Period;summary:Summary;currentRating:number|null;maxRating:number|null;
 overallScore:number;dimensions:DimensionScore[];weakestDimension:DimensionCode;
 tagStats:TagStat[];difficultyStats:DifficultyStat[];activityStats:ActivityStat[];
}
interface DimensionConfig {
 code:DimensionCode;name:string;displayOrder:number;tagMappings:Array<{tag:string;weight:number}>;
}
interface AlgorithmProblem {problemId:Id;difficulty:number|null;tags:string[];solvedCount:number|null;isGym:boolean}
interface AlgorithmSubmission {externalSubmissionId:Id;problemId:Id;verdict:Verdict;submittedAt:Instant}
interface AnalyzeRequest {
 requestId:UUID;accountId:Id;algorithmVersion:string;mappingVersion:string;
 sourceDataVersion:Id;dataCutoffAt:Instant;timezone:"Asia/Shanghai";windows:AnalysisWindow[];
 account:{currentRating:number|null;maxRating:number|null};submissions:AlgorithmSubmission[];
 problems:AlgorithmProblem[];dimensions:DimensionConfig[];
}
interface AnalyzeResponse {
 requestId:UUID;accountId:Id;algorithmVersion:string;mappingVersion:string;
 sourceDataVersion:Id;dataCutoffAt:Instant;timezone:"Asia/Shanghai";analyses:AnalysisResult[];
}
interface RecommendRequest {
 requestId:UUID;accountId:Id;analysisSnapshotId:UUID;algorithmVersion:string;mappingVersion:string;
 sourceDataVersion:Id;dataCutoffAt:Instant;mode:RecommendationMode;limit:number;
 profile:{accountId:Id;snapshotId:UUID;algorithmVersion:string;mappingVersion:string;window:"ALL";
  dataCutoffAt:Instant;sourceDataVersion:Id;overallScore:number;currentRating:number|null;
  averageSolvedDifficulty:number|null;maxSolvedDifficulty:number|null;weakestDimension:DimensionCode;
  dimensions:DimensionScore[];tagStats:TagStat[]};dimensions:DimensionConfig[];
 candidateProblems:AlgorithmProblem[];solvedProblemIds:Id[];recentRecommendationProblemIds:Id[];
}
interface RecommendResponse {
 requestId:UUID;accountId:Id;analysisSnapshotId:UUID;algorithmVersion:string;mappingVersion:string;
 sourceDataVersion:Id;dataCutoffAt:Instant;mode:RecommendationMode;targetRating:number;
 targetDimension:DimensionCode|null;candidateCount:number;
 recommendations:Array<{problemId:Id;rank:number;score:number;matchedDimension:DimensionCode|null;reasonCode:ReasonCode}>;
}
interface UserSourceAccount {accountId:Id;platform:"codeforces";dataVersion:Id;currentRating:number|null;maxRating:number|null}
interface UserAlgorithmSubmission {accountId:Id;platform:"codeforces";externalSubmissionId:Id;problemId:Id;verdict:Verdict;submittedAt:Instant}
interface UserAnalyzeRequest {
 requestId:UUID;algorithmVersion:"user-profile-v0.12.1";mappingVersion:"mapping-v0.11.1";
 sourceFingerprint:string;dataCutoffAt:Instant;timezone:"Asia/Shanghai";
 windows:["7D","30D","365D","ALL"];accounts:UserSourceAccount[];
 submissions:UserAlgorithmSubmission[];problems:AlgorithmProblem[];dimensions:DimensionConfig[];
}
interface UserAnalyzeResponse {
 requestId:UUID;algorithmVersion:"user-profile-v0.12.1";mappingVersion:"mapping-v0.11.1";
 sourceFingerprint:string;dataCutoffAt:Instant;timezone:"Asia/Shanghai";analyses:AnalysisResult[];
}
interface ReportProfileProjection {
 snapshotId:UUID;window:"ALL"|"30D";period:Period;summary:Summary;currentRating:number|null;maxRating:number|null;
 overallScore:number;dimensions:DimensionScore[];weakestDimension:DimensionCode;tagStats:TagStat[];
 difficultyStats:DifficultyStat[];activityStats:ActivityStat[];sourceAccountCount:number;
}
interface PersonalReportRequest {
 requestId:UUID;reportVersion:"personal-report-v0.12.1";sourceFingerprint:string;
 allProfile:ReportProfileProjection;recent30dProfile:ReportProfileProjection;language:"zh-CN"|"en";
}
interface PersonalReportContent {
 overview:string;strengths:string[];weaknesses:string[];recentTrend:string;actionSuggestions:string[];caution:string|null;
}
interface PersonalReportResponse {
 requestId:UUID;reportVersion:"personal-report-v0.12.1";promptVersion:string;modelName:string;
 sourceFingerprint:string;content:PersonalReportContent;
}
interface TeamMemberProfileProjection {allProfile:{snapshotId:UUID;overallScore:number;dimensions:DimensionScore[]}}
interface TeamTrainingMemberProjection {
 allTraining:{snapshotId:UUID;currentRating:number|null;averageSolvedDifficulty:number|null};
 recent30dTraining:{snapshotId:UUID;activityStats:ActivityStat[]};
}
interface TeamAnalyzeRequest {
 requestId:UUID;teamId:UUID;audience:"COACH"|"MEMBER";algorithmVersion:"team-profile-v0.12.1";
 mappingVersion:"mapping-v0.11.1";sourceFingerprint:string;dataCutoffAt:Instant;memberCount:number;
 profileMembers:TeamMemberProfileProjection[];trainingMembers:TeamTrainingMemberProjection[];
}
interface TeamDimensionScore {code:DimensionCode;name:string;displayOrder:number;score:number;memberSampleCount:number;rankOrder:number}
interface TeamActivityStat {date:DateKey;submissionCount:number;acceptedSubmissionCount:number;activeMemberCount:number}
interface TeamAnalyzeResponse {
 requestId:UUID;teamId:UUID;audience:"COACH"|"MEMBER";algorithmVersion:"team-profile-v0.12.1";
 mappingVersion:"mapping-v0.11.1";sourceFingerprint:string;dataCutoffAt:Instant;
 includedMemberCount:number;trainingMemberCount:number;levelMemberCount:number;overallScore:number;
 dimensions:TeamDimensionScore[];weakestDimension:DimensionCode;activityStats:TeamActivityStat[];targetRating:number|null;
}
type TeamRecommendationMode="WEAKNESS"|"HYBRID";
type TeamReasonCode="TEAM_WEAKNESS_MATCH"|"TEAM_LEVEL_MATCH"|"TEAM_COVERAGE_GAP"|"TEAM_BALANCED_PRACTICE";
interface TeamCandidateProblem extends AlgorithmProblem {memberSolvedCount:number;eligibleMemberCount:number}
interface TeamRecommendRequest {
 requestId:UUID;teamId:UUID;analysisSnapshotId:UUID;algorithmVersion:"team-recommend-v0.12.1";
 mappingVersion:"mapping-v0.11.1";sourceFingerprint:string;mode:TeamRecommendationMode;limit:number;
 profile:{overallScore:number;dimensions:TeamDimensionScore[];weakestDimension:DimensionCode;
  targetRating:number;includedMemberCount:number;coverageMemberCount:number};
 candidateProblems:TeamCandidateProblem[];dimensions:DimensionConfig[];
}
interface TeamRecommendResponse {
 requestId:UUID;teamId:UUID;analysisSnapshotId:UUID;algorithmVersion:"team-recommend-v0.12.1";
 mappingVersion:"mapping-v0.11.1";sourceFingerprint:string;mode:TeamRecommendationMode;
 targetRating:number;targetDimension:DimensionCode;candidateCount:number;
 recommendations:Array<{problemId:Id;rank:number;score:number;reasonCode:TeamReasonCode;memberSolvedCount:number;eligibleMemberCount:number}>;
}
interface AlgorithmError {
 requestId:UUID;error:{code:string;message:string;retryable:boolean;details:{fields:Array<{field:string;reason:string}>}};
}
type LegacyHealth = AlgorithmHealth;
```

| 旧POST端点 | 版本/预算、必须保留的语义 |
|---|---|
| `/internal/v1/analyze` | profile-v0.11.1/mapping-v0.11.1；55s计算/60s调用；按单account独立全部提交，重复externalId拒绝，四窗口全返回 |
| `/internal/v1/recommend` | recommend-v0.11.1；8s/10s；profile/sourceDataVersion/accountId/snapshotId回显一致，limit1..50，候选排除Gym/null难度/已AC |
| `/internal/v1/user-analyze` | user-profile-v0.12.1；55s/60s；CF event按platform+externalId跨账号折叠，冲突422；账号Rating取非null最大 |
| `/internal/v1/personal-report` | personal-report-v0.12.1；85s/90s；ALL+同批30D输入，旧LLM仅聚合字段，无标识/源码，配置缺失503 LLM_NOT_CONFIGURED |
| `/internal/v1/team-analyze` | team-profile-v0.12.1；15s/20s；能力/训练两授权集合分开，算法不推断隐私 |
| `/internal/v1/team-recommend` | team-recommend-v0.12.1；8s/10s；coverage由详细提交权限决定，不能以画像共享冒充 |

旧CF能力公式与上文新公式在纯CF数据时一致，difficulty=null quality=0。旧推荐target取平均已解难度??currentRating??800，round100/clamp800..3500；±200过滤、三个模式D/W/T/R评分与上文一致，不纳入PLATFORM；同分按数值problemId。LEVEL.reason难度更高为SLIGHTLY_ABOVE_LEVEL，否则LEVEL_MATCH；WEAKNESS为WEAK_DIMENSION_MATCH；HYBRID命中最弱优先WEAK_DIMENSION_MATCH，否则未做标签T>0为LOW_ATTEMPT_COVERAGE，否则BALANCED_PRACTICE，matchedDimension最大映射弱度、同值displayOrder，无映射null。

旧团队六维=profileMembers同维度分数均值round2，overall=六分均值；空能力集合六维0。activity只对trainingMembers近期30D逐日求submission/AC次数之和及activeMemberCount，不造团队去重solvedCount。targetRating对trainingMembers的averageSolvedDifficulty??currentRating非空值取中位数、round100、clamp800..3500，levelMemberCount=有效样本数。

旧team推荐排除coverage>0且memberSolvedCount=eligibleMemberCount的题；coverage=0不做已做过滤。`D=1-|difficulty-target|/400`、`C=coverage>0?1-memberSolved/eligible:null`、`W=w_weakest`、`A=max(w_d*(1-score_d/100))`。WEAKNESS只W>0，有coverage分数.45D+.35W+.20C、无coverage.55D+.45W；HYBRID有coverage.40D+.30A+.30C、无coverage.55D+.45A；clamp/round6，分数降序、难度距离/已做人数/数值problemId升序。WEAKNESS原因TEAM_WEAKNESS_MATCH；HYBRID若C>=.8则TEAM_COVERAGE_GAP，否则命中最弱则TEAM_WEAKNESS_MATCH，否则距离<=100为TEAM_LEVEL_MATCH，其余TEAM_BALANCED_PRACTICE。

两项旧文档校验勘误（不改变DTO）：coverageMemberCount≤backend实际memberCount，不要求≤includedMemberCount，因为能力/详细提交权限集合独立；旧TeamRecommendRequest无memberCount字段，algorithm只校验每项eligibleMemberCount=coverageMemberCount和memberSolved≤eligible，总人数授权上限由backend校验。targetRating=null当且仅当levelMemberCount=0，不能仅以团队人数为0判断。

旧personal-report内容固定overview/strengths/weaknesses/recentTrend/actionSuggestions/caution；禁止臆造比赛/学校/排名/未来Rating；provider非法JSON最多一次结构修复，仍失败LLM_BAD_RESPONSE。日志不输出标识、prompt、密钥；backend依requestId存一份成功不可变报告。旧团队隐私数据仍只CF分析，不自动暴露新平台源码/新学习画像。

## 10. 错误码与双方校验

| HTTP/code | 含义与重试 |
|---|---|
| 400 INVALID_ARGUMENT / INVALID_PROBLEM_REF | schema/哈希/题目引用不合法，不重试 |
| 401 SERVICE_UNAUTHORIZED | 新v2调用方错误，不重试；旧v1仍INTERNAL_UNAUTHORIZED |
| 404 TASK_NOT_FOUND | 未知analysis/profile任务，不新建假任务 |
| 409 IDEMPOTENCY_CONFLICT / EVENT_CONFLICT | 同键异内容，不重试；人工定位 |
| 413 SOURCE_TOO_LARGE / INPUT_TOO_LARGE | 明确限制，不静默截断 |
| 422 ALGORITHM_VERSION_MISMATCH / INVALID_INPUT | 新版本/映射/事件冲突不匹配，不回退 |
| 503 ALGORITHM_UNAVAILABLE / ALGORITHM_BUSY | 新服务不可用/过载，有限退避 |
| 504 ALGORITHM_TIMEOUT | 新同步recommend计算预算耗尽，可复用请求重试 |
| 500 INTERNAL_ERROR | 脱敏requestId定位，不公开堆栈 |

任务错误另有TOOL_DISABLED、TOOL_LANGUAGE_UNSUPPORTED、TOOL_PARSE_FAILED、TOOL_COMPILE_CONTEXT_INVALID、TOOL_TIMEOUT、ANALYSIS_PARTIAL、ANALYSIS_NO_USABLE_RESULT、ANALYSIS_RESULT_TOO_LARGE、TOOL_OUTPUT_LIMIT、TASK_INTERRUPTED；与backend展示analysisError一一同步。工具单次失败不把成功judge回滚，页面可展示PARTIAL证据。

旧v1保留INVALID_REQUEST、INTERNAL_UNAUTHORIZED、INPUT_TOO_LARGE、UNSUPPORTED_ALGORITHM_VERSION、UNSUPPORTED_MAPPING_VERSION、INVALID_INPUT、ALGORITHM_INTERNAL_ERROR、ALGORITHM_BUSY、COMPUTATION_TIMEOUT及V0.12 UNSUPPORTED_USER_PROFILE_VERSION/TEAM_PROFILE_VERSION/TEAM_RECOMMEND_VERSION/REPORT_VERSION、TEAM_PROFILE_EMPTY、LLM_NOT_CONFIGURED/UNAVAILABLE/TIMEOUT/BAD_RESPONSE。backend旧映射不变：版本422→ALGORITHM_VERSION_MISMATCH，非法响应→ALGORITHM_BAD_RESPONSE，不可达/5xx→ALGORITHM_UNAVAILABLE，超时→ALGORITHM_TIMEOUT；错误写旧sync/ai_jobs.errors，轮询本身200。

backend必须复核requestId/关联task身份/版本/源hash/fingerprint/cutoff、有限数值/null/枚举、四窗口/六维计数关系、结果hash、推荐候选归属/全source已AC排除/连续rank。静态finding路径/行号/消息上限校验，不能把未校验工具stdout原样公开。新resultHash=SHA256(JCS完整StaticAnalysisResult去掉resultHash字段)，源码hash与reproducibility.sourceSha256一致；ProfileResult冻结JSON另有计算工件hash在算法DB保存，不新增公开DTO字段。

## 11. 独立构建和最小联调验收

algorithm独立Dockerfile/依赖锁/工具发行清单，监听0.0.0.0:8000；仅内部网络暴露。环境：ALGORITHM_DATABASE_URL仅算法schema、BACKEND_ALGORITHM_TOKEN、ALGORITHM_BACKEND_TOKEN、INTERNAL_API_TOKEN兼容旧、ALGORITHM_CALLBACK_URL固定、私有算法工件桶；旧LLM_REPORT_ENABLED/LLM配置仍按旧功能处理。构建镜像包含固定工具链及许可文件；实际可用工具必须通过内置fixture自检才在capabilities.enabled=true。算法无访问backend/judge数据库角色。

四负责人可用本文DTO制作真实HTTP fixture。至少覆盖：纯平台无CF画像、纯CF新旧公式一致、同CF团队事件跨账号去重/冲突、同problemId跨source不合并、同平台题跨版本仍一题、CF null/Gym不造rating、异步判题pending与IE排除、C++CE仍有Lizard结果、工具部分失败/PARTIAL、全失败/语言跳过、禁用户执行与编译参数、源hash不符、源码超限、重启/失效lease/重复与乱序callback、by-request恢复未知任务、三模式/三source/无评级冷启动/空推荐。验收闭环为推荐→平台提交→judge结果先可见→静态分析后可见→学习画像版本更新→再推荐；外部题仅跳转/CF同步，不伪造静态分析。
