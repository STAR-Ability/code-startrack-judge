# V0.2 后端 API 与跨服务业务契约

契约发布号 `0.2.0`，本轮设计基线为已使用的 V0.11 + V0.12。公开接口统一 `/api/v1`；功能版本不等于 URL 版本。本文包含新增完整契约和审核保留的旧接口签名，可由后端负责人独立实施。部署与验收读同目录《V0.2-整体架构与联调说明》。

## 1. 服务与数据边界

业务容器固定 `frontend:80`、`backend:8081`、`algorithm:8000`、`judge-problem-service:8082`。Browser → frontend 同源代理 → backend；backend 主动请求两个下游。下游只向 backend 固定事件入口回传已创建任务结果，不读取其他业务 API，不直接写 backend 表。数据库、Redis、私有对象/题包存储是独立基础设施。

| 主数据 | 唯一 owner | 后端处理方式 |
|---|---|---|
| 身份、CF、团队、隐私、报告、通知；平台 Submission/私有源码；训练；业务画像与实际推荐交付 | backend | 后端独占写入，沿用旧表并增加新表 |
| 平台题目、不可变题包版本、测试/参考程序、题包许可、导入、原始判题任务结果 | judge-problem-service | 后端通过 API 获取；题目缓存和判题结果只是不可修改投影 |
| 静态分析任务、工具原始报告、计算输入/输出工件、工具版本、profile 计算任务 | algorithm | 后端保存不可修改分析展示投影；业务画像仍由后端落库 |

投影明确记录 `sourceOwner/sourceId/revision`。后端不把本地平台题目缓存视为可编辑主目录；管理员写入必须代理下游管理 API。CF 仍由 backend 访问公开 API，不搬入 judge 本地题库；没有外部源码就不分析。新综合画像与旧 CF-only 画像分开，团队隐私设置不授权分享平台源码。

## 2. 公共协议与鉴权

JSON 使用 camelCase，数据库 snake_case。`Id` 是正十进制字符串；`UUID` 是标准 UUID 字符串；`Instant` 是 RFC3339 UTC `Z`；自然日 `YYYY-MM-DD`，计算时区 `Asia/Shanghai`。timeMs 毫秒、memoryBytes 字节；缺失 difficulty/rating 为 null；数组为空 `[]`；nullable 字段必须出现。未声明请求字段 400。ID 不转 JS number。

```ts
type Id = string;
type UUID = string;
type Instant = string;
type DifficultyScale = "CF_RATING" | "PLATFORM_RATING" | "UNRATED";
interface TaskError { code:string; message:string; retryable:boolean }
interface ApiResponse<T> { data:T; requestId:UUID }
interface PageResponse<T> {
  data:T[]; meta:{page:number;pageSize:number;total:number;hasNext:boolean}; requestId:UUID;
}
interface ApiError { error:{code:string;message:string;details:Record<string,unknown>};requestId:UUID }
```

表中成功响应均写 `data` 类型；分页写 `Page<T>`。v2 内部成功也套相同 envelope；旧 `/internal/v1` 保留裸 DTO。204 无 body。page 默认 1、pageSize 默认 20 最大 100；越界页 `[]`，`hasNext=page*pageSize<total`；total 与列表使用同一次查询快照。

Session 保留 `cst_session`：不透明随机 token、HttpOnly、SameSite=Lax、Path=/、生产 Secure、固定 7 天。Browser 使用 `credentials:include`，写请求 Origin 必须等于 PUBLIC_ORIGIN。个人新增接口要求 ACTIVE 用户和 STUDENT，管理接口 ADMIN；只有旧认证公共端点可匿名。逐次校验本人资源归属；他人与不存在的资源返回同类 404。源码 `Cache-Control: private, no-store`，不纳入旧团队 detailedSubmissions 授权。

新写接口必须 `Idempotency-Key:UUID`。作用域 `(user,operation,key)`；参数补默认值后规范化并 hash，源码同时核对原 UTF8 SHA-256。首次创建对象按表中状态返回；同 key 同参数 200 原对象，包括已持久化异步任务；同 key 不同参数 409 IDEMPOTENCY_CONFLICT；尚无可返回对象的处理中 409 REQUEST_IN_PROGRESS、`Retry-After:2`。成功关联随业务对象长期保留。源码最大 UTF8 262144 bytes，空白拒绝 400；公开 JSON body 最大 2 MiB。新内部完整画像输入最大 32 MiB，超过 413 INPUT_TOO_LARGE，不截断 ALL；judge/analysis源码任务等普通内部请求最大2MiB。v2结果GET/回调最大32MiB，不能用全站2MiB body限制挡合法结构化分析结果；每分析任务全部原始报告合计8MiB，仅algorithm私有，不直接透传。旧 v1 内部上限仍 64 MiB。

## 3. 新平台题目、Submission、分析 DTO

以下共享定义同时是 frontend/backend/algorithm/judge 联调契约。平台/CF problemId 各自分配，跨来源必须使用 `(source,platform,problemId)`；版本不参与题目去重。PLATFORM 必须 `startrack` + 非空版本，EXTERNAL 必须 `codeforces` + null 版本。平台题 URL=null，前端按 ID 跳站内页；外部 URL 为已验证原题 HTTPS 链接。

```ts
type ProblemSource="PLATFORM"|"EXTERNAL";
type Platform="startrack"|"codeforces";
interface ProblemRef {
  source: ProblemSource; platform: Platform; problemId: Id; problemVersionId: UUID | null;
}
// PLATFORM必须startrack+非空版本，EXTERNAL必须codeforces+null；题目身份(source,platform,problemId)，题目版本不是题目去重key。两owner各自Id空间；禁止裸problemId跨source联结。
interface ProblemSummary {
  problemRef: ProblemRef; title: string | null; difficulty: number | null;
  difficultyScale: DifficultyScale; tags: string[]; url: string | null;
}
// 内部平台题url=null，frontend用problemId导航；外部url为CF真实链接。旧ProblemDto继续原样。
type JudgeStatus="QUEUED"|"DISPATCHING"|"RUNNING"|"COMPLETED"|"FAILED"|"CANCELLED";
type JudgeVerdict="AC"|"WA"|"TLE"|"MLE"|"RE"|"CE"|"OLE"|"IE";
type AnalysisStatus="NOT_REQUESTED"|"QUEUED"|"RUNNING"|"SUCCEEDED"|"PARTIAL"|"FAILED"|"SKIPPED";
type ProfileJobStatus="QUEUED"|"RUNNING"|"SUCCEEDED"|"FAILED";
// 远程COMPLETED仅AC/WA/TLE/MLE/RE/CE/OLE；远程FAILED有真实IE，backend本地明确拒绝/派发耗尽FAILED无真实result。均不纳入能力失败题；CANCELLED verdict=null。
interface JudgeResult { verdict:JudgeVerdict; timeMs:number|null; memoryBytes:number|null; passedTestCount:number; totalTestCount:number; score:number|null; compileLog:string|null; diagnosticCode:string|null; judgedAt:Instant }
// binaryAC/WA score=null；compileLog只当前用户/管理员可读，<=16384bytes并脱敏；不回隐藏输入、期望输出、程序stdout/stderr或测试路径；资源值=max单测试CPUms/peakbytes，未运行null。
interface SubmissionView { submissionId:Id; problem:ProblemSummary; languageId:string; judgeTaskId:UUID|null; judgeStatus:JudgeStatus; judgeRevision:number; judgeResult:JudgeResult|null; judgeError:TaskError|null; analysisId:UUID|null; analysisStatus:AnalysisStatus; analysisRevision:number; analysisError:TaskError|null; submittedAt:Instant; updatedAt:Instant }
// 旧backend.submissions及其非空FK完全保留；新增backend.platform_submissions，平台submission沿用bigint ID，复用旧submissions ID分配sequence确保全backend submissionId唯一（旧ID不变，新增列不塞入旧表）。platform_problem_id是逻辑跨owner关联，不建跨schema FK。公开旧SubmissionDto完全不变。源码另表/私有桶backend owner。
interface TaskBase { requestId:UUID; revision:number; status:string; error:TaskError|null; createdAt:Instant; updatedAt:Instant; finishedAt:Instant|null }
interface JudgeTask extends TaskBase { judgeTaskId:UUID; submissionId:Id; status:JudgeStatus; result:JudgeResult|null }
interface JudgeTaskRequest { requestId:UUID; submissionId:Id; problemRef:ProblemRef; languageId:string; sourceCode:string; sourceSha256:string }
// requestId与(submissionId,judge attempt)唯一，v0.2不公开rejudge；重试网络同requestId+相同hash返回原task，服务端保证终态版本不回退。
interface AnalysisMetrics { sourceLines:number|null; functionCount:number|null; maxCyclomaticComplexity:number|null; meanCyclomaticComplexity:number|null; duplicateLines:number|null; maintainabilityIndex:number|null }
interface AnalysisFinding { findingId:string; tool:string; ruleId:string; severity:"INFO"|"WARNING"|"ERROR"; category:"COMPLEXITY"|"BUG_RISK"|"STYLE"|"PERFORMANCE"|"DUPLICATION"; message:string; file:string; startLine:number; endLine:number; column:number|null }
interface ToolRun { tool:string; version:string; configSha256:string; status:"SUCCEEDED"|"FAILED"|"SKIPPED"; durationMs:number; error:TaskError|null }
interface StaticAnalysisResult { schemaVersion:"0.2.0"; analysisId:UUID; submissionId:Id; sourceSha256:string; languageId:string; toolchainVersion:string; resultHash:string; metrics:AnalysisMetrics; findings:AnalysisFinding[]; tools:ToolRun[]; reproducibility:{imageDigest:string; configSha256:string; sourceSha256:string}; synthesis:{status:"NOT_REQUESTED"|"QUEUED"|"RUNNING"|"SUCCEEDED"|"FAILED"|"SKIPPED"; provider:string|null; model:string|null; promptVersion:string|null; content:string|null; error:TaskError|null} }
// v0.2 synthesis固定NOT_REQUESTED，后续需单独版本授权/触发接口；工具复杂度仅圈复杂度/指标，不声称证明Big-O；CPD仅提交内重复不宣称跨用户抄袭检测。
interface AnalysisJobRequest { requestId:UUID; submissionId:Id; problemRef:ProblemRef; languageId:string; sourceCode:string; sourceSha256:string; judgeResult:JudgeResult; toolchainVersion:"static-v0.2.1" }
interface AnalysisJob extends TaskBase { analysisId:UUID; submissionId:Id; status:AnalysisStatus; result:StaticAnalysisResult|null }
interface CallbackEvent<T> { eventId:UUID; eventType:"JUDGE_TASK_UPDATED"|"ANALYSIS_JOB_UPDATED"|"PROFILE_JOB_UPDATED"; occurredAt:Instant; requestId:UUID; aggregateId:UUID; revision:number; payload:T }
// revision从1递增，payload完整Task快照；algorithm profile callback payload ProfileJob；requestId必须与原任务一致。backend ack={accepted:true,duplicate:boolean}；重复eventId/旧revision ack200不回退；同revision不同hash409 EVENT_CONFLICT；未知任务404 TASK_NOT_FOUND。task commit+callback outbox事务；callback失败1,2,4,8,16,30s退避持续24h后deadletter，backend每30s轮询所有非终态任务+终态未回传对账。后端自己的outbox恢复派发、lease过期恢复；不能只靠Redis pubsub。
```

```ts
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
interface CatalogEntry {
  problem: ProblemSummary;
  status: "PUBLISHED" | "WITHDRAWN";
}
interface CatalogSnapshotPage {
  snapshotId: UUID;
  catalogVersion: Id;
  items: CatalogEntry[];
  nextCursor: string|null;
  expiresAt: Instant;
}
interface LanguageCapability {
  languageId:string; displayName:string; languageFamily:string;
  compilerVersion:string; sourceFilename:string; analysisSupported:boolean;
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

### 3.1 判题与训练枚举映射

| JudgeVerdict | 统一训练旧 Verdict | 业务含义 |
|---|---|---|
| AC | ACCEPTED | 有效通过 |
| WA/TLE/MLE/RE/CE | WRONG_ANSWER/TIME_LIMIT/MEMORY_LIMIT/RUNTIME_ERROR/COMPILE_ERROR | 有效判题失败 |
| OLE | OTHER | 有效输出限制失败，原因保留 OLE |
| IE | 不产生能力失败事件 | 基础设施故障，judgeStatus=FAILED |
| 非终态 | PENDING | 等待，不当失败 |
| CANCELLED | 不纳入画像 | 取消，无 verdict |

`judgeStatus=COMPLETED` 仅 AC/WA/TLE/MLE/RE/CE/OLE；FAILED 的结果若存在必须 IE。judgeRevision/analysisRevision 初始 0（尚无下游任务快照），接收后按任务内 revision 从 1 单调。分析重试换 analysisId，先比 task 身份再比 revision，不能拿新旧任务 revision 直接比较。远程JudgeTask终态不回退；无task的本地接收不确定失败按第8节对账恢复。

### 3.2 静态分析约束

判题完成立即可读，不等待代码分析。COMPLETED（含 CE）创建 analysis dispatch；不支持语言为 SKIPPED，基础设施 FAILED/CANCELLED 为 SKIPPED。Lizard、clang-tidy、Infer、CPD 是首阶段 C/C++ 工具；Radon/PMD 仅适用语言开启。工具部分失败且有可用结构化结果为 PARTIAL，无可用结果 FAILED。metrics 空值不造 0；圈复杂度不声称 Big-O 证明；CPD 仅当前提交内重复，不推断抄袭。synthesis 当前固定 NOT_REQUESTED，未来独立版本触发。

## 4. 新公开 API（全部 `/api/v1`）

### 4.1 题库与语言能力

| 调用方/用途 | 方法、路径 | 参数 | 成功响应 |
|---|---|---|---|
| frontend 题库筛选 | GET `/platform-problems` | q? 1..100 trim；tag? 精确 1..128；minDifficulty?/maxDifficulty? 正整数且 min≤max；status=PUBLISHED；分页 | 200 Page<PlatformProblemSummary> |
| frontend 当前题面 | GET `/platform-problems/{problemId}` | Id | 200 PlatformProblemDetail |
| frontend 历史提交回看 | GET `/platform-problems/{problemId}/versions/{problemVersionId}` | Id、UUID | 200 PlatformProblemDetail |
| frontend 编辑器语言选择 | GET `/judge-languages` | 无 | 200 LanguageCapabilities |

普通列表 status 只可 PUBLISHED，其他值 400 INVALID_ARGUMENT。难度筛选只匹配有可信标定的 PLATFORM_RATING，null 不匹配；排序 updatedAt DESC、problemId 数值 DESC。updatedAt取公开变更时间，DRAFT新版本预览取版本createdAt；新草稿不改变公开目录排序。当前题必须已发布；历史版本必须曾发布或被本人历史 Submission 引用。历史详情保留原题包字段，catalogVersion是当前目录；指定version从未发布则status=DRAFT，曾发布则status是题目当前PUBLISHED/WITHDRAWN；撤下或非当前有效版本不能新提交。题面 content 是完整 Markdown，input/output 不能提取时 null；samples 只有公开样例，不暴露隐藏测试/参考代码/对象地址。首阶段必须有 cpp17，c11 可选；语言 capability 真实报告 compilerVersion/sourceFilename，未安装语言不展示为可用。公开 analysisSupported 由 backend 取 judge允许分析标记∩algorithm capabilities.analysisLanguages 当前真实可用能力，算法不可达显示false但判题语言仍可用；judge 不请求algorithm。公开capabilityVersion由backend计算SHA-256(JCS({judgeCapabilityVersion:内部原capabilityVersion,languages:按languageId升序的最终公开languages}))，保证能力交集变化同时改变缓存版本；judge内部capabilityVersion不改。

### 4.2 代码提交与记录

| 调用方/用途 | 方法、路径 | Request / Query | 成功响应 |
|---|---|---|---|
| frontend 提交 | POST `/submissions` | `{problemRef:ProblemRef,languageId:string,sourceCode:string,trainingRecordId?:UUID}`；Idempotency-Key | 202 SubmissionView |
| frontend 我的平台提交 | GET `/submissions` | problemId?、judgeStatus?、verdict?:JudgeVerdict、from?/to?:Instant；分页 | 200 Page<SubmissionView> |
| frontend 进度恢复/结果 | GET `/submissions/{submissionId}` | Id | 200 SubmissionView |
| frontend 本人代码回看 | GET `/submissions/{submissionId}/source` | Id | 200 `{submissionId:Id,sourceCode:string,sourceSha256:string,languageId:string}` |
| frontend 分析进度/结果 | GET `/submissions/{submissionId}/analysis` | Id | 200 SubmissionAnalysisView |
| frontend 分析重试 | POST `/submissions/{submissionId}/analysis/retry` | 无 body；Idempotency-Key | 202 SubmissionAnalysisView；在途原任务 200 |

```ts
interface SubmissionAnalysisView {
  analysisId:UUID|null;status:AnalysisStatus;revision:number;
  result:StaticAnalysisResult|null;error:TaskError|null;
}
```

提交只接受 PLATFORM。body 的版本与当前可提交题版本必须匹配，语言由服务端 capability/template 决定；不接受 shell、编译参数、回调 URL、答案或客户端 judgeResult。trainingRecordId 若带入必须本人且同 ProblemRef 题目身份；版本允许训练记录的目标版本更新到本次实际提交版本。首次持久化后返回 202，初始 DISPATCHING/null judgeTaskId；下游暂不可达仍保留已接收 Submission 并后台重试。首次预校验依赖失败返回 503/504，不创建 Submission；题目状态/版本错误 409。

提交排序 submittedAt DESC、submissionId 数值 DESC；from 包含、to 不包含且 from<to；过滤 verdict 只在 judgeResult 有对应值时匹配。此列表只有本站 Submission；旧 `/oj-accounts/.../submissions` 继续 CF-only。用户源码只从 backend owner 获取，不从 judge/algorithm 工件暴露。

分析重试仅 FAILED/PARTIAL 或暂不可用产生的 SKIPPED；不支持语言的 SKIPPED 需 capability 已支持方可重试，否则 409 ANALYSIS_NOT_RETRYABLE。判题非 COMPLETED 时不允许重试。SUCCEEDED 返回 409 ANALYSIS_ALREADY_COMPLETE；在途用同任务，不创建双任务。先保存新的 requestId/dispatch及递增attempt_generation，再替换当前 task 身份；下游ID尚空时也先核最新dispatch代次，旧attempt只归档，旧分析结果保留审计且不覆盖新任务。Submission 当前 analysisId/analysisRevision 用于本次尝试与迟到事件；usableAnalysisId/usableAnalysisRevision 是数据库内部最近可用证据引用。PARTIAL 重试进入 QUEUED 时保留旧可用 feature，FAILED/SKIPPED 也保留；仅新 SUCCEEDED/PARTIAL 原子替换 usable 引用并推进 analysisFeaturesVersion。当前分析 API 展示新尝试，不把旧 result 误放到新 analysisId；profile feature 从 usable 引用读取。GET 可返回无结果、PARTIAL 可用结果及 error；轮询失败状态本身仍 HTTP 200。

### 4.3 训练记录

```ts
type TrainingStatus = "PLANNED" | "IN_PROGRESS" | "COMPLETED";
interface TrainingRecord {
  trainingRecordId:UUID;problem:ProblemSummary;status:TrainingStatus;
  recommendationBatchId:UUID|null;firstSubmittedAt:Instant|null;lastSubmittedAt:Instant|null;
  attemptCount:number;acceptedSubmissionCount:number;lastSubmissionId:Id|null;
  completedAt:Instant|null;createdAt:Instant;updatedAt:Instant;
}
```

| 调用方/用途 | 方法、路径 | 参数 | 成功响应 |
|---|---|---|---|
| frontend 选择/推荐归因 | POST `/me/training-records` | `{problemRef:ProblemRef,recommendationBatchId?:UUID}`；Idempotency-Key | 201 TrainingRecord；同 key 200 |
| frontend 训练历史 | GET `/me/training-records` | source?:PLATFORM/EXTERNAL、status?:TrainingStatus、from?/to?:Instant、分页 | 200 Page<TrainingRecord> |
| frontend 单条训练 | GET `/me/training-records/{trainingRecordId}` | UUID | 200 TrainingRecord |

同用户、source/platform/problemId 唯一。不同 key 选择已存在目标返回 200 原记录；推荐 batch 仅接受本轮 `/me/recommendations` 的 learning 批次，必须本人且包含该题；旧账号/团队批次不作本接口归因，首次非空归因冻结，不因后续推荐重写。提交或 CF 同步可自动创建记录。点击外部链接只 PLANNED；实际提交 IN_PROGRESS；有效 AC 至少一次 COMPLETED。计数是该用户有权归属的提交事件：平台全部已接收 Submission 为 attempt，AC 为 accepted；CF 使用平台+externalSubmissionId 跨账号去重，不把同团队事件双计。IE 不当能力失败，但保留提交历史。重评使 AC 全部撤销时可 COMPLETED→IN_PROGRESS，按有效事实重算；版本不切分同题训练计数。解绑 CF 保留旧训练历史，新的综合画像源集仍仅当前未解绑账号。排序 updatedAt DESC、trainingRecordId DESC；from/to 按 lastSubmittedAt，`[from,to)`；尚无提交的 null 在任何有界过滤中不匹配。lastSubmissionId 为 backend 内部全局 submissionId，不填 CF 外部 ID。

### 4.4 综合学习画像（旧 CF 画像独立保留）

| 调用方/用途 | 方法、路径 | 参数 | 成功响应 |
|---|---|---|---|
| frontend 当前综合画像 | GET `/me/learning-profile/latest` | window=ALL，四窗口枚举 | 200 LearningProfile 或 null |
| frontend 综合历史 | GET `/me/learning-profile/history` | window=ALL；分页 | 200 Page<LearningProfile> |
| frontend 快照详情 | GET `/me/learning-profile/{snapshotId}` | UUID | 200 LearningProfile |
| frontend 手动重建 | POST `/me/learning-profile/rebuild` | 无 body；Idempotency-Key | 202 LearningProfileJob |
| frontend 重建轮询 | GET `/learning-profile-jobs/{jobId}` | UUID | 200 LearningProfileJob |

LearningProfile 与算法冻结结果的准确字段见第 7 节；它含 publicId/snapshotId/profileJobId，以及 sources/codeQuality。没有 CF 允许纯平台/零数据画像；存在未解绑 CF 时必须全部至少完整同步成功且无该用户账号同步在途，不能悄悄丢源。INVALID 的最后完整数据可参与，stale=true。无快照 null，成功无训练返回完整零画像，不能混为失败。

旧 `/me/analysis`、团队分析/分享和 personal-report 全部保持 CF-only，不自动合入平台或源码。新四窗口一次原子提交；sourceFingerprint 已变丢弃旧结果，旧job结束FAILED/DATA_CHANGED，再新建job/requestId/冻结输入；不能用旧requestId换payload。只有同用户在途合并，不能对fingerprint永久唯一；同指纹超过24h或用户新重建可使用新cutoff生成新job。judge 有效投影先更新基础画像；分析 SUCCEEDED/PARTIAL 再更新特征版本触发重建，分析失败不阻塞判题/基本画像。

### 4.5 站内与外部题目推荐

```ts
type RecommendationSource = "ALL" | "PLATFORM" | "EXTERNAL";
interface LearningRecommendation {
  rank:number;problem:ProblemSummary;score:number;reasonCode:ReasonCode;reason:string;
  matchedDimension:DimensionCode|null;solvedSinceGeneration:boolean;
}
interface LearningRecommendationBatch {
  batchId:UUID;analysisSnapshotId:UUID;sourceFingerprint:string;source:RecommendationSource;
  mode:RecommendationMode;algorithmVersion:"learning-recommend-v0.2.1";mappingVersion:string;
  candidateCount:number;resultCount:number;recommendations:LearningRecommendation[];
  generatedAt:Instant;stale:boolean;
}
```

| 调用方/用途 | 方法、路径 | 参数 | 成功响应 |
|---|---|---|---|
| frontend 新推荐 | POST `/me/recommendations/generate` | `{source?:RecommendationSource,mode?:RecommendationMode,limit?:number}`；默认 ALL/HYBRID/10，整数 1..50；Idempotency-Key | 201 LearningRecommendationBatch |
| frontend 当前推荐 | GET `/me/recommendations/latest` | source=ALL、mode=HYBRID | 200 batch 或 null |
| frontend 推荐历史 | GET `/me/recommendations/history` | source?/mode?；分页，省略过滤代表全部 | 200 Page<LearningRecommendationBatch> |
| frontend 批次详情 | GET `/me/recommendations/{batchId}` | UUID | 200 LearningRecommendationBatch |

只使用最新未 stale 的 ALL 综合画像。候选为冻结的当前 PUBLISHED 平台目录 + 合法 CF CATALOG 普通题（有正确 URL、不含特殊/损坏标签，Gym 不用于外部推荐）。候选不从用户已做列表获取、不随机截断；按来源身份排除平台全历史有效AC与当前未解绑CF账号全历史有效AC（跨账号去重）；已解绑账号保留的训练历史不参与当前已解集。平台评级不当 CF Rating；算法生成归一化 score 后统一 rank。缺少可信评级的题 HYBRID 可以标签/冷启动推荐，LEVEL 仅接受可比较尺度。最近 7 天推荐降权，算法不足候选可以少返回或空成功批次。

生成前冻结完整候选/目录版本、已 AC 集、ALL 画像及指纹；释放事务后同步算法调用；写入前核对用户源版本、最新画像、两个目录版本以及入选题当前发布状态，变化 409 DATA_CHANGED，不静默删题补位。后端生成 batchId 并保存完整 ProblemSummary 快照、固定 reason 文案与原 rank。solvedSinceGeneration 动态派生，不改历史。排序 generatedAt DESC、batchId DESC；stale 表示画像不是最新/画像 stale/版本不匹配/源或目录改变/生成超过 24 小时。

### 4.6 平台题包管理（ADMIN）

| 调用方/用途 | 方法、路径 | 请求 | 成功响应 |
|---|---|---|---|
| 管理员导入 | POST `/admin/problem-imports` | `{source:"OJ_LAB",repositoryUrl:"https://github.com/oj-lab/problem-packages",revision:string,packagePaths:string[]}`；Idempotency-Key | 202 ImportJob |
| 管理员查询导入 | GET `/admin/problem-imports/{importJobId}` | UUID | 200 ImportJob |
| 管理员发布 | POST `/admin/platform-problems/{problemId}/publish` | `{problemVersionId:UUID}`；Idempotency-Key | 200 PlatformProblemDetail |
| 管理员标签/难度管理 | POST `/admin/platform-problems/{problemId}/metadata-versions` | `{baseProblemVersionId:UUID,tags:string[],difficulty:number\|null,difficultyScale:"PLATFORM_RATING"\|"UNRATED"}`；Idempotency-Key | 201 PlatformProblemDetail（新DRAFT）；重放200 |
| 管理员撤题 | POST `/admin/platform-problems/{problemId}/withdraw` | `{reason:string}`；Idempotency-Key | 200 `{problemId:Id,status:"WITHDRAWN",catalogVersion:Id}` |

revision 必须固定完整 40 位 commit；packagePaths 1..100 唯一、只能 problems/ 下规范化相对目录，拒绝绝对路径、URL、`..`。导入返回逐包许可和验证结果；成功只 DRAFT，人工 publish 前必须技术校验通过且许可 VERIFIED。不从 CF API 下载题面/测试充作本地题包。标签≤32项、每项1..128且去重；UNRATED必须difficulty=null，PLATFORM_RATING必须正整数。metadata-versions复制基版产生新的UUID/DRAFT版本，共享只读题包，旧已发布版不变；publish后再推进目录版本。后端生成内部 requestId，持久化管理代理映射供超时恢复，绝不 INSERT judge 题表。ImportJob 同 requestId 重放200；失败轮询仍200。许可证、原源码依赖与题包来源由 judge 保留，不能用统一 MIT 标记代替逐题审查。

## 5. backend → judge-problem-service HTTP

基础地址 `http://judge-problem-service:8082`。以下成功响应套 ApiResponse/PageResponse，Caller 固定 backend；token 仅注入两方。

| 方法、路径 | 输入 | 成功响应 | 用途 |
|---|---|---|---|
| GET `/internal/v2/problems` | 与公开列表 query 同签名；内部 status 可 DRAFT/WITHDRAWN，backend 只 ADMIN 使用 | 200 Page<PlatformProblemSummary> | 目录代理 |
| GET `/internal/v2/problems/{problemId}` | Id | 200 PlatformProblemDetail | 提交预校验 |
| GET `/internal/v2/problems/{problemId}/versions/{problemVersionId}` | Id/UUID | 200 PlatformProblemDetail | 不可变版本回看 |
| GET `/internal/v2/languages` | 无 | 200 LanguageCapabilities | 语言能力 |
| GET `/internal/v2/catalog-snapshots` | cursor?；limit=100，1..1000 | 200 CatalogSnapshotPage | 冻结公开候选目录 |
| POST `/internal/v2/judge-tasks` | JudgeTaskRequest | 202 JudgeTask；重放200 | 可靠派发 |
| GET `/internal/v2/judge-tasks/{judgeTaskId}` | UUID | 200 JudgeTask | 结果对账 |
| POST `/internal/v2/judge-tasks/by-request` | `{requestIds:UUID[]}`，1..100 | 200 `{tasks:JudgeTask[],missingRequestIds:UUID[]}` | 创建响应丢失恢复 |
| POST `/internal/v2/problem-imports` | 管理导入 request + requestId | 202 ImportJob；重放200 | 题包导入 |
| GET `/internal/v2/problem-imports/{importJobId}` | UUID | 200 ImportJob | 管理轮询 |
| POST `/internal/v2/problems/{problemId}/publish` | `{requestId:UUID,problemVersionId:UUID}` | 200 PlatformProblemDetail | 管理发布 |
| POST `/internal/v2/problems/{problemId}/metadata-versions` | `{requestId:UUID,baseProblemVersionId:UUID,tags:string[],difficulty:number\|null,difficultyScale:"PLATFORM_RATING"\|"UNRATED"}` | 201 PlatformProblemDetail；重放200 | 不可变元数据版本 |
| POST `/internal/v2/problems/{problemId}/withdraw` | `{requestId:UUID,reason:string}` | 200 撤题 DTO | 管理撤题 |

CatalogSnapshotPage 首次无 cursor 冻结目录，后续沿 opaque nextCursor 读取同 snapshot/version；TTL 30 分钟，过期 410 SNAPSHOT_EXPIRED 全量重拉。完成全页后 backend 原子切换候选缓存，包含 WITHDRAWN 墓碑，不把不同版本拼起来；详情与测试仍 API owner。目录变化不回写旧 Submission 的题目版本/冻结字段。

连接超时 2 秒；普通目录/管理/任务接收总超时 5 秒；题面 5 秒；单次 by-request 批量 5 秒。新异步接收接口只完成 durable queue，不等编译。仅网络失败/超时/502/503/504 退避重试相同 requestId/body；4xx、非法 DTO/版本不重试。判题长期进度由任务轮询获取，不使浏览器请求等待。

## 6. 两下游 → backend 固定事件入口

| 调用方 | 方法、路径 | body | 200 data |
|---|---|---|---|
| judge-problem-service | POST `/internal/v2/events/judge` | CallbackEvent<JudgeTask>，eventType=JUDGE_TASK_UPDATED | `{accepted:true,duplicate:boolean}` |
| algorithm | POST `/internal/v2/events/algorithm` | CallbackEvent<AnalysisJob> 或 CallbackEvent<ProfileJob> | 同上 |

新增 S2S 均 `Authorization:Bearer <caller-specific-secret>`、`X-Request-Id:UUID`；requestId 与 body 相同。四份独立 secret：backend→algorithm、backend→judge、algorithm→backend、judge→backend。backend 配置固定 callback 地址，不接受客户端 callbackUrl；服务网络内暴露，不转 Browser Cookie。旧 v1 token 保留 INTERNAL_API_TOKEN。健康 `/health` 无用户鉴权，仅私有网络；backend readiness只强依赖自身DB，下游故障仍可认证/读历史。algorithm health 保留旧contractVersion=v1/algorithmVersions/mappingVersions及capabilities.llmReport字段，追加apiContractVersion=0.2.0与capabilities.staticAnalysis，不把旧health直接改成新DTO。

事件 payload 必须完整 Task；aggregateId=对应 task ID，revision/requestId 与 payload 一致。backend 先验证 caller、持久化 dispatch.requestId、所属 Submission/job、任务 ID 绑定；JudgeTask按requestId匹配已经冻结的源码/题版本上下文（响应未重复携带这些字段），AnalysisJob.result再核对sourceSha256与版本上下文，再做 schema/状态/result 校验。dispatch 已存但创建响应还未收到时，回调可先把下游 ID 绑定到该 dispatch，不能因本地 taskId 尚为空永远404。真正未知 requestId 404 TASK_NOT_FOUND。

同 eventId 相同内容或旧 revision 200 duplicate=true，不回退；同 revision 不同内容 409 EVENT_CONFLICT 并告警；新 revision 正常事务更新投影、inbox、版本计数、训练/profile后续 outbox，一次提交。各 owner task 更新与 callback outbox 同事务，失败 1/2/4/8/16/30 秒退避，24h 后 dead-letter 可重放。backend 每 30 秒轮询所有非终态任务及终态漏回传对账，HTTP GET status失败仍200；task 内失败读取 error。callback和poll共用同一 reducer。

## 7. backend → algorithm 新计算契约

基础地址 `http://algorithm:8000`。新增 v2 与旧 v1 独立；算法不读数据库业务表/CF/judge，不根据 accountId 拉数，只接后端冻结 DTO。

| 方法、路径 | 输入 | 成功响应 | 用途 |
|---|---|---|---|
| POST `/internal/v2/analysis-jobs` | AnalysisJobRequest | 202 AnalysisJob；重放200 | 异步代码分析 |
| GET `/internal/v2/analysis-jobs/{analysisId}` | UUID | 200 AnalysisJob | 分析对账 |
| POST `/internal/v2/analysis-jobs/by-request` | `{requestIds:UUID[]}`，1..100 | 200 `{tasks:AnalysisJob[],missingRequestIds:UUID[]}` | 丢失创建响应 |
| POST `/internal/v2/profile-jobs` | ProfileJobRequest | 202 ProfileJob；重放200 | 四窗口异步计算 |
| GET `/internal/v2/profile-jobs/{profileJobId}` | UUID | 200 ProfileJob | 画像对账 |
| POST `/internal/v2/profile-jobs/by-request` | `{requestIds:UUID[]}`，1..100 | 200 `{tasks:ProfileJob[],missingRequestIds:UUID[]}` | 丢失创建响应 |
| POST `/internal/v2/recommendations` | LearningRecommendRequest | 200 LearningRecommendResponse | 无业务写入、同步排序 |
| GET `/internal/v2/capabilities` | 无 | 200 AlgorithmCapabilities | 真实工具/版本能力 |

接收/查询总超时 5 秒，连接 2 秒；推荐算法 8 秒计算预算，后端单次10秒，仅连接/超时/502/503/504重试一次相同requestId/body，整个公开生成预算25秒，frontend/browser30秒。profile 和静态分析受算法自身有限执行预算，超时以 FAILED/task.error 结束，不要求浏览器长连接。以下完整 DTO 经算法负责人冻结，与其文档完全一致。

```ts


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
interface AlgorithmHealth {
  status: "ok" | "unavailable"; service: "algorithm"; contractVersion: "v1";
  algorithmVersions: string[]; mappingVersions: string[];
  apiContractVersion: "0.2.0"; capabilities: {llmReport:boolean; staticAnalysis:boolean};
}
interface AlgorithmCapabilities {
  contractVersion: "0.2.0"; toolchainVersion: "static-v0.2.1";
  analysisLanguages: string[]; tools: StaticToolCapability[];
  profileVersions: string[]; recommendationVersions: string[];
}
```


- Id 正十进制字符串，sourceFingerprint/resultHash/configSha256/sourceSha256 是64位小写hex；version不接受静默回退。
- `eventKey`：PLATFORM=`startrack:<submissionId>`、EXTERNAL=`codeforces:<externalSubmissionId>`，CF原提交ID由backend填入eventKey，本DTO不再重复发原字段。平台accountId=null；外部accountId必须在accounts中。跨CF重复eventKey仅在 problem身份、verdict、submittedAt一致时折叠，代表submissionId取数值最小值；冲突422 INVALID_INPUT。每window source计数使用折叠事件，不能把两个CF团队账号双计。
- 判题非终态QUEUED/DISPATCHING/RUNNING可作PENDING输入；COMPLETED映射旧Verdict。平台任意FAILED（包括未创建任务的本地拒绝）及CANCELLED不作为能力提交输入、不作为失败训练；源码仍可在提交历史读。训练记录planned不属于submission。
- Problem身份为(source,platform,problemId)；版本只影响冻结元数据。problems覆盖每个输入完整ProblemRef，PLATFORM多个历史版本可并存；同一窗口同题多个版本统计用该窗口最后提交 `(submittedAt,submissionId数值)` 的元数据，不合并成两题。AC去重不含version。externalRef version恒null。
- codeAnalysisFeatures每平台submission最多一份最近可用SUCCEEDED/PARTIAL可复现分析事实（backend usable_analysis_id/revision），只接受SUCCEEDED/PARTIAL，submission须在输入并属PLATFORM，计数非负。不传源码/完整finding消息进profile。warning/error不是已验证Bug事实。
- analyses恰好4项同请求顺序。sources计数每window去重后计算，platform+external=summary.submissionCount；sourceAccountIds为accounts全部ID按数字排序（四窗口一致）；codeAnalysisCount=codeQuality.analyzedSubmissionCount，为该window提交中有可用静态分析的去重次数。
- codeQuality计可用feature findingCounts.warning/error之和，maxCyclomaticComplexity取可用数值最大，无证据null。分析未就绪时codeQuality=零计数/null，不阻塞四窗口画像；之后backend featuresVersion变化重建。
- 新summary及dimensions中rating平均/最高只取difficultyScale=CF_RATING；其他尺度题按unratedSolvedCount计，不能把PLATFORM_RATING放入CF均分。difficultyStats按(scale,difficulty)独立分桶；UNRATED必须difficulty=null，其余必须正整数。currentRating/maxRating取accounts非null最大值，与旧多CF语义相同。
- LIZARD/CLANG_TIDY/INFER/CPD 为C/C++适配能力；RADON仅Python，PMD规则仅Java，CPD与PMD是分开能力。初版analysisLanguages必须含cpp17，c11可选；java/python未部署不可列入可用analysisLanguages。tools始终六项，enabled=false的version仍填发布清单锁定版本，不代表安装可运行，languageIds表示适配器支持范围，顶层analysisLanguages表示本部署真实可请求。disabled工具ToolRun=SKIPPED并给TOOL_DISABLED。

### 7.1 新六维确定公式（learning-profile-v0.2.1）

沿用旧映射：题对维度w为匹配tags的最大权重，同维度多个标签不累加。同window去重AC题：
`S=Σw`；CF_RATING `quality=clamp((difficulty-600)/2400,0,1)`；PLATFORM_RATING及UNRATED `quality=0`（本版仅贡献完成量，不伪造跨尺度难度）。`Q=S=0?0:Σ(w*quality)/S`；`coverage=min(S/20,1)`；`score=round2(100*(0.6*Q+0.4*coverage))`；overallScore=round2六分均值。纯CF输入和旧公式相同。codeQuality独立，不影响六维。rankOrder分数升序、displayOrder平局；空数据六维0且weakest=IMPLEMENTATION。

### 7.2 新推荐确定公式（learning-recommend-v0.2.1）

backend基础过滤全部合法目录，algorithm按source再次过滤，去除已AC Problem身份、*special/*broken，不自动造新题。难度目标按尺度独立：CF目标取profile.averageSolvedDifficulty??currentRating??800，roundHalfUp最近100再clamp[800,3500]；平台目标取ALL difficultyStats中PLATFORM_RATING已AC题按solvedCount加权平均（没有样本则null），roundHalfUp最近100且最低100，不凭CF目标推平台目标。

有同尺度目标的rated候选仅保留±200（闭区间），`D=1-abs(difficulty-target)/400`。LEVEL只接收有可比目标的rated候选；WEAKNESS/HYBRID在平台目标为null或UNRATED时可以保留，D固定0.5，并由固定reason文案注明未评级/平台评级不足。WEAKNESS仍仅保留最弱维度w>0。

`W=max_d(w_d*(1-profile.dimensions[d].score/100))`；`T=候选tags中未在profile.tagStats出现solvedCount>0的比例，空tags=0`；`R=同Problem身份最近7日推荐过?0.15:0`。LEVEL score=D；WEAKNESS score=0.6D+0.4w_weakest；HYBRID score=clamp(0.5D+0.35W+0.15T-R,0,1)。所有score先round6；跨source只比较归一化score，不比较原始rating。排序score DESC、同尺度目标绝对差ASC（无目标用固定200）、source PLATFORM在前、platform字典序、problemId数值ASC；rank连续1..N、N=min(limit,candidateCount)。无候选200空数组。

matchedDimension及reasonCode沿旧语义；无同尺度目标优先reasonCode=DEFAULT_RECOMMENDATION，backend按problem.difficultyScale输出固定补充说明，不宣称难度匹配。HYBRID codeQuality仅提供后续报告证据，本版不从静态warning自动推断知识点弱项或改变排名。数组顺序不影响结果，舍入使用十进制ROUND_HALF_UP。


## 8. 源冻结、恢复与版本

学习指纹是 SHA256(JCS/RFC8785规范JSON)：`{contractVersion,algorithmVersion,mappingVersion,accounts,externalCatalogVersion,platformCatalogVersion,platformTrainingVersion,analysisFeaturesVersion}`。accounts 按 accountId 数值升序的 `{accountId,dataVersion,bindStatus}`；计数版本为十进制 string，无目录同步为 "0"，用户训练/特征版本初值 "1"。externalCatalogVersion 是 backend 新增单调计数，旧目录实际有内容变化的成功 sync job(UUID) 推进一次并保留映射，0变化不推进，不能把 UUID 硬转 Id。platformCatalogVersion 来自已完整拉取的 judge 快照，不使用半页版本。

每次冻结在短 REPEATABLE READ 事务读取源/版本/完整四窗口输入后释放事务。submittedAt<dataCutoffAt。后端构造全量提交、ProblemSummary 关联、去重 CF event、可用分析特征以及版本；代码分析不传真实用户名/邮箱给算法。完成时重新核对版本+当前源集合；变化不提交，旧画像继续可读且 stale，重新合并排队。stale还包含 24 小时过期、INVALID源、同步在途、当前版本不匹配。summary平均/最高难度及ratedSolvedCount只用CF_RATING；其他尺度计unratedSolvedCount且分桶保留本尺度，不跨尺度相加做平均。

提交受理事务同时写 platform_submissions、source、training link、唯一 dispatch/outbox；租约 worker 重启扫描恢复。POST下游超时先按原 requestId调用by-request；查到task则绑定，missing才以同requestId重发，不能另造新judge任务。每个逻辑dispatch最多3次派发，之后先按原requestId对账；已接收任务继续轮询，仍无法确认接收则本地FAILED、judgeTaskId=null/result=null、judgeError=JUDGE_UNAVAILABLE或JUDGE_TIMEOUT且retryable=true，保留原requestId恢复线索。后续迟到真实任务结果只能经原dispatch身份验证/有记录的恢复流程落入，不能当新的用户提交。后台任务lease失效旧worker不得回写；callback每项事务校验task身份+revision。源码、任务和历史不因下游失败丢失。下游明确400/409/413/422拒绝且未创建task时，本地FAILED、无judgeResult、不伪造IE，judgeError原码/retryable=false（包括题版本/撤题竞态）；远程FAILED真实IE结果与error投影，成功或在途judgeError=null。analysis/profile派发明确拒绝同样FAILED，GET仍200。

对接收结果不确定的网络故障，派发3次耗尽仅结束当前派发尝试：Submission可本地FAILED显示可恢复judgeError，dispatch.reconciliation_required=true，仍每30秒by-request对账且保留回调入口。查到原requestId的task后原子绑定sourceId、清除本地dispatch错误，并同步该真实task状态（可由本地FAILED转RUNNING/COMPLETED/远程FAILED）；这是接收不确定状态恢复，不是修改已完成JudgeTask事实。明确4xx拒绝设置reconciliation_required=false，不能复活。不存在新Submission或第二个judge requestId；恢复后按有效训练事实推进版本。分析旧attempt与已终结profile的迟到事件只归档，不替换新的当前attempt/已发布新画像。

平台有效 judge 状态/结果变化递增 platformTrainingVersion，重复事件不增；每次新Submission受理也递增以反映pending；训练计划/状态业务变化同样递增。成功/PARTIAL分析投影替换递增analysisFeaturesVersion，纯状态轮询不增。judge完成先合并基础profile任务，分析完成再合并特征profile；新画像四窗口全成，推荐读取最后未stale ALL。

## 9. 新错误表（旧错误完整保留）

| HTTP | code | 场景/处理 |
|---|---|---|
| 400 | INVALID_ARGUMENT、INVALID_PROBLEM_REF | 修正类型、筛选、源码或来源组合 |
| 401 | SESSION_EXPIRED、SERVICE_UNAUTHORIZED | 用户重登录 / 内部caller鉴权错误 |
| 403 | ROLE_REQUIRED、ORIGIN_REJECTED | 角色不足、写请求来源不符 |
| 404 | PROBLEM_NOT_FOUND、SUBMISSION_NOT_FOUND、TASK_NOT_FOUND、TRAINING_RECORD_NOT_FOUND | 不存在或无权访问同形返回 |
| 409 | IDEMPOTENCY_CONFLICT、REQUEST_IN_PROGRESS | key参数冲突 / 尚无对象可重放 |
| 409 | PROBLEM_VERSION_CONFLICT、PROBLEM_NOT_SUBMITTABLE、LANGUAGE_NOT_SUPPORTED | 版本/撤题/语言不符合，刷新题面能力 |
| 409 | DATA_CHANGED、PROFILE_NOT_READY | 源变化或无可用ALL画像，重建后生成 |
| 409 | ANALYSIS_ALREADY_COMPLETE、ANALYSIS_NOT_RETRYABLE、EVENT_CONFLICT | 分析已完/不能重试/回调同revision冲突 |
| 410 | SNAPSHOT_EXPIRED | 整个目录重拉 |
| 413 | SOURCE_TOO_LARGE、INPUT_TOO_LARGE | 超大小，不静默截断 |
| 422 | PACKAGE_INVALID、PACKAGE_LICENSE_MISSING、PACKAGE_UNSUPPORTED、ALGORITHM_VERSION_MISMATCH、INVALID_INPUT | 新内部题包/版本错误 |
| 429 | RATE_LIMITED | Retry-After秒数，后端统一限流 |
| 502 | JUDGE_BAD_RESPONSE、ALGORITHM_BAD_RESPONSE | 下游非法DTO/校验失败 |
| 503 | JUDGE_UNAVAILABLE、ALGORITHM_UNAVAILABLE、ALGORITHM_BUSY | 下游网络/服务故障 |
| 504 | JUDGE_TIMEOUT、ALGORITHM_TIMEOUT | 请求超时；同key/内部requestId恢复 |
| 500 | INTERNAL_ERROR | requestId用于定位 |

下游 422 的版本问题对 Browser 映射502 ALGORITHM_VERSION_MISMATCH（旧同名映射保留），题包校验管理请求可返回422；本地用户语言/版本错误仍409。异步任务失败放 TaskError，GET本身200，不能让客户端把业务FAILED当“轮询网络失败”。Judge TaskError允许JUDGE_INTERRUPTED、SANDBOX_FAILURE、PACKAGE_VALIDATION_FAILED、PACKAGE_SOURCE_UNAVAILABLE；TaskError允许TOOL_DISABLED、TOOL_LANGUAGE_UNSUPPORTED、TOOL_PARSE_FAILED、TOOL_COMPILE_CONTEXT_INVALID、TOOL_TIMEOUT、ANALYSIS_PARTIAL、ANALYSIS_NO_USABLE_RESULT、ANALYSIS_RESULT_TOO_LARGE、TOOL_OUTPUT_LIMIT、TASK_INTERRUPTED，保留工具失败/跳过语义，不映射为用户判题失败。resultHash=SHA256(JCS完整StaticAnalysisResult去掉resultHash本身)。日志无源码全文、Cookie、token、题包隐藏测试、SQL、敏感provider报错。

## 10. 兼容升级决策

| 历史方案 | V0.2处理与原因 |
|---|---|
| v0.1 无认证任意user_id、单CF绑定、memory_kb、全平台submission唯一、每日四tag画像 | 已由V0.11升级；不恢复旧限制/错误单位/裸身份入口，迁移保留ID，memory_bytes依据原CF字节校准；不能假定既有memory_kb实际可信 |
| V0.11多CF、账号同步/画像/推荐 | 下面完整签名保留；不往旧Submission非空accountId塞平台记录 |
| V0.12多CF用户画像、团队/隐私/报告/通知 | 保持CF-only语义、原版本/DTO/状态；新增综合接口，旧界面不用改即可继续运行 |
| 旧 algorithm 无持久化 | 旧纯计算路径不变，新DB仅分析/profile执行证据与恢复，不迁移业务画像主表 |
| 旧仅backend数据库写入口 | 旧表仍backend独占；新增judge/algorithm各自schema独占，不跨owner写业务表 |
| 旧team coverage限制/targetRating空判断矛盾 | coverage与ability授权集合独立，coverageMemberCount≤memberCount；targetRating=null iff levelMemberCount=0，不改DTO |

## 11. 审核后保留的旧公开契约（完整签名）

以下兼容附录保留历史章节名称与编号，已在本文件声明的公共类型直接复用，不重复定义。

以下保留V0.11与V0.12已经开发使用的字段、枚举、端点与权限规则。路径仍加 `/api/v1`。新增能力不要复用旧DTO改变含义。已删去旧部署模板/工程目录/重复实现说明；业务契约保留以便负责人独立实现。

### 公共 DTO

```ts
 // PostgreSQL bigint 的十进制正整数字符串；禁止转 JS number
 // 标准 UUID 字符串
 // ISO 8601 UTC，例 2026-10-02T02:30:00Z
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



```


### 认证与用户 API

请求体记法 `{field: Type}` 为完整 JSON 类型，不是示例 JSON；所有 string 默认必填且非空。用户名为 3–32 位 ASCII 字母、数字、下划线，大小写不敏感；密码 12–128 字符，不 trim；邮箱 trim 后小写参与唯一性比较。邮箱代码为 6 位数字字符串。

| 方法与路径 | Request | 成功状态及响应 T |
| ------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| POST /auth/captcha | 无 | 200`{challengeId: UUID, imageData: string, expiresInSeconds: number}`；imageData 为 PNG data URL（base64）；有效 180 秒，一次性 |
| POST /auth/email-codes | `{email: string, purpose: "REGISTER"\|"PASSWORD_RESET"\|"EMAIL_CHANGE_OLD"\|"EMAIL_CHANGE_NEW", captchaChallengeId: UUID, captchaAnswer: string}` | 202`{verificationId: UUID, cooldownSeconds: number, expiresInSeconds: number}`；60、600 秒 |
| POST /auth/register | `{username: string, email: string, password: string, verificationId: UUID, emailCode: string}` | 201`{user: UserDto}`；验证邮箱、注册并登录，默认 STUDENT |
| POST /auth/login | `{account: string, password: string, captchaChallengeId: UUID, captchaAnswer: string}` | 200`{user: UserDto, requiresOjBinding: boolean}`；account 为用户名或邮箱；无 ACTIVE/INVALID 绑定才需绑定 |
| POST /auth/logout | 无 | 204；当前 Session 撤销，无有效会话也成功 |
| POST /auth/logout-all | 无 | 200`{revokedSessions: number}`；所有设备下线 |
| GET /me | 无 | 200 UserDto |
| GET /me/roles | 无 | 200`{primaryRole: string, roles: Array<{code: string, name: string}>}` |
| POST /me/password/change | `{currentPassword: string, newPassword: string}` | 200`{changed: true, reauthRequired: true}`；全部会话撤销 |
| POST /auth/password/reset | `{email: string, verificationId: UUID, emailCode: string, newPassword: string}` | 200`{reset: true}`；全部会话撤销 |
| POST /me/email/change | `{password: string, oldEmail: string, oldVerificationId: UUID, oldEmailCode: string, newEmail: string, newVerificationId: UUID, newEmailCode: string}` | 200`{email: string, emailVerified: true, reauthRequired: true}`；全部会话撤销 |

图形验证码每次发送邮箱代码、每次登录都需要；错误或提交后刷新 challenge。邮件发送按同邮箱跨用途至少 60 秒一次，并按 IP 限流；错误时返回 429 和 Retry-After 秒数。更换邮箱的两个用途必须登录，OLD 必须等于当前邮箱，NEW 必须未占用；最终换邮箱同时验证密码、旧/新两份未过期代码与所属用户。验证码最多错误 5 次、有效 600 秒、一次性事务消费。注册已含邮箱验证，邮箱验证页面用于录入验证码，不另造未定义的验证端点。找回密码邮件端点对不存在的邮箱也返回同形 202，使用不可兑换的 verificationId，不泄漏存在性。


### 多 CF 账号、同步 API

一个用户可同时绑定多个不同 CF。handle trim、小写仅用于冲突比较，显示以 user.info 返回的 canonical handle 为准；有效绑定包括 ACTIVE 和 INVALID。同一有效 CF 只能属于一个用户。绑定是公开数据关联，不宣称已经验证用户掌握该 CF 登录凭据。

每次解绑永久结束本次绑定，保留旧 accountId 的历史和原 userId；之后任何用户重新绑定已释放 handle 都新建 accountId，从公开 CF 数据重新同步，不转移旧快照、同步任务、推荐历史。原用户重绑也新建记录。有效占用时其他用户绑定返回 409 OJ_ACCOUNT_OWNERSHIP_CONFLICT；同用户重复绑定返回 409 OJ_ACCOUNT_ALREADY_BOUND，details.accountId 指向现有记录。INVALID 仍占位，可手动重试同步；短暂上游网络失败不改为 INVALID。

| 方法与路径 | Request / Query | 成功状态及响应 T |
| ---------------------------------------------- | ---------------------------------------------- | ------------------------------------------------------------------------------------------- |
| POST /oj-accounts | `{platform: "codeforces", username: string}` | 201`{account: OjAccountDto, initialSync: SyncJobDto}`；绑定和创建 QUEUED 任务同一事务 |
| GET /oj-accounts | `includeUnbound=false`，boolean，分页参数 | 200 Page<OjAccountDto></ojaccountdto>；默认 ACTIVE/INVALID，按 boundAt DESC、accountId DESC |
| GET /oj-accounts/{accountId} | 无 | 200 OjAccountDto；可读自己 UNBOUND 历史 |
| DELETE /oj-accounts/{accountId} | 无 | 204；幂等软解绑；停止后续写入与定时同步 |
| POST /oj-accounts/{accountId}/sync | 无 | 202 SyncJobDto，ACCOUNT_FULL；已有 QUEUED/RUNNING 时返回同一任务 |
| GET /sync-jobs/{jobId} | 无 | 200 SyncJobDto；普通用户仅能读取自己账号任务 |
| GET /oj-accounts/{accountId}/sync-status | 无 | 200 SyncStatusDto |
| POST /oj-accounts/{accountId}/analysis/rebuild | 无 | 202 SyncJobDto，ANALYSIS_ONLY；一次重建四个窗口，已有在途账号任务则返回该任务 |

手动同步/重建在无在途任务时，每 accountId 至少间隔 60 秒，否则 429 SYNC_RATE_LIMITED。UNBOUND 可以读历史，sync/rebuild/recommendations/generate 返回 409 OJ_ACCOUNT_UNBOUND。INVALID 可以手动同步和解绑，rebuild/generate 返回 409 OJ_ACCOUNT_INVALID。lastSyncedAt 表示 USER_INFO、SUBMISSIONS、RATING_HISTORY 全部成功的时间，不依赖分析是否成功。

QUEUED/RUNNING 为处理中，SUCCESS 为全部完成，PARTIAL 为有成功阶段/已提交数据但部分失败，FAILED 为无任何可保留成功阶段。errors 是数组，失败项明确 stage/code/retryable；分析服务故障显示 ANALYSIS 阶段错误，已经同步的提交仍可查询。只重建分析不会修改 lastSyncedAt。


### 账号数据与统计 API

以下每条路径都要求 accountId，不提供隐式“当前唯一账号”。

| 方法与路径 | Query（均可省略） | 成功状态及响应 T |
| -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
| GET /oj-accounts/{accountId}/problems | 分页；status=ALL（ALL/SOLVED/UNSOLVED），tag 精确匹配，minDifficulty/maxDifficulty 整数，sort=LAST_SUBMITTED_DESC（唯一排序值） | 200 Page<ProblemProgressDto></problemprogressdto> |
| GET /oj-accounts/{accountId}/submissions | 分页；verdict: Verdict，problemId: Id，from/to: Instant | 200 Page<SubmissionDto></submissiondto> |
| GET /oj-accounts/{accountId}/rating-changes | 分页 | 200 Page<RatingChangeDto></ratingchangedto> |
| GET /oj-accounts/{accountId}/training/overview | window=30D（AnalysisWindow） | 200 AnalysisDto 或 null |
| GET /oj-accounts/{accountId}/analysis/latest | window=ALL（AnalysisWindow） | 200 AnalysisDto 或 null |
| GET /oj-accounts/{accountId}/analysis/history | window=ALL，分页 | 200 Page<AnalysisDto></analysisdto> |
| GET /oj-accounts/{accountId}/analysis/{snapshotId} | 无 | 200 AnalysisDto |
| GET /oj-accounts/{accountId}/dashboard | 无 | 200 DashboardDto |

做题列表只含当前 accountId 有提交的题，按 lastSubmittedAt DESC、problemId DESC；SOLVED 为全历史至少一次 AC，UNSOLVED 为有提交且从未 AC。难度过滤时 null 不匹配，两个边界包含且 min≤max。提交列表按 submittedAt DESC、submissionId DESC；from 包含、to 不包含，无边界代表不限。Rating 列表按 occurredAt DESC、contestId DESC。分析历史按 dataCutoffAt DESC、createdAt DESC、snapshotId DESC，最新使用同序取第一条。不存在 snapshotId 返回 404 RESOURCE_NOT_FOUND。

training/overview 返回完整 AnalysisDto，直接使用 summary 和三个 Stats；与 analysis/latest 在同一 accountId/window 下必须取同一快照。未生成返回 data=null；已分析但没提交则返回零统计快照。stale 表示快照 sourceDataVersion 与账号当前数据版本不一致、分析/映射版本不匹配或 dataCutoffAt 距当前超过 24 小时；历史数据如实展示。Dashboard 使用最新 ALL 快照与最新 HYBRID 批次，无数据字段为 null；优先 nextAction：在途任务 WAIT_SYNC → 无成功同步或最近一次 ACCOUNT_FULL 数据阶段失败 SYNC → 无画像或画像过期 REBUILD_ANALYSIS → 无推荐或推荐过期 GENERATE_RECOMMENDATIONS → NONE。INVALID 返回 SYNC，UNBOUND 返回 NONE。


### 题目推荐 API

| 方法与路径 | Request / Query | 成功状态及响应 T |
| ------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------- |
| POST /oj-accounts/{accountId}/recommendations/generate | `{mode?: RecommendationMode, limit?: number}`；默认 HYBRID、10，limit 整数 1..50；必需 `Idempotency-Key: UUID` | 首次 201 RecommendationBatchDto；同 key 重放 200 原批次 |
| GET /oj-accounts/{accountId}/recommendations/latest | mode=HYBRID | 200 RecommendationBatchDto 或 null |
| GET /oj-accounts/{accountId}/recommendations/history | mode 可省略（省略=所有模式），分页 | 200 Page<RecommendationBatchDto></recommendationbatchdto> |
| GET /oj-accounts/{accountId}/recommendations/{batchId} | 无 | 200 RecommendationBatchDto |

推荐只能基于该 accountId 最新、未过期、完整 ALL 画像；无可用画像为 409 PROFILE_NOT_READY。WEAKNESS 自动取 weakestDimension，V0.11 不提供手动维度覆盖。LEVEL/WEAKNESS/HYBRID 由算法排序；前端不计算目标难度和排名。候选池来自完整题库并排除当前账号已 AC；不足 limit 时返回实际数量，包括 0 项成功批次，显示“当前难度范围暂无候选题”，不展示服务异常。

Idempotency-Key 为一次点击生成的 UUID；网络失败重试复用，同 key 不同 mode/limit 返回 409 IDEMPOTENCY_CONFLICT。同 key 在途返回 409 REQUEST_IN_PROGRESS，Retry-After: 2。失败未提交批次可使用相同 key 重试。成功历史批次不可变；后续已 AC 的题仍保留原 rank 并标 solvedSinceGeneration=true，latest/history 不触发新计算。stale 为关联画像 stale=true、analysisSnapshotId 已不是当前最新 ALL、推荐/映射版本不匹配、sourceDataVersion 与账号不一致或生成超过 24 小时。排序为 generatedAt DESC、batchId DESC。非法 batchId 或不属于当前账号返回 404 RESOURCE_NOT_FOUND。


### 公共错误码

所有错误都有 ApiError；details 默认为 `{}`，字段校验错误可含 `{fields: Array<{field: string, reason: string}>}`。

| HTTP | code | 客户端行为 |
| ---- | ----------------------------------------------------------------------------------------------------------------- | ----------------------------------- |
| 400 | INVALID_ARGUMENT、INVALID_ANALYSIS_WINDOW、INVALID_RECOMMENDATION_MODE、PLATFORM_NOT_SUPPORTED、PASSWORD_TOO_WEAK | 修正输入 |
| 400 | CAPTCHA_INVALID、CAPTCHA_EXPIRED、EMAIL_CODE_INVALID、EMAIL_CODE_EXPIRED | 刷新验证码或重新获取邮件代码 |
| 401 | INVALID_CREDENTIALS、SESSION_EXPIRED | 登录失败提示或跳转登录 |
| 403 | ACCOUNT_LOCKED、ACCOUNT_DISABLED、FORBIDDEN、ORIGIN_REJECTED | 停止受限操作 |
| 404 | OJ_ACCOUNT_NOT_FOUND、RESOURCE_NOT_FOUND、SYNC_JOB_NOT_FOUND、CF_ACCOUNT_NOT_FOUND | 刷新列表或核对 handle |
| 409 | USERNAME_ALREADY_EXISTS、EMAIL_ALREADY_REGISTERED、OJ_ACCOUNT_ALREADY_BOUND、OJ_ACCOUNT_OWNERSHIP_CONFLICT | 显示占用提示 |
| 409 | OJ_ACCOUNT_UNBOUND、OJ_ACCOUNT_INVALID、PROFILE_NOT_READY、SYNC_REQUIRED、DATA_CHANGED | 刷新账号/同步状态，必要时同步或重建 |
| 409 | IDEMPOTENCY_CONFLICT、REQUEST_IN_PROGRESS | 复用正确 key 或稍后重试 |
| 429 | EMAIL_CODE_RATE_LIMITED、SYNC_RATE_LIMITED、RATE_LIMITED | 按 Retry-After 秒数倒计时 |
| 502 | UPSTREAM_CODEFORCES_UNAVAILABLE、ALGORITHM_BAD_RESPONSE、ALGORITHM_VERSION_MISMATCH | 保留已有数据，允许重试 |
| 503 | ALGORITHM_UNAVAILABLE、EMAIL_DELIVERY_FAILED | 保留已有数据，允许重试 |
| 504 | UPSTREAM_CODEFORCES_TIMEOUT、ALGORITHM_TIMEOUT | 使用同一 key 重试生成 |
| 500 | INTERNAL_ERROR | 展示 requestId，允许重试 |

异步任务中的错误存入 errors，不把轮询 GET 变成 5xx：上述上游/算法码以及 SUBMISSION_PARSE_FAILED、SYNC_INTERRUPTED、OJ_ACCOUNT_UNBOUND、DATA_CHANGED、SYNC_REQUIRED 可出现在任务错误中。JobError.retryable 在上游/算法不可达或超时、SYNC_INTERRUPTED、DATA_CHANGED 时为 true；解析、非法 DTO、版本、身份及输入问题为 false，需要先修复数据或配置再发新任务。返回日志信息必须去除 token、邮箱代码、SQL 和堆栈。


### reasonCode 与固定展示文案

| reasonCode | reason |
| ---------------------- | ---------------------------------- |
| WEAK_DIMENSION_MATCH | 这道题覆盖你当前相对薄弱的能力。 |
| LEVEL_MATCH | 这道题的难度与你当前训练水平接近。 |
| SLIGHTLY_ABOVE_LEVEL | 这道题略高于你的当前训练水平。 |
| TAG_MATCH | 这道题包含适合你训练的知识标签。 |
| BALANCED_PRACTICE | 这道题兼顾难度与能力覆盖。 |
| RECENT_WEAKNESS | 这道题适合巩固近期较少训练的能力。 |
| LOW_ATTEMPT_COVERAGE | 这道题包含你尚未完成过的知识标签。 |
| RATING_GROWTH_STEP | 这道题适合作为提高难度的下一步。 |
| MIXED_SKILL_MATCH | 这道题可以练习多种能力的组合。 |
| DEFAULT_RECOMMENDATION | 这道题适合作为下一道练习题。 |


### 3. V0.12 新增公共 DTO

```ts






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

interface TeamDetailDto extends TeamSummaryDto {
  creator: UserBriefDto;
  canManage: boolean;
  canLeave: boolean;
  activeMemberCount: number;
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
  inviteeEmail: string | null; // 仅 OWNER 管理列表返回完整值；被邀请用户列表为 null
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

// Summary/TagStat/DifficultyStat/ActivityStat/DimensionScore 与 V0.11 完全一致。
interface UserAnalysisDto {
  publicId: UUID;
  snapshotId: UUID;
  window: AnalysisWindow;
  period: {start: Instant | null; end: Instant};
  summary: Summary;
  currentRating: number | null; // 所有参与账号 currentRating 的最大值
  maxRating: number | null;     // 所有参与账号 maxRating 的最大值
  ratingAccounts: UserRatingAccountDto[];
  overallScore: number;
  dimensions: DimensionScore[];
  weakestDimension: DimensionCode;
  tagStats: TagStat[];
  difficultyStats: DifficultyStat[];
  activityStats: ActivityStat[];
  sourceAccountCount: number;
  sourceAccountIds: Id[];
  sourceFingerprint: string; // 64 位 hex SHA-256
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

interface AiJobErrorDto {
  code: string;
  message: string;
  retryable: boolean;
}

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
  problem: ProblemDto; // 复用 V0.11
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
```


### 4. 身份与角色 API

V0.11 `GET /me` 与 `GET /me/roles` 继续使用，不新增“切换角色”状态。前端根据 `roles` 同时开放学生端与教练端导航。

#### 4.1 管理员人工授予/撤销 COACH

| 方法与路径 | 权限 | Request | 成功响应 |
|---|---|---|---|
| PUT `/admin/users/{publicId}/roles/COACH` | ADMIN | 无 | 200 `{user: UserDto}` |
| DELETE `/admin/users/{publicId}/roles/COACH` | ADMIN | 无 | 204 |

规则：

- PUT 幂等；已有 COACH 仍返回 200。
- DELETE 若用户是任意 ACTIVE/ARCHIVED 团队 owner，返回 409 `COACH_OWNS_TEAM`，必须先转让/解散；数据库约束也做同样兜底，不能只依赖 Controller 检查。
- STUDENT 不因授予 COACH 被移除。
- V0.12 不要求做完整 Admin UI，可由内部管理页面或 curl 调用。

#### 4.2 教练邀请码（P2）

| 方法与路径 | 权限 | Request / Query | 成功响应 |
|---|---|---|---|
| POST `/admin/coach-invite-codes` | ADMIN | `{organization: string\|null, maxUses: number, expiresAt: Instant}` | 201 `{codeId: UUID, code: string, organization: string\|null, maxUses: number, usedCount: 0, expiresAt: Instant, enabled: true}`；明文 code 仅此时返回 |
| GET `/admin/coach-invite-codes` | ADMIN | page/pageSize, enabled? | 200 Page`<{codeId,codePrefix,organization,maxUses,usedCount,expiresAt,enabled,createdAt}>` |
| PATCH `/admin/coach-invite-codes/{codeId}` | ADMIN | `{enabled: boolean}` | 200 同列表项 |
| POST `/coach-invite-codes/redeem` | 登录 | `{code: string}` | 200 `{user: UserDto}` |

兑换成功后 `/me` 同时包含 STUDENT+COACH。


### 5. 团队基础 API

#### 5.1 创建、列表、搜索、详情

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

创建团队事务：

1. 校验当前用户有效 COACH。
2. INSERT team。
3. INSERT 当前用户 ACTIVE OWNER team_member。
4. 提交后返回详情。

状态规则：

- ARCHIVED/DISSOLVED 不允许新申请、邀请或普通成员变更。
- archive 事务将现有 PENDING join application / invitation 统一转为 CANCELLED；已注册/已关联用户分别收到 `JOIN_APPLICATION_CANCELLED` / `TEAM_INVITATION_CANCELLED`，重新 activate 后必须重新申请/邀请。
- DISSOLVED 不可恢复；dissolve 事务取消全部 PENDING 流程，并结束所有 ACTIVE membership（含 OWNER）为 REMOVED，endReason=`TEAM_DISSOLVED`。`teams.ownerUserId` 仅保留最后负责人历史。
- transfer 的新 owner 必须是该团队 ACTIVE member 且具有 COACH；事务中旧 OWNER→MEMBER、新成员→OWNER、更新 `teams.owner_user_id`。
- dissolve 前端必须二次确认；后端仍要求 confirmation 精确等于团队名称，防止仅靠前端确认。


### 6. 团队成员 API

| 方法与路径 | 权限 | Request / Query | 成功响应 |
|---|---|---|---|
| GET `/teams/{teamId}/members` | OWNER；P2 可开放普通成员 | status=ACTIVE 默认；分页 | 200 Page<TeamMemberDto> |
| DELETE `/teams/{teamId}/members/{memberPublicId}` | OWNER | `{reason?: string}` | 204 |
| POST `/teams/{teamId}/leave` | ACTIVE MEMBER（非 OWNER） | 无 | 204 |

- OWNER 不可 remove 自己，也不可普通 leave；返回 409 `TEAM_OWNER_CANNOT_LEAVE`。
- remove 成功将 membership 标 REMOVED，记录 `endedBy/endedAt`，并给被移除用户创建 `MEMBER_REMOVED` 通知。
- leave 标 LEFT。
- 再加入时创建新 membership，不复活历史行。


### 7. 学生加入申请 API

#### 7.1 学生侧

| 方法与路径 | Request | 成功响应 |
|---|---|---|
| POST `/teams/{teamId}/applications` | `{message?: string}` | 201 JoinApplicationDto |
| GET `/me/team-applications` | page/pageSize，status? | 200 Page<JoinApplicationDto> |
| POST `/team-applications/{applicationId}/cancel` | 无 | 200 JoinApplicationDto |

规则：

- 同一团队同一用户只能一个 PENDING。
- 已是 ACTIVE member 返回 409 `TEAM_ALREADY_MEMBER`。
- ARCHIVED/DISSOLVED 返回 409 `TEAM_NOT_JOINABLE`。
- 创建成功时给 owner 创建 `JOIN_APPLICATION_CREATED` 通知。

#### 7.2 教练审批

| 方法与路径 | 权限 | Request | 成功响应 |
|---|---|---|---|
| GET `/teams/{teamId}/applications` | OWNER | status=PENDING 默认；分页 | 200 Page<JoinApplicationDto> |
| POST `/team-applications/{applicationId}/approve` | 对应团队 OWNER | 无 | 200 JoinApplicationDto |
| POST `/team-applications/{applicationId}/reject` | 对应团队 OWNER | `{reason?: string}` | 200 JoinApplicationDto |

approve 事务必须：

1. 行锁 PENDING application。
2. 再校验申请人当前非 ACTIVE member。
3. 创建 ACTIVE MEMBER。
4. application → APPROVED，`decisionReason=null`。
5. 给申请人写 `JOIN_APPLICATION_APPROVED`，给 owner 可选写 `MEMBER_JOINED`。
6. 同事务提交。

所有“approve application / accept invitation / leave / remove”涉及同一 `(teamId,userId)` 的成员变更必须先获取同一个数据库 advisory transaction lock；如果另一条路径已经创建 ACTIVE membership，本事务不得再创建第二条。某条加入路径成功后，Backend 同事务取消该用户在同团队其余 PENDING application/invitation，避免“已经入队但另一张邀请仍显示待处理”。

reject 事务必须把 application → REJECTED、保存可选 `decisionReason`，并在同一事务给申请人写 `JOIN_APPLICATION_REJECTED`。学生主动 cancel 把 application → CANCELLED；团队 archive 导致的取消由 archive 事务写 `JOIN_APPLICATION_CANCELLED` 给受影响申请人。

非 PENDING 再次 approve/reject/cancel 返回 409 `APPLICATION_ALREADY_PROCESSED`。


### 8. 团队邀请 API

#### 8.1 Owner 创建/管理邀请

| 方法与路径 | Request | 成功响应 |
|---|---|---|
| POST `/teams/{teamId}/invitations` | `{email: string}` | 201 TeamInvitationDto |
| GET `/teams/{teamId}/invitations` | status?，分页 | 200 Page<TeamInvitationDto>；OWNER 视图包含 inviteeEmail |
| POST `/team-invitations/{invitationId}/cancel` | 无 | 200 TeamInvitationDto |
| POST `/team-invitations/{invitationId}/resend` | 无 | 200 TeamInvitationDto |

规则：

- 仅 OWNER。
- 邮箱标准化后，同 team 同 email 只允许一个未过期 PENDING。创建/重邀前对 `(teamId,emailNormalized)` 获取 advisory transaction lock，并先把已过期 PENDING 原子更新为 EXPIRED，再插入/读取当前邀请，避免部分唯一索引被“逻辑已过期但状态尚未扫掉”的旧行阻塞。
- 若邮箱对应用户已经是该团队 ACTIVE member，返回 409 `TEAM_ALREADY_MEMBER`，不创建邀请。
- 已注册：填 `inviteeUserId`，创建站内 `TEAM_INVITATION` 通知，并发送邀请邮件。
- 未注册：`inviteeUserId=null`，仍发送邮件；对方以后使用同一邮箱注册并验证，或已有用户完成“更换到该邮箱”的双重验证后，Backend 在邮箱变更事务完成后按已验证 `email_normalized` 绑定其所有未过期 PENDING invitation，并创建 `TEAM_INVITATION` 站内通知。邮箱匹配逻辑完全在 Backend。
- resend 只允许 PENDING 且未过期；冷却由 `TEAM_INVITE_RESEND_COOLDOWN_SECONDS` 配置，超限 429 + Retry-After。
- 邮件发送状态通过 `emailDeliveryStatus/emailDeliveryErrorCode` 返回。创建记录后先置 PENDING；发送成功更新 SENT，失败更新 FAILED。业务邀请记录不因 SMTP 失败回滚，OWNER 页面明确显示失败并可 resend；未注册邮箱只有邮件触达，因此 FAILED 必须可见。

#### 8.2 被邀请用户

| 方法与路径 | Request | 成功响应 |
|---|---|---|
| GET `/me/team-invitations` | status=PENDING 默认；分页 | 200 Page<TeamInvitationDto>；`inviteeEmail=null` |
| POST `/team-invitations/{invitationId}/accept` | 无 | 200 TeamInvitationDto |
| POST `/team-invitations/{invitationId}/reject` | 无 | 200 TeamInvitationDto |

accept 事务：

1. 行锁 invitation。
2. 校验当前用户与 inviteeUserId 一致；若此前为空，必须已由注册邮箱自动绑定。
3. 校验 PENDING、未过期、团队 ACTIVE、当前非 member；若 `expiresAt<=now()`，同事务先将 invitation 标 EXPIRED，再返回 409 `INVITATION_EXPIRED`。
4. 创建 ACTIVE MEMBER。
5. invitation → ACCEPTED。
6. 通知团队 owner 成员加入。
7. 使用与申请审批相同的 `(teamId,userId)` advisory lock，并取消同团队该用户其他 PENDING 加入路径。

完成后不得重复处理；返回 409 `INVITATION_ALREADY_PROCESSED`。


### 9. 隐私 API

#### 9.1 用户自己的设置

| 方法与路径 | Request | 成功响应 |
|---|---|---|
| GET `/me/privacy` | 无 | 200 PrivacySettingsDto |
| PATCH `/me/privacy` | `{basicTraining?: PrivacyScope, abilityProfile?: PrivacyScope, detailedSubmissions?: PrivacyScope, analysisReport?: PrivacyScope}` | 200 PrivacySettingsDto |

所有用户初始四项 PRIVATE。

#### 9.2 成员数据访问

下列接口只允许共享 ACTIVE 团队内的访问；Backend 按目标用户的隐私 scope 强制判断。

| 方法与路径 | 权限项 | Query | 成功响应 |
|---|---|---|---|
| GET `/teams/{teamId}/members/{memberPublicId}/training/overview` | basicTraining | window=30D | 200 SharedTrainingOverviewDto 或 null |
| GET `/teams/{teamId}/members/{memberPublicId}/profile` | abilityProfile | window=ALL | 200 SharedAbilityProfileDto 或 null |
| GET `/teams/{teamId}/members/{memberPublicId}/submissions` | detailedSubmissions | V0.11 submission 过滤 + 分页 | 200 Page<UserSubmissionDto> |
| GET `/teams/{teamId}/members/{memberPublicId}/reports` | analysisReport | 分页 | 200 Page<PersonalReportDto> |
| GET `/teams/{teamId}/members/{memberPublicId}/reports/{reportId}` | analysisReport | 无 | 200 PersonalReportDto |

成员共享接口必须做**字段级最小化**：`basicTraining` 接口绝不返回 overallScore/dimensions/weakestDimension/ratingAccounts/sourceAccountIds；`abilityProfile` 接口绝不返回 summary/tagStats/difficultyStats/activityStats/ratingAccounts/sourceAccountIds。不能因为两者底层来自同一 `user_analysis_snapshots` 就序列化完整 `UserAnalysisDto` 后依赖前端隐藏。

`UserSubmissionDto`：

```ts
interface UserSubmissionDto {
  sourceAccount: { accountId: Id; platform: "codeforces"; username: string };
  submission: SubmissionDto;
}
```

访问矩阵：

| scope | 自己 | 共享团队 OWNER/COACH | 共享团队普通成员 | 非共享成员 |
|---|---:|---:|---:|---:|
| PRIVATE | ✅ | ❌ | ❌ | ❌ |
| TEAM_COACH | ✅ | ✅ | ❌ | ❌ |
| TEAM_MEMBER | ✅ | ✅ | ✅ | ❌ |
| PUBLIC | ✅ | ✅ | ✅ | V0.12 可用于未来公开页 |

权限不足且双方成员关系已可见时返回 403 `PRIVACY_DENIED`；不可见的 team/member 返回 404。


### 10. 用户级多 CF 聚合画像 API

V0.11 的 `/oj-accounts/{accountId}/analysis/**` 原样保留，继续展示单账号历史；V0.12 学生主页、个人画像、个人分析默认使用下列**用户级**接口。

| 方法与路径 | Query | 成功响应 |
|---|---|---|
| GET `/me/training/overview` | `window=30D` | 200 UserAnalysisDto 或 null |
| GET `/me/analysis/latest` | `window=ALL` | 200 UserAnalysisDto 或 null |
| GET `/me/analysis/history` | `window=ALL` + 分页 | 200 Page<UserAnalysisDto> |
| GET `/me/analysis/{snapshotId}` | 无 | 200 UserAnalysisDto |
| POST `/me/analysis/rebuild` | 无 | 202 AiJobDto |

`/me/analysis/rebuild` 是补充的可恢复入口：若用户刚同步多个 CF 但用户级画像未完成，可手动触发；至少 60 秒冷却，已有 USER_ANALYSIS QUEUED/RUNNING 时直接返回同一 job。

#### 10.1 聚合口径

- source set：当前用户所有未解绑 Codeforces 绑定（V0.11 的 ACTIVE 或 INVALID）。为了不静默漏账号，新的用户级画像只有在每个 source account 至少完成过一次完整数据同步（`lastSyncedAt != null`）且当前没有该用户任一账号同步任务在途时才允许生成；否则返回/记录 `USER_SOURCE_NOT_READY`，保留旧画像并标 stale。
- 题目：按 `problemId` 去重。
- 提交：按 `platform + externalSubmissionId` 去重，解决同一团队提交同时出现在多个绑定账号导致的重复计数。
- `currentRating`：参与账号 currentRating 非 null 的最大值。
- `maxRating`：参与账号 maxRating 非 null 的最大值。
- 详细每账号 rating 始终通过 `ratingAccounts[]` 返回，前端文案必须写“最高当前 Rating/各账号 Rating”，不把最大值伪装成统一官方 Rating。
- 四窗口算法、六维公式继续沿用 V0.11 映射，但算法版本为 `user-profile-v0.12.1`。
- 用户没有任何未解绑账号时允许生成零画像；前端仍优先显示绑定引导。若 source account 为 INVALID 但过去有成功同步，允许用最后成功数据参与聚合，同时该用户画像查询派生 `stale=true`，直到账号恢复 ACTIVE 或被解绑。

#### 10.2 自动更新

- `sourceFingerprint` 必须同时包含当前所有未解绑 accountId/dataVersion/bindStatus 集合和“最近一次“实际改变题库内容”的成功 PROBLEM_CATALOG sync job id（无则 none）”，避免题库 difficulty/tags 更新后旧用户画像仍被误判为新鲜。
- 任意 ACCOUNT_FULL 同步成功、绑定、解绑或 bindStatus 变化后，Backend 重新评估 USER_ANALYSIS；仅当全部 source accounts 已有成功数据且无在途账号任务时入队。题库版本变化后旧画像立即 stale，后台可按活跃用户分批重建，避免一次 catalog 刷新产生任务风暴。
- 多次变化合并为一个在途 job；worker 冻结当时 fingerprint。
- 结果返回时 fingerprint 已变化则丢弃并重新排队，不写旧数据为最新。


### 11. 个人分析报告 API

| 方法与路径 | Query/Request | 成功响应 |
|---|---|---|
| GET `/me/reports/latest` | 无 | 200 PersonalReportDto 或 null |
| GET `/me/reports` | 分页 | 200 Page<PersonalReportDto> |
| GET `/me/reports/{reportId}` | 无 | 200 PersonalReportDto |
| POST `/me/reports/generate` | 无 | 202 AiJobDto；P2 手动生成 |

规则：

- 定时生成由 backend scheduler 负责；执行时间来自环境配置，不写死业务代码。
- 生成必须基于最新未 stale 的 ALL 用户画像 + 对应 30D 用户画像。
- Algorithm 只接收统计/画像/最近训练聚合，不接收邮箱、密码、Session、用户名、提交源码。
- 成功报告存档，不覆盖历史。
- 手动生成冷却由 `PERSONAL_REPORT_MANUAL_COOLDOWN_SECONDS` 配置；超限 429 `REPORT_RATE_LIMITED` + Retry-After。
- 在途 PERSONAL_REPORT job 再次点击返回同一 job。


### 12. AI Job 查询

| 方法与路径 | 成功响应 |
|---|---|
| GET `/ai-jobs/{jobId}` | 200 AiJobDto |

授权：

- USER_ANALYSIS/PERSONAL_REPORT：仅 job 对应用户本人。
- TEAM_ANALYSIS/TEAM_RECOMMENDATION：仅该团队 ACTIVE member；结果生成操作仍由 OWNER 限制。
- 他人/不存在统一 404 `AI_JOB_NOT_FOUND`。

前端轮询规则与 V0.11 sync job 一致：收到 202 后每 3 秒；终态停止；页面隐藏可暂停；网络失败退避。`resultId` 固定指向：USER_ANALYSIS 的 ALL snapshot、PERSONAL_REPORT 的 report、TEAM_ANALYSIS 的 team snapshot、TEAM_RECOMMENDATION 的 batch；前端仍应在 SUCCESS 后刷新对应 latest/history，不能只靠 resultId 拼装对象。


### 13. 团队能力分析 API

#### 13.1 读取

| 方法与路径 | Query | 成功响应 |
|---|---|---|
| GET `/teams/{teamId}/analysis/latest` | 无 | 200 TeamAnalysisDto 或 null |
| GET `/teams/{teamId}/analysis/history` | 分页 | 200 Page<TeamAnalysisDto> |

Backend 自动选择 audience：

- 当前用户是该团队 OWNER 且拥有 COACH → `COACH`。COACH audience 的能力样本按 `abilityProfile` 判断，活动样本按 `basicTraining` 判断；OWNER 本人对两类数据均按 self access 可纳入，其他成员分别按对应 scope 过滤。
- 其他 ACTIVE member → `MEMBER`；MEMBER audience 是所有普通成员共享的一份团队聚合：能力样本只纳入 abilityProfile=TEAM_MEMBER/PUBLIC，活动样本只纳入 basicTraining=TEAM_MEMBER/PUBLIC；不做“viewer 自己例外”，避免同一 audience 因查看者不同而变化。
- 前端不能传 `audience=COACH` 提权。

P1 团队详情页的“整体能力概览”使用 latest；若 `includedMemberCount=0`，展示“当前没有成员允许共享能力画像”。`trainingMemberCount=0` 时近期团队活动展示“没有成员向该 audience 开放基础训练数据”。`levelMemberCount=0` 时 targetRating=null，不能把空趋势误判为无人训练。

#### 13.2 重建（OWNER/P2 可见；系统也会自动触发）

| 方法与路径 | 成功响应 |
|---|---|
| POST `/teams/{teamId}/analysis/rebuild` | 202 AiJobDto |

触发条件：成员加入/退出/移除、成员 basicTraining/abilityProfile 隐私修改、成员最新 user profile 变化时，Backend 标记指纹变化并按调度合并重建 COACH/MEMBER 两个 audience。构造输入时只使用对应成员最新 **未 stale** 的 ALL/30D user profile；abilityProfile 只投影分数/维度，并且无任何训练证据（ALL `summary.submissionCount=0`）的零画像不进入 profileMembers，避免把“无数据”当成 0 分拉低团队能力。basicTraining 才投影 currentRating/averageSolvedDifficulty/activityStats；无 source account 的空数据不进入 trainingMembers。


### 14. 团队推荐 API（P2）

| 方法与路径 | 权限 | Request / Query | 成功响应 |
|---|---|---|---|
| POST `/teams/{teamId}/recommendations/generate` | OWNER | `{mode?: "WEAKNESS"\|"HYBRID", limit?: number}` 默认 HYBRID/10 | 202 AiJobDto |
| GET `/teams/{teamId}/recommendations/latest` | ACTIVE member | mode=HYBRID | 200 TeamRecommendationBatchDto 或 null |
| GET `/teams/{teamId}/recommendations/history` | ACTIVE member | mode? + 分页 | 200 Page<TeamRecommendationBatchDto> |
| GET `/teams/{teamId}/recommendations/{batchId}` | ACTIVE member | 无 | 200 TeamRecommendationBatchDto |

生成使用最新未 stale 的 `COACH` team analysis，因为 owner 才能生成。若该快照 `targetRating=null`（没有任何成员向 COACH audience 开放可用 basicTraining），返回 409 `TEAM_LEVEL_NOT_READY`，不以默认 800 猜测团队等级。题目“已做覆盖率”只允许基于同时向 OWNER 开放 `detailedSubmissions` 的成员计算；`coverageMemberCount` 可以小于 team analysis 的 `includedMemberCount`，甚至为 0。Backend 为该次输入计算 recommendation `sourceFingerprint`（画像快照 + coverage 成员及其 OJ 数据版本 + 题库版本），Algorithm 原样回显；落库和查询 stale 时均重新核对。公开推荐响应不返回 memberSolvedCount/eligibleMemberCount，只返回团队级题目和原因，防止从聚合推荐反推出成员详细训练记录。
团队推荐固定 reason 文案由 Backend 根据 `reasonCode` 映射，Algorithm 不返回自由文本：

| reasonCode | reason |
|---|---|
| `TEAM_WEAKNESS_MATCH` | 这道题覆盖团队当前相对薄弱的能力。 |
| `TEAM_LEVEL_MATCH` | 这道题的难度与团队当前训练水平接近。 |
| `TEAM_COVERAGE_GAP` | 在允许统计的成员中，这道题的训练覆盖较低。 |
| `TEAM_BALANCED_PRACTICE` | 这道题适合作为团队的综合训练题。 |



### 15. Coach Dashboard API

| 方法与路径 | 权限 | 成功响应 |
|---|---|---|
| GET `/coach/dashboard` | COACH | 200 CoachDashboardDto |

统计口径：

- managedTeamCount：当前用户 OWNER 且非 DISSOLVED 的团队数。
- activeMemberCount：这些团队 ACTIVE membership 去重后的总人数，跨团队重复用户仍按团队成员关系计数。
- pendingApplicationCount：这些团队 PENDING application 总数。
- recentNotifications：与其管理团队相关的最近最多 10 条通知。


### 16. 通知 API

| 方法与路径 | Request / Query | 成功响应 |
|---|---|---|
| GET `/notifications` | `unreadOnly=false` + 分页 | 200 Page<NotificationDto> |
| GET `/notifications/unread-count` | 无 | 200 `{count: number}` |
| POST `/notifications/{notificationId}/read` | 无 | 200 NotificationDto |
| POST `/notifications/read-all` | 无 | 200 `{updated: number}` |

read 操作幂等。


### 17. V0.12 新增错误码

所有错误继续使用 V0.11 `ApiError`。

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



## 12. 保留的旧 backend → algorithm 内部 API

旧v1使用Bearer INTERNAL_API_TOKEN、X-Request-Id和裸DTO；旧v1输入上限64MiB，与新v2 32MiB分开。账号AnalyzeRequest/RecommendRequest、用户/报告/团队签名如下；工具分析源码只走新v2，不放旧LLM报告请求。旧纯计算重试复用requestId，后端校验后原子落库，不在线猜未知版本。

### Backend → Algorithm 正式 HTTP 协议

算法必须提供独立 HTTP 服务，不作为后端包导入。后端配置 `ALGORITHM_BASE_URL=http://algorithm:8000`。以下成功响应是直接 DTO，不套公开 API 的 data；内部请求和响应 Content-Type 均为 application/json。

| 方法与路径 | 输入 | 成功输出 |
| --------------------------- | ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| POST /internal/v1/analyze | AnalyzeRequest | 200 AnalyzeResponse |
| POST /internal/v1/recommend | RecommendRequest | 200 RecommendResponse |
| GET /health | 无 | 200 AlgorithmHealth（直接响应、不套data；版本数组包含全部已保留版本） |

POST 必须带 `Authorization: Bearer <INTERNAL_API_TOKEN>` 和 `X-Request-Id: <UUID>`；requestId 必须与头相同，响应原样回传。内部令牌通过环境变量注入，仅后端和算法持有；不转发浏览器 Cookie/Session。/health 无须令牌，只在私有网络暴露，配置未装载时返回 503 同形结构但 status="unavailable"。非法/缺失 X-Request-Id 时算法生成一个 UUID 放入错误响应。未知 JSON 字段拒绝，nullable 必须显式 null；Id 不能是 number。

后端连接超时 2 秒；analyze 单次总超时 60 秒，recommend 10 秒。算法计算预算分别 55 秒和 8 秒。仅连接失败、超时、502/503/504 重试一次，等待 500–1000ms 抖动且复用完全相同的 requestId/body；任意其他 5xx 视为失败不自动重试。两次调用上限 analyze 121 秒、recommend 21 秒（含连接），公开生成接口总预算 25 秒，frontend 代理与浏览器生成请求超时 30 秒。4xx、非法 JSON/DTO、版本不符不重试。算法无持久化副作用，相同输入确定性返回；超时任务须受计算预算约束，不得无限后台堆积。

请求体默认上限 64 MiB，超过返回 413 INPUT_TOO_LARGE，不能静默截断 ALL。部署可按实测内存同步调高双方上限。后端在短 REPEATABLE READ 事务中冻结完整输入后释放连接，再调用 HTTP；不得在网络等待期间持有数据库事务。需要的所有数据都在请求中，算法不回调后端拉数。

#### 内部 DTO

以下类型为完整契约；number 中计数、rank、displayOrder、difficulty、Rating 为整数，平均值与分数可为小数；只有 `| null` 可空。所有 ID、时间、单位与公共 DTO 一致。

```ts
 // PostgreSQL bigint 的十进制正整数字符串；禁止转 JS number
 // 标准 UUID 字符串
 // ISO 8601 UTC，例 2026-10-02T02:30:00Z
 // YYYY-MM-DD，按 timezone 的自然日












interface DimensionConfig {
  code: DimensionCode; name: string; displayOrder: number;
  tagMappings: Array<{tag: string; weight: number}>;
}
interface AlgorithmProblem {
  problemId: Id; difficulty: number | null; tags: string[];
  solvedCount: number | null; isGym: boolean;
}
interface AlgorithmSubmission {
  externalSubmissionId: Id; problemId: Id; verdict: Verdict; submittedAt: Instant;
}
interface AnalyzeRequest {
  requestId: UUID; accountId: Id; algorithmVersion: string; mappingVersion: string;
  sourceDataVersion: Id; dataCutoffAt: Instant; timezone: "Asia/Shanghai";
  windows: AnalysisWindow[];
  account: {currentRating: number | null; maxRating: number | null};
  submissions: AlgorithmSubmission[]; problems: AlgorithmProblem[];
  dimensions: DimensionConfig[];
}
interface AnalyzeResponse {
  requestId: UUID; accountId: Id; algorithmVersion: string; mappingVersion: string;
  sourceDataVersion: Id; dataCutoffAt: Instant; timezone: "Asia/Shanghai";
  analyses: AnalysisResult[];
}
interface RecommendRequest {
  requestId: UUID; accountId: Id; analysisSnapshotId: UUID;
  algorithmVersion: string; mappingVersion: string;
  sourceDataVersion: Id; dataCutoffAt: Instant;
  mode: RecommendationMode; limit: number;
  profile: {
    accountId: Id; snapshotId: UUID; algorithmVersion: string; mappingVersion: string;
    window: "ALL"; dataCutoffAt: Instant; sourceDataVersion: Id;
    overallScore: number; currentRating: number | null; averageSolvedDifficulty: number | null;
    maxSolvedDifficulty: number | null; weakestDimension: DimensionCode;
    dimensions: DimensionScore[]; tagStats: TagStat[];
  };
  dimensions: DimensionConfig[];
  candidateProblems: AlgorithmProblem[];
  solvedProblemIds: Id[];
  recentRecommendationProblemIds: Id[];
}
interface RecommendResponse {
  requestId: UUID; accountId: Id; analysisSnapshotId: UUID;
  algorithmVersion: string; mappingVersion: string;
  sourceDataVersion: Id; dataCutoffAt: Instant; mode: RecommendationMode;
  targetRating: number; targetDimension: DimensionCode | null; candidateCount: number;
  recommendations: Array<{
    problemId: Id; rank: number; score: number;
    matchedDimension: DimensionCode | null; reasonCode: ReasonCode;
  }>;
}
interface AlgorithmError {
  requestId: UUID;
  error: {code: string; message: string; retryable: boolean;
    details: {fields: Array<{field: string; reason: string}>}};
}
```

AnalyzeRequest.windows 必须恰好为 `["7D","30D","365D","ALL"]`，响应 analyses 同序四项。请求的 problems 必须覆盖所有提交 problemId 且无重复，允许额外无提交题但不计入统计。submissions.externalSubmissionId 在单账号内唯一，submittedAt 必须早于 dataCutoffAt；sourceDataVersion 是后端数据版本的十进制字符串。accountId 只在请求顶层且全部提交属于该账号；后端负责归属，不传用户隐私。

algorithmVersion 分析固定 `profile-v0.11.1`，推荐固定 `recommend-v0.11.1`，mappingVersion 固定 `mapping-v0.11.1`。维度配置必须与对应版本内置配置逐项相同（按 code/tag 排序比较），不接受同版本不同映射。后端从 Migration 种子读取配置，算法独立附带相同配置用于核对；不在线修改版本内容。

RecommendRequest.profile.accountId 必须等于 accountId，profile.snapshotId 必须等于 analysisSnapshotId；profile 为 ALL、分析版本为 profile-v0.11.1、mappingVersion 一致。sourceDataVersion 必须等于 profile.sourceDataVersion；请求 dataCutoffAt 为候选读取时刻，不早于 profile.dataCutoffAt。solvedProblemIds 为当前账号全部已 AC 去重题 ID，包括 Gym、未评级题；recentRecommendationProblemIds 为同 accountId 最近 7×24 小时推荐过的去重题 ID（所有模式）。候选数组来自完整 problems 经基础过滤后的全部有效普通题，不允许只取用户做过的题或预先随机截断；candidateProblems 中 difficulty 必须非 null、isGym=false、problemId 唯一，并与 solvedProblemIds 无交集。候选只含算法必要字段，题名、URL 合法性由后端过滤。

#### 内部错误

错误 body 必须为 AlgorithmError，details.fields 无明细时 `[]`；无用户隐私或堆栈。

| HTTP | code | retryable |
| ---- | ------------------------------------------------------------------------- | --------- |
| 400 | INVALID_REQUEST | false |
| 401 | INTERNAL_UNAUTHORIZED | false |
| 413 | INPUT_TOO_LARGE | false |
| 422 | UNSUPPORTED_ALGORITHM_VERSION、UNSUPPORTED_MAPPING_VERSION、INVALID_INPUT | false |
| 500 | ALGORITHM_INTERNAL_ERROR | false |
| 503 | ALGORITHM_BUSY | true |
| 504 | COMPUTATION_TIMEOUT | true |

后端映射：连接不可达/算法 5xx → 503 ALGORITHM_UNAVAILABLE；连接或总超时及算法 504 → 504 ALGORITHM_TIMEOUT；422 版本问题 → 502 ALGORITHM_VERSION_MISMATCH；其他非成功、非法 DTO 或非法 JSON → 502 ALGORITHM_BAD_RESPONSE。这些是后端依赖故障，不伪装成用户参数错误。重试耗尽才对外返回；分析放入 sync_jobs.errors 中，已有数据不回滚。

#### 后端接收与落库校验

1. HTTP 200 后仍需严格校验 schema、number 有限性、字段 nullability、requestId/accountId/sourceDataVersion/dataCutoffAt/algorithmVersion/mappingVersion 回显、分析 timezone 和窗口完整性；推荐额外校验 analysisSnapshotId 和 mode。
2. 每个分析结果的 period 必须由约定窗口与输入 cutoff 唯一确定；计数非负，solved≤attempted≤submission，rated+unrated=solved，accepted+failed+pending=submission；用输入重算简单计数核对。三个 Stats 都是数组、key 唯一、计数/求和符合统计口径。
3. 六维 code/name/displayOrder 与输入版本一致，恰好六个、score/overallScore 在 0..100、rankOrder 为 1..6 排列且符合 score 排序、weakestDimension 为第 1 名，空数据仍合法；average/max 的 null 条件必须匹配有评级题数量。
4. 推荐 rank 连续 1..N、problemId 不重复且属于此次候选、不在 solvedProblemIds、score 在 0..1、N≤limit；reasonCode 在固定集合；维度存在、模式/目标与当前画像一致；candidateCount 为算法模式难度与标签过滤后的数量，N=min(limit,candidateCount)。后端可以按规则复核入选资格，不自行替代排序。
5. 落库前短事务锁 account 行，检查仍未解绑、数据版本未变化；推荐还要确认 snapshot 属于本 accountId、ALL、完整、版本可用且仍是最新有效 ALL，并确认账号 ACTIVE、无其他在途账号任务。分析还要验证任务 lease_owner 未失效。不匹配返回 DATA_CHANGED/PROFILE_NOT_READY，丢弃未提交结果，不写半个批次。
6. 分析一次事务写四个快照及每个六条维度，同时更新任务成功终态与账号同步状态；推荐一次事务写批次及全部 items。任何校验失败全部不落该次结果，已有快照/推荐不覆盖。分析用 `(account_id,window_type,request_id)` 幂等，内部重试复用 requestId；推荐使用公开 Idempotency-Key 幂等。


### 19. Backend → Algorithm V0.12 新增内部 HTTP 契约

V0.11 两个端点继续存在：

```text
POST /internal/v1/analyze
POST /internal/v1/recommend
```

V0.12 新增：

| 路径 | 输入 | 输出 | 主要用途 |
|---|---|---|---|
| POST `/internal/v1/user-analyze` | UserAnalyzeRequest | UserAnalyzeResponse | 多 CF 用户级画像 |
| POST `/internal/v1/personal-report` | PersonalReportRequest | PersonalReportResponse | LLM 个人报告 |
| POST `/internal/v1/team-analyze` | TeamAnalyzeRequest | TeamAnalyzeResponse | 团队能力聚合 |
| POST `/internal/v1/team-recommend` | TeamRecommendRequest | TeamRecommendResponse | 团队题目推荐 |

鉴权、`X-Request-Id`、Content-Type、内部错误格式继续沿用 V0.11。

#### 19.1 UserAnalyzeRequest / Response

```ts
interface UserSourceAccount {
  accountId: Id;
  platform: "codeforces";
  dataVersion: Id;
  currentRating: number | null;
  maxRating: number | null;
}

interface UserAlgorithmSubmission {
  accountId: Id;
  platform: "codeforces";
  externalSubmissionId: Id;
  problemId: Id;
  verdict: Verdict;
  submittedAt: Instant;
}

interface UserAnalyzeRequest {
  requestId: UUID;
  algorithmVersion: "user-profile-v0.12.1";
  mappingVersion: "mapping-v0.11.1";
  sourceFingerprint: string;
  dataCutoffAt: Instant;
  timezone: "Asia/Shanghai";
  windows: ["7D","30D","365D","ALL"];
  accounts: UserSourceAccount[];
  submissions: UserAlgorithmSubmission[];
  problems: AlgorithmProblem[];
  dimensions: DimensionConfig[];
}

interface UserAnalyzeResponse {
  requestId: UUID;
  algorithmVersion: "user-profile-v0.12.1";
  mappingVersion: "mapping-v0.11.1";
  sourceFingerprint: string;
  dataCutoffAt: Instant;
  timezone: "Asia/Shanghai";
  analyses: AnalysisResult[]; // 4 项；currentRating/maxRating 为账号最大值
}
```

Backend 校验：

- accounts 来自目标用户当前全部未解绑且已有成功同步的数据源（ACTIVE/INVALID），accountId 唯一；如果存在从未成功同步的未解绑账号或任一账号同步在途，本次 user-analyze 不应发出。
- sourceFingerprint 为 Backend 自己计算，不信任 Algorithm 生成。
- 所有 submission.accountId 必须属于 accounts。
- 同 `platform+externalSubmissionId` 若跨账号重复，Algorithm 应折叠；如果事件字段冲突返回 INVALID_INPUT。
- Response 四窗口、计数、六维范围、fingerprint、requestId 必须严格回显；四窗口结果必须同一个事务一次性落库，任何一项校验失败都不写新快照。公开 `publicId` 与 `ratingAccounts[]` 均由 Backend 使用当前 job 主体和冻结 account 元数据自行组装；Algorithm 不接收用户 publicId/handle。
- 落库前重新计算当前 fingerprint，不一致则 `DATA_CHANGED`，不写结果。

#### 19.2 PersonalReportRequest / Response

```ts
interface ReportProfileProjection {
  snapshotId: UUID;
  window: "ALL" | "30D";
  period: Period;
  summary: Summary;
  currentRating: number | null;
  maxRating: number | null;
  overallScore: number;
  dimensions: DimensionScore[];
  weakestDimension: DimensionCode;
  tagStats: TagStat[];
  difficultyStats: DifficultyStat[];
  activityStats: ActivityStat[];
  sourceAccountCount: number;
}

interface PersonalReportRequest {
  requestId: UUID;
  reportVersion: "personal-report-v0.12.1";
  sourceFingerprint: string;
  allProfile: ReportProfileProjection;
  recent30dProfile: ReportProfileProjection;
  language: "zh-CN" | "en";
}

interface PersonalReportContent {
  overview: string;
  strengths: string[];
  weaknesses: string[];
  recentTrend: string;
  actionSuggestions: string[];
  caution: string | null;
}

interface PersonalReportResponse {
  requestId: UUID;
  reportVersion: "personal-report-v0.12.1";
  promptVersion: string;
  modelName: string;
  sourceFingerprint: string;
  content: PersonalReportContent;
}
```

Backend 只构造 `ReportProfileProjection`，不把 publicId、ratingAccounts、username、邮箱或 accountId 放进内部报告 DTO。Algorithm/LLM 都不需要知道报告属于哪个真实用户；Backend 通过 ai_job.user_id + requestId 关联结果。

#### 19.3 TeamAnalyzeRequest / Response

```ts
interface TeamMemberProfileProjection {
  allProfile: {
    snapshotId: UUID;
    overallScore: number;
    dimensions: DimensionScore[];
  };
}
interface TeamTrainingMemberProjection {
  allTraining: {
    snapshotId: UUID;
    currentRating: number | null;
    averageSolvedDifficulty: number | null;
  };
  recent30dTraining: {
    snapshotId: UUID;
    activityStats: ActivityStat[];
  };
}

interface TeamAnalyzeRequest {
  requestId: UUID;
  teamId: UUID;
  audience: "COACH" | "MEMBER";
  algorithmVersion: "team-profile-v0.12.1";
  mappingVersion: "mapping-v0.11.1";
  sourceFingerprint: string;
  dataCutoffAt: Instant;
  memberCount: number;
  profileMembers: TeamMemberProfileProjection[]; // abilityProfile 权限过滤后
  trainingMembers: TeamTrainingMemberProjection[]; // basicTraining 权限过滤后，既用于 level 也用于近期活动
}

interface TeamDimensionScore {
  code: DimensionCode;
  name: string;
  displayOrder: number;
  score: number;
  memberSampleCount: number;
  rankOrder: number;
}
interface TeamActivityStat {
  date: DateKey;
  submissionCount: number;
  acceptedSubmissionCount: number;
  activeMemberCount: number;
}

interface TeamAnalyzeResponse {
  requestId: UUID;
  teamId: UUID;
  audience: "COACH" | "MEMBER";
  algorithmVersion: "team-profile-v0.12.1";
  mappingVersion: "mapping-v0.11.1";
  sourceFingerprint: string;
  dataCutoffAt: Instant;
  includedMemberCount: number;
  trainingMemberCount: number;
  levelMemberCount: number;
  overallScore: number;
  dimensions: TeamDimensionScore[];
  weakestDimension: DimensionCode;
  activityStats: TeamActivityStat[];
  targetRating: number | null;
}
```

Algorithm 不接收/判断 PrivacyScope；Backend 必须分别按 abilityProfile/basicTraining 权限构造 `profileMembers[]` / `trainingMembers[]`，不能把一个权限集合复用于另一个。

#### 19.4 TeamRecommendRequest / Response

```ts
interface TeamCandidateProblem extends AlgorithmProblem {
  memberSolvedCount: number;
  eligibleMemberCount: number;
}

interface TeamRecommendRequest {
  requestId: UUID;
  teamId: UUID;
  analysisSnapshotId: UUID;
  algorithmVersion: "team-recommend-v0.12.1";
  mappingVersion: "mapping-v0.11.1";
  sourceFingerprint: string;
  mode: TeamRecommendationMode;
  limit: number;
  profile: {
    overallScore: number;
    dimensions: TeamDimensionScore[];
    weakestDimension: DimensionCode;
    targetRating: number;
    includedMemberCount: number;
    coverageMemberCount: number; // 允许 OWNER 使用 detailedSubmissions 的成员数
  };
  candidateProblems: TeamCandidateProblem[];
  dimensions: DimensionConfig[];
}

interface TeamRecommendResponse {
  requestId: UUID;
  teamId: UUID;
  analysisSnapshotId: UUID;
  algorithmVersion: "team-recommend-v0.12.1";
  mappingVersion: "mapping-v0.11.1";
  sourceFingerprint: string;
  mode: TeamRecommendationMode;
  targetRating: number;
  targetDimension: DimensionCode;
  candidateCount: number;
  recommendations: Array<{
    problemId: Id;
    rank: number;
    score: number;
    reasonCode: TeamReasonCode;
    memberSolvedCount: number;
    eligibleMemberCount: number;
  }>;
}
```


### 20. 内部超时与错误映射

V0.11 analyze/recommend timeout 不变。V0.12：

- `user-analyze`：60 秒，连接 2 秒；可对 502/503/504 重试一次。
- `personal-report`：90 秒，连接 2 秒；LLM 调用由 Algorithm 控制；只对明确 retryable 依赖错误重试一次。
- `team-analyze`：20 秒。
- `team-recommend`：10 秒。

Algorithm 错误映射：

- 422 版本/输入错误 → Backend 502 `ALGORITHM_VERSION_MISMATCH` / `ALGORITHM_BAD_RESPONSE`。
- 503 Algorithm/LLM busy → 503 `ALGORITHM_UNAVAILABLE` 或 `LLM_UNAVAILABLE`。
- 504 → 504 `ALGORITHM_TIMEOUT`。
- AI job 内失败存 `ai_jobs.errors`；轮询 GET 本身仍 200 返回 FAILED 状态。


## 13. 保留的 CF Provider 数据约束

### CodeforcesProvider 与标准化

以仓库 `cf字段分析.md` 和 `cf原始数据.md` 的字段和样本为基础。样本出现率不是平台完整性保证：可选字段同时接受缺失键与显式 null，不能因样本全有值就全部 NOT NULL。官方对象定义也注明 Submission.verdict、contestId 等可缺失，timeConsumedMillis 为毫秒、memoryConsumedBytes 为字节；points 与 rating 是不同字段。[Codeforces 对象定义](https://codeforces.com/apiHelp/objects)

只由 Backend 访问 `https://codeforces.com/api/`，实现以下四个 Provider 方法：

| 方法 | 请求 | 解析与保存 |
| --------------------------------- | ---------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| getUserInfo(handle) | user.info?handles=<URL编码handle> | handle、rating/maxRating、rank/maxRank、contribution、friendOfCount、名字、country/city/organization、avatar/titlePhoto、registrationTimeSeconds/lastOnlineTimeSeconds |
| getSubmissions(handle,from,count) | user.status?handle=...&from=1&count=1000 | id、contestId、creationTimeSeconds、relativeTimeSeconds、problem 全部标准字段、verdict、programmingLanguage、testset、passedTestCount、timeConsumedMillis、memoryConsumedBytes、author、points、pointsInfo |
| getRatingHistory(handle) | user.rating?handle=... | contestId、contestName、handle、rank、oldRating、newRating、ratingUpdateTimeSeconds；空数组合法 |
| getProblemset() | problemset.problems | problems 与 problemStatistics 按 contestId+index 配对，不按数组位置；缺失统计则 solvedCount=NULL |

Provider 必须检查 HTTP 状态和 JSON status=OK；HTTP 200/status=FAILED 也是失败。用户未找到仅在官方明确 handle 不存在时映射 CF_ACCOUNT_NOT_FOUND；其余归上游故障，不把任意 comment 当业务码。公开方法和 user.status 的分页参数由官方 API 定义。[Codeforces 方法](https://codeforces.com/apiHelp/methods)

所有 epoch 秒转 UTC Instant；保留 raw 扩展但不向算法转发。user.info 未定级 rating/maxRating/rank/maxRank 可空，rank 不是 ENUM；problem.rating/points 可空；author.startTimeSeconds、room、teamId/teamName、participantId、participantType、ghost 可空。author.members 保留多成员，participantType 原始值自由文本，未知只归一为 OTHER。programmingLanguage 不做封闭 ENUM；tags 保存原文字符串列表，不根据样本固定 38 或 39 项。

官方可靠题库统计只有 solvedCount，通过人数没有可靠全站尝试人数分母；本版不返回 globalAcceptanceRate 或 internalAcceptanceRate，不展示全站通过率。未来添加站内统计必须按系统用户去重、明确标注“站内统计”，不能把多账号/重绑的重复提交累加冒充全站数据。

后端统一串行限流 CF 请求，相邻起始至少 2 秒，连接超时 3 秒、单次总超时 20 秒，429/5xx/网络失败最多再试两次，间隔 2 秒、4 秒并尊重 Retry-After。限流包含绑定、手动、每日同步和题库任务；不靠每个账号各自限流。同步任务可以执行上述完整重试；绑定接口包含排队与 Provider 调用的总预算为 25 秒，按剩余预算减少重试，超时返回 UPSTREAM_CODEFORCES_TIMEOUT，不能超过前端 30 秒请求预算。接口限流要求见 [Codeforces API 使用说明](https://codeforces.com/apiHelp)。

V0.11 不依赖未验证的 CF handle 改名追踪。请求 canonical handle 与记录相比仅大小写变化可以规范化；出现实质改名或旧 handle 无法查到时标 INVALID，保留占位与历史，请用户解绑旧记录并绑定当前 handle。不能用显示名、组织、Rating 自动认定两个 handle 是同一人，也不能迁移其他用户历史。


### 分析时间与统计口径

每次输入固定 `dataCutoffAt`，结束点为该时刻且不包含端点。7D/30D/365D 的开始点为该时刻在 `timezone` 中所在日期的零点向前数 N−1 个自然日；包含今天已发生部分，共 N 个自然日。ALL 的开始点为 null，包含截止前全部已同步历史。V0.11 固定 `timezone="Asia/Shanghai"`，用户时区仅影响页面显示，不改变计算口径。输入时间仍全部为 UTC。

后端提供当前 accountId 截止前完整逐条提交及其题目，不能截取最近若干条冒充 ALL。算法在每个窗口按 `[start,end)` 筛选。团队提交归入 Provider 查询账号的数据集，每个 accountId 内按 externalSubmissionId 去重；不同账号独立计算，不合并为用户总数。

- attemptedProblemCount：窗口内提交涉及的去重题数；solvedCount：窗口内至少一次 ACCEPTED 的去重题数。即使过去已 AC，窗口内再 AC 也计为窗口 solved；unsolvedProblemCount=attemptedProblemCount−solvedCount。
- submissionCount：窗口内全部提交数；acceptedSubmissionCount 仅 ACCEPTED；pendingSubmissionCount 仅 PENDING；failedSubmissionCount 为其余最终/未知非 AC 判定数。必须满足 submissionCount=acceptedSubmissionCount+failedSubmissionCount+pendingSubmissionCount，等待判题不显示为失败。
- ratedSolvedCount 与 unratedSolvedCount 按题目 difficulty 是否为 null 划分，二者之和为 solvedCount。averageSolvedDifficulty、maxSolvedDifficulty 只按有难度的去重已 AC 题计算；无样本均为 null，不能填 0。
- tagStats 按原始 tag 字符串去重后统计，每个标签一项；多标签题可以计入多项，标签之和不要求等于总题数。空标签不造伪标签。按 tag 字典序输出。
- difficultyStats 每个难度一项，包含 difficulty=null 的未评级桶；按数值升序、null 最后；各桶 solvedCount 之和等于 summary.solvedCount。没有题则 `[]`。
- activityStats 按自然日升序，仅返回有提交的日期；缺失日期在图表视为零。每日 AC 次数按提交计数；每日 solvedCount 为该题在本窗口首次 AC 所在日的题数，跨日重复 AC 不再次计数，因此各日 solvedCount 之和等于窗口 solvedCount。它不是“全历史首次 AC”。activeDays=activityStats.length。
- dimensions 始终六项，按 displayOrder 排列；rankOrder 按 score 升序，分数相同按 displayOrder，连续 1..6，1 为最弱；weakestDimension 为 rankOrder=1 的 code。空数据仍返回六项零分、overallScore=0，最弱按固定顺序取第一项。页面标注“暂无训练证据”。
- 所有 count 为非负安全整数；分数及平均难度保留两位小数，推荐 score 保留六位，使用十进制 ROUND_HALF_UP；JSON 不允许 NaN/Infinity。currentRating/maxRating 是此次同步时资料，不伪装为窗口开始时 Rating。

