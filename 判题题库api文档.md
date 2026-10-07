# V0.2 判题与题库 API 契约

契约发布号 `0.2.0`。本负责人实施独立业务容器 `judge-problem-service:8082`，只接收 backend 的内部 HTTP 请求。完整流程以 [整体架构与联调说明](V0.2-整体架构与联调说明.md) 为准；表结构见 [判题题库数据库文档](判题题库数据库文档.md)。

## 1. 历史依据、兼容与服务边界

本设计已独立核对根目录 V0.1/V0.11 需求、API、数据库设计，V0.11/V0.12 后端及算法设计、CF 原始数据与字段分析、本次 `v0.2版本更新功能.md`。未读取或参考 `docs-fronted/`。历史文档没有本平台判题 API；本轮新增题包与异步判题契约，不把已开发的外部数据流程推倒重做。

- 旧 `/api/v1/oj-accounts/**`、CF 题目与提交、账号画像、多 CF 用户画像、团队、隐私、通知、报告保持原接口与 ID；其 owner 仍是 backend。CF `problem.rating` 缺失为 null，`points` 不是难度，资源单位保持 ms/bytes。不能将 CF 的公开题目目录当成具有测试数据授权的平台题包。
- judge 唯一维护平台题目、不可变题包版本、样例/隐藏测试/标准程序/验证器、目录版本、JudgeTask、原始判题结果、导入校验与许可证溯源。backend 拥有用户、业务 Submission、提交源码、训练记录、判题结果公开投影、分析结果投影与画像；本服务不连接 backend 的业务表。
- frontend 只调用 backend。backend 调 judge 查询题库和提交判题；judge 只向 backend 的固定事件接收地址回传既有任务，不拉用户信息、不调 algorithm、不触发推荐。代码分析与画像由 backend 编排。
- 平台题目和 CF 题目都使用正十进制字符串 ID，但属于不同命名空间；必须用 `ProblemRef` 全部身份字段关联，不能仅按 `problemId` 混接。平台题版本为 UUID，老 CF ID 不变。

## 2. HTTP 与认证

内部基址 `http://judge-problem-service:8082`，前缀 `/internal/v2`。所有业务请求带 `Authorization: Bearer <BACKEND_JUDGE_TOKEN>`、`X-Request-Id: <UUID>`；有 `requestId` 的 body 与该头严格相同。回调使用另一密钥 `JUDGE_BACKEND_TOKEN`。两者不复用，不接收浏览器 Cookie，不接受调用方提供 callbackUrl、编译命令、运行命令或测试数据。

JSON camelCase，数据库 snake_case。未带 `?` 字段必需，只有 `|null` 可空；未知请求字段 400，数组无值为 `[]`。Id 为 PostgreSQL bigint 的正十进制字符串，不转 JSON number；UUID 为标准 UUID；Instant 为 RFC3339 UTC `Z`。时间毫秒，内存字节，MiB 为 1048576 字节。所有计数为非负安全整数。

```ts
type Id = string;
type UUID = string;
type Instant = string;
interface ApiResponse<T> {data:T; requestId:UUID}
interface PageResponse<T> {
  data:T[];
  meta:{page:number; pageSize:number; total:number; hasNext:boolean};
  requestId:UUID;
}
interface ApiError {error:{code:string; message:string; details:Record<string,unknown>}; requestId:UUID}
interface TaskError {code:string; message:string; retryable:boolean}
interface TaskBase {
  requestId:UUID; revision:number; status:string; error:TaskError|null;
  createdAt:Instant; updatedAt:Instant; finishedAt:Instant|null;
}
type ProblemSource = "PLATFORM" | "EXTERNAL";
type Platform = "startrack" | "codeforces";
type DifficultyScale = "CF_RATING"|"PLATFORM_RATING"|"UNRATED";
interface ProblemRef {
  source: ProblemSource; platform: Platform; problemId: Id; problemVersionId: UUID | null;
}
interface ProblemSummary {
  problemRef: ProblemRef; title: string | null; difficulty: number | null;
  difficultyScale: DifficultyScale; tags: string[]; url: string | null;
}
```

所有 v2 成功均套上述 envelope；下面响应列写 `T`，分页写 `Page<T>`。GET 不产生判题/分析副作用。无 body 成功为 204。`GET /health` 为部署探测例外，直接返回健康对象。旧算法 `/internal/v1` 裸 DTO 不因此改变。

公共分页 `page=1,pageSize=20`，page≥1、pageSize 1..100，`hasNext=page*pageSize<total`，超末页返回 `[]`。同次查询 total 和 rows 取同数据库快照；跨页目录变化允许变化，完整推荐目录使用独立快照 API。

部署探测 `GET /health` 无认证，直接返回 `{status:"ok"|"unavailable",service:"judge-problem-service",contractVersion:"0.2.0",capabilities:{catalog:boolean,judge:boolean,imports:boolean}}`；数据库/私有存储与沙箱限制自检全部正常为200，否则503。judge=false必须停止接收新执行，可继续提供数据库可读的历史题库/任务查询；backend不因该服务健康失败关闭认证/旧业务。

所有变更请求按 `(operation, requestId)` 和规范化 body hash 幂等，首次任务 202，已有同请求任务 200；同 requestId 不同参数 409 `IDEMPOTENCY_CONFLICT`。管理 public API 的 `Idempotency-Key` 由 backend 关联到固定 requestId，重试不重新生成。业务主键关联永久保留，不能在短 TTL 到期后重复创建业务对象。

## 3. 题库、语言与导入 DTO

```ts
type PlatformProblemStatus = "DRAFT" | "PUBLISHED" | "WITHDRAWN";
interface PlatformProblemSummary extends ProblemSummary {
  problemRef:{source:"PLATFORM"; platform:"startrack"; problemId:Id; problemVersionId:UUID};
  status:PlatformProblemStatus;
  catalogVersion:Id;
  timeLimitMs:number;
  memoryLimitBytes:number;
  languageIds:string[];
  updatedAt:Instant;
}
interface PlatformProblemDetail extends PlatformProblemSummary {
  statement:{format:"MARKDOWN"; content:string; input:string|null; output:string|null};
  samples:Array<{input:string; output:string}>;
  license:{spdxId:string|null; notice:string; sourceUrl:string};
}
interface CatalogEntry {problem:ProblemSummary; status:"PUBLISHED"|"WITHDRAWN"}
interface CatalogSnapshotPage {
  snapshotId:UUID; catalogVersion:Id; items:CatalogEntry[];
  nextCursor:string|null; expiresAt:Instant;
}
interface LanguageCapability {
  languageId:string; displayName:string; languageFamily:string;
  compilerVersion:string; sourceFilename:string; analysisSupported:boolean;
}
interface LanguageCapabilities {languages:LanguageCapability[]; capabilityVersion:string}
type ImportStatus = "QUEUED"|"RUNNING"|"SUCCEEDED"|"PARTIAL"|"FAILED";
interface ImportItem {
  packagePath:string; status:"PENDING"|"VALIDATED"|"REJECTED";
  problemId:Id|null; problemVersionId:UUID|null;
  licenseStatus:"PENDING"|"VERIFIED"|"MISSING"|"REVIEW_REQUIRED";
  validationStatus:"PENDING"|"PASSED"|"FAILED"; errors:TaskError[];
}
interface ImportJob extends TaskBase {
  importJobId:UUID; status:ImportStatus; source:"OJ_LAB";
  repositoryUrl:"https://github.com/oj-lab/problem-packages";
  sourceRevision:string; packageCount:number; completedPackageCount:number;
  items:ImportItem[];
}
```

平台发布题的 title 必须非空，url 固定 null，frontend 按 problemId 导航。难度有经过本平台确认的标定才为 `PLATFORM_RATING`；否则 `difficulty=null,difficultyScale=UNRATED`。上游 oj-lab 的难度/标签原值保留溯源，不能把其 1..10 直接变成 CF Rating。标签保持自由文本，可附平台规范化标签，但不能截断或伪造 CF 原标签。

`statement.content` 保留完整 Markdown；input/output 为可提取章节，不能提取时 null，不删除 content 内原文。只返回公开样例；隐藏输入、答案、参考代码、checker 路径、题包对象地址不得进入公开 DTO。历史详情保留指定版本的题面、限制和许可；指定版本 first_published_at=null 时 status=DRAFT，曾发布版本 status 为题目当前 PUBLISHED/WITHDRAWN；catalogVersion 始终为当前目录版本。

## 4. 题库与目录 API

调用方全部为 backend；它在公开代理处完成 Session/角色/资源归属校验。

| 方法、路径 | 用途 / 参数 | 成功响应 | 主要错误 |
|---|---|---|---|
| GET `/internal/v2/problems` | 题库列表。q?、tag?、minDifficulty?、maxDifficulty?、status?、page/pageSize | 200 Page<PlatformProblemSummary> | 400 INVALID_ARGUMENT；401 SERVICE_UNAUTHORIZED |
| GET `/internal/v2/problems/{problemId}` | 当前已发布版本详情；无 query/body | 200 PlatformProblemDetail | 404 PROBLEM_NOT_FOUND |
| GET `/internal/v2/problems/{problemId}/versions/{problemVersionId}` | 不可变指定版本，供本人旧提交回看、管理员预览 | 200 PlatformProblemDetail | 404 PROBLEM_NOT_FOUND；409 PROBLEM_VERSION_CONFLICT |
| GET `/internal/v2/languages` | 本部署实际可用语言能力，不猜编译器版本 | 200 LanguageCapabilities | 503 JUDGE_UNAVAILABLE |
| GET `/internal/v2/catalog-snapshots` | 一致目录快照。cursor?、limit=100 | 200 CatalogSnapshotPage | 400 INVALID_ARGUMENT；410 SNAPSHOT_EXPIRED |

列表筛选：q trim 后 1..100，题号/标题不区分大小写包含匹配；tag 1..128 精确匹配；难度边界正整数且 min≤max，只匹配非空 `PLATFORM_RATING`。status 默认为 PUBLISHED；内部受信 backend 可指定 DRAFT/WITHDRAWN，但只能经其 ADMIN 管理分支访问，普通公开列表只能 PUBLISHED。排序 `updatedAt DESC,problemId数值 DESC`。DRAFT 导入不推进公开目录版本。公开summary.updatedAt取题目公开更新时间，只在发布/撤下等公开变更更新；DRAFT版本预览取版本createdAt，创建草稿不会改变当前公开updatedAt或列表顺序。

当前详情必须 PUBLISHED，否则 404；内部历史端点可提供可用 DRAFT 供管理员预览，backend 普通用户仅可读曾发布版本或本人历史提交引用的版本。已撤下题仍可回看既有提交，但新提交返回 `PROBLEM_NOT_SUBMITTABLE`。从不接受跨题 versionId。

目录快照首次不传 cursor，冻结当前公开目录，包含 PUBLISHED 与 WITHDRAWN 墓碑，不包含 DRAFT。快照 `catalogVersion` 单调递增 Id，初始 1；发布、撤下、公开属性更改推进，重复操作无变化不推进。墓碑包含最后曾发布 ProblemSummary，使缓存可以正确移除候选。`limit` 1..1000，默认 100；首请求固定 limit，后续同 cursor 使用相同 limit。游标为有完整性保护的不透明值，含 snapshot/offset/limit，不由客户端拼接。TTL 30 分钟；过期 410 后必须整份重拉。

backend 收齐全部快照页，校验 snapshotId/catalogVersion 一致，再原子切换只读目录缓存；禁止跨版本拼接或以部分页宣布同步成功。缓存明确 `sourceOwner=judge-problem-service`，不能改题名/难度/发布状态。algorithm 的候选由 backend 推送，algorithm 不请求此接口。

v0.2 必须提供 `cpp17`（语言族 CPP、文件名 `main.cpp`、实际 GCC/Clang 版本完整显示）；可选 `c11`。java/python 仅在对应已安装且隔离验证通过时列出，不能将“计划支持”伪装成可用。每题 languageIds 与当前 capabilities 取交集；内部 languages.analysisSupported 是本服务配置的允许分析声明；backend公开值取该flag与algorithm capabilities.analysisLanguages交集，algorithm不可达时false，judge不调用算法。judger不因分析不可用拒绝合法判题。语言模板由服务端固定，用户只传 languageId。

## 5. 异步判题 DTO 与 API

```ts
type JudgeStatus = "QUEUED"|"DISPATCHING"|"RUNNING"|"COMPLETED"|"FAILED"|"CANCELLED";
type JudgeVerdict = "AC"|"WA"|"TLE"|"MLE"|"RE"|"CE"|"OLE"|"IE";
interface JudgeResult {
  verdict:JudgeVerdict; timeMs:number|null; memoryBytes:number|null;
  passedTestCount:number; totalTestCount:number; score:number|null;
  compileLog:string|null; diagnosticCode:string|null; judgedAt:Instant;
}
interface JudgeTask extends TaskBase {
  judgeTaskId:UUID; submissionId:Id; status:JudgeStatus; result:JudgeResult|null;
}
interface JudgeTaskRequest {
  requestId:UUID; submissionId:Id; problemRef:ProblemRef; languageId:string;
  sourceCode:string; sourceSha256:string;
}
```

| 方法、路径 | 请求与用途 | 成功响应 | 主要错误 |
|---|---|---|---|
| POST `/internal/v2/judge-tasks` | JudgeTaskRequest；为已存在业务 Submission 接收判题 | 首次 202 JudgeTask，同请求重放 200 | 400 INVALID_ARGUMENT/INVALID_PROBLEM_REF；409 PROBLEM_VERSION_CONFLICT/PROBLEM_NOT_SUBMITTABLE/LANGUAGE_NOT_SUPPORTED/IDEMPOTENCY_CONFLICT；413 SOURCE_TOO_LARGE；503 JUDGE_UNAVAILABLE |
| GET `/internal/v2/judge-tasks/{judgeTaskId}` | 查询状态与原始判题结果；不创建任务 | 200 JudgeTask | 404 TASK_NOT_FOUND |
| POST `/internal/v2/judge-tasks/by-request` | `{requestIds:UUID[]}` 1..100 个唯一 ID；恢复 POST 超时未知 task | 200 `{tasks:JudgeTask[],missingRequestIds:UUID[]}` | 400 INVALID_ARGUMENT |

仅接受 `source=PLATFORM,platform=startrack,problemVersionId!=null`；题版本须属于 problemId、已校验、有有效许可，且必须等于题目 currentPublishedVersion，否则409 PROBLEM_VERSION_CONFLICT；已撤下则409 PROBLEM_NOT_SUBMITTABLE。判题创建body上限2 MiB，GET任务结果与回调完整body统一≤32MiB；sourceCode UTF-8 非空白、≤262144 字节；sourceSha256 为源码原 UTF-8 字节 SHA-256 小写 hex，保留换行，不以 trim/格式化代码后重算。校验不通过不创建 task；backend 已有业务Submission遇确定性4xx拒绝时将其本地judgeStatus=FAILED、judgeTaskId/judgeResult=null、judgeError=原拒绝错误，不伪造远程IE或无限等待，不计能力失败；网络/依赖错误保留派发重试。接收成功必须 task+入队已持久化后返回。

`requestId` 固定标识一次提交判题尝试；网络重试复用完全相同的请求。v0.2 没有公开 rejudge/cancel API，也不允许对同业务 submission 创建第二个不同判题尝试。题包发布了新版不影响已接收任务，其版本、checker、限制、语言模板和沙箱版本全部冻结。

`by-request` 不存在项放 missingRequestIds，已知项按请求顺序返回，不以某项缺失返回整批404。响应仍使用本次 HTTP requestId，tasks 内 requestId 保留原创建请求，避免混淆。

状态机：

```text
QUEUED → DISPATCHING → RUNNING → COMPLETED
   └──────────┴──────────┴──→ FAILED
   └──────────┴──────────┴──→ CANCELLED（仅维护/服务关闭策略）
```

revision 初始1，每次可见状态/结果变更严格递增；租约心跳不增加。最终事实不可回退。COMPLETED 对应 AC/WA/TLE/MLE/RE/CE/OLE，error=null、result非空；FAILED 对应 IE 且 error非空；CANCELLED result=null、error非空；在途 result/error/finishedAt 均为 null。CE 为用户代码结果，不能记为基础设施FAILED。

第一阶段只发布经过验证的 batch/pass-fail 题，暂不发布 interactive、output-only、复杂计分题；识别并保留其包、以 PACKAGE_UNSUPPORTED 阻止发布，不删数据假装通过。批次测试按冻结 manifest 顺序调度，汇总第一个非AC测试；全通过为AC，编译失败为CE，运行输出越限为OLE，沙箱/题包/checker故障为IE。checker 的输出符合其约定判定才映射WA；checker超时/崩溃不能误判用户WA。执行能力复用 go-judge 与成熟 checker/验证工具，不重写安全隔离。

`passedTestCount` 为本次真正通过的测试数，totalTestCount为冻结包测试总数，0≤passed≤total；CE 为passed=0。timeMs=max 单测试CPU毫秒，memoryBytes=max 单测试峰值字节；未运行时均null。二元判题 score=null。compileLog≤16384 UTF-8字节并脱敏，只有本人/管理员经backend可读；不得返回隐藏输入、期望输出、用户 stdout/stderr、测试文件路径和源码工件地址。

| 本服务短码 | backend 训练统一 Verdict | 训练含义 |
|---|---|---|
| AC | ACCEPTED | 已解决 |
| WA / TLE / MLE / RE / CE | WRONG_ANSWER / TIME_LIMIT / MEMORY_LIMIT / RUNTIME_ERROR / COMPILE_ERROR | 有效失败尝试 |
| OLE | OTHER | 有效输出限制失败，UI仍显示OLE |
| IE / CANCELLED | 不写有效训练失败 | 基础设施/维护问题，不降能力分 |
| 在途 | PENDING | 不能算失败 |

## 6. Judge → Backend 结果事件

固定地址 `http://backend:8081/internal/v2/events/judge`，调用方 judge，Authorization 使用 `JUDGE_BACKEND_TOKEN`。不提供通用业务回调或用户自选URL。

```ts
interface CallbackEvent<T> {
  eventId:UUID;
  eventType:"JUDGE_TASK_UPDATED"|"ANALYSIS_JOB_UPDATED"|"PROFILE_JOB_UPDATED";
  occurredAt:Instant; requestId:UUID; aggregateId:UUID; revision:number; payload:T;
}
// 本服务只发送 CallbackEvent<JudgeTask>，eventType="JUDGE_TASK_UPDATED"。
```

| 方法、路径 | 输入 | 成功响应 | 错误 |
|---|---|---|---|
| POST backend `/internal/v2/events/judge` | CallbackEvent<JudgeTask> | 200 `{accepted:true,duplicate:boolean}`，套ApiResponse | 401 SERVICE_UNAUTHORIZED；404 TASK_NOT_FOUND；409 EVENT_CONFLICT；400 INVALID_ARGUMENT |

aggregateId=judgeTaskId、revision=payload.revision、requestId=payload.requestId=原JudgeTaskRequest.requestId。事件 HTTP `X-Request-Id` 与事件 requestId 相同，body hash 以固定字段 canonical JSON计算；eventId 在所有投递重试期间不变。

task 状态提交与 callback outbox 同事务。backend inbox 先校验任务映射、submissionId，按 requestId 匹配 backend 已冻结输入上下文（JudgeTask不回显源码hash/版本）；重复eventId/较旧revision ack200，不覆盖新结果；同revision不同payload hash为409 EVENT_CONFLICT并告警。backend 尚未关联 POST 返回的任务时，事件可能先到达：它用已持久化派发requestId绑定映射；未知任务404由judge持久重试，不能丢事件。

投递按1、2、4、8、16、30秒退避，持续24小时后标死信供对账；404/409/认证错误保留并记录，不假成功。backend 每30秒轮询非终态任务和未完成回传对账项；POST超时先查 by-request，再复用原请求派发。轮询和回调共用同一投影校验，不随到达顺序覆盖。服务重启继续队列和outbox，不依赖内存channel或Redis pubsub。

backend 收到判题终态先保存公开投影/训练状态并触发基础学习画像；COMPLETED 随后异步调用 algorithm 静态分析，CE 也可分析源码；FAILED/CANCELLED 标分析SKIPPED。分析失败不回滚判题，分析SUCCEEDED/PARTIAL再触发特征版本与新画像。judge不读/写分析表，不直接调算法。

## 7. 导入、发布与撤下

| 方法、路径 | 请求 / 用途 | 成功响应 | 主要错误 |
|---|---|---|---|
| POST `/internal/v2/problem-imports` | `{requestId:UUID,source:"OJ_LAB",repositoryUrl:"https://github.com/oj-lab/problem-packages",revision:string,packagePaths:string[]}` | 首次202 ImportJob，重放200 | 400 INVALID_ARGUMENT；409 IDEMPOTENCY_CONFLICT；422 PACKAGE_INVALID；503 JUDGE_UNAVAILABLE |
| GET `/internal/v2/problem-imports/{importJobId}` | 管理员查询导入结果；backend代理 | 200 ImportJob | 404 TASK_NOT_FOUND |
| POST `/internal/v2/problems/{problemId}/metadata-versions` | `{requestId:UUID,baseProblemVersionId:UUID,tags:string[],difficulty:number\|null,difficultyScale:"PLATFORM_RATING"\|"UNRATED"}`；创建不可变元数据新版本 | 首次201 PlatformProblemDetail（DRAFT），重放200 | 400 INVALID_ARGUMENT；404 PROBLEM_NOT_FOUND；409 PROBLEM_VERSION_CONFLICT/IDEMPOTENCY_CONFLICT |
| POST `/internal/v2/problems/{problemId}/publish` | `{requestId:UUID,problemVersionId:UUID}`；原子切当前版本/发布目录 | 200 PlatformProblemDetail | 404 PROBLEM_NOT_FOUND；409 PROBLEM_VERSION_CONFLICT；422 PACKAGE_INVALID/PACKAGE_LICENSE_MISSING/PACKAGE_UNSUPPORTED |
| POST `/internal/v2/problems/{problemId}/withdraw` | `{requestId:UUID,reason:string}`；撤下新提交入口，保留已接收任务 | 200 `{problemId:Id,status:"WITHDRAWN",catalogVersion:Id}` | 404 PROBLEM_NOT_FOUND；409 IDEMPOTENCY_CONFLICT |

backend 对应公开代理为 `POST /api/v1/admin/problem-imports`、`GET /api/v1/admin/problem-imports/{importJobId}`、`POST /api/v1/admin/platform-problems/{problemId}/publish` 、`/metadata-versions` 与 `/withdraw`；全部ADMIN。公开请求去掉 requestId，写操作必需 `Idempotency-Key: UUID`，backend固定内部requestId；不直接写judge数据库。

revision 仅完整40位不可变commit；packagePaths 1..100、唯一、仅仓库 `problems/` 下规范化相对题目录，禁止URL、绝对路径、`..`、归档越界符号链接。reason 1..500。`metadata-versions` 只由ADMIN创建，baseProblemVersionId须属于problemId；tags≤32项，每项trim后1..128、去重，UNRATED必须difficulty=null，PLATFORM_RATING必须为可信人工标定的正整数，不能传CF_RATING。新version复制base不可变题面/限制/语言/许可并引用同一只读题包，只变tags/评级；返回新versionId、status=DRAFT，不改已有已发布版本或currentVersion，后续publish选择新版本。该新版本预览的DRAFT状态是待发布版本视图，历史已发布版本仍返回题目当前状态。只有固定上游源，不实现任意网络抓取或任意压缩包执行入口。仓库拉取在离线导入环境固定commit后停止网络，严格校验原包checksum。

导入状态 `QUEUED→RUNNING→SUCCEEDED/PARTIAL/FAILED`。items与请求顺序一致；completedPackageCount为VALIDATED+REJECTED数量，终态=packageCount。SUCCEEDED全VALIDATED/error=null；PARTIAL至少一VALIDATED及一REJECTED/error非空；FAILED无VALIDATED/error非空。整体拉取失败也把全部item记REJECTED。VALIDATED只创建不可变DRAFT版本，不自动发布。校验/许可失败在item.errors，GET任务仍200。

发布要求技术PASSED、许可VERIFIED、受支持batch模式、有题面/样例/隐藏测试、参考解通过全部测试、checker与资源限制验证成功。逐题许可审核可以明确记录根MIT继承及来源覆盖范围；不能因仓库LICENSE存在就不检查题包内第三方内容。MISSING/REVIEW_REQUIRED均阻止publish。发布和目录版本切换同事务；将新版本发布后，旧已接受task继续旧版本，历史题面不可改。

## 8. 开源复用、题包兼容与安全运行

以下为2026-10-07核验的官方版本，后续实现以锁定依赖/fork或submodule方式二次开发；保留原目录/许可和独立适配层，禁止复制成无来源自研OJ。

| 上游 | 锁定基线 / 许可 | 复用范围 |
|---|---|---|
| [criyle/go-judge-demo](https://github.com/criyle/go-judge-demo/tree/ed6cc756082ee9f7d792238185dc3e6a47c84b52) | commit `ed6cc756082ee9f7d792238185dc3e6a47c84b52`；MIT | 复用/参考Submit→调度→双向gRPC Judge→progress/finished→updateLoop流程；对外封装本契约 |
| [criyle/go-judge](https://github.com/criyle/go-judge/tree/v1.13.0) | `v1.13.0` / `e9d70a0d9a3df0c62182a6e7090d7af650a1d5f8`；MIT，另保留seccomp/NOTICE的Moby Apache-2.0归属 | 底层编译/执行、安全沙箱、CPU/内存/输出限制，不改写隔离实现 |
| [oj-lab/problem-packages](https://github.com/oj-lab/problem-packages/tree/a4e1d6f106879043eb30af640ba46d0fcbf8053f) | commit `a4e1d6f106879043eb30af640ba46d0fcbf8053f`；仓库根MIT | 初始14个题包，保留原包与逐题来源/许可审核，仓库许可不替代题包审查 |
| [Kattis/problemtools](https://github.com/Kattis/problemtools/tree/v1.20260907) | `v1.20260907` / `6010cbaa37a1612117f49566b2fff8646d53faa2`；MIT | verifyproblem校验题面、测试、validator、参考提交与结构；复用成熟输出验证器 |

原demo [grpc_server.go](https://github.com/criyle/go-judge-demo/blob/ed6cc756082ee9f7d792238185dc3e6a47c84b52/demoserver/grpc_server.go) 和 [judger/grpc.go](https://github.com/criyle/go-judge-demo/blob/ed6cc756082ee9f7d792238185dc3e6a47c84b52/judger/grpc.go) 使用内存channel、MongoDB和直接请求中的commands/inputAnswer。本平台在外围增加PostgreSQL持久任务、幂等、租约和outbox，以Repository/调度适配替换demo示例存储及不可信入参；编译执行、安全限制与测试执行协议保留上游组件。不能开放原demo裸submit/shell接口，不能让用户传测试答案或任意命令。

题包兼容层固定 `adapterVersion=ojlab-kattis-v0.2.1`，原始格式 `oj-lab-v1`，生成平台manifest与用于 `problemtools legacy` 的独立验证视图。上游Markdown题面、`oj-lab-metadata`、`.timelimit`、带连字符shortname不完全兼容legacy（legacy题面要求TeX），不能直接声称原包无修改通过verifyproblem。兼容层保留Markdown原件，生成转义正确的验证题面，映射合法短名、将扩展字段转manifest、按源格式显式转换秒/内存/输出单位；原值与转换策略均记录。默认checker必须保持题包规定的token/浮点/大小写语义，不用随意字符串TrimSpace替代。`2023-07-draft`在当前工具尚未完整支持，不作为生产兼容捷径。技术错误/参考解错误阻断发布，只有已登记的格式差异可以适配；升级后全量回归再切版本，不重写老包。

四个业务容器各有Dockerfile与锁文件。本服务镜像同时运行非root API/持久worker、受监督的demo judger组件及go-judge进程；底层仅监听 `127.0.0.1:5050`（不发布宿主端口，设置独立底层token且不复用S2S密钥），API监听 `0.0.0.0:8082`。不增加第五业务容器。发布镜像记录实际digest，文档不编造digest。

沙箱宿主必须Linux及可用cgroup；生产选现代Linux/cgroup v2，go-judge启动 `--no-fallback`，禁 `--no-seccomp`。锁定v1.13.0源码默认加载Moby seccomp，与该版旧中文README描述不同，按[source](https://github.com/criyle/go-judge/blob/v1.13.0/env/env_linux.go)及[config](https://github.com/criyle/go-judge/blob/v1.13.0/cmd/go-judge/config/config.go)配置。官方Docker快速启动需要privileged；不能宣称无权限普通Docker默认即可安全运行。部署人员需为本服务准备沙箱所需namespaces/cgroup委派及经验证的受限能力/挂载；若无法验证限制，readiness失败，不能退化为普通exec或rlimit冒充安全隔离。官方privileged方式仅可用于隔离测试主机验证上游行为，不能视为本系统生产默认。

go-judge进程不持业务数据库/S2S token/SMTP等凭据；只接收其独立底层API token；API与导入worker只向其提交最小任务。执行文件系统只挂当次输入、工作目录及受控工具链；不挂backend源码/桶、宿主根、Docker socket，提交程序无网络。导入参考程序/validator也按不可信代码隔离执行，不能因来自开源仓库就在API进程内运行。CPU/内存/超时/输出限制、禁网、任务间文件隔离实测通过才ready；四服务同机需限制沙箱并发，防止挤占backend/algorithm资源。

## 9. 错误、恢复与独立验收

| HTTP | code | 处理 |
|---|---|---|
| 400 | INVALID_ARGUMENT / INVALID_PROBLEM_REF | 输入不符合schema、SHA或身份组合，修正后新请求 |
| 401 | SERVICE_UNAUTHORIZED | 缺失/错误服务密钥，不重试认证错误 |
| 404 | PROBLEM_NOT_FOUND / TASK_NOT_FOUND | 无资源或错误身份；回调未知task保留并对账 |
| 409 | IDEMPOTENCY_CONFLICT / REQUEST_IN_PROGRESS / PROBLEM_VERSION_CONFLICT / PROBLEM_NOT_SUBMITTABLE / LANGUAGE_NOT_SUPPORTED / EVENT_CONFLICT | 按具体code修正/刷新，不生成第二份Submission |
| 410 | SNAPSHOT_EXPIRED | 丢弃未完成快照并重拉 |
| 413 | SOURCE_TOO_LARGE / INPUT_TOO_LARGE | 超源码/body大小；不截断代码 |
| 422 | PACKAGE_INVALID / PACKAGE_LICENSE_MISSING / PACKAGE_UNSUPPORTED | 阻止发布，不伪装为成功题库 |
| 429 | RATE_LIMITED | Retry-After秒数；backend对每用户提交限流 |
| 503 | JUDGE_UNAVAILABLE | 依赖/readiness/过载，backend保留提交派发outbox |
| 500 | INTERNAL_ERROR | 记录requestId；不暴露堆栈/SQL/密钥 |

异步error还可使用 `JUDGE_INTERRUPTED`、`SANDBOX_FAILURE`、`PACKAGE_VALIDATION_FAILED`、`PACKAGE_SOURCE_UNAVAILABLE`；TaskError.retryable只在可恢复依赖/租约中断时true。backend网络不可达映射503 JUDGE_UNAVAILABLE，超时504 JUDGE_TIMEOUT，非法DTO映射502 JUDGE_BAD_RESPONSE，均保留业务Submission和历史结果；GET任务FAILED仍200。

租约领取前持久化DISPATCHING，确认底层执行后RUNNING；worker每30秒续180秒，失效token禁止回写。崩溃恢复同task、同冻结版本重新执行，最多3次；每次新执行工件隔离，不能把旧进程结果写新租约。耗尽FAILED/IE+JUDGE_INTERRUPTED。持久task/outbox的终态不复活；历史包和结果只读保留。

本负责人仅用backend mock即可完成：导入→逐题许可审核→校验→发布→目录快照；cpp17的AC/WA/TLE/MLE/RE/CE/OLE与IE；相同requestId只一task；POST超时查by-request；版本更新后在途任务仍旧包；重复/乱序事件不回退；重启恢复；隐藏数据不泄漏；撤题阻止新提交且旧记录可读；cgroup/seccomp与隔离实测。最后与backend跑Submission→judge→结果投影→analysis→画像→推荐闭环，分析服务停机不改变已完成判题。
