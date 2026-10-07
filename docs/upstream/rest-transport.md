# Private go-judge REST transport

Scope: Q-008 / [Issue #15](https://github.com/STAR-Ability/code-startrack-judge/issues/15), contract publication `0.2.0`. The project-owned [restclient](../../internal/runtime/restclient/) implements bounded private file/execution transport. It does not implement the role-aware demo adapter, supervision, sandbox isolation, scheduling, or a public execution API. This transport and its mock tests do not complete Issue #15 or qualify a Linux deployment.

## Pinned source and ownership

The wire projection targets go-judge `v1.13.0`, commit `e9d70a0d9a3df0c62182a6e7090d7af650a1d5f8`, recorded in [upstream.lock.json](../../upstream.lock.json). Relevant verbatim upstream sources are:

- [REST request/result model](https://github.com/criyle/go-judge/blob/e9d70a0d9a3df0c62182a6e7090d7af650a1d5f8/cmd/go-judge/model/model.go), including optional output-name suffixes and JSON string file output.
- [Execution handler](https://github.com/criyle/go-judge/blob/e9d70a0d9a3df0c62182a6e7090d7af650a1d5f8/cmd/go-judge/rest_executor/cmd_handler.go) and [file handler](https://github.com/criyle/go-judge/blob/e9d70a0d9a3df0c62182a6e7090d7af650a1d5f8/cmd/go-judge/rest_executor/file_handler.go).
- [Run statuses](https://github.com/criyle/go-judge/blob/e9d70a0d9a3df0c62182a6e7090d7af650a1d5f8/envexec/run_status.go) and [file-error string enums](https://github.com/criyle/go-judge/blob/e9d70a0d9a3df0c62182a6e7090d7af650a1d5f8/envexec/cmd.go).
- [Cache ID generation](https://github.com/criyle/go-judge/blob/e9d70a0d9a3df0c62182a6e7090d7af650a1d5f8/filestore/interface.go), [local file store](https://github.com/criyle/go-judge/blob/e9d70a0d9a3df0c62182a6e7090d7af650a1d5f8/filestore/file_local.go), and [runtime authentication/cache TTL configuration](https://github.com/criyle/go-judge/blob/e9d70a0d9a3df0c62182a6e7090d7af650a1d5f8/cmd/go-judge/main.go).

These are owned Go wire types and HTTP handling, with no copied isolation implementation. Upstream license texts, provenance, and reviewed modifications remain under [dependencies](dependencies.md), [licenses](../licenses/), and [patches](patches.md). A future runtime upgrade requires explicit mapping and regression review; unknown response fields/statuses fail closed.

## Endpoint, credentials, and supported routes

The endpoint is fixed to `http://127.0.0.1:5050`, as required by [the integration contract](../contracts/v0.2/integration.md) and [Q-008](../contracts/v0.2/clarifications.md). There is no endpoint option. Production disables environment proxies and automatic compression, checks every request destination and method/path, restricts dialing to that loopback address, and refuses redirects. Only these routes are available:

| Operation | Request | Successful response |
| --- | --- | --- |
| Upload | `POST /file`, multipart field `file`, fixed filename `blob` | JSON string cache ID |
| Execute | `POST /run`, JSON `{requestId,cmd:[...]}` | Bare JSON result array |
| Download | `GET /file/{id}` | Raw bounded bytes |
| Delete | `DELETE /file/{id}` | HTTP 200, or already-absent HTTP 404 |

Every call sends `Authorization: Bearer <runtime-token>` and `Accept-Encoding: identity`. The constructor receives only the low-level runtime credential. The supervisor must validate that credential scopes are independent; S2S, database, storage, and Backend credentials must never be passed into the runtime client for comparison. Client/options formatting redacts credentials; neither token values nor raw response errors are included in returned errors. `RoundTripper` injection is solely a trusted mock seam and must be left unset in production.

This client cannot prove the server's bind address, disabled gRPC/debug/metrics listeners, safe server logging, or submission-network denial. Reviewed upstream patches and actual Linux listener/process/isolation evidence remain required.

## Exact mappings and binary fidelity

| Owned field | REST field | Unit/meaning |
| --- | --- | --- |
| `CPULimitNS`, `ClockLimitNS` | `cpuLimit`, `clockLimit` | Integer nanoseconds |
| `MemoryLimitBytes`, `StackLimitBytes` | `memoryLimit`, `stackLimit` | Integer bytes |
| `ProcessLimit` | `procLimit` | Process count |
| `CopyOutMaxBytes` | `copyOutMax` | Integer bytes |
| Cached stdin/copy-in ID | `files[].fileId`, `copyIn[name].fileId` | Opaque cache identity |
| Bounded stdout/stderr collector | `files[].name`, `max`, optional `pipe` | Owned relative name and byte cap |
| Cached output names | `copyOutCached` | Optional names append `?` |
| `CPUTimeNS`, `WallTimeNS` | `time`, `runTime` | Integer nanoseconds |
| `MemoryBytes`, `ProcessPeak` | `memory`, optional `procPeak` | Bytes and process count |
| `CachedFiles` | `fileIds` | Output-name-to-cache-ID mapping |

The runtime model's inline `files` output is `map[string]string`; JSON string encoding replaces invalid UTF-8 bytes. Therefore source, test inputs, executable artifacts, stdout/stderr, and other output bytes must use upload/cache/raw-download operations. Inline input and inline output are unavailable. Every stdout/stderr collector must have a unique name explicitly present in `copyOutCached`; unsupported collector mappings fail before any network request. Stdin must be a cached input. Additional regular cached artifacts are allowed, including optional compiler outputs.

All numeric wire values use integer Go types, including values above `2^53`; there is no JSON `float64` intermediate. Required result measurements/status/exit status are checked for presence and supported range. Results must match the command count. Output IDs must be valid, requested, unique across returned results, and distinct from input IDs. Accepted results require every nonoptional cached output; failure statuses may omit outputs.

The transport preserves all 14 pinned statuses: `Invalid`, `Accepted`, `Wrong Answer`, `Partially Correct`, `Memory Limit Exceeded`, `Time Limit Exceeded`, `Output Limit Exceeded`, `File Error`, `Nonzero Exit Status`, `Signalled`, `Dangerous Syscall`, `Judgement Failed`, `Invalid Interaction`, and `Internal Error`. It does not turn these into business verdicts: compiler, contestant, validator, reference solution, and checker roles have different exit/status meanings.

Pinned `fileError[].type` is a string enum: `CopyInOpenFile`, `CopyInCreateDir`, `CopyInCreateFile`, `CopyInCopyContent`, `CopyOutOpen`, `CopyOutNotRegularFile`, `CopyOutSizeExceeded`, `CopyOutCreateFile`, `CopyOutCopyContent`, `CollectSizeExceeded`, or `Symlink`. Numeric or unknown values fail validation. Raw error messages and file paths are discarded; results retain only `HasError` and `FileErrorCount` structural diagnostics. Hidden output bytes require an explicit private download and must not enter public DTOs or normal logs.

## Bounds and excluded features

The following defaults are also hard ceilings; trusted deployment configuration may lower them:

| Bound | Ceiling |
| --- | --- |
| Per upload/download/collector | 64 MiB |
| Execution JSON request | 2 MiB |
| JSON/delete response | 1 MiB |
| Commands per request | 8 |
| File mappings/owned cache identities | 256 |

Uploads allow at most 1 KiB multipart framing beyond the file-byte bound. Downloads bound actual bytes even with missing/misleading `Content-Length`. All response bodies are closed. The HTTP timeout is five minutes; dial timeout and independent cleanup timeout are each five seconds. Commands require finite positive CPU/wall/memory/output/process bounds; the wall bound cannot be lower than the CPU bound. Paths are canonical relative POSIX names, and IDs are the pinned eight-character uppercase base32 cache identifiers. Environment keys are limited to `PATH`, `LANG`, `LC_ALL`, `HOME`, and `TMPDIR`; the orchestrator must supply only owned nonsecret values.

Caller-provided host paths, URLs, inline content, symlinks, streaming/TTY descriptors, arbitrary pipe mappings, and runtime configuration/list/diagnostic routes are unsupported. Absolute executable arguments and remaining argv are constructed by service-owned execution profiles. This internal package exposes no public handler; the future role-aware adapter must not forward caller-selected commands or templates.

## Cancellation, cleanup, and ambiguous outcomes

Adapters should defer `Session.Close()`. A session owns only IDs acknowledged by its uploads/runs, checks input ownership, bounds accumulated IDs, and serializes operations so close cannot miss an in-flight acknowledged allocation. `Close` deletes inputs and outputs using a separate bounded context after execution cancellation; absent files are successful cleanup. Failed IDs are retained for a later `Close` retry, and cleanup failure is returned.

Structurally parsed invalid execution responses attempt deletion of valid acknowledged output IDs while excluding input IDs. A failed attempt sets `Error.CleanupFailed`; the adapter/supervisor must escalate this flag. Those protocol-error output IDs are not retained by `Session`, so another session close cannot retry their deletion. A bounded, nonzero runtime `FileTimeout`, cache-size controls, and supervised cleanup remain deployment requirements.

Lost/unparseable upload or execution responses cannot reveal all allocated IDs. Context cancellation/deadlines are preserved, but they do not prove whether the runtime executed or allocated files. `requestId` is correlation, not runtime deduplication. `Error.Retryable` classifies availability only: it does not make `POST /run` or `POST /file` idempotent or authorize blind replay. The orchestrator must use fenced task recovery for ambiguous execution outcomes, with cache TTL covering orphaned allocations.

## Recorded validation

On 2026-10-08, Go 1.26.8 on macOS (`darwin/amd64`) passed the targeted restclient tests, race tests, and `make check` (foundation/native checks, license inventory, and 60 independently verified ECMAScript canonical vectors). Fixtures derived from the pinned source exercise exact REST field names/bare-array responses, all statuses and file-error string enums, integers above `2^53`, NUL/invalid-UTF-8 byte fidelity, optional output suffixes, preflight rejection, bounds/body closure, fixed destination/proxy/redirect controls, credential/diagnostic redaction, in-flight cancellation, owned cleanup retries, and protocol cleanup failure signaling. Independent review corrected the string enum and cached collector mapping gaps.

These handlers are mocks, not a running pinned runtime. Real patched-runtime protocol tests, mature demo compile/test/checker behavior, listener inventory, sibling-process credential isolation, cancellation/cleanup under real execution, and adversarial Linux sandbox qualification remain required before Q-008 is marked implemented/qualified. See the [compatibility matrix](compatibility-matrix.md) for actual upstream qualification status.
