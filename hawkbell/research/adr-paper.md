> **Historical design record.** Research report on the uber/ADR paper and slides: production architecture, scale, headline results, and what the paper withholds.
>
> - Written on 2026-11-11, during design (the file was last modified 2026-11-11 16:57 UTC on the build machine; it reads the paper (PDF dated 2026-04-24) and slides (2026-05-21) in a local clone).
> - Written before the project had a name; the text does not name it. The project was then called spoor and was renamed hawkbell on 2026-11-12 (commit d261f98).
> - Findings, numbers, plans and file names describe the design, the prototypes and the sources as they were then, not the release. For what the release does, read [docs/ASSUMPTIONS.md](../docs/ASSUMPTIONS.md) and [docs/LIMITATIONS.md](../docs/LIMITATIONS.md).
> - Local paths (`/home/user/...`, `/root/...`, `/tmp/claude-0/...`, `$S/...` for the session scratch directory, and work-directory variables the text defines) name directories on the build machine, a Linux sandbox VM. The scripts, outputs and downloaded sources in them are not in this repository.
> - Redactions: none.
> - Below the line the text is the original, unchanged except for the redactions listed. Other records cite these files by line number; such a number counts from the original's first line, which is line 12 of this file.

---

# ADR paper and slides: what Uber actually built, measured and conceded (key: adr-paper)

## Executive summary (5 lines)
1. The paper's sensor is NOT hook-based: it is an hourly batch scraper of agent SQLite/JSONL caches on corporate MacBooks, shipped as JSON through **Fluent Bit** to GCP Cloud Logging, Pub/Sub, Kafka, Hive and an Elasticsearch-like index, with detection in Airflow. Hooks appear only in the (unreleased) prevention layer.
2. Headline bench result is small-n: 28/42 attacks caught (recall 0.667), 0/260 false positives, $0.024 and 18.5 s per task, using GPT-4o triage plus Claude Sonnet reasoning with three MCP context providers. Seven of 17 techniques have exactly one malicious task.
3. Production tells a different story from the bench: of alerts sent to humans, 34% TP, 17% "TP non-malicious", 49% FP; credential alerts "exceeded the capacity for manual review"; prompt injection was "surprisingly rare", secrets exfiltration was the dominant finding.
4. The only quantified prevention is a regex+entropy pre-prompt hook (206 TP / 6 FP, precision 97.2%, no recall given). Explorer (red-team engine) and Prevention are withheld; Explorer has no reported quantitative results.
5. The paper is silent on tamper resistance, employee consent, Windows, containers, MDM/EDR integration, discovery, and production cost. Those are the openings.

Legend: **[V]** read in primary source this session; **[I]** my inference/arithmetic from verified numbers; **[U]** not verified.
Sources: `/home/user/uber/adr/docs/adr-paper.pdf` (15 pp., MLSys 2026 Industry Track, PDF dated 2026-04-24; all pages read), `/home/user/uber/adr/docs/adr-mlsys-2026-slides.pdf` (11 slides, 2026-05-21; all read), `docs/OPEN_SOURCE_REVIEW.md`, `docs/REPRODUCIBILITY.md`, `docs/BASELINE_REPLICATION.md`, `NOTICE.md`, `CONTRIBUTING.md`, `.claude/skills/submit-malicious-skill/SKILL.md`, plus spot checks in `Detection/` and `Sensor/README.md`. arXiv id 2605.17380 is as stated in repo docs; arXiv itself not fetched [U].

## 1. Production architecture and scale

Pipeline, Figure 4, paper p.4 [V], labels verbatim:

```
Corp Laptops: Progress Chef --Deploy/Manage--> ADR Sensors --json--> Fluentbit
  --stackdriver--> GCP Cloud Logging --Pub/Sub--> "Secured Kafka for ingest logs"
  --traskor--> Hive Database (long-term storage) --Presto SQL--> Airflow Pipelines
  --traskor--> Griffith (index) --Elastic Search API--> Airflow Pipelines
  Airflow Pipelines --Detection Signals--> Griffith (index)
```

- Detection runs server-side in **batch Airflow pipelines**, not on the endpoint and not inline. Alerts go to a human review queue (p.9 §6.1) [V].
- Sensor cadence: "runs on an hourly schedule ... each run takes 0.182 seconds on average" (p.4) [V]. No CPU/RAM/disk numbers, no fleet-wide overhead numbers.
- Deployment config management is Chef. No MDM, osquery, Fleet or EDR integration is described anywhere [V: grep of full text].

Scale numbers:

| Metric | Paper (data to Oct/Nov 2025) | Slides (May 2026) |
|---|---|---|
| Hosts | "over 7,200 unique hosts", "corporate MacBook endpoints (Intel and ARM)" (p.1, p.9) | "30k endpoints, macOS + Linux devpods" (s.4) |
| Sessions/day | "over 10,000" (first session 2024-12-15; >=100/day 2025-04-10; >=10,000/day 2025-10-28; Fig. 8 p.11) | "200,000+ sessions per day" (s.2, s.4) |
| Duration | "over ten months" | n/a |
| Agents covered | Cursor, Cline, Claude Code (p.4) | Cursor, Claude, Codex, Gemini, Warp, Cline (s.5) |
| Employees, events/day, storage volume, production cost | **not reported** | **not reported** |

Slide 2 quotes a headline "Uber Burns Its 2026 AI Budget In Four Months On Claude Code" [V]. Repo README claims "7+ AI coding tools on macOS, Linux, and Windows" plus customer-facing support agents in production [V README, not in paper].

Cost extrapolation [I]: bench cost $0.024/task x 200k sessions/day = about $4.8k/day (about $1.75M/yr) if bench cost held; it would not, since triage cost of $0.017 at GPT-4o $2.50/M input implies roughly 7k input tokens per task, far below a real coding session. The paper gives no production cost at all.

## 2. Threat model and taxonomy

Three risk classes (p.3): data exfiltration and leakage; unauthorized system access; operational disruption. Adversary exploits "the semantic gap" (p.3). Scope is explicitly "AI agents operating through MCP".

Sources for the taxonomy (p.5 §4.1): (i) MITRE ATLAS and OWASP (LLM06:2025 Excessive Agency is the only OWASP item cited), (ii) incident reports: JFrog CVE-2025-6514 mcp-remote RCE, Invariant Labs (GitHub MCP, tool poisoning, toxic flows, WhatsApp MCP), Microsoft Defender, Zenity AgentFlayer, CyberArk, Solo.io, Trend Micro, (iii) Uber telemetry and red-team conversations. The repo taxonomy file carries no ATLAS/OWASP ID mapping [V: grep of `Detection/context_providers/data/threat_repository.yaml`].

Five tactics, 17 techniques (Table 3 p.15; IDs from the repo YAML; malicious-task counts from `Detection/tasks.json`, 43 tasks in repo vs 42 in paper) [V]:

| Tactic (YAML key) | ID | Technique | Tasks |
|---|---|---|---|
| Initial Access & Execution (`initial_compromise`) | ADR.T0001 | Insecure Supply Chain for Agentic Components | 1 |
| | ADR.T0002 | Indirect Prompt Injection | 3 (2 in paper set) |
| | ADR.T0003 | Agentic Control-Flow Hijacking | 13 |
| | ADR.T0004 | Abuse of Agent's Code Interpreter | 1 |
| | ADR.T0005 | Insecure Output Handling | 1 |
| | ADR.T0006 | Tool Rug Pull | 1 |
| Permission Abuse | ADR.T0007 | Exploitation of Excessive Tool Permissions | 3 |
| | ADR.T0008 | Agent Identity Spoofing | 2 |
| Security Control Bypass | ADR.T0009 | Tool Shadowing | 2 |
| | ADR.T0010 | Tool Hallucination Manipulation | 1 |
| | ADR.T0011 | Malicious Agent Collusion | 2 |
| Reasoning & Data Manipulation | ADR.T0012 | Unvetted MCP Server Connection | 2 |
| | ADR.T0013 | Semantic Data Poisoning | 4 |
| | ADR.T0014 | Long-Term Goal Hijacking | 2 |
| | ADR.T0015 | Temporal Data Attack | 1 |
| Operational Impact | ADR.T0016 | Agent-Facilitated Resource Exhaustion | 3 |
| | ADR.T0017 | Model-Layer Denial of Service | 1 |

Threat repository record schema (Appendix A.2 p.14): `threat_framework.tactics.<tactic>.techniques[] = {id, name, detection_guidance[]}` (repo adds `description`); guidance lines tagged `[EAS]` or `[CURATED]` in the paper. The released YAML has 100 guidance lines (93 "Malicious:", 7 "Benign:") and **no** EAS/CURATED tags [V].

Mismatch worth exploiting [V slides s.3, s.8-10]: the slides' real-world concern list is secret exfiltration, destructive commands (`kubectl delete ns production`, `DROP TABLE`), data exfiltration past DLP, excessive agency, hallucinated scope ("delete folder A" also deletes "A_B"), supply chain (skills, packages), and human accountability ("Many people consistently use YOLO mode without sandbox. Others approve 50+ actions per session"). Most of these have no technique in the 17-item taxonomy.

## 3. Headline results

ADR-Bench: 302 tasks (42 malicious = 13.9%, 260 benign), 133 MCP servers (14 categories; 81.2% benign / 18.8% malicious servers), 729 tools, mean 28.5 tool calls/task (pp.6-7). Detector: GPT-4o triage, Claude Sonnet 4 reasoning, "no hyperparameter tuning" (p.7). Table 2 (p.9) [V]:

| Detector | Prec. | Recall | F1 | TP/FP | FPR | $/task | Mean lat. | $/TP | P95 lat. |
|---|---|---|---|---|---|---|---|---|---|
| **ADR-Bench** ADR | 1.000 | 0.667 | 0.800 | 28/0 | 0.000 | 0.024 | 18.5 s | 0.260 | 37.9 s |
| ALRPHFS | 0.333 | 0.405 | 0.366 | 17/34 | 0.130 | 0.001 | 9.2 s | 0.022 | 14.8 s |
| GuardAgent | 0.231 | 0.214 | 0.222 | 9/30 | 0.115 | 0.012 | 9.4 s | 0.407 | 12.5 s |
| LlamaFirewall | 0.167 | 0.190 | 0.178 | 8/40 | 0.153 | 0.459 | 93.8 s | 17.377 | 225.7 s |
| **AgentDojo** (38 mal/55 ben) ADR | 0.927 | 1.000 | 0.962 | 38/3 | 0.055 | 0.012 | 18.5 s | 0.029 | 47.3 s |
| ALRPHFS | 0.914 | 0.842 | 0.877 | 32/3 | 0.055 | 0.004 | 13.6 s | 0.011 | 17.0 s |
| GuardAgent | 0.771 | 0.711 | 0.740 | 27/8 | 0.145 | 0.010 | 10.1 s | 0.033 | 13.9 s |
| LlamaFirewall | 0.638 | 0.974 | 0.771 | 37/21 | 0.382 | 0.012 | 11.4 s | 0.030 | 23.0 s |

- Per-tactic recall (p.8): Initial Access & Execution 13/19 (68%); **Permission Abuse 1/5 (20%)**; Security Control Bypass 5/5; Reasoning & Data Manipulation 5/9 (56%); Operational Impact 4/4.
- Tiering (p.8, Fig. 7 p.10): triage alone resolves 40.7% of tasks (123) at $0.017 and 2.3 s; escalated path (180 tasks, 59.3%) $0.029 and 29.7 s. Of escalated tasks, 100% called source-code inspection, 96% threat intel, 92% policy.
- Ablations (p.8, Fig. 7d): no triage: recall 0.805, precision 0.943 (2 FP), $0.031, 28.1 s. No source code: P 0.828 / R 0.571 / F1 0.676. No threat intel: 0.923 / 0.585 / 0.716. No policy: 1.000 / 0.675 / 0.806 (policy provider adds nothing measurable).
- Production (p.9 §6.1): alerts labelled **TP 34%, TPNM 17%, FP 49%**. No absolute alert counts, no alerts/day, no analyst hours, no MTTD/MTTR. TPNM came from "internal Offensive Security teams and penetration testing"; FPs from "context-rich sessions such as analyzing large, multi-file codebases".
- Emulations (p.10 §6.3): internal CTF (`curl | python3` via custom shell tool) and an emulated Zenity AgentFlayer Jira-to-Cursor chain; both detected; n=2, no numbers.

Skeptic's notes:
- [I] n=42 gives a 95% Wilson interval for recall of about 0.52-0.79. 0/260 FPs bounds FPR only below about 1.2% (rule of three), which at 200k sessions/day is still up to about 2,300 false alerts/day. Production FP share of 49% confirms the bench "zero FP" does not transfer.
- [I] Tier 1 is described as "high recall" but is the recall bottleneck: removing it raises recall 0.667 to 0.805. Triage also costs 59% of the escalated path per task; total saving is only 23% cost, 34% latency.
- [I] Ablation rows imply inconsistent denominators (33/41, 24/41, 27/40 malicious), and Fig. 7a totals 303 not 302: tasks were dropped per run.
- [V] Fig. 6 caption claims "consistently lower tail latency" but ADR's P95 (37.9 s) is 2.6-3x ALRPHFS/GuardAgent.
- [V] Released threat-intel guidance names benchmark servers (`config_manager`, `github_server`, `system_toolkit`, `cli_executor`, `openai_server`, all present in `mcp_servers_registry.json`/`tasks.json`). [I] Explorer-generated guidance was evolved in the same emulated environment used for scoring; no held-out split is described, so in-distribution leakage is plausible.
- [V] Baseline fidelity is weak: `Detection/config_detector.yaml` runs LlamaFirewall with `tool_role: []  # No tool scanning` and `gpt-4o-mini`, while the paper says "Llama Guard 3-8B ... default threshold settings". Paper says ALRPHFS thresholds 0.8/0.5 (p.7); `docs/BASELINE_REPLICATION.md` says 0.38/0.25. ALRPHFS and GuardAgent code was removed ("licensing"), so Table 2 baselines are not reproducible from the repo; that doc also wrongly says their recall/F1 "aren't published".
- [V] Repo has 304 tasks/134 servers, packed transcripts for 303; default reasoning model is now `claude-sonnet-4-6` and Tier 2 literally requires the `claude` CLI plus an OpenAI key. Bench transcripts are Claude-CLI sessions only (`claude_conversation.json`).

## 4. Explorer and Prevention: said vs withheld

Explorer (p.5) [V]: three agents (Red-Teaming, Eval in sandbox, Threat Intelligence). Evolutionary search with fitness `F = epsilon x sigma x tau^alpha` (execution depth, semantic naturalness, impact), `alpha = 1.2`, convergence constraint `rho x mu < 1.0` (survival rate x mutations per survivor). Output: guidance lines appended to the threat repository consumed by Tier 2 via `get_threat_framework`. **Withheld**: all code (README and REPRODUCIBILITY.md: "not released"), seed attacks, sandbox, and every quantitative result. The paper never reports how many variants were found or a before/after detection delta; the only indirect evidence is the no-threat-intel ablation (F1 0.800 to 0.716).

Prevention (pp.9-10 §6.2) [V]: Cursor and Claude Code hooks ("released ... late 2025"); "a regex-based detection mechanism using both pattern matching and entropy thresholds", "executed as a pre-prompt hook, which scans and, if necessary, blocks prompts before transmission". Result: "precision of 97.2% ... 206 true positives with only 6 false positives across 212 unique credentials from hundreds of thousands of MCP sessions". **Withheld**: code (README: "not included ... Stay tuned"), the 26 credential categories, recall, bypass rate, hook latency, user-friction data, and any prevention beyond secrets-in-prompts (tool-call blocking is not claimed). Paper's own verdict: "simple non-LLM checks work well for known attacks with static patterns ... but fail for attacks requiring reasoning about tool semantics".

## 5. Limitations, lessons, future work

There is no Limitations section. Concessions scattered through the text [V]:
- Detection is too late: "by the time detections were surfaced, credentials had often already been exposed externally, creating irreversible risk" (p.10).
- Alert volume: "the sheer volume of credential-related alerts quickly exceeded the capacity for manual review, requiring an automated response mechanism" (p.10).
- "moderate recall (0.667)" (p.8); bench "is not intended to mirror the true incidence rates" (p.9).
- Need "to model user personas and contextual intent" (p.9) to remove TPNM.
- Robustness risks: "brittle prompts, model updates/drift, and adversarial adaptation (e.g., attackers attempting to influence triage/reasoning)", mitigated only by "prompt/version pinning, change-control, and regression suites" (p.5). Prompt injection of the detector itself is not evaluated.
- Future work (p.12): "multi-agent coordination protocols, adaptive real-time prevention at the MCP gateway layer, and tighter integration with evolving MCP standards".
- Slides s.8: "all four concerns call for real-time guardrails that intervene before the agent executes". s.9: prompt injection "Surprisingly rare in production ... Action: No action needed currently"; personal "side hustles": "Monitor, do not block by default"; supply chain "Not rare - quickly picking up ... we found skills that collect unnecessary information" with action "Internal package registry with delay; scanning of skills". s.10: excessive/insufficient agency and hallucination: "These are open problems." s.3: "These risks led Uber to block OpenClaw and require security review before onboarding any new AI agent."

## 6. Sensor design rationale

- Why local-cache scraping (p.4) [V]: EDR "sees the file write but not the user prompt"; the sensor reconstructs "prompts -> reasoning -> tool calls -> outcomes" plus environmental context ("MCP server configurations and installed packages (pip, npm)"). Slides add skills and project `*.md` files.
- The only alternative discussed is an LLM/MCP gateway, rejected because it would "require changes to MCP hosts, are incompatible with streaming responses, and capture only partial information". Hooks are positioned as the blocking half of a "hybrid model: the sensor enables deep forensics, while inline hooks provide real-time blocking for high-severity credential leakage".
- **Not discussed at all** [V: full-text grep]: tamper resistance, user deleting or editing caches, sensor health/heartbeat, vendor format drift, cache retention windows, remote/SSH/devcontainer sessions, Windows, containers, OTel, eBPF/process telemetry, correlation with EDR.
- Repo sensor matches the paper's model (batch parsers over JSONL/SQLite; JSON/JSONL or OTLP out) and admits: "The OpenTelemetry exporter applies no redaction or field projection"; "a missing summary also cannot distinguish an idle endpoint from a sensor that never ran. Schedule runs and monitor last-seen health externally" (`Sensor/README.md`) [V].

## 7. Discovery rationale and measured coverage

The paper contains **no discovery component and no coverage measurement** [V]. "7,200 hosts" is hosts with sessions, not inventory coverage; no denominator of managed endpoints is given. Discovery exists only in the repo (`Discovery/`, stdlib-only Python, policy sanction states `approved|forbidden|unsanctioned|unknown`, reports coverage gaps) and in one slide sentence about blocking OpenClaw. The repo skill `.claude/skills/submit-malicious-skill/SKILL.md` defines a community indicator format worth mirroring:

```json
{"id": "skill-<name>-<first 12 hex>", "status": "active", "kind": "skill_sha256",
 "summary": "...", "references": [...], "target": {"sha256": "<skill_sha256>"}}
```
(skill assets carry `skill_sha256`, `install_path`, `provenance`, `archive.path`; reports use home-relative paths only.)

## 8. Privacy, consent, retention (p.9) [V]

- "Where possible, secrets and sensitive tokens are redacted from stored telemetry via automated scanning" (server-side, best-effort; not at the endpoint).
- "Telemetry is retained for 13 months for security purposes, with access limited exclusively to security personnel under a 'least-privilege' model."
- TLS in transit; "secure, auditable environments"; "rigorous review by legal, privacy, and risk management teams".
- **Absent**: employee notice or consent, opt-out, jurisdictional handling, works-council/GDPR treatment, minimisation modes, handling of personal sessions (which slides say are "a significant amount"). Full prompts and reasoning are collected.

## 9. What a competitor must match, and what is conceded unsolved

Must match: (a) causal session reconstruction for at least Cursor, Claude Code, Cline, Codex, Gemini CLI, Warp, Copilot CLI; (b) sub-second sensor runs; (c) Fluent Bit transport at 200k sessions/day and 30k endpoints; (d) tiered detection with enterprise context (tool source, threat intel, policy); (e) a public benchmark of at least 302 tasks/133 MCP servers/17 techniques with $0.024 and 18.5 s per session as the cost/latency bar and 0.80 F1 as the quality bar; (f) secrets-in-prompt blocking at about 97% precision.

Conceded or evidently unsolved: real-time detection (hourly batch plus Airflow); recall (one third of bench attacks missed, Permission Abuse 20%); production precision (49% FP); alert-volume automation; persona/context modelling; detector robustness to adversarial content; prevention beyond regex secrets; excessive agency and hallucinated-scope damage; YOLO-mode/approval-fatigue accountability; multi-agent protocols; gateway-layer prevention. Unaddressed entirely: tamper resistance, consent, Windows/containers in the paper, MDM/EDR/osquery integration, discovery coverage measurement, production cost.

## 10. Design implications for our platform

1. Fluent Bit is not a differentiator by itself: Uber already ships sensor JSON through Fluent Bit. Differentiate with first-class configs (tail/forward inputs, parsers, per-output examples), per-event records instead of whole-session blobs, and backpressure/dedup semantics.
2. Replace hourly scraping with streaming tail (seconds) plus optional hooks, so detection can precede exfiltration; keep batch scrape as fallback and for backfill.
3. Put a deterministic Tier 0 on the endpoint (secrets regex+entropy, destructive-command patterns, Unicode tag/bidi smuggling, known-bad skill hashes, permission-mode posture). The paper's own strongest production number comes from regex. Make LLM tiers optional and provider-neutral.
4. Treat posture as telemetry: YOLO/bypass modes, sandbox state, approvals per session, MCP configs, skills, project instruction files. These are the slide deck's top concerns and absent from the paper's taxonomy.
5. Redact at the edge with selectable privacy modes (metadata-only, redacted, full), configurable retention, and a documented notice model; ADR redacts server-side "where possible" and its OSS exporter redacts nothing.
6. Ship sensor health and integrity as queryable data (heartbeat, parser-drift counters, hook/config hashes) via osquery tables so Fleet policies can detect a silent or tampered sensor.
7. Use Fleet labels/teams as persona context (offsec, red team) to suppress the 17% TPNM class, and dedup alerts by credential fingerprint with webhook auto-response.
8. For MCP servers, record identity and drift (command, package+version, binary/manifest hash, tool-description hash) since source inspection is ADR's largest lever (F1 -15.5% without it) and source is often unavailable for remote servers.
9. Publish a benchmark with per-technique n>=10, held-out splits, confidence intervals, multi-agent transcripts, reproducible baselines, and the production-prevalent categories (secrets, destructive commands, scope overrun, skill supply chain); map techniques to ATLAS/OWASP IDs.
10. Cover what the paper does not: Windows, Linux devpods, containers/Kubernetes, and a measured discovery-coverage metric (endpoints scanned / endpoints managed, unknown-surface rate).
