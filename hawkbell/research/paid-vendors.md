> **Historical design record.** Research report on commercial agent endpoint security products, cited by `docs/COMPARISON.md`. As its "Evidence status" section says, almost every vendor statement in it comes from search-engine summaries of pages that could not be opened [S].
>
> - Written on 2026-11-11, during design (the file was last modified 2026-11-11 17:00 UTC on the build machine; its title says "November 2026").
> - Written before the project had a name; the text does not name it. The project was then called spoor and was renamed hawkbell on 2026-11-12 (commit d261f98).
> - Findings, numbers, plans and file names describe the design, the prototypes and the sources as they were then, not the release. For what the release does, read [docs/ASSUMPTIONS.md](../docs/ASSUMPTIONS.md) and [docs/LIMITATIONS.md](../docs/LIMITATIONS.md).
> - Local paths (`/home/user/...`, `/root/...`, `/tmp/claude-0/...`, `$S/...` for the session scratch directory, and work-directory variables the text defines) name directories on the build machine, a Linux sandbox VM. The scripts, outputs and downloaded sources in them are not in this repository.
> - Redactions: none.
> - Below the line the text is the original, unchanged except for the redactions listed. Other records cite these files by line number; such a number counts from the original's first line, which is line 12 of this file.

---

# Commercial agentic endpoint security, November 2026

## Executive summary

1. Every commercial product in this category is built from the same four parts: config-file discovery, the agents' own native hooks, an optional MCP proxy, and (for EDR incumbents only) a kernel sensor. None of the four is proprietary; the moat is intel corpora, sensor install base and packaging.
2. Runtime "enforcement" is almost always the agent's own pre-tool hook. Hooks are cooperative, fail open by default, see only part of the session, and are tamperable wherever the config is a plain file. Vendors admit this in their docs while their marketing says "block".
3. OS coverage is uneven: macOS and Windows first, Linux partial or pre-beta, and I found no vendor describing coverage for containers, devcontainers, CI runners or Kubernetes.
4. Nobody publishes an open event schema, open detection rules or a benchmark. The Latio 2026 report's own framing is that runtime detection claims need hands-on testing.
5. An open-source platform on FleetDM + Fluent Bit can match discovery, posture, hook telemetry and hook enforcement, and beat the field on Linux/containers, openness, privacy defaults and SIEM neutrality. It cannot match kernel-level ground truth, TLS inspection or curated reputation corpora without extra components.

## Evidence status (read this first)

Vendor and press hosts are blocked from this sandbox (crowdstrike.com, pillar.security, zenity.io, helpnetsecurity.com and vmblog.com all failed DNS; I stopped retrying). So:

- **[V] VERIFIED** = I read the primary source in this session. Only four sources qualify: Endor Labs' public `endorlabs/mdm-scripts` repo (README, support matrix, example configs, via raw.githubusercontent.com); Claude Code docs at code.claude.com (`hooks`, `managed-settings`, `server-managed-settings`, `monitoring-usage`); Lasso's `lasso-security/claude-hooks` README; StepSecurity's `step-security/dev-machine-guard` README.
- **[S] UNVERIFIED** = search-tool summary of a vendor, press or blog page I could not open. Every commercial-product claim below is [S] unless marked, and every one is vendor marketing until tested.

## Vendor profiles

### CrowdStrike Falcon Guardian / Falcon AIDR [S]
- **Naming:** AIDR (from the Pangea acquisition) is now sold under "Falcon Guardian"; product URL is `/platform/falcon-guardian-aidr/`. CrowdStrike's licensing page reportedly says Falcon AIDR for Agents is no longer available for new purchase as of 2026-09-01.
- **Discovery:** existing Falcon sensor. "Shadow AI Discovery for Endpoint" (announced March 2026, later GA) finds AI apps, agents, LLM runtimes, MCP servers, dev tools and IDE extensions.
- **Runtime:** "collectors": browser extension, application SDK, gateway, MCP proxy, a Claude Code hooks collector (announced 2026-07-30), and a Falcon Endpoint collector with Network Inspection. Third-party review: Network Inspection is Windows-only and report-only; browser output rules are report-only.
- **Enforcement:** Claude Code collector is a JSON hooks block in the settings file at three hook events; returns allow, block or transform. Cursor is covered through the MCP proxy, not hooks. Agent Access Controls block unauthorised agent binaries; an "AI kill switch" acts at AI gateways.
- **Documented limits (CrowdStrike's own docs, via search):** cannot see model responses, system prompts or subagent context; hooks run in parallel; no model/provider info; MCP proxy does not see client prompts or non-MCP calls; with no policy attached the collector only logs.
- **OS:** Windows and macOS; Linux described as pre-beta for Claude Code and Codex.
- **SIEM:** Falcon Next-Gen SIEM. **Pricing:** Falcon Flex; AIDR for Agents was metered by combined AI inputs/outputs per day.

### Pillar Security Agentic Endpoint [S]
- **Discovery:** own scanner deployed through the customer's MDM; inventories agent versions, sandbox state, MCP servers, skills, plugins, hooks. Claims posture scans read configuration, not source code.
- **Runtime/enforcement:** "Runtime Guardian" in each agent's pre-tool hook for Claude Code, Codex CLI, Cursor; controls are Off / Monitor / Block.
- **Intel:** catalog of "23,000+" pre-analysed MCP servers.
- **Deployment:** SaaS, or on-prem "endpoint gateway" in the customer's cluster.
- **Marketing caution:** Pillar writes the comparison posts that rank Pillar first.

### Palo Alto Networks: Koi (Cortex Agentic Endpoint Security, Prisma AIRS) [S]
- Acquisition announced 2026-02-17, closed 2026-04-14, reported at about $400M. Sold standalone and as a Cortex XDR / Prisma AIRS module.
- **Core:** software supply-chain gate for "non-binary software": extensions, packages, MCP servers, plugins, skills, models. "Wings" risk engine (publisher reputation, code behaviour, version history, sandbox results), "Koidex" intel database. Blocks risky installs and removes existing ones.
- **Mechanism:** described as agentless by an investor, yet the platform page lists SWG, EDR, MDM, PAC files and user-mode agents. A comparison lists synchronous hooks with Block / Ask rules for Cursor, Claude Code and Antigravity, on macOS, Windows, Linux. Plugin remediation removes a flagged Claude Code plugin's whole footprint.

### Noma Security [S]
- Endpoint launch 2026-09-28. **Discovery through the EDR or MDM already in place** (CrowdStrike integration named); no own agent. Inventory of agents, MCP servers, skills, connected accounts; evidence sources named as config files, skills directories, connector history, running processes.
- **Enforcement:** native hooks before and after tool calls for Claude Code and Cursor. Registry states: approved / flagged / blocked. "Contextual Policies" correlate prompts, tool calls, tool responses, identity over time. "Agent Boundaries" on endpoint is announced as planned, not shipped.
- Agents listed: Claude Code, Cowork, Cursor, Codex, Windsurf, Kiro, Antigravity, OpenClaw.

### Zenity [S]
- "Agentless": OpenTelemetry plus native hooks, "no endpoint sensor required"; blocking at PreToolUse. Cursor marketplace plugin (webhooks + OTel). Claude Compliance API integration correlates sessions with commits and PRs. Competitors note per-agent blocking coverage is not published.

### Backslash Security [S]
- Discovers agents, skills, MCP servers, hooks, rules, plugins, prompts, local models. **Local MCP proxy on the workstation** for inline blocking; policy down to individual MCP tool and skill, scoped by user group. Distribution through Intune or Jamf. Deployment modes listed: endpoint sensor, agentless via MDM/EDR, hooks, gateway.

### QuilrAI [S]
- **TLS-inspecting endpoint agent** + browser extension + MCP gateway. Auto-creates a "Guardian Agent" per discovered tool. Claims sub-50 ms enforcement. Server-count claims are inconsistent across its own pages (150+ vs 500+).

### Pluto Security [S]
- Out of stealth October 2026 with $42M; claims 1.5M endpoints. Integrates with EDR and MDM to gather prompts, commands, processes, permissions; **small models on the endpoint**; can inject corrective instructions into a live session; quarantines untrusted MCP servers. Also covers employee-built apps (Lovable, Replit).

### Others
- **Microsoft Defender for Endpoint [S]:** local AI agent discovery via the Defender sensor (50 to 60 agents, Windows GA, macOS status conflicting), inventory under Assets > AI Agents, queryable in Advanced Hunting. Runtime protection is preview, documented for Windows, modes Disabled / Audit / Block, via "agent-native event inspection" (hooks) plus network inspection, about 10 agents. Needs MDE P2; richer risk features tied to E7 / Agent 365.
- **Jamf AI Governance [S]:** macOS only; Claude Code, Claude Desktop, Codex at launch (mid-2026); uses the existing Jamf telemetry agent; MCP server inventory and allow-list; bundled into Jamf for Mac plans.
- **SentinelOne / Prompt Security [S]:** browser extension, lightweight agent or reverse proxy, MCP gateway with per-user/server/action policy, Claude Compliance API scanning. No documented Claude Code hook details found.
- **Knostic Kirin [S]:** IDE extension for Cursor, Copilot, Windsurf; endpoint client plus hooks for Claude Code; MCP quarantine. **Only public price list found:** free up to 5 users, Team $15 per user per month, Enterprise custom.
- **Harmonic [S]:** local MCP gateway, browser extension, endpoint agent; MDM via Intune, Jamf, Kandji; "coach, warn, or block" in under 200 ms.
- **BeyondTrust AI Agent Security [S]:** `pathfinder-agent hook install --provider <name>` / `--all-providers`; machine-wide managed hooks for Claude Code, Codex, Cursor, Copilot on Windows and macOS; MDM-owned config option.
- **Endor Labs Agent Governance [V]:** see next section.
- **Astrix (Cisco, closed 2026-06-29) and Token Security [S]:** MCP discovery by querying the customer's EDR, no own agent. **Oasis:** SaaS NHI focus; Cyera deal status disputed. **Wiz:** I found no endpoint coding-agent discovery; cloud-side AI inventory only.
- **Lasso [V for the OSS part]:** `claude-hooks` is a PostToolUse, regex-pattern prompt-injection scanner that only adds a warning to context; it installs into the project's `.claude/settings.local.json`, so it is neither managed nor tamper-resistant.
- **Certiv [S]:** "Scout" endpoint agent outside the coding agent's privilege, network interception plus process monitoring; author of the "All Hooks, No Anchor" critique.
- **Open-core adjacent:** StepSecurity Dev Machine Guard [V]: Apache-2.0 Go scanner for macOS, Windows, Linux with JSON output; scheduled scans (launchd / systemd / schtasks), dashboard, policy and alerting are subscription-only and upload to StepSecurity's backend. Asymptote Agent Beacon [S]: MIT, configures OTel for Claude Code and Codex, hook adapter for OpenCode.

## What a commercial hook deployment actually looks like [V]

Endor Labs publishes its whole mechanism (`endorlabs/mdm-scripts`, `agent-governance/README.md` and `docs/support-matrix.md`). This is the best primary evidence of how the category works, and the paths are worth copying.

| Agent | macOS | Linux | Windows | Tamper resistance |
| --- | --- | --- | --- | --- |
| Claude Code | `.mobileconfig`, payload `com.anthropic.claudecode` | `/etc/claude-code/managed-settings.json` | `C:\Program Files\ClaudeCode\managed-settings.json` | OS-enforced on macOS profile only |
| Cursor | `/Library/Application Support/Cursor/hooks.json` | `/etc/cursor/hooks.json` | `C:\ProgramData\Cursor\hooks.json` | plain file; "a determined developer could override it" |
| Codex | Forced pref `com.openai.codex`, key `requirements_toml_base64` | `/etc/codex/requirements.toml` | `%ProgramData%\OpenAI\Codex\requirements.toml` | managed-source hooks auto-trusted, user cannot disable |
| Copilot CLI | `/etc/github-copilot/policy.d/*.json` | same | `C:\ProgramData\GitHub\Copilot\policy.d\` | app-enforced policy level |
| Copilot in VS Code | `~/.copilot/hooks/` only | same | same | none: no admin-owned hook path |

The Cursor, Codex and Copilot paths are as Endor states them; I did not check them against those vendors' own docs. Claude Code docs [V] confirm the Claude paths and add: Windows `HKLM\SOFTWARE\Policies\ClaudeCode` value `Settings`; drop-in `managed-settings.d/`; `managed-mcp.json`; the `HKCU` variant is user-writable and is not an admin source; MDM policy is re-read every 30 minutes.

Events Endor registers [V, from `examples/`]:
- Claude Code (6 of 33 documented events): `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `PostToolUseFailure`, `Stop`, matcher `.*`.
- Cursor (12): `sessionStart`, `sessionEnd`, `beforeSubmitPrompt`, `preToolUse`, `postToolUse`, `postToolUseFailure`, `beforeShellExecution`, `afterShellExecution`, `beforeMCPExecution`, `beforeReadFile`, `afterFileEdit`, `stop`.
- Codex: `SessionStart`, `UserPromptSubmit`, `PreToolUse`, `PermissionRequest`, `PostToolUse`, `Stop`; needs `[features] hooks = true`; optional `allow_managed_hooks_only = true`.
- Copilot: the Claude set plus `SessionEnd`, `timeout: 30`.

Weaknesses visible in that primary source [V]:
- Hook command is `"$HOME/.endorctl/endorctl" ... ai-audit <agent>`: the enforcement binary lives in the user's home directory.
- API key and secret are written into the config on every laptop (README tells admins to scope them audit-only).
- `endorctl` is about 300 MB, self-downloads in the background, so the **first session on each machine is unaudited**.
- Windows cannot run the POSIX runner that keeps configs current; configs must be pre-generated and re-pushed through Intune.
- Cursor env injected at `sessionStart` is lost on resume and never reaches subagent hooks, so every hook must be self-contained.
- Search summary of Endor docs [S]: hooks fail open if the binary or the Endor API is unreachable; policy is snapshotted at session start.

## Capability matrix (all cells [S] except Endor)

| Vendor | Discovery via | Runtime telemetry | Enforcement point | OS claimed | SIEM | Price signal |
| --- | --- | --- | --- | --- | --- | --- |
| CrowdStrike Guardian/AIDR | own EDR sensor | hooks (Claude Code), MCP proxy, browser ext, network inspection | hook, MCP proxy, exec control, gateway kill switch | Win, mac; Linux pre-beta | Falcon NG-SIEM | Flex; per AI I/O |
| Microsoft Defender | own EDR sensor | hooks + network inspection | hook, Audit/Block | Win; mac discovery | Sentinel / Advanced Hunting | MDE P2, E7 |
| PANW Koi | own agent, or EDR/MDM/SWG | hooks | install gate, hook Block/Ask, removal | mac, Win, Linux | Cortex | not public |
| Pillar | own scanner via MDM | pre-tool hook | hook Off/Monitor/Block | not stated | not found | not public |
| Noma | customer's EDR/MDM | hooks | hook (Claude Code, Cursor) | not stated | not found | not public |
| Zenity | OTel + hooks, no sensor | OTel, hooks, Compliance API | PreToolUse hook, MCP gateway | not stated | not found | not public |
| Backslash | own collection via MDM | local MCP proxy, hooks | MCP proxy | not stated | not found | not public |
| QuilrAI | own TLS-inspecting agent | TLS inspection, browser ext, MCP gateway | agent + gateway | not stated | not found | not public |
| Pluto | EDR/MDM + own endpoint models | prompts, processes | stop / ask / inject instruction | not stated | not found | not public |
| Jamf | own MDM agent | inventory | MCP allow-list | mac only | not found | bundled |
| Knostic Kirin | IDE ext + endpoint client | hooks | hook deny, MCP quarantine | not stated | "SIEM" claimed | $15/user/mo |
| Endor Labs [V] | none (hooks only) | hooks, 4 agents | hook block or monitor-only | mac, Linux, Win | not checked | not public |

## Top 10 capabilities that define state of the art

1. Continuous fleet inventory of agents, MCP servers, skills, plugins, hooks, rules files and IDE extensions, tied to device and user, including personal-account sign-ins on corporate devices.
2. Config posture audit with severity: sandbox off, bypass-permissions mode, over-broad allow rules, hooks or skills that execute code, secrets in MCP config.
3. Reputation intel for MCP servers, skills and extensions (Pillar "23,000+", Koidex), with sandbox detonation.
4. Normalised hook telemetry across agents: prompt, pre/post tool, shell, file, MCP.
5. Pre-action control with Off / Monitor / Block (plus Ask), staged rollout.
6. Tamper-resistant managed delivery through MDM (profile, HKLM, system path).
7. Local MCP proxy or gateway with per-tool policy and DLP redaction.
8. Correlation of agent intent with OS effects through an EDR sensor (process tree, file, network).
9. Cross-surface reach: browser, desktop apps, SaaS agents via vendor compliance APIs.
10. Response actions: quarantine an MCP server, remove a plugin footprint, block an agent binary, kill switch, SIEM/SOAR handoff.

## Recurring criticisms

- **Hooks are cooperative and fail open.** Claude Code docs [V]: any exit code other than 0 or 2, a hook that cannot start, invalid JSON, HTTP connection failure or non-2xx are all "non-blocking error ... the action goes ahead" unless `onFailure: "block"` is set. Matching hooks run in parallel [V]. Third-party tests disagree on Cursor, Codex and Copilot defaults [S].
- **"All hooks, no anchor."** Hooks move with the agent they govern; they give no independent evidence (Certiv [S]). CrowdStrike's CTO: telling agent from human requires walking the process tree [S].
- **Blind spots.** Model responses, system prompts, non-MCP calls (CrowdStrike docs [S]); VS Code Copilot has no managed hook path [V]; Cursor Cloud lifecycle events do not fire [S]; unsupported agents get discovery only.
- **Tamper.** A local admin can edit the managed source [V, Claude docs]; file-delivered configs are not OS-enforced [V, Endor]; a Claude Code session reportedly deleted its own hook script and proceeded (anthropics/claude-code issue 32990 [S]).
- **Evasion.** Pattern rules lose to encoding and indirection ("the agent only needs one vector you missed" [S]). Pillar's July 2026 "Week of Sandbox Escapes": the agent stays inside the rules and writes a file the host later trusts [S].
- **Hooks are attack surface.** Cursor CVE-2026-48124: a workspace Claude-style settings file treated as hook config [S].
- **Privacy.** Claude Code's own OTel redacts prompts, tool arguments and tool content by default (`OTEL_LOG_USER_PROMPTS`, `OTEL_LOG_TOOL_DETAILS`, `OTEL_LOG_TOOL_CONTENT`, `OTEL_LOG_RAW_API_BODIES` all off) [V]. Vendors capture full prompts into their cloud; commentators flag GDPR minimisation and works-council exposure [S]. No enforcement case found.
- **Alert fatigue and unproven detection.** No public false-positive data or benchmark from any vendor found; VentureBeat's RSAC matrix reportedly found no vendor shipping an agent behavioural baseline [S]. Friction makes developers switch guardrails off [S].
- **Marketing inflation.** Vendor-authored rankings; inconsistent OS claims; "agentless" and "own agent" used for the same product.

## What FleetDM + Fluent Bit can match, beat, or not reach

**Match (same technique the vendors use):**
- Inventory and posture: config-file and process discovery as osquery tables; Fleet policies give pass/fail and drift.
- Managed-hook rollout: Fleet configuration profiles and scripts deliver exactly the artifacts in the table above.
- Hook telemetry and Monitor/Block: one static hook binary writing local JSONL or OTLP; Fluent Bit ships it.
- Native OTel: Claude Code managed settings pin the OTLP destination and strip developer overrides [V], so Fluent Bit's OpenTelemetry input can be the locked collector.

**Beat (inference from gaps above, not tested):**
- Linux, containers, devcontainers, CI, Kubernetes.
- Open schema, open rules, a public benchmark.
- Local policy evaluation with no cloud call on the hot path, no credentials on endpoints, root-owned hook binary, explicit fail mode per rule.
- Privacy by default (metadata and hashes; content opt-in), which vendors cannot offer while their detection lives in their cloud.
- Any SIEM through Fluent Bit rather than the vendor's own.
- Coverage-gap detection as a first-class signal: agent present but managed hook absent, modified, disabled or unsupported.

**Needs a kernel sensor:** independent process/file/network ground truth and real-time process-tree attribution; blocking unauthorised agent binaries; anti-tamper against local admins. Partial open routes: osquery evented tables (detection only), Santa on macOS, Falco or Tetragon on Linux.

**Needs a vendor cloud or separate component:** curated reputation corpus and detonation; TLS inspection of desktop and browser traffic; LLM-judge intent classification at fleet scale; SaaS-side compliance-API connectors; managed response.

## Sources

Primary, read this session: `https://raw.githubusercontent.com/endorlabs/mdm-scripts/main/agent-governance/README.md`, `.../docs/support-matrix.md`, `.../examples/{claude/settings.json,cursor/hooks.json,codex/requirements.toml,copilot/policy.json}`; `https://code.claude.com/docs/en/{hooks,managed-settings,server-managed-settings,monitoring-usage,settings}.md`; `https://raw.githubusercontent.com/lasso-security/claude-hooks/HEAD/README.md`; `https://raw.githubusercontent.com/step-security/dev-machine-guard/main/README.md`.

Search-derived, not opened: aidr-docs.crowdstrike.com/docs/aidr/collectors (and `/agentic/claude-code`, `/falcon-endpoint/deploy`); crowdstrike.com blog posts on Falcon Guardian and AIDR for Claude Code; crowdstrike.com/en-us/legal/crowdstrike-licensing; pillar.security/platform/agentic-endpoint and its 2026 comparison posts; koi.ai/platform; paloaltonetworks.com Koi press releases and "A Quarter of Innovation with Koi"; noma.security/platform/endpoint-agents and the 2026-09-28 PR Newswire release; zenity.io/blog/coding-agent-attack-surface; backslash.security/agentic-endpoint-security and "Top 7" post; quilr.ai/platform/endpoint-agent; bankinfosecurity.com on Pluto; learn.microsoft.com/defender-endpoint/local-agent-discovery-overview and configure-ai-agent-runtime-protection; jamf.com/blog/ai-governance-for-mac; knostic.ai/pricing and /kirin; harmonic.security MCP gateway pages; docs.beyondtrust.com coding-hooks pages; docs.endorlabs.com/agent-governance; certiv.ai/blog/all-hooks-no-anchor; arcjet.com/learn/coding-agent-hooks-fail-open; github.com/anthropics/claude-code/issues/32990; pulse.latio.tech 2026 AI Security Market Report; resilientcyber.io "The AI Security Market Moves to the Endpoint"; venturebeat.com RSAC 2026 agent telemetry gap; labs.cloudsecurityalliance.org note on sandbox escapes.
