> **Historical design record.** Research report on uber/ADR Discovery (the inventory CLI), cited by `docs/COMPARISON.md` and by `internal/catalog/data`.
>
> - Written on 2026-11-11, during design (the file was last modified 2026-11-11 16:51 UTC on the build machine; it reads a local clone at commit 6b33dff (2026-10-16)).
> - Written before the project had a name; the text does not name it. The project was then called spoor and was renamed hawkbell on 2026-11-12 (commit d261f98).
> - Findings, numbers, plans and file names describe the design, the prototypes and the sources as they were then, not the release. For what the release does, read [docs/ASSUMPTIONS.md](../docs/ASSUMPTIONS.md) and [docs/LIMITATIONS.md](../docs/LIMITATIONS.md).
> - Local paths (`/home/user/...`, `/root/...`, `/tmp/claude-0/...`, `$S/...` for the session scratch directory, and work-directory variables the text defines) name directories on the build machine, a Linux sandbox VM. The scripts, outputs and downloaded sources in them are not in this repository.
> - Redactions, each marked `[redacted: <reason>]` in the text: a credential-format literal in section 9, the Anthropic API key prefix of uber/ADR's canary template (1 place). Kept: GitHub account names and editor extension ids that are part of a cited repository, package or extension location, because a reader needs them to check the source (the Cline extension id `saoudrizwan.claude-dev`, in two places).
> - Below the line the text is the original, unchanged except for the redactions listed. Other records cite these files by line number; such a number counts from the original's first line, which is line 12 of this file.

---

# uber/ADR Discovery: research report (key: adr-discovery)

**Executive summary**
1. ADR Discovery is a stdlib-only Python 3.11+ CLI (`adr-discovery` 0.2.0, not on PyPI) that scans one endpoint and writes one JSON snapshot; it has no server, transport, scheduler, osquery, MDM or SIEM integration.
2. Its architecture is strong and worth copying: a single machine-access gate with budgets, an evidence ladder, a coverage ledger that travels with the result, type-level redaction, and a folder hash for skills.
3. Its recall is weak: the catalog holds 37 products, zero content hashes and zero Windows identifiers, and identity only concludes on package, bundle-ID, desktop-ID, extension-ID or installer-layout evidence.
4. Runtime visibility is mostly stubbed: exec journal and DNS cache return "unavailable" on every OS, MCP servers are never correlated with processes, and containers, WSL and Kubernetes are not implemented.
5. We can beat it with a Go static binary that emits NDJSON events and osquery tables, has real Windows and container support, a larger signed catalog, and fleet-side policy.

Source: local clone `/home/user/uber/adr` at commit `6b33dff` (2026-10-16), catalog version `2026.10.12`. Claims are VERIFIED by reading the cited file unless marked INFERENCE. I could not execute the collector in this session (execution of the clone was blocked), so behavioural claims rest on static reading.

## 1. Pipeline and data contracts

Composition root: `Discovery/adr_discovery/pipeline.py:61` `discover()`. Order: M1 world (gate) → M2 enumerate → M3 extract → M4 identify → M5 resolve → M6 judge → M7 report. Cross-cutting: C1 catalog, C2 redact, C3 coverage ledger.

| Stage | Output type (`contracts/records.py`) | Fields |
|---|---|---|
| M2 | `Candidate` | `kind, path, source, priority, detail{}` |
| M3 | `Declaration` | `kind, name, path, scope, command, args, env_names, url, raw{}`; `Extraction{declarations, errors, declared, truncated}` |
| M4 | `Verdict` | `catalog_id, kind, name, vendor, version, rung, evidence, signals, score, conflict, install_root` |
| M5 in | `Observation` | `kind, identity, path, install_root, owner, version, catalog_id, content_hash, real_path, inode, package_id, modified, liveness, attribute_of, evidence, detail` |
| M5 out | `Asset` | see below |
| M6 | `Finding` | `rule, severity, asset_id, summary, evidence[]` |
| M4 | `ReviewItem` | `path, score, signals[], evidence[]` |

Candidate kinds: `package, application, process, listening_socket, network_peer, model_port, dns_peer, exec_event, state_dir, extension, binary, model_weight_candidate, marker_file, marker_dir, instruction_file, shell_profile, locator`.

`Evidence{stage, channel, path, proof, confidence, rung}`. Channels: `filesystem, package, registry, config, runtime, network`. Rungs: `provenance, content, convention`; only the first two conclude identity (`contracts/evidence.py:43`). Confidence band = count of distinct channels: 3+ `high`, 2 `medium`, 1 `low`.

`Asset` (schema 1.2, `records.py:232`): `asset_id, kind, name, identity, catalog_id, vendor, version, install_path, install_root, install_method, owner, location, liveness, last_used, confidence{label, channels[]}, verification[], evidence[], risk{pinned, factors[], credential_kinds[], env_names[], transport, destinations[], unattended}, sanction, flags[], hook_event, hook_matcher, allowed_tools[], model, skill_sha256, content_hash, package_id, modified, running_versions[], provenance{state, host, marketplace, marketplace_source{kind, repo, url, path}, plugin, plugin_version, install_scope, installed_at, enabled}, plugin_asset_id, archive{path, sha256}`.

Kinds: `cli_agent, app, ai_browser, model_runtime, model_weights, extension, mcp_server, mcp_bundle, skill, command, plugin, output_style, agent_definition, hook, instructions, ci_agent, cloud_agent, agent_platform`. Liveness: `running, installed, declared_only`.

`Snapshot` (`contracts/snapshot.py:85`): `hostname, username, platform, timestamp, assets[], findings[], review_queue[], coverage, catalog_version, schema_version="1.2"`. `Coverage`: `roots_swept[{path, depth_reached, entries}], boundaries_hit[{path, boundary, detail}], denied[{path, reason}], unavailable[{provider, reason}], truncated[{path, kept, true_count}], probes[{name, status(ran|degraded|failed), detail}], out_of_scope["scheduling_mechanisms"]`.

`asset_id = sha256(kind \0 identity \0 owner \0 normalized_install_root)[:32]` (`resolver/keys.py:90`); it excludes version and host. Merge keys, strongest first: content hash, realpath, inode, package id, install path, catalog+owner+root, identity; union-find refuses a merge that would make a group's identity plural (`resolver/merge.py`).

## 2. What is enumerated, per OS

Shared, per discovered home (`enumerator/markers.py`, `roots.py`, `sources/*.py`):
- **Config files** (`CONFIG_FILE_TEMPLATES`): `~/.claude.json`, `~/.claude/settings.json`, `~/.claude/settings.local.json`, Claude Desktop `claude_desktop_config.json` (`~/.config/claude-desktop/`, `~/Library/Application Support/Claude/`, `~/AppData/Roaming/Claude/`), `~/.cursor/mcp.json`, `~/.codeium/windsurf/mcp_config.json`, VS Code `Code/User/mcp.json` (three OS spellings), Cline `globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`, `~/.config/zed/settings.json`, `~/AppData/Roaming/Zed/settings.json`, `~/.config/JetBrains/options/mcp.json`, `~/.config/opencode/opencode.json`, `~/.codex/config.toml`, `~/.config/goose/config.yaml`, `~/.bashrc`, `~/.zshrc`, `/etc/claude-code/managed-settings.json`, `/Library/Application Support/ClaudeCode/managed-settings.json`, `.../managed-mcp.json`, `/etc/adr/managed-mcp.json`.
- **State roots**: `~/.claude ~/.codex ~/.cursor ~/.aider ~/.continue ~/.gemini ~/.config/goose ~/.config/opencode ~/.ollama`, `~/Library/Application Support/Claude`, `Code/User`, `~/.vscode/extensions`, `~/.vscode-server/extensions`.
- **Marker sweep** (BFS): dir markers `.git .claude .cursor .windsurf .aider .continue .codeium .gemini .goose .opencode .zed agents skills commands prompts output-styles plugins .github .devcontainer .vscode`; file markers `.mcp.json .claude.json mcp.json settings.json settings.local.json config.toml config.yaml mcp_settings.json mcp_config.json cline_mcp_settings.json managed-settings.json managed-mcp.json claude_desktop_config.json opencode.json`; instructions `CLAUDE.md AGENTS.md GEMINI.md AGENT.md .cursorrules .windsurfrules copilot-instructions.md`; `.github/workflows/*.yml`; `.mcpb/manifest.json`. Roots in order: `~`, then `~/Projects ~/src ~/code ~/work ~/dev ~/git ~/repos`, then `/opt /srv /usr/local /workspace`, then `/Users /home`. Skips `.git/objects .Trash Library/Caches .cache __pycache__` and dependency caches (`node_modules .venv venv site-packages go/pkg/mod .cargo/registry vendor .gradle .m2`).
- **Binaries**: one level of `/usr/local/bin /usr/bin /bin /opt/homebrew/bin /opt/local/bin /snap/bin ~/.local/bin ~/bin ~/.cargo/bin ~/go/bin ~/.npm-global/bin ~/.bun/bin ~/.deno/bin` plus `$PATH`, 2,000 per root.
- **Extensions**: Chromium profiles (`Default`, `Profile *`) under Chrome, Brave, Edge, Arc (macOS) and `~/.config/google-chrome|chromium|microsoft-edge`; Firefox profiles; editor roots `~/.vscode|.vscode-server|.cursor|.windsurf|.trae|.kilo/extensions` (identity from `package.json` `publisher.name`).
- **Model stores**: `~/.ollama/models`, `~/.cache/huggingface/hub`, `~/.cache/lm-studio/models`, `~/Library/Application Support/LM Studio/models`, `~/.local/share/Jan/models`, `~/.cache/gpt4all`; files `*.gguf`, `*.safetensors`, `sha256-*`; verified by magic bytes (`GGUF`, safetensors header); cap 500.
- **Language packages** (`world/platform/base.py:235`): npm `package.json` under `/usr/local/lib/node_modules`, `/opt/homebrew/lib/node_modules`, `/usr/lib/node_modules`, `~/.npm-global/lib/node_modules`, `~/.nvm/versions/node`, `~/node_modules`; pipx venvs; `~/.local/share/uv/tools`; `~/.cargo/.crates2.json`; `go version -m` via `/usr/local/go/bin/go` only.
- **Plugin registries** (`extractor/registries.py`): `~/.claude/plugins/known_marketplaces.json`, `installed_plugins.json`, `enabledPlugins` / `extraKnownMarketplaces` in settings, `~/.codex/config.toml` + `~/.codex/plugins/cache`, `~/.cursor/plugins`.

| Surface | Linux (`linux.py`) | macOS (`darwin.py`) | Windows (`windows.py`) |
|---|---|---|---|
| Homes | `/home/*`, `/root` | `/Users/*`, `/var/root` | `/Users/*` |
| Processes | `/proc/<pid>/exe`, `cmdline`, `cwd`, `status`, `environ` (names only) | `/bin/ps -axo pid=,ppid=,user=,comm=` (no argv, cwd or env) | PowerShell `Get-CimInstance Win32_Process` (no user, cwd or env) |
| Sockets | `/proc/net/tcp`, `tcp6`, joined to pids via `/proc/*/fd` | `/usr/sbin/lsof -nP -iTCP` | `Get-NetTCPConnection` |
| Packages | `/var/lib/dpkg/status`, `/lib/apk/db/installed`, `/var/lib/snapd/snaps`, `/var/lib/flatpak/app`, `/usr/bin/rpm -qa` | `/opt/homebrew/Cellar`, `/usr/local/Cellar` (formulae only, no Caskroom) | applications re-labelled as manager `windows`; no npm/pipx/uv |
| Applications | `.desktop` files in `/usr/share/applications`, `/var/lib/flatpak/exports/share/applications` | `Info.plist` in `/Applications`, `/System/Applications` (`CFBundleIdentifier`) | `HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*`, `HKLM:\Software\WOW6432Node\...\Uninstall\*`, `HKCU:\...\Uninstall\*`, `Get-AppxPackage` |
| Package owner | `/usr/bin/dpkg -S <path>` | none | install-location prefix match |
| DNS cache | unavailable (runs `resolvectl statistics`, then refuses) | unavailable | unavailable |
| Exec journal | unavailable | unavailable | unavailable |

Network: an ESTABLISHED peer counts only if it matches a provider suffix (`api.anthropic.com, api.openai.com, openai.azure.com, generativelanguage.googleapis.com, aiplatform.googleapis.com, bedrock-runtime.amazonaws.com, api.mistral.ai, api.cohere.ai, api.groq.com, api.together.xyz, api.deepseek.com, api.x.ai, openrouter.ai, huggingface.co`). Socket tables hold IPs, so matching needs `--resolve`, which looks up only 7 hosts (`api.anthropic.com, api.openai.com, api.mistral.ai, api.groq.com, api.together.xyz, api.x.ai, openrouter.ai`). Local model ports: `11434, 1234, 8080, 8000, 5000, 7860`.

## 3. catalog.json

Structure: `{"version": "2026.10.12", "entries": [...]}`. Entry fields: `id, name, vendor, kind, fingerprints{binaries[], packages["<mgr>:<name>"], state_dirs[], install_layouts[{target, version_from}], bundle_ids[], desktop_ids[], extension_ids[], ports[], model_dirs[]}, proofs{provenance[], version_probe[], version_shape}, risk_factors[]`. The loader (`catalog/load.py`) rejects duplicate ids and any fingerprint claimed by two entries, and also indexes `registry_names` and `content_hashes`, which no entry uses.

37 entries (the tests README says 35):
- **cli_agent (12)**: Claude Code, Gemini CLI, Antigravity CLI, Codex CLI, Aider, opencode, goose, Amp, Crush, Qwen Code, Kilo CLI, GitHub Copilot CLI.
- **app (10)**: Google Antigravity, Cursor, Claude Desktop, Visual Studio Code, Windsurf, Zed, Trae, ChatGPT, Perplexity, Open WebUI.
- **model_runtime (7)**: Ollama, LM Studio, llama.cpp, vLLM, GPT4All, Jan, LocalAI.
- **extension (6)**: Continue, GitHub Copilot, Cline, Roo Code, Kilo Code, JetBrains AI Assistant.
- **ai_browser (2)**: Comet, Arc.

Key usage: `binaries` 16, `packages` 15, `bundle_ids` 14, `state_dirs` 13, `desktop_ids` 8, `extension_ids` 6, `ports` 2, `install_layouts` 1, `model_dirs` 1. Package managers referenced: only `brew, npm, pipx, uv`. Risk factors: `executes_shell` 8, `local_inference` 2, `browses_autonomously` 1.

Verbatim:

```json
{
  "id": "claude-code", "name": "Claude Code", "vendor": "Anthropic", "kind": "cli_agent",
  "fingerprints": {"binaries": ["claude"], "packages": ["npm:@anthropic-ai/claude-code"],
                   "state_dirs": ["~/.claude"],
                   "install_layouts": [{"target": "~/.local/share/claude/versions/*",
                                        "version_from": "basename"}]},
  "proofs": {"provenance": ["npm:@anthropic-ai/claude-code", "brew:claude"],
             "version_probe": ["--version"], "version_shape": "^\\d+\\.\\d+\\.\\d+"},
  "risk_factors": ["executes_shell"]
},
```
```json
{
  "id": "ollama", "name": "Ollama", "vendor": "Ollama", "kind": "model_runtime",
  "fingerprints": {"binaries": ["ollama"], "ports": [11434],
                   "model_dirs": ["~/.ollama/models"], "state_dirs": ["~/.ollama"]},
  "proofs": {"provenance": ["brew:ollama"],
             "version_probe": ["--version"], "version_shape": "\\d+\\.\\d+\\.\\d+"},
  "risk_factors": ["local_inference"]
},
```

Other useful IDs: bundle IDs `com.todesktop.230313mzl4w4u92` (Cursor), `com.anthropic.claudefordesktop`, `com.microsoft.VSCode`, `com.exafunction.windsurf`, `dev.zed.Zed`, `com.trae.app`, `com.openai.chat`, `com.openai.chatgpt`, `ai.perplexity.mac`, `ai.perplexity.comet`, `company.thebrowser.Browser`, `ai.elementlabs.lmstudio`, `com.nomic.gpt4all`, `com.jan.ai`, `com.google.antigravity`; extension IDs `continue.continue`, `github.copilot`, `github.copilot-chat`, `saoudrizwan.claude-dev`, `rooveterinaryinc.roo-cline`, `kilocode.kilo-code`, `com.intellij.ml.llm`. CI agent actions (`extractor/formats/workflow.py`): `anthropics/claude-code-action`, `anthropics/claude-code-base-action`, `openai/codex-action`, `google-github-actions/run-gemini-cli`, `github/copilot`, `cursor/cursor-agent`, `continuedev/continue-action`, `aider-ai/aider-action`.

## 4. Open-world flagging

`identifier/openworld.py`: uncatalogued candidates are scored on weights `network_intent 0.35, credential_affinity 0.25, mcp_participation 0.20, state_shape 0.15, runtime_shape 0.05`; threshold 0.40, or any `network_intent`, puts a `ReviewItem` in `review_queue` (never a finding). In practice only a process holding a live TCP connection to one of the 7 resolvable hosts, with `--resolve` on, can qualify: `state_dir` candidates top out at 0.35, config markers are excluded from M4, and the DNS cache is unavailable everywhere. Their own negative control N-10 (`~/bin/ask-corp-llm.sh` must be queued) has no signal that would fire (INFERENCE from code).

## 5. Policy, risk, findings

`examples/policy.example.json` keys: `tenant_domains[], approved[], forbidden[]` (catalog ids), `approved_indicators[], forbidden_indicators[]`. Indicator kinds: `skill_sha256{sha256}`, `file_sha256{sha256}`, `mcp_endpoint{url}`, `package{ecosystem: npm|pypi, name, versions[] | all_versions: true}`, `name{asset_kind, name}`. Sanction: `forbidden > approved > unsanctioned (only where the policy addresses that kind) > unknown`.

Findings (`judge/findings.py`): `forbidden_asset` (high), `unpinned_mcp_server` (medium), `undeclared_mcp_server` (high), `plaintext_transport` (medium), `unattended_execution` (high; flags `--dangerously-skip-permissions --yolo --auto-approve --no-confirm`), `third_party_destination` (medium, needs `tenant_domains`). Risk factors: `unpinned_supply_chain, plaintext_transport, deprecated_transport` (sse) plus catalog factors. Credential kinds from env-name prefixes: `anthropic, openai, google, aws, azure, github, gitlab, huggingface, mistral, cohere`, or `inherited` when no env block exists. Pinning (`judge/risk.py`) parses `npx/bunx/uvx/pipx/pip/docker/podman` with a value-flag table; `pnpm dlx`, `yarn dlx`, `npm exec`, `bun x`, `uv tool run` are folded; docker is pinned only by `@sha256:` digest.

## 6. Output, delivery, scheduling, delta, identity

- Output: one pretty-printed JSON document, `<output-dir>/snapshot-<timestamp>.json` (0600 in a 0700 dir), or stdout with `--json`. Exit 0 complete, 2 partial coverage, 1 error.
- Delivery: none. No HTTP client is imported anywhere in the package; the README assigns "fleet aggregation, fan-out and trend tracking" to a central plane that is not in the repo. No mention of osquery, Fleet, Fluent Bit, MDM or SIEM in `Discovery/`. (The separate Sensor exports OTLP logs.)
- Scheduling: none; no daemon, launchd, systemd or Task Scheduler unit.
- Delta: `--diff <previous.json>` reports `appeared, disappeared, reinstalled, version_changed, config_changed, content_changed, risk_delta` plus coverage deltas, printed as text only; the caller must keep and supply the previous snapshot.
- Host identity (`Common/adr_common/host_identity.py`): `socket.gethostname()`, process-account username, `platform.system()`. No serial, hardware UUID or machine-id. Diff refuses different hostnames.
- `last_used` comes only from an operator-supplied `--telemetry` JSON (catalog id → timestamp).

## 7. Runtime requirements

- Python >= 3.11 (uses `tomllib`), zero runtime dependencies, hatchling wheel, run via `uv run adr-discovery`. PyPI returned 404 for `adr-discovery` on 2026-11-11; only `adr-sensor` 1.0.0 is published.
- Privileges: designed for no root; unreadable homes and `/proc` entries become `denied` records. Never runs discovered binaries; helpers are absolute paths with `PATH=/usr/bin:/bin:/usr/sbin:/sbin`, 5 s and 4 MiB caps.
- Budgets (`world/budget.py`): `max_entries 200000`, `max_depth 12`, `max_children 5000` (fan-out prune), `max_seconds 120`, `max_read_bytes 4 MiB`, state roots capped at 25% of entries, 10% reserved for later stages, hashing 1 GiB per scan, tree caps 10,000 files / 20 MiB per file / 100 MiB. Walk is fair-share BFS per top-level child and prunes on `CACHEDIR.TAG`. Every scan re-walks every home; there is no cache or incremental mode.
- Multi-user: every directory under the home roots is scanned, but declared assets and packages get `owner="system"`; only processes and installer-layout installs carry a user (`pipeline.py:277`, `:323`).
- Parity: CI runs Discovery on `ubuntu-latest` only. Windows has no harness driver and no Windows identifiers in the catalog. The gate lists directories with `os.open(dir)` + `os.scandir(fd)`, which Windows Python does not support, so Windows filesystem enumeration very likely fails (INFERENCE; not executed).
- Containers, WSL, Kubernetes, remote agents, scheduled agents, account identity and code signatures: "not implemented" (`adr_discovery/README.md:27`). `location` is always `local`.

## 8. Redaction and privacy

- No file contents: skill, command and instruction bodies are never read; frontmatter is parsed under an allowlist (`name, model, allowed-tools, allowed_tools, tools, disable-model-invocation, argument-hint, version, kind`), and `description` is deliberately excluded.
- Names, never values: env maps are reduced to sorted key names inside the `Declaration` constructor; URLs lose userinfo, query and fragment; argv is scrubbed for 14 flags (`--api-key --auth --header --input --message --password --prompt --query --secret --system-prompt --token -m -p -H`) and credential-shaped `key=value`.
- Raw argv, MCP commands and hook commands are never serialized; hooks emit only event, matcher and a digest.
- Personal paths refused at the gate on the resolved target: `/.ssh/ /.gnupg/ /Documents/ /Desktop/ /Pictures/ /Music/ /Movies/ /Library/Mail/ /Library/Messages/ /AppData/Local/Microsoft/Outlook/`.
- `--explain` prints the collection rules; `--archive-skills` keeps local owner-only zips named `<skill_sha256>.zip`.
- Skill folder hash: sorted relative paths, per file `<rel>\n<x>\n` (x = 1 if any exec bit) then bytes, one running SHA-256; no hash rather than a partial one.

## 9. Test harness

Black-box method: restore a clean VM, scan, install a 120-entry TOML manifest (50 tools, 29 MCP, 19 skills/surfaces, 12 agents, 10 negative controls), scan again, and score the delta against `manifest.actual.json` (what really installed). Scores are TP/FP/FN plus a separate DUP count, per category and per OS, never pooled; field accuracy covers `version, install_path, install_method, config_scope, transport, pinning, liveness`. Six canary credentials with realistic shapes (`[redacted: credential-format literal, an Anthropic API key prefix followed by ADRE2ECANARY{random:32}]`) are generated per run and substring-searched in the serialized output; one hit fails the run. Unexplained coverage errors fail the gate. Status: only 64 of 105 Linux entries have recipes, Lima and Tart drivers cannot restore snapshots, there is no Windows driver, and `run` supports `--dry` only.

Worth emulating: negative controls (Slack, Prettier, `mcp-backup.sh`, nginx on 8081, dangling symlink), install-channel variants scored for duplication, declaration-site matrix (one identical server per config site), launch-form matrix for pinning, canaries, file-boundary design so runs can be re-scored, and the import-graph test that enforces module boundaries.

## 10. Weaknesses we can beat (verified by reading unless noted)

1. No transport, server, scheduler or fleet integration; monolithic JSON; text-only delta.
2. Needs Python 3.11+ on every endpoint; unpublished; no installers or services.
3. Windows: no catalog identifiers, no npm/pipx discovery, POSIX-only path handling (exe basenames split on `/`), untested.
4. Identity recall: zero content hashes, no code-signature checks. `goose` has no conclusive fingerprint at all; Ollama from its Linux install script cannot be concluded; nvm/fnm/volta/pnpm/bun globals, Homebrew casks, `~/Applications`, user-level `.desktop` files, JetBrains plugin directories and all browser AI extensions (no Chrome IDs in catalog) are missed.
5. Dead catalog fields: `registry_names`, `model_dirs`, `version_probe` are never consulted.
6. Runtime: exec journal and DNS cache unavailable on all OSes; macOS processes carry no argv, so a running agent launched with `--dangerously-skip-permissions` is not flagged there.
7. `undeclared_mcp_server` is unreachable: the only producer of `mcp_server` assets is config extraction, so MCP liveness is always `declared_only`.
8. MCP assets omit command, args, URL path and package coordinates, so a central team cannot retro-hunt a new bad package; indicators only match on the endpoint. No tool listing or tool-description scanning.
9. Config parsing gaps: only top-level `mcpServers | mcp_servers | servers | mcp`; misses `projects.<path>.mcpServers` in `~/.claude.json`, Zed `context_servers`, Goose `extensions`. `.jsonc` goes through strict `json.loads`. The YAML subset refuses flow collections, so a workflow containing `on: [push]` is dropped whole.
10. Redaction: separated flags outside the list (`--access-token X`, `--bearer X`, `--client-secret X`) and URL userinfo in positional args are not scrubbed; `python -m <module>` and `npx -p <pkg>` are over-redacted, which breaks package-indicator matching for `npx -p`.
11. Ownership and identity: most assets are owned by `system`; host identity is hostname only; `asset_id` is not host-scoped.
12. Performance: full home walk every run, up to 120 s.
13. Containers, WSL, Kubernetes, scheduling mechanisms: out of scope.
14. Policy: one local JSON file, no severities, exceptions, expiry or group scoping.

**License.** Apache-2.0 (`LICENSE`; appendix reads "Copyright 2024 ADR Project Contributors"). `NOTICE.md` lists third-party components only under `Detection/` (AgentDojo MIT, a YAML gist MIT, a Stack Overflow snippet CC BY-SA 3.0, OpenAI types Apache-2.0, LlamaFirewall MIT, two CC BY 4.0 papers); nothing restricts `Discovery/` or the catalog. Catalog data and the path lists may be reused under Apache-2.0 section 4: ship the license, keep attribution, and state that we modified it. There is no plain `NOTICE` file, but crediting uber/ADR in ours is the safe course.

## Design implications

- Ship a Go static binary with three front ends over one collector: NDJSON to stdout/file for Fluent Bit, an osquery extension (tables) for Fleet, and a one-shot CLI.
- Emit one event per asset, finding and coverage record with a stable host key (hardware UUID / osquery `host_identifier`) and a host-scoped asset key; emit deltas as events.
- Keep ADR's ledger, evidence rungs, exit-code-2 semantics, constructor-level redaction and skill folder hash (byte-compatible, so indicators interoperate).
- Add conclusive evidence ADR lacks: Authenticode / codesign team IDs, Windows registry and MSIX names, winget/scoop/choco, Homebrew casks, version-manager globals, Chrome extension IDs, binary hashes.
- Emit normalized MCP launch facts (runner, ecosystem, package, version, image, URL host and path) and evaluate policy centrally as well as locally.
- Correlate declared MCP servers with live processes by parent agent and argv, and add container/Kubernetes and WSL collectors.
- Parse JSONC and full YAML; cover `projects.*.mcpServers`, `context_servers`, Goose `extensions`.
- Copy the harness ideas: negative controls, canaries, DUP scoring, site and launch matrices, and run them in CI on all three OSes.
