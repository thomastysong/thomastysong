> **Historical design record.** Red-team review of design v0, detection-quality lens (a SOC detection engineer): rule hit rates replayed over the build session's own agent transcripts, the trifecta base rate, guard-mode fail-open, redaction and benchmark requirements (assumptions A8, A10, A12, A13, A26, A29, A35).
>
> - Written on 2026-11-11, during design (the file was last modified 2026-11-11 17:25 UTC on the build machine; it says "Date: 2026-11-11").
> - Written under the working name **spoor** (binary `spoor`, rule ids `SPR-...`, osquery tables `spoor_*`, environment prefix `SPOOR_`). The project was renamed hawkbell on 2026-11-12 (commit d261f98), and those became `hawkbell`, `HB-...`, `hawkbell_*` and `HAWKBELL_`.
> - Findings, numbers, plans and file names describe the design, the prototypes and the sources as they were then, not the release. For what the release does, read [docs/ASSUMPTIONS.md](../docs/ASSUMPTIONS.md) and [docs/LIMITATIONS.md](../docs/LIMITATIONS.md).
> - Local paths (`/home/user/...`, `/root/...`, `/tmp/claude-0/...`, `$S/...` for the session scratch directory, and work-directory variables the text defines) name directories on the build machine, a Linux sandbox VM. The scripts, outputs and downloaded sources in them are not in this repository.
> - Redactions, each marked `[redacted: <reason>]` in the text: the session id in the scratch directory path (2 places); credential-format test literals in section 1, an AWS example access key id and an sk- prefixed key (1 place); the same two literals in section 4 (1 place). Kept: invented passwords that have no provider's credential format (`hunter2`, `pa55w0rd`). Kept: statements in the persona's voice about past experience, such as "my own queue experience" (the source of the workflows in section 1 that the replay did not observe) and "my queue" (sections 7 and 9). The reviewer was a review session of this build given the persona named above; no data behind those statements is in this repository or was on the build machine, so treat them as unverified estimates.
> - Below the line the text is the original, unchanged except for the redactions listed. Other records cite these files by line number; such a number counts from the original's first line, which is line 12 of this file.

---

# Red team: detection quality (lens = detection-quality)

Reviewer persona: SOC detection engineer who owns the alert queue for 10,000 developers.
Target: `design/v0.md` assumptions A8, A10, A12, A13, A26, A29, A35 (plus unstated ones in the same area).
Date: 2026-11-11. All experiment files: `/tmp/claude-0/-home-user/[redacted: session id]/scratchpad/redteam/dq/`.

## 0. Method and corpus

No spoor rule engine exists yet (`/home/user/thomastysong/spoor` holds only `internal/event`), so I implemented the rule
families the design names (v0 section 5) with the logic sketches from `research/threats.md` section 3 (R11, R21, R23, R27,
R30, R32, R34, R37, R40, R41, R42, R43, R45 and friends) twice:

- `replay.py`: regex over the raw command string (what a rule author writes first).
- `shx/main.go` + `eval_ast.py`: argv / pipeline / redirect facts from `mvdan.cc/sh/v3 v3.14.1` (the parser A35 names), rules
  bound per command. This is the best case the design's "shell canonicalizer" can deliver.

Corpus: the real Claude Code transcripts on this machine (`/root/.claude/projects/**.jsonl`): this workflow's own research,
build and red-team subagent sessions. 35 to 37 sessions (other agents were still writing while I ran; counts differ by run),
1,605 to 1,711 tool calls, 1,095 to 1,175 Bash commands. No attacker is present, so **every hit is a false positive** (or, for
the other red-teamers' container-escape experiments, Uber's "TP non-malicious" class).

Limits, stated up front: n = 37 sessions, one workload (agentic security research and infra building, root in a sandbox,
68% of tool calls are shell). Infra rules (docker) are over-represented relative to a frontend developer. Intervals are wide
(7/37 = 18.9%, Wilson 95% [9.5%, 34.2%]). The conclusions below only rely on order-of-magnitude gaps.

Scaling constants: Agentmetry sizing 1,119 events per active developer per day (`research/small-oss.md` section 2). I assume
about 500 of those are distinct tool calls (pre + post + prompt/turn events make up the rest) and 10 sessions per developer
per day. Both are assumptions; halve or double them and no verdict changes.

## 1. Experiment A: single-event rule hit rates on benign sessions

Commands:
```
cd $S/redteam/dq
python3 -I replay.py /root/.claude/projects            # regex on raw text -> replay.out
python3 dump.py /root/.claude/projects > events.json
(cd shx && GOFLAGS=-mod=mod GOTOOLCHAIN=go1.26.0 go build -o shx .)
./shx/shx < events.json > facts.json
python3 eval_ast.py < facts.json                        # AST-level -> eval_ast.out
python3 tuned.py                                        # precision controls applied -> tuned.out
```

Regex on raw text (`replay.out`, 35 sessions, 1,605 tool events, 1,095 shell):
```
rule                                hits per1k_shell sessions  %sess
R23_exfil_shaped_egress               95        86.8       19   54.3
R41_destructive_infra                 38        34.7        7   20.0
R43_container_breakout                31        28.3        6   17.1
R40_rm_rf_any                         22        20.1       10   28.6
R21_secret_path_shell                 16        14.6        6   17.1
R11_agent_control_file_write          12        11.0        5   14.3
RXX_chmod_777_sudo                    10         9.1        2    5.7
R40b_rm_rf_abs_or_home                10         9.1        8   22.9
R32_pipe_to_shell                      9         8.2        6   17.1
R30_env_dump                           7         6.4        3    8.6
R37_sec_tool_tamper                    6         5.5        4   11.4
R34_evasion_constructs                 3         2.7        2    5.7
R45_revshell_tunnel                    3         2.7        3    8.6
R27_exfil_hosts                        3         2.7        3    8.6
RXX_tls_verify_off                     3         2.7        2    5.7
RXX_base64_decode                      2         1.8        2    5.7
sessions with >=1 hit of any rule: 26/35 = 74%   total hits=270 = 168.2 per 1k tool events
```

AST-level (`eval_ast.out`, 37 sessions, 1,711 tool events, 1,175 shell):
```
sessions=37 tool_events=1711 shell=1175  parse_fail=0 (0.0%)
mvdan.cc/sh parse time per real command: p50=8us p99=156us max=529us
heredoc body bytes (AST) = 230461/730382 = 32% of command bytes

rule (AST-level)                    hits per1k_shell  sess  %sess
R23b_dynamic_url_external             92        78.3    19   51.4
R41_destructive_infra                 38        32.3     7   18.9
R43_container_breakout                25        21.3     5   13.5
R40_rm_rf_any                         21        17.9     9   24.3
R40b_rm_rf_abs_home_or_var            11         9.4     7   18.9
RXX_chmod_777                         10         8.5     2    5.4
R21_secret_path_arg                    7         6.0     2    5.4
R23a_upload_flag_loopback              6         5.1     4   10.8
R34_sed_inplace                        4         3.4     3    8.1
R37_sec_tool_tamper                    3         2.6     2    5.4
RXX_tls_verify_off                     2         1.7     1    2.7
R30_env_dump                           1         0.9     1    2.7
any rule: 24/37 sessions = 65%; total hits=220 = 128.6 per 1k tool events
'high-severity' subset (...): 23/37 sessions = 62%

session flags:
  untrusted_input  25/37 = 68%
  secret_read      2/37 = 5%
  egress           24/37 = 65%
  trifecta loose: all three flags, any order                              2/37 = 5.4%
  trifecta ordered: untrusted > secret > any egress                       1/37 = 2.7%
  trifecta strict: untrusted > secret > exfil-shaped egress to non-loopback 1/37 = 2.7%
```

What AST matching fixed (this part of the design HOLDS): R32 pipe-to-shell 9 -> 0, R27 exfil hosts 3 -> 0, R45 tunnel 3 -> 0,
base64-decode 2 -> 0, R11 control-file 12 -> 0. The R32, R27, R45 and base64 regex hits were rule text inside heredocs, grep
patterns and quoted strings (agents writing rules and docs about attacks). Parse failures: 0 of 1,175.
Caveat on R11 and R21: my extractor does not recurse into `docker run ... bash -c '<script>'` strings, so some of the R11
drop (and the fall of `secret_read` from 23% to 5% of sessions) is writes and reads inside inline scripts that a real
canonicalizer must descend into. The AST numbers are therefore a lower bound on hits, which only strengthens the volume
conclusion.

What AST matching did not fix (intent-ambiguous, the command really is what the rule says):
- R23 "URL containing $VAR": 92 hits, 51% of sessions. Hosts: raw.githubusercontent.com 80, registry.npmjs.org 8,
  code.claude.com 7, proxy.golang.org 5, pypi.org 3, github.com 1 (loops like `curl https://raw.githubusercontent.com/$repo/$f`).
- R41: 38 `docker rm -f` of the agent's own test containers.
- R43: 25 `docker run --network host` / `--pid` (ENV.md tells agents to use `--network host`).
- R40b "rm -rf outside workspace": 11 hits in 7 sessions; agents keep scratch dirs in /tmp, outside cwd.
- R37 "security tooling tampering": 3 bound hits in 2 sessions: `pkill -f "osqueryd --flagfile"`, the restart command that
  this project's own ENV.md prescribes. Design section 9 ships exactly this as a self-protection rule.
- R21: `server.key` (the Fleet test stack's self-signed key), `/proc/$PID/environ`, `.claude/projects/*.jsonl`.

After precision controls (`tuned.out`: 11-host allowlist, temp-dir rm excluded, `docker rm`, `--network host`, `sed -i`,
bare `rm -rf`, loopback uploads all dropped):
```
  RXX_chmod_777                    hits= 10 sessions=2
  R21_secret_path_arg              hits=  7 sessions=2
  R43_container_breakout           hits=  4 sessions=1
  R37_sec_tool_tamper              hits=  3 sessions=2
  R40b_rm_rf_abs_home_or_var       hits=  2 sessions=2
  RXX_tls_verify_off               hits=  2 sessions=1
  R30_env_dump                     hits=  1 sessions=1
  residual hits=29 = 16.9 per 1k tool events; sessions with >=1 residual alert: 7/37 = 19%
```

Volume at scale (500 tool calls and 10 sessions per developer per day):

| Variant | per 1k tool events | per dev/day | per 1,000 devs/day | at 10,000 devs/day |
|---|---|---|---|---|
| Rules as sketched, AST-level, no allowlists | 128.6 | 64 | 64,300 | 643,000 |
| With allowlists and exclusions (tuned) | 16.9 | 8.4 | 8,450 | 84,500 |
| Tuned + one alert per session | 19% of sessions | 1.9 | 1,900 | 19,000 |
| What a 5-analyst queue absorbs (60 alerts each) | 0.06 | 0.03 | 30 | 300 |

Gap between "tuned, session-deduped" and "absorbable": about 60x. Between raw tuned hits and absorbable: about 280x.

### 22 ordinary workflows that trip the proposed rule families
Observed = seen in the replay above; the rest are from `research/threats.md` section 6 or my own queue experience.

1. `curl -fsSL https://claude.ai/install.sh | bash`, rustup, brew, nvm, bun, uv installers -> R32 pipe-to-shell.
2. Reading `.env` / `.env.local` to fix a config bug (Read tool or `cat`) -> R21, sets `secret_read`.
3. `aws sts get-caller-identity`, `aws s3 cp`, `gh auth token`, `gcloud auth print-access-token` -> R42 + `egress`.
4. `git push`, `gh pr create` -> `egress` (observed: egress set in 65% of sessions).
5. `npm install` / `pip install` / `go mod tidy` -> `untrusted_input` + `egress`, R33 brand-new package.
6. `docker run --network host`, `-v /var/run/docker.sock`, `--privileged` (testcontainers, kind, dind) -> R43 (observed 25).
7. `docker rm -f`, `docker system prune`, `kubectl delete pod|ns` in dev namespaces, `terraform destroy` in a sandbox
   workspace -> R41 (observed 38).
8. `kubectl get secret x -o jsonpath=... | base64 -d`, base64 fixtures in tests -> base64 payload feature + R42.
9. Editing `~/.claude/settings.json`, `.mcp.json`, `CLAUDE.md` after `/init`, "add this MCP server" -> R11 / section 9 self-protection.
10. `rm -rf node_modules dist build .next target`, scratch cleanup in /tmp -> R40 (observed 21, 24% of sessions; "outside
    workspace" variant observed 11 in 7 sessions).
11. Test secrets in fixtures (`[redacted: AWS documentation example access key id]`, `[redacted: sk- prefixed test key]`, `hunter2`) -> secret scanner (observed: detect-secrets
    flagged exactly these in real commands).
12. `curl -d @payload.json http://localhost:4318/v1/logs` API tests -> R23 upload flag (observed 6 in 4 sessions).
13. `curl "https://raw.githubusercontent.com/$repo/$branch/$path"` in loops -> R23 dynamic URL (observed 92, 51% of sessions).
14. Restarting osqueryd / fluent-bit / orbit during agent-assisted ops work -> R37 (observed 3 in 2 sessions).
15. `sed -i`, `find . -exec` refactors -> R34 (observed 4).
16. `chmod -R 777` on docker bind mounts, `sudo apt-get install` -> privilege rules (observed 10).
17. `curl -k https://localhost:8412` against self-signed dev servers -> TLS-verify-off (observed 2).
18. `env | grep -i proxy`, `cat /proc/<pid>/environ` while debugging -> R30 (observed 1 AST, 7 regex).
19. `git commit --no-verify` on WIP, `ngrok http 3000` for webhook tests, `nmap localhost` -> R38 / R45 / R44.
20. WebSearch / WebFetch for docs, `gh pr view`, reading `node_modules/` -> `untrusted_input` (observed: 68% of sessions).
21. Security engineers and red-teamers (Uber's 17% TPNM class): observed in this very corpus; other reviewers'
    container experiments tripped R21, R43 and R30.
22. Writing detection rules or docs that quote attack strings -> every regex-on-text rule (observed 15 hits, 0 with AST).

## 2. Experiment B: trifecta base rate (A10)

From the same runs: `untrusted_input` is set in 68% of benign sessions and `egress` in 65%, so two of the three flags are
near-constant and carry almost no information. The rule reduces to "a secret-class path was touched" (5% of sessions).
Ordered trifecta fires in 1/37 = 2.7% (Wilson 95% [0.5%, 13.8%]); any-order in 2/37 = 5.4% [1.5%, 17.7%].

Base-rate arithmetic at 10,000 developers, 100,000 sessions per day:
- 2.7% benign trigger rate -> 2,700 trifecta alerts per day. If one real trifecta attack happens per day (generous: Uber
  called prompt injection "surprisingly rare", `research/adr-paper.md` l.6), PPV = 1/2,701 = 0.04%.
- For PPV >= 50% at prevalence p the benign trigger rate f must satisfy f <= p * recall. With p = 1e-5 per session, f <= 1e-5.
- For the rule family to cost <= 10 alerts per day, f <= 1e-4.
- So the rule is unusable as an alert whenever the benign trigger rate is above roughly 1 in 10,000 sessions. Measured: about
  1 in 37. Even the bottom of the interval (1 in 200) is 50x too high.

Also unstated: flags are keyed by session with a TTL. A longer TTL raises the benign rate; a shorter one is an evasion knob
(`sleep`, or stage the read in one session / subagent and the egress in a nested `claude -p`). threats.md S10 (memory
persistence across sessions) is the same gap. In daemonless mode the state lives in a per-session file in a user-writable
spool (v0 section 7), so the code under observation can clear its own taint.

## 3. Experiment C: guard mode, fail-open and exit codes (A12)

```
cd $S/redteam/dq/guard && GOTOOLCHAIN=go1.26.0 go build -o guard .
./guard panic >/dev/null 2>&1; echo $?          # nil-map write, an ordinary evaluator bug
-> exit(panic)=2
(cd so && ./so; echo $?)                         # stack overflow WITH a deferred recover() in main
-> stack-overflow-with-deferred-recover exit=2
   runtime: goroutine stack exceeds 1000000000-byte limit
   fatal error: stack overflow
```
Go exits with status 2 on an unrecovered panic and on every runtime fatal error (stack overflow, out of memory, concurrent
map write, deadlock); fatal errors cannot be recovered. Exit 2 is the "block" signal of the shared hook contract
(`research/agent-surfaces-a.md` l.24: Claude, Codex, Copilot, Gemini, Cursor; l.52 "exit 2 = block (stderr is the reason)").
Copilot is stricter: "preToolUse command hooks fail closed on crash or non-zero exit" (l.98). So a crash in `spoor hook`
blocks the developer's tool call **even with guard mode off**. A33 ships rule packs independently of the binary through
Fleet; one pack that panics the evaluator blocks every tool call on every hooked machine at once.

Adversarial parse cost with the design's 256 KiB cap (same binary, `./guard parse <kind> <bytes> recover`):
```
flat      n=262144  parse=1.607ms          (256 KiB heredoc)
cmdsubst  n=262144  parse=145.449ms
dblquote  n=262144  parse=296.405ms
subshell  n=262144  parse=1.942539s        (131,072 nested parentheses)
arith     n=262144  parse=1.894986s
```
Real commands: p99 156 us. Worst case under the cap: 1.9 s, 12,000x the p99. Not a timeout (30 to 600 s), so not a fail-open
by itself, but it kills the "2.9 ms p50" claim for attacker-shaped input and blocks a single-threaded daemon evaluator.
No crash at this depth. Related: the cap means text after 256 KiB is never analysed; `Truncated` must itself be a detection.

Fail-open facts from the research (not re-tested here):
- Timeouts fail open on every agent; Copilot always, including policy hooks; Claude unless `onFailure:"block"` (2.1.295+)
  (`agent-surfaces-a.md` l.25, l.98).
- Codex: `permissionDecision:"ask"`, bare `"allow"` and legacy `decision:"approve"` are unsupported and fail open
  (`agent-surfaces-a.md` l.72). A rule marked `response: ask` is silently "allow" on Codex.

Would-block rate if the obvious candidates were set to `response: block` (from Experiment A, AST-level):
- narrow (R37 sensor tamper + R40b rm outside workspace): 14 / 1,711 tool calls = 0.8% -> about 4 false blocks per developer
  per day -> about 40,000 per day at 10,000 developers.
- broad (plus R41, R43, R21, R30): 85 / 1,711 = 5.0%.
A denied model retries by another route (threats.md S7 "deny-then-evade", the Ona pattern, "needs no attacker"), so each
false block also manufactures a high-severity S7 detection.

## 4. Experiment D: redaction (A29)

```
./venv/bin/pip install detect-secrets      # 1.5.0
./venv/bin/python redact_test.py           # -> redact.out
```
28 realistic secret-bearing command lines (all values fake, format-valid), two redactors: (1) Yelp detect-secrets 1.5.0,
default plugins and filters, file-scan mode; (2) a generic "known-prefix regex + keyword=value + Shannon entropy >= 4.0 on
tokens >= 20 chars" redactor.
```
case                     detect-secrets  generic(regex+kv+entropy)
mysql -p glued           LEAKED          LEAKED
PGPASSWORD env prefix    LEAKED          redacted
curl -u user:pass        LEAKED          LEAKED
basic auth in URL        redacted        LEAKED
sshpass                  LEAKED          LEAKED
docker login -p          LEAKED          LEAKED
redis-cli -a             LEAKED          LEAKED
kubectl from-literal     LEAKED          redacted
terraform -var           LEAKED          redacted
JSON body password       redacted        LEAKED
mongodb URI              redacted        LEAKED
postgres URI             redacted        LEAKED
7z password              LEAKED          LEAKED
openssl -k               LEAKED          LEAKED
net use (Windows)        LEAKED          LEAKED
PowerShell header        LEAKED          LEAKED
query-string api_key     LEAKED          redacted
base64-wrapped pw        LEAKED          LEAKED
split AWS key            LEAKED          LEAKED
heredoc .env             LEAKED          redacted
az sp login              LEAKED          redacted
gh secret set            LEAKED          LEAKED
git commit msg           LEAKED          LEAKED
AWS secret key           LEAKED          redacted
GitHub token in URL      redacted        redacted
JWT bearer               redacted        redacted
Slack webhook            redacted        redacted
Anthropic key env        LEAKED          redacted

MISSES: detect-secrets 21/28 = 75% leaked;  generic 17/28 = 61% leaked

FALSE HITS on 1095 real benign commands: detect-secrets flags 7 commands (0.6%)
    (fixtures: '[redacted: AWS documentation example access key id]', 'hunter2', 'pa55w0rd', '[redacted: sk- prefixed test key]', md5-looking hex)
generic entropy>=4.0/len>=20 token rule flags 843 commands (77.0%), 1893 tokens redacted; examples:
    /tmp/claude-0/-home-user/[redacted: session id]/scratchpad
    //codeload.github.com/uber/ADR/tar.gz/refs/heads/main
```
Note on method: my first run used detect-secrets' ad-hoc `scan_line`, which reports every token for the entropy plugins
(99.8% of commands flagged); that mode is not a redactor, so I discarded it and re-ran in file-scan mode. The table is the
file-scan run.

Mechanism: the secrets developers actually type are human-chosen, low-entropy, and sit in tool-specific argv positions
(`-pX`, `-a X`, `-u user:pass`, `-k X`, trailing positional). Pattern lists only know vendor token prefixes. Entropy does not
rescue it: a threshold low enough to catch `Passw0rd!` redacts paths, URLs, UUIDs and digests (77% of real commands lose a
token, i.e. the evidence an analyst needs), and a threshold high enough to keep paths misses 61 to 75% of the cases.

## 5. Experiment E: what "metadata" mode actually emits and what it disables (A26)

From Experiment A: 147 of 1,095 real commands (13.4%) contain a heredoc; heredoc bodies are 32% (AST) to 41% (regex) of all
command bytes; 3.7% more pass inline code to `python -c` / `bash -c`. Command length p90 1,312 bytes, p99 3,854, max 7,936.
The design's metadata tier keeps "commands and paths ... with secrets redacted" (v0 section 8). So the default tier ships
whole files, scripts, SQL, JSON bodies and commit messages: content, not metadata. The examples in my own replay output are
full Fluent Bit configs, Go source files and OCSF documents written through `cat > f <<'EOF'`.

Detections that still fire locally but cannot be adjudicated or used downstream in metadata mode:
- Trifecta S1: the discriminating condition in threats.md is "no intervening user prompt naming the destination". Prompts
  are hash + length only.
- Destructive verbs R40/R41 and control-file writes R11: the only separator from normal work is "did the user ask for
  this" (threats.md section 7b). Not answerable from metadata.
- Content scanners (hidden Unicode, injection markers, secrets in tool output), R25 data-bearing image in assistant output,
  R28 foreign API key: the "redacted evidence snippet" is either the content (privacy breach) or absent (unverifiable).
- The `escalate: true` LLM tier (v0 section 5): the downstream judge receives no prompt and no tool output.
- SIEM-side Sigma conversions (A35) of any content rule; retro-hunting a newly published injection string or IOC text.
- Rule tuning: the engineer cannot see why a rule fired, so false positives cannot be fixed from the queue.
Also: a prompt hash without a key is a dictionary oracle for short prompts ("yes", "continue", "fix the tests"); with a
per-host key it cannot correlate one injected prompt across hosts.

Works-council angle: a per-employee stream of (user, timestamp, repo, cwd, command) is behaviour and performance monitoring
regardless of content. The tiers control content only; nothing in the design pseudonymises the user or withholds the
activity stream.

## 6. Experiment F: flat predicates versus bound predicates (A35)

```
python3 flat_vs_bound.py     # -> flat.out
parsed shell commands: 1175
predicate                    flat-array  bound  spurious(flat only)
curl_upload_flag                      0      0  0
rm_rf_abs_path                       18      5  13
download_piped_to_shell               0      0  0
kill_security_tool                   10      3  7
```
"Field predicates with modifiers + all/any/not" over feature arrays (`commands[].name`, `commands[].args`) cannot say "the
same command". `rm -rf $W; cp /etc/x .` satisfies "a command is rm" and "an arg has -rf" and "an arg is absolute".
Measured inflation: 3.6x for rm-rf-absolute-path, 3.3x for kill-security-tool. The fix is either to pre-join every
combination in Go (each new rule idea becomes a binary release, which defeats A33) or to give the rule language
quantifiers with binding. CEL has them (`cmds.exists(c, c.name == 'rm' && c.args.exists(a, a.startsWith('/')))`); the Sigma
spec does not.

Other evidence against "Sigma-style, converts to Sigma" (`research/standards.md` section 6): Sigma "cannot express
arithmetic, computed fields or baseline state (rug-pull drift, first-seen)" and the report already recommends an `x-cel:`
escape hatch; the Go Sigma libraries are stale (sigma-go 2024-09, go-sigma-rule-engine 2022), so spoor would own a custom
evaluator of about 1k lines anyway; there is no ATLAS tag namespace and no agent logsource. A dialect that is "Sigma-style"
but not Sigma validates with neither sigma-cli nor cel-go. Both nearest OSS projects use CEL plus YAML with embedded tests
(numbat: 2 to 8 step sequences; Beacon Threat Rules v1.2 with `correlation{scope, window, order, steps[]}` and a cost cap of
5,000,000, `research/small-oss.md` sections 3 and 4), so CEL is also the interchange format for rule packs and corpora.
Not run here: a cel-go type-check demo (unknown field is a compile error in CEL and a silently dead rule in a YAML predicate).

## 7. A13: what an honest benchmark must contain

Evidence that the proposed bench ("scenario YAML, per-technique n >= 10 with benign look-alikes, no API key") measures
the wrong thing:
- ADR-Bench: 0/260 FP on bench, 49% FP in production (`adr-paper.md` l.93, l.97). A "server never seen in a benign task"
  oracle scores 39 TP / 0 FP, above ADR's own 28/42; 39/43 malicious tasks use a dedicated vulnerable server; two tasks are
  labelled malicious although the agent refused; no tool arguments; 7 of 17 techniques have one malicious task
  (`adr-detection.md` section 8, `adr-paper.md` l.5).
- Agentmetry: 57 cases, "0 missed / 0 FP on its own corpus" (`small-oss.md` section 2).
- n = 10: 10/10 recall has a Wilson 95% lower bound of 72%; 0/10 benign look-alikes bounds the FP rate only below 28%.
- The number my queue needs is alerts per 1,000 developer-days. To show a rule is below 1e-4 per session with 95%
  confidence takes about 30,000 benign sessions with zero hits (rule of three).
- Experiment A is the demonstration: every regex rule above passes its own inline test and still produced 15 false hits
  from heredocs that only a real-session replay exposed.

Minimum contents:
1. A real benign replay corpus (recorded hook payloads + transcripts, arguments kept), at least 30,000 sessions or 1M tool
   events, from dogfooding, consenting design partners and public agent trajectories. Headline metric: alerts per 1,000
   developer-days per rule and severity, with intervals.
2. Attacks recorded from real agents, authored blind (authors do not see the rules) or time-split (rules frozen before the
   incident date). Per-event labels with `evidence_event_ids`, and an outcome label: attempted, succeeded, refused.
3. At least 5 semantics-preserving mutations per attack (quoting, `$IFS`, wrappers, split across subagents, sleep past TTL):
   report robust recall, not recall.
4. Leakage controls: an identifier-randomised run, and published scores of trivial oracles (name-only, server-set-only) that
   every rule set must beat.
5. Ablations: hook-only, transcript-only, process-only; privacy tier metadata versus full; daemon versus daemonless.
6. Prevalence-adjusted PPV at 1e-4, 1e-5 and 1e-6; no F1 on a corpus that is 14% malicious.
7. Guard metrics: would-block rate on the benign corpus, p99.9 latency per OS, crash and exit-code behaviour.
8. Dev/test split with a hash-committed held-out set; report the gap. Cells with n < 30 are printed as "insufficient".

## 8. Other measured consequence: the "small fraction" escalation claim

v0 section 5: sessions matching "suspicious but not conclusive" rules are tagged `escalate: true` so an LLM judge "only
sees a small fraction". Measured: 65% of benign sessions hit at least one rule as sketched, 19% after tuning. ADR itself
escalated 59% (`adr-detection.md` l.7). At 100,000 sessions per day and ADR's $0.024 per session, 19% is about $456 per day
before the content problem in section 5.

## 9. Precision controls I would require before this goes on my queue

1. Three output classes per rule: `signal` (local counter and session risk score, cheap storage only), `finding` (SIEM, no
   page), `alert` (queue). A rule may be `alert` only if its measured benign rate in the replay corpus is under a budget
   stored in the rule (`max_per_1k_dev_days`), enforced by `spoor rules lint` in CI.
2. Trifecta on data flow, not co-occurrence: on a secret-class read the sensor fingerprints the values it saw (the local
   engine has the PostToolUse output) and alerts only when a later outbound command, URL or body contains a fingerprint
   (raw, base64, hex, URL-encoded), or when the destination is first-seen for this (repo, host) and not in the lockfile /
   manifest / registry allowlist. Co-occurrence stays a `signal`.
3. Taint with provenance: `untrusted_input` records source host class; package registries, the org's own SCM and docs hosts
   do not set it.
4. First-seen baselines kept in the state DB: (repo, egress host), (repo, command name + subcommand), (host, MCP server
   hash). Alert on novelty, count on repetition.
5. Dedup key `(rule_id, host_id, repo_id, target_fingerprint)` with a 24 h suppression window and a count carried on the
   heartbeat; one alert per session per rule at most.
6. Workspace = cwd + git worktree roots + OS temp + agent scratch dirs; "outside workspace" is evaluated on realpath.
7. Profiles from Fleet labels (`offsec`, `platform-eng`, `ci`) select allowlists: Uber's 17% TPNM class came from offensive
   security teams.
8. Shell rules may only match AST facts; `re`/`contains` on the raw command string is a lint error.
9. Guard: a rule is block-eligible only after a shadow period with zero would-blocks in the benign corpus and under a
   per-fleet would-block budget, with automatic demotion to `ask` or monitor when exceeded.
