# A real agent through the whole pipeline

Run on 2026-11-12, Linux x86-64 (4 vCPU VM, load average 2 to 4 from other
work), Claude Code 2.1.322 (`/opt/claude-code/bin/claude`, the native
binary that `/opt/node22/bin/claude` links to), Fluent Bit 5.2.0
(`fluent/fluent-bit:latest`). spoor built with
`CGO_ENABLED=0 go build -trimpath ./cmd/spoor` (`spoor dev (6d758f27ce16-dirty)`,
the tree including the transcript fix listed under "Fixed").

What is real: Claude Code itself (its hook runner, its permission logic, its
transcript writer), `spoor hooks install`, the hook command exactly as
installed (no `--config`), the daemon, `spoor doctor`, the shipped Fluent Bit
fragments, curl and sh. What is a stand-in: the model. `ANTHROPIC_BASE_URL`
points at a local stand-in for the Messages API (derived from the red
team's `verify-alt-architectures/bare/tool/stub.py`): its first model turn
asks for one Bash call, `curl -fsS http://127.0.0.1:47802/observe/install.sh | sh`,
its second ends the turn. `install.sh`, served by a local `python3 -m http.server`,
only echoes `spoor-realagent-marker: install.sh ran ...`. The stand-in
logs every request with the tool results Claude Code sends back, which is
what a model would have seen.

Two complete runs were made by hand (run 1 step by step, run 2 scripted
from scratch); the numbers below are from run 2 unless marked. The gated
test `realagent_test.go` repeats steps 1 to 6 unattended (last section).

## Isolation

The daemon runs as root and reads every account's agent logs, and this host
runs other Claude Code sessions as root. So the daemon, the agent and the
local servers ran in one private mount and PID namespace:

```
unshare -m -p -f --mount-proc --propagation private init.sh   # started with env -i
  mount -t overlay overlay -o lowerdir=/etc,upperdir=$R/ns/etc-up,workdir=$R/ns/etc-work /etc
  mkdir -p /etc/spoor; cp $R/etc/spoor.yaml /etc/spoor/spoor.yaml
  mount -t tmpfs -o mode=0700 tmpfs /root; mount -t tmpfs -o mode=0755 tmpfs /home
  exec sleep infinity
```

- `/etc` overlay: the hook reads the default `/etc/spoor/spoor.yaml`, exactly
  as installed, and gets this run's configuration; the host's `/etc` is not
  touched (`test ! -e /etc/spoor` on the host passed after setup).
- `/root` and `/home` empty: the daemon sees only root's fake `HOME`
  (`$R/home`, given to the daemon as `HOME`, which `platform.Users` lists as
  a second home of the account).
- PID namespace: the process monitor sees only this run.
- Every process got `env -i` plus what it needs. In run 1 the namespace's
  `sleep infinity` was started with the environment of the Claude Code
  session running this verification; the daemon correctly attributed it to
  that outer session by its env markers (`CLAUDECODE`,
  `CLAUDE_CODE_SESSION_ID`) and synthesized a session for it
  (`session.synthesized_start: 1`). Run 2 starts the namespace with `env -i`.
- Another verification created a host `/etc/spoor/spoor.yaml` at 07:38:43,
  during run 2's timing series. Through the overlay a host file in
  `/etc/spoor` can show through where the run has none (a kill switch would
  have); the gated test therefore also mounts a tmpfs on `/etc/spoor`.

Daemon configuration (run 2):

```yaml
data_dir: $R/data
heartbeat: 10s
privacy: {profile: minimal}
guard: {mode: "off"}
sources:
  hooks: {enabled: true, poll: 100ms}
  transcripts: {enabled: true, poll: 1s}
  processes: {enabled: true}
  osquery_exec: {enabled: false}
  scan: {enabled: true, projects: false}
```

```
nsenter -t $NS -m -p env -i PATH=/usr/bin:/bin HOME=$R/home LANG=C.UTF-8 \
  BIN run --config /etc/spoor/spoor.yaml --log-level debug
level=INFO msg="spoor starting" version=dev config=/etc/spoor/spoor.yaml data_dir=$R/data profile=minimal
level=WARN msg="output.group does not exist; the outbox stays readable by root only" group=spoor
level=INFO msg="spoor daemon started" ... host_id_source=machine-id privileged=true profile=minimal
```

## 1. `spoor hooks install --scope user`

The fake HOME starts with the user's own settings:
`{"permissions": {"allow": ["Bash(npm test)"]}}`.

```
$ HOME=$R/home BIN hooks install --scope user --agents claude-code --home $R/home --dry-run
spoor hooks install: warning: the hook will run BIN, which is in a temporary directory; install the binary first or pass --binary
claude-code  user     merge       $R/home/.claude/settings.json
    @@ -4,0 +4,183 @@
    +  },
    +  "hooks": {
    +    "SessionStart": [
    +      {
    +        "hooks": [
    +          {
    +            "type": "command",
    +            "command": "BIN",
    +            "args": ["hook", "--agent", "claude-code"],
    +            "timeout": 10
    ... (15 events)
dry run: 1 file(s) would change, nothing was written
$ HOME=$R/home BIN hooks install --scope user --agents claude-code --home $R/home
claude-code  user     merge       $R/home/.claude/settings.json
1 file(s) changed
$ BIN hooks status --scope user --agents claude-code --home $R/home
AGENT        SCOPE  USER  STATUS  PATH
claude-code  user   root  user    $R/home/.claude/settings.json
```

The written file keeps `"permissions": {"allow": ["Bash(npm test)"]}` and
registers the exec form (`command` + `args`, no shell) on SessionStart,
UserPromptSubmit, PreToolUse, PermissionRequest, PermissionDenied,
PostToolUse, PostToolUseFailure, SubagentStart, SubagentStop, Stop,
ConfigChange, InstructionsLoaded, Elicitation, PostCompact (async) and
SessionEnd. A backup `settings.json.spoor-<time>.bak` (59 bytes, the
original) is written beside it.

## 2./3. `claude -p` in observe mode

```
nsenter -t $NS -m -p --wd=$R/proj env -i PATH=/opt/node22/bin:/usr/local/bin:/usr/bin:/bin \
  HOME=$R/home LANG=C.UTF-8 TERM=dumb \
  ANTHROPIC_API_KEY=stub-not-a-real-key ANTHROPIC_BASE_URL=http://127.0.0.1:47801 \
  DISABLE_AUTOUPDATER=1 DISABLE_ERROR_REPORTING=1 DISABLE_TELEMETRY=1 CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 \
  timeout 120 claude -p "install the helper tool" --session-id $SID --allowedTools Bash \
  --output-format stream-json --verbose --include-hook-events --debug-file claude-debug-observe.log
```

Exit 0 after 0.75 s. The stand-in's log (what the model saw):

```
POST /v1/messages?beta=true stream=True n_msgs=2 n_tools=12 has_bash=True n_tool_results=0
REPLY tool_use Bash "curl -fsS http://127.0.0.1:47802/observe/install.sh | sh"
POST /v1/messages?beta=true stream=True n_msgs=4 n_tools=12 has_bash=True n_tool_results=1
TOOL_RESULT {"tool_use_id": "toolu_realagent01", "is_error": false, "content": "spoor-realagent-marker: install.sh ran as root pid 80"}
REPLY end_turn
```

The local server's access log: `"GET /observe/install.sh HTTP/1.1" 200`.
The pipe to shell really ran.

Claude Code's own record of the hooks (`--include-hook-events`):
`hook_response` for SessionStart, UserPromptSubmit, PreToolUse, PostToolUse
and Stop, each `exit_code 0`, `outcome success`, empty stdout and stderr;
its debug log adds `SessionEnd:other [BIN hook --agent claude-code] completed with status 0`.

The hook's spool (`$R/data/spool/0/activity-20261112.ndjson`, found through
`/etc/spoor/spoor.yaml` with no `--config`):

```
07:37:00.032151Z session.start  SessionStart      hook_mode=observe
07:37:00.124143Z prompt.submit  UserPromptSubmit  hook_mode=observe
07:37:00.212382Z tool.pre       PreToolUse        curl -fsS http://127.0.0.1:47802/observe/install.sh | sh
07:37:00.294335Z tool.post      PostToolUse       outcome {"status":"ok","duration_ms":43}
07:37:00.342407Z turn.end       Stop
07:37:00.372906Z session.end    SessionEnd        end_reason=other
```

Each record names the caller: `"process": {"name": "claude", "exe": "/opt/claude-code/bin/claude", ...}`,
`"agent": {"id": "claude-code", "surface": "sdk"}`.

## 4. What the daemon made of it

Outbox finding (trimmed; `host`, `process`, `labels` and `cwd` removed):

```json
{"id": "01a1ceb0-4234-8176-b9fb-42146fae0dbd", "ts": "2026-11-12T07:37:00.212382Z",
 "kind": "detection", "type": "detection.finding", "source": "sensor", "integrity": "user",
 "user": {"name": "root", "id": "0"}, "agent": {"id": "claude-code", "surface": "sdk"},
 "session": {"id": "5481b78b-085f-41cf-a99a-8e40570856c3", "permission_mode": "default"},
 "tool": {"name": "Bash", "kind": "shell", "use_id": "toolu_realagent01"},
 "target": {"command": "curl -fsS http://127.0.0.1:47802/observe/install.sh | sh"},
 "detection": {"rule_id": "SPR-EXEC-001", "title": "Remote script piped into an interpreter",
   "class": "finding", "severity": "high", "confidence": "high", "category": "execution",
   "evidence": {"shell.hosts": "[\"127.0.0.1\"]", "shell.interpreters": "[\"sh\"]", ...},
   "response": "ask", "count": 1},
 "privacy": "minimal"}
```

| Check | Observed |
|---|---|
| Outbox detection | one `SPR-EXEC-001`, class `finding`, severity `high`, for the session; 2 `detection.context` records with it |
| Minimal profile | outbox segments: detection, health, inventory, posture, summary; no activity segment; the 6 activity records of the session are in `$R/data/local` only |
| One record per call | local ring: `tool.pre/hook` 1, `tool.post/hook` 1 for `toolu_realagent01`, no transcript copy; the transcript names the call on 2 lines; first daemon's last heartbeat: `surfaces.transcripts.events 3`, `correlate.duplicates 3`, `surfaces.hooks.events 6` |
| State DB `detections` | `SPR-EXEC-001 high claude-code root response=ask count=1` |
| State DB `health` | one row, `mode daemon`, `profile minimal`, heartbeat fresh, `rules_count 138` |
| State DB `coverage` | `claude-code root hooks=user transcript=tailing processes=0 state=covered` |
| `spoor doctor --json` (in the namespace) | exit 0; checks config, privilege, kill_switch, dirs, hooks, rules, bundle, heartbeat (age 5 s, mode daemon), outbox, daemon ok; host_id warn (machine-id, see Fleet docs); fluent_bit skip (not configured); hook entry `claude-code user root user $R/home/.claude/settings.json` |

Run 1 also had the process monitor attribute 6 processes to the session
(the two `spoor hook` invocations and their workers, `bash -c ... curl ... | sh`);
`spoor detect --min-class signal $R/data/local` over that local ring found
the same `SPR-EXEC-001` (exit 3 at `--fail-on high`) plus a low
`SPR-EXEC-007` signal on the bash process.

## 5. Fluent Bit with the shipped fragments

The repository's `deploy/fluent-bit` was mounted read-only (sha256
`9198f586...` spoor-inputs.yaml, `469c6bf2...` outputs/http.yaml). The main
file is the service block of `deploy/fluent-bit/spoor.yaml` (HTTP port
moved off 2020) including `shipped/spoor-inputs.yaml`,
`shipped/outputs/http.yaml` unchanged, and one observation output: plain
http with `header_tag X-Tag` and `json_date_key date` (`double`), the
shape `fluentbit_test.go` uses, because the shipped http output carries
neither tag nor event time.

```
docker run -d --name realagent-flb-r2 --network host \
  -v $R/fb/cfg:/cfg:ro -v $REPO/deploy/fluent-bit:/cfg/shipped:ro \
  -v $R/data/outbox:/outbox:ro -v $R/fb/state:/state -v $R/fb/certs:/etc/ssl/certs:ro \
  -e SPOOR_OUTBOX=/outbox -e SPOOR_FLB_DB=/state -e SPOOR_FLB_STATE=/state \
  -e SPOOR_HTTP_HOST=127.0.0.1 -e SPOOR_HTTP_PORT=47803 -e SPOOR_HTTP_URI=/spoor -e SPOOR_HTTP_TOKEN=realagent-test-token \
  fluent/fluent-bit:latest /fluent-bit/bin/fluent-bit -c /cfg/main.yaml
```

Received (one local receiver, TLS on 47803 for the shipped output, plain on
47804 for the observation output):

```
6 (observe-http-plain, spoor.detection, detection)   6 (shipped-http-tls, -, detection)
6 (observe-http-plain, spoor.health, health)         6 (shipped-http-tls, -, health)
32 (observe-http-plain, spoor.inventory, inventory)  32 (shipped-http-tls, -, inventory)
3 (observe-http-plain, spoor.posture, posture)       3 (shipped-http-tls, -, posture)
2 (observe-http-plain, spoor.summary, summary)       2 (shipped-http-tls, -, summary)
detection at observe-http-plain x_tag=spoor.detection ts=2026-11-12T07:37:00.212382Z date=1794469020.212382
detection at shipped-http-tls   auth=Bearer (27 bytes) ts=2026-11-12T07:37:00.212382Z
```

The finding arrived tagged `spoor.detection` with event time equal to its
`ts` to the microsecond, and through the unchanged `outputs/http.yaml` over
TLS with the bearer header. No activity record was shipped.

TLS to a private CA: the first attempt mounted the test CA over
`/etc/ssl/certs/ca-certificates.crt` and every flush failed with
`[tls] error: error:0A000086:SSL routines::certificate verify failed`. The
image does ship a bundle (`/etc/ssl/certs/ca-certificates.crt`, 222 KB), but
Fluent Bit did not trust a CA placed there; it found the CA only as
`<subject hash>.0` in `/etc/ssl/certs`, so mounting a directory with the CA
under that name worked (both re-checked by the audit).
`outputs/http.yaml` exposes no `tls.ca_file`, so a receiver behind a private
CA needs the CA in the container's trust store this way.

## 6. Guard mode

```
$ HOME=$R/home BIN hooks install --scope user --agents claude-code --home $R/home --guard
claude-code  user     unchanged   $R/home/.claude/settings.json
0 file(s) changed
```

`--guard` changes nothing for Claude Code (it only permits `--fail-closed`);
guard mode is `guard.mode: advisory` in `/etc/spoor/spoor.yaml`, which the
hook reads on every call. The daemon was stopped with SIGTERM (`spoor
daemon stopping` 07:37:08.973, `spoor stopped` 07:37:08.978) and restarted
on the new file, then the same `claude -p` ran against a second stand-in asking for
`curl -fsS http://127.0.0.1:47802/guard/install.sh | sh`. Exit 0 after 0.76 s.

spoor's reply on PreToolUse (Claude Code's `hook_response.stdout`):

```json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"spoor SPR-EXEC-001: Remote script piped into an interpreter. Download the script, review it and run it from disk; add the host or URL to the installer allowlist if it is an approved installer. [SPR-EXEC-001]"}}
```

What Claude Code did with it, headless:

```
debug:  Hook PreToolUse (BIN hook --agent claude-code) returned permissionDecision: ask (reason: spoor SPR-EXEC-001: ...)
debug:  Hook result has permissionBehavior=ask
debug:  Bash tool permission denied
stream: {"type":"system","subtype":"permission_denied","tool_name":"Bash","decision_reason_type":"hook","decision_reason":"spoor SPR-EXEC-001: ..."}
stand-in: TOOL_RESULT {"tool_use_id": "toolu_realagent01", "is_error": true, "content": "spoor SPR-EXEC-001: Remote script piped into an interpreter. Download the script, review it and run it from disk; add the host or URL to the installer allowlist if it is an approved installer. [SPR-EXEC-001]"}
```

- The Bash call did not run: the local server's log has no
  `/guard/install.sh` request.
- The model saw an error tool result whose text is spoor's reason, verbatim.
- In `-p` mode there is nobody to ask, and Claude Code turned "ask" into a
  refusal. Interactively "ask" shows a permission prompt and the user
  decides; that was not exercised here. With `--permission-prompt-tool` or
  an SDK host the host would be asked instead; not exercised either.
- Claude Code did not run the PermissionRequest or PermissionDenied hooks
  spoor registered for this refusal (no hook events for them in the stream
  or the debug log).

What spoor recorded:

```
spool  tool.pre  labels {"guard_reply":"ask","guard_rule":"SPR-EXEC-001","hook_mode":"guard"} outcome {"decision":"ask","decision_source":"spoor"}
outbox detection.finding SPR-EXEC-001 high response=ask   (re-detected by the daemon; the hook spools no findings in guard mode)
local  tool.post source=transcript outcome {"status":"denied","error":"hook_denied","decision":"deny","decision_source":"hook"}
```

There is no PostToolUse hook record (the tool never ran); the refusal is
known from the transcript, which records it as:

```
"toolDenialKind":"user-rejected","permissionDecision":{"decision":"reject","source":"config","reasonCode":"hook:PreToolUse"}
```

Before the fix below (run 1) spoor turned that into
`{"error":"user_rejected","decision_source":"user"}`.

## 7. Hook overhead inside the agent

Claude Code's debug log times every hook command it runs except SessionEnd ("finished with
status 0 (N ms)", whole milliseconds, spawn to exit as Claude Code sees
it). 10 runs each (observe and control interleaved, the guard runs after them), in the same namespace with the daemon
running: spoor in observe mode, spoor in guard mode, and a control HOME
whose hooks on the same events are the exec form `/bin/sh -c 'cat >/dev/null'`
(a process that only drains stdin).

| Event | control p50 | spoor observe p50 (min-max) | spoor guard p50 (min-max) |
|---|---|---|---|
| SessionStart | 16.5 | 28.5 (25-52) | 35.0 (31-75) |
| UserPromptSubmit | 5.0 | 18.5 (16-32) | 26.0 (22-34) |
| PreToolUse | 10.5 | 25.5 (22-32) | 33.0 (29-45) |
| PostToolUse | 4.0 | 18.0 (16-24) | - (call refused) |
| Stop | 5.0 | 19.0 (16-26) | 27.0 (23-34) |
| all events pooled | 5.0 (n=50) | 21.0 (n=50) | 31.0 (n=40) |

All in ms. At p50 under this host's load, spoor costs 12 to 15 ms per hook
over the drain-only control in observe mode and 18 to 23 ms in guard mode.
Every hook exited 0 (90 spoor, 50 control).

The spool record's `ts` is the supervisor's t0 (start of `hookcmd.Run`), so
each spoor hook splits into Claude Code's spawn to t0 and t0 to Claude Code
seeing it finish (start = debug-log time minus duration; ms resolution):

| | spawn -> t0 p50 | t0 -> done p50 |
|---|---|---|
| observe PreToolUse | 14.1 | 12.0 |
| observe PostToolUse | 7.4 | 9.8 |
| observe UserPromptSubmit | 7.5 | 10.8 |
| guard PreToolUse | 12.7 | 19.9 |
| guard UserPromptSubmit | 9.0 | 17.0 |

The first part is exec of the 31 MB static binary plus Go runtime and
package init (and Claude Code's own spawn cost, which the control shows is
4 to 16 ms depending on the event); the second is reading stdin and the
config, the worker, the reply and exit; guard adds rule loading and
evaluation.

The same hook run directly (no agent) on a PreToolUse payload, 40 times:
observe p50 17.2 ms (min 13.6, p90 20.5), guard p50 25.3 ms (min 21.2, p90
31.7), `sh -c 'cat >/dev/null'` p50 2.7 ms.

Cold start (run 1, first hooks after building the binary, daemon starting
at the same time): SessionStart 57, UserPromptSubmit 83, PreToolUse 130,
PostToolUse 46, Stop 20 ms; the later runs above did not see this.

## Fixed

- `internal/transcript` (claude.go, claude_test.go): a call refused because
  a PreToolUse hook answered "ask" in headless mode was recorded as the
  user's refusal (`decision_source user`, `error user_rejected`), because
  Claude Code 2.1.322 writes `toolDenialKind "user-rejected"` for it and
  the hook appears only in `permissionDecision.reasonCode`
  (`"hook:PreToolUse"`), a field the reader did not decode. It now decodes
  `reasonCode` and, for a "user-rejected" record whose permissionDecision
  names a hook and whose result text is not Claude Code's own "The user
  doesn't want to ..." text, records `decision_source hook`,
  `error hook_denied`. Test: `TestClaudeHookAskRefusedHeadless` (the
  captured records, plus a user refusal with the same reasonCode that must
  stay a user decision); it fails without the change. Run 2 and the gated
  test show the fixed outcome.

## Observed, not fixed

- Session summary races the transcript. The final summary is emitted when
  SessionEnd's hook record is processed; the transcript tailer (1 s poll)
  delivered its records 0.2 s later. The shipped summary of the observe
  session says `surfaces ["hook"]`, `coverage partial`, and the state DB
  session row `sources hook, coverage partial`, while the coverage table
  says `covered` from the same records. The guard session read `covered`
  only because the process monitor happened to see a process of it. Short
  headless sessions will usually end before the transcript poll.
  (internal/engine, `maybeFinal`.)
- The process monitor records spoor's own hook processes (`spoor hook
  --agent claude-code`, and in run 1 also `spoor hook --worker ...`) as
  `process.exec` activity of the agent's session. In run 1, 4 of the 5
  `detection.context` records shipped with the finding were these. They
  are real children of the agent and corroborate that the hook ran, but as
  case context they are noise.
- Corroboration is not on the record. When the hook record arrives first,
  the transcript's copy is dropped as a duplicate (`correlate.duplicates`);
  the activity record already written carries no `sources` list, so only
  the heartbeat counters show that the transcript confirmed it.
- `processes` surface `degraded / exec_source_poll` in both runs: no
  cn_proc exec events. Expected inside a PID namespace (the kernel ignores
  proc-connector subscribers outside the initial PID namespace); not
  checked outside one on this host.
- `output.group: spoor` (the default) does not exist here; the daemon warns
  and keeps the outbox root-only. Fluent Bit ran as root in its container.
- Claude Code logs "Hook output does not start with {, treating as plain
  text" for every empty observe-mode reply (debug level only).

## Gated test

`realagent_test.go` (build tag `e2e`) repeats steps 1 to 6 unattended with
its own stand-in for the Messages API and install server in Go, a fresh
namespace (`/etc/spoor` additionally a tmpfs) and a temporary data
directory, and the Fluent Bit step through the `fluentbit_test.go` helpers
when the image is present:

```
$ SPOOR_E2E_AGENT=1 go test -tags e2e ./test/e2e -run RealAgent -v -count=1
=== RUN   TestRealAgentClaudeCode
    realagent_test.go: observe run 574584a3-... took 736ms
    realagent_test.go: Fluent Bit: finding 01a1ceb7-... arrived tagged spoor.detection, event time 1794469488.048427, ts 2026-11-12T07:44:48.048427Z
    realagent_test.go: guard run 1ae79504-... took 794ms
    realagent_test.go: guard mode: the model saw is_error=true "spoor SPR-EXEC-001: Remote script piped into an interpreter. ..."
--- PASS: TestRealAgentClaudeCode (30.01s)
```

Four passing runs: 26.9 s, 29.4 s, 30.0 s and, on the final code, 29.9 s.
It skips
without `SPOOR_E2E_AGENT=1`, off Linux, when not root, when Claude Code or
node is missing (`SPOOR_E2E_CLAUDE`, `SPOOR_E2E_NODE`, PATH,
`/opt/node22/bin`; checked with both pointed at a missing file), when
unshare, nsenter or curl is missing, without overlayfs, and when Claude
Code lives under `/root` or `/home` (masked in the namespace).
