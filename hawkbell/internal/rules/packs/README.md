# Embedded rule packs

Every `*.yaml` file here is a rule pack compiled into the hawkbell binary
(`rules.LoadEmbedded`): 13 packs, 138 rules (`hawkbell rules list`). The
format, the predicate language and the lint rules are documented in the
`internal/rules` package comment (`go doc ./internal/rules`) and, with
worked examples, in [docs/RULES.md](../../../docs/RULES.md). Rule ids are
`HB-<AREA>-<NNN>`, one area code per pack except `sequence.yaml` (`FLOW`
for its flag-only rules, `SEQ` for the rest). The precision rules a
shipped rule has to meet (parsed facts only, alert class only with two
negative tests, `response: block` never) are under "Rules for the shipped
packs" in docs/RULES.md.

After adding or editing a pack here, or `../lists.yaml`, regenerate the
pre-parsed copy that keeps guard-mode hook start-up fast:

    go generate ./internal/rules

`embedded.cache` is generated: do not edit it. A stale cache is never
wrong at run time (the YAML is parsed instead), only slower, and
`go test ./internal/rules` fails until it is regenerated
(`go run ./internal/rules/cmd/rulescache -dir internal/rules -check`
reports it without writing). The same test run checks that every pack
loads, passes its inline tests and lints without errors. Then rerun the
benchmarks and regenerate the catalogue in docs/RULES.md, as that page
describes.

## Catalogue entries without a rule

The packs implement the detection catalogue of `research/threats.md`
sections 3 (R01 to R54) and 4 (S1 to S12). That file is the project's
threat research, published as a historical design record in
[research/threats.md](../../../research/threats.md).
Every entry is cited in some rule's `references`, except these six. Each
needs a fact the sensor does not collect yet, so writing a rule now would
mean matching command text, which the linter forbids.

| Entry | What it detects | What is missing |
|---|---|---|
| R06 Pre-prompt execution | A child of the agent runs between session start and the first prompt, and its command is not an approved hook | An approved-hook list joined to process events: inventory records hook definitions with a hash (`asset.sha256`), but a `process.exec` event carries no hook identity or command hash to compare against, and process events are not reliably keyed to the same session as hook events (`SessionKey` needs the agent's user, agent and session ids). |
| R15 Plugin pin mismatch | An installed plugin's commit differs from the commit its marketplace pins | The marketplace's pinned commit per plugin. Discovery records the installed commit (`asset.detail.git_sha`), the marketplace name and its source, but does not read the marketplace manifest, so there is nothing to compare. |
| R20 Instruction or memory file written by a non-user process | CLAUDE.md, AGENTS.md, rules or memory files changed by an install script or unknown binary | File-integrity events with the writing process. The OS plane reports process starts only (`procmon`, `osqexec`); writes by tools are seen, writes by other processes are not. |
| R26 Remote `$schema` leak | A written JSON file whose `$schema` URL sends path or query data to a host off the allowlist | The URLs inside content being written. `write.*` features scan written content for secrets, invisible Unicode, instruction-override markers, autorun keys and git exec keys, not for URLs or hosts. A written script's commands are analysed like a shell event (hosts included), but a JSON file is not a script. |
| S4 Open-and-run | A first-seen repository hook or task followed by R06 within seconds of opening the repository | R06, plus a per-host first-sighting store for hook hashes that the activity engine can read (inventory novelty and activity sessions are separate today). |
| S12 Endpoint override, then credentialed traffic | R07 followed by the agent's own model traffic to the overridden host | Network telemetry for the agent's own API traffic. R07 is covered (HB-AGENT and HB-POST rules on base-URL overrides), but the agent's model requests are not tool calls and no network source is collected. |

## Gaps found by the C4 review, by feature

The review found spellings that the packs then caught from parsed
commands, but which a feature would make simpler and more complete. They
are requests to the features and shell-analysis packages, not missing
rules. Two are still open:

- Globbed paths are classified by every class a matching file could have
  (`*.json` is `cloud_credentials`, `deploy/*.yaml` is `kube_config`). The
  credential rules count a glob only when it is anchored at a home
  directory and narrow; a per-read class list (classes of each read, not
  their union) would let them count any glob precisely.
- A delete is not classed as the home directory itself (as opposed to a
  path under it): `home_root` covers both (`rm -rf ~` and
  `rm -rf ~/projects` both delete a `home_root` path). HB-DESTR-001 uses
  the literal operand and `session.cwd` instead.

Two are closed by path canonicalisation (`internal/pathcanon`; see the
"Path features" paragraph of docs/RULES.md), checked with
`features.Compute` on 2026-11-12:

- A `cd` on the same command line now applies to the relative paths after
  it: `cd ~/.aws && cat cred*` reads `~/.aws/cred*` (`cloud_credentials`),
  and `cd ~ && rm -rf *` deletes `~/*` (`home_root`). HB-DESTR-001 still
  also matches the home-directory `cd` forms on the parsed commands.
- `New-Item` and `cmd /c mkdir` are recorded in `shell.changes`, like
  `touch` and `mkdir`; they are not content writes (`shell.writes`).
  HB-EVADE-002 matches `shell.changes`.
