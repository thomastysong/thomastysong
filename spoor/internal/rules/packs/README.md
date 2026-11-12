# Embedded rule packs

Every `*.yaml` file here is a rule pack compiled into the spoor binary
(`rules.LoadEmbedded`). The format, the predicate language and the lint
rules are documented in the `internal/rules` package comment (`go doc
./internal/rules`).

After adding or editing a pack here, or `../lists.yaml`, regenerate the
pre-parsed copy that keeps guard-mode hook start-up fast:

    go generate ./internal/rules

`embedded.cache` is generated: do not edit it. A stale cache is never
wrong at run time (the YAML is parsed instead), only slower, and
`go test ./internal/rules` fails until it is regenerated. The same test run
checks that every pack loads, passes its inline tests and lints without
errors.

## Catalogue entries without a rule

The packs implement the detection catalogue of `research/threats.md`
sections 3 (R01 to R54) and 4 (S1 to S12); every entry is cited in some
rule's `references`, except these six. Each needs a fact the sensor does
not collect yet, so writing a rule now would mean matching command text,
which the linter forbids.

| Entry | What it detects | What is missing |
|---|---|---|
| R06 Pre-prompt execution | A child of the agent runs between session start and the first prompt, and its command is not an approved hook | An approved-hook list joined to process events: inventory records hook definitions with a hash (`asset.sha256`), but a `process.exec` event carries no hook identity or command hash to compare against, and process events are not reliably keyed to the same session as hook events (`SessionKey` needs the agent's user, agent and session ids). |
| R15 Plugin pin mismatch | An installed plugin's commit differs from the commit its marketplace pins | The marketplace's pinned commit per plugin. Discovery records the installed commit (`asset.detail.git_sha`), the marketplace name and its source, but does not read the marketplace manifest, so there is nothing to compare. |
| R20 Instruction or memory file written by a non-user process | CLAUDE.md, AGENTS.md, rules or memory files changed by an install script or unknown binary | File-integrity events with the writing process. The OS plane reports process starts only (`procmon`, `osqexec`); writes by tools are seen, writes by other processes are not. |
| R26 Remote `$schema` leak | A written JSON file whose `$schema` URL sends path or query data to a host off the allowlist | The URLs inside content being written. `write.*` features scan written content for secrets, markers, autorun keys and git exec keys, not for URLs or hosts. |
| S4 Open-and-run | A first-seen repository hook or task followed by R06 within seconds of opening the repository | R06, plus a per-host first-sighting store for hook hashes that the activity engine can read (inventory novelty and activity sessions are separate today). |
| S12 Endpoint override, then credentialed traffic | R07 followed by the agent's own model traffic to the overridden host | Network telemetry for the agent's own API traffic. R07 is covered (SPR-AGENT and SPR-POST rules on base-URL overrides), but the agent's model requests are not tool calls and no network source is collected. |

## Gaps found by the C4 review, by feature

These are spellings the packs now catch from parsed commands, but which a
feature would make simpler and more complete. They are requests to the
features and shell-analysis packages, not missing rules.

- `cd` is not applied to the paths that follow it in the same command line:
  `cd ~/.aws && cat cred*` has no read classes, and `cd ~ && rm -rf *` has
  no home delete. SPR-DESTR-001 matches the home-directory `cd` forms on
  the parsed commands; a resolved read or delete path would cover the rest.
- Globbed paths are classified by every class a matching file could have
  (`*.json` is `cloud_credentials`, `deploy/*.yaml` is `kube_config`). The
  credential rules count a glob only when it is anchored at a home
  directory and narrow; a per-read class list (classes of each read, not
  their union) would let them count any glob precisely.
- `New-Item`, `cmd /c mkdir` and similar Windows creations of a file are
  not recorded as writes. SPR-EVADE-002 matches them on the parsed command
  and its operand.
- A delete is not classed as the home directory itself (as opposed to a
  path under it): `home_root` covers both. SPR-DESTR-001 uses the literal
  operand and `session.cwd` instead.
