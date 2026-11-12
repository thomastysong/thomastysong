# Contributing to spoor

Thank you for helping. Bug reports, detection rules, false-positive reports, agent support and documentation fixes are all welcome. For security problems, follow [SECURITY.md](SECURITY.md) instead of opening an issue.

## Licence and sign-off

spoor is licensed under the Apache License 2.0 ([LICENSE](LICENSE)); contributions are accepted under the same licence (section 5 of the licence). There is **no contributor licence agreement**. A [Developer Certificate of Origin](https://developercertificate.org/) sign-off (`git commit -s`) is welcome but optional. Third-party code or data you bring in must be compatible with Apache-2.0 and credited in [NOTICE](NOTICE).

## Building

Go as named in `go.mod` (the `go` command downloads that toolchain when yours is older). Everything is pure Go: `CGO_ENABLED=0` always, no C toolchain.

```
CGO_ENABLED=0 go build -o spoor ./cmd/spoor     # or: make build  (writes dist/spoor)
./spoor version
```

`make build` stamps the version from the latest `v*` tag (`0.0.0-dev` without one) and builds reproducibly (`-trimpath`, no VCS stamp, empty build id). `make help` lists every target:

```
  help              list the targets
  build             build dist/spoor for this machine
  test              unit tests (no network, no docker)
  vet               go vet on every package
  fmt-check         fail when a Go file is not gofmt-formatted
  lint              gofmt, go vet, staticcheck when installed, rule lint and tests
  licenses-check    fail when THIRD_PARTY_LICENSES no longer matches the linked modules
  rules             spoor rules lint (errors fail) and every rule's inline tests
  bench             scenario benchmark gate and report (bench/results is committed)
  e2e               end-to-end tests that need only the local machine (CLI, extension)
  e2e-container     container, package, Fluent Bit and Fleet-script tests (docker, local images, nfpm)
  cross             build every release platform into dist/<os>_<arch>/
  package           deb and rpm for PKG_ARCHS with nfpm (packaging/linux/nfpm.yaml stages dist/package/spoor)
  image             node sensor image from the Dockerfile (file capabilities applied in the build stage)
  image-binary      the bare binary through the Dockerfile's `binary` target, into dist/image/
  release-snapshot  goreleaser dry run: archives, packages, checksums (no signing, no publishing)
  clean             remove dist/
```

The binary must build for linux, darwin and windows on amd64 and arm64. `make cross` builds all six:

```
$ make cross
linux/amd64
linux/arm64
darwin/amd64
darwin/arm64
windows/amd64
windows/arm64
```

Windows and macOS builds are cross-compiled and the unit tests run on Linux; behaviour on Windows and macOS hardware is not verified ([docs/LIMITATIONS.md](docs/LIMITATIONS.md)). Do not write platform claims you have not tested.

## Tests

```
go vet ./...
go test ./...          # or: make test
make fmt-check         # gofmt
make lint              # fmt-check, vet, staticcheck when installed, then `make rules`
```

Unit tests must not use the network or Docker, must write nothing outside `t.TempDir()`, and skip (rather than fail) what needs root. They are table-driven and include hostile input (huge, deeply nested, invalid UTF-8, path traversal, symbolic links, FIFOs where relevant): every input spoor reads (hook stdin, transcripts, configuration, command lines, rule packs) is attacker-controlled somewhere. A new parser or reader comes with tests of that kind.

Some files are generated, and their tests fail until they are regenerated:

| Change | Regenerate | Checked by |
|---|---|---|
| `internal/event` (the record types), the profile names in `internal/privacy/policy.go`, or the fields the skeleton writers set (`skeleton` in `internal/sink/shrink.go`, `skeleton` and `buildSkeleton` in `internal/privacy/emit.go`) | `go test ./internal/event -run TestSchema -update` (writes `docs/schema/event.schema.json` and the field reference in `docs/EVENTS.md`); a new field without a doc comment also needs a note in `fieldNotes` (`internal/event/schema_test.go`), and a new profile an entry in `neverWritten` there | `go test ./internal/event`, which also validates `docs/schema/examples/*.ndjson` |
| record shapes the binary writes | `sudo env "PATH=$PATH" docs/schema/examples/regen.sh`, then update the examples quoted in `docs/EVENTS.md` | same |
| `internal/rules/packs/*.yaml`, `internal/rules/lists.yaml` | `go generate ./internal/rules` (writes `packs/embedded.cache`) | `go test ./internal/rules` |
| the shipped packs | the catalogue in `docs/RULES.md` (jq program shown there) | review |
| `go.mod` (a dependency added, removed or bumped) | `go run ./tools/licensegen -repo . -out THIRD_PARTY_LICENSES`; it stops on a license text it has not seen, so read the new text and extend its reviewed table, and `moduleLicenses` in `cmd/spoor/version.go` | `make licenses-check` (CI) and `go test ./cmd/spoor` |

## Detection rules

Rules are the most useful contribution and the easiest to get wrong. The language, the workflow and the precision rules for the shipped packs are in [docs/RULES.md](docs/RULES.md). In short:

1. Write the rule in the relevant pack under `internal/rules/packs/` (or try it first in a directory of your own with `--dir`), with framework tags, references, false positives, a remedy, at least one positive and two negative inline tests built from benign look-alikes.
2. `go generate ./internal/rules`, then `make rules` (lint errors fail; every inline test must pass):

   ```
   $ make rules
   ...
   138 rules: 0 error(s), 53 warning(s)
   dist/spoor rules test
   579 tests over 138 rules, 0 failed
   ```

3. Measure it, do not assert it. Add attack scenarios and benign look-alikes under `bench/scenarios/` and run the scenario benchmark (`make bench`, or `go run ./internal/bench/cmd/benchrun -scenarios bench/scenarios -out <dir>`); if you can, replay real agent sessions you are allowed to use (the command is at the end of `bench/results/benign-replay.md`). Report false positives with the rule id and a synthetic reproduction.
4. Shell rules match parsed facts (`shell.*`, `any_command`), never command text: lint rejects text matching on `target.command`. If the fact you need does not exist, the fix belongs in `internal/shellx` or `internal/features`.

## Credential literals

Never commit a credential in a provider's real format, not even a fake one: test fixtures that matched provider formats have been rejected by push protection, and a scanner cannot tell a fixture from a leak. This covers AWS access key ids (`AKIA`/`ASIA` followed by 16 characters) and 40-character secret access keys, GitHub tokens (`ghp_`, `gho_`, `github_pat_` at full length), Anthropic, OpenAI and Slack token formats, PEM private key blocks, and JWTs with real-looking signatures.

- In Go tests, build such values at run time from a prefix and seeded random characters, as `internal/discovery/fixture_test.go` (`"AKIA" + randString(...)`) and `internal/privacy/canary_test.go` do.
- In YAML, Markdown and fixtures, use a generic high-entropy secret in a `password=`, `token=` or `Bearer` context, which the classifiers still detect, or a visibly broken form.
- Check before you push:

  ```
  grep -rnE 'AKIA[0-9A-Z]{16}|aws_secret_access_key *[=:] *[A-Za-z0-9/+]{40}|sk-ant-api0[3]-|ghp_[A-Za-z0-9]{36}|-----BEGIN [A-Z ]*PRIVATE KEY' <changed paths>
  ```

  It must print nothing.

The same goes for real data: no real prompts, transcripts, hostnames or user names in fixtures or bug reports.

## End-to-end tests

The end-to-end suites live in `test/e2e`, behind the `e2e` build tag, and run real processes. Each gated suite skips (with the reason) unless its environment variable is set and what it needs is present. All of them run on Linux and write nothing outside `t.TempDir()`, Docker and the Go caches.

| Suite | Command | Needs |
|---|---|---|
| CLI: build the binary, install user hooks into a fake home, pipe real-shaped hook payloads through the installed command, run the daemon, check outbox, local ring, state database and `spoor doctor --json`; `ci exec`; osquery extension dispatch | `make e2e` (`go test -tags e2e ./test/e2e -run CLI -count=1 -v`) | Linux. As root the daemon sees the whole machine read-only. |
| Fluent Bit: tags and event time per stream, the kill test (output down, restart, 5,000 of 5,000 delivered), head-of-line blocking, rejected chunks kept, an oversized record | `SPOOR_E2E_FLUENTBIT=1 go test -tags e2e ./test/e2e -run FluentBit -v` | Docker and the `fluent/fluent-bit:latest` image present locally (the tests never pull). |
| Containers and packages: the Kubernetes node sensor in Docker (`--pid=host`, two capabilities, planted symlinks refused), in-image hook mode, deb and rpm install, upgrade, remove and purge | `SPOOR_E2E_CONTAINER=1 go test -tags e2e ./test/e2e -run 'Container\|Package' -v` | Docker with `mirror.gcr.io/library/redis:7` (and `mirror.gcr.io/library/rockylinux:9` for rpm) present locally, the Dockerfile's base images; nfpm (`SPOOR_NFPM` or on `PATH`) for the package tests, which skip without it; root for the ptrace probe. |
| Fleet harness: generated Fleet content, state databases written through the daemon's writer, the Fleet install scripts in a container | `SPOOR_E2E_FLEET=1 go test -tags e2e ./test/e2e -run Fleet -v` | Docker with `mirror.gcr.io/library/redis:7` for the install scripts. |
| Fleet, live: applies the content to a running Fleet server, runs every `spoor_*` table and policy as a live query on an enrolled osquery host, restores the server's agent options | `deploy/fleet/verify.sh` (read its header first; the output of a run is `deploy/fleet/VERIFIED.md`) <!-- VERIFY: not re-run while this page was written, because it changes a shared Fleet server while it runs --> | A Fleet server you may change temporarily, `fleetctl` logged in, one enrolled osquery host. It never runs `fleetctl gitops` for real and deletes what it applied. |
| Real agent: a real Claude Code process (`claude -p`) against a local stand-in for the model API, with the hooks `spoor hooks install` registered, the daemon, Fluent Bit when available, then guard mode | `SPOOR_E2E_AGENT=1 go test -tags e2e ./test/e2e -run RealAgent -v` | Linux, root (private mount and PID namespaces), `unshare`, `nsenter`, overlayfs, Claude Code and node (`SPOOR_E2E_CLAUDE`, `SPOOR_E2E_NODE`, `PATH` or `/opt/node22/bin`) not installed under `/root` or `/home`. No model API key: the model is a local stand-in. |

`make e2e-container` runs the container, package, Fluent Bit and Fleet-script suites together. Results of these suites on real software are committed as `deploy/fluent-bit/VERIFIED.md`, `deploy/fleet/VERIFIED.md`, `deploy/kubernetes/VERIFIED.md` and `test/e2e/REAL-AGENT.md`; regenerate the one your change affects.

## Code and documentation conventions

- Pure Go, `CGO_ENABLED=0`, building for all six release platforms. Adding a module dependency needs a discussion first: the allowed set is pinned in `go.mod` and kept small on purpose (the hook is a process per tool call, and every linked package's initialisation costs every invocation).
- Treat every input as hostile: bound sizes, depth and time; never follow symbolic links out of the tree being read; open with no-follow and non-blocking flags and check the type and owner on the descriptor; never execute a discovered binary or start an MCP server; never build a file name from an untrusted id without hashing it; never panic across a package boundary.
- Never emit secret values. Names of variables and headers are fine. A digest of content is keyed (HMAC with the tenant key) or not written at all.
- The hook must never break the agent: no stderr output, exit 0, bounded time (see `go doc ./internal/hookcmd`).
- Comments explain why (the constraint), not what. No stubs for behaviour a feature promises: return an explicit "unsupported" result and document it.
- Documentation states what the code does. Run a command before you document it and paste its real output; give measured numbers with their conditions; cite the source for any claim about another project; mark anything you could not verify. Records and examples in the docs come from the binary, never from an editor.
