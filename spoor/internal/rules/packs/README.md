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
