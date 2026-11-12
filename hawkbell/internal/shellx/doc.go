// Package shellx turns a shell command line into facts that detection rules
// match on (commands, URLs and hosts, paths read, written and deleted,
// interpreters fed code, package installs, and closed-vocabulary semantic
// categories), so detections do not depend on regexes over raw text.
//
// Analyze is the only analysis entry point. It picks the dialect (POSIX
// shell, PowerShell or cmd.exe) before parsing, parses POSIX text with
// mvdan.cc/sh and the other two with bounded tokenizers, unwraps wrappers
// (sudo, env, xargs, ssh, docker exec ...), re-analyses code handed to
// interpreters, eval strings and decoded payloads, and never panics: the
// input is attacker-controlled, so every failure degrades to a heuristic,
// truncated result (Facts.ParseOK false, Facts.Truncated true).
//
// The closed vocabularies of every categorical field (Obfuscation, Opaque,
// the semantic categories, PkgInstall.Manager, InlineCode.Lang,
// Command.Origin) are returned by Vocabulary; the rule linter (through the
// features registry) rejects a rule literal outside them.
//
// # Start-up cost
//
// Linking this package costs no package init work. Every hawkbell binary links
// it and most hawkbell processes never analyse a command line (`hawkbell hook`
// starts a supervisor and a worker per agent event; only a guard or
// detect-in-hook worker calls Analyze), while Go runs every linked
// package's init before main. So the handler registry, the lookup maps and
// the dialect regexp are built on the first Analyze, Vocabulary or dialect
// check, behind one sync.Once (tables.go), and option tables are static
// composite literals (longSet is a slice, not a map). A new table goes into
// buildTables; a package-level var whose initializer is a map literal or a
// function call would show up in GODEBUG=inittrace=1 output for every hawkbell
// process.
package shellx
