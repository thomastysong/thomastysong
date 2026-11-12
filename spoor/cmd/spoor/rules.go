package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/thomastysong/spoor/internal/rules"
)

func (a *app) cmdRules(args []string) int {
	return a.dispatch("rules", []subcommand{
		{"list", "list the rules this host runs (embedded, bundle, rules.dirs, --dir)", a.rulesList},
		{"test", "run every rule's inline tests", a.rulesTest},
		{"lint", "check rules for problems the loader accepts but review must not", a.rulesLint},
	}, args)
}

type rulesFlags struct {
	cf         cfgFlags
	dirs       listFlag
	noEmbedded bool
	noHost     bool
	asJSON     bool
}

func (r *rulesFlags) register(fs *flag.FlagSet) {
	r.cf.register(fs)
	fs.Var(&r.dirs, "dir", "rules directory merged over the other sources (repeatable)")
	fs.BoolVar(&r.noEmbedded, "no-embedded", false, "use only the --dir directories")
	fs.BoolVar(&r.noHost, "no-host-rules", false, "ignore the installed bundle and configured rules.dirs")
	fs.BoolVar(&r.asJSON, "json", false, "print JSON")
}

func (a *app) rulesLoad(name string, args []string, about string, extra func(*flag.FlagSet)) (*rules.Set, ruleInfo, *rulesFlags, int, bool) {
	fs := a.newFlags(name, name+" [--dir dir] [--no-embedded] [--json]", about)
	var r rulesFlags
	r.register(fs)
	if extra != nil {
		extra(fs)
	}
	pos, code, done := a.parse(fs, args)
	if done {
		return nil, ruleInfo{}, nil, code, true
	}
	if len(pos) > 0 {
		return nil, ruleInfo{}, nil, a.usageErr(name, "unexpected argument %q (use --dir)", pos[0]), true
	}
	if r.noEmbedded {
		r.noHost = true
	}
	cfg, _, err := loadConfig(r.cf)
	if err != nil {
		return nil, ruleInfo{}, nil, a.fail(name, err), true
	}
	set, info, err := loadRules(cfg, ruleSource{dirs: r.dirs, noEmbedded: r.noEmbedded, noHost: r.noHost})
	if err != nil {
		return nil, ruleInfo{}, nil, a.fail(name, err), true
	}
	return set, info, &r, 0, false
}

func (a *app) rulesList(args []string) int {
	set, info, r, code, done := a.rulesLoad("rules list", args, "Lists every rule with its class, severity, guard response and pack.", nil)
	if done {
		return code
	}
	list := set.Rules()
	if r.asJSON {
		return a.printJSON(map[string]any{"source": info, "rules": list})
	}
	tw := a.table()
	fmt.Fprintln(tw, "ID\tCLASS\tSEVERITY\tRESPONSE\tPACK\tON\tTITLE")
	for _, x := range list {
		on := "yes"
		if !x.Enabled {
			on = "no"
		}
		resp := x.Response
		if resp == "" {
			resp = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", x.ID, x.Class, x.Severity, resp, x.Pack, on, clip(x.Title, 70))
	}
	tw.Flush()
	fmt.Fprintf(a.stdout, "%d rules (%d enabled), content %s, hash %s\n", len(list), info.Count, clip(info.Version, 120), shortHash(info.Hash))
	return exitOK
}

func (a *app) rulesTest(args []string) int {
	set, info, r, code, done := a.rulesLoad("rules test", args, "Runs every inline rule test against one engine built from the whole set. Exits 4 when a test fails.", nil)
	if done {
		return code
	}
	results := set.RunTests()
	failed := 0
	for _, t := range results {
		if !t.OK {
			failed++
		}
	}
	if r.asJSON {
		if c := a.printJSON(map[string]any{"source": info, "tests": len(results), "failed": failed, "results": results}); c != exitOK {
			return c
		}
	} else {
		for _, t := range results {
			if !t.OK {
				fmt.Fprintf(a.stdout, "FAIL %s %s: got %s, want %s: %s\n", t.RuleID, t.Name, t.Got, t.Want, t.Detail)
			}
		}
		fmt.Fprintf(a.stdout, "%d tests over %d rules, %d failed\n", len(results), info.Count, failed)
	}
	if failed > 0 {
		return exitCheck
	}
	return exitOK
}

func (a *app) rulesLint(args []string) int {
	var strict *bool
	set, info, r, code, done := a.rulesLoad("rules lint", args, `Lints the rules: unknown fields, text matching on target.command, alert rules
without two negative tests, block responses in embedded packs and more.
Exits 4 on any error (and with --strict on any warning).`, func(fs *flag.FlagSet) {
		strict = fs.Bool("strict", false, "fail on warnings too")
	})
	if done {
		return code
	}
	issues := rules.Lint(set)
	errs, warns := 0, 0
	for _, i := range issues {
		if i.Level == rules.LevelError {
			errs++
		} else {
			warns++
		}
	}
	if r.asJSON {
		if c := a.printJSON(map[string]any{"source": info, "errors": errs, "warnings": warns, "issues": issues}); c != exitOK {
			return c
		}
	} else {
		for _, i := range issues {
			fmt.Fprintln(a.stdout, i.String())
		}
		fmt.Fprintf(a.stdout, "%d rules: %d error(s), %d warning(s)\n", info.Count, errs, warns)
	}
	if errs > 0 || (*strict && warns > 0) {
		return exitCheck
	}
	return exitOK
}

func shortHash(h string) string {
	h = strings.TrimPrefix(h, "sha256:")
	if len(h) > 12 {
		return h[:12]
	}
	return h
}
