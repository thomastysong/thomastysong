//go:build spoor_bench

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/thomastysong/spoor/internal/bench"
	"github.com/thomastysong/spoor/internal/event"
)

const benchAbout = `Measures the detection content instead of asserting it.

--scenarios runs the attack and benign scenario corpus (bench/scenarios in
the source tree) with mutations and surface ablations, and reports per rule
and per technique TP/FN/FP with Wilson 95% intervals and robust recall.
--replay replays real agent session logs (Claude Code transcripts) as a
benign corpus and reports per-rule hit rates per 1,000 tool calls.
Reports are Markdown (or JSON with --json) on stdout, or files under --out.
Neither measures prevalence or a real benign fleet; the reports say so.`

func (a *app) cmdBench(args []string) int {
	fs := a.newFlags("bench", "bench [--scenarios dir] [--replay dir]... [--json] [--out dir]", benchAbout)
	scen := fs.String("scenarios", "", "scenario directory (default bench/scenarios when it exists)")
	var roots, aliases listFlag
	fs.Var(&roots, "replay", "transcript corpus root to replay as benign sessions (repeatable)")
	fs.Var(&aliases, "alias", "from=to prefix replacement in rendered replay samples (repeatable)")
	home := fs.String("home", "", "home directory of the user who ran the replayed sessions")
	user := fs.String("user", "", "OS user name stamped on replayed events (default: the caller)")
	uid := fs.String("uid", "", "OS user id stamped on replayed events (default: the caller's)")
	labels := fs.String("labels", "", "reviewed labels for replay samples (YAML)")
	before := fs.String("before", "", "earlier replay JSON report to compare against")
	samples := fs.Int("samples", 5, "unlabelled hits kept per rule for review")
	corpus := fs.String("corpus-name", "", "corpus description for the replay report")
	var dirs listFlag
	fs.Var(&dirs, "rules", "rules directory merged over the embedded packs (repeatable)")
	noEmbedded := fs.Bool("no-embedded", false, "use only the --rules directories")
	asJSON := fs.Bool("json", false, "print JSON reports instead of Markdown")
	out := fs.String("out", "", "write <name>.md and <name>.json under this directory instead of printing")
	pos, code, done := a.parse(fs, args)
	if done {
		return code
	}
	if len(pos) > 0 {
		return a.usageErr("bench", "unexpected argument %q", pos[0])
	}
	if *scen == "" && len(roots) == 0 {
		if fi, err := os.Stat(filepath.Join("bench", "scenarios")); err == nil && fi.IsDir() {
			*scen = filepath.Join("bench", "scenarios")
		} else {
			return a.usageErr("bench", "nothing to run: give --scenarios dir and/or --replay dir (the scenario corpus is in the source tree, not in the binary)")
		}
	}
	set, _, err := loadRules(nil, ruleSource{dirs: dirs, noEmbedded: *noEmbedded, noHost: true})
	if err != nil {
		return a.fail("bench", err)
	}
	r, err := bench.NewRunner(bench.Options{Rules: set})
	if err != nil {
		return a.fail("bench", err)
	}
	ctx, stop := signal.NotifyContext(a.ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *scen != "" {
		rep, err := r.RunScenarios(ctx, *scen)
		if err != nil {
			return a.fail("bench", err)
		}
		js, err := rep.JSON()
		if err != nil {
			return a.fail("bench", err)
		}
		if err := a.benchEmit(*out, "scenarios", rep.Markdown(), js, *asJSON); err != nil {
			return a.fail("bench", err)
		}
	}
	if len(roots) > 0 {
		cu := currentUser()
		o := bench.ReplayOptions{
			Roots: roots, Home: firstNonEmpty(*home, cu.Home), Samples: *samples, Corpus: *corpus,
			User: event.User{Name: firstNonEmpty(*user, cu.Name), ID: firstNonEmpty(*uid, cu.UID)},
		}
		for _, x := range aliases {
			from, to, ok := strings.Cut(x, "=")
			if !ok || from == "" {
				return a.usageErr("bench", "--alias %q: want from=to", x)
			}
			o.Aliases = append(o.Aliases, bench.Alias{From: from, To: to})
		}
		if *labels != "" {
			ls, err := bench.LoadLabels(*labels)
			if err != nil {
				return a.fail("bench", err)
			}
			o.Labels = ls
		}
		var prev *bench.ReplayReport
		if *before != "" {
			b, err := os.ReadFile(*before)
			if err != nil {
				return a.fail("bench", err)
			}
			prev = &bench.ReplayReport{}
			if err := json.Unmarshal(b, prev); err != nil {
				return a.fail("bench", fmt.Errorf("%s: %w", *before, err))
			}
		}
		rep, err := r.Replay(ctx, o)
		if err != nil {
			return a.fail("bench", err)
		}
		js, err := rep.JSON()
		if err != nil {
			return a.fail("bench", err)
		}
		if err := a.benchEmit(*out, "benign-replay", rep.Markdown(prev), js, *asJSON); err != nil {
			return a.fail("bench", err)
		}
	}
	return exitOK
}

func (a *app) benchEmit(dir, name, md string, js []byte, asJSON bool) error {
	if dir == "" {
		if asJSON {
			_, err := fmt.Fprintf(a.stdout, "%s\n", js)
			return err
		}
		_, err := fmt.Fprint(a.stdout, md)
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(dir, name+".md"), []byte(md), 0o644); err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(dir, name+".json"), append(js, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "wrote %s and %s\n", filepath.Join(dir, name+".md"), filepath.Join(dir, name+".json"))
	return nil
}
