// Command benchrun runs hawkbell's detection benchmarks and writes their
// reports. It exists until `hawkbell bench` is wired to internal/bench; both
// call the same Runner.
//
//	go run ./internal/bench/cmd/benchrun -scenarios bench/scenarios -out bench/results
//	go run ./internal/bench/cmd/benchrun -replay /root/.claude/projects -home /root \
//	    -labels bench/replay-labels.yaml -before bench/results/benign-replay-before.json -out bench/results
//
// The committed reports were made before the project was renamed from its
// working name (spoor) to hawkbell, and are regenerated with two more flags.
// -old-name reads a corpus recorded before the rename with the old name
// rewritten as the repository was (bench.RewriteOldName); the report's
// Corpus line says so. -renamed-from names the report the appended review
// was written for, as committed before the rename: benchrun compares the
// new report with it (bench.CompareRenamed) and fails when they differ;
// when they agree, the report's header says which report the review
// describes and that every number in the tables is the same. Earlier
// reports given with -before join on their rule ids read as the current
// ones (SPR-<PACK>-<NNN> as HB-<PACK>-<NNN>). The commands:
//
//	S=<scratch directory>; for n in release-benign-replay benign-replay scenarios; do
//	  git show 253369f:spoor/bench/results/$n.json > $S/$n.before-rename.json; done
//	go run ./internal/bench/cmd/benchrun -replay <snapshot taken 10:27:00Z> -home /root -samples 5 -old-name \
//	    -alias "$S=\$S" -alias "<temp root>=\$T" -alias "<session id>=<session>" \
//	    -alias "<checkout of this repository>=\$REPO" -alias "<research checkout>=\$ADR" \
//	    -corpus-name "snapshot of /root/.claude/projects taken 2026-11-12T10:27:00Z" \
//	    -labels bench/replay-labels.yaml -prefix release- \
//	    -renamed-from $S/release-benign-replay.before-rename.json \
//	    -replay-notes bench/results/release-benign-replay-notes.md -out bench/results
//	go run ./internal/bench/cmd/benchrun -replay <snapshot taken 04:28:51Z> -home /root -samples 5 -old-name \
//	    <the same -alias flags> -corpus-name "snapshot of /root/.claude/projects taken 2026-11-12T04:28:51Z" \
//	    -labels bench/replay-labels.yaml -before bench/results/benign-replay-before.json \
//	    -renamed-from $S/benign-replay.before-rename.json \
//	    -replay-notes bench/results/benign-replay-notes.md -out bench/results
//	go run ./internal/bench/cmd/benchrun -scenarios bench/scenarios -scenario-notes bench/results/scenarios-notes.md \
//	    -renamed-from $S/scenarios.before-rename.json -out bench/results
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/thomastysong/thomastysong/hawkbell/internal/bench"
	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
	"github.com/thomastysong/thomastysong/hawkbell/internal/rules"
)

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	var roots, aliases multi
	scen := flag.String("scenarios", "", "scenario directory to run")
	flag.Var(&roots, "replay", "transcript corpus root to replay (repeatable)")
	flag.Var(&aliases, "alias", "from=to prefix replacement for rendered replay samples (repeatable)")
	home := flag.String("home", "", "home directory of the user who ran the replayed sessions")
	user := flag.String("user", "root", "OS user name stamped on replayed events")
	uid := flag.String("uid", "0", "OS user id stamped on replayed events")
	corpus := flag.String("corpus-name", "", "corpus description for the replay report")
	labels := flag.String("labels", "", "reviewed labels for replay samples")
	before := flag.String("before", "", "earlier replay JSON to compare against")
	samples := flag.Int("samples", 5, "unlabelled samples kept per rule")
	rulesDir := flag.String("rules", "", "rules directory to test instead of the embedded packs")
	out := flag.String("out", "", "directory for reports (stdout when empty)")
	prefix := flag.String("prefix", "", "file name prefix for reports written to -out")
	scenNotes := flag.String("scenario-notes", "", "Markdown file appended to the scenario report")
	replayNotes := flag.String("replay-notes", "", "Markdown file appended to the replay report")
	oldName := flag.Bool("old-name", false, "the -replay corpus was recorded before the rename from spoor to hawkbell: read it with the old name rewritten")
	renamedFrom := flag.String("renamed-from", "", "JSON report made before the rename that the appended review describes; fail unless this run's report equals it")
	flag.Parse()
	notes := map[string]string{"scenarios": *scenNotes, "replay": *replayNotes}
	ren := renameOpts{oldName: *oldName, from: *renamedFrom}
	if err := run(*scen, roots, aliases, *home, *user, *uid, *corpus, *labels, *before, *samples, *rulesDir, *out, *prefix, notes, ren); err != nil {
		fmt.Fprintln(os.Stderr, "benchrun:", err)
		os.Exit(1)
	}
}

// renameOpts are the flags for reports made before the rename.
type renameOpts struct {
	oldName bool
	from    string
}

// oldNameCorpus is added to the corpus description of a replay with
// -old-name.
const oldNameCorpus = ", recorded before the rename from the working name spoor to hawkbell and read with that name rewritten as in the repository (`benchrun -old-name`: `RewriteOldName` in `internal/bench/oldname.go`)"

// compareRenamed checks a report against -renamed-from and returns the
// run it was made equal to.
func compareRenamed(path string, js []byte) (*bench.RenamedRun, error) {
	old, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	run, diffs, err := bench.CompareRenamed(old, js)
	if err != nil {
		return nil, fmt.Errorf("-renamed-from %s: %w", path, err)
	}
	if len(diffs) > 0 {
		return nil, fmt.Errorf("-renamed-from %s: the reports differ:\n  %s", path, strings.Join(diffs, "\n  "))
	}
	return run, nil
}

func run(scen string, roots, aliases []string, home, user, uid, corpus, labels, before string, samples int, rulesDir, out, prefix string, notes map[string]string, ren renameOpts) error {
	if ren.from != "" && scen != "" && len(roots) > 0 {
		return fmt.Errorf("-renamed-from names one report: give -scenarios or -replay, not both")
	}
	if ren.oldName && len(roots) == 0 {
		return fmt.Errorf("-old-name applies to a -replay corpus")
	}
	var set *rules.Set
	if rulesDir != "" {
		s, err := rules.LoadDir(rulesDir)
		if err != nil {
			return err
		}
		set = s
	}
	r, err := bench.NewRunner(bench.Options{Rules: set})
	if err != nil {
		return err
	}
	ctx := context.Background()
	if scen != "" {
		rep, err := r.RunScenarios(ctx, scen)
		if err != nil {
			return err
		}
		js, err := rep.JSON()
		if err != nil {
			return err
		}
		if ren.from != "" {
			if rep.Renamed, err = compareRenamed(ren.from, js); err != nil {
				return err
			}
			if js, err = rep.JSON(); err != nil {
				return err
			}
		}
		md, err := withNotes(rep.Markdown(), notes["scenarios"])
		if err != nil {
			return err
		}
		if err := emit(out, prefix+"scenarios", md, js); err != nil {
			return err
		}
	}
	if len(roots) > 0 {
		o := bench.ReplayOptions{Roots: roots, Home: home, User: event.User{Name: user, ID: uid}, Samples: samples, Corpus: corpus}
		if ren.oldName {
			if o.Corpus == "" {
				o.Corpus = strings.Join(roots, ", ")
			}
			o.Corpus += oldNameCorpus
			o.Rewrite = bench.RewriteOldName
		}
		for _, a := range aliases {
			from, to, ok := strings.Cut(a, "=")
			if !ok || from == "" {
				return fmt.Errorf("-alias %q: want from=to", a)
			}
			o.Aliases = append(o.Aliases, bench.Alias{From: from, To: to})
		}
		if labels != "" {
			ls, err := bench.LoadLabels(labels)
			if err != nil {
				return err
			}
			o.Labels = ls
		}
		rep, err := r.Replay(ctx, o)
		if err != nil {
			return err
		}
		var prev *bench.ReplayReport
		if before != "" {
			b, err := os.ReadFile(before)
			if err != nil {
				return err
			}
			prev = &bench.ReplayReport{}
			if err := json.Unmarshal(b, prev); err != nil {
				return fmt.Errorf("%s: %w", before, err)
			}
		}
		js, err := rep.JSON()
		if err != nil {
			return err
		}
		if ren.from != "" {
			if rep.Renamed, err = compareRenamed(ren.from, js); err != nil {
				return err
			}
			if js, err = rep.JSON(); err != nil {
				return err
			}
		}
		md, err := withNotes(rep.Markdown(prev), notes["replay"])
		if err != nil {
			return err
		}
		if err := emit(out, prefix+"benign-replay", md, js); err != nil {
			return err
		}
	}
	if scen == "" && len(roots) == 0 {
		return fmt.Errorf("nothing to do: give -scenarios and/or -replay")
	}
	return nil
}

// withNotes appends a hand-written Markdown file (the review of the
// numbers) to a generated report, so regenerating the report keeps it.
func withNotes(md, path string) (string, error) {
	if path == "" {
		return md, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return md + "\n" + string(b), nil
}

func emit(dir, name, md string, js []byte) error {
	if dir == "" {
		fmt.Print(md)
		return nil
	}
	if err := os.WriteFile(filepath.Join(dir, name+".md"), []byte(md), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name+".json"), append(js, '\n'), 0o644)
}
