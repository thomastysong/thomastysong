// Command benchrun runs spoor's detection benchmarks and writes their
// reports. It exists until `spoor bench` is wired to internal/bench; both
// call the same Runner.
//
//	go run ./internal/bench/cmd/benchrun -scenarios bench/scenarios -out bench/results
//	go run ./internal/bench/cmd/benchrun -replay /root/.claude/projects -home /root \
//	    -labels bench/replay-labels.yaml -before bench/results/benign-replay-before.json -out bench/results
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/thomastysong/spoor/internal/bench"
	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/rules"
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
	flag.Parse()
	notes := map[string]string{"scenarios": *scenNotes, "replay": *replayNotes}
	if err := run(*scen, roots, aliases, *home, *user, *uid, *corpus, *labels, *before, *samples, *rulesDir, *out, *prefix, notes); err != nil {
		fmt.Fprintln(os.Stderr, "benchrun:", err)
		os.Exit(1)
	}
}

func run(scen string, roots, aliases []string, home, user, uid, corpus, labels, before string, samples int, rulesDir, out, prefix string, notes map[string]string) error {
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
