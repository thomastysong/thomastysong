package bench

import (
	"strings"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// oracleCase is one scenario as the trivial baselines see it.
type oracleCase struct {
	kind string
	evs  []built
}

// oracles are baselines that look at nothing but tool names and event
// types. A rule set that does not clearly beat them on both recall and
// false-positive rate is measuring the corpus, not detecting anything:
// ADR-Bench's labels were reproduced by a "server never seen in a benign
// task" oracle (red-team detection-quality section 7).
var oracles = []struct {
	name, doc string
	// fit sees the whole corpus (for the leakage oracle); flag decides one
	// scenario.
	fit  func(cases []oracleCase) func(oracleCase) bool
	flag func(oracleCase) bool
}{
	{name: "any_shell", doc: "fires when the scenario runs any shell command or child process",
		flag: func(c oracleCase) bool {
			for _, b := range c.evs {
				if b.ev.Type == event.TypeProcessExec || (b.ev.Tool != nil && b.ev.Tool.Kind == event.ToolShell) {
					return true
				}
			}
			return false
		}},
	{name: "any_write", doc: "fires when the scenario writes or edits any file through a tool",
		flag: func(c oracleCase) bool {
			for _, b := range c.evs {
				if b.ev.Tool != nil && (b.ev.Tool.Kind == event.ToolFileWrite || b.ev.Tool.Kind == event.ToolFileEdit) {
					return true
				}
			}
			return false
		}},
	{name: "attack_only_names", doc: "fires on any tool, MCP server or program name that occurs in some attack and in no benign scenario (fitted on the same corpus: an optimistic leakage check)",
		fit: func(cases []oracleCase) func(oracleCase) bool {
			inAttack, inBenign := map[string]bool{}, map[string]bool{}
			for _, c := range cases {
				for _, n := range oracleNames(c) {
					if c.kind == KindAttack {
						inAttack[n] = true
					} else {
						inBenign[n] = true
					}
				}
			}
			return func(c oracleCase) bool {
				for _, n := range oracleNames(c) {
					if inAttack[n] && !inBenign[n] {
						return true
					}
				}
				return false
			}
		}},
}

// oracleNames lists the names a tool-name oracle can see: tool names, MCP
// servers, program names of process records and the first word of shell
// commands. It deliberately ignores arguments.
func oracleNames(c oracleCase) []string {
	var out []string
	for _, b := range c.evs {
		ev := b.ev
		if ev.Tool != nil {
			out = append(out, "tool:"+strings.ToLower(ev.Tool.Name))
			if ev.Tool.MCPServer != "" {
				out = append(out, "mcp:"+strings.ToLower(ev.Tool.MCPServer))
			}
			if ev.Tool.Kind == event.ToolShell && ev.Target != nil {
				if f := strings.Fields(ev.Target.Command); len(f) > 0 {
					out = append(out, "cmd:"+strings.ToLower(f[0]))
				}
			}
		}
		if ev.Process != nil && ev.Process.Name != "" {
			out = append(out, "proc:"+strings.ToLower(ev.Process.Name))
		}
		if ev.Asset != nil {
			out = append(out, "asset:"+string(ev.Asset.Kind))
		}
	}
	return out
}

func runOracles(cases []oracleCase) []OracleRow {
	var out []OracleRow
	for _, o := range oracles {
		flag := o.flag
		if o.fit != nil {
			flag = o.fit(cases)
		}
		tp, na, fp, nb := 0, 0, 0, 0
		for _, c := range cases {
			hit := flag(c)
			if c.kind == KindAttack {
				na++
				if hit {
					tp++
				}
			} else {
				nb++
				if hit {
					fp++
				}
			}
		}
		out = append(out, OracleRow{Name: o.name, Doc: o.doc, Recall: NewRate(tp, na), FPRate: NewRate(fp, nb)})
	}
	return out
}
