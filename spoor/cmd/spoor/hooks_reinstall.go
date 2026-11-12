package main

import (
	"bytes"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/thomastysong/spoor/internal/catalog"
	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/hookinstall"
)

// `hooks install --only-installed` rewrites spoor's hook entries only where
// a file at the scope already holds them. A release changes what install
// writes (the missing-binary guard, for one), and entries an earlier
// release wrote report "modified" until install runs again, so package
// upgrades and the Fleet install scripts run it. Agents that were never
// hooked are left alone: hooking them is the administrator's decision.
//
// A plain re-install would write install's default options and so turn an
// administrator's `--guard --fail-closed` registration into a fail-open
// one, or reset a --timeout. The options are therefore read back from the
// entries: every (fail-closed, timeout) pair that could have produced them
// is tried, and a pair counts only when install with it writes exactly the
// file as it is, or when `hooks status` with it recognises the file as an
// earlier release's output. Entries no option set reproduces were edited
// by hand (or by something else) and are reported, never overwritten.

// legacyEntriesMarker starts the hooks status detail of entries that are
// exactly what an earlier release wrote (internal/hookinstall legacyPrefix;
// a test keeps the two equal).
const legacyEntriesMarker = "written by an earlier spoor release"

// Reinstall outcomes, per hook file.
const (
	reinstallRewritten   = "rewritten"   // the entries were (or, with --dry-run, would be) rewritten
	reinstallCurrent     = "current"     // already what install writes: nothing to do
	reinstallLeft        = "left"        // spoor entries no install option reproduces: not touched
	reinstallUnsupported = "unsupported" // install cannot write the file; Detail says why
)

// reinstallJSON is one hook file that holds spoor entries, and what
// --only-installed did with it.
type reinstallJSON struct {
	Agent   string      `json:"agent"`
	Scope   event.Scope `json:"scope"`
	Path    string      `json:"path"`
	Outcome string      `json:"outcome"`
	// Options are the install flags the entries carry (current, left out
	// for default ones) or were rewritten with.
	Options string `json:"options,omitempty"`
	// Earlier is true when an earlier release wrote the entries.
	Earlier bool   `json:"earlier_release,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

// hookOpts are the install options that shape a hook file's entries.
// --guard alone changes nothing in a file (guard mode is a setting of the
// configuration the hook reads), so fail-closed carries it.
type hookOpts struct {
	failClosed bool
	timeout    int
}

// flags renders the options as the install flags that write them.
func (h hookOpts) flags() string {
	var f []string
	if h.failClosed {
		f = append(f, "--guard", "--fail-closed")
	}
	if h.timeout != 0 && h.timeout != defaultHookTimeout {
		f = append(f, "--timeout", strconv.Itoa(h.timeout))
	}
	return strings.Join(f, " ")
}

// defaultHookTimeout is install's --timeout default (internal/hookinstall).
const defaultHookTimeout = 10

// explicitOpts are the option flags given on the command line; they win
// over what the entries carry.
type explicitOpts struct {
	guard, failClosed, timeout bool
}

// reinstallPlan is the work --only-installed found for one hook file.
type reinstallPlan struct {
	row   reinstallJSON
	plans []hookinstall.Plan
}

// planReinstall selects the hook files at o.Scope that hold spoor entries,
// recovers each one's options and plans the rewrite with o.Binary.
func planReinstall(cat *catalog.Catalog, o hookinstall.Options, ex explicitOpts) ([]reinstallPlan, error) {
	so := hookinstall.Options{Scope: o.Scope, Agents: o.Agents, Root: o.Root, Home: o.Home, Env: o.Env, GOOS: o.GOOS}
	states, err := hookinstall.Status(cat, so)
	if err != nil {
		return nil, err
	}
	var out []reinstallPlan
	seen := map[string]bool{}
	for _, st := range states {
		// Hash is set exactly when the file holds spoor entries.
		if st.Hash == "" || seen[st.Path] {
			continue
		}
		seen[st.Path] = true
		out = append(out, planOneReinstall(cat, o, ex, st))
	}
	return out, nil
}

func planOneReinstall(cat *catalog.Catalog, o hookinstall.Options, ex explicitOpts, st hookinstall.State) reinstallPlan {
	rp := reinstallPlan{row: reinstallJSON{Agent: st.AgentID, Scope: st.Scope, Path: st.Path}}
	got, earlier, oldBin, why := recoverHookOptions(cat, o, st)
	if why != "" {
		rp.row.Outcome, rp.row.Detail = reinstallLeft, why
		return rp
	}
	if ex.failClosed || ex.guard && !o.Guard {
		// --fail-closed=false (or --guard=false) asks for a fail-open
		// registration whatever the entries carry.
		got.failClosed = o.FailClosed
	}
	if ex.timeout {
		got.timeout = o.Timeout
	}
	po := o
	po.Agents = []string{st.AgentID}
	po.FailClosed, po.Timeout = got.failClosed, got.timeout
	po.Guard = o.Guard || got.failClosed
	// The entries are already there, next to whatever other sensor shares
	// the file: rewriting them adds no second handler.
	po.Coexist = true
	plans, err := hookinstall.PlanInstall(cat, po)
	rp.row.Options, rp.row.Earlier = got.flags(), earlier
	main := planFor(plans, st.Path)
	switch {
	case err != nil:
		rp.row.Outcome, rp.row.Detail = reinstallUnsupported, err.Error()
	case main == nil:
		rp.row.Outcome, rp.row.Detail = reinstallUnsupported, "install planned nothing for this file"
	case main.Action == hookinstall.ActionUnsupported:
		rp.row.Outcome, rp.row.Detail = reinstallUnsupported, firstLine(main.Note)
	case main.Action == hookinstall.ActionUnchanged && !changes(plans):
		rp.row.Outcome = reinstallCurrent
	default:
		rp.row.Outcome = reinstallRewritten
		switch {
		case oldBin != o.Binary:
			rp.row.Detail = "the hooks now run " + o.Binary + " instead of " + oldBin
		case bytes.Equal(main.Before, main.After):
			rp.row.Detail = noteLine(main.Note, "permissions")
		}
		rp.plans = plans
	}
	return rp
}

// recoverHookOptions finds the options st's entries were installed with,
// whether an earlier release wrote them, and the binary they run. It
// returns why not when no option set reproduces them.
func recoverHookOptions(cat *catalog.Catalog, o hookinstall.Options, st hookinstall.State) (opts hookOpts, earlier bool, bin, why string) {
	bins, err := installedBinaries(st.Path)
	switch {
	case err != nil:
		return hookOpts{}, false, "", "the hook file cannot be read: " + err.Error()
	case len(bins) != 1:
		return hookOpts{}, false, "", fmt.Sprintf("the spoor entries name %d binaries; install writes one", len(bins))
	}
	timeouts := []int{defaultHookTimeout}
	if o.Timeout > 0 {
		timeouts = append(timeouts, o.Timeout)
	}
	timeouts = append(timeouts, installedTimeouts(st.Path)...)
	timeouts = uniqueInts(timeouts)
	unsupported := ""
	for _, fc := range []bool{false, true} {
		for _, t := range timeouts {
			try := hookinstall.Options{
				Scope: o.Scope, Agents: []string{st.AgentID}, Root: o.Root, Home: o.Home, Env: o.Env, GOOS: o.GOOS,
				Binary: bins[0], Guard: fc, FailClosed: fc, Timeout: t, Coexist: true, Force: o.Force,
			}
			plans, err := hookinstall.PlanInstall(cat, try)
			if err != nil {
				// The binary in the file is not one install would accept
				// (relative, another OS's path, a dollar sign).
				return hookOpts{}, false, "", "the spoor entries name a binary install does not accept: " + err.Error()
			}
			if p := planFor(plans, st.Path); p != nil {
				switch {
				case p.Action == hookinstall.ActionUnsupported:
					unsupported = firstLine(p.Note)
				case p.Action == hookinstall.ActionUnchanged || bytes.Equal(p.Before, p.After):
					// Exactly what install writes with these options (a
					// permission repair rewrites the same bytes).
					return hookOpts{failClosed: fc, timeout: t}, false, bins[0], ""
				}
			}
			try.Binary = ""
			if states, err := hookinstall.Status(cat, try); err == nil {
				for _, s := range states {
					if s.Path == st.Path && strings.Contains(s.Detail, legacyEntriesMarker) {
						return hookOpts{failClosed: fc, timeout: t}, true, bins[0], ""
					}
				}
			}
		}
	}
	if unsupported != "" {
		return hookOpts{}, false, "", "install cannot write this file: " + unsupported
	}
	return hookOpts{}, false, "", "the spoor entries differ from what install writes with any options (edited by hand?)"
}

// changes reports whether any plan writes something.
func changes(plans []hookinstall.Plan) bool {
	for _, p := range plans {
		if p.Action != hookinstall.ActionUnchanged && p.Action != hookinstall.ActionUnsupported {
			return true
		}
	}
	return false
}

func planFor(plans []hookinstall.Plan, path string) *hookinstall.Plan {
	for i := range plans {
		if plans[i].Path == path {
			return &plans[i]
		}
	}
	return nil
}

func uniqueInts(v []int) []int {
	seen := map[int]bool{}
	out := v[:0:0]
	for _, x := range v {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

// noteLine returns the first line of a plan note that mentions word, or
// the note's first line.
func noteLine(note, word string) string {
	for _, l := range strings.Split(note, "\n") {
		if strings.Contains(l, word) {
			return strings.TrimSpace(l)
		}
	}
	return firstLine(note)
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

// printReinstall reports --only-installed in one line per hook file, in the
// words the package scripts pass on ("managed hooks rewritten for X").
func (a *app) printReinstall(res planResult, scope event.Scope, dry bool) {
	rows := append([]reinstallJSON(nil), res.Reinstall...)
	sort.SliceStable(rows, func(i, j int) bool { return outcomeRank(rows[i].Outcome) < outcomeRank(rows[j].Outcome) })
	if len(rows) == 0 {
		fmt.Fprintf(a.stdout, "no agent has spoor hooks in the %s scope: nothing to do\n", term(string(scope)))
		return
	}
	for _, r := range rows {
		agent, sc := term(r.Agent), term(string(r.Scope))
		opts := ""
		if r.Options != "" {
			opts = " " + term(r.Options)
		}
		switch r.Outcome {
		case reinstallRewritten:
			why := ""
			if r.Detail != "" {
				why = " (" + clip(r.Detail, 160) + ")"
			}
			with := ""
			if opts != "" {
				with = " with" + opts
			}
			if dry {
				fmt.Fprintf(a.stdout, "%s hooks of %s would be rewritten%s%s\n", sc, agent, with, why)
			} else {
				fmt.Fprintf(a.stdout, "%s hooks rewritten for %s%s%s\n", sc, agent, with, why)
			}
		case reinstallCurrent:
			carry := ""
			if opts != "" {
				carry = " (" + strings.TrimSpace(opts) + ")"
			}
			fmt.Fprintf(a.stdout, "%s hooks of %s left as they are: already what install writes%s\n", sc, agent, carry)
		case reinstallLeft:
			fmt.Fprintf(a.stdout, "%s hooks of %s left as they are: %s; `spoor hooks install --scope %s --agents %s` with the options you want replaces them (%s)\n",
				sc, agent, clip(r.Detail, 200), sc, agent, sanitize(r.Path))
		default:
			fmt.Fprintf(a.stdout, "%s hooks of %s not rewritten: %s (%s)\n", sc, agent, clip(r.Detail, 200), sanitize(r.Path))
		}
	}
	if dry {
		fmt.Fprintln(a.stdout, "dry run: nothing was written")
	}
}

func outcomeRank(o string) int {
	switch o {
	case reinstallRewritten:
		return 0
	case reinstallCurrent:
		return 1
	case reinstallLeft:
		return 2
	}
	return 3
}
