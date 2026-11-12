package hookinstall

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/thomastysong/spoor/internal/catalog"
	"github.com/thomastysong/spoor/internal/event"
)

// PlanInstall computes, for every requested agent, the change that
// registers `<Binary> hook --agent <id>` in the agent's hook file for
// o.Scope. It reads files but writes nothing. Agents and files that cannot
// be handled safely get Action "unsupported" with the reason in Note.
// The error is reserved for invalid options.
func PlanInstall(c *catalog.Catalog, o Options) (plans []Plan, err error) {
	return plan(c, o, modeInstall)
}

// PlanUninstall computes the change that removes every spoor registration
// (and the native telemetry settings spoor wrote) from the hook files of
// the requested agents for o.Scope. Foreign hooks and keys are left as they
// are; a file that spoor created and that holds nothing else is removed.
// Binary is not required.
func PlanUninstall(c *catalog.Catalog, o Options) (plans []Plan, err error) {
	return plan(c, o, modeUninstall)
}

func plan(c *catalog.Catalog, o Options, m mode) (plans []Plan, err error) {
	defer func() {
		if r := recover(); r != nil {
			plans, err = nil, errors.New("hookinstall: internal error while planning")
		}
	}()
	if c == nil {
		return nil, errors.New("hookinstall: no catalog")
	}
	o, err = normalize(o, m)
	if err != nil {
		return nil, err
	}
	for _, t := range resolveTargets(c, o, o.Scope) {
		plans = append(plans, planTarget(t, o, m)...)
	}
	return plans, nil
}

// planTarget returns the plan for the hook file and, where native
// telemetry is involved, one more for the telemetry part.
func planTarget(t target, o Options, m mode) []Plan {
	p := Plan{AgentID: t.agentID, Path: t.path, Scope: t.scope, root: o.Root}
	if t.unsupported != "" {
		p.Action, p.Note = ActionUnsupported, t.unsupported
		return []Plan{p}
	}
	n := &notes{}
	if len(t.also) > 0 {
		n.add("this file also serves " + strings.Join(t.also, ", "))
	}
	cur, problem := readTarget(t.path, o)
	if problem != "" {
		p.Action, p.Note = ActionUnsupported, problem
		p.Before = cur.data
		return []Plan{p}
	}
	if !filepath.IsAbs(t.path) {
		n.add("rendered for " + o.GOOS + " without reading the target machine; copy the result there")
	}
	rel := inspectRelated(t, o)
	var extra []Plan
	var action, note string
	var after []byte
	if m == modeInstall {
		want, ok := dialects[t.dialect].entries(params{
			binary: o.Binary, agentID: t.cmdAgent, goos: o.GOOS,
			timeout: o.Timeout, guard: o.Guard, failClosed: o.FailClosed,
		})
		if !ok {
			p.Action, p.Note = ActionUnsupported, "hookio lists no events for this agent"
			return []Plan{p}
		}
		if t.kind == kindTOML {
			action, after, note = installTOML(cur, want)
		} else {
			var refused *Plan
			action, after, note, refused = installJSON(t, o, cur, want, rel)
			if refused != nil {
				extra = append(extra, *refused)
			}
		}
		if action != ActionUnsupported {
			// An installation that is already in place is reported as it
			// is; only a write is refused.
			if why := coexistProblem(t, o, cur, rel, n, action == ActionUnchanged); why != "" {
				action, after, note = ActionUnsupported, nil, why
			}
		}
		if action != ActionUnsupported && t.scope != event.ScopeUser {
			p.loads = managedLoads(t, o.GOOS)
			permNotes(managedProblems(t, o), n)
		}
		if action == ActionUnchanged && t.scope != event.ScopeUser {
			// The content is right but a non-admin could change it: an
			// install must leave managed files admin-only, so the same
			// bytes are written again, which repairs owner and mode.
			if why := insecureManaged(t, o); why != "" {
				action, after = ActionMerge, cur.data
				n.add("rewritten to repair permissions: " + why)
			}
		}
		if action != ActionUnsupported {
			installNotes(t, o, rel, n)
			if t.dialect == "codex" {
				if op := planCodexOTel(t, o, m, rel); op != nil {
					extra = append(extra, *op)
				}
			}
		}
	} else {
		if t.kind == kindTOML {
			action, after, note = uninstallTOML(cur)
		} else {
			action, after, note = uninstallJSON(t, o, cur)
		}
		if t.dialect == "codex" {
			if op := planCodexOTel(t, o, m, rel); op != nil {
				extra = append(extra, *op)
			}
		}
	}
	p.Action, p.Before = action, cur.data
	switch action {
	case ActionUnchanged:
		p.After = cur.data
	case ActionUnsupported, ActionRemove:
	default:
		p.After = after
	}
	if note != "" {
		n.first(note)
	}
	p.Note = n.String()
	return append([]Plan{p}, extra...)
}

// readTarget reads the hook file the way Apply will reach it, so a plan
// shows a refusal before anything is attempted. A path that is not
// absolute on this host belongs to another OS (a plan rendered for
// Windows on Linux without a Root): it is treated as absent.
func readTarget(path string, o Options) (fileState, string) {
	if !filepath.IsAbs(path) {
		return fileState{}, ""
	}
	if why := checkChain(filepath.Dir(path), o.Root); why != "" {
		return fileState{}, why
	}
	cur := readFile(path, o.Root)
	if cur.exists && cur.refused == "" && o.Scope == event.ScopeUser && os.Geteuid() == 0 {
		if why := rootEditProblem(cur.info, cur.dir); why != "" {
			// Not the user's file to have edited: its bytes are not
			// carried in the plan either.
			return fileState{exists: true}, why
		}
	}
	switch {
	case cur.refused == refusedSymlink:
		return cur, "the hook file is a symbolic link; spoor does not write through links (edit the file it points to, or replace the link with a regular file)"
	case cur.refused != "":
		return cur, "the hook file " + cur.refused
	}
	return cur, ""
}
