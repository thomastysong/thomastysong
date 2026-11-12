package discovery

import (
	"sort"
	"strings"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

const (
	flagCIUntrustedTrigger = "ci_untrusted_trigger"
	maxWorkflows           = 200
	maxWorkflowBytes       = 1 << 20
)

// untrustedTriggers are workflow events whose payload (an issue body, a
// comment, a fork's code under pull_request_target) is written by people
// outside the repository: an agent reading it can be steered by them.
var untrustedTriggers = map[string]bool{
	"pull_request_target": true,
	"issue_comment":       true,
	"issues":              true,
}

// scanWorkflows records GitHub Actions workflows in a project that run a
// catalogued agent action (anthropics/claude-code-action and the like).
func (s *scanner) scanWorkflows(uc *userCtx, dir string) {
	wdir := joinLogical(dir, ".github/workflows")
	ents, err := s.g.readDir(s.locFor(wdir, uc, dir))
	if err != nil {
		return
	}
	n := 0
	for _, e := range ents {
		low := strings.ToLower(e.name)
		if !(strings.HasSuffix(low, ".yml") || strings.HasSuffix(low, ".yaml")) {
			continue
		}
		if e.kind == kindSymlink {
			s.skipLink(joinLogical(wdir, e.name))
			continue
		}
		if e.kind != kindRegular {
			continue
		}
		n++
		if n > maxWorkflows {
			s.led.capped("workflow list truncated: " + wdir)
			return
		}
		s.scanWorkflow(joinLogical(wdir, e.name), uc, dir)
	}
}

func (s *scanner) scanWorkflow(p string, uc *userCtx, dir string) {
	l := s.locFor(p, uc, dir)
	data, _, err := s.g.readFile(l, ownerFor(l, uc), maxWorkflowBytes)
	if err != nil {
		return
	}
	doc, err := decodeDoc(data, "yaml")
	if err != nil || doc == nil {
		if err != nil {
			s.led.errored()
			s.led.note("workflow not parsed: " + p)
		}
		return
	}
	triggers := workflowTriggers(doc)
	untrusted := false
	for _, t := range triggers {
		if untrustedTriggers[t] {
			untrusted = true
		}
	}
	type use struct {
		product int
		action  string
		pinned  bool
	}
	found := map[string]use{}
	jobs, _ := asMap(mustGet(doc, "jobs"))
	for _, jn := range sortedKeys(jobs) {
		for _, st := range asList(mustGet(jobs[jn], "steps")) {
			ref := getString(st, "uses")
			if ref == "" {
				continue
			}
			action, ver, _ := strings.Cut(ref, "@")
			segs := strings.Split(action, "/")
			if len(segs) < 2 {
				continue
			}
			ownerRepo := strings.ToLower(segs[0] + "/" + segs[1])
			pr, ok := s.cat.ByPackage("gha", ownerRepo)
			if !ok {
				continue
			}
			i, ok := s.byID[pr.ID]
			if !ok {
				continue
			}
			u := found[pr.ID]
			u.product, u.action = i, ownerRepo
			u.pinned = isFullSHA(strings.ToLower(ver))
			found[pr.ID] = u
		}
	}
	if len(found) == 0 {
		return
	}
	sum := sha256Hex(data)
	for _, id := range sortedKeys(found) {
		u := found[id]
		pr := &s.products[u.product]
		a := &event.Asset{
			Kind:      event.AssetCIAgent,
			Name:      pr.Name,
			Vendor:    pr.Vendor,
			CatalogID: pr.ID,
			Path:      safeText(p, 1024),
			Scope:     event.ScopeProject,
			SHA256:    sum,
			Detail: map[string]string{
				"project":  safeText(dir, 1024),
				"action":   u.action,
				"pinned":   boolText(u.pinned),
				"triggers": strings.Join(triggers, ","),
			},
		}
		if untrusted {
			a.RiskFlags = []string{flagCIUntrustedTrigger}
		}
		if uc != nil {
			a.Owner = uc.u.Name
		}
		s.add(&record{a: a, uc: uc})
	}
}

// workflowTriggers reads "on:" in its three spellings (a string, a list, a
// map of events). Event names are reduced to a closed alphabet; they come
// from a repository file.
func workflowTriggers(doc any) []string {
	var raw []string
	on, ok := getPath(doc, "on")
	if !ok {
		on, ok = getPath(doc, "true") // YAML 1.1 readers turn a bare on: into true
	}
	if !ok {
		return nil
	}
	switch t := on.(type) {
	case string:
		raw = []string{t}
	case []any:
		for _, x := range t {
			if s, ok := x.(string); ok {
				raw = append(raw, s)
			}
		}
	case map[string]any:
		raw = sortedKeys(t)
	}
	seen := map[string]bool{}
	var out []string
	for _, r := range raw {
		r = strings.ToLower(strings.TrimSpace(r))
		if r == "" || len(r) > 40 || strings.Trim(r, "abcdefghijklmnopqrstuvwxyz_") != "" || seen[r] {
			continue
		}
		seen[r] = true
		out = append(out, r)
		if len(out) >= 32 {
			break
		}
	}
	sort.Strings(out)
	return out
}
