package hookinstall

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/thomastysong/spoor/internal/event"
)

// A managed hook file is a command that runs in every developer's session.
// If a non-admin can rewrite the file, replace it, or replace one of the
// directories above it, the "managed" tier is just a slower user tier
// (the CVE-2026-35603 class). So the file and the directories that lead to
// it from a system anchor must be admin-owned and not writable by anyone
// else.

// anchors are the system directories under which agents keep machine-wide
// configuration. They are trusted as they are (ProgramData lets every user
// create sub-directories by design, which is exactly why what is below it
// needs checking).
var anchors = [][]string{
	{"etc"},
	{"Library", "Application Support"},
	{"ProgramData"},
	{"Program Files"},
	{"Program Files (x86)"},
}

// managedChain returns the directories between the system anchor and the
// file, nearest first. With no anchor in the path only the parent directory
// is returned. The match is on path components, so it also works for a tree
// rendered under a Root.
func managedChain(path string) []string {
	dir := filepath.Dir(path)
	parts := strings.Split(filepath.ToSlash(dir), "/")
	anchorEnd := -1
	for i := range parts {
		for _, a := range anchors {
			if i+len(a) > len(parts) {
				continue
			}
			match := true
			for j, name := range a {
				if !strings.EqualFold(parts[i+j], name) {
					match = false
					break
				}
			}
			if match && i+len(a) > anchorEnd {
				anchorEnd = i + len(a)
			}
		}
	}
	if anchorEnd < 0 || anchorEnd >= len(parts) {
		return []string{dir}
	}
	var out []string
	cur := dir
	for n := len(parts); n > anchorEnd; n-- {
		out = append(out, cur)
		cur = filepath.Dir(cur)
	}
	return out
}

// loadSet names the files an agent loads from one directory of a managed
// hook file: the directory itself (up 0) or its parent (up 1). Whoever can
// write one of them can make the agent run a command for every user, so
// they get the same ownership rules as the hook file.
type loadSet struct {
	up    int
	names []string // exact names
	json  bool     // every *.json
	fold  bool     // names compare case-insensitively (macOS, Windows)
}

func (l loadSet) match(name string) bool {
	eq := func(a, b string) bool { return a == b }
	if l.fold {
		eq = strings.EqualFold
	}
	if l.json && len(name) > 5 && eq(name[len(name)-5:], ".json") {
		return true
	}
	for _, n := range l.names {
		if eq(name, n) {
			return true
		}
	}
	return false
}

// managedLoads lists what the agent loads beside a managed hook file.
// Sources: Claude Code managed-settings.md ("managed-settings.json, an
// optional managed-settings.d/ directory, and managed-mcp.json in the
// system directory", and CLAUDE.md managed memory); Codex config layers
// (config.toml, requirements.toml, the legacy managed_config.toml and
// hooks.json beside the system config); Copilot CLI policy.d/*.json;
// Gemini CLI settings.json and system-defaults.json; Cursor hooks.json.
func managedLoads(t target, goos string) []loadSet {
	if t.scope == event.ScopeUser {
		return nil
	}
	fold := goos == "windows" || goos == "darwin"
	claudeTop := []string{"managed-settings.json", "managed-mcp.json", "CLAUDE.md"}
	switch t.dialect {
	case "claude":
		if t.owned {
			return []loadSet{{up: 0, json: true, fold: fold}, {up: 1, names: claudeTop, fold: fold}}
		}
		return []loadSet{{up: 0, names: claudeTop, fold: fold}}
	case "codex":
		return []loadSet{{up: 0, names: []string{"hooks.json", "config.toml", "requirements.toml", "managed_config.toml"}, fold: fold}}
	case "copilot":
		return []loadSet{{up: 0, json: true, fold: fold}}
	case "gemini":
		return []loadSet{{up: 0, names: []string{"settings.json", "system-defaults.json"}, fold: fold}}
	case "cursor":
		return []loadSet{{up: 0, names: []string{"hooks.json"}, fold: fold}}
	}
	return nil
}

// permProblem is one managed path a non-admin can change.
type permProblem struct {
	path, why string
	sibling   bool // a file the agent loads beside the hook file
	fixable   bool // Apply can take it back (a regular file with one link)
}

func (p permProblem) String() string { return p.path + " " + p.why }

// managedProblems checks the hook file, the directories that lead to it
// from the system anchor, and the files the agent loads beside it, all
// reached through the confined walk. At most maxProblems are returned.
func managedProblems(t target, o Options) []permProblem {
	const maxProblems = 8
	var out []permProblem
	check := func(p string, sibling bool) {
		if len(out) >= maxProblems {
			return
		}
		fi, err := lstatIn(p, o.Root)
		if err != nil {
			return
		}
		if why := writableByOthers(p, fi); why != "" {
			fixable := fi.IsDir() || (fi.Mode().IsRegular() && linkCount(fi) == 1)
			out = append(out, permProblem{path: p, why: why, sibling: sibling, fixable: fixable})
		}
	}
	check(t.path, false)
	for _, d := range managedChain(t.path) {
		check(d, false)
	}
	for _, ls := range managedLoads(t, o.GOOS) {
		dir := t.dir()
		for i := 0; i < ls.up; i++ {
			dir = filepath.Dir(dir)
		}
		for _, e := range listDir(dir, o.Root) {
			p := filepath.Join(dir, e.Name())
			if p == t.path || e.IsDir() || !ls.match(e.Name()) {
				continue
			}
			check(p, true)
		}
	}
	return out
}

// insecureManaged describes the first few problems, or returns "".
func insecureManaged(t target, o Options) string {
	return describeProblems(managedProblems(t, o))
}

// fixableProblems reports whether Apply can repair at least one problem.
func fixableProblems(ps []permProblem) bool {
	for _, p := range ps {
		if p.fixable {
			return true
		}
	}
	return false
}

func describeProblems(ps []permProblem) string {
	if len(ps) > 4 {
		ps = ps[:4]
	}
	parts := make([]string, len(ps))
	for i, p := range ps {
		parts[i] = p.String()
	}
	return strings.Join(parts, "; ")
}

// repairLoads takes back the files of r (the directory at position up from
// the hook file) that the agent loads and a non-admin can change. Only
// regular files with a single link are changed, through hardenIn; anything
// else is reported, since neither a link nor its target can be secured
// safely. skip is the hook file's own name, which Apply replaces anyway.
func repairLoads(r *os.Root, dir string, up int, sets []loadSet, skip string) []error {
	var errs []error
	var ents []os.DirEntry
	if f, err := r.Open("."); err == nil {
		ents, _ = f.ReadDir(maxListed)
		f.Close()
	}
	for _, e := range ents {
		name := e.Name()
		if e.IsDir() || (up == 0 && name == skip) {
			continue
		}
		want := false
		for _, ls := range sets {
			if ls.up == up && ls.match(name) {
				want = true
			}
		}
		if !want {
			continue
		}
		fi, err := r.Lstat(name)
		if err != nil {
			continue
		}
		path := filepath.Join(dir, name)
		if writableByOthers(path, fi) == "" {
			continue
		}
		if !fi.Mode().IsRegular() || linkCount(fi) > 1 {
			errs = append(errs, fmt.Errorf("%s is loaded by the agent and can be changed by a non-admin, but is not a single regular file spoor can secure; remove it", path))
			continue
		}
		if err := hardenIn(r, name, false); err != nil {
			errs = append(errs, fmt.Errorf("%s is loaded by the agent and could not be secured (%s)", path, errClass(err)))
		}
	}
	return errs
}
