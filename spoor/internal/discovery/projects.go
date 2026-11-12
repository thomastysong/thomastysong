package discovery

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Project enumeration reads agents' own records of where they ran. The
// disk is never crawled: a project spoor does not hear about from an agent
// is a project no agent has worked in.

const (
	maxProjectCandidates = 5000
	maxSessionFiles      = 200 // Codex rollouts and Claude transcripts sampled for cwd
	maxHeadBytes         = 64 << 10
	maxDecodeListings    = 64
)

type projCand struct {
	path string
	seen time.Time
}

type projSet struct {
	s    *scanner
	uc   *userCtx
	m    map[string]*projCand
	full bool
}

func (ps *projSet) add(p string, t time.Time) {
	p = cleanLogical(strings.TrimSpace(p))
	if !isAbsLogical(p) || len(p) > 4096 || strings.ContainsAny(p, "\x00\n") {
		return
	}
	key := p
	if foldCase(ps.s.goos) {
		key = strings.ToLower(p)
	}
	if c := ps.m[key]; c != nil {
		if t.After(c.seen) {
			c.seen = t
		}
		return
	}
	if len(ps.m) >= maxProjectCandidates {
		ps.full = true
		return
	}
	ps.m[key] = &projCand{path: p, seen: t}
}

// enumerateProjects returns existing project directories for a user, most
// recently used first, capped at MaxProjects.
func (s *scanner) enumerateProjects(uc *userCtx) []string {
	ps := &projSet{s: s, uc: uc, m: map[string]*projCand{}}
	s.claudeProjects(ps)
	s.codexProjects(ps)
	s.workspaceStorageProjects(ps)
	s.copilotProjects(ps)
	s.geminiProjects(ps)
	if ps.full {
		s.led.note("project candidate list truncated for " + uc.u.Name)
	}
	cands := make([]*projCand, 0, len(ps.m))
	for _, c := range ps.m {
		cands = append(cands, c)
	}
	sort.Slice(cands, func(i, j int) bool {
		if !cands[i].seen.Equal(cands[j].seen) {
			return cands[i].seen.After(cands[j].seen)
		}
		return cands[i].path < cands[j].path
	})
	var out []string
	for _, c := range cands {
		if len(out) >= s.o.MaxProjects {
			s.led.note("projects capped at " + itoa(s.o.MaxProjects) + " for " + uc.u.Name)
			break
		}
		if !s.g.alive() {
			break
		}
		// The home itself is the user scope, already scanned as such.
		if withinLogical(c.path, uc.home, s.goos) {
			continue
		}
		s.g.allowPath(c.path)
		if s.g.isDir(loc{root: c.path, user: true}) {
			out = append(out, c.path)
		}
	}
	return out
}

// mtimeOf returns a file's modification time, zero when unknown.
func (s *scanner) mtimeOf(p string, uc *userCtx) time.Time {
	m, err := s.g.stat(s.locFor(p, uc, ""))
	if err != nil {
		return time.Time{}
	}
	return m.mtime
}

// claudeProjects reads the projects map of ~/.claude.json and the cwd of
// the newest transcript in each ~/.claude/projects/<encoded-cwd>/.
func (s *scanner) claudeProjects(ps *projSet) {
	uc := ps.uc
	i, ok := s.byID["claude-code"]
	if !ok {
		return
	}
	p := &s.products[i]
	for _, m := range p.MCP {
		if m.Format != "claude.json" {
			continue
		}
		for _, f := range m.Paths.For(s.goos) {
			e, ok := s.expand(f, uc)
			if !ok {
				continue
			}
			l := s.locFor(e, uc, "")
			d := s.doc(l, ownerFor(l, uc), "json")
			if d.err != nil {
				continue
			}
			projects, _ := asMap(mustGet(d.doc, "projects"))
			for _, k := range sortedKeys(projects) {
				ps.add(k, d.meta.mtime)
			}
		}
	}
	root, ok := s.expand("${CLAUDE_CONFIG_DIR:-~/.claude}/projects", uc)
	if !ok {
		return
	}
	ents, err := s.g.readDir(s.locFor(root, uc, ""))
	if err != nil {
		return
	}
	sampled := 0
	for _, e := range ents {
		if e.kind != kindDir || sampled >= maxSessionFiles {
			continue
		}
		dir := joinLogical(root, e.name)
		newest, t := s.newestFile(dir, ".jsonl", uc)
		if newest != "" {
			sampled++
			if cwd := s.headField(newest, uc, "cwd"); cwd != "" {
				ps.add(cwd, t)
				continue
			}
		}
		if p := s.decodeClaudeDir(e.name); p != "" {
			ps.add(p, t)
		}
	}
}

// newestFile returns the most recently modified file with the suffix.
func (s *scanner) newestFile(dir, suffix string, uc *userCtx) (string, time.Time) {
	ents, err := s.g.readDir(s.locFor(dir, uc, ""))
	if err != nil {
		return "", time.Time{}
	}
	best, bt := "", time.Time{}
	n := 0
	for _, e := range ents {
		if e.kind != kindRegular || !strings.HasSuffix(e.name, suffix) {
			continue
		}
		n++
		if n > 64 {
			break
		}
		p := joinLogical(dir, e.name)
		if t := s.mtimeOf(p, uc); best == "" || t.After(bt) {
			best, bt = p, t
		}
	}
	return best, bt
}

// headField reads the first lines of a JSONL file (64 KiB at most; the file
// is opened, read and closed at once so the agent can rotate it) and
// returns the first string value of key at the top level or under
// "payload".
func (s *scanner) headField(p string, uc *userCtx, key string) string {
	l := s.locFor(p, uc, "")
	f, _, err := s.g.open(l, ownerFor(l, uc))
	if err != nil {
		s.g.account(l, err)
		return ""
	}
	data, err := io.ReadAll(io.LimitReader(f, maxHeadBytes))
	f.Close()
	if err != nil {
		return ""
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), maxHeadBytes)
	for lines := 0; sc.Scan() && lines < 50; lines++ {
		var m map[string]json.RawMessage
		if json.Unmarshal(sc.Bytes(), &m) != nil {
			continue
		}
		if v := rawString(m[key]); v != "" {
			return v
		}
		var payload map[string]json.RawMessage
		if json.Unmarshal(m["payload"], &payload) == nil {
			if v := rawString(payload[key]); v != "" {
				return v
			}
		}
	}
	return ""
}

func rawString(r json.RawMessage) string {
	if len(r) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(r, &s) != nil {
		return ""
	}
	return s
}

// decodeClaudeDir recovers a project path from Claude Code's directory
// name (the cwd with every non-alphanumeric character replaced by "-"),
// which is ambiguous: the filesystem decides, by walking down from / and
// keeping only existing directories whose encoding is a prefix.
func (s *scanner) decodeClaudeDir(name string) string {
	if s.goos == "windows" || !strings.HasPrefix(name, "-") || len(name) > 512 {
		return ""
	}
	listings := 0
	var walk func(dir string) string
	walk = func(dir string) string {
		if listings >= maxDecodeListings {
			return ""
		}
		listings++
		ents, err := s.g.readDir(systemLoc(dir))
		if err != nil {
			return ""
		}
		for _, e := range ents {
			if e.kind != kindDir {
				continue
			}
			cand := joinLogical(dir, e.name)
			enc := encodeClaude(cand)
			if enc == name {
				return cand
			}
			if strings.HasPrefix(name, enc+"-") {
				if r := walk(cand); r != "" {
					return r
				}
			}
		}
		return ""
	}
	return walk("/")
}

func encodeClaude(p string) string {
	b := []byte(p)
	for i, c := range b {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			b[i] = '-'
		}
	}
	return string(b)
}

// codexProjects reads [projects."<path>"] from config.toml and the cwd of
// recent rollouts under sessions/YYYY/MM/DD/.
func (s *scanner) codexProjects(ps *projSet) {
	uc := ps.uc
	if e, ok := s.expand("${CODEX_HOME:-~/.codex}/config.toml", uc); ok {
		l := s.locFor(e, uc, "")
		if d := s.doc(l, ownerFor(l, uc), "toml"); d.err == nil {
			projects, _ := asMap(mustGet(d.doc, "projects"))
			for _, k := range sortedKeys(projects) {
				ps.add(k, d.meta.mtime)
			}
		}
	}
	root, ok := s.expand("${CODEX_HOME:-~/.codex}/sessions", uc)
	if !ok {
		return
	}
	sampled := 0
	for _, y := range s.sortedDirs(root, uc) {
		for _, m := range s.sortedDirs(y, uc) {
			for _, d := range s.sortedDirs(m, uc) {
				ents, err := s.g.readDir(s.locFor(d, uc, ""))
				if err != nil {
					continue
				}
				names := make([]string, 0, len(ents))
				for _, e := range ents {
					if e.kind == kindRegular && strings.HasPrefix(e.name, "rollout-") && strings.HasSuffix(e.name, ".jsonl") {
						names = append(names, e.name)
					}
				}
				sort.Sort(sort.Reverse(sort.StringSlice(names)))
				for _, n := range names {
					if sampled >= maxSessionFiles {
						return
					}
					sampled++
					p := joinLogical(d, n)
					if cwd := s.headField(p, uc, "cwd"); cwd != "" {
						ps.add(cwd, s.mtimeOf(p, uc))
					}
				}
			}
		}
	}
}

// sortedDirs lists subdirectories, newest name first (dates sort as text).
func (s *scanner) sortedDirs(dir string, uc *userCtx) []string {
	ents, err := s.g.readDir(s.locFor(dir, uc, ""))
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if e.kind == kindDir {
			out = append(out, joinLogical(dir, e.name))
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(out)))
	return out
}

// workspaceStorageProjects reads VS Code-family workspaceStorage/*/workspace.json.
func (s *scanner) workspaceStorageProjects(ps *projSet) {
	uc := ps.uc
	seen := map[string]bool{}
	for i := range s.products {
		p := &s.products[i]
		if p.Kind != "app" {
			continue
		}
		for _, sd := range p.StateDirs.For(s.goos) {
			e, ok := s.expand(sd, uc)
			if !ok {
				continue
			}
			ws := joinLogical(e, "User/workspaceStorage")
			if seen[ws] {
				continue
			}
			seen[ws] = true
			ents, err := s.g.readDir(s.locFor(ws, uc, ""))
			if err != nil {
				continue
			}
			for _, x := range ents {
				if x.kind != kindDir {
					continue
				}
				f := joinLogical(ws, x.name+"/workspace.json")
				l := s.locFor(f, uc, "")
				d := s.doc(l, ownerFor(l, uc), "json")
				if d.err != nil || d.doc == nil {
					continue
				}
				if folder := fileURIPath(getString(d.doc, "folder")); folder != "" {
					ps.add(folder, d.meta.mtime)
				} else if wsf := fileURIPath(getString(d.doc, "workspace")); wsf != "" {
					ps.add(dirName(wsf), d.meta.mtime)
				}
			}
		}
	}
}

// fileURIPath converts a file:// URI to a path; remote URIs give "".
func fileURIPath(u string) string {
	if !strings.HasPrefix(u, "file://") || len(u) > 8192 {
		return ""
	}
	parsed, err := url.Parse(u)
	if err != nil {
		return ""
	}
	p := parsed.Path
	// file:///c%3A/Users/x -> /c:/Users/x
	if len(p) >= 3 && p[0] == '/' && p[2] == ':' {
		p = p[1:]
	}
	return cleanLogical(p)
}

// copilotProjects reads session-state/*/workspace.yaml.
//
// UNVERIFIED: the key names (cwd, git_root) are taken from observed files
// described in research notes, not from a published schema.
func (s *scanner) copilotProjects(ps *projSet) {
	uc := ps.uc
	root, ok := s.expand("${COPILOT_HOME:-~/.copilot}/session-state", uc)
	if !ok {
		return
	}
	ents, err := s.g.readDir(s.locFor(root, uc, ""))
	if err != nil {
		return
	}
	n := 0
	for _, e := range ents {
		if e.kind != kindDir {
			continue
		}
		n++
		if n > maxSessionFiles {
			break
		}
		f := joinLogical(root, e.name+"/workspace.yaml")
		l := s.locFor(f, uc, "")
		d := s.doc(l, ownerFor(l, uc), "yaml")
		if d.err != nil || d.doc == nil {
			continue
		}
		for _, k := range []string{"cwd", "git_root", "workspace", "repository_root"} {
			if v := getString(d.doc, k); v != "" {
				ps.add(v, d.meta.mtime)
				break
			}
		}
	}
}

// geminiProjects reads the project registry (projects.json: {"projects":
// {"<path>": "<slug>"}}) and the .project_root marker in each tmp/<slug>/,
// as written by gemini-cli's ProjectRegistry.
func (s *scanner) geminiProjects(ps *projSet) {
	uc := ps.uc
	base, ok := s.expand("${GEMINI_CLI_HOME:-~}/.gemini", uc)
	if !ok {
		return
	}
	l := s.locFor(joinLogical(base, "projects.json"), uc, "")
	if d := s.doc(l, ownerFor(l, uc), "json"); d.err == nil {
		projects, _ := asMap(mustGet(d.doc, "projects"))
		for _, k := range sortedKeys(projects) {
			ps.add(k, d.meta.mtime)
		}
	}
	tmp := joinLogical(base, "tmp")
	ents, err := s.g.readDir(s.locFor(tmp, uc, ""))
	if err != nil {
		return
	}
	n := 0
	for _, e := range ents {
		if e.kind != kindDir {
			continue
		}
		n++
		if n > maxSessionFiles {
			break
		}
		ml := s.locFor(joinLogical(tmp, e.name+"/.project_root"), uc, "")
		if data, meta, err := s.g.readFile(ml, ownerFor(ml, uc), 8192); err == nil {
			ps.add(strings.TrimSpace(string(data)), meta.mtime)
		}
	}
}
