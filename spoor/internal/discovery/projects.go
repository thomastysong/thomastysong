package discovery

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
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
	maxDecodeListings    = 64  // directory listings per decoded Claude project name
	maxUserDecodes       = 256 // uncached listings for all of one user's decodes
	maxDecodeCache       = 100_000
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
	// decodesLeft is this user's budget of uncached directory listings for
	// decodeClaudeDir: each empty ~/.claude/projects/<name> would otherwise
	// buy up to maxDecodeListings listings of directories anywhere.
	decodesLeft int
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
//
// Recency comes from per-project evidence only: the newest transcript or
// rollout of the project, its workspaceStorage entry, its Gemini marker.
// A key of a registry file (the projects map of ~/.claude.json, Codex
// [projects], Gemini projects.json) carries no time of its own: the agent
// rewrites the whole file, so the file's mtime says nothing about which of
// its projects was used.
func (s *scanner) enumerateProjects(uc *userCtx) []string {
	ps := &projSet{s: s, uc: uc, m: map[string]*projCand{}, decodesLeft: maxUserDecodes}
	s.claudeProjects(ps)
	s.codexProjects(ps)
	s.workspaceStorageProjects(ps)
	s.copilotProjects(ps)
	s.geminiProjects(ps)
	if ps.full {
		s.led.capped("project candidate list truncated for " + uc.u.Name)
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
			// The projects past the cut are not scanned: their assets are
			// not gone, so the cut counts as skipped (no removals).
			s.led.capped("projects capped at " + itoa(s.o.MaxProjects) + " for " + uc.u.Name)
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
		if s.g.isDir(projectRoot(c.path, uc)) {
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

// claudeProjects reads the projects map of ~/.claude.json and the
// transcript directories ~/.claude/projects/<encoded-cwd>/. A directory's
// recency is its newest transcript; its project is the cwd recorded in
// that transcript, else the registry key that encodes to its name, else
// the name decoded against the filesystem. The most recent directories are
// read first; past maxSessionFiles only registry matches are used, and a
// directory left unresolved makes the enumeration partial.
func (s *scanner) claudeProjects(ps *projSet) {
	uc := ps.uc
	i, ok := s.byID["claude-code"]
	if !ok {
		return
	}
	p := &s.products[i]
	byEnc := map[string][]string{}
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
				ps.add(k, time.Time{})
				if c := cleanLogical(strings.TrimSpace(k)); isAbsLogical(c) && len(byEnc) < maxProjectCandidates {
					enc := encodeClaude(c)
					byEnc[enc] = append(byEnc[enc], c)
				}
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
	type tdir struct {
		name, newest string
		t            time.Time
	}
	var dirs []tdir
	for _, e := range ents {
		if e.kind != kindDir {
			continue
		}
		if !s.g.alive() {
			return
		}
		dir := joinLogical(root, e.name)
		newest, t := s.newestFile(dir, ".jsonl", uc)
		if newest == "" {
			if m, err := s.g.stat(s.locFor(dir, uc, "")); err == nil {
				t = m.mtime
			}
		}
		dirs = append(dirs, tdir{e.name, newest, t})
	}
	sort.Slice(dirs, func(a, b int) bool {
		if !dirs[a].t.Equal(dirs[b].t) {
			return dirs[a].t.After(dirs[b].t)
		}
		return dirs[a].name < dirs[b].name
	})
	unresolved := 0
	for n, d := range dirs {
		if n < maxSessionFiles && d.newest != "" {
			if cwd := s.headField(d.newest, uc, "cwd"); cwd != "" {
				ps.add(cwd, d.t)
				continue
			}
		}
		if known := byEnc[d.name]; len(known) > 0 {
			for _, k := range known {
				ps.add(k, d.t)
			}
			continue
		}
		if n >= maxSessionFiles {
			unresolved++
			continue
		}
		if p := s.decodeClaudeDir(ps, d.name); p != "" {
			ps.add(p, d.t)
		}
	}
	if unresolved > 0 {
		s.led.capped("Claude Code transcript directories not resolved to a project (past " + itoa(maxSessionFiles) + "): " + itoa(unresolved) + " for " + uc.u.Name)
	}
}

// newestFile returns the most recently modified file with the suffix.
func (s *scanner) newestFile(dir, suffix string, uc *userCtx) (string, time.Time) {
	ents, err := s.g.readDir(s.locFor(dir, uc, ""))
	if err != nil {
		return "", time.Time{}
	}
	best, bt := "", time.Time{}
	for _, e := range ents {
		if e.kind != kindRegular || !strings.HasSuffix(e.name, suffix) {
			continue
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
// keeping only existing directories whose encoding is a prefix. The
// directories listed are the machine's, not the user's, so listings are
// cached for the whole scan, and each user has a budget of uncached ones
// (ps.decodesLeft): the names come from a directory the user controls.
func (s *scanner) decodeClaudeDir(ps *projSet, name string) string {
	if s.goos == "windows" || !strings.HasPrefix(name, "-") || len(name) > 512 {
		return ""
	}
	listings := 0
	capped := false
	var walk func(dir string) string
	walk = func(dir string) string {
		if listings >= maxDecodeListings {
			capped = true
			return ""
		}
		listings++
		ents, ok, spent := s.decodeList(ps, dir)
		if !ok {
			capped = capped || spent
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
	r := walk("/")
	if r == "" && capped {
		s.led.capped("Claude Code project name not decoded (listing budget): " + ps.uc.u.Name)
	}
	return r
}

// decodeList lists a system directory for decodeClaudeDir, from the scan's
// cache when it can. spent reports that the user's listing budget, not the
// directory, is why there is no listing.
func (s *scanner) decodeList(ps *projSet, dir string) (ents []dentry, ok, spent bool) {
	if cached, hit := s.listCache[dir]; hit {
		return cached, cached != nil, false
	}
	if ps.decodesLeft <= 0 {
		return nil, false, true
	}
	ps.decodesLeft--
	ents, err := s.g.readDir(systemLoc(dir))
	// A listing refused for the current scope's budget or the deadline
	// says nothing about the directory: it is not cached for other users.
	transient := errors.Is(err, errBudget) || errors.Is(err, errDeadline)
	if !transient && s.listCacheSize+len(ents) <= maxDecodeCache {
		if s.listCache == nil {
			s.listCache = map[string][]dentry{}
		}
		c := ents
		if err != nil {
			c = nil
		} else if c == nil {
			c = []dentry{}
		}
		s.listCache[dir] = c
		s.listCacheSize += len(c) + 1
	}
	return ents, err == nil, false
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
				ps.add(k, time.Time{})
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
						s.led.capped("Codex rollouts sampled for project directories: newest " + itoa(maxSessionFiles) + " for " + uc.u.Name)
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
				// workspace.json is written once; the editor's state database
				// next to it changes whenever the workspace is used.
				t := d.meta.mtime
				if st := s.mtimeOf(joinLogical(ws, x.name+"/state.vscdb"), uc); st.After(t) {
					t = st
				}
				if folder := fileURIPath(getString(d.doc, "folder")); folder != "" {
					ps.add(folder, t)
				} else if wsf := fileURIPath(getString(d.doc, "workspace")); wsf != "" {
					ps.add(dirName(wsf), t)
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
			s.led.capped("Copilot sessions sampled for project directories: " + itoa(maxSessionFiles) + " for " + uc.u.Name)
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
			ps.add(k, time.Time{})
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
			s.led.capped("Gemini project markers sampled: " + itoa(maxSessionFiles) + " for " + uc.u.Name)
			break
		}
		ml := s.locFor(joinLogical(tmp, e.name+"/.project_root"), uc, "")
		if data, meta, err := s.g.readFile(ml, ownerFor(ml, uc), 8192); err == nil {
			ps.add(strings.TrimSpace(string(data)), meta.mtime)
		}
	}
}
