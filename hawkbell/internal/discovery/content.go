package discovery

import (
	"errors"
	"strconv"
	"strings"

	"github.com/thomastysong/thomastysong/hawkbell/internal/classify"
	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
	"github.com/thomastysong/thomastysong/hawkbell/internal/shellx"
)

// Text risk flags for skills, rules, subagents and commands.
const (
	flagHiddenUnicode    = "hidden_unicode"
	flagInjectionMarkers = "injection_markers"
	flagDropperText      = "dropper_text"
	flagQuarantined      = "quarantined"
)

const (
	maxContentFiles = 500 // files reported per rules/commands/subagents directory
	maxDropperLines = 200
)

// contentSite is a skills/rules/subagents/commands location and the first
// product (agents first) that reads it.
type contentSite struct {
	path   string
	kind   event.AssetKind
	parent int
}

// contentSites lists the catalog's skills, rules, subagents and commands
// locations for a home (project "") or for a project ("./" entries).
func (s *scanner) contentSites(uc *userCtx, project string) []contentSite {
	idx := map[string]int{}
	var out []contentSite
	add := func(i int, kind event.AssetKind, entries []string) {
		for _, e := range entries {
			var full string
			if strings.HasPrefix(e, "./") {
				if project == "" {
					continue
				}
				full = joinLogical(project, strings.TrimPrefix(e, "./"))
			} else {
				if project != "" {
					continue
				}
				var ok bool
				if full, ok = s.expand(e, uc); !ok {
					continue
				}
			}
			k := string(kind) + "\x00" + full
			if j, ok := idx[k]; ok {
				if s.products[out[j].parent].Kind != string(event.AssetAgent) && s.products[i].Kind == string(event.AssetAgent) {
					out[j].parent = i
				}
				continue
			}
			idx[k] = len(out)
			out = append(out, contentSite{path: full, kind: kind, parent: i})
		}
	}
	for i := range s.products {
		p := &s.products[i]
		add(i, event.AssetSkill, p.Skills)
		add(i, event.AssetRulesFile, p.Rules)
		add(i, event.AssetSubagent, p.Subagents)
		add(i, event.AssetCommand, p.Commands)
	}
	return out
}

// scanContent inventories skills, rules files, subagents and commands.
func (s *scanner) scanContent(uc *userCtx, project string) {
	scope := event.ScopeUser
	if project != "" {
		scope = event.ScopeProject
	}
	for _, site := range s.contentSites(uc, project) {
		if !s.g.alive() {
			return
		}
		parent := s.products[site.parent].ID
		if site.kind == event.AssetSkill {
			s.scanSkillsDir(site.path, parent, scope, uc, project, "")
			continue
		}
		s.scanTextSite(site.path, site.kind, parent, scope, uc, project, "")
	}
}

// scanSkillsDir records every <dir>/<name>/SKILL.md skill.
func (s *scanner) scanSkillsDir(dir, parent string, scope event.Scope, uc *userCtx, project, plugin string) {
	ents, err := s.g.readDir(s.locFor(dir, uc, project))
	if err != nil {
		return
	}
	for _, e := range ents {
		sdir := joinLogical(dir, e.name)
		if e.kind == kindSymlink {
			s.skipLink(sdir)
			continue
		}
		if e.kind != kindDir {
			continue
		}
		skillMD := s.findChild(sdir, "SKILL.md", uc, project)
		if skillMD == "" {
			if m, err := s.g.stat(s.locFor(joinLogical(sdir, "SKILL.md"), uc, project)); err == nil && m.kind == kindSymlink {
				s.skipLink(joinLogical(sdir, "SKILL.md"))
			}
			continue
		}
		// A skill is reported only once its SKILL.md has been opened through
		// the owner check: a name seen in a listing, or a file that merely
		// exists, may be another user's. An oversized SKILL.md passed that
		// check before its size was refused.
		l := s.locFor(skillMD, uc, project)
		data, _, rerr := s.g.readFile(l, ownerFor(l, uc), maxConfigBytes)
		if rerr != nil && !errors.Is(rerr, errTooLarge) {
			continue
		}
		a := &event.Asset{
			Kind:   event.AssetSkill,
			Name:   safeText(e.name, 256),
			Parent: parent,
			Path:   safeText(sdir, 1024),
			Scope:  scope,
			Detail: map[string]string{},
		}
		sum, files, reason := s.folderHash(sdir, uc, project)
		if reason == "" {
			a.SHA256 = sum
			a.Detail["files"] = strconv.Itoa(files)
		} else {
			a.Detail["hash"] = "none:" + reason
			s.led.note("no folder hash for skill " + homeRelOf(sdir, uc) + ": " + reason)
		}
		if rerr == nil {
			flags := textFlags(string(data))
			if n := frontmatterName(string(data)); n != "" {
				a.Detail["declared_name"] = safeText(n, 128)
			}
			a.RiskFlags = flags.list()
		}
		if s.quarantined(l) {
			a.RiskFlags = mergeFlags(a.RiskFlags, flagQuarantined)
		}
		s.finishDeclared(a, uc, project, plugin)
		s.add(&record{a: a, uc: uc})
	}
}

// findChild finds a file by name, case-insensitively where the filesystem
// folds case.
func (s *scanner) findChild(dir, name string, uc *userCtx, project string) string {
	p := joinLogical(dir, name)
	if m, err := s.g.stat(s.locFor(p, uc, project)); err == nil && m.kind == kindRegular {
		return p
	}
	ents, err := s.g.readDir(s.locFor(dir, uc, project))
	if err != nil {
		return ""
	}
	for _, e := range ents {
		if e.kind == kindRegular && strings.EqualFold(e.name, name) {
			return joinLogical(dir, e.name)
		}
	}
	return ""
}

// scanTextSite records a rules/subagent/command file, or every text file
// in a directory of them.
func (s *scanner) scanTextSite(p string, kind event.AssetKind, parent string, scope event.Scope, uc *userCtx, project, plugin string) {
	l := s.locFor(p, uc, project)
	m, err := s.g.stat(l)
	if err != nil {
		return
	}
	switch m.kind {
	case kindRegular:
		s.addTextAsset(p, baseName(p), kind, parent, scope, uc, project, plugin)
	case kindDir:
		count := 0
		var walk func(dir, prefix string, depth int)
		walk = func(dir, prefix string, depth int) {
			// Past the file cap the walk has already been counted as
			// capped; the depth bound is part of what a rules directory is.
			if depth > 4 || count > maxContentFiles {
				return
			}
			ents, err := s.g.readDir(s.locFor(dir, uc, project))
			if err != nil {
				return
			}
			for _, e := range ents {
				child := joinLogical(dir, e.name)
				rel := e.name
				if prefix != "" {
					rel = prefix + "/" + e.name
				}
				switch {
				case e.kind == kindDir:
					walk(child, rel, depth+1)
				case e.kind == kindSymlink:
					s.skipLink(child)
				case e.kind == kindRegular && isMarkdownLike(e.name):
					count++
					if count > maxContentFiles {
						s.led.capped("more than " + strconv.Itoa(maxContentFiles) + " files under " + homeRelOf(p, uc) + "; rest not reported")
						return
					}
					s.addTextAsset(child, rel, kind, parent, scope, uc, project, plugin)
				}
			}
		}
		walk(p, "", 0)
	case kindSymlink:
		s.skipLink(p)
	}
}

func (s *scanner) addTextAsset(p, rel string, kind event.AssetKind, parent string, scope event.Scope, uc *userCtx, project, plugin string) {
	l := s.locFor(p, uc, project)
	data, _, err := s.g.readFile(l, ownerFor(l, uc), maxConfigBytes)
	if err != nil {
		return
	}
	name := rel
	if kind == event.AssetCommand || kind == event.AssetSubagent {
		if i := strings.LastIndexByte(name, '.'); i > 0 {
			name = name[:i]
		}
		if kind == event.AssetCommand {
			name = strings.ReplaceAll(name, "/", ":")
		}
	}
	a := &event.Asset{
		Kind:   kind,
		Name:   safeText(name, 256),
		Parent: parent,
		Path:   safeText(p, 1024),
		Scope:  scope,
		SHA256: sha256Hex(data),
		Detail: map[string]string{},
	}
	flags := textFlags(string(data))
	if s.quarantined(l) {
		flags.add(flagQuarantined)
	}
	a.RiskFlags = flags.list()
	if ms := classify.ScanText(headText(data)).Markers; len(ms) > 0 {
		a.Detail["markers"] = strings.Join(ms, ",")
	}
	s.finishDeclared(a, uc, project, plugin)
	s.add(&record{a: a, uc: uc})
}

func (s *scanner) finishDeclared(a *event.Asset, uc *userCtx, project, plugin string) {
	if uc != nil {
		a.Owner = uc.u.Name
	}
	if project != "" {
		a.Detail["project"] = safeText(project, 1024)
	}
	if plugin != "" {
		a.Detail["plugin"] = safeText(plugin, 256)
	}
	if len(a.Detail) == 0 {
		a.Detail = nil
	}
}

func headText(b []byte) string {
	if len(b) > maxTextBytes {
		b = b[:maxTextBytes]
	}
	return string(b)
}

// textFlags scans instruction text an agent will load.
func textFlags(text string) flagSet {
	fs := flagSet{}
	t := headText([]byte(text))
	f := classify.ScanText(t)
	if f.HiddenUnicode() || invisibleControls(t) {
		fs.add(flagHiddenUnicode)
	}
	if len(f.Markers) > 0 {
		fs.add(flagInjectionMarkers)
	}
	if dropperText(t) {
		fs.add(flagDropperText)
	}
	return fs
}

// invisibleControls is a minimal, independent check for the two classes of
// invisible characters that have no business in instruction files (Unicode
// tag characters and bidirectional controls). It backs classify.ScanText,
// whose failure (it recovers internally and returns nothing) must not make
// the flag disappear.
func invisibleControls(t string) bool {
	for _, r := range t {
		if r >= 0xE0000 && r <= 0xE007F || r >= 0x202A && r <= 0x202E || r >= 0x2066 && r <= 0x2069 {
			return true
		}
	}
	return false
}

// dropperHints select the lines worth handing to the shell analyzer.
var dropperHints = []string{"curl", "wget", "iwr", "invoke-webrequest", "irm ", "invoke-restmethod", "base64",
	"-enc", "encodedcommand", "| sh", "|sh", "| bash", "|bash", "| zsh", "iex", "frombase64string", "python -c", "bash -c", "sh -c", "| python", "|python"}

// dropperText reports instructions that carry a pipe-to-shell or encoded
// one-liner: text that, once an agent follows it, downloads and runs code.
func dropperText(text string) bool {
	checked := 0
	for _, line := range strings.Split(text, "\n") {
		if len(line) > 4096 {
			line = line[:4096]
		}
		low := strings.ToLower(line)
		hint := false
		for _, h := range dropperHints {
			if strings.Contains(low, h) {
				hint = true
				break
			}
		}
		if !hint {
			continue
		}
		checked++
		if checked > maxDropperLines {
			return false
		}
		cmd := strings.TrimSpace(strings.Trim(strings.TrimSpace(line), "`"))
		cmd = strings.TrimPrefix(strings.TrimPrefix(cmd, "$ "), "> ")
		if dropperCommand(cmd) {
			return true
		}
	}
	return false
}

func dropperCommand(cmd string) (hit bool) {
	defer func() {
		if recover() != nil {
			hit = false
		}
	}()
	f := shellx.Analyze(cmd, "")
	if f.DownloadAndExecute || f.PipeToInterpreter && f.Downloads {
		return true
	}
	for _, o := range f.Obfuscation {
		if o == "base64_decode_exec" || o == "encoded_command" {
			return true
		}
	}
	return false
}

// frontmatterName reads "name:" from a YAML front matter block without a
// YAML parser (front matter in skills is routinely not valid YAML).
func frontmatterName(text string) string {
	if !strings.HasPrefix(text, "---") {
		return ""
	}
	lines := strings.SplitN(text, "\n", 64)
	for _, l := range lines[1:] {
		l = strings.TrimRight(l, "\r")
		if l == "---" {
			break
		}
		if v, ok := strings.CutPrefix(l, "name:"); ok {
			return strings.Trim(strings.TrimSpace(v), `"'`)
		}
	}
	return ""
}

func homeRelOf(p string, uc *userCtx) string { return p }
