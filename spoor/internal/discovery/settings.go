package discovery

import (
	"strings"

	"github.com/thomastysong/spoor/internal/catalog"
)

// Flags computed by discovery itself (the catalog's Setting probes supply
// the rest).
const (
	flagManagedMissing       = "managed_policy_missing"
	flagManagedWorldWritable = "managed_policy_world_writable"
	// flagManagedPolicyPresent is the catalog's flag for an MDM-delivered
	// managed policy (macOS managed preferences, Windows policy keys).
	flagManagedPolicyPresent = "managed_policy_present"
)

// managedFacts are machine-wide posture facts for one product, attached to
// every asset of that product.
type managedFacts struct {
	flags    []string
	insecure map[string]bool // managed files that are not root-owned or are group/world writable
}

// settingScope classifies one catalog settings path.
type settingScope int

const (
	scopeManagedFile settingScope = iota
	scopeUserFile
	scopeProjectFile
)

func classifySettingPath(p string) settingScope {
	switch {
	case strings.HasPrefix(p, "./"), strings.HasPrefix(p, `.\`):
		return scopeProjectFile
	case isHomePath(p):
		return scopeUserFile
	}
	return scopeManagedFile
}

func fileFormat(st catalog.Setting) (string, bool) {
	switch st.Format {
	case "json", "jsonc":
		return "json", true
	case "toml":
		return "toml", true
	case "yaml":
		return "yaml", true
	}
	return "", false
}

// evalSetting applies one probe to the documents found for it. "ne" means
// "no file sets the value", so it holds when no file exists at all; the
// other operators hold when any file matches.
func evalSetting(st catalog.Setting, docs []any) bool {
	if st.Op == "ne" {
		for _, d := range docs {
			if hit, _ := st.Eval(d); !hit {
				return false
			}
		}
		return true
	}
	for _, d := range docs {
		if hit, _ := st.Eval(d); hit {
			return true
		}
	}
	return false
}

// scanManagedFacts evaluates every machine-wide probe once: managed and
// system settings files, macOS managed preferences, Windows policy keys,
// and whether the managed files themselves can be trusted.
func (s *scanner) scanManagedFacts() {
	for i := range s.products {
		p := &s.products[i]
		if !hostKind(p) {
			continue
		}
		mf := &managedFacts{insecure: map[string]bool{}}
		flags := flagSet{}
		var managedFiles []string
		policyPresent := false
		for _, st := range p.Settings {
			switch st.Format {
			case "env":
				continue // a process property: the process monitor's job
			case "registry":
				if s.goos != "windows" {
					continue
				}
				hit := false
				for _, k := range st.File.For("windows") {
					if ex, ok := registryProbe(k, st.Key); ok && ex {
						hit = true
						policyPresent = true
					}
				}
				if hit == (st.Op != "ne") {
					flags.add(st.Flag)
				}
				continue
			case "plist":
				if s.goos != "darwin" {
					continue
				}
				var docs []any
				for _, f := range st.File.For(s.goos) {
					e, ok := s.expand(f, nil)
					if !ok {
						continue
					}
					l := systemLoc(e)
					d := s.doc(l, "", "plist")
					if d.err == nil {
						docs = append(docs, d.doc)
						policyPresent = true
						s.checkManagedFile(l, d.meta, mf)
					}
				}
				if len(docs) > 0 && evalSetting(st, docs) {
					flags.add(st.Flag)
				}
				continue
			}
			syntax, ok := fileFormat(st)
			if !ok {
				continue
			}
			var docs []any
			seenFile := false
			for _, f := range st.File.For(s.goos) {
				if classifySettingPath(f) != scopeManagedFile {
					continue
				}
				e, ok := s.expand(f, nil)
				if !ok {
					continue
				}
				seenFile = true
				managedFiles = append(managedFiles, e)
				l := systemLoc(e)
				d := s.doc(l, "", syntax)
				if d.err == nil {
					docs = append(docs, d.doc)
				}
			}
			if seenFile && evalSetting(st, docs) {
				flags.add(st.Flag)
			}
		}
		if p.Hooks != nil {
			for _, f := range p.Hooks.ManagedPaths.For(s.goos) {
				if e, ok := s.expand(f, nil); ok {
					managedFiles = append(managedFiles, e)
				}
			}
		}
		for _, m := range p.MCP {
			if m.Scope != "managed" {
				continue
			}
			for _, f := range m.Paths.For(s.goos) {
				if e, ok := s.expand(f, nil); ok && !hasWild(e) {
					managedFiles = append(managedFiles, e)
				}
			}
		}
		// Only products whose catalog entry has a managed settings or hooks
		// tier can lack a managed policy; a managed MCP file alone is not one.
		policyCapable := policyPresent || p.Hooks != nil && !p.Hooks.ManagedPaths.IsZero() && len(p.Hooks.ManagedPaths.For(s.goos)) > 0
		for _, st := range p.Settings {
			for _, f := range st.File.For(s.goos) {
				if (st.Format == "json" || st.Format == "jsonc" || st.Format == "toml" || st.Format == "yaml") && classifySettingPath(f) == scopeManagedFile {
					policyCapable = true
				}
			}
		}
		if len(managedFiles) == 0 && !policyPresent {
			continue
		}
		for _, f := range dedupe(managedFiles) {
			l := systemLoc(f)
			m, err := s.g.stat(l)
			if err != nil || m.kind == kindDir {
				continue
			}
			policyPresent = true
			s.checkManagedFile(l, m, mf)
		}
		if !policyPresent && policyCapable {
			flags.add(flagManagedMissing)
		}
		if len(mf.insecure) > 0 {
			flags.add(flagManagedWorldWritable)
		}
		mf.flags = flags.list()
		if len(mf.flags) > 0 || len(mf.insecure) > 0 {
			s.managed[p.ID] = mf
		}
	}
}

// checkManagedFile records a managed file that a non-administrator could
// have written: it or its directory is not owned by root, or either is
// group or world writable (the CVE-2026-35603 class). A sticky bit does not
// excuse a writable directory: in a drop-in directory such as
// managed-settings.d, adding a new file is the attack. Windows ACLs are not
// read.
func (s *scanner) checkManagedFile(l loc, m fmeta, mf *managedFacts) {
	insecure := m.kind == kindSymlink
	if m.hasOwner && m.owner != s.adminUID {
		insecure = true
	}
	if s.goos != "windows" && m.perm&0o022 != 0 {
		insecure = true
	}
	if s.goos != "windows" {
		if dm, err := s.g.stat(systemLoc(l.root)); err == nil &&
			(dm.perm&0o022 != 0 || dm.hasOwner && dm.owner != s.adminUID) {
			insecure = true
		}
	}
	if insecure {
		mf.insecure[l.String()] = true
	}
}

// settingsFlags evaluates the user-scope probes of one product for a user.
func (s *scanner) settingsFlags(i int, uc *userCtx) []string {
	p := &s.products[i]
	flags := flagSet{}
	for _, st := range p.Settings {
		syntax, ok := fileFormat(st)
		if !ok {
			continue
		}
		var docs []any
		seenFile := false
		for _, f := range st.File.For(s.goos) {
			if classifySettingPath(f) != scopeUserFile {
				continue
			}
			e, ok := s.expand(f, uc)
			if !ok {
				continue
			}
			seenFile = true
			l := s.locFor(e, uc, "")
			if d := s.doc(l, ownerFor(l, uc), syntax); d.err == nil && d.doc != nil {
				docs = append(docs, d.doc)
			}
		}
		if seenFile && evalSetting(st, docs) {
			flags.add(st.Flag)
		}
	}
	for f := range s.projectHits[projectHitKey(uc, p.ID)] {
		flags.add("project:" + f)
	}
	return flags.list()
}

// projectSettingFlags evaluates the project-relative probes of every
// product against one project. The hits are returned for the project's own
// asset and remembered so the user's agent asset carries them too, scope
// qualified ("project:bypass_permissions_default").
func (s *scanner) projectSettingFlags(uc *userCtx, dir string) map[string][]string {
	out := map[string][]string{}
	for i := range s.products {
		p := &s.products[i]
		for _, st := range p.Settings {
			syntax, ok := fileFormat(st)
			if !ok || st.Op == "ne" {
				// "not set" in a project file is the normal state, not a finding.
				continue
			}
			for _, f := range st.File.For(s.goos) {
				if classifySettingPath(f) != scopeProjectFile {
					continue
				}
				full := joinLogical(dir, strings.TrimPrefix(strings.TrimPrefix(f, "./"), `.\`))
				l := s.locFor(full, uc, dir)
				d := s.doc(l, ownerFor(l, uc), syntax)
				if d.err != nil || d.doc == nil {
					continue
				}
				if hit, _ := st.Eval(d.doc); hit {
					out[full] = append(out[full], st.Flag)
					k := projectHitKey(uc, p.ID)
					if s.projectHits[k] == nil {
						s.projectHits[k] = map[string]bool{}
					}
					s.projectHits[k][st.Flag] = true
				}
			}
		}
	}
	return out
}

func projectHitKey(uc *userCtx, id string) string { return uc.u.UID + "\x00" + uc.home + "\x00" + id }
