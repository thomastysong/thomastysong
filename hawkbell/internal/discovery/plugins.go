package discovery

import (
	"strings"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

const maxPlugins = 1000

// scanPlugins inventories agent plugins. Claude Code records installed
// plugins with their marketplace in installed_plugins.json; other agents
// keep one file or directory per plugin in their plugin directory.
// VS Code-family "extensions" directories are editor extensions and are
// handled by scanExtensions.
func (s *scanner) scanPlugins(uc *userCtx) {
	done := map[string]bool{}
	for i := range s.products {
		p := &s.products[i]
		for _, entry := range p.Plugins {
			if strings.HasPrefix(entry, "./") {
				continue
			}
			dir, ok := s.expand(entry, uc)
			if !ok || done[dir] {
				continue
			}
			done[dir] = true
			if p.Kind == string(event.AssetApp) && baseName(dir) == "extensions" {
				continue
			}
			if p.ID == "claude-code" && baseName(dir) == "plugins" {
				s.scanClaudePlugins(dir, p.ID, uc)
				continue
			}
			s.scanPluginDir(dir, p.ID, uc)
		}
	}
}

// scanClaudePlugins reads installed_plugins.json (format version 1: one
// object per plugin; version 2: a list of installs per plugin, one per
// scope), known_marketplaces.json and the enabledPlugins map of the user's
// settings.
func (s *scanner) scanClaudePlugins(dir, parent string, uc *userCtx) {
	l := s.locFor(joinLogical(dir, "installed_plugins.json"), uc, "")
	d := s.doc(l, ownerFor(l, uc), "json")
	if d.err != nil || d.doc == nil {
		return
	}
	plugins, _ := asMap(mustGet(d.doc, "plugins"))
	ml := s.locFor(joinLogical(dir, "known_marketplaces.json"), uc, "")
	markets, _ := asMap(s.doc(ml, ownerFor(ml, uc), "json").doc)
	sl := s.locFor(joinLogical(dirName(dir), "settings.json"), uc, "")
	enabled, _ := asMap(mustGet(s.doc(sl, ownerFor(sl, uc), "json").doc, "enabledPlugins"))
	count := 0
	for _, key := range sortedKeys(plugins) {
		for _, inst := range asList(plugins[key]) {
			im, ok := asMap(inst)
			if !ok {
				continue
			}
			count++
			if count > maxPlugins {
				s.led.capped("plugin list truncated: " + homeRelNote(l))
				return
			}
			s.addClaudePlugin(key, im, markets, enabled, parent, uc)
		}
	}
}

func mustGet(doc any, key string) any {
	v, _ := getPath(doc, key)
	return v
}

func (s *scanner) addClaudePlugin(key string, im, markets, enabled map[string]any, parent string, uc *userCtx) {
	name, market := key, ""
	if i := strings.LastIndexByte(key, '@'); i > 0 {
		name, market = key[:i], key[i+1:]
	}
	a := &event.Asset{
		Kind:    event.AssetPlugin,
		Name:    safeText(key, 256),
		Parent:  parent,
		Scope:   event.ScopeUser,
		Version: safeVersion(scalarString(im["version"])),
		Detail:  map[string]string{"plugin": safeText(name, 128)},
	}
	if sc := scalarString(im["scope"]); sc != "" {
		a.Detail["install_scope"] = safeText(sc, 32)
		if sc == "project" || sc == "local" {
			a.Scope = event.ScopeProject
			if pp := cleanLogical(scalarString(im["projectPath"])); isAbsLogical(pp) {
				a.Detail["project"] = safeText(pp, 1024)
			}
		}
	}
	if market != "" {
		a.Detail["marketplace"] = safeText(market, 128)
		if mm, ok := asMap(markets[market]); ok {
			if src, ok := asMap(mm["source"]); ok {
				kind := scalarString(src["source"])
				a.Detail["marketplace_source"] = safeText(kind, 32)
				switch {
				case scalarString(src["repo"]) != "":
					a.Detail["marketplace_repo"] = safeText(scalarString(src["repo"]), 256)
				case scalarString(src["url"]) != "":
					a.Detail["marketplace_host"] = safeText(urlHost(scalarString(src["url"])), 256)
				}
			}
		}
	}
	// UNVERIFIED: the gitCommitSha field name; installPath, version, scope
	// and projectPath match uber/ADR's reader of the same file.
	sha := scalarString(im["gitCommitSha"])
	pinned := isFullSHA(sha)
	if pinned {
		a.Detail["git_sha"] = sha
	}
	a.Detail["pinned"] = boolText(pinned)
	if v, ok := enabled[key]; ok {
		b, _ := asBool(v)
		a.Detail["enabled"] = boolText(b)
	}
	installPath := cleanLogical(scalarString(im["installPath"]))
	if installPath != "" && isAbsLogical(installPath) {
		// The install path comes from a user-writable file: it is used only
		// when it lies inside that user's home.
		il := s.locFor(installPath, uc, "")
		_, inHome := relLogical(uc.home, installPath, s.goos)
		if inHome {
			if m, err := s.g.stat(il); err == nil && m.kind == kindSymlink {
				s.skipLink(installPath)
			}
		}
		if inHome && s.g.isDir(il) {
			a.Path = safeText(installPath, 1024)
			if sum, _, reason := s.folderHash(installPath, uc, ""); reason == "" {
				a.SHA256 = sum
			} else {
				a.Detail["hash"] = "none:" + reason
			}
			s.scanPluginContents(installPath, key, parent, uc)
		}
	}
	if uc != nil {
		a.Owner = uc.u.Name
	}
	s.add(&record{a: a, uc: uc})
}

// scanPluginContents inventories what a plugin ships: skills, subagents,
// commands and hooks. (Its .mcp.json is found through the catalog's plugin
// MCP glob.)
func (s *scanner) scanPluginContents(root, plugin, parent string, uc *userCtx) {
	s.scanSkillsDir(joinLogical(root, "skills"), parent, event.ScopePlugin, uc, "", plugin)
	s.scanTextSite(joinLogical(root, "agents"), event.AssetSubagent, parent, event.ScopePlugin, uc, "", plugin)
	s.scanTextSite(joinLogical(root, "commands"), event.AssetCommand, parent, event.ScopePlugin, uc, "", plugin)
	hf := hookFile{path: joinLogical(root, "hooks/hooks.json"), syntax: "json", scope: event.ScopePlugin}
	if s.g.exists(s.locFor(hf.path, uc, "")) {
		if hs, _, ok := s.handlersIn(hf, uc, ""); ok {
			s.addHooks(hs, hf.path, event.ScopePlugin, parent, uc, "", plugin)
		}
	}
}

// scanPluginDir records one plugin per entry of a plugin directory.
func (s *scanner) scanPluginDir(dir, parent string, uc *userCtx) {
	ents, err := s.g.readDir(s.locFor(dir, uc, ""))
	if err != nil {
		return
	}
	n := 0
	for _, e := range ents {
		if strings.HasPrefix(e.name, ".") || e.kind == kindOther {
			continue
		}
		if e.kind == kindSymlink {
			s.skipLink(joinLogical(dir, e.name))
			continue
		}
		n++
		if n > maxPlugins {
			s.led.capped("plugin directory truncated: " + homeRelOf(dir, uc))
			return
		}
		p := joinLogical(dir, e.name)
		a := &event.Asset{
			Kind:   event.AssetPlugin,
			Name:   safeText(e.name, 256),
			Parent: parent,
			Path:   safeText(p, 1024),
			Scope:  event.ScopeUser,
			Detail: map[string]string{},
		}
		if e.kind == kindDir {
			if sum, _, reason := s.folderHash(p, uc, ""); reason == "" {
				a.SHA256 = sum
			} else {
				a.Detail["hash"] = "none:" + reason
			}
		} else {
			l := s.locFor(p, uc, "")
			if sum, err := s.fileHash(l, ownerFor(l, uc)); err == nil {
				a.SHA256 = sum
			}
		}
		s.finishDeclared(a, uc, "", "")
		s.add(&record{a: a, uc: uc})
	}
}

func isFullSHA(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func boolText(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
