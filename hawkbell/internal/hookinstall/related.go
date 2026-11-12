package hookinstall

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// related is what the other configuration files of an agent say about the
// file a plan is about to write. Hooks from several files combine at run
// time, so "is another sensor already hooked in" and "is telemetry already
// routed somewhere" cannot be answered from the target file alone.
type related struct {
	// sensors maps a foreign sensor to the file that registers it.
	sensors map[string]string
	// otelPinned names a file that already configures a telemetry
	// destination, with the member that does.
	otelPinned string
	// managedOnly names a managed file that makes the agent ignore user
	// hooks (Claude Code allowManagedHooksOnly, Codex
	// allow_managed_hooks_only).
	managedOnly string
	// hooksOff and hooksOffFile are the managed level's own switch for
	// every hook: Claude Code disableAllHooks (the last managed file that
	// sets it wins) and Gemini CLI hooksConfig.enabled in the system
	// settings, which outrank the user's. hooksOff is nil when no managed
	// file sets it.
	hooksOff     *bool
	hooksOffFile string
	// checked lists the files that were read, for Status.Detail.
	checked []string
	// unread lists files that exist but could not be read or parsed, with
	// the reason: whatever they say was not taken into account.
	unread []string
}

func (r *related) sensor(name, path string) {
	if r.sensors == nil {
		r.sensors = map[string]string{}
	}
	if _, ok := r.sensors[name]; !ok {
		r.sensors[name] = path
	}
}

func (r related) sensorList() []string {
	out := make([]string, 0, len(r.sensors))
	for n := range r.sensors {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// relatedFiles lists the other files of the same agent that take part in
// hook loading, with the layout each one uses. Managed files come first,
// in the order the agent merges them.
func relatedFiles(t target, o Options) []relFile {
	var out []relFile
	add := func(path string, kind fileKind, managed bool) {
		if path == "" || path == t.path {
			return
		}
		for _, f := range out {
			if f.path == path {
				return
			}
		}
		out = append(out, relFile{path: path, kind: kind, managed: managed})
	}
	managedTarget := func() (target, bool) {
		if t.scope == event.ScopeManaged {
			return t, true
		}
		mt := resolveTarget(t.product, o, event.ScopeManaged)
		return mt, mt.unsupported == ""
	}
	switch t.dialect {
	case "claude":
		// managed-settings.json and every managed-settings.d/*.json merge
		// into one policy, the drop-ins on top in name order.
		if mt, ok := managedTarget(); ok {
			dir := filepath.Dir(mt.path)
			if strings.EqualFold(filepath.Base(dir), "managed-settings.d") {
				add(filepath.Join(filepath.Dir(dir), "managed-settings.json"), kindGroups, true)
				for _, p := range jsonSiblings(dir, o.Root) {
					add(p, kindGroups, true)
				}
			} else {
				add(mt.path, kindGroups, true)
			}
		}
	case "copilot":
		// Every *.json of the policy or user hooks directory is loaded.
		for _, p := range jsonSiblings(t.dir(), o.Root) {
			add(p, kindFlat, t.scope != event.ScopeUser)
		}
	case "codex":
		managed := t.scope != event.ScopeUser
		add(filepath.Join(t.dir(), "hooks.json"), kindGroups, managed)
		add(filepath.Join(t.dir(), "config.toml"), kindTOML, managed)
		add(filepath.Join(t.dir(), "requirements.toml"), kindTOML, managed)
		if mt, ok := managedTarget(); ok && t.scope == event.ScopeUser {
			// The system layer: its requirements may forbid user hooks or
			// pin [otel], and its config.toml [otel] is what a user-level
			// [otel] would override.
			add(filepath.Join(filepath.Dir(mt.path), "requirements.toml"), kindTOML, true)
			add(filepath.Join(filepath.Dir(mt.path), "config.toml"), kindTOML, true)
		}
	case "gemini":
		if mt, ok := managedTarget(); ok {
			add(mt.path, kindGroups, true)
		}
	}
	return out
}

type relFile struct {
	path    string
	kind    fileKind
	managed bool
}

// inspectRelated reads the related files, through the same confined walk
// as the target. Files that are missing cannot register a hook; files that
// exist but cannot be read or parsed are listed in unread.
func inspectRelated(t target, o Options) related {
	var r related
	var spec otelSpec
	haveSpec := false
	if o.OTel != "" {
		if ep, err := parseOTelEndpoint(o.OTel); err == nil {
			spec, haveSpec = jsonOTel(t.dialect, ep)
		}
	}
	for _, f := range relatedFiles(t, o) {
		st := readFile(f.path, o.Root)
		if !st.exists {
			continue
		}
		if st.refused != "" {
			r.unread = append(r.unread, f.path+" "+st.refused)
			continue
		}
		r.checked = append(r.checked, f.path)
		if f.kind == kindTOML {
			td, err := parseTOML(st.data)
			if err != nil {
				r.unread = append(r.unread, f.path+" is "+err.Error())
				continue
			}
			_, _, sensors := td.counts()
			for _, s := range sensors {
				r.sensor(s, f.path)
			}
			if td.managedOnly && f.managed && r.managedOnly == "" && strings.EqualFold(filepath.Base(f.path), "requirements.toml") {
				r.managedOnly = f.path
			}
			if o.OTel != "" && f.managed && r.otelPinned == "" && foreignOTel(st.data) {
				r.otelPinned = f.path + " ([otel])"
			}
			continue
		}
		d, err := parseJSON(st.data)
		if err != nil {
			r.unread = append(r.unread, f.path+" is not a JSON object hawkbell can read")
			continue
		}
		_, sensors := scanHooks(d, f.kind).foreign()
		for _, s := range sensors {
			r.sensor(s, f.path)
		}
		if f.managed && t.dialect == "claude" {
			if _, v := d.root.member("allowManagedHooksOnly"); v != nil && v.kind == kindBool && v.b && r.managedOnly == "" {
				r.managedOnly = f.path
			}
			// Only a JSON boolean counts: Claude Code drops any other
			// value with a warning.
			if _, v := d.root.member("disableAllHooks"); v != nil && v.kind == kindBool {
				b := v.b
				r.hooksOff, r.hooksOffFile = &b, f.path
			}
		}
		if f.managed && t.dialect == "gemini" {
			if b, ok := geminiHooksEnabled(d); ok {
				off := !b
				r.hooksOff, r.hooksOffFile = &off, f.path
			}
		}
		if haveSpec && r.otelPinned == "" && f.managed {
			if c := spec.conflicts(d); len(c) > 0 {
				r.otelPinned = f.path + " (" + strings.Join(c, ", ") + ")"
			}
		}
	}
	return r
}

// geminiHooksEnabled returns hooksConfig.enabled when it is a boolean.
func geminiHooksEnabled(d *jsonDoc) (enabled, ok bool) {
	_, hc := d.root.member("hooksConfig")
	if _, v := hc.member("enabled"); v != nil && v.kind == kindBool {
		return v.b, true
	}
	return false, false
}

// foreignOTel reports whether a Codex TOML file configures [otel] outside
// hawkbell's own marked block.
func foreignOTel(src []byte) bool {
	rest := src
	if b, err := findBlock(src, otelBegin, otelEnd); err == nil && b.found {
		rest = cutBlock(src, b)
	}
	td, err := parseTOML(rest)
	return err == nil && td.hasOTel
}
