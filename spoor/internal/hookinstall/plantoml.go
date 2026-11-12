package hookinstall

import (
	"bytes"
	"path/filepath"

	"github.com/thomastysong/spoor/internal/event"
)

// installTOML plans the marked block in Codex's requirements.toml.
func installTOML(cur fileState, want []entry) (action string, after []byte, note string) {
	nl := "\n"
	if cur.exists {
		nl = newline(cur.data)
	}
	blk := []byte(hooksBlock(want, nl))
	if !cur.exists {
		return ActionCreate, blk, ""
	}
	td, err := parseTOML(cur.data)
	if err != nil {
		return ActionUnsupported, nil, "requirements.toml is " + err.Error() + "; it is never rewritten"
	}
	b, err := findBlock(cur.data, hooksBegin, hooksEnd)
	if err != nil {
		return ActionUnsupported, nil, err.Error() + "; fix the file by hand"
	}
	if b.found && keysAfter(cur.data, b) {
		return ActionUnsupported, nil, "a bare key follows the spoor block, which TOML attaches to the block's last hook handler; fix the file by hand"
	}
	total, _, _ := td.counts()
	inBlock := 0
	if b.found {
		if tb, err := parseTOML(cur.data[b.start:b.end]); err == nil {
			inBlock, _, _ = tb.counts()
		}
	}
	if outside := total - inBlock; outside > 0 {
		note = "spoor hook entries outside the marked block were left in place; Codex runs them too"
	}
	if b.found && sameText(cur.data[b.start:b.end], blk) {
		return ActionUnchanged, nil, note
	}
	out := putBlock(cur.data, b, string(blk), nl)
	td2, err := parseTOML(out)
	if err != nil {
		return ActionUnsupported, nil, "requirements.toml declares hooks in a form the spoor block cannot extend (an inline table or array); add the block by hand"
	}
	if got, _, _ := td2.counts(); got != len(want)+total-inBlock {
		return ActionUnsupported, nil, "requirements.toml declares hooks in a form the spoor block cannot extend"
	}
	return ActionAppend, out, note
}

// uninstallTOML removes the marked block.
func uninstallTOML(cur fileState) (action string, after []byte, note string) {
	if !cur.exists {
		return ActionUnchanged, nil, "no requirements file"
	}
	td, err := parseTOML(cur.data)
	if err != nil {
		return ActionUnsupported, nil, "requirements.toml is " + err.Error() + "; it is never rewritten"
	}
	b, err := findBlock(cur.data, hooksBegin, hooksEnd)
	if err != nil {
		return ActionUnsupported, nil, err.Error() + "; fix the file by hand"
	}
	total, _, _ := td.counts()
	if !b.found {
		if total > 0 {
			return ActionUnchanged, nil, "spoor hook entries outside a marked block were not touched"
		}
		return ActionUnchanged, nil, ""
	}
	out := cutBlock(cur.data, b)
	if len(bytes.TrimSpace(out)) == 0 {
		return ActionRemove, nil, ""
	}
	td2, err := parseTOML(out)
	if err != nil {
		return ActionUnsupported, nil, "removing the spoor block would not leave valid TOML; fix the file by hand"
	}
	if left, _, _ := td2.counts(); left > 0 {
		note = "spoor hook entries outside the marked block were not touched"
	}
	return ActionMerge, out, note
}

// planCodexOTel plans the [otel] block in the config.toml beside the hook
// file: Codex keeps telemetry in config.toml, never in hooks.json, and the
// managed tier is paired with the system config.toml (requirements may pin
// an exporter, which is checked).
func planCodexOTel(t target, o Options, m mode, rel related) *Plan {
	if m == modeInstall && o.OTel == "" {
		return nil
	}
	dir, _ := splitPath(t.logical, o.GOOS)
	logical := joinPath(dir, "config.toml", o.GOOS)
	p := &Plan{AgentID: t.agentID, Path: hostPath(o.Root, logical, o.GOOS), Scope: t.scope, root: o.Root}
	cur, problem := readTarget(p.Path, o)
	p.Before = cur.data
	if m == modeUninstall {
		if !cur.exists || problem != "" {
			return nil
		}
		b, err := findBlock(cur.data, otelBegin, otelEnd)
		if err != nil || !b.found {
			return nil
		}
		out := cutBlock(cur.data, b)
		switch {
		case len(bytes.TrimSpace(out)) == 0:
			p.Action = ActionRemove
		default:
			if _, err := parseTOML(out); err != nil {
				p.Action, p.Note = ActionUnsupported, "removing the spoor otel block would not leave valid TOML"
				return p
			}
			p.Action, p.After = ActionMerge, out
		}
		return p
	}
	refuse := func(why string) *Plan {
		p.Action = ActionUnsupported
		p.Note = "native OpenTelemetry not written: " + why + "; each agent has one OTLP destination per signal and spoor does not take over an existing one"
		return p
	}
	if problem != "" {
		return refuse(problem)
	}
	ep, err := parseOTelEndpoint(o.OTel)
	if err != nil {
		return refuse("invalid endpoint")
	}
	// Requirements beside the file may already pin an exporter, and for
	// the user tier so may the system layer: its requirements, or an
	// [otel] in the system config.toml that a user-level one would
	// override.
	req := readFile(filepath.Join(filepath.Dir(p.Path), "requirements.toml"), o.Root)
	if req.exists {
		if req.refused != "" {
			return refuse("requirements.toml " + req.refused + ", so whether it pins [otel] cannot be checked")
		}
		td, err := parseTOML(req.data)
		switch {
		case err != nil:
			return refuse("requirements.toml is " + err.Error() + ", so whether it pins [otel] cannot be checked")
		case td.hasOTel:
			return refuse("requirements.toml already configures [otel]")
		}
	}
	if rel.otelPinned != "" {
		return refuse("a telemetry destination is already configured in " + rel.otelPinned)
	}
	nl := "\n"
	if cur.exists {
		nl = newline(cur.data)
	}
	blk := otelBlock(ep, nl)
	if !cur.exists {
		p.Action, p.After = ActionCreate, []byte(blk)
		return p
	}
	if _, err := parseTOML(cur.data); err != nil {
		return refuse("config.toml is not valid TOML")
	}
	b, err := findBlock(cur.data, otelBegin, otelEnd)
	if err != nil {
		return refuse(err.Error())
	}
	rest := cur.data
	if b.found {
		rest = cutBlock(cur.data, b)
	}
	if td, err := parseTOML(rest); err != nil || td.hasOTel {
		return refuse("config.toml already configures [otel]")
	}
	if b.found && keysAfter(cur.data, b) {
		return refuse("a bare key follows the spoor otel block")
	}
	if b.found && sameText(cur.data[b.start:b.end], []byte(blk)) {
		p.Action, p.After = ActionUnchanged, cur.data
		return p
	}
	out := putBlock(cur.data, b, blk, nl)
	if td, err := parseTOML(out); err != nil || !td.hasOTel {
		return refuse("config.toml cannot take an [otel] table here")
	}
	p.Action, p.After = ActionAppend, out
	p.Note = "a user's own config.toml [otel] overrides this one"
	if t.scope == event.ScopeUser {
		p.Note = ""
	}
	return p
}
