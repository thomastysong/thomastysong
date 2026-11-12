package hookio

import (
	"strings"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/toolmap"
)

// Target extraction, tool classification, input keys and the input hash all
// come from package toolmap, which the transcript parsers use too: the two
// surfaces must describe the same call identically or cross-surface
// correlation breaks. This file only adds what a hook has and a transcript
// does not need: string-form arguments and the content being written.

// contentKeys are the argument names that hold text a write or edit puts on
// disk (Claude Code Write.content and Edit.new_string, Copilot new_str and
// file_text, Gemini write_file.content, Cursor code_edit, notebook
// new_source).
var contentKeys = []string{"content", "new_string", "new_str", "contents", "file_text", "code_edit", "new_source", "text"}

// patchKeys are where an apply_patch envelope travels: Codex hooks pass
// shell-like tools as {"command": ...}, the tool itself calls it "input".
var patchKeys = []string{"patch", "input", "diff", "command", "_raw"}

// setTarget derives Target (and, for writes, Content.FileContent) from the
// tool input for the tool kind already set on the event. Values are copied
// as the agent wrote them: detection needs the exact command, path and URL,
// and redaction of the serialized copy is the next stage's job.
func setTarget(ev *event.Event, in map[string]any) {
	ev.Target = nil
	if ev.Tool == nil || len(in) == 0 {
		return
	}
	agentID := ""
	if ev.Agent != nil {
		agentID = ev.Agent.ID
	}
	kind := ev.Tool.Kind
	t := toolmap.Target(agentID, ev.Tool.Name, kind, in)
	raw, _ := in["_raw"].(string)
	if t == nil && raw != "" {
		// Arguments that arrived as a plain string (see toolArgs).
		switch kind {
		case event.ToolShell:
			t = &event.Target{Command: raw}
		case event.ToolFileEdit:
			if ps := toolmap.PatchPaths(raw); len(ps) > 0 {
				t = &event.Target{Path: ps[0], Paths: ps[1:]}
			}
		}
	}
	if t == nil && kind == event.ToolFileEdit {
		// Codex hands hooks an apply_patch as {"command": "<patch>"}.
		if ps := toolmap.PatchPaths(patchText(obj(in))); len(ps) > 0 {
			t = &event.Target{Path: ps[0], Paths: ps[1:]}
		}
	}
	ev.Target = t
	if kind == event.ToolFileWrite || kind == event.ToolFileEdit {
		ev.Content.FileContent = writtenContent(obj(in))
	}
}

// patchText returns the apply_patch envelope carried in the input, if any.
func patchText(o obj) string {
	for _, k := range patchKeys {
		if s, ok := o[k].(string); ok && strings.Contains(s, "*** ") {
			return s
		}
	}
	return ""
}

// writtenContent returns the text a write or edit would put on disk, for
// local content scanning. Multi-edit tools carry it per edit.
func writtenContent(o obj) string {
	if s := o.str(contentKeys...); s != "" {
		return s
	}
	var parts []string
	for _, it := range o.arr("edits") {
		if m, ok := it.(map[string]any); ok {
			if s := obj(m).str("new_string", "new_str", "newText", "text"); s != "" {
				parts = append(parts, s)
			}
		}
	}
	if len(parts) > 0 {
		return strings.Join(parts, "\n")
	}
	return patchText(o)
}

// urlTarget builds a Target for a bare URL the payload carries outside tool
// arguments (an MCP elicitation's URL). Userinfo is dropped by toolmap.
func urlTarget(raw string) *event.Target {
	clean, host := toolmap.CleanURL(raw)
	if clean == "" {
		return nil
	}
	return &event.Target{URL: clean, Host: host}
}

// hostOf returns the lower-cased host of a URL, or "" when it has none.
func hostOf(raw string) string {
	_, host := toolmap.CleanURL(raw)
	return host
}
