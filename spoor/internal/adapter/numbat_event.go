package adapter

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/toolmap"
)

// numbatAction describes how one numbat event_type maps to a spoor activity.
// numbat's action types are alternatives, not layers (docs/event-model.md):
// a recognized shell request is command.exec and nothing else, tool.call is
// the fallback. Requests map to tool.pre and separately observed outcomes
// to tool.post, which is how spoor's own hook and transcript sources type a
// call and its result.
type numbatAction struct {
	typ  string
	kind event.ToolKind // "" when the tool name decides
	tool bool           // the record describes a tool call
}

var numbatActions = map[string]numbatAction{
	"session.start":        {typ: event.TypeSessionStart},
	"session.end":          {typ: event.TypeSessionEnd},
	"prompt.user":          {typ: event.TypePromptSubmit},
	"tool.call":            {typ: event.TypeToolPre, tool: true},
	"tool.result":          {typ: event.TypeToolPost, tool: true},
	"command.exec":         {typ: event.TypeToolPre, kind: event.ToolShell, tool: true},
	"command.result":       {typ: event.TypeToolPost, kind: event.ToolShell, tool: true},
	"file.read":            {typ: event.TypeToolPre, kind: event.ToolFileRead, tool: true},
	"file.write":           {typ: event.TypeToolPre, kind: event.ToolFileWrite, tool: true},
	"file.delete":          {typ: event.TypeToolPre, kind: event.ToolFileEdit, tool: true},
	"network.indicator":    {typ: event.TypeToolPre, kind: event.ToolWebFetch, tool: true},
	"permission.requested": {typ: event.TypePermissionDecision, tool: true},
	"permission.approved":  {typ: event.TypePermissionDecision, tool: true},
	"permission.denied":    {typ: event.TypePermissionDecision, tool: true},
	"config.agent":         {typ: event.TypeConfigChange},
	"config.mcp":           {typ: event.TypeConfigChange},
}

// numbatSkipped lists event types that are understood and not converted:
// spoor has no event for model output, and inventing a turn boundary from an
// assistant message would be wrong.
var numbatSkipped = map[string]bool{"message.assistant": true, "message.reasoning": true}

func (c *nctx) event() []*event.Event {
	r := c.r
	et := string(r.EventType)
	if numbatSkipped[et] {
		return nil
	}
	act, known := numbatActions[et]
	if !known {
		// A type added after 0.5.0: keep the record visible and flagged
		// instead of guessing its meaning.
		act = numbatAction{typ: event.TypeNotification, tool: r.ToolName != ""}
	}
	ts, sensor := c.stamp(r.Timestamp)
	ev := c.base(event.KindActivity, act.typ, ts, sensor)
	if r.EventID != "" {
		ev.ID = numbatID("event", string(r.EventID))
		if id, _ := cleanID(string(r.EventID), maxLabel); id != "" {
			setLabel(ev, "numbat_event_id", id)
		}
	} else {
		ev.ID = event.StableID(ts, "numbat", "line", c.lineKey())
	}
	setLabel(ev, "numbat_event_type", et)
	if !known {
		setLabel(ev, "adapter_unmapped", "1")
	}
	// numbat's confidence is extraction certainty: "high means direct
	// source evidence; medium and low are reserved for inferred or
	// best-effort normalizations" (docs/cli.md).
	switch r.Confidence {
	case "high":
		ev.Fidelity = event.FidelityObserved
	case "medium", "low":
		ev.Fidelity = event.FidelityInferred
	}
	setLabel(ev, "numbat_confidence", string(r.Confidence))
	setLabel(ev, "actor", string(r.Actor))
	setListLabel(ev, "numbat_tags", r.Tags)
	setListLabel(ev, "content_omitted", r.ContentOmitted)
	setLabel(ev, "entrypoint", string(r.Entrypoint))
	setLabel(ev, "numbat_artifact", string(r.Evidence.ArtifactType))

	// project_path uses "/" on every OS and is already redacted by numbat.
	if p := string(r.ProjectPath); p != "" {
		c.session(ev).CWD = pathField(ev, "session.cwd", p)
	}
	// For artifact scans the evidence points at the session log that was
	// parsed, in the endpoint's native path syntax.
	if p := string(r.Evidence.LocalPath); p != "" && r.SourceType == "artifact" {
		c.session(ev).Transcript = pathField(ev, "session.transcript", p)
	}
	if b := string(r.GitBranch); b != "" {
		ev.Repo = &event.Repo{Branch: field(ev, "repo.branch", b, maxName)}
	}

	switch {
	case et == "prompt.user":
		c.prompt(ev)
	case et == "config.mcp":
		setLabel(ev, "config_key", "mcp")
		setLabel(ev, "mcp_server", string(r.MCPServer))
		setLabel(ev, "mcp_tool", string(r.MCPTool))
	case et == "config.agent":
		setLabel(ev, "config_key", "agent")
	case act.tool:
		c.tool(ev, act)
	}
	return []*event.Event{ev}
}

// prompt records a user prompt. numbat exports a preview of at most 200
// code points by default and the redacted body with --content full; both go
// to Content only.
func (c *nctx) prompt(ev *event.Event) {
	r := c.r
	p := &event.Prompt{}
	text := string(r.Content)
	if text == "" {
		text = string(r.ContentPreview)
		if text != "" && (r.ContentPreviewCut.v || !r.ContentPreviewCut.ok && r.ContentBytes.v > int64(len(text))) {
			setLabel(ev, "content_partial", "1")
		}
	}
	if text != "" {
		ev.Content = &event.Content{PromptText: text}
	}
	switch {
	case r.ContentBytes.ok && r.ContentBytes.v > 0 && r.ContentBytes.v < 1<<31:
		// "Mapped message-body byte count before numbat's 1 MiB bound and
		// output redaction": the size of what the user actually sent.
		p.Len = int(r.ContentBytes.v)
	default:
		p.Len = len(text)
	}
	ev.Prompt = p
}

// tool fills Tool, Target, Outcome and Content for an action or permission
// record.
func (c *nctx) tool(ev *event.Event, act numbatAction) {
	r := c.r
	et := string(r.EventType)
	agent := ev.Agent.ID
	t := &event.Tool{}
	t.Name = field(ev, "tool.name", string(r.ToolName), maxName)
	t.UseID = field(ev, "tool.use_id", string(r.ToolCallID), maxID)

	kind, server, mcpTool := event.ToolKind(""), "", ""
	if t.Name != "" {
		kind, server, mcpTool = toolmap.Kind(agent, t.Name)
	}
	switch {
	case r.MCPServer != "":
		// MCP is a facet of a tool action in numbat: the canonical fetch
		// server's call is a network.indicator that keeps its MCP fields.
		// It is still an MCP call, and the URL goes to Target.
		kind, server, mcpTool = event.ToolMCP, string(r.MCPServer), string(r.MCPTool)
	case act.kind == event.ToolFileWrite && kind == event.ToolFileEdit:
		// numbat has one write type; the tool name tells edit from create.
	case act.kind == event.ToolWebFetch && (kind == event.ToolWebSearch || kind == event.ToolBrowser):
		// Likewise for search and browser tools among network requests.
	case act.kind != "":
		kind = act.kind
	case kind == "":
		kind = event.ToolOther
	}
	t.Kind = kind
	t.MCPServer, _ = cleanID(server, maxName)
	t.MCPTool, _ = cleanID(mcpTool, maxName)
	if et == "file.delete" {
		setLabel(ev, "file_op", "delete")
	}
	// numbat's diff_sha256 is an unkeyed hash of the change a tool made, so
	// it is not relayed: a reader could confirm a guessed edit (a password
	// written into a config file) by hashing it. The size is kept.
	if r.DiffBytes.ok {
		setLabel(ev, "diff_bytes", itoa(r.DiffBytes.v))
	}

	// The principal fields numbat extracted are authoritative for Target;
	// they are present in every content mode.
	tg := &event.Target{}
	tg.Command = strings.ToValidUTF8(string(r.Command), "�")
	if p := string(r.FilePath); p != "" {
		tg.Path = pathField(ev, "target.path", p)
	}
	if u := string(r.URL); u != "" {
		clean, host := toolmap.CleanURL(u)
		if clean != "" {
			tg.URL, tg.Host = clean, host
		}
	}

	// Content for local detection: the real arguments when numbat exported
	// them (--content full|raw), else an input rebuilt from the principal
	// fields under the argument names the detection features look for.
	input, exported := c.toolInput(ev)
	if input == nil {
		input = map[string]any{}
		if tg.Command != "" {
			input["command"] = tg.Command
		}
		if tg.Path != "" {
			input["file_path"] = tg.Path
		}
		if tg.URL != "" {
			input["url"] = string(r.URL)
		}
		if len(input) == 0 {
			input = nil
		}
	}
	if tg.Command == "" && tg.Path == "" && tg.URL == "" {
		tg = nil
		if exported {
			tg = toolmap.Target(agent, t.Name, t.Kind, input)
		}
	}
	ev.Target = tg
	if input != nil {
		c.content(ev).ToolInput = input
		if exported {
			// No InputSHA256: with --content full the arguments are
			// redacted, so the hash would not match another surface's.
			t.InputKeys = toolmap.InputKeys(input)
		}
	}
	if r.ToolInputBytes.ok {
		setLabel(ev, "tool_input_bytes", itoa(r.ToolInputBytes.v))
	}
	if r.ToolInputTruncated.v {
		ev.Truncated = appendUnique(ev.Truncated, "tool.input")
	}
	if out := string(r.ToolResult); out != "" {
		c.content(ev).ToolOutput = out
	}
	if r.ToolResultBytes.ok && r.ToolResultBytes.v >= 0 && r.ToolResultBytes.v < 1<<31 {
		t.OutputLen = int(r.ToolResultBytes.v)
	}
	if r.ToolResultTruncated.v {
		ev.Truncated = appendUnique(ev.Truncated, "tool.output")
	}
	ev.Tool = t
	ev.Outcome = c.outcome(et)
	if r.ApprovalRequired.ok {
		setLabel(ev, "approval_required", boolText(r.ApprovalRequired.v))
	}
}

// toolInput decodes numbat's tool_input, a JSON document encoded as a
// string ("explicit JSON null is the string \"null\""). exported is true
// when the record carried the member at all.
func (c *nctx) toolInput(ev *event.Event) (input map[string]any, exported bool) {
	text := strings.TrimSpace(string(c.r.ToolInput))
	if text == "" || text == "null" {
		return nil, false
	}
	if text[0] == '{' && depthWithin(text, 64) {
		var m map[string]any
		if json.Unmarshal([]byte(text), &m) == nil && m != nil {
			return m, true
		}
	}
	// An array, a scalar, a fragment numbat marked as truncated, or nesting
	// deeper than anything a tool takes: keep the text for content scans.
	return map[string]any{"_raw": text}, true
}

func (c *nctx) content(ev *event.Event) *event.Content {
	if ev.Content == nil {
		ev.Content = &event.Content{}
	}
	return ev.Content
}

// outcome maps numbat's decision vocabulary (allowed | denied | asked) and
// result fields.
func (c *nctx) outcome(et string) *event.Outcome {
	r := c.r
	o := &event.Outcome{}
	decision := string(r.Decision)
	switch et {
	case "permission.requested":
		decision = "asked"
	case "permission.approved":
		decision = "allowed"
	case "permission.denied":
		decision = "denied"
	}
	if decision == "" {
		decision = string(r.ApprovalDecision)
	}
	switch decision {
	case "allowed":
		o.Decision = "allow"
	case "denied":
		o.Decision, o.Status = "deny", "denied"
	case "asked":
		o.Decision = "ask"
	}
	if et == "command.result" || et == "tool.result" {
		if o.Status == "" {
			o.Status = "unknown"
		}
		// "An absent exit_code means the source did not provide one; it
		// does not mean success."
		if r.ExitCode.ok && r.ExitCode.v >= -1<<31 && r.ExitCode.v < 1<<31 {
			code := int(r.ExitCode.v)
			o.ExitCode = &code
			if o.Status == "unknown" {
				o.Status = "ok"
				if code != 0 {
					o.Status = "error"
				}
			}
		}
		if r.DurationMS.ok && r.DurationMS.v >= 0 {
			o.DurationMS = r.DurationMS.v
		}
	}
	if *o == (event.Outcome{}) {
		return nil
	}
	return o
}

func boolText(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
