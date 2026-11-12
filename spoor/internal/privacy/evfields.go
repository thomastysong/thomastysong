package privacy

import (
	"sort"
	"strings"

	"github.com/thomastysong/spoor/internal/event"
)

// Field accessors for detection evidence: each allowlisted field is read
// by its JSON name from the typed record (or from Content for the
// full-profile-only content fields), never by reflection over arbitrary
// names, so a rule cannot reach a field the allowlist does not name.

// eventField reads an allowlisted field by its JSON name. Identity fields
// are pseudonymized here exactly as Emit would.
func eventField(e *event.Event, f string) (any, bool) {
	head, rest, _ := strings.Cut(f, ".")
	str := func(s string) (any, bool) { return s, s != "" }
	strs := func(s []string) (any, bool) { return s, len(s) > 0 }
	num := func(n int) (any, bool) { return n, n != 0 }
	switch head {
	case "id":
		return str(e.ID)
	case "type":
		return str(e.Type)
	case "kind":
		return str(string(e.Kind))
	case "source":
		return str(string(e.Source))
	case "sources":
		if rest != "" {
			return nil, false
		}
		out := make([]string, len(e.Sources))
		for i, x := range e.Sources {
			out[i] = string(x)
		}
		return strs(out)
	case "fidelity":
		return str(string(e.Fidelity))
	case "integrity":
		return str(string(e.Integrity))
	case "host":
		if h := e.Host; h != nil {
			switch rest {
			case "id":
				return str(h.ID)
			case "name":
				return str(h.Name)
			case "os":
				return str(h.OS)
			case "arch":
				return str(h.Arch)
			}
		}
	case "user":
		if u := e.User; u != nil {
			switch rest {
			case "name":
				return str(u.Name)
			case "id":
				return str(u.ID)
			}
		}
	case "agent":
		if a := e.Agent; a != nil {
			switch rest {
			case "id":
				return str(a.ID)
			case "name":
				return str(a.Name)
			case "version":
				return str(a.Version)
			case "surface":
				return str(a.Surface)
			case "pid":
				return num(a.PID)
			}
		}
	case "account":
		if a := e.Account; a != nil {
			switch rest {
			case "kind":
				return str(a.Kind)
			case "org":
				return str(a.Org)
			}
		}
	case "session":
		if s := e.Session; s != nil {
			switch rest {
			case "id":
				return str(s.ID)
			case "parent_id":
				return str(s.ParentID)
			case "turn_id":
				return str(s.TurnID)
			case "permission_mode":
				return str(s.PermissionMode)
			case "model":
				return str(s.Model)
			case "subagent_id":
				return str(s.SubagentID)
			case "subagent_type":
				return str(s.SubagentType)
			case "cwd":
				return str(s.CWD)
			}
		}
	case "tool":
		return toolField(e, rest)
	case "target":
		if t := e.Target; t != nil {
			switch rest {
			case "command":
				return str(t.Command)
			case "path":
				return str(t.Path)
			case "paths":
				return strs(t.Paths)
			case "url":
				return str(t.URL)
			case "host":
				return str(t.Host)
			case "hosts":
				return strs(t.Hosts)
			case "query":
				return str(t.Query)
			}
		}
	case "prompt":
		if pr := e.Prompt; pr != nil || (e.Content != nil && e.Content.PromptText != "") {
			switch rest {
			case "len":
				if pr != nil && pr.Len > 0 {
					return pr.Len, true
				}
				if e.Content != nil {
					return num(len([]rune(e.Content.PromptText)))
				}
			case "text":
				if e.Content != nil && e.Content.PromptText != "" {
					return e.Content.PromptText, true
				}
				if pr != nil {
					return str(pr.Text)
				}
			}
		}
	case "content":
		if c := e.Content; c != nil {
			switch {
			case rest == "prompt_text":
				return str(c.PromptText)
			case rest == "tool_output":
				return str(c.ToolOutput)
			case rest == "file_content":
				return str(c.FileContent)
			case rest == "tool_input":
				return c.ToolInput, c.ToolInput != nil
			case strings.HasPrefix(rest, "tool_input."):
				return lookupAny(c.ToolInput, strings.TrimPrefix(rest, "tool_input."))
			}
		}
	case "outcome":
		if o := e.Outcome; o != nil {
			switch rest {
			case "status":
				return str(o.Status)
			case "decision":
				return str(o.Decision)
			case "decision_source":
				return str(o.DecisionSource)
			case "duration_ms":
				return int64(o.DurationMS), o.DurationMS != 0
			case "exit_code":
				if o.ExitCode != nil {
					return *o.ExitCode, true
				}
			}
		}
	case "process":
		if p := e.Process; p != nil {
			switch rest {
			case "pid":
				return num(p.PID)
			case "ppid":
				return num(p.PPID)
			case "name":
				return str(p.Name)
			case "exe":
				return str(p.Exe)
			case "args":
				return strs(p.Args)
			case "user":
				return str(p.User)
			case "ancestors":
				return strs(p.Ancestors)
			case "env_markers":
				return strs(p.EnvMarkers)
			case "flags":
				return strs(p.Flags)
			}
		}
	case "container":
		if c := e.Container; c != nil {
			switch rest {
			case "id":
				return str(c.ID)
			case "runtime":
				return str(c.Runtime)
			case "image":
				return str(c.Image)
			case "name":
				return str(c.Name)
			case "pod":
				return str(c.Pod)
			case "namespace":
				return str(c.Namespace)
			}
		}
	case "repo":
		if rp := e.Repo; rp != nil {
			switch rest {
			case "root":
				return str(rp.Root)
			case "remote":
				return str(rp.Remote)
			case "branch":
				return str(rp.Branch)
			}
		}
	case "asset":
		return assetField(e.Asset, rest)
	case "check":
		if c := e.Check; c != nil {
			switch rest {
			case "id":
				return str(c.ID)
			case "status":
				return str(c.Status)
			case "severity":
				return str(c.Severity)
			case "agent_id":
				return str(c.AgentID)
			case "scope":
				return str(string(c.Scope))
			case "subject":
				return str(c.Subject)
			case "expected":
				return str(c.Expected)
			case "actual":
				return str(c.Actual)
			}
		}
	}
	return nil, false
}

func toolField(e *event.Event, rest string) (any, bool) {
	t := e.Tool
	str := func(s string) (any, bool) { return s, s != "" }
	switch {
	case rest == "input":
		if e.Content != nil && e.Content.ToolInput != nil {
			return e.Content.ToolInput, true
		}
		if t != nil && t.Input != nil {
			return t.Input, true
		}
	case strings.HasPrefix(rest, "input."):
		key := strings.TrimPrefix(rest, "input.")
		if e.Content != nil && e.Content.ToolInput != nil {
			return lookupAny(e.Content.ToolInput, key)
		}
		if t != nil {
			return lookupAny(t.Input, key)
		}
	case rest == "output":
		if e.Content != nil && e.Content.ToolOutput != "" {
			return e.Content.ToolOutput, true
		}
		if t != nil {
			return str(t.Output)
		}
	}
	if t == nil {
		return nil, false
	}
	switch rest {
	case "name":
		return str(t.Name)
	case "kind":
		return str(string(t.Kind))
	case "use_id":
		return str(t.UseID)
	case "mcp_server":
		return str(t.MCPServer)
	case "mcp_tool":
		return str(t.MCPTool)
	case "input_keys":
		if len(t.InputKeys) > 0 {
			return t.InputKeys, true
		}
		if e.Content != nil && len(e.Content.ToolInput) > 0 {
			keys := make([]string, 0, len(e.Content.ToolInput))
			for k := range e.Content.ToolInput {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			return keys, true
		}
	case "output_len":
		if t.OutputLen > 0 {
			return t.OutputLen, true
		}
	}
	return nil, false
}

func assetField(a *event.Asset, rest string) (any, bool) {
	if a == nil {
		return nil, false
	}
	str := func(s string) (any, bool) { return s, s != "" }
	strs := func(s []string) (any, bool) { return s, len(s) > 0 }
	switch rest {
	case "id":
		return str(a.ID)
	case "kind":
		return str(string(a.Kind))
	case "name":
		return str(a.Name)
	case "vendor":
		return str(a.Vendor)
	case "version":
		return str(a.Version)
	case "catalog_id":
		return str(a.CatalogID)
	case "parent":
		return str(a.Parent)
	case "path":
		return str(a.Path)
	case "scope":
		return str(string(a.Scope))
	case "owner":
		return str(a.Owner)
	case "risk_flags":
		return strs(a.RiskFlags)
	case "change":
		return str(string(a.Change))
	case "confidence":
		return str(a.Confidence)
	case "signer":
		return str(a.Signer)
	}
	m := a.MCP
	if m == nil || !strings.HasPrefix(rest, "mcp.") {
		return nil, false
	}
	switch strings.TrimPrefix(rest, "mcp.") {
	case "transport":
		return str(m.Transport)
	case "command":
		return str(m.Command)
	case "args":
		return strs(m.Args)
	case "runner":
		return str(m.Runner)
	case "ecosystem":
		return str(m.Ecosystem)
	case "package":
		return str(m.Package)
	case "version":
		return str(m.Version)
	case "pinned":
		return m.Pinned, true
	case "url_host":
		return str(m.URLHost)
	case "env_keys":
		return strs(m.EnvKeys)
	case "header_keys":
		return strs(m.HeaderKeys)
	case "has_inline_secret":
		return m.HasInlineSecret, true
	case "auth_mode":
		return str(m.AuthMode)
	}
	return nil, false
}

// lookupAny follows a dotted path into decoded JSON.
func lookupAny(m map[string]any, path string) (any, bool) {
	var cur any = m
	for depth, part := range strings.Split(path, ".") {
		if depth > maxInputDeep {
			return nil, false
		}
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = mm[part]
		if !ok {
			return nil, false
		}
	}
	switch t := cur.(type) {
	case string:
		return t, t != ""
	case map[string]any:
		return t, true
	case []any:
		return map[string]any{"value": t}, true
	}
	if s, ok := renderScalar(cur); ok {
		return s, true
	}
	return nil, false
}
