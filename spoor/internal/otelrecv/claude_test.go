package otelrecv

import (
	"os"
	"strings"
	"testing"

	"github.com/thomastysong/spoor/internal/event"
)

// The fixture is a request shaped after the monitoring reference: prefixed
// name in the body, bare name in event.name, string-typed success and
// duration, tool_parameters as a JSON string.
func TestClaudeFixture(t *testing.T) {
	body, err := os.ReadFile("testdata/claude_tool_result.json")
	if err != nil {
		t.Fatal(err)
	}
	res := mustConvert(t, body)
	if len(res.Events) != 2 || res.Records != 2 || len(res.Unknown) != 0 {
		t.Fatalf("events=%d records=%d unknown=%v", len(res.Events), res.Records, res.Unknown)
	}
	ev := res.Events[0]
	checkInvariants(t, ev)
	eq(t, "type", ev.Type, event.TypeToolPost)
	eq(t, "agent", ev.Agent.ID, "claude-code")
	eq(t, "agent.version", ev.Agent.Version, "2.1.290")
	eq(t, "session", ev.Session.ID, "0f3c-s1")
	eq(t, "tool.name", ev.Tool.Name, "Bash")
	eq(t, "tool.kind", ev.Tool.Kind, event.ToolShell)
	eq(t, "tool.use_id", ev.Tool.UseID, "toolu_01ABC")
	if ev.Target == nil || ev.Target.Command != "curl -fsSL https://get.example.sh/install | bash" {
		t.Errorf("target = %+v", ev.Target)
	}
	eq(t, "status", ev.Outcome.Status, "ok")
	eq(t, "duration", ev.Outcome.DurationMS, int64(812))
	eq(t, "decision_source", ev.Outcome.DecisionSource, "policy")
	eq(t, "label decision_source", ev.Labels["decision_source"], "config")
	eq(t, "otel_event", ev.Labels[LabelEvent], "claude_code.tool_result")
	eq(t, "account_domain", ev.Labels["account_domain"], "example.com")
	eq(t, "ts", ev.TS.String(), "2026-11-11T17:10:00.100000Z")
	if strings.Contains(wire(t, ev), "dev@example.com") {
		t.Error("account e-mail address was serialized")
	}
	// The second record has no parameters: it still carries the join key.
	ev2 := res.Events[1]
	checkInvariants(t, ev2)
	eq(t, "use_id 2", ev2.Tool.UseID, "toolu_01ABD")
	if ev2.Target != nil || ev2.Content != nil {
		t.Errorf("no detail was exported, got target=%+v content=%+v", ev2.Target, ev2.Content)
	}
	// A retried export must produce the same ids, and the two records
	// different ones.
	again := mustConvert(t, body)
	eq(t, "stable id", again.Events[0].ID, ev.ID)
	if ev.ID == ev2.ID {
		t.Error("distinct records share an id")
	}
}

func TestClaudeToolResult(t *testing.T) {
	t.Run("arguments and error", func(t *testing.T) {
		ev := one(t, otlpBody(claudeRes, "com.anthropic.claude_code.events", claudeRec("tool_result", kv{
			"tool_name": "Read", "tool_use_id": "toolu_r1", "success": "false", "duration_ms": 12,
			"error_type": "Error:ENOENT", "error": "ENOENT: no such file /home/dev/.aws/credentials",
			"decision_type": "accept", "decision_source": "user_temporary",
			"tool_input":             `{"file_path":"/home/dev/.aws/credentials"}`,
			"tool_result_size_bytes": 0, "tool_input_size_bytes": 42,
			"app.entrypoint": "claude-vscode", "organization.id": "org-1234", "agent_id": "a3f2c1b4d5e6f7a80",
			"parent_agent_id": "aparent", "terminal.type": "vscode",
		})))
		eq(t, "kind", ev.Tool.Kind, event.ToolFileRead)
		eq(t, "path", ev.Target.Path, "/home/dev/.aws/credentials")
		eq(t, "status", ev.Outcome.Status, "error")
		eq(t, "error", ev.Outcome.Error, "Error:ENOENT")
		eq(t, "decision", ev.Outcome.Decision, "allow")
		eq(t, "decision_source", ev.Outcome.DecisionSource, "user")
		eq(t, "surface", ev.Agent.Surface, "ide")
		eq(t, "turn", ev.Session.TurnID, "prompt-1")
		eq(t, "subagent", ev.Session.SubagentID, "a3f2c1b4d5e6f7a80")
		eq(t, "parent_agent_id", ev.Labels["parent_agent_id"], "aparent")
		eq(t, "org", ev.Labels["org_id"], "org-1234")
		eq(t, "seq", ev.Labels["otel_seq"], "7")
		eq(t, "input bytes", ev.Labels["tool_input_bytes"], "42")
		if len(ev.Tool.InputKeys) != 1 || ev.Tool.InputKeys[0] != "file_path" {
			t.Errorf("input keys = %v", ev.Tool.InputKeys)
		}
		// Claude Code cuts argument values, so no hash may be claimed.
		eq(t, "input hash", ev.Tool.InputSHA256, "")
		if ev.Content == nil || ev.Content.ToolOutput == "" || ev.Content.ToolInput["file_path"] == nil {
			t.Fatalf("content = %+v", ev.Content)
		}
		if strings.Contains(wire(t, ev), "no such file") {
			t.Error("error message text was serialized")
		}
	})
	t.Run("mcp placeholder without detail", func(t *testing.T) {
		ev := one(t, otlpBody(claudeRes, "", claudeRec("tool_result", kv{
			"tool_name": "mcp_tool", "tool_use_id": "toolu_m1", "success": "true", "mcp_server_scope": "user",
		})))
		eq(t, "kind", ev.Tool.Kind, event.ToolMCP)
		eq(t, "name", ev.Tool.Name, "mcp_tool")
		eq(t, "server", ev.Tool.MCPServer, "")
		eq(t, "scope", ev.Labels["mcp_server_scope"], "user")
	})
	t.Run("mcp placeholder with detail", func(t *testing.T) {
		ev := one(t, otlpBody(claudeRes, "", claudeRec("tool_result", kv{
			"tool_name": "mcp_tool", "tool_use_id": "toolu_m2", "success": "true",
			"tool_parameters": `{"mcp_server_name":"github","mcp_tool_name":"create_issue"}`,
			"tool_input":      `{"repo":"acme/api","title":"x"}`,
		})))
		eq(t, "name", ev.Tool.Name, "mcp__github__create_issue")
		eq(t, "kind", ev.Tool.Kind, event.ToolMCP)
		eq(t, "server", ev.Tool.MCPServer, "github")
		eq(t, "tool", ev.Tool.MCPTool, "create_issue")
	})
	t.Run("real mcp name", func(t *testing.T) {
		ev := one(t, otlpBody(claudeRes, "", claudeRec("tool_result", kv{
			"tool_name": "mcp__jira__search", "tool_use_id": "toolu_m3", "success": "true",
		})))
		eq(t, "kind", ev.Tool.Kind, event.ToolMCP)
		eq(t, "server", ev.Tool.MCPServer, "jira")
		eq(t, "tool", ev.Tool.MCPTool, "search")
	})
	t.Run("sandbox bypass and commit", func(t *testing.T) {
		ev := one(t, otlpBody(claudeRes, "", claudeRec("tool_result", kv{
			"tool_name": "Bash", "tool_use_id": "toolu_b2", "success": "true",
			"tool_parameters": `{"bash_command":"git","full_command":"git commit -m x","dangerouslyDisableSandbox":true,"git_commit_id":"0123abcd","git_branch":"main"}`,
		})))
		eq(t, "command", ev.Target.Command, "git commit -m x")
		eq(t, "sandbox_bypass", ev.Labels["sandbox_bypass"], "1")
		eq(t, "git_commit", ev.Labels["git_commit"], "0123abcd")
		eq(t, "branch", ev.Repo.Branch, "main")
		// Rebuilt from the summary, not from real arguments.
		if ev.Tool.InputKeys != nil {
			t.Errorf("input keys invented: %v", ev.Tool.InputKeys)
		}
	})
	t.Run("arguments cut by the agent", func(t *testing.T) {
		ev := one(t, otlpBody(claudeRes, "", claudeRec("tool_result", kv{
			"tool_name": "Write", "tool_use_id": "toolu_w1", "success": "true",
			"tool_input": `{"file_path":"/tmp/x","content":"aaaaaaaa`,
		})))
		if len(ev.Truncated) != 1 || ev.Truncated[0] != "tool.input" {
			t.Errorf("truncated = %v", ev.Truncated)
		}
		if ev.Content.ToolInput["_raw"] == nil {
			t.Errorf("cut arguments not kept for local detection: %v", ev.Content.ToolInput)
		}
	})
	t.Run("opaque placeholder", func(t *testing.T) {
		ev := one(t, otlpBody(claudeRes, "", claudeRec("tool_result", kv{"tool_name": "skill_tool", "success": "true"})))
		eq(t, "kind", ev.Tool.Kind, event.ToolOther)
	})
}

func TestClaudeToolDecision(t *testing.T) {
	cases := []struct {
		name                   string
		a                      kv
		decision, status, src  string
		mode, kind, labelSrc   string
		wantLabelK, wantLabelV string
	}{
		{"hook reject", kv{"tool_name": "Bash", "tool_use_id": "t1", "decision": "reject", "source": "hook",
			"permission_mode": "default", "tool_source": "builtin",
			"tool_parameters": `{"bash_command":"rm","full_command":"rm -rf /"}`},
			"deny", "denied", "hook", "default", "shell", "hook", "tool_source", "builtin"},
		{"config accept in bypass", kv{"tool_name": "Write", "tool_use_id": "t2", "decision": "accept", "source": "config",
			"permission_mode": "bypassPermissions"},
			"allow", "", "policy", "bypass", "file_write", "config", "", ""},
		{"user abort", kv{"tool_name": "Edit", "tool_use_id": "t3", "decision": "reject", "source": "user_abort",
			"permission_mode": "acceptEdits"},
			"deny", "denied", "user", "accept_edits", "file_edit", "user_abort", "", ""},
		{"classifier block", kv{"tool_name": "WebFetch", "tool_use_id": "t4", "decision": "reject", "source": "config",
			"permission_mode": "auto", "classifier_verdict": "block", "classifier_category": "data_exfiltration"},
			"deny", "denied", "policy", "auto", "web_fetch", "config", "classifier_category", "data_exfiltration"},
		{"mcp source without name", kv{"tool_name": "mcp_tool", "tool_use_id": "t5", "decision": "accept",
			"source": "user_permanent", "tool_source": "mcp", "permission_mode": "dontAsk"},
			"allow", "", "user", "dont_ask", "mcp", "user_permanent", "tool_source", "mcp"},
		{"new mode passes through", kv{"tool_name": "Read", "decision": "accept", "source": "config",
			"permission_mode": "superSafeMode"},
			"allow", "", "policy", "super_safe_mode", "file_read", "config", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := one(t, otlpBody(claudeRes, "", claudeRec("tool_decision", tc.a)))
			eq(t, "type", ev.Type, event.TypePermissionDecision)
			eq(t, "decision", ev.Outcome.Decision, tc.decision)
			eq(t, "status", ev.Outcome.Status, tc.status)
			eq(t, "source", ev.Outcome.DecisionSource, tc.src)
			eq(t, "mode", ev.Session.PermissionMode, tc.mode)
			eq(t, "kind", string(ev.Tool.Kind), tc.kind)
			eq(t, "label source", ev.Labels["decision_source"], tc.labelSrc)
			if tc.wantLabelK != "" {
				eq(t, tc.wantLabelK, ev.Labels[tc.wantLabelK], tc.wantLabelV)
			}
		})
	}
	t.Run("rejected command is visible", func(t *testing.T) {
		ev := one(t, otlpBody(claudeRes, "", claudeRec("tool_decision", cases[0].a)))
		eq(t, "command", ev.Target.Command, "rm -rf /")
	})
	t.Run("unknown decision value", func(t *testing.T) {
		ev := one(t, otlpBody(claudeRes, "", claudeRec("tool_decision", kv{"tool_name": "Read", "decision": "defer"})))
		eq(t, "status", ev.Outcome.Status, "unknown")
		eq(t, "raw", ev.Labels["decision_raw"], "defer")
	})
}

func TestClaudeUserPrompt(t *testing.T) {
	// Assembled at run time so no credential-shaped literal is committed.
	secret := "my token is " + "sk-" + "ant-api03-" + strings.Repeat("A", 24)
	t.Run("redacted by default", func(t *testing.T) {
		ev := one(t, otlpBody(claudeRes, "", claudeRec("user_prompt", kv{
			"prompt_length": 48, "prompt": "<REDACTED>", "message.uuid": "0b1c-uuid", "command_name": "compact", "command_source": "builtin",
		})))
		eq(t, "type", ev.Type, event.TypePromptSubmit)
		eq(t, "len", ev.Prompt.Len, 48)
		eq(t, "unit", ev.Labels["prompt_len_unit"], "chars")
		eq(t, "uuid", ev.Labels["message_uuid"], "0b1c-uuid")
		eq(t, "command", ev.Labels["command"], "compact")
		if ev.Content != nil || ev.Prompt.Text != "" || ev.Prompt.SHA256 != "" {
			t.Errorf("content invented from a redacted prompt: %+v %+v", ev.Content, ev.Prompt)
		}
	})
	for _, key := range []string{"prompt", "prompt_text"} {
		t.Run("present in "+key, func(t *testing.T) {
			ev := one(t, otlpBody(claudeRes, "", claudeRec("user_prompt", kv{"prompt_length": 3, key: secret})))
			eq(t, "len", ev.Prompt.Len, len(secret))
			eq(t, "content", ev.Content.PromptText, secret)
			// Never serialized here, never hashed without the tenant key.
			if ev.Prompt.Text != "" || ev.Prompt.SHA256 != "" || strings.Contains(wire(t, ev), "sk-ant") {
				t.Errorf("prompt text left the Content holder: %s", wire(t, ev))
			}
		})
	}
}

func TestClaudeOtherEvents(t *testing.T) {
	cases := []struct {
		name   string
		a      kv
		typ    string
		labels map[string]string
		check  func(t *testing.T, ev *event.Event)
	}{
		{"permission_mode_changed", kv{"from_mode": "default", "to_mode": "bypassPermissions", "trigger": "shift_tab"},
			event.TypeConfigChange,
			map[string]string{"from_mode": "default", "to_mode": "bypass", "trigger": "shift_tab", "config_key": "permission_mode"},
			func(t *testing.T, ev *event.Event) { eq(t, "mode", ev.Session.PermissionMode, "bypass") }},
		{"mcp_server_connection", kv{"status": "failed", "transport_type": "stdio", "server_scope": "project",
			"duration_ms": 1500, "error_code": "ECONNREFUSED", "is_plugin": true, "plugin.name": "third-party",
			"plugin_id_hash": "ab12cd34", "server_name": "postgres", "error": "connect ECONNREFUSED 10.0.0.5:5432 password=hunter2"},
			event.TypeNotification,
			map[string]string{"mcp_status": "failed", "mcp_transport": "stdio", "mcp_scope": "project", "mcp_server": "postgres",
				"is_plugin": "true", "plugin": "third-party", "plugin_id_hash": "ab12cd34"},
			func(t *testing.T, ev *event.Event) {
				eq(t, "status", ev.Outcome.Status, "error")
				eq(t, "error", ev.Outcome.Error, "ECONNREFUSED")
				eq(t, "duration", ev.Outcome.DurationMS, int64(1500))
				if strings.Contains(wire(t, ev), "hunter2") {
					t.Error("connection error text was serialized")
				}
			}},
		{"plugin_installed", kv{"marketplace.is_official": "false", "install.trigger": "cli", "plugin.name": "evil-tools",
			"plugin.version": "1.2.3", "marketplace.name": "randos"},
			event.TypeConfigChange,
			map[string]string{"plugin": "evil-tools", "plugin_version": "1.2.3", "marketplace": "randos",
				"marketplace_official": "false", "install_trigger": "cli", "config_key": "plugin"}, nil},
		{"plugin_loaded", kv{"plugin.name": "third-party", "plugin.scope": "community", "enabled_via": "user-install",
			"plugin_id_hash": "ffee", "has_hooks": true, "has_mcp": false, "safe_mode": "false"},
			event.TypeNotification,
			map[string]string{"plugin": "third-party", "plugin_scope": "community", "enabled_via": "user-install",
				"has_hooks": "true", "has_mcp": "false"}, nil},
		{"skill_activated", kv{"skill.name": "custom_skill", "invocation_trigger": "claude-proactive", "skill.source": "projectSettings"},
			event.TypeNotification,
			map[string]string{"skill": "custom_skill", "skill_trigger": "claude-proactive", "skill_source": "projectSettings"}, nil},
		{"hook_registered", kv{"hook_event": "PreToolUse", "hook_type": "command", "hook_source": "policySettings"},
			event.TypeNotification,
			map[string]string{"hook_event": "PreToolUse", "hook_type": "command", "hook_source": "policySettings"}, nil},
		{"hook_execution_start", kv{"hook_event": "PreToolUse", "hook_name": "PreToolUse:Write", "num_hooks": 2,
			"managed_only": "true", "hook_source": "policySettings"},
			event.TypeNotification,
			map[string]string{"hook_event": "PreToolUse", "hook_name": "PreToolUse:Write", "hook_runs": "2", "managed_only": "true"},
			func(t *testing.T, ev *event.Event) {
				if _, _, ok := IsHookRun(ev); ok {
					t.Error("a start record must not count as a completed hook run")
				}
			}},
		{"subagent_completed", kv{"agent_type": "Explore", "agent.source": "built-in", "is_async": false,
			"total_tool_uses": 14, "duration_ms": 9000, "model": "claude-sonnet-5", "agent_id": "a1b2"},
			event.TypeSubagentStop, map[string]string{"agent_source": "built-in", "tool_uses": "14"},
			func(t *testing.T, ev *event.Event) {
				eq(t, "subagent type", ev.Session.SubagentType, "Explore")
				eq(t, "subagent id", ev.Session.SubagentID, "a1b2")
				eq(t, "duration", ev.Outcome.DurationMS, int64(9000))
			}},
		{"compaction", kv{"trigger": "auto", "success": "true", "duration_ms": 3000},
			event.TypeCompact, map[string]string{"compact_trigger": "auto"},
			func(t *testing.T, ev *event.Event) { eq(t, "status", ev.Outcome.Status, "ok") }},
		{"auth", kv{"action": "login", "success": "false", "auth_method": "oauth", "error_category": "network"},
			event.TypeNotification, map[string]string{"auth_action": "login", "auth_method": "oauth"},
			func(t *testing.T, ev *event.Event) {
				eq(t, "status", ev.Outcome.Status, "error")
				eq(t, "error", ev.Outcome.Error, "network")
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := one(t, otlpBody(claudeRes, "", claudeRec(tc.name, tc.a)))
			eq(t, "type", ev.Type, tc.typ)
			eq(t, "otel_event", ev.Labels[LabelEvent], "claude_code."+tc.name)
			for k, v := range tc.labels {
				eq(t, "label "+k, ev.Labels[k], v)
			}
			if tc.check != nil {
				tc.check(t, ev)
			}
		})
	}
}

func TestClaudeHookExecutionComplete(t *testing.T) {
	ev := one(t, otlpBody(claudeRes, "", claudeRec("hook_execution_complete", kv{
		"hook_event": "PreToolUse", "hook_name": "PreToolUse:Bash", "num_hooks": 3, "num_success": 2,
		"num_blocking": 1, "num_non_blocking_error": 0, "num_cancelled": 0, "total_duration_ms": 41,
		"managed_only": "true", "hook_source": "policySettings",
	})))
	eq(t, "type", ev.Type, event.TypeNotification)
	eq(t, "otel_event", ev.Labels[LabelEvent], "claude_code.hook_execution_complete")
	eq(t, "hook_event", ev.Labels[LabelHookEvent], "PreToolUse")
	eq(t, "hooks_blocking", ev.Labels["hooks_blocking"], "1")
	eq(t, "status", ev.Outcome.Status, "denied")
	eq(t, "decision source", ev.Outcome.DecisionSource, "hook")
	eq(t, "duration", ev.Outcome.DurationMS, int64(41))
	hook, runs, ok := IsHookRun(ev)
	if !ok || hook != "PreToolUse" || runs != 3 {
		t.Errorf("IsHookRun = %q %d %v", hook, runs, ok)
	}
	if ev.Tool != nil {
		t.Error("a hook run is not a tool call")
	}

	for name, a := range map[string]kv{
		"error":       {"hook_event": "Stop", "num_hooks": 1, "num_non_blocking_error": 1},
		"interrupted": {"hook_event": "Stop", "num_hooks": 1, "num_cancelled": 1},
		"ok":          {"hook_event": "Stop", "num_hooks": 1, "num_success": 1},
	} {
		ev := one(t, otlpBody(claudeRes, "", claudeRec("hook_execution_complete", a)))
		eq(t, name, ev.Outcome.Status, name)
	}
	if _, _, ok := IsHookRun(nil); ok {
		t.Error("IsHookRun(nil)")
	}
	if _, _, ok := IsHookRun(&event.Event{Source: event.SourceHook, Type: event.TypeNotification,
		Labels: map[string]string{LabelEvent: "claude_code.hook_execution_complete"}}); ok {
		t.Error("only otel records count")
	}
}

func TestClaudeManagedSettings(t *testing.T) {
	ev := one(t, otlpBody(claudeRes, "", claudeRec("managed_settings_resolved", kv{
		"managed_settings.trigger":         "startup",
		"managed_settings.sources":         []string{"remote", "file"},
		"managed_settings.source_behavior": "first-wins",
		"managed_settings.helper.state":    "none",
		"managed_settings.helper.applied":  "none",
		"managed_settings.resolved_sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		"managed_settings.settings":        `{"apiKeyHelper":"[REDACTED]","permissions":{"deny":["Read([REDACTED])"]}}`,
	})))
	eq(t, "type", ev.Type, event.TypeConfigChange)
	eq(t, "trigger", ev.Labels["managed_trigger"], "startup")
	eq(t, "sources", ev.Labels["managed_sources"], "remote,file")
	eq(t, "behavior", ev.Labels["managed_source_behavior"], "first-wins")
	eq(t, "sha", ev.Labels["managed_settings_sha256"], "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
	if ev.Outcome != nil {
		t.Errorf("startup is not a refusal: %+v", ev.Outcome)
	}
	if strings.Contains(wire(t, ev), "apiKeyHelper") {
		t.Error("settings document was copied")
	}

	ref := one(t, otlpBody(claudeRes, "", claudeRec("managed_settings_resolved", kv{
		"managed_settings.trigger": "refused", "error.type": "version_below_minimum",
		"managed_settings.sources": []string{},
	})))
	eq(t, "refused status", ref.Outcome.Status, "denied")
	eq(t, "refused error", ref.Outcome.Error, "version_below_minimum")
	if _, ok := ref.Labels["managed_sources"]; ok {
		t.Error("empty source list must not produce a label")
	}
}

func TestClaudeIdentification(t *testing.T) {
	a := kv{"event.name": "tool_result", "session.id": "s", "tool_name": "Bash", "success": "true"}
	t.Run("body prefix with renamed service", func(t *testing.T) {
		// OTEL_SERVICE_NAME can rename the service; the body still names the agent.
		ev := one(t, otlpBody(kv{"service.name": "my-team-claude"}, "", logRec(baseNano, "claude_code.tool_result", a)))
		eq(t, "agent", ev.Agent.ID, "claude-code")
	})
	t.Run("service name with bare event name", func(t *testing.T) {
		ev := one(t, otlpBody(kv{"service.name": "claude-code-desktop"}, "", logRec(baseNano, "", a)))
		eq(t, "agent", ev.Agent.ID, "claude-code")
		eq(t, "surface", ev.Agent.Surface, "desktop")
	})
	t.Run("scope name", func(t *testing.T) {
		ev := one(t, otlpBody(kv{}, "com.anthropic.claude_code.events", logRec(baseNano, "", a)))
		eq(t, "agent", ev.Agent.ID, "claude-code")
	})
	t.Run("eventName field", func(t *testing.T) {
		r := logRec(baseNano, "", kv{"session.id": "s", "tool_name": "Bash", "success": "true"})
		r["eventName"] = "claude_code.tool_result"
		ev := one(t, otlpBody(kv{}, "", r))
		eq(t, "type", ev.Type, event.TypeToolPost)
	})
	t.Run("standard attributes on the resource", func(t *testing.T) {
		ev := one(t, otlpBody(kv{"service.name": "claude-code", "session.id": "from-resource", "organization.id": "org-r",
			"vcs.repository.url.full": "https://user:pw@github.com/acme/api"}, "", logRec(baseNano, "claude_code.tool_result",
			kv{"event.name": "tool_result", "tool_name": "Bash", "success": "true"})))
		eq(t, "session", ev.Session.ID, "from-resource")
		eq(t, "org", ev.Labels["org_id"], "org-r")
		eq(t, "repo", ev.Repo.Remote, "https://github.com/acme/api")
	})
}
