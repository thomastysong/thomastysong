package hookio

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/thomastysong/spoor/internal/event"
)

type fixtureCase struct {
	dialect string
	file    string // relative to testdata, slash-separated
	env     map[string]string
}

// allFixtures lists every recorded payload with the dialect that owns it.
// Copilot camelCase payloads do not name their event, so the name is passed
// the way the hook entrypoint would pass it.
func allFixtures(t testing.TB) []fixtureCase {
	t.Helper()
	var out []fixtureCase
	for _, id := range []string{"claude", "codex", "copilot", "gemini", "cursor"} {
		entries, err := os.ReadDir(filepath.Join("testdata", id))
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".json") {
				continue
			}
			fc := fixtureCase{dialect: id, file: id + "/" + e.Name()}
			if id == "copilot" && strings.Contains(e.Name(), ".camel") {
				fc.env = map[string]string{EnvHookEvent: strings.SplitN(e.Name(), ".", 2)[0]}
			}
			out = append(out, fc)
		}
	}
	if len(out) < 100 {
		t.Fatalf("only %d fixtures found", len(out))
	}
	return out
}

func TestGetAndAll(t *testing.T) {
	all := All()
	var ids []string
	for _, d := range all {
		ids = append(ids, d.ID())
	}
	eq(t, "dialect ids", ids, []string{"claude", "codex", "copilot", "gemini", "cursor"})

	for alias, want := range map[string]string{
		"claude": "claude", "claude-code": "claude", " Claude-Code ": "claude",
		"codex":   "codex",
		"copilot": "copilot", "copilot-cli": "copilot", "github-copilot": "copilot",
		"gemini": "gemini", "gemini-cli": "gemini",
		"cursor": "cursor",
	} {
		d, ok := Get(alias)
		if !ok || d.ID() != want {
			t.Errorf("Get(%q) = %v, %v; want %s", alias, d, ok, want)
		}
	}
	for _, bad := range []string{"", "windsurf", "../claude", "claude\x00", "claude/../codex"} {
		if d, ok := Get(bad); ok {
			t.Errorf("Get(%q) = %s, want not found", bad, d.ID())
		}
	}

	for dialectID, agent := range map[string]string{
		"claude": "claude-code", "codex": "codex", "copilot": "copilot-cli", "gemini": "gemini-cli", "cursor": "cursor",
	} {
		got, ok := AgentIDFor(dialectID)
		if !ok || got != agent {
			t.Errorf("AgentIDFor(%s) = %q, %v", dialectID, got, ok)
		}
	}
	if _, ok := AgentIDFor("nope"); ok {
		t.Error("AgentIDFor accepted an unknown dialect")
	}
}

// Events is what the installer turns into agent config, so its internal
// consistency matters more than its content.
func TestEventsLists(t *testing.T) {
	asyncCapable := map[string]bool{"claude": true, "codex": true}
	for _, d := range All() {
		evs := d.Events()
		if len(evs) < 8 {
			t.Errorf("%s: only %d events", d.ID(), len(evs))
		}
		seen := map[string]bool{}
		var blocking []string
		for _, he := range evs {
			if he.Name == "" || seen[he.Name] {
				t.Errorf("%s: empty or duplicate event %q", d.ID(), he.Name)
			}
			seen[he.Name] = true
			if he.Blocking && he.Async {
				t.Errorf("%s/%s: an async hook cannot gate anything", d.ID(), he.Name)
			}
			if he.Async && !asyncCapable[d.ID()] {
				t.Errorf("%s/%s: agent has no async hooks", d.ID(), he.Name)
			}
			if he.Matcher != "" {
				t.Errorf("%s/%s: matcher %q; empty (match all) is the only portable value", d.ID(), he.Name, he.Matcher)
			}
			if he.Blocking {
				blocking = append(blocking, he.Name)
			}

			// Each registered event must be one the dialect maps, and its
			// Blocking flag must agree with what Parse reports.
			payload := `{"hook_event_name":"` + he.Name + `","session_id":"s","conversation_id":"s","source":"user_settings"}`
			es, req, err := d.Parse([]byte(payload), nil)
			if err != nil || len(es) == 0 {
				t.Errorf("%s/%s: registered event does not parse: %v", d.ID(), he.Name, err)
				continue
			}
			if es[0].Labels["hook_unmapped"] != "" {
				t.Errorf("%s/%s: registered event is unmapped", d.ID(), he.Name)
			}
			if req.Blocking != he.Blocking {
				t.Errorf("%s/%s: Events says blocking=%v, Parse says %v", d.ID(), he.Name, he.Blocking, req.Blocking)
			}
		}
		if !seen[firstOf(evs, event.TypeToolPre, d)] {
			t.Errorf("%s: no pre-tool event registered", d.ID())
		}
		if len(blocking) == 0 {
			t.Errorf("%s: nothing gateable registered", d.ID())
		}
		// Callers get a copy.
		evs[0].Name = "mutated"
		if d.Events()[0].Name == "mutated" {
			t.Errorf("%s: Events exposes internal state", d.ID())
		}
	}

	// Events that must never be registered for spoor.
	for _, he := range dialect(t, "claude").Events() {
		switch he.Name {
		case "WorktreeCreate", "WorktreeRemove", "MessageDisplay", "PreCompact":
			t.Errorf("claude: %s must not be registered (its stdout or exit code changes agent behaviour)", he.Name)
		}
	}
	for _, he := range dialect(t, "gemini").Events() {
		switch he.Name {
		case "AfterModel", "BeforeModel", "BeforeToolSelection":
			t.Errorf("gemini: %s must not be registered (per-chunk, whole LLM requests)", he.Name)
		}
	}
}

// firstOf returns the name of the first registered event that maps to typ.
func firstOf(evs []HookEvent, typ string, d Dialect) string {
	for _, he := range evs {
		es, _, err := d.Parse([]byte(`{"hook_event_name":"`+he.Name+`","conversation_id":"s"}`), nil)
		if err == nil && len(es) > 0 && es[0].Type == typ {
			return he.Name
		}
	}
	return ""
}

// Every fixture parses under its own dialect with a known event type, and
// the set of types the package emits stays inside the event vocabulary.
func TestAllFixturesParse(t *testing.T) {
	valid := map[string]bool{
		event.TypeSessionStart: true, event.TypeSessionEnd: true, event.TypePromptSubmit: true,
		event.TypeToolPre: true, event.TypeToolPost: true, event.TypeTurnEnd: true,
		event.TypeSubagentStart: true, event.TypeSubagentStop: true, event.TypePermissionDecision: true,
		event.TypeConfigChange: true, event.TypeNotification: true, event.TypeCompact: true,
	}
	types := map[string]bool{}
	for _, tc := range allFixtures(t) {
		d := dialect(t, tc.dialect)
		evs, req, err := d.Parse(fixture(t, tc.file), tc.env)
		if err != nil {
			t.Errorf("%s: %v", tc.file, err)
			continue
		}
		for _, e := range evs {
			checkInvariants(t, d, e, req)
			if !valid[e.Type] {
				t.Errorf("%s: type %q is not an activity type", tc.file, e.Type)
			}
			if e.Labels["hook_unmapped"] != "" {
				t.Errorf("%s: fixture event is unmapped", tc.file)
			}
			types[e.Type] = true
		}
	}
	var got []string
	for k := range types {
		got = append(got, k)
	}
	sort.Strings(got)
	if len(got) != len(valid) {
		t.Errorf("fixtures cover %d of %d event types: %v", len(got), len(valid), got)
	}
}

// Every hook event each agent documents (research/agent-surfaces-a.md) has
// an explicit mapping, so none of them falls through to "unmapped".
func TestDocumentedEventsAreMapped(t *testing.T) {
	documented := map[string]string{
		"claude": "SessionStart, Setup, InstructionsLoaded, UserPromptSubmit, UserPromptExpansion, MessageDisplay, PreToolUse, PermissionRequest, PermissionDenied, PostToolUse, PostToolUseFailure, PostToolBatch, Notification, SubagentStart, SubagentStop, TaskCreated, TaskCompleted, Stop, StopFailure, TeammateIdle, ConfigChange, CwdChanged, DirectoryAdded, FileChanged, WorktreeCreate, WorktreeRemove, PreCompact, PostCompact, PreModelSwitch, PostModelSwitch, Elicitation, ElicitationResult, SessionEnd",
		"codex":  "PreToolUse, PermissionRequest, PostToolUse, PreCompact, PostCompact, SessionStart, SessionEnd, UserPromptSubmit, Stop, SubagentStart, SubagentStop, Interrupt, PreModelRequest, PostModelRequest",
		"copilot": "sessionStart, sessionEnd, userPromptSubmitted, userPromptTransformed, preToolUse, postToolUse, postToolUseFailure, agentStop, subagentStart, subagentStop, errorOccurred, preCompact, permissionRequest, notification, " +
			"SessionStart, SessionEnd, UserPromptSubmit, PreToolUse, PostToolUse, PostToolUseFailure, Stop, SubagentStop, ErrorOccurred, PreCompact, PermissionRequest",
		"gemini": "BeforeTool, AfterTool, BeforeAgent, AfterAgent, BeforeModel, AfterModel, BeforeToolSelection, SessionStart, SessionEnd, Notification, PreCompress",
		"cursor": "beforeSubmitPrompt, beforeShellExecution, afterShellExecution, beforeMCPExecution, afterMCPExecution, beforeReadFile, afterFileEdit, afterAgentResponse, afterAgentThought, stop, preToolUse, postToolUse, postToolUseFailure, sessionStart, sessionEnd, subagentStart, subagentStop",
	}
	wantCount := map[string]int{"claude": 33, "codex": 14, "copilot": 25, "gemini": 11, "cursor": 17}
	for id, list := range documented {
		names := strings.Split(list, ", ")
		eq(t, id+" documented event count", len(names), wantCount[id])
		d := dialect(t, id)
		for _, name := range names {
			evs, req, err := d.Parse([]byte(`{"hook_event_name":"`+name+`","session_id":"s","sessionId":"s","conversation_id":"s"}`), nil)
			if err != nil || len(evs) == 0 {
				t.Errorf("%s/%s: %v", id, name, err)
				continue
			}
			if evs[0].Labels["hook_unmapped"] != "" {
				t.Errorf("%s/%s is not mapped", id, name)
			}
			eq(t, id+"/"+name+" request event", req.EventName, name)
		}
	}
}
