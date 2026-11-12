package hookio_test

import (
	"errors"
	"fmt"
	"strings"

	"github.com/thomastysong/thomastysong/hawkbell/internal/hookio"
)

// The hook entrypoint in three steps: read bounded stdin, parse with the
// agent's dialect, and answer with whatever the policy decided.
func Example() {
	stdin := strings.NewReader(`{"session_id":"abc123","cwd":"/home/u/proj","permission_mode":"default",
		"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"cat ~/.ssh/id_rsa"},"tool_use_id":"toolu_01"}`)

	payload, err := hookio.ReadInput(stdin)
	if err != nil && !errors.Is(err, hookio.ErrTooLarge) {
		return // exit 0: never stand in the agent's way because stdin failed
	}
	d, ok := hookio.Get("claude") // or hookio.Detect(payload, env) without --agent
	if !ok {
		return
	}
	events, req, err := d.Parse(payload, map[string]string{})
	if err != nil && len(events) == 0 {
		return // not a hook payload: exit 0, report a health error
	}
	e := events[0]
	fmt.Println(e.Type, e.Tool.Kind, e.Target.Command, "blocking:", req.Blocking)

	// ... redaction, detection and the sink run here ...
	decision := hookio.Decision{Action: hookio.ActionDeny, Reason: "reads an SSH private key", RuleID: "HB-0042"}

	stdout, stderr, exit := d.Respond(req, decision)
	fmt.Printf("exit=%d stderr=%q\n%s", exit, stderr, stdout)
	// Output:
	// tool.pre shell cat ~/.ssh/id_rsa blocking: true
	// exit=0 stderr=""
	// {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"hawkbell: reads an SSH private key [HB-0042]"}}
}

// The same decision rendered for Codex: the JSON block Codex honours on
// exit 0, never exit code 2.
func ExampleDialect_codex() {
	d, _ := hookio.Get("codex")
	_, req, _ := d.Parse([]byte(`{"session_id":"t1","turn_id":"turn-1","cwd":"/w","model":"gpt-5.2-codex","permission_mode":"default",
		"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"cat ~/.ssh/id_rsa"},"tool_use_id":"call_1","transcript_path":null}`), nil)
	stdout, stderr, exit := d.Respond(req, hookio.Decision{Action: hookio.ActionDeny, Reason: "reads an SSH private key", RuleID: "HB-0042"})
	fmt.Printf("exit=%d stderr=%q\n%s", exit, stderr, stdout)
	// Output:
	// exit=0 stderr=""
	// {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"hawkbell: reads an SSH private key [HB-0042]"}}
}

// What an installer needs for one agent's hook configuration.
func ExampleDialect_events() {
	d, _ := hookio.Get("gemini")
	for _, he := range d.Events() {
		fmt.Printf("%-13s blocking=%-5v async=%v\n", he.Name, he.Blocking, he.Async)
	}
	// Output:
	// SessionStart  blocking=false async=false
	// BeforeAgent   blocking=true  async=false
	// BeforeTool    blocking=true  async=false
	// AfterTool     blocking=false async=false
	// AfterAgent    blocking=false async=false
	// Notification  blocking=false async=false
	// PreCompress   blocking=false async=false
	// SessionEnd    blocking=false async=false
}
