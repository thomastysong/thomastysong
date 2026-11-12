package hookcmd

import (
	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// maxAncestors bounds the names recorded above the caller.
const maxAncestors = 8

// markerVars are agent marker variables whose NAMES are recorded in
// Process.EnvMarkers, and the variables hookio reads for session and
// project fallbacks. Values never leave the process except where hookio
// copies a session id into Session.
var markerVars = []string{
	"CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "CLAUDE_CODE_REMOTE", "CLAUDE_CODE_SESSION_ID", "CLAUDE_PROJECT_DIR",
	"CODEX_SESSION_ID", "CODEX_THREAD_ID", "CODEX_VERSION",
	"COPILOT_CLI", "AI_AGENT",
	"CURSOR_PROJECT_DIR", "CURSOR_VERSION",
	"GEMINI_CWD", "GEMINI_PROJECT_DIR", "GEMINI_SESSION_ID",
}

// hookEnv builds the environment map hookio's Parse and Detect read. Only
// the variables hookio consults are copied, so nothing else in the
// developer's environment reaches the parser.
func hookEnv(getenv func(string) string, flagEvent string) (env map[string]string, markers []string) {
	env = make(map[string]string, len(markerVars)+1)
	for _, k := range markerVars {
		if v := getenv(k); v != "" {
			env[k] = v
			markers = append(markers, k)
		}
	}
	if v := getenv("HAWKBELL_HOOK_EVENT"); v != "" {
		env["HAWKBELL_HOOK_EVENT"] = v
	}
	if flagEvent != "" {
		env["HAWKBELL_HOOK_EVENT"] = flagEvent
	}
	return env, markers
}

// callerProcess describes the process that invoked the hook: its pid, its
// parent, its start time, its executable and the names of up to eight
// ancestors (parent first). The hook is a child of the agent (or of a shell
// the agent started), so (pid, start time) here is the one exact join key
// between this event and EDR process telemetry. Exe is the only field the
// kernel vouches for; names can be set by the process itself.
func callerProcess(ppid int) (p *event.Process) {
	p = &event.Process{PID: ppid}
	defer func() {
		if recover() != nil {
			p = &event.Process{PID: ppid}
		}
	}()
	if ppid <= 0 {
		return p
	}
	fillChain(p)
	return p
}
