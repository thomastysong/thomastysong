package hookio

import (
	"errors"
	"fmt"
	"runtime"
	"strings"

	"github.com/thomastysong/spoor/internal/event"
)

// Decision actions.
const (
	ActionNone  = "none"
	ActionAllow = "allow"
	ActionDeny  = "deny"
	ActionAsk   = "ask"
)

// Input limits applied before any JSON decoding.
const (
	// MaxInput is the largest hook payload Parse decodes.
	MaxInput = 8 << 20
	// MaxDepth is the deepest object/array nesting Parse decodes.
	MaxDepth = 64
)

// EnvHookEvent names the environment variable that supplies the hook event
// name when the payload does not carry one (Copilot's camelCase payloads).
// The hook entrypoint sets it from its --event flag, or the hook config sets
// it through the agent's per-hook env map.
const EnvHookEvent = "SPOOR_HOOK_EVENT"

// Agent ids, as used in event.Agent.ID and the catalog.
const (
	AgentClaude  = "claude-code"
	AgentCodex   = "codex"
	AgentCopilot = "copilot-cli"
	AgentGemini  = "gemini-cli"
	AgentCursor  = "cursor"
)

// Errors returned by Parse. They never quote payload content.
var (
	ErrEmpty     = errors.New("hookio: empty hook input")
	ErrTooLarge  = errors.New("hookio: hook input exceeds the 8 MiB cap")
	ErrTooDeep   = errors.New("hookio: hook input nests deeper than 64 levels")
	ErrMalformed = errors.New("hookio: hook input is not one JSON object")
	ErrNoEvent   = errors.New("hookio: hook input names no event")
	ErrInternal  = errors.New("hookio: internal error")
)

// Decision is what spoor wants the agent to do with the hooked action.
type Decision struct {
	Action string // none | allow | deny | ask
	Reason string
	RuleID string
}

// Request is the context Respond needs about the invocation Parse decoded.
type Request struct {
	AgentID   string
	EventName string // the agent's own hook event name
	// Blocking is true when the agent will honour a deny for this event
	// (pre-tool, prompt submit, permission request, and Claude Code's
	// ConfigChange for non-policy sources).
	Blocking bool
	Raw      map[string]any
}

// Dialect is one agent's hook wire format.
type Dialect interface {
	// ID is the dialect name: claude | codex | copilot | gemini | cursor.
	ID() string
	// Parse converts one hook invocation (stdin bytes) into normalized
	// events (usually one). env is the hook process environment, used for
	// session and project fallbacks. Input is capped at MaxInput bytes and
	// MaxDepth levels; on ErrTooLarge and ErrTooDeep the returned events and
	// request are a best-effort salvage and are still valid to emit.
	Parse(stdin []byte, env map[string]string) ([]*event.Event, *Request, error)
	// Respond renders the agent-specific reply. For Action "none" (and for
	// any action on an event the agent will not gate) it returns empty
	// stdout, empty stderr and exit code 0, which every supported agent
	// treats as "proceed unchanged".
	Respond(req *Request, d Decision) (stdout []byte, stderr []byte, exitCode int)
	// Events lists the agent hook event names spoor wants registered, and
	// whether each should be registered async (pure telemetry) when the
	// agent supports it.
	Events() []HookEvent
}

// HookEvent is one hook registration spoor asks for.
type HookEvent struct {
	Name string
	// Matcher is the agent's matcher value. Empty means "match everything":
	// omit the matcher field from the generated config. A literal "*" is not
	// used because Copilot compiles matchers as anchored regular expressions
	// and skips a hook whose pattern does not compile.
	Matcher string
	// Async asks for background execution; only set where the agent supports
	// it and the event is never gated.
	Async bool
	// Blocking marks events whose reply the agent honours as a gate.
	Blocking bool
}

// impl is what each dialect file provides; guard adapts it to Dialect.
type impl interface {
	id() string
	agentID() string
	// build maps a decoded payload to events. raw is the trimmed stdin, or
	// nil when p was salvaged from undecodable input.
	build(p obj, env map[string]string, raw []byte) ([]*event.Event, *Request, error)
	respond(req *Request, d Decision) ([]byte, []byte, int)
	events() []HookEvent
}

// registry is every dialect, in the order All returns them.
var registry = []impl{
	claudeWire{codex: false},
	claudeWire{codex: true},
	copilot{},
	gemini{},
	cursor{},
}

// aliases lets callers pass either the dialect id or the catalog agent id.
var aliases = map[string]string{
	"claude": "claude", "claude-code": "claude", "claudecode": "claude",
	"codex": "codex", "codex-cli": "codex",
	"copilot": "copilot", "copilot-cli": "copilot", "github-copilot": "copilot",
	"gemini": "gemini", "gemini-cli": "gemini",
	"cursor": "cursor", "cursor-agent": "cursor", "cursor-cli": "cursor",
}

// Get returns the dialect for a dialect id (claude, codex, copilot, gemini,
// cursor) or the matching agent id (claude-code, copilot-cli, gemini-cli ...).
func Get(id string) (Dialect, bool) {
	want, ok := aliases[strings.ToLower(strings.TrimSpace(id))]
	if !ok {
		return nil, false
	}
	for _, d := range registry {
		if d.id() == want {
			return guard{d}, true
		}
	}
	return nil, false
}

// All returns every dialect in a stable order.
func All() []Dialect {
	out := make([]Dialect, 0, len(registry))
	for _, d := range registry {
		out = append(out, guard{d})
	}
	return out
}

// AgentIDFor maps a dialect id (or alias) to the agent id its events carry.
func AgentIDFor(dialectID string) (string, bool) {
	want, ok := aliases[strings.ToLower(strings.TrimSpace(dialectID))]
	if !ok {
		return "", false
	}
	for _, d := range registry {
		if d.id() == want {
			return d.agentID(), true
		}
	}
	return "", false
}

// guard is the package boundary: it bounds and decodes input, salvages what
// it can from undecodable input, and converts panics into errors so a hostile
// payload can never crash the hook process (a crash is a non-zero exit, which
// Copilot treats as a deny and the others as a silent fail-open).
type guard struct{ d impl }

func (g guard) ID() string { return g.d.id() }

func (g guard) Parse(stdin []byte, env map[string]string) (evs []*event.Event, req *Request, err error) {
	defer func() {
		if r := recover(); r != nil {
			evs, req, err = nil, nil, internalError(r)
		}
	}()
	m, raw, derr := decodeObject(stdin)
	if derr != nil {
		if !errors.Is(derr, ErrTooLarge) && !errors.Is(derr, ErrTooDeep) {
			return nil, nil, derr
		}
		// The agent sent something real that we refuse to decode. Report
		// what the top level says so the drop is visible and gateable.
		evs, req, berr := g.d.build(obj(salvage(stdin)), env, nil)
		if berr != nil {
			return nil, req, derr
		}
		code := "too_large"
		if errors.Is(derr, ErrTooDeep) {
			code = "too_deep"
		}
		for _, e := range evs {
			label(e, "hook_error", code)
			e.Truncated = appendUnique(e.Truncated, "content")
		}
		return evs, req, derr
	}
	return g.d.build(obj(m), env, raw)
}

func (g guard) Respond(req *Request, d Decision) (stdout, stderr []byte, exitCode int) {
	defer func() {
		if r := recover(); r != nil {
			// Rendering failed. If the caller wanted a block on a gateable
			// event, fall back to the nearest thing to a universal block:
			// exit 2 with a reason on stderr (honoured by Codex, Gemini,
			// Copilot and by Claude Code except on PermissionRequest;
			// UNVERIFIED for Cursor). Otherwise stay out of the agent's way.
			if req != nil && req.Blocking && d.Action == ActionDeny {
				stdout, stderr, exitCode = nil, []byte("spoor: blocked by policy\n"), 2
				return
			}
			stdout, stderr, exitCode = nil, nil, 0
		}
	}()
	if req == nil {
		return nil, nil, 0
	}
	switch d.Action {
	case ActionAllow, ActionDeny, ActionAsk:
	default:
		return nil, nil, 0
	}
	return g.d.respond(req, d)
}

func (g guard) Events() []HookEvent {
	return append([]HookEvent(nil), g.d.events()...)
}

// internalError describes a recovered panic without echoing payload bytes:
// runtime errors (index, nil map, type assertion) have fixed-format messages,
// anything else is reduced to its type.
func internalError(r any) error {
	if re, ok := r.(runtime.Error); ok {
		return fmt.Errorf("%w: %s", ErrInternal, re.Error())
	}
	return fmt.Errorf("%w: panic of type %T", ErrInternal, r)
}
