package hookinstall

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"runtime"
	"strings"
	"unicode/utf8"

	"github.com/thomastysong/spoor/internal/event"
)

// sensorName is the product name used for the files and markers this package
// owns (50-spoor.json, spoor.json, "# BEGIN spoor").
const sensorName = "spoor"

// hookMarker is what makes a hook entry recognisable as ours whatever binary
// path or agent id it carries.
const hookMarker = " hook --agent "

// Plan actions.
const (
	ActionCreate      = "create"      // the file does not exist and will be written
	ActionMerge       = "merge"       // an existing JSON file will be patched (install or uninstall)
	ActionAppend      = "append"      // a marked block will be appended to or replaced in an existing TOML file
	ActionRemove      = "remove"      // uninstall only: nothing but spoor content is left, the file will be deleted
	ActionUnchanged   = "unchanged"   // the file already is in the wanted state
	ActionUnsupported = "unsupported" // nothing will be written; Note says why
)

// Status values.
const (
	StatusManaged     = "managed"              // installed in the managed (or system) tier and identical to what PlanInstall would write
	StatusUser        = "user"                 // the same for the user tier
	StatusMissing     = "missing"              // no file, or no hook in it
	StatusModified    = "modified"             // spoor entries exist but differ from what PlanInstall would write
	StatusForeignOnly = "foreign_only"         // the file holds hooks, none of them spoor's
	StatusUnsupported = "unsupported"          // cannot be installed or cannot be read safely
	StatusShadowed    = "shadowed"             // installed, but a higher-ranked policy source makes the agent ignore it
	StatusInsecure    = "insecure_permissions" // installed, but the file or its directory can be rewritten by a non-admin
)

// Options selects what to install and where.
type Options struct {
	Binary string      // absolute path of the spoor binary to invoke
	Scope  event.Scope // managed | user (and system, for Codex only)
	Agents []string    // catalog ids; empty = every agent whose catalog entry has a hook dialect
	// Guard was "register blocking events synchronously, everything else
	// async". Since every tool, prompt and session hook is now registered
	// synchronously (a background hook dies with the session and loses the
	// record), Guard only gates FailClosed: a hook that never denies has no
	// reason to block the agent when it fails.
	Guard      bool
	FailClosed bool   // only where the agent supports it (Claude Code onFailure, Cursor failClosed); never the default
	Timeout    int    // seconds, default 10
	Root       string // filesystem prefix for tests and --host-root
	Home       string // user home for user scope
	GOOS       string

	// Coexist allows installing next to another sensor's hook (numbat,
	// Agent Beacon, Snyk Agent Guard). Without it PlanInstall reports the
	// other sensor and writes nothing for that agent.
	Coexist bool
	// OTel is an OTLP/HTTP endpoint (for example http://127.0.0.1:4319).
	// When set, native OpenTelemetry log export is switched on for Claude
	// Code, Codex and Gemini CLI, unless a destination is already configured.
	OTel string
	// Force patches files that contain comments or trailing commas (JSONC)
	// in place instead of reporting them as unsupported.
	Force bool
	// Env resolves the variables that relocate an agent's user directory
	// (CLAUDE_CONFIG_DIR, CODEX_HOME, COPILOT_HOME, GEMINI_CLI_HOME). Nil
	// means the default locations under Home. It is never read from the
	// process environment: a root process must not be steered by its own.
	Env map[string]string
}

// Plan is one file change, computed but not applied. Path is where this
// process finds the file (Options.Root applied). Before is the file as it
// was read (nil when it does not exist) and After what Apply will write;
// for ActionRemove the file is deleted (kept as a backup), for unchanged
// both hold the current bytes.
type Plan struct {
	AgentID, Path string
	Scope         event.Scope
	Action        string // create | merge | append | remove | unchanged | unsupported
	Before, After []byte
	Note          string

	// root is Options.Root: Apply confines the write to it and follows no
	// symbolic link below it.
	root string
}

// State is the audit result for one agent and scope.
type State struct {
	AgentID, Path string
	Scope         event.Scope
	Status        string // managed | user | missing | modified | foreign_only | unsupported | shadowed | insecure_permissions
	// Hash is the SHA-256 of the spoor entries as found in the file, in a
	// canonical encoding, so equal configurations hash equally whatever else
	// the file holds. Empty when there is no spoor entry.
	Hash   string
	Detail string
}

const (
	defaultTimeout = 10
	maxTimeout     = 3600
	maxPathLen     = 1024
)

type mode int

const (
	modeInstall mode = iota
	modeUninstall
	modeStatus
)

// normalize validates the options and fills defaults. Errors are about the
// caller's input; anything about the state of the machine is reported per
// agent in a Plan or State instead.
func normalize(o Options, m mode) (Options, error) {
	if o.GOOS == "" {
		o.GOOS = runtime.GOOS
	}
	o.GOOS = strings.ToLower(o.GOOS)
	switch o.Scope {
	case event.ScopeManaged, event.ScopeUser, event.ScopeSystem:
	case "":
		if m != modeStatus {
			return o, errors.New("hookinstall: Scope must be managed or user")
		}
	default:
		return o, fmt.Errorf("hookinstall: unsupported scope %q (want managed or user)", o.Scope)
	}
	if o.Timeout == 0 {
		o.Timeout = defaultTimeout
	}
	if o.Timeout < 1 || o.Timeout > maxTimeout {
		return o, fmt.Errorf("hookinstall: Timeout must be between 1 and %d seconds", maxTimeout)
	}
	if o.Binary != "" || m == modeInstall {
		if err := validBinary(o.Binary, o.GOOS); err != nil {
			return o, err
		}
	}
	if o.Root != "" {
		if err := validHostPath(o.Root); err != nil {
			return o, fmt.Errorf("hookinstall: Root: %w", err)
		}
	}
	if o.Home == "" && o.Scope == event.ScopeUser && o.Root == "" && o.GOOS == runtime.GOOS {
		if h, err := os.UserHomeDir(); err == nil {
			o.Home = h
		}
	}
	if o.Home != "" {
		if !absFor(o.Home, o.GOOS) || hasControl(o.Home) || len(o.Home) > maxPathLen {
			return o, errors.New("hookinstall: Home must be an absolute path")
		}
	} else if o.Scope == event.ScopeUser {
		return o, errors.New("hookinstall: Home is required for user scope")
	}
	if o.OTel != "" {
		if _, err := parseOTelEndpoint(o.OTel); err != nil {
			return o, err
		}
	}
	for _, id := range o.Agents {
		if id == "" || len(id) > 128 || hasControl(id) {
			return o, errors.New("hookinstall: Agents holds an empty or malformed id")
		}
	}
	return o, nil
}

// validBinary accepts an absolute path in the style of the target OS. The
// path ends up inside shell command strings, so anything a quoting rule
// cannot carry (control characters, newlines) is refused here rather than
// escaped hopefully later.
func validBinary(bin, goos string) error {
	switch {
	case bin == "":
		return errors.New("hookinstall: Binary is required")
	case len(bin) > maxPathLen:
		return errors.New("hookinstall: Binary path is too long")
	case hasControl(bin):
		return errors.New("hookinstall: Binary path contains control characters")
	case !utf8.ValidString(bin):
		// JSON and TOML carry Unicode text: an invalid byte would be
		// written as U+FFFD, naming a file that does not exist.
		return errors.New("hookinstall: Binary path is not valid UTF-8")
	case !absFor(bin, goos):
		return fmt.Errorf("hookinstall: Binary must be an absolute %s path", goos)
	case strings.ContainsAny(bin, "$`"):
		// Claude Code substitutes ${CLAUDE_*} placeholders into an exec-form
		// command and Gemini CLI replaces $GEMINI_* (and $CLAUDE_PROJECT_DIR)
		// in the command text before any shell sees it, so a dollar sign in
		// the path could turn into a project directory chosen by whoever
		// controls the repository.
		return errors.New("hookinstall: Binary path must not contain '$' or '`'")
	case goos != "windows" && strings.Contains(bin, `\`):
		// fish treats \ and \' as escapes even inside single quotes, so a
		// POSIX path with a backslash has no quoting valid in every login
		// shell.
		return errors.New("hookinstall: Binary path must not contain a backslash")
	}
	return nil
}

func validHostPath(p string) error {
	if len(p) > maxPathLen || hasControl(p) {
		return errors.New("malformed path")
	}
	return nil
}

func hasControl(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

// absFor reports whether p is absolute in the path style of goos, whatever
// OS this process runs on.
func absFor(p, goos string) bool {
	if goos == "windows" {
		if len(p) >= 3 && isDriveLetter(p[0]) && p[1] == ':' && (p[2] == '\\' || p[2] == '/') {
			return true
		}
		return strings.HasPrefix(p, `\\`) && len(p) > 2
	}
	return strings.HasPrefix(p, "/")
}

func isDriveLetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// otelEndpoint is a validated OTLP/HTTP destination.
type otelEndpoint struct {
	base string // scheme://host[:port][/prefix], no trailing slash and no /v1/logs
	logs string // full URL of the logs signal
}

// parseOTelEndpoint refuses anything that is not a plain http(s) URL.
// Credentials in the URL are refused because the value is written to files
// that every local user can read.
func parseOTelEndpoint(s string) (otelEndpoint, error) {
	var ep otelEndpoint
	if len(s) > maxPathLen || hasControl(s) || !utf8.ValidString(s) || strings.ContainsAny(s, " \"'\\") {
		return ep, errors.New("hookinstall: OTel must be an http(s) URL")
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ep, errors.New("hookinstall: OTel must be an http(s) URL")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return ep, errors.New("hookinstall: OTel must not carry credentials, a query or a fragment")
	}
	path := strings.TrimRight(u.Path, "/")
	prefix := strings.TrimSuffix(path, "/v1/logs")
	ep.base = u.Scheme + "://" + u.Host + prefix
	ep.logs = ep.base + "/v1/logs"
	return ep, nil
}
