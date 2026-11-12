package hookcmd

import (
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/thomastysong/spoor/internal/platform"
)

// Env is the process context Run needs. OSEnv fills it from the running
// process; tests substitute their own.
type Env struct {
	Getenv          func(string) string
	UID, User, Home string
	PID, PPID       int
	Now             func() time.Time
	// Exe is the binary the supervisor re-executes as its worker. Empty
	// means this process's own executable (/proc/self/exe on Linux, so an
	// upgrade that replaces the file mid-call still runs the same build).
	Exe string
}

// OSEnv returns the Env of the running process. User and UID come from the
// OS account database, never from anything the agent sends.
func OSEnv() Env {
	u := platform.CurrentUser()
	return Env{
		Getenv: os.Getenv,
		UID:    u.UID, User: u.Name, Home: u.Home,
		PID: os.Getpid(), PPID: os.Getppid(),
		Now: time.Now,
	}
}

// Version is stamped on health records; cmd/spoor sets it at start-up.
var Version = "dev"

// TypePayloadAnomaly is the activity type of a record that stands in for a
// hook payload spoor could not decode (empty, malformed, over the input cap,
// nested deeper than 64 levels, from an unknown agent). A payload the sensor
// silently drops is an evasion primitive, so it is reported instead.
const TypePayloadAnomaly = "hook.payload_anomaly"

// ConfigFileName is the configuration file looked for in the platform's
// config directory when --config is not given.
const ConfigFileName = "spoor.yaml"

// Timing and size limits of the hook path.
const (
	// ObserveDeadline bounds a hook that only records (and a hook that
	// detects without guarding): nothing waits on its answer except the
	// agent, so it only has to be short enough never to be noticed.
	ObserveDeadline = 2 * time.Second
	// MinGuardDeadline is the floor of the guard-mode hard deadline. The
	// worker has to start, read its config and load rules inside it; below
	// about 100 ms a loaded laptop would answer "ask" to every tool call.
	MinGuardDeadline = 100 * time.Millisecond
	// maxGuardDeadline caps guard.deadline well inside the shortest agent
	// hook timeout (30 s for Claude Code's UserPromptSubmit and Copilot).
	maxGuardDeadline = 10 * time.Second
	// MaxReply caps what the supervisor forwards. Every spoor reply is a
	// single JSON line under 2 KiB (reasons are cut at 1 KiB); anything
	// longer did not come from a healthy worker.
	MaxReply = 16 << 10
	// minInputCap is the smallest limits.max_hook_input_bytes honoured:
	// below it ordinary tool calls would be refused as oversized.
	minInputCap = 64 << 10
)

// Worker exit codes. They are private to the supervisor and worker: the
// supervisor maps every one of them (and every crash) to exit 0.
const (
	exitOK       = 0
	exitInternal = 70 // a panic was recovered in the worker
	exitSpool    = 71 // a record could not be appended
	exitRender   = 72 // no reply could be rendered for a decision
	exitWatchdog = 73 // the worker's own watchdog fired
)

// observeDeadline is ObserveDeadline; tests shorten it.
var observeDeadline = ObserveDeadline

// opts are the parsed command-line arguments of `spoor hook`.
type opts struct {
	agent  string
	config string
	event  string
	worker bool
	// Set by the supervisor for its worker only.
	ppid     int
	t0       time.Time
	deadline time.Time
	// framed: end the reply with replyEnd, so the supervisor can tell a
	// finished decision (even an empty one) from a worker that died first.
	framed bool
	// stdinCut: the supervisor stopped waiting for the agent to close
	// stdin, so the payload on the worker's stdin may be a prefix.
	stdinCut bool
	// stdinBytes and stdinSHA256 describe everything the supervisor read
	// from stdin when that was more than it passed on (over the cap).
	stdinBytes  int64
	stdinSHA256 string
}

// parseArgs reads `--name value` and `--name=value` forms. Unknown flags
// and positional words are ignored: a hook command line written by an
// older or newer installer must never turn into a failing hook.
func parseArgs(args []string) opts {
	var o opts
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			continue
		}
		name, val, hasVal := strings.Cut(strings.TrimLeft(a, "-"), "=")
		next := func() string {
			if hasVal {
				return val
			}
			if i+1 < len(args) {
				i++
				return args[i]
			}
			return ""
		}
		switch name {
		case "agent":
			o.agent = next()
		case "config":
			o.config = next()
		case "event":
			o.event = next()
		case "worker":
			o.worker = true
		case "ppid":
			o.ppid, _ = strconv.Atoi(next())
		case "t0":
			o.t0 = unixNano(next())
		case "deadline":
			o.deadline = unixNano(next())
		case "framed":
			o.framed = true
		case "stdin-cut":
			o.stdinCut = true
		case "stdin-bytes":
			o.stdinBytes, _ = strconv.ParseInt(next(), 10, 64)
		case "stdin-sha256":
			o.stdinSHA256 = next()
		}
	}
	return o
}

func unixNano(s string) time.Time {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return time.Time{}
	}
	return time.Unix(0, n)
}

// Run implements `spoor hook --agent <id> [--config <path>] [--event <name>]`.
//
// args are the arguments after "hook". The process exit status is the
// return value. Run is a supervisor: it re-executes the binary as a worker
// (`spoor hook --worker ...`) and returns 0 whatever the worker does; see
// the package documentation for the contract. stderr is never written,
// because agents show it to the user or the model.
func Run(stdin io.Reader, stdout, stderr io.Writer, args []string, env Env) (code int) {
	o := parseArgs(args)
	defer func() {
		if r := recover(); r != nil {
			// A recovered panic must never become exit 2. The worker
			// reports it to the supervisor through a private code.
			code = 0
			if o.worker {
				code = exitInternal
			}
		}
	}()
	env = env.withDefaults()
	if o.worker {
		return runWorker(stdin, stdout, o, env)
	}
	return supervise(stdin, stdout, o, env)
}

func (e Env) withDefaults() Env {
	if e.Getenv == nil {
		e.Getenv = os.Getenv
	}
	if e.Now == nil {
		e.Now = time.Now
	}
	if e.PID == 0 {
		e.PID = os.Getpid()
	}
	if e.PPID == 0 {
		e.PPID = os.Getppid()
	}
	return e
}

// configPath is the file the hook reads: --config, else spoor.yaml in the
// platform's system config directory (missing means built-in defaults).
func configPath(o opts) string {
	if o.config != "" {
		return o.config
	}
	return filepath.Join(platform.DefaultDirs().Config, ConfigFileName)
}

// killSwitch reports whether the operator disabled the hook: the platform
// kill switch (<system config dir>/disabled) or a "disabled" file next to
// the config file the hook was pointed at. A per-user location is not
// honoured: that would let the monitored user switch off a managed hook.
func killSwitch(cfgPath string) bool {
	if platform.Disabled() {
		return true
	}
	if cfgPath == "" {
		return false
	}
	_, err := os.Lstat(filepath.Join(filepath.Dir(cfgPath), platform.KillSwitchName))
	return err == nil
}
