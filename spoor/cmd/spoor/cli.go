package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
)

// Exit codes. They are part of the interface (scripts, CI and Fleet act on
// them) and are listed in `spoor help`.
const (
	exitOK       = 0 // success
	exitError    = 1 // the command could not do its work (I/O, configuration, runtime failure)
	exitUsage    = 2 // bad flags or arguments
	exitFindings = 3 // detect, ci exec: detections at or above --fail-on
	exitCheck    = 4 // a check ran and failed: rules test/lint, bundle verify, catalog verify, doctor
)

const exitCodesHelp = `Exit codes:
  0  success
  1  the command could not do its work (I/O, configuration, runtime failure)
  2  bad flags or arguments
  3  detect, ci exec: detections at or above --fail-on were found
  4  a check ran and failed: rules test, rules lint, bundle verify,
     catalog verify, doctor (at least one check failed)
  spoor hook always exits 0; ci exec otherwise exits with the command's code.`

// app holds the process context so commands can be run from tests with
// their own streams, environment and network endpoints.
type app struct {
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
	getenv func(string) string
	now    func() time.Time
	// executable returns the path hooks are registered with.
	executable func() (string, error)
	// ctx is cancelled by SIGINT/SIGTERM in long-running commands.
	ctx context.Context

	// Network endpoints and client, replaceable in tests.
	client       *http.Client
	npmRegistry  string
	pypiRegistry string
}

func newApp() *app {
	return &app{
		stdin:        os.Stdin,
		stdout:       os.Stdout,
		stderr:       os.Stderr,
		getenv:       os.Getenv,
		now:          time.Now,
		executable:   os.Executable,
		ctx:          context.Background(),
		client:       &http.Client{Timeout: 15 * time.Second},
		npmRegistry:  "https://registry.npmjs.org",
		pypiRegistry: "https://pypi.org",
	}
}

// command is one top-level command.
type command struct {
	name    string
	summary string
	run     func(a *app, args []string) int
	hidden  bool
}

// commands is built on demand rather than as a package variable so that
// none of this runs in the hook process.
func commands() []command {
	return []command{
		{name: "run", summary: "run the sensor daemon (systemd, launchd, Windows service)", run: (*app).cmdRun},
		{name: "hook", summary: "entry point AI agents call on every event (installed by `hooks install`)", run: (*app).cmdHookHelp},
		{name: "scan", summary: "inventory agents, MCP servers, hooks and posture on this host", run: (*app).cmdScan},
		{name: "detect", summary: "evaluate NDJSON events (spoor, spool or numbat) with the rules", run: (*app).cmdDetect},
		{name: "hooks", summary: "install, uninstall or audit agent hook registrations", run: (*app).cmdHooks},
		{name: "rules", summary: "list, test or lint detection rules", run: (*app).cmdRules},
		{name: "bench", summary: "run the detection benchmarks (scenarios, benign replay)", run: (*app).cmdBench},
		{name: "doctor", summary: "one-screen health check of this installation", run: (*app).cmdDoctor},
		{name: "privacy", summary: "show what is collected, tail your own records, purge a user", run: (*app).cmdPrivacy},
		{name: "export", summary: "write deployment content: config, fleet, fluent-bit, kubernetes, atc", run: (*app).cmdExport},
		{name: "bundle", summary: "create, sign, verify and install signed rule bundles", run: (*app).cmdBundle},
		{name: "catalog", summary: "list the agent catalog or verify its package references", run: (*app).cmdCatalog},
		{name: "ci", summary: "run a command with hooks in a temporary config home (experimental)", run: (*app).cmdCI},
		{name: "version", summary: "print the version", run: (*app).cmdVersion},
		{name: "licenses", summary: "print spoor's license and those of linked modules", run: (*app).cmdLicenses},
		{name: "help", summary: "show help for a command", run: (*app).cmdHelp},
	}
}

func (a *app) main(args []string) int {
	if len(args) == 0 {
		a.usage(a.stderr)
		return exitUsage
	}
	name := args[0]
	switch name {
	case "-h", "-help", "--help":
		a.usage(a.stdout)
		return exitOK
	case "-v", "-version", "--version":
		return a.cmdVersion(nil)
	}
	for _, c := range commands() {
		if c.name == name {
			return c.run(a, args[1:])
		}
	}
	fmt.Fprintf(a.stderr, "spoor: unknown command %q\n\n", name)
	a.usage(a.stderr)
	return exitUsage
}

func (a *app) usage(w io.Writer) {
	fmt.Fprintf(w, "spoor %s: AI-agent detection sensor\n\nUsage: spoor <command> [flags] [args]\n\nCommands:\n", versionString())
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, c := range commands() {
		if !c.hidden {
			fmt.Fprintf(tw, "  %s\t%s\n", c.name, c.summary)
		}
	}
	tw.Flush()
	fmt.Fprintf(w, "\nRun `spoor <command> --help` for the flags of a command.\nCommands that print data accept --json.\n\n%s\n", exitCodesHelp)
}

func (a *app) cmdHelp(args []string) int {
	if len(args) == 0 {
		a.usage(a.stdout)
		return exitOK
	}
	for _, c := range commands() {
		if c.name == args[0] {
			return c.run(a, append(args[1:], "--help"))
		}
	}
	fmt.Fprintf(a.stderr, "spoor help: unknown command %q\n", args[0])
	return exitUsage
}

// cmdHookHelp only runs for `spoor help hook`: `spoor hook` itself is
// dispatched in main before the framework exists.
func (a *app) cmdHookHelp(args []string) int {
	fmt.Fprint(a.stdout, `usage: spoor hook --agent <id> [--config <file>] [--event <name>]

Called by an AI agent for every hooked event, with the event as JSON on
stdin. It records the event in the user's spool and, in guard mode, answers
the agent on stdout. It always exits 0 and never writes to stderr; a crash,
hang or timeout of its worker answers with the agent's allow-shaped reply
(observe) or "ask" (guard). Register it with `+"`spoor hooks install`"+`.

The kill switch (a file named "disabled" in the system config directory or
next to --config) makes it exit at once without reading anything.
`)
	return exitOK
}

// subcommand is one entry of a command group (hooks, rules, export ...).
type subcommand struct {
	name    string
	summary string
	run     func(args []string) int
}

func (a *app) dispatch(group string, subs []subcommand, args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		w := a.stdout
		code := exitOK
		if len(args) == 0 {
			w, code = a.stderr, exitUsage
		}
		fmt.Fprintf(w, "usage: spoor %s <subcommand> [flags]\n\nSubcommands:\n", group)
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		for _, s := range subs {
			fmt.Fprintf(tw, "  %s\t%s\n", s.name, s.summary)
		}
		tw.Flush()
		fmt.Fprintf(w, "\nRun `spoor %s <subcommand> --help` for its flags.\n", group)
		return code
	}
	for _, s := range subs {
		if s.name == args[0] {
			return s.run(args[1:])
		}
	}
	fmt.Fprintf(a.stderr, "spoor %s: unknown subcommand %q\n", group, args[0])
	return exitUsage
}

// newFlags returns a flag set whose errors and help go to stderr.
func (a *app) newFlags(name, usage, about string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	fs.Usage = func() {
		out := fs.Output()
		fmt.Fprintf(out, "usage: spoor %s\n", usage)
		if about != "" {
			fmt.Fprintf(out, "\n%s\n", strings.TrimSpace(about))
		}
		fmt.Fprintln(out, "\nFlags:")
		fs.PrintDefaults()
	}
	return fs
}

// parse parses flags anywhere among the arguments (Go's flag package stops
// at the first positional word) until "--", after which everything is
// positional. done is true when the caller must return code.
func (a *app) parse(fs *flag.FlagSet, args []string) (pos []string, code int, done bool) {
	for {
		// --help prints to stdout and succeeds: it was asked for.
		for _, x := range args {
			if x == "--" {
				break
			}
			if x == "-h" || x == "-help" || x == "--help" {
				fs.SetOutput(a.stdout)
				fs.Usage()
				return nil, exitOK, true
			}
		}
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, exitOK, true
			}
			return nil, exitUsage, true
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return pos, 0, false
		}
		if consumed := len(args) - len(rest); consumed > 0 && args[consumed-1] == "--" {
			return append(pos, rest...), 0, false
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

// usageErr prints a usage problem and returns exitUsage.
func (a *app) usageErr(cmd, format string, v ...any) int {
	fmt.Fprintf(a.stderr, "spoor %s: %s\n", cmd, fmt.Sprintf(format, v...))
	return exitUsage
}

// fail prints an operational error and returns exitError.
func (a *app) fail(cmd string, err error) int {
	fmt.Fprintf(a.stderr, "spoor %s: %v\n", cmd, err)
	return exitError
}

func (a *app) warn(cmd, format string, v ...any) {
	fmt.Fprintf(a.stderr, "spoor %s: warning: %s\n", cmd, fmt.Sprintf(format, v...))
}

// printJSON writes v as indented JSON to stdout.
func (a *app) printJSON(v any) int {
	enc := json.NewEncoder(a.stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		fmt.Fprintf(a.stderr, "spoor: writing JSON: %v\n", err)
		return exitError
	}
	return exitOK
}

func (a *app) table() *tabwriter.Writer {
	return tabwriter.NewWriter(a.stdout, 0, 0, 2, ' ', 0)
}

// flagSet shortens signatures of helpers that register extra flags.
type flagSet = flag.FlagSet

// listFlag is a repeatable string flag that also splits on commas.
type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error {
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			*l = append(*l, p)
		}
	}
	return nil
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// clip shortens s for a table cell.
func clip(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len([]rune(s)) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}
