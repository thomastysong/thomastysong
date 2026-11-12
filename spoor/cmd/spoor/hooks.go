package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/thomastysong/spoor/internal/catalog"
	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/hookinstall"
	"github.com/thomastysong/spoor/internal/platform"
)

func (a *app) cmdHooks(args []string) int {
	return a.dispatch("hooks", []subcommand{
		{"install", "register `spoor hook` with every hook-capable agent (or --agents)", a.hooksInstall},
		{"uninstall", "remove spoor's hook registrations, leaving every other hook alone", a.hooksUninstall},
		{"status", "audit hook registrations: managed, user, missing, modified, shadowed ...", a.hooksStatus},
	}, args)
}

// hookFlags are shared by install, uninstall and status.
type hookFlags struct {
	scope  string
	agents listFlag
	home   string
	root   string
	asJSON bool
}

func (h *hookFlags) register(fs *flag.FlagSet, scopeHelp string) {
	fs.StringVar(&h.scope, "scope", "", scopeHelp)
	fs.Var(&h.agents, "agents", "catalog ids, comma separated (default: every agent spoor has a hook dialect for)")
	fs.StringVar(&h.home, "home", "", "home directory for user scope (default: $HOME of the caller)")
	fs.StringVar(&h.root, "root", "", "filesystem prefix, for a host mounted elsewhere (--host-root)")
	fs.BoolVar(&h.asJSON, "json", false, "print JSON")
}

const scopeInstallHelp = "managed (system policy files, needs root/Administrator), user (the caller's own settings) or system (Codex only); default managed when privileged, else user"

// options builds hookinstall options. User-scope relocation variables
// (CLAUDE_CONFIG_DIR, CODEX_HOME ...) are taken from the caller's own
// environment only when the caller acts on their own home: they describe
// where that user's agents read settings, and a root process editing
// another account must not be steered by root's environment.
func (a *app) hookOptions(h *hookFlags, cat *catalog.Catalog, defaultScope event.Scope) (hookinstall.Options, error) {
	o := hookinstall.Options{Agents: h.agents, Root: h.root, Scope: defaultScope}
	if h.scope != "" {
		switch s := event.Scope(h.scope); s {
		case event.ScopeManaged, event.ScopeUser, event.ScopeSystem:
			o.Scope = s
		default:
			return o, fmt.Errorf("--scope %q: want managed, user or system", h.scope)
		}
	}
	if o.Scope == event.ScopeUser || o.Scope == "" {
		if h.home != "" {
			abs, err := filepath.Abs(h.home)
			if err != nil {
				return o, err
			}
			o.Home = abs
		} else {
			o.Home = a.homeDir()
			o.Env = a.relocationEnv(cat)
		}
		if o.Scope == event.ScopeUser && o.Home == "" {
			return o, errors.New("no home directory: pass --home")
		}
	}
	return o, nil
}

// homeDir is the caller's home: $HOME (USERPROFILE on Windows) when it is
// an existing directory, else the account database's.
func (a *app) homeDir() string {
	for _, v := range []string{"HOME", "USERPROFILE"} {
		if h := a.getenv(v); h != "" && filepath.IsAbs(h) {
			if fi, err := os.Stat(h); err == nil && fi.IsDir() {
				return h
			}
		}
	}
	return platform.CurrentUser().Home
}

// relocationEnv collects the variables that move an agent's user
// directory, as named by the catalog.
func (a *app) relocationEnv(cat *catalog.Catalog) map[string]string {
	env := map[string]string{}
	for _, p := range cat.Products() {
		if p.Hooks == nil || p.Hooks.Dialect == "" {
			continue
		}
		for _, k := range p.HomeEnv {
			if v := a.getenv(k); v != "" {
				env[k] = v
			}
		}
	}
	if len(env) == 0 {
		return nil
	}
	return env
}

func defaultHookScope() event.Scope {
	if platform.IsPrivileged() {
		return event.ScopeManaged
	}
	return event.ScopeUser
}

// planJSON is a plan as printed: the diff, never the file contents (agent
// settings files can hold credentials).
type planJSON struct {
	Agent  string      `json:"agent"`
	Scope  event.Scope `json:"scope"`
	Path   string      `json:"path"`
	Action string      `json:"action"`
	Note   string      `json:"note,omitempty"`
	Diff   []string    `json:"diff,omitempty"`
}

type planResult struct {
	DryRun bool       `json:"dry_run"`
	Binary string     `json:"binary,omitempty"`
	Plans  []planJSON `json:"plans"`
	Errors []string   `json:"errors,omitempty"`
}

func (a *app) hooksInstall(args []string) int {
	return a.hooksChange("install", args)
}

func (a *app) hooksUninstall(args []string) int {
	return a.hooksChange("uninstall", args)
}

func (a *app) hooksChange(verb string, args []string) int {
	name := "hooks " + verb
	about := `Registers ` + "`<binary> hook --agent <id>`" + ` in each agent's hook file for the scope,
preserving every other key and hook. Files are replaced atomically with a
timestamped backup beside them. --dry-run prints the plan and a diff of the
changed lines only, with secrets redacted.`
	if verb == "uninstall" {
		about = `Removes spoor's registrations (and native telemetry settings spoor wrote)
from each agent's hook file for the scope; foreign hooks and keys stay.
A file that held nothing but spoor's entries is removed (kept as a backup).`
	}
	fs := a.newFlags(name, name+" [--scope managed|user|system] [--agents a,b] [--dry-run] [--json]", about)
	var h hookFlags
	h.register(fs, scopeInstallHelp)
	dry := fs.Bool("dry-run", false, "print the plan and diffs, change nothing")
	var guard, failClosed, coexist, force *bool
	var timeout *int
	var otel, binary *string
	if verb == "install" {
		guard = fs.Bool("guard", false, "guard mode registration (allows --fail-closed)")
		failClosed = fs.Bool("fail-closed", false, "with --guard, block the tool call when the hook fails (Claude Code, Cursor only)")
		timeout = fs.Int("timeout", 10, "hook timeout in seconds registered with the agent")
		coexist = fs.Bool("coexist", false, "install next to another sensor's hook (numbat, Agent Beacon, Snyk)")
		otel = fs.String("otel", "", "also switch on the agents' native OpenTelemetry to this OTLP/HTTP endpoint")
		force = fs.Bool("force", false, "patch JSONC files (comments, trailing commas) in place")
		binary = fs.String("binary", "", "absolute path of the spoor binary the hook runs (default: this binary)")
	}
	pos, code, done := a.parse(fs, args)
	if done {
		return code
	}
	if len(pos) > 0 {
		return a.usageErr(name, "unexpected argument %q", pos[0])
	}
	cat, err := catalog.Load()
	if err != nil {
		return a.fail(name, err)
	}
	o, err := a.hookOptions(&h, cat, defaultHookScope())
	if err != nil {
		return a.usageErr(name, "%v", err)
	}
	var plans []hookinstall.Plan
	if verb == "install" {
		o.Guard, o.FailClosed, o.Timeout = *guard, *failClosed, *timeout
		o.Coexist, o.OTel, o.Force = *coexist, *otel, *force
		if *failClosed && !*guard {
			return a.usageErr(name, "--fail-closed needs --guard")
		}
		o.Binary = *binary
		if o.Binary == "" {
			exe, err := a.executable()
			if err != nil {
				return a.fail(name, fmt.Errorf("cannot find this binary (pass --binary): %w", err))
			}
			o.Binary = exe
		}
		if inTempDir(o.Binary) {
			a.warn(name, "the hook will run %s, which is in a temporary directory; install the binary first or pass --binary", o.Binary)
		}
		plans, err = hookinstall.PlanInstall(cat, o)
	} else {
		o.Force = false
		plans, err = hookinstall.PlanUninstall(cat, o)
	}
	if err != nil {
		return a.usageErr(name, "%v", err)
	}
	res := planResult{DryRun: *dry, Binary: o.Binary}
	for _, p := range plans {
		pj := planJSON{Agent: p.AgentID, Scope: p.Scope, Path: p.Path, Action: p.Action, Note: p.Note}
		if p.Action != hookinstall.ActionUnchanged && p.Action != hookinstall.ActionUnsupported {
			pj.Diff = redactedDiff(p.Before, p.After)
		}
		res.Plans = append(res.Plans, pj)
	}
	if !*dry {
		if err := hookinstall.Apply(plans); err != nil {
			for _, e := range unjoin(err) {
				res.Errors = append(res.Errors, e.Error())
			}
		}
	}
	if h.asJSON {
		if c := a.printJSON(res); c != exitOK {
			return c
		}
	} else {
		a.printPlans(res, *dry)
	}
	if len(res.Errors) > 0 {
		if !h.asJSON {
			for _, e := range res.Errors {
				fmt.Fprintf(a.stderr, "spoor %s: %s\n", name, e)
			}
		}
		return exitError
	}
	return exitOK
}

func (a *app) printPlans(res planResult, dry bool) {
	changed := 0
	for _, p := range res.Plans {
		fmt.Fprintf(a.stdout, "%-12s %-8s %-11s %s\n", p.Agent, p.Scope, p.Action, p.Path)
		if p.Note != "" {
			for _, l := range strings.Split(strings.TrimSpace(p.Note), "\n") {
				fmt.Fprintf(a.stdout, "    note: %s\n", l)
			}
		}
		if len(p.Diff) > 0 {
			changed++
			if dry {
				for _, l := range p.Diff {
					fmt.Fprintf(a.stdout, "    %s\n", l)
				}
			}
		}
	}
	switch {
	case dry:
		fmt.Fprintf(a.stdout, "dry run: %d file(s) would change, nothing was written\n", changed)
	case len(res.Errors) == 0:
		fmt.Fprintf(a.stdout, "%d file(s) changed\n", changed)
	}
}

// unjoin splits an errors.Join result into its parts.
func unjoin(err error) []error {
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		return j.Unwrap()
	}
	return []error{err}
}

func inTempDir(p string) bool {
	tmp := os.TempDir()
	if tmp == "" {
		return false
	}
	rel, err := filepath.Rel(tmp, p)
	return err == nil && !strings.HasPrefix(rel, "..") && !filepath.IsAbs(rel)
}

// hookState is hookinstall.State as printed.
type hookState struct {
	Agent  string      `json:"agent"`
	Scope  event.Scope `json:"scope"`
	User   string      `json:"user,omitempty"`
	Path   string      `json:"path"`
	Status string      `json:"status"`
	Hash   string      `json:"hash,omitempty"`
	Detail string      `json:"detail,omitempty"`
	// Binaries are the programs spoor's entries in the file run; doctor
	// fills them in and reports one that is missing (hooks.binary_missing).
	Binaries      []string `json:"binaries,omitempty"`
	BinaryProblem string   `json:"binary_problem,omitempty"`
}

func toHookStates(st []hookinstall.State, user string) []hookState {
	out := make([]hookState, 0, len(st))
	for _, s := range st {
		u := ""
		if s.Scope == event.ScopeUser {
			u = user
		}
		out = append(out, hookState{Agent: s.AgentID, Scope: s.Scope, User: u, Path: s.Path, Status: s.Status, Hash: s.Hash, Detail: s.Detail})
	}
	return out
}

// allHookStates audits the managed tier once and the user tier of every
// account this process can see (every person's home when privileged).
func allHookStates(cat *catalog.Catalog, agents []string, root string) ([]hookState, error) {
	st, err := hookinstall.Status(cat, hookinstall.Options{Scope: event.ScopeManaged, Agents: agents, Root: root})
	if err != nil {
		return nil, err
	}
	out := toHookStates(st, "")
	users, uerr := platform.Users()
	seen := map[string]bool{}
	for _, u := range users {
		if u.Home == "" || seen[u.Home] {
			continue
		}
		seen[u.Home] = true
		us, err := hookinstall.Status(cat, hookinstall.Options{Scope: event.ScopeUser, Agents: agents, Root: root, Home: u.Home})
		if err != nil {
			continue
		}
		out = append(out, toHookStates(us, firstNonEmpty(u.Name, u.UID))...)
	}
	return out, uerr
}

func (a *app) hooksStatus(args []string) int {
	fs := a.newFlags("hooks status", "hooks status [--scope managed|user|system] [--all-users] [--agents a,b] [--json]",
		`Audits hook files. Status is one of managed, user (installed and exactly
what install would write), missing, modified, foreign_only, unsupported,
shadowed (a higher-ranked policy source makes the agent ignore the file) or
insecure_permissions. "managed" is not proof that the agent runs the hook:
Detail says what could not be seen from disk. Default: the managed tier and
the caller's user tier.`)
	var h hookFlags
	h.register(fs, "managed, user or system (default: managed and the caller's user tier)")
	allUsers := fs.Bool("all-users", false, "audit the user tier of every account (needs privilege to see other homes)")
	pos, code, done := a.parse(fs, args)
	if done {
		return code
	}
	if len(pos) > 0 {
		return a.usageErr("hooks status", "unexpected argument %q", pos[0])
	}
	cat, err := catalog.Load()
	if err != nil {
		return a.fail("hooks status", err)
	}
	var states []hookState
	if *allUsers {
		states, err = allHookStates(cat, h.agents, h.root)
		if err != nil && states == nil {
			return a.fail("hooks status", err)
		}
	} else {
		o, err := a.hookOptions(&h, cat, "")
		if err != nil {
			return a.usageErr("hooks status", "%v", err)
		}
		st, err := hookinstall.Status(cat, o)
		if err != nil {
			return a.fail("hooks status", err)
		}
		states = toHookStates(st, platform.CurrentUser().Name)
	}
	if h.asJSON {
		return a.printJSON(states)
	}
	tw := a.table()
	fmt.Fprintln(tw, "AGENT\tSCOPE\tUSER\tSTATUS\tPATH")
	for _, s := range states {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", s.Agent, s.Scope, s.User, s.Status, s.Path)
	}
	tw.Flush()
	for _, s := range states {
		if s.Detail != "" && s.Status != hookinstall.StatusMissing {
			fmt.Fprintf(a.stdout, "%s (%s): %s\n", s.Agent, s.Scope, clip(s.Detail, 300))
		}
	}
	return exitOK
}
