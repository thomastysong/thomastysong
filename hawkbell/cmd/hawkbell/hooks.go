package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/thomastysong/thomastysong/hawkbell/internal/catalog"
	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
	"github.com/thomastysong/thomastysong/hawkbell/internal/hookinstall"
	"github.com/thomastysong/thomastysong/hawkbell/internal/platform"
)

func (a *app) cmdHooks(args []string) int {
	return a.dispatch("hooks", []subcommand{
		{"install", "register `hawkbell hook` with every hook-capable agent (or --agents)", a.hooksInstall},
		{"uninstall", "remove hawkbell's hook registrations, leaving every other hook alone", a.hooksUninstall},
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
	fs.Var(&h.agents, "agents", "catalog ids, comma separated (default: every agent hawkbell has a hook dialect for)")
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
	// Reinstall is set by --only-installed: one entry per hook file that
	// held hawkbell entries, and what was done with it.
	Reinstall []reinstallJSON `json:"reinstall,omitempty"`
	// Guard is the configuration change --guard makes (guard.mode).
	Guard  *guardJSON `json:"guard,omitempty"`
	Errors []string   `json:"errors,omitempty"`
}

func (a *app) hooksInstall(args []string) int {
	return a.hooksChange("install", args)
}

func (a *app) hooksUninstall(args []string) int {
	return a.hooksChange("uninstall", args)
}

const hooksInstallAbout = `Registers ` + "`<binary> hook --agent <id>`" + ` in each agent's hook file for the scope,
preserving every other key and hook. Files are replaced atomically with a
timestamped backup beside them. --dry-run prints the plan and a diff of the
changed lines only, with secrets redacted.

--only-installed rewrites hawkbell's entries only in the files that already
hold them (package upgrades and the Fleet install scripts run it: entries
an earlier release wrote report "modified" until install runs again). The
options each file was installed with (--fail-closed, --timeout) are read
back from its entries and kept unless given here; entries that no options
reproduce (edited by hand) are listed and left alone. Nothing to do is not
an error.

--guard: guard mode (rules with response ask or block answer the agent) is
not part of the hook registration but the setting guard.mode in the
configuration every hook reads on each call, ` + "`<system config dir>/hawkbell.yaml`" + `
(below --root when given). With --scope managed (or system) --guard sets
guard.mode: advisory there, keeping the rest of the file as it is; when the
file cannot be edited safely nothing is written and the exact change is
printed. With --scope user it changes no machine configuration: the hooks
are registered, the change is printed for the administrator, and the exit
code is 5 unless guard mode is already on. In hook files --guard only
allows --fail-closed.`

func (a *app) hooksChange(verb string, args []string) int {
	name := "hooks " + verb
	about := hooksInstallAbout
	usage := name + " [--scope managed|user|system] [--agents a,b] [--only-installed] [--guard [--fail-closed]] [--dry-run] [--json]"
	if verb == "uninstall" {
		about = `Removes hawkbell's registrations (and native telemetry settings hawkbell wrote)
from each agent's hook file for the scope; foreign hooks and keys stay.
A file that held nothing but hawkbell's entries is removed (kept as a backup).`
		usage = name + " [--scope managed|user|system] [--agents a,b] [--dry-run] [--json]"
	}
	fs := a.newFlags(name, usage, about)
	var h hookFlags
	h.register(fs, scopeInstallHelp)
	dry := fs.Bool("dry-run", false, "print the plan and diffs, change nothing")
	var guard, failClosed, coexist, force, onlyInstalled *bool
	var timeout *int
	var otel, binary *string
	if verb == "install" {
		guard = fs.Bool("guard", false, "turn guard mode on: set guard.mode advisory in the configuration every hook reads (managed scope; see above)")
		failClosed = fs.Bool("fail-closed", false, "with --guard, block the tool call when the hook fails (Claude Code, Cursor only)")
		timeout = fs.Int("timeout", defaultHookTimeout, "hook timeout in seconds registered with the agent")
		coexist = fs.Bool("coexist", false, "install next to another sensor's hook (numbat, Agent Beacon, Snyk)")
		otel = fs.String("otel", "", "also switch on the agents' native OpenTelemetry to this OTLP/HTTP endpoint")
		force = fs.Bool("force", false, "patch JSONC files (comments, trailing commas) in place")
		binary = fs.String("binary", "", "absolute path of the hawkbell binary the hook runs (default: this binary)")
		onlyInstalled = fs.Bool("only-installed", false, "rewrite hawkbell's entries only where a file at the scope already holds them, keeping their options")
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
	res := planResult{DryRun: *dry}
	var plans []hookinstall.Plan
	var ge *guardEdit
	only := false
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
		if *guard {
			ge = planGuardMode(hookConfigPath(o.Root), guardWrites(o.Scope))
			res.Guard = &ge.guardJSON
			if ge.Action == guardManual && guardWrites(o.Scope) {
				// The administrator asked for guard mode and it cannot be
				// switched on: refuse rather than register hooks that
				// would silently only observe.
				if h.asJSON {
					a.printJSON(res)
				}
				fmt.Fprintf(a.stderr, "hawkbell %s: --guard: nothing was written: %s", name, ge.Note)
				return exitError
			}
		}
		if only = *onlyInstalled; only {
			ex := explicitOpts{}
			fs.Visit(func(f *flag.Flag) {
				switch f.Name {
				case "guard":
					ex.guard = true
				case "fail-closed":
					ex.failClosed = true
				case "timeout":
					ex.timeout = true
				}
			})
			rps, err := planReinstall(cat, o, ex)
			if err != nil {
				return a.usageErr(name, "%v", err)
			}
			for _, rp := range rps {
				res.Reinstall = append(res.Reinstall, rp.row)
				plans = append(plans, rp.plans...)
			}
		} else {
			plans, err = hookinstall.PlanInstall(cat, o)
		}
	} else {
		o.Force = false
		plans, err = hookinstall.PlanUninstall(cat, o)
	}
	if err != nil {
		return a.usageErr(name, "%v", err)
	}
	res.Binary = o.Binary
	for _, p := range plans {
		pj := planJSON{Agent: p.AgentID, Scope: p.Scope, Path: p.Path, Action: p.Action, Note: p.Note}
		if p.Action != hookinstall.ActionUnchanged && p.Action != hookinstall.ActionUnsupported {
			pj.Diff = redactedDiff(p.Before, p.After)
		}
		res.Plans = append(res.Plans, pj)
	}
	if res.Plans == nil {
		res.Plans = []planJSON{}
	}
	if !*dry {
		// The configuration first: hooks registered while guard mode
		// stays off would only observe.
		if ge != nil {
			if err := ge.apply(); err != nil {
				res.Errors = append(res.Errors, "guard.mode: "+err.Error())
				plans = nil
			}
		}
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
		if only {
			a.printReinstall(res, o.Scope, *dry)
		} else {
			a.printPlans(res, *dry)
		}
		a.printGuard(name, ge, *dry)
	}
	if len(res.Errors) > 0 {
		if !h.asJSON {
			for _, e := range res.Errors {
				fmt.Fprintf(a.stderr, "hawkbell %s: %s\n", name, e)
			}
		}
		return exitError
	}
	if ge != nil && ge.Action == guardManual {
		// --guard was asked for and guard mode is off: a script must not
		// take this run for the guarded installation it requested.
		return exitGuardOff
	}
	return exitOK
}

// printGuard reports the guard.mode part of `hooks install --guard`.
func (a *app) printGuard(name string, ge *guardEdit, dry bool) {
	if ge == nil {
		return
	}
	p := sanitize(ge.Path)
	switch ge.Action {
	case guardUnchanged:
		fmt.Fprintf(a.stdout, "guard: guard.mode is already advisory in %s\n", p)
	case guardSet, guardCreate:
		verb := "set"
		if dry {
			verb = "would set"
		}
		how := "was " + term(ge.Was)
		if ge.Action == guardCreate {
			how = "file created from the default configuration"
		}
		fmt.Fprintf(a.stdout, "guard: %s guard.mode: advisory in %s (%s); every hawkbell hook reads it on each call\n", verb, p, how)
		if dry {
			for _, l := range ge.Diff {
				fmt.Fprintf(a.stdout, "    %s\n", sanitize(l))
			}
		}
	case guardManual:
		// A user-scope install: the hooks are registered, guard mode is
		// not on. Said on stderr, and in the exit code (5).
		a.warn(name, "--guard: guard mode is NOT on (exit %d): %s", exitGuardOff, strings.TrimSpace(ge.Note))
	}
}

func (a *app) printPlans(res planResult, dry bool) {
	changed := 0
	for _, p := range res.Plans {
		// Paths, notes and diffs quote files other accounts own (an
		// administrator's install into every home): sanitized for the
		// terminal.
		fmt.Fprintf(a.stdout, "%-12s %-8s %-11s %s\n", term(p.Agent), term(string(p.Scope)), term(p.Action), sanitize(p.Path))
		if p.Note != "" {
			for _, l := range strings.Split(strings.TrimSpace(p.Note), "\n") {
				fmt.Fprintf(a.stdout, "    note: %s\n", sanitize(l))
			}
		}
		if len(p.Diff) > 0 {
			changed++
			if dry {
				for _, l := range p.Diff {
					fmt.Fprintf(a.stdout, "    %s\n", sanitize(l))
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
	// Binaries are the programs hawkbell's entries in the file run; doctor
	// fills them in and reports one that is missing (hooks.binary_missing).
	Binaries      []string `json:"binaries,omitempty"`
	BinaryProblem string   `json:"binary_problem,omitempty"`
	// home is the home of a user-scope file: its owner is the account the
	// hook runs as.
	home string
}

func toHookStates(st []hookinstall.State, user, home string) []hookState {
	out := make([]hookState, 0, len(st))
	for _, s := range st {
		u, h := "", ""
		if s.Scope == event.ScopeUser {
			u, h = user, home
		}
		out = append(out, hookState{Agent: s.AgentID, Scope: s.Scope, User: u, Path: s.Path, Status: s.Status, Hash: s.Hash, Detail: s.Detail, home: h})
	}
	return out
}

// allHookStates audits the managed tier once, the machine-wide system tier
// where it exists, and the user tier of every account this process can see
// (every person's home when privileged).
func allHookStates(cat *catalog.Catalog, agents []string, root string) ([]hookState, error) {
	st, err := hookinstall.Status(cat, hookinstall.Options{Scope: event.ScopeManaged, Agents: agents, Root: root})
	if err != nil {
		return nil, err
	}
	out := toHookStates(st, "", "")
	out = append(out, systemHookStates(cat, agents, root)...)
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
		out = append(out, toHookStates(us, firstNonEmpty(u.Name, u.UID), u.Home)...)
	}
	return out, uerr
}

// systemHookStates audits the machine-wide tier that is not policy (Codex
// reads hooks.json beside its system config.toml; `hooks install --scope
// system` writes it). Only files that exist are returned: the tier is
// optional and absent on most machines, and the agents without one have
// nothing to report.
func systemHookStates(cat *catalog.Catalog, agents []string, root string) []hookState {
	st, err := hookinstall.Status(cat, hookinstall.Options{Scope: event.ScopeSystem, Agents: agents, Root: root})
	if err != nil {
		return nil
	}
	var keep []hookinstall.State
	for _, s := range st {
		if s.Path == "" || !filepath.IsAbs(s.Path) {
			continue
		}
		if _, err := os.Lstat(s.Path); err != nil {
			continue
		}
		keep = append(keep, s)
	}
	return toHookStates(keep, "", "")
}

func (a *app) hooksStatus(args []string) int {
	fs := a.newFlags("hooks status", "hooks status [--scope managed|user|system] [--all-users] [--agents a,b] [--json]",
		`Audits hook files. Status is one of managed, user (installed and exactly
what install would write), missing, modified, foreign_only, unsupported,
shadowed (a higher-ranked policy source makes the agent ignore the file) or
insecure_permissions. "managed" is not proof that the agent runs the hook:
Detail says what could not be seen from disk. Default: the managed tier, the
system tier where a file exists (Codex), and the caller's user tier.`)
	var h hookFlags
	h.register(fs, "managed, user or system (default: managed, system where present, and the caller's user tier)")
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
		states = toHookStates(st, platform.CurrentUser().Name, o.Home)
		if o.Scope == "" {
			states = append(states, systemHookStates(cat, h.agents, h.root)...)
		}
	}
	if h.asJSON {
		return a.printJSON(states)
	}
	tw := a.table()
	fmt.Fprintln(tw, "AGENT\tSCOPE\tUSER\tSTATUS\tPATH")
	for _, s := range states {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", term(s.Agent), term(string(s.Scope)), term(s.User), term(s.Status), sanitize(s.Path))
	}
	tw.Flush()
	for _, s := range states {
		if s.Detail != "" && s.Status != hookinstall.StatusMissing {
			fmt.Fprintf(a.stdout, "%s (%s): %s\n", term(s.Agent), term(string(s.Scope)), clip(s.Detail, 300))
		}
	}
	return exitOK
}
