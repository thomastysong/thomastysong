package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"

	"github.com/thomastysong/spoor/internal/catalog"
	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/hookinstall"
	"github.com/thomastysong/spoor/internal/spool"
)

const ciAbout = `EXPERIMENTAL. Runs a command (typically an AI agent in a CI job) with spoor
hooks registered in a temporary config home for every agent that can be
relocated by an environment variable (CLAUDE_CONFIG_DIR, CODEX_HOME,
COPILOT_HOME, GEMINI_CLI_HOME), and the hook spool in a temporary
directory (SPOOR_SPOOL). When the command ends, the spool (activity with its
local content) is evaluated with the full rule set, the findings are
printed, and the exit code is 3 when a finding is at or above --fail-on,
otherwise the command's own exit code.

Limits: the temporary config home replaces the agent's own (settings, MCP
servers and stored logins are not carried over: authenticate with
environment variables, as CI normally does); Cursor has no relocation
variable and is skipped unless --in-place; Codex runs user-level hooks only
after the user trusts them, so Codex is not covered in CI; agents run inside
a uses: action step are not covered. --in-place registers user-scope hooks in
the real home instead (for throwaway runners) and removes them afterwards.
Unix only.`

func (a *app) cmdCI(args []string) int {
	return a.dispatch("ci", []subcommand{
		{"exec", "run a command with hooks in a temporary config home, then report findings", a.ciExec},
	}, args)
}

type ciResult struct {
	Command  []string    `json:"command"`
	ExitCode int         `json:"exit_code"`
	Hooks    []planJSON  `json:"hooks"`
	Report   *evalReport `json:"report"`
}

func (a *app) ciExec(args []string) int {
	fs := a.newFlags("ci exec", "ci exec [--fail-on high] [--agents a,b] [--in-place] [--keep] [--json] -- <command> [args...]", ciAbout)
	var cf cfgFlags
	cf.register(fs)
	failOn := fs.String("fail-on", "high", "exit 3 when a detection is at or above this severity or class; none disables")
	var agents listFlag
	fs.Var(&agents, "agents", "catalog ids to hook (default: every relocatable agent spoor has a dialect for)")
	inPlace := fs.Bool("in-place", false, "register user-scope hooks in the real home and remove them afterwards")
	keep := fs.Bool("keep", false, "keep the temporary directory (spool and config homes) for inspection")
	asJSON := fs.Bool("json", false, "print one JSON document")
	pos, code, done := a.parse(fs, args)
	if done {
		return code
	}
	if len(pos) == 0 {
		return a.usageErr("ci exec", "give the command after --, e.g. spoor ci exec -- claude -p \"run the tests\"")
	}
	if runtime.GOOS == "windows" {
		return a.fail("ci exec", errors.New("not supported on Windows"))
	}
	th, err := parseFailOn(*failOn)
	if err != nil {
		return a.usageErr("ci exec", "%v", err)
	}
	cfg, _, err := loadConfig(cf)
	if err != nil {
		return a.fail("ci exec", err)
	}
	set, _, err := loadRules(cfg, ruleSource{})
	if err != nil {
		return a.fail("ci exec", err)
	}
	cat, err := catalog.Load()
	if err != nil {
		return a.fail("ci exec", err)
	}
	exe, err := a.executable()
	if err != nil {
		return a.fail("ci exec", err)
	}
	tmp, err := os.MkdirTemp("", "spoor-ci-")
	if err != nil {
		return a.fail("ci exec", err)
	}
	if *keep {
		fmt.Fprintf(a.stderr, "spoor ci exec: keeping %s\n", tmp)
	} else {
		defer os.RemoveAll(tmp)
	}
	spoolDir := filepath.Join(tmp, "spool")
	if err := os.Mkdir(spoolDir, 0o700); err != nil {
		return a.fail("ci exec", err)
	}
	env := map[string]string{spool.EnvSpool: spoolDir}
	o := hookinstall.Options{Binary: exe, Scope: event.ScopeUser, Home: a.homeDir()}
	if *inPlace {
		o.Agents = agents
		o.Env = a.relocationEnv(cat)
	} else {
		o.Env = map[string]string{}
		for _, p := range cat.Products() {
			if p.Hooks == nil || p.Hooks.Dialect == "" || !wanted(agents, p.ID) {
				continue
			}
			if len(p.HomeEnv) == 0 {
				fmt.Fprintf(a.stderr, "spoor ci exec: %s skipped: it has no config-home variable (use --in-place)\n", p.ID)
				continue
			}
			home := filepath.Join(tmp, "home", p.ID)
			if err := os.MkdirAll(home, 0o700); err != nil {
				return a.fail("ci exec", err)
			}
			for _, k := range p.HomeEnv {
				o.Env[k], env[k] = home, home
			}
			o.Agents = append(o.Agents, p.ID)
		}
		if len(o.Agents) == 0 {
			return a.usageErr("ci exec", "no agent to hook (see --agents and --in-place)")
		}
	}
	plans, err := hookinstall.PlanInstall(cat, o)
	if err != nil {
		return a.fail("ci exec", err)
	}
	res := ciResult{Command: pos}
	for _, p := range plans {
		res.Hooks = append(res.Hooks, planJSON{Agent: p.AgentID, Scope: p.Scope, Path: p.Path, Action: p.Action, Note: p.Note})
	}
	if err := hookinstall.Apply(plans); err != nil {
		return a.fail("ci exec", fmt.Errorf("installing hooks: %w", err))
	}
	if *inPlace {
		defer func() {
			un, err := hookinstall.PlanUninstall(cat, o)
			if err == nil {
				err = hookinstall.Apply(un)
			}
			if err != nil {
				a.warn("ci exec", "removing the hooks: %v", err)
			}
		}()
	}
	res.ExitCode, err = a.runChild(pos, env)
	if err != nil {
		return a.fail("ci exec", err)
	}
	stats := newInputStats()
	rd := &eventReader{format: formatNative, stats: stats}
	rep, err := evaluate(evalOptions{cfg: cfg, set: set, catalog: cat, now: a.now}, stats, func(emit func(*event.Event)) error {
		files, err := spoolFiles(spoolDir)
		if err != nil {
			return err
		}
		for _, f := range files {
			if err := rd.readFile(f, emit); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return a.fail("ci exec", err)
	}
	res.Report = rep
	hits := rep.applyFailOn(th)
	if *asJSON {
		if c := a.printJSON(res); c != exitOK {
			return c
		}
	} else {
		fmt.Fprintf(a.stdout, "\n--- spoor ci exec: %s exited %d ---\n", filepath.Base(pos[0]), res.ExitCode)
		printReport(a.stdout, rep)
		if stats.Evaluated == 0 {
			fmt.Fprintln(a.stdout, "no hook record was written: the command ran no hooked agent (or its hooks did not fire)")
		}
	}
	if hits > 0 {
		return exitFindings
	}
	return res.ExitCode
}

func wanted(list []string, id string) bool {
	if len(list) == 0 {
		return true
	}
	for _, x := range list {
		if x == id {
			return true
		}
	}
	return false
}

// runChild runs the command with the extra environment and the caller's
// stdio, forwarding SIGINT and SIGTERM, and returns its exit code.
func (a *app) runChild(argv []string, extra map[string]string) (int, error) {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = a.stdin, a.stdout, a.stderr
	env := os.Environ()
	for _, k := range sortedKeys(extra) {
		env = append(env, k+"="+extra[k])
	}
	cmd.Env = env
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	if err := cmd.Start(); err != nil {
		signal.Stop(sig)
		return 0, err
	}
	go func() {
		for s := range sig {
			_ = cmd.Process.Signal(s)
		}
	}()
	err := cmd.Wait()
	signal.Stop(sig)
	close(sig)
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal()), nil
		}
		return ee.ExitCode(), nil
	}
	if err != nil {
		return 0, err
	}
	return 0, nil
}

// spoolFiles lists the spool's stream files, activity first and in date
// order, ignoring the state/ directory of guard mode.
func spoolFiles(dir string) ([]string, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if e.Type().IsRegular() && strings.HasSuffix(e.Name(), ".ndjson") {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return segmentOrder(filepath.Base(out[i])) < segmentOrder(filepath.Base(out[j]))
	})
	return out, nil
}
