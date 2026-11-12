package rules

import (
	"path"
	"sort"
	"strings"
	"time"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/features"
)

// Write-then-run. A command written into a script with a file tool and
// executed in a later event would hide every parsed shell fact from the
// rules ("sh /tmp/x.sh"). When a file_write or file_edit event writes a
// script, the engine keeps the script's shell facts (features.WrittenScripts)
// under the path digest it already uses for session.runs_written_file,
// with the script's text (credentials redacted, at most 8 KiB) so that a
// later edit is analysed in the file it lands in; when a later command or
// process.exec runs that path, the facts are merged into the executing
// event (features.Inherit) before any rule sees it, so the same rules fire
// there, with shell.inherited_kinds = written_script and
// session.written_exec_path in the detection's evidence. The bounds of
// the facts keep what the engine's rules match first (scriptKeep). A
// script that carries a credential value remembered from an earlier read
// to the network is scanned when it is written, and the execution inherits
// session.secret_flow.
//
// Nothing is read from disk: a file is never opened, whatever path a
// payload names. What is known about a file is what the agent's own file
// tools wrote into it.

// Bounds of the script memory. A session keeps at most maxScripts scripts
// (each at most features.MaxScriptBytes of facts, and the text of at most
// features.MaxScriptText, maxScriptTexts in all, for applying a later edit
// in context); writing one more evicts the least valuable (scriptRank),
// oldest first.
const (
	maxScripts     = 16
	maxScriptTexts = 32 << 10
	maxExecChecks  = 64 // executed paths examined per event, scripts run by scripts included
	maxExecDirs    = 8  // working directories one command's relative paths are resolved against
	maxFlowKinds   = 16
)

// scriptRec is one remembered script.
type scriptRec struct {
	d  string // path digest (pathDigest)
	at time.Time
	f  *features.ScriptFacts
	// text is the file's whole text with credentials redacted
	// (features.WrittenScript.Keep), or "" when it is not known.
	text string
	// flow holds the kinds of remembered credential values the script
	// sends out (session.secret_flow on its execution); flowChk says its
	// outbound text was scanned at all, flowCut that the scan hit a bound.
	flow    []string
	flowChk bool
	flowCut bool
}

func (s *sessionState) script(d string) *scriptRec {
	for i := range s.scripts {
		if s.scripts[i].d == d {
			return &s.scripts[i]
		}
	}
	return nil
}

// putScript stores r as the most recently written script, replacing an
// earlier record of the same path. Beyond maxScripts it evicts the record
// rank orders lowest, the oldest of those (r itself when it is the only
// lowest): a burst of ordinary source edits gives up its own records
// before a script that downloads and runs code. Beyond maxScriptTexts of
// held texts, the oldest texts go (their facts stay).
func (s *sessionState) putScript(r scriptRec, rank func(*scriptRec) int) {
	s.dropScript(r.d)
	s.scripts = append(s.scripts, r)
	for len(s.scripts) > maxScripts {
		low, at := -1, 0
		for i := range s.scripts {
			if v := rank(&s.scripts[i]); low < 0 || v < low {
				low, at = v, i
			}
		}
		s.scripts = append(s.scripts[:at:at], s.scripts[at+1:]...)
	}
	total := 0
	for i := range s.scripts {
		total += len(s.scripts[i].text)
	}
	for i := 0; total > maxScriptTexts && i < len(s.scripts)-1; i++ {
		total -= len(s.scripts[i].text)
		s.scripts[i].text = ""
	}
}

func (s *sessionState) dropScript(d string) {
	for i := range s.scripts {
		if s.scripts[i].d == d {
			s.scripts = append(s.scripts[:i:i], s.scripts[i+1:]...)
			return
		}
	}
}

// scriptRank orders remembered scripts for eviction: facts no rule can
// match (0), facts with commands, paths or hosts only (1), facts with a
// command a rule matches or a notable fact (2), or that send a remembered
// credential value (3).
func (e *Engine) scriptRank(r *scriptRec) int {
	switch {
	case len(r.flow) > 0:
		return 3
	case r.f.Notable():
		return 2
	case r.f.Inert():
		return 0
	}
	for _, c := range r.f.Cmds {
		if e.keep.Command(c) {
			return 2
		}
	}
	return 1
}

// inheritance is what an event inherited from the scripts it runs.
type inheritance struct {
	flow             []string
	flowChk, flowCut bool
}

// execTargets returns the paths an event names as executed (execPaths,
// which session.runs_written_file has always used) and, of those and of
// the files a shell feeds to an interpreter on standard input (bash <
// x.sh, cat x.sh | sh), the ones it really runs: only those inherit a
// written script's facts. shellx also lists chmod and attribute targets and
// the script of a syntax check (sh -n x.sh, node --check x.js) as executed,
// which is right for correlating a download with its execution on one
// command line but would make "chmod +x a.sh b.sh" or a syntax check
// carry everything the scripts do.
func execTargets(ev *event.Event) (named, run []string) {
	named = execPaths(ev)
	f := ev.Feat
	cmds, _ := f["shell.cmds"].([]map[string]any)
	exe := ""
	if ev.Type == event.TypeProcessExec && ev.Process != nil {
		exe = ev.Process.Exe
	}
	for _, p := range named {
		if p == exe || runsPath(p, cmds) {
			run = append(run, p)
		}
	}
	if readsProgram(cmds) {
		reads, _ := f["shell.reads"].([]string)
		for _, r := range reads {
			if fedToInterpreter(r, cmds) {
				run = append(run, r)
			}
		}
	}
	if len(named) > maxExecChecks {
		named = named[:maxExecChecks]
	}
	if len(run) > maxExecChecks {
		run = run[:maxExecChecks]
	}
	return named, run
}

// readsProgram reports a command line with an interpreter that reads its
// program from standard input (sh, bash -s, python3 -, pwsh -Command -):
// a file a redirect or a plain reader hands to the line can be its
// program. An interpreter given program text (sh -c, node -e) or a script
// file reads its program from there, so a one-liner elsewhere on the line
// does not make a redirect a run, and does not hide one either.
func readsProgram(cmds []map[string]any) bool {
	for _, c := range cmds {
		name, _ := c["name"].(string)
		args, _ := c["args"].([]string)
		if k, _ := launchOf(name, args); k == launchStdin {
			return true
		}
	}
	return false
}

// runsPath reports whether a parsed command runs p: p is the command word
// itself (./x.sh, /tmp/x, also behind sudo or timeout), or the script
// argument of an interpreter or of source / "." (scriptArg).
func runsPath(p string, cmds []map[string]any) bool {
	for _, c := range cmds {
		if path, _ := c["path"].(string); path == p {
			return true
		}
		name, _ := c["name"].(string)
		args, _ := c["args"].([]string)
		if i := scriptArg(name, args); i >= 0 && args[i] == p {
			return true
		}
	}
	return false
}

// launchKind is where an interpreter command takes its program from.
type launchKind uint8

const (
	launchNone  launchKind = iota // not an interpreter
	launchFile                    // a script file argument
	launchStdin                   // standard input
	launchText                    // program text on the command line (sh -c, node -e, python -m), or no program (--version)
	launchCheck                   // a check-only mode that parses the program without running it
)

// scriptArg returns the index in args of the script file the interpreter
// name runs, or -1 (see launchOf).
func scriptArg(name string, args []string) int {
	if k, i := launchOf(name, args); k == launchFile {
		return i
	}
	return -1
}

// launchOf returns where the interpreter name takes its program from and,
// for a script file, its index in args: program text given on the command
// line (sh -c, python -c / -m, node -e, perl -e, pwsh -Command), standard
// input ("-", sh -s, or no script at all), or a check-only mode that
// parses the script without running it (sh -n, sh -o noexec, node
// --check, perl -c, ruby -c, php -l). Options that take a value as the
// next word are skipped, so in "python3 -W ignore x.py" the file is x.py,
// and a shell's "+" options (bash +x, +o posix) are read like its "-" ones.
func launchOf(name string, args []string) (launchKind, int) {
	switch {
	case name == "source" || name == ".":
		if len(args) > 0 {
			return launchFile, 0
		}
		return launchNone, -1
	case name == "pwsh" || name == "powershell" || name == "powershell_ise" || name == "pwsh-preview":
		return pwshLaunch(args)
	case name == "wscript" || name == "cscript":
		for i, a := range args {
			if !strings.HasPrefix(a, "/") && !strings.HasPrefix(a, "-") {
				return launchFile, i
			}
		}
		return launchNone, -1
	}
	spec, ok := interpSpecs(name)
	if !ok {
		return launchNone, -1
	}
	i := 0
	if spec.sub != "" && len(args) > 0 && args[0] == spec.sub {
		i = 1 // deno run x.ts, bun run x.js
	}
	for ; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			if i+1 < len(args) {
				return launchFile, i + 1
			}
			return launchStdin, -1
		case a == "-":
			return launchStdin, -1
		case spec.shell && len(a) >= 2 && a[0] == '+':
			// set +x / +o name: an option turned off, never the script.
			if strings.IndexByte(spec.val, a[len(a)-1]) >= 0 {
				i++
			}
		case len(a) < 2 || a[0] != '-':
			return launchFile, i
		case strings.HasPrefix(a, "--"):
			opt, _, hasVal := strings.Cut(a, "=")
			if contains(spec.longCheck, opt) {
				return launchCheck, -1
			}
			if contains(spec.longStop, opt) {
				return launchText, -1
			}
			if !hasVal && contains(spec.longVal, opt) {
				i++
			}
		default:
			if a == "-o" && i+1 < len(args) && args[i+1] == "noexec" && spec.shell {
				return launchCheck, -1
			}
			// A short cluster: a stop letter ends it (code, check or
			// stdin), a value letter takes the rest or the next word,
			// the file letter names the script (php -f x.php).
			for j := 1; j < len(a); j++ {
				ch := a[j]
				if strings.IndexByte(spec.stop, ch) >= 0 {
					switch {
					case strings.IndexByte(spec.check, ch) >= 0:
						return launchCheck, -1
					case spec.stdin != 0 && ch == spec.stdin:
						return launchStdin, -1
					}
					return launchText, -1
				}
				if spec.file != 0 && ch == spec.file {
					if j < len(a)-1 || i+1 >= len(args) {
						return launchText, -1 // attached value: not a separate word to compare
					}
					return launchFile, i + 1
				}
				if strings.IndexByte(spec.val, ch) >= 0 {
					if j == len(a)-1 {
						i++
					}
					break
				}
			}
		}
	}
	return launchStdin, -1
}

// interpSpec is what launchOf needs to know about an interpreter's
// options: short letters that end the options because program text, a
// check-only mode or standard input follows (stop; check and stdin say
// which of them are which, the others are program text), short letters
// that take a value (val), the same for long options, and a subcommand
// that precedes the script.
type interpSpec struct {
	stop, check, val             string
	stdin, file                  byte
	longStop, longCheck, longVal []string
	sub                          string
	shell                        bool
}

// UNVERIFIED: the option letters below come from the interpreters' usage
// texts as remembered, not re-read for this table: the stop letters that
// matter most (sh -c/-n/-s, python -c/-m, node -e/-p/-c, perl -e/-c,
// ruby -e/-c, php -r/-l) are long-standing; the value-taking letters of
// perl, ruby and php are less certain. A wrong value letter only shifts
// which argument counts as the script. perl's and ruby's -x takes its
// directory attached (-xdir), never as the next word.
func interpSpecs(name string) (interpSpec, bool) {
	switch name {
	case "sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "yash", "posh", "rbash", "fish", "csh", "tcsh":
		return interpSpec{stop: "cns", check: "n", stdin: 's', val: "oO", longVal: []string{"--rcfile", "--init-file"}, shell: true}, true
	case "busybox":
		return interpSpec{}, false // busybox <applet> ...: the applet is the program
	case "node", "nodejs":
		return interpSpec{stop: "epc", check: "c", val: "rC",
			longStop:  []string{"--eval", "--print", "--test", "--interactive"},
			longCheck: []string{"--check"},
			longVal: []string{"--require", "--import", "--loader", "--experimental-loader", "--conditions",
				"--inspect-port", "--title", "--input-type", "--env-file", "--max-old-space-size", "--redirect-warnings"},
		}, true
	case "deno":
		return interpSpec{sub: "run", longStop: []string{"--eval"}}, true
	case "bun":
		return interpSpec{sub: "run", stop: "e", longStop: []string{"--eval", "--print"}}, true
	case "tsx", "ts-node":
		return interpSpec{stop: "ep", longStop: []string{"--eval", "--print"}, val: "r", longVal: []string{"--require", "--tsconfig"}}, true
	case "osascript":
		return interpSpec{stop: "e", val: "l"}, true
	case "luajit":
		return interpSpec{stop: "e", val: "l"}, true
	case "py":
		return interpSpec{stop: "cm", val: "WX"}, true
	}
	for _, x := range []struct {
		pre  string
		spec interpSpec
	}{
		{"python", interpSpec{stop: "cm", val: "WX", longStop: []string{"--version", "--help"}}},
		{"pypy", interpSpec{stop: "cm", val: "WX"}},
		{"perl", interpSpec{stop: "eEcv", check: "c", val: "IMm"}},
		{"ruby", interpSpec{stop: "ecvy", check: "c", val: "IrCEF"}},
		{"php", interpSpec{stop: "rlRBEia", check: "l", val: "cdzt", file: 'f', longStop: []string{"--run"}, longCheck: []string{"--syntax-check"}}},
		{"lua", interpSpec{stop: "e", val: "l"}},
	} {
		if rest, ok := strings.CutPrefix(name, x.pre); ok && versionTail(rest) {
			return x.spec, true
		}
	}
	return interpSpec{}, false
}

func versionTail(s string) bool {
	for i := 0; i < len(s); i++ {
		if !(s[i] >= '0' && s[i] <= '9' || s[i] == '.') {
			return false
		}
	}
	return true
}

// UNVERIFIED: that every parameter accepts an unambiguous prefix, the
// one-letter aliases (-w WindowStyle, -o OutputFormat, -f File, -c
// Command, -e EncodedCommand) and that Windows PowerShell 5.1 also takes
// /Parameter are from memory of the about_Pwsh / PowerShell.exe help, not
// re-read here.
//
// pwshLaunch finds the program of a PowerShell command line: the value of
// -File (any unambiguous prefix, case-insensitive), or the first
// positional when no -Command / -EncodedCommand came first; "-" as the
// -File or -Command value, or no program at all, reads standard input.
// Parameter values are skipped; -Sta and -Mta are switches.
func pwshLaunch(args []string) (launchKind, int) {
	for i := 0; i < len(args); i++ {
		a := strings.ToLower(args[i])
		// Windows PowerShell also takes /Option; a slash followed by a
		// path (pwsh /tmp/x.ps1 on Linux) is the script.
		slashOpt := strings.HasPrefix(a, "/") && !strings.ContainsAny(a[1:], "/.\\")
		if a == "-" {
			return launchStdin, -1
		}
		if !strings.HasPrefix(a, "-") && !slashOpt {
			return launchFile, i
		}
		opt := strings.TrimLeft(a, "-/")
		if opt, _, _ = strings.Cut(opt, ":"); opt == "" {
			continue
		}
		switch {
		case strings.HasPrefix("file", opt):
			if i+1 < len(args) && args[i+1] != "-" {
				return launchFile, i + 1
			}
			return launchStdin, -1
		case strings.HasPrefix("command", opt):
			if i+1 < len(args) && args[i+1] == "-" {
				return launchStdin, -1
			}
			return launchText, -1
		case strings.HasPrefix("encodedcommand", opt) && len(opt) >= 2, opt == "ec", opt == "e", opt == "enc":
			return launchText, -1
		case opt == "w", opt == "o":
			i++ // -w WindowStyle, -o OutputFormat
			continue
		}
		for _, v := range []string{"executionpolicy", "ep", "workingdirectory", "wd", "configurationname", "outputformat",
			"inputformat", "windowstyle", "version", "psconsolefile", "custompipename", "settingsfile"} {
			if opt == v || (len(opt) >= 2 && strings.HasPrefix(v, opt)) {
				i++
				break
			}
		}
	}
	return launchStdin, -1
}

// fedToInterpreter reports a read that reaches an interpreter's standard
// input: a redirect (no command has it as an argument) or the argument of
// a plain concatenating reader.
func fedToInterpreter(r string, cmds []map[string]any) bool {
	for _, c := range cmds {
		args, _ := c["args"].([]string)
		for _, a := range args {
			if a != r {
				continue
			}
			switch name, _ := c["name"].(string); name {
			case "cat", "tac", "type", "get-content", "gc":
				continue
			default:
				return false
			}
		}
	}
	return true
}

// execDirs returns the working directories a command's relative paths may
// be relative to: the session's, then each literal cd / pushd target in
// the command line, in order (cd build && ./run.sh).
func execDirs(ev *event.Event, cwd, home string) []string {
	dirs := []string{cwd}
	cmds, _ := ev.Feat["shell.cmds"].([]map[string]any)
	cur := cwd
	for _, c := range cmds {
		if len(dirs) >= maxExecDirs {
			break
		}
		if name, _ := c["name"].(string); name != "cd" && name != "pushd" {
			continue
		}
		if dyn, _ := c["dynamic"].(bool); dyn {
			continue
		}
		args, _ := c["args"].([]string)
		target := ""
		for _, a := range args {
			if a == "--" || (strings.HasPrefix(a, "-") && len(a) > 1) {
				continue
			}
			target = a
			break
		}
		if d := resolveDir(target, cur, home); d != "" {
			cur = d
			dirs = append(dirs, d)
		}
	}
	return dirs
}

// resolveDir resolves a cd target lexically, or returns "".
func resolveDir(target, cwd, home string) string {
	t := strings.ReplaceAll(strings.TrimSpace(target), `\`, "/")
	switch {
	case t == "" || t == "-" || len(t) > 4096 || strings.ContainsAny(t, "$`*?"):
		return ""
	case t == "~" || strings.HasPrefix(t, "~/"):
		if home == "" {
			return ""
		}
		t = strings.ReplaceAll(home, `\`, "/") + t[1:]
	case strings.HasPrefix(t, "/") || (len(t) >= 2 && t[1] == ':'):
	default:
		if cwd == "" {
			return ""
		}
		t = strings.ReplaceAll(cwd, `\`, "/") + "/" + t
	}
	return path.Clean(t)
}

// runWritten sets session.runs_written_file and session.written_exec_path
// for an event that executes a path the session wrote, and merges into
// the event the facts of every remembered script it runs (and, through
// the paths those scripts run themselves, of the scripts they start). It
// must run before the event's fields are built. written_exec_path names
// the first script whose facts were merged, else the first written path
// the event names as executed.
func (e *Engine) runWritten(st *sessionState, ev *event.Event, cwd, goos string) (inh inheritance) {
	f := ev.Feat
	named, queue := execTargets(ev)
	if len(named) == 0 && len(queue) == 0 {
		if f["shell.parse_ok"] != nil {
			f["session.runs_written_file"] = false
		}
		return inh
	}
	dirs := execDirs(ev, cwd, e.o.Home)
	firstNamed, firstInherited := "", ""
	for _, p := range named {
		for _, dir := range dirs {
			if d := pathDigest(p, dir, e.o.Home, goos); d != "" && firstNamed == "" && st.hasWritten(d) {
				firstNamed = p
			}
		}
	}
	seen := map[string]bool{}
	for i := 0; i < len(queue) && i < maxExecChecks; i++ {
		p := queue[i]
		for _, dir := range dirs {
			d := pathDigest(p, dir, e.o.Home, goos)
			if d == "" || seen[d] {
				continue
			}
			seen[d] = true
			rec := st.script(d)
			if rec == nil {
				if firstNamed == "" && st.hasWritten(d) {
					firstNamed = p
				}
				continue
			}
			// An event evaluated again (a hook retrying on newer state)
			// already carries the script's facts; its flow comes from the
			// state as it is now, like the first time.
			if !features.Inherited(ev, d) && !features.Inherit(ev, rec.f, d) {
				continue
			}
			if firstInherited == "" {
				firstInherited = p
			}
			if rec.flowChk {
				inh.flowChk = true
				inh.flow = mergeKinds(inh.flow, rec.flow)
				inh.flowCut = inh.flowCut || rec.flowCut
			}
			// A script that runs another written script passes it on
			// (only the paths it really runs; relative ones resolve
			// against the same directories).
			queue = append(queue, scriptRuns(rec.f)...)
		}
	}
	switch {
	case firstInherited != "":
		f["session.runs_written_file"] = true
		f["session.written_exec_path"] = firstInherited
	case firstNamed != "":
		f["session.runs_written_file"] = true
		f["session.written_exec_path"] = firstNamed
	default:
		f["session.runs_written_file"] = false
	}
	return inh
}

// scriptRuns returns the paths a remembered script really runs.
func scriptRuns(s *features.ScriptFacts) []string {
	paths := s.Lists["shell.executes_paths"]
	if len(paths) == 0 {
		return nil
	}
	cmds := make([]map[string]any, 0, len(s.Cmds))
	for _, c := range s.Cmds {
		cmds = append(cmds, map[string]any{"name": c.Name, "path": c.Path, "args": c.Args})
	}
	var out []string
	for _, p := range paths {
		if runsPath(p, cmds) {
			out = append(out, p)
		}
	}
	return out
}

// rememberScripts records the scripts a file-tool event writes, forgets
// files it replaces with something that is not a script or deletes, and
// scans each script that contacts the network for remembered credential
// values. An edit is applied to the text held for the file when there is
// one. stop bounds the analysis and the scan like the event's own
// outbound scan: both share the half of the event's budget the rules do
// not get.
func (e *Engine) rememberScripts(st *sessionState, ev *event.Event, cwd, goos string, now time.Time, stop func() bool) {
	ctx := features.Context{Home: e.o.Home, CWD: cwd, OS: goos}
	opts := features.ScriptOptions{
		Stop: stop,
		Keep: e.keep,
		Prior: func(p string) (string, bool) {
			if d := pathDigest(p, cwd, e.o.Home, goos); d != "" {
				if r := st.script(d); r != nil && r.text != "" {
					return r.text, true
				}
			}
			return "", false
		},
	}
	for _, ws := range features.WrittenScripts(ev, ctx, opts) {
		d := pathDigest(ws.Path, cwd, e.o.Home, goos)
		if d == "" {
			continue
		}
		var prev *scriptRec
		if ws.From != "" {
			if fd := pathDigest(ws.From, cwd, e.o.Home, goos); fd != "" {
				if r := st.script(fd); r != nil {
					cp := *r
					prev = &cp
				}
				st.dropScript(fd)
			}
		}
		if prev == nil && (!ws.Replace || ws.InContext) {
			if r := st.script(d); r != nil {
				cp := *r
				prev = &cp
			}
		}
		switch {
		case ws.Remove:
			st.dropScript(d)
			continue
		case ws.Facts == nil && (ws.Replace || prev == nil):
			// Replaced by something that is not a script (or an edit of
			// a file nothing is known about that does not read as one).
			st.dropScript(d)
			continue
		case ws.Facts == nil:
			// Moved or touched without new content: what was known moves
			// with it.
			rec := *prev
			rec.d, rec.at = d, now
			st.putScript(rec, e.scriptRank)
			continue
		}
		rec := scriptRec{d: d, at: now, f: ws.Facts, text: ws.Keep}
		rec.flow, rec.flowChk, rec.flowCut = st.scriptFlow(ws, stop)
		if prev != nil {
			switch {
			case ws.InContext:
				// The held text has credential values redacted, so the
				// scan of the edited text cannot find what the earlier
				// text sent: that is kept.
				rec.flow = mergeKinds(prev.flow, rec.flow)
				rec.flowChk = rec.flowChk || prev.flowChk
				rec.flowCut = rec.flowCut || prev.flowCut
			case !ws.Replace:
				merged := prev.f.Clone()
				merged.Merge(rec.f, e.keep)
				rec.f, rec.text = merged, ""
				rec.flow = mergeKinds(prev.flow, rec.flow)
				rec.flowChk = rec.flowChk || prev.flowChk
				rec.flowCut = rec.flowCut || prev.flowCut
			}
		}
		st.putScript(rec, e.scriptRank)
	}
}

// scriptFlow scans a written script that contacts the network for the
// credential values the session remembers, as the outbound scan would scan
// a command line carrying the same text.
func (s *sessionState) scriptFlow(ws features.WrittenScript, stop func() bool) (kinds []string, checked, truncated bool) {
	if len(s.secrets) == 0 || ws.Text == "" || ws.Facts == nil {
		return nil, false, false
	}
	l := ws.Facts.Lists
	feat := map[string]any{}
	for _, k := range []string{"shell.hosts", "shell.urls", "shell.net_tools", "shell.exfil"} {
		if v := l[k]; len(v) > 0 {
			feat[k] = v
		}
	}
	if len(feat) == 0 {
		return nil, false, false
	}
	probe := &event.Event{Target: &event.Target{Command: ws.Text}, Tool: &event.Tool{Kind: event.ToolShell}, Feat: feat}
	kinds, checked, truncated = s.secretFlow(probe, stop)
	if len(kinds) > maxFlowKinds {
		kinds = kinds[:maxFlowKinds]
	}
	return kinds, checked, truncated
}

// mergeKinds returns the sorted union of a and b.
func mergeKinds(a, b []string) []string {
	if len(b) == 0 {
		return a
	}
	seen := map[string]bool{}
	var out []string
	for _, l := range [][]string{a, b} {
		for _, k := range l {
			if !seen[k] {
				seen[k] = true
				out = append(out, k)
			}
		}
	}
	sort.Strings(out)
	if len(out) > maxFlowKinds {
		out = out[:maxFlowKinds]
	}
	return out
}

// inheritedEvidence adds the write-then-run marker to a detection's
// evidence: which kind of inheritance happened and which written path ran,
// so a finding on "sh /tmp/x.sh" says why it fired.
func (e *Engine) inheritedEvidence(ev map[string]string, fields map[string]any, memo evidenceMemo) map[string]string {
	kinds, _ := fields["shell.inherited_kinds"].([]string)
	if len(kinds) == 0 {
		return ev
	}
	if ev == nil {
		ev = map[string]string{}
	}
	for _, f := range []string{"shell.inherited_kinds", "session.written_exec_path"} {
		if _, ok := ev[f]; ok {
			continue
		}
		v, ok := memo[f]
		if !ok {
			v = e.renderEvidence(f, fields)
			if memo != nil {
				memo[f] = v
			}
		}
		if v != "" {
			ev[f] = v
		}
	}
	return ev
}

// inheritedReason is appended to a guard response's reason when the event
// runs a script written earlier, so the person asked to confirm "sh x.sh"
// learns what the script does is why.
func inheritedReason(fields map[string]any) string {
	kinds, _ := fields["shell.inherited_kinds"].([]string)
	p, _ := fields["session.written_exec_path"].(string)
	if len(kinds) == 0 || p == "" {
		return ""
	}
	return " (in " + cutString(p, 128) + ", written earlier in this session)"
}
