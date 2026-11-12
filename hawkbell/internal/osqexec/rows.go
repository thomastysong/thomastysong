package osqexec

import (
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/classify"
	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// Bounds on row content. A command line is whatever a process chose to exec.
const (
	sqlCmdline   = 4096 // substr() applied inside osquery
	maxArgs      = 64
	maxArgBytes  = 512
	maxArgsBytes = 4096
	maxPathBytes = 1024
	maxPID       = 1 << 30
)

type rowKind uint8

const (
	rowOther rowKind = iota
	rowExec
	rowFork
)

// tableSpec describes one evented process table. sql takes the lower time
// bound, the page size and the offset, in that order. Every statement
// constrains the time column; see the package comment for why that matters.
type tableSpec struct {
	name string
	sql  string
	// classify reads one row and returns its kind plus the process and
	// parent pids the row is about.
	classify func(row map[string]string) (kind rowKind, pid, ppid int)
}

// tablesFor lists the candidate tables for an OS ("" = the running one).
func tablesFor(goos string) []tableSpec {
	if goos == "" {
		goos = runtime.GOOS
	}
	switch goos {
	case "linux":
		return []tableSpec{linuxAudit}
	case "darwin":
		return []tableSpec{darwinES}
	case "windows":
		return []tableSpec{windowsETW}
	}
	return nil
}

var linuxAudit = tableSpec{
	name: "process_events",
	sql: "SELECT pid, parent, path, substr(cmdline, 1, " + strconv.Itoa(sqlCmdline) + ") AS cmdline, cwd, uid, syscall, time, eid " +
		"FROM process_events WHERE time >= %d ORDER BY time, eid LIMIT %d OFFSET %d",
	classify: func(r map[string]string) (rowKind, int, int) {
		pid, ppid := atoiPID(r["pid"]), atoiPID(r["parent"])
		switch r["syscall"] {
		case "", "execve", "execveat":
			return rowExec, pid, ppid
		case "fork", "vfork", "clone", "clone3":
			// Only present with --audit_allow_fork_process_events; useful
			// to follow a subshell, never an event of its own.
			return rowFork, pid, ppid
		}
		return rowOther, pid, ppid
	},
}

var darwinES = tableSpec{
	name: "es_process_events",
	sql: "SELECT pid, parent, path, substr(cmdline, 1, " + strconv.Itoa(sqlCmdline) + ") AS cmdline, cwd, uid, username, event_type, child_pid, time, eid " +
		"FROM es_process_events WHERE time >= %d ORDER BY time, eid LIMIT %d OFFSET %d",
	classify: func(r map[string]string) (rowKind, int, int) {
		pid, ppid := atoiPID(r["pid"]), atoiPID(r["parent"])
		// UNVERIFIED: the event_type spellings ("exec", "fork", "exit") are
		// from memory of osquery's EndpointSecurity subscriber; the table
		// spec only says "Type of EndpointSecurity event". An empty or
		// unknown type that is not fork or exit is treated as exec so that
		// a different spelling degrades to more rows, not to silence.
		switch t := strings.ToLower(r["event_type"]); {
		case strings.Contains(t, "fork"):
			// The row is about the forking process; child_pid is the new one.
			return rowFork, atoiPID(r["child_pid"]), pid
		case strings.Contains(t, "exit"):
			return rowOther, pid, ppid
		}
		return rowExec, pid, ppid
	},
}

var windowsETW = tableSpec{
	name: "process_etw_events",
	sql: "SELECT pid, ppid, path, substr(cmdline, 1, " + strconv.Itoa(sqlCmdline) + ") AS cmdline, username, type, time, eid " +
		"FROM process_etw_events WHERE time >= %d ORDER BY time, eid LIMIT %d OFFSET %d",
	classify: func(r map[string]string) (rowKind, int, int) {
		pid, ppid := atoiPID(r["pid"]), atoiPID(r["ppid"])
		// "ProcessStart" and "ProcessStop" are the values in the table spec.
		if strings.EqualFold(r["type"], "ProcessStop") {
			return rowOther, pid, ppid
		}
		return rowExec, pid, ppid
	},
}

// rec is one parsed row.
type rec struct {
	kind      rowKind
	pid, ppid int
	time      int64
	eid       uint64
	key       string // identity of the row for the seen set
	row       map[string]string
}

// parseRows validates rows and orders them oldest first. osquery returns
// every value as a string; the event id is a zero-padded string on POSIX and
// an integer on Windows, so it is compared as a number.
func parseRows(t *tableSpec, rows []map[string]string) []rec {
	out := make([]rec, 0, len(rows))
	for _, r := range rows {
		if r == nil {
			continue
		}
		ts, ok := parseInt64(r["time"])
		if !ok || ts <= 0 {
			continue
		}
		kind, pid, ppid := t.classify(r)
		if pid <= 0 {
			continue
		}
		x := rec{kind: kind, pid: pid, ppid: ppid, time: ts, row: r}
		eid := strings.TrimSpace(r["eid"])
		if n, err := strconv.ParseUint(eid, 10, 64); err == nil && len(eid) <= 20 {
			x.eid = n
			x.key = strconv.FormatUint(n, 10)
		} else {
			// No usable event id: identify the row by its content, keyed
			// (runkey.go) because the key becomes part of the event id and
			// the command line in it is unredacted.
			x.key = contentRowKey(r["time"], r["pid"], r["path"], r["cmdline"])
		}
		out = append(out, x)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].time != out[j].time {
			return out[i].time < out[j].time
		}
		return out[i].eid < out[j].eid
	})
	return out
}

func atoiPID(v string) int {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n <= 0 || n > maxPID {
		return 0
	}
	return n
}

// convert attributes one row and, for an attributed exec, builds the event.
func (s *Source) convert(t *tableSpec, r *rec) *event.Event {
	if r.kind == rowOther {
		return nil
	}
	agentID, sessionID, ok := "", "", false
	if s.attribute != nil {
		agentID, sessionID, ok = s.attribute(r.pid, r.ppid)
	}
	agentID, sessionID, ok = s.chain.resolve(r, agentID, sessionID, ok)
	if !ok || r.kind != rowExec {
		return nil
	}
	row := r.row
	ts := time.Unix(r.time, 0).UTC()
	ev := event.New(event.KindActivity, event.TypeProcessExec, event.SourceOsquery)
	ev.TS = event.At(ts)
	// Deterministic: a replayed poll (sensor restart inside the lookback)
	// produces the same id and collapses downstream. A row without an eid
	// is the exception: its key is keyed per process (runkey.go), so its id
	// is stable only until the sensor restarts.
	ev.ID = event.StableID(ts, event.TypeProcessExec, "osquery", t.name, r.key, strconv.Itoa(r.pid))
	ev.Fidelity = event.FidelityObserved
	ev.Integrity = s.integrity
	if agentID != "" {
		ev.Agent = &event.Agent{ID: agentID}
	}
	ev.Labels = map[string]string{"osquery_table": t.name}

	path := cleanText(row["path"], maxPathBytes)
	args, cut := splitCmdline(row["cmdline"])
	if cut {
		ev.Truncated = append(ev.Truncated, "process.args")
	}
	p := &event.Process{PID: r.pid, PPID: r.ppid, Exe: path, Args: classify.RedactArgs(args)}
	p.Name = baseName(path)
	if p.Name == "" && len(args) > 0 {
		p.Name = baseName(args[0])
	}
	ev.Process = p

	uid := strings.TrimSpace(row["uid"])
	if _, err := strconv.ParseUint(uid, 10, 32); err != nil {
		uid = ""
	}
	name := cleanText(row["username"], 256)
	if uid != "" || name != "" {
		ev.User = &event.User{ID: uid, Name: name}
		p.User = name
	}
	cwd := cleanCWD(row["cwd"])
	if sessionID != "" || cwd != "" {
		ev.Session = &event.Session{ID: sessionID, CWD: cwd}
	}
	return ev
}

// splitCmdline turns osquery's space-joined command line into arguments.
// The split is lossy (an argument with a space becomes two), which is fine
// for what the result is used for: redaction works on flags and tokens.
func splitCmdline(cmdline string) (args []string, cut bool) {
	if len(cmdline) >= sqlCmdline {
		cut = true // substr() inside osquery already shortened it
	}
	cmdline = strings.ToValidUTF8(cmdline, "�")
	total := 0
	for _, f := range strings.Fields(cmdline) {
		if len(args) >= maxArgs {
			return args, true
		}
		if len(f) > maxArgBytes {
			f, cut = cutUTF8(f, maxArgBytes), true
		}
		if total+len(f) > maxArgsBytes {
			return args, true
		}
		total += len(f)
		args = append(args, f)
	}
	return args, cut
}

// cutUTF8 shortens s to at most n bytes without splitting a rune.
func cutUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !isRuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }

func cleanText(v string, max int) string {
	v = strings.ToValidUTF8(strings.TrimSpace(v), "�")
	if strings.ContainsAny(v, "\x00\n\r") {
		return ""
	}
	return cutUTF8(v, max)
}

// cleanCWD strips the quotes the Linux audit subscriber leaves around the
// working directory and keeps the value only if it is an absolute path.
func cleanCWD(v string) string {
	v = cleanText(v, maxPathBytes)
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		v = v[1 : len(v)-1]
	}
	if v == "" {
		return ""
	}
	if v[0] == '/' || (len(v) >= 3 && v[1] == ':' && (v[2] == '\\' || v[2] == '/')) || strings.HasPrefix(v, `\\`) {
		return v
	}
	return ""
}

func baseName(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		p = p[i+1:]
	}
	return cutUTF8(p, 255)
}
