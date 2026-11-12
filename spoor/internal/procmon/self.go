package procmon

import (
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/thomastysong/spoor/internal/platform"
)

// spoor's own hook processes.
//
// An agent runs `spoor hook --agent <id>` on every hook event, and the hook
// supervisor re-executes itself as `spoor hook --worker ...`. Both are real
// children of the agent, so attribution alone reports them as the agent's
// process.exec activity: in the real-agent run they were 4 of the 5 context
// records shipped with a finding. They are kept in the process table (a
// child they started, if any, still belongs to the agent) but never
// reported.
//
// A process is spoor's hook when its argv[1] is "hook" AND its executable is
// spoor's own binary by file identity (device and inode, platform.FileID):
// the image this process runs (/proc/self/exe on Linux, which keeps its
// identity after an upgrade replaced the file), the file at this binary's
// path now (the upgraded binary new hooks start), and Options.SelfExes (the
// installed binary the hooks name, when the sensor runs another copy).
// Identity, not path: a path names whatever is there in the mount namespace
// of the process that ran it, and an agent can put any program at
// /usr/bin/spoor inside its own container or user namespace. Only the hook
// path is left out: any other spoor command an agent runs (hooks uninstall,
// privacy purge, ci exec) is exactly the activity a reader needs to see.
//
// Limits: the guarded shell form some agents use (sh -c '[ -x BIN ] ||
// exit 0; exec BIN hook ...') shows up as one sh process before it becomes
// spoor, and that sh is still reported; an osquery exec row for a hook
// process the table never saw (the osquery provider with a poller that
// missed a 10 ms process) cannot be told apart and is reported.

// selfRefresh is how long the identity set of spoor's binaries is reused.
// An upgrade replaces the file; within this time the new binary's hooks are
// recognised.
const selfRefresh = 30 * time.Second

// selfSet is the file identities of spoor's binaries, as of at.
type selfSet struct {
	ids map[string]bool
	at  time.Time
}

// selfIDs returns the file identities of spoor's own binaries.
func (m *Monitor) selfIDs(now time.Time) map[string]bool {
	if cur := m.selfSet.Load(); cur != nil && now.Sub(cur.at) < selfRefresh && !now.Before(cur.at) {
		return cur.ids
	}
	ids := map[string]bool{}
	add := func(p string) {
		fi, err := os.Stat(p)
		if err != nil || !fi.Mode().IsRegular() {
			return
		}
		if id := platform.FileID(fi, p); id != "" {
			ids[id] = true
		}
	}
	if runtime.GOOS == "linux" {
		add("/proc/self/exe")
	}
	if exe, err := os.Executable(); err == nil {
		add(trimDeleted(exe))
	}
	for _, p := range m.o.SelfExes {
		if filepath.IsAbs(p) {
			add(p)
		}
	}
	m.selfSet.Store(&selfSet{ids: ids, at: now})
	return ids
}

// hookArgv reports the argument shape of the hook path: `spoor hook ...`.
func hookArgv(args []string) bool { return len(args) >= 2 && args[1] == "hook" }

// isSelfHook reports whether a process is spoor's own hook supervisor or
// worker. The cheap argument test comes first, so the executable is looked
// at only for processes that call themselves a hook.
func (m *Monitor) isSelfHook(pid int, rec *platform.Proc) bool {
	if rec == nil || !hookArgv(rec.Args) {
		return false
	}
	ids := m.selfIDs(m.now())
	if len(ids) == 0 {
		return false
	}
	id := m.src.exeID(pid, rec.Exe)
	return id != "" && ids[id]
}
