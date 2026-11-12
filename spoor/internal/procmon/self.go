package procmon

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
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
// A process is spoor's hook when its argv[1] is "hook" AND it runs one of
// spoor's own binaries, judged by what the kernel says about the running
// image, never by a path the process could have arranged:
//
//   - Linux (procfs): the file identity (device and inode,
//     platform.FileID) of /proc/<pid>/exe, the image the kernel mapped,
//     is one of spoor's: the image this process runs (/proc/self/exe,
//     which keeps its identity after an upgrade replaced the file), the
//     file at this binary's path now (the upgraded binary new hooks
//     start), or Options.SelfExes (the installed binary the hooks name,
//     when the sensor runs another copy). A path names whatever is there
//     in the mount namespace of the process that ran it, and an agent can
//     put any program at /usr/bin/spoor inside its own container or user
//     namespace; the identity of the mapped image it cannot choose.
//   - macOS and Windows (platformSource): there is no link to the mapped
//     image. The kernel's own name for it (platform.ProcImagePath:
//     proc_pidpath, QueryFullProcessImageName; never the exec path in the
//     process's memory) must be one of spoor's binary paths, and the file
//     there must be spoor's by identity. The name alone is not enough, nor
//     the identity of the file at it: proc_pidpath answers with the name
//     the image had, as long as that name still resolves, so a program
//     started from a path its user controls, which then renames a hard
//     link of spoor's binary over that path, would pass an identity check
//     of the file at the name.
//
// Every path of a spoor binary used here, other than /proc/self/exe, must
// pass platform.TrustedPath: only root (or the sensor's own account) can
// change what it names. A path anyone else can write to would let them put
// their program there and have its processes taken for spoor's hook. This
// leaves hooks reported where spoor is installed in such a place (on Intel
// Macs with Homebrew, /usr/local/bin belongs to the Homebrew user).
//
// Only the hook path is left out: any other spoor command an agent runs
// (hooks uninstall, privacy purge, ci exec) is exactly the activity a
// reader needs to see.
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

// selfSet is what is known about spoor's binaries, as of at: their file
// identities (ids) and, for platformSource, their trusted paths (paths,
// keyed by selfPathKey).
type selfSet struct {
	ids   map[string]bool
	paths map[string]bool
	at    time.Time
}

// selfPathKey is how paths are compared: cleaned, and on Windows without
// regard to case.
func selfPathKey(p string) string {
	p = filepath.Clean(p)
	if runtime.GOOS == "windows" {
		p = strings.ToLower(p)
	}
	return p
}

// selfIDs returns the file identities and trusted paths of spoor's own
// binaries.
func (m *Monitor) selfIDs(now time.Time) *selfSet {
	if cur := m.selfSet.Load(); cur != nil && now.Sub(cur.at) < selfRefresh && !now.Before(cur.at) {
		return cur
	}
	set := &selfSet{ids: map[string]bool{}, paths: map[string]bool{}, at: now}
	idOf := func(p string) string {
		fi, err := os.Stat(p)
		if err != nil || !fi.Mode().IsRegular() {
			return ""
		}
		return platform.FileID(fi, p)
	}
	add := func(p string) {
		if !filepath.IsAbs(p) || m.trusted == nil || !m.trusted(p) {
			return
		}
		id := idOf(p)
		if id == "" {
			return
		}
		set.ids[id] = true
		set.paths[selfPathKey(p)] = true
		// The kernel names the image by its real path.
		if r, err := filepath.EvalSymlinks(p); err == nil {
			set.paths[selfPathKey(r)] = true
		}
	}
	if runtime.GOOS == "linux" {
		// The image this process runs: whatever happened to its file.
		if id := idOf("/proc/self/exe"); id != "" {
			set.ids[id] = true
		}
	}
	if exe, err := os.Executable(); err == nil {
		add(trimDeleted(exe))
	}
	for _, p := range m.o.SelfExes {
		add(p)
	}
	m.selfSet.Store(set)
	return set
}

// hookArgv reports the argument shape of the hook path: `spoor hook ...`.
func hookArgv(args []string) bool { return len(args) >= 2 && args[1] == "hook" }

// isSelfHook reports whether a process, read as rec under identity id, is
// spoor's own hook supervisor or worker. The cheap argument test comes
// first, so the executable is looked at only for processes that call
// themselves a hook.
func (m *Monitor) isSelfHook(id ident, rec *platform.Proc) bool {
	if rec == nil || !hookArgv(rec.Args) {
		return false
	}
	set := m.selfIDs(m.now())
	if len(set.ids) == 0 {
		return false
	}
	return m.src.selfImage(id, rec, set)
}
