package daemon

import (
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/thomastysong/spoor/internal/platform"
)

// mountView decides whether a process's working directory names, in the
// sensor's own file system view, the directory the process is in.
//
// Project scans read a directory the process monitor saw as an agent's
// working directory. In node mode (the Kubernetes DaemonSet: the host's pid
// namespace, host_root empty) the agents run in other containers: their cwd
// "/home/dev/app" or "/etc" is a path in THEIR mount namespace, and resolved
// in the sensor's own it names one of the sensor's directories. An agent
// whose uid matches an account in the sensor image's passwd (root, 65532)
// would then have the sensor read its own files on the agent's say-so (a
// confused deputy): ownProjectDir's owner check passes, because the
// directory in the sensor's view does belong to that uid.
//
// A process is in the same view when its mount namespace is the sensor's,
// or when its root directory is the sensor's (same device and inode of
// /proc/<pid>/root): systemd runs the daemon in a private mount namespace
// of its own (ProtectHome=, ReadWritePaths=, PrivateTmp=) over the host's
// root, where a home directory path names the same directory, so the
// namespace alone would turn project scans off on every systemd host. A
// container's root is its own overlay, never the host's or the sensor's.
// A process whose namespace or root cannot be read (gone, or no permission)
// is not in the same view. Where the sensor's own namespace cannot be read
// (no procfs: macOS, Windows) there is one view and every process is in it.
type mountView struct {
	proc string // procfs mount, "/proc"

	once     sync.Once
	selfNS   string // readlink /proc/self/ns/mnt, "mnt:[4026531841]"
	selfRoot string // platform.FileID of /proc/self/root
}

func newMountView(proc string) *mountView { return &mountView{proc: proc} }

func (v *mountView) init() {
	v.once.Do(func() {
		self := filepath.Join(v.proc, "self")
		v.selfNS, _ = os.Readlink(filepath.Join(self, "ns", "mnt"))
		v.selfRoot = rootID(filepath.Join(self, "root"))
	})
}

// same reports whether pid's working directory resolves in the sensor's
// view to what it is in the process's own.
func (v *mountView) same(pid int) bool {
	v.init()
	if v.selfNS == "" {
		return true
	}
	if pid <= 0 {
		return false
	}
	dir := filepath.Join(v.proc, strconv.Itoa(pid))
	if ns, err := os.Readlink(filepath.Join(dir, "ns", "mnt")); err == nil && ns == v.selfNS {
		return true
	}
	r := rootID(filepath.Join(dir, "root"))
	return r != "" && r == v.selfRoot
}

// rootID is the file identity of the directory a /proc/<pid>/root link
// leads to (the kernel resolves it in the process's own namespace).
func rootID(link string) string {
	fi, err := os.Stat(link)
	if err != nil || !fi.IsDir() {
		return ""
	}
	return platform.FileID(fi, link)
}
