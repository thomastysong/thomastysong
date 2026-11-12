package daemon

import (
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/thomastysong/thomastysong/hawkbell/internal/platform"
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
// A process's working directory means the same here when its mount
// namespace is the sensor's (every path resolves alike), or else when the
// path, resolved in the sensor's view, is the very directory the process
// is in: the same device and inode as /proc/<pid>/cwd, which the kernel
// resolves in the process's own namespace. A shared root is not enough.
// systemd runs the daemon in a private mount namespace of its own over the
// host's root (ProtectHome=, ReadWritePaths=, PrivateTmp=), where a home
// directory names the same directory as on the host, but with PrivateTmp=
// the sensor's /tmp is a private directory, so an agent's /tmp/project
// names one thing for the agent and another for the sensor; with
// ProtectHome=tmpfs, /home is an empty file system. The directory check
// accepts the first case (a read-only bind of the same file system keeps
// device and inode) and refuses the others, as it refuses a container's
// overlay. A process whose namespace or working directory cannot be read
// (gone, or no permission) is not in the same view. Where the sensor's own
// namespace cannot be read (no procfs: macOS, Windows) there is one view
// and every process is in it.
type mountView struct {
	proc string // procfs mount, "/proc"

	once   sync.Once
	selfNS string // readlink /proc/self/ns/mnt, "mnt:[4026531841]"
}

func newMountView(proc string) *mountView { return &mountView{proc: proc} }

func (v *mountView) init() {
	v.once.Do(func() {
		v.selfNS, _ = os.Readlink(filepath.Join(v.proc, "self", "ns", "mnt"))
	})
}

// same reports whether cwd, pid's working directory as the process names
// it, resolves in the sensor's view to the directory the process is in.
func (v *mountView) same(pid int, cwd string) bool {
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
	if !filepath.IsAbs(cwd) {
		return false
	}
	theirs := dirID(filepath.Join(dir, "cwd"))
	return theirs != "" && theirs == dirID(cwd)
}

// dirID is the file identity of the directory p leads to; for a
// /proc/<pid>/cwd link the kernel resolves it in the process's own
// namespace.
func dirID(p string) string {
	fi, err := os.Stat(p)
	if err != nil || !fi.IsDir() {
		return ""
	}
	return platform.FileID(fi, p)
}
