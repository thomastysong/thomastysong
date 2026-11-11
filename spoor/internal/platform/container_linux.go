//go:build linux

package platform

import (
	"os"
	"path/filepath"
	"strconv"
	"sync"
)

const (
	maxMountinfoBytes = 2 << 20
	// initCgroupNS is the fixed inode of the initial cgroup namespace
	// (PROC_CGROUP_INIT_INO in include/linux/proc_ns.h).
	initCgroupNS = "cgroup:[4026531835]"
)

var (
	cgroupNSOnce    sync.Once
	cgroupNSPrivVal bool
	// cgroupNSPrivate is a variable so tests can force either answer.
	cgroupNSPrivate = func() bool {
		cgroupNSOnce.Do(func() {
			// /proc/<pid>/cgroup shows paths relative to the READER's cgroup
			// namespace. From the initial namespace they are complete; from
			// inside a container's namespace they start at the container, so
			// the container's own id is cut off.
			link, err := os.Readlink(filepath.Join(procRoot, "self", "ns", "cgroup"))
			cgroupNSPrivVal = err == nil && link != initCgroupNS
		})
		return cgroupNSPrivVal
	}
)

// ContainerOf returns the id and runtime of the container the process runs
// in, or "", "" when it is a host process (or cannot be read). runtime is one
// of the Runtime* constants, or "" when the id is recognizable but its
// runtime is not.
func ContainerOf(pid int) (id, runtime string) {
	info := workloadOf(pid)
	return info.id, info.runtime
}

// PodOf returns the Kubernetes pod UID of the process, or "".
func PodOf(pid int) (podUID string) {
	return workloadOf(pid).pod
}

func workloadOf(pid int) (info cgroupInfo) {
	defer func() {
		if r := recover(); r != nil {
			info = cgroupInfo{}
		}
	}()
	if pid <= 0 {
		return cgroupInfo{}
	}
	dir := filepath.Join(procRoot, strconv.Itoa(pid))
	if b, err := readFileLimit(filepath.Join(dir, "cgroup"), maxSmallFile); err == nil {
		info = parseCgroup(b)
	}
	// The mount table is consulted only when this sensor itself sits in a
	// private cgroup namespace. On a host every process would otherwise cost
	// a read of its (possibly very large) mountinfo for nothing.
	if (info.id != "" && info.pod != "") || !cgroupNSPrivate() {
		return info
	}
	b, err := readFileLimit(filepath.Join(dir, "mountinfo"), maxMountinfoBytes)
	if err != nil {
		return info
	}
	m := parseMountinfo(b)
	if info.id == "" {
		info.id, info.runtime = m.id, m.runtime
	}
	if info.pod == "" {
		info.pod = m.pod
	}
	return info
}
