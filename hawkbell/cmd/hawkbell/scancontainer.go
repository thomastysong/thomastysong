package main

import (
	"path/filepath"
	"strconv"
	"strings"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
	"github.com/thomastysong/thomastysong/hawkbell/internal/platform"
)

// procRoot is where the scan looks for /proc/<pid>/root host roots; tests
// point it at a fake tree.
var procRoot = "/proc"

// containerOfPID names the container a process runs in (platform's cgroup
// and mount-table reading on Linux; nothing elsewhere). Replaced in tests.
var containerOfPID = func(pid int) (id, runtime, podUID string) {
	id, runtime = platform.ContainerOf(pid)
	if id != "" {
		podUID = platform.PodOf(pid)
	}
	return id, runtime, podUID
}

// hostRootPID returns the pid of a host root of the form /proc/<pid>/root
// (the way a node sensor scans a container's filesystem), or 0.
func hostRootPID(hostRoot string) int {
	if hostRoot == "" {
		return 0
	}
	c := filepath.Clean(hostRoot)
	rest, ok := strings.CutPrefix(c, filepath.Clean(procRoot)+string(filepath.Separator))
	if !ok {
		return 0
	}
	num, ok := strings.CutSuffix(rest, string(filepath.Separator)+"root")
	if !ok || num == "" || len(num) > 10 || strings.TrimLeft(num, "0123456789") != "" {
		return 0
	}
	pid, err := strconv.Atoi(num)
	if err != nil || pid <= 0 {
		return 0
	}
	return pid
}

// scanContainer is the container a scan of hostRoot looks into, for
// discovery to stamp on every record, and a note saying what was found.
// Only a /proc/<pid>/root root names a process whose container can be
// read; any other root (such as /host in the node sensor) is the node's
// own filesystem.
func scanContainer(hostRoot string) (*event.Container, string) {
	pid := hostRootPID(hostRoot)
	if pid == 0 {
		return nil, ""
	}
	id, rt, pod := containerOfPID(pid)
	if id == "" {
		return nil, "host root " + hostRoot + ": pid " + strconv.Itoa(pid) + " is not in a container hawkbell recognises; records carry no container id"
	}
	c := &event.Container{ID: id, Runtime: rt, PodUID: pod}
	return c, "host root " + hostRoot + ": container " + id + " of pid " + strconv.Itoa(pid) + " stamped on the records"
}
