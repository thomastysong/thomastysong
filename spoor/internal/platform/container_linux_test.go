//go:build linux

package platform

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func withCgroupNS(t *testing.T, private bool) {
	t.Helper()
	old := cgroupNSPrivate
	cgroupNSPrivate = func() bool { return private }
	t.Cleanup(func() { cgroupNSPrivate = old })
}

func TestContainerOfFixtures(t *testing.T) {
	root := t.TempDir()
	withProcRoot(t, root)

	// Seen from the host (initial cgroup namespace): the cgroup path is the
	// whole story and mountinfo is never opened.
	withCgroupNS(t, false)
	fakeProc(t, root, 100, map[string][]byte{"cgroup": []byte(cgroupV1Docker)}, nil)
	fakeProc(t, root, 101, map[string][]byte{
		"cgroup": []byte("0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod" + underscored(podU) + ".slice/cri-containerd-" + cidB + ".scope\n"),
	}, nil)
	fakeProc(t, root, 102, map[string][]byte{
		"cgroup": []byte("0::/user.slice/user-1000.slice/session-3.scope\n"),
		// Would match if it were read: a host process must not be placed in
		// a container because of its mount table.
		"mountinfo": []byte(mountinfoDocker),
	}, nil)
	fakeProc(t, root, 103, nil, nil) // no cgroup file at all

	tests := []struct {
		pid              int
		id, runtime, pod string
	}{
		{100, cidA, RuntimeDocker, ""},
		{101, cidB, RuntimeContainerd, podU},
		{102, "", "", ""},
		{103, "", "", ""},
		{999999, "", "", ""}, // no such process
		{0, "", "", ""},
		{-1, "", "", ""},
	}
	for _, tt := range tests {
		id, rt := ContainerOf(tt.pid)
		if id != tt.id || rt != tt.runtime {
			t.Errorf("ContainerOf(%d) = %q %q, want %q %q", tt.pid, id, rt, tt.id, tt.runtime)
		}
		if pod := PodOf(tt.pid); pod != tt.pod {
			t.Errorf("PodOf(%d) = %q, want %q", tt.pid, pod, tt.pod)
		}
	}

	// Seen from inside a container with a private cgroup namespace: the
	// cgroup file says "/" and the mount table identifies the container.
	withCgroupNS(t, true)
	fakeProc(t, root, 200, map[string][]byte{"cgroup": []byte("0::/\n"), "mountinfo": []byte(mountinfoDocker)}, nil)
	fakeProc(t, root, 201, map[string][]byte{
		"cgroup":    []byte("0::/\n"),
		"mountinfo": []byte("600 500 8:1 /var/lib/kubelet/pods/" + podU + "/etc-hosts /etc/hosts rw - ext4 /dev/sda1 rw\n"),
	}, nil)
	fakeProc(t, root, 202, map[string][]byte{"cgroup": []byte("0::/\n")}, nil) // mountinfo unreadable
	if id, rt := ContainerOf(200); id != cidA || rt != RuntimeDocker {
		t.Errorf("private namespace: ContainerOf = %q %q", id, rt)
	}
	if id, _ := ContainerOf(201); id != "" {
		t.Errorf("pod without a container id: %q", id)
	}
	if pod := PodOf(201); pod != podU {
		t.Errorf("private namespace: PodOf = %q, want %q", pod, podU)
	}
	if id, rt := ContainerOf(202); id != "" || rt != "" {
		t.Errorf("missing mountinfo: %q %q", id, rt)
	}
	// Even here the cgroup path wins when it does name a container.
	if id, rt := ContainerOf(100); id != cidA || rt != RuntimeDocker {
		t.Errorf("cgroup answer overridden: %q %q", id, rt)
	}
}

func TestContainerOfRealProcesses(t *testing.T) {
	procs, err := Processes()
	if err != nil {
		t.Fatal(err)
	}
	runtimes := map[string]bool{"": true, RuntimeDocker: true, RuntimeContainerd: true, RuntimeCRIO: true, RuntimePodman: true}
	inContainers, checked := 0, 0
	for _, p := range procs {
		id, rt := ContainerOf(p.PID)
		pod := PodOf(p.PID)
		if id != "" && !isContainerID(id) {
			t.Errorf("pid %d: malformed container id %q", p.PID, id)
		}
		if !runtimes[rt] {
			t.Errorf("pid %d: runtime %q outside the vocabulary", p.PID, rt)
		}
		if id == "" && rt != "" {
			t.Errorf("pid %d: runtime %q without an id", p.PID, rt)
		}
		if pod != "" && normalizePodUID(pod) != pod {
			t.Errorf("pid %d: malformed pod uid %q", p.PID, pod)
		}
		if id != "" {
			inContainers++
		}
		// Cross-check against the raw cgroup text wherever Docker's cgroupfs
		// layout is in use on this machine.
		raw, err := os.ReadFile(filepath.Join("/proc", itoa(p.PID), "cgroup"))
		if err != nil {
			continue
		}
		if i := strings.Index(string(raw), "/docker/"); i >= 0 {
			rest := string(raw)[i+len("/docker/"):]
			if len(rest) >= 64 && isContainerID(rest[:64]) && !strings.Contains(rest[:strings.IndexAny(rest+"\n", "\n")], "/docker/") {
				checked++
				if id != rest[:64] || rt != RuntimeDocker {
					t.Errorf("pid %d: ContainerOf = %q %q, cgroup says docker %q", p.PID, id, rt, rest[:64])
				}
			}
		}
	}
	t.Logf("%d processes, %d in containers, %d verified against a Docker cgroup path", len(procs), inContainers, checked)
}
