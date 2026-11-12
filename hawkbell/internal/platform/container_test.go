package platform

import (
	"strings"
	"testing"
)

const (
	cidA = "4502c8c6d0df0315704fdf9a73b86625a72d00982308fbcb64546a766a0389cf"
	cidB = "81520a8af8e8bcfd805cab96ee4b3ff6e5975a28aab72998d3c158c3d846e869"
	podU = "0a1b2c3d-1234-5678-9abc-def012345678"
)

// cgroupV1Docker is a real /proc/<pid>/cgroup of a Docker container on a
// cgroup v1 host with the cgroupfs driver (captured on the build host).
const cgroupV1Docker = `9:name=systemd:/docker/` + cidA + `
8:pids:/docker/` + cidA + `
7:blkio:/docker/` + cidA + `
6:freezer:/docker/` + cidA + `
5:devices:/docker/` + cidA + `
4:memory:/docker/` + cidA + `
3:cpuset:/docker/` + cidA + `
2:cpuacct:/docker/` + cidA + `
1:cpu:/docker/` + cidA + `
0::/docker/` + cidA + `
`

func underscored(uid string) string { return strings.ReplaceAll(uid, "-", "_") }

func TestParseCgroup(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		id      string
		runtime string
		pod     string
	}{
		{"cgroup v1 docker cgroupfs", cgroupV1Docker, cidA, RuntimeDocker, ""},
		{"cgroup v2 docker systemd", "0::/system.slice/docker-" + cidA + ".scope\n", cidA, RuntimeDocker, ""},
		{"cgroup v2 docker cgroupfs", "0::/docker/" + cidA + "\n", cidA, RuntimeDocker, ""},
		{"docker rootless", "0::/user.slice/user-1000.slice/user@1000.service/user.slice/docker-" + cidA + ".scope\n", cidA, RuntimeDocker, ""},
		{
			"cgroup v2 containerd under kubepods, systemd slices",
			"0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod" + underscored(podU) + ".slice/cri-containerd-" + cidA + ".scope\n",
			cidA, RuntimeContainerd, podU,
		},
		{
			"kubepods guaranteed qos, systemd",
			"0::/kubepods.slice/kubepods-pod" + underscored(podU) + ".slice/cri-containerd-" + cidA + ".scope\n",
			cidA, RuntimeContainerd, podU,
		},
		{
			"kubepods besteffort, cgroupfs driver, v1",
			"11:memory:/kubepods/besteffort/pod" + podU + "/" + cidA + "\n1:name=systemd:/kubepods/besteffort/pod" + podU + "/" + cidA + "\n",
			cidA, RuntimeContainerd, podU,
		},
		{
			"kubepods guaranteed, cgroupfs driver, v2",
			"0::/kubepods/pod" + podU + "/" + cidA + "\n",
			cidA, RuntimeContainerd, podU,
		},
		{
			"k8s with docker and systemd driver",
			"0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod" + underscored(podU) + ".slice/docker-" + cidA + ".scope\n",
			cidA, RuntimeDocker, podU,
		},
		{
			"cri-o systemd",
			"0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod" + underscored(podU) + ".slice/crio-" + cidA + ".scope\n",
			cidA, RuntimeCRIO, podU,
		},
		{
			"cri-o cgroupfs",
			"0::/kubepods/burstable/pod" + podU + "/crio-" + cidA + "\n",
			cidA, RuntimeCRIO, podU,
		},
		{
			"cri-o conmon is not the container",
			"0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod" + underscored(podU) + ".slice/crio-conmon-" + cidA + ".scope\n",
			"", "", podU,
		},
		{
			"static pod with a 32-hex config hash",
			"0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod0123456789abcdef0123456789abcdef.slice/cri-containerd-" + cidA + ".scope\n",
			cidA, RuntimeContainerd, "0123456789abcdef0123456789abcdef",
		},
		{
			"containerd colon triple (runc without the systemd driver)",
			"0::/kubepods-burstable-pod" + underscored(podU) + ".slice:cri-containerd:" + cidA + "\n",
			cidA, RuntimeContainerd, "",
		},
		{
			"podman rootless",
			"0::/user.slice/user-1000.slice/user@1000.service/user.slice/libpod-" + cidA + ".scope/container\n",
			cidA, RuntimePodman, "",
		},
		{"podman rootful", "0::/machine.slice/libpod-" + cidA + ".scope\n", cidA, RuntimePodman, ""},
		{"podman cgroupfs", "0::/libpod_parent/libpod-" + cidA + "\n", cidA, RuntimePodman, ""},
		{"podman conmon is not the container", "0::/machine.slice/libpod-conmon-" + cidA + ".scope\n", "", "", ""},
		{"nerdctl", "0::/system.slice/nerdctl-" + cidA + ".scope\n", cidA, RuntimeContainerd, ""},
		{"github actions job container", "0::/actions_job/" + cidA + "\n", cidA, RuntimeDocker, ""},
		{"docker in docker: innermost wins", "0::/docker/" + cidA + "/docker/" + cidB + "\n", cidB, RuntimeDocker, ""},
		{"systemd inside a container", "0::/docker/" + cidA + "/system.slice/ssh.service\n", cidA, RuntimeDocker, ""},
		{"init scope inside a pod container", "0::/kubepods/burstable/pod" + podU + "/" + cidA + "/init.scope\n", cidA, RuntimeContainerd, podU},
		{"unknown parent, bare id", "0::/ecs/task1234/" + cidA + "\n", cidA, "", ""},
		{
			"hybrid: v1 controllers at root, v2 line names the container",
			"1:name=systemd:/\n0::/system.slice/docker-" + cidA + ".scope\n",
			cidA, RuntimeDocker, "",
		},
		{
			"a named runtime beats a bare id on another line",
			"5:devices:/weird/" + cidB + "\n0::/system.slice/docker-" + cidA + ".scope\n",
			cidA, RuntimeDocker, "",
		},

		// Host processes and non-containers.
		{"host user session", "0::/user.slice/user-1000.slice/session-3.scope\n", "", "", ""},
		{"host service", "0::/system.slice/ssh.service\n", "", "", ""},
		{"inside a private cgroup namespace", "0::/\n", "", "", ""},
		{"docker daemon itself", "0::/system.slice/docker.service\n", "", "", ""},
		{"kubelet", "0::/system.slice/kubelet.service\n", "", "", ""},
		{"kubepods slice with no pod", "0::/kubepods.slice/kubepods-burstable.slice\n", "", "", ""},
		{"empty", "", "", "", ""},

		// Hostile or malformed.
		{"63 hex", "0::/docker/" + cidA[:63] + "\n", "", "", ""},
		{"65 hex", "0::/docker/" + cidA + "a\n", "", "", ""},
		{"upper-case hex", "0::/docker/" + strings.ToUpper(cidA) + "\n", "", "", ""},
		{"non-hex", "0::/docker/" + strings.Repeat("z", 64) + "\n", "", "", ""},
		{"prefix with a short id", "0::/system.slice/docker-abc123.scope\n", "", "", ""},
		{"no colons", "/docker/" + cidA + "\n", "", "", ""},
		{"one colon", "0:/docker/" + cidA + "\n", "", "", ""},
		{"line over the length cap", "0::/" + strings.Repeat("a/", 3000) + "docker/" + cidA + "\n", "", "", ""},
		{"invalid utf8", "0::/\xff\xfe/docker-\xff.scope\n", "", "", ""},
		{"pod word outside kubepods", "0::/user.slice/pod" + podU + "/" + cidA + "\n", cidA, "", ""},
		{"podman is not a pod", "0::/kubepods.slice/podman-" + cidA + ".scope\n", "", "", ""},
		{"pod uid with bad separators", "0::/kubepods/burstable/pod0a1b2c3d+1234+5678+9abc+def012345678/" + cidA + "\n", cidA, RuntimeContainerd, ""},
		{"pod uid upper-case", "0::/kubepods/burstable/pod" + strings.ToUpper(podU) + "/" + cidA + "\n", cidA, RuntimeContainerd, ""},
		{"unit name merely ending in pod", "0::/kubepods.slice/tripod" + podU + ".slice\n", "", "", ""},
	}
	for _, tt := range tests {
		got := parseCgroup([]byte(tt.in))
		if got.id != tt.id || got.runtime != tt.runtime || got.pod != tt.pod {
			t.Errorf("%s:\n got id=%q runtime=%q pod=%q\nwant id=%q runtime=%q pod=%q", tt.name, got.id, got.runtime, got.pod, tt.id, tt.runtime, tt.pod)
		}
	}
	// Thousands of lines: bounded work, still an answer from the early ones.
	many := strings.Repeat("3:cpuset:/\n", 5000) + "0::/docker/" + cidA + "\n"
	if got := parseCgroup([]byte(many)); got.id != "" {
		t.Errorf("read past the line cap: %+v", got)
	}
	early := "0::/docker/" + cidA + "\n" + strings.Repeat("3:cpuset:/\n", 5000)
	if got := parseCgroup([]byte(early)); got.id != cidA {
		t.Errorf("early line lost: %+v", got)
	}
}

// mountinfoDocker is the relevant part of a real /proc/<pid>/mountinfo inside
// a Docker container (captured on the build host).
const mountinfoDocker = `597 302 0:91 / / rw,relatime - overlay overlay rw,lowerdir=/var/lib/docker/containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/313/fs,upperdir=/var/lib/docker/containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/314/fs,workdir=/var/lib/docker/containerd/daemon/io.containerd.snapshotter.v1.overlayfs/snapshots/314/work
598 597 0:92 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
223 204 254:0 /var/lib/docker/containers/` + cidA + `/hostname /etc/hostname rw,relatime - ext4 /dev/vda rw,discard
224 204 254:0 /var/lib/docker/containers/` + cidA + `/hosts /etc/hosts rw,relatime - ext4 /dev/vda rw,discard
225 204 254:0 /var/lib/docker/containers/` + cidA + `/resolv.conf /etc/resolv.conf rw,relatime - ext4 /dev/vda rw,discard
`

// mountinfoHost is a host's mount table on a Docker machine. It mentions the
// same container directory, but as a mount POINT, and must not match.
var mountinfoHost = `25 1 254:0 / / rw,relatime shared:1 - ext4 /dev/vda rw
301 25 0:90 / /var/lib/docker/containers/` + cidA + `/mounts/shm rw,nosuid,nodev,noexec,relatime shared:150 - tmpfs shm rw,size=65536k
302 25 0:91 / /var/lib/docker/rootfs/overlayfs/` + cidA + ` rw,relatime shared:151 - overlay overlay rw
303 25 0:4 net:[4026532270] /run/docker/netns/` + cidA[:12] + ` rw shared:152 - nsfs nsfs rw
`

func TestParseMountinfo(t *testing.T) {
	podman := "500 400 0:50 /containers/storage/overlay-containers/" + cidB + "/userdata/hostname /etc/hostname rw - tmpfs tmpfs rw\n" +
		"501 400 0:50 /containers/storage/overlay-containers/" + cidB + "/userdata/hosts /etc/hosts rw - tmpfs tmpfs rw\n"
	kube := "600 500 8:1 /var/lib/kubelet/pods/" + podU + "/etc-hosts /etc/hosts rw,relatime - ext4 /dev/sda1 rw\n" +
		"601 500 8:1 /var/lib/kubelet/pods/" + podU + "/containers/app/0f3c1a2b /dev/termination-log rw,relatime - ext4 /dev/sda1 rw\n"
	crioSandbox := "602 500 0:50 /containers/storage/overlay-containers/" + cidB + "/userdata/hostname /etc/hostname rw - tmpfs tmpfs rw\n"

	tests := []struct {
		name    string
		in      string
		id      string
		runtime string
		pod     string
	}{
		{"docker container", mountinfoDocker, cidA, RuntimeDocker, ""},
		{"docker with a relocated data-root", strings.ReplaceAll(mountinfoDocker, "/var/lib/docker/", "/data/dkr/"), cidA, RuntimeDocker, ""},
		{"host mount table", mountinfoHost, "", "", ""},
		{"podman container", podman, cidB, RuntimePodman, ""},
		{"kubernetes pod: pod uid only", kube, "", "", podU},
		// In a pod the overlay-containers id is the sandbox: not reported.
		{"cri-o pod: sandbox id is not a container id", kube + crioSandbox, "", "", podU},
		{"empty", "", "", "", ""},
		{"file mounted elsewhere", "1 2 0:1 /var/lib/docker/containers/" + cidA + "/hostname /tmp/hostname rw - ext4 /dev/vda rw\n", "", "", ""},
		{"short id", "1 2 0:1 /var/lib/docker/containers/abc123/hostname /etc/hostname rw - ext4 /dev/vda rw\n", "", "", ""},
		{"wrong directory name", "1 2 0:1 /srv/boxes/" + cidA + "/hostname /etc/hostname rw - ext4 /dev/vda rw\n", "", "", ""},
		{"too few fields", "1 2 0:1 /x\n", "", "", ""},
		{"escaped space in root", "1 2 0:1 /my\\040disk/docker/containers/" + cidA + "/hosts /etc/hosts rw - ext4 /dev/vda rw\n", cidA, RuntimeDocker, ""},
		{"line cut by the read limit is ignored", "1 2 0:1 /var/lib/docker/containers/" + cidA + "/hostname /etc/hostname rw", "", "", ""},
		{"binary", "\x00\xff\xfe\n\x01\x02 \x03 \x04 \x05 \x06\n", "", "", ""},
	}
	for _, tt := range tests {
		got := parseMountinfo([]byte(tt.in))
		if got.id != tt.id || got.runtime != tt.runtime || got.pod != tt.pod {
			t.Errorf("%s:\n got id=%q runtime=%q pod=%q\nwant id=%q runtime=%q pod=%q", tt.name, got.id, got.runtime, got.pod, tt.id, tt.runtime, tt.pod)
		}
	}
}

func TestUnescapeMountField(t *testing.T) {
	for in, want := range map[string]string{
		"/plain":         "/plain",
		`/a\040b`:        "/a b",
		`/tab\011nl\012`: "/tab\tnl\n",
		`/back\134slash`: `/back\slash`,
		`/trailing\`:     `/trailing\`,
		`/short\04`:      `/short\04`,
		`/bad\999`:       `/bad\999`,
		``:               ``,
	} {
		if got := unescapeMountField(in); got != want {
			t.Errorf("unescapeMountField(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsContainerIDAndPodUID(t *testing.T) {
	if !isContainerID(cidA) || isContainerID(cidA[:12]) || isContainerID("") || isContainerID(strings.ToUpper(cidA)) {
		t.Error("isContainerID")
	}
	for in, want := range map[string]string{
		podU:                                   podU,
		underscored(podU):                      podU,
		"0123456789abcdef0123456789abcdef":     "0123456789abcdef0123456789abcdef",
		"":                                     "",
		podU + "x":                             "",
		strings.ToUpper(podU):                  "",
		"0a1b2c3d-1234-5678-9abc-def01234567":  "",
		"0a1b2c3d 1234 5678 9abc def012345678": "",
	} {
		if got := normalizePodUID(in); got != want {
			t.Errorf("normalizePodUID(%q) = %q, want %q", in, got, want)
		}
	}
}
