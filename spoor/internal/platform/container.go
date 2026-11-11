package platform

import (
	"bytes"
	"strings"
)

// Container runtimes as written to event.Container.Runtime.
const (
	RuntimeDocker     = "docker"
	RuntimeContainerd = "containerd"
	RuntimeCRIO       = "cri-o"
	RuntimePodman     = "podman"
)

// cgroupInfo is what a cgroup path says about the workload.
type cgroupInfo struct {
	id      string // 64-hex container id, "" when the process is not in a container
	runtime string // "" when the id is recognizable but the runtime is not
	pod     string // Kubernetes pod UID, "" outside Kubernetes
}

// Scope-name prefixes the runtimes give a container's cgroup, with or
// without systemd's ".scope" suffix. Patterns follow aquasecurity/tracee
// pkg/datastores/container/containers.go (Apache-2.0), as recorded in the
// OS telemetry research notes.
var containerPrefixes = []struct{ prefix, runtime string }{
	{"cri-containerd-", RuntimeContainerd},
	{"docker-", RuntimeDocker},
	{"crio-", RuntimeCRIO},
	{"libpod-", RuntimePodman},
	{"nerdctl-", RuntimeContainerd},
}

// parseCgroup reads the text of /proc/<pid>/cgroup. cgroup v1 has one line
// per hierarchy ("4:memory:/docker/<id>"), v2 a single "0::<path>" line, and
// hybrid hosts both; the first line that names a runtime wins, and a line
// with a bare id is the fallback.
func parseCgroup(data []byte) cgroupInfo {
	var best cgroupInfo
	bestScore := 0
	for lines := 0; len(data) > 0 && lines < 512; lines++ {
		var line []byte
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			line, data = data[:i], data[i+1:]
		} else {
			line, data = data, nil
		}
		if len(line) == 0 || len(line) > 4096 {
			continue
		}
		// hierarchy-id ":" controllers ":" path. The path may itself contain
		// colons, so cut at the first two only.
		i := bytes.IndexByte(line, ':')
		if i < 0 {
			continue
		}
		j := bytes.IndexByte(line[i+1:], ':')
		if j < 0 {
			continue
		}
		path := string(line[i+1+j+1:])
		id, rt := containerFromCgroupPath(path)
		score := 0
		switch {
		case id != "" && rt != "":
			score = 2
		case id != "":
			score = 1
		}
		if score > bestScore {
			best.id, best.runtime, bestScore = id, rt, score
		}
		if best.pod == "" {
			best.pod = podFromCgroupPath(path)
		}
	}
	return best
}

// containerFromCgroupPath finds the innermost container in one cgroup path.
// Components are examined deepest first because containers nest (Docker in
// Docker, systemd inside a container) and the process belongs to the
// innermost one.
func containerFromCgroupPath(path string) (id, runtime string) {
	parts := strings.Split(path, "/")
	kube := strings.Contains(path, "kubepods")
	for i := len(parts) - 1; i >= 0; i-- {
		comp := strings.TrimSuffix(parts[i], ".scope")
		if comp == "" {
			continue
		}
		// conmon is the runtime's monitor process, not the container.
		if strings.HasPrefix(comp, "crio-conmon-") || strings.HasPrefix(comp, "libpod-conmon-") {
			continue
		}
		// "<slice>:cri-containerd:<id>": the systemd-style triple containerd
		// passes to runc, which shows up verbatim when runc is not using the
		// systemd cgroup driver.
		if k := strings.LastIndexByte(comp, ':'); k >= 0 {
			if cand := comp[k+1:]; isContainerID(cand) {
				head := comp[:k]
				switch {
				case strings.HasSuffix(head, ":cri-containerd"):
					return cand, RuntimeContainerd
				case strings.HasSuffix(head, ":crio"):
					return cand, RuntimeCRIO
				case strings.HasSuffix(head, ":docker"):
					return cand, RuntimeDocker
				case strings.HasSuffix(head, ":libpod"):
					return cand, RuntimePodman
				}
				return cand, ""
			}
			continue
		}
		matched := false
		for _, p := range containerPrefixes {
			if strings.HasPrefix(comp, p.prefix) {
				matched = true
				if cand := comp[len(p.prefix):]; isContainerID(cand) {
					return cand, p.runtime
				}
			}
		}
		if matched || !isContainerID(comp) {
			continue
		}
		// A bare id: the parent directory says who made it.
		parent := ""
		if i > 0 {
			parent = parts[i-1]
		}
		switch {
		case parent == "docker" || parent == "actions_job":
			// /docker/<id> is Docker's cgroupfs driver; /actions_job/<id> is
			// a GitHub Actions job container, which Docker runs.
			return comp, RuntimeDocker
		case parent == "libpod_parent":
			return comp, RuntimePodman
		case kube:
			// kubepods/<qos>/pod<uid>/<id> (kubelet cgroupfs driver) does not
			// name the runtime. containerd is assumed, as the usual CRI.
			return comp, RuntimeContainerd
		}
		return comp, ""
	}
	return "", ""
}

// podFromCgroupPath extracts the pod UID from a kubepods cgroup path. The
// kubelet writes it as "pod<uid>" with the cgroupfs driver and, with the
// systemd driver, inside a slice name with dashes turned into underscores
// ("kubepods-burstable-pod<8>_<4>_<4>_<4>_<12>.slice"). Static pods use a
// 32-hex configuration hash instead of a UUID.
func podFromCgroupPath(path string) string {
	if !strings.Contains(path, "kubepods") {
		return ""
	}
	parts := strings.Split(path, "/")
	for i := len(parts) - 1; i >= 0; i-- {
		comp := strings.TrimSuffix(parts[i], ".slice")
		k := strings.LastIndex(comp, "pod")
		if k < 0 {
			continue
		}
		// "pod" must start the component or follow the slice-name dash, so
		// that a namespace or unit that merely contains "pod" does not match.
		if k > 0 && comp[k-1] != '-' {
			continue
		}
		if uid := normalizePodUID(comp[k+3:]); uid != "" {
			return uid
		}
	}
	return ""
}

// normalizePodUID accepts a UUID written with dashes or underscores, or a
// 32-hex hash, and returns it lower-case with dashes.
func normalizePodUID(s string) string {
	switch len(s) {
	case 32:
		for i := 0; i < len(s); i++ {
			if !isLowerHex(s[i]) {
				return ""
			}
		}
		return s
	case 36:
		b := []byte(s)
		for i, c := range b {
			switch i {
			case 8, 13, 18, 23:
				if c != '-' && c != '_' {
					return ""
				}
				b[i] = '-'
			default:
				if !isLowerHex(c) {
					return ""
				}
			}
		}
		return string(b)
	}
	return ""
}

func isLowerHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
}

// isContainerID reports whether s is a full container id: 64 lower-case hex
// digits. Truncated ids never appear in cgroup paths, and insisting on the
// full length keeps ordinary directory names from matching.
func isContainerID(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isLowerHex(s[i]) {
			return false
		}
	}
	return true
}

// parseMountinfo is the fallback for a process inside a private cgroup
// namespace, whose cgroup file only says "0::/". The runtime bind-mounts
// /etc/hostname, /etc/hosts and /etc/resolv.conf from a per-container
// directory on the host, and field 4 of mountinfo (the mount's root inside
// its filesystem) still shows that directory:
//
//	223 204 254:0 /var/lib/docker/containers/<id>/hostname /etc/hostname rw - ext4 ...
//
// Only those three mount points are considered. A host process also has
// mount POINTS under /var/lib/docker/containers/<id>/, so matching anywhere
// in the line would put host processes in containers.
func parseMountinfo(data []byte) cgroupInfo {
	var docker, podman, pod string
	for lines := 0; len(data) > 0 && lines < 8192; lines++ {
		var line []byte
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			line, data = data[:i], data[i+1:]
		} else {
			// No newline: the read limit may have cut this line.
			break
		}
		if len(line) > 8192 {
			continue
		}
		f := bytes.Fields(line)
		if len(f) < 5 {
			continue
		}
		root, mountPoint := unescapeMountField(string(f[3])), unescapeMountField(string(f[4]))
		switch mountPoint {
		case "/etc/hostname", "/etc/hosts", "/etc/resolv.conf":
			parts := strings.Split(root, "/")
			n := len(parts)
			// .../containers/<id>/<file>  (Docker, any data-root)
			if docker == "" && n >= 3 && parts[n-3] == "containers" && isContainerID(parts[n-2]) {
				docker = parts[n-2]
			}
			// .../overlay-containers/<id>/userdata/<file>  (Podman; CRI-O
			// uses the same store but there the id is the pod sandbox).
			// UNVERIFIED: Podman layout taken from memory, not a live fixture.
			if podman == "" && n >= 4 && parts[n-2] == "userdata" && parts[n-4] == "overlay-containers" && isContainerID(parts[n-3]) {
				podman = parts[n-3]
			}
		}
		// The kubelet bind-mounts /etc/hosts and the termination log from
		// /var/lib/kubelet/pods/<uid>/...
		// UNVERIFIED: kubelet layout taken from memory, not a live fixture.
		if pod == "" && (mountPoint == "/etc/hosts" || mountPoint == "/dev/termination-log") {
			parts := strings.Split(root, "/")
			for i := 0; i+1 < len(parts); i++ {
				if parts[i] == "pods" {
					if uid := normalizePodUID(parts[i+1]); uid != "" {
						pod = uid
						break
					}
				}
			}
		}
	}
	info := cgroupInfo{pod: pod}
	switch {
	case docker != "":
		info.id, info.runtime = docker, RuntimeDocker
	case podman != "" && pod == "":
		// Inside a pod this id is the sandbox, not the container: say nothing
		// rather than name the wrong thing.
		info.id, info.runtime = podman, RuntimePodman
	}
	return info
}

// unescapeMountField decodes the octal escapes (\040 for space and so on)
// the kernel uses in mountinfo fields.
func unescapeMountField(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) && isOctal(s[i+1]) && isOctal(s[i+2]) && isOctal(s[i+3]) {
			b.WriteByte((s[i+1]-'0')<<6 | (s[i+2]-'0')<<3 | (s[i+3] - '0'))
			i += 3
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isOctal(c byte) bool { return c >= '0' && c <= '7' }
