package procmon

import (
	"bytes"
	"strings"
)

// workloadIDs is what a cgroup file says about the container of a process.
type workloadIDs struct{ id, runtime, pod string }

// parseCgroupWorkload reads /proc/<pid>/cgroup in host-root mode, where
// internal/platform (which reads the sensor's own /proc) cannot be asked.
// It recognises the same layouts platform does: systemd scope names
// (docker-<id>.scope, cri-containerd-<id>.scope, crio-<id>.scope,
// libpod-<id>.scope), the cgroupfs drivers (/docker/<id>,
// /kubepods/<qos>/pod<uid>/<id>), the "<slice>:cri-containerd:<id>" triple,
// and the kubelet pod uid in both spellings. From a sensor in a private
// cgroup namespace the paths start with "/.." but keep their components, so
// the same parse applies.
func parseCgroupWorkload(data []byte) workloadIDs {
	var best workloadIDs
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
		// hierarchy-id ":" controllers ":" path; the path may contain colons.
		i := bytes.IndexByte(line, ':')
		if i < 0 {
			continue
		}
		j := bytes.IndexByte(line[i+1:], ':')
		if j < 0 {
			continue
		}
		path := string(line[i+1+j+1:])
		id, rt := cgroupContainer(path)
		score := 0
		if id != "" {
			score = 1
			if rt != "" {
				score = 2
			}
		}
		if score > bestScore {
			best.id, best.runtime, bestScore = id, rt, score
		}
		if best.pod == "" {
			best.pod = cgroupPod(path)
		}
	}
	return best
}

var scopePrefixes = []struct{ prefix, runtime string }{
	{"cri-containerd-", "containerd"},
	{"docker-", "docker"},
	{"crio-", "cri-o"},
	{"libpod-", "podman"},
	{"nerdctl-", "containerd"},
}

// cgroupContainer finds the innermost container named in one cgroup path.
func cgroupContainer(path string) (id, runtime string) {
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
		if k := strings.LastIndexByte(comp, ':'); k >= 0 {
			cand := comp[k+1:]
			if !isContainerID(cand) {
				continue
			}
			head := comp[:k]
			switch {
			case strings.HasSuffix(head, ":cri-containerd"):
				return cand, "containerd"
			case strings.HasSuffix(head, ":crio"):
				return cand, "cri-o"
			case strings.HasSuffix(head, ":docker"):
				return cand, "docker"
			case strings.HasSuffix(head, ":libpod"):
				return cand, "podman"
			}
			return cand, ""
		}
		matched := false
		for _, p := range scopePrefixes {
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
		parent := ""
		if i > 0 {
			parent = parts[i-1]
		}
		switch {
		case parent == "docker" || parent == "actions_job":
			return comp, "docker"
		case parent == "libpod_parent":
			return comp, "podman"
		case kube:
			// The cgroupfs kubelet layout does not name the runtime;
			// containerd is the usual CRI.
			return comp, "containerd"
		}
		return comp, ""
	}
	return "", ""
}

// cgroupPod extracts a kubelet pod uid ("pod<uid>" or, with the systemd
// driver, "kubepods-<qos>-pod<uid_with_underscores>.slice").
func cgroupPod(path string) string {
	if !strings.Contains(path, "kubepods") {
		return ""
	}
	parts := strings.Split(path, "/")
	for i := len(parts) - 1; i >= 0; i-- {
		comp := parts[i]
		// "<slice>:cri-containerd:<id>" carries the pod slice before the
		// first colon.
		if j := strings.IndexByte(comp, ':'); j >= 0 {
			comp = comp[:j]
		}
		comp = strings.TrimSuffix(comp, ".slice")
		k := strings.LastIndex(comp, "pod")
		if k < 0 || (k > 0 && comp[k-1] != '-') {
			continue
		}
		if uid := podUID(comp[k+3:]); uid != "" {
			return uid
		}
	}
	return ""
}

func podUID(s string) string {
	switch len(s) {
	case 32: // static pods use a config hash
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

func isLowerHex(c byte) bool { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') }

// isContainerID insists on the full 64-hex id: truncated ids never appear
// in cgroup paths, and the length keeps ordinary directory names out.
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
