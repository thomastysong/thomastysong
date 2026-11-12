package procmon

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseStat(t *testing.T) {
	tests := []struct {
		name  string
		in    string
		comm  string
		state byte
		ppid  int
		ticks uint64
		ok    bool
	}{
		{"plain", "42 (bash) S 1 42 42 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 12345 1 2", "bash", 'S', 1, 12345, true},
		{"forged name", "7 (x) R 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 99 (y) S 3 7 7 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 555 1", "x) R 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 99 (y", 'S', 3, 555, true},
		{"spaces in name", "8 (Web Content) S 2 8 8 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 77 1", "Web Content", 'S', 2, 77, true},
		{"zombie", "9 (claude) Z 1 9 9 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 88 1", "claude", 'Z', 1, 88, true},
		{"too short", "9 (x) S 1 2 3", "", 0, 0, 0, false},
		{"no parens", "9 x S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20", "", 0, 0, 0, false},
		{"bad ppid", "9 (x) S -5 9 9 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 88 1", "", 0, 0, 0, false},
		{"bad ticks", "9 (x) S 1 9 9 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 zz 1", "", 0, 0, 0, false},
		{"empty", "", "", 0, 0, 0, false},
		{"close only", ")", "", 0, 0, 0, false},
		{"state word", "9 (x) SS 1 9 9 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 88 1", "", 0, 0, 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			comm, state, ppid, ticks, ok := parseStat([]byte(tc.in))
			if ok != tc.ok || (ok && (comm != tc.comm || state != tc.state || ppid != tc.ppid || ticks != tc.ticks)) {
				t.Fatalf("parseStat = %q %c %d %d %v", comm, state, ppid, ticks, ok)
			}
		})
	}
}

func TestParseStatusUID(t *testing.T) {
	for in, want := range map[string]string{
		"Name:\tx\nUid:\t1000\t1000\t1000\t1000\nGid:\t1\n": "1000",
		"Uid:\t0\t0\t0\t0":       "0",
		"Name:\tx\n":             "",
		"Uid:\t-1\t0\n":          "",
		"Uid:\n":                 "",
		"Uid:\t99999999999\t0\n": "",
	} {
		got, ok := parseStatusUID([]byte(in))
		if got != want || ok != (want != "") {
			t.Errorf("parseStatusUID(%q) = %q %v", in, got, ok)
		}
	}
}

func TestSplitNUL(t *testing.T) {
	if got := splitNUL([]byte("a\x00\x00b\x00\x00\x00"), 10); !reflect.DeepEqual(got, []string{"a", "", "b"}) {
		t.Errorf("got %q", got)
	}
	if got := splitNUL([]byte("a\x00b\x00c"), 2); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Errorf("cap: got %q", got)
	}
	if got := splitNUL(nil, 5); got != nil {
		t.Errorf("nil: got %q", got)
	}
}

func TestParseEnviron(t *testing.T) {
	env := parseEnviron([]byte("A=1\x00A=2\x00=hidden\x00NOEQ\x00B=x=y\x00C="), false)
	want := map[string]string{"A": "1", "B": "x=y", "C": ""}
	if !reflect.DeepEqual(env, want) {
		t.Errorf("got %v", env)
	}
	// A cut block drops its incomplete last entry.
	if env := parseEnviron([]byte("A=1\x00TOKEN=abc"), true); len(env) != 1 {
		t.Errorf("truncated: %v", env)
	}
	big := strings.Repeat("K=v\x00", maxEnvVars+10)
	if env := parseEnviron([]byte(big), false); len(env) != 1 {
		t.Errorf("duplicates: %d", len(env))
	}
}

func TestParseSmallFiles(t *testing.T) {
	if got := parseChildren([]byte("12 13 x -4 0 99999999999 14 "), nil); !reflect.DeepEqual(got, []int{12, 13, 14}) {
		t.Errorf("children = %v", got)
	}
	if bt, ok := parseBtime([]byte("cpu 1 2\nbtime 1700000000\n")); !ok || bt != 1700000000 {
		t.Errorf("btime = %d %v", bt, ok)
	}
	if _, ok := parseBtime([]byte("btime -3\n")); ok {
		t.Error("negative btime accepted")
	}
	pw := parsePasswd([]byte("root:x:0:0::/root:/bin/sh\n#c\n+nis\nbad\nu:x:notnum:1\ndev:x:1000:1000::/home/dev:/bin/bash\ndup:x:1000:1:::\n"))
	if !reflect.DeepEqual(pw, map[string]string{"0": "root", "1000": "dev"}) {
		t.Errorf("passwd = %v", pw)
	}
	if got := refineName("github-copilot-", []string{"/usr/lib/node_modules/.bin/github-copilot-cli"}); got != "github-copilot-cli" {
		t.Errorf("refineName = %q", got)
	}
	if got := refineName("short", []string{"/bin/longer-name"}); got != "short" {
		t.Errorf("refineName short = %q", got)
	}
	for in, want := range map[string]bool{"1": true, "4194304": true, "0": false, "-1": false, "self": false, "12345678901": false, "": false} {
		if _, ok := parsePIDName(in); ok != want {
			t.Errorf("parsePIDName(%q) = %v", in, ok)
		}
	}
	if trimDeleted("/x/claude (deleted)") != "/x/claude" {
		t.Error("trimDeleted")
	}
}

func TestParseCgroupWorkload(t *testing.T) {
	id := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	tests := []struct {
		name, in string
		want     workloadIDs
	}{
		{"cgroup v1 docker", "12:pids:/docker/" + id + "\n11:memory:/docker/" + id + "\n", workloadIDs{id: id, runtime: "docker"}},
		{"systemd docker scope", "0::/system.slice/docker-" + id + ".scope\n", workloadIDs{id: id, runtime: "docker"}},
		{"kubepods systemd containerd", "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1b2c3d4e_5f60_7182_93a4_b5c6d7e8f901.slice/cri-containerd-" + id + ".scope\n",
			workloadIDs{id: id, runtime: "containerd", pod: "1b2c3d4e-5f60-7182-93a4-b5c6d7e8f901"}},
		{"kubepods cgroupfs", "0::/kubepods/besteffort/pod1b2c3d4e-5f60-7182-93a4-b5c6d7e8f901/" + id + "\n",
			workloadIDs{id: id, runtime: "containerd", pod: "1b2c3d4e-5f60-7182-93a4-b5c6d7e8f901"}},
		{"cri-o with conmon", "0::/machine.slice/crio-conmon-" + id + ".scope\n1:name=x:/crio-" + id + ".scope\n", workloadIDs{id: id, runtime: "cri-o"}},
		{"podman rootless", "0::/user.slice/user-1000.slice/user@1000.service/user.slice/libpod-" + id + ".scope/container\n", workloadIDs{id: id, runtime: "podman"}},
		{"containerd triple", "0::/system.slice/containerd.service/kubepods-besteffort-pod1b2c3d4e_5f60_7182_93a4_b5c6d7e8f901.slice:cri-containerd:" + id + "\n",
			workloadIDs{id: id, runtime: "containerd", pod: "1b2c3d4e-5f60-7182-93a4-b5c6d7e8f901"}},
		{"github actions", "0::/actions_job/" + id + "\n", workloadIDs{id: id, runtime: "docker"}},
		{"private namespace view", "0::/../../system.slice/docker-" + id + ".scope\n", workloadIDs{id: id, runtime: "docker"}},
		{"host process", "0::/user.slice/user-1000.slice/session-3.scope\n", workloadIDs{}},
		{"short id", "0::/docker/0123456789ab\n", workloadIDs{}},
		{"upper-case id", "0::/docker/" + strings.ToUpper(id) + "\n", workloadIDs{}},
		{"garbage", "\x00\xff:::\n::\n:\n", workloadIDs{}},
		{"podsomething namespace", "0::/kubepods/notapod/xpod1b2c3d4e-5f60-7182-93a4-b5c6d7e8f901\n", workloadIDs{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseCgroupWorkload([]byte(tc.in)); got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
	// Huge input is bounded.
	if got := parseCgroupWorkload([]byte(strings.Repeat("0::/"+strings.Repeat("a/", 3000)+"\n", 600))); got != (workloadIDs{}) {
		t.Errorf("huge = %+v", got)
	}
}

func FuzzParseStat(f *testing.F) {
	f.Add([]byte("42 (bash) S 1 42 42 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 12345 1 2"))
	f.Add([]byte("7 (x) R 1 (y) )"))
	f.Fuzz(func(t *testing.T, b []byte) {
		parseStat(b)
		parseStatusUID(b)
		parseEnviron(b, len(b)%2 == 0)
		parseCgroupWorkload(b)
		parsePasswd(b)
		parseChildren(b, nil)
	})
}
