package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestHostRootPID(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int
	}{
		{"/proc/4242/root", 4242},
		{"/proc/4242/root/", 4242},
		{"/proc/./4242/root", 4242},
		{"/proc/1/root", 1},
		{"/proc/self/root", 0},
		{"/proc/0/root", 0},
		{"/proc/-1/root", 0},
		{"/proc/4242", 0},
		{"/proc/4242/root/home", 0},
		{"/proc/4242/cwd", 0},
		{"/host", 0},
		{"/host/proc/4242/root", 0},
		{"/proc/99999999999/root", 0},
		{"", 0},
	} {
		if got := hostRootPID(tc.in); got != tc.want {
			t.Errorf("hostRootPID(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// `scan --host-root /proc/<pid>/root` stamps the container of that pid on
// every record, and says so; a pid outside any container is said too.
func TestScanStampsContainer(t *testing.T) {
	fake := t.TempDir()
	oldRoot, oldLookup := procRoot, containerOfPID
	t.Cleanup(func() { procRoot, containerOfPID = oldRoot, oldLookup })
	procRoot = filepath.Join(fake, "proc")
	asked := 0
	containerOfPID = func(pid int) (string, string, string) {
		asked = pid
		if pid == 4242 {
			return "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "containerd", "11111111-2222-3333-4444-555555555555"
		}
		return "", "", ""
	}
	uid, gid := strconv.Itoa(os.Getuid()), strconv.Itoa(os.Getgid())
	for _, pid := range []string{"4242", "77"} {
		root := filepath.Join(procRoot, pid, "root")
		writeTestFile(t, filepath.Join(root, "etc", "passwd"), "dev:x:"+uid+":"+gid+"::/home/dev:/bin/sh\n", 0o644)
		writeTestFile(t, filepath.Join(root, "home", "dev", ".cursor", "mcp.json"), `{"mcpServers":{"ctr-srv":{"command":"npx","args":["-y","some-mcp"]}}}`, 0o644)
	}
	cfg, _ := testConfig(t, "")
	ta := newTestApp(t)
	var res scanResult
	decodeJSON(t, ta.mustRun(t, exitOK, "scan", "--config", cfg, "--host-root", filepath.Join(procRoot, "4242", "root"), "--projects=false", "--json"), &res)
	if asked != 4242 {
		t.Fatalf("container lookup for pid %d", asked)
	}
	found := false
	for _, e := range res.Records {
		if e.Container == nil || !strings.HasPrefix(e.Container.ID, "0123456789abcdef") || e.Container.Runtime != "containerd" || e.Container.PodUID == "" {
			t.Errorf("record without the container: %s %+v", e.Type, e.Container)
		}
		if e.Asset != nil && e.Asset.Name == "ctr-srv" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the container's MCP server was not found: %d records, ledger %+v", len(res.Records), res.Ledger)
	}
	if !strings.Contains(strings.Join(res.Notes, "\n"), "container 0123456789abcdef") {
		t.Errorf("notes: %v", res.Notes)
	}

	// A process outside any container: no container stamped, said.
	var res2 scanResult
	decodeJSON(t, ta.mustRun(t, exitOK, "scan", "--config", cfg, "--host-root", filepath.Join(procRoot, "77", "root"), "--projects=false", "--json"), &res2)
	if len(res2.Records) == 0 {
		t.Fatal("no records for the host process root")
	}
	for _, e := range res2.Records {
		if e.Container != nil {
			t.Errorf("container stamped for a host process: %+v", e.Container)
		}
	}
	if !strings.Contains(strings.Join(res2.Notes, "\n"), "pid 77 is not in a container") {
		t.Errorf("notes: %v", res2.Notes)
	}
	// Any other root names no process.
	c, note := scanContainer(filepath.Join(fake, "host"))
	if c != nil || note != "" {
		t.Errorf("non-proc root: %+v %q", c, note)
	}
}
