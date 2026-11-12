package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/thomastysong/spoor/internal/discovery"
	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/state"
)

// fakeHostRoot builds a root filesystem with one account whose home holds
// a Claude Code configuration with an MCP server, owned by the caller (so
// the ownership checks discovery applies pass).
func fakeHostRoot(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("host roots are a Linux node-sensor feature")
	}
	root := filepath.Join(t.TempDir(), "root")
	uid, gid := os.Getuid(), os.Getgid()
	writeTestFile(t, filepath.Join(root, "etc", "passwd"), fmt.Sprintf("dev:x:%d:%d:Dev:/home/dev:/bin/sh\n", uid, gid), 0o644)
	home := filepath.Join(root, "home", "dev")
	writeTestFile(t, filepath.Join(home, ".claude", "settings.json"), `{"permissions": {"defaultMode": "bypassPermissions"}}`, 0o600)
	writeTestFile(t, filepath.Join(home, ".claude.json"), `{"mcpServers": {"files": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"]}}}`, 0o600)
	return root
}

func TestScanHostRoot(t *testing.T) {
	root := fakeHostRoot(t)
	cfg, data := testConfig(t, "")
	ta := newTestApp(t)
	var res scanResult
	decodeJSON(t, ta.mustRun(t, exitOK, "scan", "--config", cfg, "--host-root", root, "--projects=false", "--json"), &res)
	if res.Counts["inventory"] == 0 {
		t.Fatalf("no inventory from the fake root: %+v", res)
	}
	kinds := map[event.AssetKind]bool{}
	for _, e := range res.Records {
		if e.Asset != nil {
			kinds[e.Asset.Kind] = true
			if strings.Contains(e.Asset.Path, root) {
				t.Errorf("asset path shows the host-root prefix: %s", e.Asset.Path)
			}
		}
	}
	if !kinds[event.AssetAgent] || !kinds[event.AssetMCPServer] {
		t.Fatalf("asset kinds %v", kinds)
	}
	if _, err := os.Stat(filepath.Join(data, "state.db")); err == nil {
		t.Fatal("scan without --state wrote the state database")
	}

	// --state records assets and a heartbeat the Fleet policies can see.
	ta.mustRun(t, exitOK, "scan", "--config", cfg, "--host-root", root, "--projects=false", "--state")
	if !strings.Contains(ta.out.String(), "recorded in") {
		t.Fatalf("stdout:\n%s", ta.out.String())
	}
	st, err := state.OpenReadOnly(filepath.Join(data, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	rows, err := st.Query("health", nil)
	if err != nil || len(rows) != 1 {
		t.Fatalf("health rows %v %v", rows, err)
	}
	hb, err := time.Parse(time.RFC3339Nano, rows[0]["heartbeat"])
	if err != nil || time.Since(hb) > time.Minute {
		t.Fatalf("heartbeat %q", rows[0]["heartbeat"])
	}
	agents, err := st.Query("agents", nil)
	if err != nil || len(agents) == 0 {
		t.Fatalf("agents rows %v %v", agents, err)
	}
	// NDJSON output: one record per line.
	out := ta.mustRun(t, exitOK, "scan", "--config", cfg, "--host-root", root, "--projects=false", "--ndjson")
	if n := strings.Count(strings.TrimSpace(out), "\n") + 1; n < 2 {
		t.Fatalf("ndjson lines: %d", n)
	}
	ta.mustRun(t, exitUsage, "scan", "--json", "--ndjson")
}

func TestScanComplete(t *testing.T) {
	if !scanComplete(discovery.Ledger{Roots: 3, Files: 9}) {
		t.Fatal("clean ledger not complete")
	}
	for _, l := range []discovery.Ledger{
		{Truncated: true}, {Denied: 1}, {Errors: 2}, {Skipped: 1},
		{Notes: []string{"removals not reported: the scan was not complete (a home was not accessible)"}},
	} {
		if scanComplete(l) {
			t.Errorf("%+v reported complete", l)
		}
	}
}

func TestSeenAssets(t *testing.T) {
	prev := map[string]string{"a": "1", "b": "2", "c": "3"}
	evs := []*event.Event{
		{Kind: event.KindInventory, Asset: &event.Asset{ID: "b", Change: event.ChangeRemoved}},
		{Kind: event.KindInventory, Asset: &event.Asset{ID: "d", Change: event.ChangeNew}},
		{Kind: event.KindPosture, Check: &event.Check{ID: "x"}},
	}
	if got := strings.Join(seenAssets(prev, evs), ","); got != "a,c,d" {
		t.Fatalf("seen %s", got)
	}
}
