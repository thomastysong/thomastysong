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

// TestScanStateRecordsBundleVersion: `scan --state` loads the installed
// signed bundle, so its heartbeat must say which version, as the daemon's
// does. A scan-only host (tier 2, no daemon) otherwise failed the Fleet
// policy "rules bundle is current" with a current bundle installed: the
// heartbeat of a fresh state database had bundle_version "".
func TestScanStateRecordsBundleVersion(t *testing.T) {
	root := fakeHostRoot(t)
	dir := t.TempDir()
	cfg, data := testConfig(t, "")
	ta := newTestApp(t)
	key := filepath.Join(dir, "signing")
	ta.mustRun(t, exitOK, "bundle", "keygen", "--out", key)
	src := filepath.Join(dir, "src")
	writeTestFile(t, filepath.Join(src, "rules", "zz.yaml"), testPack, 0o644)
	arch := filepath.Join(dir, "bundle.tar.gz")
	ta.mustRun(t, exitOK, "bundle", "create", "--src", src, "--version", "7", "--key", key+".key", "--out", arch)
	ta.mustRun(t, exitOK, "bundle", "pull", "--config", cfg, "--file", arch, "--pub", key+".pub")

	ta.mustRun(t, exitOK, "scan", "--config", cfg, "--host-root", root, "--projects=false", "--state")
	st, err := state.OpenReadOnly(filepath.Join(data, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	rows, err := st.Query("health", nil)
	if err != nil || len(rows) != 1 {
		t.Fatalf("health rows %v %v", rows, err)
	}
	if rows[0]["mode"] != "scan" || rows[0]["bundle_version"] != "7" {
		t.Fatalf("scan heartbeat: mode %q, bundle_version %q, want scan and 7", rows[0]["mode"], rows[0]["bundle_version"])
	}
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

// `scan --outbox` must not prune by the sink's blind retention when a
// consumer is configured: with output.fluent_bit.tail_db set, only the
// daemon prunes, by what Fluent Bit has read. With no consumer at all it
// applies retention as the daemon does.
func TestScanOutboxKeepsUnshippedSegments(t *testing.T) {
	now := time.Now().UTC()
	seed := func(t *testing.T, outbox string) (old string) {
		old = filepath.Join(outbox, "detection-"+now.AddDate(0, 0, -10).Format("20060102")+"-00-0000.ndjson")
		newer := filepath.Join(outbox, "detection-"+now.AddDate(0, 0, -9).Format("20060102")+"-00-0000.ndjson")
		writeTestFile(t, old, nativeLine(t, "alice", "1001", "unshipped finding", 0), 0o640)
		writeTestFile(t, newer, nativeLine(t, "alice", "1001", "unshipped finding 2", 1), 0o640)
		return old
	}
	for _, tc := range []struct {
		name, extra string
		kept        bool
	}{
		{"tail_db", "output:\n  fluent_bit:\n    tail_db: " + filepath.Join(t.TempDir(), "flb", "spoor-findings.db") + "\n", true},
		{"otlp shipper", "output:\n  otlp:\n    endpoint: http://127.0.0.1:1/v1/logs\n", true},
		{"no consumer", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, data := testConfig(t, tc.extra)
			old := seed(t, filepath.Join(data, "outbox"))
			ta := newTestApp(t)
			var res scanResult
			decodeJSON(t, ta.mustRun(t, exitOK, "scan", "--config", cfg, "--host-root", fakeHostRoot(t), "--projects=false", "--outbox", "--json"), &res)
			_, err := os.Stat(old)
			if kept := err == nil; kept != tc.kept {
				t.Fatalf("segment 10 days old kept=%v, want %v (notes %v)", kept, tc.kept, res.Notes)
			}
			if tc.kept && len(res.Notes) == 0 {
				t.Fatal("no note that pruning is left to the daemon")
			}
		})
	}
}

// Tier 2 (scheduled `scan --outbox`, no daemon): the outbox is created as
// the daemon creates it, 2750 owned by output.group, so a shipper in that
// group can read what scan writes, and the data directory is traversable.
func TestScanOutboxUsesOutputGroup(t *testing.T) {
	if !permsChecked || os.Geteuid() != 0 {
		t.Skip("needs root on POSIX")
	}
	acc, err := lookupAccessor("daemon")
	if err != nil {
		t.Skip(err)
	}
	cfg, data := testConfig(t, "output:\n  group: daemon\n")
	// Only the modes spoor creates matter: open up the test's own dirs.
	for _, d := range []string{filepath.Dir(data), filepath.Dir(filepath.Dir(data))} {
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	ta := newTestApp(t)
	ta.mustRun(t, exitOK, "scan", "--config", cfg, "--host-root", fakeHostRoot(t), "--projects=false", "--outbox")
	ents, _ := os.ReadDir(filepath.Join(data, "outbox"))
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	if len(names) == 0 {
		t.Fatal("scan wrote no segment")
	}
	// "daemon" (uid 1, primary group daemon) stands in for the shipper
	// account that is a member of output.group.
	if ok, why := acc.canRead(filepath.Join(data, "outbox"), names); !ok {
		t.Fatalf("a member of output.group cannot read what scan --outbox wrote: %s", why)
	}
	if fi, err := os.Stat(data); err != nil || fi.Mode().Perm() != 0o711 {
		t.Fatalf("data directory mode %v", fi.Mode())
	}
}
