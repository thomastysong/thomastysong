package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func checkOf(r *doctorReport, id string) check {
	for _, c := range r.Checks {
		if c.ID == id {
			return c
		}
	}
	return check{}
}

func TestDoctorJSON(t *testing.T) {
	cfg, data := testConfig(t, "")
	ta := newTestApp(t)
	ta.run("doctor", "--config", cfg, "--json")
	var r doctorReport
	decodeJSON(t, ta.out.String(), &r)
	for _, id := range []string{"config", "privilege", "kill_switch", "host_id", "dirs", "hooks", "rules", "bundle", "heartbeat", "outbox", "fluent_bit", "daemon"} {
		if checkOf(&r, id).ID == "" {
			t.Errorf("doctor lacks check %q", id)
		}
	}
	if r.DataDir != data || r.KillSwitch.On || r.Rules == nil || r.Rules.Count == 0 || r.Host.OS == "" {
		t.Fatalf("report: %+v", r)
	}
	if c := checkOf(&r, "heartbeat"); c.Status != "warn" {
		t.Fatalf("heartbeat without a database: %+v", c)
	}

	// The kill switch next to the configuration is shown.
	writeTestFile(t, filepath.Join(filepath.Dir(cfg), "disabled"), "", 0o644)
	ta.run("doctor", "--config", cfg, "--json")
	decodeJSON(t, ta.out.String(), &r)
	if !r.KillSwitch.On || checkOf(&r, "kill_switch").Status != "warn" {
		t.Fatalf("kill switch not reported: %+v", r.KillSwitch)
	}
	os.Remove(filepath.Join(filepath.Dir(cfg), "disabled"))

	// After `scan --state` there is a fresh heartbeat and the directories
	// exist.
	ta.mustRun(t, exitOK, "scan", "--config", cfg, "--host-root", fakeHostRoot(t), "--projects=false", "--state")
	ta.run("doctor", "--config", cfg, "--json")
	decodeJSON(t, ta.out.String(), &r)
	if c := checkOf(&r, "heartbeat"); c.Status != "ok" || r.Heartbeat == nil || r.Heartbeat.Mode == "" {
		t.Fatalf("heartbeat after scan --state: %+v %+v", c, r.Heartbeat)
	}

	// A world-writable data directory fails the dirs check and exit is 4.
	if permsChecked {
		if err := os.Chmod(filepath.Join(data, "state.db"), 0o666); err != nil {
			t.Fatal(err)
		}
		code := ta.run("doctor", "--config", cfg, "--json")
		decodeJSON(t, ta.out.String(), &r)
		if c := checkOf(&r, "dirs"); c.Status != "fail" || code != exitCheck {
			t.Fatalf("world-writable state.db: %+v exit %d", c, code)
		}
	}

	// The text form fits the one-screen promise.
	ta.run("doctor", "--config", cfg)
	if !strings.Contains(ta.out.String(), "[OK  ] rules") {
		t.Fatalf("doctor text:\n%s", ta.out.String())
	}
}

func TestDoctorBrokenConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "hawkbell.yaml")
	writeTestFile(t, cfg, "privacy:\n  profile: everything\n", 0o644)
	ta := newTestApp(t)
	code := ta.run("doctor", "--config", cfg, "--data-dir", filepath.Join(dir, "d"), "--json")
	var r doctorReport
	decodeJSON(t, ta.out.String(), &r)
	if code != exitCheck || checkOf(&r, "config").Status != "fail" {
		t.Fatalf("broken config: exit %d %+v", code, checkOf(&r, "config"))
	}
}

func TestDoctorAsUser(t *testing.T) {
	if !permsChecked || os.Geteuid() != 0 {
		t.Skip("needs POSIX permissions and root to judge another account")
	}
	cfg, data := testConfig(t, "")
	writeTestFile(t, filepath.Join(data, "outbox", "detection-20261110-09-0000.ndjson"), "{}\n", 0o600)
	if err := os.Chmod(filepath.Join(data, "outbox"), 0o700); err != nil {
		t.Fatal(err)
	}
	ta := newTestApp(t)
	ta.run("doctor", "--config", cfg, "--as-user", "nobody", "--json")
	var r doctorReport
	decodeJSON(t, ta.out.String(), &r)
	if r.Outbox.Readable == nil || *r.Outbox.Readable || checkOf(&r, "outbox").Status != "fail" {
		t.Fatalf("nobody can read a 0700 root outbox? %+v %+v", r.Outbox, checkOf(&r, "outbox"))
	}
	ta.run("doctor", "--config", cfg, "--as-user", "root", "--json")
	decodeJSON(t, ta.out.String(), &r)
	if r.Outbox.Readable == nil || !*r.Outbox.Readable {
		t.Fatalf("root cannot read? %+v", r.Outbox)
	}
}

// fakeFluentBit serves the three API endpoints doctor reads, shaped like
// Fluent Bit 5.2.0's answers.
func fakeFluentBit(t *testing.T, backlog bool, dropped int) *httptest.Server {
	t.Helper()
	inputs := `"hawkbell_findings":{"status":{"overlimit":false,"mem_size":"0b","mem_limit":"0b"},"chunks":{"total":0,"up":0,"down":0,"busy":0,"busy_size":"0b"}}`
	if backlog {
		inputs += `,"storage_backlog.2":{"status":{"overlimit":false,"mem_size":"0b","mem_limit":"0b"},"chunks":{"total":0,"up":0,"down":0,"busy":0,"busy_size":"0b"}}`
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"fluent-bit":{"version":"5.2.0","edition":"Community","flags":[]}}`)
	})
	mux.HandleFunc("/api/v1/metrics", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"input":{},"filter":{},"output":{"splunk.0":{"proc_records":10,"proc_bytes":1,"errors":0,"retries":3,"retries_failed":0,"dropped_records":%d,"retried_records":3}}}`, dropped)
	})
	mux.HandleFunc("/api/v1/storage", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"storage_layer":{"chunks":{"total_chunks":0,"mem_chunks":0,"fs_chunks":0,"fs_chunks_up":0,"fs_chunks_down":0}},"input_chunks":{%s}}`, inputs)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestFluentBitAPIChecks(t *testing.T) {
	ctx := context.Background()
	c := loopbackClient(3 * time.Second)
	f, ver := checkFluentBitAPI(ctx, c, fakeFluentBit(t, true, 0).URL)
	if ver != "5.2.0" || len(f) != 0 {
		t.Fatalf("healthy: %v %+v", ver, f)
	}
	f, _ = checkFluentBitAPI(ctx, c, fakeFluentBit(t, false, 7).URL)
	codes := map[string]string{}
	for _, x := range f {
		codes[x.Code] = x.Status
	}
	if codes["shipper.dropped_records"] != "warn" || codes["shipper.unsafe_config"] != "warn" {
		t.Fatalf("findings: %+v", f)
	}
	f, _ = checkFluentBitAPI(ctx, c, "http://127.0.0.1:1")
	if len(f) != 1 || f[0].Code != "shipper.unreachable" {
		t.Fatalf("unreachable: %+v", f)
	}
}

func TestDoctorFluentBitFromConfig(t *testing.T) {
	srv := fakeFluentBit(t, false, 0)
	cfg, _ := testConfig(t, "output:\n  fluent_bit:\n    api: "+srv.URL+"\n")
	ta := newTestApp(t)
	ta.run("doctor", "--config", cfg, "--json")
	var r doctorReport
	decodeJSON(t, ta.out.String(), &r)
	if c := checkOf(&r, "fluent_bit"); c.Status != "warn" || !strings.Contains(c.Detail, "shipper.unsafe_config") {
		t.Fatalf("memory-buffered Fluent Bit not flagged: %+v", c)
	}
}

func TestFluentBitConfigShippedIsSafe(t *testing.T) {
	cfg, data := testConfig(t, "")
	dir := filepath.Join(t.TempDir(), "fb")
	ta := newTestApp(t)
	ta.mustRun(t, exitOK, "export", "fluent-bit", "--config", cfg, "--out", dir)
	secs, err := readFluentBitConfig(filepath.Join(dir, "hawkbell.yaml"), 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range checkFluentBitConfig(secs, filepath.Join(data, "outbox")) {
		t.Errorf("shipped configuration flagged: %+v", f)
	}
}

func TestFluentBitConfigUnsafe(t *testing.T) {
	dir := t.TempDir()
	classic := filepath.Join(dir, "fluent-bit.conf")
	writeTestFile(t, classic, `[SERVICE]
    Flush 1

@INCLUDE outputs.conf

[INPUT]
    Name tail
    Path /var/lib/hawkbell/outbox/*.ndjson
    Tag  hawkbell.*
`, 0o644)
	writeTestFile(t, filepath.Join(dir, "outputs.conf"), "[OUTPUT]\n    Name  http\n    Match *\n    Retry_Limit 5\n", 0o644)
	secs, err := readFluentBitConfig(classic, 0)
	if err != nil {
		t.Fatal(err)
	}
	var details []string
	for _, f := range checkFluentBitConfig(secs, "/var/lib/hawkbell/outbox") {
		details = append(details, f.Detail)
		if f.Code != "shipper.unsafe_config" || f.Status != "warn" {
			t.Errorf("finding %+v", f)
		}
	}
	// Memory buffering, no storage.path, no db, bounded retries.
	all := strings.Join(details, "\n")
	for _, want := range []string{"memory-buffered", "storage.path", "no db", "retry_limit 5"} {
		if !strings.Contains(all, want) {
			t.Errorf("no finding about %q in:\n%s", want, all)
		}
	}
	// Include loops are bounded.
	loop := filepath.Join(dir, "loop.yaml")
	writeTestFile(t, loop, "includes:\n  - loop.yaml\n", 0o644)
	if _, err := readFluentBitConfig(loop, 0); err == nil {
		t.Fatal("include loop not refused")
	}
}

// The "disabled" file next to --config stops only the hooks that read that
// configuration (internal/hookcmd); the daemon honours the system file
// alone. Doctor must not claim the collectors idle when the daemon's own
// snapshot says the switch is not engaged.
func TestDoctorKillSwitchScope(t *testing.T) {
	cfg, _ := testConfig(t, "")
	writeTestFile(t, filepath.Join(filepath.Dir(cfg), "disabled"), "", 0o644)
	ta := newTestApp(t)
	ta.run("doctor", "--config", cfg, "--json")
	var raw struct {
		KillSwitch killSwitchView `json:"kill_switch"`
		Checks     []check        `json:"checks"`
		Daemon     struct {
			KillSwitch struct {
				Engaged bool `json:"engaged"`
			} `json:"kill_switch"`
		} `json:"daemon"`
	}
	decodeJSON(t, ta.out.String(), &raw)
	var ks check
	for _, c := range raw.Checks {
		if c.ID == "kill_switch" {
			ks = c
		}
	}
	if raw.Daemon.KillSwitch.Engaged {
		t.Skip("the system kill switch is engaged on this machine")
	}
	if !raw.KillSwitch.On || raw.KillSwitch.Scope != "hooks" || ks.Status != "warn" {
		t.Fatalf("hook-only kill switch: %+v %+v", raw.KillSwitch, ks)
	}
	if strings.Contains(ks.Summary, "collectors idle") || !strings.Contains(ks.Summary, "daemon keeps collecting") {
		t.Fatalf("doctor says %q but the daemon does not honour %s", ks.Summary, cfg)
	}
}

// layoutWith creates the data layout with the given modes ("" is the data
// directory itself) and an empty state.db.
func layoutWith(t *testing.T, data string, modes map[string]os.FileMode, dbMode os.FileMode) {
	t.Helper()
	for name, mode := range modes {
		p := filepath.Join(data, name)
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
	}
	writeTestFile(t, filepath.Join(data, "state.db"), "", dbMode)
	if err := os.Chmod(filepath.Join(data, "state.db"), dbMode); err != nil {
		t.Fatal(err)
	}
}

// doctor judges the layout by the daemon's own table: record directories
// readable by every account, and world-writable directories (sticky or
// not), fail; the daemon's exact layout passes.
func TestDoctorDirsAgainstDaemonModes(t *testing.T) {
	if !permsChecked {
		t.Skip("POSIX modes")
	}
	good := map[string]os.FileMode{"": 0o711, "outbox": 0o750 | os.ModeSetgid, "local": 0o700, "spool": 0o711, "bundle": 0o755, "checkpoints": 0o700}
	for _, tc := range []struct {
		name   string
		change map[string]os.FileMode
		db     os.FileMode
		want   string
		detail string
	}{
		{"daemon layout", nil, 0o600, "ok", ""},
		{"world-readable records", map[string]os.FileMode{"outbox": 0o755, "local": 0o755, "checkpoints": 0o755, "bundle": 0o755}, 0o644, "fail", "open to every account"},
		{"sticky world-writable data and spool", map[string]os.FileMode{"": 0o777 | os.ModeSticky, "spool": 0o777 | os.ModeSticky}, 0o600, "fail", "writable by every account"},
		{"group-writable outbox", map[string]os.FileMode{"outbox": 0o770 | os.ModeSetgid}, 0o600, "fail", "writable by its group"},
		{"outbox without setgid", map[string]os.FileMode{"outbox": 0o750}, 0o600, "warn", "want 2750"},
		{"data 0755", map[string]os.FileMode{"": 0o755}, 0o600, "ok", ""},
		{"data not traversable", map[string]os.FileMode{"": 0o700}, 0o600, "warn", "not traversable"},
		{"state.db group-readable", nil, 0o640, "warn", "state.db"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, data := testConfig(t, "")
			modes := map[string]os.FileMode{}
			for k, v := range good {
				modes[k] = v
			}
			for k, v := range tc.change {
				modes[k] = v
			}
			layoutWith(t, data, modes, tc.db)
			ta := newTestApp(t)
			ta.run("doctor", "--config", cfg, "--json")
			var r doctorReport
			decodeJSON(t, ta.out.String(), &r)
			c := checkOf(&r, "dirs")
			if c.Status != tc.want || !strings.Contains(c.Detail, tc.detail) {
				t.Fatalf("dirs check %q (%s)\n%s\nwant %q containing %q", c.Status, c.Summary, c.Detail, tc.want, tc.detail)
			}
		})
	}
}

// A segment of the local ring readable by every account fails even inside
// a correctly protected directory.
func TestDoctorDirsExposedFiles(t *testing.T) {
	if !permsChecked {
		t.Skip("POSIX modes")
	}
	cfg, data := testConfig(t, "")
	layoutWith(t, data, map[string]os.FileMode{"": 0o711, "outbox": 0o750 | os.ModeSetgid, "local": 0o700, "spool": 0o711, "bundle": 0o755, "checkpoints": 0o700}, 0o600)
	seg := filepath.Join(data, "local", "activity-20261110-09-0000.ndjson")
	writeTestFile(t, seg, nativeLine(t, "alice", "1001", "psql -U admin", 0), 0o644)
	os.Chmod(seg, 0o644)
	ta := newTestApp(t)
	ta.run("doctor", "--config", cfg, "--json")
	var r doctorReport
	decodeJSON(t, ta.out.String(), &r)
	if c := checkOf(&r, "dirs"); c.Status != "fail" || !strings.Contains(c.Detail, "activity-20261110-09-0000.ndjson") {
		t.Fatalf("world-readable local segment: %+v", c)
	}
}
