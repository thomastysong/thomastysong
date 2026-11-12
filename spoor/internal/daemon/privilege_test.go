package daemon

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/thomastysong/spoor/internal/engine"
	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/platform"
	"github.com/thomastysong/spoor/internal/procmon"
)

// TestCapabilityOnlySensor: the Kubernetes node sensor runs as uid 65532
// with CAP_DAC_READ_SEARCH and CAP_SYS_PTRACE (privileged for reading, not
// root). It follows every account, and it does not try to make other
// accounts' spool directories, which needs chown (it would fail and warn
// every minute).
func TestCapabilityOnlySensor(t *testing.T) {
	f := newFixture(t)
	bob := platform.UserHome{Name: "bob", UID: "4242", Home: filepath.Join(f.root, "home", "bob")}
	mustMkdir(t, bob.Home, 0o755)
	env := f.env()
	env.users = func() ([]platform.UserHome, error) { return []platform.UserHome{f.user, bob}, nil }
	env.privileged, env.admin = true, false
	d, err := newDaemon(f.cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), env)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = d.pipe.Close()
		_ = d.closeStores()
	}()
	if got := len(d.users.all()); got != 2 {
		t.Errorf("a capability-holding sensor follows %d accounts, want every account (2)", got)
	}
	if _, err := os.Lstat(filepath.Join(f.cfg.SpoolDir(), f.user.UID)); err != nil {
		t.Errorf("own spool directory: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(f.cfg.SpoolDir(), bob.UID)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("another account's spool directory was made without root: %v", err)
	}
	if n := d.board.get("spool.dir_errors"); n != 0 {
		t.Errorf("spool.dir_errors = %d", n)
	}
	// The process's own answer agrees with what the daemon is told.
	if real := defaultEnv(); real.admin && !real.privileged {
		t.Error("platform says admin but not privileged")
	}
}

// TestHostNameFromEnvironment: in a pod the kernel's host name is the pod's
// name; SPOOR_HOST_NAME (the DaemonSet sets it from spec.nodeName) names
// the node on every record, like SPOOR_HOST_ID does for the id.
func TestHostNameFromEnvironment(t *testing.T) {
	t.Setenv(platform.EnvHostName, "node-a.example.internal")
	t.Setenv(platform.EnvHostID, "node-a")
	f := newFixture(t)
	env := f.env()
	env.host = defaultEnv().host
	d, err := newDaemon(f.cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), env)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = d.pipe.Close()
		_ = d.closeStores()
	}()
	if d.host.Name != "node-a.example.internal" || d.host.ID != "node-a" || d.hostIDSource != platform.HostIDSourceEnv {
		t.Errorf("host = %+v (%s)", d.host, d.hostIDSource)
	}
	t.Setenv(platform.EnvHostName, "pod name with spaces")
	if h, _ := defaultEnv().host(); h.Name == "pod name with spaces" {
		t.Error("an implausible host name was taken")
	}
}

// TestIdentityKeySharedWithMonitor: the daemon loads its persisted
// identity key once and gives it to the process monitor as well as the
// pipeline, so process.exec ids of live processes a restarted sensor
// reports again are the ids they had (and collapse downstream). A key
// file that cannot be used leaves the monitor on its per-process key and
// is reported by the pipeline.
func TestIdentityKeySharedWithMonitor(t *testing.T) {
	f := newFixture(t)
	on := true
	f.cfg.Sources.Processes.Enabled = &on // built, never run
	start := func() *daemon {
		t.Helper()
		d, err := newDaemon(f.cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), f.env())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = d.pipe.Close()
			_ = d.closeStores()
		})
		if d.mon == nil {
			t.Fatal("no process monitor")
		}
		return d
	}
	d := start()
	if !d.mon.Stats().StableIDs {
		t.Error("the monitor did not get the stored identity key")
	}
	d.refreshProcs()
	if d.board.get("procmon.stable_ids") != 1 {
		t.Error("procmon.stable_ids is not 1")
	}
	k1, err := engine.ReadIdentityKey(engine.IdentityKeyPath(f.cfg))
	if err != nil {
		t.Fatal(err)
	}
	start()
	if k2, err := engine.ReadIdentityKey(engine.IdentityKeyPath(f.cfg)); err != nil || !bytes.Equal(k1, k2) {
		t.Errorf("the key changed across a restart: %v", err)
	}
	if runtime.GOOS == "windows" {
		return
	}
	// A key file anyone may read is never used.
	if err := os.Chmod(engine.IdentityKeyPath(f.cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	d = start()
	if d.mon.Stats().StableIDs {
		t.Error("an unusable key file was given to the monitor")
	}
}

func TestSelfExePaths(t *testing.T) {
	if got := selfExePaths("", "linux"); !reflect.DeepEqual(got, []string{"/usr/bin/spoor", "/usr/local/bin/spoor"}) {
		t.Errorf("linux: %v", got)
	}
	if got := selfExePaths("", "darwin"); !reflect.DeepEqual(got, []string{"/usr/local/bin/spoor"}) {
		t.Errorf("darwin: %v", got)
	}
	want := []string{filepath.Join("/host", "/usr/bin/spoor"), filepath.Join("/host", "/usr/local/bin/spoor")}
	if got := selfExePaths("/host", "linux"); !reflect.DeepEqual(got, want) {
		t.Errorf("host root: %v", got)
	}
	pf := filepath.Join(t.TempDir(), "Program Files") // absolute on the build host
	t.Setenv("ProgramFiles", pf)
	if got := selfExePaths("", "windows"); len(got) != 1 || got[0] != filepath.Join(pf, "spoor", "spoor.exe") {
		t.Errorf("windows: %v", got)
	}
	t.Setenv("ProgramFiles", "relative")
	if got := selfExePaths("", "windows"); len(got) != 0 {
		t.Errorf("windows with a relative ProgramFiles: %v", got)
	}
}

// TestMonitorSurfaceUnreadable: processes the sensor may not look into
// make the processes surface degraded, after the reasons that explain more.
func TestMonitorSurfaceUnreadable(t *testing.T) {
	s := monitorSurface(procmon.Stats{Source: procmon.SourceCNProc, ExecHealthy: true, ProcsTotal: 200, ProcsUnreadable: 12})
	if s.Status != "degraded" || s.Reason != "procs_unreadable" {
		t.Errorf("surface = %+v", s)
	}
	s = monitorSurface(procmon.Stats{Source: procmon.SourcePoll, ProcsTotal: 200, ProcsUnreadable: 12})
	if s.Reason != "exec_source_poll" {
		t.Errorf("poll mode reason = %q", s.Reason)
	}
	s = monitorSurface(procmon.Stats{Source: procmon.SourceCNProc, ExecHealthy: true, ProcsTotal: 200})
	if s.Status != "ok" {
		t.Errorf("all readable: %+v", s)
	}
	// A privileged sensor refused only by protected processes (Windows
	// protected processes, this build host's sandboxed pid 1): ok.
	s = monitorSurface(procmon.Stats{Source: procmon.SourceCNProc, ExecHealthy: true, ProcsTotal: 200, ProcsUnreadable: 3, ProcsProtected: 3})
	if s.Status != "ok" {
		t.Errorf("only protected processes unreadable: %+v", s)
	}
	// One more, of another account: a privilege is missing.
	s = monitorSurface(procmon.Stats{Source: procmon.SourceCNProc, ExecHealthy: true, ProcsTotal: 200, ProcsUnreadable: 4, ProcsProtected: 3})
	if s.Status != "degraded" || s.Reason != "procs_unreadable" {
		t.Errorf("an unprotected process unreadable: %+v", s)
	}
	// hidepid=1 without the privilege: hidden processes are unreadable.
	s = monitorSurface(procmon.Stats{Source: procmon.SourceCNProc, ExecHealthy: true, ProcsTotal: 97, ProcsUnreadable: 96, ProcsHidden: 96})
	if s.Status != "degraded" || s.Reason != "procs_unreadable" {
		t.Errorf("hidepid: %+v", s)
	}
}

// TestProcReadabilityGauges: the monitor's readability counts and the count
// of spoor's own hook processes it left out reach the heartbeat counters.
func TestProcReadabilityGauges(t *testing.T) {
	f := newFixture(t)
	d, _ := f.unitDaemon()
	defer d.pipe.Close()
	d.mon = procmon.New(procmon.Options{NoOsquery: true, Idle: 20 * time.Millisecond, Emit: func(*event.Event) {}})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = d.mon.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	deadline := time.Now().Add(10 * time.Second)
	for d.mon.Stats().ProcsTotal == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no full scan within 10 s")
		}
		time.Sleep(10 * time.Millisecond)
	}
	d.refreshProcs()
	c := d.board.counters()
	for _, k := range []string{"procs_total", "procs_unreadable", "procs_hidden", "procs_protected", "procmon.self_excluded"} {
		if _, ok := c[k]; !ok {
			t.Errorf("heartbeat counter %s missing: %v", k, c)
		}
	}
	if c["procs_total"] == 0 || c["procs_unreadable"] > c["procs_total"] ||
		c["procs_hidden"] > c["procs_unreadable"] || c["procs_protected"] > c["procs_unreadable"] {
		t.Errorf("procs_total %d procs_unreadable %d procs_hidden %d procs_protected %d",
			c["procs_total"], c["procs_unreadable"], c["procs_hidden"], c["procs_protected"])
	}
}
