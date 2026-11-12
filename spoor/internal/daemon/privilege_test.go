package daemon

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

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
	t.Setenv("ProgramFiles", `C:\Program Files`)
	if got := selfExePaths("", "windows"); len(got) != 1 || filepath.Base(filepath.Dir(got[0])) != "spoor" {
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
	for _, k := range []string{"procs_total", "procs_unreadable", "procmon.self_excluded"} {
		if _, ok := c[k]; !ok {
			t.Errorf("heartbeat counter %s missing: %v", k, c)
		}
	}
	if c["procs_total"] == 0 || c["procs_unreadable"] > c["procs_total"] {
		t.Errorf("procs_total %d procs_unreadable %d", c["procs_total"], c["procs_unreadable"])
	}
}
