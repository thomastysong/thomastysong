//go:build linux

package procmon

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/thomastysong/spoor/internal/event"
)

// TestE2EOsqueryProvider runs a private osqueryd with the Linux audit
// publisher and checks that the monitor uses it as its exec provider when
// the process connector is off: short-lived children of an agent arrive as
// osquery-sourced process.exec events attributed to the agent, and the exec
// self-test passes through osquery.
//
// Gated by SPOOR_E2E_OSQUERY=1 (root needed; only one process may own the
// audit netlink socket, so auditd or another audit-enabled osqueryd makes
// this test fail at the "osquery delivering" step). SPOOR_OSQUERYD names the
// osqueryd binary.
func TestE2EOsqueryProvider(t *testing.T) {
	if os.Getenv("SPOOR_E2E_OSQUERY") != "1" {
		t.Skip("set SPOOR_E2E_OSQUERY=1 to run against a private osqueryd")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	bin := os.Getenv("SPOOR_OSQUERYD")
	if bin == "" {
		bin = "/opt/spoor-test/osquery/opt/osquery/bin/osqueryd"
	}
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("no osqueryd: %v", err)
	}
	dir := t.TempDir()
	sock := filepath.Join(dir, "o.em")
	conf := filepath.Join(dir, "osq.conf")
	if err := os.WriteFile(conf, []byte(`{"options":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "logs"), 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin,
		"--config_plugin=filesystem", "--config_path="+conf,
		"--logger_plugin=filesystem", "--logger_path="+filepath.Join(dir, "logs"),
		"--database_path="+filepath.Join(dir, "db"), "--pidfile="+filepath.Join(dir, "osqueryd.pid"),
		"--extensions_socket="+sock, "--disable_extensions=false",
		"--disable_events=false", "--disable_audit=false",
		"--audit_allow_process_events=true", "--audit_allow_config=true",
		"--disable_watchdog=true", "--force=true",
		"--host_identifier=specified", "--specified_identifier=procmon-e2e",
		"--events_expiry=60")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	logf, err := os.Create(filepath.Join(dir, "osqueryd.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer logf.Close()
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer killGroup(cmd)
	waitFor(t, 30*time.Second, "the osquery extension socket", func() bool {
		_, err := os.Stat(sock)
		return err == nil
	})

	m, c := startMonitor(t, Options{OsquerySocket: sock, OsqueryInterval: 2 * time.Second, Idle: time.Second}, func(m *Monitor) {
		m.rate, m.burst = 1e6, 1e6
		m.canaryFirst = time.Second
	})
	// osquery reads as unavailable until its publisher has delivered a row;
	// any exec on the host gets it there.
	waitFor(t, 90*time.Second, "osquery to deliver", func() bool {
		_ = exec.Command("/bin/true").Run()
		return m.Source() == SourceOsquery
	})
	const n = 20
	script := writeAgentScript(t, `i=1
while [ $i -le `+strconv.Itoa(n)+` ]; do
  sh -c ": spoor-osq-$i; sleep 0.05; :"
  i=$((i+1))
done
sleep 40`)
	agent := exec.Command(script)
	agent.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := agent.Start(); err != nil {
		t.Fatal(err)
	}
	defer killGroup(agent)
	root := agent.Process.Pid
	re := regexp.MustCompile(`spoor-osq-(\d+)`)
	count := func() int {
		seen := map[string]bool{}
		for _, e := range c.all() {
			if e.Type != event.TypeProcessExec || e.Source != event.SourceOsquery || e.Agent == nil || e.Agent.ID != "codex" {
				continue
			}
			if mt := re.FindStringSubmatch(strings.Join(e.Process.Args, " ")); mt != nil {
				seen[mt[1]] = true
			}
		}
		return len(seen)
	}
	deadline := time.Now().Add(60 * time.Second)
	for count() < n && time.Now().Before(deadline) {
		time.Sleep(500 * time.Millisecond)
	}
	got := count()
	t.Logf("osquery delivered %d of %d short-lived children of agent pid %d; stats %+v", got, n, root, m.Stats())
	if got < n*9/10 {
		t.Fatalf("osquery provider attributed only %d of %d children", got, n)
	}
	waitFor(t, 120*time.Second, "the exec self-test through osquery", m.ExecHealthy)
}
