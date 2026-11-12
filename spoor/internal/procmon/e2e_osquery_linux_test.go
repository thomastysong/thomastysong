//go:build linux

package procmon

import (
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

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
	// Only one process may own the audit netlink socket (auditd, another
	// osqueryd, go-audit ...). Taking it over would break that process, so
	// the test steps aside.
	enabled, owner, err := auditStatus()
	if err != nil {
		t.Skipf("kernel audit unavailable: %v", err)
	}
	if owner != 0 {
		if _, err := os.Stat("/proc/" + strconv.Itoa(owner)); err == nil {
			t.Skipf("the audit netlink socket is owned by pid %d", owner)
		}
	}
	t.Logf("audit before the test: enabled=%d owner=%d", enabled, owner)
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
	// SIGTERM, not SIGKILL: osquery's audit reader removes the rules it
	// installed and switches auditing off again only on a clean shutdown;
	// a killed osqueryd leaves every exec on the host audited.
	defer func() {
		stopGracefully(cmd, 30*time.Second)
		if en, own, err := auditStatus(); err == nil {
			t.Logf("audit after the test: enabled=%d owner=%d", en, own)
		}
	}()
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

// stopGracefully sends SIGTERM to the process, waits for it, and kills its
// process group only if it does not exit in time.
func stopGracefully(cmd *exec.Cmd, wait time.Duration) {
	if cmd.Process == nil {
		return
	}
	pid := cmd.Process.Pid
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	_ = cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-done:
	case <-time.After(wait):
		_ = syscall.Kill(-pid, syscall.SIGKILL)
		<-done
	}
	_ = syscall.Kill(-pid, syscall.SIGKILL) // stragglers in the group
}

// auditStatus reads the kernel audit status (AUDIT_GET): whether auditing
// is enabled and which pid owns the audit netlink socket (0 for none). It
// only reads.
func auditStatus() (enabled, owner int, err error) {
	const auditGet = 1000
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_AUDIT)
	if err != nil {
		return 0, 0, err
	}
	defer unix.Close(fd)
	tv := unix.NsecToTimeval(int64(2 * time.Second))
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return 0, 0, err
	}
	ne := binary.NativeEndian
	req := make([]byte, nlmsgHdrLen)
	ne.PutUint32(req[0:4], nlmsgHdrLen)
	ne.PutUint16(req[4:6], auditGet)
	ne.PutUint16(req[6:8], unix.NLM_F_REQUEST)
	ne.PutUint32(req[8:12], 1)
	if err := unix.Sendto(fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return 0, 0, err
	}
	buf := make([]byte, 8192)
	for i := 0; i < 8; i++ {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			return 0, 0, err
		}
		if n < nlmsgHdrLen+16 {
			continue
		}
		switch ne.Uint16(buf[4:6]) {
		case auditGet:
			// struct audit_status: mask, enabled, failure, pid, ...
			p := buf[nlmsgHdrLen:n]
			return int(ne.Uint32(p[4:8])), int(ne.Uint32(p[12:16])), nil
		case unix.NLMSG_ERROR:
			if e := int32(ne.Uint32(buf[16:20])); e != 0 {
				return 0, 0, unix.Errno(-e)
			}
		}
	}
	return 0, 0, errors.New("no audit status reply")
}
