package platform

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"testing"
)

// helperEnv turns the test binary into a child process that idles until its
// stdin closes. Tests that need a real process with a known environment and
// working directory re-exec themselves instead of depending on /bin/sleep.
// When helperSockEnv is set the child first connects to that unix socket and
// keeps the connection open, so a test can ask for a real peer's credentials.
const (
	helperEnv     = "HAWKBELL_PLATFORM_TEST_HELPER"
	helperSockEnv = "HAWKBELL_PLATFORM_TEST_SOCK"
)

// unprivReport is what the helper prints in "report" mode: the package's
// view of the system from whatever account the helper was started as.
type unprivReport struct {
	Privileged    bool
	Current       UserHome
	Users         []UserHome
	UsersErr      string
	Parent        Proc
	ParentFound   bool
	ParentEnvErr  string
	ParentEnvPerm bool
	ParentCWDErr  string
	ParentCWDPerm bool
	SelfEnvMarker string
	SelfCWD       string
	HostIDSource  string
	ContainerID   string
	Runtime       string
	PodUID        string
	// CapEff is the helper's own effective capability set as the kernel
	// reports it ("" when unreadable), so a test can tell "file
	// capabilities were not honoured here" from a wrong answer.
	CapEff  string
	IsAdmin bool
}

func runReportHelper() {
	var r unprivReport
	r.Privileged = IsPrivileged()
	r.Current = CurrentUser()
	users, err := Users()
	r.Users = users
	if err != nil {
		r.UsersErr = err.Error()
	}
	if procs, err := Processes(); err == nil {
		for _, p := range procs {
			if p.PID == os.Getppid() {
				r.Parent, r.ParentFound = p, true
			}
		}
	}
	if _, err := ProcEnv(os.Getppid()); err != nil {
		r.ParentEnvErr, r.ParentEnvPerm = err.Error(), errors.Is(err, os.ErrPermission)
	}
	if _, err := ProcCWD(os.Getppid()); err != nil {
		r.ParentCWDErr, r.ParentCWDPerm = err.Error(), errors.Is(err, os.ErrPermission)
	}
	if env, err := ProcEnv(os.Getpid()); err == nil {
		r.SelfEnvMarker = env[helperEnv]
	}
	r.SelfCWD, _ = ProcCWD(os.Getpid())
	r.HostIDSource = HostIDSource()
	r.ContainerID, r.Runtime = ContainerOf(os.Getpid())
	r.PodUID = PodOf(os.Getpid())
	r.IsAdmin = IsAdmin()
	if b, err := os.ReadFile("/proc/self/status"); err == nil {
		if eff, ok := parseCapEff(b); ok {
			r.CapEff = fmt.Sprintf("%016x", eff)
		}
	}
	_ = json.NewEncoder(os.Stdout).Encode(r)
}

func TestMain(m *testing.M) {
	if os.Getenv(helperEnv) == "report" {
		runReportHelper()
		os.Exit(0)
	}
	if os.Getenv(helperEnv) != "" {
		if sock := os.Getenv(helperSockEnv); sock != "" {
			c, err := net.Dial("unix", sock)
			if err != nil {
				fmt.Println("error")
				os.Exit(1)
			}
			defer c.Close()
		}
		fmt.Println("ready")
		_, _ = io.Copy(io.Discard, os.Stdin)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// startHelper launches the helper with extra environment entries and the
// given working directory. It returns once the child is running its Go code,
// so /proc already shows the final executable, arguments and environment.
func startHelper(t *testing.T, dir string, env ...string) *exec.Cmd {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^$", "helper-arg", "second arg")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), helperEnv+"=1")
	cmd.Env = append(cmd.Env, env...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stdin.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	buf := make([]byte, 6)
	if _, err := io.ReadFull(stdout, buf); err != nil || string(buf) != "ready\n" {
		t.Fatalf("helper did not start: %q %v", buf, err)
	}
	return cmd
}
