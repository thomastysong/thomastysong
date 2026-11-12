//go:build linux

package platform

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func findProc(procs []Proc, pid int) (Proc, bool) {
	for _, p := range procs {
		if p.PID == pid {
			return p, true
		}
	}
	return Proc{}, false
}

func TestProcessesFindsSelf(t *testing.T) {
	procs, err := Processes()
	if err != nil {
		t.Fatal(err)
	}
	self, ok := findProc(procs, os.Getpid())
	if !ok {
		t.Fatalf("own pid %d not among %d processes", os.Getpid(), len(procs))
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if want, _ := filepath.EvalSymlinks(exe); self.Exe != want {
		t.Errorf("Exe = %q, want %q", self.Exe, want)
	}
	if !reflect.DeepEqual(self.Args, os.Args) {
		t.Errorf("Args = %q, want %q", self.Args, os.Args)
	}
	if self.PPID != os.Getppid() {
		t.Errorf("PPID = %d, want %d", self.PPID, os.Getppid())
	}
	if self.UID != strconv.Itoa(os.Getuid()) {
		t.Errorf("UID = %q, want %d", self.UID, os.Getuid())
	}
	if cur := CurrentUser(); cur.Name != "" && self.User != cur.Name {
		t.Errorf("User = %q, want %q", self.User, cur.Name)
	}
	if !strings.HasPrefix(filepath.Base(exe), self.Name) && self.Name != filepath.Base(exe) {
		t.Errorf("Name = %q does not match executable %q", self.Name, filepath.Base(exe))
	}
	// The test binary started moments ago.
	if age := time.Since(self.Start); age < -2*time.Second || age > time.Hour {
		t.Errorf("Start = %v (age %v), want a few seconds ago", self.Start, age)
	}
	for i := 1; i < len(procs); i++ {
		if procs[i-1].PID >= procs[i].PID {
			t.Fatalf("not sorted by pid at %d", i)
		}
	}
	// pid 1 always exists and is its own root.
	if init, ok := findProc(procs, 1); !ok || init.PPID != 0 {
		t.Errorf("pid 1: %+v found=%v", init, ok)
	}
}

func TestChildProcessEnvCWDAndLifecycle(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cmd := startHelper(t, dir, "CLAUDE_CODE_SESSION_ID=sess-0199-test", "SPOOR_EMPTY=", "SPOOR_EQ=a=b=c")
	pid := cmd.Process.Pid

	p, err := ProcessByPID(pid)
	if err != nil {
		t.Fatal(err)
	}
	if p.PPID != os.Getpid() {
		t.Errorf("child PPID = %d, want %d", p.PPID, os.Getpid())
	}
	if want := []string{cmd.Path, "-test.run=^$", "helper-arg", "second arg"}; !reflect.DeepEqual(p.Args, want) {
		t.Errorf("child Args = %q, want %q", p.Args, want)
	}
	if want, _ := filepath.EvalSymlinks(cmd.Path); p.Exe != want {
		t.Errorf("child Exe = %q, want %q", p.Exe, want)
	}
	procs, err := Processes()
	if err != nil {
		t.Fatal(err)
	}
	listed, ok := findProc(procs, pid)
	if !ok {
		t.Fatal("child missing from Processes()")
	}
	// Start is the identity callers use to detect pid reuse: it must be the
	// same from every read.
	if !listed.Start.Equal(p.Start) || p.Start.IsZero() {
		t.Errorf("Start differs between reads: %v vs %v", listed.Start, p.Start)
	}

	env, err := ProcEnv(pid)
	if err != nil {
		t.Fatal(err)
	}
	if env["CLAUDE_CODE_SESSION_ID"] != "sess-0199-test" {
		t.Errorf("marker = %q", env["CLAUDE_CODE_SESSION_ID"])
	}
	if v, ok := env["SPOOR_EMPTY"]; !ok || v != "" {
		t.Errorf("empty variable: %q present=%v", v, ok)
	}
	if env["SPOOR_EQ"] != "a=b=c" {
		t.Errorf("value with '=': %q", env["SPOOR_EQ"])
	}
	if env[helperEnv] != "1" {
		t.Errorf("helper marker missing")
	}

	cwd, err := ProcCWD(pid)
	if err != nil {
		t.Fatal(err)
	}
	if cwd != dir {
		t.Errorf("ProcCWD = %q, want %q", cwd, dir)
	}

	// A working directory deleted under the process still resolves to its path.
	if err := os.Remove(dir); err == nil {
		if cwd, err := ProcCWD(pid); err != nil || cwd != dir {
			t.Errorf("deleted cwd: %q %v, want %q", cwd, err, dir)
		}
	}

	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	if _, err := ProcessByPID(pid); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("after exit ProcessByPID err = %v, want ErrNotExist", err)
	}
	if _, err := ProcEnv(pid); err == nil {
		t.Error("after exit ProcEnv succeeded")
	}
	if _, err := ProcCWD(pid); err == nil {
		t.Error("after exit ProcCWD succeeded")
	}
}

// TestUnprivilegedView re-runs the test binary as "nobody" and checks what
// the package claims about running without privilege: no other user's
// environment, working directory or executable path, and no other homes.
func TestUnprivilegedView(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to switch to an unprivileged account")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// The test binary sits in a root-only build directory. Handing the
	// child an open descriptor and executing /proc/self/fd/3 sidesteps the
	// directory permissions without copying or chmodding anything.
	bin, err := os.Open(exe)
	if err != nil {
		t.Fatal(err)
	}
	defer bin.Close()
	const nobody = 65534
	cmd := exec.Command("/proc/self/fd/3")
	cmd.ExtraFiles = []*os.File{bin}
	cmd.Dir = "/"
	cmd.Env = []string{helperEnv + "=report", "HOME=/tmp", "PATH=/usr/bin:/bin"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: nobody, Gid: nobody}}
	out, err := cmd.Output()
	if err != nil {
		t.Skipf("cannot run as uid %d here: %v", nobody, err)
	}
	var r unprivReport
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatalf("helper output %q: %v", out, err)
	}
	t.Logf("as nobody: %+v", r)
	if r.Privileged {
		t.Error("IsPrivileged() true for nobody")
	}
	if r.Current.UID != "65534" {
		t.Errorf("CurrentUser = %+v", r.Current)
	}
	// Only its own account, with the home the environment names (nobody's
	// registered home does not exist).
	if r.UsersErr != "" || len(r.Users) != 1 || r.Users[0].UID != "65534" || r.Users[0].Home != "/tmp" {
		t.Errorf("Users = %+v err %q, want only uid 65534 at /tmp", r.Users, r.UsersErr)
	}
	// The root-owned parent is visible, with public fields filled and the
	// protected ones left empty rather than failing the scan.
	if !r.ParentFound {
		t.Fatal("parent process not listed")
	}
	if r.Parent.PID != os.Getpid() || r.Parent.UID != "0" || len(r.Parent.Args) == 0 || r.Parent.Name == "" || r.Parent.Start.IsZero() {
		t.Errorf("parent as seen by nobody: %+v", r.Parent)
	}
	if r.Parent.Exe != "" {
		t.Errorf("another user's executable path was readable: %q", r.Parent.Exe)
	}
	if !r.ParentEnvPerm {
		t.Errorf("ProcEnv of a root process: %q, want a permission error", r.ParentEnvErr)
	}
	if !r.ParentCWDPerm {
		t.Errorf("ProcCWD of a root process: %q, want a permission error", r.ParentCWDErr)
	}
	// Its own process stays fully readable.
	if r.SelfEnvMarker != "report" || r.SelfCWD != "/" {
		t.Errorf("own process: marker %q cwd %q", r.SelfEnvMarker, r.SelfCWD)
	}
	// DMI is root-only, so an unprivileged process never reports it.
	if r.HostIDSource == HostIDSourceDMI {
		t.Errorf("unprivileged process read the DMI UUID")
	}
}

func TestProcEnvSelf(t *testing.T) {
	env, err := ProcEnv(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	// /proc shows the environment at exec time; PATH is not changed by the
	// test harness after start.
	if want := os.Getenv("PATH"); want != "" && env["PATH"] != want {
		t.Errorf("PATH = %q, want %q", env["PATH"], want)
	}
	cwd, err := ProcCWD(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if want, _ := os.Getwd(); cwd != want {
		t.Errorf("ProcCWD(self) = %q, want %q", cwd, want)
	}
}

func TestProcInvalidPIDs(t *testing.T) {
	for _, pid := range []int{0, -1, -1 << 31, 1<<31 - 1} {
		if _, err := ProcEnv(pid); err == nil {
			t.Errorf("ProcEnv(%d) succeeded", pid)
		}
		if _, err := ProcCWD(pid); err == nil {
			t.Errorf("ProcCWD(%d) succeeded", pid)
		}
		if _, err := ProcessByPID(pid); err == nil {
			t.Errorf("ProcessByPID(%d) succeeded", pid)
		}
	}
}

// fakeProc writes one /proc/<pid> directory into a fixture tree.
func fakeProc(t *testing.T, root string, pid int, files map[string][]byte, links map[string]string) {
	t.Helper()
	dir := filepath.Join(root, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
}

func withProcRoot(t *testing.T, root string) {
	t.Helper()
	clock() // read the real boot time before the root moves
	old := procRoot
	procRoot = root
	t.Cleanup(func() { procRoot = old })
}

const statTail = " S 1 100 100 0 -1 4194304 500 0 0 0 10 5 0 0 20 0 3 0 250 1 1\n"

func TestProcessesOnHostileFixtureTree(t *testing.T) {
	root := t.TempDir()
	withProcRoot(t, root)

	// 10: a well-formed agent process whose binary was replaced by an update.
	fakeProc(t, root, 10, map[string][]byte{
		"stat":    []byte("10 (claude)" + statTail),
		"cmdline": []byte("claude\x00--dangerously-skip-permissions\x00"),
		"status":  []byte("Name:\tclaude\nUid:\t4242\t0\t0\t0\n"),
		"environ": []byte("CLAUDECODE=1\x00HOME=/home/a\x00"),
	}, map[string]string{"exe": "/home/a/.local/share/claude/versions/2.1.100 (deleted)", "cwd": "/home/a/repo"})
	// 11: a name built to forge the fields after it, raw bytes in arguments.
	fakeProc(t, root, 11, map[string][]byte{
		"stat":    []byte("11 (evil) S 999 (x)" + statTail),
		"cmdline": []byte("a\xff\xfe\x00\n\x1b[2J\x00"),
		"status":  []byte("Name:\tevil\nUid:\tnot-a-number\n"),
	}, nil)
	// 12: a command line far past the cap, with no status and no exe.
	fakeProc(t, root, 12, map[string][]byte{
		"stat":    []byte("12 (big)" + statTail),
		"cmdline": bytes.Repeat([]byte("A"), maxCmdlineBytes*2),
	}, nil)
	// 13: truncated name that argv[0] completes.
	fakeProc(t, root, 13, map[string][]byte{
		"stat":    []byte("13 (github-copilot-)" + statTail),
		"cmdline": []byte("/usr/bin/github-copilot-cli\x00"),
	}, nil)
	// 14: stat is garbage: the process is skipped, not an error.
	fakeProc(t, root, 14, map[string][]byte{"stat": []byte("garbage")}, nil)
	// 15: a directory with no stat at all (exited between readdir and open).
	fakeProc(t, root, 15, nil, nil)
	// Non-pid entries are ignored.
	for _, name := range []string{"self", "sys", "0", "-3", "12abc", "99999999999"} {
		if err := os.MkdirAll(filepath.Join(root, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "16"), []byte("a file named like a pid"), 0o644); err != nil {
		t.Fatal(err)
	}

	procs, err := Processes()
	if err != nil {
		t.Fatal(err)
	}
	var pids []int
	for _, p := range procs {
		pids = append(pids, p.PID)
	}
	if !reflect.DeepEqual(pids, []int{10, 11, 12, 13}) {
		t.Fatalf("pids = %v, want [10 11 12 13]", pids)
	}

	p10, p11, p12, p13 := procs[0], procs[1], procs[2], procs[3]
	if p10.Exe != "/home/a/.local/share/claude/versions/2.1.100" {
		t.Errorf("deleted marker not trimmed: %q", p10.Exe)
	}
	// Uid line is "real effective saved fs": the real uid is reported.
	if p10.UID != "4242" {
		t.Errorf("UID = %q, want the real uid 4242", p10.UID)
	}
	if !reflect.DeepEqual(p10.Args, []string{"claude", "--dangerously-skip-permissions"}) || p10.PPID != 1 {
		t.Errorf("p10 = %+v", p10)
	}
	if p11.Name != "evil) S 999 (x" || p11.PPID != 1 {
		t.Errorf("forged stat fields were believed: name %q ppid %d", p11.Name, p11.PPID)
	}
	if !reflect.DeepEqual(p11.Args, []string{"a\xff\xfe", "\n\x1b[2J"}) {
		t.Errorf("raw argument bytes changed: %q", p11.Args)
	}
	if p11.UID != "" || p11.User != "" {
		t.Errorf("malformed uid accepted: %q %q", p11.UID, p11.User)
	}
	if len(p12.Args) != 1 || len(p12.Args[0]) != maxCmdlineBytes {
		t.Errorf("command line not capped: %d args, first is %d bytes", len(p12.Args), len(p12.Args[0]))
	}
	if p12.Exe != "" || p12.UID != "" {
		t.Errorf("missing files must leave fields empty: %+v", Proc{Exe: p12.Exe, UID: p12.UID})
	}
	if p13.Name != "github-copilot-cli" {
		t.Errorf("truncated name not completed: %q", p13.Name)
	}

	env, err := ProcEnv(10)
	if err != nil || env["CLAUDECODE"] != "1" || env["HOME"] != "/home/a" {
		t.Errorf("ProcEnv fixture: %q %v", env, err)
	}
	if cwd, err := ProcCWD(10); err != nil || cwd != "/home/a/repo" {
		t.Errorf("ProcCWD fixture: %q %v", cwd, err)
	}
	if _, err := ProcEnv(12); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing environ: %v", err)
	}
	if _, err := ProcessByPID(14); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("garbage stat: %v", err)
	}
}

func TestProcEnvIsCapped(t *testing.T) {
	root := t.TempDir()
	withProcRoot(t, root)
	var env bytes.Buffer
	env.WriteString("FIRST=1\x00")
	// One value that straddles the cap, then a variable past it.
	env.WriteString("BIG=")
	env.Write(bytes.Repeat([]byte("x"), maxEnvBytes))
	env.WriteString("\x00AFTER=1\x00")
	fakeProc(t, root, 20, map[string][]byte{"environ": env.Bytes()}, nil)
	got, err := ProcEnv(20)
	if err != nil {
		t.Fatal(err)
	}
	if got["FIRST"] != "1" {
		t.Errorf("FIRST lost")
	}
	if _, ok := got["BIG"]; ok {
		t.Error("a value cut at the read limit was reported")
	}
	if _, ok := got["AFTER"]; ok {
		t.Error("read past the cap")
	}
}

func TestReadProcDoesNotFollowLinksOutOfProcDir(t *testing.T) {
	root := t.TempDir()
	withProcRoot(t, root)
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("claude\x00--from-outside\x00"), 0o644); err != nil {
		t.Fatal(err)
	}
	// In a fixture (or a hostile bind mount over /proc) the files could be
	// symlinks pointing elsewhere; the directory handle refuses to leave.
	fakeProc(t, root, 30, map[string][]byte{"stat": []byte("30 (x)" + statTail)}, map[string]string{"cmdline": secret})
	p, err := ProcessByPID(30)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Args) != 0 {
		t.Errorf("followed a symlink out of the process directory: %q", p.Args)
	}
}

func TestLinuxClock(t *testing.T) {
	c := linuxClock{boot: 1_700_000_000, ticks: 100}
	if got := c.startTime(250); !got.Equal(time.Unix(1_700_000_002, 500_000_000)) {
		t.Errorf("startTime(250) = %v", got)
	}
	// Ten years of uptime in ticks must not overflow.
	ticks := uint64(10 * 365 * 24 * 3600 * 100)
	if got, want := c.startTime(ticks), time.Unix(1_700_000_000+10*365*24*3600, 0); !got.Equal(want) {
		t.Errorf("large uptime: %v, want %v", got, want)
	}
	if got := c.startTime(1 << 63); !got.IsZero() {
		t.Errorf("out-of-range ticks: %v", got)
	}
	if got := (linuxClock{ticks: 100}).startTime(5); !got.IsZero() {
		t.Errorf("unknown boot time must give zero Start, got %v", got)
	}
	real := readClock("/proc")
	if real.ticks != 100 {
		t.Logf("clock ticks = %d (unusual but legal)", real.ticks)
	}
	if real.boot <= 0 || time.Unix(real.boot, 0).After(time.Now()) {
		t.Errorf("boot time %d is not in the past", real.boot)
	}
	// A fixture root without auxv or stat falls back cleanly.
	if got := readClock(t.TempDir()); got.ticks != 100 || got.boot != 0 {
		t.Errorf("fallback clock = %+v", got)
	}
}

func TestClockFollowsWallClockSteps(t *testing.T) {
	root := t.TempDir()
	withProcRoot(t, root)
	oldMeasure := wallMinusBoot
	offset := 1000 * time.Hour
	wallMinusBoot = func() (time.Duration, bool) { return offset, true }
	clockState.Lock()
	saved := clockState.val
	savedRef, savedOK := clockState.ref, clockState.refOK
	clockState.loaded = false
	clockState.Unlock()
	t.Cleanup(func() {
		wallMinusBoot = oldMeasure
		clockState.Lock()
		clockState.val, clockState.ref, clockState.refOK, clockState.loaded = saved, savedRef, savedOK, true
		clockState.Unlock()
	})
	setBoot := func(sec int64) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, "stat"), []byte("cpu 1 2 3\nbtime "+strconv.FormatInt(sec, 10)+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	fakeProc(t, root, 40, map[string][]byte{"stat": []byte("40 (x)" + statTail)}, nil)
	start := func() time.Time {
		t.Helper()
		p, err := ProcessByPID(40)
		if err != nil {
			t.Fatal(err)
		}
		return p.Start
	}

	// The sensor starts while the clock is three hours behind.
	setBoot(1_700_000_000)
	first := start()
	if want := time.Unix(1_700_000_002, 500_000_000); !first.Equal(want) {
		t.Fatalf("Start = %v, want %v", first, want)
	}
	// Slewing and sub-threshold corrections do not move Start, even if the
	// kernel's btime ticks over by a second.
	setBoot(1_700_000_001)
	offset += 1500 * time.Millisecond
	if got := start(); !got.Equal(first) {
		t.Errorf("Start moved on a %v adjustment: %v", 1500*time.Millisecond, got)
	}
	// NTP steps the clock by three hours: Start follows, once.
	setBoot(1_700_000_000 + 3*3600)
	offset += 3 * time.Hour
	stepped := start()
	if want := first.Add(3 * time.Hour); !stepped.Equal(want) {
		t.Errorf("after a 3h step Start = %v, want %v", stepped, want)
	}
	if got := start(); !got.Equal(stepped) {
		t.Errorf("Start not stable after the step: %v", got)
	}
	// A step backwards is followed too.
	setBoot(1_700_000_000)
	offset -= 3 * time.Hour
	if got := start(); !got.Equal(first) {
		t.Errorf("after stepping back Start = %v, want %v", got, first)
	}
	// If the clocks cannot be measured, the first reading simply stays.
	wallMinusBoot = func() (time.Duration, bool) { return 0, false }
	setBoot(1_800_000_000)
	if got := start(); !got.Equal(first) {
		t.Errorf("Start moved without a measurement: %v", got)
	}
}
