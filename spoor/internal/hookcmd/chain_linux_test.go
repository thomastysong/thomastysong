package hookcmd

import (
	"os"
	"testing"

	"github.com/thomastysong/spoor/internal/platform"
)

// The fast ancestor walk must agree with the platform's process table.
func TestProcStatMatchesPlatform(t *testing.T) {
	for _, pid := range []int{os.Getpid(), os.Getppid(), 1} {
		name, ppid, ok := procStat(pid)
		p, err := platform.ProcessByPID(pid)
		if err != nil {
			continue
		}
		if !ok || name != p.Name || ppid != p.PPID {
			t.Fatalf("pid %d: procStat (%q, %d, %v), platform (%q, %d)", pid, name, ppid, ok, p.Name, p.PPID)
		}
	}
	if _, _, ok := procStat(-5); ok {
		t.Fatal("negative pid")
	}
	if _, _, ok := procStat(1 << 30); ok {
		t.Fatal("missing pid")
	}
	cp := callerProcess(os.Getpid())
	if cp.PID != os.Getpid() || cp.PPID != os.Getppid() || len(cp.Ancestors) == 0 || len(cp.Ancestors) > maxAncestors {
		t.Fatalf("%+v", cp)
	}
	if pp, err := platform.ProcessByPID(os.Getppid()); err == nil && cp.Ancestors[0] != pp.Name {
		t.Fatalf("first ancestor %q, parent is %q", cp.Ancestors[0], pp.Name)
	}
	if callerProcess(0).Exe != "" || callerProcess(-1).PID != -1 {
		t.Fatal("invalid ppid")
	}
}
