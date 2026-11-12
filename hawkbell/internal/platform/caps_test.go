package platform

import (
	"os"
	"runtime"
	"strings"
	"testing"
)

// statusFixture is /proc/self/status of a real process (Linux 6.x layout)
// with the capability lines replaced.
func statusFixture(capLines string) string {
	return "Name:\thawkbell\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t4242\nNgid:\t0\nPid:\t4242\nPPid:\t1\n" +
		"Uid:\t65532\t65532\t65532\t65532\nGid:\t65532\t65532\t65532\t65532\nFDSize:\t64\n" +
		"NStgid:\t4242\nNSpid:\t4242\nVmRSS:\t   21480 kB\nThreads:\t9\n" +
		"SigQ:\t0/63432\nSigPnd:\t0000000000000000\nShdPnd:\t0000000000000000\n" +
		capLines +
		"NoNewPrivs:\t0\nSeccomp:\t2\nSeccomp_filters:\t1\nSpeculation_Store_Bypass:\tthread vulnerable\n" +
		"Cpus_allowed_list:\t0-3\nvoluntary_ctxt_switches:\t150\nnonvoluntary_ctxt_switches:\t3\n"
}

// The node sensor (deploy/kubernetes): uid 65532 with the two file
// capabilities, CapPrm = CapEff = 0x80004 (VERIFIED.md), must count as
// privileged for reading; anything short of both effective must not.
func TestReaderCapsFromStatus(t *testing.T) {
	cases := []struct {
		name string
		caps string
		want bool
		eff  uint64
		ok   bool
	}{
		{"node sensor: both, exactly", "CapInh:\t0000000000000000\nCapPrm:\t0000000000080004\nCapEff:\t0000000000080004\nCapBnd:\t0000000000080004\nCapAmb:\t0000000000000000\n", true, 0x80004, true},
		{"root's full set", "CapInh:\t0000000000000000\nCapPrm:\t000001ffffffffff\nCapEff:\t000001ffffffffff\nCapBnd:\t000001ffffffffff\nCapAmb:\t0000000000000000\n", true, 0x1ffffffffff, true},
		{"systemd unit set (DAC_READ_SEARCH, SYS_PTRACE, NET_ADMIN, CHOWN, FOWNER)", "CapPrm:\t000000000008100d\nCapEff:\t000000000008100d\n", true, 0x8100d, true},
		{"ptrace only", "CapPrm:\t0000000000080000\nCapEff:\t0000000000080000\n", false, 0x80000, true},
		{"dac_read_search only", "CapPrm:\t0000000000000004\nCapEff:\t0000000000000004\n", false, 0x4, true},
		{"permitted but not effective", "CapPrm:\t0000000000080004\nCapEff:\t0000000000000000\n", false, 0, true},
		{"ordinary user", "CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\n", false, 0, true},
		{"no CapEff line (old kernel, hidepid, truncated read)", "CapPrm:\t0000000000080004\n", false, 0, false},
		{"not hex", "CapEff:\t00000000000800zz\n", false, 0, false},
		{"too many digits", "CapEff:\t10000000000080004\n", false, 0, false},
		{"empty value", "CapEff:\t\n", false, 0, false},
		{"first CapEff wins", "CapEff:\t0000000000000000\nCapEff:\t0000000000080004\n", false, 0, true},
		{"CRLF and spaces", "CapEff:   0000000000080004  \r\n", true, 0x80004, true},
	}
	for _, c := range cases {
		st := []byte(statusFixture(c.caps))
		eff, ok := parseCapEff(st)
		if eff != c.eff || ok != c.ok {
			t.Errorf("%s: parseCapEff = %#x, %v; want %#x, %v", c.name, eff, ok, c.eff, c.ok)
		}
		if got := readerCapsIn(st); got != c.want {
			t.Errorf("%s: readerCapsIn = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestParseCapEffHostile(t *testing.T) {
	for _, in := range []string{
		"",
		"CapEff:",
		"CapEff",
		"capeff:\t0000000000080004\n",
		" CapEff:\t0000000000080004\n", // not at the start of a line
		"CapEff:\t-000000000080004\n",
		"CapEff:\t0x0000000000080004\n",
		"CapEff:\t\xff\xfe\n",
		strings.Repeat("CapPrm:\t0000000000080004\n", 10000),
		"CapEff:\t" + strings.Repeat("0", 1<<16) + "\n",
	} {
		if readerCapsIn([]byte(in)) {
			t.Errorf("readerCapsIn(%.40q) = true", in)
		}
	}
}

// IsPrivileged on this host agrees with the kernel's view of the process:
// uid 0, or both reader capabilities effective. IsAdmin is uid 0 alone.
func TestIsPrivilegedMatchesThisProcess(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("capabilities are a Linux concept")
	}
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Skip(err)
	}
	want := os.Geteuid() == 0 || readerCapsIn(b)
	if got := IsPrivileged(); got != want {
		t.Errorf("IsPrivileged = %v, want %v (euid %d)", got, want, os.Geteuid())
	}
	if got := IsAdmin(); got != (os.Geteuid() == 0) {
		t.Errorf("IsAdmin = %v with euid %d", got, os.Geteuid())
	}
}
