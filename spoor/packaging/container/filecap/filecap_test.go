package main

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The xattr values setcap(8) (libcap 2.66, Ubuntu 24.04) wrote for these
// texts, and what getcap(8) printed for them.
var golden = []struct {
	text, hex, getcap string
}{
	{"cap_dac_read_search,cap_sys_ptrace=ep", "0100000204000800000000000000000000000000", "cap_dac_read_search,cap_sys_ptrace=ep"},
	{"cap_net_admin,cap_chown=p", "0000000201100000000000000000000000000000", "cap_chown,cap_net_admin=p"},
	{"cap_checkpoint_restore,cap_bpf=eip", "0100000200000000000000008001000080010000", "cap_bpf,cap_checkpoint_restore=eip"},
}

func TestEncodeMatchesSetcap(t *testing.T) {
	for _, g := range golden {
		s, err := Parse(g.text)
		if err != nil {
			t.Fatalf("%s: %v", g.text, err)
		}
		if got := hex.EncodeToString(s.Encode()); got != g.hex {
			t.Errorf("%s: encoded %s, setcap wrote %s", g.text, got, g.hex)
		}
		raw, _ := hex.DecodeString(g.hex)
		d, err := Decode(raw)
		if err != nil {
			t.Fatalf("decode %s: %v", g.hex, err)
		}
		if !d.Equal(s) {
			t.Errorf("%s: decode(encode) = %+v, want %+v", g.text, d, s)
		}
		if d.String() != g.getcap {
			t.Errorf("%s: String() = %q, getcap printed %q", g.text, d.String(), g.getcap)
		}
	}
}

func TestParse(t *testing.T) {
	ok := []string{"cap_sys_ptrace=ep", "CAP_SYS_PTRACE+ep", "sys_ptrace=p", "cap_chown,cap_fowner=eip"}
	for _, s := range ok {
		if _, err := Parse(s); err != nil {
			t.Errorf("Parse(%q): %v", s, err)
		}
	}
	bad := []string{
		"", "=ep", "cap_sys_ptrace", "cap_sys_ptrace=", "cap_nope=ep",
		"cap_sys_ptrace=ex", "cap_sys_ptrace=ep cap_chown=p", "cap_sys_ptrace=ep-i",
		"cap_sys_ptrace+ep+i", strings.Repeat("cap_chown,", 10000) + "x=p",
	}
	for _, s := range bad {
		if _, err := Parse(s); err == nil {
			t.Errorf("Parse(%q) accepted", s)
		}
	}
}

func TestDecodeHostile(t *testing.T) {
	cases := map[string][]byte{
		"empty":       nil,
		"short":       {1, 0, 0},
		"rev1":        {0, 0, 0, 1, 0, 0, 0, 0},
		"rev2 short":  {0, 0, 0, 2, 0, 0, 0, 0},
		"rev2 long":   bytes.Repeat([]byte{0}, 24),
		"rev3 short":  append([]byte{0, 0, 0, 3}, bytes.Repeat([]byte{0}, 16)...),
		"bad flags":   append([]byte{2, 0, 0, 2}, bytes.Repeat([]byte{0}, 16)...),
		"rev9":        append([]byte{0, 0, 0, 9}, bytes.Repeat([]byte{0}, 16)...),
		"huge":        bytes.Repeat([]byte{0xff}, 1<<16),
		"rev2 + junk": append([]byte{0, 0, 0, 2}, bytes.Repeat([]byte{0}, 17)...),
	}
	for name, b := range cases {
		if _, err := Decode(b); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
	v3 := append([]byte{1, 0, 0, 3, 4, 0, 8, 0}, bytes.Repeat([]byte{0}, 12)...)
	v3 = append(v3, 0xe8, 0x03, 0, 0) // rootid 1000
	s, err := Decode(v3)
	if err != nil || s.Revision != 3 || s.RootID != 1000 || s.String() != "cap_dac_read_search,cap_sys_ptrace=ep" {
		t.Errorf("rev3: %+v %v", s, err)
	}
}

func TestStringMixedFlags(t *testing.T) {
	s := Set{Permitted: 1<<2 | 1<<19, Inheritable: 1 << 19}
	if got := s.String(); got != "cap_dac_read_search=p cap_sys_ptrace=ip" {
		t.Errorf("String() = %q", got)
	}
}

func TestRunUsage(t *testing.T) {
	var out, errb bytes.Buffer
	for _, args := range [][]string{nil, {"set"}, {"set", "cap_chown=p"}, {"bogus", "x"}, {"set", "nope=p", "f"}} {
		out.Reset()
		errb.Reset()
		if code := run(args, &out, &errb); code != 2 {
			t.Errorf("run(%q) = %d, want 2", args, code)
		}
	}
}

// TestFileRoundTrip writes the attribute for real. Setting it needs
// CAP_SETFCAP (root); reading works for anyone.
func TestFileRoundTrip(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("file capabilities are Linux only")
	}
	dir := t.TempDir()
	f := filepath.Join(dir, "bin")
	if err := os.WriteFile(f, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"get", f}, &out, &errb); code != 0 || out.Len() != 0 {
		t.Fatalf("get on a plain file: code %d out %q err %q", code, out.String(), errb.String())
	}
	if code := run([]string{"verify", "cap_sys_ptrace=ep", f}, &out, &errb); code != 1 {
		t.Fatalf("verify on a plain file: code %d", code)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(f, link); err != nil {
		t.Fatal(err)
	}
	errb.Reset()
	if code := run([]string{"set", "cap_sys_ptrace=ep", link}, &out, &errb); code != 1 || !strings.Contains(errb.String(), "not a regular file") {
		t.Fatalf("set through a symlink: code %d err %q", code, errb.String())
	}
	errb.Reset()
	code := run([]string{"set", golden[0].text, f}, &out, &errb)
	if code != 0 {
		if os.Geteuid() != 0 {
			t.Skipf("setting file capabilities needs CAP_SETFCAP: %s", errb.String())
		}
		t.Fatalf("set: %s", errb.String())
	}
	out.Reset()
	if code := run([]string{"verify", golden[0].text, f}, &out, &errb); code != 0 {
		t.Fatalf("verify after set: %s", errb.String())
	}
	if want := f + " " + golden[0].getcap + "\n"; out.String() != want {
		t.Errorf("verify printed %q, want %q", out.String(), want)
	}
	b, err := getCaps(f)
	if err != nil || hex.EncodeToString(b) != golden[0].hex {
		t.Errorf("xattr = %x (%v), want %s", b, err, golden[0].hex)
	}
	if code := run([]string{"verify", "cap_sys_ptrace=p", f}, &out, &errb); code != 1 {
		t.Errorf("verify with a different set passed")
	}
	if code := run([]string{"clear", f}, &out, &errb); code != 0 {
		t.Fatalf("clear: %s", errb.String())
	}
	if _, err := getCaps(f); err != errNoCaps {
		t.Errorf("after clear: %v", err)
	}
}
