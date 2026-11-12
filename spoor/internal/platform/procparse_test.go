package platform

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestSplitArgs(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"only nuls", "\x00\x00\x00", nil},
		{"normal", "claude\x00--dangerously-skip-permissions\x00-p\x00hi there\x00", []string{"claude", "--dangerously-skip-permissions", "-p", "hi there"}},
		{"no trailing nul", "a\x00b", []string{"a", "b"}},
		{"empty middle argument kept", "sh\x00-c\x00\x00x\x00", []string{"sh", "-c", "", "x"}},
		{"setproctitle padding", "nginx: master process\x00\x00\x00\x00\x00", []string{"nginx: master process"}},
		{"invalid utf8 preserved", "a\xff\xfe\x00b\x00", []string{"a\xff\xfe", "b"}},
		{"newline and escape preserved", "a\n\x1b[31m\x00", []string{"a\n\x1b[31m"}},
	}
	for _, tt := range tests {
		if got := splitArgs([]byte(tt.in)); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%s: got %q, want %q", tt.name, got, tt.want)
		}
	}
	// A process cannot make the sensor build an unbounded argument list.
	huge := bytes.Repeat([]byte("a\x00"), maxArgs*3)
	if got := splitArgs(huge); len(got) != maxArgs {
		t.Errorf("huge: %d args, want cap %d", len(got), maxArgs)
	}
}

func TestParseEnviron(t *testing.T) {
	block := "PATH=/usr/bin\x00CLAUDE_CODE_SESSION_ID=abc-123\x00EMPTY=\x00WITH=EQ=UALS\x00NOEQUALS\x00=novalue\x00PATH=/second\x00BIN=\xff\xfe\x00"
	got := parseEnviron([]byte(block), false)
	want := map[string]string{
		"PATH":                   "/usr/bin", // first definition wins, like getenv
		"CLAUDE_CODE_SESSION_ID": "abc-123",
		"EMPTY":                  "",
		"WITH":                   "EQ=UALS",
		"BIN":                    "\xff\xfe",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q\nwant %q", got, want)
	}
	if got := parseEnviron(nil, false); len(got) != 0 || got == nil {
		t.Errorf("empty block: %v", got)
	}
	// Unterminated last entry: complete when the block was read whole,
	// half a value (and dropped) when the read hit the limit.
	if got := parseEnviron([]byte("A=1\x00B=22"), false); got["B"] != "22" {
		t.Errorf("unterminated tail lost: %q", got)
	}
	if got := parseEnviron([]byte("A=1\x00B=22"), true); len(got) != 1 || got["A"] != "1" {
		t.Errorf("truncated tail kept: %q", got)
	}
	var huge bytes.Buffer
	for i := 0; i < maxEnvVars*2; i++ {
		huge.WriteString("K")
		huge.WriteString(strings.Repeat("x", i%7))
		huge.WriteString(string(rune('a' + i%26)))
		huge.WriteString(itoa(i))
		huge.WriteString("=v\x00")
	}
	if got := parseEnviron(huge.Bytes(), false); len(got) > maxEnvVars {
		t.Errorf("huge: %d vars, cap %d", len(got), maxEnvVars)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func TestParseLinuxStat(t *testing.T) {
	const tail = " S 4321 100 100 0 -1 4194304 500 0 0 0 10 5 0 0 20 0 3 0 74352 123456789 100 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 2 0 0 0 0 0\n"
	tests := []struct {
		name      string
		in        string
		comm      string
		ppid      int
		ticks     uint64
		wantError bool
	}{
		{name: "plain", in: "1234 (claude)" + tail, comm: "claude", ppid: 4321, ticks: 74352},
		{name: "spaces", in: "1234 (Web Content)" + tail, comm: "Web Content", ppid: 4321, ticks: 74352},
		// A process names itself to look like the following fields. Only the
		// last ")" ends the name, so ppid and starttime cannot be forged.
		{name: "forged fields", in: "1234 (x) R 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 0 0 0 0 1 (y)" + tail, comm: "x) R 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 0 0 0 0 1 (y", ppid: 4321, ticks: 74352},
		{name: "paren soup", in: "1 (((())))" + tail, comm: "((()))", ppid: 4321, ticks: 74352},
		{name: "newline in name", in: "1 (a\nb)" + tail, comm: "a\nb", ppid: 4321, ticks: 74352},
		{name: "invalid utf8 name", in: "1 (\xff\xfe)" + tail, comm: "\xff\xfe", ppid: 4321, ticks: 74352},
		{name: "empty name", in: "1 ()" + tail, comm: "", ppid: 4321, ticks: 74352},
		{name: "empty", in: "", wantError: true},
		{name: "no parens", in: "1234 claude S 1", wantError: true},
		{name: "close before open", in: ") (", wantError: true},
		{name: "too few fields", in: "1 (a) S 1 2 3", wantError: true},
		{name: "ppid not a number", in: "1 (a) S x 100 100 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 5 1 1", wantError: true},
		{name: "negative ppid", in: "1 (a) S -5 100 100 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 5 1 1", wantError: true},
		{name: "start not a number", in: "1 (a) S 1 100 100 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 zz 1 1", wantError: true},
		{name: "start overflow", in: "1 (a) S 1 100 100 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 99999999999999999999999 1 1", wantError: true},
	}
	for _, tt := range tests {
		comm, ppid, ticks, ok := parseLinuxStat([]byte(tt.in))
		if ok == tt.wantError {
			t.Errorf("%s: ok = %v", tt.name, ok)
			continue
		}
		if ok && (comm != tt.comm || ppid != tt.ppid || ticks != tt.ticks) {
			t.Errorf("%s: got (%q, %d, %d), want (%q, %d, %d)", tt.name, comm, ppid, ticks, tt.comm, tt.ppid, tt.ticks)
		}
	}
}

func TestParseLinuxStatusUID(t *testing.T) {
	status := "Name:\tredis-server\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t17121\nPPid:\t17091\nUid:\t999\t1000\t1001\t1002\nGid:\t999\t999\t999\t999\n"
	if uid, ok := parseLinuxStatusUID([]byte(status)); !ok || uid != "999" {
		t.Errorf("got %q %v, want real uid 999", uid, ok)
	}
	bad := []string{
		"",
		"Name:\tx\n",
		"Uid:\n",
		"Uid:\t-1\t0\n",
		"Uid:\tabc\n",
		"Uid:\t99999999999\n",
		// A process named "Uid:" appears as "Name:\tUid:\t0", never at line start.
		"Name:\tUid:\t0\t0\t0\t0\n",
	}
	for _, in := range bad {
		if uid, ok := parseLinuxStatusUID([]byte(in)); ok {
			t.Errorf("parseLinuxStatusUID(%q) = %q, want failure", in, uid)
		}
	}
	// The name is attacker-chosen and may contain a newline, but the kernel
	// escapes it in status, so a real "Uid:" line is always the kernel's.
	if uid, ok := parseLinuxStatusUID([]byte("Name:\tx\\nUid:\\t0\nUid:\t1000\t1000\t1000\t1000\n")); !ok || uid != "1000" {
		t.Errorf("escaped name: %q %v", uid, ok)
	}
}

func TestParseBootTime(t *testing.T) {
	stat := "cpu  1 2 3 4\ncpu0 1 2 3 4\nintr 5\nctxt 6\nbtime 1794414995\nprocesses 7\n"
	if bt, ok := parseBootTime([]byte(stat)); !ok || bt != 1794414995 {
		t.Errorf("got %d %v", bt, ok)
	}
	for _, in := range []string{"", "cpu 1\n", "btime \n", "btime x\n", "btime 0\n", "btime -5\n", "xbtime 5\n"} {
		if bt, ok := parseBootTime([]byte(in)); ok {
			t.Errorf("parseBootTime(%q) = %d, want failure", in, bt)
		}
	}
}

func TestParseAuxvClockTicks(t *testing.T) {
	type byteOrder interface {
		binary.ByteOrder
		binary.AppendByteOrder
	}
	build := func(order byteOrder, wordSize int, pairs ...uint64) []byte {
		var b []byte
		for _, v := range pairs {
			if wordSize == 8 {
				b = order.AppendUint64(b, v)
			} else {
				b = order.AppendUint32(b, uint32(v))
			}
		}
		return b
	}
	for _, order := range []byteOrder{binary.LittleEndian, binary.BigEndian} {
		for _, ws := range []int{4, 8} {
			b := build(order, ws, 33, 0x7fff0000, 16, 0x1234, 6, 4096, 17, 100, 3, 0x400040, 0, 0)
			if got, ok := parseAuxvClockTicks(b, ws, order); !ok || got != 100 {
				t.Errorf("%v/%d: got %d %v", order, ws, got, ok)
			}
			// AT_CLKTCK after AT_NULL is not part of the vector.
			b = build(order, ws, 6, 4096, 0, 0, 17, 250)
			if _, ok := parseAuxvClockTicks(b, ws, order); ok {
				t.Errorf("%v/%d: read past AT_NULL", order, ws)
			}
			for _, v := range []uint64{0, 5_000_000} {
				if _, ok := parseAuxvClockTicks(build(order, ws, 17, v), ws, order); ok {
					t.Errorf("%v/%d: accepted tick rate %d", order, ws, v)
				}
			}
		}
	}
	if _, ok := parseAuxvClockTicks(nil, 8, binary.LittleEndian); ok {
		t.Error("empty vector")
	}
	if _, ok := parseAuxvClockTicks([]byte{17, 0, 0, 0, 0, 0, 0, 0, 100}, 8, binary.LittleEndian); ok {
		t.Error("truncated pair")
	}
	if _, ok := parseAuxvClockTicks(make([]byte, 64), 3, binary.LittleEndian); ok {
		t.Error("bad word size")
	}
}

// procArgs2Fixture builds a kern.procargs2 buffer the way XNU lays it out.
func procArgs2Fixture(argc int32, execPath string, pad int, args, env []string, tail string) []byte {
	b := binary.LittleEndian.AppendUint32(nil, uint32(argc))
	b = append(b, execPath...)
	b = append(b, 0)
	b = append(b, make([]byte, pad)...)
	for _, a := range args {
		b = append(b, a...)
		b = append(b, 0)
	}
	for _, e := range env {
		b = append(b, e...)
		b = append(b, 0)
	}
	return append(b, tail...)
}

func TestParseProcArgs2(t *testing.T) {
	args := []string{"node", "/Users/a/.npm/bin/claude", "--dangerously-skip-permissions", "", "-p", "fix the bug"}
	env := []string{"PATH=/usr/bin:/bin", "CLAUDECODE=1", "CLAUDE_CODE_SESSION_ID=0199-aa", "HOME=/Users/a"}

	exe, gotArgs, gotEnv, ok := parseProcArgs2(procArgs2Fixture(int32(len(args)), "/opt/homebrew/bin/node", 5, args, env, "\x00\x00\x00ptr_munge=\x00main_stack=\x00"))
	if !ok || exe != "/opt/homebrew/bin/node" {
		t.Fatalf("exe %q ok %v", exe, ok)
	}
	if !reflect.DeepEqual(gotArgs, args) {
		t.Errorf("args %q, want %q (empty argument must survive)", gotArgs, args)
	}
	if !reflect.DeepEqual(gotEnv, env) {
		t.Errorf("env %q, want %q (strings after the empty terminator are not environment)", gotEnv, env)
	}
	m := envListToMap(gotEnv)
	if m["CLAUDE_CODE_SESSION_ID"] != "0199-aa" || len(m) != 4 {
		t.Errorf("env map %q", m)
	}

	// Restricted binary: the kernel returns arguments but no environment.
	_, gotArgs, gotEnv, ok = parseProcArgs2(procArgs2Fixture(2, "/usr/bin/ssh", 3, []string{"ssh", "host"}, nil, ""))
	if !ok || len(gotArgs) != 2 || len(gotEnv) != 0 {
		t.Errorf("restricted: args %q env %q ok %v", gotArgs, gotEnv, ok)
	}
	// No padding at all between the path and argv[0].
	_, gotArgs, _, ok = parseProcArgs2(procArgs2Fixture(1, "/bin/ls", 0, []string{"ls"}, nil, ""))
	if !ok || !reflect.DeepEqual(gotArgs, []string{"ls"}) {
		t.Errorf("no padding: %q %v", gotArgs, ok)
	}
	// argc 0: everything after the path is environment.
	_, gotArgs, gotEnv, ok = parseProcArgs2(procArgs2Fixture(0, "/bin/x", 1, nil, []string{"A=1"}, ""))
	if !ok || len(gotArgs) != 0 || !reflect.DeepEqual(gotEnv, []string{"A=1"}) {
		t.Errorf("argc 0: args %q env %q", gotArgs, gotEnv)
	}
	// Truncated buffer: the last argument is cut; it is kept (better a
	// prefix than nothing) and there is no environment.
	full := procArgs2Fixture(2, "/bin/x", 1, []string{"x", "secondargument"}, []string{"A=1"}, "")
	cut := full[:len(full)-10]
	_, gotArgs, gotEnv, ok = parseProcArgs2(cut)
	if !ok || len(gotArgs) != 2 || gotArgs[1] != "secondarg" || len(gotEnv) != 0 {
		t.Errorf("truncated: args %q env %q ok %v", gotArgs, gotEnv, ok)
	}
	// Truncated inside an environment value: the half value is dropped.
	full = procArgs2Fixture(1, "/bin/x", 1, []string{"x"}, []string{"A=1", "TOKEN=abcdefgh"}, "")
	_, _, gotEnv, _ = parseProcArgs2(full[:len(full)-4])
	if !reflect.DeepEqual(gotEnv, []string{"A=1"}) {
		t.Errorf("cut env value kept: %q", gotEnv)
	}

	hostile := []struct {
		name   string
		buf    []byte
		wantOK bool
	}{
		{"empty", nil, false},
		{"three bytes", []byte{1, 0, 0}, false},
		{"argc only", []byte{1, 0, 0, 0}, true},
		{"negative argc", procArgs2Fixture(-1, "/bin/x", 1, []string{"x"}, nil, ""), false},
		{"min argc", []byte{0, 0, 0, 0x80, '/', 'x', 0}, false},
		{"argc far beyond data", procArgs2Fixture(0x7fffffff, "/bin/x", 1, []string{"x"}, nil, ""), true},
		{"path never terminated", append([]byte{1, 0, 0, 0}, bytes.Repeat([]byte("A"), 5000)...), true},
		{"all nuls", make([]byte, 4096), true},
		{"all 0xff", bytes.Repeat([]byte{0xff}, 4096), false},
	}
	for _, tt := range hostile {
		_, a, e, ok := parseProcArgs2(tt.buf)
		if ok != tt.wantOK {
			t.Errorf("%s: ok = %v, want %v", tt.name, ok, tt.wantOK)
		}
		if len(a) > maxArgs || len(e) > maxEnvVars {
			t.Errorf("%s: unbounded result (%d args, %d env)", tt.name, len(a), len(e))
		}
	}
	// argc larger than the cap: the surplus is skipped, and the environment
	// still starts in the right place.
	many := make([]string, maxArgs+50)
	for i := range many {
		many[i] = "a"
	}
	_, gotArgs, gotEnv, _ = parseProcArgs2(procArgs2Fixture(int32(len(many)), "/bin/x", 1, many, []string{"MARK=1"}, ""))
	if len(gotArgs) != maxArgs || !reflect.DeepEqual(gotEnv, []string{"MARK=1"}) {
		t.Errorf("over cap: %d args, env %q", len(gotArgs), gotEnv)
	}
}

func utf16Block(entries ...string) []uint16 {
	var u []uint16
	for _, e := range entries {
		u = append(u, utf16.Encode([]rune(e))...)
		u = append(u, 0)
	}
	return append(u, 0)
}

func TestParseEnvBlock16(t *testing.T) {
	block := utf16Block(`=C:=C:\Users\a`, `=ExitCode=00000000`, `ALLUSERSPROFILE=C:\ProgramData`, `CLAUDECODE=1`, `Path=C:\Windows;C:\bin`, `EMPTY=`, `Ünï=wért`, `Path=second`)
	block = append(block, utf16.Encode([]rune("AFTER=terminator"))...)
	block = append(block, 0)
	got := parseEnvBlock16(block)
	want := map[string]string{
		"ALLUSERSPROFILE": `C:\ProgramData`,
		"CLAUDECODE":      "1",
		"Path":            `C:\Windows;C:\bin`,
		"EMPTY":           "",
		"Ünï":             "wért",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q\nwant %q", got, want)
	}
	if got := parseEnvBlock16(nil); len(got) != 0 {
		t.Errorf("nil block: %q", got)
	}
	if got := parseEnvBlock16([]uint16{0, 0}); len(got) != 0 {
		t.Errorf("empty block: %q", got)
	}
	// Cut mid-entry (the read stopped at the size cap): no half values.
	cut := utf16Block("A=1", "TOKEN=abcdef")
	if got := parseEnvBlock16(cut[:len(cut)-4]); len(got) != 1 || got["A"] != "1" {
		t.Errorf("cut block: %q", got)
	}
	// Unpaired surrogates decode to U+FFFD instead of failing.
	if got := parseEnvBlock16([]uint16{'K', '=', 0xD800, 0, 0}); got["K"] != "\uFFFD" {
		t.Errorf("lone surrogate: %q", got)
	}
	var huge []uint16
	for i := 0; i < maxEnvVars+100; i++ {
		huge = append(huge, utf16.Encode([]rune("K"+itoa(i)+"=v"))...)
		huge = append(huge, 0)
	}
	if got := parseEnvBlock16(huge); len(got) > maxEnvVars {
		t.Errorf("huge: %d", len(got))
	}
}

// fakeMemory serves reads from a byte slice mapped at base; addresses past
// mapped bytes fail, like ReadProcessMemory on an unmapped page.
type fakeMemory struct {
	base   uintptr
	data   []byte
	mapped int // readable prefix of data
	reads  []int
}

func (m *fakeMemory) read(addr uintptr, n int) ([]byte, error) {
	m.reads = append(m.reads, n)
	off := int(addr - m.base)
	if addr < m.base || off+n > m.mapped {
		return nil, errors.New("unmapped")
	}
	return m.data[off : off+n], nil
}

func utf16Bytes(u []uint16) []byte {
	b := make([]byte, 0, 2*len(u))
	for _, c := range u {
		b = append(b, byte(c), byte(c>>8))
	}
	return b
}

func TestReadEnvBlockPaged(t *testing.T) {
	block := utf16Bytes(utf16Block("CLAUDECODE=1", "PATH="+strings.Repeat(`C:\dir;`, 900), "LAST=z"))
	trailing := bytes.Repeat([]byte{0xAA}, 3*4096)
	data := append(append([]byte(nil), block...), trailing...)

	// Starts mid-page: every read must end on a page boundary, and reading
	// stops at the terminator instead of running into the bytes after it.
	m := &fakeMemory{base: 0x1234_0f10, data: data, mapped: len(data)}
	got := readEnvBlockPaged(m.read, m.base, 1<<20)
	if !bytes.Equal(got, block) {
		t.Fatalf("got %d bytes, want the %d-byte block exactly", len(got), len(block))
	}
	at := m.base
	for i, n := range m.reads {
		if end := at + uintptr(n); end%4096 != 0 && i != len(m.reads)-1 {
			t.Errorf("read %d (%d bytes at %#x) crosses a page boundary", i, n, at)
		}
		if n > 4096 {
			t.Errorf("read %d is %d bytes, more than a page", i, n)
		}
		at += uintptr(n)
	}
	env := parseEnvBlock16(bytesToUTF16(got))
	if env["CLAUDECODE"] != "1" || env["LAST"] != "z" || len(env) != 3 {
		t.Errorf("parsed %d variables: CLAUDECODE=%q LAST=%q", len(env), env["CLAUDECODE"], env["LAST"])
	}

	// The block runs into an unmapped page before any terminator (a lying
	// size field): keep what was readable, drop the cut variable.
	noTerm := utf16Bytes(utf16.Encode([]rune("A=1\x00" + "BIG=" + strings.Repeat("x", 5000))))
	m = &fakeMemory{base: 0x1000, data: noTerm, mapped: 4096}
	got = readEnvBlockPaged(m.read, m.base, 1<<20)
	if len(got) != 4096 {
		t.Errorf("unmapped tail: got %d bytes, want the one mapped page", len(got))
	}
	if env := parseEnvBlock16(bytesToUTF16(got)); len(env) != 1 || env["A"] != "1" {
		t.Errorf("unmapped tail parsed as %q", env)
	}

	// The limit is a hard cap even when memory goes on forever.
	endless := &fakeMemory{base: 0x2000, data: bytes.Repeat([]byte{'x', 0}, 1<<16), mapped: 1 << 17}
	if got := readEnvBlockPaged(endless.read, endless.base, 10_000); len(got) != 10_000 {
		t.Errorf("limit: got %d bytes", len(got))
	}
	// Nothing readable at all.
	if got := readEnvBlockPaged((&fakeMemory{base: 0x3000}).read, 0x3000, 4096); len(got) != 0 {
		t.Errorf("unreadable: got %d bytes", len(got))
	}
	// A reader that returns more than asked cannot overrun the limit.
	greedy := func(uintptr, int) ([]byte, error) { return bytes.Repeat([]byte{'y', 0}, 8192), nil }
	if got := readEnvBlockPaged(greedy, 0, 100); len(got) != 100 {
		t.Errorf("greedy reader: got %d bytes", len(got))
	}
	// An empty block is just the terminator.
	empty := &fakeMemory{base: 0x4000, data: make([]byte, 4096), mapped: 4096}
	if got := readEnvBlockPaged(empty.read, empty.base, 4096); len(got) != 4 {
		t.Errorf("empty block: got %d bytes, want 4", len(got))
	}
}

func TestBytesToUTF16(t *testing.T) {
	if got := bytesToUTF16([]byte{'A', 0, 'B', 0, 'C'}); !reflect.DeepEqual(got, []uint16{'A', 'B'}) {
		t.Errorf("got %v", got)
	}
	if got := bytesToUTF16(nil); len(got) != 0 {
		t.Errorf("nil: %v", got)
	}
}

func TestRefineName(t *testing.T) {
	tests := []struct {
		comm string
		args []string
		max  int
		want string
	}{
		{"claude", []string{"claude", "-p"}, 15, "claude"},
		{"github-copilot-", []string{"/usr/local/bin/github-copilot-cli", "x"}, 15, "github-copilot-cli"},
		{"github-copilot-", []string{"github-copilot-cli"}, 15, "github-copilot-cli"},
		{"github-copilot-", nil, 15, "github-copilot-"},
		// argv[0] is unrelated to the name the process gave itself: keep the name.
		{"MainThread-12345", []string{"/usr/bin/node", "cli.js"}, 16, "MainThread-12345"},
		{"exactly15chars!", []string{"exactly15chars!"}, 15, "exactly15chars!"},
		{"aaaaaaaaaaaaaaa", []string{"aaaaaaaaaaaaaaa" + strings.Repeat("b", 1000)}, 15, "aaaaaaaaaaaaaaa"},
		{"", []string{"x"}, 15, ""},
	}
	for _, tt := range tests {
		if got := refineName(tt.comm, tt.args, tt.max); got != tt.want {
			t.Errorf("refineName(%q, %q) = %q, want %q", tt.comm, tt.args, got, tt.want)
		}
	}
}

func TestTrimDeletedAndParsePID(t *testing.T) {
	if got := trimDeleted("/home/a/.local/share/claude/versions/2.1.100 (deleted)"); got != "/home/a/.local/share/claude/versions/2.1.100" {
		t.Errorf("trimDeleted: %q", got)
	}
	if got := trimDeleted("/usr/bin/node"); got != "/usr/bin/node" {
		t.Errorf("trimDeleted: %q", got)
	}
	good := map[string]int{"1": 1, "4194304": 4194304, "007": 7}
	for in, want := range good {
		if got, ok := parsePID(in); !ok || got != want {
			t.Errorf("parsePID(%q) = %d %v", in, got, ok)
		}
	}
	for _, in := range []string{"", "0", "-1", "self", "12a", "1.5", " 1", "99999999999", "4294967296", "１２"} {
		if got, ok := parsePID(in); ok {
			t.Errorf("parsePID(%q) = %d, want failure", in, got)
		}
	}
}

// TestParsersSurviveNoise feeds every parser random and adversarial bytes.
// The assertion is simply that none of them panics or returns more than its
// bound: these run on data a hostile process writes about itself.
func TestParsersSurviveNoise(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	seeds := [][]byte{
		nil,
		{0},
		bytes.Repeat([]byte{0}, 1<<16),
		bytes.Repeat([]byte{0xff}, 1<<16),
		bytes.Repeat([]byte("(((((("), 1<<12),
		bytes.Repeat([]byte(")))))"), 1<<12),
		bytes.Repeat([]byte("=\x00"), 1<<15),
		bytes.Repeat([]byte(":"), 1<<15),
		bytes.Repeat([]byte("/"), 1<<15),
		[]byte(strings.Repeat("0::/kubepods/pod", 5000)),
	}
	for i := 0; i < 300; i++ {
		b := make([]byte, rng.Intn(4096))
		rng.Read(b)
		seeds = append(seeds, b)
	}
	for _, b := range seeds {
		if a := splitArgs(b); len(a) > maxArgs {
			t.Fatalf("splitArgs unbounded: %d", len(a))
		}
		if e := parseEnviron(b, false); len(e) > maxEnvVars {
			t.Fatalf("parseEnviron unbounded: %d", len(e))
		}
		parseEnviron(b, true)
		parseLinuxStat(b)
		parseLinuxStatusUID(b)
		parseBootTime(b)
		parseAuxvClockTicks(b, 8, binary.LittleEndian)
		parseAuxvClockTicks(b, 4, binary.BigEndian)
		if _, a, e, _ := parseProcArgs2(b); len(a) > maxArgs || len(e) > maxEnvVars {
			t.Fatalf("parseProcArgs2 unbounded")
		}
		if e := parseEnvBlock16(bytesToUTF16(b)); len(e) > maxEnvVars {
			t.Fatalf("parseEnvBlock16 unbounded")
		}
		parseCgroup(b)
		parseMountinfo(b)
		parsePasswd(b)
		parseUIDMin(b)
		parseIORegUUID(b)
		smbiosSystemUUID(b)
		cleanHardwareUUID(string(b))
		machineIDToUUID(string(b))
		sanitizeHostID(string(b))
		unescapeMountField(string(b))
	}
}

func FuzzParseProcArgs2(f *testing.F) {
	f.Add(procArgs2Fixture(2, "/bin/x", 3, []string{"x", "y"}, []string{"A=1"}, ""))
	f.Add([]byte{0xff, 0xff, 0xff, 0x7f, 'a', 0, 'b'})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, args, env, _ := parseProcArgs2(b)
		if len(args) > maxArgs || len(env) > maxEnvVars {
			t.Fatal("unbounded")
		}
	})
}

func FuzzParseLinuxStat(f *testing.F) {
	f.Add([]byte("1 (a) S 1 100 100 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 5 1 1"))
	f.Add([]byte("1 (a) b) S"))
	f.Fuzz(func(t *testing.T, b []byte) {
		comm, ppid, _, ok := parseLinuxStat(b)
		if ok && (ppid < 0 || len(comm) > len(b)) {
			t.Fatal("inconsistent result")
		}
	})
}

func FuzzParseCgroup(f *testing.F) {
	f.Add([]byte("0::/system.slice/docker-" + strings.Repeat("a", 64) + ".scope\n"))
	f.Add([]byte("1:name=systemd:/kubepods/besteffort/pod0a1b2c3d-1234-5678-9abc-def012345678/" + strings.Repeat("b", 64)))
	f.Fuzz(func(t *testing.T, b []byte) {
		info := parseCgroup(b)
		if info.id != "" && !isContainerID(info.id) {
			t.Fatalf("bad id %q", info.id)
		}
		if info.pod != "" && normalizePodUID(info.pod) != info.pod {
			t.Fatalf("bad pod uid %q", info.pod)
		}
	})
}
