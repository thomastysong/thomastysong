package pathcanon

import "testing"

func TestClean(t *testing.T) {
	home := Options{Home: "/root"}
	win := Options{Windows: true}
	for _, tc := range []struct {
		in   string
		o    Options
		want string
		fl   Flags
	}{
		// Duplicate separators, "." and "..".
		{"/etc//spoor/disabled", Options{}, "/etc/spoor/disabled", 0},
		{"/etc/./spoor/disabled", Options{}, "/etc/spoor/disabled", 0},
		{"/etc/x/../spoor/spoor.yaml", Options{}, "/etc/spoor/spoor.yaml", 0},
		{"/usr//bin/spoor", Options{}, "/usr/bin/spoor", 0},
		{"/var//lib/spoor/state.db", Options{}, "/var/lib/spoor/state.db", 0},
		{"//etc/spoor", Options{}, "/etc/spoor", 0},
		{"/tmp/../root/.ssh/id_rsa", Options{}, "/root/.ssh/id_rsa", 0},
		{"/../../etc/spoor", Options{}, "/etc/spoor", 0},
		{"/etc/spoor/", Options{}, "/etc/spoor", 0},
		{"/", Options{}, "/", 0},
		{"/.", Options{}, "/", 0},
		// Another process's root.
		{"/proc/self/root/etc/spoor/disabled", Options{}, "/etc/spoor/disabled", ProcRoot},
		{"/proc/1/root/etc/spoor", Options{}, "/etc/spoor", ProcRoot},
		{"/proc/thread-self/root/etc/spoor", Options{}, "/etc/spoor", ProcRoot},
		{"/proc/1/task/1/root/etc/spoor", Options{}, "/etc/spoor", ProcRoot},
		{"/proc/self/root/root/.ssh/id_rsa", Options{}, "/root/.ssh/id_rsa", ProcRoot},
		{"/proc/self/root", Options{}, "/", ProcRoot},
		{"/proc/self/root/proc/1/root/etc", Options{}, "/etc", ProcRoot},
		{"/proc/self/root/../etc", Options{}, "/etc", ProcRoot},
		{"/proc/1/mounts", Options{}, "/proc/1/mounts", 0},
		{"/proc/self/environ", Options{}, "/proc/self/environ", 0},
		{"/proc/self/cwd/x", Options{CWD: "/etc/spoor"}, "/etc/spoor/x", 0},
		{"/proc/self/cwd/x", Options{}, "x", 0},
		// Relative paths: kept, or joined with a known working directory.
		{"src/main.go", Options{}, "src/main.go", 0},
		{"./x.sh", Options{}, "x.sh", 0},
		{".", Options{}, ".", 0},
		{"./", Options{}, ".", 0},
		{"..", Options{}, "..", 0},
		{"../..", Options{}, "../..", 0},
		{"a/../../x", Options{}, "../x", 0},
		{"../*/.env", Options{}, "../*/.env", 0},
		{"disabled", Options{CWD: "/etc/spoor"}, "/etc/spoor/disabled", 0},
		{"spoor", Options{CWD: "/etc"}, "/etc/spoor", 0},
		{"../../.env", Options{CWD: "sub"}, "../.env", 0},
		{".ssh/id_rsa", Options{CWD: "~"}, "~/.ssh/id_rsa", 0},
		{"/abs/path", Options{CWD: "/etc"}, "/abs/path", 0},
		// Anchors of unknown depth.
		{"~/.ssh/id_rsa", Options{}, "~/.ssh/id_rsa", 0},
		{"~/./.ssh//id_rsa", Options{}, "~/.ssh/id_rsa", 0},
		{"~", Options{}, "~", 0},
		{"~/", Options{}, "~", 0},
		{"~/../x", Options{}, "~/../x", 0},
		{"~/../../etc/spoor", home, "/etc/spoor", 0},
		{"$HOME/../../etc/spoor", home, "/etc/spoor", 0},
		{"$TMPDIR/../x", home, "$TMPDIR/../x", 0},
		{"$HOME/.aws/credentials", Options{}, "$HOME/.aws/credentials", 0},
		{"/etc/$X/../spoor", Options{}, "/etc/$X/../spoor", 0},
		{"$(...)/x", Options{}, "$(...)/x", 0},
		// Globs, braces and spaces are ordinary characters.
		{"~/.aws/cred*", Options{}, "~/.aws/cred*", 0},
		{"~/.aws/{config,credentials}", Options{}, "~/.aws/{config,credentials}", 0},
		{"/Users/a b/Library/Application Support/spoor", Options{}, "/Users/a b/Library/Application Support/spoor", 0},
		{"dir with space/../f", Options{}, "f", 0},
		// Not paths.
		{"https://example.com/a/../b", Options{}, "https://example.com/a/../b", 0},
		{"<(...)", Options{}, "<(...)", 0},
		{"", Options{}, "", 0},
		// A POSIX file name may contain a backslash.
		{`a\b`, Options{}, `a\b`, 0},
		// Windows.
		{`C:\ProgramData\spoor\disabled`, Options{}, `C:\ProgramData\spoor\disabled`, 0},
		{`c:/programdata//spoor/./disabled`, Options{}, `C:\programdata\spoor\disabled`, 0},
		{`C:\ProgramData\x\..\spoor`, win, `C:\ProgramData\spoor`, 0},
		{`C:\..\..\Windows`, win, `C:\Windows`, 0},
		{`\\?\C:\ProgramData\spoor`, win, `C:\ProgramData\spoor`, 0},
		{`//?/C:/ProgramData/spoor`, Options{}, `C:\ProgramData\spoor`, 0},
		{`\??\C:\ProgramData\spoor`, win, `C:\ProgramData\spoor`, 0},
		{`\\.\C:\ProgramData\spoor`, win, `C:\ProgramData\spoor`, 0},
		{`\\?\UNC\srv\share\x\..\y`, win, `\\srv\share\y`, 0},
		{`\\srv\share\..\..\x`, win, `\\srv\share\x`, 0},
		{`\\.\PhysicalDrive0`, win, `\\.\PhysicalDrive0`, 0},
		{`\\.\C:`, win, `\\.\C:`, 0},
		{`C:`, win, `C:`, 0},
		{`C:\`, win, `C:\`, 0},
		{`$env:LOCALAPPDATA\spoor\..\spoor`, win, `$env:LOCALAPPDATA\spoor`, 0},
		{`%PROGRAMDATA%\spoor\.\disabled`, win, `%PROGRAMDATA%\spoor\disabled`, 0},
		{`spoor\disabled`, Options{Windows: true, CWD: `C:\ProgramData`}, `C:\ProgramData\spoor\disabled`, 0},
		// PowerShell drives and providers are not relative paths.
		{`Env:\FOO`, Options{Windows: true, CWD: `C:\x`}, `Env:\FOO`, 0},
		{`HKCU:\Software\x\..\y`, Options{Windows: true, CWD: `C:\x`}, `HKCU:\Software\y`, 0},
		{`Registry::HKEY_CURRENT_USER\Software\x`, Options{Windows: true, CWD: `C:\x`}, `Registry::HKEY_CURRENT_USER\Software\x`, 0},
		// PowerShell on Linux and macOS: forward slashes only stay POSIX.
		{"/etc//spoor", win, "/etc/spoor", 0},
	} {
		got, fl := Clean(tc.in, tc.o)
		if got != tc.want || fl != tc.fl {
			t.Errorf("Clean(%q, %+v) = %q, %v; want %q, %v", tc.in, tc.o, got, fl, tc.want, tc.fl)
		}
		// Idempotent.
		if again, _ := Clean(got, Options{Windows: tc.o.Windows}); again != got {
			t.Errorf("Clean(Clean(%q)) = %q, want %q", tc.in, again, got)
		}
	}
}

// TestCleanOptions pins the forms the review of the first version found
// unresolved: one-character bracket expressions, a colon in a POSIX name,
// literal "$" and "%", process roots behind any id, and the Windows forms
// Win32 normalises (trailing dots, local admin shares, drive-relative
// roots).
func TestCleanOptions(t *testing.T) {
	glob := Options{Glob: true}
	posix := Options{Posix: true, CWD: "/home/u/proj"}
	lit := Options{Literal: true, CWD: "/home/u/proj"}
	win := Options{Windows: true}
	for _, tc := range []struct {
		in   string
		o    Options
		want string
		fl   Flags
	}{
		// A bracket expression that matches one character is that character.
		{"/etc/[s]poor/disabled", glob, "/etc/spoor/disabled", 0},
		{"/etc/[s][p]oor/disabled", glob, "/etc/spoor/disabled", 0},
		{"/etc/spoo[r]/disabled", glob, "/etc/spoor/disabled", 0},
		{`C:\ProgramData\[s]poor\disabled`, Options{Windows: true, Glob: true}, `C:\ProgramData\spoor\disabled`, 0},
		// Not active, or more than one character: kept.
		{"/etc/[s]poor/disabled", Options{}, "/etc/[s]poor/disabled", 0},
		{"/etc/[sx]poor/disabled", glob, "/etc/[sx]poor/disabled", 0},
		{"/etc/[!s]poor", glob, "/etc/[!s]poor", 0},
		{"/etc/[^s]poor", glob, "/etc/[^s]poor", 0},
		{"/etc/[a-z]poor", glob, "/etc/[a-z]poor", 0},
		{"/etc/[]]x", glob, "/etc/[]]x", 0},
		{"/etc/[/]x", glob, "/etc/[/]x", 0},
		{"/etc/spo[", glob, "/etc/spo[", 0},
		{"[[0]]", glob, "[[0]]", 0},
		{`[/..\[0]`, Options{Windows: true, Glob: true}, "0", 0},
		{"/etc/[sp]o[o]r", glob, "/etc/[sp]oor", 0},
		// A colon is an ordinary character in a POSIX name on a POSIX host.
		{"a:/../../../../etc/spoor/disabled", posix, "/etc/spoor/disabled", 0},
		{"ab:/../../../../etc/spoor/disabled", posix, "/etc/spoor/disabled", 0},
		{"a:/x", Options{Posix: true}, "./a:/x", 0},
		// Literal "$" and "%" do not stop "..".
		{"q$x/../../../../etc/spoor/disabled", lit, "/etc/spoor/disabled", 0},
		{"100%/../../../../etc/spoor/disabled", lit, "/etc/spoor/disabled", 0},
		{"q$x/../../../etc/spoor/disabled", Options{CWD: "/home/u/proj"}, "/home/u/proj/q$x/../../../etc/spoor/disabled", 0},
		// Any id before /root is a process root.
		{"/proc/$PID/root/tmp/x.sh", Options{}, "/tmp/x.sh", ProcRoot},
		{"/proc/$$/root/etc/spoor/disabled", Options{}, "/etc/spoor/disabled", ProcRoot},
		{"/proc/$(...)/root/etc/spoor", Options{}, "/etc/spoor", ProcRoot},
		{"/proc/*/root/tmp/x.sh", Options{}, "/tmp/x.sh", ProcRoot},
		{"/proc/$PID/task/$TID/root/etc", Options{}, "/etc", ProcRoot},
		{"/proc/$$/cwd/state.db", Options{CWD: "/var/lib/spoor"}, "/var/lib/spoor/state.db", 0},
		{"/proc/1/cwd/x", Options{CWD: "/var/lib/spoor"}, "/proc/1/cwd/x", 0},
		{"/proc/sys/kernel/x", Options{}, "/proc/sys/kernel/x", 0},
		// Win32 drops a period that ends a component, and trailing periods
		// and spaces of the last one.
		{`C:\ProgramData\spoor.\disabled`, win, `C:\ProgramData\spoor\disabled`, 0},
		{`C:\ProgramData\spoor\disabled.`, win, `C:\ProgramData\spoor\disabled`, 0},
		{`C:\ProgramData\spoor\disabled . .`, win, `C:\ProgramData\spoor\disabled`, 0},
		{`C:\ProgramData\spoor.\`, win, `C:\ProgramData\spoor`, 0},
		{`C:\ProgramData\spoor..\x`, win, `C:\ProgramData\spoor..\x`, 0},
		{`C:\x\...\y`, win, `C:\x\...\y`, 0},
		{`C:\x\*.`, win, `C:\x\*.`, 0},
		{`\\?\C:\ProgramData\spoor.\disabled`, win, `\\?\C:\ProgramData\spoor.\disabled`, 0},
		{`\\?\C:\ProgramData\spoor\x\..\disabled`, win, `C:\ProgramData\spoor\disabled`, 0},
		{`\\?\UNC\srv\share\spoor.\x`, win, `\\?\UNC\srv\share\spoor.\x`, 0},
		// A share of the local host is its drive.
		{`\\localhost\C$\ProgramData\spoor`, win, `C:\ProgramData\spoor`, 0},
		{`\\127.0.0.1\c$\ProgramData\spoor`, win, `C:\ProgramData\spoor`, 0},
		{`\\?\UNC\localhost\C$\ProgramData\spoor`, win, `C:\ProgramData\spoor`, 0},
		{`\\srv\C$\ProgramData\spoor`, win, `\\srv\C$\ProgramData\spoor`, 0},
		{`\\srv`, win, `\\srv`, 0},
		// A root without a drive is on the working directory's drive.
		{`\ProgramData\spoor`, Options{Windows: true, CWD: `C:\Users\u\repo`}, `C:\ProgramData\spoor`, 0},
		{`\ProgramData\spoor`, win, `\ProgramData\spoor`, 0},
		// A root working directory is not doubled into a share.
		{`ProgramData\spoor`, Options{Windows: true, CWD: `\`}, `\ProgramData\spoor`, 0},
		{`ProgramData\spoor`, Options{Windows: true, CWD: `C:\`}, `C:\ProgramData\spoor`, 0},
		{"etc/spoor", Options{CWD: "/"}, "/etc/spoor", 0},
	} {
		got, fl := Clean(tc.in, tc.o)
		if got != tc.want || fl != tc.fl {
			t.Errorf("Clean(%q, %+v) = %q, %v; want %q, %v", tc.in, tc.o, got, fl, tc.want, tc.fl)
		}
		if again, _ := Clean(got, Options{Windows: tc.o.Windows}); again != got {
			t.Errorf("Clean(Clean(%q)) = %q, want %q", tc.in, again, got)
		}
	}
	// Found by fuzzing: a relative result that starts with "a:" read as a
	// drive when cleaned again, and extra slashes before a namespace prefix.
	for _, tc := range []struct{ in, cwd string }{{"../a:", "0"}, {`\\\?\0`, ""}, {`\\?\0.\0`, ""}, {`C:\x\y \`, ""}, {`C:\x\a..\y\..`, ""}, {`./\\`, ""}, {`//?///?/0`, ""}, {`\??\\??\x`, ""}, {`\\?/./A: `, ""}, {`.\a:`, ""}, {`.\a:0/0`, ""}} {
		got, _ := Clean(tc.in, Options{CWD: tc.cwd})
		if again, _ := Clean(got, Options{}); again != got {
			t.Errorf("Clean(%q) = %q, cleaned again %q", tc.in, got, again)
		}
	}
}

// TestCleanFastPath checks that an absolute POSIX path already in canonical
// form comes back without allocating, and that the fast path does not
// accept a path that needs work.
func TestCleanFastPath(t *testing.T) {
	for _, p := range []string{"/etc/spoor/spoor.yaml", "/home/u/.ssh/id_rsa", "/", "/a/.b/..c/c."} {
		if n := testing.AllocsPerRun(100, func() { Clean(p, Options{}) }); n != 0 {
			t.Errorf("Clean(%q) allocates %v times", p, n)
		}
	}
	for _, p := range []string{"/etc//x", "/etc/./x", "/etc/../x", "/etc/x/", "/etc/x/.", "/etc/x/..", "/proc/1/root/x", "//x"} {
		if canonicalPosix(p, Options{}) {
			t.Errorf("canonicalPosix(%q) = true", p)
		}
	}
	if canonicalPosix("/etc/[s]poor", Options{Glob: true}) || canonicalPosix(`/etc\x`, Options{Windows: true}) {
		t.Error("canonicalPosix accepted a path that needs work")
	}
	// Plain relative paths: unchanged, or joined with a canonical working
	// directory in one allocation; the same result as the full walk.
	for _, tc := range []struct{ p, cwd string }{
		{"src/main.go", ""}, {"disabled", "/etc/spoor"}, {"etc/spoor", "/"}, {"proc/1/root/x", "/"},
		{"1/root/x", "/proc"}, {"a/b", "/x/y"}, {"x.sh", "~/proj"}, {".env", "/srv/app"},
	} {
		o := Options{CWD: tc.cwd}
		got, fl := Clean(tc.p, o)
		var slowFl Flags
		slow := clean(tc.p, o, &slowFl, 0)
		if got != slow || fl != slowFl {
			t.Errorf("Clean(%q, cwd %q) = %q %v, full walk %q %v", tc.p, tc.cwd, got, fl, slow, slowFl)
		}
	}
	if n := testing.AllocsPerRun(100, func() { Clean("src/main.go", Options{}) }); n != 0 {
		t.Errorf("Clean of a plain relative path allocates %v times", n)
	}
	if n := testing.AllocsPerRun(100, func() { Clean("src/main.go", Options{CWD: "/home/u/proj"}) }); n > 1 {
		t.Errorf("joining a plain relative path allocates %v times", n)
	}
	for _, p := range []string{"./x", "x/../y", "x//y", "x/", "~/x", "$H/x", "a:/x", `a\b`, "x/.", ".."} {
		if simpleRel(p, Options{}) {
			t.Errorf("simpleRel(%q) = true", p)
		}
	}
}

func TestDir(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		win      bool
	}{
		{"/tmp/s", "/tmp", false},
		{"/s", "/", false},
		{"s", "", false},
		{"a/b", "a", false},
		{`C:\x`, `C:\`, true},
		{`C:\x\y`, `C:\x`, true},
	} {
		if got := Dir(tc.in, tc.win); got != tc.want {
			t.Errorf("Dir(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func FuzzClean(f *testing.F) {
	for _, s := range []string{"/etc//spoor", `\\?\C:\x`, "~/../x", "/proc/1/root/..", "a/../../b"} {
		f.Add(s, false)
	}
	f.Fuzz(func(t *testing.T, s string, w bool) {
		for _, o := range []Options{{Windows: w}, {Windows: w, Glob: true}, {Posix: !w, Literal: true}} {
			got, _ := Clean(s, o)
			if again, _ := Clean(got, o); again != got {
				t.Fatalf("not idempotent under %+v: %q -> %q -> %q", o, s, got, again)
			}
		}
	})
}
