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
		{"/etc//hawkbell/disabled", Options{}, "/etc/hawkbell/disabled", 0},
		{"/etc/./hawkbell/disabled", Options{}, "/etc/hawkbell/disabled", 0},
		{"/etc/x/../hawkbell/hawkbell.yaml", Options{}, "/etc/hawkbell/hawkbell.yaml", 0},
		{"/usr//bin/hawkbell", Options{}, "/usr/bin/hawkbell", 0},
		{"/var//lib/hawkbell/state.db", Options{}, "/var/lib/hawkbell/state.db", 0},
		{"//etc/hawkbell", Options{}, "/etc/hawkbell", 0},
		{"/tmp/../root/.ssh/id_rsa", Options{}, "/root/.ssh/id_rsa", 0},
		{"/../../etc/hawkbell", Options{}, "/etc/hawkbell", 0},
		{"/etc/hawkbell/", Options{}, "/etc/hawkbell", 0},
		{"/", Options{}, "/", 0},
		{"/.", Options{}, "/", 0},
		// Another process's root.
		{"/proc/self/root/etc/hawkbell/disabled", Options{}, "/etc/hawkbell/disabled", ProcRoot},
		{"/proc/1/root/etc/hawkbell", Options{}, "/etc/hawkbell", ProcRoot},
		{"/proc/thread-self/root/etc/hawkbell", Options{}, "/etc/hawkbell", ProcRoot},
		{"/proc/1/task/1/root/etc/hawkbell", Options{}, "/etc/hawkbell", ProcRoot},
		{"/proc/self/root/root/.ssh/id_rsa", Options{}, "/root/.ssh/id_rsa", ProcRoot},
		{"/proc/self/root", Options{}, "/", ProcRoot},
		{"/proc/self/root/proc/1/root/etc", Options{}, "/etc", ProcRoot},
		{"/proc/self/root/../etc", Options{}, "/etc", ProcRoot},
		{"/proc/1/mounts", Options{}, "/proc/1/mounts", 0},
		{"/proc/self/environ", Options{}, "/proc/self/environ", 0},
		{"/proc/self/cwd/x", Options{CWD: "/etc/hawkbell"}, "/etc/hawkbell/x", 0},
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
		{"disabled", Options{CWD: "/etc/hawkbell"}, "/etc/hawkbell/disabled", 0},
		{"hawkbell", Options{CWD: "/etc"}, "/etc/hawkbell", 0},
		{"../../.env", Options{CWD: "sub"}, "../.env", 0},
		{".ssh/id_rsa", Options{CWD: "~"}, "~/.ssh/id_rsa", 0},
		{"/abs/path", Options{CWD: "/etc"}, "/abs/path", 0},
		// Anchors of unknown depth.
		{"~/.ssh/id_rsa", Options{}, "~/.ssh/id_rsa", 0},
		{"~/./.ssh//id_rsa", Options{}, "~/.ssh/id_rsa", 0},
		{"~", Options{}, "~", 0},
		{"~/", Options{}, "~", 0},
		{"~/../x", Options{}, "~/../x", 0},
		{"~/../../etc/hawkbell", home, "/etc/hawkbell", 0},
		{"$HOME/../../etc/hawkbell", home, "/etc/hawkbell", 0},
		{"$TMPDIR/../x", home, "$TMPDIR/../x", 0},
		{"$HOME/.aws/credentials", Options{}, "$HOME/.aws/credentials", 0},
		{"/etc/$X/../hawkbell", Options{}, "/etc/$X/../hawkbell", 0},
		{"$(...)/x", Options{}, "$(...)/x", 0},
		// Globs, braces and spaces are ordinary characters.
		{"~/.aws/cred*", Options{}, "~/.aws/cred*", 0},
		{"~/.aws/{config,credentials}", Options{}, "~/.aws/{config,credentials}", 0},
		{"/Users/a b/Library/Application Support/hawkbell", Options{}, "/Users/a b/Library/Application Support/hawkbell", 0},
		{"dir with space/../f", Options{}, "f", 0},
		// Not paths.
		{"https://example.com/a/../b", Options{}, "https://example.com/a/../b", 0},
		{"<(...)", Options{}, "<(...)", 0},
		{"", Options{}, "", 0},
		// A POSIX file name may contain a backslash.
		{`a\b`, Options{}, `a\b`, 0},
		// Windows.
		{`C:\ProgramData\hawkbell\disabled`, Options{}, `C:\ProgramData\hawkbell\disabled`, 0},
		{`c:/programdata//hawkbell/./disabled`, Options{}, `C:\programdata\hawkbell\disabled`, 0},
		{`C:\ProgramData\x\..\hawkbell`, win, `C:\ProgramData\hawkbell`, 0},
		{`C:\..\..\Windows`, win, `C:\Windows`, 0},
		{`\\?\C:\ProgramData\hawkbell`, win, `C:\ProgramData\hawkbell`, 0},
		{`//?/C:/ProgramData/hawkbell`, Options{}, `C:\ProgramData\hawkbell`, 0},
		{`\??\C:\ProgramData\hawkbell`, win, `C:\ProgramData\hawkbell`, 0},
		{`\\.\C:\ProgramData\hawkbell`, win, `C:\ProgramData\hawkbell`, 0},
		{`\\?\UNC\srv\share\x\..\y`, win, `\\srv\share\y`, 0},
		{`\\srv\share\..\..\x`, win, `\\srv\share\x`, 0},
		{`\\.\PhysicalDrive0`, win, `\\.\PhysicalDrive0`, 0},
		{`\\.\C:`, win, `\\.\C:`, 0},
		{`C:`, win, `C:`, 0},
		{`C:\`, win, `C:\`, 0},
		{`$env:LOCALAPPDATA\hawkbell\..\hawkbell`, win, `$env:LOCALAPPDATA\hawkbell`, 0},
		{`%PROGRAMDATA%\hawkbell\.\disabled`, win, `%PROGRAMDATA%\hawkbell\disabled`, 0},
		{`hawkbell\disabled`, Options{Windows: true, CWD: `C:\ProgramData`}, `C:\ProgramData\hawkbell\disabled`, 0},
		// PowerShell drives and providers are not relative paths.
		{`Env:\FOO`, Options{Windows: true, CWD: `C:\x`}, `Env:\FOO`, 0},
		{`HKCU:\Software\x\..\y`, Options{Windows: true, CWD: `C:\x`}, `HKCU:\Software\y`, 0},
		{`Registry::HKEY_CURRENT_USER\Software\x`, Options{Windows: true, CWD: `C:\x`}, `Registry::HKEY_CURRENT_USER\Software\x`, 0},
		// PowerShell on Linux and macOS: forward slashes only stay POSIX.
		{"/etc//hawkbell", win, "/etc/hawkbell", 0},
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
		{"/etc/[h]awkbell/disabled", glob, "/etc/hawkbell/disabled", 0},
		{"/etc/[h][a]wkbell/disabled", glob, "/etc/hawkbell/disabled", 0},
		{"/etc/hawkbel[l]/disabled", glob, "/etc/hawkbell/disabled", 0},
		{`C:\ProgramData\[h]awkbell\disabled`, Options{Windows: true, Glob: true}, `C:\ProgramData\hawkbell\disabled`, 0},
		// Not active, or more than one character: kept.
		{"/etc/[h]awkbell/disabled", Options{}, "/etc/[h]awkbell/disabled", 0},
		{"/etc/[hx]awkbell/disabled", glob, "/etc/[hx]awkbell/disabled", 0},
		{"/etc/[!h]awkbell", glob, "/etc/[!h]awkbell", 0},
		{"/etc/[^h]awkbell", glob, "/etc/[^h]awkbell", 0},
		{"/etc/[a-z]awkbell", glob, "/etc/[a-z]awkbell", 0},
		{"/etc/[]]x", glob, "/etc/[]]x", 0},
		{"/etc/[/]x", glob, "/etc/[/]x", 0},
		{"/etc/haw[", glob, "/etc/haw[", 0},
		{"[[0]]", glob, "[[0]]", 0},
		{`[/..\[0]`, Options{Windows: true, Glob: true}, "0", 0},
		{"/etc/[ha]w[k]bell", glob, "/etc/[ha]wkbell", 0},
		// A colon is an ordinary character in a POSIX name on a POSIX host.
		{"a:/../../../../etc/hawkbell/disabled", posix, "/etc/hawkbell/disabled", 0},
		{"ab:/../../../../etc/hawkbell/disabled", posix, "/etc/hawkbell/disabled", 0},
		{"a:/x", Options{Posix: true}, "./a:/x", 0},
		// Literal "$" and "%" do not stop "..".
		{"q$x/../../../../etc/hawkbell/disabled", lit, "/etc/hawkbell/disabled", 0},
		{"100%/../../../../etc/hawkbell/disabled", lit, "/etc/hawkbell/disabled", 0},
		{"q$x/../../../etc/hawkbell/disabled", Options{CWD: "/home/u/proj"}, "/home/u/proj/q$x/../../../etc/hawkbell/disabled", 0},
		// Any id before /root is a process root.
		{"/proc/$PID/root/tmp/x.sh", Options{}, "/tmp/x.sh", ProcRoot},
		{"/proc/$$/root/etc/hawkbell/disabled", Options{}, "/etc/hawkbell/disabled", ProcRoot},
		{"/proc/$(...)/root/etc/hawkbell", Options{}, "/etc/hawkbell", ProcRoot},
		{"/proc/*/root/tmp/x.sh", Options{}, "/tmp/x.sh", ProcRoot},
		{"/proc/$PID/task/$TID/root/etc", Options{}, "/etc", ProcRoot},
		{"/proc/$$/cwd/state.db", Options{CWD: "/var/lib/hawkbell"}, "/var/lib/hawkbell/state.db", 0},
		{"/proc/1/cwd/x", Options{CWD: "/var/lib/hawkbell"}, "/proc/1/cwd/x", 0},
		{"/proc/sys/kernel/x", Options{}, "/proc/sys/kernel/x", 0},
		// Win32 drops a period that ends a component, and trailing periods
		// and spaces of the last one.
		{`C:\ProgramData\hawkbell.\disabled`, win, `C:\ProgramData\hawkbell\disabled`, 0},
		{`C:\ProgramData\hawkbell\disabled.`, win, `C:\ProgramData\hawkbell\disabled`, 0},
		{`C:\ProgramData\hawkbell\disabled . .`, win, `C:\ProgramData\hawkbell\disabled`, 0},
		{`C:\ProgramData\hawkbell.\`, win, `C:\ProgramData\hawkbell`, 0},
		{`C:\ProgramData\hawkbell..\x`, win, `C:\ProgramData\hawkbell..\x`, 0},
		{`C:\x\...\y`, win, `C:\x\...\y`, 0},
		{`C:\x\*.`, win, `C:\x\*.`, 0},
		{`\\?\C:\ProgramData\hawkbell.\disabled`, win, `\\?\C:\ProgramData\hawkbell.\disabled`, 0},
		{`\\?\C:\ProgramData\hawkbell\x\..\disabled`, win, `C:\ProgramData\hawkbell\disabled`, 0},
		{`\\?\UNC\srv\share\hawkbell.\x`, win, `\\?\UNC\srv\share\hawkbell.\x`, 0},
		// A share of the local host is its drive.
		{`\\localhost\C$\ProgramData\hawkbell`, win, `C:\ProgramData\hawkbell`, 0},
		{`\\127.0.0.1\c$\ProgramData\hawkbell`, win, `C:\ProgramData\hawkbell`, 0},
		{`\\?\UNC\localhost\C$\ProgramData\hawkbell`, win, `C:\ProgramData\hawkbell`, 0},
		{`\\srv\C$\ProgramData\hawkbell`, win, `\\srv\C$\ProgramData\hawkbell`, 0},
		{`\\srv`, win, `\\srv`, 0},
		// A root without a drive is on the working directory's drive.
		{`\ProgramData\hawkbell`, Options{Windows: true, CWD: `C:\Users\u\repo`}, `C:\ProgramData\hawkbell`, 0},
		{`\ProgramData\hawkbell`, win, `\ProgramData\hawkbell`, 0},
		// A root working directory is not doubled into a share.
		{`ProgramData\hawkbell`, Options{Windows: true, CWD: `\`}, `\ProgramData\hawkbell`, 0},
		{`ProgramData\hawkbell`, Options{Windows: true, CWD: `C:\`}, `C:\ProgramData\hawkbell`, 0},
		{"etc/hawkbell", Options{CWD: "/"}, "/etc/hawkbell", 0},
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
	for _, p := range []string{"/etc/hawkbell/hawkbell.yaml", "/home/u/.ssh/id_rsa", "/", "/a/.b/..c/c."} {
		if n := testing.AllocsPerRun(100, func() { Clean(p, Options{}) }); n != 0 {
			t.Errorf("Clean(%q) allocates %v times", p, n)
		}
	}
	for _, p := range []string{"/etc//x", "/etc/./x", "/etc/../x", "/etc/x/", "/etc/x/.", "/etc/x/..", "/proc/1/root/x", "//x"} {
		if canonicalPosix(p, Options{}) {
			t.Errorf("canonicalPosix(%q) = true", p)
		}
	}
	if canonicalPosix("/etc/[h]awkbell", Options{Glob: true}) || canonicalPosix(`/etc\x`, Options{Windows: true}) {
		t.Error("canonicalPosix accepted a path that needs work")
	}
	// Plain relative paths: unchanged, or joined with a canonical working
	// directory in one allocation; the same result as the full walk.
	for _, tc := range []struct{ p, cwd string }{
		{"src/main.go", ""}, {"disabled", "/etc/hawkbell"}, {"etc/hawkbell", "/"}, {"proc/1/root/x", "/"},
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
	for _, s := range []string{"/etc//hawkbell", `\\?\C:\x`, "~/../x", "/proc/1/root/..", "a/../../b"} {
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
