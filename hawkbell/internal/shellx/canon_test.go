package shellx

import (
	"slices"
	"testing"
)

// TestCanonicalPathLists pins the canonical form of the path lists
// (pathcanon) for the spellings that used to slip past anchored rules, and
// the benign forms that must come out as written.
func TestCanonicalPathLists(t *testing.T) {
	type want struct {
		reads, writes, deletes, changes, execs, procRoot, aliases []string
	}
	for _, tc := range []struct {
		cmd string
		d   Dialect
		w   want
	}{
		// Doubled separators, dot segments, another process's root.
		{"touch /etc//hawkbell/disabled", Posix, want{changes: []string{"/etc/hawkbell/disabled"}}},
		{"echo 'data_dir: /dev/null' > /etc//hawkbell/hawkbell.yaml", Posix, want{writes: []string{"/etc/hawkbell/hawkbell.yaml"}}},
		{"sed -i 's/a/b/' /etc//hawkbell/hawkbell.yaml", Posix, want{writes: []string{"/etc/hawkbell/hawkbell.yaml"}}},
		{"cp /bin/true /usr//bin/hawkbell", Posix, want{reads: []string{"/bin/true"}, writes: []string{"/usr/bin/hawkbell"}}},
		{"rm -f /usr//bin/hawkbell", Posix, want{deletes: []string{"/usr/bin/hawkbell"}}},
		{"truncate -s0 /var//lib/hawkbell/state.db", Posix, want{writes: []string{"/var/lib/hawkbell/state.db"}}},
		{"touch /etc/x/../hawkbell/./disabled", Posix, want{changes: []string{"/etc/hawkbell/disabled"}}},
		{"touch /proc/self/root/etc/hawkbell/disabled", Posix, want{changes: []string{"/etc/hawkbell/disabled"}, procRoot: []string{"change"}}},
		{"rm -rf /proc/1/root/etc/hawkbell", Posix, want{deletes: []string{"/etc/hawkbell"}, procRoot: []string{"delete"}}},
		{"cat /tmp/../root/.ssh/id_rsa", Posix, want{reads: []string{"/root/.ssh/id_rsa"}}},
		{"cat /proc/self/root/root/.ssh/id_rsa", Posix, want{reads: []string{"/root/.ssh/id_rsa"}, procRoot: []string{"read"}}},
		{"sh /proc/1/root/tmp/x.sh", Posix, want{execs: []string{"/tmp/x.sh"}, procRoot: []string{"execute"}}},
		{"echo x > /dev//null", Posix, want{}},
		// The working directory a cd sets.
		{"cd /etc/hawkbell && touch disabled", Posix, want{changes: []string{"/etc/hawkbell/disabled"}}},
		{"cd /etc && rm -rf hawkbell", Posix, want{deletes: []string{"/etc/hawkbell"}}},
		{"cd /etc; cd hawkbell; touch ./disabled", Posix, want{changes: []string{"/etc/hawkbell/disabled"}}},
		{"cd ~ && cat .ssh/id_rsa", Posix, want{reads: []string{"~/.ssh/id_rsa"}}},
		{"pushd /etc/hawkbell && popd && touch disabled", Posix, want{changes: []string{"disabled"}}},
		{"cd /proc/1/root/etc && rm -rf hawkbell", Posix, want{deletes: []string{"/etc/hawkbell"}}},
		{"cd /d C:\\ProgramData\\hawkbell && type nul > disabled", Cmd, want{writes: []string{`C:\ProgramData\hawkbell\disabled`}}},
		{`Set-Location C:\ProgramData\hawkbell; New-Item disabled`, PowerShell, want{changes: []string{`C:\ProgramData\hawkbell\disabled`}}},
		// A cd that does not last, or goes somewhere unknown.
		{"(cd /etc/hawkbell && ls); touch disabled", Posix, want{changes: []string{"disabled"}}},
		{"cd /etc/hawkbell | true; touch disabled", Posix, want{changes: []string{"disabled"}}},
		{"sh -c 'cd /etc/hawkbell'; touch disabled", Posix, want{changes: []string{"disabled"}}},
		{"x=$(cd /etc/hawkbell && pwd); touch disabled", Posix, want{changes: []string{"disabled"}}},
		{"cd \"$X\" && touch disabled", Posix, want{changes: []string{"disabled"}}},
		{"cd \"$X\" && cd sub && touch disabled", Posix, want{changes: []string{"disabled"}}},
		{"cd - && touch disabled", Posix, want{changes: []string{"disabled"}}},
		// Links and bind mounts that reach a path under another name: the
		// path reached is an alias, not a change.
		{"ln -s /etc/hawkbell /tmp/s", Posix, want{writes: []string{"/tmp/s"}, aliases: []string{"/etc/hawkbell"}}},
		{"cd /tmp && ln -s ../etc/hawkbell s", Posix, want{writes: []string{"/tmp/s"}, aliases: []string{"/etc/hawkbell"}}},
		{"ln -s ../../etc/hawkbell /tmp/a/s", Posix, want{writes: []string{"/tmp/a/s"}, aliases: []string{"/etc/hawkbell"}}},
		{"ln -s /etc/hawkbell /tmp/", Posix, want{writes: []string{"/tmp/hawkbell"}, aliases: []string{"/etc/hawkbell"}}},
		{"ln /etc/hawkbell/hawkbell.yaml /tmp/c.yaml", Posix, want{writes: []string{"/tmp/c.yaml"}, aliases: []string{"/etc/hawkbell/hawkbell.yaml"}}},
		{"ln -sf /dev/null /etc/hawkbell/hawkbell.yaml", Posix, want{writes: []string{"/etc/hawkbell/hawkbell.yaml"}}},
		{"mount --bind /tmp/empty /etc/hawkbell", Posix, want{changes: []string{"/etc/hawkbell"}, aliases: []string{"/tmp/empty"}}},
		{"mount -o bind /etc/hawkbell /tmp/s", Posix, want{changes: []string{"/tmp/s"}, aliases: []string{"/etc/hawkbell"}}},
		// An operand after the link on the same line that goes through it
		// is also recorded under the path it reaches.
		{"ln -s /etc/hawkbell /tmp/s && touch /tmp/s/disabled", Posix, want{writes: []string{"/tmp/s"}, aliases: []string{"/etc/hawkbell"},
			changes: []string{"/tmp/s/disabled", "/etc/hawkbell/disabled"}}},
		{"ln -s /etc/hawkbell /tmp/s; cd /tmp/s && echo x > hawkbell.yaml", Posix, want{writes: []string{"/tmp/s", "/tmp/s/hawkbell.yaml", "/etc/hawkbell/hawkbell.yaml"},
			aliases: []string{"/etc/hawkbell"}}},
		{"ln -s /etc/hawkbell/hawkbell.yaml c && echo x > c", Posix, want{writes: []string{"c", "/etc/hawkbell/hawkbell.yaml"}, aliases: []string{"/etc/hawkbell/hawkbell.yaml"}}},
		{"ln -s /etc/hawkbell/hawkbell.yaml c && rm c", Posix, want{writes: []string{"c"}, deletes: []string{"c"}, aliases: []string{"/etc/hawkbell/hawkbell.yaml"}}},
		{"mount --bind /etc/hawkbell /mnt/x && touch /mnt/x/disabled", Posix, want{changes: []string{"/mnt/x", "/mnt/x/disabled", "/etc/hawkbell/disabled"},
			aliases: []string{"/etc/hawkbell"}}},
		// chown -h and touch -h act on the link itself.
		{"ln -sfn /etc/hawkbell /home/dev/.gemini && chown -h 1000:1000 /home/dev/.gemini", Posix, want{writes: []string{"/home/dev/.gemini"},
			changes: []string{"/home/dev/.gemini"}, aliases: []string{"/etc/hawkbell"}}},
		{"ln -sfn /etc/hawkbell /home/dev/.gemini && chown 1000:1000 /home/dev/.gemini", Posix, want{writes: []string{"/home/dev/.gemini"},
			changes: []string{"/home/dev/.gemini", "/etc/hawkbell"}, aliases: []string{"/etc/hawkbell"}}},
		{`New-Item -ItemType SymbolicLink -Path C:\x -Target C:\ProgramData\hawkbell`, PowerShell, want{writes: []string{`C:\x`}, aliases: []string{`C:\ProgramData\hawkbell`}}},
		{`New-Item -ItemType Junction -Path C:\x -Value C:\ProgramData\hawkbell`, PowerShell, want{writes: []string{`C:\x`}, aliases: []string{`C:\ProgramData\hawkbell`}}},
		{`mklink /D C:\x C:\ProgramData\hawkbell`, Cmd, want{writes: []string{`C:\x`}, aliases: []string{`C:\ProgramData\hawkbell`}}},
		{`mklink /J C:\x C:\ProgramData\hawkbell`, Cmd, want{writes: []string{`C:\x`}, aliases: []string{`C:\ProgramData\hawkbell`}}},
		{"mount -t tmpfs tmpfs /etc/hawkbell", Posix, want{changes: []string{"/etc/hawkbell"}}},
		{"umount /etc/hawkbell", Posix, want{changes: []string{"/etc/hawkbell"}}},
		{"mount", Posix, want{}},
		// Windows forms.
		{`New-Item -ItemType File -Path C:\ProgramData\.\hawkbell\disabled`, PowerShell, want{changes: []string{`C:\ProgramData\hawkbell\disabled`}}},
		{`Remove-Item -Recurse \\?\C:\ProgramData\hawkbell`, PowerShell, want{deletes: []string{`C:\ProgramData\hawkbell`}}},
		{`Remove-Item c:/programdata//hawkbell`, PowerShell, want{deletes: []string{`C:\programdata\hawkbell`}}},
		{`ren C:\ProgramData\hawkbell\hawkbell.yaml x`, Cmd, want{reads: []string{`C:\ProgramData\hawkbell\hawkbell.yaml`}, changes: []string{`C:\ProgramData\hawkbell\hawkbell.yaml`}}},
		{`Set-Acl -Path C:\ProgramData\hawkbell -AclObject $a`, PowerShell, want{changes: []string{`C:\ProgramData\hawkbell`}}},
		// Benign forms that keep their spelling.
		{"rm -rf node_modules dist/", Posix, want{deletes: []string{"node_modules", "dist"}}},
		{"cat src/main.go internal/x/y.go", Posix, want{reads: []string{"src/main.go", "internal/x/y.go"}}},
		{"cat ../shared/config.json", Posix, want{reads: []string{"../shared/config.json"}}},
		{"cat ~/.aws/cred*", Posix, want{reads: []string{"~/.aws/cred*"}}},
		{"cat 'My Documents/a b.txt'", Posix, want{reads: []string{"My Documents/a b.txt"}}},
		{"rm -rf '/Users/a b/Library/Application Support/x'", Posix, want{deletes: []string{"/Users/a b/Library/Application Support/x"}}},
		{"curl -o out.json https://example.com/a/../b.json", Posix, want{writes: []string{"out.json"}}},
		{`type C:\Users\dev\repo\README.md`, Cmd, want{reads: []string{`C:\Users\dev\repo\README.md`}}},
		{"Get-Content ./notes.txt", PowerShell, want{reads: []string{"notes.txt"}}},
		{"Remove-Item /etc//hawkbell", PowerShell, want{deletes: []string{"/etc/hawkbell"}}},
		{`cd C:\x; Set-Content Env:\FOO bar`, PowerShell, want{writes: []string{`Env:\FOO`}}},
		{`cd C:\x; Remove-Item Registry::HKEY_CURRENT_USER\Software\x`, PowerShell, want{deletes: []string{`Registry::HKEY_CURRENT_USER\Software\x`}}},
	} {
		f := Analyze(tc.cmd, tc.d)
		for _, l := range []struct {
			name      string
			got, want []string
		}{
			{"reads", f.Reads, tc.w.reads}, {"writes", f.Writes, tc.w.writes}, {"deletes", f.Deletes, tc.w.deletes},
			{"changes", f.Changes, tc.w.changes}, {"executes", f.ExecutesPaths, tc.w.execs}, {"proc_root", f.ProcRoot, tc.w.procRoot},
			{"aliases", f.Aliases, tc.w.aliases},
		} {
			if len(l.got) == 0 && len(l.want) == 0 {
				continue
			}
			if !slices.Equal(l.got, l.want) {
				t.Errorf("%s: %s = %q, want %q", tc.cmd, l.name, l.got, l.want)
			}
		}
	}
}

// TestCanonicalClassification checks that the classification form
// (normPath) sees the canonical path, so the analyser's own categories do
// not depend on the spelling either.
func TestCanonicalClassification(t *testing.T) {
	for _, tc := range []struct {
		cmd, field, val string
	}{
		{"rm -rf /tmp/../etc", "destructive", "rm_recursive_root"},
		{"rm -rf /proc/self/root/", "destructive", "rm_recursive_root"},
		{"rm -rf /home/u/", "destructive", "rm_recursive_home"},
		{"touch /etc//hawkbell/disabled", "evasion", "sensor_tamper"},
		{"cd /etc/hawkbell && touch disabled", "evasion", "sensor_tamper"},
		{"ln -s /etc/hawkbell /tmp/s && touch /tmp/s/disabled", "evasion", "sensor_tamper"},
		{"cat /proc/self/root/etc/shadow", "cred", "secret_file_read"},
		{"cd /root/.ssh && cat id_rsa", "cred", "ssh_key_read"},
		{"echo x >> /etc//sudoers.d/x", "priv", "sudoers_edit"},
		{"echo x > /etc/./cron.d/x", "persist", "cron"},
		{"cp evil.service /etc/systemd/system/", "persist", "systemd"},
		{"cp evil.service /etc/systemd/system", "persist", "systemd"},
		{"cp agent.plist ~/Library/LaunchAgents/", "persist", "launchd"},
		{"cp hook .git//hooks/", "persist", "git_hook"},
		{"cp x.sh /etc/profile.d/", "persist", "shell_profile"},
	} {
		f := Analyze(tc.cmd, Posix)
		var got []string
		switch tc.field {
		case "destructive":
			got = f.Destructive
		case "evasion":
			got = f.DefenseEvasion
		case "cred":
			got = f.CredAccess
		case "priv":
			got = f.Privilege
		case "persist":
			got = f.Persistence
		}
		if !slices.Contains(got, tc.val) {
			t.Errorf("%s: %s = %q, want %q", tc.cmd, tc.field, got, tc.val)
		}
	}
}

func TestSpecialModeBits(t *testing.T) {
	for _, tc := range []struct {
		mode     string
		uid, gid bool
	}{
		{"4755", true, false}, {"04755", true, false}, {"2750", false, true}, {"02750", false, true},
		{"6755", true, true}, {"1777", false, false}, {"0755", false, false}, {"755", false, false},
		{"12750", false, false}, {"u+s", true, false}, {"g+s", false, true}, {"+s", true, true},
		{"a+s", true, true}, {"o+s", false, false}, {"ug=rwxs", true, true}, {"g-s", false, false},
		{"u+x,g+s", false, true}, {"u-x+s", true, false}, {"+x", false, false},
	} {
		uid, gid := specialBits(tc.mode)
		if uid != tc.uid || gid != tc.gid {
			t.Errorf("specialBits(%q) = %v, %v; want %v, %v", tc.mode, uid, gid, tc.uid, tc.gid)
		}
	}
	for _, tc := range []struct {
		cmd  string
		want []string
	}{
		{"chmod 4755 /tmp/x", []string{"setuid_chmod"}},
		{"chmod 2755 /tmp/x", []string{"setgid_chmod"}},
		{"chmod g+s /tmp/x", []string{"setgid_chmod"}},
		{"mkdir -p pt/data/outbox && chmod 2750 pt/data/outbox", nil},
		{"mkdir -p $T/data/outbox && chmod 2750 $T/data/outbox", nil},
		{"install -d -m 2750 /var/lib/x && chmod 2750 /var/lib/x", nil},
		{"chmod g+s shared/", nil},
		{"mkdir a && chmod 2750 a b", []string{"setgid_chmod"}},
		{"install -m 2755 x /usr/local/bin/x", []string{"setgid_chmod"}},
		{"install -m 4755 x /usr/local/bin/x", []string{"setuid_chmod"}},
	} {
		f := Analyze(tc.cmd, Posix)
		var got []string
		for _, p := range f.Privilege {
			if p == "setuid_chmod" || p == "setgid_chmod" {
				got = append(got, p)
			}
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: privilege = %q, want %q", tc.cmd, got, tc.want)
		}
	}
}

func TestSensorCLIHelp(t *testing.T) {
	for _, tc := range []struct {
		cmd  string
		stop bool
	}{
		{"hawkbell hooks uninstall", true},
		{"hawkbell hooks uninstall --agent claude-code", true},
		{"hawkbell hooks uninstall --help", false},
		{"hawkbell hooks uninstall -h", false},
		{"hawkbell help hooks", false},
		{"hawkbell --version", false},
		// Only hawkbell's own CLI is known to print usage for --help anywhere.
		{"orbit uninstall --help", true},
		{"osqueryctl stop", true},
		{"osqueryctl stop --help", true},
		{"osqueryctl stop -h", true},
		{"sudo osqueryctl stop --help", true},
		{"osqueryctl --help", false},
		{"osqueryctl --help stop", false},
		{"osqueryctl status", false},
		{"sentinelctl unload -h", true},
		{"falconctl uninstall --help", true},
		{"hawkbell hooks uninstall -- --help", true},
	} {
		f := Analyze(tc.cmd, Posix)
		if got := slices.Contains(f.DefenseEvasion, "stop_security_tool"); got != tc.stop {
			t.Errorf("%s: stop_security_tool = %v, want %v", tc.cmd, got, tc.stop)
		}
	}
}

func TestTokenPrintLiteralLoop(t *testing.T) {
	for _, tc := range []struct {
		cmd   string
		token bool
	}{
		{`printf '%s' "$GITHUB_TOKEN"`, true},
		{`echo "$pat"`, true},
		{`for pat in 'hawkbell?' 'hawkbell[AB]' '*'; do printf '%s\n' "$pat"; done`, false},
		{`W=/tmp/w; for pat in "$W/db//hawkbellA/state.db"; do printf '{"path": "%s"}' "$pat"; done`, false},
		{`for pat in $(gh auth token); do echo "$pat"; done`, true},
		{`for TOKEN in "$@"; do echo "$TOKEN"; done`, true},
	} {
		f := Analyze(tc.cmd, Posix)
		if got := slices.Contains(f.CredAccess, "token_print"); got != tc.token {
			t.Errorf("%s: token_print = %v, want %v", tc.cmd, got, tc.token)
		}
	}
}

// TestCanonicalReviewForms pins the forms the review of the first version
// found: a one-character bracket glob, a process root behind a variable,
// rm operands rm refuses, Windows mkdir and md, install -d, a backgrounded
// cd, and on a POSIX host a name with a colon and a literal "$".
func TestCanonicalReviewForms(t *testing.T) {
	type want struct {
		writes, deletes, changes, execs, procRoot []string
	}
	linux := Options{OS: "linux"}
	for _, tc := range []struct {
		cmd string
		d   Dialect
		o   Options
		w   want
	}{
		// A bracket expression with one character is that character when the
		// glob is active; quoted, it is a literal name.
		{"touch /etc/[h]awkbell/disabled", Posix, Options{}, want{changes: []string{"/etc/hawkbell/disabled"}}},
		{"touch /etc/[h][a]wkbell/disabled", Posix, Options{}, want{changes: []string{"/etc/hawkbell/disabled"}}},
		{"rm -rf /var/lib/hawkbel[l]", Posix, Options{}, want{deletes: []string{"/var/lib/hawkbell"}}},
		{"echo x > /etc/[h]awkbell/hawkbell.yaml", Posix, Options{}, want{writes: []string{"/etc/hawkbell/hawkbell.yaml"}}},
		{"touch '/etc/[h]awkbell/disabled'", Posix, Options{}, want{changes: []string{"/etc/[h]awkbell/disabled"}}},
		{"touch /etc/haw?bell/disabled", Posix, Options{}, want{changes: []string{"/etc/haw?bell/disabled"}}},
		{`New-Item C:\ProgramData\[h]awkbell\disabled`, PowerShell, Options{}, want{changes: []string{`C:\ProgramData\hawkbell\disabled`}}},
		// Any id before /root is a process root.
		{"sh /proc/$PID/root/tmp/x.sh", Posix, Options{}, want{execs: []string{"/tmp/x.sh"}, procRoot: []string{"execute"}}},
		{"touch /proc/$$/root/etc/hawkbell/disabled", Posix, Options{}, want{changes: []string{"/etc/hawkbell/disabled"}, procRoot: []string{"change"}}},
		{"rm -rf /proc/$(pgrep -n sshd)/root/etc/hawkbell", Posix, Options{}, want{deletes: []string{"/etc/hawkbell"}, procRoot: []string{"delete"}}},
		// rm and rmdir refuse a last component of "." or "..".
		{"rm -rf /tmp/..", Posix, Options{}, want{}},
		{"rm -rf /etc/hawkbell/x/..", Posix, Options{}, want{}},
		{"rmdir /etc/hawkbell/.", Posix, Options{}, want{}},
		{"rm -rf /tmp/../*", Posix, Options{}, want{deletes: []string{"/*"}}},
		// Windows mkdir and md create directories.
		{`md C:\ProgramData\hawkbell\disabled`, PowerShell, Options{}, want{changes: []string{`C:\ProgramData\hawkbell\disabled`}}},
		{`mkdir C:\ProgramData\hawkbell\disabled -Force`, PowerShell, Options{}, want{changes: []string{`C:\ProgramData\hawkbell\disabled`}}},
		{`mkdir -Path C:\ProgramData\hawkbell -Name disabled`, PowerShell, Options{}, want{changes: []string{`C:\ProgramData\hawkbell\disabled`}}},
		{`md C:\ProgramData\hawkbell\disabled`, Cmd, Options{}, want{changes: []string{`C:\ProgramData\hawkbell\disabled`}}},
		{`mkdir C:\ProgramData\hawkbell\disabled`, Cmd, Options{}, want{changes: []string{`C:\ProgramData\hawkbell\disabled`}}},
		{`cmd /c md C:\ProgramData\hawkbell\disabled`, PowerShell, Options{}, want{changes: []string{`C:\ProgramData\hawkbell\disabled`}}},
		{`cmd.exe /c "md C:\ProgramData\hawkbell\disabled"`, PowerShell, Options{}, want{changes: []string{`C:\ProgramData\hawkbell\disabled`}}},
		// install -d creates its operands.
		{"install -d /etc/hawkbell/disabled", Posix, Options{}, want{changes: []string{"/etc/hawkbell/disabled"}}},
		// "cd /x &" changes nothing for the next command.
		{"cd /etc/hawkbell & touch disabled", Posix, Options{}, want{changes: []string{"disabled"}}},
		// On a POSIX host a colon is part of a name; literal "$" and "%" do
		// not stop "..".
		{"mkdir -p a: && touch a:/../../etc/hawkbell/disabled", Posix, linux, want{changes: []string{"./a:", "../etc/hawkbell/disabled"}}},
		{"cd /tmp && touch ab:/../../etc/hawkbell/disabled", Posix, linux, want{changes: []string{"/etc/hawkbell/disabled"}}},
		{"cd /tmp && touch 'q$x/../../etc/hawkbell/disabled'", Posix, linux, want{changes: []string{"/etc/hawkbell/disabled"}}},
		{"cd /tmp && touch 100%/../../etc/hawkbell/disabled", Posix, linux, want{changes: []string{"/etc/hawkbell/disabled"}}},
		// An unresolved variable is an anchor of unknown depth.
		{"cd /tmp && touch \"$X\"/../../etc/hawkbell/disabled", Posix, linux, want{changes: []string{"$X/../../etc/hawkbell/disabled"}}},
		// A Windows-looking name in a POSIX shell on an unknown host stays a
		// drive (Git Bash).
		{"rm -rf C:/ProgramData/hawkbell", Posix, Options{}, want{deletes: []string{`C:\ProgramData\hawkbell`}}},
	} {
		f := AnalyzeWith(tc.cmd, tc.d, tc.o)
		for _, l := range []struct {
			name      string
			got, want []string
		}{
			{"writes", f.Writes, tc.w.writes}, {"deletes", f.Deletes, tc.w.deletes}, {"changes", f.Changes, tc.w.changes},
			{"executes", f.ExecutesPaths, tc.w.execs}, {"proc_root", f.ProcRoot, tc.w.procRoot},
		} {
			if len(l.got) == 0 && len(l.want) == 0 {
				continue
			}
			if !slices.Equal(l.got, l.want) {
				t.Errorf("%s: %s = %q, want %q", tc.cmd, l.name, l.got, l.want)
			}
		}
	}
	// rm refuses "/tmp/..": not rm -rf /.
	for _, cmd := range []string{"rm -rf /tmp/..", "rm -rf /tmp/../", "rm -rf ~/x/..", "rm -rf /tmp/x/../..", "rm -rf /home/u/proj/build/../.."} {
		if f := Analyze(cmd, Posix); len(f.Destructive) != 0 {
			t.Errorf("%s: destructive = %q, want none", cmd, f.Destructive)
		}
	}
	for _, cmd := range []string{"rm -rf /tmp/../*", "rm -rf /", "rm -rf ~", "rm -rf .."} {
		if f := Analyze(cmd, Posix); len(f.Destructive) == 0 {
			t.Errorf("%s: no destructive fact", cmd)
		}
	}
}

// TestPathSegmentHelpers pins the allocation-free segment tests that
// replaced string concatenation in the classification helpers.
func TestPathSegmentHelpers(t *testing.T) {
	for _, tc := range []struct {
		norm, seg string
		want      bool
	}{
		{"~/.ssh/id_rsa", ".ssh", true}, {".ssh/id_rsa", ".ssh", true}, {"/x/.ssh", ".ssh", true}, {".ssh", ".ssh", true},
		{"/x/a.ssh/y", ".ssh", false}, {"/x/.sshd/y", ".ssh", false}, {"/x/.ssh.bak/.ssh/y", ".ssh", true}, {"", ".ssh", false},
	} {
		if got := pathHasSeg(tc.norm, tc.seg); got != tc.want {
			t.Errorf("pathHasSeg(%q, %q) = %v", tc.norm, tc.seg, got)
		}
	}
	if !endsWithSeg("/x/.aws/credentials", ".aws/credentials") || endsWithSeg("/x/y.aws/credentials", ".aws/credentials") || !endsWithSeg(".netrc", ".netrc") {
		t.Error("endsWithSeg")
	}
	if !underDir("/etc/shadow", "/etc/shadow") || !underDir("/etc/sudoers.d/x", "/etc/sudoers.d") || underDir("/etc/shadowx", "/etc/shadow") {
		t.Error("underDir")
	}
}
