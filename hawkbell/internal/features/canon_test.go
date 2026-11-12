package features

import (
	"slices"
	"testing"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// TestFileToolTargetsCanonical pins path.targets and path.proc_root: the
// canonical form of a file tool's target paths, which anchored rules match
// instead of target.path (kept as the tool call carried it).
func TestFileToolTargetsCanonical(t *testing.T) {
	win := Context{Home: `C:\Users\dev`, OS: "windows"}
	for _, tc := range []struct {
		path    string
		ctx     Context
		targets []string
		proc    bool
		class   string // a class path.classes must hold, or ""
	}{
		{"/etc//hawkbell/disabled", linuxCtx, []string{"/etc/hawkbell/disabled"}, false, "sensor_files"},
		{"/proc/self/root/etc/hawkbell/hawkbell.yaml", linuxCtx, []string{"/etc/hawkbell/hawkbell.yaml"}, true, "sensor_files"},
		{"/proc/1/root/etc/claude-code/managed-settings.json", linuxCtx, []string{"/etc/claude-code/managed-settings.json"}, true, "agent_managed_policy"},
		{"/tmp/../home/dev/.ssh/id_ed25519", linuxCtx, []string{"/home/dev/.ssh/id_ed25519"}, false, "ssh_private_key"},
		{"~/../../etc/hawkbell/disabled", linuxCtx, []string{"/etc/hawkbell/disabled"}, false, ""},
		// Relative paths are joined with the session directory.
		{"src/main.go", linuxCtx, []string{home + "/proj/src/main.go"}, false, ""},
		{"../../../etc/hawkbell/disabled", linuxCtx, []string{"/etc/hawkbell/disabled"}, false, ""},
		// Benign forms.
		{home + "/proj/My Notes/a b.md", linuxCtx, []string{home + "/proj/My Notes/a b.md"}, false, ""},
		{"~/.aws/config", linuxCtx, []string{"~/.aws/config"}, false, ""},
		{`C:\Users\dev\repo\main.go`, win, []string{`C:\Users\dev\repo\main.go`}, false, ""},
		{`\\?\C:\ProgramData\hawkbell\disabled`, win, []string{`C:\ProgramData\hawkbell\disabled`}, false, ""},
		{`c:/ProgramData/./hawkbell/disabled`, win, []string{`C:\ProgramData\hawkbell\disabled`}, false, ""},
	} {
		e := fileEvent(event.ToolFileWrite, tc.path)
		if tc.ctx.OS == "windows" {
			e.Session.CWD = `C:\Users\dev\repo`
		}
		f := computed(e, tc.ctx)
		if got := strs(t, f, "path.targets"); !slices.Equal(got, tc.targets) {
			t.Errorf("%s: path.targets = %q, want %q", tc.path, got, tc.targets)
		}
		if got := boolean(t, f, "path.proc_root"); got != tc.proc {
			t.Errorf("%s: path.proc_root = %v, want %v", tc.path, got, tc.proc)
		}
		if f["target.path"] != tc.path {
			t.Errorf("%s: target.path = %v, want the path as written", tc.path, f["target.path"])
		}
		if tc.class != "" && !has(strs(t, f, "path.classes"), tc.class) {
			t.Errorf("%s: path.classes = %q, want %s", tc.path, strs(t, f, "path.classes"), tc.class)
		}
	}
}

// TestShellListsCanonical checks the shell.* path features end to end:
// the analyzer's canonical lists, the new shell.changes family, the
// process-root fact, and home-climbing paths resolved against the home.
func TestShellListsCanonical(t *testing.T) {
	for _, tc := range []struct {
		cmd, key string
		want     []string
	}{
		{"touch /etc//hawkbell/disabled", "shell.changes", []string{"/etc/hawkbell/disabled"}},
		{"touch /etc//hawkbell/disabled", "shell.change_classes", []string{"sensor_files"}},
		{"cd /etc/hawkbell && touch disabled", "shell.changes", []string{"/etc/hawkbell/disabled"}},
		{"touch /proc/self/root/etc/hawkbell/disabled", "shell.proc_root", []string{"change"}},
		{"cat /proc/self/root/root/.ssh/id_rsa", "shell.reads", []string{"/root/.ssh/id_rsa"}},
		{"cat /proc/self/root/root/.ssh/id_rsa", "shell.proc_root", []string{"read"}},
		{"echo x > ~/../../etc/hawkbell/hawkbell.yaml", "shell.writes", []string{"/etc/hawkbell/hawkbell.yaml"}},
		{"rm -rf node_modules ./dist/", "shell.deletes", []string{"node_modules", "dist"}},
		{"cat ~/.ssh/config ../x/.env", "shell.reads", []string{"~/.ssh/config", "../x/.env"}},
		{"ln -s /etc/hawkbell /tmp/s", "shell.aliases", []string{"/etc/hawkbell"}},
		{"ln -s /etc/hawkbell /tmp/s && touch /tmp/s/disabled", "shell.changes", []string{"/tmp/s/disabled", "/etc/hawkbell/disabled"}},
	} {
		f := computed(shellEvent(tc.cmd), linuxCtx)
		got := strs(t, f, tc.key)
		if tc.key == "shell.change_classes" {
			if !has(got, tc.want[0]) {
				t.Errorf("%s: %s = %q, want %q", tc.cmd, tc.key, got, tc.want)
			}
			continue
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: %s = %q, want %q", tc.cmd, tc.key, got, tc.want)
		}
	}
}

// TestShellSensorSelfClass checks the class HB-EVADE-002 matches beside
// its anchored path list: a glob that can only reach the sensor's files,
// and a path relative to the session directory, carry sensor_self in the
// shell.*_classes features, while the lists keep the canonical spelling.
func TestShellSensorSelfClass(t *testing.T) {
	for _, tc := range []struct {
		cmd, cwd, key string
		want          bool
	}{
		{"touch /etc/haw?bell/disabled", "", "shell.change_classes", true},
		{"rm -rf /e*/hawkbell", "", "shell.delete_classes", true},
		{"echo x > /etc/hawkbell*/hawkbell.yaml", "", "shell.write_classes", true},
		{"touch disabled", "/etc/hawkbell", "shell.change_classes", true},
		{"cd hawkbell && rm -f state.db", "/var/lib", "shell.delete_classes", true},
		{"cd .local/state/hawkbell && rm -f state.db", home, "shell.delete_classes", true},
		{"rm -f /proc/self/cwd/state.db", "/var/lib/hawkbell", "shell.delete_classes", true},
		{"touch ../../../etc/hawkbell/disabled", home + "/proj", "shell.change_classes", true},
		{"rm -rf etc/hawkbell", "/", "shell.delete_classes", true},
		// Not the sensor's files.
		{"chmod +x /usr/local/bin/*", "", "shell.change_classes", false},
		{"rm -rf /var/log/*", "", "shell.delete_classes", false},
		{"cd /tmp/pkgroot && touch etc/hawkbell/disabled", "", "shell.change_classes", false},
		{"touch disabled", home + "/proj", "shell.change_classes", false},
	} {
		e := shellEvent(tc.cmd)
		if tc.cwd != "" {
			e.Session.CWD = tc.cwd
		}
		f := computed(e, linuxCtx)
		if got := has(strs(t, f, tc.key), "sensor_self"); got != tc.want {
			t.Errorf("%s (cwd %s): %s = %q, sensor_self %v, want %v", tc.cmd, e.Session.CWD, tc.key, strs(t, f, tc.key), got, tc.want)
		}
	}
	// The list itself is not joined with the session directory.
	e := shellEvent("touch disabled")
	e.Session.CWD = "/etc/hawkbell"
	if got := strs(t, computed(e, linuxCtx), "shell.changes"); !slices.Equal(got, []string{"disabled"}) {
		t.Errorf("shell.changes = %q, want [disabled]", got)
	}
}
