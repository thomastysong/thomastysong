package classify

import (
	"slices"
	"testing"
)

// TestSensorSelf pins the sensor_self class: this sensor's own install
// locations, matched like any other class against globs and against paths
// relative to the session directory, but with a strict reading of the
// sensor's own name: a bare wildcard there counts only when the path names
// something literal below it.
func TestSensorSelf(t *testing.T) {
	lin := PathCtx{Home: "/home/u", CWD: "/home/u/proj", OS: "linux"}
	inHome := PathCtx{Home: "/home/u", CWD: "/home/u", OS: "linux"}
	inVarLib := PathCtx{Home: "/home/u", CWD: "/var/lib", OS: "linux"}
	win := PathCtx{Home: `C:\Users\u`, CWD: `C:\Users\u\repo`, OS: "windows"}
	for _, tc := range []struct {
		p    string
		ctx  PathCtx
		want bool
	}{
		{"/etc/spoor/disabled", lin, true},
		{"/etc/spoor", lin, true},
		{"/usr/local/bin/spoor", lin, true},
		{"/sbin/spoor", lin, true},
		{"/etc/systemd/system/spoor.service.d/override.conf", lin, true},
		{"/Library/LaunchDaemons/com.github.thomastysong.spoor.plist", PathCtx{OS: "darwin"}, true},
		{"~/.local/state/spoor/outbox", lin, true},
		{"/Users/me/Library/Application Support/spoor/x", PathCtx{OS: "darwin"}, true},
		// Globs that can only reach the sensor's files.
		{"/etc/spo?r/disabled", lin, true},
		{"/e*/spoor/disabled", lin, true},
		{"/etc/spoor*/disabled", lin, true},
		{"/etc/[sx]poor/disabled", lin, true},
		{"/etc/*/disabled", lin, true},
		// Relative to the session directory, and dot segments.
		{".local/state/spoor/x", inHome, true},
		{"spoor/state.db", inVarLib, true},
		{"../../../etc/spoor/disabled", lin, true},
		{"~x/../../etc/spoor/disabled", lin, true},
		// Not the sensor's files.
		{".local/state/spoor/x", lin, false},
		{"/home/u/proj/spoor", lin, false},
		{"/tmp/pkgroot/etc/spoor/x", lin, false},
		{"/etc/spoorx", lin, false},
		{"/*/*/x", lin, false},
		// Every name in a directory, the sensor's among them: not this class.
		{"/usr/local/bin/*", lin, false},
		{"/var/log/*", lin, false},
		{"/opt/*", lin, false},
		{"/var/lib/apt/lists/*", lin, false},
		// Windows.
		{`C:\ProgramData\spoor\disabled`, win, true},
		{`\ProgramData\spoor`, win, true},
		{`%PROGRAMDATA%\spoor`, win, true},
		{`$env:ProgramData\spoor\disabled`, win, true},
		{`C:\ProgramData\sp*\disabled`, win, true},
		{`%LOCALAPPDATA%\spoor\x`, win, true},
		{`C:\Users\u\AppData\Local\spoor\x`, win, true},
		{`C:\ProgramData\*`, win, false},
		{`C:\Users\u\repo\spoor\x`, win, false},
	} {
		got := slices.Contains(PathClasses(tc.p, tc.ctx), PathSensorSelf)
		if got != tc.want {
			t.Errorf("%s (cwd %s): sensor_self = %v, want %v (classes %v)", tc.p, tc.ctx.CWD, got, tc.want, PathClasses(tc.p, tc.ctx))
		}
	}
}
