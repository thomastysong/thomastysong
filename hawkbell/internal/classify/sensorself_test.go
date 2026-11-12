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
		{"/etc/hawkbell/disabled", lin, true},
		{"/etc/hawkbell", lin, true},
		{"/usr/local/bin/hawkbell", lin, true},
		{"/sbin/hawkbell", lin, true},
		{"/etc/systemd/system/hawkbell.service.d/override.conf", lin, true},
		{"/Library/LaunchDaemons/com.github.thomastysong.hawkbell.plist", PathCtx{OS: "darwin"}, true},
		{"~/.local/state/hawkbell/outbox", lin, true},
		{"/Users/me/Library/Application Support/hawkbell/x", PathCtx{OS: "darwin"}, true},
		// Globs that can only reach the sensor's files.
		{"/etc/haw?bell/disabled", lin, true},
		{"/e*/hawkbell/disabled", lin, true},
		{"/etc/hawkbell*/disabled", lin, true},
		{"/etc/[hx]awkbell/disabled", lin, true},
		{"/etc/*/disabled", lin, true},
		// Relative to the session directory, and dot segments.
		{".local/state/hawkbell/x", inHome, true},
		{"hawkbell/state.db", inVarLib, true},
		{"../../../etc/hawkbell/disabled", lin, true},
		{"~x/../../etc/hawkbell/disabled", lin, true},
		// Not the sensor's files.
		{".local/state/hawkbell/x", lin, false},
		{"/home/u/proj/hawkbell", lin, false},
		{"/tmp/pkgroot/etc/hawkbell/x", lin, false},
		{"/etc/hawkbellx", lin, false},
		{"/*/*/x", lin, false},
		// Every name in a directory, the sensor's among them: not this class.
		{"/usr/local/bin/*", lin, false},
		{"/var/log/*", lin, false},
		{"/opt/*", lin, false},
		{"/var/lib/apt/lists/*", lin, false},
		// Windows.
		{`C:\ProgramData\hawkbell\disabled`, win, true},
		{`\ProgramData\hawkbell`, win, true},
		{`%PROGRAMDATA%\hawkbell`, win, true},
		{`$env:ProgramData\hawkbell\disabled`, win, true},
		{`C:\ProgramData\ha*\disabled`, win, true},
		{`%LOCALAPPDATA%\hawkbell\x`, win, true},
		{`C:\Users\u\AppData\Local\hawkbell\x`, win, true},
		{`C:\ProgramData\*`, win, false},
		{`C:\Users\u\repo\hawkbell\x`, win, false},
	} {
		got := slices.Contains(PathClasses(tc.p, tc.ctx), PathSensorSelf)
		if got != tc.want {
			t.Errorf("%s (cwd %s): sensor_self = %v, want %v (classes %v)", tc.p, tc.ctx.CWD, got, tc.want, PathClasses(tc.p, tc.ctx))
		}
	}
}
