package fleetgen

import (
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/platform"
)

func TestDefaultPathsMatchPlatform(t *testing.T) {
	goos := runtime.GOOS
	if !isPlatform(goos) {
		t.Skipf("no hawkbell build for %s", goos)
	}
	want := platform.DefaultDirs().StateDB
	if goos == PlatformWindows {
		// DefaultDirs reads %ProgramData%; the generator assumes the default.
		want = strings.Replace(want, platformProgramData(), `C:\ProgramData`, 1)
	}
	if got := DefaultDBPaths()[goos]; got != want {
		t.Errorf("DefaultDBPaths()[%s] = %q, platform.DefaultDirs().StateDB = %q", goos, got, want)
	}
}

func TestOptionsValidation(t *testing.T) {
	long := "/" + strings.Repeat("a", 1100)
	bad := []struct {
		name string
		o    Options
		want string
	}{
		{"relative", Options{DBPaths: map[string]string{"linux": "var/lib/hawkbell/state.db"}}, "not an absolute POSIX path"},
		{"dotdot", Options{DBPaths: map[string]string{"linux": "/var/lib/../../etc/shadow"}}, "not clean"},
		{"dot", Options{DBPaths: map[string]string{"darwin": "/a/./b"}}, "not clean"},
		{"wildcard", Options{DBPaths: map[string]string{"linux": "/home/%/state.db"}}, "wildcard"},
		{"newline", Options{DBPaths: map[string]string{"linux": "/x\nquery: SELECT 1"}}, "control"},
		{"bidi override", Options{DBPaths: map[string]string{"linux": "/x\u202e/state.db"}}, "formatting"},
		{"nul", Options{BinPaths: map[string]string{"linux": "/usr/bin/haw\x00kbell"}}, "control"},
		{"invalid utf-8", Options{DBPaths: map[string]string{"linux": "/x/\xff.db"}}, "UTF-8"},
		{"too long", Options{DBPaths: map[string]string{"linux": long}}, "longer"},
		{"empty", Options{BinPaths: map[string]string{"linux": ""}}, "empty"},
		{"backslash on posix", Options{DBPaths: map[string]string{"linux": `/x\y`}}, "POSIX"},
		{"windows relative", Options{DBPaths: map[string]string{"windows": `ProgramData\hawkbell\state.db`}}, "Windows"},
		{"windows dotdot", Options{DBPaths: map[string]string{"windows": `C:\ProgramData\..\Windows\x.db`}}, "Windows"},
		{"windows posix", Options{BinPaths: map[string]string{"windows": "/usr/bin/hawkbell"}}, "Windows"},
		{"unknown platform", Options{DBPaths: map[string]string{"freebsd": "/var/db/hawkbell.db"}}, "unknown platform"},
		{"alert too short", Options{AlertWindow: 30 * time.Second}, "alert window"},
		{"guard negative", Options{GuardWindow: -time.Hour}, "guard window"},
		{"guard too long", Options{GuardWindow: 31 * 24 * time.Hour}, "guard window"},
		{"guard shorter than alert", Options{AlertWindow: 2 * time.Hour, GuardWindow: time.Hour}, "shorter"},
		{"fractional seconds", Options{AlertWindow: 90*time.Second + time.Millisecond}, "whole seconds"},
		{"bundle too large", Options{MinBundleVersion: 1 << 63}, "too large"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Generate(tc.o)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

// TestOptionsRefuseGlobPatterns: osquery resolves an ATC path with glob(3)
// and GLOB_BRACE (osquery 5.19 read hawkbellA and hawkbellB for "hawkbell?",
// "hawkbell[AB]" and "hawkbell{A,B}"), plus its own %, while the "installed" label
// compares paths exactly, so any pattern character is refused.
func TestOptionsRefuseGlobPatterns(t *testing.T) {
	paths := map[string][]string{
		PlatformLinux:   {"/var/lib/hawkbell?/state.db", "/var/lib/hawkbell[12]/state.db", "/srv/*/state.db", "/srv/hawkbell{A,B}/state.db", "/srv/x]/state.db", "/srv/x}/state.db", "/home/%/state.db"},
		PlatformDarwin:  {"/Library/Application Support/hawkbell*/state.db", "/usr/local/bin/ha?kbell"},
		PlatformWindows: {`C:\ProgramData\hawkbell?\state.db`, `C:\ProgramData\hawkbell[1]\state.db`, `C:\Program Files\{hawkbell}\hawkbell.exe`},
	}
	for plat, ps := range paths {
		for _, p := range ps {
			for _, o := range []Options{{DBPaths: map[string]string{plat: p}}, {BinPaths: map[string]string{plat: p}}} {
				_, err := Build(o)
				if err == nil || !strings.Contains(err.Error(), "wildcard or glob") {
					t.Errorf("%s path %q: err = %v, want a glob refusal", plat, p, err)
				}
			}
		}
	}
}

// TestOptionsRefuseUncleanPaths: ATC reports a canonical path
// ("/a//b" reads back as "/a/b" on osquery 5.19) while the file table, which
// the "installed" label reads, reports the path as written, so only clean
// spellings are accepted.
func TestOptionsRefuseUncleanPaths(t *testing.T) {
	for _, tc := range []struct{ plat, path string }{
		{PlatformLinux, "/var//lib/hawkbell/state.db"},
		{PlatformLinux, "/var/lib/hawkbell/state.db/"},
		{PlatformLinux, "/"},
		{PlatformDarwin, "/usr/local/bin/hawkbell/"},
		{PlatformDarwin, "//usr/local/bin/hawkbell"},
		{PlatformWindows, `C:\ProgramData\\hawkbell\state.db`},
		{PlatformWindows, `C:\ProgramData\hawkbell\`},
		{PlatformWindows, `C:\`},
		{PlatformWindows, `C:/ProgramData/hawkbell/state.db`},
		{PlatformWindows, `C:\ProgramData/hawkbell\state.db`},
		{PlatformWindows, `C:\ProgramData\.\hawkbell\state.db`},
		{PlatformWindows, `\\server\share`},
		{PlatformWindows, `\\server\\share\state.db`},
	} {
		if _, err := Build(Options{DBPaths: map[string]string{tc.plat: tc.path}}); err == nil || !strings.Contains(err.Error(), "clean") {
			t.Errorf("%s path %q: err = %v, want a refusal as not clean", tc.plat, tc.path, err)
		}
	}
	for _, tc := range []struct{ plat, path string }{
		{PlatformLinux, "/srv/hawkbell/state.db"},
		{PlatformDarwin, "/Library/Application Support/hawkbell/state.db"},
		{PlatformWindows, `D:\hawkbell\state.db`},
		{PlatformWindows, `\\server\share\hawkbell\state.db`},
	} {
		if _, err := Build(Options{DBPaths: map[string]string{tc.plat: tc.path}}); err != nil {
			t.Errorf("%s path %q refused: %v", tc.plat, tc.path, err)
		}
	}
}

// TestCustomPaths is what `hawkbell export fleet` relies on: paths and windows
// given in Options reach the ATC blocks, the labels and the policies, and
// SQL quoting holds for a path with a quote in it.
func TestCustomPaths(t *testing.T) {
	o := Options{
		DBPaths:          map[string]string{"linux": "/srv/o'brien/state.db", "windows": `D:\hawkbell\state.db`},
		BinPaths:         map[string]string{"darwin": "/opt/hawkbell/bin/hawkbell"},
		AlertWindow:      45 * time.Minute,
		GuardWindow:      48 * time.Hour,
		MinBundleVersion: 17,
	}
	c := mustBuild(t, o)
	if p := c.ATC["linux"]["hawkbell_health"].(map[string]any)["path"]; p != "/srv/o'brien/state.db" {
		t.Errorf("linux ATC path %v", p)
	}
	if p := c.ATC["windows"]["hawkbell_agents"].(map[string]any)["path"]; p != `D:\hawkbell\state.db` {
		t.Errorf("windows ATC path %v", p)
	}
	if p := c.ATC["darwin"]["hawkbell_agents"].(map[string]any)["path"]; p != DefaultDBPaths()["darwin"] {
		t.Errorf("darwin ATC path %v, want the default", p)
	}
	stock := mustProfile(t, c, ProfileStock)
	if q := stock.Labels[0].Query; !strings.Contains(q, "'/srv/o''brien/state.db'") || !strings.Contains(q, "'/opt/hawkbell/bin/hawkbell'") {
		t.Errorf("installed label does not carry the custom paths:\n%s", q)
	}
	for _, p := range stock.Policies {
		switch p.Key {
		case "sensor_reporting":
			if !strings.Contains(p.Query, "'-2700 seconds'") || p.Window != 45*time.Minute {
				t.Errorf("sensor policy window: %s", p.Query)
			}
		case "bundle_current":
			if !strings.Contains(p.Query, "< 17") || !strings.Contains(p.Query, "'-172800 seconds'") {
				t.Errorf("bundle policy: %s", p.Query)
			}
		default:
			if !strings.Contains(p.Query, "'-172800 seconds'") || p.Window != 48*time.Hour {
				t.Errorf("%s: guard window not applied: %s", p.Key, p.Query)
			}
		}
	}
	// The emulator agrees: a quoted path does not break the SQL.
	e := newEmu(t, "", atcFlavour)
	e.exec("INSERT INTO file (path) VALUES (?)", "/srv/o'brien/state.db")
	if !labelResults(e, stock)["hawkbell installed"] {
		t.Error("installed label with a quoted custom path does not match")
	}
	// Defaults are not mutated by a custom build.
	if DefaultDBPaths()["linux"] != "/var/lib/hawkbell/state.db" {
		t.Error("DefaultDBPaths changed")
	}
}

func TestDefaultsAreTheSpecWindows(t *testing.T) {
	c := mustBuild(t, Options{})
	if c.AlertWindow != 30*time.Minute || c.GuardWindow != 24*time.Hour {
		t.Fatalf("windows %v / %v, the C5 addendum asks for 30 min and 24 h", c.AlertWindow, c.GuardWindow)
	}
	for _, p := range mustProfile(t, c, ProfileStock).Policies {
		want := "'-86400 seconds')) AND NOT EXISTS ("
		if p.Key == "sensor_reporting" {
			want = "'-1800 seconds'));"
		}
		if !strings.Contains(p.Query, want) {
			t.Errorf("%s: heartbeat guard missing or wrong:\n%s", p.Key, p.Query)
		}
		if !strings.HasPrefix(p.Query, "SELECT 1 WHERE EXISTS (SELECT 1 FROM hawkbell_health WHERE heartbeat >= ") {
			t.Errorf("%s: not built by state.PolicySQLWithin", p.Key)
		}
	}
}

func platformProgramData() string {
	if v := os.Getenv("ProgramData"); v != "" {
		return v
	}
	return `C:\ProgramData`
}
