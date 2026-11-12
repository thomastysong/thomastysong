package fleetgen

import (
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/thomastysong/spoor/internal/platform"
)

func TestDefaultPathsMatchPlatform(t *testing.T) {
	goos := runtime.GOOS
	if !isPlatform(goos) {
		t.Skipf("no spoor build for %s", goos)
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
		{"relative", Options{DBPaths: map[string]string{"linux": "var/lib/spoor/state.db"}}, "not an absolute POSIX path"},
		{"dotdot", Options{DBPaths: map[string]string{"linux": "/var/lib/../../etc/shadow"}}, "not clean"},
		{"dot", Options{DBPaths: map[string]string{"darwin": "/a/./b"}}, "not clean"},
		{"wildcard", Options{DBPaths: map[string]string{"linux": "/home/%/state.db"}}, "wildcard"},
		{"newline", Options{DBPaths: map[string]string{"linux": "/x\nquery: SELECT 1"}}, "control"},
		{"bidi override", Options{DBPaths: map[string]string{"linux": "/x\u202e/state.db"}}, "formatting"},
		{"nul", Options{BinPaths: map[string]string{"linux": "/usr/bin/sp\x00oor"}}, "control"},
		{"invalid utf-8", Options{DBPaths: map[string]string{"linux": "/x/\xff.db"}}, "UTF-8"},
		{"too long", Options{DBPaths: map[string]string{"linux": long}}, "longer"},
		{"empty", Options{BinPaths: map[string]string{"linux": ""}}, "empty"},
		{"backslash on posix", Options{DBPaths: map[string]string{"linux": `/x\y`}}, "POSIX"},
		{"windows relative", Options{DBPaths: map[string]string{"windows": `ProgramData\spoor\state.db`}}, "Windows"},
		{"windows dotdot", Options{DBPaths: map[string]string{"windows": `C:\ProgramData\..\Windows\x.db`}}, "Windows"},
		{"windows posix", Options{BinPaths: map[string]string{"windows": "/usr/bin/spoor"}}, "Windows"},
		{"unknown platform", Options{DBPaths: map[string]string{"freebsd": "/var/db/spoor.db"}}, "unknown platform"},
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

// TestCustomPaths is what `spoor export fleet` relies on: paths and windows
// given in Options reach the ATC blocks, the labels and the policies, and
// SQL quoting holds for a path with a quote in it.
func TestCustomPaths(t *testing.T) {
	o := Options{
		DBPaths:          map[string]string{"linux": "/srv/o'brien/state.db", "windows": `D:\spoor\state.db`},
		BinPaths:         map[string]string{"darwin": "/opt/spoor/bin/spoor"},
		AlertWindow:      45 * time.Minute,
		GuardWindow:      48 * time.Hour,
		MinBundleVersion: 17,
	}
	c := mustBuild(t, o)
	if p := c.ATC["linux"]["spoor_health"].(map[string]any)["path"]; p != "/srv/o'brien/state.db" {
		t.Errorf("linux ATC path %v", p)
	}
	if p := c.ATC["windows"]["spoor_agents"].(map[string]any)["path"]; p != `D:\spoor\state.db` {
		t.Errorf("windows ATC path %v", p)
	}
	if p := c.ATC["darwin"]["spoor_agents"].(map[string]any)["path"]; p != DefaultDBPaths()["darwin"] {
		t.Errorf("darwin ATC path %v, want the default", p)
	}
	stock := mustProfile(t, c, ProfileStock)
	if q := stock.Labels[0].Query; !strings.Contains(q, "'/srv/o''brien/state.db'") || !strings.Contains(q, "'/opt/spoor/bin/spoor'") {
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
	if !labelResults(e, stock)["spoor installed"] {
		t.Error("installed label with a quoted custom path does not match")
	}
	// Defaults are not mutated by a custom build.
	if DefaultDBPaths()["linux"] != "/var/lib/spoor/state.db" {
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
		if !strings.HasPrefix(p.Query, "SELECT 1 WHERE EXISTS (SELECT 1 FROM spoor_health WHERE heartbeat >= ") {
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
