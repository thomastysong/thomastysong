package fleetgen

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/thomastysong/spoor/internal/catalog"
)

// Operating systems that get an ATC block, in output order. The values are
// both osquery's ATC "platform" match strings and Fleet's
// overrides.platforms keys ("SELECT platform FROM os_version" reports
// darwin and windows; Linux distributions report their own names and so
// read the base config, which is why linux goes there).
const (
	PlatformLinux   = "linux"
	PlatformDarwin  = "darwin"
	PlatformWindows = "windows"
)

// Platforms lists the operating systems content is generated for.
var Platforms = []string{PlatformLinux, PlatformDarwin, PlatformWindows}

// fleetPlatforms is the "platform" value of policies and reports.
const fleetPlatforms = "darwin,linux,windows"

const (
	// DefaultAlertWindow is the heartbeat age the "sensor is reporting"
	// policy and the "sensor unhealthy" label accept: six missed beats at
	// the daemon's default five-minute interval.
	DefaultAlertWindow = 30 * time.Minute
	// DefaultGuardWindow is the heartbeat age every other spoor policy
	// accepts before it fails closed.
	DefaultGuardWindow = 24 * time.Hour
	// DefaultMinBundleVersion is the lowest signed content bundle version the
	// "rules bundle is current" policy accepts: any installed bundle.
	DefaultMinBundleVersion = 1
)

// DefaultDBPaths returns the state database location of a system install on
// each operating system. They mirror platform.DefaultDirs().StateDB, which
// can only be computed for the running OS; a test holds the two together.
func DefaultDBPaths() map[string]string {
	return map[string]string{
		PlatformLinux:   "/var/lib/spoor/state.db",
		PlatformDarwin:  "/Library/Application Support/spoor/state.db",
		PlatformWindows: `C:\ProgramData\spoor\state.db`,
	}
}

// Options selects what Generate produces. The zero value gives the content
// committed under deploy/fleet/lib.
type Options struct {
	// DBPaths maps a platform (PlatformLinux ...) to the state database path
	// on hosts of that OS. Missing entries take DefaultDBPaths.
	DBPaths map[string]string
	// AlertWindow is the heartbeat age accepted by the "sensor is reporting"
	// policy and the "sensor unhealthy" label. Default DefaultAlertWindow.
	AlertWindow time.Duration
	// GuardWindow is the heartbeat age every other spoor policy accepts.
	// Default DefaultGuardWindow. It may not be shorter than AlertWindow.
	GuardWindow time.Duration
	// MinBundleVersion is the oldest signed content bundle the "rules bundle
	// is current" policy accepts. Default DefaultMinBundleVersion.
	MinBundleVersion uint64
	// Catalog supplies agent vocabulary. Nil loads the embedded catalog.
	Catalog *catalog.Catalog
}

// resolved is Options with defaults applied and checked.
type resolved struct {
	dbPaths          map[string]string
	alert, guard     time.Duration
	minBundleVersion uint64
	cat              *catalog.Catalog
}

// maxWindow bounds both windows: SQLTimeAgo counts seconds, and a window of
// years is a typo, not a policy.
const maxWindow = 30 * 24 * time.Hour

func (o Options) resolve() (*resolved, error) {
	r := &resolved{
		dbPaths:          DefaultDBPaths(),
		alert:            o.AlertWindow,
		guard:            o.GuardWindow,
		minBundleVersion: o.MinBundleVersion,
		cat:              o.Catalog,
	}
	if r.alert == 0 {
		r.alert = DefaultAlertWindow
	}
	if r.guard == 0 {
		r.guard = DefaultGuardWindow
	}
	if r.minBundleVersion == 0 {
		r.minBundleVersion = DefaultMinBundleVersion
	}
	switch {
	case r.alert < time.Minute || r.alert > maxWindow:
		return nil, fmt.Errorf("fleetgen: alert window %v outside 1m..%v", r.alert, maxWindow)
	case r.guard < time.Minute || r.guard > maxWindow:
		return nil, fmt.Errorf("fleetgen: guard window %v outside 1m..%v", r.guard, maxWindow)
	case r.guard < r.alert:
		return nil, fmt.Errorf("fleetgen: guard window %v is shorter than the alert window %v", r.guard, r.alert)
	case r.alert%time.Second != 0 || r.guard%time.Second != 0:
		return nil, errors.New("fleetgen: windows must be whole seconds")
	}
	// A bundle version is compared after CAST(... AS INTEGER), which is a
	// signed 64-bit value in SQLite.
	if r.minBundleVersion > 1<<62 {
		return nil, fmt.Errorf("fleetgen: minimum bundle version %d too large", r.minBundleVersion)
	}
	keys := make([]string, 0, len(o.DBPaths))
	for k := range o.DBPaths {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, p := range keys {
		path := o.DBPaths[p]
		if !isPlatform(p) {
			return nil, fmt.Errorf("fleetgen: unknown platform %q in DBPaths (want linux, darwin or windows)", p)
		}
		if err := checkDBPath(p, path); err != nil {
			return nil, err
		}
		r.dbPaths[p] = path
	}
	if r.cat == nil {
		c, err := catalog.Load()
		if err != nil {
			return nil, fmt.Errorf("fleetgen: load catalog: %w", err)
		}
		r.cat = c
	}
	return r, nil
}

func isPlatform(p string) bool {
	for _, q := range Platforms {
		if p == q {
			return true
		}
	}
	return false
}

// checkDBPath accepts an absolute path for the target OS. The path ends up
// in YAML, in an SQL string literal and in osquery's ATC loader, so control
// characters are refused outright, and so is %, which ATC would treat as a
// wildcard while the "installed" label compares the path exactly.
func checkDBPath(platform, path string) error {
	if path == "" {
		return fmt.Errorf("fleetgen: empty state database path for %s", platform)
	}
	if len(path) > 1024 {
		return fmt.Errorf("fleetgen: state database path for %s is longer than 1024 bytes", platform)
	}
	for _, r := range path {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' || r == '\ufeff' {
			return fmt.Errorf("fleetgen: state database path for %s contains a control character", platform)
		}
	}
	if strings.ContainsRune(path, '%') {
		return fmt.Errorf("fleetgen: state database path for %s contains %%, which ATC treats as a wildcard", platform)
	}
	if platform == PlatformWindows {
		if !windowsAbs(path) {
			return fmt.Errorf("fleetgen: state database path %q is not an absolute Windows path", path)
		}
		return nil
	}
	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("fleetgen: state database path %q is not absolute", path)
	}
	for _, el := range strings.Split(path, "/") {
		if el == ".." {
			return fmt.Errorf("fleetgen: state database path %q contains ..", path)
		}
	}
	return nil
}

// windowsAbs accepts C:\dir\file and \\server\share\file.
func windowsAbs(p string) bool {
	switch {
	case len(p) >= 3 && isLetter(p[0]) && p[1] == ':' && (p[2] == '\\' || p[2] == '/'):
	case strings.HasPrefix(p, `\\`) && len(p) > 2:
	default:
		return false
	}
	for _, el := range strings.FieldsFunc(p, func(r rune) bool { return r == '\\' || r == '/' }) {
		if el == ".." {
			return false
		}
	}
	return true
}

func isLetter(b byte) bool { return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') }
