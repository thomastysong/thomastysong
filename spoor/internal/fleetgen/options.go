package fleetgen

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

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

// DefaultBinPaths returns where the spoor binary is installed on each
// operating system: the paths the service definitions in packaging/ start
// and the install scripts in deploy/fleet/scripts write.
func DefaultBinPaths() map[string]string {
	return map[string]string{
		PlatformLinux:   "/usr/bin/spoor",
		PlatformDarwin:  "/usr/local/bin/spoor",
		PlatformWindows: `C:\Program Files\spoor\spoor.exe`,
	}
}

// Options selects what Generate produces. The zero value gives the content
// committed under deploy/fleet/lib.
type Options struct {
	// DBPaths maps a platform (PlatformLinux ...) to the state database path
	// on hosts of that OS. Missing entries take DefaultDBPaths.
	DBPaths map[string]string
	// BinPaths maps a platform to the spoor binary path; with DBPaths it
	// decides membership of the "spoor installed" label. Missing entries
	// take DefaultBinPaths.
	BinPaths map[string]string
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
	binPaths         map[string]string
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
		binPaths:         DefaultBinPaths(),
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
	if err := overridePaths("state database", r.dbPaths, o.DBPaths); err != nil {
		return nil, err
	}
	if err := overridePaths("binary", r.binPaths, o.BinPaths); err != nil {
		return nil, err
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

// overridePaths validates and copies caller-supplied paths over defaults,
// in a fixed order so the first error reported does not depend on map
// iteration.
func overridePaths(what string, dst, src map[string]string) error {
	keys := make([]string, 0, len(src))
	for k := range src {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, p := range keys {
		if !isPlatform(p) {
			return fmt.Errorf("fleetgen: unknown platform %q for the %s path (want linux, darwin or windows)", p, what)
		}
		if err := checkHostPath(what, p, src[p]); err != nil {
			return err
		}
		dst[p] = src[p]
	}
	return nil
}

func isPlatform(p string) bool {
	for _, q := range Platforms {
		if p == q {
			return true
		}
	}
	return false
}

// checkHostPath accepts an absolute path for the target OS. The path ends
// up in YAML, in an SQL string literal and in osquery's ATC loader, so
// control and invisible formatting characters and invalid UTF-8 are refused
// outright, and so is %, which ATC and osquery's file table treat as a
// wildcard while the "installed" label compares paths exactly.
func checkHostPath(what, platform, path string) error {
	if path == "" {
		return fmt.Errorf("fleetgen: empty %s path for %s", what, platform)
	}
	if len(path) > 1024 {
		return fmt.Errorf("fleetgen: %s path for %s is longer than 1024 bytes", what, platform)
	}
	if !utf8.ValidString(path) {
		return fmt.Errorf("fleetgen: %s path for %s is not valid UTF-8", what, platform)
	}
	for _, r := range path {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' {
			return fmt.Errorf("fleetgen: %s path for %s contains a control or formatting character", what, platform)
		}
	}
	if strings.ContainsRune(path, '%') {
		return fmt.Errorf("fleetgen: %s path for %s contains %%, which osquery treats as a wildcard", what, platform)
	}
	if platform == PlatformWindows {
		if !windowsAbs(path) {
			return fmt.Errorf("fleetgen: %s path %q is not an absolute Windows path", what, path)
		}
		return nil
	}
	if !strings.HasPrefix(path, "/") || strings.ContainsRune(path, '\\') {
		return fmt.Errorf("fleetgen: %s path %q is not an absolute POSIX path", what, path)
	}
	for _, el := range strings.Split(path, "/") {
		if el == ".." || el == "." {
			return fmt.Errorf("fleetgen: %s path %q is not clean", what, path)
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
		if el == ".." || el == "." {
			return false
		}
	}
	return true
}

func isLetter(b byte) bool { return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') }
