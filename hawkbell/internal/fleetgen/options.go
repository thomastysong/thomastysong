package fleetgen

import (
	"errors"
	"fmt"
	pathpkg "path"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/thomastysong/thomastysong/hawkbell/internal/catalog"
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
	// DefaultGuardWindow is the heartbeat age every other hawkbell policy
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
		PlatformLinux:   "/var/lib/hawkbell/state.db",
		PlatformDarwin:  "/Library/Application Support/hawkbell/state.db",
		PlatformWindows: `C:\ProgramData\hawkbell\state.db`,
	}
}

// DefaultBinPaths returns where the hawkbell binary is installed on each
// operating system: the paths the service definitions in packaging/ start
// and the install scripts in deploy/fleet/scripts write.
func DefaultBinPaths() map[string]string {
	return map[string]string{
		PlatformLinux:   "/usr/bin/hawkbell",
		PlatformDarwin:  "/usr/local/bin/hawkbell",
		PlatformWindows: `C:\Program Files\hawkbell\hawkbell.exe`,
	}
}

// Options selects what Generate produces. The zero value gives the content
// committed under deploy/fleet/lib.
type Options struct {
	// DBPaths maps a platform (PlatformLinux ...) to the state database path
	// on hosts of that OS. Missing entries take DefaultDBPaths.
	DBPaths map[string]string
	// BinPaths maps a platform to the hawkbell binary path; with DBPaths it
	// decides membership of the "hawkbell installed" label. Missing entries
	// take DefaultBinPaths.
	BinPaths map[string]string
	// AlertWindow is the heartbeat age accepted by the "sensor is reporting"
	// policy and the "sensor unhealthy" label. Default DefaultAlertWindow.
	AlertWindow time.Duration
	// GuardWindow is the heartbeat age every other hawkbell policy accepts.
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

// globMeta are the characters osquery expands in an ATC "path": % is
// osquery's own wildcard, and the rest is resolved with glob(3) and
// GLOB_BRACE (checked with osquery 5.19: "hawkbell?", "hawkbell[AB]" and
// "hawkbell{A,B}" each read several databases). The "installed" label compares
// paths exactly, so a pattern would make the two disagree.
const globMeta = "%*?[]{}"

// checkHostPath accepts an absolute, clean path for the target OS. The path
// ends up in YAML, in an SQL string literal and in osquery's ATC loader, so
// control and invisible formatting characters and invalid UTF-8 are refused
// outright, and so are osquery's wildcard and glob characters. It must be
// clean (no empty, "." or ".." element, no trailing separator) because ATC
// reports a canonical path while osquery's file table, which the
// "installed" label reads, reports the path exactly as written.
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
	if i := strings.IndexAny(path, globMeta); i >= 0 {
		return fmt.Errorf("fleetgen: %s path for %s contains %q, which osquery treats as a wildcard or glob pattern",
			what, platform, path[i])
	}
	if platform == PlatformWindows {
		if !windowsAbs(path) {
			return fmt.Errorf("fleetgen: %s path %q is not an absolute Windows path", what, path)
		}
		if !windowsClean(path) {
			return fmt.Errorf("fleetgen: %s path %q is not clean for Windows (backslashes only, one between "+
				"elements, no trailing backslash, no . or ..)", what, path)
		}
		return nil
	}
	if !strings.HasPrefix(path, "/") || strings.ContainsRune(path, '\\') {
		return fmt.Errorf("fleetgen: %s path %q is not an absolute POSIX path", what, path)
	}
	if path == "/" || pathpkg.Clean(path) != path {
		return fmt.Errorf("fleetgen: %s path %q is not clean (no //, . or .. element, no trailing /)", what, path)
	}
	return nil
}

// windowsAbs accepts C:\dir\file and \\server\share\file shapes.
func windowsAbs(p string) bool {
	switch {
	case len(p) >= 3 && isLetter(p[0]) && p[1] == ':' && (p[2] == '\\' || p[2] == '/'):
		return true
	case strings.HasPrefix(p, `\\`) && len(p) > 2:
		return true
	}
	return false
}

// windowsClean reports whether an absolute Windows path is in the form
// osquery's file table reports: backslash separators, no empty, "." or ".."
// element and no trailing separator. A UNC path needs a server and a share.
func windowsClean(p string) bool {
	if strings.ContainsRune(p, '/') {
		return false
	}
	var rest string
	minElems := 1
	if strings.HasPrefix(p, `\\`) {
		rest, minElems = p[2:], 3
	} else {
		rest = p[3:]
	}
	els := strings.Split(rest, `\`)
	if len(els) < minElems {
		return false
	}
	for _, el := range els {
		if el == "" || el == "." || el == ".." {
			return false
		}
	}
	return true
}

func isLetter(b byte) bool { return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') }
