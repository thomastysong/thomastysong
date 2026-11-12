package catalog

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// Bounds on individual values. They exist so that an overlay file cannot
// make lookups expensive or smuggle multi-megabyte strings into inventory
// events.
const (
	maxListLen     = 256
	maxStringLen   = 512
	maxNotesLen    = 4096
	maxPatternLen  = 256
	maxProcessArgs = 16
	maxErrors      = 40
)

// The validation patterns are compiled on first use, not at package init:
// every process that links the catalog (the hook included, twice per hooked
// event) would otherwise pay for them, and only catalog loading needs them.
var (
	idRe       = lazyRegexp(`^[a-z][a-z0-9._-]{0,63}$`)
	versionRe  = lazyRegexp(`^[0-9A-Za-z][0-9A-Za-z.+_-]{0,31}$`)
	slugRe     = lazyRegexp(`^[a-z0-9][a-z0-9_.-]{0,63}$`)
	envNameRe  = lazyRegexp(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
	chromeIDRe = lazyRegexp(`^[a-p]{32}$`)
	extIDRe    = lazyRegexp(`^[A-Za-z0-9][A-Za-z0-9-]*\.[A-Za-z0-9][A-Za-z0-9._-]*$`)
	hostRe     = lazyRegexp(`^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
	teamIDRe   = lazyRegexp(`^[A-Z0-9]{10}$`)
	flagRe     = lazyRegexp(`^--?[A-Za-z0-9][A-Za-z0-9_-]*( [^\s]+)?$`)
)

// lazyRegexp returns a function that compiles pattern once, on first call.
func lazyRegexp(pattern string) func() *regexp.Regexp {
	return sync.OnceValue(func() *regexp.Regexp { return regexp.MustCompile(pattern) })
}

// errList collects validation errors up to a cap, so one broken file is
// reported in full without producing an unbounded message.
type errList struct {
	errs    []error
	dropped int
}

func (l *errList) addf(format string, a ...any) {
	if len(l.errs) >= maxErrors {
		l.dropped++
		return
	}
	l.errs = append(l.errs, fmt.Errorf(format, a...))
}

func (l *errList) err() error {
	if len(l.errs) == 0 {
		return nil
	}
	errs := l.errs
	if l.dropped > 0 {
		errs = append(errs, fmt.Errorf("catalog: %d more errors not shown", l.dropped))
	}
	return errors.Join(errs...)
}

// validateProduct checks one product in isolation.
func validateProduct(p *Product, l *errList) {
	bad := func(format string, a ...any) {
		l.addf("catalog: product %q: "+format, append([]any{p.ID}, a...)...)
	}
	if !idRe().MatchString(p.ID) {
		bad("id must match %s", idRe())
		return
	}
	if strings.TrimSpace(p.Name) == "" {
		bad("name is required")
	}
	if !productKinds[p.Kind] {
		bad("kind %q is not a catalogued asset kind", p.Kind)
	}
	if !statuses[p.Status] {
		bad("status %q must be active, deprecated or discontinued", p.Status)
	}
	checkText := func(field, s string, max int) {
		switch {
		case len(s) > max:
			bad("%s is longer than %d bytes", field, max)
		case !utf8.ValidString(s):
			bad("%s is not valid UTF-8", field)
		case strings.ContainsRune(s, 0):
			bad("%s contains a NUL byte", field)
		}
	}
	checkText("name", p.Name, maxStringLen)
	checkText("vendor", p.Vendor, maxStringLen)
	checkText("notes", p.Notes, maxNotesLen)

	// checkList applies the bounds every string list shares and returns
	// false when the list should not be inspected further.
	checkList := func(field string, list []string, each func(s string) string) {
		if len(list) > maxListLen {
			bad("%s has more than %d entries", field, maxListLen)
			return
		}
		seen := make(map[string]bool, len(list))
		for _, s := range list {
			if s == "" || strings.TrimSpace(s) != s {
				bad("%s has an empty or space-padded entry %q", field, s)
				continue
			}
			checkText(field, s, maxStringLen)
			if seen[s] {
				bad("%s lists %q twice", field, s)
			}
			seen[s] = true
			if each != nil {
				if msg := each(s); msg != "" {
					bad("%s: %q %s", field, s, msg)
				}
			}
		}
	}
	exeName := func(s string) string {
		switch {
		case strings.ContainsAny(s, `/\`):
			return "must be a basename, not a path"
		case strings.HasSuffix(strings.ToLower(s), ".exe"):
			return "must not include .exe"
		case genericNames[strings.ToLower(s)]:
			return "is a generic name that cannot identify a product"
		}
		return ""
	}
	envName := func(s string) string {
		if !envNameRe().MatchString(s) {
			return "is not an environment variable name"
		}
		return ""
	}
	// pathEntry accepts a location the scanner can resolve without a
	// working directory: home-relative, variable-rooted or absolute.
	// projectOK also admits "./x", relative to a project root.
	pathCheck := func(projectOK bool) func(string) string {
		return func(s string) string {
			switch {
			case len(s) > maxGlobLen:
				return "is too long"
			case hasDotDotElement(s):
				return "must not contain a .. element"
			case rootedPath(s):
				return ""
			case projectOK && strings.HasPrefix(s, "./"):
				return ""
			}
			if projectOK {
				return `must start with ~, a variable, / or a drive, or with ./ for a project-relative path`
			}
			return "must start with ~, a variable, / or a drive"
		}
	}
	pathEntry := pathCheck(false)
	checkPathsWith := func(field string, o OSPaths, each func(string) string) {
		checkList(field+".linux", o.Linux, each)
		checkList(field+".darwin", o.Darwin, each)
		checkList(field+".windows", o.Windows, each)
	}
	checkPaths := func(field string, o OSPaths) { checkPathsWith(field, o, pathEntry) }

	checkList("aliases", p.Aliases, nil)
	checkList("binaries", p.Binaries, exeName)
	checkList("process_names", p.ProcessNames, exeName)
	if len(p.ProcessArgs) > maxProcessArgs {
		bad("process_args has more than %d patterns", maxProcessArgs)
	}
	checkList("process_args", p.ProcessArgs, func(s string) string {
		if len(s) > maxPatternLen {
			return "is longer than the pattern limit"
		}
		re, err := regexp.Compile(s)
		if err != nil {
			return "is not a valid RE2 pattern: " + err.Error()
		}
		// A pattern that matches the empty string matches every process.
		if re.MatchString("") {
			return "matches the empty string"
		}
		return ""
	})
	checkList("packages", p.Packages, func(s string) string {
		mgr, name, ok := strings.Cut(s, ":")
		if !ok || name == "" {
			return `must be "<manager>:<name>"`
		}
		if _, known := managerCanon[mgr]; !known {
			return "uses an unknown package manager"
		}
		return ""
	})
	checkList("bundle_ids", p.BundleIDs, func(s string) string {
		if !strings.Contains(s, ".") || strings.ContainsAny(s, `/\ `) {
			return "is not a bundle identifier"
		}
		return ""
	})
	checkList("win_display", p.WinDisplay, func(s string) string {
		// Short substrings match unrelated software ("dia" in "NVIDIA").
		if len(strings.TrimSuffix(strings.TrimPrefix(s, "^"), "$")) < 3 {
			return "is too short to be a safe DisplayName pattern"
		}
		return ""
	})
	checkList("appx", p.Appx, nil)
	checkList("desktop_ids", p.DesktopIDs, nil)
	checkList("extension_ids", p.ExtensionIDs, func(s string) string {
		if !extIDRe().MatchString(s) {
			return `must be "publisher.name"`
		}
		return ""
	})
	checkList("jetbrains_ids", p.JetBrainsIDs, nil)
	checkList("chrome_ids", p.ChromeIDs, func(s string) string {
		if !chromeIDRe().MatchString(s) {
			return "is not a 32-letter Chromium extension id"
		}
		return ""
	})
	checkPaths("install_paths", p.InstallPaths)
	checkPaths("state_dirs", p.StateDirs)
	checkList("home_env", p.HomeEnv, envName)
	checkList("env_markers", p.EnvMarkers, envName)
	checkList("session_env", p.SessionEnv, envName)
	checkList("skills", p.Skills, pathCheck(true))
	checkList("rules", p.Rules, pathCheck(true))
	checkList("plugins", p.Plugins, pathCheck(true))
	checkList("subagents", p.Subagents, pathCheck(true))
	checkList("commands", p.Commands, pathCheck(true))
	checkList("risky_flags", p.RiskyFlags, func(s string) string {
		if !flagRe().MatchString(s) {
			return `must be "--flag" or "--flag value"`
		}
		return ""
	})
	checkList("api_hosts", p.APIHosts, func(s string) string {
		if !hostRe().MatchString(s) {
			return "is not a lowercase host name"
		}
		return ""
	})
	checkList("capabilities", p.Capabilities, func(s string) string {
		if !capabilities[s] {
			return "is not in the capability vocabulary"
		}
		return ""
	})
	checkList("sources", p.Sources, func(s string) string {
		if !strings.HasPrefix(s, "https://") && !strings.HasPrefix(s, "research:") && !strings.HasPrefix(s, "repo:") {
			return "must be an https URL, or a research: or repo: reference"
		}
		return ""
	})
	checkList("unverified", p.Unverified, func(s string) string {
		top, _, _ := strings.Cut(s, ".")
		if !productFields[top] {
			return "does not name a product field"
		}
		return ""
	})
	if len(p.Ports) > maxListLen {
		bad("ports has more than %d entries", maxListLen)
	}
	for _, port := range p.Ports {
		if port < 1 || port > 65535 {
			bad("port %d is out of range", port)
		}
	}
	if len(p.MCP) > maxListLen {
		bad("mcp has more than %d entries", maxListLen)
	}
	for i, m := range p.MCP {
		field := fmt.Sprintf("mcp[%d]", i)
		if m.Paths.IsZero() && len(m.ProjectPaths) == 0 {
			bad("%s has neither paths nor project_paths", field)
		}
		if !mcpFormats[m.Format] {
			bad("%s.format %q is not an mcpconf format", field, m.Format)
		}
		if !scopes[m.Scope] {
			bad("%s.scope %q is not a scope", field, m.Scope)
		}
		checkPaths(field+".paths", m.Paths)
		checkList(field+".project_paths", m.ProjectPaths, relPath)
	}
	if t := p.Transcript; t != nil {
		if !slugRe().MatchString(t.Format) {
			bad("transcript.format %q must be a lowercase slug", t.Format)
		}
		if t.Globs.IsZero() {
			bad("transcript has no globs")
		}
		// "./x" is allowed: Aider writes its history into the project.
		checkPathsWith("transcript.globs", t.Globs, pathCheck(true))
		if t.HomeEnv != "" && !envNameRe().MatchString(t.HomeEnv) {
			bad("transcript.home_env %q is not an environment variable name", t.HomeEnv)
		}
	}
	if h := p.Hooks; h != nil {
		if !hookDialects[h.Dialect] {
			bad("hooks.dialect %q is not one of claude, codex, copilot, gemini, cursor", h.Dialect)
		}
		if h.ManagedPaths.IsZero() && h.UserPaths.IsZero() && len(h.ProjectPaths) == 0 {
			bad("hooks lists no paths")
		}
		checkPaths("hooks.managed_paths", h.ManagedPaths)
		checkPaths("hooks.user_paths", h.UserPaths)
		checkList("hooks.project_paths", h.ProjectPaths, relPath)
		checkText("hooks.notes", h.Notes, maxNotesLen)
	}
	if len(p.Settings) > maxListLen {
		bad("settings has more than %d entries", maxListLen)
	}
	for i, s := range p.Settings {
		field := fmt.Sprintf("settings[%d]", i)
		if !settingFormats[s.Format] {
			bad("%s.format %q is not supported", field, s.Format)
		}
		if !settingOps[s.Op] {
			bad("%s.op %q must be eq, ne, exists, contains or in", field, s.Op)
		}
		if s.Key == "" {
			bad("%s.key is required", field)
		} else if _, err := splitKey(s.Key); err != nil {
			bad("%s.key: %v", field, err)
		}
		if s.Op != "exists" && s.Value == "" {
			bad("%s.value is required for op %q", field, s.Op)
		}
		// A value on an exists probe is a copy-paste or YAML-merge leftover
		// and would be reported as the "expected" value of the check.
		if s.Op == "exists" && s.Value != "" {
			bad("%s.value must be empty for op exists", field)
		}
		if !slugRe().MatchString(s.Flag) {
			bad("%s.flag %q must be a lowercase slug", field, s.Flag)
		}
		if s.Severity != "" && event.SeverityRank(s.Severity) == 0 {
			bad("%s.severity %q is not a severity", field, s.Severity)
		}
		switch s.Format {
		case "env":
			if !envNameRe().MatchString(s.Key) {
				bad("%s.key %q must be an environment variable name for format env", field, s.Key)
			}
			if !s.File.IsZero() {
				bad("%s.file is not used for format env", field)
			}
		case "registry":
			if len(s.File.Windows) == 0 || len(s.File.Linux)+len(s.File.Darwin) > 0 {
				bad("%s.file must list windows registry keys only", field)
			}
		case "plist":
			if len(s.File.Darwin) == 0 || len(s.File.Linux)+len(s.File.Windows) > 0 {
				bad("%s.file must list darwin plist paths only", field)
			}
		default:
			if s.File.IsZero() {
				bad("%s.file is required for format %q", field, s.Format)
			}
		}
		if s.Format == "registry" {
			checkList(field+".file.windows", s.File.Windows, func(k string) string {
				if !strings.HasPrefix(k, `HKLM\`) && !strings.HasPrefix(k, `HKCU\`) && !strings.HasPrefix(k, `HKU\`) {
					return `must be a registry key under HKLM\, HKCU\ or HKU\`
				}
				return ""
			})
		} else {
			checkPathsWith(field+".file", s.File, pathCheck(true))
		}
		checkText(field+".value", s.Value, maxStringLen)
	}
	if id := p.Signers.DarwinTeamID; id != "" && !teamIDRe().MatchString(id) {
		bad("signers.darwin_team_id %q is not a 10-character team id", id)
	}
	checkText("signers.windows_publisher", p.Signers.WindowsPublisher, maxStringLen)

	if !hasFingerprint(p) {
		bad("has no fingerprint: set at least one of binaries, process_names, process_args, packages, bundle_ids, win_display, appx, desktop_ids, extension_ids, jetbrains_ids, chrome_ids, install_paths or state_dirs")
	}
}

// hasFingerprint reports whether a scanner could ever find the product.
func hasFingerprint(p *Product) bool {
	return len(p.Binaries)+len(p.ProcessNames)+len(p.ProcessArgs)+len(p.Packages)+
		len(p.BundleIDs)+len(p.WinDisplay)+len(p.Appx)+len(p.DesktopIDs)+
		len(p.ExtensionIDs)+len(p.JetBrainsIDs)+len(p.ChromeIDs) > 0 ||
		!p.InstallPaths.IsZero() || !p.StateDirs.IsZero()
}

// rootedPath reports whether a catalog path starts at a known place: the
// home, a variable, the filesystem root, a Windows drive or a UNC share.
func rootedPath(s string) bool {
	switch {
	case s == "~", strings.HasPrefix(s, "~/"), strings.HasPrefix(s, `~\`):
		return true
	case strings.HasPrefix(s, "/"), strings.HasPrefix(s, `\\`):
		return true
	case strings.HasPrefix(s, "$"), strings.HasPrefix(s, "%"):
		return true
	case len(s) >= 3 && isAlpha(s[0]) && s[1] == ':' && (s[2] == '\\' || s[2] == '/'):
		return true
	}
	return false
}

func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

func hasDotDotElement(s string) bool {
	for _, el := range strings.FieldsFunc(s, func(r rune) bool { return r == '/' || r == '\\' }) {
		if el == ".." {
			return true
		}
	}
	return false
}

// relPath validates a project-relative path: the scanner joins it to a
// project root, so it must not be able to climb out of that root.
func relPath(s string) string {
	switch {
	case len(s) > maxGlobLen:
		return "is too long"
	case strings.HasPrefix(s, "/") || strings.HasPrefix(s, `\`) || strings.HasPrefix(s, "~"):
		return "must be relative to the project root"
	case len(s) > 1 && s[1] == ':':
		return "must be relative to the project root"
	case strings.ContainsAny(s, "$%"):
		return "must not use variables"
	case hasDotDotElement(s):
		return "must not contain a .. element"
	}
	return ""
}

// claim is one exclusive fingerprint: class plus normalized value.
type claim struct{ class, value string }

// claims lists the fingerprints a product asserts as its own. Ports, API
// hosts and environment markers are deliberately absent: they are shared by
// nature and are never identity on their own.
func claims(p *Product) []claim {
	var out []claim
	add := func(class, v string) { out = append(out, claim{class, v}) }
	for _, s := range p.Binaries {
		add("executable name", exeKey(s))
	}
	for _, s := range p.ProcessNames {
		add("executable name", exeKey(s))
	}
	for _, s := range p.Packages {
		add("package", packageKey(s))
	}
	for _, s := range p.BundleIDs {
		add("bundle id", strings.ToLower(s))
	}
	for _, s := range p.WinDisplay {
		add("windows display name", strings.ToLower(s))
	}
	for _, s := range p.Appx {
		add("appx name", strings.ToLower(s))
	}
	for _, s := range p.DesktopIDs {
		add("desktop id", strings.ToLower(s))
	}
	for _, s := range p.ExtensionIDs {
		add("extension id", strings.ToLower(s))
	}
	for _, s := range p.JetBrainsIDs {
		add("jetbrains plugin id", strings.ToLower(s))
	}
	for _, s := range p.ChromeIDs {
		add("chrome extension id", s)
	}
	for _, op := range p.StateDirs.all() {
		add("state directory", pathKey(op))
	}
	for _, op := range p.InstallPaths.all() {
		add("install path", pathKey(op))
	}
	return out
}

// pathKey normalizes a path claim. The same string on two OSes is the same
// claim: "~/.codex" means one thing everywhere.
func pathKey(op osPath) string {
	p := strings.TrimRight(slashed(op.path), "/")
	if op.os != "linux" {
		p = strings.ToLower(p)
	}
	return p
}

// packageKey normalizes "<mgr>:<name>" to "<ecosystem>:<name>".
func packageKey(s string) string {
	mgr, name, _ := strings.Cut(s, ":")
	return packageKeyParts(mgr, name)
}

func packageKeyParts(mgr, name string) string {
	eco, ok := managerCanon[strings.ToLower(strings.TrimSpace(mgr))]
	if !ok {
		eco = strings.ToLower(mgr)
	}
	name = strings.ToLower(strings.TrimSpace(name))
	if eco == "pypi" {
		// PEP 503: runs of -, _ and . are equivalent in project names.
		name = pep503(name)
	}
	return eco + ":" + name
}

func pep503(name string) string {
	var b strings.Builder
	prevSep := false
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c == '-' || c == '_' || c == '.' {
			if !prevSep {
				b.WriteByte('-')
			}
			prevSep = true
			continue
		}
		prevSep = false
		b.WriteByte(c)
	}
	return b.String()
}

// validateClaims enforces the shared-fingerprint rule across products.
func validateClaims(products []Product, l *errList) {
	owner := map[claim]int{}
	for i := range products {
		for _, c := range claims(&products[i]) {
			j, taken := owner[c]
			if !taken {
				owner[c] = i
				continue
			}
			if j == i {
				continue
			}
			if !lists(products[i].Aliases, products[j].ID) || !lists(products[j].Aliases, products[i].ID) {
				l.addf("catalog: %s %q is claimed by both %q and %q; if that is intended, each must list the other's id in aliases",
					c.class, c.value, products[j].ID, products[i].ID)
			}
		}
	}
}

func lists(aliases []string, id string) bool {
	for _, a := range aliases {
		if strings.EqualFold(a, id) {
			return true
		}
	}
	return false
}
