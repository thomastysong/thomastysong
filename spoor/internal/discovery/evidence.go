package discovery

import (
	"sort"
	"strconv"
	"strings"

	"github.com/thomastysong/spoor/internal/catalog"
	"github.com/thomastysong/spoor/internal/event"
)

// Evidence classes recorded in Asset.Evidence. They fall into independent
// channels; Confidence "high" needs two channels, as the event contract
// asks ("two independent classes").
const (
	evPackage   = "package:" // + manager: npm, pipx, uv, brew, cask ...
	evBundleID  = "bundle_id"
	evDesktopID = "desktop_id"
	evRegistry  = "registry"
	evExtension = "extension_id"
	evJetBrains = "jetbrains_id"
	evPath      = "path"      // a catalogued install path exists
	evBinary    = "binary"    // the product's executable is in a well-known bin directory
	evStateDir  = "state_dir" // the product's state directory exists
	evProcess   = "process"   // a running process matched the product
)

func channelOf(class string) string {
	switch {
	case strings.HasPrefix(class, evPackage), class == evBundleID, class == evDesktopID,
		class == evRegistry, class == evExtension, class == evJetBrains:
		return "installer"
	case class == evPath, class == evBinary:
		return "filesystem"
	case class == evStateDir:
		return "state"
	case class == evProcess:
		return "runtime"
	}
	return class
}

// Path and version preference: the most specific source wins.
const (
	rankState   = 1
	rankBinary  = 2
	rankInstall = 3
	rankPackage = 4

	vrankLayout   = 1 // a version-shaped directory name in an install layout
	vrankCellar   = 2
	vrankManifest = 3 // package.json, Info.plist, registry, dist-info
)

// evidence accumulates what was seen of one product for one owner.
type evidence struct {
	classes  map[string]bool
	weak     map[string]bool // classes that do not identify on their own
	path     string
	pathRank int
	version  string
	verRank  int
	pids     []int
}

func (e *evidence) add(class string, weak bool) {
	if e.classes == nil {
		e.classes = map[string]bool{}
		e.weak = map[string]bool{}
	}
	if weak {
		if !e.classes[class] {
			e.weak[class] = true
		}
		e.classes[class] = true
		return
	}
	e.classes[class] = true
	delete(e.weak, class)
}

func (e *evidence) setPath(p string, rank int) {
	if p != "" && rank > e.pathRank {
		e.path, e.pathRank = p, rank
	}
}

func (e *evidence) setVersion(v string, rank int) {
	v = safeVersion(v)
	if v != "" && rank > e.verRank {
		e.version, e.verRank = v, rank
	}
}

func (e *evidence) empty() bool { return e == nil || len(e.classes) == 0 }

// merge combines machine-wide and per-user evidence.
func mergeEvidence(parts ...*evidence) *evidence {
	out := &evidence{}
	for _, p := range parts {
		if p == nil {
			continue
		}
		for c := range p.classes {
			out.add(c, p.weak[c])
		}
		out.setPath(p.path, p.pathRank)
		if p.verRank > out.verRank {
			out.version, out.verRank = p.version, p.verRank
		}
		out.pids = append(out.pids, p.pids...)
	}
	return out
}

// qualifies decides whether the evidence identifies the product at all. A
// weak class (an ambiguous binary name such as goose or q in a bin
// directory, a state directory several products share) needs a second
// class from another channel.
func (e *evidence) qualifies() bool {
	if e.empty() {
		return false
	}
	weakChannels := map[string]bool{}
	for c := range e.classes {
		if !e.weak[c] {
			return true
		}
		weakChannels[channelOf(c)] = true
	}
	return len(weakChannels) >= 2
}

func (e *evidence) channels() int {
	ch := map[string]bool{}
	for c := range e.classes {
		ch[channelOf(c)] = true
	}
	return len(ch)
}

func (e *evidence) confidence() string {
	n := e.channels()
	switch {
	case n >= 2:
		return "high"
	case e.classes[evStateDir] && len(e.classes) == 1:
		return "low"
	default:
		return "medium"
	}
}

func (e *evidence) list() []string {
	out := make([]string, 0, len(e.classes))
	for c := range e.classes {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// hostKinds are catalogued kinds that are installed on the host (as
// opposed to editor extensions, found in extension directories, and CI
// agents, found in workflow files).
func hostKind(p *catalog.Product) bool {
	switch event.AssetKind(p.Kind) {
	case event.AssetIDEExtension, event.AssetBrowserExtension, event.AssetCIAgent:
		return false
	}
	return true
}

// versionLike reports whether a directory or file name looks like a
// version ("2.1.3", "1.0.0-beta.2", "v0.9").
func versionLike(s string) bool {
	s = strings.TrimPrefix(s, "v")
	if s == "" || s[0] < '0' || s[0] > '9' {
		return false
	}
	return safeVersion(s) != "" && strings.Contains(s, ".")
}

// compareVersions orders dotted versions numerically where it can.
func compareVersions(a, b string) int {
	as := strings.FieldsFunc(a, func(r rune) bool { return r == '.' || r == '-' || r == '_' || r == '+' })
	bs := strings.FieldsFunc(b, func(r rune) bool { return r == '.' || r == '-' || r == '_' || r == '+' })
	for i := 0; i < len(as) && i < len(bs); i++ {
		ai, aerr := strconv.Atoi(as[i])
		bi, berr := strconv.Atoi(bs[i])
		if aerr == nil && berr == nil {
			if ai != bi {
				if ai < bi {
					return -1
				}
				return 1
			}
			continue
		}
		if c := strings.Compare(as[i], bs[i]); c != 0 {
			return c
		}
	}
	switch {
	case len(as) < len(bs):
		return -1
	case len(as) > len(bs):
		return 1
	}
	return 0
}

// pep503 normalizes a Python distribution name.
func pep503(name string) string {
	var b strings.Builder
	prevSep := false
	for _, c := range strings.ToLower(name) {
		if c == '-' || c == '_' || c == '.' {
			if !prevSep {
				b.WriteByte('-')
			}
			prevSep = true
			continue
		}
		prevSep = false
		b.WriteRune(c)
	}
	return b.String()
}
