package procmon

import (
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/thomastysong/spoor/internal/catalog"
	"github.com/thomastysong/spoor/internal/event"
)

// prodInfo is the part of a catalog product the monitor needs on its hot
// path, copied once per catalog version.
type prodInfo struct {
	id, name, kind string
	sessionEnv     []string
	homeEnv        []string
	dialect        string
}

func (p *prodInfo) isAgent() bool { return p != nil && p.kind == string(event.AssetAgent) }

// catIndex maps environment variable names to the products that set them.
type catIndex struct {
	version string
	count   int
	prods   map[string]*prodInfo
	// marker maps an EnvMarkers or SessionEnv name to the product it marks.
	// When several products list a name, an agent wins over an app, then
	// catalog order decides.
	marker map[string]string
	// strong names are the ones the agent itself sets for its children and
	// that the catalog has verified: SessionEnv of agents, and EnvMarkers of
	// agents whose env_markers field is not marked unverified. Only these
	// can turn an unidentified parent into an agent root; a user-exported
	// switch such as COPILOT_MODEL appears in every process of a shell.
	strong map[string]bool
	// keep is every variable name the monitor reads a value or presence
	// from; the rest of an environment is skipped while parsing.
	keep map[string]bool
}

func buildIndex(c *catalog.Catalog) *catIndex {
	ix := &catIndex{
		version: c.Version(),
		count:   c.Len(),
		prods:   map[string]*prodInfo{},
		marker:  map[string]string{},
		strong:  map[string]bool{},
		keep:    map[string]bool{},
	}
	for _, name := range envAlwaysKept {
		ix.keep[name] = true
	}
	for _, t := range traitsByAgent {
		for _, l := range [][]string{t.bareEnv, t.persistEnv} {
			for _, name := range l {
				ix.keep[name] = true
			}
		}
	}
	products := c.Products()
	for i := range products {
		p := &products[i]
		pi := &prodInfo{
			id:         p.ID,
			name:       p.Name,
			kind:       p.Kind,
			sessionEnv: append([]string(nil), p.SessionEnv...),
			homeEnv:    append([]string(nil), p.HomeEnv...),
		}
		if p.Hooks != nil {
			pi.dialect = p.Hooks.Dialect
		}
		ix.prods[p.ID] = pi
		for _, l := range [][]string{p.EnvMarkers, p.SessionEnv, p.HomeEnv} {
			for _, name := range l {
				ix.keep[name] = true
			}
		}
	}
	// Two passes so that agents claim shared names before apps do.
	for pass := 0; pass < 2; pass++ {
		for i := range products {
			p := &products[i]
			agent := p.Kind == string(event.AssetAgent)
			if agent != (pass == 0) {
				continue
			}
			for _, name := range p.MarkerEnv() {
				if _, dup := ix.marker[name]; !dup {
					ix.marker[name] = p.ID
				}
			}
			if !agent {
				continue
			}
			for _, name := range p.SessionEnv {
				ix.strong[name] = true
			}
			if !p.IsUnverified("env_markers") {
				for _, name := range p.EnvMarkers {
					ix.strong[name] = true
				}
			}
		}
	}
	return ix
}

func (ix *catIndex) prod(id string) *prodInfo { return ix.prods[id] }

// envAlwaysKept are read for LifecycleParent.
var envAlwaysKept = []string{"npm_lifecycle_event", "npm_config_user_agent", "npm_execpath"}

const (
	maxMarkers      = 16
	maxSessionLen   = 128
	maxConfigHome   = 1024
	maxEnvSessions  = 4
	maxSessionsKept = 16
)

// envFacts is what the monitor keeps from a process environment: marker
// names and the allowlisted values (session ids). The rest of the
// environment is dropped as soon as it has been scanned.
type envFacts struct {
	known   bool
	markers []string // catalog marker names present, sorted
	// product is the product the markers name ("" none); strong says it was
	// named by a strong marker.
	product  string
	strong   bool
	sessions []prodSession
}

type prodSession struct{ product, id string }

func (f *envFacts) session(product string) string {
	for _, s := range f.sessions {
		if s.product == product {
			return s.id
		}
	}
	return ""
}

func (f *envFacts) hasProduct(product string, ix *catIndex) bool {
	for _, m := range f.markers {
		if ix.marker[m] == product {
			return true
		}
	}
	return false
}

// scanEnv extracts envFacts from a raw environment.
func (ix *catIndex) scanEnv(env map[string]string) envFacts {
	f := envFacts{known: env != nil}
	if env == nil {
		return f
	}
	for name := range env {
		if _, ok := ix.marker[name]; ok && len(f.markers) < maxMarkers {
			f.markers = append(f.markers, name)
		}
	}
	sort.Strings(f.markers)
	// The product is chosen deterministically: strong names first, then
	// session variables, then name order.
	bestRank := 0
	for _, name := range f.markers {
		p := ix.marker[name]
		rank := 1
		if ix.strong[name] {
			rank = 3
		} else if pi := ix.prods[p]; pi != nil && pi.isAgent() {
			rank = 2
		}
		if rank > bestRank {
			bestRank, f.product, f.strong = rank, p, rank == 3
		}
	}
	// Session variables are tried in catalog order: the first one listed is
	// the one that equals the session id in the agent's hook payloads
	// (CLAUDE_CODE_SESSION_ID before the remote and bridge ids).
	for _, name := range f.markers {
		p := ix.marker[name]
		pi := ix.prods[p]
		if pi == nil || f.session(p) != "" || len(f.sessions) >= maxEnvSessions {
			continue
		}
		for _, sv := range pi.sessionEnv {
			if id := cleanSessionID(env[sv]); id != "" {
				f.sessions = append(f.sessions, prodSession{product: p, id: id})
				break
			}
		}
	}
	return f
}

// cleanSessionID keeps a session id only when it looks like one. Session ids
// are the one environment VALUE the monitor emits, so anything that is not a
// plain identifier (a path, a URL, a token pasted into the variable) is
// dropped rather than shipped.
func cleanSessionID(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || len(v) > maxSessionLen {
		return ""
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-', c == '_', c == '.', c == ':':
		default:
			return ""
		}
	}
	return v
}

// configHome returns the value of the first HomeEnv override present. The
// value is a directory path the agent was told to use instead of its default
// state directory; it is allowlisted for emission so that the transcript and
// config readers can follow it.
func configHome(homeEnv []string, env map[string]string) string {
	for _, name := range homeEnv {
		if v, ok := env[name]; ok {
			if v = cleanPath(v); v != "" {
				return v
			}
		}
	}
	return ""
}

// cleanPath bounds and validates a path-like value before it is kept.
func cleanPath(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || len(v) > maxConfigHome || !utf8.ValidString(v) {
		return ""
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x20 || v[i] == 0x7f {
			return ""
		}
	}
	return v
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}
