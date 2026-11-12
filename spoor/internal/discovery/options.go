package discovery

import (
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/thomastysong/spoor/internal/catalog"
	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/platform"
)

// Defaults applied when an Options field is zero.
const (
	DefaultMaxProjects = 200
	DefaultDeadline    = 60 * time.Second
)

// Options configures Scan and ScanProject.
type Options struct {
	Catalog *catalog.Catalog
	// Users are the homes to inspect. Empty means platform.Users() (every
	// person's home when privileged, only the caller's otherwise), or, with
	// HostRoot set, the accounts in the root's own /etc/passwd. Homes are
	// paths as seen inside HostRoot.
	Users []platform.UserHome
	// HostRoot is "" or a prefix such as /host or /proc/<pid>/root for
	// container scans. Every path is then resolved inside it and no symlink
	// may lead out of it.
	HostRoot string
	// Projects enumerates project directories from each agent's own state
	// (never by crawling the disk) and scans their control files.
	Projects bool
	// MaxProjects bounds the projects scanned per user, most recently used
	// first. Default 200.
	MaxProjects int
	// Deadline bounds the whole scan. Default 60s. Partial results are
	// returned with Ledger.Truncated set.
	Deadline time.Duration
	// Processes is an optional process snapshot used to mark agents running.
	Processes []platform.Proc
	// Container is stamped on every record when scanning a container root.
	Container *event.Container

	// Prev maps asset id to the SHA256 last reported for it (state.Snapshot).
	// With Prev set, assets carry Change new or changed, assets missing from
	// a complete scan are returned with Change removed, and unchanged assets
	// are returned only when Full is set.
	Prev map[string]string
	// Full returns unchanged assets too (Change unchanged): the daily
	// snapshot that lets downstream rebuild state from scratch.
	Full bool

	// Host is stamped on every record and its ID scopes AssetID. Nil means
	// platform.HostInfo().
	Host *event.Host
	// Env returns the environment to expand catalog paths with for one user
	// (CLAUDE_CONFIG_DIR, CODEX_HOME ...). Nil means none: catalog defaults
	// apply and a relocated state directory is reported as not found. The
	// values are used to build paths only, never emitted.
	Env func(u platform.UserHome) map[string]string
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// Ledger is the coverage statement that travels with a result. "Not
// collected" must never read as "clean": every refusal, skip and error is
// counted, and Truncated says the scan stopped before it was complete.
type Ledger struct {
	Roots, Files, Denied, Skipped, Errors int
	Truncated                             bool
	Notes                                 []string
}

// Result is what a scan returns.
type Result struct {
	Events []*event.Event
	Ledger Ledger
}

// maxNotes bounds Ledger.Notes: a hostile tree can produce a refusal per
// entry, and the ledger travels with every result.
const maxNotes = 200

// ledger is the scan-internal, concurrency-safe view of a Ledger.
type ledger struct {
	mu      sync.Mutex
	l       Ledger
	seen    map[string]bool
	dropped int
}

func newLedger() *ledger { return &ledger{seen: map[string]bool{}} }

func (g *ledger) add(field *int, n int) {
	g.mu.Lock()
	*field += n
	g.mu.Unlock()
}

func (g *ledger) root()    { g.add(&g.l.Roots, 1) }
func (g *ledger) file()    { g.add(&g.l.Files, 1) }
func (g *ledger) denied()  { g.add(&g.l.Denied, 1) }
func (g *ledger) skipped() { g.add(&g.l.Skipped, 1) }
func (g *ledger) errored() { g.add(&g.l.Errors, 1) }

func (g *ledger) truncate(note string) {
	g.mu.Lock()
	g.l.Truncated = true
	g.mu.Unlock()
	g.note(note)
}

// note records a deduplicated, bounded, secret-free remark. Notes name
// paths and reasons; they never carry file content.
func (g *ledger) note(s string) {
	s = safeText(s, 300)
	if s == "" {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.seen[s] {
		return
	}
	g.seen[s] = true
	if len(g.l.Notes) >= maxNotes {
		g.dropped++
		return
	}
	g.l.Notes = append(g.l.Notes, s)
}

func (g *ledger) snapshot() Ledger {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := g.l
	out.Notes = append([]string(nil), g.l.Notes...)
	if g.dropped > 0 {
		out.Notes = append(out.Notes, "further notes dropped: "+itoa(g.dropped))
	}
	return out
}

// flagSet keeps risk flags unique and sorted.
type flagSet map[string]bool

func (f flagSet) add(flags ...string) {
	for _, x := range flags {
		if x != "" {
			f[x] = true
		}
	}
}

func (f flagSet) list() []string {
	if len(f) == 0 {
		return nil
	}
	out := make([]string, 0, len(f))
	for k := range f {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func mergeFlags(a []string, b ...string) []string {
	fs := flagSet{}
	fs.add(a...)
	fs.add(b...)
	return fs.list()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}
