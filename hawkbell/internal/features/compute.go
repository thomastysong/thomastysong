package features

import (
	"runtime"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// Context is what feature computation needs to know about the session that
// the event does not carry reliably. Empty fields fall back to the event
// (Session.CWD, Host.OS) and then to the running OS.
type Context struct{ Home, CWD, OS string }

// Cost bounds. Every input here is attacker-authored (a command line, a web
// page the agent fetched, a file it wrote), and Compute runs in the hook
// process that stands between the agent and its tool call.
const (
	// maxScan is the longest string scanned whole; longer ones are scanned
	// head scanHead + tail scanTail only and content.truncated_scan is set.
	maxScan  = 128 << 10
	scanHead = 64 << 10
	scanTail = 64 << 10

	// List caps. Each is at least the cap of the analyzer that feeds it
	// (shellx keeps 512 entries per list, 2048 commands per analysis and
	// 1024 arguments per command), so a list is cut here only when several
	// analyses were merged (head, tail and tail rescan of an oversized
	// command line) or an analyzer already stopped; shell.argv, the
	// flattened arguments of every command, is the exception (shell.cmds
	// keeps the structured form, which is what rules should use). A cut
	// keeps the first
	// and the last half, because a payload appended after padding sits at
	// the end, and it is never silent: the field is named in
	// content.truncated_fields (and shell.truncated is set for shell
	// features), which makes in_list and operator suppressions on it fail
	// closed.
	maxList   = 512  // entries kept in any derived []string feature
	maxArgv   = 4096 // entries in shell.argv
	maxCmds   = 4096 // entries in shell.cmds
	maxCmdArg = 1024 // args kept per shell.cmds entry, packages and flags per install entry

	// shellxListCap is shellx's own per-list cap. A Facts list that long may
	// have been cut by the analyzer without Facts.Truncated being set, so
	// it is treated as incomplete.
	shellxListCap = 512
)

// internalPrefix starts the Feat keys that are bookkeeping of this package
// rather than features; Fields leaves them out of the field view.
const internalPrefix = "features."

// computedKey marks a Feat map as filled. It is not part of the field view.
const computedKey = internalPrefix + "computed"

// Compute fills e.Feat with the features rules match on (see the package
// documentation for the vocabulary). It is idempotent: a second call on the
// same event returns immediately. Compute never panics: each analyzer runs
// behind a recover, and a failure sets content.analyzer_error instead of
// taking down the hook process (a crashed hook exits 2, which every agent
// reads as "block").
func Compute(e *event.Event, ctx Context) {
	if e == nil {
		return
	}
	if e.Feat != nil {
		if _, done := e.Feat[computedKey]; done {
			return
		}
	} else {
		e.Feat = make(map[string]any, 32)
	}
	c := &computer{e: e, f: e.Feat}
	c.ctx = ctx
	if c.ctx.CWD == "" && e.Session != nil {
		c.ctx.CWD = e.Session.CWD
	}
	if c.ctx.OS == "" && e.Host != nil {
		c.ctx.OS = e.Host.OS
	}
	if c.ctx.OS == "" {
		c.ctx.OS = runtime.GOOS
	}
	c.ctx.OS = strings.ToLower(c.ctx.OS)
	c.f[computedKey] = true
	c.run(c.shell)
	c.run(c.paths)
	c.run(c.mcp)
	c.run(c.network)
	c.run(c.content)
	c.finish()
}

// truncatedKey is the feature naming the incomplete list features.
const truncatedKey = "content.truncated_fields"

// markCut records that the feature key holds an incomplete value.
func (c *computer) markCut(key string) {
	if c.cut == nil {
		c.cut = map[string]bool{}
	}
	c.cut[key] = true
}

// finish publishes the truncation record: content.truncated_fields lists
// every incomplete feature (sorted), and an incomplete shell feature also
// sets shell.truncated, the one signal rules score for an analysis they
// cannot fully see.
func (c *computer) finish() {
	if len(c.cut) == 0 {
		return
	}
	keys := make([]string, 0, len(c.cut))
	for k := range c.cut {
		keys = append(keys, k)
		if strings.HasPrefix(k, "shell.") {
			c.f["shell.truncated"] = true
		}
	}
	sort.Strings(keys)
	c.f[truncatedKey] = keys
}

// computer carries one Compute call.
type computer struct {
	e   *event.Event
	f   map[string]any
	ctx Context
	// urls and hosts collected by the shell and MCP passes for the network
	// pass.
	urls  []string
	hosts []string
	// cut names the features whose value is incomplete; netCut says that
	// the hosts and URLs handed to the network pass are.
	cut    map[string]bool
	netCut bool
	// A written script's analysis (script.go) may know the credential
	// kinds of its text already (secrets), or skip the scan for the time
	// budget (secretsSkipped).
	secrets        *[]string
	secretsSkipped bool
}

func (c *computer) run(fn func()) {
	defer func() {
		if recover() != nil {
			c.f["content.analyzer_error"] = true
		}
	}()
	fn()
}

// bound returns s, or its head and tail when s is longer than maxScan, and
// records the truncation.
func (c *computer) bound(s string) string {
	if len(s) <= maxScan {
		return s
	}
	c.f["content.truncated_scan"] = true
	return headTail(s)
}

func headTail(s string) string {
	if len(s) <= maxScan {
		return s
	}
	return cutHead(s, scanHead) + "\n" + cutTail(s, scanTail)
}

// cutHead returns at most n leading bytes of s without splitting a rune.
func cutHead(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// cutTail returns at most n trailing bytes of s without splitting a rune.
func cutTail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	i := len(s) - n
	for i < len(s) && !utf8.RuneStart(s[i]) {
		i++
	}
	return s[i:]
}

func (c *computer) toolKind() event.ToolKind {
	if c.e.Tool == nil {
		return ""
	}
	return c.e.Tool.Kind
}

// headTailCut returns l, or its first n/2 and last n - n/2 entries when it
// is longer than n, and whether it cut.
func headTailCut[T any](l []T, n int) ([]T, bool) {
	if len(l) <= n {
		return l, false
	}
	h := n / 2
	out := make([]T, 0, n)
	out = append(out, l[:h]...)
	out = append(out, l[len(l)-(n-h):]...)
	return out, true
}

// setList stores a non-empty copy of list under key, cut to maxList head
// and tail entries (recorded in content.truncated_fields), and returns what
// it stored.
func (c *computer) setList(key string, list []string) []string {
	if len(list) == 0 {
		return nil
	}
	kept, cut := headTailCut(list, maxList)
	if cut {
		c.markCut(key)
	} else {
		kept = append([]string(nil), list...)
	}
	c.f[key] = kept
	return kept
}

// setDerived stores list under key like setList and marks it incomplete
// when the list it was derived from is.
func (c *computer) setDerived(key string, list []string, srcCut bool) {
	if c.setList(key, list) != nil && srcCut {
		c.markCut(key)
	}
}

// uniqList collects distinct non-empty strings in first-seen order. It
// switches from a linear scan to a set once it holds more than a few
// entries, so thousands of hostile names cost linear time.
type uniqList struct {
	list []string
	seen map[string]struct{}
}

func (u *uniqList) add(v string) {
	if v == "" {
		return
	}
	if u.seen != nil {
		if _, ok := u.seen[v]; ok {
			return
		}
		u.seen[v] = struct{}{}
	} else {
		for _, x := range u.list {
			if x == v {
				return
			}
		}
		if len(u.list) >= 16 {
			u.seen = make(map[string]struct{}, 2*len(u.list)+2)
			for _, x := range u.list {
				u.seen[x] = struct{}{}
			}
			u.seen[v] = struct{}{}
		}
	}
	u.list = append(u.list, v)
}

func (u *uniqList) addAll(vs []string) {
	for _, v := range vs {
		u.add(v)
	}
}

func sortedUniq(vs []string) []string {
	if len(vs) == 0 {
		return nil
	}
	m := make(map[string]struct{}, len(vs))
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		if _, ok := m[v]; ok || v == "" {
			continue
		}
		m[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
