package features

import (
	"runtime"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/thomastysong/spoor/internal/event"
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

	maxList   = 64   // entries kept in any derived []string feature
	maxArgv   = 256  // entries in shell.argv
	maxArgLen = 1024 // bytes kept of one argument in shell.argv / shell.cmds
	maxCmds   = 128  // entries in shell.cmds
	maxCmdArg = 64   // args kept per shell.cmds entry
	maxPaths  = 64   // paths classified per family
)

// computedKey marks a Feat map as filled. It is not part of the field view.
const computedKey = "features.computed"

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

// setList stores a non-empty, capped copy of list under key.
func (c *computer) setList(key string, list []string) {
	if len(list) == 0 {
		return
	}
	if len(list) > maxList {
		list = list[:maxList]
	}
	c.f[key] = append([]string(nil), list...)
}

// uniq appends v to *list unless present or empty, keeping first-seen order
// and the maxList cap.
func uniq(list *[]string, v string) {
	if v == "" || len(*list) >= maxList {
		return
	}
	for _, x := range *list {
		if x == v {
			return
		}
	}
	*list = append(*list, v)
}

func uniqAll(list *[]string, vs []string) {
	for _, v := range vs {
		uniq(list, v)
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
