package sink

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"unicode/utf8"

	"github.com/thomastysong/spoor/internal/event"
)

// Label keys that keep the identity of a command cut by the shrinker, so
// truncation is never silent and two cut commands can still be compared.
const (
	LabelCommandSHA256 = "target.command.sha256"
	LabelCommandLen    = "target.command.len"
)

// minCommandKeep is the shortest command head the shrinker leaves before it
// moves on to other fields: the start of a command line is the part that
// identifies it.
const minCommandKeep = 256

// fitLine encodes e as one line of at most max bytes.
//
// A line longer than the reader's buffer is worse than a shortened one:
// Fluent Bit's tail input skips it entirely (or, without skip_long_lines,
// stops reading the file). So an oversize event is shrunk, in the order of
// least forensic loss, and the cut fields are named in Truncated:
//
//  1. tool.input and tool.output are dropped (their hashes and lengths stay).
//  2. target.command loses its tail; a hash of the full command is kept in
//     Labels.
//  3. other free-form fields are capped (prompt text, error text, path and
//     argument lists, evidence, labels).
//  4. as a last resort only identity fields survive, sanitized and clipped,
//     with Truncated ["*"].
//
// The caller's event is never modified.
func fitLine(e *event.Event, f string, max int) ([]byte, error) {
	return fit(e, max, func(x *event.Event) ([]byte, error) { return encodeLine(x, f) })
}

// fit is fitLine for any encoding: enc is called on progressively smaller
// copies of e until its output is at most max bytes.
func fit(e *event.Event, max int, enc func(*event.Event) ([]byte, error)) ([]byte, error) {
	line, err := enc(e)
	if err != nil {
		return nil, err
	}
	if len(line) <= max {
		return line, nil
	}
	c := cloneWithoutInput(e)
	fits := func() bool {
		line, err = enc(c)
		return err == nil && len(line) <= max
	}
	mark := func(names ...string) {
		for _, n := range names {
			c.Truncated = appendOnce(c.Truncated, n)
		}
	}

	// Step 1: tool input and output.
	if e.Tool != nil {
		if e.Tool.Input != nil {
			mark("tool.input")
		}
		if c.Tool.Output != "" {
			c.Tool.Output = ""
			mark("tool.output")
		}
	}
	if fits() {
		return line, nil
	}
	if err != nil {
		return nil, err
	}

	// Step 2: the tail of the command.
	if c.Target != nil && len(c.Target.Command) > minCommandKeep {
		full := c.Target.Command
		sum := sha256.Sum256([]byte(full))
		if c.Labels == nil {
			c.Labels = make(map[string]string, 2)
		}
		c.Labels[LabelCommandSHA256] = hex.EncodeToString(sum[:])
		c.Labels[LabelCommandLen] = strconv.Itoa(len(full))
		mark("target.command")
		keep := len(full) / 2
		if keep > max/2 {
			keep = max / 2
		}
		for ; ; keep /= 2 {
			if keep < minCommandKeep {
				keep = minCommandKeep
			}
			c.Target.Command = clipString(full, keep)
			if fits() {
				return line, nil
			}
			if keep == minCommandKeep {
				break
			}
		}
	}

	// Step 3: every other field an agent or a config file can make large.
	for _, step := range shrinkSteps {
		if names := step(c); len(names) > 0 {
			mark(names...)
			if fits() {
				return line, nil
			}
		}
	}

	// Step 4: identity only.
	c = skeleton(c)
	if fits() {
		return line, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("event %s is %d bytes after shrinking, limit %d", safeString(e.ID, 64), len(line), max)
}

// cloneWithoutInput deep-copies e except Tool.Input, which is dropped first:
// it is the field most likely to be huge or deeply nested, and copying it
// only to discard it would be the most expensive part of the shrink.
func cloneWithoutInput(e *event.Event) *event.Event {
	tmp := *e
	if e.Tool != nil {
		t := *e.Tool
		t.Input = nil
		tmp.Tool = &t
	}
	return tmp.Clone()
}

// shrinkSteps are applied in order until the line fits. Each returns the
// names of the fields it actually cut.
var shrinkSteps = []func(*event.Event) []string{
	func(c *event.Event) []string {
		if c.Prompt != nil && c.Prompt.Text != "" {
			c.Prompt.Text = ""
			return []string{"prompt.text"}
		}
		return nil
	},
	func(c *event.Event) (names []string) {
		if c.Outcome != nil && clipField(&c.Outcome.Error, 1024) {
			names = append(names, "outcome.error")
		}
		return names
	},
	func(c *event.Event) (names []string) {
		t := c.Target
		if t == nil {
			return nil
		}
		if clipList(&t.Paths, 16, 512) {
			names = append(names, "target.paths")
		}
		if clipList(&t.Hosts, 16, 256) {
			names = append(names, "target.hosts")
		}
		if clipField(&t.Path, 2048) {
			names = append(names, "target.path")
		}
		if clipField(&t.URL, 2048) {
			names = append(names, "target.url")
		}
		if clipField(&t.Host, 256) {
			names = append(names, "target.host")
		}
		if clipField(&t.Query, 1024) {
			names = append(names, "target.query")
		}
		return names
	},
	func(c *event.Event) (names []string) {
		p := c.Process
		if p == nil {
			return nil
		}
		if clipList(&p.Args, 32, 256) {
			names = append(names, "process.args")
		}
		if clipList(&p.Ancestors, 32, 128) {
			names = append(names, "process.ancestors")
		}
		if clipList(&p.EnvMarkers, 32, 128) {
			names = append(names, "process.env_markers")
		}
		if clipList(&p.Flags, 32, 128) {
			names = append(names, "process.flags")
		}
		if clipField(&p.Exe, 1024) {
			names = append(names, "process.exe")
		}
		return names
	},
	func(c *event.Event) (names []string) {
		d := c.Detection
		if d == nil {
			return nil
		}
		if clipMap(d.Evidence, 32, 512) {
			names = append(names, "detection.evidence")
		}
		if clipList(&d.EventIDs, 64, 128) {
			names = append(names, "detection.event_ids")
		}
		if clipList(&d.Tags, 64, 128) {
			names = append(names, "detection.tags")
		}
		if clipList(&d.Flags, 64, 128) {
			names = append(names, "detection.flags")
		}
		if clipField(&d.Remedy, 1024) {
			names = append(names, "detection.remedy")
		}
		if clipField(&d.Title, 512) {
			names = append(names, "detection.title")
		}
		return names
	},
	func(c *event.Event) (names []string) {
		k := c.Check
		if k == nil {
			return nil
		}
		for _, f := range []struct {
			p    *string
			name string
		}{{&k.Expected, "check.expected"}, {&k.Actual, "check.actual"}, {&k.Subject, "check.subject"}, {&k.Remedy, "check.remedy"}, {&k.Title, "check.title"}} {
			if clipField(f.p, 1024) {
				names = append(names, f.name)
			}
		}
		return names
	},
	func(c *event.Event) (names []string) {
		a := c.Asset
		if a == nil {
			return nil
		}
		if clipMap(a.Detail, 32, 512) {
			names = append(names, "asset.detail")
		}
		if clipList(&a.Evidence, 32, 128) {
			names = append(names, "asset.evidence")
		}
		if clipList(&a.RiskFlags, 64, 128) {
			names = append(names, "asset.risk_flags")
		}
		if clipField(&a.Path, 2048) {
			names = append(names, "asset.path")
		}
		if m := a.MCP; m != nil {
			if clipList(&m.Args, 32, 256) {
				names = append(names, "asset.mcp.args")
			}
			if clipList(&m.EnvKeys, 64, 128) {
				names = append(names, "asset.mcp.env_keys")
			}
			if clipList(&m.HeaderKeys, 64, 128) {
				names = append(names, "asset.mcp.header_keys")
			}
			if clipField(&m.URLPath, 1024) {
				names = append(names, "asset.mcp.url_path")
			}
		}
		return names
	},
	func(c *event.Event) (names []string) {
		h := c.Health
		if h == nil {
			return nil
		}
		if clipField(&h.Detail, 1024) {
			names = append(names, "health.detail")
		}
		if len(h.Surfaces) > 32 {
			h.Surfaces = h.Surfaces[:32]
			names = append(names, "health.surfaces")
		}
		if len(h.Coverage) > 64 {
			h.Coverage = h.Coverage[:64]
			names = append(names, "health.coverage")
		}
		if len(h.Counters) > 128 {
			h.Counters = nil
			names = append(names, "health.counters")
		}
		return names
	},
	func(c *event.Event) (names []string) {
		if clipMap(c.Labels, 32, 256) {
			names = append(names, "labels")
		}
		if c.Session != nil {
			if clipField(&c.Session.CWD, 1024) {
				names = append(names, "session.cwd")
			}
			if clipField(&c.Session.Transcript, 1024) {
				names = append(names, "session.transcript")
			}
		}
		if c.Repo != nil {
			if clipField(&c.Repo.Root, 1024) {
				names = append(names, "repo.root")
			}
			if clipField(&c.Repo.Remote, 1024) {
				names = append(names, "repo.remote")
			}
		}
		return names
	},
}

// skeleton returns an event with identity fields only. Strings are reduced
// to a conservative printable subset and clipped so the encoded size has a
// fixed upper bound no matter what the input held (JSON escaping can expand
// a hostile byte sixfold).
func skeleton(c *event.Event) *event.Event {
	const n = 64
	s := &event.Event{
		V: c.V, ID: safeString(c.ID, n), TS: c.TS, Seq: c.Seq,
		Kind: event.Kind(safeString(string(c.Kind), 16)), Type: safeString(c.Type, n),
		Source: event.Source(safeString(string(c.Source), 16)), Fidelity: event.Fidelity(safeString(string(c.Fidelity), 16)),
		Privacy:   safeString(c.Privacy, 16),
		Truncated: []string{"*"},
	}
	if h := c.Host; h != nil {
		s.Host = &event.Host{ID: safeString(h.ID, n), Name: safeString(h.Name, n), OS: safeString(h.OS, 16), Arch: safeString(h.Arch, 16)}
	}
	if u := c.User; u != nil {
		s.User = &event.User{Name: safeString(u.Name, n), ID: safeString(u.ID, n)}
	}
	if a := c.Agent; a != nil {
		s.Agent = &event.Agent{ID: safeString(a.ID, n), Version: safeString(a.Version, 32), PID: a.PID}
	}
	if x := c.Session; x != nil {
		s.Session = &event.Session{ID: safeString(x.ID, n)}
	}
	if t := c.Tool; t != nil {
		s.Tool = &event.Tool{
			Name: safeString(t.Name, n), Kind: event.ToolKind(safeString(string(t.Kind), 16)), UseID: safeString(t.UseID, n),
			InputSHA256: safeString(t.InputSHA256, n), OutputSHA256: safeString(t.OutputSHA256, n), OutputLen: t.OutputLen,
		}
	}
	if d := c.Detection; d != nil {
		s.Detection = &event.Detection{
			RuleID: safeString(d.RuleID, n), Title: safeString(d.Title, n), Severity: safeString(d.Severity, 16),
			Confidence: safeString(d.Confidence, 16), Response: safeString(d.Response, 16), Enforced: d.Enforced,
			DedupKey: safeString(d.DedupKey, n), Count: d.Count,
		}
	}
	if k := c.Check; k != nil {
		s.Check = &event.Check{ID: safeString(k.ID, n), Status: safeString(k.Status, 16), Severity: safeString(k.Severity, 16)}
	}
	if a := c.Asset; a != nil {
		s.Asset = &event.Asset{ID: safeString(a.ID, n), Kind: event.AssetKind(safeString(string(a.Kind), 32)), Name: safeString(a.Name, n)}
	}
	if h := c.Health; h != nil {
		s.Health = &event.Health{SensorVersion: safeString(h.SensorVersion, 32), Mode: safeString(h.Mode, 16), Reason: safeString(h.Reason, n)}
	}
	return s
}

// safeString keeps letters, digits and a few separators, replaces every
// other byte with '_' and clips to n bytes. Nothing it returns needs JSON
// escaping.
func safeString(s string, n int) string {
	if len(s) > n {
		s = s[:n]
	}
	clean := true
	for i := 0; i < len(s); i++ {
		if !safeByte(s[i]) {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	b := []byte(s)
	for i, c := range b {
		if !safeByte(c) {
			b[i] = '_'
		}
	}
	return string(b)
}

func safeByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	switch c {
	case ' ', '.', '_', '-', ':', '/', '@', '+', '=', ',', '(', ')', '[', ']':
		return true
	}
	return false
}

// clipString cuts s to at most n bytes without splitting a UTF-8 sequence.
func clipString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func clipField(p *string, n int) bool {
	if len(*p) <= n {
		return false
	}
	*p = clipString(*p, n)
	return true
}

func clipList(p *[]string, maxLen, maxItem int) bool {
	changed := false
	if len(*p) > maxLen {
		*p = (*p)[:maxLen]
		changed = true
	}
	for i := range *p {
		if clipField(&(*p)[i], maxItem) {
			changed = true
		}
	}
	return changed
}

// clipMap clips values, and drops the whole map content beyond maxKeys
// (which keys go is arbitrary, so the field is reported as truncated).
func clipMap(m map[string]string, maxKeys, maxVal int) bool {
	changed := false
	for k, v := range m {
		if len(m) > maxKeys || len(k) > 256 {
			delete(m, k)
			changed = true
			continue
		}
		if len(v) > maxVal {
			m[k] = clipString(v, maxVal)
			changed = true
		}
	}
	return changed
}

func appendOnce(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}
