package privacy

import (
	"encoding/json"
	"strings"

	"github.com/thomastysong/spoor/internal/event"
)

// level is the field policy applied to a record: what activity fields may
// carry. minimal and standard both use levelStandard for anything they
// write (shipped detections, the local ring, detection context); full uses
// levelFull.
type level uint8

const (
	levelStandard level = iota
	levelFull
)

// Emit returns the record to write and where: ship=true means the outbox
// (leaves the host), ship=false means the local ring only, ok=false means
// drop (excluded, or nil input).
//
// The input is never modified; the returned record is a redacted copy whose
// Privacy field names the profile. Emit never panics: if redaction itself
// fails, a content-free skeleton of the record is returned instead (an
// unredacted record must never escape because of a bug).
func (p *Policy) Emit(e *event.Event) (out *event.Event, ship bool, ok bool) {
	if e == nil {
		return nil, false, false
	}
	if p.Excluded(e) {
		return nil, false, false
	}
	s := p.settings()
	ship = shipped(s.profile, e.Kind)
	lv := levelStandard
	if s.profile == ProfileFull {
		lv = levelFull
	}
	defer func() {
		if recover() != nil {
			out = p.skeleton(e, s, string(s.profile), "privacy_error", nil)
			ok = out != nil
			ship = ship && ok
		}
	}()
	out = p.render(e, s, lv, string(s.profile))
	if out == nil {
		return nil, false, false
	}
	return out, ship, true
}

// shipped is the outbox decision. Unknown kinds are treated as activity:
// a new record type must not start leaving hosts by accident.
func shipped(prof Profile, k event.Kind) bool {
	switch k {
	case event.KindDetection, event.KindInventory, event.KindPosture, event.KindHealth, event.KindSummary:
		return true
	}
	return prof == ProfileStandard || prof == ProfileFull
}

// run carries per-record state while one record is redacted.
type run struct {
	p        *Policy
	s        settings
	lv       level
	src      *event.Event // original (content, features)
	out      *event.Event
	goos     string
	user     string // acting account (before pseudonymization)
	home     *homeRewriter
	lossy    bool
	keyed    bool // a keyed digest or pseudonym was written
	bucketed bool
	trunc    []string
	stamp    map[string]string
}

func (p *Policy) render(e *event.Event, s settings, lv level, privacyName string) *event.Event {
	return p.renderStamped(e, s, lv, privacyName, nil)
}

// renderStamped is render with labels this package sets on the output
// (written last, never cut).
func (p *Policy) renderStamped(e *event.Event, s settings, lv level, privacyName string, stamp map[string]string) *event.Event {
	r := &run{p: p, s: s, lv: lv, src: e, goos: eventOS(e), user: actingUser(e), stamp: stamp}
	var others func(string) string
	if s.pseudo && s.key != nil {
		others = p.Pseudonym
	}
	r.home = newHomeRewriter(p.homeOf(r.user, r.goos), r.goos, others)

	out := e.Clone()
	out.Content = nil
	out.Feat = nil
	out.Privacy = privacyName
	r.out = out
	r.trunc = append(r.trunc, out.Truncated...)

	r.identity()
	r.session()
	r.target()
	r.tool()
	r.prompt()
	r.process()
	r.outcome()
	r.repo()
	r.account()
	r.asset()
	r.check()
	r.detection()
	r.health()
	r.summary()
	r.labels()
	r.safetyPass()
	r.finish()
	r.fitLine()
	return r.out
}

// note records a field name in Truncated (deduplicated, bounded).
func (r *run) note(name string) {
	for _, t := range r.trunc {
		if t == name {
			return
		}
	}
	if len(r.trunc) < maxTruncNames {
		r.trunc = append(r.trunc, name)
	}
}

const maxTruncNames = 32

// finish writes the bookkeeping labels and the truncated list.
func (r *run) finish() {
	out := r.out
	if r.lossy {
		r.setLabel("lossy", "true")
	}
	if r.keyed && r.s.keyID != "" {
		r.setLabel("key_id", r.s.keyID)
	}
	if r.bucketed {
		r.setLabel("len_bucketed", "true")
	}
	for k, v := range r.stamp {
		r.setLabel(k, v)
	}
	if len(r.trunc) > 0 {
		names := make([]string, 0, len(r.trunc))
		for _, t := range r.trunc {
			names = append(names, r.truncName(t))
		}
		out.Truncated = names
	} else {
		out.Truncated = nil
	}
}

// truncName prepares a "truncated" entry. It is written after the safety
// pass, and its names are not all ours: the input record's own list is
// copied in, and "tool.input.<key>" carries a key from agent-supplied tool
// input. So every name gets the safety pass's treatment, redaction before
// the cap so a secret cannot straddle it.
func (r *run) truncName(t string) string {
	t = cleanUTF8(t)
	if len(t) > maxTextScan {
		t = t[:safeCut(t, maxTextScan)]
	}
	if len(t) >= 8 {
		t = redactText(t)
	}
	return capBytes(r.home.rewrite(rewriteMarkers(t, r.s.key)), 64)
}

func (r *run) setLabel(k, v string) {
	if r.out.Labels == nil {
		r.out.Labels = map[string]string{}
	}
	r.out.Labels[k] = v
}

// skeleton is the record written when redaction failed or a line cannot be
// brought under the cap: identity and routing only, no content, plus the
// labels this package stamps (a context record must still say which
// finding it belongs to). It is itself forced under the line budget: its
// fields come from the input and a 128-byte field of "<" encodes to 768
// bytes, so seventeen of them would not fit a small MaxLine. The values
// get the pattern pass too, since on the error path they are raw input.
func (p *Policy) skeleton(e *event.Event, s settings, privacyName, reason string, stamp map[string]string) (out *event.Event) {
	defer func() {
		if recover() != nil {
			out = nil
		}
	}()
	budget := s.lineBudget()
	base := func(v string) string {
		if v == "" {
			return ""
		}
		return rewriteMarkers(safeRedactText(capBytes(cleanUTF8(v), 128)), s.key)
	}
	sk := buildSkeleton(e, privacyName, reason, stamp, base)
	if skeletonFits(sk, budget) {
		return sk
	}
	// Give every non-empty value the same encoded width: the overhead is
	// measured with each value replaced by one byte, the rest is shared.
	n := 0
	probe := buildSkeleton(e, privacyName, reason, stamp, func(v string) string {
		if base(v) == "" {
			return ""
		}
		n++
		return "x"
	})
	if b, err := json.Marshal(probe); err == nil && n > 0 {
		per := (budget-len(b))/n + 1 // encoded content bytes per value ("x" is 1)
		if per >= 8 {
			sk = buildSkeleton(e, privacyName, reason, stamp, func(v string) string { return capEncoded(base(v), per) })
			if skeletonFits(sk, budget) {
				return sk
			}
		}
	}
	// Routing only.
	return &event.Event{
		V: e.V, TS: e.TS, Emitted: e.Emitted, Seq: e.Seq,
		Kind:    event.Kind(capEncoded(base(string(e.Kind)), 32)),
		Privacy: privacyName, Truncated: []string{"*"},
		Labels: map[string]string{reason: "true"},
	}
}

func buildSkeleton(e *event.Event, privacyName, reason string, stamp map[string]string, c func(string) string) *event.Event {
	sk := &event.Event{
		V: e.V, ID: c(e.ID), TS: e.TS, Emitted: e.Emitted, Seq: e.Seq,
		Kind: event.Kind(c(string(e.Kind))), Type: c(e.Type), Source: event.Source(c(string(e.Source))),
		Fidelity: event.Fidelity(c(string(e.Fidelity))), Integrity: event.Integrity(c(string(e.Integrity))),
		Writer: c(e.Writer), Privacy: privacyName,
		Truncated: []string{"*"},
		Labels:    map[string]string{reason: "true"},
	}
	for k, v := range stamp {
		sk.Labels[k] = c(v)
	}
	if e.Host != nil {
		sk.Host = &event.Host{ID: c(e.Host.ID), OS: c(e.Host.OS), Arch: c(e.Host.Arch)}
	}
	if e.Agent != nil {
		sk.Agent = &event.Agent{ID: c(e.Agent.ID)}
	}
	if e.Session != nil {
		sk.Session = &event.Session{ID: c(e.Session.ID)}
	}
	if e.Detection != nil {
		sk.Detection = &event.Detection{
			RuleID: c(e.Detection.RuleID), Title: c(e.Detection.Title),
			Class: c(e.Detection.Class), Severity: c(e.Detection.Severity),
		}
	}
	return sk
}

func skeletonFits(sk *event.Event, budget int) bool {
	b, err := json.Marshal(sk)
	return err == nil && len(b) <= budget
}

// capEncoded cuts s to its longest prefix (on a rune boundary) whose JSON
// encoding, quotes excluded, is at most n bytes.
func capEncoded(s string, n int) string {
	acc := 0
	for i := 0; i < len(s); {
		e, size := encRune(s, i)
		if acc+e > n {
			return s[:i]
		}
		acc += e
		i += size
	}
	return s
}

// safeRedactText is redactText for the error path: a panic in the pattern
// pass yields the failure marker, never the input.
func safeRedactText(v string) (out string) {
	defer func() {
		if recover() != nil {
			out = failMarker
		}
	}()
	return redactText(v)
}

// isMarkerOnly reports a value that is entirely one marker.
func isMarkerOnly(v string) bool {
	return strings.HasPrefix(v, markerOpen) && strings.HasSuffix(v, "]") && strings.Count(v, "[") == 1
}
