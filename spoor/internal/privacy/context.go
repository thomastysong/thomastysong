package privacy

import (
	"github.com/thomastysong/spoor/internal/event"
)

// Detection context. In the minimal profile activity never leaves the
// host, so a finding alone would arrive without the steps that led to it.
// The engine keeps a short ring of each session's preceding events; when a
// finding is emitted those events are rendered with the standard field
// policy (structurally redacted command, no prompt text, no tool input or
// output) and written to the detection stream next to it, so a case is
// self-contained in every profile.

// MaxContext bounds how many preceding events one detection carries.
const MaxContext = 50

// Context returns up to n of the last events in prev (oldest first),
// redacted with the standard field policy whatever the profile, and
// labelled "context=true". Context has no detection id to stamp; callers
// that have one use ContextFor, which sets labels.context_for. Excluded
// events, nil entries, detections and health records are skipped.
func (p *Policy) Context(prev []*event.Event, n int) []*event.Event {
	return p.ContextFor("", prev, n)
}

// ContextFor is Context with labels.context_for set to detectionID.
func (p *Policy) ContextFor(detectionID string, prev []*event.Event, n int) (out []*event.Event) {
	if n <= 0 || len(prev) == 0 {
		return nil
	}
	if n > MaxContext {
		n = MaxContext
	}
	s := p.settings()
	// Walk back from the newest, then restore order.
	var picked []*event.Event
	for i := len(prev) - 1; i >= 0 && len(picked) < n; i-- {
		e := prev[i]
		if e == nil || e.Kind == event.KindDetection || e.Kind == event.KindHealth {
			continue
		}
		if p.Excluded(e) {
			continue
		}
		picked = append(picked, e)
	}
	detID := capBytes(cleanUTF8(detectionID), 128)
	for i := len(picked) - 1; i >= 0; i-- {
		if c := p.contextOne(picked[i], s, detID); c != nil {
			out = append(out, c)
		}
	}
	return out
}

func (p *Policy) contextOne(e *event.Event, s settings, detID string) (out *event.Event) {
	defer func() {
		if recover() != nil {
			out = p.skeleton(e, s, string(ProfileStandard), "privacy_error")
		}
	}()
	stamp := map[string]string{"context": "true"}
	if detID != "" {
		stamp = map[string]string{"context_for": detID}
	}
	return p.renderStamped(e, s, levelStandard, string(ProfileStandard), stamp)
}
