package privacy

import (
	"strings"

	"github.com/thomastysong/spoor/internal/event"
)

// Detection context. In the minimal profile activity never leaves the
// host, so a finding alone would arrive without the steps that led to it.
// The engine keeps a short ring of each session's preceding events; when a
// finding is emitted those events are rendered with the standard field
// policy (structurally redacted command, no prompt text, no tool input or
// output) and written to the detection stream next to it, so a case is
// self-contained in every profile.
//
// A context record is routed by its kind, like every record, so it is
// re-kinded: Kind "detection", Type TypeContext, and labels that say what
// it was (context_kind, context_type), which event it shows
// (context_event_id), which finding it belongs to (context_for) and which
// field policy rendered it (context_policy, always "standard"); Privacy
// names the configured profile, as on every record. It gets its own
// deterministic id: the same activity record can be shipped on the
// activity stream (standard profile) and be context for several findings,
// and consumers dedupe at-least-once deliveries on the id. Seq and Writer
// are cleared because they are per stream and set by the writer.
//
// Every context record carries context_for: a record that cannot be
// joined to its finding is activity shipped for no case, which minimal
// promises not to do. So Context needs the finding in prev and ContextFor
// needs its id; without one they return nil. The engine holds the finding
// separately from its per-session ring and calls ContextFor
// (internal/engine/process.go).

// TypeContext is the Type of a detection-context record.
const TypeContext = "detection.context"

// MaxContext bounds how many preceding events one detection carries.
const MaxContext = 50

// Labels set on context records.
const (
	LabelContextFor     = "context_for"
	LabelContextKind    = "context_kind"
	LabelContextType    = "context_type"
	LabelContextEventID = "context_event_id"
	LabelContextPolicy  = "context_policy"
)

// Context returns up to n preceding session events (oldest first),
// redacted with the standard field policy whatever the profile, as
// detection-stream records labelled labels.context_for=<detection id>.
//
// The detection is found in prev itself: the newest detection record in
// prev (one with an id) is the finding, the events before it are its
// context, and when the finding names a session only events of that
// session qualify. Without a detection in prev the result is nil, since
// records without context_for could not be joined to anything; callers
// that hold the detection separately from the ring use ContextFor. Nil
// entries, excluded events and records that ship in every profile anyway
// (detections, inventory, posture, health, summaries) are skipped.
func (p *Policy) Context(prev []*event.Event, n int) []*event.Event {
	for i := len(prev) - 1; i >= 0; i-- {
		d := prev[i]
		if d == nil || d.Kind != event.KindDetection || d.ID == "" || d.Type == TypeContext {
			continue
		}
		sess := ""
		if d.Session != nil {
			sess = d.Session.ID
		}
		return p.context(d.ID, sess, prev[:i], n)
	}
	return nil
}

// ContextFor is Context with the detection id given explicitly: every
// qualifying event in prev is a candidate, whatever its session. An empty
// id yields nil.
func (p *Policy) ContextFor(detectionID string, prev []*event.Event, n int) []*event.Event {
	return p.context(detectionID, "", prev, n)
}

func (p *Policy) context(detectionID, session string, prev []*event.Event, n int) (out []*event.Event) {
	detID := capBytes(cleanUTF8(detectionID), 128)
	if n <= 0 || len(prev) == 0 || strings.TrimSpace(detID) == "" {
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
		if e == nil || shipped(ProfileMinimal, e.Kind) {
			continue
		}
		if session != "" && (e.Session == nil || e.Session.ID != session) {
			continue
		}
		if p.Excluded(e) {
			continue
		}
		picked = append(picked, e)
	}
	for i := len(picked) - 1; i >= 0; i-- {
		if c := p.contextOne(picked[i], s, detID); c != nil {
			out = append(out, c)
		}
	}
	return out
}

func (p *Policy) contextOne(e *event.Event, s settings, detID string) (out *event.Event) {
	// Ids and types are the sensor's own, but they are copied into labels
	// after the safety pass, so they get the pattern pass here.
	clip := func(v string) string {
		return capBytes(rewriteMarkers(redactText(cleanUTF8(capBytes(v, 256))), nil), 128)
	}
	stamp := map[string]string{
		LabelContextKind:    clip(string(e.Kind)),
		LabelContextType:    clip(e.Type),
		LabelContextEventID: clip(e.ID),
		LabelContextFor:     detID,
		LabelContextPolicy:  string(ProfileStandard),
	}
	privacyName := string(s.profile)
	// Re-kind a shallow copy before rendering, so the line cap measures
	// the record as it is written. Rendering clones before it changes
	// anything, so the copy sharing pointers with e is harmless.
	c := *e
	c.Kind = event.KindDetection
	c.Type = TypeContext
	c.ID = event.StableID(e.TS.Time, "spoor/context", detID, e.ID, e.Dedupe, e.Type)
	c.Seq = 0
	c.Writer = ""
	c.Emitted = event.Time{}
	defer func() {
		if recover() != nil {
			out = p.skeleton(&c, s, privacyName, "privacy_error", stamp)
		}
	}()
	return p.renderStamped(&c, s, levelStandard, privacyName, stamp)
}
