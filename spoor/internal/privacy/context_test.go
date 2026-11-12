package privacy

import (
	"strings"
	"testing"

	"github.com/thomastysong/spoor/internal/event"
)

func contextRing() []*event.Event {
	var prev []*event.Event
	for i := 0; i < 8; i++ {
		e := shellEvent("mysql -pCtxPw" + string(rune('a'+i)) + "123 db")
		e.ID = "ev-" + string(rune('a'+i))
		e.Seq = uint64(100 + i)
		e.Writer = "w-1"
		e.Content.PromptText = "prompt"
		prev = append(prev, e)
	}
	inv := event.New(event.KindInventory, event.TypeInventoryAsset, event.SourceScan)
	inv.Asset = &event.Asset{ID: "a", Kind: event.AssetAgent, Name: "x"}
	prev = append(prev, nil, event.New(event.KindHealth, event.TypeHealthHeartbeat, event.SourceSensor), inv)
	return prev
}

func TestContextFor(t *testing.T) {
	prev := contextRing()
	det := event.New(event.KindDetection, event.TypeDetectionFinding, event.SourceSensor)
	prev = append(prev, det)

	for _, prof := range Profiles {
		p := &Policy{Profile: prof}
		got := p.ContextFor("det-123", prev, 3)
		if len(got) != 3 {
			t.Fatalf("%s: %d context events", prof, len(got))
		}
		if got[0].Labels[LabelContextEventID] != "ev-f" || got[2].Labels[LabelContextEventID] != "ev-h" {
			t.Errorf("%s: order %v %v", prof, got[0].Labels, got[2].Labels)
		}
		ids := map[string]bool{}
		for _, c := range got {
			l := line(t, c)
			if strings.Contains(l, "CtxPw") {
				t.Errorf("%s: context leaked:\n%s", prof, l)
			}
			if c.Labels[LabelContextFor] != "det-123" || c.Privacy != "standard" {
				t.Errorf("%s: labels %v privacy %q", prof, c.Labels, c.Privacy)
			}
			// Routed to the detection stream, as its own record.
			if c.Kind != event.KindDetection || c.Kind.Stream() != "detection" || c.Type != TypeContext {
				t.Errorf("%s: kind %q type %q", prof, c.Kind, c.Type)
			}
			if c.Labels[LabelContextKind] != "activity" || c.Labels[LabelContextType] != event.TypeToolPre {
				t.Errorf("%s: original kind/type not kept: %v", prof, c.Labels)
			}
			if strings.HasPrefix(c.ID, "ev-") || c.ID == "" || ids[c.ID] {
				t.Errorf("%s: context id %q must be new and unique", prof, c.ID)
			}
			ids[c.ID] = true
			if c.Seq != 0 || c.Writer != "" {
				t.Errorf("%s: per-stream writer fields copied: seq %d writer %q", prof, c.Seq, c.Writer)
			}
			if c.Tool.Input != nil || c.Prompt != nil && c.Prompt.Text != "" {
				t.Errorf("%s: context carries content", prof)
			}
			if c.Session.Transcript != "" || !strings.HasPrefix(c.Session.CWD, "~/") {
				t.Errorf("%s: session not redacted: %+v", prof, c.Session)
			}
		}
		// Deterministic ids: rendering again gives the same ids; another
		// finding gives different ones.
		again := p.ContextFor("det-123", prev, 3)
		other := p.ContextFor("det-456", prev, 3)
		if again[1].ID != got[1].ID || other[1].ID == got[1].ID {
			t.Errorf("%s: ids not deterministic per finding", prof)
		}
	}
	if (&Policy{}).ContextFor("d", prev, 0) != nil || (&Policy{}).ContextFor("d", nil, 5) != nil {
		t.Error("n=0 or no events gives nil")
	}
	if got := (&Policy{}).ContextFor("d", prev, 1000); len(got) != 8 {
		t.Errorf("cap/availability: %d (inventory, health, nil and detections are not context)", len(got))
	}
	ex := &Policy{Exclude: Exclusions{Paths: []string{"~/work/**"}}}
	if got := ex.ContextFor("d", prev, 5); len(got) != 0 {
		t.Errorf("excluded events must not become context: %d", len(got))
	}
	// The input events are not modified.
	if prev[0].Labels != nil || !strings.Contains(prev[0].Target.Command, "CtxPw") || prev[0].Kind != event.KindActivity || prev[0].ID != "ev-a" {
		t.Error("context mutated its input")
	}
}

func TestContextFindsDetectionInRing(t *testing.T) {
	prev := contextRing()
	other := shellEvent("ls")
	other.ID = "ev-other-session"
	other.Session.ID = "sess-2"
	prev = append(prev, other)
	det := event.New(event.KindDetection, event.TypeDetectionFinding, event.SourceSensor)
	det.ID = "det-in-ring"
	det.Session = &event.Session{ID: "sess-1"}
	prev = append(prev, det)
	after := shellEvent("echo after the finding")
	after.ID = "ev-after"
	prev = append(prev, after)

	got := (&Policy{}).Context(prev, 3)
	if len(got) != 3 {
		t.Fatalf("%d context events", len(got))
	}
	for _, c := range got {
		if c.Labels[LabelContextFor] != "det-in-ring" {
			t.Errorf("context_for = %q", c.Labels[LabelContextFor])
		}
		switch c.Labels[LabelContextEventID] {
		case "ev-other-session", "ev-after":
			t.Errorf("event %s is not preceding context of the finding's session", c.Labels[LabelContextEventID])
		}
	}
	if got[2].Labels[LabelContextEventID] != "ev-h" {
		t.Errorf("newest context = %v", got[2].Labels)
	}

	// No detection in the ring: everything qualifies, no context_for.
	plain := (&Policy{}).Context(contextRing(), 2)
	if len(plain) != 2 || plain[0].Type != TypeContext {
		t.Fatalf("Context without a detection: %+v", plain)
	}
	if _, ok := plain[0].Labels[LabelContextFor]; ok {
		t.Error("context_for must not be invented")
	}
	if (&Policy{}).Context(prev, 0) != nil || (&Policy{}).Context(nil, 5) != nil {
		t.Error("n=0 or no events gives nil")
	}
}

func TestContextUnderLineCap(t *testing.T) {
	e := shellEvent("echo " + strings.Repeat("<>&", 20000))
	e.ID = "ev-big"
	e.Target.Paths = make([]string, 3000)
	for i := range e.Target.Paths {
		e.Target.Paths[i] = "/srv/" + strings.Repeat("p", 40)
	}
	p := &Policy{MaxLine: MinMaxLine}
	got := p.ContextFor("det-1", []*event.Event{e}, 1)
	if len(got) != 1 {
		t.Fatalf("%d records", len(got))
	}
	l := line(t, got[0])
	if len(l) > MinMaxLine-LineHeadroom {
		t.Errorf("context line %d bytes", len(l))
	}
	if got[0].Labels[LabelContextFor] != "det-1" || got[0].Labels[LabelContextEventID] != "ev-big" || got[0].Kind != event.KindDetection {
		t.Errorf("routing lost under the cap: %v", got[0].Labels)
	}
}
