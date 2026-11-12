package privacy

import (
	"strings"
	"testing"

	"github.com/thomastysong/spoor/internal/event"
)

func TestContext(t *testing.T) {
	var prev []*event.Event
	for i := 0; i < 8; i++ {
		e := shellEvent("mysql -pCtxPw" + string(rune('a'+i)) + "123 db")
		e.ID = "ev-" + string(rune('a'+i))
		e.Content.PromptText = "prompt"
		prev = append(prev, e)
	}
	prev = append(prev, nil, event.New(event.KindHealth, event.TypeHealthHeartbeat, event.SourceSensor))
	det := event.New(event.KindDetection, event.TypeDetectionFinding, event.SourceSensor)
	prev = append(prev, det)

	for _, prof := range Profiles {
		p := &Policy{Profile: prof}
		got := p.ContextFor("det-123", prev, 3)
		if len(got) != 3 {
			t.Fatalf("%s: %d context events", prof, len(got))
		}
		if got[0].ID != "ev-f" || got[2].ID != "ev-h" {
			t.Errorf("%s: order %s %s", prof, got[0].ID, got[2].ID)
		}
		for _, c := range got {
			l := line(t, c)
			if strings.Contains(l, "CtxPw") {
				t.Errorf("%s: context leaked:\n%s", prof, l)
			}
			if c.Labels["context_for"] != "det-123" || c.Privacy != "standard" {
				t.Errorf("%s: labels %v privacy %q", prof, c.Labels, c.Privacy)
			}
			if c.Tool.Input != nil || c.Prompt != nil && c.Prompt.Text != "" {
				t.Errorf("%s: context carries content", prof)
			}
		}
	}
	plain := (&Policy{}).Context(prev, 2)
	if len(plain) != 2 || plain[0].Labels["context"] != "true" {
		t.Errorf("Context labels: %+v", plain)
	}
	if (&Policy{}).Context(prev, 0) != nil || (&Policy{}).Context(nil, 5) != nil {
		t.Error("n=0 or no events gives nil")
	}
	if got := (&Policy{}).Context(prev, 1000); len(got) != 8 {
		t.Errorf("cap/availability: %d", len(got))
	}
	ex := &Policy{Exclude: Exclusions{Paths: []string{"~/work/**"}}}
	if got := ex.Context(prev, 5); len(got) != 0 {
		t.Errorf("excluded events must not become context: %d", len(got))
	}
	// The input events are not modified.
	if prev[0].Labels != nil || !strings.Contains(prev[0].Target.Command, "CtxPw") {
		t.Error("context mutated its input")
	}
}
