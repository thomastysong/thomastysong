package privacy

import (
	"testing"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/features"
)

// TestClosedVocabulariesListedByName: every field the rule registry gives
// a closed vocabulary is in the evidence allowlist by its own name, so its
// redaction mode is a reviewed choice rather than the fallback for names
// ending in _kinds, _classes or .markers.
func TestClosedVocabulariesListedByName(t *testing.T) {
	for _, f := range features.Registry() {
		if f.Vocab == nil {
			continue
		}
		_, ev := evidenceFields[f.Name]
		_, ft := featureFields[f.Name]
		if !ev && !ft {
			t.Errorf("%s has a closed vocabulary but is not listed in evidenceFields or featureFields", f.Name)
		}
	}
	e := shellEvent("sh ./build.sh")
	e.Sources = []event.Source{"hook", "transcript"}
	e.Feat = map[string]any{"shell.inherited_kinds": []string{"written_script"}}
	ev := (&Policy{}).Evidence(e, []string{"sources", "shell.inherited_kinds"})
	if ev["sources"] != `["hook","transcript"]` || ev["shell.inherited_kinds"] != `["written_script"]` {
		t.Errorf("evidence %v", ev)
	}
}
