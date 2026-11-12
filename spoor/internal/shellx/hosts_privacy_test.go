package shellx_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/privacy"
	"github.com/thomastysong/spoor/internal/shellx"
)

// A URL fact carries the userinfo's unkeyed fingerprint on the endpoint.
// Wherever the fact is quoted in a record that leaves (a label, detection
// evidence, the Evidence helper), package privacy must rewrite that
// fingerprint: keyed with the tenant key, or dropped without one. This is
// the end-to-end check that shellx's marker has the shape privacy expects.
func TestPrivacyRewritesUserinfoMarker(t *testing.T) {
	tok := "Zx81kPwm" + "3RtY6vBn"
	f := shellx.Analyze("git clone https://deploy:"+tok+"@git.example.com/org/repo.git", "")
	if len(f.URLs) != 1 {
		t.Fatalf("urls %q", f.URLs)
	}
	u := f.URLs[0]
	sum := sha256.Sum256([]byte("deploy:" + tok))
	fp := hex.EncodeToString(sum[:4])
	if !strings.Contains(u, fp) {
		t.Fatalf("fact %q does not carry the endpoint fingerprint this test looks for", u)
	}

	for name, key := range map[string][]byte{"no key": nil, "tenant key": bytes.Repeat([]byte{7}, 32)} {
		t.Run(name, func(t *testing.T) {
			p := &privacy.Policy{Profile: privacy.ProfileStandard, Key: key, KeyID: "k1"}

			det := event.New(event.KindDetection, event.TypeDetectionFinding, event.SourceSensor)
			det.Agent = &event.Agent{ID: "claude-code"}
			det.Detection = &event.Detection{
				RuleID: "SPR-TEST-1", Title: "clone " + u, Severity: event.SevHigh,
				Evidence: map[string]string{"shell.urls": u},
			}
			det.Labels = map[string]string{"url": u}
			act := event.New(event.KindActivity, event.TypeToolPre, event.SourceHook)
			act.Agent = &event.Agent{ID: "claude-code"}
			act.Labels = map[string]string{"first_url": u}

			var shipped []string
			for _, e := range []*event.Event{det, act} {
				out, ship, ok := p.Emit(e)
				if !ok || !ship || out == nil {
					t.Fatalf("%s not shipped: ship=%v ok=%v", e.Type, ship, ok)
				}
				b, err := json.Marshal(out)
				if err != nil {
					t.Fatal(err)
				}
				shipped = append(shipped, string(b))
			}
			src := event.New(event.KindActivity, event.TypeToolPre, event.SourceHook)
			src.Feat = map[string]any{"shell.urls": f.URLs}
			ev := p.Evidence(src, []string{"shell.urls"})
			if ev["shell.urls"] == "" || ev["shell.urls"] == privacy.Withheld {
				t.Fatalf("evidence %v", ev)
			}
			shipped = append(shipped, ev["shell.urls"])

			for _, s := range shipped {
				if strings.Contains(s, tok) {
					t.Fatalf("the credential shipped: %s", s)
				}
				if strings.Contains(s, fp) {
					t.Fatalf("the unkeyed fingerprint shipped: %s", s)
				}
			}
			// Both records quote the marker; privacy rewrote rather than lost it.
			all := strings.Join(shipped[:2], "\n")
			if !strings.Contains(all, "[REDACTED:basic_auth_url") {
				t.Fatalf("marker lost: %s", all)
			}
			if key == nil && strings.Contains(all, ":hmac=") {
				t.Fatalf("keyed marker without a key: %s", all)
			}
			if key != nil && !strings.Contains(all, "[REDACTED:basic_auth_url:hmac=") {
				t.Fatalf("marker not keyed: %s", all)
			}

			// The fact ships exactly as the raw credential URL ships: privacy
			// recognised shellx's marker as classify's own and rewrote its
			// fingerprint, rather than treating the marker as a new secret
			// and fingerprinting the fingerprint (which is what happened to
			// the old lower-case "[redacted:<fp>]" form). Same credential,
			// same keyed marker, wherever it was seen.
			raw := "https://deploy:" + tok + "@git.example.com/org/repo.git"
			ship := func(v string) string {
				e := event.New(event.KindActivity, event.TypeToolPre, event.SourceHook)
				e.Agent = &event.Agent{ID: "claude-code"}
				e.Labels = map[string]string{"url": v}
				out, _, ok := p.Emit(e)
				if !ok || out == nil {
					t.Fatal("not emitted")
				}
				return out.Labels["url"]
			}
			if fromFact, fromRaw := ship(u), ship(raw); fromFact != fromRaw {
				t.Fatalf("the fact ships as %q, the raw URL as %q", fromFact, fromRaw)
			}
		})
	}
}
