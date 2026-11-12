package engine

import (
	"testing"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/config"
	"github.com/thomastysong/thomastysong/hawkbell/internal/rules"
)

// A suppression's expires value means the same in rules.suppressions and
// in a bundle's suppressions.yaml: a bare date lasts through the end of
// that day (UTC), an RFC 3339 time is exact.
func TestSuppressionExpiryMatchesTheBundle(t *testing.T) {
	for _, exp := range []string{"2027-01-31", "2027-01-31T18:30:00-05:00"} {
		cfg, err := suppressions([]config.Suppression{{Rule: "HB-EXEC-*", Expires: exp}})
		if err != nil {
			t.Fatal(err)
		}
		b, err := rules.Load(map[string][]byte{"suppressions.yaml": []byte("suppressions:\n  - {rule: HB-EXEC-*, expires: \"" + exp + "\", reason: r}\n")})
		if err != nil {
			t.Fatal(err)
		}
		bs := b.Suppressions()
		if len(cfg) != 1 || len(bs) != 1 || !cfg[0].Expires.Equal(bs[0].Expires) {
			t.Errorf("expires %q: config %v, bundle %v", exp, cfg, bs)
		}
	}
	cfg, err := suppressions([]config.Suppression{{Rule: "*", Expires: "2027-01-31"}})
	if err != nil || len(cfg) != 1 || !cfg[0].Expires.Equal(time.Date(2027, 2, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("config date: %v, %v; want the end of 2027-01-31 UTC", cfg, err)
	}
	for _, bad := range []string{"31/01/2027", "  "} {
		if _, err := suppressions([]config.Suppression{{Rule: "*", Expires: bad}}); err == nil {
			t.Errorf("unreadable expiry %q accepted", bad)
		}
	}
}
