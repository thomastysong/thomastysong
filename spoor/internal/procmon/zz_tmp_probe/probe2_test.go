package probe

import (
	"sort"
	"testing"

	"github.com/thomastysong/spoor/internal/catalog"
)

func TestMarkers(t *testing.T) {
	c, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	ps := c.Products()
	sort.Slice(ps, func(i, j int) bool { return ps[i].ID < ps[j].ID })
	for _, p := range ps {
		if len(p.EnvMarkers)+len(p.SessionEnv) == 0 {
			continue
		}
		t.Logf("%-22s kind=%-8s unverified(env_markers)=%v markers=%v session=%v markerEnv=%v", p.ID, p.Kind, p.IsUnverified("env_markers"), p.EnvMarkers, p.SessionEnv, p.MarkerEnv())
	}
}
