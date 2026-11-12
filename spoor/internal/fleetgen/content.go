package fleetgen

import (
	"fmt"
	"time"

	"github.com/thomastysong/spoor/internal/state"
)

// Label is a Fleet dynamic label.
type Label struct {
	Name        string
	Description string
	Query       string
	Platform    string // "" = all platforms
}

// Policy is a Fleet policy. Query returns a row when the host passes.
type Policy struct {
	Key         string // stable identifier inside spoor; not sent to Fleet
	Name        string
	Description string
	Resolution  string
	Query       string
	Platform    string
	// Violation is the row-returning check the query wraps ("" for the
	// sensor heartbeat policy and for builtin policies without a guard).
	Violation string
	// Window is the heartbeat age the query accepts; 0 when it has no
	// heartbeat guard (builtin profile).
	Window time.Duration
}

// Report is a Fleet report (formerly "query").
type Report struct {
	Key                string
	Name               string
	Description        string
	Query              string
	Platform           string
	Interval           int    // seconds; 0 = never scheduled
	Logging            string // snapshot | differential | differential_ignore_removals
	AutomationsEnabled bool   // forward results to the log destination
	DiscardData        bool   // do not store results in Fleet
}

// Profile is one deployable content set.
type Profile struct {
	Name     string // stock | fleetd | builtin
	Title    string
	Summary  string
	Labels   []Label
	Policies []Policy
	Reports  []Report
}

// Content is everything Generate renders.
type Content struct {
	// ATC maps a platform to its auto_table_construction block
	// (state.ATCConfig for that platform's database path).
	ATC map[string]map[string]any
	// DBPaths are the state database paths the ATC blocks point at.
	DBPaths map[string]string
	// BinPaths are the spoor binary paths the "installed" label looks for.
	BinPaths map[string]string
	// Profiles: stock, fleetd, builtin, in that order.
	Profiles []Profile
	// OptIn holds the opt-in exec-events reports (one per OS).
	OptIn []Report
	// CatalogVersion is the version of the catalog the vocabulary came from.
	CatalogVersion string
	// AlertWindow and GuardWindow are the heartbeat windows used.
	AlertWindow, GuardWindow time.Duration
	// MinBundleVersion is what the "rules bundle is current" policy requires.
	MinBundleVersion uint64
}

// Profile names.
const (
	ProfileStock   = "stock"
	ProfileFleetd  = "fleetd"
	ProfileBuiltin = "builtin"
)

// Profile returns the named profile.
func (c *Content) Profile(name string) (Profile, bool) {
	for _, p := range c.Profiles {
		if p.Name == name {
			return p, true
		}
	}
	return Profile{}, false
}

// Build computes the content without rendering it.
func Build(o Options) (c *Content, err error) {
	defer func() {
		if r := recover(); r != nil {
			c, err = nil, fmt.Errorf("fleetgen: internal error: %v", r)
		}
	}()
	r, err := o.resolve()
	if err != nil {
		return nil, err
	}
	v := vocabularyOf(r.cat)
	c = &Content{
		ATC:            map[string]map[string]any{},
		DBPaths:          r.dbPaths,
		BinPaths:         r.binPaths,
		CatalogVersion:   v.catalogVersion,
		AlertWindow:      r.alert,
		GuardWindow:      r.guard,
		MinBundleVersion: r.minBundleVersion,
	}
	for _, p := range Platforms {
		c.ATC[p] = state.ATCConfig(r.dbPaths[p], p)
	}
	g := &gen{r: r, v: v}
	c.Profiles = []Profile{g.stock(), g.fleetd(), g.builtin()}
	c.OptIn = g.optIn()
	return c, nil
}

// gen holds what every builder needs.
type gen struct {
	r *resolved
	v vocabulary
}
