package hookcmd

import (
	"runtime"
	"strings"
	"time"

	"github.com/thomastysong/spoor/internal/bundle"
	"github.com/thomastysong/spoor/internal/config"
	"github.com/thomastysong/spoor/internal/rules"
)

// loadRuleSet builds the rule set a hook evaluates: the embedded packs,
// then the installed signed bundle, then the operator's rule directories
// (later sources override earlier ones by rule id), minus rules.disable;
// in guard-only mode just the guard subset. It is the same order the daemon
// uses, so a hook and the daemon judge one event by the same content.
// degraded is true when a configured source could not be loaded (the hook
// carries on with what did load and labels its records). It is a variable
// so tests can prove observe mode never calls it.
var loadRuleSet = func(cfg *config.Config, guardOnly bool) (set *rules.Set, degraded bool, err error) {
	set, err = rules.LoadEmbedded()
	if err != nil {
		return nil, true, err
	}
	// Current reads two small files and hashes nothing; it is meant for
	// this path. A bundle the hook cannot read (the data directory is not
	// readable by users) leaves the embedded content in force.
	if dir, _, ok := bundle.Current(cfg.BundleDir()); ok {
		if b, berr := rules.LoadDir(dir); berr == nil {
			set.Merge(b)
		} else {
			degraded = true
		}
	}
	for _, d := range cfg.Rules.Dirs {
		if d == "" {
			continue
		}
		if o, derr := rules.LoadDir(d); derr == nil {
			set.Merge(o)
		} else {
			degraded = true
		}
	}
	set.Disable(cfg.Rules.Disable...)
	if guardOnly {
		set = set.GuardSubset()
	}
	return set, degraded, nil
}

// engineOptions configures the one-shot engine of a hook process.
func engineOptions(cfg *config.Config, env Env, now time.Time, budget time.Duration) (rules.Options, bool) {
	sup, degraded := suppressions(cfg.Rules.Suppressions)
	return rules.Options{
		Now:          func() time.Time { return now },
		SuppressFor:  cfg.Rules.SuppressFor.D(),
		Deadline:     budget,
		Suppressions: sup,
		Home:         env.Home,
		OS:           runtime.GOOS,
		HostTags:     cfg.Tags,
		// A one-shot process has no memory of earlier sightings, so an
		// in-memory baseline would call every sighting a first one and tag
		// (or raise) every match. Reporting everything as already seen
		// keeps novelty blocks inert in the hook; the daemon, which keeps
		// a real baseline, applies them.
		Baseline: seenAll{},
	}, degraded
}

type seenAll struct{}

func (seenAll) Seen(string) bool { return true }

// suppressions converts operator exceptions from the config. An entry
// whose expiry cannot be read is dropped (more findings, never fewer) and
// reported as degraded.
func suppressions(in []config.Suppression) (out []rules.Suppression, degraded bool) {
	for _, s := range in {
		r := rules.Suppression{RuleID: s.Rule, Match: s.Match, Reason: s.Reason, Tags: s.Tags}
		if e := strings.TrimSpace(s.Expires); e != "" {
			t, ok := parseExpiry(e)
			if !ok {
				degraded = true
				continue
			}
			r.Expires = t
		}
		out = append(out, r)
	}
	return out, degraded
}

// parseExpiry reads RFC 3339 or a bare date. A bare date expires at the
// start of that day in UTC: the earlier reading, so an exception never
// outlives what the operator wrote.
func parseExpiry(s string) (time.Time, bool) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, true
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t.UTC(), true
	}
	return time.Time{}, false
}
