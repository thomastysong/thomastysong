package main

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/thomastysong/spoor/internal/catalog"
	"github.com/thomastysong/spoor/internal/config"
	"github.com/thomastysong/spoor/internal/engine"
	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/privacy"
	"github.com/thomastysong/spoor/internal/rules"
)

// captureSink is the non-shipping sink of detect, scan and ci: it keeps the
// records a command prints (detections, posture, summaries, inventory when
// asked) and only counts the rest, so a large replay in the standard profile
// does not hold every activity record in memory.
type captureSink struct {
	name string
	keep map[event.Kind]bool

	mu      sync.Mutex
	records []*event.Event
	counts  map[string]int
}

func newCaptureSink(name string, kinds ...event.Kind) *captureSink {
	k := map[event.Kind]bool{}
	for _, x := range kinds {
		k[x] = true
	}
	return &captureSink{name: name, keep: k, counts: map[string]int{}}
}

func (c *captureSink) Name() string { return c.name }

func (c *captureSink) Write(batch []*event.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range batch {
		if e == nil {
			continue
		}
		c.counts[e.Kind.Stream()]++
		if c.keep[e.Kind] {
			c.records = append(c.records, e.Clone())
		}
	}
	return nil
}

func (c *captureSink) Flush() error { return nil }
func (c *captureSink) Close() error { return nil }

func (c *captureSink) all() []*event.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*event.Event(nil), c.records...)
}

// threshold is a --fail-on value: a severity or a detection class.
type threshold struct {
	raw  string
	by   string // severity | class | none
	rank int
}

func parseFailOn(s string) (threshold, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "none", "never", "off":
		return threshold{raw: s, by: "none"}, nil
	case event.ClassSignal, event.ClassFinding, event.ClassAlert:
		return threshold{raw: s, by: "class", rank: event.ClassRank(s)}, nil
	}
	if r := event.SeverityRank(s); r > 0 {
		return threshold{raw: s, by: "severity", rank: r}, nil
	}
	return threshold{}, fmt.Errorf("--fail-on %q: want none, a severity (info, low, medium, high, critical) or a class (signal, finding, alert)", s)
}

func (t threshold) hit(d *event.Detection) bool {
	if d == nil {
		return false
	}
	switch t.by {
	case "severity":
		return event.SeverityRank(d.Severity) >= t.rank
	case "class":
		return event.ClassRank(d.Class) >= t.rank
	}
	return false
}

// evalOptions configures an engine run in detect mode.
type evalOptions struct {
	cfg     *config.Config
	set     *rules.Set
	catalog *catalog.Catalog
	now     func() time.Time
}

// evalReport is what detect and ci exec print.
type evalReport struct {
	Detections []*event.Event `json:"detections"`
	Posture    []*event.Event `json:"posture,omitempty"`
	Summaries  []*event.Event `json:"sessions,omitempty"`
	Summary    evalSummary    `json:"summary"`
}

type evalSummary struct {
	Input       *inputStats       `json:"input"`
	Detections  int               `json:"detections"`
	ByRule      map[string]int    `json:"by_rule,omitempty"`
	BySeverity  map[string]int    `json:"by_severity,omitempty"`
	ByClass     map[string]int    `json:"by_class,omitempty"`
	FailOn      string            `json:"fail_on"`
	AtOrAbove   int               `json:"at_or_above_fail_on"`
	Sessions    int               `json:"sessions"`
	Rules       int               `json:"rules"`
	RulesHash   string            `json:"rules_hash"`
	Profile     string            `json:"privacy_profile"`
	Engine      map[string]uint64 `json:"engine,omitempty"`
	EmittedByTo map[string]int    `json:"records,omitempty"`
}

// evaluate runs events through a detect-mode pipeline. Host is left zero so
// every record keeps its own host (central re-evaluation); Close writes the
// final session summaries. Records go through the privacy policy like
// anything the daemon writes, so the printout is no more revealing than the
// outbox would be.
func evaluate(o evalOptions, stats *inputStats, feed func(emit func(*event.Event)) error) (*evalReport, error) {
	out := newCaptureSink("detect", event.KindDetection, event.KindPosture, event.KindSummary)
	local := newCaptureSink("detect-local", event.KindDetection, event.KindPosture, event.KindSummary)
	now := o.now
	if now == nil {
		now = time.Now
	}
	p, err := engine.New(engine.Options{
		Config:        o.cfg,
		Catalog:       o.catalog,
		Rules:         o.set,
		Outbox:        out,
		Local:         local,
		Mode:          engine.ModeDetect,
		Now:           now,
		SensorVersion: versionString(),
		// Re-evaluating someone's records is not collection: the host's
		// kill switch does not apply to it.
		Disabled: func() bool { return false },
	})
	if err != nil {
		return nil, err
	}
	var batch []*event.Event
	flush := func() {
		if len(batch) > 0 {
			p.Ingest(batch...)
			batch = batch[:0]
		}
	}
	ferr := feed(func(e *event.Event) {
		batch = append(batch, e)
		if len(batch) >= 256 {
			flush()
		}
	})
	flush()
	cerr := p.Close()
	if ferr != nil {
		return nil, ferr
	}
	if cerr != nil {
		return nil, cerr
	}
	rep := &evalReport{Summary: evalSummary{
		Input: stats, ByRule: map[string]int{}, BySeverity: map[string]int{}, ByClass: map[string]int{},
		Rules: o.set.Count(), RulesHash: o.set.Hash(), Profile: o.cfg.Privacy.Profile,
		Engine: p.Stats(), EmittedByTo: map[string]int{},
	}}
	for k, v := range out.counts {
		rep.Summary.EmittedByTo["outbox."+k] += v
	}
	for k, v := range local.counts {
		rep.Summary.EmittedByTo["local."+k] += v
	}
	sessions := map[string]bool{}
	for _, e := range append(out.all(), local.all()...) {
		switch {
		case e.Kind == event.KindDetection && e.Type == event.TypeDetectionFinding && e.Detection != nil:
			rep.Detections = append(rep.Detections, e)
		case e.Kind == event.KindPosture:
			rep.Posture = append(rep.Posture, e)
		case e.Kind == event.KindSummary && e.Summary != nil && e.Summary.Final:
			rep.Summaries = append(rep.Summaries, e)
			if e.Session != nil {
				sessions[agentOf(e)+"\x00"+e.Session.ID] = true
			}
		}
	}
	sortByTime(rep.Detections)
	sortByTime(rep.Posture)
	sortByTime(rep.Summaries)
	for _, e := range rep.Detections {
		d := e.Detection
		rep.Summary.ByRule[d.RuleID]++
		rep.Summary.BySeverity[d.Severity]++
		rep.Summary.ByClass[d.Class]++
	}
	rep.Summary.Detections = len(rep.Detections)
	rep.Summary.Sessions = len(sessions)
	return rep, nil
}

// applyFailOn counts the detections at or above the threshold.
func (r *evalReport) applyFailOn(t threshold) int {
	r.Summary.FailOn = t.raw
	n := 0
	for _, e := range r.Detections {
		if t.hit(e.Detection) {
			n++
		}
	}
	r.Summary.AtOrAbove = n
	return n
}

func sortByTime(evs []*event.Event) {
	sort.SliceStable(evs, func(i, j int) bool { return evs[i].TS.Time.Before(evs[j].TS.Time) })
}

func agentOf(e *event.Event) string {
	if e.Agent != nil {
		return e.Agent.ID
	}
	return ""
}

// printReport renders a report for a terminal: one block per detection,
// then the run summary.
func printReport(w io.Writer, r *evalReport) {
	for _, e := range r.Detections {
		d := e.Detection
		fmt.Fprintf(w, "%s  %-8s %-7s %s  %s\n", e.TS.Time.UTC().Format(time.RFC3339), d.Severity, d.Class, d.RuleID, d.Title)
		var ctx []string
		if e.Host != nil && e.Host.Name != "" {
			ctx = append(ctx, "host="+e.Host.Name)
		}
		if e.User != nil && (e.User.Name != "" || e.User.ID != "") {
			ctx = append(ctx, "user="+firstNonEmpty(e.User.Name, e.User.ID))
		}
		if e.Agent != nil {
			ctx = append(ctx, "agent="+e.Agent.ID)
		}
		if e.Session != nil && e.Session.ID != "" {
			ctx = append(ctx, "session="+clip(e.Session.ID, 40))
		}
		if d.Count > 1 {
			ctx = append(ctx, fmt.Sprintf("count=%d", d.Count))
		}
		if len(ctx) > 0 {
			fmt.Fprintf(w, "    %s\n", strings.Join(ctx, " "))
		}
		for _, k := range sortedKeys(d.Evidence) {
			fmt.Fprintf(w, "    %s: %s\n", k, clip(d.Evidence[k], 200))
		}
	}
	for _, e := range r.Posture {
		if c := e.Check; c != nil && c.Status == "fail" {
			fmt.Fprintf(w, "posture  %-8s %s  %s  %s\n", c.Severity, c.ID, clip(c.Title, 60), clip(c.Subject, 80))
		}
	}
	s := r.Summary
	fmt.Fprintf(w, "\n%d detection(s) in %d session(s) from %d evaluated record(s) (%d line(s), %d file(s)); rules %d, profile %s\n",
		s.Detections, s.Sessions, s.Input.Evaluated, s.Input.Lines, s.Input.Files, s.Rules, s.Profile)
	if len(s.BySeverity) > 0 {
		var parts []string
		for _, sev := range []string{event.SevCritical, event.SevHigh, event.SevMedium, event.SevLow, event.SevInfo} {
			if n := s.BySeverity[sev]; n > 0 {
				parts = append(parts, fmt.Sprintf("%s %d", sev, n))
			}
		}
		fmt.Fprintf(w, "by severity: %s\n", strings.Join(parts, ", "))
	}
	if len(s.Input.Skipped) > 0 {
		var parts []string
		for _, k := range sortedKeys(s.Input.Skipped) {
			parts = append(parts, fmt.Sprintf("%s %d", k, s.Input.Skipped[k]))
		}
		fmt.Fprintf(w, "not evaluated: %s\n", strings.Join(parts, ", "))
	}
	if s.FailOn != "" && s.FailOn != "none" {
		fmt.Fprintf(w, "at or above --fail-on %s: %d\n", s.FailOn, s.AtOrAbove)
	}
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// profileOverride applies --profile to a configuration copy.
func profileOverride(cfg *config.Config, profile string) error {
	if profile == "" {
		return nil
	}
	p, err := privacy.ParseProfile(profile)
	if err != nil {
		return err
	}
	cfg.Privacy.Profile = string(p)
	return cfg.Validate()
}
