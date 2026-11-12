package bench

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/thomastysong/spoor/internal/classify"
	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/transcript"
)

// Replay caps: a corpus directory is user data and may be enormous.
const (
	defaultMaxFiles   = 20000
	defaultMaxEvents  = 2_000_000
	defaultSamples    = 5
	maxSampleText     = 240
	maxLabelledSample = 40
)

// ReplayOptions configures a benign replay.
type ReplayOptions struct {
	// Roots are directories walked (without following symbolic links) for
	// session logs; "*.jsonl" files are read.
	Roots []string
	// Format is the transcript format id (transcript.FormatClaude when
	// empty).
	Format string
	// User is stamped on every event (the owner of the logs).
	User event.User
	// Home and OS describe the machine the sessions ran on, for path
	// classes ("~/.ssh" is only a secret path relative to the right home).
	Home, OS string
	// Samples is how many hits per rule are kept for review (default 5);
	// every hit that has a label is kept as well, up to 40 per rule.
	Samples int
	// Labels are reviewed verdicts for sampled hits (LoadLabels).
	Labels   []Label
	MaxFiles int
	MaxLine  int
	// Corpus names the corpus in the report (a path or a snapshot name).
	Corpus string
	// Aliases shorten long machine-specific prefixes in rendered samples
	// (a scratch directory to "$S"), longest prefix first.
	Aliases []Alias
}

// Alias replaces From with To in rendered sample text.
type Alias struct{ From, To string }

// CorpusStats describes what a replay read.
type CorpusStats struct {
	Files     int            `json:"files"`
	Unread    int            `json:"files_unreadable"`
	Sessions  int            `json:"sessions"`
	Threads   int            `json:"threads"`
	Events    int            `json:"events"`
	ToolCalls int            `json:"tool_calls"`
	Shell     int            `json:"shell_commands"`
	Prompts   int            `json:"prompts"`
	ToolKinds map[string]int `json:"tool_kinds"`
	First     string         `json:"first_event,omitempty"`
	Last      string         `json:"last_event,omitempty"`
}

// ReplaySample is one sampled hit, rendered for review.
type ReplaySample struct {
	EventID string `json:"event_id"`
	Thread  string `json:"thread"`
	TS      string `json:"ts"`
	Tool    string `json:"tool,omitempty"`
	Summary string `json:"summary"`
	Label   string `json:"label,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

// ReplayRule is one rule's replay result.
type ReplayRule struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Class    string `json:"class"`
	Severity string `json:"severity"`
	Hits     int    `json:"hits"`
	Threads  int    `json:"threads"`
	// Per1k is hits per 1,000 tool calls.
	Per1k      float64        `json:"per_1k_tool_calls"`
	HitRate    Rate           `json:"hit_rate"`
	ThreadRate Rate           `json:"thread_rate"`
	Labels     map[string]int `json:"labels,omitempty"`
	Samples    []ReplaySample `json:"samples,omitempty"`
}

// ReplayReport is the result of Replay.
type ReplayReport struct {
	Date         string       `json:"date"`
	Corpus       string       `json:"corpus"`
	RulesVersion string       `json:"rules_version"`
	RulesHash    string       `json:"rules_hash"`
	RulesCount   int          `json:"rules_count"`
	Stats        CorpusStats  `json:"stats"`
	Rules        []ReplayRule `json:"rules"`
	// ThreadsAny is the share of agent threads with at least one hit per
	// class.
	ThreadsAny map[string]Rate        `json:"threads_with_hit_by_class"`
	Engine     map[string]uint64      `json:"engine,omitempty"`
	Problems   []string               `json:"problems,omitempty"`
	Limits     []string               `json:"limits"`
	elapsed    time.Duration          `json:"-"`
	byID       map[string]*ReplayRule `json:"-"`
}

type replayEvent struct {
	ev     *event.Event
	thread string
}

// Replay reads every session log under o.Roots, evaluates all events in
// timestamp order (as a live daemon would have seen them) and reports per
// rule. Hits are matches: the engine's dedup window is shorter than any
// gap between events, so a report counts what the rules matched, not what
// survived suppression.
func (r *Runner) Replay(ctx context.Context, o ReplayOptions) (*ReplayReport, error) {
	start := time.Now()
	if len(o.Roots) == 0 {
		return nil, errors.New("bench: replay needs at least one corpus root")
	}
	if o.Format == "" {
		o.Format = transcript.FormatClaude
	}
	parser, ok := transcript.ForFormat(o.Format)
	if !ok {
		return nil, fmt.Errorf("bench: unknown transcript format %q", o.Format)
	}
	if o.Samples <= 0 {
		o.Samples = defaultSamples
	}
	if o.MaxFiles <= 0 {
		o.MaxFiles = defaultMaxFiles
	}
	if o.OS == "" {
		o.OS = "linux"
	}
	rep := &ReplayReport{
		Date:         r.o.Now().UTC().Format(time.DateOnly),
		Corpus:       o.Corpus,
		RulesVersion: r.set.Version(),
		RulesHash:    r.set.Hash(),
		RulesCount:   r.set.Count(),
		ThreadsAny:   map[string]Rate{},
		Limits:       replayLimits,
		byID:         map[string]*ReplayRule{},
	}
	if rep.Corpus == "" {
		rep.Corpus = strings.Join(o.Roots, ", ")
	}
	files, err := corpusFiles(o.Roots, o.MaxFiles)
	if err != nil {
		return nil, err
	}
	var all []replayEvent
	sessions := map[string]bool{}
	st := &rep.Stats
	st.ToolKinds = map[string]int{}
	threadName := map[string]string{}
	for _, f := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		evs, fs, err := transcript.ReadFile(f, parser, o.User, o.MaxLine)
		if err != nil {
			st.Unread++
			rep.Problems = append(rep.Problems, fmt.Sprintf("%s: %v", relTo(o.Roots, f), err))
			continue
		}
		if fs != nil && fs.Malformed > 0 {
			rep.Problems = append(rep.Problems, fmt.Sprintf("%s: %d malformed lines", relTo(o.Roots, f), fs.Malformed))
		}
		st.Files++
		th := relTo(o.Roots, f)
		threadName[f] = th
		if len(all)+len(evs) > defaultMaxEvents {
			return nil, fmt.Errorf("bench: corpus has more than %d events", defaultMaxEvents)
		}
		for _, e := range evs {
			if e == nil {
				continue
			}
			all = append(all, replayEvent{ev: e, thread: th})
			if e.Session != nil && e.Session.ID != "" {
				sessions[e.Session.ID] = true
			}
			switch e.Type {
			case event.TypeToolPre:
				st.ToolCalls++
				if e.Tool != nil {
					st.ToolKinds[string(e.Tool.Kind)]++
					if e.Tool.Kind == event.ToolShell {
						st.Shell++
					}
				}
			case event.TypePromptSubmit:
				st.Prompts++
			}
		}
	}
	st.Threads = len(threadName)
	st.Sessions = len(sessions)
	st.Events = len(all)
	sort.SliceStable(all, func(i, j int) bool { return all[i].ev.TS.Time.Before(all[j].ev.TS.Time) })
	if len(all) > 0 {
		st.First = all[0].ev.TS.UTC().Format(time.RFC3339)
		st.Last = all[len(all)-1].ev.TS.UTC().Format(time.RFC3339)
	}

	evf := r.factory(o.Home, o.OS)
	if r.o.NewEvaluator == nil {
		evf = RulesFactory(RulesOptions{Set: r.set, Home: o.Home, OS: o.OS})
	}
	ev, err := evf()
	if err != nil {
		return nil, err
	}
	defer ev.Close()

	type acc struct {
		hits    []hitRef
		threads map[string]bool
	}
	accs := map[string]*acc{}
	threadClass := map[string]map[string]bool{}
	byEventID := map[string]replayEvent{}
	var last time.Time
	for i, re := range all {
		if i%256 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		byEventID[re.ev.ID] = re
		hs := hitsOf(ev.Eval(re.ev), re.ev.ID)
		if re.ev.TS.Time.After(last) {
			last = re.ev.TS.Time
		}
		for _, h := range hs {
			a := accs[h.RuleID]
			if a == nil {
				a = &acc{threads: map[string]bool{}}
				accs[h.RuleID] = a
			}
			th := re.thread
			if src, ok := byEventID[h.EventID]; ok {
				th = src.thread
			}
			a.hits = append(a.hits, hitRef{hit: h, thread: th})
			a.threads[th] = true
			c := r.classOf(h)
			if threadClass[c] == nil {
				threadClass[c] = map[string]bool{}
			}
			threadClass[c][th] = true
		}
	}
	for _, h := range hitsOf(ev.Drain(last), "") {
		a := accs[h.RuleID]
		if a == nil {
			a = &acc{threads: map[string]bool{}}
			accs[h.RuleID] = a
		}
		a.hits = append(a.hits, hitRef{hit: h})
	}
	if re, ok := ev.(*RulesEvaluator); ok {
		rep.Engine = map[string]uint64{}
		for k, v := range re.Stats() {
			if !strings.HasPrefix(k, "rule_ns.") {
				rep.Engine[k] = v
			}
		}
		if n := rep.Engine["timeouts"] + rep.Engine["panics"]; n > 0 {
			rep.Problems = append(rep.Problems, fmt.Sprintf("engine reported %d timeouts and %d panics: counts are incomplete", rep.Engine["timeouts"], rep.Engine["panics"]))
		}
	}

	labels := indexLabels(o.Labels)
	for _, id := range r.ruleIDs() {
		in := r.infos[id]
		a := accs[id]
		row := ReplayRule{ID: id, Title: in.Title, Class: in.Class, Severity: in.Severity}
		if a != nil {
			row.Hits = len(a.hits)
			row.Threads = len(a.threads)
			row.Samples, row.Labels = sampleHits(id, a.hits, byEventID, labels, o.Samples, o.Aliases)
		}
		if st.ToolCalls > 0 {
			row.Per1k = 1000 * float64(row.Hits) / float64(st.ToolCalls)
		}
		row.HitRate = NewRate(min(row.Hits, st.ToolCalls), st.ToolCalls)
		row.ThreadRate = NewRate(row.Threads, st.Threads)
		rep.Rules = append(rep.Rules, row)
	}
	for i := range rep.Rules {
		rep.byID[rep.Rules[i].ID] = &rep.Rules[i]
	}
	for _, c := range []string{event.ClassAlert, event.ClassFinding, event.ClassSignal} {
		rep.ThreadsAny[c] = NewRate(len(threadClass[c]), st.Threads)
	}
	// Problems name corpus files, whose paths hold the same machine
	// prefixes and session ids as the samples.
	for i, p := range rep.Problems {
		rep.Problems[i] = applyAliases(p, o.Aliases)
	}
	rep.elapsed = time.Since(start)
	return rep, nil
}

type hitRef struct {
	hit    Hit
	thread string
}

var replayLimits = []string{
	"One workload: Claude Code agents building and red-teaming this project on one Linux machine, as root, in a sandbox. Shell is most of the tool calls; there is no frontend, data-science or Windows work in it.",
	"Agent threads (one transcript file each: a main session and its subagents) are the unit for 'threads hit'; they share one root session, so they are not independent developers.",
	"Hits per 1,000 tool calls use tool.pre events as the denominator. Wilson intervals treat tool calls as independent trials, which they are not inside one thread; read them as a lower bound on the uncertainty.",
	"The corpus contains deliberate red-team experiments (privileged containers, stopping osqueryd, writing managed settings into overlays, downloading research material). Those hits are labelled red_team: true positives without malice.",
	"Zero hits for a rule here bounds its benign rate only for this workload. It says nothing about prevalence and cannot stand in for a benign fleet of real developers.",
	"Events come from transcripts only: the process monitor, inventory scans and hooks were not part of the replay, so OS-plane and posture rules are not exercised here.",
}

// corpusFiles walks roots for *.jsonl regular files without following
// symbolic links.
func corpusFiles(roots []string, max int) ([]string, error) {
	var out []string
	for _, root := range roots {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil // an unreadable subtree is skipped, not fatal
			}
			if d.Type()&fs.ModeSymlink != 0 {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if d.Type().IsRegular() && strings.HasSuffix(d.Name(), ".jsonl") {
				out = append(out, p)
				if len(out) > max {
					return fmt.Errorf("bench: corpus has more than %d files", max)
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(out)
	return out, nil
}

func relTo(roots []string, p string) string {
	for _, r := range roots {
		if rel, err := filepath.Rel(r, p); err == nil && !strings.HasPrefix(rel, "..") {
			return filepath.ToSlash(rel)
		}
	}
	return filepath.Base(p)
}

// sampleHits keeps every labelled hit (up to a cap) and n evenly spaced
// unlabelled ones, and counts labels over the kept samples.
func sampleHits(rule string, hits []hitRef, byID map[string]replayEvent, labels map[string]Label, n int, aliases []Alias) ([]ReplaySample, map[string]int) {
	var out []ReplaySample
	counts := map[string]int{}
	keep := map[int]bool{}
	for i, h := range hits {
		if _, ok := labels[labelKey(rule, h.hit.EventID)]; ok && len(keep) < maxLabelledSample {
			keep[i] = true
		}
	}
	unl := 0
	if len(hits) > 0 {
		step := float64(len(hits)) / float64(n)
		if step < 1 {
			step = 1
		}
		for k := 0.0; int(k) < len(hits) && unl < n; k += step {
			i := int(k)
			if !keep[i] {
				keep[i] = true
				unl++
			}
		}
	}
	idx := sortedInts(keep)
	for _, i := range idx {
		h := hits[i]
		s := ReplaySample{EventID: h.hit.EventID, Thread: applyAliases(h.thread, aliases), Summary: summarize(h.hit.Evidence, aliases)}
		if re, ok := byID[h.hit.EventID]; ok {
			s.TS = re.ev.TS.UTC().Format(time.RFC3339)
			if re.ev.Tool != nil {
				s.Tool = re.ev.Tool.Name
			}
			if s.Summary == "" {
				s.Summary = summarizeEvent(re.ev, aliases)
			}
		}
		if l, ok := labels[labelKey(rule, h.hit.EventID)]; ok {
			s.Label, s.Reason = l.Label, l.Reason
			counts[l.Label]++
		} else {
			counts["unlabelled"]++
		}
		out = append(out, s)
	}
	return out, counts
}

func sortedInts(m map[int]bool) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

// summarize renders the engine's (already redacted) evidence for review,
// redacted once more, with aliases applied, cut, on one line.
func summarize(ev map[string]string, aliases []Alias) string {
	if len(ev) == 0 {
		return ""
	}
	keys := sortedKeys(ev)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+ev[k])
	}
	return cleanText(applyAliases(strings.Join(parts, "; "), aliases))
}

func summarizeEvent(ev *event.Event, aliases []Alias) string {
	switch {
	case ev.Target == nil:
		return ""
	case ev.Target.Path != "":
		return cleanText(applyAliases("target.path="+ev.Target.Path, aliases))
	case ev.Target.URL != "":
		return cleanText(applyAliases("target.url="+classify.RedactURL(ev.Target.URL, false), aliases))
	case ev.Target.Host != "":
		return cleanText("target.host=" + ev.Target.Host)
	}
	return ""
}

// minAliasCut is the shortest cut copy of an identifier alias that is
// replaced (see applyAliases).
const minAliasCut = 6

// applyAliases replaces each alias's From with its To, longest first. An
// alias whose From is an identifier (no path separator, such as a session
// id) also replaces a cut copy of it: the engine cuts long evidence values,
// so a value can end part-way through the id ("$T/-home-user/3f9c2e71-5b;").
// A cut copy is a prefix of From of at least minAliasCut bytes that starts
// and ends at an identifier boundary.
func applyAliases(s string, as []Alias) string {
	sorted := append([]Alias(nil), as...)
	sort.SliceStable(sorted, func(i, j int) bool { return len(sorted[i].From) > len(sorted[j].From) })
	for _, a := range sorted {
		if a.From != "" {
			s = strings.ReplaceAll(s, a.From, a.To)
		}
	}
	for _, a := range sorted {
		if len(a.From) > minAliasCut && !strings.ContainsAny(a.From, `/\`) {
			s = replaceCut(s, a)
		}
	}
	return s
}

// replaceCut replaces cut copies of a.From in s (see applyAliases).
func replaceCut(s string, a Alias) string {
	head := a.From[:minAliasCut]
	if !strings.Contains(s, head) {
		return s
	}
	var b strings.Builder
	i := 0
	for {
		j := strings.Index(s[i:], head)
		if j < 0 {
			break
		}
		j += i
		n := minAliasCut
		for n < len(a.From) && j+n < len(s) && s[j+n] == a.From[n] {
			n++
		}
		startOK := j == 0 || !idByte(s[j-1])
		endOK := j+n == len(s) || !idByte(s[j+n])
		b.WriteString(s[i:j])
		if startOK && endOK {
			b.WriteString(a.To)
		} else {
			b.WriteString(s[j : j+n])
		}
		i = j + n
	}
	b.WriteString(s[i:])
	return b.String()
}

func idByte(c byte) bool {
	return c == '-' || c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func cleanText(s string) string {
	s, _ = classify.Redact(s)
	s = trimLines(s)
	if len(s) > maxSampleText {
		cut := maxSampleText
		for cut > 0 && (s[cut]&0xC0) == 0x80 {
			cut--
		}
		s = s[:cut] + " [...]"
	}
	return s
}
