package engine

import (
	"sort"
	"strconv"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
	"github.com/thomastysong/thomastysong/hawkbell/internal/state"
)

// Coverage (BUILD-C C2 item 4, DECISIONS A1, A3, A6).
//
// Per (agent, account) the engine remembers when each surface last
// delivered and which agent processes the process monitor reported. The
// state is:
//
//	blind    a running, root-observed agent process that is hook-free or
//	         persistence-free, or that has been running for BlindAfter with
//	         no hook and no transcript/OTel activity since it started
//	covered  hook records and another surface (transcript or OTel) delivered
//	         within coverageWindow, and the hook did not fall silent while
//	         the other surface kept delivering (hookStaleAfter)
//	partial  one of them delivered, or only the process monitor sees it
//	absent   known (inventory, earlier activity) but nothing delivers
//
// The hook-bypass FINDING needs an independent root-observed surface: the
// process monitor (Options.RootSaw, or root-integrity agent.process
// records) must see that agent running for the same account, at least
// BypassMinUnmatched tool calls must have reached hawkbell on another surface
// without a hook record (or the agent's OTel hook-run counts must exceed
// the hook records received by as many), and Options.Hooked must say hooks
// should be there. With only self-reported surfaces it is a low-severity
// signal, at most one per session. Everything is keyed by the account the
// collector established, so one account's records never count for
// another's.
//
// The process table only takes agent.process.start and stop records that
// are root-integrity and come from the process monitor or osquery: a
// monitored user can write any Source into a spool record (it is then
// user-integrity), and a forged stop must not remove the root-observed
// process the hook-bypass finding and Fleet's agent_processes table rest
// on, nor a forged start add one. A pipeline that runs unprivileged has no
// root-integrity records, so it keeps no process table (Options.RootSaw
// still applies).
//
// Coverage entries are bounded per account (maxCoveragePerUser; a new entry
// evicts that account's oldest), and with a catalog only its agent ids are
// tracked, so records naming made-up agent ids cannot evict another
// account's coverage.

// Engine-generated rule ids. The 9xx range is reserved for the engine so
// that rule packs never collide with them.
const (
	RuleHookBypass       = "HB-COV-901" // finding: root-observed agent, hooks expected, calls without hook records
	RuleHookBypassSignal = "HB-COV-902" // signal: the same from self-reported surfaces only
)

// Labels on the hook-bypass records.
const (
	LabelHooksState       = "hooks_state"          // Options.Hooked for the agent and account
	LabelSurfaces         = "surfaces"             // surfaces that reported the session
	LabelUnmatchedCalls   = "unmatched_tool_calls" // calls seen without a hook record
	LabelOTelHookMismatch = "otel_hook_mismatch"   // OTel tool-hook firings beyond hook records
	LabelRootObserved     = "root_observed"        // the process monitor saw the agent
)

type covKey struct{ agent, user string }

type covEntry struct {
	agent, user, userID       string
	lastHook, lastOther, last time.Time
	updated                   time.Time
}

type proc struct {
	ap        state.AgentProcess
	key       covKey
	hookFree  bool
	integrity event.Integrity
	seen      time.Time
}

// userKey is how an account is named to Hooked, RootSaw and in Coverage:
// its name when the collector knows it, else its uid/SID.
func userKey(u *event.User) string {
	if u == nil {
		return ""
	}
	if u.Name != "" {
		return u.Name
	}
	return u.ID
}

// covEntry returns the coverage entry of an agent and account, creating
// it; nil when the agent is not one the catalog knows.
func (p *Pipeline) covEntry(agent string, u *event.User, now time.Time) *covEntry {
	k := covKey{agent, userKey(u)}
	e := p.cov[k]
	if e == nil {
		if p.o.Catalog != nil {
			if _, ok := p.o.Catalog.Get(agent); !ok {
				p.ctr.covUnknownAgent++
				return nil
			}
		}
		if p.covPerUser[k.user] >= maxCoveragePerUser {
			p.evictCoverage(k.user, true)
		}
		if len(p.cov) >= maxCoverage {
			p.evictCoverage("", false)
		}
		e = &covEntry{agent: agent, user: k.user}
		p.cov[k] = e
		p.covPerUser[k.user]++
	}
	if u != nil && u.ID != "" {
		e.userID = u.ID
	}
	e.updated = now
	return e
}

// evictCoverage removes the least recently updated entry (of one account
// when sameUser is set).
func (p *Pipeline) evictCoverage(user string, sameUser bool) {
	var oldest covKey
	var at time.Time
	first := true
	for k, e := range p.cov {
		if sameUser && k.user != user {
			continue
		}
		if first || e.updated.Before(at) {
			oldest, at, first = k, e.updated, false
		}
	}
	if first {
		return
	}
	delete(p.cov, oldest)
	if p.covPerUser[oldest.user] <= 1 {
		delete(p.covPerUser, oldest.user)
	} else {
		p.covPerUser[oldest.user]--
	}
}

// observeCoverage records which surface delivered for the agent and
// account of an activity record, duplicates included: a transcript twin of
// a hook record still proves the transcript is delivering.
func (p *Pipeline) observeCoverage(ev *event.Event, s *session, now time.Time) {
	if ev.Agent == nil || ev.Agent.ID == "" {
		return
	}
	switch ev.Type {
	case event.TypeAgentProcessStart:
		p.trackProcess(ev, now, true)
	case event.TypeAgentProcessStop:
		p.trackProcess(ev, now, false)
	}
	e := p.covEntry(ev.Agent.ID, ev.User, now)
	if e == nil {
		return
	}
	switch ev.Source {
	case event.SourceHook:
		e.lastHook = now
		e.last = now
	case event.SourceTranscript, event.SourceOTel:
		e.lastOther = now
		e.last = now
	}
}

func (p *Pipeline) observeInventory(ev *event.Event, now time.Time) {
	a := ev.Asset
	if a == nil || a.CatalogID == "" || a.Owner == "" || a.Change == event.ChangeRemoved {
		return
	}
	if a.Kind != event.AssetAgent {
		return
	}
	p.covEntry(a.CatalogID, &event.User{Name: a.Owner}, now)
}

func procKey(pr *event.Process) string {
	return strconv.Itoa(pr.PID) + "@" + strconv.FormatInt(pr.StartTime.UnixNano(), 10)
}

// trackProcess maintains the set of running agent roots from the process
// monitor's start and stop records.
func (p *Pipeline) trackProcess(ev *event.Event, now time.Time, start bool) {
	if ev.Process == nil || ev.Process.PID <= 0 {
		return
	}
	if ev.Source != event.SourceProcess && ev.Source != event.SourceOsquery {
		return
	}
	if ev.Integrity != event.IntegrityRoot {
		// A user-written record (normalize has set its integrity) never
		// changes what the process monitor saw.
		p.ctr.untrustedProcess++
		return
	}
	k := procKey(ev.Process)
	if !start {
		delete(p.procs, k)
		return
	}
	if len(p.procs) >= maxProcs {
		var oldest string
		var at time.Time
		first := true
		for pk, pr := range p.procs {
			if first || pr.seen.Before(at) {
				oldest, at, first = pk, pr.seen, false
			}
		}
		delete(p.procs, oldest)
	}
	pr := &proc{
		key:       covKey{ev.Agent.ID, userKey(ev.User)},
		integrity: ev.Integrity,
		seen:      now,
		hookFree:  ev.Labels["hook_free"] == "true" || ev.Labels["persistence_free"] == "true",
	}
	pr.ap = state.AgentProcess{
		PID:       ev.Process.PID,
		StartTime: ev.Process.StartTime.Time,
		AgentID:   ev.Agent.ID,
		Exe:       ev.Process.Exe,
		Flags:     append([]string(nil), ev.Process.Flags...),
	}
	if ev.User != nil {
		pr.ap.User, pr.ap.UserID = ev.User.Name, ev.User.ID
	}
	if ev.Session != nil {
		pr.ap.SessionID = ev.Session.ID
	}
	if ev.Container != nil {
		pr.ap.ContainerID = ev.Container.ID
	}
	p.procs[k] = pr
}

// rootSaw reports whether the process monitor sees the agent running for
// the account: Options.RootSaw when given, else the root-integrity process
// records this pipeline received.
func (p *Pipeline) rootSaw(agent, user string) bool {
	if p.o.RootSaw != nil {
		return p.o.RootSaw(agent, user)
	}
	for _, pr := range p.procs {
		if pr.key.agent == agent && pr.key.user == user && pr.integrity == event.IntegrityRoot {
			return true
		}
	}
	return false
}

// hooked returns discovery's hook state for the agent and account, or
// "unsupported" when the catalog knows the agent has no hook dialect hawkbell
// speaks, or "" when unknown.
func (p *Pipeline) hooked(agent, user string) string {
	if p.o.Hooked != nil {
		return p.o.Hooked(agent, user)
	}
	if p.o.Catalog != nil {
		if prod, ok := p.o.Catalog.Get(agent); ok && (prod.Hooks == nil || prod.Hooks.Dialect == "") {
			return "unsupported"
		}
	}
	return ""
}

// hooksExpected reports whether hook records should be arriving. Without
// discovery's view, hooks are expected once they have delivered for this
// agent and account before.
func (p *Pipeline) hooksExpected(agent, user string) bool {
	if p.o.Hooked != nil {
		switch p.o.Hooked(agent, user) {
		case "managed", "user", "modified":
			return true
		}
		return false
	}
	if e := p.cov[covKey{agent, user}]; e != nil {
		return !e.lastHook.IsZero()
	}
	return false
}

// coverage builds the per-agent, per-account statement; pmu is held.
func (p *Pipeline) coverage(now time.Time) []event.Coverage {
	type agg struct {
		n        int
		hookFree bool
		since    time.Time
	}
	running := map[covKey]*agg{}
	for _, pr := range p.procs {
		a := running[pr.key]
		if a == nil {
			a = &agg{since: pr.seen}
			running[pr.key] = a
		}
		a.n++
		a.hookFree = a.hookFree || pr.hookFree
		if pr.seen.Before(a.since) {
			a.since = pr.seen
		}
		if p.cov[pr.key] == nil {
			p.covEntry(pr.key.agent, &event.User{Name: pr.key.user, ID: pr.ap.UserID}, pr.seen)
		}
	}
	out := make([]event.Coverage, 0, len(p.cov))
	for k, e := range p.cov {
		c := event.Coverage{AgentID: k.agent, User: k.user, Hooks: p.hooked(k.agent, k.user)}
		r := running[k]
		if r != nil {
			c.Processes = r.n
		}
		isRunning := r != nil || p.rootSaw(k.agent, k.user)
		if !e.lastOther.IsZero() && now.Sub(e.lastOther) <= coverageWindow {
			c.Transcript = "tailing"
		}
		hookOK := !e.lastHook.IsZero() && now.Sub(e.lastHook) <= coverageWindow &&
			!(e.lastOther.Sub(e.lastHook) > hookStaleAfter)
		otherOK := c.Transcript == "tailing"
		switch {
		case isRunning && r != nil && r.hookFree:
			c.State = "blind"
		case isRunning && r != nil && now.Sub(r.since) >= BlindAfter && !e.last.After(r.since):
			c.State = "blind"
		case hookOK && otherOK:
			c.State = "covered"
		case hookOK || otherOK || isRunning:
			c.State = "partial"
		default:
			c.State = "absent"
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].AgentID != out[j].AgentID {
			return out[i].AgentID < out[j].AgentID
		}
		return out[i].User < out[j].User
	})
	return out
}

// checkBypass evaluates the hook-bypass logic for every live session.
func (p *Pipeline) checkBypass(now time.Time) {
	keys := make([]string, 0, len(p.sessions))
	for k := range p.sessions {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		s := p.sessions[k].Value.(*session)
		if s.bypassFinding || s.agent == nil || userKey(s.user) == "" {
			// A session without an account (OTel no session claimed) has
			// nobody a coverage detection could be about.
			continue
		}
		unmatched := len(s.unmatched)
		mismatch := s.otelMismatch(now)
		if max(unmatched, mismatch) < BypassMinUnmatched {
			continue
		}
		user := userKey(s.user)
		if !p.hooksExpected(s.agent.ID, user) {
			continue
		}
		if p.rootSaw(s.agent.ID, user) {
			s.bypassFinding = true
			p.ctr.bypassFindings++
			p.detection(p.bypassRecord(s, now, unmatched, mismatch, true), s, now)
			continue
		}
		if !s.bypassSignal {
			s.bypassSignal = true
			p.ctr.bypassSignals++
			p.detection(p.bypassRecord(s, now, unmatched, mismatch, false), s, now)
		}
	}
}

func (p *Pipeline) bypassRecord(s *session, now time.Time, unmatched, mismatch int, root bool) *event.Event {
	rule, class, sev, conf := RuleHookBypassSignal, event.ClassSignal, event.SevLow, "low"
	title := "Agent tool calls without hook records (self-reported surfaces only)"
	integ := event.IntegrityUser
	if root {
		rule, class, sev, conf = RuleHookBypass, event.ClassFinding, event.SevHigh, "medium"
		title = "Hook bypass suspected: a root-observed agent made tool calls its hooks did not report"
		integ = p.integrity
	}
	ss := s.sess
	d := &event.Event{
		V:         event.SchemaVersion,
		TS:        event.At(now),
		Kind:      event.KindDetection,
		Type:      event.TypeDetectionFinding,
		Source:    event.SourceSensor,
		Fidelity:  event.FidelityInferred,
		Integrity: integ,
		Host:      s.host,
		User:      s.user,
		Agent:     s.agent,
		Session:   &ss,
		// The coverage facts have no field in the event contract, so they
		// are labels; Detection.Evidence is reserved for matched field
		// values (and the privacy allowlist only passes registered fields).
		Labels: map[string]string{
			LabelHooksState:       p.hooked(s.agent.ID, userKey(s.user)),
			LabelSurfaces:         surfaceList(s),
			LabelUnmatchedCalls:   strconv.Itoa(unmatched),
			LabelOTelHookMismatch: strconv.Itoa(mismatch),
			LabelRootObserved:     strconv.FormatBool(root),
		},
		Detection: &event.Detection{
			RuleID:     rule,
			Title:      title,
			Class:      class,
			Severity:   sev,
			Confidence: conf,
			Maturity:   "experimental",
			Category:   "coverage",
			// T1562.001 Impair Defenses: Disable or Modify Tools.
			Tags:     []string{"attack.t1562.001", "hawkbell.coverage"},
			EventIDs: append([]string(nil), s.unmatchedIDs...),
			Count:    1,
			Remedy:   "Run `hawkbell hooks status` for this user and agent; check for a higher-precedence managed settings source, a removed or edited hook entry, or an agent started in a hook-free mode.",
		},
	}
	if len(d.Detection.EventIDs) > 16 {
		d.Detection.EventIDs = d.Detection.EventIDs[:16]
	}
	host, user, agent, sid := idParts(d)
	d.Dedupe = event.DedupeKey("detection", rule, host, user, agent, sid)
	d.ID = event.StableID(now, "hawkbell/coverage", rule, d.Dedupe)
	d.Detection.DedupKey = event.DedupeKey(rule, s.key)
	p.stamp(d)
	return d
}

func surfaceList(s *session) string {
	var l []string
	for _, src := range []event.Source{event.SourceHook, event.SourceTranscript, event.SourceOTel, event.SourceProcess, event.SourceOsquery} {
		if s.surfaces[src] {
			l = append(l, string(src))
		}
	}
	out := ""
	for i, x := range l {
		if i > 0 {
			out += ","
		}
		out += x
	}
	return out
}

// stateProcesses is the agent_processes table content, with the account
// pseudonymized exactly as the privacy stage pseudonymizes it in records.
func (p *Pipeline) stateProcesses() []state.AgentProcess {
	out := make([]state.AgentProcess, 0, len(p.procs))
	for _, pr := range p.procs {
		ap := pr.ap
		ap.Flags = append([]string(nil), pr.ap.Flags...)
		ap.User, ap.UserID = p.pseudoUser(ap.User, ap.UserID)
		out = append(out, ap)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].PID != out[j].PID {
			return out[i].PID < out[j].PID
		}
		return out[i].StartTime.Before(out[j].StartTime)
	})
	return out
}

// pseudoUser mirrors privacy's identity pass: with pseudonyms on, the name
// (or, without a name, the id) becomes the keyed pseudonym, and without a
// key the account is removed.
func (p *Pipeline) pseudoUser(name, id string) (string, string) {
	if !p.pol.PseudonymizeUsers {
		return name, id
	}
	if name != "" {
		ps := p.pol.Pseudonym(name)
		return ps, ps
	}
	return "", p.pol.Pseudonym(id)
}
