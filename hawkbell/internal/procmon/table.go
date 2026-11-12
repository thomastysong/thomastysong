package procmon

import (
	"sort"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
	"github.com/thomastysong/thomastysong/hawkbell/internal/platform"
)

// procKey identifies one process instance: a later process that reuses the
// pid has a different start key.
type procKey struct {
	pid int
	key uint64
}

// exitMark remembers that a pid exited at a table sequence number, so a
// scan that listed the process just before it exited does not bring it
// back.
type exitMark struct {
	seq uint64
	at  time.Time
}

// node is one process in the table. The table holds every visible process
// with a few fields each (so any pid can be attributed by walking parents);
// only agent roots keep their command line.
type node struct {
	pid, ppid int
	key       uint64
	comm      string // kernel name as the cheap identity pass sees it
	name, exe string
	start     time.Time
	uid, user string
	added     uint64 // table sequence number at insertion
	full      bool   // a full record was read
	resolved  bool   // attribution was decided
	root      *root  // set when this process is itself an agent root
	// owner is the nearest enclosing agent root, decided when the process
	// was first seen and kept afterwards: a child that outlives its parent
	// is re-parented to init (or a subreaper) but still belongs to the
	// agent that started it.
	owner  *root
	env    envFacts
	exited time.Time // set on tombstones
	// self: hawkbell's own hook process (self.go), never reported.
	self bool
	// kthread: a kernel thread, left out of the readability counts.
	kthread bool
	// unreadable: the last full read of the process was refused with
	// EACCES or EPERM (its environment, which needs the same access as
	// its executable link and working directory).
	unreadable bool
}

// root is one agent root process.
type root struct {
	n     *node
	k     procKey
	prod  *prodInfo
	ap    AgentProc
	alive bool
	// launcher is set when the root was identified from its command line
	// only (npx, uvx, bunx naming the package): the real agent it starts is
	// its payload, not a second agent.
	launcher bool
	argsCut  bool
	// bucket rate-caps the root's process.exec events on the monitor's
	// clock; osqBucket does the same for osquery rows on their own event
	// time, so that a delivery batch is not mistaken for a burst.
	bucket, osqBucket bucket
}

func (r *root) addSession(id string) {
	if id == "" || contains(r.ap.SessionIDs, id) || len(r.ap.SessionIDs) >= maxSessionsKept {
		return
	}
	r.ap.SessionIDs = append(r.ap.SessionIDs, id)
}

// absorb merges what the payload of a launcher root shows about the run.
// The launcher's command line is "npx @openai/codex ..." or, worse, an npm
// process title that has eaten the arguments; the payload's is the agent's
// real one. The start event has already gone out; Agents, Attribute, the
// stop event and the payload's own process.exec event carry the result.
func (r *root) absorb(p *AgentProc) {
	for _, f := range p.Flags {
		if !contains(r.ap.Flags, f) && len(r.ap.Flags) < maxMarkers*4 {
			r.ap.Flags = append(r.ap.Flags, f)
		}
	}
	r.ap.Headless = r.ap.Headless || p.Headless
	r.ap.Bare = r.ap.Bare || p.Bare
	r.ap.HookFree = r.ap.HookFree || p.HookFree
	r.ap.PersistenceFree = r.ap.PersistenceFree || p.PersistenceFree
	if r.ap.ConfigHome == "" {
		r.ap.ConfigHome = p.ConfigHome
	}
}

// observed is one process read from the OS outside the table lock.
type observed struct {
	id   ident
	rec  *platform.Proc
	envF envFacts
	cand *rootCand
	via  string    // cn_proc | poll | osquery
	ts   time.Time // exec time for exec events
	exec bool      // the process just ran exec (report it even if known)
	cwd  string
	// name, args and argsCut are the emitted (redacted, bounded) forms,
	// computed outside the table lock: redaction runs regular expressions
	// and must not hold up the connector reader. args is set only when
	// argsDone (for processes likely to be reported).
	name     string
	args     []string
	argsCut  bool
	argsDone bool
	canary   bool
	// rename: a re-read of a known process that changed its own name
	// (setproctitle, a Node process.title) without running exec.
	rename bool
	isNew  bool // first full sighting (set by ingest)
	// self: hawkbell's own hook process (self.go).
	self bool
	// unreadable: reading the process was refused (EACCES, EPERM).
	unreadable bool
}

const (
	viaCNProc = SourceCNProc
	viaPoll   = SourcePoll
)

func (n *node) update(o *observed) {
	if o.id.key != 0 {
		n.key = o.id.key
		n.kthread = o.id.kthread
	}
	if o.id.comm != "" {
		n.comm = o.id.comm
	}
	if o.id.ppid > 0 {
		n.ppid = o.id.ppid
	}
	if r := o.rec; r != nil {
		if o.name == "" && r.Name != "" {
			o.name = emitName(r.Name)
		}
		n.name = o.name
		n.exe = capString(r.Exe, 4096)
		n.start = r.Start
		n.uid = capString(r.UID, 128)
		n.user = capString(r.User, 256)
		n.full = true
		n.self = o.self
		n.unreadable = o.unreadable
		if r.PPID > 0 {
			n.ppid = r.PPID
		}
	}
	if o.envF.known {
		n.env = o.envF
	}
}

func (n *node) attributed() bool { return n.root != nil || n.owner != nil || n.env.verified }

// ingest merges observations into the table and returns the events they
// cause plus the pids of parents that the marker logic wants promoted to
// agent roots. The caller holds m.mu. seq0 is the table sequence number
// taken before the observations were read.
func (m *Monitor) ingest(obs []*observed, seq0 uint64, now time.Time) (evs []*event.Event, promote []int) {
	// Parents normally start before their children; ordering by start time
	// and then pid lets one pass resolve a whole new subtree.
	sort.SliceStable(obs, func(i, j int) bool {
		a, b := obs[i], obs[j]
		if a.rec != nil && b.rec != nil && !a.rec.Start.Equal(b.rec.Start) {
			return a.rec.Start.Before(b.rec.Start)
		}
		return a.id.pid < b.id.pid
	})
	fresh := make([]*node, len(obs))
	for i, o := range obs {
		if o == nil || o.canary || o.id.pid <= 0 {
			continue
		}
		n := m.nodes[o.id.pid]
		if n != nil && n.key != 0 && o.id.key != 0 && n.key != o.id.key {
			// The pid was reused while nobody was looking.
			evs = append(evs, m.retire(n, now, nil)...)
			n = nil
		}
		if n == nil {
			if mk, ok := m.exitMark[o.id.pid]; ok && mk.seq > seq0 {
				continue // exited after it was read
			}
			if len(m.nodes) >= maxTable {
				m.st.tableFull.Add(1)
				continue
			}
			m.seq++
			n = &node{pid: o.id.pid, added: m.seq}
			m.nodes[n.pid] = n
		}
		// A fork the connector reported and that only renamed itself is
		// not new: it never ran exec.
		o.isNew = !n.full && o.rec != nil && !o.rename
		n.update(o)
		fresh[i] = n
	}
	for i, o := range obs {
		n := fresh[i]
		if n == nil || m.nodes[n.pid] != n {
			continue
		}
		e, p := m.resolve(n, o, now)
		evs = append(evs, e...)
		if p > 0 {
			promote = append(promote, p)
		}
	}
	return evs, promote
}

// resolve decides whether n is an agent root, which root it belongs to, and
// which events its observation causes.
func (m *Monitor) resolve(n *node, o *observed, now time.Time) (evs []*event.Event, promote int) {
	parent := m.parentOf(n)
	if parent != nil && !parent.resolved {
		m.settle(parent)
	}
	enc := m.enclosing(n)
	if o.self {
		return m.resolveSelf(n, o, enc, now), 0
	}
	was := n.root
	if was != nil && was.alive && !o.exec && !o.isNew {
		// Read again without an exec (the agent renamed itself): it is
		// still the agent it was. Only an exec can end a live root.
		n.resolved = true
		return nil, 0
	}
	if c := o.cand; c != nil {
		if was != nil && was.alive && was.prod.id == c.prod.id {
			// The agent ran exec on itself (a self-update or relaunch).
			n.resolved = true
			return nil, 0
		}
		if m.becomesRoot(n, parent, enc, c) {
			if was != nil {
				evs = append(evs, m.endRoot(was, now, nil)...)
			}
			if r := m.newRoot(n, c, enc); r != nil {
				evs = append(evs, m.startEvent(r, now))
				n.resolved = true
				// An agent started by another agent is also something the
				// enclosing agent ran.
				if enc != nil && (o.exec || o.isNew) {
					evs = append(evs, m.execFor(n, o, enc, "", now)...)
				}
				return evs, 0
			}
		}
		if enc != nil && enc.launcher && enc.prod.id == c.prod.id && n.root == nil {
			enc.absorb(&c.ap)
		}
	}
	if was != nil {
		// The root ran exec into something that is not the same agent.
		evs = append(evs, m.endRoot(was, now, nil)...)
		n.root = nil
	}
	if n.owner == nil {
		n.owner = enc
	}
	n.resolved = true
	owner, marker := n.owner, ""
	if owner == nil && n.env.verified {
		// Only a verified marker reports a process on its own; a weak one
		// (a user-exported switch, an unverified name) is in every process
		// of the shell that exported it and only answers Attribute.
		marker = n.env.product
	}
	if owner == nil && marker == "" {
		return evs, 0
	}
	if owner != nil {
		owner.addSession(n.env.session(owner.prod.id))
	}
	if o.exec || o.isNew {
		evs = append(evs, m.execFor(n, o, owner, marker, now)...)
	}
	// Marker boundary: the children of an agent the catalog could not
	// identify (renamed binary, unknown build) still carry the marker it
	// sets. The nearest ancestor whose own environment lacks the marker is
	// that agent.
	if owner == nil && n.env.strong && parent != nil && parent.pid > 1 && parent.full &&
		parent.root == nil && parent.owner == nil && parent.env.known && !parent.env.hasProduct(marker, m.index()) {
		promote = parent.pid
	}
	return evs, promote
}

// resolveSelf settles hawkbell's own hook process: it stays in the table with
// the agent it belongs to (so whatever it starts is still that agent's) and
// produces no event. A root that ran exec into it has ended.
func (m *Monitor) resolveSelf(n *node, o *observed, enc *root, now time.Time) (evs []*event.Event) {
	if was := n.root; was != nil {
		evs = m.endRoot(was, now, nil)
		n.root = nil
	}
	if n.owner == nil {
		n.owner = enc
	}
	n.resolved = true
	if o.exec || o.isNew {
		m.st.selfExcluded.Add(1)
	}
	return evs
}

// countReadability stores the readability counts of the live user-space
// processes (Stats.ProcsTotal, ProcsUnreadable, ProcsHidden,
// ProcsProtected): the table's, plus denied, the processes the last listing
// found but could not read at all and that are not in the table. nDenied
// is how many the listing found in all. The caller holds m.mu.
func (m *Monitor) countReadability(denied []ident, nDenied int) {
	var total, unreadable, protected uint64
	for _, n := range m.nodes {
		if n.kthread || n.pid <= 0 {
			continue
		}
		total++
		if n.unreadable {
			unreadable++
			if m.protectedOwner(n.uid) {
				protected++
			}
		}
	}
	for _, id := range denied {
		// Kernel threads cannot be told apart here: they count too.
		total++
		unreadable++
		if m.protectedOwner(id.uid) {
			protected++
		}
	}
	m.st.procsTotal.Store(total)
	m.st.procsUnreadable.Store(unreadable)
	m.st.procsHidden.Store(uint64(nDenied))
	m.st.procsProtected.Store(protected)
}

// protectedOwner reports whether a process of this account that refuses
// the monitor is a protected process rather than a sign of a missing
// privilege: the monitor holds the read privilege (root, or the reader
// capabilities, or an elevated token) and the process runs as the system
// account (platform.IsSystemAccount). Windows protected processes and a
// sandbox's init refuse even such a monitor, and no privilege the sensor
// can be given opens them.
func (m *Monitor) protectedOwner(uid string) bool {
	return m.privileged && platform.IsSystemAccount(uid)
}

// settle resolves a node seen without an observation of its own (a parent
// that was already in the table, or a fork the connector reported).
func (m *Monitor) settle(n *node) {
	if n.owner == nil && n.root == nil {
		n.owner = m.enclosing(n)
	}
	n.resolved = true
}

func (m *Monitor) parentOf(n *node) *node {
	if n == nil || n.ppid <= 0 || n.ppid == n.pid {
		return nil
	}
	return m.nodes[n.ppid]
}

// enclosing returns the nearest agent root above n (n itself excluded).
func (m *Monitor) enclosing(n *node) *root {
	p := m.parentOf(n)
	for d := 0; p != nil && d < maxWalk; d++ {
		if p.root != nil {
			return p.root
		}
		if p.owner != nil {
			return p.owner
		}
		p = m.parentOf(p)
	}
	return nil
}

// depthTo counts the parent steps from n up to anc (maxWalk when anc is not
// an ancestor).
func (m *Monitor) depthTo(n, anc *node) int {
	p := m.parentOf(n)
	for d := 1; p != nil && d < maxWalk; d++ {
		if p == anc {
			return d
		}
		p = m.parentOf(p)
	}
	return maxWalk
}

// becomesRoot applies the nesting rules. A process of the same agent as its
// direct parent root is that agent's helper or relaunch (Gemini CLI
// re-executes itself; Electron-style agents fork helpers). The payload of a
// launcher root (npx -> sh -> node codex.js) is the same agent too. Any
// other agent below an agent is a nested agent and gets its own root.
func (m *Monitor) becomesRoot(n, parent *node, enc *root, c *rootCand) bool {
	if parent != nil && parent.root != nil && parent.root.prod.id == c.prod.id {
		return false
	}
	if enc != nil && enc.prod.id == c.prod.id && enc.launcher && m.depthTo(n, enc.n) <= 3 {
		return false
	}
	if len(m.roots) >= maxRoots {
		m.st.tableFull.Add(1)
		return false
	}
	return true
}

func (m *Monitor) newRoot(n *node, c *rootCand, enc *root) *root {
	r := &root{n: n, k: procKey{n.pid, n.key}, prod: c.prod, ap: c.ap.clone(), alive: true, launcher: c.launcher, argsCut: c.argsCut}
	if r.ap.Start.IsZero() {
		r.ap.Start = n.start
	}
	if enc != nil {
		r.ap.ParentAgent = enc.prod.id
	}
	if old := m.roots[r.k]; old != nil && old.alive {
		old.alive = false
	}
	m.roots[r.k] = r
	n.root = r
	n.owner = enc
	return r
}

func (m *Monitor) endRoot(r *root, at time.Time, exit *exitInfo) []*event.Event {
	if r == nil || !r.alive {
		return nil
	}
	r.alive = false
	if m.roots[r.k] == r {
		delete(m.roots, r.k)
	}
	return []*event.Event{m.stopEvent(r, at, exit)}
}

// retire removes a process that is gone. Attributed processes stay
// reachable as tombstones for a while: osquery delivers exec rows seconds
// after the process ended, and the attribution must still be answerable.
func (m *Monitor) retire(n *node, at time.Time, exit *exitInfo) []*event.Event {
	var evs []*event.Event
	if n.root != nil {
		evs = m.endRoot(n.root, at, exit)
	}
	if m.nodes[n.pid] == n {
		delete(m.nodes, n.pid)
	}
	if n.attributed() {
		n.exited = at
		if len(m.tomb) < maxTomb {
			m.tomb[n.pid] = n
		}
	}
	return evs
}

// prune drops expired tombstones and exit marks. Caller holds m.mu.
func (m *Monitor) prune(now time.Time) {
	for pid, n := range m.tomb {
		if now.Sub(n.exited) > tombTTL || now.Before(n.exited) {
			delete(m.tomb, pid)
		}
	}
	for pid, mk := range m.exitMark {
		if now.Sub(mk.at) > exitMarkTTL || now.Before(mk.at) {
			delete(m.exitMark, pid)
		}
	}
	for k, b := range m.markerB {
		if now.Sub(b.last) > tombTTL {
			delete(m.markerB, k)
		}
	}
}

// attributionOf answers Attribute for a node. Caller holds m.mu.
func (m *Monitor) attributionOf(n *node) (AgentProc, bool) {
	if n.root != nil {
		return n.root.ap.clone(), true
	}
	if n.owner != nil {
		return n.owner.ap.clone(), true
	}
	// A root found after this process was first seen (a promoted marker
	// boundary) still owns it.
	if n.exited.IsZero() {
		if r := m.enclosing(n); r != nil {
			n.owner = r
			return r.ap.clone(), true
		}
	}
	if n.env.product != "" {
		return m.markerProc(n), true
	}
	return AgentProc{}, false
}

// markerProc describes the agent behind a marker-attributed process that
// has no agent root above it: the process that set the marker (the parent
// of the topmost process carrying it) when that is known, else the topmost
// carrier itself.
func (m *Monitor) markerProc(n *node) AgentProc {
	product := n.env.product
	ix := m.index()
	top := n
	for d := 0; d < maxWalk; d++ {
		p := m.parentOf(top)
		if p == nil || p.pid <= 1 || !p.env.known || !p.env.hasProduct(product, ix) {
			break
		}
		top = p
	}
	b := top
	if p := m.parentOf(top); p != nil && p.pid > 1 && p.full {
		b = p
	}
	evidence := EvidenceEnvMarker
	if !n.env.verified {
		evidence = EvidenceEnvMarkerWeak
	}
	ap := AgentProc{
		PID: b.pid, PPID: b.ppid, Start: b.start, AgentID: product, Name: b.name, Exe: b.exe,
		User:     event.User{Name: b.user, ID: b.uid},
		Evidence: []string{evidence},
	}
	if pi := ix.prod(product); pi == nil || pi.dialect == "" {
		ap.HookFree = true
	}
	if s := n.env.session(product); s != "" {
		ap.SessionIDs = []string{s}
	}
	return ap
}

func capString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}
