package procmon

import (
	"strings"
	"time"

	"github.com/thomastysong/spoor/internal/catalog"
	"github.com/thomastysong/spoor/internal/classify"
	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/platform"
)

// rootCand is everything about a would-be agent root that has to be read
// from the OS. It is gathered outside the table lock; whether the process
// really becomes a root (nesting rules) is decided under it.
type rootCand struct {
	prod     *prodInfo
	ap       AgentProc
	launcher bool
}

// prepare reads one process for ingestion. It must be called without m.mu.
// rec may be a record the backend already read during a listing.
func (m *Monitor) prepare(id ident, rec *platform.Proc, via string, ts time.Time) *observed {
	if rec == nil {
		r, rid, ok := m.src.read(id.pid)
		if !ok {
			return nil
		}
		rec, id = &r, rid
	}
	o := &observed{id: id, rec: rec, via: via, ts: ts}
	if m.isCanary(rec) {
		o.canary = true
		return o
	}
	ix := m.index()
	env, err := m.src.env(id.pid, ix.keep)
	if err != nil {
		env = nil
	}
	o.envF = ix.scanEnv(env)
	if id.pid != m.self {
		o.cand = m.candidate(rec, env, o.envF)
	}
	if o.cand == nil && (o.envF.product != "" || m.parentAttributed(id.ppid)) {
		o.cwd = m.src.cwd(id.pid)
	}
	return o
}

// parentAttributed is a cheap pre-check so that the working directory is
// read only for processes likely to be reported.
func (m *Monitor) parentAttributed(ppid int) bool {
	if ppid <= 0 {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	p := m.nodes[ppid]
	return p != nil && (p.root != nil || p.owner != nil || p.env.product != "" || m.enclosing(p) != nil)
}

// candidate identifies an agent root from the catalog. Only products of
// kind "agent" are roots: an IDE or desktop app runs plenty of processes a
// person started by hand, so its children are attributed only through the
// marker variables it sets for agent-run commands.
func (m *Monitor) candidate(rec *platform.Proc, env map[string]string, ef envFacts) *rootCand {
	if m.cat == nil || (rec.Exe == "" && len(rec.Args) == 0) {
		return nil
	}
	mt, ok := m.cat.MatchProcessDetail(rec.Name, rec.Exe, rec.Args)
	if !ok || mt.Product.Kind != string(event.AssetAgent) {
		return nil
	}
	return m.buildCand(rec, env, ef, mt.Product, mt.Evidence)
}

func (m *Monitor) buildCand(rec *platform.Proc, env map[string]string, ef envFacts, p catalog.Product, evidence []string) *rootCand {
	pi := m.index().prod(p.ID)
	if pi == nil {
		pi = &prodInfo{id: p.ID, name: p.Name, kind: p.Kind, sessionEnv: p.SessionEnv, homeEnv: p.HomeEnv}
		if p.Hooks != nil {
			pi.dialect = p.Hooks.Dialect
		}
	}
	ops := operands(rec.Args)
	t := traitsByAgent[p.ID]
	args, _ := capArgs(rec.Args)
	ap := AgentProc{
		PID:             rec.PID,
		PPID:            rec.PPID,
		Start:           rec.Start,
		AgentID:         p.ID,
		Name:            capString(rec.Name, 255),
		Exe:             capString(rec.Exe, 4096),
		User:            event.User{Name: capString(rec.User, 256), ID: capString(rec.UID, 128)},
		Args:            classify.RedactArgs(args),
		Flags:           p.RiskyArgs(ops),
		Headless:        t.headless(ops),
		Bare:            t.bare(ops, env),
		PersistenceFree: t.persistenceFree(ops, env),
		HookFree:        t.hookFree(ops) || pi.dialect == "",
		ConfigHome:      configHome(p.HomeEnv, env),
		EnvMarkers:      append([]string(nil), ef.markers...),
		Evidence:        append([]string(nil), evidence...),
	}
	anc := m.ancestry(rec.PPID)
	for _, a := range anc {
		ap.Ancestors = append(ap.Ancestors, capString(a.name, 255))
	}
	ap.LifecycleParent = lifecycleParent(env, anc)
	id, rt, pod := m.src.workload(rec.PID)
	ap.Container = event.Container{ID: id, Runtime: rt, PodUID: pod}
	ap.CWD = m.src.cwd(rec.PID)
	launcher := isRunner(rec)
	if !launcher {
		launcher = true
		for _, e := range evidence {
			switch e {
			case catalog.EvidenceProcessName, catalog.EvidenceScriptName, catalog.EvidenceBundleExe, EvidenceEnvMarker:
				launcher = false
			}
		}
	}
	return &rootCand{prod: pi, ap: ap, launcher: launcher}
}

// runnerNames are package runners: a root identified because one of them
// names an agent package is a launcher, and the agent it starts a few
// processes below is its payload.
var runnerNames = map[string]bool{
	"npx": true, "npm": true, "pnpx": true, "pnpm": true, "yarn": true, "bunx": true, "bun": true,
	"uvx": true, "uv": true, "pipx": true,
}

func isRunner(rec *platform.Proc) bool {
	name := rec.Name
	if i := strings.IndexByte(name, ' '); i > 0 {
		name = name[:i] // process.title of npm exec: "npm exec @openai/codex"
	}
	if runnerNames[normName(name)] || runnerNames[normName(baseAny(rec.Exe))] {
		return true
	}
	if len(rec.Args) > 0 {
		a0 := rec.Args[0]
		if i := strings.IndexByte(a0, ' '); i > 0 {
			a0 = a0[:i]
		}
		if runnerNames[normName(baseAny(a0))] {
			return true
		}
	}
	if isNode(normName(baseAny(rec.Exe))) {
		if s, _ := scriptArg(rec.Args); s != "" {
			switch normName(baseAny(s)) {
			case "npx-cli.js", "npm-cli.js", "pnpm.cjs", "yarn.js":
				return true
			}
		}
	}
	return false
}

// ancestry reads the processes above an agent root, nearest first, up to
// init. Fresh reads (rather than the table) give the command lines the
// lifecycle check needs. Must be called without m.mu.
func (m *Monitor) ancestry(ppid int) []ancestor {
	var out []ancestor
	seen := map[int]bool{}
	for pid := ppid; pid > 0 && len(out) < maxAncestors && !seen[pid]; {
		seen[pid] = true
		r, _, ok := m.src.read(pid)
		if !ok {
			// Gone already, or unreadable (PID 1 can be): use what the
			// table remembers.
			m.mu.Lock()
			n := m.nodes[pid]
			name, next := "", 0
			if n != nil {
				name, next = n.name, n.ppid
			}
			m.mu.Unlock()
			if name == "" {
				break
			}
			out = append(out, ancestor{pid: pid, name: name})
			pid = next
			continue
		}
		args := r.Args
		if len(args) > 64 {
			args = args[:64]
		}
		out = append(out, ancestor{pid: pid, name: r.Name, exe: r.Exe, args: args})
		if pid == 1 {
			break
		}
		pid = r.PPID
	}
	return out
}

// fullScan lists every process, retires the ones that are gone and ingests
// the new ones. With the process connector running it is the periodic
// resync; otherwise it is the poller.
func (m *Monitor) fullScan(now time.Time) {
	m.st.scans.Add(1)
	m.mu.Lock()
	seq0 := m.seq
	m.mu.Unlock()
	ids, recs, err := m.src.list()
	if err != nil {
		m.st.errors.Add(1)
		return
	}
	present := make(map[int]struct{}, len(ids))
	var need []ident
	var execd []bool
	var evs []*event.Event
	m.mu.Lock()
	for _, id := range ids {
		present[id.pid] = struct{}{}
		n := m.nodes[id.pid]
		switch {
		case n == nil:
			if mk, ok := m.exitMark[id.pid]; !ok || mk.seq <= seq0 {
				need, execd = append(need, id), append(execd, false)
			}
		case n.key == 0 && n.comm != "" && id.comm != "" && n.comm != id.comm:
			// A fork the connector reported, whose exec it then lost.
			need, execd = append(need, id), append(execd, true)
		case n.key == 0:
			// A fork the connector reported; the image is the parent's.
			n.key, n.comm = id.key, id.comm
			if n.ppid <= 0 {
				n.ppid = id.ppid
			}
		case n.key != id.key:
			need, execd = append(need, id), append(execd, false)
		case id.comm != "" && n.comm != "" && n.comm != id.comm:
			// The process ran exec without the connector telling us.
			need, execd = append(need, id), append(execd, true)
		default:
			if id.ppid > 0 && n.ppid != id.ppid {
				n.ppid = id.ppid // re-parented; attribution is kept
			}
		}
	}
	var gone []*node
	for pid, n := range m.nodes {
		if _, ok := present[pid]; !ok && n.added <= seq0 {
			gone = append(gone, n)
		}
	}
	for _, n := range gone {
		evs = append(evs, m.retire(n, now, nil)...)
	}
	m.mu.Unlock()
	m.enqueue(evs)

	obs := make([]*observed, 0, len(need))
	for i, id := range need {
		o := m.prepare(id, recs[id.pid], viaPoll, time.Time{})
		if o == nil {
			continue
		}
		o.exec = execd[i]
		obs = append(obs, o)
	}
	m.commit(obs, seq0, now)
}

// commit ingests observations, emits their events and runs any marker
// promotions they asked for. Must be called without m.mu.
func (m *Monitor) commit(obs []*observed, seq0 uint64, now time.Time) {
	if len(obs) == 0 {
		return
	}
	m.mu.Lock()
	evs, promote := m.ingest(obs, seq0, now)
	m.mu.Unlock()
	m.enqueue(evs)
	m.promote(promote, now)
}

// activeScan follows the children of every live agent root (procfs only),
// so short-lived descendants are caught at the Active interval without a
// full listing. Exits are left to the full scan, except for the roots
// themselves, whose end is checked here.
func (m *Monitor) activeScan(now time.Time) bool {
	m.mu.Lock()
	seq0 := m.seq
	var roots []*root
	for _, r := range m.roots {
		if r.alive {
			roots = append(roots, r)
		}
	}
	m.mu.Unlock()
	if len(roots) == 0 {
		return true
	}
	m.st.activeScans.Add(1)
	var ended []*root
	var need []ident
	seen := map[int]bool{}
	for _, r := range roots {
		if id, ok := m.src.identOf(r.k.pid); !ok || id.key != r.k.key {
			ended = append(ended, r)
			continue
		}
		queue := []int{r.k.pid}
		for len(queue) > 0 && len(seen) < 4096 {
			pid := queue[0]
			queue = queue[1:]
			kids, ok := m.src.children(pid)
			if !ok {
				return false // backend cannot list children: use full scans
			}
			for _, k := range kids {
				if seen[k] {
					continue
				}
				seen[k] = true
				queue = append(queue, k)
			}
		}
	}
	m.mu.Lock()
	var evs []*event.Event
	for _, r := range ended {
		if r.alive {
			evs = append(evs, m.retire(r.n, now, nil)...)
		}
	}
	m.mu.Unlock()
	m.enqueue(evs)
	for pid := range seen {
		id, ok := m.src.identOf(pid)
		if !ok {
			continue
		}
		m.mu.Lock()
		n := m.nodes[pid]
		known := n != nil && (n.key == id.key || n.key == 0) && (n.comm == id.comm || n.comm == "")
		m.mu.Unlock()
		if !known {
			need = append(need, id)
		}
	}
	obs := make([]*observed, 0, len(need))
	for _, id := range need {
		if o := m.prepare(id, nil, viaPoll, time.Time{}); o != nil {
			obs = append(obs, o)
		}
	}
	m.commit(obs, seq0, now)
	return true
}

// promote turns marker boundaries into agent roots: a process whose
// children carry a strong marker of agent P while it does not, and that the
// catalog could not identify. Must be called without m.mu.
func (m *Monitor) promote(pids []int, now time.Time) {
	for i, pid := range pids {
		if i >= 8 {
			break
		}
		m.mu.Lock()
		n := m.nodes[pid]
		var product string
		if n != nil && n.root == nil {
			for _, c := range m.nodes {
				if c.ppid == pid && c.env.strong && c.owner == nil {
					product = c.env.product
					break
				}
			}
		}
		seq0 := m.seq
		m.mu.Unlock()
		if product == "" || m.cat == nil {
			continue
		}
		p, ok := m.cat.Get(product)
		if !ok || p.Kind != string(event.AssetAgent) {
			continue
		}
		rec, id, ok := m.src.read(pid)
		if !ok {
			continue
		}
		env, err := m.src.env(pid, m.index().keep)
		if err != nil {
			env = nil
		}
		ef := m.index().scanEnv(env)
		if ef.hasProduct(product, m.index()) {
			continue // it carries the marker itself: not the boundary
		}
		o := &observed{id: id, rec: &rec, envF: ef, via: viaPoll}
		o.cand = m.buildCand(&rec, env, ef, p, []string{EvidenceEnvMarker})
		m.mu.Lock()
		evs, _ := m.ingest([]*observed{o}, seq0, now)
		m.mu.Unlock()
		m.enqueue(evs)
	}
}

// Attribute returns the agent root a process belongs to: the nearest
// ancestor that is an agent root (the process itself when it is one). It is
// also true when the process environment carries an agent marker; the
// AgentProc then describes the process that set the marker and has Evidence
// "env_marker". A process the monitor has not seen yet is read on demand.
func (m *Monitor) Attribute(pid int) (ap AgentProc, ok bool) {
	defer func() {
		if recover() != nil {
			ap, ok = AgentProc{}, false
			m.st.errors.Add(1)
		}
	}()
	if pid <= 0 || pid > maxPID || m.src == nil {
		return AgentProc{}, false
	}
	m.mu.Lock()
	if n := m.nodes[pid]; n != nil && n.resolved {
		ap, ok = m.attributionOf(n)
		m.mu.Unlock()
		return ap, ok
	}
	t := m.tomb[pid]
	seq0 := m.seq
	m.mu.Unlock()
	if _, alive := m.src.identOf(pid); !alive {
		if t == nil {
			return AgentProc{}, false
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		return m.attributionOf(t)
	}
	now := m.now()
	m.commit(m.loadChain(pid), seq0, now)
	m.mu.Lock()
	defer m.mu.Unlock()
	if n := m.nodes[pid]; n != nil {
		return m.attributionOf(n)
	}
	return AgentProc{}, false
}

// loadChain reads a process and the ancestors the table does not know yet.
func (m *Monitor) loadChain(pid int) []*observed {
	var out []*observed
	for d := 0; pid > 0 && d < maxWalk; d++ {
		o := m.prepare(ident{pid: pid}, nil, viaPoll, time.Time{})
		if o == nil {
			break
		}
		out = append(out, o)
		pp := o.id.ppid
		if pp <= 0 || pp == pid {
			break
		}
		m.mu.Lock()
		p := m.nodes[pp]
		known := p != nil && p.resolved
		m.mu.Unlock()
		if known {
			break
		}
		pid = pp
	}
	return out
}
