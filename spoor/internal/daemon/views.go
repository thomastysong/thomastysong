package daemon

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/thomastysong/spoor/internal/catalog"
	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/platform"
	"github.com/thomastysong/spoor/internal/procmon"
)

// The pipeline calls Hooked, RootSaw, HomeOf, Surfaces and Gauges with its
// own lock held and they must not call back into it. They therefore read
// these small views, which the daemon refreshes from its own goroutines.

// userSet is the current account list.
type userSet struct {
	mu     sync.RWMutex
	list   []platform.UserHome
	byUID  map[string]platform.UserHome
	byName map[string]platform.UserHome
}

func newUserSet() *userSet {
	return &userSet{byUID: map[string]platform.UserHome{}, byName: map[string]platform.UserHome{}}
}

func (s *userSet) set(list []platform.UserHome) {
	byUID := make(map[string]platform.UserHome, len(list))
	byName := make(map[string]platform.UserHome, len(list))
	out := make([]platform.UserHome, 0, len(list))
	for _, u := range list {
		if u.Home == "" {
			continue
		}
		// platform.Users may list a second home for the current account
		// ($HOME differing from the account database); the first one is
		// the account's identity, both are read.
		if _, ok := byUID[u.UID]; !ok && u.UID != "" {
			byUID[u.UID] = u
		}
		if _, ok := byName[u.Name]; !ok && u.Name != "" {
			byName[u.Name] = u
		}
		out = append(out, u)
	}
	s.mu.Lock()
	s.list, s.byUID, s.byName = out, byUID, byName
	s.mu.Unlock()
}

func (s *userSet) all() []platform.UserHome {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]platform.UserHome(nil), s.list...)
}

func (s *userSet) byID(uid string) (platform.UserHome, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.byUID[uid]
	return u, ok
}

// homeOf is engine.Options.HomeOf.
func (s *userSet) homeOf(uid, name string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if u, ok := s.byUID[uid]; ok && uid != "" {
		return u.Home
	}
	if u, ok := s.byName[name]; ok && name != "" {
		return u.Home
	}
	return ""
}

// procView is the process monitor's agent table as of the last tick, and the
// configuration homes it has seen in agents' environments.
type procView struct {
	mu     sync.RWMutex
	agents []procmon.AgentProc
	// homes: uid -> agent id -> distinct configuration directories, most
	// recent last. Kept after the agent exits: a resumed session writes to
	// the same place.
	homes map[string]map[string][]string
}

// maxHomesPerAgent bounds the configuration homes followed per account and
// agent: each one is a transcript root and a directory the scanner reads.
const maxHomesPerAgent = 8

func newProcView() *procView {
	return &procView{homes: map[string]map[string][]string{}}
}

func (v *procView) set(agents []procmon.AgentProc, users *userSet) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.agents = agents
	for _, a := range agents {
		if a.ConfigHome == "" || a.User.ID == "" {
			continue
		}
		if _, known := users.byID(a.User.ID); !known {
			continue
		}
		dir, ok := configHomeDir(a.ConfigHome, a.User.ID)
		if !ok {
			continue
		}
		m := v.homes[a.User.ID]
		if m == nil {
			m = map[string][]string{}
			v.homes[a.User.ID] = m
		}
		list := m[a.AgentID]
		found := false
		for _, d := range list {
			if d == dir {
				found = true
				break
			}
		}
		if !found {
			list = append(list, dir)
			if len(list) > maxHomesPerAgent {
				list = list[len(list)-maxHomesPerAgent:]
			}
			m[a.AgentID] = list
		}
	}
}

// configHomeDir validates a configuration home read from an agent's
// environment. The value is user-controlled, so it is only followed when it
// is an absolute, clean path to a real directory owned by the agent's own
// account; the readers then refuse any file in it that account does not own.
func configHomeDir(v, uid string) (string, bool) {
	if v == "" || !filepath.IsAbs(v) || strings.ContainsRune(v, 0) {
		return "", false
	}
	c := filepath.Clean(v)
	if c != v && c+string(filepath.Separator) != v {
		return "", false
	}
	fi, err := os.Lstat(c)
	if err != nil || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		return "", false
	}
	if owner, ok := platform.PathOwner(c); ok && owner != uid {
		return "", false
	}
	return c, true
}

func (v *procView) list() []procmon.AgentProc {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return append([]procmon.AgentProc(nil), v.agents...)
}

// configHomes returns uid -> agent id -> directories.
func (v *procView) configHomes() map[string]map[string][]string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make(map[string]map[string][]string, len(v.homes))
	for uid, m := range v.homes {
		c := make(map[string][]string, len(m))
		for a, l := range m {
			c[a] = append([]string(nil), l...)
		}
		out[uid] = c
	}
	return out
}

// rootSaw is engine.Options.RootSaw: the monitor currently sees the agent
// running for the account (named by account name or uid).
func (v *procView) rootSaw(agentID, user string) bool {
	if agentID == "" || user == "" {
		return false
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	for _, a := range v.agents {
		if a.AgentID == agentID && (a.User.Name == user || a.User.ID == user) {
			return true
		}
	}
	return false
}

// envFor returns the relocation variables seen for an account, the way the
// scanner and hookinstall take them: variable name -> directory.
func (v *procView) envFor(uid string, cat *catalog.Catalog) map[string]string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	m := v.homes[uid]
	if len(m) == 0 {
		return nil
	}
	out := map[string]string{}
	for agent, dirs := range m {
		p, ok := cat.Get(agent)
		if !ok || len(p.HomeEnv) == 0 || len(dirs) == 0 {
			continue
		}
		// The most recent one; a variable holds one value.
		out[p.HomeEnv[0]] = dirs[len(dirs)-1]
	}
	return out
}

// hookView is hookinstall's view of hook registrations per agent and
// account, answering engine.Options.Hooked.
type hookView struct {
	mu sync.RWMutex
	m  map[[2]string]string // {agent, account name or uid} -> state
}

func newHookView() *hookView { return &hookView{m: map[[2]string]string{}} }

func (h *hookView) lookup(agentID, user string) string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.m[[2]string{agentID, user}]
}

func (h *hookView) set(m map[[2]string]string) {
	h.mu.Lock()
	h.m = m
	h.mu.Unlock()
}

func (h *hookView) snapshot() map[[2]string]string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make(map[[2]string]string, len(h.m))
	for k, v := range h.m {
		out[k] = v
	}
	return out
}

// board collects what collectors report for the heartbeat: totals since
// start (Gauges) and surface status (Surfaces).
type board struct {
	mu   sync.Mutex
	ctr  map[string]uint64
	surf map[string]event.SurfaceStatus
}

// maxBoardKeys bounds the counter names (some carry a reason code from a
// user-writable spool); the heartbeat must fit its line.
const maxBoardKeys = 256

func newBoard() *board {
	return &board{ctr: map[string]uint64{}, surf: map[string]event.SurfaceStatus{}}
}

func (b *board) add(name string, n uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.ctr[name]; !ok && len(b.ctr) >= maxBoardKeys {
		name = "daemon.counters_omitted"
	}
	b.ctr[name] += n
}

func (b *board) set(name string, v uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.ctr[name]; !ok && len(b.ctr) >= maxBoardKeys {
		return
	}
	b.ctr[name] = v
}

func (b *board) unset(name string) {
	b.mu.Lock()
	delete(b.ctr, name)
	b.mu.Unlock()
}

func (b *board) get(name string) uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.ctr[name]
}

// counters is engine.Options.Gauges.
func (b *board) counters() map[string]uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make(map[string]uint64, len(b.ctr))
	for k, v := range b.ctr {
		out[k] = v
	}
	return out
}

func (b *board) surface(s event.SurfaceStatus) {
	b.mu.Lock()
	b.surf[s.Name] = s
	b.mu.Unlock()
}

// update changes one surface in place.
func (b *board) update(name string, fn func(*event.SurfaceStatus)) {
	b.mu.Lock()
	defer b.mu.Unlock()
	s, ok := b.surf[name]
	if !ok {
		s = event.SurfaceStatus{Name: name, Status: "ok"}
	}
	fn(&s)
	b.surf[name] = s
}

// surfaces is engine.Options.Surfaces.
func (b *board) surfaces() []event.SurfaceStatus {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]event.SurfaceStatus, 0, len(b.surf))
	for _, s := range b.surf {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
