package rules

import (
	"bytes"
	"container/list"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/thomastysong/spoor/internal/event"
)

// Per-session bounds. A session can run for days and the agent decides how
// many events it produces, so every structure here is capped; what falls
// off is the oldest state.
const (
	maxThreads         = 32  // subagent threads with their own flags
	maxFlagsPerThread  = 64  // flags held by one thread (or the session scope)
	maxWritten         = 200 // paths written by the session (write-then-run)
	maxSecretFPs       = 64  // fingerprints of credential values read
	maxDedup           = 256 // dedup keys remembered
	maxSessionCounters = 64  // per-rule threshold counters
	maxRecentUse       = 32  // tool-use ids, to count a call once across pre and post
	maxScopedRefs      = 64  // per-user / per-host threshold counters a session fed
	maxExport          = 64 << 10
	exportVersion      = 1
	// maxRef is the longest id kept verbatim in session state: tool-use
	// ids, subagent thread ids and the event ids recorded with flags and
	// threshold hits. Longer ids, and ids that are not valid UTF-8, are
	// kept as a digest (see stateRef), so whatever the engine stores it
	// can export, and whatever it exports it imports.
	maxRef = 64
)

// stateRef returns the form of an id the session state keeps: the id
// itself when it is valid UTF-8 of at most maxRef bytes, otherwise "#"
// and a 128-bit digest of it. JSON cannot carry invalid UTF-8 (it is
// rewritten to U+FFFD, three bytes per bad byte), so such an id would not
// survive an export.
func stateRef(id string) string {
	if len(id) <= maxRef && utf8.ValidString(id) {
		return id
	}
	sum := sha256.Sum256([]byte(id))
	return "#" + hex.EncodeToString(sum[:16])
}

// SessionKey returns the key the engine keeps state under: a hash of the
// OS user id, the agent id and the session id (user and agent only when
// the event has no session id). The user id must be the one the caller
// established (the owner of the spool or transcript file), never a name
// taken from the payload; it is read from Event.User.ID. The key is hex,
// so it is safe to use as a file name.
func SessionKey(ev *event.Event) string {
	if ev == nil {
		return ""
	}
	var uid, agent, sid string
	if ev.User != nil {
		uid = ev.User.ID
	}
	if ev.Agent != nil {
		agent = ev.Agent.ID
	}
	if ev.Session != nil {
		sid = ev.Session.ID
	}
	h := sha256.New()
	h.Write([]byte("spoor-session\x00"))
	h.Write([]byte(uid))
	h.Write([]byte{0})
	h.Write([]byte(agent))
	h.Write([]byte{0})
	h.Write([]byte(sid))
	return hex.EncodeToString(h.Sum(nil)[:16])
}

type flagEntry struct {
	exp time.Time
	at  time.Time
	ev  string // id of the event that set the flag
}

type hit struct {
	t  time.Time
	ev string
}

type dedupEntry struct {
	last       time.Time
	suppressed int
}

type secretFP struct {
	fp, kind string
	n        int // length of the value in bytes; 0 when unknown
}

// scopedRef names a per-user or per-host threshold counter (in the
// engine's scoped store) that events of this session fed.
type scopedRef struct{ rule, by, key string }

// sessionState is everything the engine remembers about one session.
type sessionState struct {
	key           string
	created, last time.Time
	events        int
	toolCalls     int
	prompts       int
	recentUse     []string
	threads       map[string]map[string]flagEntry // subagent id ("" = main thread) -> flags
	threadOrder   []string                        // least recently used first
	sflags        map[string]flagEntry            // flags set with scope: session
	written       []string                        // digests of written paths, oldest first
	salt          []byte
	secrets       []secretFP
	counters      map[string][]hit
	dedup         map[string]*dedupEntry
	// scoped lists the per-user / per-host counters this session fed, so
	// a one-shot hook process can carry them in its export; pending holds
	// imported ones ("RULE/by" -> hits) until the next event of the
	// session names the user or host they belong to.
	scoped  []scopedRef
	pending map[string][]hit
}

func newSession(key string, now time.Time) *sessionState {
	return &sessionState{
		key: key, created: now, last: now,
		threads:  map[string]map[string]flagEntry{},
		sflags:   map[string]flagEntry{},
		counters: map[string][]hit{},
		dedup:    map[string]*dedupEntry{},
	}
}

func (s *sessionState) ensureSalt() {
	if len(s.salt) == 0 {
		s.salt = make([]byte, 16)
		_, _ = rand.Read(s.salt)
	}
}

// expire drops flags whose TTL has passed.
func (s *sessionState) expire(now time.Time) {
	for t, fl := range s.threads {
		for k, v := range fl {
			if !now.Before(v.exp) {
				delete(fl, k)
			}
		}
		if len(fl) == 0 {
			delete(s.threads, t)
			s.dropThreadOrder(t)
		}
	}
	for k, v := range s.sflags {
		if !now.Before(v.exp) {
			delete(s.sflags, k)
		}
	}
}

func (s *sessionState) dropThreadOrder(t string) {
	for i, x := range s.threadOrder {
		if x == t {
			s.threadOrder = append(s.threadOrder[:i], s.threadOrder[i+1:]...)
			return
		}
	}
}

func (s *sessionState) touchThread(t string) {
	s.dropThreadOrder(t)
	s.threadOrder = append(s.threadOrder, t)
}

// visible returns the flags a rule evaluated in thread sees: its own and
// the session-scoped ones, or, when all is true (a rule with flags.scope:
// session), those of every thread.
func (s *sessionState) visible(thread string, all bool) map[string]flagEntry {
	out := make(map[string]flagEntry, len(s.sflags)+8)
	for k, v := range s.sflags {
		out[k] = v
	}
	if all {
		for _, fl := range s.threads {
			for k, v := range fl {
				if cur, ok := out[k]; !ok || v.at.Before(cur.at) {
					out[k] = v
				}
			}
		}
		return out
	}
	for k, v := range s.threads[thread] {
		out[k] = v
	}
	return out
}

func (s *sessionState) setFlag(thread, scope, name string, ttl time.Duration, now time.Time, ev string) {
	e := flagEntry{exp: now.Add(ttl), at: now, ev: ev}
	if scope == ScopeSession {
		if _, ok := s.sflags[name]; !ok && len(s.sflags) >= maxFlagsPerThread {
			evictOldestFlag(s.sflags)
		}
		s.sflags[name] = e
		return
	}
	fl := s.threads[thread]
	if fl == nil {
		if len(s.threads) >= maxThreads && len(s.threadOrder) > 0 {
			old := s.threadOrder[0]
			delete(s.threads, old)
			s.dropThreadOrder(old)
		}
		fl = map[string]flagEntry{}
		s.threads[thread] = fl
	}
	s.touchThread(thread)
	if _, ok := fl[name]; !ok && len(fl) >= maxFlagsPerThread {
		evictOldestFlag(fl)
	}
	fl[name] = e
}

func evictOldestFlag(fl map[string]flagEntry) {
	var oldest string
	var at time.Time
	first := true
	for k, v := range fl {
		if first || v.at.Before(at) || (v.at.Equal(at) && k < oldest) {
			oldest, at, first = k, v.at, false
		}
	}
	delete(fl, oldest)
}

func (s *sessionState) flagNames(thread string) []string {
	vis := s.visible(thread, false)
	if len(vis) == 0 {
		return nil
	}
	out := make([]string, 0, len(vis))
	for k := range vis {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// seenUse and rememberUse take ids in their stateRef form.
func (s *sessionState) seenUse(id string) bool {
	for _, x := range s.recentUse {
		if x == id {
			return true
		}
	}
	return false
}

func (s *sessionState) rememberUse(id string) {
	if id == "" || s.seenUse(id) {
		return
	}
	if len(s.recentUse) >= maxRecentUse {
		s.recentUse = s.recentUse[1:]
	}
	s.recentUse = append(s.recentUse, id)
}

func (s *sessionState) addWritten(d string) {
	for i, x := range s.written {
		if x == d {
			s.written = append(s.written[:i], s.written[i+1:]...)
			break
		}
	}
	if len(s.written) >= maxWritten {
		s.written = s.written[1:]
	}
	s.written = append(s.written, d)
}

func (s *sessionState) hasWritten(d string) bool {
	for _, x := range s.written {
		if x == d {
			return true
		}
	}
	return false
}

func (s *sessionState) addSecret(fp, kind string, n int) {
	for _, x := range s.secrets {
		if x.fp == fp {
			return
		}
	}
	if len(s.secrets) >= maxSecretFPs {
		s.secrets = s.secrets[1:]
	}
	s.secrets = append(s.secrets, secretFP{fp: fp, kind: kind, n: n})
}

// noteScoped records that this session fed the scoped counter key.
func (s *sessionState) noteScoped(rule, by, key string) {
	for i, x := range s.scoped {
		if x.key == key {
			s.scoped = append(append(s.scoped[:i:i], s.scoped[i+1:]...), x)
			return
		}
	}
	if len(s.scoped) >= maxScopedRefs {
		s.scoped = s.scoped[1:]
	}
	s.scoped = append(s.scoped, scopedRef{rule: rule, by: by, key: key})
}

func (s *sessionState) putDedup(key string, e *dedupEntry) {
	if _, ok := s.dedup[key]; !ok && len(s.dedup) >= maxDedup {
		var oldest string
		var at time.Time
		first := true
		for k, v := range s.dedup {
			if first || v.last.Before(at) {
				oldest, at, first = k, v.last, false
			}
		}
		delete(s.dedup, oldest)
	}
	s.dedup[key] = e
}

// sessions is an LRU of session states.
type sessions struct {
	max   int
	lru   *list.List // front = most recent
	items map[string]*list.Element
}

func newSessions(max int) *sessions {
	return &sessions{max: max, lru: list.New(), items: map[string]*list.Element{}}
}

func (ss *sessions) get(key string) *sessionState {
	if el, ok := ss.items[key]; ok {
		ss.lru.MoveToFront(el)
		return el.Value.(*sessionState)
	}
	return nil
}

// put stores st and returns how many sessions were evicted.
func (ss *sessions) put(st *sessionState) int {
	if el, ok := ss.items[st.key]; ok {
		el.Value = st
		ss.lru.MoveToFront(el)
		return 0
	}
	ss.items[st.key] = ss.lru.PushFront(st)
	evicted := 0
	for ss.lru.Len() > ss.max {
		el := ss.lru.Back()
		ss.lru.Remove(el)
		delete(ss.items, el.Value.(*sessionState).key)
		evicted++
	}
	return evicted
}

func (ss *sessions) len() int { return ss.lru.Len() }

// Export format. Times are Unix milliseconds; short keys keep a session
// well under the 64 KiB import limit.
type exportState struct {
	V        int                              `json:"v"`
	Key      string                           `json:"k"`
	Created  int64                            `json:"c"`
	Last     int64                            `json:"l"`
	Events   int                              `json:"n,omitempty"`
	Tools    int                              `json:"tc,omitempty"`
	Prompts  int                              `json:"p,omitempty"`
	Recent   []string                         `json:"u,omitempty"`
	Threads  map[string]map[string]exportFlag `json:"f,omitempty"`
	Order    []string                         `json:"o,omitempty"`
	Session  map[string]exportFlag            `json:"sf,omitempty"`
	Written  []string                         `json:"w,omitempty"`
	Salt     string                           `json:"salt,omitempty"`
	Secrets  []exportSecret                   `json:"s,omitempty"`
	Counters map[string][]exportHit           `json:"t,omitempty"`
	Dedup    map[string][2]int64              `json:"d,omitempty"`
	// Scoped holds the per-user and per-host threshold counters the
	// session fed, keyed "RULE-ID/user" or "RULE-ID/host". The user or
	// host itself is not stored: on import they are bound to whoever the
	// session's next event names.
	Scoped map[string][]exportHit `json:"st,omitempty"`
}

type exportFlag struct {
	Exp int64  `json:"x"`
	At  int64  `json:"a"`
	Ev  string `json:"e,omitempty"`
}

type exportSecret struct {
	FP   string `json:"h"`
	Kind string `json:"k"`
	N    int    `json:"n,omitempty"`
}

type exportHit struct {
	T  int64  `json:"t"`
	Ev string `json:"e,omitempty"`
}

func ms(t time.Time) int64 { return t.UnixMilli() }

func fromMS(v int64) time.Time { return time.UnixMilli(v).UTC() }

func (s *sessionState) export() exportState {
	x := exportState{
		V: exportVersion, Key: s.key, Created: ms(s.created), Last: ms(s.last),
		Events: s.events, Tools: s.toolCalls, Prompts: s.prompts,
		Recent: append([]string(nil), s.recentUse...), Order: append([]string(nil), s.threadOrder...),
		Written: append([]string(nil), s.written...),
	}
	if len(s.threads) > 0 {
		x.Threads = map[string]map[string]exportFlag{}
		for t, fl := range s.threads {
			m := map[string]exportFlag{}
			for k, v := range fl {
				m[k] = exportFlag{Exp: ms(v.exp), At: ms(v.at), Ev: v.ev}
			}
			x.Threads[t] = m
		}
	}
	if len(s.sflags) > 0 {
		x.Session = map[string]exportFlag{}
		for k, v := range s.sflags {
			x.Session[k] = exportFlag{Exp: ms(v.exp), At: ms(v.at), Ev: v.ev}
		}
	}
	if len(s.salt) > 0 {
		x.Salt = hex.EncodeToString(s.salt)
	}
	for _, sc := range s.secrets {
		x.Secrets = append(x.Secrets, exportSecret{FP: sc.fp, Kind: sc.kind, N: sc.n})
	}
	if len(s.counters) > 0 {
		x.Counters = map[string][]exportHit{}
		for r, hits := range s.counters {
			hs := make([]exportHit, len(hits))
			for i, h := range hits {
				hs[i] = exportHit{T: ms(h.t), Ev: h.ev}
			}
			x.Counters[r] = hs
		}
	}
	if len(s.dedup) > 0 {
		x.Dedup = map[string][2]int64{}
		for k, v := range s.dedup {
			x.Dedup[k] = [2]int64{ms(v.last), int64(v.suppressed)}
		}
	}
	for k, hs := range s.pending {
		if x.Scoped == nil {
			x.Scoped = map[string][]exportHit{}
		}
		x.Scoped[k] = exportHits(hs)
	}
	return x
}

func exportHits(hits []hit) []exportHit {
	hs := make([]exportHit, len(hits))
	for i, h := range hits {
		hs[i] = exportHit{T: ms(h.t), Ev: h.ev}
	}
	return hs
}

// scopedName is the export key of a scoped counter.
func scopedName(rule, by string) string { return rule + "/" + by }

// marshalBounded encodes the state and, if it exceeds maxExport, sheds the
// least valuable state first (threshold history, then dedup memory, then
// the oldest written paths) until it fits.
func marshalBounded(x exportState) ([]byte, error) {
	for round := 0; round < 64; round++ {
		b, err := json.Marshal(x)
		if err != nil {
			return nil, err
		}
		if len(b) <= maxExport {
			return b, nil
		}
		switch {
		case len(x.Scoped) > 0:
			for k, hs := range x.Scoped {
				if len(hs) > 1 {
					x.Scoped[k] = hs[len(hs)/2:]
				} else {
					delete(x.Scoped, k)
				}
			}
		case len(x.Counters) > 0:
			for k, hs := range x.Counters {
				if len(hs) > 1 {
					x.Counters[k] = hs[len(hs)/2:]
				} else {
					delete(x.Counters, k)
				}
			}
		case len(x.Dedup) > 0:
			n := 0
			for k := range x.Dedup {
				if n%2 == 0 {
					delete(x.Dedup, k)
				}
				n++
			}
		case len(x.Written) > 0:
			x.Written = x.Written[len(x.Written)/2:]
		case len(x.Recent) > 0:
			x.Recent = nil
		default:
			for k := range x.Threads {
				delete(x.Threads, k)
				break
			}
			if len(x.Threads) == 0 && len(x.Session) == 0 {
				return nil, errors.New("rules: session state does not fit the export limit")
			}
			if len(x.Threads) == 0 {
				x.Session = nil
			}
		}
	}
	return nil, errors.New("rules: session state does not fit the export limit")
}

// ErrBadSession is returned by ImportSession for state that is oversized,
// malformed, for another key, or outside the engine's bounds.
var ErrBadSession = errors.New("rules: bad session state")

func badState(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrBadSession, fmt.Sprintf(format, a...))
}

func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func validEventRef(s string) bool { return len(s) <= maxRef }

// importState validates x and converts it. The state lives in a file the
// monitored user can write, so it is parsed as hostile input: the worst a
// forger can do is clear or invent their own session's flags, which is
// documented as a limit of daemonless mode.
func importState(key string, data []byte, now time.Time) (*sessionState, error) {
	if len(data) > maxExport {
		return nil, badState("larger than %d bytes", maxExport)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var x exportState
	if err := dec.Decode(&x); err != nil {
		return nil, badState("%v", err)
	}
	if dec.More() {
		return nil, badState("trailing data")
	}
	if x.V != exportVersion {
		return nil, badState("version %d", x.V)
	}
	if x.Key != key {
		return nil, badState("state is for another session")
	}
	latest := ms(now.Add(24 * time.Hour))
	okTime := func(v int64) bool { return v >= 0 && v <= latest }
	if !okTime(x.Created) || !okTime(x.Last) || x.Events < 0 || x.Tools < 0 || x.Prompts < 0 {
		return nil, badState("times or counters out of range")
	}
	st := newSession(key, fromMS(x.Created))
	st.last = fromMS(x.Last)
	st.events, st.toolCalls, st.prompts = x.Events, x.Tools, x.Prompts
	if len(x.Recent) > maxRecentUse {
		return nil, badState("too many tool-use ids")
	}
	for _, u := range x.Recent {
		if len(u) > 256 {
			return nil, badState("tool-use id too long")
		}
	}
	st.recentUse = x.Recent
	if len(x.Threads) > maxThreads {
		return nil, badState("too many threads")
	}
	maxExp := now.Add(maxTTL)
	convFlags := func(in map[string]exportFlag) (map[string]flagEntry, error) {
		if len(in) > maxFlagsPerThread {
			return nil, badState("too many flags")
		}
		out := make(map[string]flagEntry, len(in))
		for name, f := range in {
			if !flagRe.MatchString(name) || !validEventRef(f.Ev) || !okTime(f.At) || f.Exp < 0 {
				return nil, badState("invalid flag %q", name)
			}
			exp := fromMS(f.Exp)
			if exp.After(maxExp) {
				exp = maxExp
			}
			out[name] = flagEntry{exp: exp, at: fromMS(f.At), ev: f.Ev}
		}
		return out, nil
	}
	for t, fl := range x.Threads {
		if len(t) > 256 {
			return nil, badState("thread id too long")
		}
		m, err := convFlags(fl)
		if err != nil {
			return nil, err
		}
		st.threads[t] = m
	}
	if len(x.Order) > maxThreads {
		return nil, badState("too many threads")
	}
	for _, t := range x.Order {
		if _, ok := st.threads[t]; ok {
			st.touchThread(t)
		}
	}
	for t := range st.threads {
		found := false
		for _, o := range st.threadOrder {
			found = found || o == t
		}
		if !found {
			st.threadOrder = append(st.threadOrder, t)
		}
	}
	sf, err := convFlags(x.Session)
	if err != nil {
		return nil, err
	}
	st.sflags = sf
	if len(x.Written) > maxWritten {
		return nil, badState("too many written paths")
	}
	for _, w := range x.Written {
		if !isHex(w, 16) {
			return nil, badState("invalid path digest")
		}
	}
	st.written = x.Written
	if x.Salt != "" {
		if !isHex(x.Salt, 32) {
			return nil, badState("invalid salt")
		}
		st.salt, _ = hex.DecodeString(x.Salt)
	}
	if len(x.Secrets) > maxSecretFPs {
		return nil, badState("too many fingerprints")
	}
	for _, sc := range x.Secrets {
		if !isHex(sc.FP, 24) || len(sc.Kind) > 64 || len(st.salt) == 0 || sc.N < 0 || sc.N > maxSecretValue {
			return nil, badState("invalid fingerprint")
		}
		st.secrets = append(st.secrets, secretFP{fp: sc.FP, kind: sc.Kind, n: sc.N})
	}
	if len(x.Counters) > maxSessionCounters {
		return nil, badState("too many counters")
	}
	for r, hs := range x.Counters {
		if !ruleIDRe.MatchString(r) || len(hs) > maxThreshold {
			return nil, badState("invalid counter %q", r)
		}
		conv := make([]hit, 0, len(hs))
		for _, h := range hs {
			if !okTime(h.T) || !validEventRef(h.Ev) {
				return nil, badState("invalid counter entry")
			}
			conv = append(conv, hit{t: fromMS(h.T), ev: h.Ev})
		}
		st.counters[r] = conv
	}
	if len(x.Dedup) > maxDedup {
		return nil, badState("too many dedup keys")
	}
	for k, v := range x.Dedup {
		if !isHex(k, 32) || !okTime(v[0]) || v[1] < 0 || v[1] > 1<<31 {
			return nil, badState("invalid dedup entry")
		}
		st.dedup[k] = &dedupEntry{last: fromMS(v[0]), suppressed: int(v[1])}
	}
	if len(x.Scoped) > maxScopedRefs {
		return nil, badState("too many scoped counters")
	}
	for k, hs := range x.Scoped {
		i := strings.LastIndexByte(k, '/')
		if i < 0 || !ruleIDRe.MatchString(k[:i]) || (k[i+1:] != ByUser && k[i+1:] != ByHost) || len(hs) > maxThreshold {
			return nil, badState("invalid scoped counter %q", k)
		}
		conv := make([]hit, 0, len(hs))
		for _, h := range hs {
			if !okTime(h.T) || !validEventRef(h.Ev) {
				return nil, badState("invalid counter entry")
			}
			conv = append(conv, hit{t: fromMS(h.T), ev: h.Ev})
		}
		if st.pending == nil {
			st.pending = map[string][]hit{}
		}
		st.pending[k] = conv
	}
	return st, nil
}
