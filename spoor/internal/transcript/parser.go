package transcript

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/toolmap"
)

// Parser converts the lines of one agent's session log into events.
type Parser interface {
	AgentID() string
	// Match reports whether a file path is one of this agent's session logs.
	Match(path string) bool
	// ParseLine converts one complete line into zero or more events. st
	// carries per-file state (session id, cwd, model, pending tool calls for
	// pairing). It tolerates unknown record types (counted in st.Unknown)
	// and never panics. A line that is not a JSON object is counted in
	// st.Malformed and reported as an error wrapping ErrMalformed. The line
	// is not retained.
	ParseLine(line []byte, st *FileState) ([]*event.Event, error)
}

// ErrMalformed is wrapped by ParseLine errors for lines that do not decode.
var ErrMalformed = errors.New("transcript: malformed line")

// FileState is the per-file parsing state. The zero value is ready to use.
type FileState struct {
	Path, SessionID, ParentSessionID, CWD, Model, Version, PermissionMode string
	Unknown, Malformed, Lines                                             uint64
	// Oversize counts lines longer than TailerOptions.MaxLine that the
	// tailer skipped without parsing.
	Oversize uint64
	Pending  map[string]*event.Event // tool_use id -> tool.pre event, for pairing with results
	Extra    map[string]string

	// User is stamped on every event when set (the tailer copies Root.User).
	user *event.User
	// lastTS is the newest record timestamp seen; records without their
	// own timestamp inherit it.
	lastTS time.Time
	// pendOrder is the arrival order of Pending ids, so the oldest can be
	// dropped when a hostile log opens calls without ever closing them.
	pendOrder []string
	// hints holds per-call facts learned from side records before the
	// result arrives (Codex exec_command_end, Copilot permission results).
	hints map[string]*callHint
	// seen is a bounded set of record and call ids already turned into
	// events, for formats that re-append the same record as it updates.
	seen     map[string]struct{}
	seenRing []string
	// key is the line key of lineDigest (the Tailer's; nil: the
	// per-process key). Never stored with the state.
	key []byte
}

type callHint struct {
	exit    *int
	durMS   int64
	failed  *bool
	denied  bool
	source  string // decision source for a denial
	server  string
	tool    string
	request string // Copilot permission kind
}

// Bookkeeping bounds. A session log is attacker-influenced, so every map
// keyed by ids from it has a ceiling.
const (
	maxPending = 4096
	maxHints   = 2048
	maxSeen    = 16384
	maxExtra   = 64
)

// Length bounds for strings copied from records into emitted fields.
const (
	maxIDLen      = 256
	maxNameLen    = 256
	maxCWDLen     = 4096
	maxModelLen   = 128
	maxVersionLen = 64
)

// safeToken returns s when it is a short identifier-like value (letters,
// digits and "_-.:"), and "" otherwise. Labels are serialized, so a value
// copied from a record must not be able to carry content.
func safeToken(s string) string {
	if s == "" || len(s) > 48 {
		return ""
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.' || c == ':') {
			return ""
		}
	}
	return s
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && s[n]&0xC0 == 0x80 { // do not split a UTF-8 sequence
		n--
	}
	return s[:n]
}

func (st *FileState) setExtra(k, v string) {
	if st.Extra == nil {
		st.Extra = map[string]string{}
	}
	if _, ok := st.Extra[k]; !ok && len(st.Extra) >= maxExtra {
		return
	}
	st.Extra[k] = v
}

func (st *FileState) extra(k string) string { return st.Extra[k] }

func (st *FileState) addPending(id string, e *event.Event) {
	if id == "" {
		return
	}
	if st.Pending == nil {
		st.Pending = map[string]*event.Event{}
	}
	if _, dup := st.Pending[id]; !dup {
		st.pendOrder = append(st.pendOrder, id)
	}
	st.Pending[id] = e
	for len(st.Pending) > maxPending {
		if len(st.pendOrder) == 0 || st.pendOrder[0] == id {
			// Pending was filled by the caller, not by addPending: there
			// is no order to honour, drop any entry but the new one.
			for k := range st.Pending {
				if k != id {
					delete(st.Pending, k)
					break
				}
			}
			continue
		}
		old := st.pendOrder[0]
		st.pendOrder = st.pendOrder[1:]
		delete(st.Pending, old)
	}
	// Completed calls leave their id in pendOrder; compact it when it has
	// grown well past the live set so it stays bounded too.
	if len(st.pendOrder) > 2*maxPending {
		live := st.pendOrder[:0]
		for _, k := range st.pendOrder {
			if _, ok := st.Pending[k]; ok {
				live = append(live, k)
			}
		}
		st.pendOrder = live
	}
}

func (st *FileState) takePending(id string) *event.Event {
	if id == "" || st.Pending == nil {
		return nil
	}
	e := st.Pending[id]
	delete(st.Pending, id)
	return e
}

func (st *FileState) hint(id string) *callHint {
	if id == "" {
		return &callHint{}
	}
	if st.hints == nil {
		st.hints = map[string]*callHint{}
	}
	h := st.hints[id]
	if h == nil {
		if len(st.hints) >= maxHints {
			st.hints = map[string]*callHint{}
		}
		h = &callHint{}
		st.hints[id] = h
	}
	return h
}

func (st *FileState) takeHint(id string) *callHint {
	h := st.hints[id]
	delete(st.hints, id)
	return h
}

// remember records key and reports whether it had been seen before.
func (st *FileState) remember(key string) (already bool) {
	if st.seen == nil {
		st.seen = map[string]struct{}{}
	}
	if _, ok := st.seen[key]; ok {
		return true
	}
	if len(st.seenRing) >= maxSeen {
		drop := len(st.seenRing) / 2
		for _, k := range st.seenRing[:drop] {
			delete(st.seen, k)
		}
		st.seenRing = append(st.seenRing[:0], st.seenRing[drop:]...)
	}
	st.seen[key] = struct{}{}
	st.seenRing = append(st.seenRing, key)
	return false
}

func (st *FileState) wasSeen(key string) bool {
	_, ok := st.seen[key]
	return ok
}

// lineCtx is the context of one ParseLine call.
type lineCtx struct {
	agent string
	st    *FileState
	line  []byte
	// rec is the log's own id of the record the next events come from
	// (prefixed by its kind), "" when the record has none; see eventIDs.
	rec   string
	seeds []idSeed // parallel to out
	out   []*event.Event
}

// idSeed is what an event's id is derived from besides the event itself.
type idSeed struct {
	rec string    // c.rec when the event was created
	t   time.Time // the time the id carries
}

// record sets the record id of the events created next. Ids come from the
// log, so they are bounded like every other copied value.
func (c *lineCtx) record(kind, id string) {
	if id == "" {
		c.rec = ""
		return
	}
	c.rec = kind + clip(id, maxIDLen)
}

// stamp resolves a record timestamp: the record's own when it has one,
// otherwise the newest seen in the file, otherwise now.
func (c *lineCtx) stamp(ts time.Time) (use time.Time, forID time.Time) {
	if !ts.IsZero() {
		if ts.After(c.st.lastTS) {
			c.st.lastTS = ts
		}
		return ts, ts
	}
	if !c.st.lastTS.IsZero() {
		return c.st.lastTS, c.st.lastTS
	}
	// No timestamp anywhere: the event still needs a time, but the id must
	// not depend on when the sensor happened to read the line.
	return time.Now().UTC(), time.Unix(0, 0)
}

// newEvent appends an activity event for the current line.
func (c *lineCtx) newEvent(typ string, ts time.Time) *event.Event {
	use, idTime := c.stamp(ts)
	st := c.st
	e := &event.Event{
		V:        event.SchemaVersion,
		TS:       event.At(use),
		Kind:     event.KindActivity,
		Type:     typ,
		Source:   event.SourceTranscript,
		Fidelity: event.FidelityObserved,
		Agent:    &event.Agent{ID: c.agent, Version: st.Version, Surface: st.Extra["surface"]},
		Session: &event.Session{
			ID:             st.SessionID,
			ParentID:       st.ParentSessionID,
			TurnID:         st.Extra["turn_id"],
			CWD:            st.CWD,
			PermissionMode: st.PermissionMode,
			Model:          st.Model,
			Transcript:     st.Path,
			SubagentID:     st.Extra["subagent_id"],
			SubagentType:   st.Extra["subagent_type"],
		},
	}
	if ts.IsZero() {
		e.Labels = map[string]string{"ts_source": "sensor"}
	}
	if st.user != nil && (st.user.Name != "" || st.user.ID != "") {
		u := *st.user
		e.User = &u
	}
	c.out = append(c.out, e)
	c.seeds = append(c.seeds, idSeed{rec: c.rec, t: idTime})
	return e
}

// eventIDs gives every event of the line its id, once the line has been
// parsed and the events are complete. An id is UUIDv7-shaped: the record
// time, then a digest of what identifies the event, never of its content.
// Event.ID is serialized, so it must not be a guessing oracle: the line
// holds prompts and tool output, and every other input of a digest of it
// is in the shipped record. The record is identified by:
//
//   - its own id in the log when the format has one (Claude Code "uuid",
//     Copilot event "id", Gemini message id; a Gemini session start by its
//     session id): random values the agent generates, so those ids are the
//     same whenever and wherever the log is read;
//   - otherwise (Codex records, Claude Code bookkeeping records) an HMAC of
//     the line under the line key (keyfile.go): the Tailer's, which it
//     keeps beside its checkpoint store (or derives from
//     TailerOptions.IdentityKey), so re-reading a line after a crash, a
//     replacement or a cancelled archive pass yields the same ids in this
//     process and in a restarted one; ReadFile and a Tailer without a
//     StateFile use a key drawn once per process.
//
// The engine derives the identity of tool and prompt activity (Dedupe) from
// tool-call ids and keyed prompt digests, not from these ids.
//
// An event is then identified by its record, its type and its tool-call id,
// and events of one line that share all three are numbered in order, so a
// record that yields several (two calls, a turn's settings changes, a
// Gemini document) gives each its own id.
func (c *lineCtx) eventIDs() {
	if len(c.out) == 0 {
		return
	}
	type slot struct{ rec, typ, use string }
	nth := make(map[slot]uint32, len(c.out))
	lineRec := ""
	for i, e := range c.out {
		seed := c.seeds[i]
		rec, use := seed.rec, ""
		if e.Tool != nil {
			use = e.Tool.UseID
		}
		if rec == "" {
			if lineRec == "" {
				lineRec = "l:" + lineDigest(c.st.key, c.agent, c.line)
			}
			rec = lineRec
		}
		sess := ""
		if e.Session != nil {
			sess = e.Session.ID
		}
		k := slot{rec, e.Type, use}
		n := nth[k]
		nth[k] = n + 1
		e.ID = eventID(seed.t, c.agent, sess, rec, e.Type, use, n)
	}
}

// lineDigest is the identity of a record the log gives no id: an HMAC of
// the line under the line key (nil: the per-process key), so it cannot be
// recomputed from a guess about its content.
func lineDigest(key []byte, agent string, line []byte) string {
	if len(key) == 0 {
		key = processLineKey()
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte("spoor/transcript/line/v2\x00"))
	m.Write([]byte(agent))
	m.Write([]byte{0})
	m.Write(line)
	return hex.EncodeToString(m.Sum(nil)[:16])
}

// eventID derives the UUIDv7-shaped id of one event. Its inputs are ids
// the agent generated (record and tool-call ids) or a keyed line digest,
// the agent, session and type, and the event's number among its line's
// events of that identity.
func eventID(t time.Time, agent, session, rec, typ, use string, n uint32) string {
	h := sha256.New()
	h.Write([]byte("spoor/transcript/v2\x00"))
	for _, s := range [...]string{agent, session, rec, typ, use} {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(s)))
		h.Write(l[:])
		h.Write([]byte(s))
	}
	var idx [4]byte
	binary.BigEndian.PutUint32(idx[:], n)
	h.Write(idx[:])
	sum := h.Sum(nil)

	var b [16]byte
	ms := t.UnixMilli()
	if ms < 0 {
		ms = 0
	}
	binary.BigEndian.PutUint64(b[0:8], uint64(ms)<<16)
	copy(b[6:], sum[:10])
	b[6] = (b[6] & 0x0f) | 0x70 // version 7
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	var out [36]byte
	hex.Encode(out[0:8], b[0:4])
	out[8] = '-'
	hex.Encode(out[9:13], b[4:6])
	out[13] = '-'
	hex.Encode(out[14:18], b[6:8])
	out[18] = '-'
	hex.Encode(out[19:23], b[8:10])
	out[23] = '-'
	hex.Encode(out[24:36], b[10:16])
	return string(out[:])
}

func (c *lineCtx) label(e *event.Event, k, v string) {
	if v == "" {
		return
	}
	if e.Labels == nil {
		e.Labels = map[string]string{}
	}
	e.Labels[k] = v
}

// toolPre builds a tool.pre event and registers it for pairing.
func (c *lineCtx) toolPre(ts time.Time, name, useID string, kind event.ToolKind, server, tool string, input map[string]any) *event.Event {
	e := c.newEvent(event.TypeToolPre, ts)
	name = clip(name, maxNameLen)
	useID = clip(useID, maxIDLen)
	e.Tool = &event.Tool{
		Name:        name,
		Kind:        kind,
		UseID:       useID,
		MCPServer:   clip(server, maxNameLen),
		MCPTool:     clip(tool, maxNameLen),
		InputSHA256: toolmap.InputHash(input),
		InputKeys:   toolmap.InputKeys(input),
	}
	e.Content = &event.Content{ToolInput: input, FileContent: fileContent(kind, name, input)}
	e.Target = toolmap.Target(c.agent, name, kind, input)
	c.st.addPending(useID, e)
	return e
}

// toolPost builds a tool.post event for call useID, completing it from the
// pending tool.pre when there is one.
func (c *lineCtx) toolPost(ts time.Time, useID, output string, oc *event.Outcome) *event.Event {
	useID = clip(useID, maxIDLen)
	pre := c.st.takePending(useID)
	e := c.newEvent(event.TypeToolPost, ts)
	e.Tool = &event.Tool{UseID: useID}
	e.Content = &event.Content{ToolOutput: output}
	if pre != nil {
		if pre.Tool != nil {
			t := *pre.Tool
			t.InputKeys = append([]string(nil), pre.Tool.InputKeys...)
			e.Tool = &t
		}
		if pre.Content != nil {
			e.Content.ToolInput = pre.Content.ToolInput
		}
		if pre.Target != nil {
			t := *pre.Target
			t.Paths = append([]string(nil), pre.Target.Paths...)
			t.Hosts = append([]string(nil), pre.Target.Hosts...)
			e.Target = &t
		}
		if pre.Session != nil && e.Session != nil {
			// The result belongs to the actor that made the call, even
			// when another actor's record carries it.
			if e.Session.SubagentID == "" {
				e.Session.SubagentID = pre.Session.SubagentID
				e.Session.SubagentType = pre.Session.SubagentType
			}
			if e.Session.TurnID == "" {
				e.Session.TurnID = pre.Session.TurnID
			}
		}
	}
	if output != "" {
		// Length only. No digest of the output: an unkeyed one is
		// recovered with a dictionary for short outputs, and the privacy
		// stage derives the keyed output_sha256 from Content.ToolOutput,
		// which carries the whole text on this path.
		e.Tool.OutputLen = len(output)
	}
	if oc == nil {
		oc = &event.Outcome{Status: statusUnknown}
	}
	e.Outcome = oc
	return e
}

// prompt builds a prompt.submit event.
func (c *lineCtx) prompt(ts time.Time, text string) *event.Event {
	e := c.newEvent(event.TypePromptSubmit, ts)
	e.Prompt = &event.Prompt{Len: len(text)}
	e.Content = &event.Content{PromptText: text}
	return e
}

// Outcome statuses (event.Outcome.Status vocabulary).
const (
	statusOK          = "ok"
	statusError       = "error"
	statusDenied      = "denied"
	statusInterrupted = "interrupted"
	statusUnknown     = "unknown"
)

// fileContent returns the content a write or edit tool carries, for local
// content scanning.
func fileContent(kind event.ToolKind, name string, input map[string]any) string {
	switch kind {
	case event.ToolFileWrite, event.ToolFileEdit:
	default:
		return ""
	}
	for _, k := range []string{"content", "new_string", "new_source", "file_text", "new_str", "new_content"} {
		if s, ok := input[k].(string); ok && s != "" {
			return s
		}
	}
	if strings.EqualFold(name, "apply_patch") {
		for _, k := range []string{"input", "patch"} {
			if s, ok := input[k].(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

// lineFn parses one trimmed, non-empty line that starts with '{'.
type lineFn func(c *lineCtx) error

// errSyntax marks a line whose JSON did not decode.
var errSyntax = errors.New("invalid JSON")

// parseGuard is the common ParseLine frame: counting, trimming, the
// malformed-line rule and the recover that keeps a parser bug or a hostile
// record from taking the daemon down.
func parseGuard(agent string, line []byte, st *FileState, fn lineFn) (evs []*event.Event, err error) {
	if st == nil {
		return nil, errors.New("transcript: nil FileState")
	}
	st.Lines++
	line = trimLine(line)
	if len(line) == 0 {
		return nil, nil
	}
	if line[0] != '{' {
		st.Malformed++
		return nil, fmt.Errorf("%w: not a JSON object", ErrMalformed)
	}
	c := &lineCtx{agent: agent, st: st, line: line}
	defer func() {
		if r := recover(); r != nil {
			st.Malformed++
			evs, err = nil, fmt.Errorf("%w: %s parser recovered from panic: %v", ErrMalformed, agent, r)
		}
	}()
	if ferr := fn(c); ferr != nil {
		st.Malformed++
		return nil, fmt.Errorf("%w: %v", ErrMalformed, ferr)
	}
	c.eventIDs()
	return c.out, nil
}

// trimLine strips what a torn or padded write leaves around a record: CR,
// spaces, NUL padding and a UTF-8 byte order mark.
func trimLine(line []byte) []byte {
	line = bytes.TrimPrefix(line, []byte{0xEF, 0xBB, 0xBF})
	return bytes.Trim(line, " \t\r\n\x00")
}

// Format ids accepted by ForFormat.
const (
	FormatClaude  = "claude-jsonl"
	FormatCodex   = "codex-rollout"
	FormatCopilot = "copilot-events"
	FormatGemini  = "gemini-chats"
)

// formatter is implemented by the built-in parsers; the tailer stores the
// format id next to each checkpoint.
type formatter interface{ Format() string }

// fileMode says how a file must be read.
type fileMode int

const (
	modeTail     fileMode = iota // append-only line log, read incrementally
	modeZstd                     // zstd-compressed line log, read whole
	modeDocument                 // one JSON document rewritten in place, read whole
)

// moder is implemented by parsers whose format includes files that cannot be
// tailed line by line.
type moder interface{ mode(path string) fileMode }

var builtin = []Parser{claudeParser{}, codexParser{}, copilotParser{}, geminiParser{}}

// Parsers returns the built-in parsers: claude-jsonl, codex-rollout,
// copilot-events, gemini-chats.
func Parsers() []Parser { return append([]Parser(nil), builtin...) }

// ForFormat returns the parser for a format id. Agent ids ("claude-code",
// "codex", "copilot-cli", "gemini-cli") are accepted as well.
func ForFormat(id string) (Parser, bool) {
	for _, p := range builtin {
		if f, ok := p.(formatter); ok && f.Format() == id {
			return p, true
		}
	}
	canon := toolmap.Canonical(id)
	for _, p := range builtin {
		if p.AgentID() == canon {
			return p, true
		}
	}
	return nil, false
}

// ForPath returns the first built-in parser whose Match accepts the path.
func ForPath(path string) (Parser, bool) {
	for _, p := range builtin {
		if p.Match(path) {
			return p, true
		}
	}
	return nil, false
}

func formatOf(p Parser) string {
	if f, ok := p.(formatter); ok {
		return f.Format()
	}
	return p.AgentID()
}

// ToolKindFor maps an agent's tool name to the normalized tool kind and, for
// MCP tools, the server and tool parts. It is a thin wrapper over
// toolmap.Kind so hooks and transcripts classify identically.
func ToolKindFor(agentID, toolName string) (event.ToolKind, string /*mcp server*/, string /*mcp tool*/) {
	return toolmap.Kind(agentID, toolName)
}

// slashPath normalizes separators so Match works on Windows paths too.
func slashPath(p string) string { return strings.ReplaceAll(p, `\`, "/") }

func baseName(p string) string {
	p = slashPath(p)
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}
