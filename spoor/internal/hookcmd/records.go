package hookcmd

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/platform"
	"github.com/thomastysong/spoor/internal/spool"
)

// Health reasons a hook reports (Health.Reason of health.error records).
// The detail of each is fixed text or a number, never payload content.
const (
	ReasonWorkerStart   = "hook_worker_start"   // the worker could not be started
	ReasonWorkerTimeout = "hook_worker_timeout" // the worker missed the hard deadline and was killed
	ReasonWorkerCrash   = "hook_worker_crash"   // the worker exited abnormally (Go fatal error, signal, panic)
	ReasonBadReply      = "hook_bad_reply"      // the worker's stdout was not one complete JSON object under MaxReply
	ReasonSpool         = "hook_spool"          // the worker could not append its records
	ReasonRender        = "hook_render"         // no reply could be rendered for a guard decision
	ReasonStdin         = "hook_stdin_timeout"  // the agent did not close stdin in time
)

// Payload anomaly codes (Labels["hook_error"] of TypePayloadAnomaly records).
// too_large and too_deep match the codes hookio puts on salvaged events.
const (
	anomalyEmpty        = "empty"
	anomalyMalformed    = "malformed"
	anomalyNoEvent      = "no_event"
	anomalyTooLarge     = "too_large"
	anomalyTooDeep      = "too_deep"
	anomalyInternal     = "internal"
	anomalyUnknownAgent = "unknown_agent"
	anomalyStdin        = "stdin_timeout"
)

// stamper holds what every record of one invocation is stamped with.
type stamper struct {
	t0      time.Time
	host    event.Host
	user    event.User
	integ   event.Integrity
	proc    event.Process
	labels  map[string]string // operator labels and hook-mode labels
	salt    []byte            // per-user secret for payload-derived keys; nil disables them
	payload []byte
	pkey    string // cached payload key
}

func newStamper(t0 time.Time, env Env, ppid int, markers []string, labels map[string]string) *stamper {
	s := &stamper{
		t0:     t0,
		host:   platform.HostInfo(),
		user:   event.User{Name: env.User, ID: env.UID},
		integ:  event.IntegrityUser,
		labels: labels,
	}
	if platform.IsPrivileged() {
		s.integ = event.IntegrityRoot
	}
	s.proc = *callerProcess(ppid)
	s.proc.EnvMarkers = append([]string(nil), markers...)
	return s
}

// stamp sets the fields that must come from the OS, never from the payload:
// host, user, integrity, time, the caller process chain, and a
// deterministic id and dedupe key. natural is the action's natural key
// (tool use id, else a keyed payload digest); see the package doc for the
// exact formula.
func (s *stamper) stamp(e *event.Event, natural string) {
	e.V = event.SchemaVersion
	e.TS = event.At(s.t0)
	h, u, p := s.host, s.user, s.proc
	p.Ancestors = append([]string(nil), s.proc.Ancestors...)
	p.EnvMarkers = append([]string(nil), s.proc.EnvMarkers...)
	e.Host, e.User, e.Process = &h, &u, &p
	e.Integrity = s.integ
	for k, v := range s.labels {
		if e.Labels == nil {
			e.Labels = map[string]string{}
		}
		if _, set := e.Labels[k]; !set {
			e.Labels[k] = v
		}
	}
	agent, session := "", ""
	if e.Agent != nil {
		agent = e.Agent.ID
	}
	if e.Session != nil {
		session = e.Session.ID
	}
	if natural == "" {
		natural = "id:" + e.ID // nothing reproducible: unique, never content-derived
	}
	e.ID = event.StableID(s.t0, h.ID, agent, session, natural, e.Type)
	e.Dedupe = event.DedupeKey(h.ID, agent, session, natural, e.Type)
}

// payloadKey is the natural key of an action without a tool use id: a
// digest of the raw payload keyed with a per-user secret kept in the spool's
// state directory. The key lets duplicate registrations of the same hook
// (managed and user settings both naming spoor) collapse downstream; the
// secret stops a reader of the log store from confirming a guessed prompt
// by hashing candidate payloads, which an unkeyed digest would allow
// (Dedupe ships at every privacy tier). Without the secret there is no
// payload key at all.
func (s *stamper) payloadKey() string {
	if s.pkey != "" || s.salt == nil {
		return s.pkey
	}
	m := hmac.New(sha256.New, s.salt)
	_, _ = m.Write(s.payload)
	s.pkey = "p:" + hex.EncodeToString(m.Sum(nil)[:16])
	return s.pkey
}

// saltState names the spool state entry holding the payload-key secret.
// The spool hashes these into the file name.
const saltAgent, saltSession = "spoor-hook", "payload-key-secret"

// loadSalt returns the per-user payload-key secret, creating it on first use.
func loadSalt(w *spool.Writer) []byte {
	if w == nil {
		return nil
	}
	if b, ok := w.LoadState(saltAgent, saltSession); ok && len(b) == 64 {
		if raw, err := hex.DecodeString(string(b)); err == nil {
			return raw
		}
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil
	}
	if w.SaveState(saltAgent, saltSession, []byte(hex.EncodeToString(raw))) != nil {
		return nil
	}
	return raw
}

// naturalKey picks the natural key of event i of n from one payload.
func (s *stamper) naturalKey(e *event.Event, i int, dup bool) string {
	k := ""
	if e.Tool != nil && e.Tool.UseID != "" {
		k = "tool:" + e.Tool.UseID
	} else {
		k = s.payloadKey()
	}
	if k != "" && dup {
		k += "#" + strconv.Itoa(i)
	}
	return k
}

// anomalyRecord stands in for a payload that produced no usable event. It
// carries only what can be said without decoding: size, a digest of the raw
// bytes (in Tool.InputSHA256, which the privacy stage keys or drops before
// anything ships), and the top-level identifiers when they could be read.
func anomalyRecord(agentID, code string, payload []byte) *event.Event {
	e := event.New(event.KindActivity, TypePayloadAnomaly, event.SourceHook)
	e.Fidelity = event.FidelityObserved
	if agentID == "" {
		agentID = "unknown"
	}
	e.Agent = &event.Agent{ID: agentID}
	f := topLevelStrings(payload, "session_id", "sessionId", "conversation_id", "cwd", "hook_event_name", "hookEventName")
	e.Session = &event.Session{}
	sid := firstOf(f["session_id"], f["sessionId"], f["conversation_id"])
	if c, cut := cleanID(sid, 128); c != "" {
		e.Session.ID = c
		if cut {
			e.Truncated = append(e.Truncated, "session.id")
		}
	}
	if cwd := f["cwd"]; cwd != "" && len(cwd) <= 4096 && !strings.ContainsAny(cwd, "\x00\n\r") {
		e.Session.CWD = cwd
	}
	sum := sha256.Sum256(payload)
	e.Tool = &event.Tool{InputSHA256: hex.EncodeToString(sum[:])}
	e.Labels = map[string]string{
		"hook_error":    code,
		"payload_bytes": strconv.Itoa(len(payload)),
	}
	if n := token(firstOf(f["hook_event_name"], f["hookEventName"]), 64); n != "" {
		e.Labels["hook_event"] = n
	}
	return e
}

// healthRecord is a health.error the supervisor appends when its worker
// failed. Reason is one of the Reason* constants; detail is fixed text.
func healthRecord(agentID, eventName, reason, detail string) *event.Event {
	e := event.New(event.KindHealth, event.TypeHealthError, event.SourceSensor)
	if agentID != "" {
		e.Agent = &event.Agent{ID: agentID}
	}
	e.Health = &event.Health{SensorVersion: Version, Mode: "hook", Reason: reason, Detail: detail}
	if eventName != "" {
		e.Labels = map[string]string{"hook_event": eventName}
	}
	return e
}

// cleanID strips control and format characters and cuts at n bytes on a
// rune boundary.
func cleanID(s string, n int) (string, bool) {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == unicode.ReplacementChar {
			return -1
		}
		return r
	}, s)
	if len(s) <= n {
		return s, false
	}
	cut := n
	for cut > 0 && !utf8Start(s[cut]) {
		cut--
	}
	return s[:cut], true
}

func utf8Start(b byte) bool { return b&0xC0 != 0x80 }

func firstOf(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
