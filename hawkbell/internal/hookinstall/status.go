package hookinstall

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/thomastysong/thomastysong/hawkbell/internal/catalog"
	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// Status audits the hook files of the requested agents. With o.Scope empty
// it reports the managed tier and, when o.Home is set, the user tier. When
// o.Binary is empty the installed binary path is taken from the file, so
// every other field is still compared with what PlanInstall would write.
//
// A status of managed or user means the file holds exactly the
// registration PlanInstall would produce. It does not prove that the agent
// runs it: Detail lists what was checked and what cannot be seen from disk
// (server-managed policy, per-user trust decisions), and the hook path's
// own records are the evidence that hooks actually fire.
func Status(c *catalog.Catalog, o Options) (states []State, err error) {
	defer func() {
		if r := recover(); r != nil {
			states, err = nil, errors.New("hookinstall: internal error while checking status")
		}
	}()
	if c == nil {
		return nil, errors.New("hookinstall: no catalog")
	}
	o, err = normalize(o, modeStatus)
	if err != nil {
		return nil, err
	}
	scopes := []event.Scope{o.Scope}
	if o.Scope == "" {
		scopes = []event.Scope{event.ScopeManaged}
		if o.Home != "" {
			scopes = append(scopes, event.ScopeUser)
		}
	}
	for _, scope := range scopes {
		for _, t := range resolveTargets(c, o, scope) {
			states = append(states, statusOf(t, o))
		}
	}
	return states, nil
}

func statusOf(t target, o Options) State {
	st := State{AgentID: t.agentID, Path: t.path, Scope: t.scope}
	if t.unsupported != "" {
		st.Status, st.Detail = StatusUnsupported, t.unsupported
		return st
	}
	managed := t.scope != event.ScopeUser
	if !filepath.IsAbs(t.path) {
		st.Status, st.Detail = StatusUnsupported, "the file belongs to another OS and is not reachable from here"
		return st
	}
	if why := checkChain(filepath.Dir(t.path), o.Root); why != "" {
		st.Status, st.Detail = StatusUnsupported, why
		if managed {
			st.Status = StatusInsecure
		}
		return st
	}
	cur := readFile(t.path, o.Root)
	switch {
	case !cur.exists:
		st.Status, st.Detail = StatusMissing, "no hook file"
		return st
	case cur.refused == refusedSymlink && managed:
		st.Status, st.Detail = StatusInsecure, "the managed hook file is a symbolic link: the agent follows it, so whoever can change the link target controls the hook"
		return st
	case cur.refused != "":
		st.Status, st.Detail = StatusUnsupported, "the hook file "+cur.refused
		return st
	case !managed && os.Geteuid() == 0:
		if why := rootEditProblem(cur.info, cur.dir); why != "" {
			st.Status, st.Detail = StatusUnsupported, why
			return st
		}
	}

	var c check
	if t.kind == kindTOML {
		c = checkTOML(t, o, cur.data)
	} else {
		c = checkJSON(t, o, cur.data)
	}
	st.Hash = c.hash
	var detail []string
	if c.detail != "" {
		detail = append(detail, c.detail)
	}
	switch c.state {
	case checkUnreadable:
		st.Status = StatusUnsupported
	case checkNone:
		st.Status = StatusMissing
		if c.foreign > 0 {
			st.Status = StatusForeignOnly
		}
	case checkModified:
		st.Status = StatusModified
	case checkOK:
		st.Status = StatusUser
		if managed {
			st.Status = StatusManaged
		}
	}
	if len(c.sensors) > 0 {
		detail = append(detail, "other sensors registered: "+strings.Join(c.sensors, ", "))
	}

	// Effectiveness: is something making the agent ignore the file? Only
	// meaningful once hawkbell's registration is there.
	if c.state == checkOK || c.state == checkModified {
		rel := inspectRelated(t, o)
		sh := shadowOf(t, o, rel, hooksOffIn(t, cur.data))
		if sh.shadowed && c.state == checkOK {
			st.Status = StatusShadowed
		}
		if d := sh.detail(); d != "" {
			detail = append(detail, d)
		}
		if managed {
			if why := insecureManaged(t, o); why != "" {
				st.Status = StatusInsecure
				detail = append([]string{why}, detail...)
			}
		}
	}
	st.Detail = strings.Join(detail, "; ")
	return st
}

type checkState uint8

const (
	checkUnreadable checkState = iota
	checkNone
	checkModified
	checkOK
)

// check is the content audit of one file.
type check struct {
	state   checkState
	detail  string
	hash    string
	foreign int
	sensors []string
}

// wantFor renders the registration PlanInstall would write, with the
// caller's binary or, without one, the binary already in the file. With
// legacy it renders what a release before the missing-binary guard wrote.
func wantFor(t target, o Options, installed string, legacy bool) ([]entry, bool) {
	bin := o.Binary
	if bin == "" {
		bin = installed
	}
	if bin == "" {
		return nil, false
	}
	return dialects[t.dialect].entries(params{
		binary: bin, agentID: t.cmdAgent, goos: o.GOOS,
		timeout: o.Timeout, guard: o.Guard, failClosed: o.FailClosed,
		legacy: legacy,
	})
}

// legacyPrefix starts the Status detail of entries that are exactly what
// an earlier release installed: not tampered with, only older.
const legacyPrefix = "written by an earlier hawkbell release"

// legacyDetail is that detail when a command the agent runs on this OS
// lacks the missing-binary check install now writes.
const legacyDetail = legacyPrefix + " whose hook commands fail when the hawkbell binary is missing; install again to update"

// legacyRunsCurrent is that detail when every command the agent runs on
// this OS is already what install writes, so only fields used on other
// OSes are older: Codex on Windows with a path written bare runs
// commandWindows, which both releases write the same way (and which stays
// without the check, see windowsCommand).
const legacyRunsCurrent = legacyPrefix + "; the commands the agent runs on this OS are already what install writes, only fields it uses on other OSes differ; install again to update them"

// legacyDetailFor picks the detail for entries that match what an earlier
// release wrote with binary bin.
func legacyDetailFor(t target, o Options, bin string) string {
	cur, ok := wantFor(t, o, bin, false)
	old, okOld := wantFor(t, o, bin, true)
	if !ok || !okOld || len(cur) != len(old) {
		return legacyDetail
	}
	key := dialects[t.dialect].runKey(o.GOOS)
	for i := range cur {
		a, aok := cur[i].handler.get(key)
		b, bok := old[i].handler.get(key)
		as, _ := a.(string)
		bs, _ := b.(string)
		if !aok || !bok || as == "" || as != bs {
			return legacyDetail
		}
	}
	return legacyRunsCurrent
}

func checkJSON(t target, o Options, data []byte) check {
	d, err := parseJSON(data)
	if err != nil {
		return check{state: checkUnreadable, detail: "the file is not a JSON object (" + err.Error() + ")"}
	}
	sc := scanHooks(d, t.kind)
	if sc.malformed != "" {
		return check{state: checkUnreadable, detail: sc.malformed}
	}
	c := check{hash: sc.hash()}
	c.foreign, c.sensors = sc.foreign()
	if len(sc.hawkbellAll()) == 0 {
		c.state = checkNone
		return c
	}
	want, ok := wantFor(t, o, sc.binary(), false)
	if !ok {
		c.state, c.detail = checkModified, "the hawkbell entries name no binary hawkbell can recognise"
		return c
	}
	state, diff := sc.compare(want, t.kind)
	switch state {
	case contentOK:
		c.state = checkOK
	default:
		c.state, c.detail = checkModified, diff
		if old, ok := wantFor(t, o, sc.binary(), true); ok {
			if st, _ := sc.compare(old, t.kind); st == contentOK {
				c.detail = legacyDetailFor(t, o, sc.binary())
			}
		}
	}
	if t.kind == kindFlat {
		if _, v := d.root.member("version"); v == nil || v.kind != kindNumber || v.num != 1 {
			c.state = checkModified
			c.detail = joinNonEmpty(c.detail, `"version" is not 1, so the agent rejects the whole file`)
		}
	}
	return c
}

func checkTOML(t target, o Options, data []byte) check {
	td, err := parseTOML(data)
	if err != nil {
		return check{state: checkUnreadable, detail: "requirements.toml is " + err.Error()}
	}
	c := check{}
	var hawkbell int
	hawkbell, c.foreign, c.sensors = td.counts()
	b, err := findBlock(data, hooksBegin, hooksEnd)
	if err != nil {
		c.state, c.detail = checkModified, err.Error()
		return c
	}
	if b.found {
		c.hash = blockHash(data[b.start:b.end])
	}
	if hawkbell == 0 && !b.found {
		c.state = checkNone
		return c
	}
	want, ok := wantFor(t, o, td.binary(), false)
	if !ok {
		c.state, c.detail = checkModified, "the hawkbell entries name no binary hawkbell can recognise"
		return c
	}
	if !b.found {
		c.state, c.detail = checkModified, "hawkbell hook entries exist outside a marked block"
		return c
	}
	blk := []byte(hooksBlock(want, newline(data)))
	inBlock := 0
	if tb, err := parseTOML(data[b.start:b.end]); err == nil {
		inBlock, _, _ = tb.counts()
	}
	switch {
	case !sameText(data[b.start:b.end], blk):
		c.state, c.detail = checkModified, "the hawkbell block differs from what install writes"
		if old, ok := wantFor(t, o, td.binary(), true); ok && sameText(data[b.start:b.end], []byte(hooksBlock(old, newline(data)))) {
			c.detail = legacyDetailFor(t, o, td.binary())
		}
	case hawkbell != inBlock:
		c.state, c.detail = checkModified, "hawkbell hook entries also exist outside the marked block"
	case keysAfter(data, b):
		c.state, c.detail = checkModified, "a bare key after the hawkbell block becomes part of its last hook handler"
	default:
		c.state = checkOK
	}
	return c
}

// hooksOffIn returns the file's own switch for every hook: Claude Code
// disableAllHooks, or Gemini CLI hooksConfig.enabled negated. Nil when the
// file does not set it as a boolean.
func hooksOffIn(t target, data []byte) *bool {
	if t.kind == kindTOML {
		return nil
	}
	d, err := parseJSON(data)
	if err != nil {
		return nil
	}
	switch t.dialect {
	case "claude":
		if _, v := d.root.member("disableAllHooks"); v != nil && v.kind == kindBool {
			b := v.b
			return &b
		}
	case "gemini":
		if on, ok := geminiHooksEnabled(d); ok {
			off := !on
			return &off
		}
	}
	return nil
}

func joinNonEmpty(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	}
	return a + ", " + b
}
