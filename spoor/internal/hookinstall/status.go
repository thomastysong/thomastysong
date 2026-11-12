package hookinstall

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/thomastysong/spoor/internal/catalog"
	"github.com/thomastysong/spoor/internal/event"
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
	// meaningful once spoor's registration is there.
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
// caller's binary or, without one, the binary already in the file.
func wantFor(t target, o Options, installed string) ([]entry, bool) {
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
	})
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
	if len(sc.spoorAll()) == 0 {
		c.state = checkNone
		return c
	}
	want, ok := wantFor(t, o, sc.binary())
	if !ok {
		c.state, c.detail = checkModified, "the spoor entries name no binary spoor can recognise"
		return c
	}
	state, diff := sc.compare(want, t.kind)
	switch state {
	case contentOK:
		c.state = checkOK
	default:
		c.state, c.detail = checkModified, diff
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
	var spoor int
	spoor, c.foreign, c.sensors = td.counts()
	b, err := findBlock(data, hooksBegin, hooksEnd)
	if err != nil {
		c.state, c.detail = checkModified, err.Error()
		return c
	}
	if b.found {
		c.hash = blockHash(data[b.start:b.end])
	}
	if spoor == 0 && !b.found {
		c.state = checkNone
		return c
	}
	want, ok := wantFor(t, o, td.binary())
	if !ok {
		c.state, c.detail = checkModified, "the spoor entries name no binary spoor can recognise"
		return c
	}
	if !b.found {
		c.state, c.detail = checkModified, "spoor hook entries exist outside a marked block"
		return c
	}
	blk := []byte(hooksBlock(want, newline(data)))
	inBlock := 0
	if tb, err := parseTOML(data[b.start:b.end]); err == nil {
		inBlock, _, _ = tb.counts()
	}
	switch {
	case !sameText(data[b.start:b.end], blk):
		c.state, c.detail = checkModified, "the spoor block differs from what install writes"
	case spoor != inBlock:
		c.state, c.detail = checkModified, "spoor hook entries also exist outside the marked block"
	case keysAfter(data, b):
		c.state, c.detail = checkModified, "a bare key after the spoor block becomes part of its last hook handler"
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
