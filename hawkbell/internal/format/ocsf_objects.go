package format

import (
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// epochMillis is OCSF timestamp_t. A zero time maps to 0 rather than to the
// year-1 value UnixMilli would return, so "unset" stays recognizable.
func epochMillis(t event.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// clip cuts s to at most n bytes without splitting a UTF-8 sequence.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func stringsToAny(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

// baseName returns the last path element for either separator style: events
// from a Windows endpoint may be formatted on any OS, so path/filepath (which
// follows the build target) would be wrong here.
func baseName(p string) string {
	t := strings.TrimRight(p, `/\`)
	if t == "" {
		return p
	}
	if i := strings.LastIndexAny(t, `/\`); i >= 0 {
		return t[i+1:]
	}
	return t
}

// device builds the OCSF device. type_id is required and stays 0 (Unknown):
// the sensor cannot tell a laptop from a server, and a wrong guess is worse
// than none.
func (b *ocsfBuilder) device() map[string]any {
	d := map[string]any{"type_id": 0, "type": "Unknown"}
	h := b.e.Host
	if h != nil {
		if h.Name != "" {
			d["hostname"] = h.Name
		}
		if h.ID != "" {
			d["uid"] = h.ID
		}
		switch h.OS {
		case "linux":
			d["os"] = map[string]any{"name": "Linux", "type_id": 200, "type": "Linux"}
		case "darwin":
			d["os"] = map[string]any{"name": "macOS", "type_id": 300, "type": "macOS"}
		case "windows":
			d["os"] = map[string]any{"name": "Windows", "type_id": 100, "type": "Windows"}
		}
	}
	if c := b.e.Container; c != nil && (c.ID != "" || c.Name != "") {
		co := map[string]any{}
		setStr(co, "uid", c.ID)
		setStr(co, "name", c.Name)
		setStr(co, "runtime", c.Runtime)
		setStr(co, "pod_uuid", c.PodUID)
		if c.Pod != "" || c.Namespace != "" || c.PodUID != "" {
			co["orchestrator"] = "Kubernetes"
		}
		d["container"] = co
		b.profile("container")
	}
	return d
}

func setStr(m map[string]any, k, v string) {
	if v != "" {
		m[k] = v
	}
}

func userObj(name, id string) map[string]any {
	if name == "" && id == "" {
		return nil
	}
	u := map[string]any{}
	setStr(u, "name", name)
	setStr(u, "uid", id)
	return u
}

func (b *ocsfBuilder) eventUser() map[string]any {
	if b.e.User == nil {
		return nil
	}
	return userObj(b.e.User.Name, b.e.User.ID)
}

// actor describes who acted: the OS user plus the agent as the application.
// The agent process is included only when its pid is known, because an OCSF
// process needs a pid or uid. With required set, a placeholder is returned
// when nothing is known so classes that require actor stay valid.
func (b *ocsfBuilder) actor(required bool) map[string]any {
	e := b.e
	a := map[string]any{}
	if u := b.eventUser(); u != nil {
		a["user"] = u
	}
	if e.Agent != nil {
		name := firstNonEmpty(e.Agent.Name, e.Agent.ID)
		setStr(a, "app_name", name)
		setStr(a, "app_uid", e.Agent.ID)
		if e.Agent.PID > 0 {
			p := map[string]any{"pid": e.Agent.PID}
			setStr(p, "name", name)
			a["process"] = p
		}
	}
	if len(a) == 0 {
		if !required {
			return nil
		}
		a["app_name"] = "unknown"
	}
	return a
}

// aiAgent builds the ai_agent object of the ai_operation profile and enables
// the profile. It is only called for classes the profile is registered on
// (system, network, application); findings and discovery keep the agent in
// evidences or unmapped.hawkbell.
func (b *ocsfBuilder) aiAgent() map[string]any {
	e := b.e
	if e.Agent == nil || (e.Agent.ID == "" && e.Agent.Name == "") {
		return nil
	}
	a := map[string]any{"type_id": 0, "type": "Unknown"}
	setStr(a, "uid", e.Agent.ID)
	setStr(a, "name", firstNonEmpty(e.Agent.Name, e.Agent.ID))
	setStr(a, "version", e.Agent.Version)
	if e.Session != nil {
		setStr(a, "instance_uid", e.Session.ID)
		if p := modelProvider(e.Session.Model); p != "" {
			a["ai_model"] = map[string]any{"name": e.Session.Model, "ai_provider": p}
		}
	}
	return a
}

func (b *ocsfBuilder) withAIAgent() {
	if a := b.aiAgent(); a != nil {
		b.m["ai_agent"] = a
		b.profile("ai_operation")
	}
}

// modelProvider names the organization behind a model id. OCSF requires
// ai_model.ai_provider, and the native event only carries the model id, so
// the object is emitted only for families whose naming is unambiguous.
// UNVERIFIED: this is a naming-convention inference, not a fact from the
// research reports; unknown families simply omit ai_model.
func modelProvider(model string) string {
	m := strings.ToLower(model)
	switch {
	case m == "":
		return ""
	case strings.Contains(m, "claude"):
		return "Anthropic"
	case strings.HasPrefix(m, "gpt-"), strings.Contains(m, "codex"):
		return "OpenAI"
	case strings.Contains(m, "gemini"):
		return "Google"
	}
	return ""
}

// fileObj builds an OCSF file; name and type_id are required.
func fileObj(path string, typeID int, typeName string) map[string]any {
	name := baseName(path)
	f := map[string]any{"name": name, "path": path, "type_id": typeID, "type": typeName}
	if i := strings.LastIndexByte(name, '.'); i > 0 && i < len(name)-1 {
		f["ext"] = name[i+1:]
	}
	return f
}

// urlObj builds an OCSF url. url_string is always present (the object needs
// url_string or path); the parsed parts are best effort because the value
// came from an agent and may not be a URL at all.
func urlObj(raw string) map[string]any {
	u := map[string]any{"url_string": raw}
	p, err := url.Parse(raw)
	if err != nil || p == nil {
		return u
	}
	setStr(u, "scheme", p.Scheme)
	setStr(u, "hostname", p.Hostname())
	setStr(u, "path", p.Path)
	setStr(u, "query_string", p.RawQuery)
	if n, err := strconv.Atoi(p.Port()); err == nil && n > 0 && n < 65536 {
		u["port"] = n
	}
	return u
}

// endpointObj builds a network endpoint from a host name or address.
func endpointObj(host string, port int) map[string]any {
	if host == "" {
		return nil
	}
	ep := map[string]any{}
	if addr, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		ep["ip"] = addr.String()
	} else {
		ep["hostname"] = host
	}
	if port > 0 {
		ep["port"] = port
	}
	return ep
}

// srcEndpoint describes this endpoint as the source of a network or API
// call. Classes that require it get a named placeholder when the host is
// unknown, since an endpoint needs at least one identifying attribute.
func (b *ocsfBuilder) srcEndpoint() map[string]any {
	ep := map[string]any{}
	if h := b.e.Host; h != nil {
		setStr(ep, "hostname", h.Name)
		setStr(ep, "uid", h.ID)
	}
	if len(ep) == 0 {
		ep["name"] = "unknown"
	}
	return ep
}

// targetHost returns the destination host and port of a web tool call.
func targetHost(t *event.Target) (string, int) {
	if t == nil {
		return "", 0
	}
	if t.URL != "" {
		if p, err := url.Parse(t.URL); err == nil && p != nil && p.Hostname() != "" {
			port, _ := strconv.Atoi(p.Port())
			if port == 0 {
				switch p.Scheme {
				case "https", "wss":
					port = 443
				case "http", "ws":
					port = 80
				}
			}
			return p.Hostname(), port
		}
	}
	if t.Host != "" {
		return t.Host, 0
	}
	if len(t.Hosts) > 0 {
		return t.Hosts[0], 0
	}
	return "", 0
}
