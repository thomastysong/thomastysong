package engine

import (
	"net"
	"net/url"
	"strings"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
	"github.com/thomastysong/thomastysong/hawkbell/internal/features"
)

// Secret flow skeleton (C2 item 6).
//
// The rules engine sets session.secret_flow when a command line, URL, query
// or MCP/web argument carries (raw, URL-encoded, base64 or hex) a credential
// value read earlier in the session. The engine never learns the value
// (the rules engine keeps keyed fingerprints only), and the redactor cannot
// recognise an encoded value, so a record that triggered secret flow is
// reduced to a skeleton before anything is written: every field that
// carries a string from the agent's input is replaced, and only facts that
// cannot carry the value are kept. The rule is default-deny, so a new field
// or feature cannot fall behind the detector:
//
//   - command: the program names only; URL: scheme, host and port only;
//     query, tool input and output, prompt text, error text, process
//     arguments: removed; paths (target.path, target.paths): the marker.
//   - hosts are kept, because where the data went is what the finding is
//     about, except for host labels shaped like an encoding (16 characters
//     or more, or 8 or more with a digit or an upper-case letter; host
//     names are lower-case words). A dotless host is compared whole by the
//     detector, so the same rule covers a value sent as a bare hex "host".
//   - features: booleans, numbers and closed vocabularies (classes, kinds,
//     markers, flags) are kept; host lists are filtered as above; command
//     names as above; everything else (paths, argv, URLs, installs,
//     objects) is dropped, so no evidence or summary can be rendered from
//     it.
//
// Limit: a credential that is itself a plain lower-case word without
// digits, used as a host label, is indistinguishable from a host name and
// is kept.

// flowMarker replaces values that could carry a session secret.
const flowMarker = "[REDACTED:secret_flow]"

// minFlowToken is the shortest value the detector fingerprints (rules
// minSecretValue): anything shorter cannot be a carrier.
const minFlowToken = 8

// flowCarrier reports whether a token is shaped like an encoded value.
func flowCarrier(tok string) bool {
	if len(tok) >= 16 {
		return true
	}
	if len(tok) < minFlowToken {
		return false
	}
	for i := 0; i < len(tok); i++ {
		if c := tok[i]; c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' {
			return true
		}
	}
	return false
}

// flowHost keeps a host name unless a label of it could carry the value.
func flowHost(h string) string {
	if h == "" {
		return ""
	}
	if net.ParseIP(strings.Trim(h, "[]")) != nil {
		return h
	}
	labels := strings.Split(h, ".")
	for i, l := range labels {
		if flowCarrier(l) {
			labels[i] = flowMarker
		}
	}
	return strings.Join(labels, ".")
}

func flowHosts(l []string) []string {
	if len(l) == 0 {
		return nil
	}
	out := make([]string, len(l))
	for i, h := range l {
		out[i] = flowHost(h)
	}
	return out
}

// flowNames keeps the names that cannot carry the value.
func flowNames(l []string) []string {
	var out []string
	for _, n := range l {
		if n != "" && !flowCarrier(n) && !strings.ContainsAny(n, "/\\=:%") {
			out = append(out, n)
		}
	}
	return out
}

func urlSkeleton(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return flowMarker
	}
	scheme := strings.ToLower(u.Scheme)
	if flowCarrier(scheme) {
		scheme = flowMarker
	}
	host := flowHost(u.Hostname())
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		host = "[" + host + "]"
	}
	if port := u.Port(); port != "" && len(port) <= 5 {
		host += ":" + port
	}
	return scheme + "://" + host + "/" + flowMarker
}

func markAll(l []string) []string {
	if len(l) == 0 {
		return nil
	}
	out := make([]string, len(l))
	for i := range out {
		out[i] = flowMarker
	}
	return out
}

// flowHostFeatures are host lists, filtered with flowHost.
var flowHostFeatures = map[string]bool{"net.host": true, "shell.hosts": true, "mcp.arg_hosts": true}

// flowNameFeatures are name lists from the command line or a URL scheme.
var flowNameFeatures = map[string]bool{"shell.commands": true, "shell.interpreters": true, "net.scheme": true}

// flowKeptStrings are string features that never come from the agent's
// input: the MCP server and tool are the agent's naming of the tool, and
// session flags are rule-set names.
var flowKeptStrings = map[string]bool{"mcp.server": true, "mcp.tool": true, "session.flags": true}

// closedFeature reports a feature whose values come from a closed
// vocabulary (the registry says so, or it is a class, kind or marker list,
// the families the privacy allowlist also treats as closed).
func closedFeature(k string) bool {
	if fi, ok := features.Lookup(k); ok && fi.Vocab != nil {
		return true
	}
	for _, suf := range []string{"_classes", "_kinds", ".classes", ".kinds", ".markers", "_markers"} {
		if strings.HasSuffix(k, suf) {
			return true
		}
	}
	return false
}

// flowFeatures is the feature view of a flow record: default-deny for
// anything that holds strings.
func flowFeatures(f map[string]any) map[string]any {
	if f == nil {
		return nil
	}
	out := make(map[string]any, len(f))
	for k, v := range f {
		switch x := v.(type) {
		case bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
			out[k] = x
		case string:
			if closedFeature(k) || flowKeptStrings[k] {
				out[k] = x
			}
		case []string:
			switch {
			case flowHostFeatures[k]:
				out[k] = flowHosts(x)
			case flowNameFeatures[k]:
				out[k] = flowNames(x)
			case closedFeature(k) || flowKeptStrings[k]:
				out[k] = append([]string(nil), x...)
			}
		}
	}
	return out
}

// scrubFlow reduces a record that carried a session secret to its
// skeleton (see above). It copies every part it changes: the rules engine
// shares Content and Feat between an event and its detections.
func scrubFlow(e *event.Event) {
	if e == nil {
		return
	}
	if e.Target != nil {
		t := *e.Target
		if t.Command != "" {
			names, _ := e.Feat["shell.commands"].([]string)
			t.Command = strings.TrimSpace(strings.Join(flowNames(names), " ") + " " + flowMarker)
		}
		if t.URL != "" {
			t.URL = urlSkeleton(t.URL)
		}
		t.Query = ""
		if t.Path != "" {
			t.Path = flowMarker
		}
		t.Paths = markAll(t.Paths)
		t.Host = flowHost(t.Host)
		t.Hosts = flowHosts(t.Hosts)
		e.Target = &t
	}
	if e.Tool != nil {
		tt := *e.Tool
		tt.Input = nil
		tt.Output = ""
		tt.InputKeys = append([]string(nil), e.Tool.InputKeys...)
		e.Tool = &tt
	}
	if e.Prompt != nil && e.Prompt.Text != "" {
		pr := *e.Prompt
		pr.Text = ""
		e.Prompt = &pr
	}
	if e.Outcome != nil && e.Outcome.Error != "" {
		o := *e.Outcome
		o.Error = flowMarker
		e.Outcome = &o
	}
	if e.Process != nil && len(e.Process.Args) > 0 {
		pr := *e.Process
		pr.Args = []string{flowMarker}
		pr.Ancestors = append([]string(nil), e.Process.Ancestors...)
		pr.EnvMarkers = append([]string(nil), e.Process.EnvMarkers...)
		pr.Flags = append([]string(nil), e.Process.Flags...)
		e.Process = &pr
	}
	e.Content = nil
	e.Feat = flowFeatures(e.Feat)
	l := make(map[string]string, len(e.Labels)+1)
	for k, v := range e.Labels {
		l[k] = v
	}
	l["redacted"] = "secret_flow"
	e.Labels = l
	if e.Detection != nil && len(e.Detection.Evidence) > 0 {
		// The engine rebuilds evidence from the record (ruleDetection), so
		// only the field names matter; the values the rules engine rendered
		// from the unscrubbed record must not survive.
		d := *e.Detection
		d.Evidence = make(map[string]string, len(e.Detection.Evidence))
		for k := range e.Detection.Evidence {
			d.Evidence[k] = flowMarker
		}
		e.Detection = &d
	}
}
