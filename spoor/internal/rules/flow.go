package rules

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/thomastysong/spoor/internal/classify"
	"github.com/thomastysong/spoor/internal/event"
)

// Data flow of credential VALUES within a session (threat research S1,
// red-team precision control 2): when a tool result comes from a
// credential-class source, the engine keeps keyed fingerprints of the
// values in it; a later command, URL or MCP argument that carries one of
// those values (raw, URL-encoded, base64 or hex) sets session.secret_flow.
// Fingerprints are HMAC-SHA-256 under a random per-session salt, so the
// exported session state neither contains the values nor lets anyone match
// them across sessions or hosts.

const (
	minSecretValue  = 8
	maxSecretValue  = 4096
	maxFlowCands    = 4096
	maxFlowText     = 256 << 10
	maxEnvLines     = 4096
	minValueEntropy = 3.0
)

var envLine = regexp.MustCompile(`^\s*(?:export\s+)?"?([A-Za-z_][A-Za-z0-9_.\-]{0,127})"?\s*[:=]\s*(.*?)\s*,?\s*$`)

var secretNameParts = []string{"KEY", "TOKEN", "SECRET", "PASS", "PWD", "AUTH", "CRED", "PRIVATE", "SESSION", "COOKIE", "SIGNATURE", "DSN", "CONN"}

func secretName(k string) bool {
	u := strings.ToUpper(k)
	for _, p := range secretNameParts {
		if strings.Contains(u, p) {
			return true
		}
	}
	return false
}

type secretValue struct{ v, kind string }

// secretValues extracts credential values from the output of a
// credential-class read: everything classify.FindSecrets recognises, plus
// the values of KEY=VALUE / "key": "value" lines whose name is secret-like
// or whose value looks machine generated (dotenv files, INI credential
// files, JSON key files).
func secretValues(text string) []secretValue {
	if len(text) > maxFlowText {
		text = text[:maxFlowText]
	}
	var out []secretValue
	seen := map[string]bool{}
	add := func(v, kind string) {
		v = strings.TrimSpace(v)
		if len(v) < minSecretValue || len(v) > maxSecretValue || seen[v] {
			return
		}
		seen[v] = true
		out = append(out, secretValue{v, kind})
	}
	for _, h := range classify.FindSecrets(text) {
		if h.Start >= 0 && h.End <= len(text) && h.Start < h.End {
			add(text[h.Start:h.End], h.Kind)
		}
	}
	lines := strings.SplitN(text, "\n", maxEnvLines+1)
	if len(lines) > maxEnvLines {
		lines = lines[:maxEnvLines]
	}
	for _, ln := range lines {
		m := envLine.FindStringSubmatch(ln)
		if m == nil {
			continue
		}
		v := strings.Trim(m[2], `"'`)
		if strings.ContainsAny(v, " \t") {
			continue
		}
		if secretName(m[1]) || classify.Entropy(v) >= minValueEntropy {
			add(v, "env_value")
		}
	}
	return out
}

func (s *sessionState) fingerprint(v string) string {
	return s.fingerprinter()(v)
}

// fingerprinter returns a function that fingerprints many values with one
// HMAC instance.
func (s *sessionState) fingerprinter() func(string) string {
	s.ensureSalt()
	m := hmac.New(sha256.New, s.salt)
	var buf [sha256.Size]byte
	return func(v string) string {
		m.Reset()
		m.Write([]byte(v))
		return hex.EncodeToString(m.Sum(buf[:0])[:12])
	}
}

// readsSecrets reports whether the event read a credential-class source.
func readsSecrets(f map[string]any) bool {
	if b, _ := f["path.sensitive_read"].(bool); b {
		return true
	}
	if cl, _ := f["shell.read_classes"].([]string); classify.IsSensitiveRead(cl) {
		return true
	}
	if ca, _ := f["shell.cred_access"].([]string); len(ca) > 0 {
		return true
	}
	if cl, _ := f["mcp.arg_path_classes"].([]string); classify.IsSensitiveRead(cl) {
		return true
	}
	return false
}

// captureSecrets records fingerprints of the credential values in the
// event's tool output when the event read a credential-class source.
func (s *sessionState) captureSecrets(ev *event.Event) {
	if ev.Content == nil || ev.Content.ToolOutput == "" || !readsSecrets(ev.Feat) {
		return
	}
	fp := s.fingerprinter()
	for _, sv := range secretValues(ev.Content.ToolOutput) {
		s.addSecret(fp(sv.v), sv.kind)
	}
}

// outboundTexts returns the strings of the event that leave the machine:
// the command line of a shell command that contacts the network, the URL
// and query of a web tool, and every string argument of an MCP call.
func outboundTexts(ev *event.Event) []string {
	f := ev.Feat
	var out []string
	kind := event.ToolKind("")
	if ev.Tool != nil {
		kind = ev.Tool.Kind
	}
	if t := ev.Target; t != nil && t.Command != "" {
		hosts, _ := f["shell.hosts"].([]string)
		urls, _ := f["shell.urls"].([]string)
		nt, _ := f["shell.net_tools"].([]string)
		ex, _ := f["shell.exfil"].([]string)
		if len(hosts)+len(urls)+len(nt)+len(ex) > 0 {
			out = append(out, t.Command)
		}
	}
	switch kind {
	case event.ToolWebFetch, event.ToolWebSearch, event.ToolBrowser:
		if t := ev.Target; t != nil {
			out = append(out, t.URL, t.Query)
		}
		out = append(out, inputStrings(ev, 256)...)
	case event.ToolMCP:
		out = append(out, inputStrings(ev, 1024)...)
	}
	return out
}

func inputStrings(ev *event.Event, limit int) []string {
	if ev.Content == nil || len(ev.Content.ToolInput) == 0 {
		return nil
	}
	var out []string
	var walk func(v any, depth int)
	walk = func(v any, depth int) {
		if depth > 8 || len(out) >= limit {
			return
		}
		switch t := v.(type) {
		case string:
			out = append(out, t)
		case map[string]any:
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				walk(t[k], depth+1)
			}
		case []any:
			for _, x := range t {
				walk(x, depth+1)
			}
		}
	}
	walk(ev.Content.ToolInput, 0)
	return out
}

// secretFlow returns the kinds of remembered credential values that appear
// in the event's outbound strings, and whether anything was checked.
func (s *sessionState) secretFlow(ev *event.Event) (kinds []string, checked bool) {
	if len(s.secrets) == 0 || len(s.salt) == 0 {
		return nil, false
	}
	texts := outboundTexts(ev)
	if len(texts) == 0 {
		return nil, false
	}
	want := make(map[string]string, len(s.secrets))
	for _, sc := range s.secrets {
		want[sc.fp] = sc.kind
	}
	found := map[string]bool{}
	fp := s.fingerprinter()
	budget := maxFlowCands
	total := 0
	for _, t := range texts {
		if t == "" {
			continue
		}
		total += len(t)
		if total > maxFlowText {
			break
		}
		flowCandidates(t, &budget, func(c string) {
			if k, ok := want[fp(c)]; ok {
				found[k] = true
			}
		})
	}
	for k := range found {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	return kinds, true
}

const coarseSep = " \t\r\n'\"`;|&<>(){}[],"

// flowCandidates calls emit with every substring of text that could be a
// whole credential value: tokens at three granularities, each also after
// URL, base64 and hex decoding (one level).
func flowCandidates(text string, budget *int, emit func(string)) {
	versions := []string{text}
	if strings.ContainsRune(text, '%') {
		if d, err := url.QueryUnescape(text); err == nil && d != text {
			versions = append(versions, d)
		}
	}
	for _, v := range versions {
		for _, tok := range strings.FieldsFunc(v, func(r rune) bool { return strings.ContainsRune(coarseSep, r) }) {
			consider(tok, budget, emit, true)
			for _, sub := range splitAny(tok, "=:&?@#") {
				consider(sub, budget, emit, true)
			}
			for _, sub := range splitAny(tok, "=:&?@#/") {
				consider(sub, budget, emit, true)
			}
			if *budget <= 0 {
				return
			}
		}
	}
}

func splitAny(s, seps string) []string {
	if !strings.ContainsAny(s, seps) {
		return nil
	}
	return strings.FieldsFunc(s, func(r rune) bool { return strings.ContainsRune(seps, r) })
}

func consider(c string, budget *int, emit func(string), decode bool) {
	if *budget <= 0 || len(c) < minSecretValue || len(c) > maxSecretValue {
		return
	}
	*budget--
	emit(c)
	if !decode {
		return
	}
	for _, d := range decodings(c) {
		consider(strings.TrimSpace(d), budget, emit, false)
		for _, tok := range strings.FieldsFunc(d, func(r rune) bool { return strings.ContainsRune(coarseSep+"=:", r) }) {
			consider(tok, budget, emit, false)
		}
	}
}

// decodings returns c decoded as base64 (any alphabet) or hex, when it
// decodes to text.
func decodings(c string) []string {
	var out []string
	if len(c) >= 12 && isBase64ish(c) {
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			if b, err := enc.DecodeString(c); err == nil && printable(b) {
				out = append(out, string(b))
				break
			}
		}
	}
	if len(c) >= 16 && len(c)%2 == 0 {
		if b, err := hex.DecodeString(c); err == nil && printable(b) {
			out = append(out, string(b))
		}
	}
	return out
}

func isBase64ish(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '=' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func printable(b []byte) bool {
	if len(b) == 0 || !utf8.Valid(b) {
		return false
	}
	for _, c := range b {
		if c < 0x20 && c != '\n' && c != '\r' && c != '\t' {
			return false
		}
	}
	return true
}

// pathDigest normalizes a path lexically (home expansion, cwd join, clean,
// case folding where the filesystem folds) and hashes it, so "./run.sh",
// "run.sh" and "/repo/run.sh" in the same session compare equal.
func pathDigest(p, cwd, home, goos string) string {
	p = strings.Trim(strings.TrimSpace(p), `"'`)
	if p == "" || len(p) > 4096 {
		return ""
	}
	win := goos == "windows"
	p = strings.ReplaceAll(p, `\`, "/")
	switch {
	case p == "~" || strings.HasPrefix(p, "~/"):
		if home == "" {
			return ""
		}
		p = strings.ReplaceAll(home, `\`, "/") + p[1:]
	case strings.HasPrefix(p, "$HOME/") || strings.HasPrefix(p, "${HOME}/"):
		if home == "" {
			return ""
		}
		p = strings.ReplaceAll(home, `\`, "/") + p[strings.IndexByte(p, '/'):]
	}
	abs := strings.HasPrefix(p, "/") || (len(p) >= 2 && p[1] == ':')
	if !abs {
		if cwd == "" {
			return ""
		}
		p = strings.ReplaceAll(cwd, `\`, "/") + "/" + p
	}
	p = path.Clean(p)
	if win || goos == "darwin" {
		p = strings.ToLower(p)
	}
	sum := sha256.Sum256([]byte(p))
	return hex.EncodeToString(sum[:8])
}

// execPaths returns the paths an event executes.
func execPaths(ev *event.Event) []string {
	var out []string
	if l, ok := ev.Feat["shell.executes_paths"].([]string); ok {
		out = append(out, l...)
	}
	if ev.Type == event.TypeProcessExec && ev.Process != nil && ev.Process.Exe != "" {
		out = append(out, ev.Process.Exe)
	}
	return out
}

// writtenPaths returns the paths an event writes: file tool targets, shell
// redirections and copy destinations, and the path arguments of an MCP
// tool whose name says it writes.
func writtenPaths(ev *event.Event) []string {
	var out []string
	if ev.Tool != nil {
		switch ev.Tool.Kind {
		case event.ToolFileWrite, event.ToolFileEdit:
			if t := ev.Target; t != nil {
				if t.Path != "" {
					out = append(out, t.Path)
				}
				out = append(out, t.Paths...)
			}
		case event.ToolMCP:
			name := strings.ToLower(ev.Tool.MCPTool)
			for _, w := range []string{"write", "create", "edit", "save", "put", "upload", "move", "copy"} {
				if strings.Contains(name, w) {
					if l, ok := ev.Feat["mcp.arg_paths"].([]string); ok {
						out = append(out, l...)
					}
					break
				}
			}
		}
	}
	if l, ok := ev.Feat["shell.writes"].([]string); ok {
		out = append(out, l...)
	}
	return out
}
