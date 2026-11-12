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
	maxSecretText   = 256 << 10 // secret-file output read for values: head and tail half each
	maxEnvLines     = 4096
	minValueEntropy = 3.0
)

// Bounds of the outbound scan. Every outbound string is scanned, shortest
// first, so a padding string sorts after the short value it is meant to
// hide; a string over flowTextScan is scanned on its head and tail. Hitting
// any bound sets session.secret_flow_truncated, so a padded request is
// never silently clean.
const (
	flowTextScan = 64 << 10 // longer strings: head and tail flowTextScan/2 each
	maxFlowBytes = 1 << 20  // bytes scanned per event
	maxFlowCands = 1 << 17  // distinct candidate strings per event
	maxFlowTexts = 1024     // MCP argument strings per event
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
	if len(text) > maxSecretText {
		text = cutHead(text, maxSecretText/2) + "\n" + cutTail(text, maxSecretText/2)
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
		s.addSecret(fp(sv.v), sv.kind, len(sv.v))
	}
}

// outboundTexts returns the strings of the event that leave the machine:
// the command line of a shell command that contacts the network, the URL
// and query of a web tool, and every string argument of an MCP call; and
// whether the argument walk stopped at a bound.
func outboundTexts(ev *event.Event) ([]string, bool) {
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
	cut := false
	switch kind {
	case event.ToolWebFetch, event.ToolWebSearch, event.ToolBrowser:
		if t := ev.Target; t != nil {
			out = append(out, t.URL, t.Query)
		}
		var in []string
		in, cut = inputStrings(ev, maxFlowTexts)
		out = append(out, in...)
	case event.ToolMCP:
		var in []string
		in, cut = inputStrings(ev, maxFlowTexts)
		out = append(out, in...)
	}
	return out, cut
}

// inputStrings returns up to limit string values of the tool input (depth
// 8), and whether it left any out.
func inputStrings(ev *event.Event, limit int) ([]string, bool) {
	if ev.Content == nil || len(ev.Content.ToolInput) == 0 {
		return nil, false
	}
	var out []string
	cut := false
	var walk func(v any, depth int)
	walk = func(v any, depth int) {
		if depth > 8 {
			cut = true
			return
		}
		switch t := v.(type) {
		case string:
			if len(out) >= limit {
				cut = true
				return
			}
			out = append(out, t)
		case map[string]any:
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if len(out) >= limit {
					cut = true
					return
				}
				walk(t[k], depth+1)
			}
		case []any:
			for _, x := range t {
				if len(out) >= limit {
					cut = true
					return
				}
				walk(x, depth+1)
			}
		}
	}
	walk(ev.Content.ToolInput, 0)
	return out, cut
}

// secretFlow returns the kinds of remembered credential values that appear
// in the event's outbound strings, whether anything was checked, and
// whether the scan stopped at a bound (some outbound text was not seen).
func (s *sessionState) secretFlow(ev *event.Event) (kinds []string, checked, truncated bool) {
	if len(s.secrets) == 0 || len(s.salt) == 0 {
		return nil, false, false
	}
	texts, truncated := outboundTexts(ev)
	if len(texts) == 0 {
		return nil, false, false
	}
	want := make(map[string]string, len(s.secrets))
	sc := &flowScan{budget: maxFlowCands, seen: map[string]bool{}, lens: map[int]bool{}}
	for _, x := range s.secrets {
		want[x.fp] = x.kind
		if x.n > 0 {
			sc.lens[x.n] = true
		} else {
			sc.anyLen = true // state from before lengths were recorded
		}
	}
	found := map[string]bool{}
	fp := s.fingerprinter()
	sc.match = func(c string) {
		if k, ok := want[fp(c)]; ok {
			found[k] = true
		}
	}
	// Shortest first: a value hidden behind a long padding string is
	// reached before the padding spends the byte budget.
	sort.SliceStable(texts, func(i, j int) bool { return len(texts[i]) < len(texts[j]) })
	total := 0
scan:
	for _, t := range texts {
		if t == "" {
			continue
		}
		parts := []string{t}
		if len(t) > flowTextScan {
			parts = []string{cutHead(t, flowTextScan/2), cutTail(t, flowTextScan/2)}
			truncated = true
		}
		for _, p := range parts {
			if total+len(p) > maxFlowBytes {
				truncated = true
				break scan
			}
			total += len(p)
			flowCandidates(p, sc)
		}
	}
	truncated = truncated || sc.exhausted
	for k := range found {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	return kinds, true, truncated
}

// cutHead returns at most n leading bytes of s without splitting a rune.
func cutHead(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// cutTail returns at most n trailing bytes of s without splitting a rune.
func cutTail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	i := len(s) - n
	for i < len(s) && !utf8.RuneStart(s[i]) {
		i++
	}
	return s[i:]
}

const coarseSep = " \t\r\n'\"`;|&<>(){}[],"

// flowScan carries the candidate budget of one event. A candidate is
// fingerprinted only when its length is the length of a remembered value,
// and each distinct candidate is considered once, so repeated or
// wrong-length padding costs no fingerprints.
type flowScan struct {
	budget    int
	seen      map[string]bool // candidate -> its decodings were tried
	lens      map[int]bool
	anyLen    bool
	match     func(string)
	exhausted bool
}

// flowCandidates considers every substring of text that could be a whole
// credential value: tokens at three granularities, each also after URL,
// base64 and hex decoding (one level).
func flowCandidates(text string, sc *flowScan) {
	versions := []string{text}
	if strings.ContainsRune(text, '%') {
		if d, err := url.QueryUnescape(text); err == nil && d != text {
			versions = append(versions, d)
		}
	}
	for _, v := range versions {
		for _, tok := range strings.FieldsFunc(v, func(r rune) bool { return strings.ContainsRune(coarseSep, r) }) {
			sc.consider(tok, true)
			for _, sub := range splitAny(tok, "=:&?@#") {
				sc.consider(sub, true)
			}
			for _, sub := range splitAny(tok, "=:&?@#/") {
				sc.consider(sub, true)
			}
			if sc.exhausted {
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

func (sc *flowScan) consider(c string, decode bool) {
	if len(c) < minSecretValue || len(c) > maxSecretValue {
		return
	}
	tried, ok := sc.seen[c]
	if ok && (tried || !decode) {
		return
	}
	if !ok {
		if sc.budget <= 0 {
			sc.exhausted = true
			return
		}
		sc.budget--
		if sc.anyLen || sc.lens[len(c)] {
			sc.match(c)
		}
	}
	sc.seen[c] = decode
	if !decode {
		return
	}
	for _, d := range decodings(c) {
		sc.consider(strings.TrimSpace(d), false)
		for _, tok := range strings.FieldsFunc(d, func(r rune) bool { return strings.ContainsRune(coarseSep+"=:", r) }) {
			sc.consider(tok, false)
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
