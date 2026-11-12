package privacy

import (
	"sort"
	"strings"

	"github.com/thomastysong/thomastysong/hawkbell/internal/classify"
	"github.com/thomastysong/thomastysong/hawkbell/internal/shellx"
)

// Structural command redaction.
//
// Pattern-and-entropy redaction alone leaked 8 of 17 ordinary credentials
// in the privacy red team's corpus (mysql -pSommer2026!, curl -u
// alice:Winter2026, sshpass -p ...): human passwords have low entropy and
// carry no recognisable prefix, so they are only visible from where they
// sit in a command. The redactor therefore works in layers:
//
//  1. Every simple command at the top level is split into words with their
//     byte spans (lex.go) and its argument vector goes through
//     classify.RedactArgs, which knows secret-bearing flags, tool-specific
//     short flags, NAME=value assignments, headers, request bodies and URL
//     userinfo, and through this package's own flag table (argrules.go).
//     Rules no single argv expresses are added here (specials.go):
//     literals piped or here-stringed into a consumer that reads a
//     credential from stdin (--password-stdin, sudo -S, passwd, kinit,
//     openssl -pass stdin, vault login -), text written into a
//     credential-class file, printf arguments a format labels as a
//     password, PowerShell assignments and environment setters,
//     ConvertTo-SecureString -AsPlainText, "net user NAME PASSWORD", setx,
//     htpasswd -b.
//  2. shellx.Analyze sees what the top level cannot: commands inside
//     bash -c strings, cmd /c, eval, $( ), wrappers and decoded payloads.
//     Each of those argument vectors is redacted the same way and the
//     redacted argument is put back where it occurs inside the enclosing
//     word.
//  3. Every secret value recovered from steps 1 and 2 is then searched for
//     as plain text, reversed, and inside base64, hex and escape-sequence
//     runs (a decoded payload's password is only present encoded).
//  4. If a secret found structurally cannot be located in the text, the
//     command is replaced by a skeleton (program names and flags only):
//     losing detail is acceptable, leaking a secret is not.
//  5. classify.Redact runs over the result as the pattern pass.
//
// Coverage: every emitted byte must have been seen by every view. A view
// that stops part of the way (a token cap, shellx's command budget) would
// otherwise let the rest of the line be copied out unexamined, so the line
// is cut where the first view stopped and only its head is emitted (see
// cover).
//
// The result still carries classify's unkeyed fingerprints; the caller
// rewrites them (see Policy.rewriteMarkers).

const (
	// maxCommandScan is how much of a command line is analysed, and so the
	// most of it that can be emitted. Every emitted byte must have been
	// seen by every view (word lexer, shellx, the nested re-lex and the
	// syntax-blind view): a view that stops early and lets the rest be
	// copied out unseen is how a password after 65,536 tokens leaked. The
	// costliest view to run to the end, argument-vector redaction of every
	// syntax-blind segment and every quoted multi-word value, takes about
	// 25-30 ms each for 64 KiB of worst-case input, so that is the cap. The
	// emitted field (MaxField) is far smaller anyway; a longer line loses
	// its tail, never its redaction.
	maxCommandScan = 64 << 10
	// minShellxCover is the length below which a truncated shellx analysis
	// is accepted. shellx's count budgets (2,048 commands, 400,000 work
	// units, 256 sub-analyses) cannot be exhausted by a line this short;
	// what still truncates it is nesting deeper than MaxDepth, which no
	// shorter cut would fix. Above it, a truncated analysis means shellx
	// stopped somewhere in the line, at an offset it does not report, so
	// the line is halved until shellx sees all of it.
	minShellxCover = 2 << 10
	// maxCoverPasses bounds the shrinking (64 KiB halves to minShellxCover
	// in five passes).
	maxCoverPasses = 8
	// maxNestedTexts bounds how many inline-code and decoded payloads from
	// shellx are re-lexed for structural redaction. Quoted values, heredoc
	// bodies and comments of the line itself are disjoint spans of at most
	// maxCommandScan bytes, so they are all re-lexed, without a count cap.
	maxNestedTexts = 64
	maxNestedLen   = 64 << 10
	// maxPairs bounds the number of nested redactions tracked; a command
	// with more than this many redacted arguments is reduced to a skeleton.
	maxPairs = 512
	// minSearch is the shortest secret searched for as a bare substring
	// anywhere in the text. Shorter ones are only replaced where they
	// occur as a whole argument.
	minSearch = 4
	// maxSecretScan bounds the substring searches for recovered secrets:
	// (number of secrets) x (bytes of text) per pass. Every secret is
	// searched for over the whole text several times (plain, reversed,
	// encoded), so an agent-written line with thousands of distinct
	// credentials would otherwise cost seconds per event (measured: 5.5 s
	// for 12,800 secrets in 256 KiB). Beyond the budget the command is
	// reduced to its skeleton instead.
	maxSecretScan = 32 << 20
	// maxSkeleton bounds the fail-closed rendering, so the final check
	// that no secret survives in it stays cheap as well.
	maxSkeleton = 4 << 10

	kindEncoded    = "encoded_secret"
	kindUnresolved = "unresolved_secret"
	kindCommand    = "command"
	kindFailure    = "redaction_failure"
)

// failMarker replaces a value whose redaction failed: an unredacted value
// must never escape because of a bug.
var failMarker = markerOpen + kindFailure + "]"

// pair is one nested argument that was redacted: where it can be found and
// what replaces it.
type pair struct {
	oldRaw, newRaw string // as written in the nested text (may be empty)
	oldVal, newVal string // quotes and escapes removed
	secrets        []secret
	strict         bool // came from a decoded payload: absence is not proof
	optional       bool // from the syntax-blind view: a misread, not a miss, when it cannot be placed
	resolved       bool
}

type cmdRedactor struct {
	src      string
	d        shellx.Dialect
	toks     []token
	vals     []string // current value per token
	dirty    []bool
	segs     []segment
	secrets  []secret
	pairs    []*pair
	topOld   map[string]string // top-level original value -> redacted value
	fail     bool              // a secret could not be placed: emit the skeleton
	nameMemo map[string]bool
	argMemo  *argvMemo // shared with the sub-redactors of nested texts
	lexStop  int       // where the word lexer's token cap stopped it, -1 when it did not
}

// redactCommandUncached is redactCommand without the memo (memo.go).
func redactCommandUncached(cmd string, hint shellx.Dialect) (out string, precapped bool) {
	defer func() {
		if recover() != nil {
			out, precapped = failMarker, false
		}
	}()
	if strings.TrimSpace(cmd) == "" {
		return cmd, false
	}
	src, _ := controlsToSpace(cmd)
	if len(src) > maxCommandScan {
		src = src[:safeCut(src, maxCommandScan)]
	}
	f, r := cover(src, hint)
	src = r.src
	precapped = len(src) < len(cmd)
	r.topLevel()
	r.nested(f)
	if !r.fail {
		r.applyPairs()
		r.substituteSecrets()
	}
	if r.fail {
		// Already fail-closed: the searches below would only cost time.
		out = r.skeleton()
	} else {
		out = r.render()
		out = r.stringLevel(out)
		if r.unresolved() {
			out = r.skeleton()
		}
	}
	out = redactText(out)
	if precapped {
		out += truncMarker(len(cmd) - len(src))
	}
	return out, precapped
}

// cover analyses src, shortening it until every structural view has seen
// all of it: the word lexer (token cap) and shellx (count and work
// budgets, which it reports only as Truncated). The syntax-blind view and
// the nested re-lex run to the end of anything up to maxCommandScan. If
// the views still disagree after maxCoverPasses, the redactor is marked
// failed and the command is emitted as its skeleton.
func cover(src string, hint shellx.Dialect) (*shellx.Facts, *cmdRedactor) {
	for pass := 1; ; pass++ {
		f := shellx.Analyze(src, hint)
		r := newCmdRedactor(src, f.Dialect)
		h := len(src)
		if r.lexStop >= 0 && r.lexStop < h {
			h = r.lexStop
		}
		if f.Truncated && len(src) > minShellxCover {
			h = min(h, len(src)/2)
		}
		if h >= len(src) {
			return f, r
		}
		if pass >= maxCoverPasses {
			r.fail = true
			return f, r
		}
		src = src[:safeCut(src, h)]
	}
}

func newCmdRedactor(src string, d shellx.Dialect) *cmdRedactor {
	r := &cmdRedactor{src: src, d: d, topOld: map[string]string{}, argMemo: &argvMemo{}}
	r.toks, r.lexStop = lexStop(src, d)
	r.vals = make([]string, len(r.toks))
	r.dirty = make([]bool, len(r.toks))
	for i, t := range r.toks {
		r.vals[i] = t.val
	}
	r.segs = segments(r.toks)
	return r
}

func (r *cmdRedactor) setVal(i int, v string) {
	if r.vals[i] == v {
		return
	}
	r.vals[i] = v
	r.dirty[i] = true
}

// argv returns the current argument values of a segment.
func (r *cmdRedactor) argv(s segment) []string {
	out := make([]string, len(s.words))
	for k, w := range s.words {
		out[k] = r.vals[w]
	}
	return out
}

// edit replaces token i's value, recording the secrets it contained.
func (r *cmdRedactor) edit(i int, red string) {
	old := r.vals[i]
	if old == red {
		return
	}
	r.secrets = append(r.secrets, alignSecrets(old, red)...)
	if r.toks[i].kind == tWord {
		r.topOld[r.toks[i].val] = red
	}
	r.setVal(i, red)
}

// redactWhole replaces a whole token value with a marker of kind.
func (r *cmdRedactor) redactWhole(i int, kind string) {
	v := r.vals[i]
	if v == "" || keepRef(v) {
		return
	}
	trail := ""
	if r.toks[i].kind == tHeredoc {
		trimmed := strings.TrimRight(v, "\r\n")
		trail = v[len(trimmed):]
		v = trimmed
		if v == "" {
			return
		}
	}
	m := newMarker(kind, v)
	r.secrets = append(r.secrets, secret{value: v, marker: m})
	r.setVal(i, m+trail)
}

// topLevel applies argv redaction and the multi-word rules to every simple
// command of the source.
func (r *cmdRedactor) topLevel() {
	for _, s := range r.segs {
		if len(s.words) == 0 {
			continue
		}
		argv := r.argv(s)
		red := r.argMemo.redact(argv)
		for k := range argv {
			if k < len(red) && red[k] != argv[k] {
				r.edit(s.words[k], red[k])
			}
		}
	}
	r.specials()
}

// nested collects redactions from code inside the command: inline shell
// code and decoded payloads are re-lexed (exact raw spans), and every
// command shellx found at any depth is redacted as an argument vector.
func (r *cmdRedactor) nested(f *shellx.Facts) {
	texts := 0
	addText := func(text string, d shellx.Dialect, strict, own bool) {
		if text == "" {
			return
		}
		if !own {
			// Payloads from shellx (inline code, decoded text) are not
			// spans of the line and can repeat it; they are bounded.
			if texts >= maxNestedTexts || len(text) > maxNestedLen {
				return
			}
			texts++
		}
		sub := newCmdRedactor(text, d)
		if sub.lexStop >= 0 {
			// Cannot happen for a span of a line under maxCommandScan;
			// if it does, nothing of that text may be trusted as seen.
			r.fail = true
		}
		sub.nameMemo = r.nameMemo
		sub.argMemo = r.argMemo
		sub.topLevel()
		r.nameMemo = sub.nameMemo
		for i, t := range sub.toks {
			if !sub.dirty[i] {
				continue
			}
			p := &pair{
				oldVal: t.val, newVal: sub.vals[i], strict: strict,
				secrets: alignSecrets(t.val, sub.vals[i]),
			}
			if t.kind == tWord {
				p.oldRaw = text[t.start:t.end]
				p.newRaw = requote(sub.vals[i], d, t.quote)
			}
			if len(p.secrets) == 0 {
				p.secrets = sub.secrets
			}
			r.addPair(p)
		}
		// Secrets from multi-word rules (stdin feeders, assignments) are
		// tracked even when the token edit itself is found above.
		r.secrets = append(r.secrets, sub.secrets...)
	}
	for _, ic := range f.Inline {
		switch ic.Lang {
		case "sh":
			addText(ic.Code, shellx.Posix, false, false)
		case "powershell":
			addText(ic.Code, shellx.PowerShell, false, false)
		case "cmd":
			addText(ic.Code, shellx.Cmd, false, false)
		default:
			// Foreign-language code: the pattern pass covers it, and its
			// hits are added as searchable secrets so escaping differences
			// between the code and the shell word do not hide them.
			if len(ic.Code) <= maxNestedLen {
				for _, h := range classify.FindSecrets(ic.Code) {
					if h.Start >= 0 && h.End <= len(ic.Code) && h.Start < h.End {
						r.secrets = append(r.secrets, secret{value: ic.Code[h.Start:h.End], marker: classify.Marker(h.Kind, h.Fingerprint)})
					}
				}
			}
		}
	}
	for _, d := range f.Decoded {
		addText(d, shellx.Posix, true, false)
	}
	// Any quoted multi-word value, heredoc body or comment may hold a
	// command line shellx does not model (watch "...", tmux send-keys
	// "...", su -c, an unterminated quote bash would reject, "# ran mysql
	// -p..."): treating it as one costs little and only ever removes more.
	for i, t := range r.toks {
		switch {
		case t.kind == tHeredoc:
			addText(r.vals[i], r.d, false, true)
		case t.kind == tComment:
			addText(strings.TrimLeft(t.val, "#"), r.d, false, true)
		case t.kind == tWord && t.quote != 0 && strings.ContainsAny(t.val, " \t\n"):
			addText(t.val, r.d, false, true)
		}
	}
	// A last, syntax-blind view: split the line on whitespace and
	// separators with quote characters stripped. Unbalanced quotes,
	// brackets or backticks make the shell reject a line (and make both
	// parsers see one long word), but its text is still emitted; this view
	// still hands every flag and value to argument-vector redaction. It
	// covers the whole line (at most maxCommandScan bytes).
	for _, argv := range naiveSegments(r.src) {
		red := r.argMemo.redact(argv)
		for k := range argv {
			if k < len(red) && red[k] != argv[k] {
				r.addPair(&pair{oldVal: argv[k], newVal: red[k], secrets: alignSecrets(argv[k], red[k]), optional: true})
			}
		}
	}
	for _, c := range f.Commands {
		argv := make([]string, 0, len(c.Args)+1)
		argv = append(argv, c.Path)
		argv = append(argv, c.Args...)
		red := r.argMemo.redact(argv)
		for k := range argv {
			if k >= len(red) || red[k] == argv[k] {
				continue
			}
			r.addPair(&pair{
				oldVal: argv[k], newVal: red[k],
				strict:  c.Origin == shellx.OriginDecoded,
				secrets: alignSecrets(argv[k], red[k]),
			})
		}
	}
}

func (r *cmdRedactor) addPair(p *pair) {
	if len(r.pairs) >= maxPairs {
		r.fail = true
		return
	}
	r.pairs = append(r.pairs, p)
}

// applyPairs puts each nested redaction back into the top-level word that
// contains it, matching whole arguments only.
func (r *cmdRedactor) applyPairs() {
	done := map[string]bool{}
	for _, p := range r.pairs {
		key := p.oldVal + "\x00" + p.newVal
		if red, ok := r.topOld[p.oldVal]; ok && red == p.newVal {
			p.resolved = true // the same argument was redacted at top level
		}
		if done[key] {
			p.resolved = true // the same argument seen through another view
		}
		for i, t := range r.toks {
			if t.kind == tOp {
				continue
			}
			v := r.vals[i]
			n := 0
			if p.oldRaw != "" && p.oldRaw != p.oldVal {
				v, n = replaceOutside(v, p.oldRaw, p.newRaw, true)
			}
			var m int
			v, m = replaceOutside(v, p.oldVal, p.newVal, true)
			if n+m > 0 {
				r.setVal(i, v)
				p.resolved = true
			}
		}
		if p.resolved {
			done[key] = true
		}
		r.secrets = append(r.secrets, p.secrets...)
	}
}

// substituteSecrets replaces every recovered secret of searchable length
// wherever it still occurs inside a token, whatever surrounds it.
func (r *cmdRedactor) substituteSecrets() {
	r.secrets = dedupSecrets(r.secrets)
	if len(r.secrets) > 0 && len(r.secrets) > maxSecretScan/max(len(r.src), 1) {
		r.fail = true
		return
	}
	for _, s := range r.secrets {
		if len(s.value) < minSearch {
			continue
		}
		for i, t := range r.toks {
			if t.kind == tOp {
				continue
			}
			if v, n := replaceOutside(r.vals[i], s.value, s.marker, false); n > 0 {
				r.setVal(i, v)
			}
		}
	}
}

func dedupSecrets(in []secret) []secret {
	seen := make(map[string]bool, len(in))
	out := in[:0]
	for _, s := range in {
		if s.value == "" || seen[s.value] {
			continue
		}
		seen[s.value] = true
		out = append(out, s)
	}
	// Longer secrets first, so a secret that contains a shorter one is
	// replaced whole.
	sort.SliceStable(out, func(i, j int) bool { return len(out[i].value) > len(out[j].value) })
	return out
}

// render rebuilds the command: untouched tokens and everything between
// tokens are copied verbatim; edited words are re-quoted.
func (r *cmdRedactor) render() string {
	var b strings.Builder
	b.Grow(len(r.src))
	last := 0
	for i, t := range r.toks {
		if t.start < last || t.end > len(r.src) || t.start > t.end {
			continue
		}
		b.WriteString(r.src[last:t.start])
		if r.dirty[i] {
			if t.kind == tWord {
				b.WriteString(r.renderWord(i))
			} else {
				b.WriteString(r.vals[i])
			}
		} else {
			b.WriteString(r.src[t.start:t.end])
		}
		last = t.end
	}
	if last < len(r.src) {
		b.WriteString(r.src[last:])
	}
	return b.String()
}

// renderWord writes an edited word. Where every replaced secret occurs
// verbatim in the word as written, the raw text is patched in place, so
// quoting, $( ) and escapes stay as the user wrote them; the patch is
// accepted only if lexing it yields exactly the redacted value. Otherwise
// the value is re-quoted.
func (r *cmdRedactor) renderWord(i int) string {
	t := r.toks[i]
	raw := r.src[t.start:t.end]
	want := r.vals[i]
	patched := raw
	for _, s := range alignSecrets(t.val, want) {
		patched, _ = replaceOutside(patched, s.value, s.marker, false)
	}
	if patched != raw {
		if toks := lex(patched, r.d); len(toks) == 1 && toks[0].kind == tWord && toks[0].val == want {
			return patched
		}
	}
	return requote(want, r.d, t.quote)
}

// stringLevel searches the rendered text for every recovered secret in
// plain, reversed and encoded form.
func (r *cmdRedactor) stringLevel(s string) string {
	for _, sec := range r.secrets {
		if len(sec.value) >= minSearch {
			s, _ = replaceOutside(s, sec.value, sec.marker, false)
		}
		if len(sec.value) >= 6 {
			if rev := reverse(sec.value); rev != sec.value {
				s, _ = replaceOutside(s, rev, sec.marker, false)
			}
		}
	}
	var needles []string
	for _, sec := range r.secrets {
		if len(sec.value) >= minSearch {
			needles = append(needles, sec.value)
		}
	}
	for _, p := range r.pairs {
		if len(p.oldVal) >= minSearch {
			needles = append(needles, p.oldVal)
		}
	}
	if len(needles) == 0 {
		return s
	}
	out, hits := redactEncoded(s, needles)
	for _, h := range hits {
		for _, p := range r.pairs {
			if p.oldVal == h || containsSecret(p.secrets, h) {
				p.resolved = true
			}
		}
	}
	return out
}

func containsSecret(ss []secret, v string) bool {
	for _, s := range ss {
		if s.value == v {
			return true
		}
	}
	return false
}

// unresolved reports a structurally found secret whose position in the
// text could not be established, so its absence cannot be proven.
func (r *cmdRedactor) unresolved() bool {
	if r.fail {
		return true
	}
	for _, p := range r.pairs {
		if p.resolved || p.optional {
			continue
		}
		if p.strict {
			return true
		}
		for _, s := range p.secrets {
			if len(s.value) < minSearch {
				return true
			}
		}
		if len(p.secrets) == 0 {
			return true
		}
	}
	return false
}

// skeleton is the fail-closed rendering: for each top-level command the
// program word and its flag names, nothing positional. It may run before
// the nested redactions were applied (a budget was exceeded), so a word a
// nested view redacted is replaced by its redacted form here, and the
// result is checked against every secret recovered by any view.
func (r *cmdRedactor) skeleton() string {
	nestedRed := make(map[string]string, len(r.pairs))
	for _, p := range r.pairs {
		nestedRed[p.oldVal] = p.newVal
	}
	word := func(v string) string {
		if red, ok := nestedRed[v]; ok {
			return red
		}
		return v
	}
	var b strings.Builder
	full := false
	put := func(sep, w string, tok int) {
		if full {
			return
		}
		if b.Len()+len(sep)+len(w) > maxSkeleton {
			b.WriteString(" ")
			b.WriteString(truncMarker(len(r.src) - r.toks[tok].start))
			full = true
			return
		}
		b.WriteString(sep)
		b.WriteString(w)
	}
	for _, s := range r.segs {
		if len(s.words) == 0 || full {
			continue
		}
		prog := word(r.vals[s.words[0]])
		if strings.ContainsAny(prog, " \t\r\n'\"`") {
			// A quoted or multi-word "program" is text, not a name.
			prog = markerOpen + kindCommand + "]"
		}
		sep := ""
		if b.Len() > 0 {
			sep = " ; "
		}
		put(sep, prog, s.words[0])
		for _, w := range s.words[1:] {
			v := word(r.vals[w])
			if len(v) < 2 || (v[0] != '-' && !(v[0] == '/' && r.d != shellx.Posix)) {
				continue
			}
			if i := strings.IndexAny(v, "=:"); i > 1 {
				v = v[:i]
			}
			put(" ", v, w)
		}
	}
	out := b.String() + " " + markerOpen + kindUnresolved + "]"
	leaked := func(v string) bool { return len(v) >= minSearch && strings.Contains(out, v) }
	for _, sec := range r.secrets {
		if leaked(sec.value) {
			return markerOpen + kindCommand + "]"
		}
	}
	for _, p := range r.pairs {
		for _, sec := range p.secrets {
			if leaked(sec.value) {
				return markerOpen + kindCommand + "]"
			}
		}
	}
	return out
}

// naiveSegments splits s into argument vectors without honouring quotes.
// There is no segment cap: a capped view would stop seeing the line part of
// the way through, and s is at most maxCommandScan bytes.
func naiveSegments(s string) [][]string {
	var out [][]string
	for _, seg := range strings.FieldsFunc(s, func(r rune) bool {
		return r == '\n' || r == ';' || r == '|' || r == '&' || r == '(' || r == ')'
	}) {
		var argv []string
		for _, w := range strings.Fields(seg) {
			if w = strings.Trim(w, "\"'`\\"); w != "" {
				argv = append(argv, w)
			}
		}
		if len(argv) > 0 {
			out = append(out, argv)
		}
	}
	return out
}

func reverse(s string) string {
	b := []byte(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}

// requote renders a word value so it reads as one word of dialect d,
// keeping the original quoting style where there was one.
func requote(v string, d shellx.Dialect, style byte) string {
	if v == "" {
		switch d {
		case shellx.Cmd:
			return `""`
		default:
			return "''"
		}
	}
	if style == 0 && safeBare(v, d) {
		return v
	}
	switch d {
	case shellx.PowerShell:
		if style == '"' {
			r := strings.NewReplacer("`", "``", `"`, "`\"", "$", "`$")
			return `"` + r.Replace(v) + `"`
		}
		return "'" + strings.ReplaceAll(v, "'", "''") + "'"
	case shellx.Cmd:
		if safeBare(v, d) {
			return v
		}
		return `"` + strings.ReplaceAll(v, `"`, `""`) + `"`
	default:
		if style == '"' {
			r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "$", `\$`, "`", "\\`")
			return `"` + r.Replace(v) + `"`
		}
		if safeBare(v, d) {
			return v
		}
		return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'"
	}
}

// safeBare reports a value that needs no quoting in dialect d. Markers
// ("[REDACTED:kind:...]") are bare-safe so they stay readable.
func safeBare(v string, d shellx.Dialect) bool {
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("_@%+=:,./-[]~^", c) >= 0:
		case c == '\\' && d != shellx.Posix:
		default:
			return false
		}
	}
	return true
}

// safeCut picks a cut point at or before limit that does not split a token
// (the last whitespace within 4 KiB), else a rune boundary.
func safeCut(s string, limit int) int {
	if limit >= len(s) {
		return len(s)
	}
	if limit < 0 {
		return 0
	}
	floor := limit - 4096
	if floor < 0 {
		floor = 0
	}
	for i := limit; i > floor; i-- {
		switch s[i-1] {
		case ' ', '\n', '\t', '\r':
			return i
		}
	}
	for limit > 0 && !runeStart(s[limit]) {
		limit--
	}
	return limit
}

func runeStart(b byte) bool { return b&0xC0 != 0x80 }

// keepRef reports values that are references to a secret held elsewhere
// rather than the secret: $VAR, ${VAR}, $(cmd), %VAR%, @file and existing
// markers. Those carry no credential and are useful to an analyst.
func keepRef(v string) bool {
	if v == "" || strings.Contains(v, markerOpen) {
		return true
	}
	switch v[0] {
	case '$':
		if len(v) > 1 && (v[1] == '{' || v[1] == '(' || isIdentStart(v[1])) {
			return !strings.ContainsAny(v[1:], " \t")
		}
	case '%':
		return len(v) > 2 && v[len(v)-1] == '%' && !strings.ContainsAny(v, " \t")
	case '@':
		return len(v) > 1 && (v[1] == '/' || v[1] == '.' || v[1] == '~')
	}
	return false
}

func isIdentStart(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}
