package privacy

import (
	"strings"
	"unicode/utf8"

	"github.com/thomastysong/thomastysong/hawkbell/internal/shellx"
)

// String pipeline. Every emitted string goes: clean UTF-8 -> redact (by
// the field's mode) -> rewrite secret fingerprints -> home-relative paths
// -> cap. Redaction always happens before the cap so a secret can never
// straddle the cut and leave its head behind.

func cleanUTF8(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	return strings.ToValidUTF8(s, "�")
}

// capBytes cuts s to at most n bytes on a rune boundary, without a marker.
func capBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// cleanLabel is for short operator-supplied identifiers (key id).
func cleanLabel(s string, n int) string {
	return capBytes(cleanUTF8(strings.TrimSpace(s)), n)
}

// cutString shortens s to at most max bytes including a "[TRUNCATED:nB]"
// marker. headOnly keeps the beginning; otherwise the beginning and the
// end are kept (a command's tail, "| sh", matters as much as its head).
// Markers already in s are never split.
func cutString(s string, max int, headOnly bool) (string, bool) {
	if max <= 0 || len(s) <= max {
		return s, false
	}
	// The marker length depends on the number of cut bytes; reserve for the
	// widest possible.
	room := max - len(truncMarker(len(s)))
	if room < 0 {
		return capBytes(truncMarker(len(s)), max), true
	}
	if headOnly {
		h := markerSafe(s, runeFloor(s, room), true)
		return s[:h] + truncMarker(len(s)-h), true
	}
	headN := (room + 1) / 2
	tailN := room - headN
	h := markerSafe(s, runeFloor(s, headN), true)
	t := markerSafe(s, runeCeil(s, len(s)-tailN), false)
	if t < h {
		t = h
	}
	return s[:h] + truncMarker(t-h) + s[t:], true
}

func runeFloor(s string, i int) int {
	if i >= len(s) {
		return len(s)
	}
	if i < 0 {
		return 0
	}
	for i > 0 && !utf8.RuneStart(s[i]) {
		i--
	}
	return i
}

func runeCeil(s string, i int) int {
	if i <= 0 {
		return 0
	}
	for i < len(s) && !utf8.RuneStart(s[i]) {
		i++
	}
	return i
}

// markerSafe moves a cut point out of any marker: down for a head cut, up
// for a tail cut.
func markerSafe(s string, i int, down bool) int {
	for _, sp := range protectedSpans(s) {
		if i > sp[0] && i < sp[1] {
			if down {
				return sp[0]
			}
			return sp[1]
		}
	}
	return i
}

// finish applies the common tail of the pipeline to a redacted value.
func (r *run) finishStr(s, name string, max int, headOnly bool) string {
	s = rewriteMarkers(s, r.s.key)
	if r.s.key != nil && !r.keyed && strings.Contains(s, ":hmac=") {
		r.keyed = true // the record carries keyed fingerprints: name the key
	}
	s = r.home.rewrite(s)
	if max > 0 {
		var cut bool
		if s, cut = cutString(s, max, headOnly); cut {
			r.note(name)
		}
	}
	return s
}

func (r *run) clean(s string) string {
	if !utf8.ValidString(s) {
		r.lossy = true
		return strings.ToValidUTF8(s, "�")
	}
	return s
}

// textStr redacts free text (prompts, output, error messages) by pattern.
// Free-text password detection is heuristic: "password=x" is redacted,
// "the password is x" is not; structure is used wherever it exists.
func (r *run) textStr(s, name string, max int, headOnly bool) string {
	if s == "" {
		return s
	}
	s = r.clean(s)
	pre := false
	if len(s) > maxTextScan {
		s = s[:safeCut(s, maxTextScan)]
		pre = true
	}
	red := redactText(s)
	if pre {
		r.note(name)
		headOnly = true
	}
	return r.finishStr(red, name, max, headOnly)
}

// maxTextScan bounds the text redacted for one field; only a head of at
// most MaxField is emitted, so scanning far beyond it buys nothing.
const maxTextScan = 64 << 10

// valueStr redacts a short structured value (label, config value, check
// result): NAME=value, flags, URLs and headers structurally, then by
// pattern.
func (r *run) valueStr(s, name string, max int) string {
	if s == "" {
		return s
	}
	s = r.clean(s)
	if len(s) > maxTextScan {
		return r.textStr(s, name, max, true)
	}
	red := redactArgs([]string{s})
	v := s
	if len(red) == 1 {
		v = red[0]
	}
	v = redactText(v)
	return r.finishStr(v, name, max, false)
}

// urlStr redacts a URL: userinfo always, query and fragment unless kept.
func (r *run) urlStr(s, name string, keepQuery bool, max int) string {
	if s == "" {
		return s
	}
	s = r.clean(s)
	pre := false
	if len(s) > maxTextScan {
		s = s[:safeCut(s, maxTextScan)]
		pre = true
		r.note(name)
	}
	return r.finishStr(redactURL(s, keepQuery), name, max, pre)
}

// commandStr redacts a command line structurally.
func (r *run) commandStr(s, name string, max int) string {
	if s == "" {
		return s
	}
	s = r.clean(s)
	if c, changed := controlsToSpace(s); changed {
		s, r.lossy = c, true
	}
	red, pre := redactCommand(s, r.dialectHint())
	if pre {
		r.note(name)
	}
	return r.finishStr(red, name, max, pre)
}

// dialectHint picks PowerShell for Windows hosts only when the tool says
// so; otherwise shellx auto-detects.
func (r *run) dialectHint() shellx.Dialect {
	if r.src != nil && r.src.Tool != nil {
		n := strings.ToLower(r.src.Tool.Name)
		switch {
		case strings.Contains(n, "powershell") || strings.Contains(n, "pwsh"):
			return shellx.PowerShell
		}
	}
	return ""
}

// argsStr redacts an argument vector: flag-aware RedactArgs, plus
// structural command redaction of the script handed to a shell
// ("bash -c '...'", "cmd /c ...", "pwsh -Command ...", -EncodedCommand).
func (r *run) argsStr(args []string, name string, maxEach, maxN int) []string {
	if len(args) == 0 {
		return args
	}
	if len(args) > maxN {
		args = args[:maxN]
		r.note(name)
	}
	cleaned := make([]string, len(args))
	for i, a := range args {
		cleaned[i] = r.clean(a)
		if c, changed := controlsToSpace(cleaned[i]); changed {
			cleaned[i], r.lossy = strings.TrimSpace(c), true
		}
		if len(cleaned[i]) > maxTextScan {
			cleaned[i] = cleaned[i][:safeCut(cleaned[i], maxTextScan)]
			r.note(name)
		}
	}
	red := redactArgv(cleaned)
	out := make([]string, len(red))
	for i, a := range red {
		out[i] = r.finishStr(a, name, maxEach, false)
	}
	return out
}

// redactArgv is RedactArgs plus nested scripts.
func redactArgv(args []string) []string {
	red := redactArgs(args)
	if len(red) != len(args) {
		out := make([]string, len(args))
		for i := range out {
			out[i] = failMarker
		}
		return out
	}
	prog := ""
	if len(args) > 0 {
		prog = progName(args[0])
	}
	var d shellx.Dialect
	switch prog {
	case "sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish", "busybox":
		d = shellx.Posix
	case "cmd":
		d = shellx.Cmd
	case "powershell", "pwsh":
		d = shellx.PowerShell
	default:
		return red
	}
	for i := 1; i+1 < len(args); i++ {
		f := strings.ToLower(args[i])
		script := false
		switch d {
		case shellx.Posix:
			script = len(f) >= 2 && f[0] == '-' && f[1] != '-' && strings.ContainsRune(f, 'c')
		case shellx.Cmd:
			script = f == "/c" || f == "/k" || f == "/r"
		case shellx.PowerShell:
			if f == "-encodedcommand" || f == "-enc" || f == "-e" || f == "-ec" {
				red[i+1] = redactEncodedCommand(args[i+1])
				i++
				continue
			}
			script = f == "-command" || f == "-c" || f == "/c" || f == "/command"
		}
		if !script {
			continue
		}
		if d == shellx.Posix || len(args) == i+2 {
			c, _ := redactCommand(args[i+1], d)
			red[i+1] = c
		} else {
			// cmd /c and -Command take the rest of the line: redact each
			// remaining word as part of one command.
			joined := strings.Join(args[i+1:], " ")
			c, _ := redactCommand(joined, d)
			if c != joined {
				for j := i + 1; j < len(args); j++ {
					if red[j] == args[j] && !strings.Contains(c, args[j]) {
						red[j] = newMarker(kindCommand, args[j])
					}
				}
			}
		}
		break
	}
	return red
}

// redactEncodedCommand decodes a PowerShell -EncodedCommand payload; if the
// decoded script carries a credential the payload is replaced, since
// anyone can decode it.
func redactEncodedCommand(b64 string) string {
	for _, d := range decodings(b64, 1) {
		script := string(d)
		if c, _ := redactCommand(script, shellx.PowerShell); c != script {
			return newMarker(kindEncoded, b64)
		}
	}
	return b64
}
