package privacy

import (
	"strings"

	"github.com/thomastysong/spoor/internal/classify"
	"github.com/thomastysong/spoor/internal/shellx"
)

// Multi-word redaction rules: secrets whose position is defined by more
// than one argument vector (a pipeline feeding a --password-stdin consumer)
// or by syntax RedactArgs does not see (PowerShell "$x = 'v'").

// stdinNames are flag names (without leading dashes) that make a program
// read a credential from standard input.
var stdinNames = map[string]bool{
	"password-stdin": true, "pass-stdin": true, "passphrase-stdin": true,
	"token-stdin": true, "secret-stdin": true, "password-from-stdin": true,
	"api-key-stdin": true, "apikey-stdin": true, "key-stdin": true,
	"with-token":          true, // gh auth login --with-token
	"client-secret-stdin": true, "registry-password-stdin": true,
}

func stdinFlag(a string) bool {
	if len(a) < 3 || a[0] != '-' {
		return false
	}
	name := strings.ToLower(strings.TrimLeft(a, "-"))
	if i := strings.IndexByte(name, '='); i >= 0 {
		name = name[:i]
	}
	if stdinNames[name] {
		return true
	}
	if !strings.Contains(name, "stdin") {
		return false
	}
	for _, w := range []string{"pass", "token", "secret", "key", "cred"} {
		if strings.Contains(name, w) {
			return true
		}
	}
	return false
}

// readsSecretFromStdin reports a command whose standard input is a
// credential.
func readsSecretFromStdin(argv []string) bool {
	if len(argv) == 0 {
		return false
	}
	low := make([]string, len(argv))
	for i, a := range argv {
		low[i] = strings.ToLower(a)
	}
	prog := progName(low[0])
	has := func(w string) bool {
		for _, a := range low[1:] {
			if a == w {
				return true
			}
		}
		return false
	}
	for i, a := range argv[1:] {
		if stdinFlag(a) {
			return true
		}
		// gpg --passphrase-fd 0
		if (low[i+1] == "--passphrase-fd" && i+2 < len(argv) && argv[i+2] == "0") || low[i+1] == "--passphrase-fd=0" {
			return true
		}
	}
	switch prog {
	case "chpasswd":
		return true
	case "passwd":
		return has("--stdin")
	case "docker", "podman":
		// docker secret create NAME - : the secret is read from stdin.
		return has("secret") && has("create") && low[len(low)-1] == "-"
	case "gh":
		return has("secret") && has("set") && !has("--body") && !has("-b")
	case "wrangler":
		return has("secret") && has("put")
	case "vercel":
		return has("env") && has("add")
	case "npx", "pnpm", "bunx":
		return has("wrangler") && has("secret") && has("put")
	}
	return false
}

// progName is the lower-cased base name of a program word, ".exe" removed.
func progName(w string) string {
	if i := strings.LastIndexAny(w, `/\`); i >= 0 {
		w = w[i+1:]
	}
	return strings.TrimSuffix(strings.ToLower(w), ".exe")
}

// feederProgs print their arguments; filterProgs pass stdin through.
var (
	feederProgs = map[string]bool{"echo": true, "printf": true, "print": true, "write-output": true, "write-host": true, "echo.exe": true}
	filterProgs = map[string]bool{"tr": true, "sed": true, "head": true, "tail": true, "cut": true, "base64": true, "xxd": true, "cat": true, "awk": true, "tee": true}
	echoFlags   = map[string]bool{"-n": true, "-e": true, "-E": true, "-ne": true, "-en": true, "-nonewline": true}
)

func (r *cmdRedactor) specials() {
	for si, s := range r.segs {
		argv := r.argv(s)
		if readsSecretFromStdin(argv) {
			r.redactFeeders(si)
		}
		r.psAssignments(s, argv)
		r.positionalSecrets(s, argv)
	}
}

// redactFeeders removes the literal a stdin-reading credential consumer is
// given: its here-strings and heredocs, and the arguments of echo/printf
// stages feeding it through a pipe (walking back over plain filters).
func (r *cmdRedactor) redactFeeders(si int) {
	s := r.segs[si]
	for _, i := range s.herestr {
		r.redactWhole(i, classify.KindPassword)
	}
	for _, i := range s.heredocs {
		r.redactWhole(i, classify.KindPassword)
	}
	for hop, cur := 0, s.pipeFrom; cur >= 0 && cur < len(r.segs) && hop < 4; hop++ {
		f := r.segs[cur]
		for _, i := range f.herestr {
			r.redactWhole(i, classify.KindPassword)
		}
		for _, i := range f.heredocs {
			r.redactWhole(i, classify.KindPassword)
		}
		if len(f.words) == 0 {
			break
		}
		prog := progName(r.vals[f.words[0]])
		switch {
		case feederProgs[prog]:
			args := f.words[1:]
			if prog == "printf" && len(args) > 1 && strings.Contains(r.vals[args[0]], "%") {
				args = args[1:] // the format string is not the secret
			}
			for _, i := range args {
				if echoFlags[strings.ToLower(r.vals[i])] {
					continue
				}
				r.redactWhole(i, classify.KindPassword)
			}
			return
		case filterProgs[prog]:
			cur = f.pipeFrom
			continue
		}
		return
	}
}

// psAssignments handles PowerShell variable assignments to secret-like
// names: "$password = 'x'", "$env:API_KEY='x'", "$token=x". RedactArgs
// handles NAME=value but not the "$" and "$env:" forms.
func (r *cmdRedactor) psAssignments(s segment, argv []string) {
	if r.d != shellx.PowerShell {
		return
	}
	for k, a := range argv {
		name, rest, ok := psVar(a)
		if !ok {
			continue
		}
		switch {
		case rest == "" && k+2 < len(argv) && argv[k+1] == "=":
			if r.secretName(name) {
				r.redactAssigned(s.words[k+2], argv, k+2)
			}
		case strings.HasPrefix(rest, "="):
			if v := rest[1:]; v != "" && r.secretName(name) && !keepRef(v) && !strings.Contains(v, markerOpen) {
				i := s.words[k]
				prefix := r.vals[i][:len(r.vals[i])-len(v)]
				r.secrets = append(r.secrets, secret{value: v, marker: newMarker(classify.KindGenericSecret, v)})
				r.setVal(i, prefix+newMarker(classify.KindGenericSecret, v))
			}
		}
	}
}

// redactAssigned redacts the value of an assignment, unless the value is a
// command whose own arguments are handled elsewhere (ConvertTo-SecureString
// "x" -AsPlainText is handled by positionalSecrets).
func (r *cmdRedactor) redactAssigned(i int, argv []string, k int) {
	v := argv[k]
	if keepRef(v) || strings.Contains(v, markerOpen) {
		return
	}
	if r.toks[i].quote == 0 && strings.Contains(v, "-") && !strings.ContainsAny(v, " \t") && k+1 < len(argv) {
		// "Get-Secret -Name x": a cmdlet call, not a literal.
		if strings.IndexByte(v, '-') > 0 && isIdentStart(v[0]) {
			return
		}
	}
	r.redactWhole(i, classify.KindGenericSecret)
}

// psVar splits "$name", "$env:NAME" and "$name=value" words.
func psVar(a string) (name, rest string, ok bool) {
	if len(a) < 2 || a[0] != '$' {
		return "", "", false
	}
	b := a[1:]
	if len(b) > 4 && strings.EqualFold(b[:4], "env:") {
		b = b[4:]
	}
	j := 0
	for j < len(b) && (isIdentStart(b[j]) || (j > 0 && b[j] >= '0' && b[j] <= '9')) {
		j++
	}
	if j == 0 {
		return "", "", false
	}
	return b[:j], b[j:], true
}

// secretName reports whether RedactArgs treats NAME as secret-bearing, by
// asking it about a NAME=value assignment. This keeps one definition of
// "secret-like name" across the code base.
func (r *cmdRedactor) secretName(name string) bool {
	if r.nameMemo == nil {
		r.nameMemo = map[string]bool{}
	}
	if v, ok := r.nameMemo[name]; ok {
		return v
	}
	probe := name + "=Zq7xWv"
	out := classify.RedactArgs([]string{probe})
	v := len(out) == 1 && out[0] != probe
	if len(r.nameMemo) < 256 {
		r.nameMemo[name] = v
	}
	return v
}

// positionalSecrets covers programs that take a password as a plain
// positional argument.
func (r *cmdRedactor) positionalSecrets(s segment, argv []string) {
	low := make([]string, len(argv))
	for i, a := range argv {
		low[i] = strings.ToLower(a)
	}
	// ConvertTo-SecureString "plain" -AsPlainText (anywhere in the segment,
	// it is usually the right-hand side of an assignment).
	for k, a := range low {
		if a != "convertto-securestring" {
			continue
		}
		plain := false
		for _, b := range low[k+1:] {
			if strings.HasPrefix(b, "-asplain") {
				plain = true
			}
		}
		if !plain {
			continue
		}
		for j := k + 1; j < len(argv); j++ {
			if low[j] == "-string" && j+1 < len(argv) {
				r.redactWhole(s.words[j+1], classify.KindPassword)
				break
			}
			if !strings.HasPrefix(argv[j], "-") {
				r.redactWhole(s.words[j], classify.KindPassword)
				break
			}
		}
	}
	if len(argv) < 2 {
		return
	}
	switch progName(low[0]) {
	case "net", "net1":
		// net user NAME PASSWORD [/add]; net use \\host\share PASSWORD /user:x
		if len(argv) >= 4 && (low[1] == "user" || low[1] == "use") {
			pos := 0
			for j := 2; j < len(argv); j++ {
				if strings.HasPrefix(argv[j], "/") {
					continue
				}
				pos++
				if pos == 2 && argv[j] != "*" {
					r.redactWhole(s.words[j], classify.KindPassword)
				}
			}
		}
	case "setx":
		// setx [/m] NAME VALUE
		var pos []int
		for j := 1; j < len(argv); j++ {
			if strings.HasPrefix(argv[j], "/") {
				continue
			}
			pos = append(pos, j)
		}
		if len(pos) >= 2 && r.secretName(argv[pos[0]]) {
			r.redactWhole(s.words[pos[1]], classify.KindGenericSecret)
		}
	case "htpasswd":
		// htpasswd -b[c] FILE USER PASSWORD
		batch := false
		var pos []int
		for j := 1; j < len(argv); j++ {
			if strings.HasPrefix(argv[j], "-") {
				if strings.ContainsRune(argv[j], 'b') {
					batch = true
				}
				continue
			}
			pos = append(pos, j)
		}
		if batch && len(pos) >= 3 {
			r.redactWhole(s.words[pos[len(pos)-1]], classify.KindPassword)
		}
	}
}
