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
	case "chpasswd", "chgpasswd", "passwd", "kinit", "k5start", "smbpasswd", "cryptsetup", "mkpasswd":
		// Whatever is piped into these is a password: passwd and chpasswd
		// read new passwords (with or without --stdin, agents feed both
		// "pw\npw" pairs), kinit the Kerberos password, smbpasswd -s and
		// cryptsetup a passphrase, mkpasswd -s the password to hash.
		return true
	case "sudo":
		return sudoStdin(argv[1:]) // case matters: -s is a shell, -S is stdin
	case "htpasswd":
		// htpasswd -i reads the password from stdin (-i may sit in a
		// cluster such as -Bci).
		for _, a := range low[1:] {
			if len(a) > 1 && a[0] == '-' && a[1] != '-' && strings.ContainsRune(a[1:], 'i') {
				return true
			}
		}
	case "openssl":
		// -pass stdin / -passin fd:0 / openssl passwd -stdin.
		for i, a := range low[1:] {
			switch a {
			case "-pass", "-passin", "-passout", "-kfile":
				if i+2 < len(low) && (low[i+2] == "stdin" || low[i+2] == "fd:0" || low[i+2] == "file:/dev/stdin" || low[i+2] == "/dev/stdin") {
					return true
				}
			case "-stdin":
				return has("passwd")
			}
		}
	case "vault":
		// vault login - : the token is read from stdin.
		return has("login") && has("-")
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

// sudoStdin reports sudo -S / --stdin among sudo's own options (before
// the command it runs). Options that take a value consume the next word,
// so "sudo -u bob -S cmd" is found and "sudo cmd -S" is not.
func sudoStdin(args []string) bool {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" || len(a) < 2 || a[0] != '-' {
			return false
		}
		if strings.HasPrefix(a, "--") {
			name, _, eq := strings.Cut(a[2:], "=")
			switch name {
			case "stdin":
				return true
			case "user", "group", "close-from", "prompt", "role", "type", "other-user", "chdir", "chroot", "command-timeout", "host":
				if !eq {
					i++
				}
			}
			continue
		}
		for k := 1; k < len(a); k++ {
			switch c := a[k]; c {
			case 'S':
				return true
			case 'u', 'g', 'C', 'p', 'r', 't', 'U', 'D', 'R', 'T':
				// Takes a value: the rest of the cluster or the next word.
				if k == len(a)-1 {
					i++
				}
				k = len(a)
			}
		}
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
	feederProgs = map[string]bool{"echo": true, "printf": true, "print": true, "write-output": true, "write-host": true, "echo.exe": true, "yes": true}
	filterProgs = map[string]bool{"tr": true, "sed": true, "head": true, "tail": true, "cut": true, "base64": true, "xxd": true, "cat": true, "awk": true, "tee": true}
	echoFlags   = map[string]bool{"-n": true, "-e": true, "-E": true, "-ne": true, "-en": true, "-nonewline": true}
)

func (r *cmdRedactor) specials() {
	for si, s := range r.segs {
		argv := r.argv(s)
		if readsSecretFromStdin(argv) {
			r.redactFeeders(si, classify.KindPassword, false)
		}
		if r.writesCredentialFile(s, argv) {
			r.redactWritten(si, argv)
		}
		r.printfKeys(s, argv)
		r.psAssignments(s, argv)
		r.envItemSetters(s, argv)
		r.positionalSecrets(s, argv)
	}
	r.setEnvironmentVariable()
}

// redactFeeders removes the literal a stdin-reading consumer is given: its
// here-strings and heredocs, and the arguments of echo/printf stages
// feeding it through a pipe (walking back over plain filters). With
// content set the whole fed text is the secret (a credential file being
// written), so a printf format is removed too; otherwise the format is
// kept, as it is not the password.
func (r *cmdRedactor) redactFeeders(si int, kind string, content bool) {
	s := r.segs[si]
	for _, i := range s.herestr {
		r.redactWhole(i, kind)
	}
	for _, i := range s.heredocs {
		r.redactWhole(i, kind)
	}
	for hop, cur := 0, s.pipeFrom; cur >= 0 && cur < len(r.segs) && hop < 4; hop++ {
		f := r.segs[cur]
		for _, i := range f.herestr {
			r.redactWhole(i, kind)
		}
		for _, i := range f.heredocs {
			r.redactWhole(i, kind)
		}
		if len(f.words) == 0 {
			break
		}
		prog := progName(r.vals[f.words[0]])
		switch {
		case feederProgs[prog]:
			r.redactPrinted(f.words[1:], prog, kind, content)
			return
		case r.d == shellx.PowerShell && r.literalsOnly(f.words):
			// PowerShell: "'text' | Out-File x" pipes a bare literal.
			for _, i := range f.words {
				r.redactWhole(i, kind)
			}
			return
		case filterProgs[prog]:
			cur = f.pipeFrom
			continue
		}
		return
	}
}

// redactPrinted redacts the arguments an echo/printf stage prints.
func (r *cmdRedactor) redactPrinted(args []int, prog, kind string, content bool) {
	if prog == "printf" && len(args) > 1 && r.vals[args[0]] == "-v" {
		args = args[2:] // printf -v VAR: the variable name is not printed
	}
	if !content && prog == "printf" && len(args) > 1 && strings.Contains(r.vals[args[0]], "%") {
		args = args[1:] // the format string is not the secret
	}
	for _, i := range args {
		if echoFlags[strings.ToLower(r.vals[i])] {
			continue
		}
		r.redactWhole(i, kind)
	}
}

// literalsOnly reports a segment made of quoted literals only.
func (r *cmdRedactor) literalsOnly(words []int) bool {
	for _, i := range words {
		if r.toks[i].quote == 0 {
			return false
		}
	}
	return len(words) > 0
}

// secretFileClasses are the path classes whose files hold credentials: what
// a shell command writes into them is credential material as a whole,
// whatever its format (netrc lines, pgpass fields, dotenv, JSON configs,
// key files), so it cannot be left to pattern matching.
var secretFileClasses = map[string]bool{
	classify.PathSecretEnv: true, classify.PathSSHPrivateKey: true, classify.PathCloudCredentials: true,
	classify.PathKubeConfig: true, classify.PathDockerConfig: true, classify.PathGitCredentials: true,
	classify.PathNetrc: true, classify.PathNPMToken: true, classify.PathPyPIToken: true,
	classify.PathGPGKeyring: true, classify.PathPasswordStore: true, classify.PathKeychain: true,
	classify.PathCryptoWallet: true, classify.PathSystemAuth: true, classify.PathCertPrivateKey: true,
	classify.PathTokenFile: true,
}

func secretFile(path string) bool {
	if path == "" {
		return false
	}
	for _, c := range classify.PathClasses(path, classify.PathCtx{}) {
		if secretFileClasses[c] {
			return true
		}
	}
	return false
}

// psWriters are PowerShell cmdlets (and aliases) that write a -Value or
// their pipeline input to a -Path.
var psWriters = map[string]bool{"set-content": true, "add-content": true, "out-file": true, "sc": true, "ac": true, "new-item": true, "ni": true}

// writesCredentialFile reports a segment whose output goes to a
// credential-class file: a redirection target ("> ~/.netrc"), a tee
// argument (after sudo/doas wrappers), or a PowerShell Set-Content /
// Add-Content / Out-File / New-Item path.
func (r *cmdRedactor) writesCredentialFile(s segment, argv []string) bool {
	for _, i := range s.outs {
		if secretFile(r.vals[i]) {
			return true
		}
	}
	k := 0
	for k < len(argv) && wrapperWord(argv[k]) {
		k++
	}
	if k >= len(argv) {
		return false
	}
	prog := progName(argv[k])
	if prog != "tee" && !(r.d == shellx.PowerShell && psWriters[prog]) {
		return false
	}
	for _, a := range argv[k+1:] {
		if strings.HasPrefix(a, "-") && len(a) > 1 {
			continue
		}
		if secretFile(a) {
			return true
		}
	}
	return false
}

// wrapperWord is a word that runs the rest of the line as another program
// (privilege and environment wrappers, their options and assignments).
func wrapperWord(w string) bool {
	switch progName(w) {
	case "sudo", "doas", "env", "command", "nice", "nohup", "stdbuf", "time":
		return true
	}
	return strings.HasPrefix(w, "-") || strings.Contains(w, "=")
}

// redactWritten removes the text a segment writes into a credential file:
// its heredocs and here-strings, the arguments of an echo/printf that is
// the writer itself, everything piped into it, and a PowerShell -Value.
func (r *cmdRedactor) redactWritten(si int, argv []string) {
	s := r.segs[si]
	kind := classify.KindGenericSecret
	r.redactFeeders(si, kind, true)
	k := 0
	for k < len(argv) && wrapperWord(argv[k]) {
		k++
	}
	if k >= len(argv) {
		return
	}
	prog := progName(argv[k])
	switch {
	case feederProgs[prog]:
		r.redactPrinted(s.words[k+1:], prog, kind, true)
	case r.d == shellx.PowerShell && psWriters[prog]:
		// Set-Content [-Path] P [-Value] V: everything but the path and
		// the parameter names is content.
		path := false
		for j := k + 1; j < len(argv); j++ {
			low := strings.ToLower(argv[j])
			switch {
			case low == "-path" || low == "-literalpath" || low == "-filepath":
				j++
				path = true
			case strings.HasPrefix(low, "-") && len(low) > 1 && low != "-value":
				// Switches such as -Force, -Encoding utf8: names and enums.
				if low == "-encoding" || low == "-itemtype" || low == "-name" {
					j++
				}
			case low == "-value":
			case !path && secretFile(argv[j]):
				path = true
			default:
				r.redactWhole(s.words[j], kind)
			}
		}
	}
}

// printfKeys redacts printf arguments that a format places after a
// secret-named key ("password=%s", "token: %s", netrc's "password %s"):
// the format says what the argument is, wherever the output goes.
func (r *cmdRedactor) printfKeys(s segment, argv []string) {
	k := 0
	for k < len(argv) && wrapperWord(argv[k]) {
		k++
	}
	if k >= len(argv) || progName(argv[k]) != "printf" {
		return
	}
	j := k + 1
	if j+1 < len(argv) && argv[j] == "-v" {
		j += 2
	}
	if j < len(argv) && argv[j] == "--" {
		j++
	}
	if j >= len(argv) {
		return
	}
	secretAt := formatSecrets(argv[j], r.isSecretKey)
	if len(secretAt) == 0 {
		return
	}
	args := s.words[j+1:]
	n := len(secretAt)
	for a := range args {
		// printf reuses the format while arguments remain.
		if secretAt[a%n] {
			r.redactWhole(args[a], classify.KindPassword)
		}
	}
}

// isSecretKey reports a key name a format or config line uses for a
// credential.
func (r *cmdRedactor) isSecretKey(name string) bool {
	switch strings.ToLower(name) {
	case "password", "passwd", "pass", "pwd", "passphrase", "secret", "token":
		return true
	}
	return r.secretName(name)
}

// formatSecrets parses a printf format and returns, per argument it
// consumes, whether the key written just before the conversion is
// secret-named. nil when no conversion follows such a key.
func formatSecrets(format string, secretKey func(string) bool) []bool {
	var out []bool
	found := false
	lineStart := 0
	for i := 0; i < len(format) && len(out) < 256; i++ {
		c := format[i]
		if c == '\\' && i+1 < len(format) {
			if format[i+1] == 'n' {
				lineStart = i + 2
			}
			i++
			continue
		}
		if c == '\n' {
			lineStart = i + 1
			continue
		}
		if c != '%' {
			continue
		}
		if i+1 < len(format) && format[i+1] == '%' {
			i++
			continue
		}
		key := keyBefore(format[lineStart:i])
		j := i + 1
		for j < len(format) && strings.IndexByte("-+ #0'", format[j]) >= 0 {
			j++
		}
		for j < len(format) && (format[j] >= '0' && format[j] <= '9' || format[j] == '*' || format[j] == '.') {
			if format[j] == '*' {
				out = append(out, false) // width or precision argument
			}
			j++
		}
		if j >= len(format) {
			break
		}
		sec := key != "" && secretKey(key)
		found = found || sec
		out = append(out, sec)
		i = j
	}
	if !found {
		return nil
	}
	return out
}

// keyBefore returns the key name that ends text: "password=" ->
// "password", "token: " -> "token", "login u password " -> "password".
func keyBefore(text string) string {
	t := strings.TrimRight(text, " \t\"'")
	t = strings.TrimRight(t, "=:")
	t = strings.TrimRight(t, " \t\"'")
	end := len(t)
	start := end
	for start > 0 {
		c := t[start-1]
		if !(isIdentStart(c) || c >= '0' && c <= '9' || c == '-' || c == '.') {
			break
		}
		start--
	}
	return t[start:end]
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

// envItemSetters handles PowerShell's provider form of an environment
// assignment: "Set-Item env:API_KEY 'v'", "Set-Item -Path Env:\API_KEY
// -Value v", "New-Item -Path env: -Name API_KEY -Value v". It runs in every
// dialect: the dialect guess can miss a one-line cmdlet call, and nothing
// else spells a command this way.
func (r *cmdRedactor) envItemSetters(s segment, argv []string) {
	if len(argv) < 3 {
		return
	}
	switch progName(argv[0]) {
	case "set-item", "si", "new-item", "ni", "set-content", "sc":
	default:
		return
	}
	path, name, value := "", "", -1
	var pos []int
	for j := 1; j < len(argv); j++ {
		switch strings.ToLower(argv[j]) {
		case "-path", "-literalpath":
			if j+1 < len(argv) {
				path = argv[j+1]
				j++
			}
		case "-name":
			if j+1 < len(argv) {
				name = argv[j+1]
				j++
			}
		case "-value":
			if j+1 < len(argv) {
				value = j + 1
				j++
			}
		default:
			if !strings.HasPrefix(argv[j], "-") {
				pos = append(pos, j)
			}
		}
	}
	if path == "" && len(pos) > 0 {
		path, pos = argv[pos[0]], pos[1:]
	}
	if value < 0 && len(pos) > 0 {
		value = pos[0]
	}
	low := strings.ToLower(path)
	if !strings.HasPrefix(low, "env:") || value < 0 {
		return
	}
	if v := strings.TrimLeft(path[4:], `\/`); v != "" {
		name = v
	}
	if name != "" && r.secretName(name) {
		r.redactWhole(s.words[value], classify.KindGenericSecret)
	}
}

// setEnvironmentVariable handles
// [Environment]::SetEnvironmentVariable('NAME', 'value', 'User'): the
// argument list follows a "(" operator, so it is not part of any segment's
// argument vector. Arguments may be one word ("'A','v','User'") or one
// word each ("'A', 'v',"); the value is the second comma-separated field.
func (r *cmdRedactor) setEnvironmentVariable() {
	for i := 0; i+2 < len(r.toks); i++ {
		t := r.toks[i]
		if t.kind != tWord || !strings.HasSuffix(strings.ToLower(t.val), "::setenvironmentvariable") {
			continue
		}
		if op := r.toks[i+1]; op.kind != tOp || op.val != "(" {
			continue
		}
		type field struct {
			tok int
			val string
		}
		var fields []field
		for j := i + 2; j < len(r.toks) && len(fields) < 3; j++ {
			w := r.toks[j]
			if w.kind != tWord {
				break
			}
			for _, f := range strings.Split(r.vals[j], ",") {
				if f = strings.TrimSpace(f); f != "" {
					fields = append(fields, field{tok: j, val: f})
				}
			}
		}
		if len(fields) < 2 || keepRef(fields[1].val) || !r.secretName(fields[0].val) {
			continue
		}
		v := fields[1]
		r.edit(v.tok, strings.Replace(r.vals[v.tok], v.val, newMarker(classify.KindGenericSecret, v.val), 1))
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
