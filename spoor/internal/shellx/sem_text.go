package shellx

import "strings"

// Text-producing and text-transforming commands. Their handlers do two jobs:
// record file reads/writes, and evaluate the output statically when every
// input is known, so that "echo <b64> | base64 -d | sh" is seen through.

func registerText() {
	register(hEcho, "echo")
	register(hPrintf, "printf")
	register(hCat, "cat", "tac", "bat", "batcat", "nl", "more", "less", "most", "zcat", "gzcat", "bzcat", "xzcat", "zstdcat")
	register(hBase64, "base64", "gbase64", "base32", "basenc", "b64decode")
	register(hXxd, "xxd")
	register(hRev, "rev")
	register(hTr, "tr")
	register(hGunzip, "gunzip", "gzip", "pigz", "bunzip2", "bzip2", "unxz", "xz", "zstd", "unzstd", "lz4", "uncompress")
	register(hTee, "tee")
	register(hReaders, "head", "tail", "strings", "od", "hexdump", "hd", "sort", "uniq", "wc", "cut", "paste",
		"fold", "fmt", "column", "jq", "yq", "tomlq", "md5sum", "sha1sum", "sha256sum", "sha512sum", "shasum", "cksum",
		"file", "diff", "cmp", "comm", "view", "pbcopy", "xclip", "xsel", "wl-copy", "clip", "iconv", "dos2unix",
		"expand", "csplit", "split", "zip", "7z", "7za", "plutil", "readelf", "objdump", "nm", "sqlite3_analyzer")
	register(hGrep, "grep", "egrep", "fgrep", "rg", "ag", "ack", "zgrep", "ggrep", "ripgrep", "git-grep")
	register(hSed, "sed", "gsed")
	register(hNoOutput, ":", "true")
}

func hNoOutput(a *analyzer, c *simple, in flow, out *flow) {
	empty := ""
	out.static, out.t = &empty, 0
}

// secretVarRefs reports "$NAME" / "%NAME%" / "$env:NAME" references to
// variables whose names denote credentials.
func secretVarRef(s string) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '$':
			j := i + 1
			if j < len(s) && s[j] == '{' {
				j++
			}
			if hasPrefixFold(s[j:], "env:") {
				j += 4
			}
			k := j
			for k < len(s) && isIdentByte(s[k]) {
				k++
			}
			if k > j && secretName(s[j:k]) {
				return true
			}
			i = k - 1
			if i < 0 {
				i = 0
			}
		case '%':
			k := i + 1
			for k < len(s) && isIdentByte(s[k]) {
				k++
			}
			if k > i+1 && k < len(s) && s[k] == '%' && secretName(s[i+1:k]) {
				return true
			}
		}
	}
	return false
}

func hEcho(a *analyzer, c *simple, in flow, out *flow) {
	args := c.rest()
	newline, escapes := true, false
	if c.dialect == Posix {
		for len(args) > 0 {
			s := args[0].s
			if len(s) < 2 || s[0] != '-' || strings.Trim(s[1:], "neE") != "" {
				break
			}
			for _, ch := range s[1:] {
				switch ch {
				case 'n':
					newline = false
				case 'e':
					escapes = true
				case 'E':
					escapes = false
				}
			}
			args = args[1:]
		}
	}
	var t taint
	static := true
	for i := range args {
		t |= args[i].t
		if args[i].dyn {
			static = false
			if secretVarRef(args[i].s) {
				a.cred("token_print")
			}
		}
	}
	out.t = t
	out.static = nil
	if !static {
		return
	}
	s := joinArgs(args)
	if escapes {
		var coded bool
		s, coded = unescapeC(s)
		if coded {
			out.t |= tEsc
		}
	}
	if newline {
		s += "\n"
	}
	if len(s) <= maxStatic {
		out.static = &s
	}
}

func hPrintf(a *analyzer, c *simple, in flow, out *flow) {
	args := c.rest()
	out.static = nil
	out.t = anyTaint(args)
	assignTo := ""
	if len(args) >= 2 && args[0].s == "-v" {
		assignTo = args[1].s
		args = args[2:]
	}
	if len(args) > 0 && args[0].s == "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		return
	}
	for i := range args {
		if args[i].dyn {
			if secretVarRef(args[i].s) {
				a.cred("token_print")
			}
			return
		}
	}
	s, coded, ok := formatPrintf(args[0].s, strs(args[1:]))
	if !ok {
		return
	}
	if coded {
		out.t |= tEsc
	}
	if assignTo != "" {
		a.envAssign(assignTo)
		a.setVar(assignTo, value{s: s, static: true, t: out.t})
		empty := ""
		out.static = &empty
		return
	}
	out.static = &s
}

func hCat(a *analyzer, c *simple, in flow, out *flow) {
	pos := c.positionals()
	out.static = nil
	if len(pos) == 0 || (len(pos) == 1 && pos[0].s == "-") {
		// Pass-through of stdin.
		static, t, _ := c.input(a, in)
		out.static, out.t = static, t
		return
	}
	out.t = 0
	if len(pos) == 1 && pos[0].s == "/dev/null" {
		empty := ""
		out.static = &empty
		return
	}
	for _, p := range pos {
		if p.proc {
			out.t |= p.t
			continue
		}
		a.read(p.s)
		if t, ok := a.droppedTaint(p.s); ok {
			out.t |= t
		}
	}
}

// decodeMode reports whether a base64-family command is decoding.
func decodeMode(c *simple) bool {
	for _, r := range c.rest() {
		s := r.s
		if s == "--decode" || s == "-D" {
			return true
		}
		if len(s) >= 2 && s[0] == '-' && s[1] != '-' && strings.IndexByte(s[1:], 'd') >= 0 {
			return true
		}
	}
	return c.name == "b64decode"
}

func hBase64(a *analyzer, c *simple, in flow, out *flow) {
	o := parseOpts(c.rest(), &optSpec{short: "wbio", long: longSet{"--wrap", "--break", "--input", "--output"}})
	var files []arg
	files = append(files, o.pos...)
	if f, ok := o.get("-i", "--input"); ok && f.s != "-" {
		files = append(files, f)
	}
	static, t, _ := c.input(a, in)
	for _, f := range files {
		if f.s == "-" || f.proc {
			t |= f.t
			continue
		}
		a.read(f.s)
		static = nil
		t = 0
		if dt, ok := a.droppedTaint(f.s); ok {
			t |= dt
		}
	}
	if of, ok := o.get("-o", "--output"); ok {
		a.write(of.s)
	}
	out.static = nil
	if !decodeMode(c) {
		// Encoding: content changes, provenance does not.
		out.t = t
		return
	}
	out.t = t | tB64
	if of, ok := o.get("-o", "--output"); ok {
		a.drop(of.s, out.t)
	}
	if static == nil || c.name == "base32" {
		return
	}
	raw, ok := decodeBase64(*static)
	if !ok || len(raw) > maxStatic {
		return
	}
	s := string(raw)
	out.static = &s
}

func hXxd(a *analyzer, c *simple, in flow, out *flow) {
	static, t, _ := c.input(a, in)
	pos := c.positionals()
	// xxd [opts] [infile [outfile]]; numeric option values look positional.
	var files []arg
	for _, p := range pos {
		if !isDigits(p.s) {
			files = append(files, p)
		}
	}
	if len(files) > 0 && files[0].s != "-" {
		a.read(files[0].s)
		static, t = nil, 0
		if dt, ok := a.droppedTaint(files[0].s); ok {
			t |= dt
		}
	}
	if len(files) > 1 {
		a.write(files[1].s)
	}
	out.static = nil
	out.t = t
	if !c.hasShort('r', "-revert") {
		return
	}
	out.t |= tHex
	if len(files) > 1 {
		a.drop(files[1].s, out.t)
	}
	if static == nil || !c.hasShort('p', "-ps", "-plain") {
		return
	}
	raw, ok := decodeHex(*static)
	if !ok {
		return
	}
	s := string(raw)
	out.static = &s
}

func hRev(a *analyzer, c *simple, in flow, out *flow) {
	static, t, _ := c.input(a, in)
	for _, p := range c.positionals() {
		a.read(p.s)
		static = nil
	}
	out.t = t | tRev
	out.static = nil
	if static != nil {
		s := reverseLines(*static)
		out.static = &s
	}
}

// hTr evaluates "tr -d SET" and "tr SET1 SET2" on static input. Substitution
// ciphers (rot13) piped to a shell are a known way to hide a command.
func hTr(a *analyzer, c *simple, in flow, out *flow) {
	static, t, _ := c.input(a, in)
	out.t, out.static = t, nil
	if static == nil {
		return
	}
	args := c.rest()
	del := false
	var sets []string
	for _, r := range args {
		if r.dyn {
			return
		}
		if strings.HasPrefix(r.s, "-") && len(r.s) > 1 && len(sets) == 0 {
			if strings.Contains(r.s, "d") {
				del = true
			}
			if strings.ContainsAny(r.s, "cCs") {
				return
			}
			continue
		}
		sets = append(sets, r.s)
	}
	if len(sets) == 0 {
		return
	}
	s1, ok := trSet(sets[0])
	if !ok {
		return
	}
	var sb strings.Builder
	if del {
		for i := 0; i < len(*static); i++ {
			if strings.IndexByte(s1, (*static)[i]) < 0 {
				sb.WriteByte((*static)[i])
			}
		}
	} else {
		if len(sets) < 2 {
			return
		}
		s2, ok := trSet(sets[1])
		if !ok || s2 == "" {
			return
		}
		for i := 0; i < len(*static); i++ {
			ch := (*static)[i]
			if j := strings.IndexByte(s1, ch); j >= 0 {
				if j >= len(s2) {
					j = len(s2) - 1
				}
				ch = s2[j]
			}
			sb.WriteByte(ch)
		}
	}
	s := sb.String()
	out.static = &s
}

// trSet expands a tr set with ranges and the common escapes.
func trSet(spec string) (string, bool) {
	spec, _ = unescapeC(spec)
	switch spec {
	case "[:space:]":
		return " \t\n\r\v\f", true
	case "[:upper:]":
		spec = "A-Z"
	case "[:lower:]":
		spec = "a-z"
	case "[:digit:]":
		spec = "0-9"
	case "[:alpha:]":
		spec = "A-Za-z"
	case "[:alnum:]":
		spec = "A-Za-z0-9"
	}
	if strings.Contains(spec, "[:") {
		return "", false
	}
	var sb strings.Builder
	for i := 0; i < len(spec); i++ {
		if i+2 < len(spec) && spec[i+1] == '-' && spec[i+2] >= spec[i] {
			for ch := int(spec[i]); ch <= int(spec[i+2]); ch++ {
				sb.WriteByte(byte(ch))
			}
			i += 2
			continue
		}
		sb.WriteByte(spec[i])
		if sb.Len() > 512 {
			return "", false
		}
	}
	return sb.String(), true
}

func hGunzip(a *analyzer, c *simple, in flow, out *flow) {
	static, t, _ := c.input(a, in)
	out.t, out.static = t, nil
	pos := c.positionals()
	for _, p := range pos {
		a.read(p.s)
	}
	decompress := strings.HasPrefix(c.name, "un") || c.hasShort('d', "--decompress", "--uncompress")
	if len(pos) > 0 || static == nil || !decompress {
		return
	}
	if raw, ok := gunzip([]byte(*static)); ok {
		s := string(raw)
		out.static = &s
	}
}

func hTee(a *analyzer, c *simple, in flow, out *flow) {
	static, t, _ := c.input(a, in)
	out.static, out.t = static, t
	app := c.hasShort('a', "--append")
	text := ""
	if static != nil {
		text = *static
	}
	for _, p := range c.positionals() {
		if p.proc {
			continue
		}
		mode := mWrite
		if app {
			mode = mAppend
		}
		a.useText(p.s, mode, text)
		if t&(tDownload|tCoded) != 0 {
			a.drop(p.s, t)
		}
		if h, ok := devTCPHost(p.s); ok && !isLoopback(cleanHost(h)) {
			a.exfil("netcat_out")
		}
	}
}

// hReaders records file arguments of commands that read their operands.
func hReaders(a *analyzer, c *simple, in flow, out *flow) {
	pos := c.positionals()
	skipFirst := false
	switch c.name {
	case "jq", "yq", "tomlq":
		// First positional is the filter unless -f gives a file.
		skipFirst = !c.has("-f", "--from-file")
	case "zip", "7z", "7za":
		// zip ARCHIVE files...: the archive is written, the rest read.
		for len(pos) > 0 && c.name != "zip" && len(pos[0].s) == 1 {
			pos = pos[1:] // 7z a|x|l
		}
		if len(pos) > 0 {
			a.write(pos[0].s)
			pos = pos[1:]
		}
	case "split", "csplit":
		if len(pos) > 1 {
			pos = pos[:1]
		}
	}
	for i, p := range pos {
		if skipFirst && i == 0 {
			continue
		}
		if p.proc || p.s == "-" {
			continue
		}
		if c.name == "head" || c.name == "tail" {
			if isDigits(strings.TrimLeft(p.s, "+")) {
				continue // "tail -n +5" style values parsed as positionals
			}
		}
		a.read(p.s)
	}
}

var grepSpec = &optSpec{
	short: "efmABCdDgtTjMr",
	long: longSet{"--regexp", "--file", "--max-count", "--after-context", "--before-context", "--context",
		"--include", "--exclude", "--exclude-dir", "--glob", "--type", "--type-not", "--threads", "--max-depth",
		"--color", "--colour", "--binary-files", "--devices", "--directories", "--label", "--replace", "--pre", "--pre-glob"},
}

func hGrep(a *analyzer, c *simple, in flow, out *flow) {
	sp := grepSpec
	if c.name != "rg" && c.name != "ripgrep" {
		// For grep, -r is a boolean; only rg gives it a value (--replace).
		cp := *grepSpec
		cp.short = "efmABCdD"
		sp = &cp
	}
	o := parseOpts(c.rest(), sp)
	pats := o.all("-e", "--regexp")
	pos := o.pos
	if len(pats) == 0 && !o.has("-f", "--file") && len(pos) > 0 {
		pats = append(pats, pos[0])
		pos = pos[1:]
	}
	for _, f := range o.all("-f", "--file") {
		a.read(f.s)
	}
	recursive := c.name == "rg" || c.name == "ripgrep" || c.name == "ag" || c.name == "ack" || c.name == "git-grep" ||
		o.has("-r", "-R", "--recursive", "--dereference-recursive")
	for _, p := range pos {
		if p.proc || p.s == "-" {
			continue
		}
		a.read(p.s)
	}
	if v, ok := o.get("--pre"); ok {
		// rg --pre CMD runs CMD on every file searched.
		a.runInner(c, []arg{v}, noFlow(), false, true)
	}
	if recursive {
		for _, p := range pats {
			if secretPattern(p.s) {
				a.recon("find_secrets")
				break
			}
		}
	}
}

var sedSpec = &optSpec{short: "eflE", long: longSet{"--expression", "--file", "--line-length"}}

func hSed(a *analyzer, c *simple, in flow, out *flow) {
	args := c.rest()
	inPlace := false
	// -i takes an optional attached suffix (GNU) or a separate one (BSD: -i '').
	clean := make([]arg, 0, len(args))
	for i := 0; i < len(args); i++ {
		s := args[i].s
		if s == "-i" || strings.HasPrefix(s, "-i") && !strings.HasPrefix(s, "--") && len(s) > 2 && s[2] != 'n' ||
			s == "--in-place" || strings.HasPrefix(s, "--in-place=") {
			inPlace = true
			if s == "-i" && i+1 < len(args) && args[i+1].s == "" {
				i++ // BSD sed -i ''
			}
			continue
		}
		if len(s) > 2 && s[0] == '-' && s[1] != '-' && strings.Contains(s, "i") && !strings.ContainsAny(s[1:], "ef") {
			inPlace = true // -ni, -Ei
		}
		clean = append(clean, args[i])
	}
	o := parseOpts(clean, sedSpec)
	scripts := o.all("-e", "--expression")
	pos := o.pos
	if len(scripts) == 0 && !o.has("-f", "--file") && len(pos) > 0 {
		scripts = append(scripts, pos[0])
		pos = pos[1:]
	}
	text := ""
	for _, s := range scripts {
		text += s.s + "\n"
		// GNU sed's "e" command and "s///e" flag execute shell commands;
		// "w file" writes. Only the unambiguous spellings are recognised.
		if strings.HasPrefix(s.s, "1e") || strings.HasPrefix(s.s, "e ") || strings.HasSuffix(s.s, "/e") || strings.Contains(s.s, "/e;") {
			if cmd := sedExec(s.s); cmd != "" {
				a.sub(cmd, Posix, OriginInlinePrefix+c.name, c.depth+1, noFlow())
			}
		}
	}
	for _, p := range pos {
		if p.proc || p.s == "-" {
			continue
		}
		if inPlace {
			a.useText(p.s, mWrite, text)
			if n := normPath(p.s); n == "/etc/selinux/config" && (containsFold(text, "disabled") || containsFold(text, "permissive")) {
				a.evasion("selinux_disable")
			}
		} else {
			a.read(p.s)
		}
	}
}

func sedExec(script string) string {
	switch {
	case strings.HasPrefix(script, "1e"):
		return strings.TrimSpace(script[2:])
	case strings.HasPrefix(script, "e "):
		return strings.TrimSpace(script[2:])
	}
	return ""
}
