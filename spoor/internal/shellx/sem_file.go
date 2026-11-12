package shellx

import "strings"

func registerFile() {
	register(hRm, "rm", "grm", "srm")
	register(hRmdir, "rmdir", "unlink")
	register(hShred, "shred", "wipe")
	register(hCp, "cp", "gcp", "mv", "gmv", "install", "ginstall", "ditto")
	register(hLn, "ln", "gln")
	register(hDd, "dd", "gdd", "dcfldd")
	register(hTar, "tar", "gtar", "bsdtar")
	register(hUnzip, "unzip")
	register(hChmod, "chmod", "gchmod")
	register(hChown, "chown", "chgrp", "chattr", "chflags", "setfacl")
	register(hTruncate, "truncate")
	register(hTouch, "touch", "mkdir")
	register(hMkfs, "mkswap", "mke2fs", "newfs", "newfs_hfs", "newfs_apfs", "newfs_msdos")
	register(hDiskTools, "wipefs", "blkdiscard", "sgdisk", "parted", "hdparm", "diskutil", "badblocks")
	register(hOpenssl, "openssl")
	register(hSetcap, "setcap")
}

// recursiveFlags reports -r/-R/--recursive in an rm-style command.
func recursiveFlags(c *simple) bool {
	return c.hasShort('r', "--recursive") || c.hasShort('R')
}

// rmTargetClass classifies one deletion target of a recursive delete.
func rmTargetClass(t arg) string {
	s := t.s
	n := normPath(s)
	switch {
	case t.guard:
		return "" // ${VAR:?}: the shell aborts when unset
	case isHomeRoot(n):
		return "rm_recursive_home"
	case s == "/" || isRootLike(n):
		return "rm_recursive_root"
	case t.dyn && unsetVarRoot(s):
		// rm -rf "$DIR/": deletes the root when DIR is unset.
		return "rm_recursive_root"
	}
	switch n {
	case "*", ".", "..", "./*", "../*", ".*", "**", "../", "../..", "*/":
		// A catch-all relative to a working directory the analysis cannot see.
		return "rm_recursive_wildcard"
	}
	if t.glob && (n == "~/*" || strings.HasPrefix(n, "*") && strings.Trim(n, "*/.") == "") {
		return "rm_recursive_wildcard"
	}
	if t.dyn && (s == "$PWD" || s == "$PWD/" || s == "$PWD/*" || s == "$(...)/*" || s == "$(...)/") {
		return "rm_recursive_wildcard"
	}
	return ""
}

func hRm(a *analyzer, c *simple, in flow, out *flow) {
	if c.dialect != Posix && winDelete(a, c) {
		return
	}
	rec := recursiveFlags(c)
	noPreserve := c.has("--no-preserve-root")
	for _, t := range c.positionals() {
		if t.proc {
			continue
		}
		a.del(t.s)
		if !rec {
			continue
		}
		if cls := rmTargetClass(t); cls != "" {
			a.destructive(cls)
		}
		if noPreserve {
			a.destructive("rm_recursive_root")
		}
	}
}

func hRmdir(a *analyzer, c *simple, in flow, out *flow) {
	if c.dialect != Posix && winDelete(a, c) {
		return
	}
	for _, t := range c.positionals() {
		a.del(t.s)
	}
}

func hShred(a *analyzer, c *simple, in flow, out *flow) {
	o := parseOpts(c.rest(), &optSpec{short: "ns", long: longSet{"--iterations", "--size", "--random-source"}})
	for _, t := range o.pos {
		a.del(t.s)
		if isDevicePath(normPath(t.s)) {
			a.destructive("disk_wipe")
		}
	}
}

var cpSpec = &optSpec{short: "tSmogb", long: longSet{"--target-directory", "--suffix", "--mode", "--owner", "--group", "--backup", "--reflink", "--sparse"}}

// hCp covers cp, mv and install: sources are read (and removed for mv),
// the destination is written.
func hCp(a *analyzer, c *simple, in flow, out *flow) {
	if c.dialect != Posix && winCopyMove(a, c) {
		return
	}
	sp := cpSpec
	if c.name == "cp" || c.name == "gcp" || c.name == "ditto" {
		// cp has no -m/-o/-g values; -t and -S only.
		sp = &optSpec{short: "tS", long: cpSpec.long}
	}
	if c.name == "mv" || c.name == "gmv" {
		sp = &optSpec{short: "tS", long: cpSpec.long}
	}
	o := parseOpts(c.rest(), sp)
	pos := o.pos
	var dest arg
	hasDest := false
	if t, ok := o.get("-t", "--target-directory"); ok {
		dest, hasDest = t, true
	} else if len(pos) >= 2 {
		dest, hasDest = pos[len(pos)-1], true
		pos = pos[:len(pos)-1]
	}
	move := c.name == "mv" || c.name == "gmv"
	if c.name == "install" || c.name == "ginstall" {
		if o.has("-d", "--directory") {
			return
		}
		if m, ok := o.get("-m", "--mode"); ok && setuidMode(m.s) {
			a.priv("setuid_chmod")
		}
	}
	var srcT taint
	for _, s := range pos {
		if s.proc {
			srcT |= s.t
			continue
		}
		if move {
			a.use(s.s, mMove)
		} else {
			a.read(s.s)
		}
		if t, ok := a.droppedTaint(s.s); ok {
			srcT |= t
		}
		if s.s == "/dev/null" && hasDest && !move {
			a.destructive("truncate_file") // cp /dev/null file
		}
	}
	if hasDest {
		a.write(dest.s)
		if srcT != 0 {
			a.drop(dest.s, srcT)
		}
		if isDevicePath(normPath(dest.s)) {
			a.destructive("disk_wipe")
		}
	}
}

func hLn(a *analyzer, c *simple, in flow, out *flow) {
	o := parseOpts(c.rest(), &optSpec{short: "tS", long: longSet{"--target-directory", "--suffix"}})
	pos := o.pos
	if len(pos) == 0 {
		return
	}
	if len(pos) == 1 {
		a.use(baseName(pos[0].s), mLink)
		return
	}
	link := pos[len(pos)-1]
	target := pos[0]
	a.use(link.s, mLink)
	// ln -sf /dev/null ~/.bash_history: the history file can never fill.
	if target.s == "/dev/null" && isHistoryFile(normPath(link.s)) {
		a.evasion("history_clear")
	}
	if cls := readClass(target.s); cls != "" {
		// A link to a secret is a read waiting to happen (symlink escape).
		a.read(target.s)
	}
}

func hDd(a *analyzer, c *simple, in flow, out *flow) {
	var inF, outF string
	for _, r := range c.rest() {
		if v, ok := strings.CutPrefix(r.s, "if="); ok {
			inF = v
		}
		if v, ok := strings.CutPrefix(r.s, "of="); ok {
			outF = v
		}
	}
	if inF != "" {
		a.read(inF)
	}
	if outF != "" {
		a.write(outF)
		n := normPath(outF)
		if isDevicePath(n) {
			a.destructive("disk_wipe")
		} else if inF == "/dev/null" {
			a.destructive("truncate_file")
		}
	}
}

func hTar(a *analyzer, c *simple, in flow, out *flow) {
	args := c.rest()
	if len(args) == 0 {
		return
	}
	// Old-style "tar czf out.tgz files" has no dash on the first word.
	if !strings.HasPrefix(args[0].s, "-") {
		args = append([]arg{{s: "-" + args[0].s}}, args[1:]...)
	}
	o := parseOpts(args, &optSpec{short: "fCTXIbHKNVg", long: longSet{"--file", "--directory", "--files-from", "--exclude-from",
		"--use-compress-program", "--exclude", "--to-command", "--checkpoint", "--checkpoint-action", "--transform",
		"--strip-components", "--rsh-command", "--newer", "--owner", "--group", "--mode", "--format"}})
	create := o.has("-c", "--create", "-r", "--append", "-u", "--update")
	extract := o.has("-x", "--extract", "--get")
	archive, hasArchive := o.get("-f", "--file")
	if create {
		for _, p := range o.pos {
			a.read(p.s)
		}
		if f, ok := o.get("-T", "--files-from"); ok {
			a.read(f.s)
		}
		if hasArchive {
			a.write(archive.s)
		}
	} else if hasArchive && archive.s != "-" {
		a.read(archive.s)
		if extract {
			a.ranArchive(archive.s)
		}
	} else if extract && in.t&tDownload != 0 {
		a.unpacked = true // curl x | tar xz
	}
	// --checkpoint-action=exec=CMD, --to-command=CMD, -I/--use-compress-program
	// CMD and --rsh-command run arbitrary programs (threats.md R34).
	for _, f := range o.all("--checkpoint-action") {
		if cmd, ok := strings.CutPrefix(f.s, "exec="); ok {
			a.sub(cmd, Posix, OriginWrapper, c.depth+1, noFlow())
		}
	}
	for _, f := range o.all("--to-command", "--use-compress-program", "-I", "--rsh-command") {
		a.sub(f.s, Posix, OriginWrapper, c.depth+1, noFlow())
	}
}

// ranArchive notes that an archive written by a download was unpacked. The
// files inside are unknown, so this only keeps the taint alive for a later
// "./install.sh" style execution of a relative path.
func (a *analyzer) ranArchive(path string) {
	if t, ok := a.droppedTaint(path); ok && t&tDownload != 0 {
		a.unpacked = true
	}
}

func hUnzip(a *analyzer, c *simple, in flow, out *flow) {
	o := parseOpts(c.rest(), &optSpec{short: "dxP"})
	if len(o.pos) > 0 {
		a.read(o.pos[0].s)
		a.ranArchive(o.pos[0].s)
	}
}

// setuidMode reports chmod modes that set the setuid or setgid bit.
func setuidMode(m string) bool {
	if isDigits(m) {
		return len(m) == 4 && (m[0] == '4' || m[0] == '2' || m[0] == '6' || m[0] == '7' || m[0] == '5' || m[0] == '3')
	}
	for _, part := range strings.Split(m, ",") {
		i := strings.IndexAny(part, "+=")
		if i < 0 {
			continue
		}
		who, perms := part[:i], part[i+1:]
		if strings.Contains(perms, "s") && !strings.Contains(who, "o") {
			return true
		}
	}
	return false
}

// openMode reports chmod modes that make the target world-writable.
func openMode(m string) bool {
	if isDigits(m) {
		last := m[len(m)-1]
		return len(m) >= 3 && (last == '2' || last == '3' || last == '6' || last == '7')
	}
	for _, part := range strings.Split(m, ",") {
		i := strings.IndexAny(part, "+=")
		if i < 0 {
			continue
		}
		who, perms := part[:i], part[i+1:]
		if strings.Contains(perms, "w") && (strings.Contains(who, "o") || strings.Contains(who, "a")) {
			return true
		}
	}
	return false
}

func execMode(m string) bool {
	if isDigits(m) {
		for i := 0; i < len(m); i++ {
			if (m[i]-'0')&1 == 1 {
				return len(m) >= 3
			}
		}
		return false
	}
	for _, part := range strings.Split(m, ",") {
		if i := strings.IndexAny(part, "+="); i >= 0 && strings.Contains(part[i+1:], "x") {
			return true
		}
	}
	return false
}

func hChmod(a *analyzer, c *simple, in flow, out *flow) {
	args := c.rest()
	rec := false
	var mode string
	var targets []arg
	for i, r := range args {
		s := r.s
		if mode == "" && len(s) > 1 && s[0] == '-' && !strings.ContainsAny(s[1:2], "rwxXstugo") {
			if strings.ContainsAny(s, "R") || s == "--recursive" {
				rec = true
			}
			if s == "--reference" && i+1 < len(args) {
				mode = "ref"
			}
			continue
		}
		if mode == "" {
			mode = s
			continue
		}
		targets = append(targets, r)
	}
	if mode == "" {
		return
	}
	for _, t := range targets {
		a.attr(t.s)
		if execMode(mode) {
			// chmod +x on a file this command line downloaded or decoded.
			a.ranFile(t.s)
		}
	}
	if setuidMode(mode) {
		a.priv("setuid_chmod")
	}
	if rec && openMode(mode) {
		a.destructive("chmod_recursive_open")
	}
}

func hChown(a *analyzer, c *simple, in flow, out *flow) {
	pos := c.positionals()
	if len(pos) < 2 {
		return
	}
	for _, t := range pos[1:] {
		a.attr(t.s)
	}
}

func hTruncate(a *analyzer, c *simple, in flow, out *flow) {
	o := parseOpts(c.rest(), &optSpec{short: "sr", long: longSet{"--size", "--reference"}})
	size, _ := o.get("-s", "--size")
	zero := strings.Trim(size.s, "=0") == "" || strings.HasPrefix(size.s, "0")
	for _, t := range o.pos {
		if zero {
			a.write(t.s)
			a.destructive("truncate_file")
		} else {
			a.attr(t.s)
		}
	}
}

func hTouch(a *analyzer, c *simple, in flow, out *flow) {
	// Creating an empty file or directory is not a content write, but it is
	// how a hook directory or settings file starts to exist; record it as an
	// attribute change so tamper rules can see it.
	if c.dialect != Posix && c.name == "mkdir" {
		return
	}
	o := parseOpts(c.rest(), &optSpec{short: "dtrm", long: longSet{"--date", "--reference", "--time", "--mode"}})
	for _, t := range o.pos {
		a.attr(t.s)
	}
}

func hMkfs(a *analyzer, c *simple, in flow, out *flow) {
	a.destructive("mkfs")
}

func hDiskTools(a *analyzer, c *simple, in flow, out *flow) {
	rest := c.rest()
	switch c.name {
	case "diskutil":
		if len(rest) == 0 {
			return
		}
		switch strings.ToLower(rest[0].s) {
		case "erasedisk", "zerodisk", "randomdisk", "secureerase", "partitiondisk", "reformat":
			a.destructive("disk_wipe")
		case "erasevolume":
			a.destructive("disk_wipe")
			a.destructive("mkfs")
		case "apfs":
			if len(rest) > 1 && hasPrefixFold(rest[1].s, "delete") {
				a.destructive("disk_wipe")
			}
		}
	case "sgdisk":
		if c.has("--zap-all", "-Z", "--zap", "-z", "-o", "--clear") {
			a.destructive("disk_wipe")
		}
	case "parted":
		if containsArgFold(rest, "mklabel") || containsArgFold(rest, "mktable") || containsArgFold(rest, "rm") {
			a.destructive("disk_wipe")
		}
	case "hdparm":
		if containsArgFold(rest, "--security-erase") || containsArgFold(rest, "--trim-sector-ranges") {
			a.destructive("disk_wipe")
		}
	case "badblocks":
		if c.hasShort('w') {
			a.destructive("disk_wipe")
		}
	default: // wipefs, blkdiscard
		if c.name == "wipefs" && !c.hasShort('a', "--all") && !c.hasShort('o', "--offset") {
			return // listing signatures
		}
		a.destructive("disk_wipe")
	}
}

func hOpenssl(a *analyzer, c *simple, in flow, out *flow) {
	rest := c.rest()
	if len(rest) == 0 {
		return
	}
	sub := strings.ToLower(rest[0].s)
	o := parseOpts(rest[1:], &optSpec{oneDash: true, long: longSet{"-in", "-out", "-inkey", "-key", "-cert", "-CAfile", "-CApath",
		"-connect", "-pass", "-passin", "-passout", "-k", "-K", "-iv", "-keyout", "-config", "-servername", "-proxy", "-keyfile", "-signkey"}})
	for _, f := range o.all("-in", "-inkey", "-key", "-keyfile", "-signkey") {
		a.read(f.s)
	}
	for _, f := range o.all("-out", "-keyout") {
		a.write(f.s)
	}
	if h, ok := o.get("-connect"); ok {
		a.host(h.s)
	}
	static, t, _ := c.input(a, in)
	if _, ok := o.get("-in"); ok {
		static = nil
	}
	decoding := o.has("-d")
	b64 := sub == "base64" || (sub == "enc" && o.has("-base64", "-a", "-A"))
	out.static, out.t = nil, t
	if b64 && decoding {
		out.t |= tB64
		if f, ok := o.get("-out"); ok {
			a.drop(f.s, out.t)
		}
		if static != nil {
			if raw, ok := decodeBase64(*static); ok && len(raw) <= maxStatic {
				s := string(raw)
				out.static = &s
			}
		}
	}
	if sub == "s_client" && (in.piped || c.stdin != nil || c.hasIn) {
		// Data piped into a TLS client leaves the machine.
		if h, ok := o.get("-connect"); ok && !isLoopback(cleanHost(h.s)) {
			a.exfil("netcat_out")
		}
	}
}

func hSetcap(a *analyzer, c *simple, in flow, out *flow) {
	pos := c.positionals()
	if len(pos) >= 2 && !c.hasShort('r') {
		a.priv("cap_add")
		for _, t := range pos[1:] {
			a.attr(t.s)
		}
	}
}
