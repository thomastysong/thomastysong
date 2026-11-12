package shellx

import (
	"strings"

	"github.com/thomastysong/spoor/internal/pathcanon"
)

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
	register(hTouch, "touch", "mkdir", "md")
	register(hMklink, "mklink")
	register(hMkfs, "mkswap", "mke2fs", "newfs", "newfs_hfs", "newfs_apfs", "newfs_msdos")
	register(hDiskTools, "wipefs", "blkdiscard", "sgdisk", "parted", "hdparm", "diskutil", "badblocks")
	register(hOpenssl, "openssl")
	register(hSetcap, "setcap")
	register(hMount, "mount", "umount", "bindfs")
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
		if t.proc || refusedDot(t.s) {
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
		if !refusedDot(t.s) {
			a.del(t.s)
		}
	}
}

// refusedDot reports an rm or rmdir operand whose last component is "." or
// "..", such as /tmp/.. or ~/x/../: POSIX rm and rmdir refuse it and remove
// nothing, so it is not the directory it resolves to. A bare "." or ".."
// is left to the caller: rm -rf .. is how a working directory the analysis
// cannot see is emptied in a script that cds first.
func refusedDot(s string) bool {
	t := strings.TrimRight(s, "/")
	i := strings.LastIndexByte(t, '/')
	if i < 0 {
		return false
	}
	last := t[i+1:]
	return last == "." || last == ".."
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
			// install -d creates each operand as a directory, as mkdir -p
			// does.
			for _, p := range pos {
				a.attr(p.s)
				a.madeDir(p.s)
			}
			if hasDest {
				a.attr(dest.s)
				a.madeDir(dest.s)
			}
			return
		}
		if m, ok := o.get("-m", "--mode"); ok {
			uid, gid := specialBits(m.s)
			if uid {
				a.priv("setuid_chmod")
			} else if gid {
				a.priv("setgid_chmod")
			}
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
	symbolic := o.has("-s", "--symbolic")
	// ln TARGET (link in the working directory), ln TARGET LINK, ln
	// TARGET... DIR, ln -t DIR TARGET...
	targets, dir, link := pos, "", ""
	if t, ok := o.get("-t", "--target-directory"); ok {
		dir = t.s
	} else if len(pos) >= 2 {
		targets = pos[:len(pos)-1]
		if len(pos) > 2 {
			dir = pos[len(pos)-1].s
		} else if l := pos[len(pos)-1].s; strings.HasSuffix(l, "/") || strings.HasSuffix(l, `\`) {
			dir = l // ln -s TARGET DIR/
		} else {
			link = l
		}
	}
	for _, target := range targets {
		l := link
		switch {
		case dir != "":
			l = strings.TrimRight(dir, "/\\") + "/" + baseName(target.s)
		case l == "":
			l = baseName(target.s)
		}
		a.use(l, mLink)
		// ln -sf /dev/null ~/.bash_history: the history file can never fill.
		if target.s == "/dev/null" && isHistoryFile(normPath(l)) {
			a.evasion("history_clear")
		}
		if !target.dyn && !target.proc {
			a.linkSource(target.s, l, symbolic)
		}
		if cls := readClass(target.s); cls != "" {
			// A link to a secret is a read waiting to happen (symlink escape).
			a.read(target.s)
		}
	}
}

// linkSource records the existing path a new link makes reachable under
// another name, and the link itself, so that an operand later on the line
// that goes through it is also recorded under the path it reaches. A
// relative symlink target is relative to the directory of the link, not
// to the working directory.
func (a *analyzer) linkSource(target, link string, symbolic bool) {
	if pseudoPath(strings.TrimSpace(target)) {
		return
	}
	l, _ := a.canon(link)
	to, fl := "", pathcanon.Flags(0)
	if symbolic && relativePath(target) {
		if d := pathcanon.Dir(l, a.dial != Posix); d != "" {
			o := a.canonOpts()
			o.CWD = ""
			to, fl = pathcanon.Clean(d+"/"+target, o)
		}
	}
	if to == "" {
		to, fl = a.canon(target)
	}
	a.aliasTo(l, to, fl)
}

// linkTo records a Windows link created at link that reaches target
// (New-Item -ItemType SymbolicLink, Junction or HardLink).
func (a *analyzer) linkTo(link, target string) {
	if pseudoPath(strings.TrimSpace(target)) {
		return
	}
	l, _ := a.canon(link)
	to, fl := a.canon(target)
	a.aliasTo(l, to, fl)
}

// aliasTo records that the canonical name now reaches the canonical path
// to (a link or a bind mount made on this command line).
func (a *analyzer) aliasTo(name, to string, fl pathcanon.Flags) {
	a.useCanonical(to, fl, mAlias)
	if r := a.reached(to, mRead); r != to {
		a.useCanonical(r, 0, mAlias)
		to = r
	}
	a.link(name, to)
}

// hMount covers mount, umount and bindfs: the mount point is changed (its
// contents are replaced or uncovered), and the source of a bind mount is
// made reachable under the mount point's name.
func hMount(a *analyzer, c *simple, in flow, out *flow) {
	o := parseOpts(c.rest(), &optSpec{short: "tOoLUTN", long: longSet{"--types", "--options", "--test-opts", "--label", "--uuid",
		"--fstab", "--namespace", "--source", "--target", "--target-prefix", "--map-users", "--map-groups", "--mirror", "-o"}})
	pos := o.pos
	if c.name == "umount" {
		for _, p := range pos {
			a.attr(p.s)
		}
		return
	}
	bind := c.name == "bindfs" || o.has("--bind", "-B", "--rbind", "-R", "--move", "-M")
	for _, v := range o.all("-o", "--options") {
		for _, opt := range strings.Split(v.s, ",") {
			if opt == "bind" || opt == "rbind" || opt == "move" {
				bind = true
			}
		}
	}
	src, hasSrc := o.get("--source")
	dst, hasDst := o.get("--target")
	switch {
	case hasSrc && hasDst:
	case len(pos) >= 2:
		src, dst, hasSrc, hasDst = pos[len(pos)-2], pos[len(pos)-1], true, true
	case len(pos) == 1 && !hasDst:
		dst, hasDst = pos[0], true // remount, or a mount point from fstab
	}
	if hasDst {
		a.attr(dst.s)
	}
	if bind && hasSrc && !src.dyn {
		to, fl := a.canon(src.s)
		name := ""
		if hasDst {
			name, _ = a.canon(dst.s)
		}
		a.aliasTo(name, to, fl)
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

// specialBits reports whether a chmod mode sets the setuid and the setgid
// bit. Octal modes carry them in the digit before the last three (4 setuid,
// 2 setgid, 1 sticky; "04755" and "4755" alike); symbolic modes in
// "+s"/"=s" for u (setuid), g (setgid), or both when the who part is
// empty or "a". "o+s" sets neither.
func specialBits(m string) (setuid, setgid bool) {
	if isDigits(m) {
		if len(m) < 4 || len(m) > 5 || strings.ContainsAny(m, "89") {
			return false, false
		}
		d := m[len(m)-4] - '0'
		if len(m) == 5 && m[0] != '0' {
			return false, false
		}
		return d&4 != 0, d&2 != 0
	}
	for _, clause := range strings.Split(m, ",") {
		i := 0
		for i < len(clause) && strings.IndexByte("ugoa", clause[i]) >= 0 {
			i++
		}
		who := clause[:i]
		u := who == "" || strings.ContainsAny(who, "ua")
		g := who == "" || strings.ContainsAny(who, "ga")
		// One or more operations: u+s-x, g=rws.
		for i < len(clause) {
			op := clause[i]
			if op != '+' && op != '=' && op != '-' {
				break
			}
			j := i + 1
			for j < len(clause) && clause[j] != '+' && clause[j] != '=' && clause[j] != '-' {
				j++
			}
			if op != '-' && strings.IndexByte(clause[i+1:j], 's') >= 0 {
				setuid = setuid || u
				setgid = setgid || g
			}
			i = j
		}
	}
	return setuid, setgid
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
	uid, gid := specialBits(mode)
	switch {
	case uid:
		a.priv("setuid_chmod")
	case gid && !a.allMadeDirs(targets):
		// setgid on a directory only makes new files inherit its group;
		// on a program it runs with that group's rights. A directory this
		// command line created (mkdir, install -d) or a target written
		// with a trailing slash is a directory.
		a.priv("setgid_chmod")
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
	// chown -h and chgrp -h change a symbolic link itself, not what it
	// points at.
	defer a.noFollow(c.dialect == Posix && (c.name == "chown" || c.name == "chgrp") && c.has("-h", "--no-dereference"))()
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
	if c.dialect != Posix {
		// cmd.exe's md and mkdir: every operand is a directory to create
		// (PowerShell's mkdir is New-Item, see psSetContent).
		if c.name == "mkdir" || c.name == "md" {
			for _, t := range c.rest() {
				if !strings.HasPrefix(t.s, "/") {
					a.attr(t.s)
					a.madeDir(t.s)
				}
			}
		}
		return
	}
	o := parseOpts(c.rest(), &optSpec{short: "dtrm", long: longSet{"--date", "--reference", "--time", "--mode"}})
	// touch -h changes a symbolic link's own times.
	defer a.noFollow(c.name == "touch" && o.has("-h", "--no-dereference"))()
	for _, t := range o.pos {
		a.attr(t.s)
		if c.name == "mkdir" {
			a.madeDir(t.s)
		}
	}
}

// hMklink covers cmd.exe's mklink [/D | /H | /J] LINK TARGET: the link is
// placed at LINK and reaches TARGET. A relative symbolic link target is
// relative to the link's directory; a junction's or hard link's to the
// working directory.
func hMklink(a *analyzer, c *simple, in flow, out *flow) {
	symbolic := true
	var pos []arg
	for _, t := range c.rest() {
		switch strings.ToLower(t.s) {
		case "/d":
		case "/h", "/j":
			symbolic = false
		default:
			if !strings.HasPrefix(t.s, "/") {
				pos = append(pos, t)
			}
		}
	}
	if len(pos) < 2 {
		return
	}
	link, target := pos[0], pos[1]
	a.use(link.s, mLink)
	if !target.dyn {
		if symbolic {
			a.linkSource(target.s, link.s, true)
		} else {
			a.linkTo(link.s, target.s)
		}
	}
}

// madeDir remembers a directory created on this command line.
func (a *analyzer) madeDir(p string) {
	if c, _ := a.canon(p); c != "" && len(a.mkdirs) < maxList {
		a.mkdirs = append(a.mkdirs, c)
	}
}

// allMadeDirs reports whether every target is known to be a directory:
// created on this command line, or written with a trailing slash.
func (a *analyzer) allMadeDirs(targets []arg) bool {
	if len(targets) == 0 {
		return false
	}
	for _, t := range targets {
		if strings.HasSuffix(t.s, "/") {
			continue
		}
		c, _ := a.canon(t.s)
		found := false
		for _, d := range a.mkdirs {
			if d == c {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
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
