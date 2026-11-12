package classify

import "strings"

// PathClasses returns the closed-vocabulary classes of a path (see
// PathClassVocabulary and the package documentation). The path may be
// relative; it is resolved against ctx.CWD lexically. "~", "~user", $HOME,
// ${HOME}, %USERPROFILE%, $env:USERPROFILE and the other well-known directory
// variables are expanded. Matching is case-insensitive on Windows and macOS.
// The filesystem is never touched.
//
// Shell patterns in the path ("~/.ssh/*", "/etc/shad*", "~/.aws/{config,
// credentials}") are classified by what they can expand to, provided the
// pattern carries some literal text: a bare "*" matches nothing by itself.
//
// The result is ordered as in PathClassVocabulary and is nil when no class
// applies. PathClasses never panics.
func PathClasses(path string, ctx PathCtx) (out []string) {
	defer func() {
		if recover() != nil {
			out = nil
		}
	}()
	if path == "" || len(path) > maxPathLen || len(ctx.CWD) > maxPathLen || len(ctx.Home) > maxPathLen {
		return nil
	}
	raw := cleanInput(path)
	if raw == "" || raw == "-" || isRemoteURL(raw) {
		return nil
	}
	var set pathSet
	for _, alt := range expandBraces(raw) {
		classifyPath(alt, ctx, &set)
	}
	return set.names()
}

// expandBraces expands the first {a,b,c} group of a path (at most 16
// alternatives). Nested and repeated groups are left alone: the goal is that
// the common "~/.aws/{config,credentials}" does not hide a path, not a full
// shell.
func expandBraces(s string) []string {
	open := -1
	for i := 0; i < len(s); i++ {
		if s[i] == '{' && (i == 0 || s[i-1] != '$') {
			open = i
			break
		}
	}
	if open < 0 {
		return []string{s}
	}
	end := strings.IndexByte(s[open:], '}')
	if end < 0 {
		return []string{s}
	}
	inner := s[open+1 : open+end]
	if !strings.Contains(inner, ",") || strings.ContainsAny(inner, "{$") {
		return []string{s}
	}
	parts := strings.Split(inner, ",")
	if len(parts) > 16 {
		parts = parts[:16]
	}
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		out = append(out, s[:open]+part+s[open+end+1:])
	}
	return out
}

func classifyPath(raw string, ctx PathCtx, set *pathSet) {
	lp, cwd, home, os := resolvePath(raw, ctx)
	switch lp.vol {
	case volRegistry:
		classifyRegistry(lp, set)
		return
	case volDevice:
		classifyWindowsDevice(lp, set)
		return
	}
	matchPatterns(lp, os, set)
	classifySSHDir(lp, set)
	classifyEnvFile(lp, set)
	classifyKeyFile(lp, set)
	classifyTokenName(lp, set)
	if i := findAgentDir(lp); i >= 0 {
		set.add(agentSubclass(lp.lsegs[i:]))
	}
	classifyGit(lp, set)
	classifyLocation(lp, cwd, home, os, set)
}

// segIs compares a component with a lower-case literal under the path's case
// rule.
func (p *lexPath) segIs(i int, lowerLit string) bool {
	if p.fold {
		return p.lsegs[i] == lowerLit
	}
	return p.segs[i] == lowerLit
}

// sshConfigNames are the files in ~/.ssh that configure the client and are
// not private keys.
var sshConfigNames = map[string]bool{
	"config": true, "config.d": true, "known_hosts": true, "known_hosts.old": true,
	"known_hosts2": true, "rc": true, "environment": true, "allowed_signers": true,
	"ssh_config": true,
}

// classifySSHDir classifies the contents of a .ssh directory. Private keys
// have no fixed name (github, work_ed25519, deploy.pem), so everything that
// is not a known non-secret file counts as one; the directory itself does
// too, because a recursive copy takes the keys with it.
func classifySSHDir(lp *lexPath, set *pathSet) {
	for i := range lp.segs {
		if !lp.segIs(i, ".ssh") {
			continue
		}
		if i == len(lp.segs)-1 {
			set.add(pcSSHPrivateKey)
			return
		}
		name := lp.lsegs[i+1]
		switch {
		case name == "authorized_keys" || name == "authorized_keys2":
			set.add(pcSSHAuthorizedKeys)
		case sshConfigNames[name]:
			set.add(pcSSHConfig)
		case strings.HasSuffix(name, ".pub"):
		case name == "sockets" || name == "multiplex" || strings.HasPrefix(name, "agent") ||
			strings.HasPrefix(name, "cm-") || strings.HasPrefix(name, "control"):
			// ControlMaster and agent sockets.
		default:
			set.add(pcSSHPrivateKey)
		}
		return
	}
}

// envTemplateWords mark dotenv files that are committed on purpose and hold
// names, not values.
var envTemplateWords = map[string]bool{
	"example": true, "sample": true, "template": true, "tmpl": true, "tpl": true,
	"dist": true, "schema": true, "defaults": true, "default": true, "ex": true,
	"examples": true, "skel": true,
}

func classifyEnvFile(lp *lexPath, set *pathSet) {
	if len(lp.segs) == 0 {
		return
	}
	b := lp.base()
	if lp.fold {
		b = lp.lbase()
	}
	if lp.wild[len(lp.segs)-1] {
		// ".env*" and ".e*v" style patterns: decided by the literal prefix.
		if pre := globPrefix(b); strings.HasPrefix(pre, ".env") || (len(pre) >= 3 && strings.HasPrefix(".env", pre)) {
			set.add(pcSecretEnv)
		}
		return
	}
	switch {
	case b == ".env" || b == ".envrc":
		set.add(pcSecretEnv)
	case strings.HasPrefix(b, ".env."):
		for _, part := range strings.Split(strings.ToLower(b[5:]), ".") {
			if envTemplateWords[part] {
				return
			}
		}
		set.add(pcSecretEnv)
	case strings.HasSuffix(b, ".env") && len(b) > 4:
		for _, part := range strings.FieldsFunc(strings.ToLower(b[:len(b)-4]), func(r rune) bool { return r == '.' || r == '-' || r == '_' }) {
			if envTemplateWords[part] {
				return
			}
		}
		set.add(pcSecretEnv)
	}
}

var keyExtensions = map[string]bool{
	".pem": true, ".key": true, ".p12": true, ".pfx": true, ".jks": true,
	".keystore": true, ".p8": true, ".pk8": true, ".ovpn": true, ".agekey": true,
}

// publicKeyHints mark PEM-family files that hold certificates or public keys.
var publicKeyHints = []string{
	"cert", "chain", "ca-bundle", "cacert", "public", "pubkey", ".pub.", ".crt.",
	".csr", "dhparam", "truststore", "cacerts", "bundle",
}

// publicKeyDirs are system trust stores: full of *.pem, none of them private.
var publicKeyDirs = map[string]bool{
	"certs": true, "ca-certificates": true, "ca-trust": true, "certifi": true,
	"anchors": true, "trust-source": true,
}

func extOf(name string) string {
	if i := strings.LastIndexByte(name, '.'); i > 0 {
		return name[i:]
	}
	return ""
}

// classifyKeyFile assigns cert_private_key by file name. The extension is a
// convention across every OS, so it is matched case-insensitively everywhere.
func classifyKeyFile(lp *lexPath, set *pathSet) {
	n := len(lp.segs)
	if n == 0 {
		return
	}
	b := lp.lbase()
	named := strings.Contains(b, "privkey") || strings.Contains(b, "private_key") ||
		strings.Contains(b, "private-key") || strings.Contains(b, "privatekey")
	ext := extOf(b)
	if named && !sourceExtensions[ext] {
		set.add(pcCertPrivateKey)
		return
	}
	if !keyExtensions[ext] {
		return
	}
	if strings.Contains(b, "public") || strings.Contains(b, "pubkey") || strings.Contains(b, ".pub.") ||
		strings.Contains(b, "truststore") || strings.Contains(b, "cacerts") {
		return
	}
	// ".pem" is also the usual container for certificates; the other
	// extensions say "key" themselves.
	if ext == ".pem" && !strings.Contains(strings.TrimSuffix(b, ext), "key") {
		for _, h := range publicKeyHints {
			if strings.Contains(b, h) {
				return
			}
		}
		for _, d := range lp.lsegs[:n-1] {
			if publicKeyDirs[d] {
				return
			}
		}
	}
	set.add(pcCertPrivateKey)
}

// sourceExtensions are files that talk ABOUT tokens and secrets (code and
// documentation) rather than hold them.
var sourceExtensions = map[string]bool{
	".go": true, ".py": true, ".pyi": true, ".js": true, ".mjs": true, ".cjs": true,
	".ts": true, ".tsx": true, ".jsx": true, ".java": true, ".kt": true, ".kts": true,
	".rb": true, ".rs": true, ".c": true, ".h": true, ".cc": true, ".cpp": true,
	".hpp": true, ".cs": true, ".php": true, ".swift": true, ".scala": true,
	".m": true, ".mm": true, ".lua": true, ".pl": true, ".pm": true, ".ex": true,
	".exs": true, ".erl": true, ".hs": true, ".clj": true, ".dart": true,
	".vue": true, ".svelte": true, ".html": true, ".htm": true, ".css": true,
	".scss": true, ".less": true, ".md": true, ".mdx": true, ".rst": true,
	".adoc": true, ".proto": true, ".graphql": true, ".sh": true, ".bash": true,
	".zsh": true, ".fish": true, ".ps1": true, ".bat": true, ".cmd": true,
	".tf": true, ".sql": true, ".r": true, ".jl": true, ".zig": true, ".nim": true,
	".svg": true, ".png": true, ".jpg": true, ".gif": true, ".snap": true,
	".d.ts": true, ".map": true, ".ipynb": true, ".tmpl": true, ".j2": true,
	".example": true, ".sample": true, ".template": true, ".dist": true,
}

var tokenNameWords = []string{
	"token", "secret", "credential", "creds", "password", "passwd", "apikey", "api_key", "api-key",
}

// tokenNameExclusions are names that contain a token word but are not secret
// stores.
var tokenNameExclusions = []string{
	"tokenizer", "tokenize", "tokenization", "design-token", "design_token",
	".secrets.baseline", "secretlint", "example", "sample", "template",
}

// tokenFileNames are credential files whose names carry no token word.
var tokenFileNames = map[string]bool{
	".pgpass": true, "pgpass.conf": true, ".my.cnf": true, ".mylogin.cnf": true,
	".htpasswd": true,
}

// secretDirNames are directories whose non-code contents are secrets by
// convention (config/secrets/prod.yaml, /etc/secrets/db).
var secretDirNames = map[string]bool{
	"secrets": true, ".secrets": true, "secret": true, "credentials": true, ".credentials": true,
}

// classifyTokenName assigns token_file from the file name: a token word in a
// file that is data, not code or documentation.
func classifyTokenName(lp *lexPath, set *pathSet) {
	n := len(lp.segs)
	if n == 0 {
		return
	}
	b := lp.lbase()
	if tokenFileNames[b] {
		set.add(pcTokenFile)
		return
	}
	// A project file is what its role says, whatever words its name contains
	// (.github/workflows/secret-scan.yml is a workflow, not a secret store).
	if set.has(pcCIConfig) || set.has(pcPackageManifest) || set.has(pcLockfile) || set.has(pcDockerfile) || set.has(pcVCSHook) {
		return
	}
	if sourceExtensions[extOf(b)] {
		return
	}
	if b == "passwd" || b == "passwd-" {
		return // /etc/passwd holds no passwords
	}
	for _, ex := range tokenNameExclusions {
		if strings.Contains(b, ex) {
			return
		}
	}
	for _, w := range tokenNameWords {
		if strings.Contains(b, w) {
			set.add(pcTokenFile)
			return
		}
	}
	for _, d := range lp.lsegs[:n-1] {
		if secretDirNames[d] {
			set.add(pcTokenFile)
			return
		}
	}
}

// classifyGit classifies the inside of a repository's .git directory, and of
// bare repositories (name.git/hooks/...).
func classifyGit(lp *lexPath, set *pathSet) {
	n := len(lp.segs)
	for i := 0; i < n; i++ {
		isGit := lp.segIs(i, ".git")
		if !isGit && strings.HasSuffix(lp.lsegs[i], ".git") && i+1 < n {
			switch lp.lsegs[i+1] {
			case "hooks", "config", "objects", "refs", "head", "info", "packed-refs":
				isGit = true
			}
		}
		if !isGit {
			continue
		}
		rest := lp.lsegs[i+1:]
		for j, r := range rest {
			if r != "hooks" {
				continue
			}
			// Only directly under .git, or under modules/<name>/ and
			// worktrees/<name>/, is "hooks" the hook directory.
			if j == 0 || rest[0] == "modules" || rest[0] == "worktrees" {
				// The *.sample files git ships are inert.
				if j == len(rest)-1 || !strings.HasSuffix(lp.lbase(), ".sample") {
					set.add(pcVCSHook)
				}
				return
			}
		}
		set.add(pcVCSInternal)
		return
	}
}

// blockDevicePrefixes are /dev names of disks and raw memory. Character
// devices that are safe to write (null, zero, tty, stdout) are not here.
var blockDevicePrefixes = []string{
	"sd", "hd", "vd", "xvd", "nvme", "mmcblk", "disk", "rdisk", "dm-", "md",
	"loop", "sr", "nbd", "zd", "zram", "mapper", "mtd", "sg",
}

func isBlockDevice(name string) bool {
	switch name {
	case "mem", "kmem", "port", "mapper", "disk":
		return true
	}
	for _, pre := range blockDevicePrefixes {
		if !strings.HasPrefix(name, pre) || len(name) == len(pre) {
			continue
		}
		next := name[len(pre)]
		switch pre {
		case "sd", "hd", "vd", "xvd":
			// sda, hdb: a drive letter follows. Keeps "shm", "stdin" out.
			if next >= 'a' && next <= 'z' || next == '*' || next == '?' || next == '[' {
				return true
			}
		case "dm-", "mapper", "disk", "rdisk":
			return true
		default:
			if isDigit(next) || next == '*' || next == '?' || next == '[' || (pre == "mtd" && next == 'b') {
				return true
			}
		}
	}
	return false
}

// posixSystemRoots are the top-level directories that belong to the OS.
var posixSystemRoots = map[string]bool{
	"etc": true, "bin": true, "sbin": true, "usr": true, "lib": true, "lib32": true,
	"lib64": true, "libx32": true, "boot": true, "sys": true, "proc": true,
	"var": true, "run": true, "snap": true, "nix": true,
}

var darwinSystemRoots = map[string]bool{
	"system": true, "library": true, "applications": true, "private": true, "cores": true,
}

var windowsSystemRoots = map[string]bool{
	"windows": true, "program files": true, "program files (x86)": true,
	"programdata": true, "system volume information": true, "$recycle.bin": true,
	"recovery": true, "boot": true, "efi": true,
}

// sharedWindowsProfiles are C:\Users entries that are not a person's home.
var sharedWindowsProfiles = map[string]bool{
	"public": true, "default": true, "default user": true, "all users": true,
}

// homeDepth returns how many leading components of lp form a home directory,
// or -1. Other users' homes count: reading /home/alice/.ssh from bob's
// session is no less sensitive.
func homeDepth(lp, home *lexPath, os string) int {
	if !lp.abs {
		return -1
	}
	if home != nil && len(home.segs) > 0 && lp.under(home) {
		return len(home.segs)
	}
	s := lp.lsegs
	if os == "windows" {
		if len(s) >= 2 && s[0] == "users" && !sharedWindowsProfiles[s[1]] {
			return 2
		}
		return -1
	}
	switch {
	case len(s) >= 2 && lp.segs[0] == "home":
		return 2
	case len(s) >= 2 && s[0] == "users" && (os == "darwin" || lp.segs[0] == "Users") && s[1] != "shared":
		return 2
	case len(s) >= 1 && lp.segs[0] == "root":
		return 1
	case os == "darwin" && len(s) >= 2 && s[0] == "var" && s[1] == "root":
		return 2
	}
	return -1
}

// classifyLocation adds the classes that depend on where the path is rather
// than what it is named.
func classifyLocation(lp, cwd, home *lexPath, os string, set *pathSet) {
	n := len(lp.segs)
	s := lp.lsegs
	win := os == "windows"

	// outside_cwd.
	switch {
	case lp.abs && cwd != nil:
		if !lp.under(cwd) {
			set.add(pcOutsideCWD)
		}
	case !lp.abs && lp.up > 0:
		set.add(pcOutsideCWD)
	}
	if !lp.abs {
		return
	}

	temp := false
	switch {
	case n >= 1 && s[0] == "tmp":
		temp = true
	case !win && n >= 2 && s[0] == "var" && (s[1] == "tmp" || s[1] == "folders"):
		temp = true
	case !win && n >= 2 && (s[0] == "dev" || s[0] == "run") && s[1] == "shm":
		temp = true
	case win && n >= 2 && s[0] == "windows" && s[1] == "temp":
		temp = true
	case win:
		for i := 0; i+2 < n; i++ {
			if s[i] == "appdata" && s[i+1] == "local" && s[i+2] == "temp" {
				temp = true
				break
			}
		}
	}
	if temp {
		set.add(pcTemp)
	}

	if !win {
		if n >= 2 && s[0] == "dev" && isBlockDevice(s[1]) {
			set.add(pcDevice)
		}
		// /proc/<pid>/environ and /proc/<pid>/mem: another process's secrets.
		if n >= 3 && s[0] == "proc" && (s[n-1] == "environ" || s[n-1] == "mem") {
			set.add(pcProcEnviron)
		}
	}

	hd := homeDepth(lp, home, os)
	if hd >= 0 {
		if n-hd <= 1 {
			set.add(pcHomeRoot)
		}
		if n > hd && s[hd] == "downloads" {
			set.add(pcDownloads)
		}
		return // nothing under a home is a system directory
	}

	switch {
	case n == 0:
		set.add(pcSystemDir) // the filesystem or drive root
	case win:
		if windowsSystemRoots[s[0]] || (s[0] == "users" && n == 1) {
			set.add(pcSystemDir)
		}
	case temp:
	case s[0] == "dev":
		if n == 1 {
			set.add(pcSystemDir)
		}
	case posixSystemRoots[lp.segs[0]] || (lp.fold && posixSystemRoots[s[0]]):
		set.add(pcSystemDir)
	case os == "darwin" && darwinSystemRoots[s[0]]:
		set.add(pcSystemDir)
	case n == 1 && (s[0] == "home" || s[0] == "users" || s[0] == "opt" || s[0] == "srv" || s[0] == "mnt" || s[0] == "media"):
		set.add(pcSystemDir) // the directory itself, not what users keep in it
	}
}

// classifyRegistry handles Windows registry paths as PowerShell and reg.exe
// write them. Registry locations are where Windows keeps what files hold
// elsewhere: autoruns, policy, and credential hives.
func classifyRegistry(lp *lexPath, set *pathSet) {
	key := "/" + strings.Join(lp.lsegs, "/") + "/"
	has := func(sub string) bool { return strings.Contains(key, sub) }
	switch {
	case has("/currentversion/run/"), has("/currentversion/runonce/"), has("/currentversion/runonceex/"),
		has("/currentversion/runservices/"), has("/policies/explorer/run/"),
		has("/currentversion/winlogon/"), has("/image file execution options/"),
		has("/active setup/installed components/"), has("/currentcontrolset/services/"),
		has("/command processor/"), has("/appinit_dlls/"):
		set.add(pcStartupItem)
	}
	switch {
	// research/agent-surfaces-a.md: HKLM\SOFTWARE\Policies\ClaudeCode,
	// HKLM\Software\Policies\GitHub\Copilot, HKLM\SOFTWARE\Policies\GitHubCopilot.
	case has("/policies/claudecode/"), has("/policies/github/copilot/"), has("/policies/githubcopilot/"):
		set.add(pcAgentManagedPolicy)
	}
	switch {
	case has("/sam/sam/"), has("/security/policy/secrets/"), has("/security/cache/"):
		set.add(pcSystemAuth)
	}
	if has("/windows defender/") || has("/microsoft/sysmon/") || has("/services/sysmon") || has("/services/windefend/") {
		set.add(pcSensorFiles)
	}
}

// classifyWindowsDevice handles the \\.\ namespace: raw disks and named pipes.
func classifyWindowsDevice(lp *lexPath, set *pathSet) {
	if len(lp.lsegs) == 0 {
		return
	}
	name := lp.lsegs[0]
	switch {
	case strings.HasPrefix(name, "physicaldrive"), strings.HasPrefix(name, "harddisk"),
		strings.HasPrefix(name, "cdrom"), strings.HasPrefix(name, "scsi"),
		strings.HasPrefix(name, "globalroot"), len(name) == 2 && name[1] == ':',
		strings.HasPrefix(name, "physicalmemory"):
		set.add(pcDevice)
	case name == "pipe" && len(lp.lsegs) >= 2 && strings.HasPrefix(lp.lsegs[1], "docker"):
		set.add(pcDockerConfig) // \\.\pipe\docker_engine is the Windows docker.sock
	}
}
