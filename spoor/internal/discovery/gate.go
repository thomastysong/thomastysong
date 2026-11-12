package discovery

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Gate limits. Every input below comes from a tree the scanned user
// controls, so each bound exists to keep one hostile home from exhausting
// the scan for everybody else. The entry and hash budgets are per scope:
// the machine-wide pass, each home and each project start with their own
// (see gate.scope), so a home that spends its budget starves only itself.
const (
	maxConfigBytes    = 20 << 20  // largest config file parsed
	maxTextBytes      = 1 << 20   // text read for content scans (classify.ScanText reads 1 MiB)
	maxEntries        = 200_000   // directory entries listed per home (and machine-wide)
	maxProjectEntries = 50_000    // directory entries listed per project
	maxChildren       = 5_000     // entries listed per directory; larger fan-outs are skipped
	maxWalkDepth      = 8         // recursion depth of ** globs and tree walks
	maxGlobMatches    = 10_000    // results per glob
	maxHashBytes      = 1 << 30   // bytes hashed per home (skill and plugin folder hashes)
	maxProjectHash    = 256 << 20 // bytes hashed per project
	maxTreeFiles      = 10_000    // files in one hashed tree
	maxTreeBytes      = 100 << 20
	maxTreeFileSize   = 20 << 20
	maxCacheBytes     = 64 << 20 // file bytes kept for re-use within one scan
)

// Gate refusals. They are counted in the ledger by class: errDenied-like
// refusals as Denied, size and type refusals as Skipped.
var (
	errEscape   = errors.New("path resolves outside its root")
	errOwner    = errors.New("file not owned by the expected user")
	errTooLarge = errors.New("file exceeds the size cap")
	errPersonal = errors.New("personal directory not inspected")
	errBudget   = errors.New("scan budget exhausted")
	errDeadline = errors.New("scan deadline reached")
	errSymlink  = errors.New("symbolic link not followed")
	errNotReg   = errors.New("not a regular file")
	errNotDir   = errors.New("not a directory")
	errBadPath  = errors.New("path not acceptable")
)

// fkind is the type of a directory entry, as seen without following links.
type fkind uint8

const (
	kindOther fkind = iota
	kindRegular
	kindDir
	kindSymlink
)

// fmeta describes a file from its open descriptor (or from lstat).
type fmeta struct {
	kind     fkind
	size     int64
	perm     os.FileMode
	owner    string // uid on POSIX; "" when the OS has no simple owner
	hasOwner bool
	nlink    uint64
	mtime    time.Time
}

func (m fmeta) exec() bool { return m.perm&0o111 != 0 }

// loc names a file as a confinement root plus a slash-separated path below
// it. Nothing below root may resolve outside root; root itself is resolved
// normally (it is a home directory, a project directory taken from agent
// state, or a system directory).
type loc struct {
	root string // absolute logical path (inside HostRoot when one is set)
	rel  string // cleaned, slash-separated, no "..", "" for root itself
	home bool   // root is a user's home: personal-directory refusal applies
	user bool   // root belongs to the scanned user (home or project): owner checks apply
	// uid is the owner a listed directory must have when the scan is
	// privileged ("" for system locations). Files are checked against the
	// owner their reader passes; directory listings against this.
	uid string
}

func (l loc) String() string {
	if l.rel == "" {
		return l.root
	}
	return joinLogical(l.root, l.rel)
}

// opener performs the confined opens. Implementations are per OS: openat2
// with RESOLVE_BENEATH / RESOLVE_IN_ROOT on Linux, a no-follow
// component walk on other unix systems and on old kernels, os.Root elsewhere.
type opener interface {
	openFile(root, rel string) (*os.File, error)
	openDir(root, rel string) (*os.File, error)
	lstat(root, rel string) (fmeta, error)
	readlink(root, rel string) (string, error)
	close()
}

// dentry is one listed directory entry.
type dentry struct {
	name string
	kind fkind
}

// gate is the only code in the package that touches the filesystem.
type gate struct {
	ctx      context.Context
	led      *ledger
	op       opener
	priv     bool
	goos     string
	hostRoot string

	mu        sync.Mutex
	entries   int
	hashLeft  int64
	scopeName string // what the current budget belongs to, for notes
	allow     []string
	cache     map[string]cachedFile
	cacheSize int64
	expired   bool
}

type cachedFile struct {
	data []byte
	meta fmeta
	err  error
}

func newGate(ctx context.Context, led *ledger, hostRoot string, priv bool, goos string) (*gate, error) {
	op, err := newOpener(hostRoot)
	if err != nil {
		return nil, err
	}
	return &gate{
		ctx: ctx, led: led, op: op, priv: priv, goos: goos, hostRoot: hostRoot,
		entries: maxEntries, hashLeft: maxHashBytes, scopeName: "machine-wide scan", cache: map[string]cachedFile{},
	}, nil
}

// scope gives the work that follows its own directory-entry and hashing
// budget (a home, a project) and returns the function that restores the
// enclosing scope's budget. Scans are sequential, so scopes nest like
// calls: a user's projects are scanned inside the user's scope.
func (g *gate) scope(name string, entries int, hash int64) (restore func()) {
	g.mu.Lock()
	prevE, prevH, prevN := g.entries, g.hashLeft, g.scopeName
	g.entries, g.hashLeft, g.scopeName = entries, hash, name
	g.mu.Unlock()
	return func() {
		g.mu.Lock()
		g.entries, g.hashLeft, g.scopeName = prevE, prevH, prevN
		g.mu.Unlock()
	}
}

func (g *gate) close() { g.op.close() }

// alive reports whether the scan may continue. The first call after the
// deadline marks the ledger truncated.
func (g *gate) alive() bool {
	if g.ctx.Err() == nil {
		return true
	}
	g.mu.Lock()
	first := !g.expired
	g.expired = true
	g.mu.Unlock()
	if first {
		g.led.truncate("deadline reached; results are partial")
	}
	return false
}

// allowPath exempts a location from the personal-directory refusal because
// the catalog or the agent's own state points inside it.
func (g *gate) allowPath(p string) {
	if p == "" {
		return
	}
	c := cleanLogical(p)
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, a := range g.allow {
		if a == c {
			return
		}
	}
	if len(g.allow) < 4096 {
		g.allow = append(g.allow, c)
	}
}

// personalDirs are home-relative prefixes that hold the user's own data.
// A root sensor has no business in them, and on macOS touching them raises
// privacy prompts, so they are refused unless allowed explicitly.
var personalDirs = []string{
	"documents", "desktop", "pictures", "music", "movies", "videos",
	"library/mail", "library/messages", "library/safari", "library/keychains",
	"library/cookies", "library/photos", "library/application support/google/chrome",
	"library/application support/firefox", "library/application support/bravesoftware",
	"library/application support/microsoft edge", "library/application support/arc",
	".mozilla", ".config/google-chrome", ".config/chromium", ".config/microsoft-edge",
	".config/bravesoftware", ".ssh", ".gnupg", ".password-store",
	"appdata/local/google/chrome", "appdata/roaming/mozilla", "appdata/local/microsoft/edge",
	"appdata/local/microsoft/outlook", "appdata/local/bravesoftware",
}

// isPersonalRel reports a home-relative path inside a personal directory.
func isPersonalRel(rel string) bool {
	if rel == "" {
		return false
	}
	low := strings.ToLower(rel)
	for _, p := range personalDirs {
		if low == p || strings.HasPrefix(low, p+"/") {
			return true
		}
	}
	return false
}

func (g *gate) personal(l loc) bool {
	if !l.home || !isPersonalRel(l.rel) {
		return false
	}
	full := cleanLogical(l.String())
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, a := range g.allow {
		if withinLogical(a, full, g.goos) {
			return false
		}
	}
	return true
}

// account classifies an error into the ledger and returns it unchanged.
// A missing file is not an event: absence is the normal case.
func (g *gate) account(l loc, err error) error {
	switch {
	case err == nil:
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, errNotDir):
	case errors.Is(err, errDeadline):
	case errors.Is(err, errPersonal):
		g.led.denied()
		g.led.note("personal directory not inspected: " + homeRelNote(l))
	case errors.Is(err, fs.ErrPermission), errors.Is(err, errEscape), errors.Is(err, errOwner):
		g.led.denied()
		g.led.note("denied (" + reason(err) + "): " + homeRelNote(l))
	case errors.Is(err, errSymlink), errors.Is(err, errNotReg), errors.Is(err, errTooLarge), errors.Is(err, errBudget), errors.Is(err, errBadPath):
		g.led.skipped()
		g.led.note("skipped (" + reason(err) + "): " + homeRelNote(l))
	default:
		g.led.errored()
		g.led.note("error reading " + homeRelNote(l))
	}
	return err
}

func reason(err error) string {
	for _, e := range []error{errEscape, errOwner, errSymlink, errNotReg, errTooLarge, errBudget, errBadPath} {
		if errors.Is(err, e) {
			return e.Error()
		}
	}
	if errors.Is(err, fs.ErrPermission) {
		return "permission denied"
	}
	return "error"
}

// homeRelNote renders a location for a ledger note. Notes stay on the
// endpoint's result and name the full path, so two users' files are never
// confused.
func homeRelNote(l loc) string {
	return l.String()
}

func (g *gate) checkOwner(l loc, m fmeta, owner string) error {
	if !g.priv || owner == "" || !m.hasOwner {
		return nil
	}
	if m.owner != owner {
		return errOwner
	}
	return nil
}

// readFile reads a whole regular file of at most max bytes. When the scan
// runs privileged and owner is set, the file must belong to that uid. The
// result is cached for the rest of the scan, so the many probes that look
// at one settings file open it once.
func (g *gate) readFile(l loc, owner string, max int64) ([]byte, fmeta, error) {
	if !g.alive() {
		return nil, fmeta{}, errDeadline
	}
	key := l.String() + "\x00" + owner
	g.mu.Lock()
	if c, ok := g.cache[key]; ok && int64(len(c.data)) <= max {
		g.mu.Unlock()
		return c.data, c.meta, c.err
	}
	g.mu.Unlock()
	data, meta, err := g.readUncached(l, owner, max)
	g.account(l, err)
	g.mu.Lock()
	// Size, personal-directory and deadline refusals depend on the caller
	// or on state that can change during the scan, so they are not kept.
	if !errors.Is(err, errTooLarge) && !errors.Is(err, errPersonal) && !errors.Is(err, errDeadline) &&
		g.cacheSize+int64(len(data)) <= maxCacheBytes {
		g.cache[key] = cachedFile{data, meta, err}
		g.cacheSize += int64(len(data))
	}
	g.mu.Unlock()
	return data, meta, err
}

func (g *gate) readUncached(l loc, owner string, max int64) ([]byte, fmeta, error) {
	f, meta, err := g.open(l, owner)
	if err != nil {
		return nil, meta, err
	}
	defer f.Close()
	if meta.size > max {
		return nil, meta, errTooLarge
	}
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, meta, err
	}
	if int64(len(data)) > max {
		return nil, meta, errTooLarge
	}
	g.led.file()
	return data, meta, nil
}

// open returns an open regular file; the caller closes it. Ledger
// accounting is the caller's (use readFile unless streaming).
func (g *gate) open(l loc, owner string) (*os.File, fmeta, error) {
	if !g.alive() {
		return nil, fmeta{}, errDeadline
	}
	if !validRel(l.rel) || l.rel == "" {
		return nil, fmeta{}, errBadPath
	}
	if g.personal(l) {
		return nil, fmeta{}, errPersonal
	}
	f, err := g.op.openFile(l.root, l.rel)
	if err != nil {
		return nil, fmeta{}, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmeta{}, err
	}
	m := metaOf(fi)
	if m.kind != kindRegular {
		f.Close()
		return nil, m, errNotReg
	}
	if err := g.checkOwner(l, m, owner); err != nil {
		f.Close()
		return nil, m, err
	}
	return f, m, nil
}

// stat describes a path without following a final symlink.
func (g *gate) stat(l loc) (fmeta, error) {
	if !g.alive() {
		return fmeta{}, errDeadline
	}
	if !validRel(l.rel) {
		return fmeta{}, g.account(l, errBadPath)
	}
	if g.personal(l) {
		return fmeta{}, errPersonal
	}
	m, err := g.op.lstat(l.root, l.rel)
	if err != nil && !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, errNotDir) {
		g.account(l, err)
	}
	return m, err
}

// exists reports whether a path exists (as anything, links not followed).
func (g *gate) exists(l loc) bool {
	_, err := g.stat(l)
	return err == nil
}

// isDir reports whether a path is a real directory (not a link to one).
func (g *gate) isDir(l loc) bool {
	m, err := g.stat(l)
	return err == nil && m.kind == kindDir
}

func (g *gate) readlink(l loc) (string, error) {
	if !g.alive() {
		return "", errDeadline
	}
	if !validRel(l.rel) || l.rel == "" {
		return "", errBadPath
	}
	if g.personal(l) {
		return "", errPersonal
	}
	t, err := g.op.readlink(l.root, l.rel)
	if err != nil {
		return "", err
	}
	if len(t) > 4096 {
		return "", errBadPath
	}
	return t, nil
}

// readDir lists a directory (not a link to one), charging the entry budget.
// A directory with more than maxChildren entries is not listed at all: a
// partial listing would make "not found" ambiguous.
func (g *gate) readDir(l loc) ([]dentry, error) {
	if !g.alive() {
		return nil, errDeadline
	}
	if !validRel(l.rel) {
		return nil, g.account(l, errBadPath)
	}
	if g.personal(l) {
		return nil, g.account(l, errPersonal)
	}
	f, err := g.op.openDir(l.root, l.rel)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, errNotDir) {
			// A linked directory is common (dotfile managers) and is not an
			// error; it is not followed, and counted as skipped.
			g.account(l, err)
		}
		return nil, err
	}
	defer f.Close()
	// A listing names what is inside: when privileged, a directory in a
	// user's tree is listed only if it belongs to that user, exactly as a
	// file there is read only if it does (another user's skill names are
	// not this user's assets). The check is on the open descriptor.
	if g.priv && l.uid != "" {
		fi, err := f.Stat()
		if err != nil {
			return nil, g.account(l, err)
		}
		if err := g.checkOwner(l, metaOf(fi), l.uid); err != nil {
			return nil, g.account(l, err)
		}
	}
	ents, err := f.ReadDir(maxChildren + 1)
	if err != nil && err != io.EOF {
		return nil, g.account(l, err)
	}
	if len(ents) > maxChildren {
		g.led.skipped()
		g.led.note("directory has too many entries, not listed: " + homeRelNote(l))
		return nil, errBudget
	}
	g.mu.Lock()
	if g.entries < len(ents) {
		g.entries = 0
		name := g.scopeName
		g.mu.Unlock()
		g.led.truncate("directory entry budget exhausted for " + name)
		return nil, errBudget
	}
	g.entries -= len(ents)
	g.mu.Unlock()
	out := make([]dentry, 0, len(ents))
	for _, e := range ents {
		name := e.Name()
		if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") {
			continue
		}
		out = append(out, dentry{name: name, kind: kindOfMode(e.Type())})
	}
	return out, nil
}

// takeHash reserves n bytes of the current scope's hashing budget.
func (g *gate) takeHash(n int64) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if n > g.hashLeft {
		return false
	}
	g.hashLeft -= n
	return true
}

func kindOfMode(m fs.FileMode) fkind {
	switch {
	case m&fs.ModeSymlink != 0:
		return kindSymlink
	case m.IsDir():
		return kindDir
	case m.IsRegular():
		return kindRegular
	}
	return kindOther
}

// validRel accepts cleaned relative paths without ".." or NUL.
func validRel(rel string) bool {
	if rel == "" {
		return true
	}
	if len(rel) > 4096 || strings.IndexByte(rel, 0) >= 0 || strings.HasPrefix(rel, "/") {
		return false
	}
	for _, c := range strings.Split(rel, "/") {
		if c == "" || c == "." || c == ".." {
			return false
		}
	}
	return true
}

// cleanLogical normalizes a logical path: native separators become "/",
// "." and ".." are resolved lexically, a trailing separator is dropped.
func cleanLogical(p string) string {
	if p == "" {
		return ""
	}
	p = strings.ReplaceAll(p, `\`, "/")
	vol := ""
	if len(p) >= 2 && p[1] == ':' {
		vol, p = p[:2], p[2:]
	}
	c := path.Clean(p)
	if c == "." {
		c = ""
	}
	return vol + c
}

func joinLogical(root, rel string) string {
	root = cleanLogical(root)
	if rel == "" {
		return root
	}
	if strings.HasSuffix(root, "/") {
		return root + rel
	}
	return root + "/" + rel
}

// foldCase reports whether paths compare case-insensitively on goos.
func foldCase(goos string) bool { return goos == "windows" || goos == "darwin" }

// withinLogical reports whether p equals base or lies below it.
func withinLogical(base, p, goos string) bool {
	base, p = cleanLogical(base), cleanLogical(p)
	if base == "" || p == "" {
		return false
	}
	if foldCase(goos) {
		base, p = strings.ToLower(base), strings.ToLower(p)
	}
	if p == base {
		return true
	}
	if base == "/" {
		return strings.HasPrefix(p, "/")
	}
	return strings.HasPrefix(p, base+"/")
}

// relLogical returns p relative to base ("" when equal), or false.
func relLogical(base, p, goos string) (string, bool) {
	if !withinLogical(base, p, goos) {
		return "", false
	}
	base, p = cleanLogical(base), cleanLogical(p)
	if len(p) == len(base) {
		return "", true
	}
	if base == "/" {
		return p[1:], true
	}
	return p[len(base)+1:], true
}

// realPath maps a logical path to the path in the scanning process's own
// namespace (used only for names given to os.File and error notes).
func realPath(hostRoot, logical string) string {
	if hostRoot == "" {
		return filepath.FromSlash(logical)
	}
	return filepath.Join(hostRoot, filepath.FromSlash(strings.TrimPrefix(cleanLogical(logical), "/")))
}

// systemLoc confines a system path to its parent directory: the parent is
// resolved normally (system directories are administrator-owned), the final
// component is never followed.
func systemLoc(p string) loc {
	p = cleanLogical(p)
	dir, base := path.Split(p)
	dir = strings.TrimSuffix(dir, "/")
	if dir == "" {
		dir = "/"
	}
	if len(dir) == 2 && dir[1] == ':' {
		dir += "/"
	}
	return loc{root: dir, rel: base}
}
