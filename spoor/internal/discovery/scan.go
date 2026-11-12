package discovery

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/thomastysong/spoor/internal/catalog"
	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/platform"
)

// record is one asset under construction.
type record struct {
	a  *event.Asset
	uc *userCtx // owner; nil for machine-wide assets
	// content is the hook command text: local-only material for detection,
	// carried in Event.Content and never serialized.
	content string
}

type scanner struct {
	o        Options
	ctx      context.Context
	cat      *catalog.Catalog
	products []catalog.Product
	byID     map[string]int
	g        *gate
	led      *ledger
	goos     string
	now      time.Time
	host     event.Host
	sysEnv   map[string]string

	users []*userCtx
	recs  []*record
	keys  map[string]bool // declared items already recorded (path + identity)

	sysEv    map[string]*evidence              // product id -> machine-wide evidence
	userEv   map[*userCtx]map[string]*evidence // per user
	procs    procIndex
	managed  map[string]*managedFacts
	docs     map[string]docResult // parsed config documents by path + owner
	brew     map[string][]int     // "brew:<last segment>" / "cask:<token>" -> product indexes
	shared   map[string]int       // expanded state dir pattern -> number of products claiming it
	projSeen map[string]bool
	binNames map[string][]int
	// projectHits are catalog project-scope probe hits per (user, product),
	// reported scope-qualified on the user's agent asset.
	projectHits map[string]map[string]bool
	homeDenied  bool
	docBytes    int64
}

type docResult struct {
	doc  any
	meta fmeta
	err  error
}

// maxDocCacheBytes bounds the parsed documents kept for re-use: a hostile
// home can fill every catalogued config file to the 20 MiB cap.
const maxDocCacheBytes = 128 << 20

// Scan inventories the machine: agents, apps, extensions, runtimes, MCP
// servers, hooks, skills, plugins, rules files and (with Options.Projects)
// the control files of the projects agents have worked in. Partial results
// are returned with a ledger that says what was not collected. The error is
// non-nil only when nothing could be scanned at all.
func Scan(ctx context.Context, o Options) (res *Result, err error) {
	defer func() {
		if r := recover(); r != nil {
			res, err = nil, fmt.Errorf("discovery: internal error: %v", safeText(fmt.Sprint(r), 200))
		}
	}()
	s, cancel, err := newScanner(ctx, o)
	if err != nil {
		return nil, err
	}
	defer cancel()
	defer s.g.close()
	s.users = s.resolveUsers()
	s.scanSystem()
	for _, uc := range s.users {
		if !s.g.alive() {
			break
		}
		s.scanUser(uc)
	}
	s.buildProducts()
	return s.finish(true), nil
}

// ScanProject is the fast path run when a session starts in a directory:
// only that project's agent control files (project settings, MCP
// declarations, hooks, skills, rules, IDE and git exec sinks, CI agent
// workflows). u is the user the project belongs to; when privileged, files
// not owned by u are refused.
func ScanProject(ctx context.Context, dir string, u platform.UserHome, o Options) (res *Result, err error) {
	defer func() {
		if r := recover(); r != nil {
			res, err = nil, fmt.Errorf("discovery: internal error: %v", safeText(fmt.Sprint(r), 200))
		}
	}()
	dir = cleanLogical(dir)
	if !isAbsLogical(dir) {
		return nil, errors.New("discovery: project directory must be an absolute path")
	}
	s, cancel, err := newScanner(ctx, o)
	if err != nil {
		return nil, err
	}
	defer cancel()
	defer s.g.close()
	uc := s.userCtx(u)
	s.users = []*userCtx{uc}
	s.g.allowPath(dir)
	s.scanProject(uc, dir)
	return s.finish(false), nil
}

func newScanner(ctx context.Context, o Options) (*scanner, context.CancelFunc, error) {
	if o.Catalog == nil {
		return nil, nil, errors.New("discovery: Options.Catalog is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if o.Deadline <= 0 {
		o.Deadline = DefaultDeadline
	}
	if o.MaxProjects <= 0 {
		o.MaxProjects = DefaultMaxProjects
	}
	now := time.Now
	if o.Now != nil {
		now = o.Now
	}
	ctx, cancel := context.WithTimeout(ctx, o.Deadline)
	led := newLedger()
	goos := runtime.GOOS
	if o.HostRoot != "" {
		// A container root is a Linux filesystem whatever the node runs.
		goos = "linux"
	}
	g, err := newGate(ctx, led, o.HostRoot, platform.IsPrivileged(), goos)
	if err != nil {
		cancel()
		return nil, nil, fmt.Errorf("discovery: host root: %w", err)
	}
	s := &scanner{
		o: o, ctx: ctx, cat: o.Catalog, g: g, led: led, goos: goos, now: now().UTC(),
		sysEnv: machineEnv(goos), keys: map[string]bool{},
		sysEv: map[string]*evidence{}, userEv: map[*userCtx]map[string]*evidence{},
		managed: map[string]*managedFacts{}, docs: map[string]docResult{}, projSeen: map[string]bool{},
		projectHits: map[string]map[string]bool{},
	}
	if o.Host != nil {
		s.host = *o.Host
	} else {
		s.host = platform.HostInfo()
	}
	s.products = o.Catalog.Products()
	s.byID = make(map[string]int, len(s.products))
	for i, p := range s.products {
		s.byID[p.ID] = i
	}
	s.indexPackages()
	s.indexProcesses()
	return s, cancel, nil
}

func (s *scanner) userCtx(u platform.UserHome) *userCtx {
	uc := &userCtx{u: u, home: cleanLogical(u.Home), env: map[string]string{}}
	for k, v := range s.sysEnv {
		uc.env[k] = v
	}
	if s.o.Env != nil {
		for k, v := range s.o.Env(u) {
			if len(k) <= 128 && len(v) <= 4096 {
				uc.env[k] = v
			}
		}
	}
	// The scanned home always wins over anything in the environment.
	uc.env["HOME"] = u.Home
	if s.goos == "windows" {
		uc.env["USERPROFILE"] = u.Home
	}
	return uc
}

func (s *scanner) resolveUsers() []*userCtx {
	users := s.o.Users
	if len(users) == 0 {
		if s.o.HostRoot != "" {
			users = s.containerUsers()
		} else {
			var err error
			users, err = platform.Users()
			if err != nil {
				s.led.errored()
				s.led.note("user enumeration failed")
			}
		}
	}
	var out []*userCtx
	seen := map[string]bool{}
	for _, u := range users {
		h := cleanLogical(u.Home)
		if !isAbsLogical(h) || seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, s.userCtx(u))
	}
	return out
}

// containerUsers reads the container root's own account database: the
// node's users are irrelevant inside a container.
func (s *scanner) containerUsers() []platform.UserHome {
	data, _, err := s.g.readFile(systemLoc("/etc/passwd"), "", 4<<20)
	if err != nil {
		s.led.note("container /etc/passwd not readable; no homes scanned")
		return nil
	}
	var out []platform.UserHome
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 7 || f[0] == "" || strings.HasPrefix(f[0], "#") {
			continue
		}
		shell := f[6]
		if strings.HasSuffix(shell, "nologin") || strings.HasSuffix(shell, "/false") || strings.HasSuffix(shell, "/sync") {
			continue
		}
		home := cleanLogical(f[5])
		if !isAbsLogical(home) || home == "/" || !s.g.isDir(systemLoc(home)) {
			continue
		}
		out = append(out, platform.UserHome{Name: safeText(f[0], 64), UID: f[2], Home: home})
		if len(out) >= 256 {
			break
		}
	}
	return out
}

func (s *scanner) scanSystem() {
	s.led.root()
	s.detectSystem()
	s.scanManagedFacts()
	s.scanMCPFiles(nil, "")
	s.scanHookFiles(nil, "")
}

func (s *scanner) scanUser(uc *userCtx) {
	s.led.root()
	if !s.g.isDir(loc{root: uc.home, user: true, home: true}) {
		s.led.denied()
		s.led.note("home not accessible: " + uc.home)
		s.homeDenied = true
		return
	}
	s.detectUser(uc)
	s.scanExtensions(uc)
	s.scanMCPFiles(uc, "")
	s.scanHookFiles(uc, "")
	s.scanContent(uc, "")
	s.scanPlugins(uc)
	if s.o.Projects {
		for _, dir := range s.enumerateProjects(uc) {
			if !s.g.alive() {
				return
			}
			s.scanProject(uc, dir)
		}
	}
}

// scanProject inspects one project's control files.
func (s *scanner) scanProject(uc *userCtx, dir string) {
	key := uc.u.UID + "\x00" + strings.ToLower(dir)
	if s.projSeen[key] {
		return
	}
	s.projSeen[key] = true
	s.led.root()
	if !s.g.isDir(loc{root: dir, user: true}) {
		s.led.note("project directory not accessible: " + dir)
		return
	}
	s.scanMCPFiles(uc, dir)
	s.scanHookFiles(uc, dir)
	s.scanContent(uc, dir)
	s.scanProjectConfig(uc, dir)
	s.scanWorkflows(uc, dir)
}

// add records a declared item once per (kind, path, identity, owner).
func (s *scanner) add(r *record) {
	owner := ""
	if r.uc != nil {
		owner = r.uc.u.UID
	}
	k := string(r.a.Kind) + "\x00" + r.a.Path + "\x00" + r.a.Name + "\x00" + r.a.Parent + "\x00" + owner + "\x00" + r.a.Detail["project"] + "\x00" + r.a.Detail["handler"]
	if s.keys[k] {
		return
	}
	s.keys[k] = true
	s.recs = append(s.recs, r)
}

// doc reads and parses a config file once per scan.
func (s *scanner) doc(l loc, owner, syntax string) docResult {
	key := l.String() + "\x00" + owner + "\x00" + syntax
	if d, ok := s.docs[key]; ok {
		return d
	}
	data, meta, err := s.g.readFile(l, owner, maxConfigBytes)
	d := docResult{meta: meta, err: err}
	if err == nil {
		d.doc, d.err = decodeDoc(data, syntax)
		if d.err != nil {
			s.led.errored()
			s.led.note("could not parse " + homeRelNote(l) + ": " + d.err.Error())
		}
	}
	if s.docBytes+int64(len(data)) <= maxDocCacheBytes {
		s.docBytes += int64(len(data))
		s.docs[key] = d
	}
	return d
}
