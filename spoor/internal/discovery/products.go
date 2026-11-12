package discovery

import (
	"path"
	"sort"
	"strings"

	"github.com/thomastysong/spoor/internal/catalog"
	"github.com/thomastysong/spoor/internal/event"
)

// Package-manager install locations. All of them are read as files only:
// no package manager is ever run.
var (
	systemBinDirs = map[string][]string{
		"linux":  {"/usr/local/bin", "/usr/bin", "/bin", "/opt/homebrew/bin", "/home/linuxbrew/.linuxbrew/bin", "/snap/bin", "/opt/local/bin"},
		"darwin": {"/usr/local/bin", "/opt/homebrew/bin", "/usr/bin", "/opt/local/bin"},
	}
	userBinDirs = map[string][]string{
		"posix": {"~/.local/bin", "~/bin", "~/.cargo/bin", "~/go/bin", "~/.npm-global/bin", "~/.npm-packages/bin",
			"~/.bun/bin", "~/.deno/bin", "~/.volta/bin", "~/.yarn/bin", "~/.local/share/pnpm", "~/Library/pnpm",
			"~/.linuxbrew/bin", "~/.opencode/bin"},
		"windows": {"~/.local/bin", "%LOCALAPPDATA%/Microsoft/WinGet/Links", "~/scoop/shims", "%APPDATA%/npm",
			"~/.cargo/bin", "~/go/bin", "~/.bun/bin", "%LOCALAPPDATA%/pnpm"},
	}
	systemNpmRoots = map[string][]string{
		"posix":   {"/usr/local/lib/node_modules", "/opt/homebrew/lib/node_modules", "/usr/lib/node_modules", "/home/linuxbrew/.linuxbrew/lib/node_modules"},
		"windows": {"%ProgramFiles%/nodejs/node_modules"},
	}
	userNpmRoots = map[string][]string{
		"posix": {"~/.npm-global/lib/node_modules", "~/.npm-packages/lib/node_modules", "~/.local/lib/node_modules",
			"~/.nvm/versions/node/*/lib/node_modules", "~/.local/share/fnm/node-versions/*/installation/lib/node_modules",
			"~/Library/Application Support/fnm/node-versions/*/installation/lib/node_modules",
			"~/.volta/tools/image/packages/*/lib/node_modules", "~/.bun/install/global/node_modules",
			"~/.local/share/pnpm/global/5/node_modules", "~/Library/pnpm/global/5/node_modules",
			"~/.config/yarn/global/node_modules", "~/node_modules"},
		"windows": {"%APPDATA%/npm/node_modules", "%LOCALAPPDATA%/pnpm/global/5/node_modules", "~/.bun/install/global/node_modules"},
	}
	userPipxVenvs = map[string][]string{
		"posix":   {"~/.local/pipx/venvs", "~/.local/share/pipx/venvs"},
		"windows": {"~/pipx/venvs", "%LOCALAPPDATA%/pipx/pipx/venvs", "~/.local/pipx/venvs"},
	}
	userUVTools = map[string][]string{
		"posix":   {"~/.local/share/uv/tools"},
		"windows": {"%APPDATA%/uv/data/tools"},
	}
	systemCellars  = []string{"/opt/homebrew/Cellar", "/usr/local/Cellar", "/home/linuxbrew/.linuxbrew/Cellar"}
	systemCasks    = []string{"/opt/homebrew/Caskroom", "/usr/local/Caskroom"}
	systemDesktops = []string{"/usr/share/applications", "/usr/local/share/applications",
		"/var/lib/flatpak/exports/share/applications", "/var/lib/snapd/desktop/applications"}
	userDesktops = []string{"~/.local/share/applications", "~/.local/share/flatpak/exports/share/applications"}
)

func forOS(m map[string][]string, goos string) []string {
	if l, ok := m[goos]; ok {
		return l
	}
	if goos != "windows" {
		return m["posix"]
	}
	return nil
}

// indexPackages builds lookups from installed-package names to products.
func (s *scanner) indexPackages() {
	s.brew = map[string][]int{}
	s.shared = map[string]int{}
	for i := range s.products {
		p := &s.products[i]
		for _, pk := range p.Packages {
			mgr, name, ok := strings.Cut(pk, ":")
			if !ok {
				continue
			}
			switch mgr {
			case "brew", "cask":
				k := mgr + ":" + strings.ToLower(lastSegment(name))
				s.brew[k] = append(s.brew[k], i)
			}
		}
		for _, d := range p.StateDirs.For(s.goos) {
			s.shared[d]++
		}
	}
}

func lastSegment(name string) string {
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		return name[i+1:]
	}
	return name
}

func (s *scanner) ev(uc *userCtx, i int) *evidence {
	id := s.products[i].ID
	if uc == nil {
		e := s.sysEv[id]
		if e == nil {
			e = &evidence{}
			s.sysEv[id] = e
		}
		return e
	}
	m := s.userEv[uc]
	if m == nil {
		m = map[string]*evidence{}
		s.userEv[uc] = m
	}
	e := m[id]
	if e == nil {
		e = &evidence{}
		m[id] = e
	}
	return e
}

func (s *scanner) productByPackage(mgr, name string) (int, bool) {
	p, ok := s.cat.ByPackage(mgr, name)
	if !ok {
		return 0, false
	}
	i, ok := s.byID[p.ID]
	return i, ok && hostKind(&s.products[i])
}

// detectSystem gathers machine-wide install evidence.
func (s *scanner) detectSystem() {
	for _, d := range systemBinDirs[s.goos] {
		s.scanBinDir(d, nil)
	}
	for _, r := range forOS(systemNpmRoots, s.goos) {
		if e, ok := s.expand(r, nil); ok {
			s.scanNpmRoot(e, nil)
		}
	}
	if s.goos != "windows" {
		for _, c := range systemCellars {
			s.scanCellar(c, "brew", nil)
		}
		for _, c := range systemCasks {
			s.scanCellar(c, "cask", nil)
		}
	}
	switch s.goos {
	case "darwin":
		s.scanApps("/Applications", nil)
	case "linux":
		for _, d := range systemDesktops {
			s.scanDesktopDir(d, nil)
		}
	case "windows":
		s.scanRegistry(nil)
	}
	for i := range s.products {
		p := &s.products[i]
		if !hostKind(p) {
			continue
		}
		for _, ip := range p.InstallPaths.For(s.goos) {
			if isHomePath(ip) {
				continue
			}
			if e, ok := s.expand(ip, nil); ok {
				s.installPath(i, e, ip, nil)
			}
		}
		for _, sd := range p.StateDirs.For(s.goos) {
			if isHomePath(sd) {
				continue
			}
			if e, ok := s.expand(sd, nil); ok && s.g.isDir(systemLoc(e)) {
				ev := s.ev(nil, i)
				ev.add(evStateDir, s.shared[sd] > 1)
				ev.setPath(e, rankState)
			}
		}
	}
}

// detectUser gathers per-user install evidence.
func (s *scanner) detectUser(uc *userCtx) {
	for _, d := range forOS(userBinDirs, s.goos) {
		if e, ok := s.expand(d, uc); ok {
			s.scanBinDir(e, uc)
		}
	}
	for _, r := range forOS(userNpmRoots, s.goos) {
		e, ok := s.expand(r, uc)
		if !ok {
			continue
		}
		for _, root := range s.glob(e, uc, "", 64) {
			s.scanNpmRoot(root, uc)
		}
	}
	for _, r := range forOS(userPipxVenvs, s.goos) {
		if e, ok := s.expand(r, uc); ok {
			s.scanPipx(e, uc)
		}
	}
	for _, r := range forOS(userUVTools, s.goos) {
		if e, ok := s.expand(r, uc); ok {
			s.scanUVTools(e, uc)
		}
	}
	switch s.goos {
	case "darwin":
		if e, ok := s.expand("~/Applications", uc); ok {
			s.scanApps(e, uc)
		}
	case "linux":
		if e, ok := s.expand("~/.linuxbrew/Cellar", uc); ok {
			s.scanCellar(e, "brew", uc)
		}
		for _, d := range userDesktops {
			if e, ok := s.expand(d, uc); ok {
				s.scanDesktopDir(e, uc)
			}
		}
	case "windows":
		s.scanRegistry(uc)
	}
	for i := range s.products {
		p := &s.products[i]
		if !hostKind(p) {
			continue
		}
		for _, ip := range p.InstallPaths.For(s.goos) {
			if !isHomePath(ip) {
				continue
			}
			if e, ok := s.expand(ip, uc); ok {
				s.installPath(i, e, ip, uc)
			}
		}
		for _, sd := range p.StateDirs.For(s.goos) {
			if !isHomePath(sd) {
				continue
			}
			e, ok := s.expand(sd, uc)
			if !ok {
				continue
			}
			if s.g.isDir(s.locFor(e, uc, "")) {
				ev := s.ev(uc, i)
				ev.add(evStateDir, s.shared[sd] > 1)
				ev.setPath(e, rankState)
			}
		}
	}
}

// installPath records a catalogued install location (possibly a glob such
// as ~/.local/share/claude/versions/*).
func (s *scanner) installPath(i int, expanded, raw string, uc *userCtx) {
	matches := s.glob(expanded, uc, "", 64)
	if len(matches) == 0 {
		return
	}
	ev := s.ev(uc, i)
	ev.add(evPath, false)
	best := matches[0]
	if strings.HasSuffix(raw, "/*") {
		// A version layout: the newest version directory is the install.
		for _, m := range matches {
			if versionLike(baseName(m)) && (!versionLike(baseName(best)) || compareVersions(baseName(m), baseName(best)) > 0) {
				best = m
			}
		}
		if versionLike(baseName(best)) {
			ev.setVersion(baseName(best), vrankLayout)
		}
	}
	ev.setPath(best, rankInstall)
	if s.goos == "darwin" && strings.HasSuffix(strings.ToLower(best), ".app") {
		if id, ver := s.bundleInfo(best, uc); id != "" {
			if p, ok := s.cat.ByBundleID(id); ok && p.ID == s.products[i].ID {
				ev.add(evBundleID, false)
			}
			ev.setVersion(ver, vrankManifest)
		}
	}
}

// binaryNames maps executable basenames to products, built once.
func (s *scanner) binaryNames() map[string][]int {
	if s.binNames != nil {
		return s.binNames
	}
	m := map[string][]int{}
	for i := range s.products {
		p := &s.products[i]
		if !hostKind(p) {
			continue
		}
		for _, b := range p.Binaries {
			m[b] = append(m[b], i)
		}
	}
	s.binNames = m
	return m
}

// scanBinDir looks up every catalogued binary name in one directory. Names
// are looked up rather than listed: /usr/bin can hold more entries than the
// listing cap, and lookups cost one fstatat each.
func (s *scanner) scanBinDir(dir string, uc *userCtx) {
	if !s.g.isDir(s.locFor(dir, uc, "")) {
		return
	}
	names := s.binaryNames()
	for _, name := range sortedKeys(names) {
		if !s.g.alive() {
			return
		}
		cands := []string{name}
		if s.goos == "windows" {
			cands = []string{name + ".exe", name + ".cmd"}
		}
		for _, c := range cands {
			full := joinLogical(dir, c)
			l := s.locFor(full, uc, "")
			m, err := s.g.stat(l)
			if err != nil || (m.kind != kindRegular && m.kind != kindSymlink) {
				continue
			}
			for _, i := range names[name] {
				s.binaryHit(i, name, full, l, m, uc)
			}
			break
		}
	}
}

func (s *scanner) binaryHit(i int, name, full string, l loc, m fmeta, uc *userCtx) {
	ev := s.ev(uc, i)
	ev.add(evBinary, s.cat.IsAmbiguousName(name))
	ev.setPath(full, rankBinary)
	if m.kind != kindSymlink {
		return
	}
	target, err := s.g.readlink(l)
	if err != nil || target == "" {
		return
	}
	t := cleanLogical(target)
	if !isAbsLogical(t) {
		t = cleanLogical(joinLogical(dirName(full), target))
	}
	// A link in a user's bin directory may point anywhere; only targets in
	// the same tree are read (a link into /etc is not a package).
	if uc != nil {
		if _, ok := relLogical(uc.home, t, s.goos); !ok {
			return
		}
	}
	if pkg, root := npmPackageOf(t); pkg != "" {
		if j, ok := s.productByPackage("npm", pkg); ok && j == i {
			ev.add(evPackage+"npm", false)
			ev.setPath(joinLogical(root, pkg), rankPackage)
			s.npmVersion(ev, joinLogical(root, pkg), pkg, uc)
		}
		return
	}
	// Native installers keep one directory (or file) per version and link
	// the binary to the current one.
	for _, c := range []string{baseName(t), baseName(dirName(t))} {
		if versionLike(c) {
			ev.setVersion(c, vrankLayout)
			ev.setPath(t, rankInstall)
			ev.add(evPath, false)
			break
		}
	}
}

// npmPackageOf extracts "<name>" or "@scope/name" after the last
// node_modules element of a path, with the node_modules directory.
func npmPackageOf(p string) (pkg, root string) {
	i := strings.LastIndex(p, "/node_modules/")
	if i < 0 {
		return "", ""
	}
	root = p[:i+len("/node_modules")]
	rest := strings.Split(p[i+len("/node_modules/"):], "/")
	if len(rest) == 0 || rest[0] == "" {
		return "", ""
	}
	if strings.HasPrefix(rest[0], "@") {
		if len(rest) < 2 || rest[1] == "" {
			return "", ""
		}
		return rest[0] + "/" + rest[1], root
	}
	return rest[0], root
}

func (s *scanner) npmVersion(ev *evidence, dir, pkg string, uc *userCtx) {
	l := s.locFor(joinLogical(dir, "package.json"), uc, "")
	d := s.doc(l, ownerFor(l, uc), "json")
	if d.err != nil || d.doc == nil {
		return
	}
	if getString(d.doc, "name") != pkg {
		return
	}
	ev.setVersion(getString(d.doc, "version"), vrankManifest)
}

// npmScopes lists the scopes of catalogued npm packages, so a node_modules
// directory is only descended into scopes that can matter.
func (s *scanner) npmScopes() map[string]bool {
	out := map[string]bool{}
	for i := range s.products {
		for _, pk := range s.products[i].Packages {
			mgr, name, _ := strings.Cut(pk, ":")
			if (mgr == "npm" || mgr == "pnpm" || mgr == "yarn" || mgr == "bun") && strings.HasPrefix(name, "@") {
				if sc, _, ok := strings.Cut(name, "/"); ok {
					out[strings.ToLower(sc)] = true
				}
			}
		}
	}
	return out
}

func (s *scanner) scanNpmRoot(root string, uc *userCtx) {
	ents, err := s.g.readDir(s.locFor(root, uc, ""))
	if err != nil {
		return
	}
	scopes := s.npmScopes()
	var names []string
	for _, e := range ents {
		if e.kind != kindDir {
			continue
		}
		if strings.HasPrefix(e.name, "@") {
			if !scopes[strings.ToLower(e.name)] {
				continue
			}
			sub, err := s.g.readDir(s.locFor(joinLogical(root, e.name), uc, ""))
			if err != nil {
				continue
			}
			for _, x := range sub {
				if x.kind == kindDir {
					names = append(names, e.name+"/"+x.name)
				}
			}
			continue
		}
		names = append(names, e.name)
	}
	for _, n := range names {
		i, ok := s.productByPackage("npm", n)
		if !ok {
			continue
		}
		ev := s.ev(uc, i)
		ev.add(evPackage+"npm", false)
		ev.setPath(joinLogical(root, n), rankPackage)
		s.npmVersion(ev, joinLogical(root, n), n, uc)
	}
}

func (s *scanner) scanPipx(venvs string, uc *userCtx) {
	ents, err := s.g.readDir(s.locFor(venvs, uc, ""))
	if err != nil {
		return
	}
	for _, e := range ents {
		if e.kind != kindDir {
			continue
		}
		i, ok := s.productByPackage("pipx", e.name)
		if !ok {
			continue
		}
		dir := joinLogical(venvs, e.name)
		ev := s.ev(uc, i)
		ev.add(evPackage+"pipx", false)
		ev.setPath(dir, rankPackage)
		l := s.locFor(joinLogical(dir, "pipx_metadata.json"), uc, "")
		if d := s.doc(l, ownerFor(l, uc), "json"); d.err == nil {
			if pep503(getString(d.doc, "main_package", "package")) == pep503(e.name) {
				ev.setVersion(getString(d.doc, "main_package", "package_version"), vrankManifest)
			}
		}
	}
}

func (s *scanner) scanUVTools(tools string, uc *userCtx) {
	ents, err := s.g.readDir(s.locFor(tools, uc, ""))
	if err != nil {
		return
	}
	for _, e := range ents {
		if e.kind != kindDir {
			continue
		}
		i, ok := s.productByPackage("uv", e.name)
		if !ok {
			continue
		}
		dir := joinLogical(tools, e.name)
		ev := s.ev(uc, i)
		ev.add(evPackage+"uv", false)
		ev.setPath(dir, rankPackage)
		if v := s.distInfoVersion(dir, e.name, uc); v != "" {
			ev.setVersion(v, vrankManifest)
		}
	}
}

// distInfoVersion finds "<name>-<version>.dist-info" in a venv.
func (s *scanner) distInfoVersion(venv, name string, uc *userCtx) string {
	want := strings.ReplaceAll(pep503(name), "-", "_")
	var sites []string
	if s.goos == "windows" {
		sites = []string{joinLogical(venv, "Lib/site-packages")}
	} else {
		for _, py := range s.glob(joinLogical(venv, "lib/python*"), uc, "", 8) {
			sites = append(sites, joinLogical(py, "site-packages"))
		}
	}
	for _, site := range sites {
		ents, err := s.g.readDir(s.locFor(site, uc, ""))
		if err != nil {
			continue
		}
		for _, e := range ents {
			n := strings.ToLower(e.name)
			if e.kind != kindDir || !strings.HasSuffix(n, ".dist-info") {
				continue
			}
			base := strings.TrimSuffix(n, ".dist-info")
			if dn, ver, ok := strings.Cut(base, "-"); ok && strings.ReplaceAll(pep503(dn), "-", "_") == want {
				return ver
			}
		}
	}
	return ""
}

// scanCellar reads Homebrew's Cellar (formulae) or Caskroom (casks).
func (s *scanner) scanCellar(dir, mgr string, uc *userCtx) {
	ents, err := s.g.readDir(s.locFor(dir, uc, ""))
	if err != nil {
		return
	}
	for _, e := range ents {
		if e.kind != kindDir {
			continue
		}
		for _, i := range s.brew[mgr+":"+strings.ToLower(e.name)] {
			if !hostKind(&s.products[i]) {
				continue
			}
			pdir := joinLogical(dir, e.name)
			ev := s.ev(uc, i)
			ev.add(evPackage+mgr, false)
			ev.setPath(pdir, rankPackage)
			if vers, err := s.g.readDir(s.locFor(pdir, uc, "")); err == nil {
				best := ""
				for _, v := range vers {
					if v.kind == kindDir && versionLike(v.name) && (best == "" || compareVersions(v.name, best) > 0) {
						best = v.name
					}
				}
				ev.setVersion(best, vrankCellar)
			}
		}
	}
}

// bundleInfo reads an app bundle's identifier and version.
func (s *scanner) bundleInfo(app string, uc *userCtx) (id, version string) {
	l := s.locFor(joinLogical(app, "Contents/Info.plist"), uc, "")
	d := s.doc(l, ownerFor(l, uc), "plist")
	if d.err != nil {
		return "", ""
	}
	id = getString(d.doc, "CFBundleIdentifier")
	version = getString(d.doc, "CFBundleShortVersionString")
	if version == "" {
		version = getString(d.doc, "CFBundleVersion")
	}
	return id, version
}

func (s *scanner) scanApps(dir string, uc *userCtx) {
	ents, err := s.g.readDir(s.locFor(dir, uc, ""))
	if err != nil {
		return
	}
	for _, e := range ents {
		if e.kind != kindDir || !strings.HasSuffix(strings.ToLower(e.name), ".app") {
			continue
		}
		app := joinLogical(dir, e.name)
		id, ver := s.bundleInfo(app, uc)
		if id == "" {
			continue
		}
		p, ok := s.cat.ByBundleID(id)
		if !ok {
			continue
		}
		i, ok := s.byID[p.ID]
		if !ok || !hostKind(&s.products[i]) {
			continue
		}
		ev := s.ev(uc, i)
		ev.add(evBundleID, false)
		ev.setPath(app, rankPackage)
		ev.setVersion(ver, vrankManifest)
	}
}

func (s *scanner) scanDesktopDir(dir string, uc *userCtx) {
	ents, err := s.g.readDir(s.locFor(dir, uc, ""))
	if err != nil {
		return
	}
	for _, e := range ents {
		if (e.kind != kindRegular && e.kind != kindSymlink) || !strings.HasSuffix(e.name, ".desktop") {
			continue
		}
		id := strings.TrimSuffix(e.name, ".desktop")
		p, ok := s.cat.ByDesktopID(id)
		if !ok {
			continue
		}
		i, ok := s.byID[p.ID]
		if !ok || !hostKind(&s.products[i]) {
			continue
		}
		ev := s.ev(uc, i)
		ev.add(evDesktopID, false)
		ev.setPath(joinLogical(dir, e.name), rankBinary)
	}
}

// scanRegistry reads Windows Uninstall keys (machine-wide for uc nil, the
// user's hive otherwise).
func (s *scanner) scanRegistry(uc *userCtx) {
	sid := ""
	if uc != nil {
		sid = uc.u.UID
	}
	for _, w := range windowsInstalls(sid) {
		p, ok := s.cat.ByWinDisplay(w.display)
		if !ok {
			continue
		}
		i, ok := s.byID[p.ID]
		if !ok || !hostKind(&s.products[i]) {
			continue
		}
		ev := s.ev(uc, i)
		ev.add(evRegistry, false)
		ev.setVersion(w.version, vrankManifest)
		if loc := cleanLogical(w.location); isAbsLogical(loc) {
			ev.setPath(loc, rankPackage)
		}
	}
}

// procHit is one running process of a product.
type procHit struct {
	pid  int
	user string // account name the process table reported ("" when unknown)
}

// procIndex maps product id -> uid -> matching processes.
type procIndex map[string]map[string][]procHit

func (s *scanner) indexProcesses() {
	s.procs = procIndex{}
	for _, p := range s.o.Processes {
		m, ok := s.cat.MatchProcessDetail(p.Name, p.Exe, p.Args)
		if !ok {
			continue
		}
		byUID := s.procs[m.Product.ID]
		if byUID == nil {
			byUID = map[string][]procHit{}
			s.procs[m.Product.ID] = byUID
		}
		byUID[p.UID] = append(byUID[p.UID], procHit{pid: p.PID, user: p.User})
	}
}

// buildProducts turns evidence into agent/app/runtime assets: one per user
// who has the product, plus one machine-wide asset when it is installed but
// nobody's home shows it.
func (s *scanner) buildProducts() {
	// Several scanned homes can share a uid (a home directory without a
	// passwd entry is reported with its owner's uid; containers often run
	// everyone as root). A process is then attributed by account name, and
	// one that matches none of them is reported machine-wide instead of
	// marking every such home as running it.
	homesByUID := map[string]map[string]bool{}
	for _, uc := range s.users {
		if homesByUID[uc.u.UID] == nil {
			homesByUID[uc.u.UID] = map[string]bool{}
		}
		homesByUID[uc.u.UID][uc.u.Name] = true
	}
	pidsFor := func(id string, uc *userCtx) []int {
		var out []int
		shared := len(homesByUID[uc.u.UID]) > 1
		for _, h := range s.procs[id][uc.u.UID] {
			if !shared || h.user == uc.u.Name {
				out = append(out, h.pid)
			}
		}
		return out
	}
	for i := range s.products {
		p := &s.products[i]
		if !hostKind(p) {
			continue
		}
		sysE := s.sysEv[p.ID]
		emitted := false
		for _, uc := range s.users {
			ue := s.userEv[uc][p.ID]
			pids := pidsFor(p.ID, uc)
			if ue.empty() && len(pids) == 0 {
				continue
			}
			e := mergeEvidence(sysE, ue)
			if len(pids) > 0 {
				e.add(evProcess, false)
				e.pids = append(e.pids, pids...)
			}
			if !e.qualifies() {
				continue
			}
			s.addProduct(i, e, uc)
			emitted = true
		}
		var orphan []int
		for uid, hits := range s.procs[p.ID] {
			homes := homesByUID[uid]
			for _, h := range hits {
				if len(homes) == 0 || len(homes) > 1 && !homes[h.user] {
					orphan = append(orphan, h.pid)
				}
			}
		}
		if emitted && len(orphan) == 0 {
			continue
		}
		e := mergeEvidence(sysE)
		if len(orphan) > 0 {
			e.add(evProcess, false)
			e.pids = append(e.pids, orphan...)
		}
		if !emitted && e.qualifies() || emitted && len(orphan) > 0 {
			s.addProduct(i, e, nil)
		}
	}
}

func (s *scanner) addProduct(i int, e *evidence, uc *userCtx) {
	p := &s.products[i]
	a := &event.Asset{
		Kind:       event.AssetKind(p.Kind),
		Name:       p.Name,
		Vendor:     p.Vendor,
		Version:    e.version,
		CatalogID:  p.ID,
		Path:       safeText(e.path, 1024),
		Evidence:   e.list(),
		Confidence: e.confidence(),
		Scope:      event.ScopeSystem,
	}
	if uc != nil {
		a.Scope = event.ScopeUser
		a.Owner = uc.u.Name
	}
	if len(e.pids) > 0 {
		sort.Ints(e.pids)
		a.Running, a.PID = true, e.pids[0]
	}
	if p.Status == catalog.StatusDeprecated || p.Status == catalog.StatusDiscontinued {
		a.Detail = map[string]string{"status": p.Status}
	}
	flags := flagSet{}
	if mf := s.managed[p.ID]; mf != nil {
		flags.add(mf.flags...)
	}
	if uc != nil {
		user := s.settingsFlags(i, uc)
		flags.add(user...)
		disabled := false
		for _, f := range user {
			disabled = disabled || f == "hooks_disabled"
		}
		a.Telemetry = s.telemetry(i, uc, disabled)
	}
	a.RiskFlags = flags.list()
	s.recs = append(s.recs, &record{a: a, uc: uc})
}

func pathExt(p string) string { return strings.ToLower(path.Ext(p)) }
