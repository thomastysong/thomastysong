package catalog

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// snapshot is one immutable, fully indexed state of the catalog.
type snapshot struct {
	version  string
	products []Product
	// source is what the snapshot was built from, kept so LoadOverlay can
	// layer on top of it.
	source *state

	byID       map[string]int
	byAlias    map[string][]int
	byExe      map[string][]int
	byExe15    map[string][]int // first 15 bytes of longer names (Linux comm)
	byPackage  map[string][]int
	byBundle   map[string][]int
	byExt      map[string][]int
	byJB       map[string][]int
	byChrome   map[string][]int
	byDesktop  map[string][]int
	byAppx     map[string][]int
	byPort     map[int][]int
	byEnv      map[string][]int
	byHost     map[string][]int
	winDisplay []winPattern

	ambiguous    map[string]bool
	interpreters map[string]string
	matchers     []procMatcher
}

type winPattern struct {
	pattern string // lowercased
	idx     int
}

// procMatcher is the precompiled process evidence for one product.
type procMatcher struct {
	args     []*regexp.Regexp
	paths    []*regexp.Regexp
	pkgPaths []string          // lowercased path fragments that only this product's packages produce
	pkgByEco map[string]string // ecosystem -> set marker, to know which interpreters corroborate a script name
	ociRefs  []string          // lowercased image references
}

// build validates the accumulated state and indexes it.
func (st *state) build() (*snapshot, error) {
	l := &errList{}
	if st.version == "" {
		l.addf("catalog: no data file sets a version")
	} else if !versionRe.MatchString(st.version) {
		l.addf("catalog: version %q is malformed", st.version)
	}
	for i := range st.products {
		validateProduct(&st.products[i], l)
	}
	for name, eco := range st.interpreters {
		if eco != "npm" && eco != "pypi" {
			l.addf("catalog: interpreter %q: ecosystem %q must be npm or pypi", name, eco)
		}
	}
	if err := l.err(); err != nil {
		return nil, err
	}
	validateClaims(st.products, l)
	if err := l.err(); err != nil {
		return nil, err
	}

	s := &snapshot{
		version:      st.version,
		products:     st.products,
		source:       st,
		byID:         map[string]int{},
		byAlias:      map[string][]int{},
		byExe:        map[string][]int{},
		byExe15:      map[string][]int{},
		byPackage:    map[string][]int{},
		byBundle:     map[string][]int{},
		byExt:        map[string][]int{},
		byJB:         map[string][]int{},
		byChrome:     map[string][]int{},
		byDesktop:    map[string][]int{},
		byAppx:       map[string][]int{},
		byPort:       map[int][]int{},
		byEnv:        map[string][]int{},
		byHost:       map[string][]int{},
		ambiguous:    map[string]bool{},
		interpreters: st.interpreters,
		matchers:     make([]procMatcher, len(st.products)),
	}
	if st.overlay != "" {
		// The suffix lets a fleet query spot hosts whose catalog differs
		// from the shipped one, and tell two different overlays apart.
		s.version = st.version + "+overlay." + st.overlay
	}
	for _, n := range st.ambiguous {
		s.ambiguous[exeKey(n)] = true
	}
	for i := range st.products {
		p := &st.products[i]
		s.byID[p.ID] = i
		for _, a := range p.Aliases {
			addIdx(s.byAlias, strings.ToLower(a), i)
		}
		for _, list := range [][]string{p.Binaries, p.ProcessNames} {
			for _, n := range list {
				k := exeKey(n)
				addIdx(s.byExe, k, i)
				if len(k) > 15 {
					addIdx(s.byExe15, k[:15], i)
				}
			}
		}
		for _, pkg := range p.Packages {
			addIdx(s.byPackage, packageKey(pkg), i)
		}
		for _, v := range p.BundleIDs {
			addIdx(s.byBundle, strings.ToLower(v), i)
		}
		for _, v := range p.ExtensionIDs {
			addIdx(s.byExt, strings.ToLower(v), i)
		}
		for _, v := range p.JetBrainsIDs {
			addIdx(s.byJB, strings.ToLower(v), i)
		}
		for _, v := range p.ChromeIDs {
			addIdx(s.byChrome, v, i)
		}
		for _, v := range p.DesktopIDs {
			addIdx(s.byDesktop, strings.ToLower(v), i)
		}
		for _, v := range p.Appx {
			addIdx(s.byAppx, strings.ToLower(v), i)
		}
		for _, v := range p.Ports {
			s.byPort[v] = appendUnique(s.byPort[v], i)
		}
		for _, v := range p.MarkerEnv() {
			addIdx(s.byEnv, v, i)
		}
		for _, v := range p.APIHosts {
			addIdx(s.byHost, v, i)
		}
		for _, v := range p.WinDisplay {
			s.winDisplay = append(s.winDisplay, winPattern{strings.ToLower(v), i})
		}
		m, err := compileMatcher(p)
		if err != nil {
			return nil, fmt.Errorf("catalog: product %q: %w", p.ID, err)
		}
		s.matchers[i] = m
	}
	// Longest pattern first, so "Antigravity IDE" wins over "Antigravity".
	sort.SliceStable(s.winDisplay, func(a, b int) bool {
		return len(s.winDisplay[a].pattern) > len(s.winDisplay[b].pattern)
	})
	return s, nil
}

func addIdx(m map[string][]int, k string, i int) { m[k] = appendUnique(m[k], i) }

func appendUnique(l []int, i int) []int {
	for _, v := range l {
		if v == i {
			return l
		}
	}
	return append(l, i)
}

func compileMatcher(p *Product) (procMatcher, error) {
	m := procMatcher{pkgByEco: map[string]string{}}
	for _, pat := range p.ProcessArgs {
		re, err := regexp.Compile(pat)
		if err != nil {
			return m, fmt.Errorf("process_args %q: %w", pat, err)
		}
		m.args = append(m.args, re)
	}
	seen := map[string]bool{}
	for _, op := range p.InstallPaths.all() {
		if seen[op.path] {
			continue
		}
		seen[op.path] = true
		re, err := installPathRegexp(op.path)
		if err != nil {
			return m, fmt.Errorf("install_paths %q: %w", op.path, err)
		}
		m.paths = append(m.paths, re)
	}
	for _, pkg := range p.Packages {
		mgr, name, _ := strings.Cut(pkg, ":")
		eco := managerCanon[mgr]
		m.pkgByEco[eco] = name
		lower := strings.ToLower(name)
		switch eco {
		case "npm":
			m.pkgPaths = append(m.pkgPaths, "/node_modules/"+lower+"/")
		case "pypi":
			norm := pep503(lower)
			m.pkgPaths = append(m.pkgPaths,
				"/site-packages/"+strings.ReplaceAll(norm, "-", "_")+"/",
				"/pipx/venvs/"+norm+"/",
				"/uv/tools/"+norm+"/")
		case "brew":
			// A tapped formula ("org/tap/name") still installs to Cellar/name.
			m.pkgPaths = append(m.pkgPaths, "/cellar/"+lower[strings.LastIndexByte(lower, '/')+1:]+"/")
		case "cask":
			m.pkgPaths = append(m.pkgPaths, "/caskroom/"+lower+"/")
		case "scoop":
			m.pkgPaths = append(m.pkgPaths, "/scoop/apps/"+lower+"/")
		case "choco":
			m.pkgPaths = append(m.pkgPaths, "/chocolatey/lib/"+lower+"/")
		case "winget":
			// Portable WinGet packages unpack to
			// ...\WinGet\Packages\<Id>_<source>\.
			m.pkgPaths = append(m.pkgPaths, "/winget/packages/"+lower+"_")
		case "snap":
			m.pkgPaths = append(m.pkgPaths, "/snap/"+lower+"/")
		case "flatpak":
			m.pkgPaths = append(m.pkgPaths, "/flatpak/app/"+lower+"/")
		case "oci":
			m.ociRefs = append(m.ociRefs, lower)
		}
	}
	return m, nil
}

// Version returns the catalog data version, with an "+overlay.<digest>"
// suffix when overlay files are loaded.
func (c *Catalog) Version() string { return c.snap.Load().version }

// Products returns a copy of every product in catalog order.
func (c *Catalog) Products() []Product {
	s := c.snap.Load()
	out := make([]Product, len(s.products))
	for i := range s.products {
		out[i] = s.products[i].clone()
	}
	return out
}

// Len returns the number of products.
func (c *Catalog) Len() int { return len(c.snap.Load().products) }

// Get returns the product with exactly this id.
func (c *Catalog) Get(id string) (Product, bool) {
	s := c.snap.Load()
	if i, ok := s.byID[id]; ok {
		return s.products[i].clone(), true
	}
	return Product{}, false
}

// Resolve finds a product by id or, failing that, by a former name listed in
// Aliases (case-insensitive). An alias that several products carry does not
// resolve: a rename has exactly one successor.
func (c *Catalog) Resolve(nameOrID string) (Product, bool) {
	s := c.snap.Load()
	if i, ok := s.byID[nameOrID]; ok {
		return s.products[i].clone(), true
	}
	key := strings.ToLower(strings.TrimSpace(nameOrID))
	if i, ok := s.byID[key]; ok {
		return s.products[i].clone(), true
	}
	if l := s.byAlias[key]; len(l) == 1 {
		return s.products[l[0]].clone(), true
	}
	return Product{}, false
}

// ByBinary returns every product that lists the name (basename, with or
// without ".exe", any case) as a binary or process name. Several products
// can share a name; use MatchProcess to choose between them.
func (c *Catalog) ByBinary(name string) []Product {
	s := c.snap.Load()
	return s.many(s.byExe[exeKey(name)])
}

// ByBundleID returns the product owning a macOS bundle identifier.
func (c *Catalog) ByBundleID(id string) (Product, bool) {
	s := c.snap.Load()
	return s.first(s.byBundle[strings.ToLower(id)])
}

// ByExtensionID returns the product owning a VS Code family extension id
// ("publisher.name", any case).
func (c *Catalog) ByExtensionID(id string) (Product, bool) {
	s := c.snap.Load()
	return s.first(s.byExt[strings.ToLower(id)])
}

// ByJetBrainsID returns the product owning a JetBrains plugin id.
func (c *Catalog) ByJetBrainsID(id string) (Product, bool) {
	s := c.snap.Load()
	return s.first(s.byJB[strings.ToLower(id)])
}

// ByChromeID returns the product owning a Chromium extension id.
func (c *Catalog) ByChromeID(id string) (Product, bool) {
	s := c.snap.Load()
	return s.first(s.byChrome[id])
}

// ByDesktopID returns the product owning a Linux .desktop id (with or
// without the ".desktop" suffix).
func (c *Catalog) ByDesktopID(id string) (Product, bool) {
	s := c.snap.Load()
	return s.first(s.byDesktop[strings.TrimSuffix(strings.ToLower(id), ".desktop")])
}

// ByAppx returns the product owning an AppX/MSIX package. It accepts a
// package name ("Microsoft.Copilot"), a family name
// ("Microsoft.Copilot_8wekyb3d8bbwe") or a full name with version.
func (c *Catalog) ByAppx(name string) (Product, bool) {
	s := c.snap.Load()
	key := strings.ToLower(name)
	if p, ok := s.first(s.byAppx[key]); ok {
		return p, true
	}
	if i := strings.IndexByte(key, '_'); i > 0 {
		if p, ok := s.first(s.byAppx[key[:i]]); ok {
			return p, true
		}
		// Family name: <name>_<publisher hash>, from a full name
		// <name>_<version>_<arch>_<resource>_<publisher hash>.
		if j := strings.LastIndexByte(key, '_'); j > i {
			return s.first(s.byAppx[key[:i]+key[j:]])
		}
	}
	return Product{}, false
}

// ByPackage returns the product installed by a package. Managers that share
// an ecosystem are interchangeable (pip, pipx and uv all name PyPI projects).
func (c *Catalog) ByPackage(mgr, name string) (Product, bool) {
	s := c.snap.Load()
	return s.first(s.byPackage[packageKeyParts(mgr, name)])
}

// ByWinDisplay returns the product whose DisplayName pattern occurs in a
// registry Uninstall display name. Patterns match case-insensitively and
// only on word boundaries: "Dia" must not match "NVIDIA Control Panel".
func (c *Catalog) ByWinDisplay(displayName string) (Product, bool) {
	s := c.snap.Load()
	if len(displayName) > maxStringLen {
		displayName = displayName[:maxStringLen]
	}
	hay := strings.ToLower(displayName)
	for _, wp := range s.winDisplay {
		if containsWord(hay, wp.pattern) {
			return s.products[wp.idx].clone(), true
		}
	}
	return Product{}, false
}

// ByPort returns the products whose default listening port this is. A port
// is corroboration only; never report a runtime from a port alone.
func (c *Catalog) ByPort(port int) []Product {
	s := c.snap.Load()
	return s.many(s.byPort[port])
}

// ByEnvMarker returns the products that set an environment variable for
// their child processes (EnvMarkers and SessionEnv).
func (c *Catalog) ByEnvMarker(name string) []Product {
	s := c.snap.Load()
	return s.many(s.byEnv[name])
}

// ByAPIHost returns the products known to talk to a host. Entries written
// as "*.example.com" match any subdomain.
func (c *Catalog) ByAPIHost(host string) []Product {
	s := c.snap.Load()
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	idx := append([]int(nil), s.byHost[host]...)
	for rest := host; ; {
		i := strings.IndexByte(rest, '.')
		if i < 0 {
			break
		}
		rest = rest[i+1:]
		for _, j := range s.byHost["*."+rest] {
			idx = appendUnique(idx, j)
		}
	}
	return s.many(idx)
}

// IsAmbiguousName reports whether a process name needs a second class of
// evidence before it identifies anything.
func (c *Catalog) IsAmbiguousName(name string) bool {
	return c.snap.Load().isAmbiguous(exeKey(name))
}

func (s *snapshot) isAmbiguous(key string) bool {
	return len(key) <= 2 || s.ambiguous[key]
}

func (s *snapshot) first(idx []int) (Product, bool) {
	if len(idx) == 0 {
		return Product{}, false
	}
	return s.products[idx[0]].clone(), true
}

func (s *snapshot) many(idx []int) []Product {
	if len(idx) == 0 {
		return nil
	}
	out := make([]Product, len(idx))
	for i, j := range idx {
		out[i] = s.products[j].clone()
	}
	return out
}

// containsWord reports whether want occurs in hay delimited by
// non-alphanumeric bytes or the string edges. Both must be lowercased.
func containsWord(hay, want string) bool {
	if want == "" {
		return false
	}
	for from := 0; from+len(want) <= len(hay); {
		i := strings.Index(hay[from:], want)
		if i < 0 {
			return false
		}
		i += from
		before := i == 0 || !isAlnum(hay[i-1])
		after := i+len(want) == len(hay) || !isAlnum(hay[i+len(want)])
		if before && after {
			return true
		}
		from = i + 1
	}
	return false
}

func isAlnum(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// exeKey normalizes a process or binary name for lookup: basename, lower
// case, no ".exe", no Electron helper suffix such as " (Renderer)".
func exeKey(name string) string {
	if len(name) > maxStringLen {
		name = name[:maxStringLen]
	}
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	name = strings.ToLower(strings.TrimSpace(name))
	name = strings.TrimSuffix(name, ".exe")
	if strings.HasSuffix(name, ")") {
		if i := strings.LastIndex(name, " ("); i > 0 {
			name = name[:i]
		}
	}
	return name
}
