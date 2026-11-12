package discovery

import (
	"archive/zip"
	"encoding/xml"
	"io"
	"sort"
	"strings"

	"github.com/thomastysong/spoor/internal/catalog"
	"github.com/thomastysong/spoor/internal/event"
)

// extraEditorDirs are VS Code-family extension directories of forks the
// catalog lists without a plugins entry, and of remote/server installs.
// Each maps to the catalog id of the editor that owns it.
var extraEditorDirs = map[string]string{
	"~/.vscode-server-insiders/extensions": "vscode-insiders",
	"~/.cursor-server/extensions":          "cursor",
	"~/.windsurf/extensions":               "devin-desktop",
	"~/.windsurf-server/extensions":        "devin-desktop",
	"~/.kiro/extensions":                   "kiro",
	"~/.antigravity/extensions":            "antigravity",
	"~/.positron/extensions":               "",
}

const (
	maxJarSize      = 64 << 20
	maxJarsPerPlug  = 64
	maxPluginXML    = 1 << 20
	maxExtPerEditor = 2000
)

// editorExtensionDirs returns (dir, owning editor id) for a user.
func (s *scanner) editorExtensionDirs(uc *userCtx) [][2]string {
	seen := map[string]bool{}
	var out [][2]string
	for i := range s.products {
		p := &s.products[i]
		if p.Kind != string(event.AssetApp) {
			continue
		}
		for _, e := range p.Plugins {
			d, ok := s.expand(e, uc)
			if !ok || baseName(d) != "extensions" || seen[d] {
				continue
			}
			seen[d] = true
			out = append(out, [2]string{d, p.ID})
		}
	}
	for _, e := range sortedKeys(extraEditorDirs) {
		d, ok := s.expand(e, uc)
		if !ok || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, [2]string{d, extraEditorDirs[e]})
	}
	return out
}

// scanExtensions records catalogued editor extensions (VS Code family and
// JetBrains) installed for a user.
func (s *scanner) scanExtensions(uc *userCtx) {
	for _, de := range s.editorExtensionDirs(uc) {
		s.scanVSCodeDir(de[0], de[1], uc)
	}
	s.scanJetBrains(uc)
}

type extHit struct {
	product catalog.Product
	version string
	path    string
}

func (s *scanner) scanVSCodeDir(dir, editor string, uc *userCtx) {
	ents, err := s.g.readDir(s.locFor(dir, uc, ""))
	if err != nil {
		return
	}
	best := map[string]*extHit{}
	n := 0
	for _, e := range ents {
		if strings.HasPrefix(e.name, ".") {
			continue
		}
		if e.kind == kindSymlink {
			s.skipLink(joinLogical(dir, e.name))
			continue
		}
		if e.kind != kindDir {
			continue
		}
		n++
		if n > maxExtPerEditor {
			s.led.capped("editor extensions truncated: " + homeRelOf(dir, uc))
			break
		}
		edir := joinLogical(dir, e.name)
		id, version := s.extensionManifest(edir, uc)
		if id == "" {
			id, version = splitExtensionDir(e.name)
		}
		p, ok := s.cat.ByExtensionID(id)
		if !ok {
			continue
		}
		cur := best[p.ID]
		if cur == nil || compareVersions(version, cur.version) > 0 {
			best[p.ID] = &extHit{product: p, version: version, path: edir}
		}
	}
	for _, id := range sortedKeys(best) {
		h := best[id]
		s.addExtension(h, editor, evExtension, uc, nil)
	}
}

func (s *scanner) extensionManifest(edir string, uc *userCtx) (id, version string) {
	l := s.locFor(joinLogical(edir, "package.json"), uc, "")
	d := s.doc(l, ownerFor(l, uc), "json")
	if d.err != nil || d.doc == nil {
		return "", ""
	}
	pub, name := getString(d.doc, "publisher"), getString(d.doc, "name")
	if pub == "" || name == "" {
		return "", ""
	}
	return pub + "." + name, getString(d.doc, "version")
}

// vscodePlatforms are the target-platform suffixes of platform-specific
// extension directories ("ms-python.python-2025.1.0-linux-x64").
var vscodePlatforms = []string{"win32-x64", "win32-arm64", "win32-ia32", "linux-x64", "linux-arm64", "linux-armhf",
	"alpine-x64", "alpine-arm64", "darwin-x64", "darwin-arm64", "web", "universal"}

// splitExtensionDir reads "publisher.name-1.2.3[-platform]".
func splitExtensionDir(dir string) (id, version string) {
	for _, p := range vscodePlatforms {
		if strings.HasSuffix(dir, "-"+p) {
			dir = strings.TrimSuffix(dir, "-"+p)
			break
		}
	}
	for i := 0; i < len(dir)-1; i++ {
		if dir[i] == '-' && dir[i+1] >= '0' && dir[i+1] <= '9' {
			return dir[:i], dir[i+1:]
		}
	}
	return dir, ""
}

func (s *scanner) addExtension(h *extHit, editor, class string, uc *userCtx, detail map[string]string) {
	e := &evidence{}
	e.add(class, false)
	for _, sd := range h.product.StateDirs.For(s.goos) {
		if d, ok := s.expand(sd, uc); ok && s.g.isDir(s.locFor(d, uc, "")) {
			e.add(evStateDir, false)
			break
		}
	}
	a := &event.Asset{
		Kind:       event.AssetIDEExtension,
		Name:       h.product.Name,
		Vendor:     h.product.Vendor,
		Version:    safeVersion(h.version),
		CatalogID:  h.product.ID,
		Parent:     editor,
		Path:       safeText(h.path, 1024),
		Scope:      event.ScopeUser,
		Owner:      uc.u.Name,
		Evidence:   e.list(),
		Confidence: e.confidence(),
		Detail:     detail,
	}
	s.add(&record{a: a, uc: uc})
}

// jetBrainsRoots are where JetBrains IDEs keep per-version configuration;
// plugins live directly under it on Linux and under plugins/ elsewhere.
func (s *scanner) jetBrainsRoots(uc *userCtx) []string {
	var pats []string
	switch s.goos {
	case "linux":
		pats = []string{"~/.local/share/JetBrains/*"}
	case "darwin":
		pats = []string{"~/Library/Application Support/JetBrains/*/plugins"}
	case "windows":
		pats = []string{"%APPDATA%/JetBrains/*/plugins"}
	}
	var out []string
	for _, p := range pats {
		if e, ok := s.expand(p, uc); ok {
			out = append(out, s.glob(e, uc, "", 64)...)
		}
	}
	return out
}

func (s *scanner) scanJetBrains(uc *userCtx) {
	for _, root := range s.jetBrainsRoots(uc) {
		ide := baseName(root)
		if ide == "plugins" {
			ide = baseName(dirName(root))
		}
		ents, err := s.g.readDir(s.locFor(root, uc, ""))
		if err != nil {
			continue
		}
		for _, e := range ents {
			if e.kind != kindDir || strings.HasPrefix(e.name, ".") {
				continue
			}
			pdir := joinLogical(root, e.name)
			id, version := s.jetBrainsPlugin(pdir, e.name, uc)
			if id == "" {
				continue
			}
			p, ok := s.cat.ByJetBrainsID(id)
			if !ok {
				continue
			}
			h := &extHit{product: p, version: version, path: pdir}
			s.addExtension(h, "", evJetBrains, uc, map[string]string{"ide": safeText(ide, 64)})
		}
	}
}

// pluginXML holds the identity fields of META-INF/plugin.xml.
type pluginXML struct {
	ID      string `xml:"id"`
	Name    string `xml:"name"`
	Version string `xml:"version"`
}

// jetBrainsPlugin reads a plugin's identity from META-INF/plugin.xml, in
// an exploded directory or inside one of its lib/*.jar files (read through
// the zip central directory; nothing is extracted to disk).
func (s *scanner) jetBrainsPlugin(pdir, dirName string, uc *userCtx) (id, version string) {
	l := s.locFor(joinLogical(pdir, "META-INF/plugin.xml"), uc, "")
	if data, _, err := s.g.readFile(l, ownerFor(l, uc), maxPluginXML); err == nil {
		return parsePluginXML(data)
	}
	lib := joinLogical(pdir, "lib")
	ents, err := s.g.readDir(s.locFor(lib, uc, ""))
	if err != nil {
		return "", ""
	}
	var jars []string
	for _, e := range ents {
		if e.kind == kindRegular && strings.HasSuffix(strings.ToLower(e.name), ".jar") {
			jars = append(jars, e.name)
		}
	}
	// The main jar is usually named after the plugin directory.
	sort.SliceStable(jars, func(i, j int) bool {
		a, b := strings.HasPrefix(jars[i], dirName), strings.HasPrefix(jars[j], dirName)
		return a && !b
	})
	if len(jars) > maxJarsPerPlug {
		jars = jars[:maxJarsPerPlug]
	}
	for _, j := range jars {
		if id, v := s.pluginXMLInJar(joinLogical(lib, j), uc); id != "" {
			return id, v
		}
	}
	return "", ""
}

func (s *scanner) pluginXMLInJar(jar string, uc *userCtx) (id, version string) {
	defer func() {
		if recover() != nil {
			id, version = "", ""
		}
	}()
	l := s.locFor(jar, uc, "")
	f, meta, err := s.g.open(l, ownerFor(l, uc))
	if err != nil {
		s.g.account(l, err)
		return "", ""
	}
	defer f.Close()
	if meta.size > maxJarSize {
		return "", ""
	}
	zr, err := zip.NewReader(f, meta.size)
	if err != nil {
		return "", ""
	}
	if len(zr.File) > 100_000 {
		return "", ""
	}
	for _, zf := range zr.File {
		if zf.Name != "META-INF/plugin.xml" {
			continue
		}
		if zf.UncompressedSize64 > maxPluginXML {
			return "", ""
		}
		rc, err := zf.Open()
		if err != nil {
			return "", ""
		}
		data, err := io.ReadAll(io.LimitReader(rc, maxPluginXML))
		rc.Close()
		if err != nil {
			return "", ""
		}
		s.led.file()
		return parsePluginXML(data)
	}
	return "", ""
}

func parsePluginXML(data []byte) (id, version string) {
	var px pluginXML
	d := xml.NewDecoder(strings.NewReader(string(data)))
	d.Strict = false
	if err := d.Decode(&px); err != nil {
		return "", ""
	}
	id = strings.TrimSpace(px.ID)
	if id == "" {
		id = strings.TrimSpace(px.Name)
	}
	return id, strings.TrimSpace(px.Version)
}
