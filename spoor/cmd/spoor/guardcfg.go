package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/thomastysong/spoor/internal/config"
	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/hookcmd"
	"github.com/thomastysong/spoor/internal/platform"
)

// Guard mode is not part of a hook registration. Every `spoor hook` reads
// guard.mode from the configuration file on each call (internal/hookcmd),
// and the command line hooks install writes names no --config, so that
// file is spoor.yaml in the system config directory. --guard therefore
// changes nothing in an agent's hook file except where it enables
// --fail-closed; on its own it would have been a silent no-op (for Claude
// Code always). `hooks install --guard` sets guard.mode: advisory in that
// file for the managed (and Codex system) tier, which is the
// administrator's; a user-scope install does not change the machine's
// configuration for every account and prints the exact change instead.

// Guard configuration actions.
const (
	guardSet       = "set"       // guard.mode is (or, with --dry-run, would be) changed to advisory
	guardCreate    = "create"    // the file does not exist and is (would be) written with guard.mode advisory
	guardUnchanged = "unchanged" // guard.mode is already advisory
	guardManual    = "manual"    // spoor does not change the file; Note says exactly what to change
)

// maxConfigFile is config.Load's own size limit.
const maxConfigFile = 1 << 20

// guardJSON is the configuration part of `hooks install --guard`.
type guardJSON struct {
	Path   string `json:"path"`
	Action string `json:"action"`
	// Was is guard.mode before the change ("off" when the file or key is
	// absent: the built-in default).
	Was  string   `json:"was,omitempty"`
	Note string   `json:"note,omitempty"`
	Diff []string `json:"diff,omitempty"`
}

type guardEdit struct {
	guardJSON
	before, after []byte
}

// hookConfigPath is the configuration file `spoor hook` reads when its
// command line names none (which is how hooks install registers it), below
// root when one is given.
func hookConfigPath(root string) string {
	p := filepath.Join(platform.DefaultDirs().Config, hookcmd.ConfigFileName)
	if root == "" {
		return p
	}
	return filepath.Join(root, strings.TrimPrefix(p, filepath.VolumeName(p)))
}

// guardInstruction is what to change by hand.
func guardInstruction(path, why string) string {
	return fmt.Sprintf("guard mode is the setting guard.mode in %s, which every spoor hook reads on each call (%s); set it there:\n\n  guard:\n    mode: advisory\n", path, why)
}

// planGuardMode works out how to turn guard mode on in the configuration
// file at path. With write false (a user-scope install) nothing will be
// written, and anything but "unchanged" is a manual instruction.
func planGuardMode(path string, write bool) *guardEdit {
	g := &guardEdit{guardJSON: guardJSON{Path: path, Was: "off"}}
	manual := func(why string) *guardEdit {
		g.Action, g.Note, g.after = guardManual, guardInstruction(path, why), nil
		return g
	}
	fi, err := os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if !write {
			return manual("the file does not exist, so guard mode is off; a user-scope install does not create the machine's configuration")
		}
		if runtime.GOOS == "windows" {
			// The installer gives the directory and spoor.yaml the ACLs
			// hooks need (packaging/windows/install-service.ps1); a file
			// created here would lack the Users read grant.
			return manual("the file does not exist; packaging/windows/install-service.ps1 creates it with the access hooks need")
		}
		def, err := defaultConfigYAML(platform.DefaultDirs().Data)
		if err != nil {
			return manual("the default configuration could not be rendered: " + err.Error())
		}
		after, _, err := setGuardModeYAML(def)
		if err != nil {
			return manual(err.Error())
		}
		g.Action, g.after = guardCreate, after
		g.Note = "the file does not exist (built-in defaults, guard off): it is written from the default configuration with guard.mode advisory"
		return g
	case err != nil:
		return manual(err.Error())
	case fi.Mode()&fs.ModeSymlink != 0:
		return manual("it is a symbolic link, which spoor does not write through")
	case !fi.Mode().IsRegular():
		return manual("it is not a regular file")
	case fi.Size() > maxConfigFile:
		return manual("it is larger than 1 MiB, which the hook does not read")
	}
	// Hooks run as the developer: guard mode in a file they cannot read
	// is guard mode no hook applies (a Fleet install for Windows before
	// this release gave Users no access to the data directory).
	if why := hooksCannotRead(path); why != "" {
		return manual(why)
	}
	data, err := readConfigFile(path)
	if err != nil {
		return manual(err.Error())
	}
	g.before = data
	after, was, err := setGuardModeYAML(data)
	if err != nil {
		return manual(err.Error())
	}
	g.Was = was
	if was == "advisory" {
		g.Action, g.after = guardUnchanged, nil
		return g
	}
	if !write {
		return manual("guard.mode is " + was + " there; a user-scope install does not change the machine's configuration for every account")
	}
	g.Action, g.after = guardSet, after
	g.Diff = redactedDiff(data, after)
	return g
}

// readConfigFile reads a configuration file without following a final
// link, within config.Load's size limit.
func readConfigFile(path string) ([]byte, error) {
	f, err := platform.OpenNoFollow(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxConfigFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxConfigFile {
		return nil, fmt.Errorf("%s is larger than 1 MiB", path)
	}
	return b, nil
}

// apply writes the planned change. The file must still hold what the plan
// read: a concurrent edit is not overwritten.
func (g *guardEdit) apply() error {
	switch g.Action {
	case guardCreate:
		dir := filepath.Dir(g.Path)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		// 0644: unprivileged hooks read it (the packages write it so too).
		return writeExport(g.Path, g.after, 0o644, false)
	case guardSet:
		cur, err := readConfigFile(g.Path)
		if err != nil {
			return err
		}
		if !bytes.Equal(cur, g.before) {
			return fmt.Errorf("%s changed after it was read; run the command again", g.Path)
		}
		return replaceConfig(g.Path, g.after)
	}
	return nil
}

// replaceConfig writes a new content into an existing configuration file,
// keeping its mode, owner and (on Windows) its ACL: hooks running as every
// user must still be able to read it.
func replaceConfig(path string, data []byte) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s: not a regular file", path)
	}
	if runtime.GOOS == "windows" {
		// A plain file renamed over spoor.yaml would carry the directory's
		// inherited ACL, not the explicit Users read grant the installer
		// gave the file, and an in-place rewrite lets a hook read half a
		// file: the new file gets the old one's DACL, then the rename.
		return replaceKeepingACL(path, data)
	}
	// POSIX: a rename, so a hook never reads half a file.
	if err := writeFileAtomic(path, data, fi.Mode().Perm()); err != nil {
		return err
	}
	if uid, gid, ok := fileOwner(fi); ok && (uid != os.Geteuid() || gid != os.Getegid()) {
		return os.Lchown(path, uid, gid)
	}
	return nil
}

// setGuardModeYAML returns src with guard.mode set to advisory, changing
// only that value (or adding the key) so comments and layout stay, and the
// previous value ("off" when absent). It refuses whatever it cannot edit
// as text with certainty (flow mappings, multi-line scalars, anchors,
// several documents ...): the result is decoded again and must equal the
// original with exactly that one value changed, and must load as a spoor
// configuration.
func setGuardModeYAML(src []byte) (out []byte, was string, err error) {
	defer func() {
		if r := recover(); r != nil {
			out, was, err = nil, "", errors.New("the configuration could not be edited safely")
		}
	}()
	if len(src) > maxConfigFile {
		return nil, "", errors.New("the configuration is larger than 1 MiB")
	}
	if !utf8.Valid(src) {
		return nil, "", errors.New("the configuration is not UTF-8 text")
	}
	if err := loadsAsConfig(src); err != nil {
		return nil, "", fmt.Errorf("the configuration does not load (%v); fix it first", err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(src, &doc); err != nil {
		return nil, "", fmt.Errorf("the configuration is not valid YAML: %v", err)
	}
	nl := "\n"
	if bytes.Contains(src, []byte("\r\n")) {
		nl = "\r\n"
	}
	starts := lineStarts(src)
	was = "off"
	var root *yaml.Node
	if doc.Kind == yaml.DocumentNode && len(doc.Content) == 1 {
		root = doc.Content[0]
	}
	switch {
	case root == nil || root.Kind == yaml.ScalarNode && root.Tag == "!!null":
		// Empty, or comments only.
		out = appendLines(src, nl, "guard:", "  mode: advisory")
	case root.Kind != yaml.MappingNode || root.Style&yaml.FlowStyle != 0:
		return nil, "", errors.New("the top level of the configuration is not a block mapping")
	default:
		gk, gv := mappingValue(root, "guard")
		switch {
		case gk == nil:
			ind := ""
			if len(root.Content) > 0 {
				ind = lineIndent(src, starts, root.Content[0].Line)
			}
			out = appendLines(src, nl, ind+"guard:", ind+"  mode: advisory")
		case gv.Kind == yaml.ScalarNode && gv.Tag == "!!null" && gv.Value == "":
			// "guard:" with nothing after it.
			ind := lineIndent(src, starts, gk.Line) + "  "
			out = insertLine(src, starts, gk.Line+1, ind+"mode: advisory"+nl, nl)
		case gv.Kind != yaml.MappingNode || gv.Style&yaml.FlowStyle != 0 || gv.Anchor != "" || len(gv.Content) == 0:
			return nil, "", errors.New("guard is not a block mapping spoor can edit")
		default:
			mk, mv := mappingValue(gv, "mode")
			if mk == nil {
				ind := lineIndent(src, starts, gv.Content[0].Line)
				out = insertLine(src, starts, gv.Content[0].Line, ind+"mode: advisory"+nl, nl)
				break
			}
			if mv.Kind != yaml.ScalarNode {
				return nil, "", errors.New("guard.mode is not a plain value")
			}
			was = mv.Value
			if mv.Value == "advisory" {
				return src, was, nil
			}
			if mv.Line != mk.Line || mv.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0 || mv.Anchor != "" {
				return nil, "", errors.New("guard.mode is not written on one line with its key")
			}
			out, err = replaceScalarAt(src, starts, mv)
			if err != nil {
				return nil, "", err
			}
		}
	}
	if err := sameExceptGuard(src, out); err != nil {
		return nil, "", err
	}
	return out, was, nil
}

// loadsAsConfig decodes b the way config.Load does (unknown keys are
// errors) and validates the result.
func loadsAsConfig(b []byte) error {
	c := config.Default(platform.DefaultDirs().Data)
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return c.Validate()
}

// sameExceptGuard checks an edit: after decodes to before with only
// guard.mode set to advisory, and loads as a configuration in guard mode.
func sameExceptGuard(before, after []byte) error {
	var a, b map[string]any
	if err := yaml.Unmarshal(before, &a); err != nil {
		return err
	}
	if err := yaml.Unmarshal(after, &b); err != nil {
		return fmt.Errorf("the edited configuration would not be valid YAML: %v", err)
	}
	if a == nil {
		a = map[string]any{}
	}
	g, ok := a["guard"].(map[string]any)
	if !ok {
		if a["guard"] != nil {
			return errors.New("guard is not a mapping")
		}
		g = map[string]any{}
		a["guard"] = g
	}
	g["mode"] = "advisory"
	if !reflect.DeepEqual(a, b) {
		return errors.New("the configuration could not be edited without changing more than guard.mode")
	}
	c := config.Default(platform.DefaultDirs().Data)
	dec := yaml.NewDecoder(bytes.NewReader(after))
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if err := c.Validate(); err != nil {
		return err
	}
	if c.Guard.Mode != "advisory" {
		return errors.New("the edited configuration does not turn guard mode on")
	}
	return nil
}

// mappingValue returns the key and value nodes of key in a mapping node.
func mappingValue(m *yaml.Node, key string) (k, v *yaml.Node) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Kind == yaml.ScalarNode && m.Content[i].Value == key {
			return m.Content[i], m.Content[i+1]
		}
	}
	return nil, nil
}

// lineStarts returns the byte offset of each line (line 1 at index 0).
func lineStarts(b []byte) []int {
	starts := []int{0}
	for i, c := range b {
		if c == '\n' && i+1 < len(b) {
			starts = append(starts, i+1)
		}
	}
	return starts
}

func lineText(b []byte, starts []int, line int) string {
	if line < 1 || line > len(starts) {
		return ""
	}
	s := b[starts[line-1]:]
	if i := bytes.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSuffix(string(s), "\r")
}

func lineIndent(b []byte, starts []int, line int) string {
	t := lineText(b, starts, line)
	return t[:len(t)-len(strings.TrimLeft(t, " "))]
}

// insertLine inserts text (a whole line with its newline) before line.
func insertLine(b []byte, starts []int, line int, text, nl string) []byte {
	pos := len(b)
	if line >= 1 && line <= len(starts) {
		pos = starts[line-1]
	}
	out := append([]byte(nil), b[:pos]...)
	if pos == len(b) && len(b) > 0 && b[len(b)-1] != '\n' {
		out = append(out, nl...)
	}
	out = append(out, text...)
	return append(out, b[pos:]...)
}

// appendLines adds lines at the end of b.
func appendLines(b []byte, nl string, lines ...string) []byte {
	out := append([]byte(nil), b...)
	if len(out) > 0 && out[len(out)-1] != '\n' {
		out = append(out, nl...)
	}
	for _, l := range lines {
		out = append(out, l...)
		out = append(out, nl...)
	}
	return out
}

// replaceScalarAt replaces the one-line scalar n (plain or quoted) with
// "advisory". Columns count characters, not bytes.
func replaceScalarAt(b []byte, starts []int, n *yaml.Node) ([]byte, error) {
	text := lineText(b, starts, n.Line)
	off, col := 0, 1
	for off < len(text) && col < n.Column {
		_, w := utf8.DecodeRuneInString(text[off:])
		off += w
		col++
	}
	if col != n.Column || off >= len(text) {
		return nil, errors.New("guard.mode could not be located in the file")
	}
	end := -1
	switch q := text[off]; q {
	case '\'':
		for i := off + 1; i < len(text); i++ {
			if text[i] == '\'' {
				if i+1 < len(text) && text[i+1] == '\'' {
					i++
					continue
				}
				end = i + 1
				break
			}
		}
	case '"':
		for i := off + 1; i < len(text); i++ {
			if text[i] == '\\' {
				i++
				continue
			}
			if text[i] == '"' {
				end = i + 1
				break
			}
		}
	default:
		end = len(text)
		if i := strings.Index(text[off:], " #"); i >= 0 {
			end = off + i
		}
		if i := strings.Index(text[off:end], "\t#"); i >= 0 {
			end = off + i
		}
		for end > off && (text[end-1] == ' ' || text[end-1] == '\t') {
			end--
		}
	}
	if end <= off {
		return nil, errors.New("guard.mode could not be located in the file")
	}
	pos := starts[n.Line-1]
	out := append([]byte(nil), b[:pos+off]...)
	out = append(out, "advisory"...)
	return append(out, b[pos+end:]...), nil
}

// guardWrites says whether --guard may write the configuration at scope:
// the managed and Codex system tiers are the administrator's.
func guardWrites(scope event.Scope) bool {
	return scope == event.ScopeManaged || scope == event.ScopeSystem
}
