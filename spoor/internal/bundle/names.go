package bundle

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// maxNameLen keeps every path inside the 100-byte name field of a plain tar
// header, so an archive never needs the extended headers this package
// refuses.
const maxNameLen = 100

const contentExt = ".yaml"

// topLevel and contentDirs are the whole allow-list: two fixed files and
// *.yaml directly inside two directories. Content is data for the rule
// engine and the catalog; nothing executable or free-form is carried.
var (
	topLevel    = map[string]bool{"lists.yaml": true, "suppressions.yaml": true}
	contentDirs = map[string]bool{"rules": true, "catalog": true}
)

// checkName accepts exactly the content paths a bundle may carry. It returns
// ErrUnsafePath for names that are dangerous in themselves (traversal,
// absolute paths, separators or device names another OS would interpret) and
// ErrNotAllowed for harmless names that are simply not bundle content.
func checkName(name string) error {
	switch {
	case name == "":
		return fmt.Errorf("%w: empty name", ErrUnsafePath)
	case !utf8.ValidString(name):
		return fmt.Errorf("%w: %s is not valid UTF-8", ErrUnsafePath, quote(name))
	case strings.HasPrefix(name, "/"):
		return fmt.Errorf("%w: %s is absolute", ErrUnsafePath, quote(name))
	case strings.ContainsAny(name, "\x00\\:"):
		// Backslash is a separator and colon introduces a drive or an
		// alternate data stream on Windows.
		return fmt.Errorf("%w: %s contains a NUL, backslash or colon", ErrUnsafePath, quote(name))
	}
	for _, el := range strings.Split(name, "/") {
		if el == "" || el == "." || el == ".." {
			return fmt.Errorf("%w: %s is not a clean relative path", ErrUnsafePath, quote(name))
		}
	}
	if len(name) > maxNameLen {
		return fmt.Errorf("%w: %s is longer than %d bytes", ErrNotAllowed, quote(name), maxNameLen)
	}
	if topLevel[name] {
		return nil
	}
	dir, base, nested := strings.Cut(name, "/")
	if !nested || !contentDirs[dir] || strings.Contains(base, "/") {
		return fmt.Errorf("%w: %s (allowed: rules/*.yaml, catalog/*.yaml, lists.yaml, suppressions.yaml)", ErrNotAllowed, quote(name))
	}
	return checkBase(name, base)
}

// checkBase restricts file names to a portable ASCII subset: no leading dot
// (hidden and editor temp files), no spaces, nothing that needs quoting in a
// shell or changes meaning under Unicode normalisation on macOS.
func checkBase(name, base string) error {
	stem, ok := strings.CutSuffix(base, contentExt)
	if !ok || stem == "" {
		return fmt.Errorf("%w: %s (only *%s files are loaded)", ErrNotAllowed, quote(name), contentExt)
	}
	for i := 0; i < len(stem); i++ {
		c := stem[i]
		alnum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !alnum && (i == 0 || (c != '.' && c != '-' && c != '_')) {
			return fmt.Errorf("%w: %s (file names use letters, digits, '.', '-' and '_' and start with a letter or digit)", ErrNotAllowed, quote(name))
		}
	}
	if reservedDevice(stem) {
		return fmt.Errorf("%w: %s is a device name on Windows", ErrUnsafePath, quote(name))
	}
	return nil
}

// reservedDevice reports whether Windows would open a device instead of a
// file: the check there ignores case and everything after the first dot.
func reservedDevice(stem string) bool {
	s, _, _ := strings.Cut(strings.ToUpper(stem), ".")
	switch s {
	case "CON", "PRN", "AUX", "NUL":
		return true
	}
	if len(s) == 4 && (strings.HasPrefix(s, "COM") || strings.HasPrefix(s, "LPT")) {
		return s[3] >= '0' && s[3] <= '9'
	}
	return false
}
