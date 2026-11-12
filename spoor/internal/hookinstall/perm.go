package hookinstall

import (
	"os"
	"path/filepath"
	"strings"
)

// A managed hook file is a command that runs in every developer's session.
// If a non-admin can rewrite the file, replace it, or replace one of the
// directories above it, the "managed" tier is just a slower user tier
// (the CVE-2026-35603 class). So the file and the directories that lead to
// it from a system anchor must be admin-owned and not writable by anyone
// else.

// anchors are the system directories under which agents keep machine-wide
// configuration. They are trusted as they are (ProgramData lets every user
// create sub-directories by design, which is exactly why what is below it
// needs checking).
var anchors = [][]string{
	{"etc"},
	{"Library", "Application Support"},
	{"ProgramData"},
	{"Program Files"},
	{"Program Files (x86)"},
}

// managedChain returns the directories between the system anchor and the
// file, nearest first. With no anchor in the path only the parent directory
// is returned. The match is on path components, so it also works for a tree
// rendered under a Root.
func managedChain(path string) []string {
	dir := filepath.Dir(path)
	parts := strings.Split(filepath.ToSlash(dir), "/")
	anchorEnd := -1
	for i := range parts {
		for _, a := range anchors {
			if i+len(a) > len(parts) {
				continue
			}
			match := true
			for j, name := range a {
				if !strings.EqualFold(parts[i+j], name) {
					match = false
					break
				}
			}
			if match && i+len(a) > anchorEnd {
				anchorEnd = i + len(a)
			}
		}
	}
	if anchorEnd < 0 || anchorEnd >= len(parts) {
		return []string{dir}
	}
	var out []string
	cur := dir
	for n := len(parts); n > anchorEnd; n-- {
		out = append(out, cur)
		cur = filepath.Dir(cur)
	}
	return out
}

// insecureManaged checks the file and its directory chain and describes
// the first few problems, or returns "".
func insecureManaged(path string) string {
	var problems []string
	check := func(p string) {
		fi, err := os.Lstat(p)
		if err != nil {
			return
		}
		if why := writableByOthers(p, fi); why != "" {
			problems = append(problems, p+" "+why)
		}
	}
	check(path)
	for _, d := range managedChain(path) {
		check(d)
	}
	if len(problems) > 4 {
		problems = problems[:4]
	}
	return strings.Join(problems, "; ")
}
