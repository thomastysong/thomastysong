package discovery

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"sort"
	"strings"
)

// treeMember is one regular file of a hashed tree.
type treeMember struct {
	rel  string
	size int64
}

// folderHash computes the skill folder hash, byte-compatible with
// uber/ADR's (Apache-2.0) so indicators interoperate: every regular file
// below dir, links never followed, sorted by its "/"-separated relative
// path byte-wise, folded into one running SHA-256 as "<rel>\n<x>\n" then
// the file's bytes, where x is 1 when any execute bit is set. A tree that
// is over a cap or has any unreadable member gets no hash at all rather
// than a partial one, which would name a tree that does not exist; the
// returned reason says why.
func (s *scanner) folderHash(dir string, uc *userCtx, project string) (sum string, files int, reason string) {
	var members []treeMember
	var total int64
	type pending struct {
		rel   string
		depth int
	}
	stack := []pending{{"", 0}}
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if cur.depth > 2*maxWalkDepth {
			return "", 0, "too_deep"
		}
		abs := dir
		if cur.rel != "" {
			abs = joinLogical(dir, cur.rel)
		}
		ents, err := s.g.readDir(s.locFor(abs, uc, project))
		if err != nil {
			return "", 0, "unlistable"
		}
		for _, e := range ents {
			rel := e.name
			if cur.rel != "" {
				rel = cur.rel + "/" + e.name
			}
			switch e.kind {
			case kindDir:
				stack = append(stack, pending{rel, cur.depth + 1})
			case kindRegular:
				m, err := s.g.stat(s.locFor(joinLogical(dir, rel), uc, project))
				if err != nil || m.kind != kindRegular {
					return "", 0, "unreadable_member"
				}
				if m.size > maxTreeFileSize {
					return "", 0, "file_too_large"
				}
				total += m.size
				members = append(members, treeMember{rel, m.size})
				if len(members) > maxTreeFiles {
					return "", 0, "too_many_files"
				}
				if total > maxTreeBytes {
					return "", 0, "tree_too_large"
				}
			}
			// Links and special files are not part of the tree, exactly as
			// in ADR, which never follows them either.
		}
	}
	sort.Slice(members, func(i, j int) bool { return members[i].rel < members[j].rel })
	if !s.g.takeHash(total) {
		return "", 0, "hash_budget_exhausted"
	}
	h := sha256.New()
	var read int64
	for _, m := range members {
		l := s.locFor(joinLogical(dir, m.rel), uc, project)
		f, meta, err := s.g.open(l, ownerFor(l, uc))
		if err != nil {
			s.g.account(l, err)
			return "", 0, "unreadable_member"
		}
		x := "0"
		if s.execBit(m.rel, meta) {
			x = "1"
		}
		_, _ = io.WriteString(h, m.rel+"\n"+x+"\n")
		n, err := io.Copy(h, io.LimitReader(f, maxTreeFileSize+1))
		f.Close()
		if err != nil {
			return "", 0, "unreadable_member"
		}
		if n > maxTreeFileSize {
			return "", 0, "file_too_large"
		}
		read += n
		if read > maxTreeBytes {
			return "", 0, "tree_too_large"
		}
		s.led.file()
	}
	return hex.EncodeToString(h.Sum(nil)), len(members), ""
}

// execBit mirrors what ADR's Python reads as st_mode: POSIX execute bits,
// and on Windows the execute bits Python synthesizes for .exe, .bat, .cmd
// and .com files.
func (s *scanner) execBit(rel string, m fmeta) bool {
	if s.goos == "windows" {
		switch pathExt(rel) {
		case ".exe", ".bat", ".cmd", ".com":
			return true
		}
		return false
	}
	return m.exec()
}

// fileHash hashes one file through the gate.
func (s *scanner) fileHash(l loc, owner string) (string, error) {
	data, _, err := s.g.readFile(l, owner, maxConfigBytes)
	if err != nil {
		return "", err
	}
	return sha256Hex(data), nil
}

func isMarkdownLike(name string) bool {
	n := strings.ToLower(name)
	for _, ext := range []string{".md", ".mdc", ".markdown", ".txt", ".toml", ".yaml", ".yml", ".json", ".prompt"} {
		if strings.HasSuffix(n, ext) {
			return true
		}
	}
	return false
}
