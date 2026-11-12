package transcript

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func globRel(t *testing.T, base, pattern string) []string {
	t.Helper()
	var out []string
	for _, c := range expandGlob(context.Background(), 0, filepath.Join(base, filepath.FromSlash(pattern))) {
		rel, err := filepath.Rel(base, c.path)
		if err != nil {
			t.Fatal(err)
		}
		if got := filepath.Join(c.base, c.rel); got != c.path {
			t.Errorf("base+rel = %q, path = %q", got, c.path)
		}
		out = append(out, filepath.ToSlash(rel))
	}
	sort.Strings(out)
	return out
}

func TestExpandGlob(t *testing.T) {
	base := t.TempDir()
	for _, f := range []string{
		"projects/a/s1.jsonl", "projects/a/s2.jsonl", "projects/a/notes.txt",
		"projects/b/s3.jsonl", "projects/a/s1/subagents/agent-1.jsonl",
		"projects/a/s1/subagents/deep/er/agent-2.jsonl", "projects/a/s1/tool-results/x.jsonl",
		"sessions/2026/11/01/rollout-a.jsonl", "sessions/2026/11/02/rollout-b.jsonl.zst", "top.jsonl",
	} {
		writeFile(t, filepath.Join(base, filepath.FromSlash(f)), "x\n")
	}
	cases := []struct {
		pattern string
		want    []string
	}{
		{"projects/*/*.jsonl", []string{"projects/a/s1.jsonl", "projects/a/s2.jsonl", "projects/b/s3.jsonl"}},
		{"projects/*/*/subagents/**/agent-*.jsonl", []string{"projects/a/s1/subagents/agent-1.jsonl", "projects/a/s1/subagents/deep/er/agent-2.jsonl"}},
		{"sessions/**/rollout-*.jsonl*", []string{"sessions/2026/11/01/rollout-a.jsonl", "sessions/2026/11/02/rollout-b.jsonl.zst"}},
		{"**/*.jsonl", []string{"projects/a/s1.jsonl", "projects/a/s1/subagents/agent-1.jsonl", "projects/a/s1/subagents/deep/er/agent-2.jsonl", "projects/a/s1/tool-results/x.jsonl", "projects/a/s2.jsonl", "projects/b/s3.jsonl", "sessions/2026/11/01/rollout-a.jsonl", "top.jsonl"}},
		{"projects/a/s?.jsonl", []string{"projects/a/s1.jsonl", "projects/a/s2.jsonl"}},
		{"projects/a/s1.jsonl", []string{"projects/a/s1.jsonl"}},
		{"projects/a/**", []string{"projects/a/notes.txt", "projects/a/s1.jsonl", "projects/a/s1/subagents/agent-1.jsonl", "projects/a/s1/subagents/deep/er/agent-2.jsonl", "projects/a/s1/tool-results/x.jsonl", "projects/a/s2.jsonl"}},
		{"missing/*/*.jsonl", nil},
		{"projects/a", nil}, // a directory is not a log
		{"projects/[/*.jsonl", nil},
	}
	for _, c := range cases {
		if got := globRel(t, base, c.pattern); strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("glob %q:\n got %v\nwant %v", c.pattern, got, c.want)
		}
	}
}

func TestExpandGlobBoundsAndCancel(t *testing.T) {
	base := t.TempDir()
	// A tree deeper than the walk limit: the walk stops, it does not recurse forever.
	deep := base
	for i := 0; i < maxWalkDepth+10; i++ {
		deep = filepath.Join(deep, "d")
	}
	writeFile(t, filepath.Join(deep, "bottom.jsonl"), "x\n")
	writeFile(t, filepath.Join(base, "d", "shallow.jsonl"), "x\n")
	got := globRel(t, base, "**/*.jsonl")
	if len(got) != 1 || got[0] != "d/shallow.jsonl" {
		t.Errorf("deep walk = %v", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if c := expandGlob(ctx, 0, filepath.Join(base, "**", "*.jsonl")); len(c) != 0 {
		t.Errorf("cancelled walk returned %d", len(c))
	}
}

func TestExpandGlobDoesNotFollowDirectorySymlinks(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir()
	writeFile(t, filepath.Join(outside, "x.jsonl"), "x\n")
	writeFile(t, filepath.Join(base, "real", "y.jsonl"), "y\n")
	if err := os.Symlink(outside, filepath.Join(base, "link")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	// A directory loop must not hang the walk either.
	os.Symlink(base, filepath.Join(base, "real", "loop"))
	// Only wildcard segments are policed here: a link named literally in
	// the fixed prefix is the operator's choice (see Root.Base).
	for _, pattern := range []string{"*/*.jsonl", "**/*.jsonl", "*/x.jsonl"} {
		got := globRel(t, base, pattern)
		for _, g := range got {
			if strings.HasPrefix(g, "link/") || strings.Contains(g, "loop") {
				t.Errorf("glob %q went through a symlink: %v", pattern, got)
			}
		}
	}
}

func TestSplitGlob(t *testing.T) {
	sep := string(filepath.Separator)
	cases := []struct {
		in, base string
		segs     []string
	}{
		{"/home/a/.claude/projects/*/*.jsonl", sep + filepath.Join("home", "a", ".claude", "projects"), []string{"*", "*.jsonl"}},
		{"/home/a/x.jsonl", sep + filepath.Join("home", "a", "x.jsonl"), nil},
		{"rel/**/f", "rel", []string{"**", "f"}},
		{"*.jsonl", ".", []string{"*.jsonl"}},
	}
	for _, c := range cases {
		base, segs := splitGlob(c.in)
		if base != c.base || strings.Join(segs, "|") != strings.Join(c.segs, "|") {
			t.Errorf("splitGlob(%q) = %q %v; want %q %v", c.in, base, segs, c.base, c.segs)
		}
	}
}
