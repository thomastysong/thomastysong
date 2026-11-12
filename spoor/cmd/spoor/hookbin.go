package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/thomastysong/spoor/internal/platform"
)

// The hook commands spoor writes are guarded: when the binary they name is
// missing, a POSIX or PowerShell guard makes the hook exit 0 without a word
// (otherwise Copilot would deny every tool call). That keeps agents working
// through an uninstall or a half-finished upgrade, but it also makes a
// missing binary silent, so doctor looks for it (hooks.binary_missing).
// internal/hookinstall does not expose the binary it found in a file, so
// this reads the hook files Status reported as holding spoor entries.

// maxHookFile bounds a hook or settings file read for this check.
const maxHookFile = 1 << 20

// installedBinaries returns the spoor binaries the hook entries of one file
// name, in the order found, without duplicates.
func installedBinaries(path string) ([]string, error) {
	f, err := platform.OpenNoFollow(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxHookFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxHookFile {
		return nil, fmt.Errorf("%s: larger than %d bytes", path, maxHookFile)
	}
	var doc any
	if strings.EqualFold(filepath.Ext(path), ".toml") {
		var m map[string]any
		if _, err := toml.Decode(string(b), &m); err == nil {
			doc = m
		}
	} else if json.Unmarshal(b, &doc) != nil {
		doc = nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(bin string) {
		if bin != "" && !seen[bin] {
			seen[bin] = true
			out = append(out, bin)
		}
	}
	if doc != nil {
		walkHookValues(doc, 0, add)
	} else {
		// JSONC or a file the decoder refuses: the quoted strings are still
		// enough to find the command lines.
		for _, s := range quotedStrings(b) {
			add(binaryFromCommand(s))
		}
	}
	return out, nil
}

func walkHookValues(v any, depth int, add func(string)) {
	if depth > 64 {
		return
	}
	switch t := v.(type) {
	case map[string]any:
		// Exec form (Claude Code): "command": BIN, "args": ["hook", "--agent", id].
		if cmd, ok := t["command"].(string); ok {
			if args, ok := t["args"].([]any); ok && len(args) >= 2 && args[0] == "hook" && args[1] == "--agent" {
				add(cmd)
			}
		}
		for _, x := range t {
			walkHookValues(x, depth+1, add)
		}
	case []any:
		for _, x := range t {
			walkHookValues(x, depth+1, add)
		}
	case []map[string]any:
		for _, x := range t {
			walkHookValues(x, depth+1, add)
		}
	case string:
		add(binaryFromCommand(t))
	}
}

// binaryFromCommand extracts the program of a rendered hook command line:
// the last shell word before " hook --agent ". It understands the forms
// hookinstall writes: POSIX single quotes ('\” for an apostrophe),
// PowerShell verbatim strings (” for an apostrophe) and bare paths.
func binaryFromCommand(s string) string {
	i := strings.LastIndex(s, " hook --agent ")
	if i <= 0 {
		return ""
	}
	prefix := s[:i]
	if !strings.ContainsAny(prefix, `'"`) {
		f := strings.Fields(prefix)
		return f[len(f)-1]
	}
	ps := strings.Contains(s, "Test-Path") || strings.HasPrefix(strings.TrimSpace(s), "&")
	words := shellWords(prefix, ps)
	if len(words) == 0 {
		return ""
	}
	return words[len(words)-1]
}

// shellWords splits a command line into words. Operators (; | & { } ( ))
// separate words and are dropped.
func shellWords(s string, powershell bool) []string {
	var words []string
	var cur strings.Builder
	inWord := false
	flush := func() {
		if inWord {
			words = append(words, cur.String())
			cur.Reset()
			inWord = false
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'':
			inWord = true
			for i++; i < len(s); i++ {
				if s[i] == '\'' {
					if powershell && i+1 < len(s) && s[i+1] == '\'' {
						cur.WriteByte('\'')
						i++
						continue
					}
					break
				}
				cur.WriteByte(s[i])
			}
		case c == '"':
			inWord = true
			for i++; i < len(s) && s[i] != '"'; i++ {
				if !powershell && s[i] == '\\' && i+1 < len(s) && strings.IndexByte("\"\\$`", s[i+1]) >= 0 {
					i++
				}
				cur.WriteByte(s[i])
			}
		case c == '\\' && !powershell && i+1 < len(s):
			inWord = true
			i++
			cur.WriteByte(s[i])
		case c == ' ' || c == '\t' || strings.IndexByte(";|&{}()", c) >= 0:
			flush()
		default:
			inWord = true
			cur.WriteByte(c)
		}
	}
	flush()
	return words
}

// quotedStrings returns the JSON string literals of a text that is not
// strict JSON (comments, trailing commas).
func quotedStrings(b []byte) []string {
	var out []string
	for i := 0; i < len(b); i++ {
		if b[i] != '"' {
			continue
		}
		j := i + 1
		for j < len(b) && b[j] != '"' {
			if b[j] == '\\' {
				j++
			}
			j++
		}
		if j >= len(b) {
			break
		}
		var s string
		if json.Unmarshal(b[i:j+1], &s) == nil && bytes.Contains(b[i:j+1], []byte(" hook --agent ")) {
			out = append(out, s)
		}
		i = j
	}
	return out
}

// binaryProblem says why a hook binary cannot run on this machine, or "".
// Paths written for another OS are not judged.
func binaryProblem(bin string) string {
	if !filepath.IsAbs(bin) {
		return ""
	}
	fi, err := os.Stat(bin)
	switch {
	case err != nil:
		return "not found"
	case !fi.Mode().IsRegular():
		return "not a regular file"
	case runtime.GOOS != "windows" && fi.Mode().Perm()&0o111 == 0:
		return "not executable"
	}
	return ""
}
