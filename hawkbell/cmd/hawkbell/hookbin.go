package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/thomastysong/thomastysong/hawkbell/internal/platform"
)

// The hook commands hawkbell writes are guarded: when the binary they name is
// missing, a POSIX or PowerShell guard makes the hook exit 0 without a word
// (otherwise Copilot would deny every tool call). That keeps agents working
// through an uninstall or a half-finished upgrade, but it also makes a
// missing binary silent, so doctor looks for it (hooks.binary_missing).
// internal/hookinstall does not expose the binary it found in a file, so
// this reads the hook files Status reported as holding hawkbell entries.

// maxHookFile bounds a hook or settings file read for this check.
const maxHookFile = 1 << 20

// installedBinaries returns the hawkbell binaries the hook entries of one file
// name, in the order found, without duplicates. The file belongs to whoever
// owns the home it is in: when doctor runs as root it reads every account's
// settings, so nothing in it may make this panic, and only the hook-command
// positions of the dialects hookinstall writes are read (a status line,
// an MCP server or a note elsewhere in the file is not a hook).
func installedBinaries(path string) (bins []string, err error) {
	defer func() {
		if r := recover(); r != nil {
			bins, err = nil, fmt.Errorf("%s: internal error while reading the hook entries", path)
		}
	}()
	doc, b, err := readHookDoc(path)
	if err != nil {
		return nil, err
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
		// Every dialect keeps its registrations under the top-level
		// "hooks" key (grouped, flat or [[hooks.<Event>]] tables).
		if root, ok := doc.(map[string]any); ok {
			walkHookValues(root["hooks"], 0, add)
		}
	} else {
		// JSONC or a file the decoder refuses: the quoted strings are still
		// enough to find the command lines.
		for _, s := range quotedStrings(b) {
			add(binaryFromCommand(s))
		}
	}
	return out, nil
}

// readHookDoc reads one hook or settings file without following a final
// link and decodes it (JSON, or TOML for .toml). doc is nil when the file
// does not decode (JSONC, damage); raw is returned either way.
func readHookDoc(path string) (doc any, raw []byte, err error) {
	f, err := platform.OpenNoFollow(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxHookFile+1))
	if err != nil {
		return nil, nil, err
	}
	if len(b) > maxHookFile {
		return nil, nil, fmt.Errorf("%s: larger than %d bytes", path, maxHookFile)
	}
	if strings.EqualFold(filepath.Ext(path), ".toml") {
		var m map[string]any
		if _, err := toml.Decode(string(b), &m); err == nil {
			doc = m
		}
	} else if json.Unmarshal(b, &doc) != nil {
		doc = nil
	}
	return doc, b, nil
}

// installedTimeouts returns the distinct timeouts, in seconds, written in
// the hook handlers of one file: "timeout" (seconds for Claude Code, Codex
// and Cursor, milliseconds for Gemini CLI) and "timeoutSec" (Copilot).
// A value that is a whole number of thousands is also offered divided by
// 1000, since the file does not say which dialect wrote it. They are
// candidates for recovering the --timeout an installation used; the
// caller confirms each one against what install would write.
func installedTimeouts(path string) []int {
	doc, _, err := readHookDoc(path)
	if err != nil || doc == nil {
		return nil
	}
	root, ok := doc.(map[string]any)
	if !ok {
		return nil
	}
	seen := map[int]bool{}
	var out []int
	add := func(n int) {
		if n >= 1 && n <= 3600 && !seen[n] && len(out) < 16 {
			seen[n] = true
			out = append(out, n)
		}
	}
	var walk func(v any, depth int)
	walk = func(v any, depth int) {
		if depth > 64 {
			return
		}
		switch t := v.(type) {
		case map[string]any:
			for k, x := range t {
				if k == "timeout" || k == "timeoutSec" {
					var n int64
					switch y := x.(type) {
					case float64:
						if y != float64(int64(y)) || y < 0 || y > 3600*1000 {
							continue
						}
						n = int64(y)
					case int64:
						n = y
					default:
						continue
					}
					if n > 0 && n%1000 == 0 {
						add(int(n / 1000))
					}
					if n <= 3600 {
						add(int(n))
					}
					continue
				}
				walk(x, depth+1)
			}
		case []any:
			for _, x := range t {
				walk(x, depth+1)
			}
		case []map[string]any:
			for _, x := range t {
				walk(x, depth+1)
			}
		}
	}
	walk(root["hooks"], 0)
	return out
}

// hookCommandKeys are the handler fields hookinstall writes a command line
// into: "command" (Claude Code shell form, Codex, Gemini CLI, Cursor),
// "commandWindows" (Codex on Windows), "bash" and "powershell" (Copilot).
var hookCommandKeys = map[string]bool{"command": true, "commandWindows": true, "bash": true, "powershell": true}

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
		for k, x := range t {
			if s, ok := x.(string); ok {
				if hookCommandKeys[k] {
					add(binaryFromCommand(s))
				}
				continue
			}
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
		// Only blanks before " hook --agent " (a user's own string in a
		// file doctor reads as root) name no program.
		f := strings.Fields(prefix)
		if len(f) == 0 {
			return ""
		}
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

// binaryProblem reports why bin cannot run hawkbell for every account, or
// "". Managed and system hooks run as whichever account starts the agent,
// and the guard `[ -x BIN ] || exit 0` runs as that account: a binary only
// its owner or group may execute, or one in a directory others cannot
// search, makes every other account's hook exit 0 without a record. Paths
// written for another OS are not judged.
func binaryProblem(bin string) string { return binaryProblemAs(bin, nil) }

// binaryProblemAs is binaryProblem for a hook that only acc runs (a
// user-scope hook); acc nil means every account.
func binaryProblemAs(bin string, acc *accessor) string {
	if !filepath.IsAbs(bin) {
		return ""
	}
	fi, err := os.Stat(bin)
	switch {
	case err != nil:
		return "not found"
	case !fi.Mode().IsRegular():
		return "not a regular file"
	case !permsChecked:
		return ""
	case fi.Mode().Perm()&0o111 == 0:
		return "not executable"
	}
	return execProblem(bin, acc)
}
