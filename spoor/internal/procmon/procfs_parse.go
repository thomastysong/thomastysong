package procmon

import (
	"bytes"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Pure parsers for Linux procfs files. They take bytes so the tests can feed
// hostile fixtures on any build host.

// Bounds on attacker-influenced procfs content.
const (
	maxStatBytes     = 4096
	maxStatusBytes   = 8192
	maxCmdlineBytes  = 256 << 10
	maxEnvironBytes  = 256 << 10
	maxEnvVars       = 4096
	maxRawArgs       = 4096
	maxChildrenBytes = 64 << 10
	maxThreads       = 4096
	maxPasswdBytes   = 4 << 20
	maxPID           = 1 << 30
)

// parseStat parses /proc/<pid>/stat. The command name sits between the first
// "(" and the LAST ")": a process may name itself "a) R 1 (b", so splitting
// on spaces from the left would let it forge every later field. state is the
// one-letter process state; startTicks is field 22.
func parseStat(b []byte) (comm string, state byte, ppid int, startTicks uint64, ok bool) {
	open := bytes.IndexByte(b, '(')
	end := bytes.LastIndexByte(b, ')')
	if open < 0 || end < open || end+2 > len(b) {
		return "", 0, 0, 0, false
	}
	comm = string(b[open+1 : end])
	f := bytes.Fields(b[end+1:])
	// f[0] state, f[1] ppid, ..., f[19] starttime.
	if len(f) < 20 || len(f[0]) != 1 {
		return "", 0, 0, 0, false
	}
	pp, err := strconv.Atoi(string(f[1]))
	if err != nil || pp < 0 || pp > maxPID {
		return "", 0, 0, 0, false
	}
	st, err := strconv.ParseUint(string(f[19]), 10, 64)
	if err != nil {
		return "", 0, 0, 0, false
	}
	return comm, f[0][0], pp, st, true
}

// parseStatusUID returns the real uid from the "Uid:" line of
// /proc/<pid>/status.
func parseStatusUID(b []byte) (string, bool) {
	for len(b) > 0 {
		line := b
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			line, b = b[:i], b[i+1:]
		} else {
			b = nil
		}
		rest, found := bytes.CutPrefix(line, []byte("Uid:"))
		if !found {
			continue
		}
		f := bytes.Fields(rest)
		if len(f) == 0 {
			return "", false
		}
		if _, err := strconv.ParseUint(string(f[0]), 10, 32); err != nil {
			return "", false
		}
		return string(f[0]), true
	}
	return "", false
}

// splitNUL splits a NUL-separated block (cmdline). Trailing NULs are padding
// and are dropped; empty strings between arguments are real and are kept.
func splitNUL(b []byte, max int) []string {
	b = bytes.TrimRight(b, "\x00")
	if len(b) == 0 {
		return nil
	}
	var out []string
	for len(b) > 0 && len(out) < max {
		i := bytes.IndexByte(b, 0)
		if i < 0 {
			out = append(out, string(b))
			break
		}
		out = append(out, string(b[:i]))
		b = b[i+1:]
	}
	return out
}

// parseEnviron parses a NUL-separated KEY=VALUE block. truncated says the
// block was cut at the read limit: the last entry is then incomplete and is
// dropped rather than reported with half a value. The first definition of a
// name wins, which is what getenv returns.
func parseEnviron(b []byte, truncated bool) map[string]string {
	return parseEnvironKeep(b, truncated, nil)
}

// parseEnvironKeep is parseEnviron restricted to the names in keep (every
// name when keep is nil).
func parseEnvironKeep(b []byte, truncated bool, keep map[string]bool) map[string]string {
	env := make(map[string]string)
	for len(b) > 0 && len(env) < maxEnvVars {
		i := bytes.IndexByte(b, 0)
		var entry []byte
		if i < 0 {
			if truncated {
				break
			}
			entry, b = b, nil
		} else {
			entry, b = b[:i], b[i+1:]
		}
		k := bytes.IndexByte(entry, '=')
		if k <= 0 || (keep != nil && !keep[string(entry[:k])]) {
			continue
		}
		name := string(entry[:k])
		if _, dup := env[name]; !dup {
			env[name] = string(entry[k+1:])
		}
	}
	return env
}

// parseChildren parses /proc/<pid>/task/<tid>/children: space-separated pids.
func parseChildren(b []byte, out []int) []int {
	for _, f := range bytes.Fields(b) {
		n, err := strconv.Atoi(string(f))
		if err != nil || n <= 0 || n > maxPID {
			continue
		}
		out = append(out, n)
	}
	return out
}

// parseBtime returns the boot time (seconds since the epoch) from /proc/stat.
func parseBtime(b []byte) (int64, bool) {
	for len(b) > 0 {
		line := b
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			line, b = b[:i], b[i+1:]
		} else {
			b = nil
		}
		rest, found := bytes.CutPrefix(line, []byte("btime "))
		if !found {
			continue
		}
		v, err := strconv.ParseInt(string(bytes.TrimSpace(rest)), 10, 64)
		if err != nil || v <= 0 {
			return 0, false
		}
		return v, true
	}
	return 0, false
}

// parsePasswd maps uid to account name from an /etc/passwd file.
func parsePasswd(b []byte) map[string]string {
	out := map[string]string{}
	for len(b) > 0 && len(out) < 1<<16 {
		line := b
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			line, b = b[:i], b[i+1:]
		} else {
			b = nil
		}
		if len(line) == 0 || line[0] == '#' || line[0] == '+' || line[0] == '-' {
			continue
		}
		f := bytes.SplitN(line, []byte(":"), 4)
		if len(f) < 3 || len(f[0]) == 0 || len(f[0]) > 64 {
			continue
		}
		if _, err := strconv.ParseUint(string(f[2]), 10, 32); err != nil {
			continue
		}
		uid := string(f[2])
		if _, dup := out[uid]; !dup && utf8.Valid(f[0]) {
			out[uid] = string(f[0])
		}
	}
	return out
}

// refineName undoes the kernel's 15-byte truncation of the command name when
// argv[0] visibly carries the full name. Both values are chosen by the
// process, so this adds legibility, not trust.
func refineName(comm string, args []string) string {
	const commMax = 15
	if len(comm) < commMax || len(args) == 0 {
		return comm
	}
	base := args[0]
	if i := strings.LastIndexByte(base, '/'); i >= 0 {
		base = base[i+1:]
	}
	if len(base) > len(comm) && len(base) <= 255 && strings.HasPrefix(base, comm) {
		return base
	}
	return comm
}

// trimDeleted removes the " (deleted)" marker Linux appends to the exe and
// cwd links of unlinked files: an agent that updated itself while running
// would otherwise stop matching its own install path.
func trimDeleted(p string) string { return strings.TrimSuffix(p, " (deleted)") }

// parsePIDName accepts a /proc directory name that is a positive decimal pid.
func parsePIDName(name string) (int, bool) {
	if name == "" || len(name) > 10 {
		return 0, false
	}
	n := 0
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	if n <= 0 || n > maxPID {
		return 0, false
	}
	return n, true
}
