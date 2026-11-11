package platform

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"strings"
	"unicode/utf16"
)

// This file holds the parsers for every OS's process wire formats. They are
// pure functions so the fixtures in the tests exercise them on any build
// host, including the formats of operating systems the tests cannot run on.

// splitArgs splits a NUL-separated argument block. Trailing NULs are padding
// (setproctitle rewrites leave a run of them) and are dropped; empty strings
// between arguments are real empty arguments and are kept.
func splitArgs(b []byte) []string {
	b = bytes.TrimRight(b, "\x00")
	if len(b) == 0 {
		return nil
	}
	var out []string
	for len(b) > 0 && len(out) < maxArgs {
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

// parseEnviron parses a NUL-separated KEY=VALUE block such as
// /proc/<pid>/environ. truncated says the block was cut at the read limit, in
// which case the last entry is incomplete and is dropped rather than
// reported with half a value.
func parseEnviron(b []byte, truncated bool) map[string]string {
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
		addEnv(env, string(entry))
	}
	return env
}

// addEnv stores one KEY=VALUE entry. The first definition wins, which is what
// getenv returns when a name is repeated. Entries without a name (including
// Windows' hidden "=C:=C:\dir" drive entries) are skipped.
func addEnv(env map[string]string, entry string) {
	i := strings.IndexByte(entry, '=')
	if i <= 0 {
		return
	}
	if _, dup := env[entry[:i]]; !dup {
		env[entry[:i]] = entry[i+1:]
	}
}

// parseLinuxStat parses /proc/<pid>/stat. The command name sits between the
// first "(" and the LAST ")": a process may name itself "a) R 1 (b", so
// splitting on spaces from the left would let it forge every later field.
func parseLinuxStat(b []byte) (comm string, ppid int, startTicks uint64, ok bool) {
	open := bytes.IndexByte(b, '(')
	end := bytes.LastIndexByte(b, ')')
	if open < 0 || end < open {
		return "", 0, 0, false
	}
	comm = string(b[open+1 : end])
	// After ")": state(3) ppid(4) ... starttime(22).
	fields := strings.Fields(string(b[end+1:]))
	if len(fields) < 20 {
		return "", 0, 0, false
	}
	ppid, err := strconv.Atoi(fields[1])
	if err != nil || ppid < 0 {
		return "", 0, 0, false
	}
	startTicks, err = strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return "", 0, 0, false
	}
	return comm, ppid, startTicks, true
}

// parseLinuxStatusUID returns the real uid from /proc/<pid>/status
// ("Uid:\t<real>\t<effective>\t<saved>\t<fs>"). The real uid is the account
// that started the process even when it runs a setuid binary.
func parseLinuxStatusUID(b []byte) (string, bool) {
	for len(b) > 0 {
		line := b
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			line, b = b[:i], b[i+1:]
		} else {
			b = nil
		}
		if !bytes.HasPrefix(line, []byte("Uid:")) {
			continue
		}
		f := bytes.Fields(line[4:])
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

// parseBootTime returns the "btime" value (seconds since the epoch) from
// /proc/stat.
func parseBootTime(b []byte) (int64, bool) {
	for len(b) > 0 {
		line := b
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			line, b = b[:i], b[i+1:]
		} else {
			b = nil
		}
		if !bytes.HasPrefix(line, []byte("btime ")) {
			continue
		}
		v, err := strconv.ParseInt(string(bytes.TrimSpace(line[6:])), 10, 64)
		if err != nil || v <= 0 {
			return 0, false
		}
		return v, true
	}
	return 0, false
}

// parseAuxvClockTicks reads AT_CLKTCK from an ELF auxiliary vector
// (/proc/self/auxv): pairs of native words, type then value. It is how a
// static binary learns the unit of /proc/<pid>/stat's starttime without libc.
func parseAuxvClockTicks(b []byte, wordSize int, order binary.ByteOrder) (int64, bool) {
	const atClkTck = 17
	if wordSize != 4 && wordSize != 8 {
		return 0, false
	}
	word := func(p []byte) uint64 {
		if wordSize == 4 {
			return uint64(order.Uint32(p))
		}
		return order.Uint64(p)
	}
	for len(b) >= 2*wordSize {
		typ, val := word(b), word(b[wordSize:])
		b = b[2*wordSize:]
		if typ == 0 { // AT_NULL
			break
		}
		if typ == atClkTck {
			if val == 0 || val > 1_000_000 {
				return 0, false
			}
			return int64(val), true
		}
	}
	return 0, false
}

// parseProcArgs2 parses the buffer returned by macOS sysctl kern.procargs2:
//
//	int32 argc | exec_path NUL | NUL padding | argv[0..argc) NUL-terminated |
//	environment NUL-terminated strings | an empty string
//
// The environment is absent when the kernel withholds it (other users'
// processes for a non-root caller never reach here; restricted binaries
// arrive with arguments only). Layout per XNU bsd/kern/kern_sysctl.c
// (sysctl_procargsx) and Apple's ps(1), which stops the environment at the
// first empty string.
func parseProcArgs2(buf []byte) (exe string, args, env []string, ok bool) {
	if len(buf) < 4 {
		return "", nil, nil, false
	}
	// Both macOS architectures are little-endian.
	argc := int(int32(binary.LittleEndian.Uint32(buf[:4])))
	if argc < 0 {
		return "", nil, nil, false
	}
	rest := buf[4:]
	i := bytes.IndexByte(rest, 0)
	if i < 0 {
		return string(rest), nil, nil, true
	}
	exe, rest = string(rest[:i]), rest[i:]
	for len(rest) > 0 && rest[0] == 0 {
		rest = rest[1:]
	}
	// Every argument occupies at least its terminator, so an argc larger
	// than what is left is a lie; the loop simply runs out of bytes.
	for k := 0; k < argc && len(rest) > 0; k++ {
		var s []byte
		if e := bytes.IndexByte(rest, 0); e < 0 {
			s, rest = rest, nil
		} else {
			s, rest = rest[:e], rest[e+1:]
		}
		if len(args) < maxArgs {
			args = append(args, string(s))
		}
	}
	for len(rest) > 0 && len(env) < maxEnvVars {
		e := bytes.IndexByte(rest, 0)
		if e <= 0 {
			// e == 0: the empty string that ends the environment.
			// e < 0: an unterminated tail, i.e. a cut-off value; dropped.
			break
		}
		env = append(env, string(rest[:e]))
		rest = rest[e+1:]
	}
	return exe, args, env, true
}

// envListToMap converts KEY=VALUE strings to a map (first definition wins).
func envListToMap(list []string) map[string]string {
	env := make(map[string]string, len(list))
	for _, e := range list {
		addEnv(env, e)
	}
	return env
}

// parseEnvBlock16 parses a Windows environment block: UTF-16 strings, each
// NUL-terminated, the block ending with an empty string. Names keep the case
// they have in the block (Windows itself compares them case-insensitively).
func parseEnvBlock16(u []uint16) map[string]string {
	env := make(map[string]string)
	for len(u) > 0 && len(env) < maxEnvVars {
		end := -1
		for i, c := range u {
			if c == 0 {
				end = i
				break
			}
		}
		if end <= 0 {
			// end == 0 is the terminating empty string; end < 0 is a block
			// cut mid-entry, whose value would be incomplete.
			break
		}
		addEnv(env, string(utf16.Decode(u[:end])))
		u = u[end+1:]
	}
	return env
}

// bytesToUTF16 reinterprets little-endian bytes as UTF-16 code units,
// ignoring a trailing odd byte.
func bytesToUTF16(b []byte) []uint16 {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return u
}

// refineName undoes the kernel's truncation of the command name (15 bytes on
// Linux, 16 on macOS) when argv[0] visibly carries the full name. Both values
// are chosen by the process, so this adds no trust, only legibility:
// "github-copilot-" becomes "github-copilot-cli".
func refineName(comm string, args []string, commMax int) string {
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
// cwd links of unlinked files. Agents that update themselves while running
// would otherwise stop matching their own install path.
func trimDeleted(path string) string {
	return strings.TrimSuffix(path, " (deleted)")
}

// parsePID accepts a /proc directory name that is a positive decimal pid.
func parsePID(name string) (int, bool) {
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
	if n <= 0 || n > 1<<30 {
		return 0, false
	}
	return n, true
}
