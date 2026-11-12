package mcpconf

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
)

// loaderVars are environment variables whose value decides what code a
// process loads or where its traffic goes. They are not secrets, and
// changing one is the cheapest way to hijack a server without touching its
// command line, so their values take part in the definition hash.
func buildLoaderVars(t *tables) {
	t.loaderVars = set(
		"PATH", "NODE_OPTIONS", "NODE_PATH", "NODE_EXTRA_CA_CERTS", "NODE_TLS_REJECT_UNAUTHORIZED",
		"ELECTRON_RUN_AS_NODE", "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT",
		"DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH",
		"PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME", "PERL5LIB", "PERL5OPT", "RUBYOPT", "RUBYLIB",
		"JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "DOTNET_STARTUP_HOOKS",
		"BASH_ENV", "ENV", "NPM_CONFIG_REGISTRY", "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL",
		"UV_INDEX_URL", "UV_DEFAULT_INDEX", "UV_EXTRA_INDEX_URL", "HTTP_PROXY", "HTTPS_PROXY",
		"ALL_PROXY", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "ANTHROPIC_BASE_URL", "OPENAI_BASE_URL",
	)
}

// DefinitionHash is a stable SHA-256 over transport, command, args, sorted env NAMES, URL (no userinfo/query), sorted header NAMES. Used for drift ("rug pull") detection of the declaration.
//
// The hash answers "would this declaration start or contact something
// different than before?" and stays the same when only a credential
// rotates. To that end:
//   - env and header VALUES are left out, except the values of variables
//     that select code or routing (NODE_OPTIONS, LD_PRELOAD, PATH, proxy and
//     index URLs ...), which are included with URL credentials stripped;
//   - in command and args, the slots that hold credentials by construction
//     are blanked: the value of a secret-named flag or NAME=value pair, an
//     Authorization header, docker -e values, URL userinfo and secret query
//     parameters. A bare token passed as a positional argument is hashed as
//     written, because recognising it would tie the hash to a pattern list
//     that changes between releases;
//   - a headers-helper command is included: it is code the client runs.
//
// The name, source path, project and enabled state are not part of the hash.
// The result is 64 lower-case hex digits, or "" if hashing failed.
func DefinitionHash(s Server) (sum string) {
	defer func() {
		if r := recover(); r != nil {
			sum = ""
		}
	}()
	r := redactor{mark: hashMark}
	l := analyze(s)

	h := sha256.New()
	var lenBuf [binary.MaxVarintLen64]byte
	put := func(v string) {
		// Length-prefixed so that ("ab","c") and ("a","bc") differ.
		n := binary.PutUvarint(lenBuf[:], uint64(len(v)))
		h.Write(lenBuf[:n])
		h.Write([]byte(v))
	}

	put("hawkbell/mcp-definition/v1")
	put(transportName(s))
	put(r.text(s.Command))

	args := r.args(s.Args, l.container)
	put(strconv.Itoa(len(args)))
	for _, a := range args {
		put(a)
	}

	names := make([]string, 0, len(s.Env))
	for k := range s.Env {
		names = append(names, k)
	}
	sort.Strings(names)
	put(strconv.Itoa(len(names)))
	for _, k := range names {
		put(k)
		if tab().loaderVars[strings.ToUpper(k)] {
			put("=" + r.text(s.Env[k]))
		}
	}

	put(sanitizedURL(s.URL))

	headers := make([]string, 0, len(s.Headers))
	for k := range s.Headers {
		headers = append(headers, strings.ToLower(k)) // header names are case-insensitive
	}
	sort.Strings(headers)
	put(strconv.Itoa(len(headers)))
	for _, k := range headers {
		put(k)
	}

	put(r.text(s.headersHelper))
	return hex.EncodeToString(h.Sum(nil))
}
