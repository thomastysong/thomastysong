package mcpconf

import (
	"sort"
	"strconv"
	"strings"

	"github.com/thomastysong/spoor/internal/event"
)

// Output bounds. A declaration is attacker-sized; an inventory record is not
// allowed to be. Cuts are visible (a "[+N more]" element, a "~<8 hex>"
// suffix keyed per process, see runkey.go) and the definition hash always
// covers the full declaration.
const (
	maxOutArgs    = 64
	maxOutArg     = 1024
	maxOutCommand = 1024
	maxOutKeys    = 128
	maxOutKey     = 128
	maxOutPackage = 256
	maxOutVersion = 128
	maxOutHost    = 255
	maxOutPath    = 1024
	// maxScanValues bounds how many values of one server are scanned for
	// secrets.
	maxScanValues = 4096
)

// Normalize derives launch facts. Never includes secret values.
//
// Command and Args are returned as declared, with credentials replaced by
// "[REDACTED:<kind>:<fingerprint>]" (classify's marker shape, whose unkeyed
// fingerprint package privacy keys or removes before anything is shipped).
// Command is the full declared path: reducing it to a basename for lower
// privacy tiers is the redaction stage's decision, and it cannot be undone
// here.
//
// Runner follows event.MCP's vocabulary; launchers with the same behaviour
// are folded (pnpm dlx, yarn dlx, npm exec -> npx; bun x -> bunx; uv tool run
// -> uvx; uv run, python -m -> python; bun/tsx script -> node). Version is
// the version as declared, which may be a range or a tag; Pinned says whether
// it identifies immutable content: an exact npm or PEP 440 version, an OCI
// digest, or a full git commit id. For a stdio bridge to a remote endpoint
// (mcp-remote and the like) URLHost and URLPath describe that endpoint.
//
// AuthMode: for remote transports oauth (OAuth is configured), header (a
// literal credential is sent: a static auth header, a headers helper, or a
// credential in the URL), env (auth headers only reference variables or
// prompts) or none; for stdio env (an env block is declared) or inherited
// (none is, so the server sees the whole parent environment).
func Normalize(s Server) (m event.MCP) {
	defer func() {
		if r := recover(); r != nil {
			m = event.MCP{}
		}
	}()
	r := redactor{mark: outputMark, scan: true}
	l := analyze(s)
	t := transportName(s)

	m.Transport = t
	if s.Enabled != nil {
		en := *s.Enabled
		m.Enabled = &en
	}
	m.EnvKeys = outKeys(s.Env, r)
	m.HeaderKeys = outKeys(s.Headers, r)

	endpoint := s.URL
	if l.declCmd != "" {
		// Launch facts are read from the redacted launch line, not the raw
		// one. If an unknown flag makes a credential look like the package
		// or image operand, what is reported is the marker, never the value.
		cmd := r.text(window(l.declCmd))
		args, more := redactedArgs(l.declArgs, l.container, r)
		out := analyzeArgv(cmd, args)
		m.Command = capString(cmd, maxOutCommand)
		m.Args = capArgs(args, more)
		m.Runner = out.runner
		if out.has && !out.spec.local {
			m.Ecosystem = out.eco
			m.Package = capString(out.spec.name, maxOutPackage)
			m.Version = capString(out.spec.version, maxOutVersion)
			m.Pinned = out.pinned()
		}
		if endpoint == "" || t == "stdio" {
			// A stdio declaration is not contacted at its stray url; a
			// bridge is contacted at the endpoint in its arguments.
			if out.bridgeURL != "" {
				endpoint = out.bridgeURL
			}
		}
	}
	if endpoint != "" {
		u := splitURL(window(endpoint))
		m.URLHost = capString(redactHits(u.host, outputMark), maxOutHost)
		m.URLPath = capString(redactHits(redactPath(u.path, outputMark), outputMark), maxOutPath)
	}

	inline := inlineSecret(s, &l)
	urlCred := tokenInURL(s, &l)
	m.HasInlineSecret = inline || urlCred
	m.AuthMode = authMode(s, t, urlCred)
	return m
}

// transportName returns the transport in the closed vocabulary, inferring it
// for a Server that was built by hand without one.
func transportName(s Server) string {
	switch s.Transport {
	case "stdio", "http", "sse", "ws":
		return s.Transport
	}
	return transportOf(s.Transport, strings.TrimSpace(s.Command) != "", "", s.URL)
}

func outKeys(m map[string]string, r redactor) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	more := 0
	if len(keys) > maxOutKeys {
		more = len(keys) - maxOutKeys
		keys = keys[:maxOutKeys]
	}
	for i, k := range keys {
		// Names are safe by convention only: a value pasted where the name
		// belongs is still a secret.
		keys[i] = capString(redactHits(window(k), r.mark), maxOutKey)
	}
	if more > 0 {
		keys = append(keys, "[+"+strconv.Itoa(more)+" more]")
	}
	return keys
}

// redactedArgs returns the first maxOutArgs arguments with credentials
// replaced, and how many arguments were left out.
func redactedArgs(args []string, container bool, r redactor) (out []string, more int) {
	if len(args) > maxOutArgs {
		more = len(args) - maxOutArgs
		args = args[:maxOutArgs]
	}
	return r.args(args, container), more
}

// capArgs bounds each argument and makes the cut visible.
func capArgs(args []string, more int) []string {
	if len(args) == 0 && more == 0 {
		return nil
	}
	out := make([]string, len(args), len(args)+1)
	for i, a := range args {
		out[i] = capString(a, maxOutArg)
	}
	if more > 0 {
		out = append(out, "[+"+strconv.Itoa(more)+" more]")
	}
	return out
}

// authHeader reports whether a header name carries a credential.
func authHeader(name string) bool { return isSecretParam(name) }

func authMode(s Server, transport string, urlCred bool) string {
	if transport == "stdio" {
		if len(s.Env) > 0 {
			return "env"
		}
		// No env block does not mean no credentials: the process inherits
		// every variable of the agent that starts it.
		return "inherited"
	}
	if s.oauth {
		return "oauth"
	}
	literal, referenced := false, false
	for name, v := range s.Headers {
		if !authHeader(name) || strings.TrimSpace(v) == "" {
			continue
		}
		if isReference(v) {
			referenced = true
		} else {
			literal = true
		}
	}
	switch {
	case literal || urlCred || strings.TrimSpace(s.headersHelper) != "":
		return "header"
	case referenced:
		return "env"
	}
	return "none"
}

// inlineSecret reports a credential-shaped literal in the command line, the
// arguments, env values, header values, the headers helper or the OAuth
// client secret. Detection is classify.FindSecrets'; this function only
// supplies the name=value context it needs and skips pure references.
func inlineSecret(s Server, l *launch) bool {
	budget := maxScanValues
	spend := func() bool {
		budget--
		return budget >= 0
	}
	if l.declCmd != "" && spend() && hasSecret("", l.declCmd) {
		return true
	}
	args := l.declArgs
	for i, a := range args {
		if !spend() {
			break
		}
		if hasSecret("", a) {
			return true
		}
		if i > 0 && isFlag(args[i-1]) && !strings.Contains(args[i-1], "=") && !isFlag(a) {
			if hasSecret(strings.TrimLeft(args[i-1], "-"), a, "=") {
				return true
			}
		}
	}
	for k, v := range s.Env {
		if !spend() {
			break
		}
		if hasSecret(k, v, "=") {
			return true
		}
	}
	for k, v := range s.Headers {
		if !spend() {
			break
		}
		if hasSecret(k, v, ": ", "=") {
			return true
		}
	}
	if s.headersHelper != "" && hasSecret("", s.headersHelper) {
		return true
	}
	return s.oauthSecret != "" && hasSecret("client_secret", s.oauthSecret, "=")
}

// tokenInURL reports a credential carried by the endpoint URL itself:
// userinfo, a secret-named query parameter, a scanner hit, or a long opaque
// path segment that is not shaped like an identifier.
func tokenInURL(s Server, l *launch) bool {
	for _, raw := range []string{s.URL, l.bridgeURL} {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		raw = window(raw)
		if urlCredential(raw) {
			return true
		}
		for _, seg := range strings.Split(splitURL(raw).path, "/") {
			if _, secret := pathToken(seg); secret {
				return true
			}
		}
		if len(secretHits(raw)) > 0 {
			return true
		}
	}
	return false
}
