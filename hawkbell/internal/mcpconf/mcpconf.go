// Package mcpconf reads MCP (Model Context Protocol) server declarations out
// of agent configuration files and turns each one into launch facts a central
// team can hunt on: which package or image is fetched, whether it is pinned,
// which endpoint is contacted, how it authenticates, and a hash that changes
// when the declaration is silently rewritten.
//
// The package is a pure function of its input. It never opens files, never
// resolves paths, never starts a declared server and never contacts a declared
// URL: inventory must not execute what it discovers. Every input is treated as
// attacker controlled (a repository can ship its own .mcp.json), so sizes are
// capped, nesting is bounded before a parser that recurses is allowed near the
// data, and no exported function panics.
//
// Secrets: Server.Env and Server.Headers hold values because detection needs
// them on the endpoint. Nothing derived from a Server (Normalize,
// DefinitionHash, RiskFlags, error messages) contains a credential value.
//
// Dialects understood (Parse with FormatAuto tries all of them):
//
//	mcpServers     {"mcpServers": {name: {...}}}, also the "amp.mcpServers"
//	               settings key and the flat {name: {...}} form of plugin
//	               .mcp.json files
//	claude.json    top-level mcpServers plus projects.<path>.mcpServers
//	vscode         "servers", "mcp": {"servers"}, the dotted "mcp.servers"
//	               key, .code-workspace "settings" and devcontainer
//	               "customizations.vscode.mcp.servers"
//	zed            "context_servers"
//	codex.toml     [mcp_servers.<name>] (also YAML/JSON "mcp_servers")
//	opencode       "mcp": {name: {type: local|remote, command: [...]}}
//	continue.yaml  "mcpServers" list or map, legacy
//	               "experimental.modelContextProtocolServers"
//	goose.yaml     "extensions": {name: {type, cmd, args, uri, envs}}
//
// Unsupported, by design:
//   - JSON5 beyond comments and trailing commas (single-quoted strings,
//     unquoted keys). Such a file returns a *SyntaxError.
//   - Goose builtin/platform extensions and Zed extension-provided servers
//     that carry no settings: they declare nothing launchable, so they are
//     skipped rather than reported with invented facts.
//   - Evaluating the declaration: environment variables, ${input:...}
//     prompts and shell expansions are never resolved. A launch that depends
//     on them is described as written.
//   - Shell scripts handed to "sh -c": only a word-level reading is done to
//     find the runner; full shell semantics belong to package shellx.
//
// Data provenance: the dialect key names were cross-checked against
// snyk/agent-scan (Apache-2.0), the value-taking-flag approach to reading a
// launch line follows uber/ADR's judge/risk.py (Apache-2.0) and the
// remote_fetch_exec notion follows Fleet's ai_tools table (MIT). No code was
// copied.
package mcpconf

import (
	"errors"
	"fmt"
)

// Format names the dialect of a configuration file.
type Format string

const (
	FormatMCPServers Format = "mcpServers"    // {"mcpServers": {name: {...}}}: Claude Code/Desktop, Cursor, Windsurf, Cline, Gemini CLI, Copilot CLI, Amp, Kiro, Antigravity ...
	FormatClaudeJSON Format = "claude.json"   // ~/.claude.json: top-level mcpServers plus projects.<path>.mcpServers
	FormatVSCode     Format = "vscode"        // {"servers": {...}} and settings.json "mcp": {"servers": ...}
	FormatZed        Format = "zed"           // settings.json "context_servers"
	FormatCodexTOML  Format = "codex.toml"    // [mcp_servers.<name>]
	FormatOpenCode   Format = "opencode"      // "mcp": {name: {type: local|remote, command: [..], url}}
	FormatContinue   Format = "continue.yaml" // mcpServers list in YAML (and legacy config.json)
	FormatGoose      Format = "goose.yaml"    // extensions: {name: {type: stdio|sse|streamable_http, cmd, args, uri, envs}}
	FormatAuto       Format = ""              // sniff by content
)

const (
	// MaxFileSize is the largest input Parse accepts.
	MaxFileSize = 20 << 20
	// MaxServers bounds the servers returned for one file. A hostile file can
	// declare a million entries in 20 MiB; the cap keeps the caller's memory
	// and event volume bounded, and ErrTooManyServers keeps the cut visible.
	MaxServers = 4096
)

var (
	// ErrTooLarge is returned when the input exceeds MaxFileSize.
	ErrTooLarge = errors.New("mcpconf: config exceeds the 20 MiB limit")
	// ErrTooManyServers is returned together with the first MaxServers
	// servers (in output order) when a file declares more than that.
	ErrTooManyServers = errors.New("mcpconf: more servers declared than the per-file limit, list truncated")
	// errInternal replaces a recovered panic. The panic value is dropped
	// because parser panics can quote file content, and file content can be a
	// credential.
	errInternal = errors.New("mcpconf: internal error while reading config")
)

// SyntaxError reports a file that is not well-formed in the syntax it was
// read as. It deliberately carries no excerpt of the file: parser messages
// quote the offending token, and in a config file that token can be a secret.
type SyntaxError struct {
	Syntax string // json | toml | yaml
	Line   int    // 1-based; 0 when unknown
	Reason string // malformed | too deeply nested | too many values in
}

func (e *SyntaxError) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("mcpconf: %s %s at line %d", e.Reason, e.Syntax, e.Line)
	}
	return fmt.Sprintf("mcpconf: %s %s", e.Reason, e.Syntax)
}

// Server is one declared MCP server as written in a config file.
//
// Env and Headers carry values and are LOCAL ONLY. They are tagged json:"-"
// so that marshalling a Server by accident cannot ship a credential.
type Server struct {
	// Name and Project identify the server. Parse cuts a name over 256
	// bytes, and a project over 1024, to its head, "~" and a rank that is
	// the same in every process (see builder.cutIdentity).
	Name       string
	SourcePath string
	Project    string            // project path when declared under projects.<path> or found in a project file
	Transport  string            // stdio | http | sse | ws
	Command    string            // executable as declared; may be a whole command line when the file wrote one
	Args       []string          // as declared, may contain secrets
	Env        map[string]string `json:"-"` // LOCAL ONLY: never emit values
	URL        string            // as declared, may contain credentials
	Headers    map[string]string `json:"-"` // LOCAL ONLY
	Enabled    *bool

	// oauth records that the declaration configures OAuth (an "oauth" block,
	// auth = "oauth", an auth provider type). The exported fields cannot
	// express it and AuthMode needs it.
	oauth bool
	// headersHelper is a command the client runs to produce request headers
	// (Claude Code "headersHelper", Codex "http_headers_helper"). It is code
	// execution declared next to a remote server, so it takes part in the
	// definition hash and in the risk flags.
	headersHelper string
	// oauthSecret is a client secret written inside the oauth block. It is
	// kept only so the inline-secret check can see it.
	oauthSecret string
}
