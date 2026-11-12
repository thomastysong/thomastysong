package mcpconf

import (
	"strings"
)

// Risk flag vocabulary, in the order RiskFlags reports it.
const (
	RiskUnpinnedPackage     = "unpinned_package"     // a fetched package or image can change under the same declaration
	RiskRemoteFetchExec     = "remote_fetch_exec"    // code is downloaded and run at launch
	RiskInlineSecret        = "inline_secret"        // credential-shaped literal in args, env or headers
	RiskPlaintextTransport  = "plaintext_transport"  // http:// or ws:// to a host other than this machine
	RiskDeprecatedTransport = "deprecated_transport" // HTTP+SSE, superseded by streamable HTTP
	RiskShellWrapper        = "shell_wrapper"        // a shell interprets the launch line
	RiskBroadFilesystem     = "broad_filesystem"     // a filesystem root or a whole home directory is exposed
	RiskLocalScript         = "local_script"         // runs code from a location the user can overwrite
	RiskTokenInURL          = "token_in_url"         // the endpoint URL carries a credential
	RiskDockerPrivileged    = "docker_privileged"    // container started with host-level privileges
	RiskDockerSocket        = "docker_socket"        // container runtime socket mounted into the container
)

// RiskFlags: closed vocabulary — unpinned_package, remote_fetch_exec (npx -y / uvx / bunx / docker run :latest / curl|sh in command), inline_secret (credential-shaped literal in args, env or headers), plaintext_transport (http:// to non-loopback), deprecated_transport (sse), shell_wrapper (sh -c / bash -c / cmd /c / powershell -c as command), broad_filesystem (filesystem server rooted at / or ~ ), local_script (launches a script from a user-writable path), token_in_url, docker_privileged, docker_socket.
//
// Flags are derived from the declaration text alone and come back in the
// order of the vocabulary above; nil means none. Notes on scope:
//   - unpinned_package needs something that is actually fetched: a registry
//     runner or a container image. "node server.js" is never unpinned.
//   - remote_fetch_exec is raised for every fetch-at-launch runner, pinned or
//     not: an exact version still downloads and executes code on each cold
//     start. Containers raise it only when the tag is re-resolved (:latest,
//     no tag, --pull=always).
//   - local_script and broad_filesystem judge paths by spelling (home
//     directories, temp directories, relative paths); nothing is stat'ed.
func RiskFlags(s Server) (flags []string) {
	defer func() {
		if r := recover(); r != nil {
			flags = nil
		}
	}()
	l := analyze(s)
	t := transportName(s)
	add := func(cond bool, flag string) {
		if cond {
			flags = append(flags, flag)
		}
	}

	add(l.has && !l.spec.local && l.unpinned && (l.fetch || l.container), RiskUnpinnedPackage)
	add(l.fetch || l.latest || fetchesAndRuns(s, &l), RiskRemoteFetchExec)
	add(inlineSecret(s, &l), RiskInlineSecret)
	add(plaintext(s, &l, t), RiskPlaintextTransport)
	add(t == "sse", RiskDeprecatedTransport)
	add(l.shell, RiskShellWrapper)
	add(broadFilesystem(s, &l), RiskBroadFilesystem)
	add(!l.container && l.script != "" && userWritable(l.script), RiskLocalScript)
	add(tokenInURL(s, &l), RiskTokenInURL)
	add(l.privileged, RiskDockerPrivileged)
	add(l.socket, RiskDockerSocket)
	return flags
}

// fetchesAndRuns looks for download-into-interpreter in every piece of shell
// text the declaration carries.
func fetchesAndRuns(s Server, l *launch) bool {
	for _, script := range l.inline {
		if fetchPipe(script) {
			return true
		}
	}
	if fetchPipe(s.headersHelper) {
		return true
	}
	// Some clients hand "command" to a shell; a pipeline written there, or
	// spread over args, is read as a line.
	line := s.Command
	for _, a := range s.Args {
		if len(line) > maxScript {
			break
		}
		line += " " + a
	}
	return fetchPipe(line)
}

func plaintext(s Server, l *launch, transport string) bool {
	check := func(raw string) bool {
		if strings.TrimSpace(raw) == "" {
			return false
		}
		u := splitURL(raw)
		return (u.scheme == "http" || u.scheme == "ws") && !isLocalHost(u.host)
	}
	if transport != "stdio" && check(s.URL) {
		return true
	}
	return check(l.bridgeURL)
}

// broadFilesystem reports a filesystem server given a root or home directory
// as an allowed path, or a container with such a directory bind-mounted.
func broadFilesystem(s Server, l *launch) bool {
	for _, m := range l.mounts {
		if broadRoot(m) {
			return true
		}
	}
	if l.container {
		return false // arguments after the image are paths inside the container
	}
	hay := strings.ToLower(s.Name + " " + l.spec.name + " " + cmdBase(l.cmd) + " " + baseName(l.script))
	if !strings.Contains(hay, "filesystem") && !strings.Contains(hay, "file-system") && !strings.Contains(hay, "file_system") {
		return false
	}
	for _, a := range l.rest {
		if !isFlag(a) && broadRoot(a) {
			return true
		}
	}
	return false
}
