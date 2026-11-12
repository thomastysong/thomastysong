// Command spoor is the AI-agent detection sensor: one binary that is the
// daemon (`spoor run`), the hook every agent calls (`spoor hook`), the
// osquery extension (started by osquery as spoor.ext), and the operator's
// tool for scans, rules, hooks, bundles, exports and diagnostics.
//
// Two entry points bypass the command framework entirely, because the
// program that starts them reads spoor's output as a protocol:
//
//   - `spoor hook ...` is called by an AI agent on every tool call. Its stdout
//     is the agent's control channel and its stderr is shown to the user or
//     the model, so nothing may be printed before internal/hookcmd takes
//     over, and nothing else is initialised on its way there.
//   - osquery starts extensions with --socket, --timeout and --interval and
//     no command word; the binary also recognises the extension name it is
//     installed under (spoor.ext, spoor.ext.exe).
package main

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/thomastysong/spoor/internal/hookcmd"
)

func main() {
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "hook" {
		// The hot path: one process per agent event. hookcmd.Run exits 0 on
		// every outcome and never writes to stderr.
		hookcmd.Version = versionString()
		os.Exit(hookcmd.Run(os.Stdin, os.Stdout, os.Stderr, args[1:], hookcmd.OSEnv()))
	}
	if isExtension(os.Args) {
		os.Exit(runExtension(args, os.Stderr))
	}
	os.Exit(newApp().main(args))
}

// isExtension reports whether osquery started this process as an
// extension: either the executable carries the extension name, or the
// arguments are osquery's (they start with a flag and include --socket).
// A command word first ("spoor doctor --socket") is never an extension
// call, so a typo cannot turn an operator command into a socket client.
func isExtension(argv []string) bool {
	if len(argv) == 0 {
		return false
	}
	name := strings.ToLower(filepath.Base(argv[0]))
	if strings.HasSuffix(name, ".ext") || strings.HasSuffix(name, ".ext.exe") {
		return true
	}
	args := argv[1:]
	if len(args) == 0 || !strings.HasPrefix(args[0], "-") {
		return false
	}
	for _, a := range args {
		if a == "--socket" || a == "-socket" || strings.HasPrefix(a, "--socket=") || strings.HasPrefix(a, "-socket=") {
			return true
		}
	}
	return false
}
