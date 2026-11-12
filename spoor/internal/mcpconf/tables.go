package mcpconf

import (
	"regexp"
	"sync"
	"sync/atomic"
)

// Start-up cost. spoor links this package into every binary, and the hook
// path starts two processes per agent event (supervisor and worker), most
// of which never read an MCP configuration. Go runs package init in each of
// them before main, and this package's regular expressions and lookup maps
// used to cost 0.53 to 0.61 ms, 376 KB and 2,691 allocations per process
// there. They are now built on first use, once per process, by
// buildTables, and every reader reaches them through tab(). Measured with
// GODEBUG=inittrace=1, seven runs each of a binary that links only this
// package (2026-11-12): package init went from 0.53-0.61 ms, 376,200 bytes,
// 2,691 allocs to 0 ms, 88 bytes, 2 allocs (runKey's sync.OnceValue). The
// first Parse pays the build instead. TestPackageInitAllocs keeps it so.
//
// Every table is a field here and is read only through tab(), never kept in
// a package variable, so no code path can see a table that was not built.
// Each builder sits next to the code that reads its tables.
type tables struct {
	// decode.go
	reTOMLHeader, reTOMLAssign, reYAMLLine *regexp.Regexp
	// hash.go
	loaderVars map[string]bool
	// launch.go
	shells, runners, interpreters map[string]bool
	rePython                      *regexp.Regexp
	wrappers                      map[string]wrapSpec
	reEnvAssign                   *regexp.Regexp
	psValueFlags                  map[string]bool
	reFetchPipe                   []*regexp.Regexp
	bridges                       map[string]bool
	// pkgspec.go
	reSemverExact, rePEP440Exact, reCommitID, reDigest, reGoExact, rePyName, rePySep *regexp.Regexp
	// runners.go
	nodePkgValueFlags, nodeValueFlags, bunValueFlags, uvValueFlags, pipxValueFlags,
	pipValueFlags, denoValueFlags, goValueFlags, dockerGlobalValueFlags,
	dockerRunValueFlags, scriptRunnerPackages map[string]bool
	// secrets.go
	reRef, reAuthScheme                                          *regexp.Regexp
	secretWords, keyQualifiers, paramWords                       map[string]bool
	reURLInText, reAssign, reAuthHeader, reHeaderLine, reEnvName *regexp.Regexp
	// urlx.go
	reScheme, reUUID, reHex, reTok *regexp.Regexp
}

// tablesOnce and builtTables are plain variables rather than a
// sync.OnceValue so that declaring them costs nothing at init.
var (
	tablesOnce  sync.Once
	builtTables *tables
	tablesReady atomic.Bool // for tests: read without racing a build
)

// tab returns the package's tables, building them on the first call. After
// that it costs one atomic load.
func tab() *tables {
	tablesOnce.Do(buildTables)
	return builtTables
}

func buildTables() {
	t := &tables{}
	buildDecodeTables(t)      // decode.go
	buildLoaderVars(t)        // hash.go
	buildLaunchers(t)         // launch.go
	buildWrappers(t)          // launch.go
	buildEnvAssign(t)         // launch.go
	buildPSValueFlags(t)      // launch.go
	buildFetchPipe(t)         // launch.go
	buildBridges(t)           // launch.go
	buildVersionPatterns(t)   // pkgspec.go
	buildRunnerFlags(t)       // runners.go
	buildReferencePatterns(t) // secrets.go
	buildSecretWords(t)       // secrets.go
	buildTextPatterns(t)      // secrets.go
	buildScheme(t)            // urlx.go
	buildTokenPatterns(t)     // urlx.go
	builtTables = t
	tablesReady.Store(true)
}

// tablesBuilt reports whether the tables exist yet, for tests.
func tablesBuilt() bool { return tablesReady.Load() }
