package shellx

import "sync"

// Start-up cost. Every hawkbell binary links this package and most hawkbell
// processes never analyse a command line: `hawkbell hook` starts two processes
// per agent event (supervisor and worker) and only a guard or detect-in-hook
// worker calls Analyze. Go runs package init in every process before main,
// so the handler registry, the lookup maps and the dialect regexp used to
// cost about 0.2 to 0.6 ms and 450 allocations per process for nothing.
// They are now built on first use instead, once per process, behind
// tablesOnce. Option specs (optSpec, interpDef, pkgDef) need no build step:
// longSet is a slice, so they are static data in the binary.
//
// The invariant: every path into the analyzer goes through ensureTables
// first. The entry points are Analyze, Vocabulary and detectDialect (which
// tests call directly); everything else is reached only from them. A nil
// map reads as empty rather than panicking, so a missed entry point would
// silently find nothing; TestTablesBuiltLazily and TestTablesComplete guard
// both halves of the invariant.

var tablesOnce sync.Once

// ensureTables builds the analyzer's tables on first use. It costs one
// atomic load once they exist.
func ensureTables() { tablesOnce.Do(buildTables) }

// buildTables runs what used to be package-level map initialisers and init
// functions, in the order Go ran them: data tables first (registerInstall
// reads pkgDefs), then the registrations in source file order, so a name
// registered by two files keeps the later registration exactly as before.
func buildTables() {
	buildPsVerbs()         // entry.go
	buildWinVars()         // entry.go
	buildPosixFuncDef()    // entry.go
	buildVocabulary()      // facts.go
	buildShellCalls()      // foreign.go
	buildDownloadMarkers() // foreign.go
	buildPkgDefs()         // install.go
	buildRegistryFlags()   // install.go
	buildInterpDefs()      // interp.go
	buildShReserved()      // lex.go
	buildPsAliases()       // sem_ps.go
	handlers = map[string]handler{}
	wrappers = map[string]wrapper{}

	registerInstall()   // install.go
	registerInterp()    // interp.go
	registerDev()       // sem_dev.go
	registerFile()      // sem_file.go
	registerCwd()       // sem_cwd.go
	registerNet()       // sem_net.go
	registerPS()        // sem_ps.go
	registerSys()       // sem_sys.go
	registerPidLookup() // sem_sys.go
	registerText()      // sem_text.go
	registerWin()       // sem_win.go
	registerWrappers()  // wrappers.go
}
