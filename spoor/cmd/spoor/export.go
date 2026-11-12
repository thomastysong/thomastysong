package main

import (
	"fmt"
	"io/fs"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/thomastysong/spoor/deploy"
	"github.com/thomastysong/spoor/internal/fleetgen"
	"github.com/thomastysong/spoor/internal/platform"
)

func (a *app) cmdExport(args []string) int {
	return a.dispatch("export", []subcommand{
		{"config", "the default configuration, commented (stdout or --out file)", a.exportConfig},
		{"fleet", "Fleet content: labels, policies, reports, ATC, install scripts (--out dir)", a.exportFleet},
		{"fluent-bit", "Fluent Bit inputs, parsers and output examples for the outbox (--out dir)", a.exportFluentBit},
		{"kubernetes", "the node sensor DaemonSet and container notes (--out dir)", a.exportKubernetes},
		{"atc", "osquery auto table construction fragment for this host's state database", a.exportATC},
	}, args)
}

// devOnly are embedded files that document how content was verified in
// the source tree; they are not deployment content.
func devOnly(name string) bool {
	base := path.Base(name)
	return base == "VERIFIED.md" || base == "verify.sh"
}

type exportFlags struct {
	cf    cfgFlags
	out   string
	force bool
	list  bool
}

func (a *app) exportParse(name, usage, about string, args []string, extra func(*flagSet)) (*exportFlags, int, bool) {
	fs := a.newFlags(name, usage, about)
	var e exportFlags
	e.cf.register(fs)
	fs.StringVar(&e.out, "out", "", "output directory (file for config and atc)")
	fs.BoolVar(&e.force, "force", false, "replace existing files")
	fs.BoolVar(&e.list, "list", false, "list the files that would be written, write nothing")
	if extra != nil {
		extra(fs)
	}
	pos, code, done := a.parse(fs, args)
	if done {
		return nil, code, true
	}
	if len(pos) > 0 {
		return nil, a.usageErr(name, "unexpected argument %q", pos[0]), true
	}
	return &e, 0, false
}

func (a *app) exportConfig(args []string) int {
	e, code, done := a.exportParse("export config", "export config [--out file] [--data-dir dir] [--force]",
		"Writes the built-in default configuration with comments. The install scripts call it\nto create /etc/spoor/spoor.yaml (mode 0644: unprivileged hooks read it).", args, nil)
	if done {
		return code
	}
	dataDir := e.cf.dataDir
	if dataDir == "" {
		dataDir = platform.DefaultDirs().Data
	} else if abs, err := filepath.Abs(dataDir); err == nil {
		dataDir = abs
	}
	b, err := defaultConfigYAML(dataDir)
	if err != nil {
		return a.fail("export config", err)
	}
	if e.out == "" || e.out == "-" {
		_, err := a.stdout.Write(b)
		if err != nil {
			return a.fail("export config", err)
		}
		return exitOK
	}
	if err := writeExport(e.out, b, 0o644, e.force); err != nil {
		return a.fail("export config", err)
	}
	fmt.Fprintf(a.stderr, "wrote %s\n", e.out)
	return exitOK
}

// writeTree writes files (slash paths relative to dir) and reports them.
func (a *app) writeTree(name, dir string, files map[string][]byte, force, list bool) int {
	if dir == "" && !list {
		return a.usageErr(name, "--out is required (or --list)")
	}
	keys := sortedKeys(files)
	for _, k := range keys {
		if !fs.ValidPath(k) {
			return a.fail(name, fmt.Errorf("refusing unsafe path %q", k))
		}
	}
	if list {
		for _, k := range keys {
			fmt.Fprintln(a.stdout, filepath.Join(dir, filepath.FromSlash(k)))
		}
		return exitOK
	}
	for _, k := range keys {
		mode := fs.FileMode(0o644)
		if strings.HasSuffix(k, ".sh") {
			mode = 0o755
		}
		p := filepath.Join(dir, filepath.FromSlash(k))
		if err := writeExport(p, files[k], mode, force); err != nil {
			return a.fail(name, err)
		}
	}
	fmt.Fprintf(a.stdout, "wrote %d file(s) under %s\n", len(keys), dir)
	return exitOK
}

// embeddedSet reads one embedded content set, minus verification files.
func embeddedSet(set string, skip func(string) bool) (map[string][]byte, bool, error) {
	sub, ok := deploy.Sub(set)
	if !ok {
		return nil, false, nil
	}
	files := map[string][]byte{}
	err := fs.WalkDir(sub, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || devOnly(p) || (skip != nil && skip(p)) {
			return nil
		}
		b, err := fs.ReadFile(sub, p)
		if err != nil {
			return err
		}
		files[p] = b
		return nil
	})
	return files, true, err
}

func (a *app) exportFluentBit(args []string) int {
	e, code, done := a.exportParse("export fluent-bit", "export fluent-bit --out dir [--force] [--list]",
		`Writes the Fluent Bit content verified against the real image: an includable
inputs fragment (filesystem buffering, one tail input per stream group, the
parser for spoor's time format), a standalone example and output examples.
The default outbox path is replaced with this host's (output of data_dir).`, args, nil)
	if done {
		return code
	}
	cfg, _, err := loadConfig(e.cf)
	if err != nil {
		return a.fail("export fluent-bit", err)
	}
	files, ok, err := embeddedSet("fluent-bit", nil)
	if err != nil {
		return a.fail("export fluent-bit", err)
	}
	if !ok {
		return a.fail("export fluent-bit", fmt.Errorf("this build carries no Fluent Bit content"))
	}
	substituteOutbox(files, defaultOutbox(), cfg.OutboxDir())
	return a.writeTree("export fluent-bit", e.out, files, e.force, e.list)
}

// defaultOutbox is the outbox path written into the shipped Fluent Bit
// files (the Linux system default).
func defaultOutbox() string { return "/var/lib/spoor/outbox" }

// substituteOutbox rewrites the default outbox path to this host's in every
// file, as the default of ${SPOOR_OUTBOX:-...} and wherever else it occurs.
func substituteOutbox(files map[string][]byte, from, to string) {
	if from == to || to == "" {
		return
	}
	// Fluent Bit accepts forward slashes in tail paths on Windows too, and
	// backslashes would need YAML escaping in some of the files.
	to = filepath.ToSlash(to)
	for k, b := range files {
		files[k] = []byte(strings.ReplaceAll(string(b), from, to))
	}
}

func (a *app) exportKubernetes(args []string) int {
	e, code, done := a.exportParse("export kubernetes", "export kubernetes --out dir [--force] [--list]",
		"Writes the Kubernetes node sensor manifests and the in-image hook mode notes.", args, nil)
	if done {
		return code
	}
	files, ok, err := embeddedSet("kubernetes", nil)
	if err != nil {
		return a.fail("export kubernetes", err)
	}
	if !ok || len(files) == 0 {
		return a.fail("export kubernetes", fmt.Errorf("this build carries no Kubernetes content (deploy/kubernetes was not present when it was built)"))
	}
	return a.writeTree("export kubernetes", e.out, files, e.force, e.list)
}

// fleetOptions maps this host's configuration onto the generator: the state
// database of this OS comes from the configuration; the binary path is the
// packaged location unless --bin-path says otherwise.
func fleetOptions(dbPath, binPath string, minBundle uint64) fleetgen.Options {
	o := fleetgen.Options{
		DBPaths:          map[string]string{runtime.GOOS: dbPath},
		MinBundleVersion: minBundle,
	}
	if binPath != "" {
		o.BinPaths = map[string]string{runtime.GOOS: binPath}
	}
	return o
}

func (a *app) exportFleet(args []string) int {
	var minBundle *uint64
	var binPath *string
	e, code, done := a.exportParse("export fleet", "export fleet --out dir [--min-bundle-version N] [--bin-path path] [--force] [--list]",
		`Writes the Fleet content: lib/ (labels, policies and reports for the stock,
fleetd and builtin profiles, the ATC agent-options fragment, CONTENT.md),
generated for this host's state database path, plus the install scripts,
GitOps examples and package examples, in the same layout as deploy/fleet so
the GitOps files' relative paths work. Read lib/CONTENT.md and README.md
before applying anything: agent options are replaced as a whole by Fleet.`,
		args, func(fs *flagSet) {
			minBundle = fs.Uint64("min-bundle-version", fleetgen.DefaultMinBundleVersion, "lowest signed bundle version the \"rules bundle is current\" policy accepts; raise it each time you publish a bundle")
			binPath = fs.String("bin-path", "", "spoor binary path on hosts of this OS (default: the packaged location)")
		})
	if done {
		return code
	}
	if *minBundle == 0 {
		return a.usageErr("export fleet", "--min-bundle-version must be at least 1")
	}
	cfg, _, err := loadConfig(e.cf)
	if err != nil {
		return a.fail("export fleet", err)
	}
	gen, err := fleetgen.Generate(fleetOptions(cfg.StateDB(), *binPath, *minBundle))
	if err != nil {
		return a.fail("export fleet", err)
	}
	files, ok, err := embeddedSet("fleet", func(p string) bool { return p == "lib" || strings.HasPrefix(p, "lib/") })
	if err != nil {
		return a.fail("export fleet", err)
	}
	if !ok {
		files = map[string][]byte{}
	}
	for k, v := range gen {
		files["lib/"+k] = v
	}
	return a.writeTree("export fleet", e.out, files, e.force, e.list)
}

func (a *app) exportATC(args []string) int {
	e, code, done := a.exportParse("export atc", "export atc [--out file] [--force]",
		`Writes the osquery auto_table_construction fragment for every OS, with this
OS's entry pointing at this host's state database. It is a FRAGMENT to merge
into existing agent options (see lib/CONTENT.md of `+"`export fleet`"+`): replacing
agent options with it drops existing ATC tables, decorators and options.`, args, nil)
	if done {
		return code
	}
	cfg, _, err := loadConfig(e.cf)
	if err != nil {
		return a.fail("export atc", err)
	}
	gen, err := fleetgen.Generate(fleetOptions(cfg.StateDB(), "", fleetgen.DefaultMinBundleVersion))
	if err != nil {
		return a.fail("export atc", err)
	}
	b, ok := gen[fleetgen.FileATC]
	if !ok {
		return a.fail("export atc", fmt.Errorf("the generator produced no %s", fleetgen.FileATC))
	}
	if e.out == "" || e.out == "-" {
		if _, err := a.stdout.Write(b); err != nil {
			return a.fail("export atc", err)
		}
		return exitOK
	}
	if err := writeExport(e.out, b, 0o644, e.force); err != nil {
		return a.fail("export atc", err)
	}
	fmt.Fprintf(a.stderr, "wrote %s\n", e.out)
	return exitOK
}

// deploySets is for doctor and version output: which content sets the
// binary carries.
func deploySets() []string {
	s := deploy.Sets()
	sort.Strings(s)
	return s
}
