// Command licensegen writes spoor's THIRD_PARTY_LICENSES from the Go module
// cache. It is standard-library only and is run from the repository root:
//
//	go run ./tools/licensegen -repo . -out THIRD_PARTY_LICENSES
//	go run ./tools/licensegen -repo . -check   # exit 1 when the file is stale (make licenses-check)
//
// Scope: every module that the go command links into ./cmd/spoor for any
// release target (linux, darwin, windows on amd64 and arm64, CGO disabled),
// plus the Go standard library and runtime from the toolchain's GOROOT.
//
// It never guesses. A linked module without a license file, a license file
// whose detected license families differ from the reviewed table below, or a
// linked module the table does not know stops the run with an error, so a
// dependency bump forces a human to read the new text before the file is
// regenerated.
package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var targets = [][2]string{
	{"linux", "amd64"}, {"linux", "arm64"},
	{"darwin", "amd64"}, {"darwin", "arm64"},
	{"windows", "amd64"}, {"windows", "arm64"},
}

// licenseName matches the files that carry license terms or notices.
var licenseName = regexp.MustCompile(`(?i)^(licen[cs]e|copying|notice|patents|unlicense)([._-].*)?$`)

// isLicenseName reports whether a file name is a license, notice or patent
// file; Go source files (license.go, license_test.go) are code, not terms.
func isLicenseName(n string) bool {
	return licenseName.MatchString(n) && !strings.HasSuffix(strings.ToLower(n), ".go")
}

// reviewed is the table a human checked against the texts on 2026-11-12:
// for each module, the license that applies to the code spoor links, an
// optional remark, and for each license file the license families the
// detector must find in it. Keys of files are paths relative to the module
// root.
type review struct {
	license string
	remark  string
	files   map[string]string // file -> comma-separated detected families, sorted
}

var reviewed = map[string]review{
	"github.com/BurntSushi/toml":    {license: "MIT", files: map[string]string{"COPYING": "MIT"}},
	"github.com/Microsoft/go-winio": {license: "MIT", files: map[string]string{"LICENSE": "MIT"}},
	"github.com/apache/thrift": {license: "Apache-2.0",
		remark: "the LICENSE appendix lists subcomponents of the Thrift source distribution under other terms; spoor links only lib/go/thrift",
		files:  map[string]string{"LICENSE": "Apache-2.0,BSD-3-Clause,public-domain", "NOTICE": "notice"}},
	"github.com/dustin/go-humanize": {license: "MIT", files: map[string]string{"LICENSE": "MIT"}},
	"github.com/go-logr/logr":       {license: "Apache-2.0", files: map[string]string{"LICENSE": "Apache-2.0"}},
	"github.com/go-logr/stdr":       {license: "Apache-2.0", files: map[string]string{"LICENSE": "Apache-2.0"}},
	"github.com/google/uuid":        {license: "BSD-3-Clause", files: map[string]string{"LICENSE": "BSD-3-Clause"}},
	"github.com/klauspost/compress": {license: "BSD-3-Clause AND MIT",
		remark: "linked: zstd and its internals (BSD-3-Clause), internal/snapref (BSD-3-Clause), zstd/internal/xxhash (MIT); the Apache-2.0 and MIT sections of the root LICENSE cover gzhttp and s2 commands, which spoor does not link",
		files: map[string]string{
			"LICENSE":                          "Apache-2.0,BSD-3-Clause,MIT",
			"internal/snapref/LICENSE":         "BSD-3-Clause",
			"zstd/internal/xxhash/LICENSE.txt": "MIT",
		}},
	"github.com/mattn/go-isatty":       {license: "MIT", files: map[string]string{"LICENSE": "MIT"}},
	"github.com/ncruces/go-strftime":   {license: "MIT", files: map[string]string{"LICENSE": "MIT"}},
	"github.com/osquery/osquery-go":    {license: "MIT", files: map[string]string{"LICENSE": "MIT"}},
	"github.com/pkg/errors":            {license: "BSD-2-Clause", files: map[string]string{"LICENSE": "BSD-2-Clause"}},
	"github.com/remyoudompheng/bigfft": {license: "BSD-3-Clause", files: map[string]string{"LICENSE": "BSD-3-Clause"}},
	"go.opentelemetry.io/otel":         {license: "Apache-2.0", files: map[string]string{"LICENSE": "Apache-2.0"}},
	"go.opentelemetry.io/otel/metric":  {license: "Apache-2.0", files: map[string]string{"LICENSE": "Apache-2.0"}},
	"go.opentelemetry.io/otel/trace":   {license: "Apache-2.0", files: map[string]string{"LICENSE": "Apache-2.0"}},
	"golang.org/x/sys": {license: "BSD-3-Clause", remark: "with Google's additional patent grant (PATENTS)",
		files: map[string]string{"LICENSE": "BSD-3-Clause", "PATENTS": "patent-grant"}},
	"golang.org/x/text": {license: "BSD-3-Clause", remark: "with Google's additional patent grant (PATENTS)",
		files: map[string]string{"LICENSE": "BSD-3-Clause", "PATENTS": "patent-grant"}},
	"gopkg.in/yaml.v3": {license: "MIT AND Apache-2.0",
		remark: "files ported from libyaml are MIT, the rest Apache-2.0 (see LICENSE and NOTICE)",
		files:  map[string]string{"LICENSE": "Apache-2.0,MIT", "NOTICE": "Apache-2.0,notice"}},
	"modernc.org/libc": {license: "BSD-3-Clause AND MIT",
		remark: "LICENSE-3RD-PARTY.md: code derived from Go (BSD-3-Clause), musl libc, go-netdb and NixOS/nixpkgs (MIT)",
		files:  map[string]string{"LICENSE": "BSD-3-Clause", "LICENSE-3RD-PARTY.md": "BSD-3-Clause,MIT,public-domain"}},
	"modernc.org/mathutil": {license: "BSD-3-Clause", files: map[string]string{"LICENSE": "BSD-3-Clause"}},
	"modernc.org/memory": {license: "BSD-3-Clause",
		remark: "LICENSE-GO and LICENSE-MMAP-GO cover code derived from Go and mmap-go (both BSD-3-Clause); LICENSE-LOGO is the source of the project logo, which is not linked",
		files: map[string]string{"LICENSE": "BSD-3-Clause", "LICENSE-GO": "BSD-3-Clause",
			"LICENSE-LOGO": "reference", "LICENSE-MMAP-GO": "BSD-3-Clause"}},
	"modernc.org/sqlite": {license: "BSD-3-Clause; SQLite itself is public domain",
		remark: "LICENSE-SQLITE_VEC covers modernc.org/sqlite/vec, which spoor does not link; LICENSE-3RD-PARTY.md is the module's own inventory of everything else",
		files: map[string]string{"LICENSE": "BSD-3-Clause", "LICENSE-3RD-PARTY.md": "Apache-2.0,BSD-3-Clause,MIT,MPL-2.0,public-domain",
			"LICENSE-SQLITE": "public-domain", "LICENSE-SQLITE_VEC": "MIT"}},
	"mvdan.cc/sh/v3": {license: "BSD-3-Clause", files: map[string]string{"LICENSE": "BSD-3-Clause"}},
}

// goRuntime is the reviewed entry for the toolchain's own license files.
var goRuntime = review{license: "BSD-3-Clause", remark: "with Google's additional patent grant (PATENTS)",
	files: map[string]string{"LICENSE": "BSD-3-Clause", "PATENTS": "patent-grant"}}

// detect names the license families a text contains. It recognises the
// operative sentences of each license, not its title, so a file that merely
// mentions a license by name is not counted as carrying it.
func detect(text string) string {
	t := strings.Join(strings.Fields(text), " ")
	low := strings.ToLower(t)
	var fam []string
	if strings.Contains(t, "TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION") ||
		strings.Contains(t, `Licensed under the Apache License, Version 2.0`) {
		fam = append(fam, "Apache-2.0")
	}
	if strings.Contains(t, "Redistribution and use in source and binary forms") {
		if strings.Contains(low, "neither the name") || strings.Contains(low, "may be used to endorse") {
			fam = append(fam, "BSD-3-Clause")
		} else {
			fam = append(fam, "BSD-2-Clause")
		}
	}
	if strings.Contains(t, "Permission is hereby granted, free of charge") {
		fam = append(fam, "MIT")
	}
	if strings.Contains(t, "Mozilla Public License Version 2.0") || strings.Contains(t, "Mozilla Public License, version 2.0") {
		fam = append(fam, "MPL-2.0")
	}
	if strings.Contains(low, "dedicated to the public domain") || strings.Contains(low, "public domain.") || strings.Contains(low, "in the public domain") {
		fam = append(fam, "public-domain")
	}
	if strings.Contains(t, "Additional IP Rights Grant (Patents)") {
		fam = append(fam, "patent-grant")
	}
	if strings.Contains(t, "This product includes software developed at") || strings.HasPrefix(strings.TrimSpace(t), "Copyright 2011-2016 Canonical") {
		fam = append(fam, "notice")
	}
	if len(fam) == 0 && regexp.MustCompile(`^https?://\S+$`).MatchString(strings.TrimSpace(t)) {
		fam = append(fam, "reference")
	}
	sort.Strings(fam)
	return strings.Join(fam, ",")
}

type module struct {
	path, version, dir string
	targets            map[string]bool
	pkgDirs            map[string]bool
}

type licFile struct {
	rel, abs, text string
}

func run(repo string, args ...string) (string, error) {
	return runEnv(repo, nil, args...)
}

func runEnv(repo string, env []string, args ...string) (string, error) {
	cmd := exec.Command("go", args...)
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), env...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("go %s: %v: %s", strings.Join(args, " "), err, errb.String())
	}
	return out.String(), nil
}

func linked(repo string) (map[string]*module, error) {
	mods := map[string]*module{}
	const tmpl = `{{if .Module}}{{if not .Module.Main}}{{with .Module.Replace}}{{.Path}}{{"\t"}}{{.Version}}{{"\t"}}{{.Dir}}{{else}}{{.Module.Path}}{{"\t"}}{{.Module.Version}}{{"\t"}}{{.Module.Dir}}{{end}}{{"\t"}}{{.Dir}}{{end}}{{end}}`
	for _, tg := range targets {
		out, err := runEnv(repo, []string{"CGO_ENABLED=0", "GOOS=" + tg[0], "GOARCH=" + tg[1], "GOFLAGS=-mod=readonly"},
			"list", "-deps", "-f", tmpl, "./cmd/spoor")
		if err != nil {
			return nil, err
		}
		sc := bufio.NewScanner(strings.NewReader(out))
		for sc.Scan() {
			f := strings.Split(sc.Text(), "\t")
			if len(f) != 4 {
				continue
			}
			if f[2] == "" {
				return nil, fmt.Errorf("module %s %s is not in the module cache (run go mod download)", f[0], f[1])
			}
			m := mods[f[0]]
			if m == nil {
				m = &module{path: f[0], version: f[1], dir: f[2], targets: map[string]bool{}, pkgDirs: map[string]bool{}}
				mods[f[0]] = m
			}
			if m.version != f[1] {
				return nil, fmt.Errorf("module %s linked at two versions: %s and %s", f[0], m.version, f[1])
			}
			m.targets[tg[0]+"/"+tg[1]] = true
			m.pkgDirs[f[3]] = true
		}
	}
	// Every linked module must be in the build list (go list -m all).
	all, err := run(repo, "list", "-m", "-f", "{{.Path}} {{.Version}}", "all")
	if err != nil {
		return nil, err
	}
	inGraph := map[string]bool{}
	for _, l := range strings.Split(all, "\n") {
		inGraph[strings.TrimSpace(l)] = true
	}
	for _, m := range mods {
		if !inGraph[m.path+" "+m.version] {
			return nil, fmt.Errorf("module %s %s is linked but not in go list -m all", m.path, m.version)
		}
	}
	return mods, nil
}

func readLic(abs, rel string) (licFile, error) {
	b, err := os.ReadFile(abs)
	if err != nil {
		return licFile{}, err
	}
	return licFile{rel: filepath.ToSlash(rel), abs: abs, text: string(b)}, nil
}

// licenseFiles returns the license files at the module root and in every
// directory between a linked package and the module root.
func licenseFiles(m *module) ([]licFile, error) {
	seen := map[string]bool{}
	var out []licFile
	add := func(dir string) error {
		ents, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, e := range ents {
			if e.IsDir() || !isLicenseName(e.Name()) {
				continue
			}
			abs := filepath.Join(dir, e.Name())
			if seen[abs] {
				continue
			}
			seen[abs] = true
			rel, _ := filepath.Rel(m.dir, abs)
			lf, err := readLic(abs, rel)
			if err != nil {
				return err
			}
			out = append(out, lf)
		}
		return nil
	}
	if err := add(m.dir); err != nil {
		return nil, err
	}
	rootHas := len(out) > 0
	for d := range m.pkgDirs {
		for dir := d; dir != m.dir && strings.HasPrefix(dir, m.dir+string(filepath.Separator)); dir = filepath.Dir(dir) {
			if err := add(dir); err != nil {
				return nil, err
			}
		}
	}
	if !rootHas {
		return nil, fmt.Errorf("module %s %s: no license file at the module root %s", m.path, m.version, m.dir)
	}
	sort.Slice(out, func(i, j int) bool {
		di, dj := strings.Count(out[i].rel, "/"), strings.Count(out[j].rel, "/")
		if di != dj {
			return di < dj
		}
		return out[i].rel < out[j].rel
	})
	return out, nil
}

func checkReview(name string, rv review, files []licFile) error {
	var errs []string
	got := map[string]bool{}
	for _, f := range files {
		got[f.rel] = true
		want, ok := rv.files[f.rel]
		if !ok {
			errs = append(errs, fmt.Sprintf("%s: license file %s is not in the reviewed table (detected %q)", name, f.rel, detect(f.text)))
			continue
		}
		if d := detect(f.text); d != want {
			errs = append(errs, fmt.Sprintf("%s: %s: detected %q, reviewed %q: read the text and update the table", name, f.rel, d, want))
		}
	}
	for f := range rv.files {
		if !got[f] {
			errs = append(errs, fmt.Sprintf("%s: reviewed license file %s was not found", name, f))
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "\n"))
	}
	return nil
}

func linkedOn(set map[string]bool) string {
	if len(set) == len(targets) {
		return "all release targets"
	}
	byOS := map[string][]string{}
	for t := range set {
		p := strings.SplitN(t, "/", 2)
		byOS[p[0]] = append(byOS[p[0]], p[1])
	}
	var parts []string
	for _, tg := range targets {
		os := tg[0]
		if archs, ok := byOS[os]; ok {
			sort.Strings(archs)
			if len(archs) == 2 {
				parts = append(parts, os)
			} else {
				parts = append(parts, os+"/"+strings.Join(archs, ","))
			}
			delete(byOS, os)
		}
	}
	return strings.Join(parts, ", ") + " only"
}

const rule = "================================================================================"

func generate(repo string) ([]byte, error) {
	mods, err := linked(repo)
	if err != nil {
		return nil, err
	}
	var names []string
	for p := range mods {
		names = append(names, p)
	}
	sort.Strings(names)

	type entry struct {
		m     *module
		rv    review
		files []licFile
	}
	var entries []entry
	var errs []string
	for _, p := range names {
		m := mods[p]
		rv, ok := reviewed[p]
		if !ok {
			errs = append(errs, fmt.Sprintf("%s %s is linked but has no reviewed entry: read its license files and add one", p, m.version))
			continue
		}
		files, err := licenseFiles(m)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		if err := checkReview(p, rv, files); err != nil {
			errs = append(errs, err.Error())
			continue
		}
		entries = append(entries, entry{m, rv, files})
	}
	for p := range reviewed {
		if mods[p] == nil {
			errs = append(errs, fmt.Sprintf("%s is in the reviewed table but no longer linked: remove it", p))
		}
	}

	env, err := run(repo, "env", "GOROOT", "GOVERSION")
	if err != nil {
		return nil, err
	}
	ev := strings.Fields(env)
	if len(ev) != 2 {
		return nil, fmt.Errorf("unexpected go env output %q", env)
	}
	goroot, gover := ev[0], ev[1]
	var goFiles []licFile
	for _, n := range []string{"LICENSE", "PATENTS"} {
		lf, err := readLic(filepath.Join(goroot, n), n)
		if err != nil {
			errs = append(errs, fmt.Sprintf("Go toolchain %s: %v", gover, err))
			continue
		}
		goFiles = append(goFiles, lf)
	}
	if err := checkReview("Go "+gover, goRuntime, goFiles); err != nil {
		errs = append(errs, err.Error())
	}
	if len(errs) > 0 {
		sort.Strings(errs)
		return nil, errors.New(strings.Join(errs, "\n"))
	}

	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	w("THIRD-PARTY LICENSES FOR spoor\n\n")
	w("spoor itself is licensed under the Apache License, Version 2.0 (see LICENSE);\n")
	w("credits for reused data and designs are in NOTICE.\n\n")
	w("The spoor binary (cmd/spoor) is statically linked. It contains the Go\n")
	w("standard library and runtime and the third-party Go modules listed below.\n")
	w("For each of them this file reproduces, unmodified, every license, notice and\n")
	w("patent file found at the module root and in the directories of the packages\n")
	w("spoor links, as published in the module (read from the Go module cache).\n\n")
	w("Scope: the modules linked into ./cmd/spoor for any release target (linux,\n")
	w("darwin and windows on amd64 and arm64, CGO_ENABLED=0), i.e. the union over\n")
	w("those targets of\n\n")
	w("    go list -deps -f '{{with .Module}}{{.Path}} {{.Version}}{{end}}' ./cmd/spoor\n\n")
	w("Modules in `go list -m all` that are not linked (test and build tooling) are\n")
	w("not distributed in the binary and are not listed. The \"License\" column names\n")
	w("the terms of the code spoor links; a remark explains where a module's files\n")
	w("name more. Toolchain: %s.\n\n", gover)
	w("After a dependency change, regenerate this file from the repository root:\n\n")
	w("    go run ./tools/licensegen -repo . -out THIRD_PARTY_LICENSES\n\n")
	w("It runs the command above for every release target and, for each module\n")
	w("found, takes every file named LICENSE*, LICENCE*, COPYING*, NOTICE* or\n")
	w("PATENTS* at the module root (go list -m -f '{{.Dir}}' <module>) and in the\n")
	w("directories between each linked package and that root. It stops when a\n")
	w("module has no such file, or when a module or its license text is not in\n")
	w("its reviewed table, so a person reads the new text before a license name\n")
	w("below changes. `make licenses-check` (run in CI) fails when this file is\n")
	w("stale.\n\n")

	w("INDEX\n\n")
	type row struct{ mod, ver, lic, on string }
	var rows []row
	for _, e := range entries {
		rows = append(rows, row{e.m.path, e.m.version, e.rv.license, linkedOn(e.m.targets)})
	}
	rows = append(rows, row{"Go standard library and runtime", gover, goRuntime.license, "all release targets"})
	wm, wv := len("Module"), len("Version")
	for _, r := range rows {
		wm = max(wm, len(r.mod))
		wv = max(wv, len(r.ver))
	}
	w("%-*s  %-*s  %s\n", wm, "Module", wv, "Version", "License (linked code); linked on")
	for _, r := range rows {
		w("%-*s  %-*s  %s; %s\n", wm, r.mod, wv, r.ver, r.lic, r.on)
	}
	w("\n")

	section := func(name, ver, lic, on, remark string, files []licFile) {
		w("%s\n%s %s\n%s\n\n", rule, name, ver, rule)
		w("License: %s\n", lic)
		w("Linked on: %s\n", on)
		if remark != "" {
			w("Remark: %s\n", remark)
		}
		var fl []string
		for _, f := range files {
			fl = append(fl, f.rel)
		}
		w("Files: %s\n\n", strings.Join(fl, ", "))
		for _, f := range files {
			w("---- %s %s: %s ----\n\n", name, ver, f.rel)
			t := strings.ReplaceAll(f.text, "\r\n", "\n")
			t = strings.TrimRight(t, "\n")
			w("%s\n\n", t)
		}
	}
	for _, e := range entries {
		section(e.m.path, e.m.version, e.rv.license, linkedOn(e.m.targets), e.rv.remark, e.files)
	}
	section("Go standard library and runtime", gover, goRuntime.license, "all release targets", goRuntime.remark, goFiles)
	w("%s\nEnd of THIRD_PARTY_LICENSES\n", rule)
	return []byte(b.String()), nil
}

func main() {
	repo := flag.String("repo", ".", "repository root (module github.com/thomastysong/spoor)")
	out := flag.String("out", "THIRD_PARTY_LICENSES", "output file, relative to -repo")
	check := flag.Bool("check", false, "compare with the existing file instead of writing; exit 1 when it differs")
	dump := flag.Bool("dump", false, "print each linked module's license files and detected families, then exit")
	flag.Parse()

	if *dump {
		mods, err := linked(*repo)
		if err != nil {
			fmt.Fprintln(os.Stderr, "licensegen:", err)
			os.Exit(1)
		}
		var names []string
		for p := range mods {
			names = append(names, p)
		}
		sort.Strings(names)
		for _, p := range names {
			m := mods[p]
			files, err := licenseFiles(m)
			if err != nil {
				fmt.Println(p, "ERROR", err)
				continue
			}
			for _, f := range files {
				fmt.Printf("%s %s %s %q [%s]\n", p, m.version, f.rel, detect(f.text), linkedOn(m.targets))
			}
		}
		return
	}

	data, err := generate(*repo)
	if err != nil {
		fmt.Fprintln(os.Stderr, "licensegen: refusing to write THIRD_PARTY_LICENSES:")
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	path := filepath.Join(*repo, *out)
	if *check {
		cur, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, "licensegen:", err)
			os.Exit(1)
		}
		if !bytes.Equal(cur, data) {
			fmt.Fprintf(os.Stderr, "licensegen: %s is stale: regenerate it\n", path)
			os.Exit(1)
		}
		fmt.Printf("licensegen: %s is current (%d bytes)\n", path, len(cur))
		return
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "licensegen:", err)
		os.Exit(1)
	}
	fmt.Printf("licensegen: wrote %s (%d bytes)\n", path, len(data))
}
