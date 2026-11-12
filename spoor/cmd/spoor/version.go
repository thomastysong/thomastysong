package main

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
)

// Set at link time by the release build:
//
//	-ldflags "-X main.version=1.2.3 -X main.commit=abc1234 -X main.date=2026-11-12T00:00:00Z"
//
// A plain `go build` falls back to the module and VCS data Go embeds.
var (
	version = ""
	commit  = ""
	date    = ""
)

type buildInfo struct {
	Version   string `json:"version"`
	Commit    string `json:"commit,omitempty"`
	Date      string `json:"date,omitempty"`
	Modified  bool   `json:"modified,omitempty"`
	GoVersion string `json:"go_version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

func readBuildInfo() buildInfo {
	b := buildInfo{Version: version, Commit: commit, Date: date, GoVersion: runtime.Version(), OS: runtime.GOOS, Arch: runtime.GOARCH}
	if bi, ok := debug.ReadBuildInfo(); ok {
		if b.Version == "" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			b.Version = bi.Main.Version
		}
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				if b.Commit == "" {
					b.Commit = s.Value
				}
			case "vcs.time":
				if b.Date == "" {
					b.Date = s.Value
				}
			case "vcs.modified":
				b.Modified = s.Value == "true"
			}
		}
	}
	if b.Version == "" {
		b.Version = "dev"
	}
	if len(b.Commit) > 12 {
		b.Commit = b.Commit[:12]
	}
	return b
}

// versionString is what hooks, health records and the osquery extension
// report.
func versionString() string { return readBuildInfo().Version }

func (a *app) cmdVersion(args []string) int {
	fs := a.newFlags("version", "version [--json]", "Prints the version, commit, Go version and platform.")
	asJSON := fs.Bool("json", false, "print JSON")
	if _, code, done := a.parse(fs, args); done {
		return code
	}
	b := readBuildInfo()
	if *asJSON {
		return a.printJSON(b)
	}
	var extra []string
	if b.Commit != "" {
		c := b.Commit
		if b.Modified {
			c += "-dirty"
		}
		extra = append(extra, c)
	}
	if b.Date != "" {
		extra = append(extra, b.Date)
	}
	fmt.Fprintf(a.stdout, "spoor %s", b.Version)
	if len(extra) > 0 {
		fmt.Fprintf(a.stdout, " (%s)", strings.Join(extra, ", "))
	}
	fmt.Fprintf(a.stdout, " %s %s/%s\n", b.GoVersion, b.OS, b.Arch)
	return exitOK
}

// moduleLicenses maps the modules spoor links to their licenses, read from
// each module's LICENSE file in the module cache (2026-11-12). The full texts
// ship in THIRD_PARTY_LICENSES with the source and release archives.
// moduleLicenses names the license of the code spoor links from each module.
// TestModuleLicensesMatchThirdPartyFile holds it to the INDEX of
// THIRD_PARTY_LICENSES, which tools/licensegen generates from the license
// files themselves.
func moduleLicenses() map[string]string {
	return map[string]string{
		"github.com/BurntSushi/toml":       "MIT",
		"github.com/apache/thrift":         "Apache-2.0",
		"github.com/klauspost/compress":    "BSD-3-Clause AND MIT (the Apache-2.0 part, gzhttp, is not linked)",
		"github.com/osquery/osquery-go":    "MIT",
		"golang.org/x/sys":                 "BSD-3-Clause",
		"golang.org/x/text":                "BSD-3-Clause",
		"gopkg.in/yaml.v3":                 "MIT AND Apache-2.0",
		"modernc.org/sqlite":               "BSD-3-Clause (SQLite itself is public domain)",
		"mvdan.cc/sh/v3":                   "BSD-3-Clause",
		"github.com/Microsoft/go-winio":    "MIT",
		"github.com/dustin/go-humanize":    "MIT",
		"github.com/google/uuid":           "BSD-3-Clause",
		"github.com/mattn/go-isatty":       "MIT",
		"github.com/ncruces/go-strftime":   "MIT",
		"github.com/pkg/errors":            "BSD-2-Clause",
		"github.com/remyoudompheng/bigfft": "BSD-3-Clause",
		"modernc.org/libc":                 "BSD-3-Clause AND MIT",
		"modernc.org/mathutil":             "BSD-3-Clause",
		"modernc.org/memory":               "BSD-3-Clause",
		"github.com/go-logr/logr":          "Apache-2.0",
		"github.com/go-logr/stdr":          "Apache-2.0",
		"go.opentelemetry.io/otel":         "Apache-2.0",
		"go.opentelemetry.io/otel/metric":  "Apache-2.0",
		"go.opentelemetry.io/otel/trace":   "Apache-2.0",
	}
}

type moduleLicense struct {
	Path    string `json:"path"`
	Version string `json:"version"`
	License string `json:"license"`
}

func (a *app) cmdLicenses(args []string) int {
	fs := a.newFlags("licenses", "licenses [--json]", "Prints spoor's license and the license of every module linked into this binary.")
	asJSON := fs.Bool("json", false, "print JSON")
	if _, code, done := a.parse(fs, args); done {
		return code
	}
	var mods []moduleLicense
	known := moduleLicenses()
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			m := d
			if d.Replace != nil {
				m = d.Replace
			}
			lic := known[m.Path]
			if lic == "" {
				lic = "see the module's own LICENSE"
			}
			mods = append(mods, moduleLicense{Path: m.Path, Version: m.Version, License: lic})
		}
	}
	if *asJSON {
		return a.printJSON(map[string]any{"spoor": "Apache-2.0", "modules": mods})
	}
	fmt.Fprintln(a.stdout, "spoor is licensed under the Apache License 2.0 (LICENSE, NOTICE).")
	fmt.Fprintln(a.stdout, "Linked modules (full texts in THIRD_PARTY_LICENSES):")
	tw := a.table()
	for _, m := range mods {
		fmt.Fprintf(tw, "  %s\t%s\t%s\n", m.Path, m.Version, m.License)
	}
	tw.Flush()
	return exitOK
}
