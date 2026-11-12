// Command rulescache regenerates internal/rules/packs/embedded.cache, the
// pre-parsed copy of the embedded rule packs that keeps guard-mode hook
// start-up inside its budget. Run it through go generate after editing
// anything under internal/rules/packs or internal/rules/lists.yaml:
//
//	go generate ./internal/rules
//
// With -check it writes nothing and exits 1 when the cache is stale, for
// CI. A stale or missing cache is never wrong at run time (LoadEmbedded
// falls back to parsing the YAML), only slower; the rules package tests
// fail until it is regenerated.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/thomastysong/thomastysong/hawkbell/internal/rules"
)

func main() {
	dir := flag.String("dir", ".", "the internal/rules directory")
	out := flag.String("out", "packs/embedded.cache", "cache file, relative to -dir")
	check := flag.Bool("check", false, "report whether the cache is current; write nothing")
	flag.Parse()
	if err := run(*dir, *out, *check); err != nil {
		fmt.Fprintln(os.Stderr, "rulescache:", err)
		os.Exit(1)
	}
}

func run(dir, out string, check bool) error {
	files, err := content(dir)
	if err != nil {
		return err
	}
	b, err := rules.EncodeCache(files)
	if err != nil {
		return err
	}
	target := filepath.Join(dir, out)
	cur, err := os.ReadFile(target)
	if err == nil && bytes.Equal(cur, b) {
		return nil
	}
	if check {
		return fmt.Errorf("%s is stale: run go generate ./internal/rules", target)
	}
	tmp := target + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, target); err != nil {
		os.Remove(tmp)
		return err
	}
	fmt.Printf("rulescache: wrote %s (%d bytes from %d files)\n", target, len(b), len(files))
	return nil
}

// content reads the files LoadEmbedded embeds, under the names it uses:
// packs/*.yaml (no dot files) and lists.yaml.
func content(dir string) (map[string][]byte, error) {
	files := map[string][]byte{}
	entries, err := os.ReadDir(filepath.Join(dir, "packs"))
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		n := e.Name()
		if e.Type().IsRegular() && strings.HasSuffix(n, ".yaml") && !strings.HasPrefix(n, ".") {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join(dir, "packs", n))
		if err != nil {
			return nil, err
		}
		files["packs/"+n] = b
	}
	if b, err := os.ReadFile(filepath.Join(dir, "lists.yaml")); err == nil {
		files["lists.yaml"] = b
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return files, nil
}
