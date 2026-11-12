package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/thomastysong/thomastysong/hawkbell/internal/bundle"
	"github.com/thomastysong/thomastysong/hawkbell/internal/catalog"
	"github.com/thomastysong/thomastysong/hawkbell/internal/config"
	"github.com/thomastysong/thomastysong/hawkbell/internal/hookcmd"
	"github.com/thomastysong/thomastysong/hawkbell/internal/platform"
	"github.com/thomastysong/thomastysong/hawkbell/internal/rules"
)

// cfgFlags are the flags every command that reads the configuration takes.
type cfgFlags struct {
	path    string
	dataDir string
}

func (c *cfgFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&c.path, "config", "", "configuration file (default "+defaultConfigPath()+"; a missing file means built-in defaults)")
	fs.StringVar(&c.dataDir, "data-dir", "", "data directory, overriding data_dir in the configuration")
}

// defaultConfigPath is the file `hawkbell hook` reads too, so the hook, the
// daemon and the CLI agree without being told.
func defaultConfigPath() string {
	return filepath.Join(platform.DefaultDirs().Config, hookcmd.ConfigFileName)
}

// loadConfig reads the configuration the way the hook and daemon do: the
// given file or the platform default, over built-in defaults rooted at the
// platform data directory. It returns the path that was used.
func loadConfig(c cfgFlags) (*config.Config, string, error) {
	path := c.path
	if path == "" {
		path = defaultConfigPath()
	}
	cfg, err := config.Load(path, platform.DefaultDirs().Data)
	if err != nil {
		return nil, path, fmt.Errorf("config %s: %w", path, err)
	}
	if c.dataDir != "" {
		abs, err := filepath.Abs(c.dataDir)
		if err != nil {
			return nil, path, err
		}
		cfg.DataDir = abs
	}
	if cfg.DataDir == "" {
		return nil, path, errors.New("no data directory: set data_dir or --data-dir")
	}
	return cfg, path, nil
}

// configExists reports whether the configuration file is present; doctor
// distinguishes "defaults because there is no file" from "the file".
func configExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// ruleSource selects rule content for the commands that evaluate rules.
type ruleSource struct {
	dirs       []string // extra directories, merged last (later wins by rule id)
	noEmbedded bool     // use only dirs
	noHost     bool     // ignore the installed bundle and config rules.dirs
}

// ruleInfo says where the rules came from, for doctor and listings.
type ruleInfo struct {
	Embedded      bool     `json:"embedded"`
	BundleDir     string   `json:"bundle_dir,omitempty"`
	BundleVersion uint64   `json:"bundle_version,omitempty"`
	Dirs          []string `json:"dirs,omitempty"`
	Count         int      `json:"count"`
	Version       string   `json:"version"`
	Hash          string   `json:"hash"`
	Problems      []string `json:"problems,omitempty"`
}

// loadRules builds the rule set in the order the hook and daemon use:
// embedded packs, the installed signed bundle, config rules.dirs, then the
// directories given on the command line. Unlike the hook, a source that
// cannot be loaded is an error here: an operator asking for a listing or a
// test run must not be shown a partial picture without being told.
// rules.disable is applied, so listings show what this host runs (the
// engine applies it again to its own copy, which changes nothing).
func loadRules(cfg *config.Config, src ruleSource) (*rules.Set, ruleInfo, error) {
	var info ruleInfo
	var set *rules.Set
	add := func(s *rules.Set) {
		if set == nil {
			set = s
			return
		}
		set.Merge(s)
	}
	if !src.noEmbedded {
		s, err := rules.LoadEmbedded()
		if err != nil {
			return nil, info, fmt.Errorf("embedded rules: %w", err)
		}
		info.Embedded = true
		add(s)
	}
	if !src.noHost && cfg != nil {
		if dir, m, ok := bundle.Current(cfg.BundleDir()); ok {
			s, err := rules.LoadDir(dir)
			if err != nil {
				return nil, info, fmt.Errorf("installed bundle %s: %w", dir, err)
			}
			info.BundleDir, info.BundleVersion = dir, m.Version
			add(s)
		}
		for _, d := range cfg.Rules.Dirs {
			if d == "" {
				continue
			}
			s, err := rules.LoadDir(d)
			if err != nil {
				return nil, info, fmt.Errorf("rules.dirs %s: %w", d, err)
			}
			info.Dirs = append(info.Dirs, d)
			add(s)
		}
	}
	for _, d := range src.dirs {
		s, err := rules.LoadDir(d)
		if err != nil {
			return nil, info, fmt.Errorf("rules directory %s: %w", d, err)
		}
		info.Dirs = append(info.Dirs, d)
		add(s)
	}
	if set == nil {
		return nil, info, errors.New("no rule content: --no-embedded needs at least one --dir")
	}
	if cfg != nil {
		set.Disable(cfg.Rules.Disable...)
	}
	info.Count, info.Version, info.Hash = set.Count(), set.Version(), set.Hash()
	return set, info, nil
}

// loadCatalog returns the embedded catalog with the overlay of the
// installed bundle, when there is one. An overlay that fails validation
// leaves the embedded catalog in force and is returned as overlayErr.
func loadCatalog(cfg *config.Config) (c *catalog.Catalog, overlayErr, err error) {
	c, err = catalog.Load()
	if err != nil {
		return nil, nil, err
	}
	if cfg == nil {
		return c, nil, nil
	}
	if dir, _, ok := bundle.Current(cfg.BundleDir()); ok {
		over := filepath.Join(dir, "catalog")
		if fi, serr := os.Stat(over); serr == nil && fi.IsDir() {
			if oerr := c.LoadOverlay(over); oerr != nil {
				return c, fmt.Errorf("bundle catalog overlay: %w", oerr), nil
			}
		}
	}
	return c, nil, nil
}
