package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/bundle"
	"github.com/thomastysong/thomastysong/hawkbell/internal/catalog"
	"github.com/thomastysong/thomastysong/hawkbell/internal/rules"
)

func (a *app) cmdBundle(args []string) int {
	return a.dispatch("bundle", []subcommand{
		{"keygen", "create an Ed25519 signing key pair (<prefix>.key, <prefix>.pub)", a.bundleKeygen},
		{"create", "pack and sign rules, lists, suppressions and catalog overlays", a.bundleCreate},
		{"verify", "check a bundle's signature and contents against trusted keys", a.bundleVerify},
		{"pull", "fetch (or take a local file), verify and install a bundle", a.bundlePull},
	}, args)
}

// maxKeyFile bounds key files read from disk.
const maxKeyFile = 16 << 10

func (a *app) bundleKeygen(args []string) int {
	fs := a.newFlags("bundle keygen", "bundle keygen --out <prefix> [--json]",
		`Creates a signing key pair: <prefix>.key (private, mode 0600) and <prefix>.pub.
Put the public key in bundle.public_keys on every host; keep the private key
offline, used for nothing but hawkbell bundles. Existing files are never replaced.`)
	out := fs.String("out", "", "file name prefix for the key pair (required)")
	asJSON := fs.Bool("json", false, "print JSON")
	if pos, code, done := a.parse(fs, args); done {
		return code
	} else if len(pos) > 0 {
		return a.usageErr("bundle keygen", "unexpected argument %q", pos[0])
	}
	if *out == "" {
		return a.usageErr("bundle keygen", "--out <prefix> is required: the private key is never printed")
	}
	pub, priv, err := bundle.GenerateKey()
	if err != nil {
		return a.fail("bundle keygen", err)
	}
	keyPath, pubPath := *out+".key", *out+".pub"
	if err := writeExport(keyPath, []byte(bundle.EncodePrivateKey(priv)+"\n"), 0o600, false); err != nil {
		return a.fail("bundle keygen", err)
	}
	if err := writeExport(pubPath, []byte(bundle.EncodePublicKey(pub)+"\n"), 0o644, false); err != nil {
		os.Remove(keyPath)
		return a.fail("bundle keygen", err)
	}
	if *asJSON {
		return a.printJSON(map[string]string{"private_key_file": keyPath, "public_key_file": pubPath, "public_key": bundle.EncodePublicKey(pub), "key_id": bundle.KeyID(pub)})
	}
	fmt.Fprintf(a.stdout, "private key: %s (keep it offline)\npublic key:  %s\nkey id:      %s\n\nbundle:\n  public_keys:\n    - %s\n", keyPath, pubPath, bundle.KeyID(pub), bundle.EncodePublicKey(pub))
	return exitOK
}

func readPrivateKey(path string) (ed25519.PrivateKey, error) {
	b, err := readSmall(path, maxKeyFile)
	if err != nil {
		return nil, err
	}
	if fi, err := os.Stat(path); err == nil && fi.Mode().Perm()&0o077 != 0 && runtime.GOOS != "windows" {
		return nil, fmt.Errorf("%s: a signing key must not be readable by group or others (chmod 600)", path)
	}
	return bundle.ParsePrivateKey(strings.TrimSpace(string(b)))
}

// readPublicKeys accepts key values and files holding one key per line.
func readPublicKeys(specs []string) ([]ed25519.PublicKey, error) {
	var out []ed25519.PublicKey
	for _, s := range specs {
		vals := []string{s}
		if fi, err := os.Stat(s); err == nil && fi.Mode().IsRegular() {
			b, err := readSmall(s, maxKeyFile)
			if err != nil {
				return nil, err
			}
			vals = nil
			for _, l := range strings.Split(string(b), "\n") {
				if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
					vals = append(vals, l)
				}
			}
		}
		for _, v := range vals {
			k, err := bundle.ParsePublicKey(v)
			if err != nil {
				return nil, fmt.Errorf("public key %s: %w", clip(s, 60), err)
			}
			out = append(out, k)
		}
	}
	return out, nil
}

func readSmall(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", path)
	}
	if fi.Size() > max {
		return nil, fmt.Errorf("%s: larger than %d bytes", path, max)
	}
	b := make([]byte, fi.Size())
	if _, err := io.ReadFull(f, b); err != nil {
		return nil, err
	}
	return b, nil
}

func (a *app) bundleCreate(args []string) int {
	fs := a.newFlags("bundle create", "bundle create --src dir --version N --key file --out bundle.tar.gz [--note text]",
		`Packs rules/*.yaml, lists.yaml, suppressions.yaml and catalog/*.yaml from --src
with a manifest, proves the archive passes the same verification every host
runs, and writes <out> and its detached signature <out>.sig. Versions must
only ever increase: hosts refuse a downgrade. SOURCE_DATE_EPOCH (or --created)
makes the archive reproducible.`)
	src := fs.String("src", "", "source directory (required)")
	ver := fs.Uint64("version", 0, "bundle version, higher than every one published before (required)")
	key := fs.String("key", "", "private key file from `bundle keygen` (required)")
	out := fs.String("out", "", "archive to write (required)")
	note := fs.String("note", "", "free text shown to operators (max 1024 bytes)")
	created := fs.String("created", "", "creation time (RFC 3339); default SOURCE_DATE_EPOCH or now")
	force := fs.Bool("force", false, "replace existing output files")
	asJSON := fs.Bool("json", false, "print the manifest as JSON")
	if pos, code, done := a.parse(fs, args); done {
		return code
	} else if len(pos) > 0 {
		return a.usageErr("bundle create", "unexpected argument %q", pos[0])
	}
	if *src == "" || *ver == 0 || *key == "" || *out == "" {
		return a.usageErr("bundle create", "--src, --version (>= 1), --key and --out are required")
	}
	o := bundle.CreateOptions{Version: *ver, Note: *note}
	switch {
	case *created != "":
		t, err := time.Parse(time.RFC3339, *created)
		if err != nil {
			return a.usageErr("bundle create", "--created: %v", err)
		}
		o.Created = t
	case a.getenv("SOURCE_DATE_EPOCH") != "":
		var sec int64
		if _, err := fmt.Sscanf(a.getenv("SOURCE_DATE_EPOCH"), "%d", &sec); err != nil || sec <= 0 {
			return a.usageErr("bundle create", "SOURCE_DATE_EPOCH is not a positive integer")
		}
		o.Created = time.Unix(sec, 0).UTC()
	}
	priv, err := readPrivateKey(*key)
	if err != nil {
		return a.fail("bundle create", err)
	}
	var buf bytes.Buffer
	m, err := bundle.CreateWith(*src, o, priv, &buf)
	if err != nil {
		return a.fail("bundle create", err)
	}
	sig := bundle.Sign(buf.Bytes(), priv)
	if sig == nil {
		return a.fail("bundle create", errors.New("signing failed"))
	}
	if err := writeExport(*out, buf.Bytes(), 0o644, *force); err != nil {
		return a.fail("bundle create", err)
	}
	if err := writeExport(*out+".sig", sig, 0o644, *force); err != nil {
		return a.fail("bundle create", err)
	}
	if *asJSON {
		return a.printJSON(manifestView(m))
	}
	fmt.Fprintf(a.stdout, "wrote %s (%d bytes, %d files, version %d) and %s.sig\n", *out, buf.Len(), len(m.Files), m.Version, *out)
	return exitOK
}

type manifestJSON struct {
	Version uint64            `json:"version"`
	Created time.Time         `json:"created"`
	Note    string            `json:"note,omitempty"`
	Digest  string            `json:"digest"`
	Files   map[string]string `json:"files"`
}

func manifestView(m *bundle.Manifest) manifestJSON {
	return manifestJSON{Version: m.Version, Created: m.Created, Note: m.Note, Digest: m.Digest(), Files: m.Files}
}

func (a *app) bundleVerify(args []string) int {
	fs := a.newFlags("bundle verify", "bundle verify --pub key|file [--sig file] [--json] <bundle.tar.gz>",
		"Checks the detached signature against the trusted keys, then the archive's structure and every file\nagainst the manifest. Exits 4 when the bundle does not verify.")
	var pubs listFlag
	fs.Var(&pubs, "pub", "trusted public key or key file (repeatable; default: bundle.public_keys of the configuration)")
	sigPath := fs.String("sig", "", "signature file (default <bundle>.sig)")
	var cf cfgFlags
	cf.register(fs)
	asJSON := fs.Bool("json", false, "print JSON")
	pos, code, done := a.parse(fs, args)
	if done {
		return code
	}
	if len(pos) != 1 {
		return a.usageErr("bundle verify", "give exactly one bundle archive")
	}
	keys, err := a.trustedKeys(pubs, cf)
	if err != nil {
		return a.fail("bundle verify", err)
	}
	tarball, err := readSmall(pos[0], bundle.MaxBytes)
	if err != nil {
		return a.fail("bundle verify", err)
	}
	if *sigPath == "" {
		*sigPath = pos[0] + ".sig"
	}
	sig, err := readSmall(*sigPath, 4<<10)
	if err != nil {
		return a.fail("bundle verify", err)
	}
	m, err := bundle.Verify(tarball, sig, keys)
	if err != nil {
		if *asJSON {
			a.printJSON(map[string]any{"ok": false, "reason": bundle.Reason(err), "error": err.Error()})
		} else {
			fmt.Fprintf(a.stdout, "INVALID: %v\n", err)
		}
		return exitCheck
	}
	if *asJSON {
		return a.printJSON(map[string]any{"ok": true, "manifest": manifestView(m)})
	}
	fmt.Fprintf(a.stdout, "OK: version %d, created %s, %d files, digest %s\n", m.Version, m.Created.UTC().Format(time.RFC3339), len(m.Files), shortHash(m.Digest()))
	for _, p := range m.Paths() {
		fmt.Fprintf(a.stdout, "  %s\n", p)
	}
	return exitOK
}

func (a *app) trustedKeys(pubs []string, cf cfgFlags) ([]ed25519.PublicKey, error) {
	if len(pubs) == 0 {
		cfg, _, err := loadConfig(cf)
		if err != nil {
			return nil, err
		}
		pubs = cfg.Bundle.PublicKeys
	}
	if len(pubs) == 0 {
		return nil, errors.New("no trusted key: pass --pub or set bundle.public_keys")
	}
	return readPublicKeys(pubs)
}

func (a *app) bundlePull(args []string) int {
	fs := a.newFlags("bundle pull", "bundle pull [--url URL | --file bundle.tar.gz] [--pub key] [--json]",
		`Fetches the bundle (bundle.url of the configuration, or --url) with its .sig,
verifies it against the trusted keys, checks that its rules and catalog
overlays load, and installs it under <data_dir>/bundle when it is newer than
the installed one. --file installs a local archive instead (air-gapped hosts,
MDM drops); its signature is <file>.sig unless --sig says otherwise. The
running daemon picks the new content up without a restart.`)
	var cf cfgFlags
	cf.register(fs)
	url := fs.String("url", "", "bundle URL (default bundle.url)")
	file := fs.String("file", "", "install a local bundle archive instead of downloading")
	sigPath := fs.String("sig", "", "signature of --file (default <file>.sig)")
	var pubs listFlag
	fs.Var(&pubs, "pub", "trusted public key or key file (repeatable; default bundle.public_keys)")
	timeout := fs.Duration("timeout", 2*time.Minute, "download timeout")
	asJSON := fs.Bool("json", false, "print JSON")
	if pos, code, done := a.parse(fs, args); done {
		return code
	} else if len(pos) > 0 {
		return a.usageErr("bundle pull", "unexpected argument %q", pos[0])
	}
	cfg, _, err := loadConfig(cf)
	if err != nil {
		return a.fail("bundle pull", err)
	}
	if len(pubs) == 0 {
		pubs = cfg.Bundle.PublicKeys
	}
	if len(pubs) == 0 {
		return a.fail("bundle pull", errors.New("no trusted key: pass --pub or set bundle.public_keys (unsigned content is never installed)"))
	}
	keys, err := readPublicKeys(pubs)
	if err != nil {
		return a.fail("bundle pull", err)
	}
	dest := cfg.BundleDir()
	// Hooks run unprivileged and read the bundle: the directory is public
	// content (signed), so it is created world-readable.
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return a.fail("bundle pull", err)
	}
	var updated bool
	var m *bundle.Manifest
	if *file != "" {
		if *sigPath == "" {
			*sigPath = *file + ".sig"
		}
		m, updated, err = installLocal(*file, *sigPath, keys, dest)
	} else {
		u := firstNonEmpty(*url, cfg.Bundle.URL)
		if u == "" {
			return a.usageErr("bundle pull", "no bundle URL: pass --url or --file, or set bundle.url")
		}
		ctx, cancel := context.WithTimeout(a.ctx, *timeout)
		defer cancel()
		updated, m, err = bundle.Pull(ctx, bundle.PullOptions{URL: u, Pubs: keys, DestDir: dest, Validate: validateBundle})
	}
	if err != nil {
		// A downgrade or a reused version number is refused loudly: it is
		// what a replayed old bundle looks like.
		return a.fail("bundle pull", err)
	}
	if *asJSON {
		res := map[string]any{"updated": updated, "dir": dest}
		if m != nil {
			res["manifest"] = manifestView(m)
		}
		return a.printJSON(res)
	}
	switch {
	case m == nil:
		fmt.Fprintln(a.stdout, "no bundle installed")
	case updated:
		fmt.Fprintf(a.stdout, "installed bundle version %d (%d files) under %s\n", m.Version, len(m.Files), dest)
	default:
		fmt.Fprintf(a.stdout, "bundle version %d is current\n", m.Version)
	}
	return exitOK
}

// installLocal verifies and installs a bundle file. The installed bundle
// offered again is not an error; an older one is (ErrDowngrade).
func installLocal(file, sigPath string, keys []ed25519.PublicKey, dest string) (*bundle.Manifest, bool, error) {
	tarball, err := readSmall(file, bundle.MaxBytes)
	if err != nil {
		return nil, false, err
	}
	sig, err := readSmall(sigPath, 4<<10)
	if err != nil {
		return nil, false, err
	}
	m, err := bundle.Verify(tarball, sig, keys)
	if err != nil {
		return nil, false, err
	}
	if err := bundle.InstallWith(tarball, m, dest, bundle.InstallOptions{Validate: validateBundle}); err != nil {
		if errors.Is(err, bundle.ErrAlreadyInstalled) {
			return m, false, nil
		}
		return nil, false, err
	}
	return m, true, nil
}

// validateBundle refuses a correctly signed bundle whose content would not
// load, so a broken bundle never replaces a working one.
func validateBundle(dir string, _ *bundle.Manifest) error {
	if _, err := rules.LoadDir(dir); err != nil {
		return fmt.Errorf("rules: %w", err)
	}
	over := filepath.Join(dir, "catalog")
	if fi, err := os.Stat(over); err == nil && fi.IsDir() {
		c, err := catalog.Load()
		if err != nil {
			return err
		}
		if err := c.LoadOverlay(over); err != nil {
			return fmt.Errorf("catalog overlay: %w", err)
		}
	}
	return nil
}
