package daemon

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/thomastysong/spoor/internal/bundle"
	"github.com/thomastysong/spoor/internal/catalog"
	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/rules"
)

// bundleMgr loads detection content and keeps it current.
//
// Content order is the hook's (internal/hookcmd loadRuleSet): the embedded
// packs, then the installed signed bundle, then the operator's rules.dirs,
// later sources replacing earlier ones by rule id; the pipeline applies
// rules.disable and the suppressions. A bundle is audited (every file
// re-hashed against its manifest, unlisted files refused) before it is
// loaded, at start and whenever the current bundle changes, whether this
// daemon pulled it or `spoor bundle pull` installed it.
type bundleMgr struct {
	d    *daemon
	dir  string
	pubs []ed25519.PublicKey

	mu      sync.Mutex
	version uint64 // loaded bundle version; 0 = none
	refused uint64 // a version that failed its audit or did not load
}

func newBundleMgr(d *daemon) *bundleMgr {
	b := &bundleMgr{d: d, dir: d.layout.bundle}
	for i, k := range d.cfg.Bundle.PublicKeys {
		pub, err := bundle.ParsePublicKey(k)
		if err != nil {
			d.log.Error("bundle.public_keys entry is not a usable key; ignored", "index", i)
			d.board.add("bundle.bad_keys", 1)
			continue
		}
		b.pubs = append(b.pubs, pub)
	}
	return b
}

// initial loads the content the pipeline starts with.
func (b *bundleMgr) initial() (*rules.Set, string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	set, ver := b.load()
	b.version = ver
	if ver == 0 {
		return set, ""
	}
	return set, strconv.FormatUint(ver, 10)
}

// load builds the rule set from every source and layers the bundle's
// catalog overlay. A source that fails is reported and left out; the
// embedded packs are always there (the pipeline loads them itself when even
// they fail, which only a broken build can cause). b.mu is held.
func (b *bundleMgr) load() (*rules.Set, uint64) {
	d := b.d
	set, err := rules.LoadEmbedded()
	if err != nil {
		d.log.Error("embedded rules do not load", "error", err)
		d.board.add("rules.embedded_errors", 1)
		return nil, 0
	}
	var ver uint64
	info, err := bundle.Installed(b.dir)
	switch {
	case err == nil:
		if info.Manifest.Version == b.refused {
			break
		}
		if _, aerr := bundle.Audit(b.dir); aerr != nil {
			b.fail(info.Manifest.Version, "audit", aerr)
			break
		}
		bs, lerr := rules.LoadDir(info.Dir)
		if lerr != nil {
			b.fail(info.Manifest.Version, "rules", lerr)
			break
		}
		set.Merge(bs)
		if ov := filepath.Join(info.Dir, "catalog"); isDir(ov) {
			if cerr := d.cat.LoadOverlay(ov); cerr != nil {
				// Rules from the bundle still apply; the catalog stays as it was.
				d.board.add("bundle.catalog_errors", 1)
				d.log.Error("bundle catalog overlay rejected", "version", info.Manifest.Version, "error", cerr)
			}
		}
		ver = info.Manifest.Version
		d.board.set("bundle.version", ver)
		if !info.Manifest.Created.IsZero() {
			d.board.set("bundle.created_unix", uint64(max(info.Manifest.Created.Unix(), 0)))
		}
	case errors.Is(err, bundle.ErrNotInstalled):
	default:
		d.board.add("bundle."+bundle.Reason(err), 1)
		d.log.Warn("installed bundle unusable; running without it", "reason", bundle.Reason(err))
	}
	for _, dir := range d.cfg.Rules.Dirs {
		if dir == "" {
			continue
		}
		rs, err := rules.LoadDir(dir)
		if err != nil {
			d.board.add("rules.dir_errors", 1)
			d.log.Error("rules.dirs entry does not load", "dir", dir, "error", err)
			continue
		}
		set.Merge(rs)
	}
	return set, ver
}

// fail records a bundle version that cannot be used, once.
func (b *bundleMgr) fail(version uint64, what string, err error) {
	b.refused = version
	b.d.board.add("bundle."+what+"_failed", 1)
	b.d.log.Error("installed bundle refused; running without it", "version", version, "stage", what, "error", err)
	b.d.emit(healthError(b.d.env.now(), "bundle."+what+"_failed",
		fmt.Sprintf("bundle version %d was not loaded (%s)", version, bundle.Reason(err))))
}

// check notices a change of the current bundle and hot-loads it.
func (b *bundleMgr) check() {
	_, m, ok := bundle.Current(b.dir)
	b.mu.Lock()
	defer b.mu.Unlock()
	if !ok || m == nil || m.Version == b.version || m.Version == b.refused {
		return
	}
	set, ver := b.load()
	if set == nil || ver == 0 {
		return
	}
	if err := b.d.pipe.SetRules(set, strconv.FormatUint(ver, 10)); err != nil {
		b.d.board.add("bundle.reload_errors", 1)
		b.d.log.Error("bundle loaded but the pipeline refused it", "version", ver, "error", err)
		return
	}
	b.version = ver
	b.d.board.add("bundle.reloads", 1)
	b.d.log.Info("content bundle loaded", "version", ver, "rules", set.Count())
}

// run pulls the bundle every bundle.interval when bundle.url is set.
func (b *bundleMgr) run(ctx context.Context) error {
	d := b.d
	if d.cfg.Bundle.URL == "" {
		<-ctx.Done()
		return nil
	}
	if len(b.pubs) == 0 {
		d.log.Error("bundle.url is set but no bundle.public_keys entry is usable; not pulling")
		<-ctx.Done()
		return nil
	}
	interval := d.cfg.Bundle.Interval.D()
	if interval < time.Minute {
		interval = time.Hour
	}
	// A fleet restarted together must not hit the server together.
	wait := time.Duration(rand.Int64N(int64(time.Minute)))
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
		if !d.env.disabled() {
			b.pull(ctx)
		}
		wait = interval - interval/10 + time.Duration(rand.Int64N(int64(interval/5)+1))
	}
}

func (b *bundleMgr) pull(ctx context.Context) {
	d := b.d
	updated, _, err := bundle.Pull(ctx, bundle.PullOptions{
		URL:      d.cfg.Bundle.URL,
		Pubs:     b.pubs,
		DestDir:  b.dir,
		Validate: validateBundle,
	})
	d.board.add("bundle.pulls", 1)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		reason := bundle.Reason(err)
		d.board.add("bundle.pull_errors", 1)
		d.log.Warn("bundle pull failed", "reason", reason, "error", err)
		d.emit(healthError(d.env.now(), "bundle."+reason, "bundle pull failed"))
		return
	}
	if updated {
		b.check()
	}
}

// validateBundle is run on a verified bundle before it becomes current, so
// that correctly signed but broken content never replaces working content.
func validateBundle(dir string, _ *bundle.Manifest) error {
	if _, err := rules.LoadDir(dir); err != nil {
		return fmt.Errorf("rules: %w", err)
	}
	if ov := filepath.Join(dir, "catalog"); isDir(ov) {
		c, err := catalog.Load()
		if err != nil {
			return err
		}
		if err := c.LoadOverlay(ov); err != nil {
			return fmt.Errorf("catalog overlay: %w", err)
		}
	}
	return nil
}

func isDir(p string) bool {
	fi, err := os.Lstat(p)
	return err == nil && fi.IsDir()
}

// healthError builds a content-free health.error record.
func healthError(now time.Time, reason, detail string) *event.Event {
	return &event.Event{
		V:        event.SchemaVersion,
		TS:       event.At(now),
		Kind:     event.KindHealth,
		Type:     event.TypeHealthError,
		Source:   event.SourceSensor,
		Fidelity: event.FidelityObserved,
		Health: &event.Health{
			SensorVersion: Version,
			Mode:          "daemon",
			Reason:        reason,
			Detail:        detail,
		},
	}
}
