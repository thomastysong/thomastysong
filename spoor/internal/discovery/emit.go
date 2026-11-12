package discovery

import (
	"crypto/sha256"
	"encoding/hex"
	"runtime"
	"sort"
	"strings"

	"github.com/thomastysong/spoor/internal/event"
)

// AssetID is the stable identity of an asset: the first 32 hex digits of
// SHA-256 over the host id, kind, identity, owner, scope and normalized
// path. The identity is the catalog id when the asset is a catalogued
// product, otherwise its name, qualified by its parent agent and, where
// one file declares several items of one name, by the project and handler
// position recorded in Detail. Version and content are deliberately not
// part of it: an upgrade or an edit is a change of the same asset.
func AssetID(hostID string, a *event.Asset) string {
	if a == nil {
		return ""
	}
	identity := a.Name
	if a.CatalogID != "" && productKind(a.Kind) {
		identity = a.CatalogID
	}
	var extra []string
	if a.Detail != nil {
		for _, k := range []string{"project", "handler", "action"} {
			if v := a.Detail[k]; v != "" {
				extra = append(extra, k+"="+v)
			}
		}
	}
	h := sha256.New()
	for _, p := range []string{hostID, string(a.Kind), identity + "\x1f" + a.Parent + "\x1f" + strings.Join(extra, "\x1f"),
		a.Owner, string(a.Scope), normalizePath(a.Path)} {
		_, _ = h.Write([]byte(p))
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// productKind reports kinds identified through the catalog, whose identity
// is the catalog id rather than a declared name.
func productKind(k event.AssetKind) bool {
	switch k {
	case event.AssetAgent, event.AssetApp, event.AssetIDEExtension, event.AssetBrowser,
		event.AssetBrowserExtension, event.AssetModelRuntime, event.AssetCIAgent:
		return true
	}
	return false
}

// normalizePath folds separators and, where the platform's filesystems
// ignore case (or the path is a Windows path), case.
func normalizePath(p string) string {
	if p == "" {
		return ""
	}
	winPath := strings.Contains(p, `\`) || len(p) >= 2 && p[1] == ':'
	c := cleanLogical(p)
	if winPath || runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		c = strings.ToLower(c)
	}
	return c
}

// observationDigest is the SHA256 reported for catalogued products. The
// event contract describes it as a binary hash for agents; discovery does
// not hash binaries (a native agent build is hundreds of megabytes, read on
// every endpoint at every scan), so the field carries a digest of what was
// observed instead: version, install path, evidence, risk flags and
// telemetry. Differential inventory compares this value, so a settings
// change that adds a risk flag re-emits the agent.
func observationDigest(a *event.Asset) string {
	parts := []string{"obs/v1", a.Version, normalizePath(a.Path), strings.Join(a.Evidence, ","), strings.Join(a.RiskFlags, ",")}
	if a.Telemetry != nil {
		parts = append(parts, a.Telemetry.Hooks, a.Telemetry.Transcript, a.Telemetry.NativeOTel)
	}
	return digestParts(parts...)
}

// changeDigest is what Prev is compared with: the asset's SHA256 (what the
// state store keeps), which is the content or definition hash of declared
// items and the observation digest of products.
func changeDigest(a *event.Asset) string { return a.SHA256 }

// finish builds the result: inventory events with stable asset ids,
// differential against Options.Prev, then the posture checks the scanner
// itself produces (refused files), which are emitted on every scan.
func (s *scanner) finish(fullScan bool) *Result {
	var events, checks []*event.Event
	seen := map[string]bool{}
	for _, r := range s.recs {
		a := r.a
		if productKind(a.Kind) && a.Kind != event.AssetCIAgent && a.SHA256 == "" {
			a.SHA256 = observationDigest(a)
		}
		a.ID = AssetID(s.host.ID, a)
		if seen[a.ID] {
			continue
		}
		seen[a.ID] = true
		if r.check != nil {
			c := *r.check
			c.AssetID = a.ID
			checks = append(checks, s.newCheck(&c, r.uc))
		}
		a.LastSeen = event.At(s.now)
		if s.o.Prev != nil {
			prev, ok := s.o.Prev[a.ID]
			switch {
			case !ok:
				a.Change = event.ChangeNew
			case prev != changeDigest(a):
				a.Change = event.ChangeChanged
			default:
				a.Change = event.ChangeUnchanged
				if !s.o.Full {
					continue
				}
			}
		} else {
			a.Change = event.ChangeNew
		}
		events = append(events, s.newEvent(a, r.uc, r.content))
	}
	led := s.led.snapshot()
	if fullScan && s.o.Prev != nil {
		events = append(events, s.removed(seen, led)...)
	}
	sort.SliceStable(events, func(i, j int) bool {
		ai, aj := events[i].Asset, events[j].Asset
		if ai.Kind != aj.Kind {
			return ai.Kind < aj.Kind
		}
		return ai.ID < aj.ID
	})
	for _, cr := range s.checks {
		c := *cr.c
		checks = append(checks, s.newCheck(&c, cr.uc))
	}
	sort.SliceStable(checks, func(i, j int) bool {
		ci, cj := checks[i].Check, checks[j].Check
		if ci.Subject != cj.Subject {
			return ci.Subject < cj.Subject
		}
		return ci.AssetID < cj.AssetID
	})
	events = append(events, checks...)
	return &Result{Events: events, Ledger: s.led.snapshot()}
}

// newCheck wraps a posture check of this scan in an event.
func (s *scanner) newCheck(c *event.Check, uc *userCtx) *event.Event {
	ev := event.New(event.KindPosture, event.TypePostureCheck, event.SourceScan)
	ev.TS = event.At(s.now)
	ev.Fidelity = event.FidelityObserved
	ev.Host = &event.Host{ID: s.host.ID, Name: s.host.Name, OS: s.host.OS, Arch: s.host.Arch}
	if s.o.Container != nil {
		cc := *s.o.Container
		ev.Container = &cc
	}
	if uc != nil {
		ev.User = &event.User{Name: uc.u.Name, ID: uc.u.UID}
	}
	if c.AgentID != "" {
		ev.Agent = &event.Agent{ID: c.AgentID}
	}
	ev.Check = c
	return ev
}

// removed reports assets of Prev that this scan did not see. Only a
// complete scan may conclude that something is gone: after a deadline or
// an exhausted budget, a refused home, a read error, a refused or skipped
// read (a config that became a symbolic link, a directory that resolves
// outside its root, a file over its cap, another user's file) or a cap
// that cut an enumeration short (MaxProjects, a sample of transcripts, a
// truncated listing), the absence proves nothing. Prev holds asset ids
// only, so an unread location cannot be matched to the assets it declared
// last time: any such gap suppresses every removal, and the ledger says
// why.
func (s *scanner) removed(seen map[string]bool, led Ledger) []*event.Event {
	if why := incompleteReason(led, s.homeDenied); why != "" {
		s.led.note("removals not reported: the scan was not complete (" + why + ")")
		return nil
	}
	var out []*event.Event
	for _, id := range sortedKeys(s.o.Prev) {
		if seen[id] {
			continue
		}
		a := &event.Asset{ID: id, Change: event.ChangeRemoved, LastSeen: event.At(s.now)}
		ev := event.New(event.KindInventory, event.TypeInventoryAsset, event.SourceScan)
		ev.TS = event.At(s.now)
		ev.Fidelity = event.FidelityObserved
		ev.Host = &event.Host{ID: s.host.ID, Name: s.host.Name, OS: s.host.OS, Arch: s.host.Arch}
		if s.o.Container != nil {
			c := *s.o.Container
			ev.Container = &c
		}
		ev.Asset = a
		out = append(out, ev)
	}
	return out
}

func (s *scanner) newEvent(a *event.Asset, uc *userCtx, content string) *event.Event {
	ev := event.New(event.KindInventory, event.TypeInventoryAsset, event.SourceScan)
	ev.TS = event.At(s.now)
	ev.Fidelity = event.FidelityObserved
	ev.Host = &event.Host{ID: s.host.ID, Name: s.host.Name, OS: s.host.OS, Arch: s.host.Arch}
	if s.o.Container != nil {
		c := *s.o.Container
		ev.Container = &c
	}
	if uc != nil {
		ev.User = &event.User{Name: uc.u.Name, ID: uc.u.UID}
	}
	agentID := a.Parent
	if a.Kind == event.AssetAgent || a.Kind == event.AssetApp || a.Kind == event.AssetIDEExtension {
		agentID = a.CatalogID
	}
	if agentID != "" {
		ev.Agent = &event.Agent{ID: agentID}
		if agentID == a.CatalogID {
			ev.Agent.Name = a.Name
			ev.Agent.Version = a.Version
		}
	}
	if content != "" {
		ev.Content = &event.Content{FileContent: content}
	}
	ev.Asset = a
	return ev
}

// incompleteReason says why a scan cannot prove absence, or "" when it can.
func incompleteReason(led Ledger, homeDenied bool) string {
	var why []string
	if led.Truncated {
		why = append(why, "truncated")
	}
	if homeDenied {
		why = append(why, "a home was not accessible")
	}
	if led.Errors > 0 {
		why = append(why, itoa(led.Errors)+" errors")
	}
	if led.Denied > 0 {
		why = append(why, itoa(led.Denied)+" denied")
	}
	if led.Skipped > 0 {
		why = append(why, itoa(led.Skipped)+" skipped or capped")
	}
	return strings.Join(why, ", ")
}
