package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

func (a *app) cmdCatalog(args []string) int {
	return a.dispatch("catalog", []subcommand{
		{"list", "list the catalogued AI products", a.catalogList},
		{"verify", "validate the catalog and check its npm and PyPI packages exist", a.catalogVerify},
	}, args)
}

type productRow struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Vendor   string   `json:"vendor,omitempty"`
	Kind     string   `json:"kind"`
	Status   string   `json:"status,omitempty"`
	Hooks    string   `json:"hook_dialect,omitempty"`
	Packages []string `json:"packages,omitempty"`
}

func (a *app) catalogList(args []string) int {
	fs := a.newFlags("catalog list", "catalog list [--kind agent] [--hooks] [--json]", "Lists the products in the catalog this binary carries (plus the bundle overlay, if installed).")
	var cf cfgFlags
	cf.register(fs)
	kind := fs.String("kind", "", "only this asset kind (agent, app, ide_extension, mcp_server ...)")
	hooks := fs.Bool("hooks", false, "only agents spoor can register hooks with")
	asJSON := fs.Bool("json", false, "print JSON")
	if pos, code, done := a.parse(fs, args); done {
		return code
	} else if len(pos) > 0 {
		return a.usageErr("catalog list", "unexpected argument %q", pos[0])
	}
	cfg, _, err := loadConfig(cf)
	if err != nil {
		return a.fail("catalog list", err)
	}
	c, overlayErr, err := loadCatalog(cfg)
	if err != nil {
		return a.fail("catalog list", err)
	}
	if overlayErr != nil {
		a.warn("catalog list", "%v", overlayErr)
	}
	var rows []productRow
	for _, p := range c.Products() {
		if *kind != "" && p.Kind != *kind {
			continue
		}
		r := productRow{ID: p.ID, Name: p.Name, Vendor: p.Vendor, Kind: p.Kind, Status: p.Status, Packages: p.Packages}
		if p.Hooks != nil {
			r.Hooks = p.Hooks.Dialect
		}
		if *hooks && r.Hooks == "" {
			continue
		}
		rows = append(rows, r)
	}
	if *asJSON {
		return a.printJSON(map[string]any{"version": c.Version(), "products": rows})
	}
	tw := a.table()
	fmt.Fprintln(tw, "ID\tKIND\tHOOKS\tNAME\tVENDOR")
	for _, r := range rows {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", r.ID, r.Kind, r.Hooks, clip(r.Name, 40), clip(r.Vendor, 30))
	}
	tw.Flush()
	fmt.Fprintf(a.stdout, "%d products, catalog %s\n", len(rows), c.Version())
	return exitOK
}

// pkgCheck is the registry verdict for one package reference.
type pkgCheck struct {
	Product  string `json:"product"`
	Ref      string `json:"ref"`
	Registry string `json:"registry"`
	// Status: ok | not_found | renamed | deprecated | unreachable | error
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// registryOf maps a catalog package manager to the registry that serves it.
func registryOf(mgr string) string {
	switch mgr {
	case "npm", "pnpm", "yarn", "bun":
		return "npm"
	case "pip", "pipx", "uv", "pypi":
		return "pypi"
	}
	return ""
}

func (a *app) catalogVerify(args []string) int {
	fs := a.newFlags("catalog verify", "catalog verify [--offline] [--json]",
		`Validates the embedded catalog (and the bundle overlay), then asks the npm and
PyPI registries about every npm:/pip: package reference: a 404 means the
fingerprint can never match, a different canonical name or a deprecation
notice usually means a rename. Unreachable registries are reported, not
failed (network is optional). Exits 4 when a package is missing.`)
	var cf cfgFlags
	cf.register(fs)
	offline := fs.Bool("offline", false, "validate only, no registry requests")
	timeout := fs.Duration("timeout", 10*time.Second, "per-request timeout")
	parallel := fs.Int("parallel", 8, "concurrent registry requests")
	asJSON := fs.Bool("json", false, "print JSON")
	if pos, code, done := a.parse(fs, args); done {
		return code
	} else if len(pos) > 0 {
		return a.usageErr("catalog verify", "unexpected argument %q", pos[0])
	}
	cfg, _, err := loadConfig(cf)
	if err != nil {
		return a.fail("catalog verify", err)
	}
	c, overlayErr, err := loadCatalog(cfg)
	if err != nil {
		// Load validates: an invalid embedded catalog is a failed check.
		fmt.Fprintf(a.stdout, "INVALID catalog: %v\n", err)
		return exitCheck
	}
	var checks []pkgCheck
	if !*offline {
		var refs []pkgCheck
		for _, p := range c.Products() {
			for _, ref := range p.Packages {
				mgr, name, ok := strings.Cut(ref, ":")
				if !ok || registryOf(mgr) == "" || name == "" {
					continue
				}
				refs = append(refs, pkgCheck{Product: p.ID, Ref: ref, Registry: registryOf(mgr)})
			}
		}
		checks = a.checkRegistries(refs, *timeout, *parallel)
	}
	counts := map[string]int{}
	for _, ch := range checks {
		counts[ch.Status]++
	}
	failed := counts["not_found"] > 0 || overlayErr != nil
	if *asJSON {
		res := map[string]any{"version": c.Version(), "products": c.Len(), "valid": overlayErr == nil, "packages": checks, "counts": counts}
		if overlayErr != nil {
			res["overlay_error"] = overlayErr.Error()
		}
		if code := a.printJSON(res); code != exitOK {
			return code
		}
	} else {
		fmt.Fprintf(a.stdout, "catalog %s: %d products, valid\n", c.Version(), c.Len())
		if overlayErr != nil {
			fmt.Fprintf(a.stdout, "INVALID bundle overlay: %v\n", overlayErr)
		}
		for _, ch := range checks {
			if ch.Status != "ok" {
				fmt.Fprintf(a.stdout, "%-11s %-22s %s %s\n", ch.Status, ch.Product, ch.Ref, clip(ch.Detail, 120))
			}
		}
		if len(checks) > 0 {
			var parts []string
			for _, k := range sortedKeys(counts) {
				parts = append(parts, fmt.Sprintf("%s %d", k, counts[k]))
			}
			fmt.Fprintf(a.stdout, "%d package reference(s): %s\n", len(checks), strings.Join(parts, ", "))
		}
	}
	if failed {
		return exitCheck
	}
	return exitOK
}

func (a *app) checkRegistries(refs []pkgCheck, timeout time.Duration, parallel int) []pkgCheck {
	if parallel < 1 {
		parallel = 1
	}
	out := make([]pkgCheck, len(refs))
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	for i := range refs {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			ctx, cancel := context.WithTimeout(a.ctx, timeout)
			defer cancel()
			out[i] = a.checkPackage(ctx, refs[i])
		}(i)
	}
	wg.Wait()
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Product != out[j].Product {
			return out[i].Product < out[j].Product
		}
		return out[i].Ref < out[j].Ref
	})
	return out
}

// checkPackage asks one registry about one package. Only the package name
// from the catalog is sent; the reply is read with a size cap and only a
// few fields are kept.
func (a *app) checkPackage(ctx context.Context, ch pkgCheck) pkgCheck {
	_, name, _ := strings.Cut(ch.Ref, ":")
	var u string
	switch ch.Registry {
	case "npm":
		// Scoped names keep their "@" and encode the slash, as the npm
		// registry expects.
		u = a.npmRegistry + "/" + url.PathEscape(name)
	case "pypi":
		u = a.pypiRegistry + "/pypi/" + url.PathEscape(name) + "/json"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		ch.Status, ch.Detail = "error", err.Error()
		return ch
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "spoor-catalog-verify")
	resp, err := a.client.Do(req)
	if err != nil {
		ch.Status, ch.Detail = "unreachable", shortNetErr(err)
		return ch
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		ch.Status = "not_found"
		return ch
	case resp.StatusCode != http.StatusOK:
		ch.Status, ch.Detail = "error", resp.Status
		return ch
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		ch.Status, ch.Detail = "error", err.Error()
		return ch
	}
	ch.Status = "ok"
	switch ch.Registry {
	case "npm":
		var doc struct {
			Name     string            `json:"name"`
			DistTags map[string]string `json:"dist-tags"`
			Versions map[string]struct {
				Deprecated json.RawMessage `json:"deprecated"`
			} `json:"versions"`
		}
		if json.Unmarshal(body, &doc) != nil {
			ch.Status, ch.Detail = "error", "unreadable registry reply"
			return ch
		}
		if doc.Name != "" && doc.Name != name {
			ch.Status, ch.Detail = "renamed", "registry name "+clip(doc.Name, 80)
		}
		if v, ok := doc.Versions[doc.DistTags["latest"]]; ok && len(v.Deprecated) > 0 && string(v.Deprecated) != "false" && string(v.Deprecated) != `""` {
			var msg string
			if json.Unmarshal(v.Deprecated, &msg) != nil {
				msg = "deprecated"
			}
			ch.Status, ch.Detail = "deprecated", clip(msg, 160)
		}
	case "pypi":
		var doc struct {
			Info struct {
				Name string `json:"name"`
			} `json:"info"`
		}
		if json.Unmarshal(body, &doc) != nil {
			ch.Status, ch.Detail = "error", "unreadable registry reply"
			return ch
		}
		if doc.Info.Name != "" && pep503(doc.Info.Name) != pep503(name) {
			ch.Status, ch.Detail = "renamed", "registry name "+clip(doc.Info.Name, 80)
		}
	}
	return ch
}

// pep503 normalizes a Python project name (PEP 503): runs of -, _ and .
// are one "-", case is ignored.
func pep503(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	dash := false
	for _, r := range s {
		if r == '-' || r == '_' || r == '.' {
			if !dash {
				b.WriteByte('-')
			}
			dash = true
			continue
		}
		dash = false
		b.WriteRune(r)
	}
	return b.String()
}

func shortNetErr(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	return clip(err.Error(), 120)
}
