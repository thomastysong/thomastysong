package state

import (
	"database/sql"
	"errors"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// assetTables are the three tables that hold inventory, in Tables order.
var assetTables = []string{"agents", "mcp_servers", "extensions"}

// assetTable picks the table for an asset kind. Kinds this version does not
// know go to extensions, the table with a kind column and no kind-specific
// columns, so a newer scanner's records are kept rather than dropped.
func assetTable(k event.AssetKind) string {
	switch k {
	case event.AssetAgent, event.AssetApp, event.AssetIDEExtension, event.AssetBrowser,
		event.AssetBrowserExtension, event.AssetModelRuntime:
		return "agents"
	case event.AssetMCPServer:
		return "mcp_servers"
	default:
		return "extensions"
	}
}

// prior is what an asset row held before this write.
type prior struct {
	exists                                         bool
	firstSeen, lastSeen, fp, removedAt, lastChange string
}

func (b *batch) priorAsset(table, id string) (prior, error) {
	// agents has no last_changed column; its "change" column is recomputed.
	q := "SELECT first_seen, last_seen, fp, removed_at, last_changed FROM " + quoteIdent(table) + " WHERE asset_id = ?"
	if table == "agents" {
		q = "SELECT first_seen, last_seen, fp, removed_at, '' FROM agents WHERE asset_id = ?"
	}
	st, err := b.stmt(q)
	if err != nil {
		return prior{}, err
	}
	p := prior{exists: true}
	err = st.QueryRowContext(b.ctx, id).Scan(&p.firstSeen, &p.lastSeen, &p.fp, &p.removedAt, &p.lastChange)
	if errors.Is(err, sql.ErrNoRows) {
		return prior{}, nil
	}
	return p, err
}

// applyAsset upserts one inventory record.
//
// The change state is derived from what the table held, not from
// Asset.Change: the scanner computes its label against whatever previous
// snapshot it was given (none after a restart, when everything looks new),
// while the table knows what was really there. The one label that carries
// information the table cannot derive is "removed".
func (b *batch) applyAsset(e *event.Event, now time.Time) (table string, ok bool, err error) {
	a := e.Asset
	id := clip(a.ID, maxID)
	if id == "" {
		return "", false, nil
	}
	table = assetTable(a.Kind)
	t := mustTable(table)
	p, err := b.priorAsset(table, id)
	if err != nil {
		return table, false, err
	}
	seen := stamp(e.TS.Time, now)
	if a.Change == event.ChangeRemoved {
		if !p.exists || p.removedAt != "" {
			return table, true, nil
		}
		return table, true, b.markRemoved(table, id, seen, 0)
	}

	first, last := optStamp(a.FirstSeen.Time, now), optStamp(a.LastSeen.Time, now)
	if first == "" {
		first = seen
	}
	if last == "" {
		last = seen
	}
	if p.exists {
		if p.firstSeen != "" && p.firstSeen < first {
			first = p.firstSeen
		}
		if p.lastSeen > last {
			last = p.lastSeen
		}
	}

	owner := clip(a.Owner, maxName)
	ownerID := ""
	if e.User != nil {
		// The scanner sets User to the owner. Only trust the id for this
		// row when the names agree (or the asset names no owner).
		name, uid := userOf(e.User)
		if owner == "" {
			owner = name
		}
		if owner == name {
			ownerID = uid
		}
	}

	r := &row{}
	r.set("asset_id", id)
	var desc []any // descriptive values, digested into fp
	add := func(col string, v any) {
		r.set(col, v)
		desc = append(desc, v)
	}
	switch table {
	case "agents":
		add("name", clip(a.Name, maxName))
		add("vendor", clip(a.Vendor, maxName))
		add("kind", clip(string(a.Kind), maxID))
		add("catalog_id", clip(a.CatalogID, maxID))
		add("version", clip(a.Version, maxID))
		add("install_path", clip(a.Path, maxPath))
		add("owner", owner)
		add("scope", clip(string(a.Scope), maxID))
		// running and pid change from scan to scan without the install
		// changing, so they stay out of the fingerprint.
		r.set("running", boolInt(a.Running))
		r.set("pid", max(a.PID, 0))
		add("sha256", clip(a.SHA256, maxID))
		add("signer", clip(a.Signer, maxName))
		add("confidence", clip(a.Confidence, maxID))
		add("evidence", joinList(a.Evidence))
		add("risk_flags", joinList(a.RiskFlags))
		var tel event.Telemetry
		if a.Telemetry != nil {
			tel = *a.Telemetry
		}
		add("hooks", clip(tel.Hooks, maxID))
		add("transcript", clip(tel.Transcript, maxID))
		add("native_otel", clip(tel.NativeOTel, maxID))
	case "mcp_servers":
		var m event.MCP
		if a.MCP != nil {
			m = *a.MCP
		}
		add("name", clip(a.Name, maxName))
		add("parent", clip(a.Parent, maxID))
		add("scope", clip(string(a.Scope), maxID))
		add("owner", owner)
		add("source_path", clip(a.Path, maxPath))
		add("transport", clip(m.Transport, maxID))
		// Base name only: the directory can name a user's home, and the
		// arguments (never stored) are where secrets and payloads live.
		add("command", clip(baseName(m.Command), maxName))
		add("runner", clip(m.Runner, maxID))
		add("ecosystem", clip(m.Ecosystem, maxID))
		add("package", clip(m.Package, maxName))
		add("version", clip(m.Version, maxID))
		add("pinned", boolInt(m.Pinned))
		add("url_host", clip(m.URLHost, maxName))
		add("env_keys", joinList(m.EnvKeys))
		add("auth_mode", clip(m.AuthMode, maxID))
		add("risk_flags", joinList(a.RiskFlags))
		add("sha256", clip(a.SHA256, maxID))
	default:
		add("kind", clip(string(a.Kind), maxID))
		add("name", clip(a.Name, maxName))
		add("parent", clip(a.Parent, maxID))
		add("scope", clip(string(a.Scope), maxID))
		add("owner", owner)
		add("source_path", clip(a.Path, maxPath))
		add("sha256", clip(a.SHA256, maxID))
		add("risk_flags", joinList(a.RiskFlags))
	}
	fp := fingerprint(desc...)

	change := event.ChangeUnchanged
	switch {
	case !p.exists, p.removedAt != "":
		change = event.ChangeNew
	case p.fp != fp:
		change = event.ChangeChanged
	}
	r.set("first_seen", first)
	r.set("last_seen", last)
	if table == "agents" {
		r.set("change", string(change))
	} else {
		changed := p.lastChange
		if change != event.ChangeUnchanged || changed == "" {
			changed = seen
		}
		r.set("last_changed", changed)
	}
	r.set("owner_id", ownerID)
	r.set("fp", fp)
	r.set("removed_at", "")
	r.set("removed_scan", 0)
	return table, true, b.upsert(t, r)
}

// markRemoved flags an asset as gone without deleting it. scan is the scan
// sequence that found it missing, or 0 when a "removed" event said so (those
// are not reported again by Removed).
func (b *batch) markRemoved(table, id, at string, scan int64) error {
	var err error
	if table == "agents" {
		_, err = b.exec(`UPDATE agents SET change = 'removed', running = 0, pid = 0, removed_at = ?, removed_scan = ?
			WHERE asset_id = ?`, at, scan, id)
	} else {
		_, err = b.exec("UPDATE "+quoteIdent(table)+` SET last_changed = ?, removed_at = ?, removed_scan = ?
			WHERE asset_id = ?`, at, at, scan, id)
	}
	return err
}
