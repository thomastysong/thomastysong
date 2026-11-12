package state

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// MarkScan records the outcome of a discovery scan.
//
// A complete scan passes a non-zero finished time and seen, the ids of every
// asset the scan observed (unchanged assets included, even when a
// differential scan did not re-emit them). Every asset not in seen is marked
// removed, which Removed then reports; seen assets get their last_seen moved
// to finished; health.last_scan and scan_complete are set; and the scan
// sequence that ages posture rows advances.
//
// A partial scan (deadline hit, or only one project or container examined)
// must pass a zero finished time. Nothing is removed, because "not looked
// at" is not "gone", and health.scan_complete becomes 0.
func (s *Store) MarkScan(started, finished time.Time, seen []string) (err error) {
	defer guard(&err)
	if !finished.IsZero() && !started.IsZero() && finished.Before(started) {
		return errors.New("state: scan finished before it started")
	}
	ctx, cancel := opContext()
	defer cancel()
	now := s.now()
	return s.write(ctx, func(tx *sql.Tx) error {
		b := newBatch(ctx, tx, s)
		defer b.close()
		begun := optStamp(started, now)
		if finished.IsZero() {
			_, err := b.exec(`INSERT INTO health (id, scan_complete, scan_started) VALUES (1, 0, ?)
				ON CONFLICT(id) DO UPDATE SET scan_complete = 0, scan_started = excluded.scan_started`, begun)
			return err
		}
		done := stamp(finished, now)
		seq, err := metaInt(ctx, tx, metaScanSeq)
		if err != nil {
			return err
		}
		seq++
		if err := setMetaInt(ctx, tx, metaScanSeq, seq); err != nil {
			return err
		}

		// The seen set can hold tens of thousands of ids, far past what an
		// IN list should carry, so it goes through a temporary table.
		if _, err := b.exec(`CREATE TEMP TABLE IF NOT EXISTS scan_seen (asset_id TEXT PRIMARY KEY) WITHOUT ROWID`); err != nil {
			return err
		}
		if _, err := b.exec(`DELETE FROM scan_seen`); err != nil {
			return err
		}
		for _, id := range seen {
			if id = clip(id, maxID); id == "" {
				continue
			}
			if _, err := b.exec(`INSERT OR IGNORE INTO scan_seen (asset_id) VALUES (?)`, id); err != nil {
				return err
			}
		}
		for _, table := range assetTables {
			name := quoteIdent(table)
			gone := "last_changed = ?1, removed_at = ?1, removed_scan = ?2"
			if table == "agents" {
				gone = "change = 'removed', running = 0, pid = 0, removed_at = ?1, removed_scan = ?2"
			}
			if _, err := b.exec("UPDATE "+name+" SET "+gone+
				" WHERE removed_at = '' AND asset_id NOT IN (SELECT asset_id FROM scan_seen)", done, seq); err != nil {
				return fmt.Errorf("state: mark removed in %s: %w", table, err)
			}
			if _, err := b.exec("UPDATE "+name+" SET last_seen = ?1"+
				" WHERE removed_at = '' AND last_seen < ?1 AND asset_id IN (SELECT asset_id FROM scan_seen)", done); err != nil {
				return fmt.Errorf("state: refresh %s: %w", table, err)
			}
		}
		if _, err := b.exec(`DELETE FROM scan_seen`); err != nil {
			return err
		}
		_, err = b.exec(`INSERT INTO health (id, last_scan, scan_complete, scan_started) VALUES (1, ?, 1, ?)
			ON CONFLICT(id) DO UPDATE SET last_scan = excluded.last_scan, scan_complete = 1,
			scan_started = excluded.scan_started`, done, begun)
		return err
	})
}

// Removed returns one inventory event with Change "removed" for every asset
// that the most recent complete MarkScan found missing. It is idempotent:
// until the next complete scan it returns the same events with the same ids,
// so a caller that crashes before emitting them can simply ask again.
// Host and Integrity are left for the caller to stamp.
func (s *Store) Removed() (events []*event.Event, err error) {
	defer guard(&err)
	if s.closed.Load() {
		return nil, ErrClosed
	}
	ctx, cancel := opContext()
	defer cancel()
	seq, err := metaInt(ctx, s.db, metaScanSeq)
	if err != nil {
		if s.readOnly && isNoSuchTable(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("state: read scan sequence: %w", err)
	}
	if seq == 0 {
		return nil, nil
	}
	queries := []string{
		`SELECT asset_id, kind, name, vendor, version, catalog_id, '' AS parent, install_path, scope, owner, owner_id,
			sha256, first_seen, last_seen, removed_at, '', '', '', '', '', '', 0, '', ''
			FROM agents WHERE removed_scan = ?`,
		`SELECT asset_id, 'mcp_server', name, '', '', '', parent, source_path, scope, owner, owner_id,
			sha256, first_seen, last_seen, removed_at, transport, command, runner, ecosystem, package, version, pinned,
			url_host, auth_mode
			FROM mcp_servers WHERE removed_scan = ?`,
		`SELECT asset_id, kind, name, '', '', '', parent, source_path, scope, owner, owner_id,
			sha256, first_seen, last_seen, removed_at, '', '', '', '', '', '', 0, '', ''
			FROM extensions WHERE removed_scan = ?`,
	}
	for i, q := range queries {
		rows, err := s.db.QueryContext(ctx, q+" ORDER BY asset_id", seq)
		if err != nil {
			return nil, fmt.Errorf("state: removed %s: %w", assetTables[i], err)
		}
		for rows.Next() {
			var (
				a                                            event.Asset
				kind, scope, ownerID, first, last, removedAt string
				m                                            event.MCP
				mcpVersion                                   string
				pinned                                       int
			)
			if err := rows.Scan(&a.ID, &kind, &a.Name, &a.Vendor, &a.Version, &a.CatalogID, &a.Parent, &a.Path,
				&scope, &a.Owner, &ownerID, &a.SHA256, &first, &last, &removedAt,
				&m.Transport, &m.Command, &m.Runner, &m.Ecosystem, &m.Package, &mcpVersion, &pinned,
				&m.URLHost, &m.AuthMode); err != nil {
				rows.Close()
				return nil, err
			}
			a.Kind, a.Scope, a.Change = event.AssetKind(kind), event.Scope(scope), event.ChangeRemoved
			a.FirstSeen, a.LastSeen = parseTime(first), parseTime(last)
			if a.Kind == event.AssetMCPServer {
				m.Version, m.Pinned = mcpVersion, pinned != 0
				a.MCP = &m
			}
			at := parseTime(removedAt)
			e := &event.Event{
				V: event.SchemaVersion,
				// Deterministic id: the same removal reported twice collapses downstream.
				ID:       event.StableID(at.Time, "inventory.removed", a.ID, removedAt),
				TS:       at,
				Kind:     event.KindInventory,
				Type:     event.TypeInventoryAsset,
				Source:   event.SourceScan,
				Fidelity: event.FidelityInferred,
				Asset:    &a,
			}
			if a.Owner != "" || ownerID != "" {
				e.User = &event.User{Name: a.Owner, ID: ownerID}
			}
			events = append(events, e)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	return events, nil
}

func parseTime(s string) event.Time {
	if s == "" {
		return event.Time{}
	}
	t, err := time.Parse(TimeFormat, s)
	if err != nil {
		return event.Time{}
	}
	return event.At(t)
}

// Snapshot returns asset id to content hash for every asset that is present
// (not removed), across agents, MCP servers and extensions. The scanner
// compares it with what it finds to emit only what changed.
func (s *Store) Snapshot() (snap map[string]string, err error) {
	defer guard(&err)
	if s.closed.Load() {
		return nil, ErrClosed
	}
	ctx, cancel := opContext()
	defer cancel()
	snap = map[string]string{}
	parts := make([]string, len(assetTables))
	for i, table := range assetTables {
		parts[i] = "SELECT asset_id, sha256 FROM " + quoteIdent(table) + " WHERE removed_at = ''"
	}
	rows, err := s.db.QueryContext(ctx, strings.Join(parts, " UNION ALL "))
	if err != nil {
		if s.readOnly && isNoSuchTable(err) {
			return snap, nil
		}
		return nil, fmt.Errorf("state: snapshot: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, sum string
		if err := rows.Scan(&id, &sum); err != nil {
			return nil, err
		}
		snap[id] = sum
	}
	return snap, rows.Err()
}
