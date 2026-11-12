package state

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// Names the heartbeat mapping reads (see the package comment). Counters are
// totals since the writing process started.
const (
	CounterEventsIn   = "events_in"
	CounterEventsOut  = "events_out"
	CounterDropped    = "dropped"
	CounterDetections = "detections"
	CounterErrors     = "errors"

	LabelProfile       = "profile"
	LabelRulesVersion  = "rules_version"
	LabelBundleVersion = "bundle_version"
	LabelHostIDSource  = "host_id_source"
)

// Health is the content of the single health row, for SetHealth.
type Health struct {
	SensorVersion  string
	Mode           string // daemon | scan
	Profile        string // minimal | standard | full
	Started        time.Time
	Heartbeat      time.Time // zero means now
	RulesCount     int
	RulesVersion   string
	RulesHash      string
	CatalogVersion string
	BundleVersion  string
	EventsIn       uint64
	EventsOut      uint64
	Dropped        uint64
	Detections     uint64
	Errors         uint64
	HostID         string
	HostIDSource   string
}

// healthRow mirrors the stored row while it is being merged.
type healthRow struct {
	exists                                                 bool
	version, mode, profile, started, heartbeat             string
	rulesCount                                             int
	rulesVersion, rulesHash, catalogVersion, bundleVersion string
	in, out, dropped, detections, errs                     int64
	hostID, hostIDSource, writer, lastEventID, lastScan    string
}

func (b *batch) loadHealth() (healthRow, error) {
	st, err := b.stmt(`SELECT sensor_version, mode, profile, started, heartbeat, rules_count, rules_version,
		rules_hash, catalog_version, bundle_version, events_in, events_out, dropped, detections, errors,
		host_id, host_id_source, writer, last_event_id, last_scan FROM health WHERE id = 1`)
	if err != nil {
		return healthRow{}, err
	}
	h := healthRow{exists: true}
	err = st.QueryRowContext(b.ctx).Scan(&h.version, &h.mode, &h.profile, &h.started, &h.heartbeat, &h.rulesCount,
		&h.rulesVersion, &h.rulesHash, &h.catalogVersion, &h.bundleVersion, &h.in, &h.out, &h.dropped,
		&h.detections, &h.errs, &h.hostID, &h.hostIDSource, &h.writer, &h.lastEventID, &h.lastScan)
	if errors.Is(err, sql.ErrNoRows) {
		return healthRow{}, nil
	}
	return h, err
}

func (b *batch) storeHealth(h healthRow) error {
	r := &row{}
	r.set("id", 1)
	r.set("sensor_version", h.version)
	r.set("mode", h.mode)
	r.set("profile", h.profile)
	r.set("started", h.started)
	r.set("heartbeat", h.heartbeat)
	r.set("rules_count", h.rulesCount)
	r.set("rules_version", h.rulesVersion)
	r.set("rules_hash", h.rulesHash)
	r.set("catalog_version", h.catalogVersion)
	r.set("bundle_version", h.bundleVersion)
	r.set("events_in", h.in)
	r.set("events_out", h.out)
	r.set("dropped", h.dropped)
	r.set("detections", h.detections)
	r.set("errors", h.errs)
	r.set("host_id", h.hostID)
	r.set("host_id_source", h.hostIDSource)
	r.set("writer", h.writer)
	r.set("last_event_id", h.lastEventID)
	r.set("last_scan", h.lastScan)
	// scan_complete and scan_started belong to MarkScan and are left alone.
	return b.upsert(mustTable("health"), r)
}

// applyHealth folds a health event into the single row. A heartbeat rewrites
// it; a health.error only counts, because an error record must not make a
// sensor that has stopped beating look alive.
func (b *batch) applyHealth(e *event.Event, now time.Time) error {
	hv := e.Health
	cur, err := b.loadHealth()
	if err != nil {
		return err
	}
	eventID := clip(e.ID, maxID)
	if eventID != "" && cur.exists && cur.lastEventID == eventID {
		return nil // replay of the record already applied
	}
	writer := clip(e.Writer, maxID)
	same := cur.exists && writer != "" && cur.writer == writer

	if e.Type == event.TypeHealthError {
		if !cur.exists {
			cur = healthRow{version: clip(hv.SensorVersion, maxID), mode: clip(hv.Mode, maxID), writer: writer}
		}
		cur.errs = satAdd(cur.errs, 1)
		cur.lastEventID = eventID
		return b.storeHealth(cur)
	}

	beat := stamp(e.TS.Time, now)
	next := healthRow{
		version:        clip(hv.SensorVersion, maxID),
		mode:           clip(hv.Mode, maxID),
		heartbeat:      beat,
		rulesCount:     max(hv.RulesCount, 0),
		rulesHash:      clip(hv.RulesHash, maxID),
		catalogVersion: clip(hv.CatalogVer, maxID),
		writer:         writer,
		lastEventID:    eventID,
		lastScan:       cur.lastScan,
		hostID:         cur.hostID,
	}
	if cur.heartbeat > beat {
		next.heartbeat = cur.heartbeat // a late record never moves the beat back
	}
	if ls := optStamp(hv.LastScan.Time, now); ls > next.lastScan {
		next.lastScan = ls
	}
	if e.Host != nil && e.Host.ID != "" {
		next.hostID = clip(e.Host.ID, maxID)
	}

	// started: stable for the life of one writer, so that uptime arithmetic
	// with one-second resolution does not change the row on every beat.
	switch {
	case same && cur.started != "":
		next.started = cur.started
	case hv.UptimeS > 0:
		next.started = stamp(e.TS.Time.Add(-time.Duration(hv.UptimeS)*time.Second), now)
	default:
		next.started = beat
	}

	label := func(name, prev string) string {
		if v, ok := e.Labels[name]; ok {
			return clip(v, maxID)
		}
		if same {
			return prev
		}
		return ""
	}
	next.profile = label(LabelProfile, cur.profile)
	if _, ok := e.Labels[LabelProfile]; !ok && e.Privacy != "" {
		next.profile = clip(e.Privacy, maxID)
	}
	next.rulesVersion = label(LabelRulesVersion, cur.rulesVersion)
	next.bundleVersion = label(LabelBundleVersion, cur.bundleVersion)
	next.hostIDSource = label(LabelHostIDSource, cur.hostIDSource)

	// Counters: an explicit total wins. Without one, per-interval stream
	// counters are added to the running total of the same writer.
	base := func(prev int64) int64 {
		if same {
			return prev
		}
		return 0
	}
	total := func(name string, prev int64, interval uint64) int64 {
		if v, ok := hv.Counters[name]; ok {
			return clampInt(v)
		}
		return satAdd(base(prev), clampInt(interval))
	}
	var emitted, dropped uint64
	for k, v := range hv.Counters {
		if !strings.HasPrefix(k, "stream.") {
			continue
		}
		switch {
		case strings.HasSuffix(k, ".emitted"):
			emitted = satAddU(emitted, v)
		case strings.HasSuffix(k, ".dropped"):
			dropped = satAddU(dropped, v)
		}
	}
	next.out = total(CounterEventsOut, cur.out, emitted)
	next.dropped = total(CounterDropped, cur.dropped, dropped)
	next.detections = total(CounterDetections, cur.detections, hv.Counters["stream.detection.emitted"])
	next.errs = total(CounterErrors, cur.errs, 0)
	if v, ok := hv.Counters[CounterEventsIn]; ok {
		next.in = clampInt(v)
	} else {
		// Surfaces report how many records each collector has produced.
		var in uint64
		for _, sf := range hv.Surfaces {
			in = satAddU(in, sf.Events)
		}
		next.in = max(base(cur.in), clampInt(in))
	}
	return b.storeHealth(next)
}

// SetHealth writes the health row directly. Heartbeat defaults to now. It
// does not touch last_scan and scan_complete, which MarkScan owns.
func (s *Store) SetHealth(h Health) (err error) {
	defer guard(&err)
	ctx, cancel := opContext()
	defer cancel()
	now := s.now()
	return s.write(ctx, func(tx *sql.Tx) error {
		b := newBatch(ctx, tx, s)
		defer b.close()
		cur, err := b.loadHealth()
		if err != nil {
			return err
		}
		next := healthRow{
			version:        clip(h.SensorVersion, maxID),
			mode:           clip(h.Mode, maxID),
			profile:        clip(h.Profile, maxID),
			started:        optStamp(h.Started, now),
			heartbeat:      stamp(h.Heartbeat, now),
			rulesCount:     max(h.RulesCount, 0),
			rulesVersion:   clip(h.RulesVersion, maxID),
			rulesHash:      clip(h.RulesHash, maxID),
			catalogVersion: clip(h.CatalogVersion, maxID),
			bundleVersion:  clip(h.BundleVersion, maxID),
			in:             clampInt(h.EventsIn),
			out:            clampInt(h.EventsOut),
			dropped:        clampInt(h.Dropped),
			detections:     clampInt(h.Detections),
			errs:           clampInt(h.Errors),
			hostID:         clip(h.HostID, maxID),
			hostIDSource:   clip(h.HostIDSource, maxID),
			lastScan:       cur.lastScan,
		}
		return b.storeHealth(next)
	})
}

const maxInt64 = int64(^uint64(0) >> 1)

// clampInt converts a counter to SQLite's signed 64-bit integer.
func clampInt(v uint64) int64 {
	if v > uint64(maxInt64) {
		return maxInt64
	}
	return int64(v)
}

func satAdd(a, b int64) int64 {
	if a > maxInt64-b {
		return maxInt64
	}
	return a + b
}

func satAddU(a, b uint64) uint64 {
	if a+b < a {
		return ^uint64(0)
	}
	return a + b
}
