package daemon

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"time"

	"github.com/thomastysong/spoor/internal/bundle"
	"github.com/thomastysong/spoor/internal/config"
	"github.com/thomastysong/spoor/internal/platform"
	"github.com/thomastysong/spoor/internal/state"
)

// Snapshot is the daemon's side of `spoor doctor`: what can be read from
// disk about an installation, without talking to a running daemon and
// without writing anything (the state database and Fluent Bit's tail
// databases are opened read-only). Problems lists, in plain words, what an
// operator should look at; an empty list means nothing was found wrong, not
// that the daemon is running (State.Fresh says whether it wrote a heartbeat
// recently).
type Snapshot struct {
	Time       time.Time `json:"time"`
	OS         string    `json:"os"`
	Version    string    `json:"version"`
	Privileged bool      `json:"privileged"`

	KillSwitch KillSwitchStatus `json:"kill_switch"`
	Host       HostStatus       `json:"host"`
	Dirs       []DirStatus      `json:"dirs"`
	State      StateStatus      `json:"state"`
	Outbox     OutboxStatus     `json:"outbox"`
	Bundle     BundleStatus     `json:"bundle"`

	Problems []string `json:"problems,omitempty"`
}

// KillSwitchStatus is platform.Disabled: the file whose presence idles
// every collector and makes `spoor hook` exit at once.
type KillSwitchStatus struct {
	Path    string `json:"path"`
	Engaged bool   `json:"engaged"`
}

// HostStatus is the identity records are stamped with and where it came
// from (config | env | file | dmi | machine-id | gethostuuid | ioreg |
// smbios | machineguid | none).
type HostStatus struct {
	ID     string `json:"id,omitempty"`
	Name   string `json:"name,omitempty"`
	Source string `json:"source"`
}

// DirStatus is one directory of the layout with its expected access.
type DirStatus struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	Exists bool   `json:"exists"`
	// Mode, Owner and Group are POSIX values ("2750", uid, gid); ACL is
	// the Windows security descriptor in SDDL.
	Mode    string `json:"mode,omitempty"`
	Owner   string `json:"owner,omitempty"`
	Group   string `json:"group,omitempty"`
	ACL     string `json:"acl,omitempty"`
	Want    string `json:"want,omitempty"`
	OK      bool   `json:"ok"`
	Problem string `json:"problem,omitempty"`
}

// StateStatus is the state database's health row: the heartbeat Fleet's
// policies check.
type StateStatus struct {
	Path     string `json:"path"`
	Readable bool   `json:"readable"`
	Error    string `json:"error,omitempty"`

	Heartbeat     time.Time `json:"heartbeat,omitzero"`
	HeartbeatAgeS int64     `json:"heartbeat_age_s,omitempty"`
	// Fresh is true when the heartbeat is younger than the alert window
	// Fleet's "sensor reporting" policy uses (state.DefaultAlertMaxAge).
	Fresh          bool           `json:"fresh"`
	SensorVersion  string         `json:"sensor_version,omitempty"`
	Mode           string         `json:"mode,omitempty"`
	Profile        string         `json:"profile,omitempty"`
	RulesCount     int            `json:"rules_count,omitempty"`
	RulesVersion   string         `json:"rules_version,omitempty"`
	RulesHash      string         `json:"rules_hash,omitempty"`
	CatalogVersion string         `json:"catalog_version,omitempty"`
	BundleVersion  string         `json:"bundle_version,omitempty"`
	HostID         string         `json:"host_id,omitempty"`
	HostIDSource   string         `json:"host_id_source,omitempty"`
	LastScan       time.Time      `json:"last_scan,omitzero"`
	ScanComplete   bool           `json:"scan_complete"`
	EventsIn       uint64         `json:"events_in"`
	EventsOut      uint64         `json:"events_out"`
	Dropped        uint64         `json:"dropped"`
	Detections     uint64         `json:"detections"`
	Errors         uint64         `json:"errors"`
	Rows           map[string]int `json:"rows,omitempty"`
}

// OutboxStatus is the shipped-record queue and how far its consumers got.
type OutboxStatus struct {
	Dir      string                `json:"dir"`
	Segments int                   `json:"segments"`
	Bytes    int64                 `json:"bytes"`
	Oldest   time.Time             `json:"oldest,omitzero"`
	Newest   time.Time             `json:"newest,omitzero"`
	Streams  map[string]StreamSize `json:"streams,omitempty"`
	// LagBytes is shipper_lag_bytes: bytes no consumer has read yet. It is
	// only known when a Fluent Bit tail database or a shipper is configured.
	LagKnown  bool             `json:"lag_known"`
	LagBytes  int64            `json:"lag_bytes,omitempty"`
	Consumers []ConsumerStatus `json:"consumers,omitempty"`
}

// ConsumerStatus is one reader of the outbox: a Fluent Bit tail database or
// a spoor shipper's checkpoint.
type ConsumerStatus struct {
	ID       string `json:"id"`
	Readable bool   `json:"readable"`
	Error    string `json:"error,omitempty"`
	LagBytes int64  `json:"lag_bytes"`
}

// BundleStatus is the installed signed content bundle.
type BundleStatus struct {
	Dir         string    `json:"dir"`
	Installed   bool      `json:"installed"`
	Version     uint64    `json:"version,omitempty"`
	Created     time.Time `json:"created,omitzero"`
	InstalledAt time.Time `json:"installed_at,omitzero"`
	Error       string    `json:"error,omitempty"`
}

// Status reads the installation described by cfg for `spoor doctor`.
// The error is reserved for an unusable configuration; everything the
// snapshot could not read is reported inside it.
func Status(cfg *config.Config) (Snapshot, error) {
	return status(cfg, statusEnv{
		now:        time.Now(),
		privileged: platform.IsPrivileged(),
		disabled:   platform.Disabled,
		killPath:   filepath.Join(platform.DefaultDirs().Config, platform.KillSwitchName),
		host: func() HostStatus {
			h := platform.HostInfo()
			return HostStatus{ID: h.ID, Name: h.Name, Source: platform.HostIDSource()}
		},
	})
}

type statusEnv struct {
	now        time.Time
	privileged bool
	disabled   func() bool
	killPath   string
	host       func() HostStatus
}

func status(cfg *config.Config, env statusEnv) (Snapshot, error) {
	if cfg == nil {
		return Snapshot{}, errors.New("daemon: no configuration")
	}
	if cfg.DataDir == "" {
		return Snapshot{}, errors.New("daemon: data_dir is not set")
	}
	s := Snapshot{
		Time:       env.now.UTC(),
		OS:         runtime.GOOS,
		Version:    Version,
		Privileged: env.privileged,
		KillSwitch: KillSwitchStatus{Path: env.killPath, Engaged: env.disabled()},
		Host:       env.host(),
	}
	if cfg.HostID != "" {
		s.Host.ID, s.Host.Source = cfg.HostID, "config"
	}
	if !s.Privileged {
		s.problem("not running privileged: the daemon must run as root (Administrator), or on Linux with CAP_DAC_READ_SEARCH and CAP_SYS_PTRACE, to see every user's agents")
	}
	if s.KillSwitch.Engaged {
		s.problem("the kill switch is engaged (" + s.KillSwitch.Path + "): collectors are idle and hooks exit at once")
	}
	if s.Host.ID == "" {
		s.problem("no host id could be derived: set host_id or SPOOR_HOST_ID")
	}
	s.Dirs = dirStatuses(cfg)
	for _, d := range s.Dirs {
		if d.Problem != "" {
			s.problem(d.Name + " " + d.Path + ": " + d.Problem)
		}
	}
	s.State = stateStatus(cfg.StateDB(), env.now)
	switch {
	case !s.State.Readable:
		s.problem("state database unreadable: " + s.State.Error)
	case s.State.Heartbeat.IsZero():
		s.problem("the state database holds no heartbeat: the daemon has not run")
	case !s.State.Fresh:
		s.problem(fmt.Sprintf("last heartbeat is %s old: the daemon is not running or cannot write", time.Duration(s.State.HeartbeatAgeS)*time.Second))
	}
	s.Outbox = outboxStatus(cfg, env.now)
	for _, c := range s.Outbox.Consumers {
		if !c.Readable {
			s.problem("outbox consumer " + c.ID + " unreadable: " + c.Error)
		}
	}
	s.Bundle = bundleStatus(cfg.BundleDir())
	if s.Bundle.Error != "" {
		s.problem("bundle: " + s.Bundle.Error)
	}
	return s, nil
}

func (s *Snapshot) problem(p string) { s.Problems = append(s.Problems, p) }

// dirStatuses checks every directory of the layout against what the
// daemon creates (see the package comment).
func dirStatuses(cfg *config.Config) []DirStatus {
	type want struct {
		name, path string
		kind       dirKind
	}
	list := []want{
		{"data", cfg.DataDir, dirData},
		{"outbox", cfg.OutboxDir(), dirOutbox},
		{"local", cfg.LocalDir(), dirPrivate},
		{"checkpoints", cfg.CheckDir(), dirPrivate},
		{"spool", cfg.SpoolDir(), dirSpoolRoot},
		{"bundle", cfg.BundleDir(), dirBundle},
	}
	var out []DirStatus
	for _, w := range list {
		out = append(out, checkDir(w.name, w.path, w.kind, ""))
	}
	// Per-account spools.
	ents, err := os.ReadDir(cfg.SpoolDir())
	if err == nil {
		var names []string
		for _, e := range ents {
			if validUID(e.Name()) {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)
		if len(names) > 64 {
			names = names[:64]
		}
		for _, n := range names {
			out = append(out, checkDir("spool/"+n, filepath.Join(cfg.SpoolDir(), n), dirUserSpool, n))
		}
	}
	// The state database file itself.
	out = append(out, checkStateFile(cfg.StateDB()))
	return out
}

func stateStatus(path string, now time.Time) StateStatus {
	st := StateStatus{Path: path}
	if _, err := os.Lstat(path); err != nil {
		st.Error = err.Error()
		return st
	}
	db, err := state.OpenReadOnly(path)
	if err != nil {
		st.Error = err.Error()
		return st
	}
	defer db.Close()
	st.Readable = true
	rows, err := db.Query("health", nil)
	if err != nil {
		st.Readable = false
		st.Error = err.Error()
		return st
	}
	if stats, err := db.Stats(); err == nil {
		st.Rows = map[string]int{}
		for _, t := range state.Tables {
			st.Rows[t.Name] = stats.Rows[t.Name]
		}
	}
	if len(rows) == 0 {
		return st
	}
	r := rows[0]
	st.Heartbeat = parseTS(r["heartbeat"])
	st.LastScan = parseTS(r["last_scan"])
	if !st.Heartbeat.IsZero() {
		age := now.Sub(st.Heartbeat)
		st.HeartbeatAgeS = int64(age / time.Second)
		st.Fresh = age >= -time.Minute && age <= state.DefaultAlertMaxAge
	}
	st.SensorVersion = r["sensor_version"]
	st.Mode = r["mode"]
	st.Profile = r["profile"]
	st.RulesVersion = r["rules_version"]
	st.RulesHash = r["rules_hash"]
	st.CatalogVersion = r["catalog_version"]
	st.BundleVersion = r["bundle_version"]
	st.HostID = r["host_id"]
	st.HostIDSource = r["host_id_source"]
	st.ScanComplete = r["scan_complete"] == "1"
	st.RulesCount, _ = strconv.Atoi(r["rules_count"])
	st.EventsIn, _ = strconv.ParseUint(r["events_in"], 10, 64)
	st.EventsOut, _ = strconv.ParseUint(r["events_out"], 10, 64)
	st.Dropped, _ = strconv.ParseUint(r["dropped"], 10, 64)
	st.Detections, _ = strconv.ParseUint(r["detections"], 10, 64)
	st.Errors, _ = strconv.ParseUint(r["errors"], 10, 64)
	return st
}

func parseTS(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// outboxStatus measures the outbox and its consumers without changing
// anything (no deletion, no saved coverage, no scratch copies).
func outboxStatus(cfg *config.Config, now time.Time) OutboxStatus {
	o := OutboxStatus{Dir: cfg.OutboxDir()}
	var shipCons []consumer
	if f := cfg.Output.Forward; f != nil && f.Addr != "" {
		shipCons = append(shipCons, &shipperConsumer{name: "forward", path: filepath.Join(cfg.CheckDir(), "shipper-forward.checkpoint")})
	}
	if t := cfg.Output.OTLP; t != nil && t.Endpoint != "" {
		shipCons = append(shipCons, &shipperConsumer{name: "otlp", path: filepath.Join(cfg.CheckDir(), "shipper-otlp.checkpoint")})
	}
	spec := cfg.Output.FluentBit.TailDB
	p := newOutboxPruner(pruneOptions{
		dir: cfg.OutboxDir(),
		consumers: func() []consumer {
			return append(tailDBConsumers(spec, ""), shipCons...)
		},
		statePath: filepath.Join(cfg.CheckDir(), "outbox-consumers.json"),
		readOnly:  true,
	})
	_, res := func() ([]*outSeg, pruneResult) {
		p.mu.Lock()
		defer p.mu.Unlock()
		return p.measure(now)
	}()
	o.Segments, o.Bytes, o.Oldest, o.Newest = res.segments, res.bytes, res.oldest, res.newest
	o.Streams = res.perStream
	o.LagKnown, o.LagBytes = res.lagKnown, res.lag
	ids := make([]string, 0, len(res.consumerLag))
	for id := range res.consumerLag {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		c := ConsumerStatus{ID: id, Readable: res.consumerErr[id] == "", Error: res.consumerErr[id], LagBytes: res.consumerLag[id]}
		o.Consumers = append(o.Consumers, c)
	}
	return o
}

func bundleStatus(dir string) BundleStatus {
	b := BundleStatus{Dir: dir}
	info, err := bundle.Installed(dir)
	switch {
	case err == nil:
		b.Installed = true
		b.Version = info.Manifest.Version
		b.Created = info.Manifest.Created
		b.InstalledAt = info.InstalledAt
	case errors.Is(err, bundle.ErrNotInstalled):
	default:
		b.Error = bundle.Reason(err)
	}
	return b
}
