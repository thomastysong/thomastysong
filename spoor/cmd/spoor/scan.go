package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/thomastysong/spoor/internal/config"
	"github.com/thomastysong/spoor/internal/discovery"
	"github.com/thomastysong/spoor/internal/engine"
	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/platform"
	"github.com/thomastysong/spoor/internal/sink"
	"github.com/thomastysong/spoor/internal/state"
)

const scanAbout = `Inventories AI agents, apps, extensions, MCP servers, hooks, skills, rules
files and (with projects on) the control files of projects agents worked in,
then evaluates the inventory rules (posture). Nothing found on disk is
executed. Output passes through the configured privacy profile.

--state also records the result in the state database that the osquery
extension and Fleet read (with a heartbeat, so the fail-closed Fleet
policies see a live sensor): this is tier 2, a scheduled scan without the
daemon. --outbox also writes the shipped records to the outbox for Fluent
Bit. It never deletes a segment a configured consumer (the Fluent Bit tail
database in output.fluent_bit.tail_db, a forward or OTLP shipper) may not
have read: that pruning is the daemon's, which reads those positions. With
no consumer configured it applies retention.outbox and retention.outbox_bytes
as the daemon does. While the kill switch is on, --state and --outbox record
nothing.`

func (a *app) cmdScan(args []string) int {
	fs := a.newFlags("scan", "scan [--json|--ndjson] [--state] [--outbox] [--host-root dir] [--projects=false]", scanAbout)
	var cf cfgFlags
	cf.register(fs)
	asJSON := fs.Bool("json", false, "print one JSON document (ledger and records)")
	asNDJSON := fs.Bool("ndjson", false, "print the records as NDJSON")
	withState := fs.Bool("state", false, "record the result in the state database")
	withOutbox := fs.Bool("outbox", false, "also write shipped records to the outbox")
	hostRoot := fs.String("host-root", "", "scan another root, such as /host in a node sensor (default: host_root)")
	projects := fs.Bool("projects", true, "scan the control files of projects agents worked in (default: sources.scan.projects)")
	full := fs.Bool("full", false, "with --state: report unchanged assets too (a complete snapshot)")
	deadline := fs.Duration("deadline", 60*time.Second, "bound the scan; a scan cut short is reported as partial")
	pos, code, done := a.parse(fs, args)
	if done {
		return code
	}
	if len(pos) > 0 {
		return a.usageErr("scan", "unexpected argument %q", pos[0])
	}
	if *asJSON && *asNDJSON {
		return a.usageErr("scan", "--json and --ndjson are exclusive")
	}
	projectsSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "projects" {
			projectsSet = true
		}
	})
	cfg, _, err := loadConfig(cf)
	if err != nil {
		return a.fail("scan", err)
	}
	if *hostRoot != "" {
		cfg.HostRoot = *hostRoot
	}
	if !projectsSet {
		*projects = config.On(cfg.Sources.Scan.Projects, true)
	}
	ctx, stop := signal.NotifyContext(a.ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	res, err := a.scan(ctx, cfg, scanOptions{state: *withState, outbox: *withOutbox, projects: *projects, full: *full, deadline: *deadline})
	if err != nil {
		return a.fail("scan", err)
	}
	switch {
	case *asJSON:
		return a.printJSON(res)
	case *asNDJSON:
		enc := json.NewEncoder(a.stdout)
		enc.SetEscapeHTML(false)
		for _, e := range res.Records {
			if err := enc.Encode(e); err != nil {
				return a.fail("scan", err)
			}
		}
		return exitOK
	}
	a.printScan(res)
	return exitOK
}

type scanOptions struct {
	state, outbox, projects, full bool
	deadline                      time.Duration
}

type scanResult struct {
	Started  time.Time         `json:"started"`
	Finished time.Time         `json:"finished"`
	Complete bool              `json:"complete"`
	Ledger   discovery.Ledger  `json:"ledger"`
	Records  []*event.Event    `json:"records"`
	State    string            `json:"state_db,omitempty"`
	Disabled bool              `json:"kill_switch,omitempty"`
	Counts   map[string]int    `json:"counts"`
	Engine   map[string]uint64 `json:"engine,omitempty"`
	Notes    []string          `json:"notes,omitempty"`
}

// scan runs discovery and pushes its records through a scan-mode pipeline,
// which applies the inventory rules, the privacy policy and, with --state,
// the state database.
func (a *app) scan(ctx context.Context, cfg *config.Config, o scanOptions) (*scanResult, error) {
	set, info, err := loadRules(cfg, ruleSource{})
	if err != nil {
		return nil, err
	}
	cat, overlayErr, err := loadCatalog(cfg)
	if err != nil {
		return nil, err
	}
	if overlayErr != nil {
		a.warn("scan", "%v (embedded catalog used)", overlayErr)
	}
	disabled := platform.Disabled()
	if disabled && (o.state || o.outbox) {
		a.warn("scan", "the kill switch is on (%s): nothing is recorded", filepath.Join(platform.DefaultDirs().Config, platform.KillSwitchName))
	}
	if o.state || o.outbox {
		prepareDataDir(cfg.DataDir)
	}
	var st *state.Store
	var prev map[string]string
	if o.state {
		st, err = state.Open(cfg.StateDB())
		if err != nil {
			return nil, fmt.Errorf("state database: %w", err)
		}
		defer st.Close()
		prev, err = st.Snapshot()
		if err != nil {
			return nil, fmt.Errorf("state database: %w", err)
		}
	}
	host := platform.HostInfo()
	if cfg.HostID != "" {
		host.ID = cfg.HostID
	}
	capture := newCaptureSink("scan", event.KindInventory, event.KindPosture, event.KindDetection)
	var outbox sink.Sink = capture
	var notes []string
	if o.outbox {
		notes = append(notes, prepareOutbox(cfg.OutboxDir(), cfg.Output.Group)...)
		age, size := cfg.Retention.Outbox.D(), cfg.Retention.OutboxBytes
		if outboxConsumers(cfg) {
			// The sink prunes blindly whenever it starts a segment; with a
			// consumer configured that would delete segments it has not
			// read (DECISIONS A14). Only the daemon prunes then: it reads
			// the tail database and shipper checkpoints, keeps unread data
			// until the hard cap and reports outbox.dropped_unshipped.
			age, size = -1, -1
			notes = append(notes, "outbox not pruned by scan: a consumer is configured (Fluent Bit tail database or shipper), so only the daemon prunes, by what was read")
		}
		files, err := sink.NewFiles(sink.FilesOptions{
			Dir: cfg.OutboxDir(), MaxSegment: cfg.Output.MaxSegment, MaxLineBytes: cfg.Output.MaxLine,
			RetainAge: age, RetainBytes: size, FileMode: 0o640, Format: cfg.Output.Format,
		})
		if err != nil {
			return nil, fmt.Errorf("outbox: %w", err)
		}
		defer files.Close()
		outbox = teeSink{capture, files}
	}
	started := a.now()
	res := &scanResult{Started: started.UTC(), Disabled: disabled, Counts: map[string]int{}, Notes: notes}
	dres, err := discovery.Scan(ctx, discovery.Options{
		Catalog: cat, HostRoot: cfg.HostRoot, Projects: o.projects, Deadline: o.deadline,
		Prev: prev, Full: o.full || prev == nil, Host: &host, Now: a.now,
	})
	if err != nil {
		return nil, err
	}
	finished := a.now()
	res.Finished, res.Ledger = finished.UTC(), dres.Ledger
	res.Complete = scanComplete(dres.Ledger) && ctx.Err() == nil
	hostIDSource := platform.HostIDSource()
	if cfg.HostID != "" {
		hostIDSource = "config"
	}
	// The heartbeat names the installed bundle the scan ran with, as the
	// daemon's does: on a scan-only host it is the only heartbeat, and the
	// Fleet policy "rules bundle is current" reads it.
	bundleVer := ""
	if info.BundleVersion > 0 {
		bundleVer = strconv.FormatUint(info.BundleVersion, 10)
	}
	p, err := engine.New(engine.Options{
		Config: cfg, Catalog: cat, Rules: set, Outbox: outbox, Local: capture, State: st,
		Host: host, Mode: engine.ModeScan, Now: a.now, SensorVersion: versionString(),
		HostIDSource: hostIDSource, BundleVersion: bundleVer,
	})
	if err != nil {
		return nil, err
	}
	p.Ingest(dres.Events...)
	// The first Tick always writes a heartbeat; with --state it lands in
	// the database, which is what keeps the Fleet policies' guard green.
	p.Tick(a.now())
	if err := p.Close(); err != nil {
		return nil, err
	}
	res.Engine = p.Stats()
	if st != nil && !disabled {
		res.State = st.Path()
		var seen []string
		fin := time.Time{}
		if res.Complete {
			fin = finished
			seen = seenAssets(prev, dres.Events)
		}
		if err := st.MarkScan(started, fin, seen); err != nil {
			return nil, fmt.Errorf("state database: %w", err)
		}
	}
	res.Records = capture.all()
	sortByTime(res.Records)
	for _, e := range res.Records {
		res.Counts[string(e.Kind)]++
	}
	return res, nil
}

// outboxConsumers reports whether something is configured to read the
// outbox whose read position the daemon knows: a Fluent Bit tail database
// or one of spoor's own shippers.
func outboxConsumers(cfg *config.Config) bool {
	return cfg.Output.FluentBit.TailDB != "" ||
		(cfg.Output.Forward != nil && cfg.Output.Forward.Addr != "") ||
		(cfg.Output.OTLP != nil && cfg.Output.OTLP.Endpoint != "")
}

// scanComplete applies discovery's own rule for a scan that can prove
// absence: nothing truncated, refused, skipped or failed (a refused home
// shows up only as the ledger note discovery writes when it withholds
// removals).
func scanComplete(l discovery.Ledger) bool {
	if l.Truncated || l.Errors > 0 || l.Denied > 0 || l.Skipped > 0 {
		return false
	}
	for _, n := range l.Notes {
		if strings.HasPrefix(n, "removals not reported") {
			return false
		}
	}
	return true
}

// seenAssets is every asset a complete differential scan observed: the
// previous snapshot minus what it reported removed, plus what it reported
// new, changed or unchanged.
func seenAssets(prev map[string]string, evs []*event.Event) []string {
	set := map[string]bool{}
	for id := range prev {
		set[id] = true
	}
	for _, e := range evs {
		if e.Kind != event.KindInventory || e.Asset == nil || e.Asset.ID == "" {
			continue
		}
		if e.Asset.Change == event.ChangeRemoved {
			delete(set, e.Asset.ID)
		} else {
			set[e.Asset.ID] = true
		}
	}
	return sortedKeys(set)
}

// teeSink writes every batch to several sinks; the first error wins.
type teeSink []sink.Sink

func (t teeSink) Name() string { return "tee" }
func (t teeSink) Write(b []*event.Event) error {
	var first error
	for _, s := range t {
		if err := s.Write(b); err != nil && first == nil {
			first = err
		}
	}
	return first
}
func (t teeSink) Flush() error {
	var first error
	for _, s := range t {
		if err := s.Flush(); err != nil && first == nil {
			first = err
		}
	}
	return first
}
func (t teeSink) Close() error { return nil }

func (a *app) printScan(r *scanResult) {
	tw := a.table()
	fmt.Fprintln(tw, "KIND\tNAME\tVERSION\tOWNER\tSCOPE\tCHANGE\tPATH")
	for _, e := range r.Records {
		if e.Kind != event.KindInventory || e.Asset == nil {
			continue
		}
		as := e.Asset
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", term(string(as.Kind)), clip(as.Name, 40), clip(as.Version, 16), clip(as.Owner, 32), term(string(as.Scope)), term(string(as.Change)), clip(as.Path, 70))
	}
	tw.Flush()
	fails := 0
	for _, e := range r.Records {
		if e.Kind == event.KindPosture && e.Check != nil && e.Check.Status == "fail" {
			if fails == 0 {
				fmt.Fprintln(a.stdout, "\nPosture failures:")
			}
			fails++
			c := e.Check
			fmt.Fprintf(a.stdout, "  %-8s %s  %s  %s\n", term(c.Severity), term(c.ID), clip(c.Title, 60), clip(c.Subject, 70))
		}
	}
	l := r.Ledger
	state := "partial"
	if r.Complete {
		state = "complete"
	}
	fmt.Fprintf(a.stdout, "\nscan %s in %s: %d inventory, %d posture record(s); roots %d, files %d, denied %d, skipped %d, errors %d\n",
		state, r.Finished.Sub(r.Started).Round(time.Millisecond), r.Counts[string(event.KindInventory)], r.Counts[string(event.KindPosture)],
		l.Roots, l.Files, l.Denied, l.Skipped, l.Errors)
	for _, n := range l.Notes {
		fmt.Fprintf(a.stdout, "  note: %s\n", clip(n, 200))
	}
	for _, n := range r.Notes {
		fmt.Fprintf(a.stdout, "  note: %s\n", clip(n, 300))
	}
	if r.State != "" {
		fmt.Fprintf(a.stdout, "recorded in %s\n", r.State)
	}
}
