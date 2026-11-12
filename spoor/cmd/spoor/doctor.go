package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/thomastysong/spoor/internal/bundle"
	"github.com/thomastysong/spoor/internal/catalog"
	"github.com/thomastysong/spoor/internal/config"
	"github.com/thomastysong/spoor/internal/hookinstall"
	"github.com/thomastysong/spoor/internal/platform"
	"github.com/thomastysong/spoor/internal/sink"
	"github.com/thomastysong/spoor/internal/state"
)

const doctorAbout = `One screen on the health of this installation: privilege, configuration,
the kill switch, directories and their modes, host identity and its source,
hook registrations per agent and user (shadowed and insecure included),
rules and bundle versions, the last heartbeat in the state database, the
outbox (and whether --as-user can read it, e.g. the Fluent Bit account),
Fluent Bit's buffering and retry settings when output.fluent_bit.api (or
--fluent-bit-config) is given, and the daemon's own status.
Each check is ok, warn, fail or skip. Exits 4 when a check fails.`

type check struct {
	ID      string `json:"id"`
	Status  string `json:"status"` // ok | warn | fail | skip
	Summary string `json:"summary"`
	Detail  string `json:"detail,omitempty"`
}

type dirView struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	Exists bool   `json:"exists"`
	Mode   string `json:"mode,omitempty"`
	Owner  string `json:"owner,omitempty"`
}

type killSwitchView struct {
	On    bool     `json:"on"`
	Files []string `json:"files,omitempty"`
}

type hostView struct {
	ID     string `json:"id"`
	Source string `json:"source"`
	Name   string `json:"name,omitempty"`
	OS     string `json:"os"`
	Arch   string `json:"arch"`
}

type heartbeatView struct {
	At      string `json:"at,omitempty"`
	AgeS    int64  `json:"age_s,omitempty"`
	Mode    string `json:"mode,omitempty"`
	Version string `json:"sensor_version,omitempty"`
	Profile string `json:"profile,omitempty"`
	Rules   string `json:"rules_version,omitempty"`
	Bundle  string `json:"bundle_version,omitempty"`
}

type outboxView struct {
	Segments int    `json:"segments"`
	Bytes    int64  `json:"bytes"`
	Oldest   string `json:"oldest,omitempty"`
	AsUser   string `json:"as_user,omitempty"`
	Readable *bool  `json:"readable_as_user,omitempty"`
}

type bundleView struct {
	URL         string `json:"url,omitempty"`
	Installed   bool   `json:"installed"`
	Version     uint64 `json:"version,omitempty"`
	InstalledAt string `json:"installed_at,omitempty"`
	Problem     string `json:"problem,omitempty"`
}

type doctorReport struct {
	Version    buildInfo      `json:"version"`
	Config     string         `json:"config"`
	ConfigFile bool           `json:"config_file_present"`
	DataDir    string         `json:"data_dir"`
	Privileged bool           `json:"privileged"`
	KillSwitch killSwitchView `json:"kill_switch"`
	Host       hostView       `json:"host"`
	Dirs       []dirView      `json:"dirs"`
	Hooks      []hookState    `json:"hooks"`
	Rules      *ruleInfo      `json:"rules,omitempty"`
	Bundle     bundleView     `json:"bundle"`
	Heartbeat  *heartbeatView `json:"heartbeat,omitempty"`
	Outbox     outboxView     `json:"outbox"`
	FluentBit  *fluentBitView `json:"fluent_bit,omitempty"`
	Content    []string       `json:"deploy_content"`
	Daemon     any            `json:"daemon,omitempty"`
	DaemonErr  string         `json:"daemon_error,omitempty"`
	Checks     []check        `json:"checks"`
	Counts     map[string]int `json:"counts"`
}

func (r *doctorReport) add(id, status, summary, detail string) {
	r.Checks = append(r.Checks, check{ID: id, Status: status, Summary: summary, Detail: detail})
}

func (a *app) cmdDoctor(args []string) int {
	fs := a.newFlags("doctor", "doctor [--config file] [--as-user name] [--fluent-bit-config file] [--json]", doctorAbout)
	var cf cfgFlags
	cf.register(fs)
	asUser := fs.String("as-user", "", "check that this account (the shipper's) can read the outbox")
	home := fs.String("home", "", "audit the user-tier hooks of this home only (default: every account visible to the caller)")
	fbConfig := fs.String("fluent-bit-config", "", "Fluent Bit configuration file to check (YAML or classic, includes followed)")
	asJSON := fs.Bool("json", false, "print JSON")
	if pos, code, done := a.parse(fs, args); done {
		return code
	} else if len(pos) > 0 {
		return a.usageErr("doctor", "unexpected argument %q", pos[0])
	}
	r := a.doctor(cf, *asUser, *fbConfig, *home)
	if *asJSON {
		if code := a.printJSON(r); code != exitOK {
			return code
		}
	} else {
		a.printDoctor(r)
	}
	if r.Counts["fail"] > 0 {
		return exitCheck
	}
	return exitOK
}

func (a *app) doctor(cf cfgFlags, asUser, fbConfig, home string) *doctorReport {
	r := &doctorReport{Version: readBuildInfo(), Privileged: platform.IsPrivileged(), Content: deploySets(), Counts: map[string]int{}}
	cfg, path, err := loadConfig(cf)
	r.Config, r.ConfigFile = path, configExists(path)
	if err != nil {
		r.add("config", "fail", "the configuration does not load", err.Error())
		cfg = config.Default(platform.DefaultDirs().Data)
		if cf.dataDir != "" {
			cfg.DataDir = cf.dataDir
		}
	} else if r.ConfigFile {
		r.add("config", "ok", "configuration loaded", fmt.Sprintf("%s; profile %s, guard %s", path, cfg.Privacy.Profile, cfg.Guard.Mode))
	} else {
		r.add("config", "ok", "no configuration file: built-in defaults", fmt.Sprintf("%s does not exist; profile %s, guard %s", path, cfg.Privacy.Profile, cfg.Guard.Mode))
	}
	r.DataDir = cfg.DataDir

	if r.Privileged {
		r.add("privilege", "ok", "running with administrator rights", "")
	} else {
		r.add("privilege", "warn", "not running as root/Administrator", "other users' hooks and root-only directories cannot be checked")
	}

	a.doctorKillSwitch(r, path)
	a.doctorHost(r, cfg)
	a.doctorDirs(r, cfg)
	a.doctorHooks(r, cfg, home)
	a.doctorRules(r, cfg)
	a.doctorBundle(r, cfg)
	a.doctorHeartbeat(r, cfg)
	a.doctorOutbox(r, cfg, asUser)
	a.doctorFluentBit(r, cfg, fbConfig)
	a.doctorDaemon(r, cfg)

	for _, c := range r.Checks {
		r.Counts[c.Status]++
	}
	return r
}

func (a *app) doctorKillSwitch(r *doctorReport, cfgPath string) {
	sys := filepath.Join(platform.DefaultDirs().Config, platform.KillSwitchName)
	files := []string{sys}
	if next := filepath.Join(filepath.Dir(cfgPath), platform.KillSwitchName); next != sys {
		files = append(files, next)
	}
	for _, f := range files {
		if _, err := os.Lstat(f); err == nil {
			r.KillSwitch.On = true
			r.KillSwitch.Files = append(r.KillSwitch.Files, f)
		}
	}
	if r.KillSwitch.On {
		r.add("kill_switch", "warn", "the kill switch is ON: hooks exit at once and collectors idle", strings.Join(r.KillSwitch.Files, ", ")+" (remove the file to resume)")
	} else {
		r.add("kill_switch", "ok", "kill switch off", "create "+sys+" to stop all collection without uninstalling")
	}
}

func (a *app) doctorHost(r *doctorReport, cfg *config.Config) {
	h := platform.HostInfo()
	r.Host = hostView{ID: h.ID, Source: platform.HostIDSource(), Name: h.Name, OS: runtime.GOOS, Arch: runtime.GOARCH}
	if cfg.HostID != "" {
		r.Host.ID, r.Host.Source = cfg.HostID, "config"
	}
	switch {
	case r.Host.ID == "":
		r.add("host_id", "fail", "no host id could be derived", "set host_id in the configuration (Fleet's host UUID)")
	case r.Host.Source == platform.HostIDSourceMachineID:
		r.add("host_id", "warn", "host id "+r.Host.ID+" from /etc/machine-id", "osquery does not use machine-id: events may not join Fleet hosts until the osquery extension records system_info.uuid")
	default:
		r.add("host_id", "ok", "host id "+r.Host.ID, "source "+r.Host.Source)
	}
}

func dirInfo(name, path string) (dirView, os.FileInfo) {
	v := dirView{Name: name, Path: path}
	fi, err := os.Lstat(path)
	if err != nil {
		return v, nil
	}
	v.Exists = true
	v.Mode = fi.Mode().String()
	if uid, gid, ok := fileOwner(fi); ok {
		v.Owner = fmt.Sprintf("%d:%d", uid, gid)
	}
	return v, fi
}

func (a *app) doctorDirs(r *doctorReport, cfg *config.Config) {
	type want struct {
		name, path string
		public     bool // must be readable by every user (hooks read it)
		file       bool
	}
	wants := []want{
		{"data", cfg.DataDir, true, false},
		{"outbox", cfg.OutboxDir(), false, false},
		{"local", cfg.LocalDir(), false, false},
		{"spool", cfg.SpoolDir(), true, false},
		{"bundle", cfg.BundleDir(), true, false},
		{"checkpoints", cfg.CheckDir(), false, false},
		{"state_db", cfg.StateDB(), false, true},
	}
	var problems, missing []string
	status := "ok"
	for _, w := range wants {
		v, fi := dirInfo(w.name, w.path)
		r.Dirs = append(r.Dirs, v)
		if fi == nil {
			missing = append(missing, w.name)
			continue
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			problems = append(problems, w.path+" is a symbolic link")
			status = "fail"
			continue
		}
		if !permsChecked {
			continue
		}
		perm := fi.Mode().Perm()
		if perm&0o002 != 0 && fi.Mode()&os.ModeSticky == 0 {
			problems = append(problems, fmt.Sprintf("%s is world-writable (%s)", w.path, perm))
			status = "fail"
		} else if perm&0o020 != 0 && !w.public {
			problems = append(problems, fmt.Sprintf("%s is group-writable (%s)", w.path, perm))
			status = "fail"
		}
		if w.public && !w.file && perm&0o005 != 0o005 && w.name == "bundle" {
			problems = append(problems, fmt.Sprintf("%s is not readable by other users (%s): unprivileged hooks fall back to the embedded rules", w.path, perm))
			if status == "ok" {
				status = "warn"
			}
		}
		if w.name == "state_db" && r.Privileged {
			if uid, _, ok := fileOwner(fi); ok && uid != 0 {
				problems = append(problems, fmt.Sprintf("%s is owned by uid %d, not root: osquery reads it without checking", w.path, uid))
				status = "fail"
			}
		}
	}
	summary := "directories present with safe modes"
	if len(missing) > 0 {
		summary = "not created yet: " + strings.Join(missing, ", ") + " (the daemon or `scan --state` creates them)"
		if status == "ok" {
			status = "warn"
		}
	}
	if !permsChecked {
		summary += " (Windows: access is decided by ACLs, not checked here)"
	}
	r.add("dirs", status, summary, strings.Join(problems, "\n"))
}

func (a *app) doctorHooks(r *doctorReport, cfg *config.Config, home string) {
	cat, err := catalog.Load()
	if err != nil {
		r.add("hooks", "fail", "catalog does not load", err.Error())
		return
	}
	var states []hookState
	switch {
	case home != "":
		var st []hookinstall.State
		st, err = hookinstall.Status(cat, hookinstall.Options{Home: home})
		states = toHookStates(st, filepath.Base(home))
	case r.Privileged:
		states, err = allHookStates(cat, nil, "")
	default:
		var st []hookinstall.State
		st, err = hookinstall.Status(cat, hookinstall.Options{Home: a.homeDir(), Env: a.relocationEnv(cat)})
		states = toHookStates(st, currentUser().Name)
	}
	r.Hooks = states
	if states == nil && err != nil {
		r.add("hooks", "fail", "hook status could not be read", err.Error())
		return
	}
	counts := map[string]int{}
	var notes []string
	missingBin := 0
	for i := range states {
		s := &states[i]
		if s.Hash != "" {
			bins, berr := installedBinaries(s.Path)
			s.Binaries = bins
			for _, b := range bins {
				if why := binaryProblem(b); why != "" {
					s.BinaryProblem = b + ": " + why
					missingBin++
					notes = append(notes, fmt.Sprintf("hooks.binary_missing: %s %s hook runs %s, which is %s (the guarded hook exits silently: no records)", s.Agent, s.Scope, b, why))
				}
			}
			if berr != nil {
				notes = append(notes, fmt.Sprintf("%s: cannot read %s: %v", s.Agent, s.Path, berr))
			}
		}
	}
	for _, s := range states {
		counts[s.Status]++
		switch s.Status {
		case hookinstall.StatusShadowed, hookinstall.StatusModified, hookinstall.StatusInsecure:
			who := s.Agent
			if s.User != "" {
				who += " (" + s.User + ")"
			}
			notes = append(notes, fmt.Sprintf("%s %s: %s", who, s.Status, clip(s.Detail, 160)))
		}
	}
	var parts []string
	for _, k := range sortedKeys(counts) {
		parts = append(parts, fmt.Sprintf("%s %d", k, counts[k]))
	}
	status := "ok"
	switch {
	case counts[hookinstall.StatusInsecure] > 0 || missingBin > 0:
		status = "fail"
	case counts[hookinstall.StatusShadowed]+counts[hookinstall.StatusModified] > 0:
		status = "warn"
	case counts[hookinstall.StatusManaged]+counts[hookinstall.StatusUser] == 0:
		status = "warn"
		notes = append(notes, "no agent has spoor hooks: run `spoor hooks install`")
	}
	r.add("hooks", status, "hook registrations: "+strings.Join(parts, ", "), strings.Join(notes, "\n"))
}

func (a *app) doctorRules(r *doctorReport, cfg *config.Config) {
	_, info, err := loadRules(cfg, ruleSource{})
	if err != nil {
		r.add("rules", "fail", "rules do not load", err.Error())
		return
	}
	r.Rules = &info
	r.add("rules", "ok", fmt.Sprintf("%d rules loaded", info.Count), fmt.Sprintf("hash %s; %s", shortHash(info.Hash), clip(info.Version, 200)))
}

func (a *app) doctorBundle(r *doctorReport, cfg *config.Config) {
	r.Bundle.URL = endpointOrEmpty(cfg.Bundle.URL)
	info, err := bundle.Installed(cfg.BundleDir())
	switch {
	case err == nil:
		r.Bundle.Installed, r.Bundle.Version = true, info.Manifest.Version
		r.Bundle.InstalledAt = info.InstalledAt.UTC().Format(time.RFC3339)
		if _, aerr := bundle.Audit(cfg.BundleDir()); aerr != nil {
			r.Bundle.Problem = aerr.Error()
			r.add("bundle", "fail", fmt.Sprintf("bundle version %d does not match its manifest", info.Manifest.Version), aerr.Error())
			return
		}
		r.add("bundle", "ok", fmt.Sprintf("bundle version %d installed %s", info.Manifest.Version, r.Bundle.InstalledAt), "")
	case errors.Is(err, bundle.ErrNotInstalled):
		if cfg.Bundle.URL != "" {
			r.add("bundle", "warn", "no bundle installed although bundle.url is set", "run `spoor bundle pull`; the embedded rules are in force")
		} else {
			r.add("bundle", "ok", "no bundle configured: embedded rules", "")
		}
	default:
		r.Bundle.Problem = err.Error()
		r.add("bundle", "fail", "the installed bundle cannot be used", err.Error())
	}
}

func endpointOrEmpty(s string) string {
	if s == "" {
		return ""
	}
	return endpointHost(s)
}

func (a *app) doctorHeartbeat(r *doctorReport, cfg *config.Config) {
	if _, err := os.Stat(cfg.StateDB()); err != nil {
		r.add("heartbeat", "warn", "no state database yet", cfg.StateDB()+": the daemon (or `spoor scan --state`) has not run; Fleet policies fail closed until it does")
		return
	}
	st, err := state.OpenReadOnly(cfg.StateDB())
	if err != nil {
		r.add("heartbeat", "fail", "the state database cannot be opened", err.Error())
		return
	}
	defer st.Close()
	rows, err := st.Query("health", nil)
	if err != nil {
		r.add("heartbeat", "fail", "the state database cannot be read", err.Error())
		return
	}
	if len(rows) == 0 || rows[0]["heartbeat"] == "" {
		r.add("heartbeat", "warn", "no heartbeat recorded", "")
		return
	}
	row := rows[0]
	hb := &heartbeatView{At: row["heartbeat"], Mode: row["mode"], Version: row["sensor_version"], Profile: row["profile"], Rules: row["rules_version"], Bundle: row["bundle_version"]}
	r.Heartbeat = hb
	t, err := time.Parse(time.RFC3339Nano, row["heartbeat"])
	if err != nil {
		r.add("heartbeat", "warn", "heartbeat timestamp unreadable", row["heartbeat"])
		return
	}
	age := a.now().Sub(t)
	hb.AgeS = int64(age / time.Second)
	limit := 3 * cfg.Heartbeat.D()
	switch {
	case age > 30*time.Minute:
		r.add("heartbeat", "fail", fmt.Sprintf("last heartbeat %s ago (%s)", age.Round(time.Second), hb.Mode), "Fleet's \"sensor is reporting\" policy fails after 30 minutes")
	case age > limit:
		r.add("heartbeat", "warn", fmt.Sprintf("last heartbeat %s ago (%s)", age.Round(time.Second), hb.Mode), fmt.Sprintf("expected every %s", cfg.Heartbeat.D()))
	default:
		r.add("heartbeat", "ok", fmt.Sprintf("last heartbeat %s ago (%s, sensor %s)", age.Round(time.Second), hb.Mode, hb.Version), "")
	}
}

func (a *app) doctorOutbox(r *doctorReport, cfg *config.Config, asUser string) {
	dir := cfg.OutboxDir()
	ents, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			r.add("outbox", "warn", "no outbox yet", dir)
		} else {
			r.add("outbox", "warn", "outbox not readable by this account", err.Error())
		}
		return
	}
	var names []string
	var oldest time.Time
	for _, e := range ents {
		if _, ok := sink.ParseSegmentName(e.Name()); !ok || !e.Type().IsRegular() {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		names = append(names, e.Name())
		r.Outbox.Segments++
		r.Outbox.Bytes += fi.Size()
		if oldest.IsZero() || fi.ModTime().Before(oldest) {
			oldest = fi.ModTime()
		}
	}
	if !oldest.IsZero() {
		r.Outbox.Oldest = oldest.UTC().Format(time.RFC3339)
	}
	status, detail := "ok", ""
	if cfg.Retention.OutboxBytes > 0 && r.Outbox.Bytes > cfg.Retention.OutboxBytes*9/10 {
		status, detail = "warn", "the outbox is near retention.outbox_bytes: unshipped data will be dropped (is the shipper running?)"
	}
	if asUser != "" {
		r.Outbox.AsUser = asUser
		acc, err := lookupAccessor(asUser)
		if err != nil {
			status, detail = "warn", fmt.Sprintf("--as-user %s: %v", asUser, err)
		} else {
			sort.Strings(names)
			ok, why := acc.canRead(dir, names)
			r.Outbox.Readable = &ok
			if !ok {
				status, detail = "fail", why+fmt.Sprintf(" (add %s to the %q group or adjust output.group)", asUser, cfg.Output.Group)
			}
		}
	}
	r.add("outbox", status, fmt.Sprintf("%d segment(s), %s", r.Outbox.Segments, bytesStr(r.Outbox.Bytes)), detail)
}

func (a *app) doctorFluentBit(r *doctorReport, cfg *config.Config, fbConfig string) {
	api := cfg.Output.FluentBit.API
	if api == "" && fbConfig == "" && cfg.Output.FluentBit.TailDB == "" {
		r.add("fluent_bit", "skip", "Fluent Bit not configured for checks", "set output.fluent_bit.api (and tail_db) or pass --fluent-bit-config")
		return
	}
	v := &fluentBitView{API: api, Config: fbConfig, TailDB: cfg.Output.FluentBit.TailDB}
	r.FluentBit = v
	if api != "" {
		ctx, cancel := context.WithTimeout(a.ctx, 5*time.Second)
		defer cancel()
		f, ver := checkFluentBitAPI(ctx, loopbackClient(3*time.Second), api)
		v.Version = ver
		v.Findings = append(v.Findings, f...)
	}
	if fbConfig != "" {
		secs, err := readFluentBitConfig(fbConfig, 0)
		if err != nil {
			v.Findings = append(v.Findings, fbFinding{Code: "shipper.config", Status: "warn", Detail: err.Error()})
		} else {
			v.Findings = append(v.Findings, checkFluentBitConfig(secs, cfg.OutboxDir())...)
		}
	}
	v.Findings = append(v.Findings, checkTailDB(cfg.Output.FluentBit.TailDB)...)
	status := "ok"
	var details []string
	for _, f := range v.Findings {
		details = append(details, f.Code+": "+f.Detail)
		if f.Status == "fail" {
			status = "fail"
		} else if f.Status == "warn" && status == "ok" {
			status = "warn"
		}
	}
	summary := "Fluent Bit settings are safe"
	if v.Version != "" {
		summary += " (Fluent Bit " + v.Version + ")"
	}
	if status != "ok" {
		summary = fmt.Sprintf("%d Fluent Bit problem(s)", len(v.Findings))
	}
	if v.Findings == nil {
		v.Findings = []fbFinding{}
	}
	r.add("fluent_bit", status, summary, strings.Join(details, "\n"))
}

func (a *app) doctorDaemon(r *doctorReport, cfg *config.Config) {
	snap, err := daemonStatus(cfg)
	if err != nil {
		r.DaemonErr = err.Error()
		r.add("daemon", "warn", "daemon status unavailable", err.Error())
		return
	}
	// Round-trip through JSON so the report holds plain data whatever the
	// snapshot type is.
	b, err := json.Marshal(snap)
	if err == nil {
		var v any
		if json.Unmarshal(b, &v) == nil {
			r.Daemon = v
		}
	}
	r.add("daemon", "ok", "daemon status read", "")
}

func (a *app) printDoctor(r *doctorReport) {
	fmt.Fprintf(a.stdout, "spoor %s on %s/%s, host %s, data %s\n\n", r.Version.Version, r.Host.OS, r.Host.Arch, term(firstNonEmpty(r.Host.Name, "?")), sanitize(r.DataDir))
	for _, c := range r.Checks {
		fmt.Fprintf(a.stdout, "[%-4s] %-12s %s\n", strings.ToUpper(c.Status), c.ID, sanitize(c.Summary))
		if c.Detail != "" && c.Status != "ok" {
			for _, d := range strings.Split(c.Detail, "\n") {
				fmt.Fprintf(a.stdout, "       %-12s %s\n", "", clip(d, 200))
			}
		}
	}
	var shown []hookState
	for _, s := range r.Hooks {
		if s.Status != hookinstall.StatusMissing || s.Hash != "" {
			shown = append(shown, s)
		}
	}
	if len(shown) > 0 {
		fmt.Fprintln(a.stdout, "\nHooks (missing ones omitted):")
		tw := a.table()
		for _, s := range shown {
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", term(s.Agent), term(string(s.Scope)), term(s.User), term(s.Status))
		}
		tw.Flush()
	}
	if m, ok := r.Daemon.(map[string]any); ok && len(m) > 0 {
		fmt.Fprintln(a.stdout, "\nDaemon:")
		for _, k := range sortedKeys(m) {
			b, _ := json.Marshal(m[k])
			fmt.Fprintf(a.stdout, "  %s: %s\n", k, clip(string(b), 160))
		}
	}
	fmt.Fprintf(a.stdout, "\n%d ok, %d warn, %d fail, %d skip\n", r.Counts["ok"], r.Counts["warn"], r.Counts["fail"], r.Counts["skip"])
}
