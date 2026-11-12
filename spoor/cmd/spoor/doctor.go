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
	"strconv"
	"strings"
	"time"

	"github.com/thomastysong/spoor/internal/bundle"
	"github.com/thomastysong/spoor/internal/catalog"
	"github.com/thomastysong/spoor/internal/config"
	"github.com/thomastysong/spoor/internal/daemon"
	"github.com/thomastysong/spoor/internal/event"
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
	Name    string `json:"name"`
	Path    string `json:"path"`
	Exists  bool   `json:"exists"`
	Mode    string `json:"mode,omitempty"`
	Owner   string `json:"owner,omitempty"`
	Want    string `json:"want,omitempty"`
	Problem string `json:"problem,omitempty"`
}

type killSwitchView struct {
	On bool `json:"on"`
	// Scope is "all" for the system kill switch (hooks exit, the daemon's
	// collectors idle) and "hooks" for a "disabled" file next to --config,
	// which only `spoor hook --config <that file>` honours.
	Scope string   `json:"scope,omitempty"`
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

	// One read of the daemon's view of the installation: its directory
	// table is what the dirs check judges against.
	snap, snapErr := daemonStatus(cfg)
	a.doctorKillSwitch(r, path)
	a.doctorHost(r, cfg)
	a.doctorDirs(r, cfg, snap, snapErr)
	a.doctorHooks(r, cfg, home)
	a.doctorRules(r, cfg)
	a.doctorBundle(r, cfg)
	a.doctorHeartbeat(r, cfg)
	a.doctorOutbox(r, cfg, asUser)
	a.doctorFluentBit(r, cfg, fbConfig)
	a.doctorDaemon(r, snap, snapErr)

	for _, c := range r.Checks {
		r.Counts[c.Status]++
	}
	return r
}

// doctorKillSwitch reports the two kill-switch files and, accurately, what
// each stops: platform.Disabled (the system file) idles the daemon's
// collectors and makes every hook exit; a "disabled" file next to --config
// is honoured by `spoor hook --config <that file>` only (internal/hookcmd),
// while the daemon and `scan` keep collecting.
func (a *app) doctorKillSwitch(r *doctorReport, cfgPath string) {
	sys := filepath.Join(platform.DefaultDirs().Config, platform.KillSwitchName)
	next := filepath.Join(filepath.Dir(cfgPath), platform.KillSwitchName)
	present := func(p string) bool { _, err := os.Lstat(p); return err == nil }
	sysOn := present(sys)
	nextOn := cfgPath != "" && next != sys && present(next)
	if sysOn {
		r.KillSwitch.Files = append(r.KillSwitch.Files, sys)
	}
	if nextOn {
		r.KillSwitch.Files = append(r.KillSwitch.Files, next)
	}
	r.KillSwitch.On = sysOn || nextOn
	switch {
	case sysOn:
		r.KillSwitch.Scope = "all"
		r.add("kill_switch", "warn", "the kill switch is ON: hooks exit at once and collectors idle", strings.Join(r.KillSwitch.Files, ", ")+" (remove the file to resume)")
	case nextOn:
		r.KillSwitch.Scope = "hooks"
		r.add("kill_switch", "warn", "a hook-only kill switch is ON: hooks that read this configuration exit at once; the daemon keeps collecting",
			next+" is honoured by `spoor hook --config "+cfgPath+"` only; the daemon (`spoor run`) and `spoor scan` honour "+sys+" alone. Create that file to idle the collectors too, or remove "+next+" to resume the hooks.")
	default:
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

// privateDirs hold records or reader positions that must never be open to
// other local accounts (the local ring is never shipped at all).
var privateDirs = map[string]bool{"outbox": true, "local": true, "checkpoints": true, "state.db": true, "spool/<uid>": true}

// doctorDirs judges every directory of the layout (and state.db) against
// the modes and owners the daemon itself creates (daemon.Snapshot.Dirs):
// one table, so doctor cannot call "safe" what the daemon would repair.
// Anything another account can write, any record directory or file other
// accounts can read, a link, and a sensor directory owned by another
// account fail; other differences from the daemon's modes warn.
func (a *app) doctorDirs(r *doctorReport, cfg *config.Config, snap daemon.Snapshot, snapErr error) {
	if snapErr != nil {
		r.add("dirs", "warn", "the directory layout could not be checked", snapErr.Error())
		return
	}
	var problems, missing []string
	status := "ok"
	raise := func(sev string) {
		if sev == "fail" || (sev == "warn" && status == "ok") {
			status = sev
		}
	}
	for _, d := range snap.Dirs {
		v, _ := dirInfo(d.Name, d.Path)
		v.Want, v.Problem = d.Want, d.Problem
		r.Dirs = append(r.Dirs, v)
		if !d.Exists {
			missing = append(missing, d.Name)
			continue
		}
		sev, why := judgeDir(d)
		if sev != "ok" {
			problems = append(problems, fmt.Sprintf("%s %s: %s", d.Name, d.Path, why))
			raise(sev)
		}
	}
	if permsChecked {
		for _, dir := range []string{cfg.OutboxDir(), cfg.LocalDir(), cfg.CheckDir()} {
			if why := exposedFiles(dir); why != "" {
				problems = append(problems, why)
				raise("fail")
			}
		}
	}
	var parts []string
	switch {
	case status == "fail":
		parts = append(parts, "unsafe directory or file modes")
	case status == "warn":
		parts = append(parts, "directory modes differ from the daemon's")
	case len(missing) < len(snap.Dirs):
		parts = append(parts, "directories present with the daemon's modes")
	}
	if len(missing) > 0 {
		parts = append(parts, "not created yet: "+strings.Join(missing, ", ")+" (the daemon or `scan --state` creates them)")
		raise("warn")
	}
	summary := strings.Join(parts, "; ")
	if !permsChecked {
		summary += " (Windows: ACLs are shown in the daemon snapshot, not judged)"
	}
	r.add("dirs", status, summary, strings.Join(problems, "\n"))
}

// judgeDir grades one entry of the daemon's directory table.
func judgeDir(d daemon.DirStatus) (string, string) {
	p := d.Problem
	if p == "" {
		return "ok", ""
	}
	if d.Mode == "" || !permsChecked {
		// No mode read: a link, a reparse point, not a directory (or not a
		// regular file), or Windows.
		if strings.Contains(p, "link") || strings.Contains(p, "reparse") || strings.HasPrefix(p, "is not") {
			return "fail", p
		}
		return "warn", p
	}
	mode, err := strconv.ParseUint(d.Mode, 8, 32)
	if err != nil {
		return "warn", p
	}
	perm := os.FileMode(mode) & os.ModePerm
	name := d.Name
	if strings.HasPrefix(name, "spool/") {
		name = "spool/<uid>"
	}
	want := firstNonEmpty(d.Want, "?")
	switch {
	case perm&0o002 != 0:
		// The sticky bit does not make a sensor directory safe: any
		// account could create entries in it (a state.db before the
		// daemon, another account's spool/<uid>).
		return "fail", fmt.Sprintf("writable by every account (mode %s, want %s)", d.Mode, want)
	case perm&0o020 != 0:
		return "fail", fmt.Sprintf("writable by its group (mode %s, want %s)", d.Mode, want)
	case privateDirs[name] && perm&0o007 != 0:
		return "fail", fmt.Sprintf("open to every account (mode %s, want %s): it holds records or positions other users must not read", d.Mode, want)
	}
	if strings.HasPrefix(p, "owned by uid ") || strings.HasPrefix(p, "not owned by root") {
		if d.Owner != "0" {
			return "fail", p + ": another account controls a directory the sensor writes as root"
		}
		// Root owns it, and doctor (unprivileged) compared with its own
		// uid: judge the mode alone. A root-owned spool/<uid> only stops
		// that account's hooks from using it.
		if name == "spool/<uid>" {
			return "warn", p + ": the account's hooks fall back to their home spool"
		}
		if modeAsWanted(d) {
			return "ok", ""
		}
		return "warn", fmt.Sprintf("mode %s, want %s", d.Mode, want)
	}
	if name == "bundle" && perm&0o005 != 0o005 {
		return "warn", p + ": unprivileged hooks cannot read it and fall back to the embedded rules"
	}
	return "warn", p
}

// modeAsWanted compares a mode with the daemon's expectation; the data
// directory accepts any mode that is traversable by all and writable by
// the owner only ("0711 (or 0755)").
func modeAsWanted(d daemon.DirStatus) bool {
	if strings.Contains(d.Want, "(or") {
		m, err := strconv.ParseUint(d.Mode, 8, 32)
		return err == nil && m&0o022 == 0 && m&0o001 != 0
	}
	return d.Mode == d.Want
}

// exposedFiles reports files in a record directory that other accounts can
// read or write (segments the daemon writes 0640 or 0600), or "".
func exposedFiles(dir string) string {
	f, err := os.Open(dir)
	if err != nil {
		return ""
	}
	ents, _ := f.ReadDir(4096)
	f.Close()
	n, example := 0, ""
	for _, e := range ents {
		if !e.Type().IsRegular() {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		if perm := fi.Mode().Perm(); perm&0o027 != 0 {
			if n == 0 {
				example = fmt.Sprintf("%s (mode %04o)", e.Name(), uint32(perm))
			}
			n++
		}
	}
	if n == 0 {
		return ""
	}
	return fmt.Sprintf("%s: %d file(s) readable or writable by other accounts, e.g. %s", dir, n, example)
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
		states = toHookStates(st, filepath.Base(home), home)
		states = append(states, systemHookStates(cat, nil, "")...)
	case r.Privileged:
		states, err = allHookStates(cat, nil, "")
	default:
		var st []hookinstall.State
		h := a.homeDir()
		st, err = hookinstall.Status(cat, hookinstall.Options{Home: h, Env: a.relocationEnv(cat)})
		states = toHookStates(st, currentUser().Name, h)
		states = append(states, systemHookStates(cat, nil, "")...)
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
			// A user-scope hook runs as the home's account; managed and
			// system hooks as any account.
			var acc *accessor
			if s.Scope == event.ScopeUser {
				acc = accessorForHome(s.User, s.home)
			}
			for _, b := range bins {
				if why := binaryProblemAs(b, acc); why != "" {
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

func (a *app) doctorDaemon(r *doctorReport, snap daemon.Snapshot, err error) {
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
