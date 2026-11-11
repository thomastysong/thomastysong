// Package config is the single definition of every operator-facing setting.
// A config file is optional: defaults are safe (observe only, privacy profile
// "minimal", nothing leaves the host except findings, inventory, posture,
// health and session summaries).
package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration is a time.Duration that reads "5m", "72h" from YAML.
type Duration time.Duration

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return err
	}
	v, err := time.ParseDuration(strings.TrimSpace(s))
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	if v < 0 {
		return fmt.Errorf("line %d: negative duration", n.Line)
	}
	*d = Duration(v)
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (d Duration) MarshalYAML() (any, error) { return time.Duration(d).String(), nil }

// D returns the value as a time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// Config is the whole configuration.
type Config struct {
	// DataDir holds outbox/, local/, spool/, state.db, bundle/ and checkpoints.
	DataDir string `yaml:"data_dir"`
	// HostID overrides host identity detection (use Fleet's host UUID).
	HostID string `yaml:"host_id"`
	// HostRoot is a filesystem prefix for scanning another root, such as /host
	// in a Kubernetes node sensor.
	HostRoot string `yaml:"host_root"`
	// Tags describe the host or its owner's role (for example offsec, ci,
	// platform-eng); rules and suppressions can match on them. Typically
	// stamped from Fleet labels at install time.
	Tags []string `yaml:"tags"`
	// Labels are copied onto every emitted record.
	Labels map[string]string `yaml:"labels"`

	Privacy   Privacy   `yaml:"privacy"`
	Guard     Guard     `yaml:"guard"`
	Sources   Sources   `yaml:"sources"`
	Output    Output    `yaml:"output"`
	Rules     Rules     `yaml:"rules"`
	Bundle    Bundle    `yaml:"bundle"`
	Retention Retention `yaml:"retention"`
	Limits    Limits    `yaml:"limits"`

	// Heartbeat is the interval between health records.
	Heartbeat Duration `yaml:"heartbeat"`
}

// Privacy controls what leaves the endpoint. Detection always runs locally
// on full content; these settings only govern what is written for shipping.
type Privacy struct {
	// Profile: minimal (default) ships findings, inventory, posture, health
	// and session summaries; standard also ships activity with field-level
	// redaction and no prompt text or tool output; full adds redacted content.
	Profile string `yaml:"profile"`
	// HMACKeyFile holds the tenant key for content-derived digests and
	// pseudonyms (root-only file). Without a key no such digest is emitted.
	HMACKeyFile string `yaml:"hmac_key_file"`
	KeyID       string `yaml:"key_id"`
	// PseudonymizeUsers replaces user names with keyed pseudonyms.
	PseudonymizeUsers bool `yaml:"pseudonymize_users"`
	// Exclude drops sessions before any content is processed. Globs.
	Exclude Exclude `yaml:"exclude"`
	// ContextEvents is how many preceding session events accompany a finding
	// in the detection stream (0 disables).
	ContextEvents int `yaml:"context_events"`
}

// Exclude lists sessions that must not be monitored.
type Exclude struct {
	Paths []string `yaml:"paths"` // session working directory globs
	Repos []string `yaml:"repos"` // repository remote globs
	Users []string `yaml:"users"` // OS account names
}

// Guard configures the optional pre-action decisions. It is advisory: agent
// hooks fail open on timeout, so guard is a speed bump, not a control.
type Guard struct {
	// Mode: off (default) | advisory (rules with response ask/block answer hooks).
	Mode string `yaml:"mode"`
	// Deadline bounds rule evaluation in the hook; on expiry the answer is "ask".
	Deadline Duration `yaml:"deadline"`
	// MaxResponse caps what a rule may request: ask | block.
	MaxResponse string `yaml:"max_response"`
}

// Sources switches collectors on and off.
type Sources struct {
	Hooks       HookSource       `yaml:"hooks"`
	Transcripts TranscriptSource `yaml:"transcripts"`
	Processes   ProcessSource    `yaml:"processes"`
	OsqueryExec OsquerySource    `yaml:"osquery_exec"`
	OTLP        OTLPSource       `yaml:"otlp"`
	Scan        ScanSource       `yaml:"scan"`
	Adapters    []AdapterSource  `yaml:"adapters"`
}

// HookSource is the spool the hook entrypoint writes and the daemon ingests.
type HookSource struct {
	Enabled *bool    `yaml:"enabled"`
	Poll    Duration `yaml:"poll"`
}

// TranscriptSource tails agents' on-disk session logs.
type TranscriptSource struct {
	Enabled *bool    `yaml:"enabled"`
	Agents  []string `yaml:"agents"` // catalog ids; empty = all supported
	Poll    Duration `yaml:"poll"`
	// Backfill is how far back to read files that existed before first sight
	// (0 = start at end of file).
	Backfill Duration `yaml:"backfill"`
}

// ProcessSource is the OS process monitor.
type ProcessSource struct {
	Enabled *bool    `yaml:"enabled"`
	Idle    Duration `yaml:"idle"`
	Active  Duration `yaml:"active"`
	// ExecEvents enables the Linux process connector when available.
	ExecEvents *bool `yaml:"exec_events"`
}

// OsquerySource pulls process exec rows from a running osqueryd over its
// extension socket when the organisation has evented tables switched on.
// Rows are filtered to agent descendants locally and nothing is scheduled in
// Fleet: a Fleet-scheduled query over evented process tables would send every
// command line on the host to the Fleet server, outside the privacy profile.
type OsquerySource struct {
	Enabled  *bool    `yaml:"enabled"`
	Socket   string   `yaml:"socket"` // empty = try the well-known orbit and osquery sockets
	Interval Duration `yaml:"interval"`
}

// OTLPSource is the loopback receiver for agent-native OpenTelemetry (experimental).
type OTLPSource struct {
	Enabled bool   `yaml:"enabled"`
	Addr    string `yaml:"addr"`
}

// ScanSource schedules inventory and posture scans.
type ScanSource struct {
	Enabled  *bool    `yaml:"enabled"`
	Interval Duration `yaml:"interval"`
	// FullEvery is how often a complete snapshot is emitted; scans in between
	// emit only changes.
	FullEvery Duration `yaml:"full_every"`
	Projects  *bool    `yaml:"projects"`
}

// AdapterSource tails another sensor's NDJSON output (experimental).
type AdapterSource struct {
	Format string   `yaml:"format"` // numbat
	Paths  []string `yaml:"paths"`  // globs
}

// Output selects where records go.
type Output struct {
	// Format of the outbox: native (default) | ocsf.
	Format string `yaml:"format"`
	// Stdout also writes shipped records to standard output (containers).
	Stdout bool `yaml:"stdout"`
	// MaxSegment rolls an outbox segment past this many bytes.
	MaxSegment int64 `yaml:"max_segment_bytes"`
	// MaxLine caps one record; larger fields are cut and listed in "truncated".
	MaxLine   int         `yaml:"max_line_bytes"`
	Forward   *Forward    `yaml:"forward"`
	OTLP      *OTLP       `yaml:"otlp"`
	FluentBit FluentBit   `yaml:"fluent_bit"`
	Streams   []string    `yaml:"streams"` // restrict shipped streams; empty = profile default
	Group     string      `yaml:"group"`   // group allowed to read the outbox (POSIX)
	Mode      os.FileMode `yaml:"-"`
}

// Forward ships outbox segments with the Fluent Forward protocol (experimental).
type Forward struct {
	Addr      string   `yaml:"addr"`
	TagPrefix string   `yaml:"tag_prefix"`
	SharedKey string   `yaml:"shared_key"`
	Compress  bool     `yaml:"compress"`
	Timeout   Duration `yaml:"timeout"`
}

// OTLP ships outbox segments as OTLP/HTTP JSON logs (experimental).
type OTLP struct {
	Endpoint string            `yaml:"endpoint"`
	Headers  map[string]string `yaml:"headers"`
	Gzip     bool              `yaml:"gzip"`
	Timeout  Duration          `yaml:"timeout"`
}

// FluentBit lets the sensor observe its shipper: with the tail database it
// prunes only segments Fluent Bit has read and reports shipper lag.
type FluentBit struct {
	TailDB string `yaml:"tail_db"`
	API    string `yaml:"api"` // http://127.0.0.1:2020
}

// Rules configures detection content.
type Rules struct {
	Dirs         []string      `yaml:"dirs"`
	Disable      []string      `yaml:"disable"`
	SuppressFor  Duration      `yaml:"suppress_for"`
	Suppressions []Suppression `yaml:"suppressions"`
	// MinClass is the lowest class written to the detection stream:
	// signal | finding (default) | alert.
	MinClass string `yaml:"min_class"`
}

// Suppression is an operator exception.
type Suppression struct {
	Rule    string            `yaml:"rule"`
	Match   map[string]string `yaml:"match"` // field -> glob
	Tags    []string          `yaml:"tags"`  // only on hosts carrying one of these tags
	Expires string            `yaml:"expires"`
	Reason  string            `yaml:"reason"`
}

// Bundle configures signed content updates.
type Bundle struct {
	URL        string   `yaml:"url"`
	PublicKeys []string `yaml:"public_keys"`
	Interval   Duration `yaml:"interval"`
}

// Retention bounds every local store.
type Retention struct {
	Outbox      Duration `yaml:"outbox"`       // age cap for shipped segments
	OutboxBytes int64    `yaml:"outbox_bytes"` // hard cap; unread data dropped beyond it is reported
	Local       Duration `yaml:"local"`        // local activity ring
	LocalBytes  int64    `yaml:"local_bytes"`
	Spool       Duration `yaml:"spool"`
	Detections  Duration `yaml:"detections"` // state DB
	Sessions    Duration `yaml:"sessions"`   // state DB
}

// Limits bounds volume and cost.
type Limits struct {
	ActivityPerSecond int `yaml:"activity_per_second"` // per session token bucket
	ActivityBurst     int `yaml:"activity_burst"`
	MaxHookInput      int `yaml:"max_hook_input_bytes"`
}

// Default returns the built-in configuration for a data directory.
func Default(dataDir string) *Config {
	// Every switch gets its own pointer: the YAML decoder writes through
	// existing pointers, so a shared one would let "transcripts.enabled:
	// false" switch every other source off as well.
	on := func() *bool { v := true; return &v }
	return &Config{
		DataDir: dataDir,
		Privacy: Privacy{Profile: "minimal", ContextEvents: 5},
		Guard:   Guard{Mode: "off", Deadline: Duration(150 * time.Millisecond), MaxResponse: "ask"},
		Sources: Sources{
			Hooks:       HookSource{Enabled: on(), Poll: Duration(100 * time.Millisecond)},
			Transcripts: TranscriptSource{Enabled: on(), Poll: Duration(2 * time.Second)},
			Processes:   ProcessSource{Enabled: on(), Idle: Duration(2 * time.Second), Active: Duration(200 * time.Millisecond), ExecEvents: on()},
			OsqueryExec: OsquerySource{Enabled: on(), Interval: Duration(5 * time.Second)},
			OTLP:        OTLPSource{Enabled: false, Addr: "127.0.0.1:4319"},
			Scan:        ScanSource{Enabled: on(), Interval: Duration(time.Hour), FullEvery: Duration(24 * time.Hour), Projects: on()},
		},
		Output: Output{Format: "native", MaxSegment: 16 << 20, MaxLine: 16 << 10, Group: "spoor"},
		Rules:  Rules{SuppressFor: Duration(24 * time.Hour), MinClass: "finding"},
		Bundle: Bundle{Interval: Duration(time.Hour)},
		Retention: Retention{
			Outbox: Duration(7 * 24 * time.Hour), OutboxBytes: 512 << 20,
			Local: Duration(72 * time.Hour), LocalBytes: 256 << 20,
			Spool:      Duration(72 * time.Hour),
			Detections: Duration(30 * 24 * time.Hour), Sessions: Duration(7 * 24 * time.Hour),
		},
		Limits:    Limits{ActivityPerSecond: 20, ActivityBurst: 200, MaxHookInput: 8 << 20},
		Heartbeat: Duration(5 * time.Minute),
	}
}

// Paths derived from DataDir.
func (c *Config) OutboxDir() string  { return filepath.Join(c.DataDir, "outbox") }
func (c *Config) LocalDir() string   { return filepath.Join(c.DataDir, "local") }
func (c *Config) SpoolDir() string   { return filepath.Join(c.DataDir, "spool") }
func (c *Config) StateDB() string    { return filepath.Join(c.DataDir, "state.db") }
func (c *Config) BundleDir() string  { return filepath.Join(c.DataDir, "bundle") }
func (c *Config) CheckDir() string   { return filepath.Join(c.DataDir, "checkpoints") }
func (c *Config) HostIDFile() string { return filepath.Join(c.DataDir, "host_id") }

// On reports a tri-state switch, treating unset as def.
func On(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

// Load reads a YAML config file over the defaults. Unknown keys are errors so
// a typo cannot silently disable a control. A missing file is not an error.
func Load(path, dataDir string) (*Config, error) {
	c := Default(dataDir)
	if path == "" {
		return c, c.Validate()
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return c, c.Validate()
	}
	if err != nil {
		return nil, err
	}
	if len(b) > 1<<20 {
		return nil, fmt.Errorf("config %s: larger than 1 MiB", path)
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil && !errors.Is(err, errEOF(err)) {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	if c.DataDir == "" {
		c.DataDir = dataDir
	}
	return c, c.Validate()
}

// errEOF returns err itself when it is io.EOF (an empty document), so Load
// can treat an empty file as "all defaults".
func errEOF(err error) error {
	if err != nil && err.Error() == "EOF" {
		return err
	}
	return nil
}

// Validate rejects values that would silently weaken the sensor.
func (c *Config) Validate() error {
	switch c.Privacy.Profile {
	case "minimal", "standard", "full":
	default:
		return fmt.Errorf("privacy.profile %q: want minimal, standard or full", c.Privacy.Profile)
	}
	switch c.Guard.Mode {
	case "off", "advisory":
	default:
		return fmt.Errorf("guard.mode %q: want off or advisory", c.Guard.Mode)
	}
	switch c.Guard.MaxResponse {
	case "ask", "block":
	default:
		return fmt.Errorf("guard.max_response %q: want ask or block", c.Guard.MaxResponse)
	}
	switch c.Output.Format {
	case "native", "ocsf":
	default:
		return fmt.Errorf("output.format %q: want native or ocsf", c.Output.Format)
	}
	switch c.Rules.MinClass {
	case "signal", "finding", "alert":
	default:
		return fmt.Errorf("rules.min_class %q: want signal, finding or alert", c.Rules.MinClass)
	}
	if c.Output.MaxLine < 2048 || c.Output.MaxLine > 64<<10 {
		return fmt.Errorf("output.max_line_bytes %d: want 2048..65536 (Fluent Bit's default tail buffer is 32k)", c.Output.MaxLine)
	}
	if c.Privacy.PseudonymizeUsers && c.Privacy.HMACKeyFile == "" {
		return errors.New("privacy.pseudonymize_users needs privacy.hmac_key_file")
	}
	if c.Bundle.URL != "" && len(c.Bundle.PublicKeys) == 0 {
		return errors.New("bundle.url needs at least one bundle.public_keys entry: unsigned content is never loaded")
	}
	if c.Heartbeat.D() < 10*time.Second {
		return errors.New("heartbeat: minimum is 10s")
	}
	for _, a := range c.Sources.Adapters {
		if a.Format != "numbat" {
			return fmt.Errorf("sources.adapters format %q: only numbat is supported", a.Format)
		}
	}
	return nil
}
