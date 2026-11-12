package engine

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/catalog"
	"github.com/thomastysong/thomastysong/hawkbell/internal/config"
	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
	"github.com/thomastysong/thomastysong/hawkbell/internal/platform"
	"github.com/thomastysong/thomastysong/hawkbell/internal/privacy"
	"github.com/thomastysong/thomastysong/hawkbell/internal/rules"
	"github.com/thomastysong/thomastysong/hawkbell/internal/sink"
	"github.com/thomastysong/thomastysong/hawkbell/internal/state"
)

// Modes.
const (
	ModeDaemon = "daemon"
	ModeScan   = "scan"
	ModeDetect = "detect"
	ModeHook   = "hook"
)

// Timing and size constants. They trace to design/BUILD-C.md section C2
// (items 3, 4, 7 and 10, and the bounded ingest queue of its API) and its
// addendum (late events), and to design/DECISIONS.md A6 (root-observed
// surfaces), A21 (session summaries) and A22 (one activity record per
// action).
const (
	// HoldFor is how long a transcript or OTel tool event waits for the hook
	// record of the same call before it is processed as the activity record
	// itself. The hook is the primary surface; the wait keeps one record per
	// action while still keeping coverage when hooks are absent.
	HoldFor = 10 * time.Second
	// LateAfter: a record written more than this after its ts gets Emitted.
	LateAfter = time.Minute
	// SummaryEvery is the period of the rolling (Final=false) session summary.
	SummaryEvery = 15 * time.Minute
	// SessionIdle ends a session that has been silent this long.
	SessionIdle = 15 * time.Minute
	// BlindAfter: a root-observed agent with no hook and no transcript
	// activity for this long is blind.
	BlindAfter = 60 * time.Second
	// BypassMinUnmatched is how many tool calls seen on another surface
	// without a hook record make a session a hook-bypass candidate.
	BypassMinUnmatched = 3
	// DefaultQueueSize bounds the daemon's ingest queue (events).
	DefaultQueueSize = 16384
	// BaselineKeys is the size of the first-seen baseline.
	BaselineKeys = 20000
	// BaselineFile is the baseline's file name under the checkpoint dir.
	// The name is kept across format versions (the header carries the
	// version), so the first save after an upgrade overwrites a file in
	// an older format.
	BaselineFile = "baseline.v1"
)

const (
	maxSessions    = 4096    // live sessions kept in memory
	maxExcluded    = 4096    // remembered excluded session keys
	maxCorrelation = 1 << 17 // correlation keys remembered
	corrTTL        = 30 * time.Minute
	maxHeld        = 8192
	maxCoverage    = 2000
	// maxCoveragePerUser bounds one account's coverage entries, so one
	// account's records cannot evict another's.
	maxCoveragePerUser = 64
	maxProcs           = 4096
	coverageWindow     = 24 * time.Hour
	hookStaleAfter     = 10 * time.Minute
	baselineSaveGap    = time.Minute
	disabledTTL        = time.Second
	localSuffix        = ".local"
)

// Options configures a Pipeline. Fields marked additive are not part of the
// API in design/BUILD-C.md section C2; the daemon may leave them zero.
type Options struct {
	Config  *config.Config   // nil: config.Default("")
	Catalog *catalog.Catalog // catalog version and hook capability; may be nil
	Rules   *rules.Set       // nil: rules.LoadEmbedded()
	Policy  *privacy.Policy  // nil: PolicyFromConfig(Config)
	Outbox  sink.Sink        // shipped records (root-owned segments or stdout); required
	Local   sink.Sink        // local ring for records that must not leave the host (may be nil)
	State   *state.Store     // may be nil (hook/detect/CI modes)
	// Host is stamped on every record when Host.ID or Host.Name is set. Leave
	// it zero for central re-evaluation of other hosts' events (`hawkbell detect`).
	Host      event.Host
	Mode      string          // daemon | scan | detect | hook (default daemon)
	Integrity event.Integrity // default: root when privileged, else user
	Now       func() time.Time
	// Hooked is discovery's view of hook state for an agent and OS account:
	// managed|user|missing|modified|shadowed|unsupported. user is the account
	// name when the event has one, else its uid/SID.
	Hooked func(agentID, user string) string
	// RootSaw reports whether the process monitor (root-observed) currently
	// sees that agent running for that account.
	RootSaw func(agentID, user string) bool

	// SensorVersion goes into heartbeats (additive; default "dev").
	SensorVersion string
	// BundleVersion is the installed content bundle, stamped on findings and
	// heartbeats (additive; SetRules updates it).
	BundleVersion string
	// HostIDSource is platform.HostIDSource() or "config", copied into the
	// heartbeat for the state DB (additive).
	HostIDSource string
	// QueueSize bounds the daemon ingest queue (additive; default 16384).
	QueueSize int
	// Disabled is the kill switch (additive; default platform.Disabled).
	Disabled func() bool
	// Surfaces returns collector status (schema drift, errors) that the
	// engine cannot see from events; merged into the heartbeat (additive).
	// It is called with the pipeline locked and must not call back into it.
	Surfaces func() []event.SurfaceStatus
	// Gauges returns extra heartbeat counters such as shipper_lag_bytes
	// (additive). Same locking rule as Surfaces.
	Gauges func() map[string]uint64
	// HomeOf returns the home directory of an account (uid or name may be
	// empty). Default: the platform account list, cached (additive).
	HomeOf func(uid, name string) string
	// IdentityKey keys every identifier derived from content (the prompt
	// digest that pairs a hook prompt with its transcript twin, the digest
	// that names a record which came without an id) and every key the
	// first-seen baseline stores, so Dedupe, ID and the baseline file never
	// let a reader test a guess about a prompt, a redacted secret or a
	// host. Empty in daemon mode with a data directory: New loads the key
	// kept at IdentityKeyPath, creating it on first start
	// (LoadOrCreateIdentityKey), so identities and the baseline hold
	// across restarts; a key file that cannot be used is reported
	// (heartbeat identity.key_errors) and the per-process key is used.
	// Empty otherwise (scan, detect, hook modes): a random key drawn once
	// per process, so identities hold for this run only. At least
	// MinIdentityKeyLen bytes when set (additive).
	IdentityKey []byte
}

// PolicyFromConfig builds the privacy policy the configuration describes:
// profile, exclusions, pseudonyms, line cap (output.max_line_bytes) and the
// tenant HMAC key from privacy.hmac_key_file. A configured key file that
// cannot be read, is shorter than privacy.MinKeyLen, or is accessible to
// group or others is an error: the operator asked for keyed digests, and
// silently emitting none (or using a key other users can read) is not what
// they asked for.
func PolicyFromConfig(cfg *config.Config) (*privacy.Policy, error) {
	if cfg == nil {
		cfg = config.Default("")
	}
	prof, err := privacy.ParseProfile(cfg.Privacy.Profile)
	if err != nil {
		return nil, err
	}
	p := &privacy.Policy{
		Profile:           prof,
		KeyID:             cfg.Privacy.KeyID,
		PseudonymizeUsers: cfg.Privacy.PseudonymizeUsers,
		Exclude: privacy.Exclusions{
			Paths: append([]string(nil), cfg.Privacy.Exclude.Paths...),
			Repos: append([]string(nil), cfg.Privacy.Exclude.Repos...),
			Users: append([]string(nil), cfg.Privacy.Exclude.Users...),
		},
		MaxLine: cfg.Output.MaxLine,
	}
	if f := cfg.Privacy.HMACKeyFile; f != "" {
		key, err := ReadKeyFile(f)
		if err != nil {
			return nil, err
		}
		p.Key = key
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return p, nil
}

const maxKeyFile = 4096

// ReadKeyFile reads a tenant HMAC key: no symlinks, a regular file of at
// most 4 KiB, not accessible to group or others on POSIX systems, at least
// privacy.MinKeyLen bytes after trailing white space is trimmed.
func ReadKeyFile(path string) ([]byte, error) {
	f, err := platform.OpenNoFollow(path)
	if err != nil {
		return nil, fmt.Errorf("privacy.hmac_key_file: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("privacy.hmac_key_file: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("privacy.hmac_key_file %s: not a regular file", path)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("privacy.hmac_key_file %s: mode %04o lets group or others read it; chmod 600", path, fi.Mode().Perm())
	}
	b, err := io.ReadAll(io.LimitReader(f, maxKeyFile+1))
	if err != nil {
		return nil, fmt.Errorf("privacy.hmac_key_file: %w", err)
	}
	if len(b) > maxKeyFile {
		return nil, fmt.Errorf("privacy.hmac_key_file %s: larger than %d bytes", path, maxKeyFile)
	}
	b = bytes.TrimRight(b, " \t\r\n")
	if len(b) < privacy.MinKeyLen {
		return nil, fmt.Errorf("privacy.hmac_key_file %s: key is %d bytes, at least %d required", path, len(b), privacy.MinKeyLen)
	}
	return b, nil
}

// suppressions converts the operator suppressions of the configuration.
func suppressions(in []config.Suppression) ([]rules.Suppression, error) {
	out := make([]rules.Suppression, 0, len(in))
	for i, s := range in {
		if strings.TrimSpace(s.Rule) == "" {
			return nil, fmt.Errorf("rules.suppressions[%d]: rule is required", i)
		}
		r := rules.Suppression{RuleID: s.Rule, Reason: s.Reason, Tags: append([]string(nil), s.Tags...)}
		if len(s.Match) > 0 {
			r.Match = make(map[string]string, len(s.Match))
			for k, v := range s.Match {
				r.Match[k] = v
			}
		}
		if s.Expires != "" {
			// A bare date lasts through the end of that day (UTC), as in a
			// bundle's suppressions.yaml.
			t, err := rules.ParseExpiry(s.Expires)
			if err != nil {
				return nil, fmt.Errorf("rules.suppressions[%d].expires: %w", i, err)
			}
			r.Expires = t
		}
		out = append(out, r)
	}
	return out, nil
}

// ruleSet returns the set the engine runs: the caller's set, or a copy of
// it with the configured rules disabled (Disable mutates, and the set
// belongs to the caller).
func ruleSet(s *rules.Set, disable []string) (*rules.Set, error) {
	if s == nil {
		var err error
		if s, err = rules.LoadEmbedded(); err != nil {
			return nil, fmt.Errorf("engine: embedded rules: %w", err)
		}
		if len(disable) > 0 {
			s.Disable(disable...)
		}
		return s, nil
	}
	if len(disable) == 0 {
		return s, nil
	}
	c, err := rules.Load(map[string][]byte{})
	if err != nil {
		return nil, fmt.Errorf("engine: copy rules: %w", err)
	}
	c.Merge(s)
	c.Disable(disable...)
	return c, nil
}

func validMode(m string) bool {
	switch m {
	case ModeDaemon, ModeScan, ModeDetect, ModeHook:
		return true
	}
	return false
}

func validClass(c string) bool {
	switch c {
	case event.ClassSignal, event.ClassFinding, event.ClassAlert:
		return true
	}
	return false
}

// baselinePath is where the daemon keeps the first-seen baseline.
func baselinePath(cfg *config.Config, mode string) string {
	if mode != ModeDaemon || cfg.DataDir == "" {
		return ""
	}
	return filepath.Join(cfg.CheckDir(), BaselineFile)
}

var errNoOutbox = errors.New("engine: Options.Outbox is required")

// defaultDisabled is the platform kill switch.
func defaultDisabled() bool { return platform.Disabled() }
