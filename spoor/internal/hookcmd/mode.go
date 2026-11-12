package hookcmd

import (
	"errors"
	"fmt"
	"time"

	"github.com/thomastysong/spoor/internal/config"
	"github.com/thomastysong/spoor/internal/hookio"
	"github.com/thomastysong/spoor/internal/platform"
)

// mode is what one hook invocation does, derived from the configuration.
type mode struct {
	enabled bool // sources.hooks.enabled
	guard   bool // guard.mode advisory: answer the agent from the guard rules
	detect  bool // sources.hooks.detect_in_hook: full rule set, detections spooled
}

func modeOf(cfg *config.Config) mode {
	return mode{
		enabled: config.On(cfg.Sources.Hooks.Enabled, true),
		guard:   cfg.Guard.Mode == "advisory",
		detect:  cfg.Sources.Hooks.DetectInHook,
	}
}

// rules reports whether any rule is loaded. Observe mode loads none.
func (m mode) rules() bool { return m.guard || m.detect }

func (m mode) String() string {
	switch {
	case m.guard && m.detect:
		return "guard_detect"
	case m.guard:
		return "guard"
	case m.detect:
		return "detect"
	}
	return "observe"
}

// loadConfig reads the configuration. A file that cannot be read or
// parsed falls back to the built-in defaults (observe mode): a broken
// config must not break every tool call of every developer, and the error
// is reported on the records instead (label hook_config=invalid).
//
// A file that parses but fails validation is NOT replaced by defaults:
// config.Load returns the decoded configuration with the error, and one bad
// value (often a daemon-only setting such as heartbeat, which the hook
// never reads) must not silently drop guard mode, rules.dirs,
// rules.disable, privacy exclusions or sources.hooks.enabled: false. Only
// the invalid values the hook reads are repaired (repairForHook).
func loadConfig(path string) (cfg *config.Config, err error) {
	dataDir := platform.DefaultDirs().Data
	defer func() {
		if r := recover(); r != nil {
			cfg, err = config.Default(dataDir), fmt.Errorf("config: internal error: %T", r)
		}
	}()
	c, err := config.Load(path, dataDir)
	if c == nil {
		if err == nil {
			err = errors.New("config: no configuration")
		}
		return config.Default(dataDir), err
	}
	if err != nil {
		repairForHook(c, config.Default(dataDir))
	}
	return c, err
}

// repairForHook replaces the invalid values among those the hook reads,
// each in the direction that does not weaken the sensor: an unknown
// privacy profile becomes minimal, an unknown guard.mode other than empty
// becomes advisory (the operator configured the guard; an enforcing hook
// must not turn into observe mode on a typo), the rest take their
// defaults. Values the hook does not read are left alone.
func repairForHook(c, def *config.Config) {
	switch c.Privacy.Profile {
	case "minimal", "standard", "full":
	default:
		c.Privacy.Profile = def.Privacy.Profile
	}
	switch c.Guard.Mode {
	case "off", "advisory":
	case "":
		c.Guard.Mode = def.Guard.Mode
	default:
		c.Guard.Mode = "advisory"
	}
	switch c.Guard.MaxResponse {
	case "ask", "block":
	default:
		c.Guard.MaxResponse = def.Guard.MaxResponse
	}
	switch c.Rules.MinClass {
	case "signal", "finding", "alert":
	default:
		c.Rules.MinClass = def.Rules.MinClass
	}
	if c.Output.MaxLine < 8<<10 || c.Output.MaxLine > 64<<10 {
		c.Output.MaxLine = def.Output.MaxLine
	}
	if c.DataDir == "" {
		c.DataDir = def.DataDir
	}
}

// hardDeadline is how long the supervisor waits for its worker, measured
// from when the supervisor started. In guard mode it is guard.deadline (at
// least MinGuardDeadline): the operator's knob bounds the whole decision the
// developer waits for, and an expired deadline answers "ask". Otherwise
// nothing depends on the answer and ObserveDeadline applies.
func hardDeadline(cfg *config.Config, m mode) time.Duration {
	if !m.guard {
		return observeDeadline
	}
	d := cfg.Guard.Deadline.D()
	if d < MinGuardDeadline {
		d = MinGuardDeadline
	}
	// guard.deadline is an evaluation budget, not a way to hold an agent
	// for minutes; the shortest agent hook timeouts are 30 s.
	if d > maxGuardDeadline {
		d = maxGuardDeadline
	}
	return d
}

// inputCap is limits.max_hook_input_bytes clamped to what hookio can parse.
// At exactly hookio.MaxInput the hookio salvage of oversized payloads
// applies; a smaller cap reports oversized payloads as anomalies only.
func inputCap(cfg *config.Config) int {
	n := cfg.Limits.MaxHookInput
	switch {
	case n <= 0 || n > hookio.MaxInput:
		return hookio.MaxInput
	case n < minInputCap:
		return minInputCap
	}
	return n
}
