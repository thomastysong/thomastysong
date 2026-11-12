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

// loadConfig reads the configuration, falling back to the built-in defaults
// (observe mode) when the file cannot be used. A broken config must not
// break every tool call of every developer; the error is reported on the
// records instead.
func loadConfig(path string) (cfg *config.Config, err error) {
	dataDir := platform.DefaultDirs().Data
	defer func() {
		if r := recover(); r != nil {
			cfg, err = config.Default(dataDir), fmt.Errorf("config: internal error: %T", r)
		}
	}()
	c, err := config.Load(path, dataDir)
	if err != nil || c == nil {
		if err == nil {
			err = errors.New("config: no configuration")
		}
		return config.Default(dataDir), err
	}
	return c, nil
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
