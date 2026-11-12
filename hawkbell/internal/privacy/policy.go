package privacy

import (
	"errors"
	"fmt"
	"path"
	"runtime"
	"strings"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// Profile names what leaves the endpoint.
type Profile string

const (
	// ProfileMinimal (the default) ships detections, inventory, posture,
	// health and session summaries. Activity stays in the local ring and is
	// attached to a detection as redacted context.
	ProfileMinimal Profile = "minimal"
	// ProfileStandard also ships activity, with field-level redaction and
	// no prompt text, tool input or tool output.
	ProfileStandard Profile = "standard"
	// ProfileFull adds prompt text, tool input and the head of tool output,
	// all redacted.
	ProfileFull Profile = "full"
)

// Profiles lists the valid profile names, least to most content.
var Profiles = []Profile{ProfileMinimal, ProfileStandard, ProfileFull}

// ParseProfile validates a configured profile name. "" means minimal.
func ParseProfile(s string) (Profile, error) {
	switch p := Profile(strings.ToLower(strings.TrimSpace(s))); p {
	case "":
		return ProfileMinimal, nil
	case ProfileMinimal, ProfileStandard, ProfileFull:
		return p, nil
	}
	return ProfileMinimal, fmt.Errorf("privacy: unknown profile %q (want minimal, standard or full)", s)
}

// Exclusions are globs for sessions that must not be monitored. Paths match
// the session working directory (and the repository root), Repos the
// repository remote, Users the OS account name or id.
type Exclusions struct{ Paths, Repos, Users []string }

// Policy decides what each record may carry when it leaves the endpoint.
// The zero value is usable: minimal profile, no key, default caps.
type Policy struct {
	Profile Profile
	// Key is the tenant HMAC key. nil (or shorter than MinKeyLen) means no
	// content-derived digest and no pseudonym is emitted at all.
	Key   []byte
	KeyID string
	// PseudonymizeUsers replaces user names and ids with
	// "u_" + hex(HMAC-SHA-256(Key, name))[:16]. Requires Key; without one
	// the names are removed instead.
	PseudonymizeUsers bool
	Exclude           Exclusions
	// MaxLine caps one encoded NDJSON line, newline included (default
	// 16 KiB). Emit leaves LineHeadroom bytes of it for fields the writer
	// sets afterwards.
	MaxLine int
	// MaxField caps any single string field (default 4 KiB), the version
	// labels included; detection evidence values get half of it (2 KiB by
	// default).
	MaxField int
	// HomeOf returns the home directory of an OS account. When nil or when
	// it returns "", the platform convention for the event's OS is used
	// (/home/<u>, /Users/<u>, C:\Users\<u>).
	HomeOf func(user string) string
}

const (
	// DefaultMaxLine stays well under Fluent Bit's 32k default tail buffer.
	DefaultMaxLine = 16 << 10
	// DefaultMaxField is the per-string cap.
	DefaultMaxField = 4 << 10
	// MinMaxLine is the smallest line cap honoured.
	MinMaxLine = 2 << 10
	// MinMaxField is the smallest field cap honoured.
	MinMaxField = 256
	// MinKeyLen is the shortest tenant key used. A shorter key makes every
	// keyed digest brute-forceable, so it is treated as no key.
	MinKeyLen = 16
	// LineHeadroom is reserved under MaxLine for fields a writer sets after
	// Emit (writer id, sequence number, emitted time).
	LineHeadroom = 256
	// DigestMinLen is the shortest value that gets a keyed digest: below it
	// the value space is small enough to enumerate even through a key
	// rotation leak, and the digest adds little.
	DigestMinLen = 32
)

// settings is a Policy with defaults applied, computed per call so that a
// caller may change the Policy between calls.
type settings struct {
	profile  Profile
	key      []byte
	keyID    string
	pseudo   bool
	maxLine  int
	maxField int
	evidCap  int
}

func (p *Policy) settings() settings {
	s := settings{profile: ProfileMinimal, maxLine: DefaultMaxLine, maxField: DefaultMaxField}
	if p == nil {
		s.evidCap = s.maxField / 2
		return s
	}
	if prof, err := ParseProfile(string(p.Profile)); err == nil {
		s.profile = prof
	}
	if len(p.Key) >= MinKeyLen {
		s.key = p.Key
		s.keyID = cleanLabel(p.KeyID, 64)
	}
	s.pseudo = p.PseudonymizeUsers
	if p.MaxLine > 0 {
		s.maxLine = max(p.MaxLine, MinMaxLine)
	}
	if p.MaxField > 0 {
		s.maxField = max(p.MaxField, MinMaxField)
	}
	if s.maxField > s.maxLine/2 {
		s.maxField = s.maxLine / 2
	}
	s.evidCap = s.maxField / 2
	return s
}

// lineBudget is the largest marshalled JSON object (without the newline)
// Emit produces.
func (s settings) lineBudget() int { return s.maxLine - LineHeadroom - 1 }

// Validate reports configuration that cannot work as written. Emit never
// fails on a bad policy: it falls back to the safer behaviour (unknown
// profile -> minimal, short key -> no key, pseudonyms without key -> names
// removed), and Validate is how the operator learns about it.
func (p *Policy) Validate() error {
	if p == nil {
		return nil
	}
	var errs []error
	if _, err := ParseProfile(string(p.Profile)); err != nil {
		errs = append(errs, err)
	}
	if len(p.Key) > 0 && len(p.Key) < MinKeyLen {
		errs = append(errs, fmt.Errorf("privacy: tenant key is %d bytes; at least %d are required, so it is ignored", len(p.Key), MinKeyLen))
	}
	if p.PseudonymizeUsers && len(p.Key) < MinKeyLen {
		errs = append(errs, errors.New("privacy: pseudonymize_users needs a tenant key; user names are removed instead"))
	}
	if p.MaxLine > 0 && p.MaxLine < MinMaxLine {
		errs = append(errs, fmt.Errorf("privacy: max line %d is below the minimum %d", p.MaxLine, MinMaxLine))
	}
	if p.MaxField > 0 && p.MaxField < MinMaxField {
		errs = append(errs, fmt.Errorf("privacy: max field %d is below the minimum %d", p.MaxField, MinMaxField))
	}
	for _, g := range p.Exclude.Paths {
		if err := checkGlob(g); err != nil {
			errs = append(errs, fmt.Errorf("privacy: exclude path %q: %w", g, err))
		}
	}
	for _, g := range p.Exclude.Repos {
		if err := checkGlob(g); err != nil {
			errs = append(errs, fmt.Errorf("privacy: exclude repo %q: %w", g, err))
		}
	}
	for _, g := range p.Exclude.Users {
		if _, err := path.Match(strings.ReplaceAll(strings.ToLower(g), `\`, `\\`), ""); err != nil {
			errs = append(errs, fmt.Errorf("privacy: exclude user %q: %w", g, err))
		}
	}
	return errors.Join(errs...)
}

// eventOS is the OS whose path conventions apply to an event.
func eventOS(e *event.Event) string {
	if e != nil && e.Host != nil {
		switch os := strings.ToLower(e.Host.OS); os {
		case "linux", "darwin", "windows":
			return os
		}
	}
	return runtime.GOOS
}

// actingUser is the account whose home is rewritten to "~".
func actingUser(e *event.Event) string {
	switch {
	case e == nil:
		return ""
	case e.User != nil && e.User.Name != "":
		return e.User.Name
	case e.Process != nil && e.Process.User != "":
		return e.Process.User
	case e.Asset != nil && e.Asset.Owner != "":
		return e.Asset.Owner
	case e.Check != nil && e.Check.Owner != "":
		return e.Check.Owner
	}
	return ""
}

// homeOf resolves an account's home directory, falling back to the OS
// convention. It returns "" when nothing safe can be derived.
func (p *Policy) homeOf(user, goos string) (home string) {
	if user == "" {
		return ""
	}
	if p != nil && p.HomeOf != nil {
		func() {
			defer func() {
				if recover() != nil {
					home = ""
				}
			}()
			home = p.HomeOf(user)
		}()
		if usableHome(home) {
			return home
		}
	}
	name := user
	if i := strings.LastIndexByte(name, '\\'); i >= 0 {
		name = name[i+1:] // DOMAIN\user
	}
	if !plainName(name) {
		return ""
	}
	switch goos {
	case "darwin":
		if name == "root" {
			return "/var/root"
		}
		return "/Users/" + name
	case "windows":
		return `C:\Users\` + name
	default:
		if name == "root" {
			return "/root"
		}
		return "/home/" + name
	}
}

// usableHome rejects homes that would rewrite unrelated paths ("/", "",
// relative paths).
func usableHome(h string) bool {
	h = strings.TrimRight(strings.ReplaceAll(h, `\`, "/"), "/")
	if len(h) < 2 || len(h) > 512 {
		return false
	}
	if h[0] == '/' {
		return strings.Count(h, "/") >= 1 && h != "/"
	}
	return len(h) >= 4 && h[1] == ':' && h[2] == '/'
}

// plainName accepts account names that can be a path component.
func plainName(n string) bool {
	if n == "" || len(n) > 64 || n == "." || n == ".." {
		return false
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		if c < 0x20 || c == 0x7f || strings.IndexByte(`/\:*?"<>|`, c) >= 0 {
			return false
		}
	}
	return true
}
