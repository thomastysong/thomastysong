package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	manifestName     = "manifest.json"
	maxManifestBytes = 1 << 20
	maxNoteBytes     = 1024
)

// Manifest describes one bundle. It travels inside the archive as
// manifest.json, so the detached signature covers it together with the
// content it lists.
type Manifest struct {
	// Version orders bundles. A host only ever moves to a higher one, so
	// publishers must never reuse or lower it. Zero is not a valid version.
	Version uint64 `json:"version"`
	// Created is when the bundle was built (UTC, whole seconds).
	Created time.Time `json:"created"`
	// Files maps each content path (relative, slash-separated) to the
	// lower-case hex SHA-256 of its bytes. manifest.json is not listed.
	Files map[string]string `json:"files"`
	// Note is free text from the publisher, at most 1024 bytes.
	Note string `json:"note,omitempty"`

	// sum and verified tie a manifest returned by Verify to the exact bytes
	// whose signature was checked. Install compares them with the tarball it
	// is given, so content that never passed Verify cannot be installed by
	// handing Install a hand-built manifest. Unexported fields are not part
	// of the JSON form.
	sum      [sha256.Size]byte
	verified bool
}

// Paths returns the content paths in sorted order. Loaders should iterate
// this list (and read with ReadFile) instead of globbing the directory.
func (m *Manifest) Paths() []string {
	if m == nil {
		return nil
	}
	out := make([]string, 0, len(m.Files))
	for p := range m.Files {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// Equal reports whether two manifests describe the same bundle: same
// version, creation time, note and file hashes.
func (m *Manifest) Equal(o *Manifest) bool {
	if m == nil || o == nil {
		return m == o
	}
	if m.Version != o.Version || !m.Created.Equal(o.Created) || m.Note != o.Note || len(m.Files) != len(o.Files) {
		return false
	}
	for p, sum := range m.Files {
		if other, ok := o.Files[p]; !ok || other != sum {
			return false
		}
	}
	return true
}

// Digest identifies the bundle content: the hex SHA-256 of the manifest's
// canonical JSON form. Two bundles with the same digest carry the same
// version and the same bytes in every file, however the archive was packed.
func (m *Manifest) Digest() string {
	if m == nil {
		return ""
	}
	b, err := m.clone().encode()
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// clone copies the exported content only, so the copy is never accepted by
// Install and callers cannot reach the original through the map.
func (m *Manifest) clone() *Manifest {
	c := &Manifest{Version: m.Version, Created: m.Created.UTC(), Note: m.Note, Files: make(map[string]string, len(m.Files))}
	for p, sum := range m.Files {
		c.Files[p] = sum
	}
	return c
}

// encode is the canonical form written into archives: encoding/json sorts
// map keys, so the same manifest always yields the same bytes.
func (m *Manifest) encode() ([]byte, error) {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrManifest, err)
	}
	return append(b, '\n'), nil
}

// parseManifest decodes and validates manifest.json. Unknown fields are
// ignored so that a newer publisher can add fields without locking older
// sensors out of content updates.
func parseManifest(b []byte) (*Manifest, error) {
	if len(b) > maxManifestBytes {
		return nil, fmt.Errorf("%w: %s is larger than %d bytes", ErrManifest, manifestName, maxManifestBytes)
	}
	if !utf8.Valid(b) {
		return nil, fmt.Errorf("%w: %s is not valid UTF-8", ErrManifest, manifestName)
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrManifest, err)
	}
	if m.Files == nil {
		m.Files = map[string]string{}
	}
	m.Created = m.Created.UTC()
	if err := m.validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

func (m *Manifest) validate() error {
	if m.Version == 0 {
		return fmt.Errorf("%w: version must be at least 1", ErrManifest)
	}
	// The tar header stores the time as seconds since 1970, and JSON cannot
	// carry years beyond 9999.
	if y := m.Created.UTC().Year(); m.Created.IsZero() || y < 1970 || y > 9999 {
		return fmt.Errorf("%w: created time is missing or out of range", ErrManifest)
	}
	if len(m.Note) > maxNoteBytes {
		return fmt.Errorf("%w: note is longer than %d bytes", ErrManifest, maxNoteBytes)
	}
	if !plainText(m.Note) {
		// The note ends up in terminals and health records.
		return fmt.Errorf("%w: note contains control characters or invalid UTF-8", ErrManifest)
	}
	// manifest.json itself counts towards MaxFiles.
	if len(m.Files) > MaxFiles-1 {
		return fmt.Errorf("%w: manifest lists %d files, limit %d", ErrTooLarge, len(m.Files), MaxFiles-1)
	}
	folded := make(map[string]struct{}, len(m.Files))
	for _, p := range m.Paths() {
		if err := checkName(p); err != nil {
			return err
		}
		if !isHexSum(m.Files[p]) {
			return fmt.Errorf("%w: %s: hash is not 64 lower-case hex digits", ErrManifest, quote(p))
		}
		k := strings.ToLower(p)
		if _, dup := folded[k]; dup {
			return fmt.Errorf("%w: %s collides with another name on a case-insensitive filesystem", ErrManifest, quote(p))
		}
		folded[k] = struct{}{}
	}
	return nil
}

// matches checks the hashes computed from an archive (or a directory)
// against the manifest in both directions: nothing unlisted, nothing missing.
func (m *Manifest) matches(sums map[string]string) error {
	for _, p := range m.Paths() {
		got, ok := sums[p]
		if !ok {
			return fmt.Errorf("%w: %s is listed in the manifest but missing", ErrMismatch, quote(p))
		}
		if got != m.Files[p] {
			return fmt.Errorf("%w: %s has a different SHA-256 than the manifest lists", ErrMismatch, quote(p))
		}
	}
	if len(sums) != len(m.Files) {
		extra := make([]string, 0, len(sums))
		for p := range sums {
			if _, ok := m.Files[p]; !ok {
				extra = append(extra, p)
			}
		}
		sort.Strings(extra)
		return fmt.Errorf("%w: %s is not listed in the manifest", ErrMismatch, quote(extra[0]))
	}
	return nil
}

func isHexSum(s string) bool {
	if len(s) != hex.EncodedLen(sha256.Size) {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// plainText accepts valid UTF-8 without C0/C1 control characters other than
// tab and newline.
func plainText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r == '\t' || r == '\n' {
			continue
		}
		if r < 0x20 || (r >= 0x7f && r < 0xa0) {
			return false
		}
	}
	return true
}
