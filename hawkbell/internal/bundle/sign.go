package bundle

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// maxSigBytes bounds a signature file: 64 raw bytes, or a hex or base64
// rendering of them with some surrounding whitespace.
const maxSigBytes = 1024

// Sign returns the detached signature for a tarball: Ed25519 over the
// SHA-256 digest of its bytes, 64 raw bytes. The caller publishes it next to
// the archive as <name>.sig. A private key of the wrong length yields nil
// (the function has no error result and must not panic).
//
// Use a key that signs nothing but hawkbell bundles: the signed message is a
// bare 32-byte digest with no domain separation.
func Sign(tarball []byte, priv ed25519.PrivateKey) []byte {
	if len(priv) != ed25519.PrivateKeySize {
		return nil
	}
	digest := sha256.Sum256(tarball)
	return ed25519.Sign(priv, digest[:])
}

// Verify checks the signature against the trusted keys and only then opens
// the archive, validates its structure and compares every file with the
// manifest. The returned Manifest is bound to these exact bytes and is the
// only kind Install accepts.
//
// sig is what Sign produced; a hex or base64 rendering of the same 64 bytes
// is accepted too, for hosts that mangle binary files. Several keys allow
// rotation: add the new key everywhere, start signing with it, then remove
// the old one.
func Verify(tarball, sig []byte, pubs []ed25519.PublicKey) (m *Manifest, err error) {
	defer func() {
		if r := recover(); r != nil {
			m, err = nil, recovered(r)
		}
	}()
	keys := usableKeys(pubs)
	if len(keys) == 0 {
		return nil, ErrNoKeys
	}
	if len(tarball) > MaxBytes {
		return nil, fmt.Errorf("%w: archive is %d bytes, limit %d", ErrTooLarge, len(tarball), MaxBytes)
	}
	raw, ok := decodeSig(sig)
	if !ok {
		return nil, fmt.Errorf("%w: signature is not 64 bytes (raw, hex or base64)", ErrSignature)
	}
	digest := sha256.Sum256(tarball)
	if !verifiedBy(keys, digest[:], raw) {
		return nil, ErrSignature
	}
	m, err = checkArchive(tarball)
	if err != nil {
		return nil, err
	}
	m.sum, m.verified = digest, true
	return m, nil
}

func verifiedBy(keys []ed25519.PublicKey, digest, sig []byte) bool {
	for _, k := range keys {
		if ed25519.Verify(k, digest, sig) {
			return true
		}
	}
	return false
}

// usableKeys drops keys ed25519.Verify would panic on (wrong length) and the
// all-zero placeholder, for which signatures can be forged.
func usableKeys(pubs []ed25519.PublicKey) []ed25519.PublicKey {
	out := make([]ed25519.PublicKey, 0, len(pubs))
	for _, k := range pubs {
		if len(k) == ed25519.PublicKeySize && !allZero(k) {
			out = append(out, k)
		}
	}
	return out
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// decodeSig returns the 64 signature bytes. The three renderings have
// different lengths (64, 128, 86 to 88), so there is no ambiguity between
// them.
func decodeSig(sig []byte) ([]byte, bool) {
	if len(sig) == ed25519.SignatureSize {
		return sig, true
	}
	if len(sig) > maxSigBytes {
		return nil, false
	}
	b, ok := decodeText(strings.TrimSpace(string(sig)), ed25519.SignatureSize)
	return b, ok
}

// decodeText decodes hex or any common base64 alphabet, with or without
// padding, and accepts the result only when it has one of the wanted
// lengths. Hex is tried first, and only at exactly twice a wanted length,
// because a string of hex digits is also valid base64.
func decodeText(s string, sizes ...int) ([]byte, bool) {
	want := func(n int) bool {
		for _, size := range sizes {
			if n == size {
				return true
			}
		}
		return false
	}
	if len(s)%2 == 0 && want(len(s)/2) {
		if b, err := hex.DecodeString(s); err == nil {
			return b, true
		}
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil && want(len(b)) {
			return b, true
		}
	}
	return nil, false
}
