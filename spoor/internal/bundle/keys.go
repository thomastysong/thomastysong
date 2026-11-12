package bundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
)

// maxKeyText bounds a key string before any decoding. A PEM-wrapped Ed25519
// key is under 200 bytes.
const maxKeyText = 4096

// spkiPrefix is the fixed DER header of an Ed25519 SubjectPublicKeyInfo
// (RFC 8410); the 32 key bytes follow it. It lets a config carry the
// base64 body of a PEM file without the armour lines.
var spkiPrefix = []byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}

// GenerateKey creates a signing key pair from the system's secure random
// source.
func GenerateKey() (pub ed25519.PublicKey, priv ed25519.PrivateKey, err error) {
	return ed25519.GenerateKey(rand.Reader)
}

// ParsePublicKey reads an Ed25519 public key written as base64 (standard or
// URL alphabet, padded or not) or hex of the 32 key bytes. It also accepts
// what OpenSSL produces: a PEM "PUBLIC KEY" block or the base64 of its DER
// body. An optional "ed25519:" prefix is ignored.
func ParsePublicKey(s string) (pub ed25519.PublicKey, err error) {
	defer func() {
		if r := recover(); r != nil {
			pub, err = nil, recovered(r)
		}
	}()
	s, err = keyText(s)
	if err != nil {
		return nil, err
	}
	var raw []byte
	if strings.HasPrefix(s, "-----BEGIN") {
		block, _ := pem.Decode([]byte(s))
		if block == nil || block.Type != "PUBLIC KEY" {
			return nil, fmt.Errorf("%w: want a PEM block of type PUBLIC KEY", ErrKey)
		}
		raw = block.Bytes
	} else {
		var ok bool
		raw, ok = decodeText(s, ed25519.PublicKeySize, len(spkiPrefix)+ed25519.PublicKeySize)
		if !ok {
			return nil, fmt.Errorf("%w: want 32 bytes as base64 or hex", ErrKey)
		}
	}
	if len(raw) == len(spkiPrefix)+ed25519.PublicKeySize {
		if !bytes.HasPrefix(raw, spkiPrefix) {
			return nil, fmt.Errorf("%w: not an Ed25519 public key", ErrKey)
		}
		raw = raw[len(spkiPrefix):]
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: not an Ed25519 public key", ErrKey)
	}
	if allZero(raw) {
		// A placeholder left in a config would otherwise become a key
		// whose signatures anyone can forge.
		return nil, fmt.Errorf("%w: the all-zero key is not a valid public key", ErrKey)
	}
	return ed25519.PublicKey(append([]byte(nil), raw...)), nil
}

// EncodePublicKey renders a public key as standard base64, the form
// ParsePublicKey reads back and the configuration file carries.
func EncodePublicKey(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub)
}

// ParsePrivateKey reads a signing key written by EncodePrivateKey (base64
// of the 32-byte seed). It also accepts hex, the 64-byte seed-plus-public
// form, and an unencrypted PKCS #8 PEM block as written by
// `openssl genpkey -algorithm ed25519`. Errors never echo the input.
func ParsePrivateKey(s string) (priv ed25519.PrivateKey, err error) {
	defer func() {
		if r := recover(); r != nil {
			priv, err = nil, recovered(r)
		}
	}()
	s, err = keyText(s)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(s, "-----BEGIN") {
		block, _ := pem.Decode([]byte(s))
		if block == nil || block.Type != "PRIVATE KEY" {
			return nil, fmt.Errorf("%w: want an unencrypted PEM block of type PRIVATE KEY", ErrKey)
		}
		k, perr := x509.ParsePKCS8PrivateKey(block.Bytes)
		if perr != nil {
			return nil, fmt.Errorf("%w: not a PKCS #8 private key", ErrKey)
		}
		ek, ok := k.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: not an Ed25519 private key", ErrKey)
		}
		return ek, nil
	}
	raw, ok := decodeText(s, ed25519.SeedSize, ed25519.PrivateKeySize)
	if !ok {
		return nil, fmt.Errorf("%w: want a 32-byte seed as base64 or hex", ErrKey)
	}
	priv = ed25519.NewKeyFromSeed(raw[:ed25519.SeedSize])
	if len(raw) == ed25519.PrivateKeySize && !bytes.Equal(priv, raw) {
		// The second half of the long form is the public key; if it does
		// not belong to the seed the text is damaged or not a key at all.
		return nil, fmt.Errorf("%w: seed and public halves do not match", ErrKey)
	}
	return priv, nil
}

// EncodePrivateKey renders the 32-byte seed of a signing key as standard
// base64. It returns "" for a key of the wrong length.
func EncodePrivateKey(priv ed25519.PrivateKey) string {
	if len(priv) != ed25519.PrivateKeySize {
		return ""
	}
	return base64.StdEncoding.EncodeToString(priv.Seed())
}

// KeyID is a short public identifier for a key (the first 16 hex digits of
// the SHA-256 of the public key), for logs and for telling keys apart during
// a rotation. It returns "" for a key of the wrong length.
func KeyID(pub ed25519.PublicKey) string {
	if len(pub) != ed25519.PublicKeySize {
		return ""
	}
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// keyText trims a key string and strips the optional algorithm prefix.
func keyText(s string) (string, error) {
	if len(s) > maxKeyText {
		return "", fmt.Errorf("%w: longer than %d bytes", ErrKey, maxKeyText)
	}
	s = strings.TrimSpace(s)
	if len(s) >= 8 && strings.EqualFold(s[:8], "ed25519:") {
		s = strings.TrimSpace(s[8:])
	}
	if s == "" {
		return "", fmt.Errorf("%w: empty", ErrKey)
	}
	return s, nil
}
