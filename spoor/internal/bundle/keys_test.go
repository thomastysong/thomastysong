package bundle

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
)

func pemBlock(t *testing.T, typ string, der []byte) string {
	t.Helper()
	return string(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}))
}

func TestGenerateKey(t *testing.T) {
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub2, _, _ := GenerateKey()
	if len(pub) != ed25519.PublicKeySize || len(priv) != ed25519.PrivateKeySize || bytes.Equal(pub, pub2) {
		t.Fatalf("GenerateKey returned a %d/%d byte pair (or repeated a key)", len(pub), len(priv))
	}
	// A freshly generated pair works end to end, through its text forms.
	parsedPub, err := ParsePublicKey(EncodePublicKey(pub))
	if err != nil {
		t.Fatal(err)
	}
	parsedPriv, err := ParsePrivateKey(EncodePrivateKey(priv))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := Create(writeTree(t, sampleFiles("k")), 1, parsedPriv, &buf); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(buf.Bytes(), Sign(buf.Bytes(), parsedPriv), []ed25519.PublicKey{parsedPub}); err != nil {
		t.Fatalf("Verify with a generated key: %v", err)
	}
	if _, err := Verify(buf.Bytes(), Sign(buf.Bytes(), parsedPriv), trusted()); !errors.Is(err, ErrSignature) {
		t.Fatalf("a generated key verified against another key: %v", err)
	}
}

func TestParsePublicKey(t *testing.T) {
	spki, err := x509.MarshalPKIXPublicKey(testPub)
	if err != nil {
		t.Fatal(err)
	}
	good := map[string]string{
		"base64 std":             base64.StdEncoding.EncodeToString(testPub),
		"base64 std, no padding": base64.RawStdEncoding.EncodeToString(testPub),
		"base64 url":             base64.URLEncoding.EncodeToString(testPub),
		"base64 url, no padding": base64.RawURLEncoding.EncodeToString(testPub),
		"hex":                    hex.EncodeToString(testPub),
		"hex upper":              strings.ToUpper(hex.EncodeToString(testPub)),
		"surrounding whitespace": "  \t" + base64.StdEncoding.EncodeToString(testPub) + "\r\n",
		"algorithm prefix":       "ed25519:" + base64.StdEncoding.EncodeToString(testPub),
		"prefix, case and space": "ED25519: " + hex.EncodeToString(testPub),
		"PEM":                    pemBlock(t, "PUBLIC KEY", spki),
		"PEM with indentation":   "\n  " + strings.TrimSpace(pemBlock(t, "PUBLIC KEY", spki)) + "\n",
		"base64 of the DER body": base64.StdEncoding.EncodeToString(spki),
		"hex of the DER body":    hex.EncodeToString(spki),
		"EncodePublicKey":        EncodePublicKey(testPub),
	}
	for name, s := range good {
		t.Run(name, func(t *testing.T) {
			pub, err := ParsePublicKey(s)
			if err != nil || !bytes.Equal(pub, testPub) {
				t.Fatalf("ParsePublicKey(%q) = %x, %v", s, pub, err)
			}
		})
	}

	// Every byte value survives, in every text form: there is no key whose
	// base64 or hex rendering is misread as the other encoding.
	for i := 0; i < 200; i++ {
		raw := make([]byte, ed25519.PublicKeySize)
		rand.Read(raw)
		if i < 16 {
			for j := range raw { // strings made only of hex digits when base64-encoded are the risky ones
				raw[j] = byte(i*17 + j)
			}
		}
		for _, s := range []string{
			hex.EncodeToString(raw), base64.StdEncoding.EncodeToString(raw), base64.RawStdEncoding.EncodeToString(raw),
			base64.URLEncoding.EncodeToString(raw), base64.RawURLEncoding.EncodeToString(raw),
		} {
			if pub, err := ParsePublicKey(s); err != nil || !bytes.Equal(pub, raw) {
				t.Fatalf("round trip of %x through %q = %x, %v", raw, s, pub, err)
			}
		}
	}

	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecSPKI, _ := x509.MarshalPKIXPublicKey(&ec.PublicKey)
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(testPriv)
	wrongOID := append([]byte(nil), spki...)
	wrongOID[8] ^= 0x01
	bad := map[string]string{
		"empty":                    "",
		"whitespace":               "  \n\t ",
		"prefix only":              "ed25519:",
		"words":                    "not a key at all",
		"31 bytes hex":             hex.EncodeToString(testPub[:31]),
		"33 bytes hex":             hex.EncodeToString(append(append([]byte(nil), testPub...), 1)),
		"31 bytes base64":          base64.StdEncoding.EncodeToString(testPub[:31]),
		"64 bytes base64":          base64.StdEncoding.EncodeToString(testPriv),
		"odd hex":                  hex.EncodeToString(testPub)[:63],
		"hex with a bad digit":     "zz" + hex.EncodeToString(testPub)[2:],
		"all zero hex":             strings.Repeat("0", 64),
		"all zero base64":          base64.StdEncoding.EncodeToString(make([]byte, 32)),
		"all zero PEM":             pemBlock(t, "PUBLIC KEY", append(append([]byte(nil), spkiPrefix...), make([]byte, 32)...)),
		"ECDSA PEM":                pemBlock(t, "PUBLIC KEY", ecSPKI),
		"private key PEM":          pemBlock(t, "PRIVATE KEY", pkcs8),
		"PEM with the wrong label": pemBlock(t, "CERTIFICATE", spki),
		"PEM with a damaged body":  "-----BEGIN PUBLIC KEY-----\n!!!!\n-----END PUBLIC KEY-----",
		"unterminated PEM":         "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA",
		"DER with another OID":     base64.StdEncoding.EncodeToString(wrongOID),
		"invalid UTF-8":            "\xff\xfe\xfd",
		"NUL bytes":                string(make([]byte, 44)),
		"huge":                     strings.Repeat("A", 1<<20),
		"two keys":                 base64.StdEncoding.EncodeToString(testPub) + "," + base64.StdEncoding.EncodeToString(otherPub),
	}
	for name, s := range bad {
		t.Run("bad/"+name, func(t *testing.T) {
			pub, err := ParsePublicKey(s)
			if !errors.Is(err, ErrKey) || pub != nil {
				t.Fatalf("ParsePublicKey = %x, %v; want ErrKey", pub, err)
			}
			if len(err.Error()) > 200 {
				t.Errorf("error is %d bytes long", len(err.Error()))
			}
		})
	}
}

func TestParsePrivateKey(t *testing.T) {
	pkcs8, err := x509.MarshalPKCS8PrivateKey(testPriv)
	if err != nil {
		t.Fatal(err)
	}
	good := map[string]string{
		"EncodePrivateKey":   EncodePrivateKey(testPriv),
		"seed base64":        base64.StdEncoding.EncodeToString(testPriv.Seed()),
		"seed raw url":       base64.RawURLEncoding.EncodeToString(testPriv.Seed()),
		"seed hex":           hex.EncodeToString(testPriv.Seed()),
		"full key base64":    base64.StdEncoding.EncodeToString(testPriv),
		"full key hex":       hex.EncodeToString(testPriv),
		"PKCS #8 PEM":        pemBlock(t, "PRIVATE KEY", pkcs8),
		"with prefix and nl": "ed25519:" + EncodePrivateKey(testPriv) + "\n",
	}
	for name, s := range good {
		t.Run(name, func(t *testing.T) {
			priv, err := ParsePrivateKey(s)
			if err != nil || !bytes.Equal(priv, testPriv) {
				t.Fatalf("ParsePrivateKey = %v (%d bytes)", err, len(priv))
			}
		})
	}

	mismatched := append(append([]byte(nil), testPriv.Seed()...), otherPub...)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecPKCS8, _ := x509.MarshalPKCS8PrivateKey(ec)
	spki, _ := x509.MarshalPKIXPublicKey(testPub)
	bad := map[string]string{
		"empty":                "",
		"too short":            base64.StdEncoding.EncodeToString(testPriv.Seed()[:31]),
		"48 bytes":             base64.StdEncoding.EncodeToString(testPriv[:48]),
		"halves do not match":  base64.StdEncoding.EncodeToString(mismatched),
		"ECDSA PKCS #8":        pemBlock(t, "PRIVATE KEY", ecPKCS8),
		"public key PEM":       pemBlock(t, "PUBLIC KEY", spki),
		"encrypted-style PEM":  pemBlock(t, "ENCRYPTED PRIVATE KEY", pkcs8),
		"garbage in PEM":       pemBlock(t, "PRIVATE KEY", []byte("garbage")),
		"secret-looking words": "hunter2-is-not-a-key",
	}
	for name, s := range bad {
		t.Run("bad/"+name, func(t *testing.T) {
			priv, err := ParsePrivateKey(s)
			if !errors.Is(err, ErrKey) || priv != nil {
				t.Fatalf("ParsePrivateKey = %d bytes, %v; want ErrKey", len(priv), err)
			}
			// The input is secret material (or a mistyped secret): it must
			// never be quoted back in an error that ends up in a log.
			trimmed := strings.TrimSpace(s)
			if len(trimmed) >= 8 && strings.Contains(err.Error(), trimmed[:8]) {
				t.Errorf("error echoes the input: %v", err)
			}
		})
	}
}

func TestEncodeAndKeyID(t *testing.T) {
	if got := EncodePrivateKey(testPriv[:10]); got != "" {
		t.Errorf("EncodePrivateKey of a short key = %q", got)
	}
	if strings.Contains(EncodePrivateKey(testPriv), EncodePublicKey(testPub)) {
		t.Error("the private key text embeds the public key text")
	}
	id := KeyID(testPub)
	if len(id) != 16 || id != KeyID(testPub) || id == KeyID(otherPub) || strings.ToLower(id) != id {
		t.Errorf("KeyID = %q", id)
	}
	if _, err := hex.DecodeString(id); err != nil {
		t.Errorf("KeyID is not hex: %q", id)
	}
	if KeyID(nil) != "" || KeyID(testPub[:5]) != "" {
		t.Error("KeyID of a malformed key is not empty")
	}
}
