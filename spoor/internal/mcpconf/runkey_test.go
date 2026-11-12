package mcpconf

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestRunKeyDrawnOnce(t *testing.T) {
	k := runKey()
	if len(k) != 32 || bytes.Equal(k, make([]byte, 32)) {
		t.Fatalf("run key is %d bytes or zero", len(k))
	}
	if !bytes.Equal(runKey(), k) {
		t.Fatal("run key changed within one process")
	}
}

// A cut value ends in a digest keyed per process, never the unkeyed fp8 of
// the whole value: that would let a reader confirm a guess about the tail.
func TestCapStringKeyed(t *testing.T) {
	head := strings.Repeat("n", 300)
	a, b := head+"-alpha", head+"-beta"
	ca, cb := capString(a, maxNameLen), capString(b, maxNameLen)
	for _, c := range []struct{ full, got string }{{a, ca}, {b, cb}} {
		if len(c.got) > maxNameLen {
			t.Fatalf("cut value is %d bytes", len(c.got))
		}
		i := strings.LastIndexByte(c.got, '~')
		if i < 0 || len(c.got)-i-1 != 8 {
			t.Fatalf("no 8-digit cut marker: %q", c.got[len(c.got)-20:])
		}
		suffix := c.got[i+1:]
		if suffix == fp8(c.full) {
			t.Fatal("the cut marker is the unkeyed fingerprint of the full value")
		}
		if suffix != runFP8(c.full) {
			t.Fatalf("suffix %q, want the keyed digest", suffix)
		}
	}
	if ca == cb {
		t.Fatal("two different long values collided after the cut")
	}
	if capString(a, maxNameLen) != ca {
		t.Fatal("capString is not stable within one process")
	}
	if short := "short"; capString(short, maxNameLen) != short {
		t.Fatal("a value under the cap was changed")
	}
	// Multi-byte runes are not split.
	r := capString(strings.Repeat("é", 400), 64)
	if !strings.HasSuffix(r[:strings.LastIndexByte(r, '~')], "é") {
		t.Fatalf("cut inside a rune: %q", r)
	}
}

// Every capped field of an inventory record is free of unkeyed digests of
// the value it cut.
func TestNormalizedCutsCarryNoUnkeyedDigest(t *testing.T) {
	long := func(p string, n int) string { return p + strings.Repeat("z", n) }
	s := Server{
		Name:      capString(long("srv-", 600), maxNameLen),
		Transport: "stdio",
		Command:   long("/opt/tools/", 3000),
		Args:      []string{long("--opt=", 3000), long("pkg@", 600)},
	}
	full := []string{long("srv-", 600), s.Command, s.Args[0], s.Args[1]}
	n := Normalize(s)
	out, err := json.Marshal(n)
	if err != nil {
		t.Fatal(err)
	}
	text := string(out) + s.Name
	for _, f := range full {
		if strings.Contains(text, fp8(f)) {
			t.Errorf("an unkeyed fingerprint of a %d-byte value reached the output", len(f))
		}
	}
	if !strings.Contains(text, "~") {
		t.Fatalf("nothing was cut: %s", out)
	}
}
