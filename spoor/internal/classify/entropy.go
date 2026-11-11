package classify

import "math"

// Entropy returns the Shannon entropy of s in bits per byte (0 for the empty
// string, at most 8). It is computed over bytes rather than runes so invalid
// UTF-8 cannot change the result or cause an error.
func Entropy(s string) float64 {
	n := len(s)
	if n == 0 {
		return 0
	}
	var counts [256]int
	for i := 0; i < n; i++ {
		counts[s[i]]++
	}
	var h float64
	fn := float64(n)
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / fn
		h -= p * math.Log2(p)
	}
	return h
}

// asciiLower lower-cases A-Z only and keeps the byte length of s, so offsets
// computed on the result are valid for s. strings.ToLower is not usable for
// that: it rewrites invalid UTF-8 and some runes change length when folded.
func asciiLower(s string) string {
	i := 0
	for ; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			break
		}
	}
	if i == len(s) {
		return s
	}
	b := []byte(s)
	for ; i < len(b); i++ {
		if c := b[i]; c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// distinctBytes reports how many different byte values occur in s, stopping
// once limit is reached.
func distinctBytes(s string, limit int) int {
	var seen [256]bool
	n := 0
	for i := 0; i < len(s); i++ {
		if !seen[s[i]] {
			seen[s[i]] = true
			n++
			if n >= limit {
				return n
			}
		}
	}
	return n
}
