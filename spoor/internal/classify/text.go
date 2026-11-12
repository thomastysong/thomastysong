package classify

import (
	"regexp"
	"strconv"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const (
	// maxScanText is the input cap of ScanText.
	maxScanText = 1 << 20
	// maxDecodedTags caps TextFindings.DecodedTags.
	maxDecodedTags = 512
	// maxNormalized caps the text markers are searched in: compatibility
	// normalization can expand hostile input many times over.
	maxNormalized = 2 << 20
)

// TextFindings is what ScanText found in a piece of text an agent may read:
// characters a person cannot see, and phrasing that tries to give the agent
// orders. Counts are code points.
type TextFindings struct {
	TagChars    int      // U+E0000..U+E007F (ASCII smuggling); emoji flag tag sequences are not counted
	Bidi        int      // U+202A..U+202E, U+2066..U+2069
	ZeroWidth   int      // U+200B..U+200D, U+2060, U+FEFF (not at offset 0); joiners inside emoji and Arabic/Indic words are not counted
	Variation   int      // variation selectors in suspicious runs (two or more in a row, or supplementary selectors off an ideograph)
	Homoglyph   bool     // an identifier-like token mixes ASCII letters with look-alike letters of another script
	DecodedTags string   // tag characters decoded to ASCII, capped at 512 bytes
	Markers     []string // closed vocabulary, see MarkerVocabulary
}

// HiddenUnicode reports whether the text carries invisible characters in a
// quantity or of a kind that ordinary writing does not produce: any tag or
// bidirectional control, any suspicious variation-selector run, or three or
// more zero-width characters (a single stray zero-width space is a common
// copy-and-paste artifact).
func (f TextFindings) HiddenUnicode() bool {
	return f.TagChars > 0 || f.Bidi > 0 || f.Variation > 0 || f.ZeroWidth >= 3
}

// ScanText inspects s for hidden Unicode and instruction-override markers.
// Only the first 1 MiB is examined. Markers are searched in a normalized view
// of the text (invisible characters removed, compatibility forms and
// look-alike letters folded to ASCII, case folded), and also in the text that
// tag characters and variation-selector runs decode to, so "ignore previous
// instructions" is found whether it is written plainly, with zero-width
// characters between the letters, in full-width letters, or smuggled as tag
// characters. Escaped forms of the same code points ("‮",
// "\U000E0041", "󠁁"), as they appear in JSON that was not
// decoded, are counted as well. ScanText never panics.
func ScanText(s string) (f TextFindings) {
	defer func() {
		if recover() != nil {
			f = TextFindings{}
		}
	}()
	if len(s) > maxScanText {
		cut := maxScanText
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut]
	}
	if s == "" {
		return f
	}
	var sc textScan
	vis := s
	if !isASCII(s) {
		vis = sc.scanRunes(s)
	}
	if strings.Contains(s, `\u`) || strings.Contains(s, `\U`) {
		sc.scanEscapes(s)
	}
	f.TagChars, f.Bidi, f.ZeroWidth, f.Variation = sc.tags, sc.bidi, sc.zeroWidth, sc.variation
	f.Homoglyph = sc.homoglyph
	f.DecodedTags = sc.decoded.String()

	var ms markerSet
	scanMarkers(vis, &ms, true)
	if f.DecodedTags != "" {
		scanMarkers(f.DecodedTags, &ms, false)
	}
	if sc.vsBytes.Len() >= 8 && mostlyPrintable(sc.vsBytes.String()) {
		scanMarkers(sc.vsBytes.String(), &ms, false)
	}
	f.Markers = ms.names()
	return f
}

// textScan accumulates the per-rune findings.
type textScan struct {
	tags, bidi, zeroWidth, variation int
	homoglyph                        bool
	decoded                          strings.Builder // tag characters as ASCII
	vsBytes                          strings.Builder // variation-selector runs as bytes
	lastTagEnd                       int             // byte offset just past the previous tag character
}

func isTag(r rune) bool  { return r >= 0xE0000 && r <= 0xE007F }
func isBidi(r rune) bool { return r >= 0x202A && r <= 0x202E || r >= 0x2066 && r <= 0x2069 }
func isVariation(r rune) bool {
	return r >= 0xFE00 && r <= 0xFE0F || r >= 0xE0100 && r <= 0xE01EF
}
func isZeroWidth(r rune) bool {
	return r >= 0x200B && r <= 0x200D || r == 0x2060 || r == 0xFEFF
}

// isInvisible covers everything removed before marker matching: the counted
// classes plus other format characters used to split words.
func isInvisible(r rune) bool {
	switch {
	case isTag(r), isBidi(r), isVariation(r), isZeroWidth(r):
		return true
	case r == 0x00AD, r == 0x180E, r == 0x200E, r == 0x200F, r >= 0x2061 && r <= 0x2064,
		r == 0x115F, r == 0x1160, r == 0x3164, r == 0xFFA0, r == 0x034F:
		return true
	}
	return false
}

func isEmojiish(r rune) bool {
	switch {
	case r >= 0x1F000 && r <= 0x1FAFF, r >= 0x2600 && r <= 0x27BF, r >= 0x2190 && r <= 0x21FF,
		r >= 0x2300 && r <= 0x23FF, r >= 0x2B00 && r <= 0x2BFF, r == 0xFE0F, r == 0x20E3:
		return true
	}
	return false
}

// joinerScripts use ZWJ and ZWNJ in ordinary spelling.
var joinerScripts = []*unicode.RangeTable{
	unicode.Arabic, unicode.Devanagari, unicode.Bengali, unicode.Gurmukhi,
	unicode.Gujarati, unicode.Oriya, unicode.Tamil, unicode.Telugu,
	unicode.Kannada, unicode.Malayalam, unicode.Sinhala, unicode.Khmer,
	unicode.Myanmar, unicode.Tibetan, unicode.Mongolian, unicode.Syriac,
}

func usesJoiners(r rune) bool { return r >= 0x0600 && unicode.IsOneOf(joinerScripts, r) }

// scanRunes counts hidden characters and returns the text with invisible
// characters removed (the "visible" text markers are searched in).
func (sc *textScan) scanRunes(s string) string {
	var vis strings.Builder
	vis.Grow(len(s))
	var prev rune = -1
	vsRun := 0        // length of the current variation-selector run
	flagTags := 0     // tag characters still allowed as part of an emoji flag sequence
	tokASCII := 0     // ASCII letters in the current identifier-like token
	tokLookalike := 0 // look-alike letters in it
	tokForeign := 0   // other non-ASCII letters in it
	endToken := func() {
		if tokASCII >= 1 && tokLookalike >= 1 && tokForeign == 0 && tokASCII+tokLookalike >= 4 {
			sc.homoglyph = true
		}
		tokASCII, tokLookalike, tokForeign = 0, 0, 0
	}
	vsCounted := 0 // selectors of the current run already counted singly
	endVSRun := func() {
		if vsRun >= 2 {
			sc.variation += vsRun - vsCounted
		}
		vsRun, vsCounted = 0, 0
	}
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			// Invalid UTF-8: keep the byte out of the visible text.
			endToken()
			endVSRun()
			prev = r
			i++
			continue
		}
		next := rune(-1)
		if i+size < len(s) {
			next, _ = utf8.DecodeRuneInString(s[i+size:])
		}
		if !isVariation(r) {
			endVSRun()
		}
		switch {
		case isTag(r):
			if flagTags > 0 {
				// U+1F3F4 followed by tag characters is a subdivision flag
				// (England, Scotland, Wales): legitimate emoji.
				flagTags--
				if r == 0xE007F {
					flagTags = 0
				}
				break
			}
			sc.tags++
			if r >= 0xE0020 && r <= 0xE007E && sc.decoded.Len() < maxDecodedTags {
				if sc.decoded.Len() > 0 && sc.lastTagEnd != i {
					sc.decoded.WriteByte(' ') // separate runs
				}
				sc.decoded.WriteByte(byte(r - 0xE0000))
			}
			sc.lastTagEnd = i + size
		case isBidi(r):
			sc.bidi++
		case r == 0x200C || r == 0x200D:
			legit := usesJoiners(prev) && (usesJoiners(next) || next == -1)
			if r == 0x200D && isEmojiish(prev) && isEmojiish(next) {
				legit = true
			}
			if !legit {
				sc.zeroWidth++
			}
		case isZeroWidth(r):
			if !(r == 0xFEFF && i == 0) {
				sc.zeroWidth++
			}
		case isVariation(r):
			vsRun++
			if sc.vsBytes.Len() < 2048 {
				if r <= 0xFE0F {
					sc.vsBytes.WriteByte(byte(r - 0xFE00))
				} else {
					sc.vsBytes.WriteByte(byte(r - 0xE0100 + 16))
				}
			}
			if r >= 0xE0100 && vsRun == 1 && !unicode.Is(unicode.Han, prev) {
				sc.variation++
				vsCounted = 1
			}
		}
		if r != 0x1F3F4 && !isTag(r) {
			flagTags = 0
		}
		if r == 0x1F3F4 {
			flagTags = 8
		}
		if !isInvisible(r) {
			vis.WriteRune(r)
			// Homoglyph bookkeeping on visible characters only.
			switch {
			case r < 0x80:
				switch {
				case r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z':
					tokASCII++
				case r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.':
				default:
					endToken()
				}
			case lookalike(r) != 0:
				tokLookalike++
			case unicode.IsLetter(r):
				tokForeign++
			case unicode.IsMark(r) || unicode.IsDigit(r):
			default:
				endToken()
			}
		}
		prev = r
		i += size
	}
	endToken()
	endVSRun()
	return vis.String()
}

var (
	escapeOnce sync.Once
	escapeRe   *regexp.Regexp
)

// scanEscapes counts the same hidden code points written as escape
// sequences. Transcripts and tool results often hold JSON text that was never
// decoded, and an agent that later decodes it sees the real characters.
func (sc *textScan) scanEscapes(s string) {
	escapeOnce.Do(func() {
		escapeRe = regexp.MustCompile(`\\[uU](?:\{0*([0-9a-fA-F]{4,6})\}|000([eE]0[01][0-9a-fA-F]{2})|[dD][bB]40\\u([dD][cC][0-7][0-9a-fA-F])|([0-9a-fA-F]{4}))`)
	})
	for n, m := range escapeRe.FindAllStringSubmatch(s, 4096) {
		if n >= 4096 {
			break
		}
		var r rune
		switch {
		case m[1] != "":
			v, _ := strconv.ParseUint(m[1], 16, 32)
			r = rune(v)
		case m[2] != "":
			v, _ := strconv.ParseUint(m[2], 16, 32)
			r = rune(v)
		case m[3] != "":
			// Low surrogate DCxx after high surrogate DB40 is U+E00xx.
			v, _ := strconv.ParseUint(m[3], 16, 32)
			r = rune(0xE0000 + (v - 0xDC00))
		default:
			v, _ := strconv.ParseUint(m[4], 16, 32)
			r = rune(v)
		}
		switch {
		case isTag(r):
			sc.tags++
			if r >= 0xE0020 && r <= 0xE007E && sc.decoded.Len() < maxDecodedTags {
				sc.decoded.WriteByte(byte(r - 0xE0000))
			}
		case isBidi(r):
			sc.bidi++
		case isZeroWidth(r):
			sc.zeroWidth++
		}
	}
}

func mostlyPrintable(s string) bool {
	if s == "" {
		return false
	}
	ok := 0
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 0x20 && c < 0x7f || c == '\n' || c == '\t' || c == '\r' {
			ok++
		}
	}
	return ok*100 >= len(s)*85
}

// lookalikes maps letters of other scripts that are near-identical to an
// ASCII letter in common fonts. It is deliberately small: only pairs a reader
// cannot tell apart, so ordinary mixed-language text is not flagged.
var lookalikes = map[rune]byte{
	// Cyrillic lower case.
	'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y',
	'і': 'i', 'ј': 'j', 'ѕ': 's', 'һ': 'h', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w', 'ѵ': 'v',
	// Cyrillic upper case.
	'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O',
	'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X', 'У': 'Y', 'І': 'I', 'Ј': 'J',
	'Ѕ': 'S', 'Ԛ': 'Q', 'Ԝ': 'W',
	// Greek.
	'ο': 'o', 'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Ι': 'I',
	'Κ': 'K', 'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X',
	// Armenian and Latin look-alikes.
	'օ': 'o', 'ս': 'u', 'հ': 'h', 'ı': 'i', 'ɑ': 'a', 'ɡ': 'g', 'ℓ': 'l',
}

func lookalike(r rune) byte {
	if r < 0x100 {
		return 0
	}
	if r >= 0xFF21 && r <= 0xFF3A || r >= 0xFF41 && r <= 0xFF5A {
		return byte(r - 0xFF21 + 'A') // full-width Latin
	}
	return lookalikes[r]
}

// normalizeForMarkers returns the lower-cased, ASCII-folded form of visible
// text that phrase and tag markers are matched against.
func normalizeForMarkers(vis string) string {
	if isASCII(vis) {
		return asciiLower(vis)
	}
	n := norm.NFKC.String(vis)
	if len(n) > maxNormalized {
		n = n[:maxNormalized]
	}
	var b strings.Builder
	b.Grow(len(n))
	for _, r := range n {
		switch {
		case r == utf8.RuneError:
			b.WriteByte(' ')
		case r < 0x80:
			if r >= 'A' && r <= 'Z' {
				r += 'a' - 'A'
			}
			b.WriteByte(byte(r))
		default:
			if c := lookalike(r); c != 0 {
				if c >= 'A' && c <= 'Z' {
					c += 'a' - 'A'
				}
				b.WriteByte(c)
			} else {
				b.WriteRune(unicode.ToLower(r))
			}
		}
	}
	return b.String()
}
