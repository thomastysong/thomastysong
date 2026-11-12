package sink

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	segmentExt = ".ndjson"
	// maxSegmentN bounds the roll counter to nine digits so a planted name
	// with an absurd counter is simply not a segment.
	maxSegmentN = 999_999_999
	// dirBatch is how many directory entries are read per call, so a
	// directory stuffed with junk costs time but not unbounded memory.
	dirBatch = 1024
)

// SegmentName returns the file name of segment n of a stream for the hour
// containing t (UTC): <stream>-<YYYYMMDD>-<HH>-<n>.ndjson, n zero padded to
// four digits. The name carries the hour so retention can be decided from
// the name alone, and never changes once the file exists: Fluent Bit tracks
// files by inode and offset and a rename would only add risk.
//
// A stream that is not a plain lower-case identifier is replaced by
// "unknown" so the result can never contain a path separator.
func SegmentName(stream string, t time.Time, n int) string {
	if !validStream(stream) {
		stream = "unknown"
	}
	if n < 0 {
		n = 0
	}
	if n > maxSegmentN {
		n = maxSegmentN
	}
	return fmt.Sprintf("%s-%s-%04d%s", stream, t.UTC().Format("20060102-15"), n, segmentExt)
}

// ParseSegmentName reports whether name is a segment file name and returns
// its stream.
func ParseSegmentName(name string) (stream string, ok bool) {
	seg, ok := parseSegment(name)
	return seg.stream, ok
}

// segment is a parsed segment file name.
type segment struct {
	name   string
	stream string
	bucket time.Time // start of the hour, UTC
	n      int
	size   int64 // filled by statSegments
}

func validStream(s string) bool {
	if s == "" || len(s) > 32 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

func parseSegment(name string) (segment, bool) {
	base, found := strings.CutSuffix(name, segmentExt)
	if !found {
		return segment{}, false
	}
	// Split from the right: the stream cannot contain '-', so the three
	// trailing fields are unambiguous.
	i := strings.LastIndexByte(base, '-')
	if i < 0 {
		return segment{}, false
	}
	nStr := base[i+1:]
	base = base[:i]
	i = strings.LastIndexByte(base, '-')
	if i < 0 {
		return segment{}, false
	}
	hour := base[i+1:]
	base = base[:i]
	i = strings.LastIndexByte(base, '-')
	if i < 0 {
		return segment{}, false
	}
	day, stream := base[i+1:], base[:i]

	if !validStream(stream) || len(day) != 8 || len(hour) != 2 || len(nStr) == 0 || len(nStr) > 9 {
		return segment{}, false
	}
	if !allDigits(day) || !allDigits(hour) || !allDigits(nStr) {
		return segment{}, false
	}
	n, err := strconv.Atoi(nStr)
	if err != nil {
		return segment{}, false
	}
	bucket, err := time.Parse("20060102-15", day+"-"+hour)
	if err != nil {
		return segment{}, false
	}
	return segment{name: name, stream: stream, bucket: bucket.UTC(), n: n}, true
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// segmentLess orders segments oldest first within and across streams.
func segmentLess(a, b segment) bool {
	if !a.bucket.Equal(b.bucket) {
		return a.bucket.Before(b.bucket)
	}
	if a.n != b.n {
		return a.n < b.n
	}
	return a.stream < b.stream
}

// listSegments returns the names in dir that start with prefix and parse as
// segments, unsorted. Names only: nothing is opened or followed. The prefix
// is checked before parsing because a hook process lists a directory that
// may hold a week of segments just to find the handful for this hour.
func listSegments(dir, prefix string) ([]segment, error) {
	d, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	var out []segment
	for {
		names, err := d.Readdirnames(dirBatch)
		for _, name := range names {
			if !strings.HasPrefix(name, prefix) {
				continue
			}
			if seg, ok := parseSegment(name); ok {
				out = append(out, seg)
			}
		}
		if err == io.EOF || (err == nil && len(names) == 0) {
			return out, nil
		}
		if err != nil {
			return out, err
		}
	}
}

// hourPrefix is the part of a segment name shared by every segment of one
// stream and hour.
func hourPrefix(stream string, bucket time.Time) string {
	name := SegmentName(stream, bucket, 0)
	return name[:len(name)-len("0000"+segmentExt)]
}

func sortSegments(segs []segment) {
	sort.Slice(segs, func(i, j int) bool { return segmentLess(segs[i], segs[j]) })
}
