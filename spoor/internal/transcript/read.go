package transcript

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"

	"github.com/klauspost/compress/zstd"
)

const (
	readChunk = 256 << 10
	// tailLen is how many bytes before the checkpoint are fingerprinted to
	// notice a log rewritten in place.
	tailLen = 256
	// maxDocument bounds a file read as one JSON document.
	maxDocument = 64 << 20
	// maxArchive bounds the decompressed size of one archive, so a small
	// hostile .zst cannot expand without limit.
	maxArchive = 2 << 30
	// zstdWindow bounds decoder memory; real rollouts use small windows.
	zstdWindow = 128 << 20
)

// readResult describes one incremental read.
type readResult struct {
	offset   int64 // first byte not consumed
	skipping bool  // inside an oversize line whose LF has not arrived yet
	oversize uint64
	more     bool // stopped on the byte budget with complete lines left
}

// readLines feeds every complete (LF-terminated) line in [start, size) to
// fn. It never reads past size, the length observed when the file was
// opened, and never passes on an unterminated final line: the writer may be
// halfway through it. A line longer than maxLine is skipped without being
// buffered; skipping carries that state across calls when the oversize line
// is itself still being written.
func readLines(f *os.File, start, size int64, maxLine int, skipping bool, budget *int64, stop func() bool, fn func(line []byte)) (readResult, error) {
	res := readResult{offset: start, skipping: skipping}
	buf := make([]byte, 0, readChunk)
	pos := start
	for pos < size {
		// The byte budget is only honoured between lines: stopping in the
		// middle of one would re-read it from its start on every poll and,
		// with a budget smaller than the line, never get past it.
		if stop() || (*budget <= 0 && len(buf) == 0) {
			res.more = true
			break
		}
		// Make room: grow up to one maximal line plus its LF.
		if len(buf) == cap(buf) {
			if cap(buf) > maxLine {
				// A whole buffer without an LF: the line is oversize.
				// Drop what is held and discard up to the next LF.
				buf = buf[:0]
				res.skipping = true
				res.offset = pos
			} else {
				n := 2 * cap(buf)
				if n > maxLine+1 {
					n = maxLine + 1
				}
				nb := make([]byte, len(buf), n)
				copy(nb, buf)
				buf = nb
			}
		}
		want := cap(buf) - len(buf)
		if rem := size - pos; int64(want) > rem {
			want = int(rem)
		}
		n, err := f.ReadAt(buf[len(buf):len(buf)+want], pos)
		if n == 0 {
			if err == io.EOF || err == nil {
				break // the file shrank under us; the next poll will notice
			}
			return res, err
		}
		chunk := buf[len(buf) : len(buf)+n]
		buf = buf[:len(buf)+n]
		pos += int64(n)
		*budget -= int64(n)

		if res.skipping {
			i := bytes.IndexByte(chunk, '\n')
			if i < 0 {
				buf = buf[:0]
				res.offset = pos
				continue
			}
			// The oversize line ends here; keep what follows it.
			res.oversize++
			res.skipping = false
			rest := chunk[i+1:]
			res.offset = pos - int64(len(rest))
			buf = append(buf[:0], rest...)
		}
		// Hand over every complete line in the buffer.
		consumed := 0
		for {
			i := bytes.IndexByte(buf[consumed:], '\n')
			if i < 0 {
				break
			}
			line := buf[consumed : consumed+i]
			consumed += i + 1
			res.offset += int64(i + 1)
			if len(line) > maxLine {
				res.oversize++
				continue
			}
			fn(line)
		}
		if consumed > 0 {
			buf = append(buf[:0], buf[consumed:]...)
		}
		if err != nil && err != io.EOF {
			return res, err
		}
		if *budget <= 0 && consumed > 0 {
			res.more = pos < size
			break
		}
	}
	return res, nil
}

// tailPrint fingerprints the bytes just before offset.
func tailPrint(f *os.File, offset int64) string {
	if offset <= 0 {
		return ""
	}
	n := int64(tailLen)
	if offset < n {
		n = offset
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(io.NewSectionReader(f, offset-n, n), b); err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

// lastByte returns the byte before offset.
func lastByte(f *os.File, offset int64) (byte, bool) {
	if offset <= 0 {
		return 0, false
	}
	var b [1]byte
	if _, err := f.ReadAt(b[:], offset-1); err != nil {
		return 0, false
	}
	return b[0], true
}

var errTooLarge = errors.New("file exceeds the size bound for its format")

// readZstdLines decompresses a whole archive and feeds its complete lines to
// fn, with the same line rules as readLines.
func readZstdLines(f *os.File, maxLine int, stop func() bool, fn func(line []byte)) (oversize uint64, err error) {
	dec, err := zstd.NewReader(f,
		zstd.WithDecoderConcurrency(1),
		zstd.WithDecoderMaxWindow(zstdWindow),
		zstd.WithDecoderLowmem(true))
	if err != nil {
		return 0, err
	}
	defer dec.Close()
	return scanLines(io.LimitReader(dec, maxArchive+1), maxArchive, maxLine, stop, fn)
}

// scanLines splits a stream into LF-terminated lines, skipping oversize ones
// without buffering them and ignoring an unterminated tail.
func scanLines(r io.Reader, limit int64, maxLine int, stop func() bool, fn func(line []byte)) (oversize uint64, err error) {
	br := bufio.NewReaderSize(r, readChunk)
	var line []byte
	var total int64
	dropping := false
	for {
		if stop() {
			return oversize, errStopped
		}
		frag, rerr := br.ReadSlice('\n')
		total += int64(len(frag))
		if total > limit {
			return oversize, errTooLarge
		}
		complete := rerr == nil
		switch {
		case dropping:
			if complete {
				dropping = false
				oversize++
			}
		case len(line)+len(frag) > maxLine+1:
			line = line[:0]
			if complete {
				oversize++
			} else {
				dropping = true
			}
		case complete:
			if len(line) == 0 {
				fn(frag[:len(frag)-1])
			} else {
				line = append(line, frag...)
				fn(line[:len(line)-1])
				line = line[:0]
			}
		default:
			line = append(line, frag...)
		}
		if rerr != nil && rerr != bufio.ErrBufferFull {
			if rerr == io.EOF {
				return oversize, nil
			}
			return oversize, rerr
		}
	}
}

var errStopped = errors.New("stopped")

// readDocument returns the whole file when it fits the document bound.
func readDocument(f *os.File, size int64) ([]byte, error) {
	if size > maxDocument {
		return nil, errTooLarge
	}
	b, err := io.ReadAll(io.LimitReader(f, maxDocument+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxDocument {
		return nil, errTooLarge
	}
	return b, nil
}
