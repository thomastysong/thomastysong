package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Limits on what a bundle may contain. They bound memory, disk and time on
// the endpoint whatever a publisher (or a thief of the signing key) sends.
const (
	// MaxFiles is the highest number of archive entries, manifest included.
	MaxFiles = 500
	// MaxBytes caps both the compressed archive and the sum of the
	// uncompressed file sizes.
	MaxBytes = 32 << 20
)

// maxStreamBytes bounds the decompressed tar stream: the content, one
// header block and up to one block of padding per entry, and slack for the
// end-of-archive marker and record padding. It is what stops a small gzip
// stream from inflating into gigabytes of headers or padding.
const maxStreamBytes = MaxBytes + MaxFiles*1024 + 2<<20

// entryFunc receives one archive entry. r yields exactly size bytes.
type entryFunc func(name string, size int64, r io.Reader) error

// walk is the only archive reader in the package: Verify, Create's self
// check and Install all go through it, so there is no second parser that
// could disagree about what an archive contains. It enforces every
// structural rule and calls fn for each entry in archive order.
func walk(tarball []byte, fn entryFunc) error {
	if len(tarball) > MaxBytes {
		return fmt.Errorf("%w: archive is %d bytes, limit %d", ErrTooLarge, len(tarball), MaxBytes)
	}
	// bytes.Reader is an io.ByteReader, so the decompressor consumes exactly
	// the bytes of the gzip member and src.Len() afterwards is what follows.
	src := bytes.NewReader(tarball)
	zr, err := gzip.NewReader(src)
	if err != nil {
		return fmt.Errorf("%w: not a gzip stream: %v", ErrFormat, err)
	}
	// One member only: tools disagree on whether concatenated members are
	// one archive, and a reviewer must see what the sensor will load.
	zr.Multistream(false)
	stream := &capReader{r: zr, left: maxStreamBytes}
	tr := tar.NewReader(stream)

	seen := make(map[string]struct{})
	var total int64
	for n := 0; ; n++ {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return readError(err)
		}
		if n >= MaxFiles {
			return fmt.Errorf("%w: more than %d entries", ErrTooLarge, MaxFiles)
		}
		if err := checkHeader(hdr); err != nil {
			return err
		}
		// A second entry with the same name would silently replace the
		// first on extraction; on Windows and macOS a different case does
		// the same.
		key := strings.ToLower(hdr.Name)
		if _, dup := seen[key]; dup {
			return fmt.Errorf("%w: duplicate entry %s", ErrFormat, quote(hdr.Name))
		}
		seen[key] = struct{}{}
		if hdr.Size < 0 || hdr.Size > MaxBytes-total {
			return fmt.Errorf("%w: content is larger than %d bytes", ErrTooLarge, MaxBytes)
		}
		total += hdr.Size
		if err := fn(hdr.Name, hdr.Size, tr); err != nil {
			return err
		}
	}
	if err := onlyZeros(stream); err != nil {
		return err
	}
	if src.Len() != 0 {
		return fmt.Errorf("%w: %d bytes follow the gzip stream", ErrFormat, src.Len())
	}
	return nil
}

// checkHeader accepts regular files with allow-listed names and no extended
// attributes of any kind.
func checkHeader(h *tar.Header) error {
	if h.Typeflag != tar.TypeReg {
		return fmt.Errorf("%w: %s is a %s", ErrNotRegular, quote(h.Name), typeName(h.Typeflag))
	}
	if h.Name != manifestName {
		if err := checkName(h.Name); err != nil {
			return err
		}
	}
	// PAX records can rename an entry, declare it sparse or attach xattrs.
	// Every allowed name fits a plain header, so nothing legitimate needs
	// them.
	if len(h.PAXRecords) != 0 {
		return fmt.Errorf("%w: %s carries extended (PAX) headers", ErrFormat, quote(h.Name))
	}
	return nil
}

func typeName(flag byte) string {
	switch flag {
	case tar.TypeSymlink:
		return "symbolic link"
	case tar.TypeLink:
		return "hard link"
	case tar.TypeDir:
		return "directory"
	case tar.TypeChar, tar.TypeBlock:
		return "device"
	case tar.TypeFifo:
		return "fifo"
	case tar.TypeXGlobalHeader:
		return "global extended header"
	case tar.TypeGNUSparse:
		return "sparse file"
	default:
		return fmt.Sprintf("special entry (type %q)", flag)
	}
}

// onlyZeros consumes the rest of the decompressed stream, which may only be
// the zero padding tar writers add after the end-of-archive marker. Reading
// to the end also makes compress/gzip check the CRC and length trailer.
func onlyZeros(r io.Reader) error {
	buf := make([]byte, 32<<10)
	for {
		n, err := r.Read(buf)
		for _, b := range buf[:n] {
			if b != 0 {
				return fmt.Errorf("%w: data after the end-of-archive marker", ErrFormat)
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return readError(err)
		}
	}
}

// readError classifies a failure to read the archive itself.
func readError(err error) error {
	switch {
	case errors.Is(err, ErrTooLarge), errors.Is(err, ErrFormat):
		return err
	case errors.Is(err, tar.ErrInsecurePath):
		return fmt.Errorf("%w: %v", ErrUnsafePath, err)
	default:
		return fmt.Errorf("%w: %v", ErrFormat, err)
	}
}

// capReader fails with ErrTooLarge once more than left bytes have been read,
// instead of reporting a clean EOF the way io.LimitReader does: a truncated
// view of an oversized stream must not look like a short, valid archive.
type capReader struct {
	r    io.Reader
	left int64
}

func (c *capReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if c.left <= 0 {
		var one [1]byte
		n, err := io.ReadFull(c.r, one[:])
		if n > 0 {
			return 0, fmt.Errorf("%w: decompressed archive is larger than %d bytes", ErrTooLarge, int64(maxStreamBytes))
		}
		if err == io.ErrUnexpectedEOF {
			err = io.EOF
		}
		return 0, err
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	return n, err
}

// checkArchive validates the structure of an archive and the consistency of
// its content with the embedded manifest. It does not look at signatures.
func checkArchive(tarball []byte) (*Manifest, error) {
	sums := make(map[string]string)
	var raw []byte
	found := false
	err := walk(tarball, func(name string, size int64, r io.Reader) error {
		if name == manifestName {
			if size > maxManifestBytes {
				return fmt.Errorf("%w: %s is larger than %d bytes", ErrManifest, manifestName, maxManifestBytes)
			}
			b, err := io.ReadAll(r)
			if err != nil {
				return readError(err)
			}
			raw, found = b, true
			return nil
		}
		h := sha256.New()
		if _, err := io.Copy(h, r); err != nil {
			return readError(err)
		}
		sums[name] = hex.EncodeToString(h.Sum(nil))
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("%w: archive has no %s", ErrManifest, manifestName)
	}
	m, err := parseManifest(raw)
	if err != nil {
		return nil, err
	}
	if err := m.matches(sums); err != nil {
		return nil, err
	}
	return m, nil
}
