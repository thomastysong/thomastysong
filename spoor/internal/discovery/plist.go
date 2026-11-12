package discovery

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"math"
	"strconv"
	"strings"
	"unicode/utf16"
)

// A minimal property-list reader: enough to read Info.plist identity keys
// and managed-preference documents. Both encodings are supported: XML and
// binary ("bplist00"). Dates and data become strings ("<date>", "<data>"):
// no probe compares them, and data blobs are never emitted.

const (
	maxPlistBytes   = 4 << 20
	maxPlistObjects = 100_000
	// maxPlistExpansion bounds the string bytes a binary plist decodes to,
	// counted once per reference, as a multiple of the input size (plus a
	// fixed allowance). Objects are shared by reference, so without it one
	// 3 MiB string referenced 100,000 times reads as 300 GiB of text to
	// every consumer of the tree. A real Info.plist or managed-preferences
	// document references its uniqued keys a few times each.
	maxPlistExpansion = 8
	plistExpansionMin = 1 << 20
)

var errPlist = errors.New("malformed plist")

func parsePlist(data []byte) (any, error) {
	if len(data) > maxPlistBytes {
		return nil, errTooLarge
	}
	if bytes.HasPrefix(data, []byte("bplist00")) {
		return parseBinaryPlist(data)
	}
	return parseXMLPlist(data)
}

// ---------------------------------------------------------------- XML

func parseXMLPlist(data []byte) (any, error) {
	d := xml.NewDecoder(bytes.NewReader(data))
	d.Strict = false
	// External entities are never resolved by encoding/xml; Entity stays
	// empty so only the predefined XML entities are understood.
	for {
		tok, err := d.Token()
		if err != nil {
			return nil, errPlist
		}
		if se, ok := tok.(xml.StartElement); ok {
			if se.Name.Local == "plist" {
				continue
			}
			count := 0
			return xmlValue(d, se, 0, &count)
		}
	}
}

func xmlValue(d *xml.Decoder, se xml.StartElement, depth int, count *int) (any, error) {
	*count++
	if depth > maxNesting || *count > maxPlistObjects {
		return nil, errNesting
	}
	switch se.Name.Local {
	case "dict":
		m := map[string]any{}
		key := ""
		haveKey := false
		for {
			tok, err := d.Token()
			if err != nil {
				return nil, errPlist
			}
			switch t := tok.(type) {
			case xml.StartElement:
				if t.Name.Local == "key" {
					s, err := xmlText(d)
					if err != nil {
						return nil, err
					}
					key, haveKey = s, true
					continue
				}
				v, err := xmlValue(d, t, depth+1, count)
				if err != nil {
					return nil, err
				}
				if haveKey {
					m[key] = v
					haveKey = false
				}
			case xml.EndElement:
				return m, nil
			}
		}
	case "array":
		var l []any
		for {
			tok, err := d.Token()
			if err != nil {
				return nil, errPlist
			}
			switch t := tok.(type) {
			case xml.StartElement:
				v, err := xmlValue(d, t, depth+1, count)
				if err != nil {
					return nil, err
				}
				l = append(l, v)
			case xml.EndElement:
				return l, nil
			}
		}
	case "true", "false":
		if err := d.Skip(); err != nil {
			return nil, errPlist
		}
		return se.Name.Local == "true", nil
	case "string":
		return xmlText(d)
	case "integer":
		s, err := xmlText(d)
		if err != nil {
			return nil, err
		}
		if i, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64); err == nil {
			return i, nil
		}
		return s, nil
	case "real":
		s, err := xmlText(d)
		if err != nil {
			return nil, err
		}
		if f, err := strconv.ParseFloat(strings.TrimSpace(s), 64); err == nil {
			return f, nil
		}
		return s, nil
	case "date":
		if err := d.Skip(); err != nil {
			return nil, errPlist
		}
		return "<date>", nil
	default: // data and anything unknown
		if err := d.Skip(); err != nil {
			return nil, errPlist
		}
		return "<data>", nil
	}
}

func xmlText(d *xml.Decoder) (string, error) {
	var b strings.Builder
	depth := 0
	for {
		tok, err := d.Token()
		if err != nil {
			return "", errPlist
		}
		switch t := tok.(type) {
		case xml.CharData:
			if b.Len() < 1<<20 {
				b.Write(t)
			}
		case xml.StartElement:
			depth++
		case xml.EndElement:
			if depth == 0 {
				return b.String(), nil
			}
			depth--
		}
	}
}

// ---------------------------------------------------------------- binary

type bplist struct {
	data       []byte
	offsets    []uint64
	refSize    int
	count      int
	visiting   map[uint64]bool
	objectsLft int
	// strs memoizes decoded strings by object reference: a Go string is
	// immutable, so every reference to one object shares one copy and the
	// memory decoded is bounded by the input.
	strs map[uint64]string
	// textLeft is the string budget, charged per reference (memoized or
	// not), so the logical size of the tree is bounded too.
	textLeft int64
}

func parseBinaryPlist(data []byte) (v any, err error) {
	defer func() {
		if recover() != nil {
			v, err = nil, errPlist
		}
	}()
	if len(data) < 40 {
		return nil, errPlist
	}
	tr := data[len(data)-32:]
	offSize := int(tr[6])
	refSize := int(tr[7])
	numObj := binary.BigEndian.Uint64(tr[8:16])
	top := binary.BigEndian.Uint64(tr[16:24])
	tableOff := binary.BigEndian.Uint64(tr[24:32])
	if offSize < 1 || offSize > 8 || refSize < 1 || refSize > 8 || numObj == 0 || numObj > maxPlistObjects ||
		top >= numObj || tableOff >= uint64(len(data)) || tableOff+numObj*uint64(offSize) > uint64(len(data)-32) {
		return nil, errPlist
	}
	p := &bplist{data: data, refSize: refSize, count: int(numObj), visiting: map[uint64]bool{}, objectsLft: maxPlistObjects,
		strs: map[uint64]string{}, textLeft: int64(len(data))*maxPlistExpansion + plistExpansionMin}
	p.offsets = make([]uint64, numObj)
	for i := uint64(0); i < numObj; i++ {
		p.offsets[i] = readUint(data[tableOff+i*uint64(offSize):], offSize)
		if p.offsets[i] >= tableOff {
			return nil, errPlist
		}
	}
	return p.object(top, 0)
}

func readUint(b []byte, n int) uint64 {
	var v uint64
	for i := 0; i < n; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v
}

// length decodes an object's count: inline in the low nibble, or an int
// object following the marker when the nibble is 0xF.
func (p *bplist) length(off uint64, nib byte) (n uint64, start uint64, err error) {
	if nib != 0x0F {
		return uint64(nib), off + 1, nil
	}
	if off+2 > uint64(len(p.data)) {
		return 0, 0, errPlist
	}
	m := p.data[off+1]
	if m>>4 != 0x1 {
		return 0, 0, errPlist
	}
	size := 1 << (m & 0x0F)
	if size > 8 || off+2+uint64(size) > uint64(len(p.data)) {
		return 0, 0, errPlist
	}
	return readUint(p.data[off+2:], size), off + 2 + uint64(size), nil
}

func (p *bplist) object(ref uint64, depth int) (any, error) {
	if ref >= uint64(p.count) || depth > maxNesting {
		return nil, errPlist
	}
	p.objectsLft--
	if p.objectsLft < 0 {
		return nil, errPlist
	}
	if p.visiting[ref] {
		return nil, errPlist // a reference cycle
	}
	p.visiting[ref] = true
	defer delete(p.visiting, ref)
	off := p.offsets[ref]
	m := p.data[off]
	typ, nib := m>>4, m&0x0F
	switch typ {
	case 0x0:
		switch m {
		case 0x08:
			return false, nil
		case 0x09:
			return true, nil
		}
		return nil, nil
	case 0x1:
		size := 1 << nib
		if size > 8 || off+1+uint64(size) > uint64(len(p.data)) {
			return nil, errPlist
		}
		return int64(readUint(p.data[off+1:], size)), nil
	case 0x2:
		size := 1 << nib
		if off+1+uint64(size) > uint64(len(p.data)) {
			return nil, errPlist
		}
		switch size {
		case 4:
			return float64(math.Float32frombits(uint32(readUint(p.data[off+1:], 4)))), nil
		case 8:
			return math.Float64frombits(readUint(p.data[off+1:], 8)), nil
		}
		return nil, errPlist
	case 0x3:
		return "<date>", nil
	case 0x4:
		return "<data>", nil
	case 0x5, 0x6:
		if v, ok := p.strs[ref]; ok {
			return p.charge(v)
		}
		n, start, err := p.length(off, nib)
		if err != nil {
			return nil, err
		}
		var v string
		if typ == 0x5 {
			if start+n > uint64(len(p.data)) {
				return nil, errPlist
			}
			v = string(p.data[start : start+n])
		} else {
			if start+2*n > uint64(len(p.data)) {
				return nil, errPlist
			}
			u := make([]uint16, n)
			for i := uint64(0); i < n; i++ {
				u[i] = binary.BigEndian.Uint16(p.data[start+2*i:])
			}
			v = string(utf16.Decode(u))
		}
		p.strs[ref] = v
		return p.charge(v)
	case 0xA, 0xD:
		n, start, err := p.length(off, nib)
		if err != nil {
			return nil, err
		}
		width := uint64(p.refSize)
		if typ == 0xD {
			width *= 2
		}
		if n > uint64(p.count) || start+n*width > uint64(len(p.data)) {
			return nil, errPlist
		}
		if typ == 0xA {
			out := make([]any, 0, n)
			for i := uint64(0); i < n; i++ {
				r := readUint(p.data[start+i*uint64(p.refSize):], p.refSize)
				v, err := p.object(r, depth+1)
				if err != nil {
					return nil, err
				}
				out = append(out, v)
			}
			return out, nil
		}
		out := make(map[string]any, n)
		for i := uint64(0); i < n; i++ {
			kr := readUint(p.data[start+i*uint64(p.refSize):], p.refSize)
			vr := readUint(p.data[start+(n+i)*uint64(p.refSize):], p.refSize)
			k, err := p.object(kr, depth+1)
			if err != nil {
				return nil, err
			}
			ks, ok := k.(string)
			if !ok {
				return nil, errPlist
			}
			v, err := p.object(vr, depth+1)
			if err != nil {
				return nil, err
			}
			out[ks] = v
		}
		return out, nil
	}
	return nil, errPlist
}

// charge takes a string's length from the expansion budget.
func (p *bplist) charge(v string) (any, error) {
	p.textLeft -= int64(len(v))
	if p.textLeft < 0 {
		return nil, errPlist
	}
	return v, nil
}
