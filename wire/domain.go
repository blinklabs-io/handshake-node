// Copyright (c) 2024-2025 The blinklabs-io developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.
//
// Portions of this file are derived from cdnsd
// (https://github.com/blinklabs-io/cdnsd) handshake/domain.go, which is
// Copyright 2025 Blink Labs Software and licensed under the MIT license.
// The cdnsd code was itself ported from hsd/hnsd.

package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
)

// DNS name limits per RFC 1035.  Handshake follows the same bounds.
const (
	// DnsMaxName is the maximum length of an encoded DNS name in bytes.
	DnsMaxName = 255

	// DnsMaxLabel is the maximum length of a single DNS label in bytes.
	DnsMaxLabel = 63
)

// Handshake DNS resource record type identifiers.  These are the 1-byte tags
// that prefix each record inside a DomainResourceData blob.
const (
	// RecordTypeDS is the DNSSEC delegation signer record.
	RecordTypeDS uint8 = 0

	// RecordTypeNS is a nameserver record.
	RecordTypeNS uint8 = 1

	// RecordTypeGLUE4 is an IPv4 glue record (nameserver + A address).
	RecordTypeGLUE4 uint8 = 2

	// RecordTypeGLUE6 is an IPv6 glue record (nameserver + AAAA address).
	RecordTypeGLUE6 uint8 = 3

	// RecordTypeSYNTH4 is a synthesized IPv4 record.
	RecordTypeSYNTH4 uint8 = 4

	// RecordTypeSYNTH6 is a synthesized IPv6 record.
	RecordTypeSYNTH6 uint8 = 5

	// RecordTypeTEXT is a TXT record.
	RecordTypeTEXT uint8 = 6
)

// maxTextItems is the maximum number of strings a TEXT record may contain.
// The count is encoded as a single byte.
const maxTextItems = 255

// maxTextItemSize is the maximum size of a single TEXT item.  The size is
// encoded as a single byte.
const maxTextItemSize = 255

// maxDsDigestSize is the maximum size of a DS record digest.  The size is
// encoded as a single byte.
const maxDsDigestSize = 255

// DomainResourceData is the parsed form of the resource-record payload
// carried by Handshake name covenants (e.g. the UPDATE covenant).  It holds
// the protocol version byte followed by a list of DNS-style records.
//
// Wire format:
//
//	version(1 byte) + concatenated records
//
// Each record begins with a 1-byte type tag; records continue until the
// stream is exhausted or an unknown record type is encountered.  To match
// hsd's behavior, decoding is lenient: if the stream ends mid-record or an
// unknown type appears, the records successfully parsed so far are retained
// and no error is returned.
type DomainResourceData struct {
	Version uint8
	Records []DomainRecord
}

// DomainRecord is implemented by every Handshake DNS resource record type
// carried inside a DomainResourceData payload.
type DomainRecord interface {
	// Type returns the 1-byte record type tag.
	Type() uint8

	// encode serializes the record body (without the type tag) to w.
	encode(w io.Writer) error

	// decode deserializes the record body (without the type tag) from r.
	decode(r *domainReader) error

	// serializeSize returns the number of bytes the record body occupies
	// on the wire (without the type tag).
	serializeSize() int
}

// Encode serializes the resource data to w in Handshake wire format.
//
// Records are written uncompressed.  The decoder accepts both compressed and
// uncompressed forms, so round-trips through Encode/Decode are lossless for
// record contents even when the input used name compression.
func (d *DomainResourceData) Encode(w io.Writer) error {
	if err := binary.Write(w, binary.LittleEndian, d.Version); err != nil {
		return err
	}
	for i, record := range d.Records {
		if record == nil {
			return messageError("DomainResourceData.Encode",
				fmt.Sprintf("record %d is nil", i))
		}
		if err := binary.Write(w, binary.LittleEndian, record.Type()); err != nil {
			return err
		}
		if err := record.encode(w); err != nil {
			return err
		}
	}
	return nil
}

// Decode deserializes resource data from r.
//
// The entire reader contents are consumed because Handshake DNS name
// compression references earlier byte offsets in the blob; random access
// to the original buffer is required to resolve pointers.  Callers should
// pass a reader that supplies exactly one resource-data payload.
func (d *DomainResourceData) Decode(r io.Reader) error {
	buf, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	return d.decodeBytes(buf)
}

// SerializeSize returns the number of bytes needed to serialize the resource
// data in uncompressed form (matching what Encode produces).
func (d *DomainResourceData) SerializeSize() int {
	n := 1 // version
	for _, record := range d.Records {
		if record == nil {
			continue
		}
		n += 1 + record.serializeSize() // type + body
	}
	return n
}

// NewDomainResourceDataFromBytes parses a DomainResourceData from a byte
// slice.  This mirrors the constructor from cdnsd for convenience.
func NewDomainResourceDataFromBytes(data []byte) (*DomainResourceData, error) {
	d := &DomainResourceData{}
	if err := d.decodeBytes(data); err != nil {
		return nil, err
	}
	return d, nil
}

// decodeBytes parses resource data from a complete byte slice.  A shared
// original-buffer reference is threaded through a domainReader so that
// compressed name pointers can hop back to earlier offsets.
func (d *DomainResourceData) decodeBytes(data []byte) error {
	r := newDomainReader(data)
	// Version
	if err := binary.Read(r, binary.LittleEndian, &d.Version); err != nil {
		return fmt.Errorf("read version: %w", err)
	}
	// Records
	var recordType uint8
	d.Records = nil
recordLoop:
	for {
		if err := binary.Read(r, binary.LittleEndian, &recordType); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("read record type: %w", err)
		}
		var record DomainRecord
		switch recordType {
		case RecordTypeDS:
			record = &DsDomainRecord{}
		case RecordTypeNS:
			record = &NsDomainRecord{}
		case RecordTypeGLUE4:
			record = &Glue4DomainRecord{}
		case RecordTypeGLUE6:
			record = &Glue6DomainRecord{}
		case RecordTypeSYNTH4:
			record = &Synth4DomainRecord{}
		case RecordTypeSYNTH6:
			record = &Synth6DomainRecord{}
		case RecordTypeTEXT:
			record = &TextDomainRecord{}
		default:
			// Unknown record type: stop cleanly, matching hsd.
			break recordLoop
		}
		if err := record.decode(r); err != nil {
			// Stop on partial/invalid record.  Retain whatever we
			// parsed so far and return a nil error to match hsd's
			// lenient decode behavior.
			break recordLoop
		}
		d.Records = append(d.Records, record)
	}
	// nolint:nilerr
	return nil
}

// domainReader combines a *bytes.Buffer (which is consumed as records are
// decoded) with a reference to the original byte slice so that DNS name
// compression pointers can rewind to earlier offsets in the buffer.
type domainReader struct {
	*bytes.Buffer
	origBytes []byte
}

func newDomainReader(buf []byte) *domainReader {
	r := &domainReader{
		Buffer: bytes.NewBuffer(buf),
	}
	if buf != nil {
		r.origBytes = make([]byte, len(buf))
		copy(r.origBytes, buf)
	}
	return r
}

// OriginalBytes returns a copy of the byte slice the reader was created from.
// It is used by DNS name decompression to resolve back-pointer offsets.
func (r *domainReader) OriginalBytes() []byte {
	return r.origBytes
}

// Glue4DomainRecord is an IPv4 nameserver glue record: a DNS name bound to
// an IPv4 address.
type Glue4DomainRecord struct {
	Name    string
	Address net.IP
}

// Type returns the record type tag.
func (*Glue4DomainRecord) Type() uint8 { return RecordTypeGLUE4 }

func (g *Glue4DomainRecord) encode(w io.Writer) error {
	if err := encodeDomainName(w, g.Name); err != nil {
		return err
	}
	return encodeIPv4(w, g.Address)
}

func (g *Glue4DomainRecord) decode(r *domainReader) error {
	name, err := decodeDomainName(r)
	if err != nil {
		return err
	}
	g.Name = name
	addr, err := decodeIPv4(r)
	if err != nil {
		return err
	}
	g.Address = addr
	return nil
}

func (g *Glue4DomainRecord) serializeSize() int {
	return domainNameSerializeSize(g.Name) + net.IPv4len
}

// Glue6DomainRecord is an IPv6 nameserver glue record: a DNS name bound to
// an IPv6 address.
type Glue6DomainRecord struct {
	Name    string
	Address net.IP
}

// Type returns the record type tag.
func (*Glue6DomainRecord) Type() uint8 { return RecordTypeGLUE6 }

func (g *Glue6DomainRecord) encode(w io.Writer) error {
	if err := encodeDomainName(w, g.Name); err != nil {
		return err
	}
	return encodeIPv6(w, g.Address)
}

func (g *Glue6DomainRecord) decode(r *domainReader) error {
	name, err := decodeDomainName(r)
	if err != nil {
		return err
	}
	g.Name = name
	addr, err := decodeIPv6(r)
	if err != nil {
		return err
	}
	g.Address = addr
	return nil
}

func (g *Glue6DomainRecord) serializeSize() int {
	return domainNameSerializeSize(g.Name) + net.IPv6len
}

// NsDomainRecord is a nameserver record: a DNS name with no address.
type NsDomainRecord struct {
	Name string
}

// Type returns the record type tag.
func (*NsDomainRecord) Type() uint8 { return RecordTypeNS }

func (n *NsDomainRecord) encode(w io.Writer) error {
	return encodeDomainName(w, n.Name)
}

func (n *NsDomainRecord) decode(r *domainReader) error {
	name, err := decodeDomainName(r)
	if err != nil {
		return err
	}
	n.Name = name
	return nil
}

func (n *NsDomainRecord) serializeSize() int {
	return domainNameSerializeSize(n.Name)
}

// DsDomainRecord is a DNSSEC Delegation Signer record.
type DsDomainRecord struct {
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     []byte
}

// Type returns the record type tag.
func (*DsDomainRecord) Type() uint8 { return RecordTypeDS }

func (d *DsDomainRecord) encode(w io.Writer) error {
	if len(d.Digest) > maxDsDigestSize {
		return messageError("DsDomainRecord.encode",
			fmt.Sprintf("digest length %d exceeds max %d",
				len(d.Digest), maxDsDigestSize))
	}
	// Note: KeyTag is BigEndian; everything else is LittleEndian.
	if err := binary.Write(w, binary.BigEndian, d.KeyTag); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, d.Algorithm); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, d.DigestType); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, uint8(len(d.Digest))); err != nil {
		return err
	}
	_, err := w.Write(d.Digest)
	return err
}

func (d *DsDomainRecord) decode(r *domainReader) error {
	if err := binary.Read(r, binary.BigEndian, &d.KeyTag); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &d.Algorithm); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &d.DigestType); err != nil {
		return err
	}
	var size uint8
	if err := binary.Read(r, binary.LittleEndian, &size); err != nil {
		return err
	}
	d.Digest = make([]byte, size)
	if _, err := io.ReadFull(r, d.Digest); err != nil {
		return err
	}
	return nil
}

func (d *DsDomainRecord) serializeSize() int {
	// keyTag(2) + algo(1) + digestType(1) + digestLen(1) + digest
	return 5 + len(d.Digest)
}

// Synth4DomainRecord is a synthesized IPv4 record, consisting only of an
// address with no name.
type Synth4DomainRecord struct {
	Address net.IP
}

// Type returns the record type tag.
func (*Synth4DomainRecord) Type() uint8 { return RecordTypeSYNTH4 }

func (s *Synth4DomainRecord) encode(w io.Writer) error {
	return encodeIPv4(w, s.Address)
}

func (s *Synth4DomainRecord) decode(r *domainReader) error {
	addr, err := decodeIPv4(r)
	if err != nil {
		return err
	}
	s.Address = addr
	return nil
}

func (s *Synth4DomainRecord) serializeSize() int { return net.IPv4len }

// Synth6DomainRecord is a synthesized IPv6 record, consisting only of an
// address with no name.
type Synth6DomainRecord struct {
	Address net.IP
}

// Type returns the record type tag.
func (*Synth6DomainRecord) Type() uint8 { return RecordTypeSYNTH6 }

func (s *Synth6DomainRecord) encode(w io.Writer) error {
	return encodeIPv6(w, s.Address)
}

func (s *Synth6DomainRecord) decode(r *domainReader) error {
	addr, err := decodeIPv6(r)
	if err != nil {
		return err
	}
	s.Address = addr
	return nil
}

func (s *Synth6DomainRecord) serializeSize() int { return net.IPv6len }

// TextDomainRecord is a TXT record, holding a list of byte strings.  Each
// string and the list itself are limited to 255 entries/bytes by the 1-byte
// length prefixes.
type TextDomainRecord struct {
	Items [][]byte
}

// Type returns the record type tag.
func (*TextDomainRecord) Type() uint8 { return RecordTypeTEXT }

func (t *TextDomainRecord) encode(w io.Writer) error {
	if len(t.Items) > maxTextItems {
		return messageError("TextDomainRecord.encode",
			fmt.Sprintf("item count %d exceeds max %d",
				len(t.Items), maxTextItems))
	}
	for i, item := range t.Items {
		if len(item) > maxTextItemSize {
			return messageError("TextDomainRecord.encode",
				fmt.Sprintf("item %d size %d exceeds max %d",
					i, len(item), maxTextItemSize))
		}
	}
	if err := binary.Write(w, binary.LittleEndian, uint8(len(t.Items))); err != nil {
		return err
	}
	for _, item := range t.Items {
		if err := binary.Write(w, binary.LittleEndian, uint8(len(item))); err != nil {
			return err
		}
		if _, err := w.Write(item); err != nil {
			return err
		}
	}
	return nil
}

func (t *TextDomainRecord) decode(r *domainReader) error {
	var length uint8
	if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
		return err
	}
	t.Items = nil
	for range int(length) {
		var size uint8
		if err := binary.Read(r, binary.LittleEndian, &size); err != nil {
			return err
		}
		buf := make([]byte, size)
		if _, err := io.ReadFull(r, buf); err != nil {
			return err
		}
		t.Items = append(t.Items, buf)
	}
	return nil
}

func (t *TextDomainRecord) serializeSize() int {
	n := 1 // item count
	for _, item := range t.Items {
		n += 1 + len(item) // item length + item bytes
	}
	return n
}

// encodeIPv4 writes a 4-byte IPv4 address to w.  A nil/empty address is
// treated as all-zeros for forgiving encoding; callers that need strict
// validation should check up front.
func encodeIPv4(w io.Writer, ip net.IP) error {
	var buf [net.IPv4len]byte
	if v4 := ip.To4(); v4 != nil {
		copy(buf[:], v4)
	} else if len(ip) == net.IPv4len {
		copy(buf[:], ip)
	} else if ip != nil {
		return messageError("encodeIPv4",
			fmt.Sprintf("address %q is not a valid IPv4", ip))
	}
	_, err := w.Write(buf[:])
	return err
}

// encodeIPv6 writes a 16-byte IPv6 address to w.
func encodeIPv6(w io.Writer, ip net.IP) error {
	var buf [net.IPv6len]byte
	if len(ip) == net.IPv6len {
		copy(buf[:], ip)
	} else if v4 := ip.To4(); v4 != nil {
		// Map an IPv4 address to IPv4-in-IPv6 form.  Unusual but
		// permitted so callers don't have to manually convert.
		copy(buf[:], ip.To16())
	} else if ip != nil {
		return messageError("encodeIPv6",
			fmt.Sprintf("address %q is not a valid IPv6", ip))
	}
	_, err := w.Write(buf[:])
	return err
}

func decodeIPv4(r *domainReader) (net.IP, error) {
	buf := make([]byte, net.IPv4len)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return net.IP(buf), nil
}

func decodeIPv6(r *domainReader) (net.IP, error) {
	buf := make([]byte, net.IPv6len)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return net.IP(buf), nil
}

// encodeDomainName writes a DNS name to w in uncompressed form (a sequence
// of length-prefixed labels terminated by a zero byte).  The trailing dot
// on the input string (if any) is ignored; an empty input produces just the
// terminator.
func encodeDomainName(w io.Writer, name string) error {
	// Strip trailing dot for label walking, but remember that an empty
	// name still gets a lone terminator.
	trimmed := strings.TrimSuffix(name, ".")
	var total int
	if trimmed != "" {
		labels := strings.Split(trimmed, ".")
		for _, label := range labels {
			if len(label) == 0 {
				return messageError("encodeDomainName",
					"empty label in name")
			}
			if len(label) > DnsMaxLabel {
				return messageError("encodeDomainName",
					fmt.Sprintf("label %q length %d exceeds max %d",
						label, len(label), DnsMaxLabel))
			}
			total += 1 + len(label)
			if total+1 > DnsMaxName { // +1 for terminator
				return messageError("encodeDomainName",
					fmt.Sprintf("name %q exceeds max length %d",
						name, DnsMaxName))
			}
			if err := binary.Write(w, binary.LittleEndian, uint8(len(label))); err != nil {
				return err
			}
			if _, err := io.WriteString(w, label); err != nil {
				return err
			}
		}
	}
	// Terminator.
	_, err := w.Write([]byte{0x00})
	return err
}

// domainNameSerializeSize returns the uncompressed serialized length of a
// DNS name in the Handshake wire format.  It mirrors encodeDomainName.
func domainNameSerializeSize(name string) int {
	trimmed := strings.TrimSuffix(name, ".")
	if trimmed == "" {
		return 1 // just the terminator
	}
	n := 1 // terminator
	for _, label := range strings.Split(trimmed, ".") {
		n += 1 + len(label)
	}
	return n
}

// decodeDomainName reads a Handshake-encoded DNS name from r, resolving
// back-pointer compression against the reader's original byte slice.
//
// Handshake's encoding is similar to RFC 1035 but differs in two notable
// ways:
//
//  1. A pointer byte with the top two bits set (0xc0) is followed by a
//     single byte; the full 14-bit offset is `((c ^ 0xc0) << 8) | c1`,
//     measured from the start of the containing resource-data blob (not
//     the start of the current record).
//
//  2. Labels containing raw NUL (0x00) or '.' (0x2e) bytes are remapped
//     to 0xff and 0xfe respectively during decoding so the resulting
//     dotted-string representation cannot be ambiguous.  This matches
//     hnsd.
//
// Because pointer resolution requires random access, the underlying buffer
// is rewound via domainReader.OriginalBytes().
func decodeDomainName(r *domainReader) (string, error) {
	var sb strings.Builder
	hops := 0
	for {
		c, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		if c == 0x00 {
			break
		}
		switch c & 0xc0 {
		case 0x00:
			if c > DnsMaxLabel {
				return "", errors.New("label too long")
			}
			for range int(c) {
				b, err := r.ReadByte()
				if err != nil {
					return "", err
				}
				// Replace NUL and '.' to avoid ambiguous
				// dotted-string output.
				if b == 0x00 {
					b = 0xff
				}
				if b == 0x2e {
					b = 0xfe
				}
				sb.WriteByte(b)
			}
			if sb.Len() > 0 {
				sb.WriteByte('.')
			}
			if sb.Len() > DnsMaxName {
				return "", errors.New("name too long")
			}
		case 0xc0:
			// Pointer: read low byte, jump to absolute offset in
			// the original buffer, and continue reading from
			// there.
			c1, err := r.ReadByte()
			if err != nil {
				return "", err
			}
			// Cap pointer hops so circular references (e.g. a
			// pointer that resolves to itself) cannot loop
			// forever without ever appending a label.
			hops++
			if hops > DnsMaxName {
				return "", errors.New("too many name pointer hops")
			}
			offset := (int(c^0xc0) << 8) | int(c1)
			data := r.OriginalBytes()
			if offset >= len(data) {
				return "", errors.New("name pointer out of range")
			}
			r = newDomainReader(data)
			for range offset {
				if _, err := r.ReadByte(); err != nil {
					return "", err
				}
			}
		default:
			return "", errors.New("unexpected value")
		}
	}
	return sb.String(), nil
}
