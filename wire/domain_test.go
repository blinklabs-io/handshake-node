// Copyright (c) 2024-2025 The blinklabs-io developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.
//
// Portions of this file are derived from cdnsd
// (https://github.com/blinklabs-io/cdnsd) handshake/domain_test.go, which is
// Copyright 2025 Blink Labs Software and licensed under the MIT license.

package wire

import (
	"bytes"
	"net"
	"reflect"
	"testing"
)

// TestDomainResourceDataDecodeMainnet decodes the resource-data blob from
// Handshake mainnet transaction
// 63ba84b6362724aa8fd484d3616c8d1bdea68240c8e0cd6a104fcf85a35d52fb and
// verifies every record matches the expected struct.
//
// This test vector exercises DNS name compression: the NS records use
// pointers back to the glue record names earlier in the buffer.
func TestDomainResourceDataDecodeMainnet(t *testing.T) {
	// From cdnsd handshake/domain_test.go.
	testBytes := hexToBytes(
		"0002036e73310a69727677696c6c69616d002ce706b701c00202036e7332c00636d688f601c01a00d5580d0114402ed0125506f35ba249265f39b988d7028a28c300d5580d02200c6c45064c26b529b4ac074dff5de60a99d6025d5b0d7f32c2b8c7d40ec8b3de00d5580d043071cb0417852b08b965413f3b871b033996159d121a585e35111a335d4cfb79b67e49a99c3829f6a1f42e100f7f33d7d9",
	)
	expected := &DomainResourceData{
		Version: 0,
		Records: []DomainRecord{
			&Glue4DomainRecord{
				Name:    "ns1.irvwilliam.",
				Address: net.ParseIP("44.231.6.183").To4(),
			},
			&NsDomainRecord{
				Name: "ns1.irvwilliam.",
			},
			&Glue4DomainRecord{
				Name:    "ns2.irvwilliam.",
				Address: net.ParseIP("54.214.136.246").To4(),
			},
			&NsDomainRecord{
				Name: "ns2.irvwilliam.",
			},
			&DsDomainRecord{
				KeyTag:     54616,
				Algorithm:  13,
				DigestType: 1,
				Digest: hexToBytes(
					"402ed0125506f35ba249265f39b988d7028a28c3",
				),
			},
			&DsDomainRecord{
				KeyTag:     54616,
				Algorithm:  13,
				DigestType: 2,
				Digest: hexToBytes(
					"0c6c45064c26b529b4ac074dff5de60a99d6025d5b0d7f32c2b8c7d40ec8b3de",
				),
			},
			&DsDomainRecord{
				KeyTag:     54616,
				Algorithm:  13,
				DigestType: 4,
				Digest: hexToBytes(
					"71cb0417852b08b965413f3b871b033996159d121a585e35111a335d4cfb79b67e49a99c3829f6a1f42e100f7f33d7d9",
				),
			},
		},
	}

	// Decode via Decode(io.Reader).
	var got DomainResourceData
	if err := got.Decode(bytes.NewReader(testBytes)); err != nil {
		t.Fatalf("Decode: unexpected error: %v", err)
	}
	if got.Version != expected.Version {
		t.Fatalf("Version: got %d, want %d",
			got.Version, expected.Version)
	}
	if len(got.Records) != len(expected.Records) {
		t.Fatalf("Records length: got %d, want %d",
			len(got.Records), len(expected.Records))
	}
	for i := range got.Records {
		if !reflect.DeepEqual(got.Records[i], expected.Records[i]) {
			t.Errorf("Records[%d]:\n got: %#v\nwant: %#v",
				i, got.Records[i], expected.Records[i])
		}
	}

	// Also verify NewDomainResourceDataFromBytes returns the same result.
	d, err := NewDomainResourceDataFromBytes(testBytes)
	if err != nil {
		t.Fatalf("NewDomainResourceDataFromBytes: %v", err)
	}
	if len(d.Records) != len(expected.Records) {
		t.Fatalf("NewDomainResourceDataFromBytes records length: got %d, want %d",
			len(d.Records), len(expected.Records))
	}
}

// TestDomainResourceDataRoundTrip verifies that each Handshake resource
// record type survives an encode -> decode cycle via the wire format.  The
// encoder emits DNS names uncompressed so the re-encoded bytes are not
// necessarily identical to any compressed input, but the decoded struct
// must match.
func TestDomainResourceDataRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		data *DomainResourceData
	}{
		{
			name: "empty (version only)",
			data: &DomainResourceData{Version: 0},
		},
		{
			name: "single DS",
			data: &DomainResourceData{
				Version: 0,
				Records: []DomainRecord{
					&DsDomainRecord{
						KeyTag:     0xdead,
						Algorithm:  13,
						DigestType: 2,
						Digest: hexToBytes(
							"0c6c45064c26b529b4ac074dff5de60a99d6025d5b0d7f32c2b8c7d40ec8b3de",
						),
					},
				},
			},
		},
		{
			name: "single NS",
			data: &DomainResourceData{
				Version: 0,
				Records: []DomainRecord{
					&NsDomainRecord{Name: "ns1.example."},
				},
			},
		},
		{
			name: "glue4 + glue6",
			data: &DomainResourceData{
				Version: 0,
				Records: []DomainRecord{
					&Glue4DomainRecord{
						Name:    "ns1.example.",
						Address: net.ParseIP("192.0.2.1").To4(),
					},
					&Glue6DomainRecord{
						Name:    "ns2.example.",
						Address: net.ParseIP("2001:db8::1"),
					},
				},
			},
		},
		{
			name: "synth4 + synth6",
			data: &DomainResourceData{
				Version: 0,
				Records: []DomainRecord{
					&Synth4DomainRecord{
						Address: net.ParseIP("203.0.113.5").To4(),
					},
					&Synth6DomainRecord{
						Address: net.ParseIP("2001:db8::cafe"),
					},
				},
			},
		},
		{
			name: "text single item",
			data: &DomainResourceData{
				Version: 0,
				Records: []DomainRecord{
					&TextDomainRecord{
						Items: [][]byte{
							[]byte("v=spf1 -all"),
						},
					},
				},
			},
		},
		{
			name: "text multi item",
			data: &DomainResourceData{
				Version: 0,
				Records: []DomainRecord{
					&TextDomainRecord{
						Items: [][]byte{
							[]byte("hello"),
							[]byte("world"),
							[]byte(""),
							{0x00, 0x01, 0x02},
						},
					},
				},
			},
		},
		{
			name: "mixed record types (version 1)",
			data: &DomainResourceData{
				Version: 1,
				Records: []DomainRecord{
					&Glue4DomainRecord{
						Name:    "a.b.c.example.",
						Address: net.ParseIP("10.0.0.1").To4(),
					},
					&NsDomainRecord{Name: "ns.example."},
					&TextDomainRecord{
						Items: [][]byte{[]byte("ok")},
					},
					&DsDomainRecord{
						KeyTag:     1,
						Algorithm:  2,
						DigestType: 3,
						Digest:     []byte{0xaa, 0xbb, 0xcc},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Encode to bytes.
			var buf bytes.Buffer
			if err := test.data.Encode(&buf); err != nil {
				t.Fatalf("Encode: unexpected error: %v", err)
			}

			// SerializeSize must match the encoded length.
			if got, want := test.data.SerializeSize(), buf.Len(); got != want {
				t.Errorf("SerializeSize: got %d, want %d",
					got, want)
			}

			// Decode and compare.
			var decoded DomainResourceData
			if err := decoded.Decode(bytes.NewReader(buf.Bytes())); err != nil {
				t.Fatalf("Decode: unexpected error: %v", err)
			}
			if decoded.Version != test.data.Version {
				t.Errorf("Version: got %d, want %d",
					decoded.Version, test.data.Version)
			}
			if len(decoded.Records) != len(test.data.Records) {
				t.Fatalf("Records length: got %d, want %d",
					len(decoded.Records), len(test.data.Records))
			}
			for i := range decoded.Records {
				if !reflect.DeepEqual(decoded.Records[i], test.data.Records[i]) {
					t.Errorf("Records[%d]:\n got: %#v\nwant: %#v",
						i, decoded.Records[i], test.data.Records[i])
				}
			}
		})
	}
}

// TestDomainResourceDataLenientDecode verifies that an unknown trailing
// record type causes decoding to stop without error, retaining the records
// already parsed.  This mirrors hsd's behavior.
func TestDomainResourceDataLenientDecode(t *testing.T) {
	// version=0 + NS("x.") + unknown record type 0xff.
	buf := []byte{
		0x00,       // version
		0x01,       // NS
		0x01, 'x',  // label "x"
		0x00,       // terminator
		0xff,       // unknown record type -> stop
		0xde, 0xad, // trailing junk
	}

	var d DomainResourceData
	if err := d.Decode(bytes.NewReader(buf)); err != nil {
		t.Fatalf("Decode: unexpected error: %v", err)
	}
	if len(d.Records) != 1 {
		t.Fatalf("Records length: got %d, want 1", len(d.Records))
	}
	ns, ok := d.Records[0].(*NsDomainRecord)
	if !ok {
		t.Fatalf("Records[0] wrong type: %T", d.Records[0])
	}
	if ns.Name != "x." {
		t.Errorf("NS name: got %q, want %q", ns.Name, "x.")
	}
}

// TestDomainResourceDataTruncatedRecord verifies that a partially-written
// record at the tail of the stream is swallowed without error (matching the
// lenient cdnsd/hsd behavior), preserving any previously parsed records.
func TestDomainResourceDataTruncatedRecord(t *testing.T) {
	// version=0 + NS("y.") + GLUE4 header but truncated mid-address.
	buf := []byte{
		0x00,       // version
		0x01,       // NS
		0x01, 'y',  // label "y"
		0x00,       // terminator
		0x02,       // GLUE4
		0x01, 'z',  // label "z"
		0x00,       // name terminator
		0x7f, 0x00, // only 2 bytes of what should be a 4-byte IPv4
	}

	var d DomainResourceData
	if err := d.Decode(bytes.NewReader(buf)); err != nil {
		t.Fatalf("Decode: unexpected error: %v", err)
	}
	if len(d.Records) != 1 {
		t.Fatalf("Records length: got %d, want 1", len(d.Records))
	}
}

// TestDomainNameEncodeValidation exercises the input validation of the
// internal encodeDomainName helper via NsDomainRecord.encode.
func TestDomainNameEncodeValidation(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"empty name", "", false},
		{"simple name", "example.", false},
		{"nested name", "a.b.c.d.", false},
		{"no trailing dot", "example", false},
		{
			name:    "label too long",
			input:   string(make([]byte, DnsMaxLabel+1)) + ".",
			wantErr: true,
		},
		{"double dot", "foo..bar.", true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := encodeDomainName(&buf, test.input)
			if test.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !test.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestDomainResourceDataEncodeValidation covers the per-record validation
// paths that reject oversized inputs.
func TestDomainResourceDataEncodeValidation(t *testing.T) {
	t.Run("DS digest too large", func(t *testing.T) {
		d := &DomainResourceData{
			Version: 0,
			Records: []DomainRecord{
				&DsDomainRecord{
					KeyTag:     1,
					Algorithm:  1,
					DigestType: 1,
					Digest:     make([]byte, maxDsDigestSize+1),
				},
			},
		}
		var buf bytes.Buffer
		if err := d.Encode(&buf); err == nil {
			t.Fatal("expected error for oversized digest")
		}
	})

	t.Run("TEXT too many items", func(t *testing.T) {
		items := make([][]byte, maxTextItems+1)
		for i := range items {
			items[i] = []byte{0x00}
		}
		d := &DomainResourceData{
			Version: 0,
			Records: []DomainRecord{
				&TextDomainRecord{Items: items},
			},
		}
		var buf bytes.Buffer
		if err := d.Encode(&buf); err == nil {
			t.Fatal("expected error for too many text items")
		}
	})

	t.Run("TEXT item too large", func(t *testing.T) {
		d := &DomainResourceData{
			Version: 0,
			Records: []DomainRecord{
				&TextDomainRecord{
					Items: [][]byte{
						make([]byte, maxTextItemSize+1),
					},
				},
			},
		}
		var buf bytes.Buffer
		if err := d.Encode(&buf); err == nil {
			t.Fatal("expected error for oversized text item")
		}
	})

	t.Run("nil record", func(t *testing.T) {
		d := &DomainResourceData{
			Version: 0,
			Records: []DomainRecord{nil},
		}
		var buf bytes.Buffer
		if err := d.Encode(&buf); err == nil {
			t.Fatal("expected error for nil record")
		}
	})
}

// TestDecodeDomainNamePointerLoops ensures that circular DNS name
// compression pointers are rejected rather than spinning forever.
func TestDecodeDomainNamePointerLoops(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			// 0xc0 0x00 at offset 0 points back to itself.
			name: "self pointer",
			data: []byte{0xc0, 0x00},
		},
		{
			// Offset 0 points to offset 2, offset 2 points
			// back to offset 0.
			name: "mutual pointers",
			data: []byte{0xc0, 0x02, 0xc0, 0x00},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := newDomainReader(test.data)
			if _, err := decodeDomainName(r); err == nil {
				t.Fatal("expected error for circular pointers, got nil")
			}
		})
	}
}
