// Copyright (c) 2024-2025 The blinklabs-io developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"testing"
)

// TestCovenantEncodeDecode tests round-trip encoding and decoding of
// covenants with various item counts.
func TestCovenantEncodeDecode(t *testing.T) {
	tests := []struct {
		name     string
		covenant *Covenant
	}{
		{
			name:     "NONE covenant with 0 items",
			covenant: NewCovenant(CovenantNone, nil),
		},
		{
			name: "OPEN covenant with 1 item",
			covenant: NewCovenant(CovenantOpen, [][]byte{
				{0xab, 0xcd, 0xef, 0x01},
			}),
		},
		{
			name: "BID covenant with 5 items",
			covenant: NewCovenant(CovenantBid, [][]byte{
				{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
					0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
					0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
					0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20},
				{0x00, 0x00, 0x01, 0x00},
				{0x74, 0x65, 0x73, 0x74}, // "test"
				{0xde, 0xad, 0xbe, 0xef},
				{0xff},
			}),
		},
		{
			name:     "NONE covenant with empty items slice",
			covenant: NewCovenant(CovenantNone, [][]byte{}),
		},
		{
			name: "REGISTER covenant with empty item",
			covenant: NewCovenant(CovenantRegister, [][]byte{
				{},
				{0x01, 0x02},
			}),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var buf bytes.Buffer

			// Encode.
			err := test.covenant.Encode(&buf)
			if err != nil {
				t.Fatalf("Encode: unexpected error: %v", err)
			}

			// Decode.
			var decoded Covenant
			err = decoded.Decode(&buf)
			if err != nil {
				t.Fatalf("Decode: unexpected error: %v", err)
			}

			// Verify type.
			if decoded.Type != test.covenant.Type {
				t.Errorf("Type mismatch: got %d, want %d",
					decoded.Type, test.covenant.Type)
			}

			// Verify item count.
			wantLen := len(test.covenant.Items)
			if len(decoded.Items) != wantLen {
				t.Fatalf("Items length mismatch: got %d, want %d",
					len(decoded.Items), wantLen)
			}

			// Verify each item.
			for i := range decoded.Items {
				if !bytes.Equal(decoded.Items[i], test.covenant.Items[i]) {
					t.Errorf("Item[%d] mismatch: got %x, want %x",
						i, decoded.Items[i],
						test.covenant.Items[i])
				}
			}
		})
	}
}

// TestCovenantEncodeValidation verifies that Encode rejects covenants that
// exceed protocol limits, mirroring the checks in Decode.
func TestCovenantEncodeValidation(t *testing.T) {
	t.Run("too many items", func(t *testing.T) {
		items := make([][]byte, maxCovenantItems+1)
		for i := range items {
			items[i] = []byte{0x00}
		}
		c := NewCovenant(CovenantNone, items)

		var buf bytes.Buffer
		err := c.Encode(&buf)
		if err == nil {
			t.Fatal("Encode: expected error for too many items, got nil")
		}
	})

	t.Run("item too large", func(t *testing.T) {
		c := NewCovenant(CovenantOpen, [][]byte{
			make([]byte, maxCovenantItemSize+1),
		})

		var buf bytes.Buffer
		err := c.Encode(&buf)
		if err == nil {
			t.Fatal("Encode: expected error for oversized item, got nil")
		}
	})

	t.Run("max items allowed", func(t *testing.T) {
		items := make([][]byte, maxCovenantItems)
		for i := range items {
			items[i] = []byte{0x00}
		}
		c := NewCovenant(CovenantNone, items)

		var buf bytes.Buffer
		err := c.Encode(&buf)
		if err != nil {
			t.Fatalf("Encode: unexpected error for max items: %v", err)
		}
	})

	t.Run("max item size allowed", func(t *testing.T) {
		c := NewCovenant(CovenantOpen, [][]byte{
			make([]byte, maxCovenantItemSize),
		})

		var buf bytes.Buffer
		err := c.Encode(&buf)
		if err != nil {
			t.Fatalf("Encode: unexpected error for max item size: %v",
				err)
		}
	})
}

// TestCovenantSerializeSize verifies that SerializeSize matches the actual
// encoded length for various covenants.
func TestCovenantSerializeSize(t *testing.T) {
	tests := []struct {
		name     string
		covenant *Covenant
	}{
		{
			name:     "NONE with no items",
			covenant: NewCovenant(CovenantNone, nil),
		},
		{
			name: "OPEN with 3 items",
			covenant: NewCovenant(CovenantOpen, [][]byte{
				make([]byte, 32),
				{0x00, 0x00, 0x00, 0x00},
				{0x74, 0x65, 0x73, 0x74},
			}),
		},
		{
			name: "BID with large item",
			covenant: NewCovenant(CovenantBid, [][]byte{
				make([]byte, 256),
			}),
		},
		{
			name:     "NONE with empty items slice",
			covenant: NewCovenant(CovenantNone, [][]byte{}),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := test.covenant.Encode(&buf)
			if err != nil {
				t.Fatalf("Encode: unexpected error: %v", err)
			}

			actualSize := buf.Len()
			computedSize := test.covenant.SerializeSize()
			if computedSize != actualSize {
				t.Errorf("SerializeSize mismatch: computed %d, "+
					"actual %d", computedSize, actualSize)
			}
		})
	}
}

// TestCovenantString verifies the human-readable name for all 12 covenant
// types.
func TestCovenantString(t *testing.T) {
	tests := []struct {
		typ  uint8
		want string
	}{
		{CovenantNone, "NONE"},
		{CovenantClaim, "CLAIM"},
		{CovenantOpen, "OPEN"},
		{CovenantBid, "BID"},
		{CovenantReveal, "REVEAL"},
		{CovenantRedeem, "REDEEM"},
		{CovenantRegister, "REGISTER"},
		{CovenantUpdate, "UPDATE"},
		{CovenantRenew, "RENEW"},
		{CovenantTransfer, "TRANSFER"},
		{CovenantFinalize, "FINALIZE"},
		{CovenantRevoke, "REVOKE"},
	}

	for _, test := range tests {
		c := NewCovenant(test.typ, nil)
		got := c.String()
		if got != test.want {
			t.Errorf("String() for type %d: got %q, want %q",
				test.typ, got, test.want)
		}
	}

	// Verify unknown type produces a reasonable string.
	c := NewCovenant(99, nil)
	got := c.String()
	want := "UNKNOWN(99)"
	if got != want {
		t.Errorf("String() for unknown type: got %q, want %q",
			got, want)
	}
}

// TestAddressEncodeDecode tests round-trip encoding and decoding of addresses
// with both 20-byte and 32-byte hashes at version 0.
func TestAddressEncodeDecode(t *testing.T) {
	tests := []struct {
		name    string
		version uint8
		hash    []byte
	}{
		{
			name:    "version 0 with 20-byte hash",
			version: 0,
			hash: []byte{
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
				0x11, 0x12, 0x13, 0x14,
			},
		},
		{
			name:    "version 0 with 32-byte hash",
			version: 0,
			hash: []byte{
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
				0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
				0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
			},
		},
		{
			name:    "version 1 with 20-byte hash",
			version: 1,
			hash:    make([]byte, 20),
		},
		{
			name:    "version 31 with 2-byte hash (minimum)",
			version: 31,
			hash:    []byte{0xaa, 0xbb},
		},
		{
			name:    "version 5 with 40-byte hash (maximum)",
			version: 5,
			hash:    make([]byte, 40),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			addr, err := NewAddress(test.version, test.hash)
			if err != nil {
				t.Fatalf("NewAddress: unexpected error: %v", err)
			}

			var buf bytes.Buffer
			err = addr.Encode(&buf)
			if err != nil {
				t.Fatalf("Encode: unexpected error: %v", err)
			}

			var decoded Address
			err = decoded.Decode(&buf)
			if err != nil {
				t.Fatalf("Decode: unexpected error: %v", err)
			}

			if decoded.Version != test.version {
				t.Errorf("Version mismatch: got %d, want %d",
					decoded.Version, test.version)
			}

			if !bytes.Equal(decoded.Hash, test.hash) {
				t.Errorf("Hash mismatch: got %x, want %x",
					decoded.Hash, test.hash)
			}
		})
	}
}

// TestAddressSerializeSize verifies that SerializeSize returns the correct
// value for addresses.
func TestAddressSerializeSize(t *testing.T) {
	tests := []struct {
		name    string
		version uint8
		hash    []byte
	}{
		{
			name:    "20-byte hash",
			version: 0,
			hash:    make([]byte, 20),
		},
		{
			name:    "32-byte hash",
			version: 0,
			hash:    make([]byte, 32),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			addr, err := NewAddress(test.version, test.hash)
			if err != nil {
				t.Fatalf("NewAddress: unexpected error: %v", err)
			}

			var buf bytes.Buffer
			err = addr.Encode(&buf)
			if err != nil {
				t.Fatalf("Encode: unexpected error: %v", err)
			}

			want := buf.Len()
			got := addr.SerializeSize()
			if got != want {
				t.Errorf("SerializeSize: got %d, want %d",
					got, want)
			}
		})
	}
}

// TestAddressValidation tests that NewAddress and Decode properly reject
// invalid addresses.
func TestAddressValidation(t *testing.T) {
	tests := []struct {
		name    string
		version uint8
		hash    []byte
	}{
		{
			name:    "version > 31",
			version: 32,
			hash:    make([]byte, 20),
		},
		{
			name:    "hash too short (1 byte)",
			version: 1,
			hash:    []byte{0x01},
		},
		{
			name:    "hash too long (41 bytes)",
			version: 1,
			hash:    make([]byte, 41),
		},
		{
			name:    "version 0 with wrong hash size (16 bytes)",
			version: 0,
			hash:    make([]byte, 16),
		},
		{
			name:    "version 0 with wrong hash size (24 bytes)",
			version: 0,
			hash:    make([]byte, 24),
		},
	}

	for _, test := range tests {
		t.Run("NewAddress/"+test.name, func(t *testing.T) {
			_, err := NewAddress(test.version, test.hash)
			if err == nil {
				t.Fatal("NewAddress: expected error, got nil")
			}
		})
	}

	// Also test Decode rejects invalid wire data.
	decodeTests := []struct {
		name string
		data []byte
	}{
		{
			name: "version > 31",
			data: []byte{32, 20}, // version=32, hashLen=20
		},
		{
			name: "hash too short (1 byte)",
			data: []byte{1, 1}, // version=1, hashLen=1
		},
		{
			name: "hash too long (41 bytes)",
			data: []byte{1, 41}, // version=1, hashLen=41
		},
		{
			name: "version 0 with wrong hash size",
			data: []byte{0, 16}, // version=0, hashLen=16
		},
	}

	for _, test := range decodeTests {
		t.Run("Decode/"+test.name, func(t *testing.T) {
			var addr Address
			err := addr.Decode(bytes.NewReader(test.data))
			if err == nil {
				t.Fatal("Decode: expected error, got nil")
			}
		})
	}

	// Also test Encode rejects invalid addresses.
	for _, test := range tests {
		t.Run("Encode/"+test.name, func(t *testing.T) {
			addr := &Address{
				Version: test.version,
				Hash:    test.hash,
			}
			var buf bytes.Buffer
			err := addr.Encode(&buf)
			if err == nil {
				t.Fatal("Encode: expected error, got nil")
			}
		})
	}
}

// TestAddressWitnessProgram verifies the witness program output for version 0
// addresses.
func TestAddressWitnessProgram(t *testing.T) {
	tests := []struct {
		name    string
		version uint8
		hash    []byte
		want    []byte
	}{
		{
			name:    "v0 20-byte hash",
			version: 0,
			hash: []byte{
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
				0x11, 0x12, 0x13, 0x14,
			},
			want: append([]byte{0x00, 0x14}, // OP_0, len=20
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
				0x11, 0x12, 0x13, 0x14,
			),
		},
		{
			name:    "v0 32-byte hash",
			version: 0,
			hash: []byte{
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
				0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
				0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
			},
			want: append([]byte{0x00, 0x20}, // OP_0, len=32
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
				0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
				0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
			),
		},
		{
			name:    "v1 20-byte hash",
			version: 1,
			hash:    make([]byte, 20),
			want:    append([]byte{0x51, 0x14}, make([]byte, 20)...), // OP_1=0x51, len=20
		},
		{
			name:    "v16 2-byte hash",
			version: 16,
			hash:    []byte{0xaa, 0xbb},
			want:    []byte{0x60, 0x02, 0xaa, 0xbb}, // OP_16=0x60, len=2
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			addr, err := NewAddress(test.version, test.hash)
			if err != nil {
				t.Fatalf("NewAddress: unexpected error: %v", err)
			}

			got := addr.WitnessProgram()
			if !bytes.Equal(got, test.want) {
				t.Errorf("WitnessProgram mismatch:\ngot  %x\nwant %x",
					got, test.want)
			}
		})
	}
}

func TestAddressWitnessProgramCompatibilityBoundary(t *testing.T) {
	hash := []byte{0xaa, 0xbb}
	addr, err := NewAddress(17, hash)
	if err != nil {
		t.Fatalf("NewAddress: unexpected error: %v", err)
	}

	var buf bytes.Buffer
	if err := addr.Encode(&buf); err != nil {
		t.Fatalf("Encode: unexpected error: %v", err)
	}

	var decoded Address
	if err := decoded.Decode(&buf); err != nil {
		t.Fatalf("Decode: unexpected error: %v", err)
	}
	if decoded.Version != 17 || !bytes.Equal(decoded.Hash, hash) {
		t.Fatalf("Decode mismatch: got version=%d hash=%x, want version=17 hash=%x",
			decoded.Version, decoded.Hash, hash)
	}

	program := decoded.WitnessProgram()
	if len(program) == 0 {
		t.Fatal("WitnessProgram returned empty script")
	}
	if program[0] <= 0x60 {
		t.Fatalf("version 17 WitnessProgram first opcode = 0x%02x, want above OP_16",
			program[0])
	}
}
