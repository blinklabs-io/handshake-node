// Copyright (c) 2013-2016 The btcsuite developers
// Copyright (c) 2025-2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"
	"time"

	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/davecgh/go-spew/spew"
)

// hexToBytes decodes a hex string to bytes, panicking on error.
func hexToBytes(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("invalid hex in test: " + err.Error())
	}
	return b
}

// hexToHash decodes a hex string in raw wire byte order to a chainhash.Hash.
// Handshake hashes are stored and displayed in raw byte order (not reversed
// like Bitcoin's big-endian display convention).
func hexToHash(s string) chainhash.Hash {
	b := hexToBytes(s)
	var h chainhash.Hash
	copy(h[:], b)
	return h
}

// Test vector 1: Handshake mainnet block ~271014.
// First 236 bytes of raw block hex taken directly from cdnsd test vectors.
var testVector1Bytes = hexToBytes(
	// Wire order: Nonce(4) Time(8) PrevBlock(32) NameRoot(32) ExtraNonce(24)
	// ReservedRoot(32) WitnessRoot(32) MerkleRoot(32) Version(4) Bits(4) Mask(32)
	"c29fc32b" +
		"a934ec6700000000" +
		"0000000000000008fb98a534f78c6594b9c5581d6e7ca688efebca93e3567d98" +
		"0b5cc7b8bb7632532df5d5adc0af9f2a830fcb72b2595cd7c4e34e6371465f17" +
		"c907ca66957417a200000000000000000000000000000000" +
		"0000000000000000000000000000000000000000000000000000000000000000" +
		"45779eb2591efda24b4e502cb186d6b7b3d786bb8b247180205b8e8edc70ec6c" +
		"7daf23875654e512d4235898dfda96202d6a11f0314945c9835f60b8d14a64cc" +
		"00000000" +
		"70930919" +
		"0000000000000000000000000000000000000000000000000000000000000000",
)

// Test vector 2: early Handshake mainnet block.
// First 236 bytes of raw block hex taken directly from cdnsd test vectors.
var testVector2Bytes = hexToBytes(
	"e10afe1d" +
		"0575465e00000000" +
		"0000000000000660013cac2e01c211a6c1035f31395126c4ed9d6d0f9c8b01b9" +
		"0000000000000000000000000000000000000000000000000000000000000000" +
		"00001cb89fa82d7900000000000000000000000000000000" +
		"0000000000000000000000000000000000000000000000000000000000000000" +
		"f154361b707effe251bea1832f6406808b6cbfe0e66545ac8bd24d34d48df318" +
		"c55e70b65ad508c302b8de3b1801978d6c2c6a977a1fe092931f1233303d37c6" +
		"01000000" +
		"9a80081a" +
		"0000000000000000000000000000000000000000000000000000000000000000",
)

// TestBlockHeader tests the BlockHeader API with the new Handshake signature.
func TestBlockHeader(t *testing.T) {
	nonce64, err := RandomUint64()
	if err != nil {
		t.Fatalf("RandomUint64: Error generating nonce: %v", err)
	}
	nonce := uint32(nonce64)

	prevHash := hexToHash("0000000000000008fb98a534f78c6594b9c5581d6e7ca688efebca93e3567d98")
	merkleHash := hexToHash("7daf23875654e512d4235898dfda96202d6a11f0314945c9835f60b8d14a64cc")
	nameRoot := hexToHash("0b5cc7b8bb7632532df5d5adc0af9f2a830fcb72b2595cd7c4e34e6371465f17")
	witnessRoot := hexToHash("45779eb2591efda24b4e502cb186d6b7b3d786bb8b247180205b8e8edc70ec6c")
	bits := uint32(0x19099370)

	bh := NewBlockHeader(0, &prevHash, &merkleHash, &nameRoot, &witnessRoot, bits, nonce)

	// Ensure we get the same data back out.
	if !bh.PrevBlock.IsEqual(&prevHash) {
		t.Errorf("NewBlockHeader: wrong prev hash - got %v, want %v",
			spew.Sprint(bh.PrevBlock), spew.Sprint(prevHash))
	}
	if !bh.MerkleRoot.IsEqual(&merkleHash) {
		t.Errorf("NewBlockHeader: wrong merkle root - got %v, want %v",
			spew.Sprint(bh.MerkleRoot), spew.Sprint(merkleHash))
	}
	if !bh.NameRoot.IsEqual(&nameRoot) {
		t.Errorf("NewBlockHeader: wrong name root - got %v, want %v",
			spew.Sprint(bh.NameRoot), spew.Sprint(nameRoot))
	}
	if !bh.WitnessRoot.IsEqual(&witnessRoot) {
		t.Errorf("NewBlockHeader: wrong witness root - got %v, want %v",
			spew.Sprint(bh.WitnessRoot), spew.Sprint(witnessRoot))
	}
	if bh.Bits != bits {
		t.Errorf("NewBlockHeader: wrong bits - got %v, want %v",
			bh.Bits, bits)
	}
	if bh.Nonce != nonce {
		t.Errorf("NewBlockHeader: wrong nonce - got %v, want %v",
			bh.Nonce, nonce)
	}
}

// TestBlockHeaderWire tests the BlockHeader wire encode and decode for
// Handshake's 236-byte header format.
func TestBlockHeaderWire(t *testing.T) {
	pver := uint32(70001)

	// Decode test vector 1 to build the expected header.
	var expectedHdr1 BlockHeader
	rbuf := bytes.NewReader(testVector1Bytes)
	err := readBlockHeader(rbuf, 0, &expectedHdr1)
	if err != nil {
		t.Fatalf("failed to decode test vector 1: %v", err)
	}

	// Verify key decoded fields.
	if expectedHdr1.Nonce != 734240706 {
		t.Errorf("vector 1 Nonce: got %d, want 734240706", expectedHdr1.Nonce)
	}
	if expectedHdr1.Timestamp.Unix() != 1743533225 {
		t.Errorf("vector 1 Time: got %d, want 1743533225", expectedHdr1.Timestamp.Unix())
	}
	if expectedHdr1.Version != 0 {
		t.Errorf("vector 1 Version: got %d, want 0", expectedHdr1.Version)
	}
	if expectedHdr1.Bits != 420057968 {
		t.Errorf("vector 1 Bits: got %d, want 420057968", expectedHdr1.Bits)
	}

	tests := []struct {
		in   *BlockHeader    // Data to encode
		out  *BlockHeader    // Expected decoded data
		buf  []byte          // Wire encoding
		pver uint32          // Protocol version for wire encoding
		enc  MessageEncoding // Message encoding variant to use
	}{
		{
			&expectedHdr1,
			&expectedHdr1,
			testVector1Bytes,
			ProtocolVersion,
			BaseEncoding,
		},
		{
			&expectedHdr1,
			&expectedHdr1,
			testVector1Bytes,
			pver,
			BaseEncoding,
		},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// Encode to wire format.
		var buf bytes.Buffer
		err := writeBlockHeader(&buf, test.pver, test.in)
		if err != nil {
			t.Errorf("writeBlockHeader #%d error %v", i, err)
			continue
		}
		if !bytes.Equal(buf.Bytes(), test.buf) {
			t.Errorf("writeBlockHeader #%d\n got: %s want: %s", i,
				spew.Sdump(buf.Bytes()), spew.Sdump(test.buf))
			continue
		}

		buf.Reset()
		err = test.in.BtcEncode(&buf, pver, 0)
		if err != nil {
			t.Errorf("BtcEncode #%d error %v", i, err)
			continue
		}
		if !bytes.Equal(buf.Bytes(), test.buf) {
			t.Errorf("BtcEncode #%d\n got: %s want: %s", i,
				spew.Sdump(buf.Bytes()), spew.Sdump(test.buf))
			continue
		}

		// Decode the block header from wire format.
		var bh BlockHeader
		rbuf := bytes.NewReader(test.buf)
		err = readBlockHeader(rbuf, test.pver, &bh)
		if err != nil {
			t.Errorf("readBlockHeader #%d error %v", i, err)
			continue
		}
		if !reflect.DeepEqual(&bh, test.out) {
			t.Errorf("readBlockHeader #%d\n got: %s want: %s", i,
				spew.Sdump(&bh), spew.Sdump(test.out))
			continue
		}

		rbuf = bytes.NewReader(test.buf)
		err = bh.BtcDecode(rbuf, pver, test.enc)
		if err != nil {
			t.Errorf("BtcDecode #%d error %v", i, err)
			continue
		}
		if !reflect.DeepEqual(&bh, test.out) {
			t.Errorf("BtcDecode #%d\n got: %s want: %s", i,
				spew.Sdump(&bh), spew.Sdump(test.out))
			continue
		}
	}
}

// TestBlockHeaderSerialize tests BlockHeader serialize and deserialize.
func TestBlockHeaderSerialize(t *testing.T) {
	// Decode test vector 1 to build the expected header.
	var expectedHdr BlockHeader
	rbuf := bytes.NewReader(testVector1Bytes)
	err := readBlockHeader(rbuf, 0, &expectedHdr)
	if err != nil {
		t.Fatalf("failed to decode test vector 1: %v", err)
	}

	tests := []struct {
		in  *BlockHeader // Data to encode
		out *BlockHeader // Expected decoded data
		buf []byte       // Serialized data
	}{
		{
			&expectedHdr,
			&expectedHdr,
			testVector1Bytes,
		},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// Serialize the block header.
		var buf bytes.Buffer
		err := test.in.Serialize(&buf)
		if err != nil {
			t.Errorf("Serialize #%d error %v", i, err)
			continue
		}
		if !bytes.Equal(buf.Bytes(), test.buf) {
			t.Errorf("Serialize #%d\n got: %s want: %s", i,
				spew.Sdump(buf.Bytes()), spew.Sdump(test.buf))
			continue
		}

		// Deserialize the block header.
		var bh BlockHeader
		rbuf := bytes.NewReader(test.buf)
		err = bh.Deserialize(rbuf)
		if err != nil {
			t.Errorf("Deserialize #%d error %v", i, err)
			continue
		}
		if !reflect.DeepEqual(&bh, test.out) {
			t.Errorf("Deserialize #%d\n got: %s want: %s", i,
				spew.Sdump(&bh), spew.Sdump(test.out))
			continue
		}
	}
}

// TestBlockHeaderPoWHash tests that BlockHash() produces the correct PoW hash
// for known Handshake mainnet blocks.
func TestBlockHeaderPoWHash(t *testing.T) {
	tests := []struct {
		name     string
		raw      []byte
		wantHash string // Big-endian display hash
	}{
		{
			name:     "mainnet block ~271014",
			raw:      testVector1Bytes,
			wantHash: "0000000000000000aaeb53f05d5d6f9ec895f3ab7858c8a6b5911e41e410ebc7",
		},
		{
			name:     "early mainnet block",
			raw:      testVector2Bytes,
			wantHash: "0000000000000424ee6c2a5d6e0da5edfc47a4a10328c1792056ee48303c3e40",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var bh BlockHeader
			rbuf := bytes.NewReader(tc.raw)
			err := readBlockHeader(rbuf, 0, &bh)
			if err != nil {
				t.Fatalf("failed to decode header: %v", err)
			}

			gotHash := bh.BlockHash()
			wantHash := hexToHash(tc.wantHash)

			if !gotHash.IsEqual(&wantHash) {
				t.Errorf("BlockHash mismatch:\n  got:  %s\n  want: %s",
					gotHash.String(), wantHash.String())
			}
		})
	}
}

// TestBlockHeaderSize verifies that the header serializes to exactly 236 bytes.
func TestBlockHeaderSize(t *testing.T) {
	var bh BlockHeader
	bh.Timestamp = time.Unix(0, 0)
	var buf bytes.Buffer
	err := bh.Serialize(&buf)
	if err != nil {
		t.Fatalf("Serialize error: %v", err)
	}
	if buf.Len() != blockHeaderLen {
		t.Errorf("serialized header length = %d, want %d", buf.Len(), blockHeaderLen)
	}
}
