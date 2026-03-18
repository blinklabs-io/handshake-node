// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"compress/bzip2"
	"fmt"
	"io"
	"net"
	"os"
	"testing"

	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
)

// genesisCoinbaseTx is a Handshake-style coinbase transaction used for
// benchmarks.
var genesisCoinbaseTx = MsgTx{
	Version: 0,
	TxIn: []*TxIn{
		{
			PreviousOutPoint: OutPoint{
				Hash:  chainhash.Hash{},
				Index: 0xffffffff,
			},
			Sequence: 0xffffffff,
			Witness: [][]byte{
				{0x04, 0xff, 0xff, 0x00, 0x1d, 0x01, 0x04},
			},
		},
	},
	TxOut: []*TxOut{
		{
			Value: 0x12a05f200,
			Address: Address{
				Version: 0,
				Hash: []byte{
					0x96, 0xb5, 0x38, 0xe8, 0x53, 0x51, 0x9c, 0x72,
					0x6a, 0x2c, 0x91, 0xe6, 0x1e, 0xc1, 0x16, 0x00,
					0xae, 0x13, 0x90, 0x81,
				},
			},
			Covenant: Covenant{Type: CovenantNone},
		},
	},
	LockTime: 0,
}

// BenchmarkWriteVarInt1 performs a benchmark on how long it takes to write
// a single byte variable length integer.
func BenchmarkWriteVarInt1(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		WriteVarInt(io.Discard, 0, 1)
	}
}

// BenchmarkWriteVarInt3 performs a benchmark on how long it takes to write
// a three byte variable length integer.
func BenchmarkWriteVarInt3(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		WriteVarInt(io.Discard, 0, 65535)
	}
}

// BenchmarkWriteVarInt5 performs a benchmark on how long it takes to write
// a five byte variable length integer.
func BenchmarkWriteVarInt5(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		WriteVarInt(io.Discard, 0, 4294967295)
	}
}

// BenchmarkWriteVarInt9 performs a benchmark on how long it takes to write
// a nine byte variable length integer.
func BenchmarkWriteVarInt9(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		WriteVarInt(io.Discard, 0, 18446744073709551615)
	}
}

// BenchmarkReadVarInt1 performs a benchmark on how long it takes to read
// a single byte variable length integer.
func BenchmarkReadVarInt1(b *testing.B) {
	b.ReportAllocs()

	buf := []byte{0x01}
	r := bytes.NewReader(buf)
	for i := 0; i < b.N; i++ {
		r.Seek(0, 0)
		ReadVarInt(r, 0)
	}
}

// BenchmarkReadVarInt3 performs a benchmark on how long it takes to read
// a three byte variable length integer.
func BenchmarkReadVarInt3(b *testing.B) {
	b.ReportAllocs()

	buf := []byte{0x0fd, 0xff, 0xff}
	r := bytes.NewReader(buf)
	for i := 0; i < b.N; i++ {
		r.Seek(0, 0)
		ReadVarInt(r, 0)
	}
}

// BenchmarkReadVarInt5 performs a benchmark on how long it takes to read
// a five byte variable length integer.
func BenchmarkReadVarInt5(b *testing.B) {
	b.ReportAllocs()

	buf := []byte{0xfe, 0xff, 0xff, 0xff, 0xff}
	r := bytes.NewReader(buf)
	for i := 0; i < b.N; i++ {
		r.Seek(0, 0)
		ReadVarInt(r, 0)
	}
}

// BenchmarkReadVarInt9 performs a benchmark on how long it takes to read
// a nine byte variable length integer.
func BenchmarkReadVarInt9(b *testing.B) {
	b.ReportAllocs()

	buf := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	r := bytes.NewReader(buf)
	for i := 0; i < b.N; i++ {
		r.Seek(0, 0)
		ReadVarInt(r, 0)
	}
}

// BenchmarkWriteVarIntBuf1 performs a benchmark on how long it takes to write
// a single byte variable length integer.
func BenchmarkWriteVarIntBuf1(b *testing.B) {
	b.ReportAllocs()

	buffer := binarySerializer.Borrow()
	for i := 0; i < b.N; i++ {
		WriteVarIntBuf(io.Discard, 0, 1, buffer)
	}
	binarySerializer.Return(buffer)
}

// BenchmarkWriteVarIntBuf3 performs a benchmark on how long it takes to write
// a three byte variable length integer.
func BenchmarkWriteVarIntBuf3(b *testing.B) {
	b.ReportAllocs()

	buffer := binarySerializer.Borrow()
	for i := 0; i < b.N; i++ {
		WriteVarIntBuf(io.Discard, 0, 65535, buffer)
	}
	binarySerializer.Return(buffer)
}

// BenchmarkWriteVarIntBuf5 performs a benchmark on how long it takes to write
// a five byte variable length integer.
func BenchmarkWriteVarIntBuf5(b *testing.B) {
	b.ReportAllocs()

	buffer := binarySerializer.Borrow()
	for i := 0; i < b.N; i++ {
		WriteVarIntBuf(io.Discard, 0, 4294967295, buffer)
	}
	binarySerializer.Return(buffer)
}

// BenchmarkWriteVarIntBuf9 performs a benchmark on how long it takes to write
// a nine byte variable length integer.
func BenchmarkWriteVarIntBuf9(b *testing.B) {
	b.ReportAllocs()

	buffer := binarySerializer.Borrow()
	for i := 0; i < b.N; i++ {
		WriteVarIntBuf(io.Discard, 0, 18446744073709551615, buffer)
	}
	binarySerializer.Return(buffer)
}

// BenchmarkReadVarIntBuf1 performs a benchmark on how long it takes to read
// a single byte variable length integer.
func BenchmarkReadVarIntBuf1(b *testing.B) {
	b.ReportAllocs()

	buffer := binarySerializer.Borrow()
	buf := []byte{0x01}
	r := bytes.NewReader(buf)
	for i := 0; i < b.N; i++ {
		r.Seek(0, 0)
		ReadVarIntBuf(r, 0, buffer)
	}
	binarySerializer.Return(buffer)
}

// BenchmarkReadVarIntBuf3 performs a benchmark on how long it takes to read
// a three byte variable length integer.
func BenchmarkReadVarIntBuf3(b *testing.B) {
	b.ReportAllocs()

	buffer := binarySerializer.Borrow()
	buf := []byte{0x0fd, 0xff, 0xff}
	r := bytes.NewReader(buf)
	for i := 0; i < b.N; i++ {
		r.Seek(0, 0)
		ReadVarIntBuf(r, 0, buffer)
	}
	binarySerializer.Return(buffer)
}

// BenchmarkReadVarIntBuf5 performs a benchmark on how long it takes to read
// a five byte variable length integer.
func BenchmarkReadVarIntBuf5(b *testing.B) {
	b.ReportAllocs()

	buffer := binarySerializer.Borrow()
	buf := []byte{0xfe, 0xff, 0xff, 0xff, 0xff}
	r := bytes.NewReader(buf)
	for i := 0; i < b.N; i++ {
		r.Seek(0, 0)
		ReadVarIntBuf(r, 0, buffer)
	}
	binarySerializer.Return(buffer)
}

// BenchmarkReadVarIntBuf9 performs a benchmark on how long it takes to read
// a nine byte variable length integer.
func BenchmarkReadVarIntBuf9(b *testing.B) {
	b.ReportAllocs()

	buffer := binarySerializer.Borrow()
	buf := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	r := bytes.NewReader(buf)
	for i := 0; i < b.N; i++ {
		r.Seek(0, 0)
		ReadVarIntBuf(r, 0, buffer)
	}
	binarySerializer.Return(buffer)
}

// BenchmarkReadVarStr4 performs a benchmark on how long it takes to read a
// four byte variable length string.
func BenchmarkReadVarStr4(b *testing.B) {
	b.ReportAllocs()

	buf := []byte{0x04, 't', 'e', 's', 't'}
	r := bytes.NewReader(buf)
	for i := 0; i < b.N; i++ {
		r.Seek(0, 0)
		ReadVarString(r, 0)
	}
}

// BenchmarkReadVarStr10 performs a benchmark on how long it takes to read a
// ten byte variable length string.
func BenchmarkReadVarStr10(b *testing.B) {
	b.ReportAllocs()

	buf := []byte{0x0a, 't', 'e', 's', 't', '0', '1', '2', '3', '4', '5'}
	r := bytes.NewReader(buf)
	for i := 0; i < b.N; i++ {
		r.Seek(0, 0)
		ReadVarString(r, 0)
	}
}

// BenchmarkWriteVarStr4 performs a benchmark on how long it takes to write a
// four byte variable length string.
func BenchmarkWriteVarStr4(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		WriteVarString(io.Discard, 0, "test")
	}
}

// BenchmarkWriteVarStr10 performs a benchmark on how long it takes to write a
// ten byte variable length string.
func BenchmarkWriteVarStr10(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		WriteVarString(io.Discard, 0, "test012345")
	}
}

// BenchmarkReadVarStrBuf4 performs a benchmark on how long it takes to read a
// four byte variable length string.
func BenchmarkReadVarStrBuf4(b *testing.B) {
	b.ReportAllocs()

	buffer := binarySerializer.Borrow()
	buf := []byte{0x04, 't', 'e', 's', 't'}
	r := bytes.NewReader(buf)
	for i := 0; i < b.N; i++ {
		r.Seek(0, 0)
		readVarStringBuf(r, 0, buffer)
	}
	binarySerializer.Return(buffer)
}

// BenchmarkReadVarStrBuf10 performs a benchmark on how long it takes to read a
// ten byte variable length string.
func BenchmarkReadVarStrBuf10(b *testing.B) {
	b.ReportAllocs()

	buffer := binarySerializer.Borrow()
	buf := []byte{0x0a, 't', 'e', 's', 't', '0', '1', '2', '3', '4', '5'}
	r := bytes.NewReader(buf)
	for i := 0; i < b.N; i++ {
		r.Seek(0, 0)
		readVarStringBuf(r, 0, buf)
	}
	binarySerializer.Return(buffer)
}

// BenchmarkWriteVarStrBuf4 performs a benchmark on how long it takes to write a
// four byte variable length string.
func BenchmarkWriteVarStrBuf4(b *testing.B) {
	b.ReportAllocs()

	buf := binarySerializer.Borrow()
	for i := 0; i < b.N; i++ {
		writeVarStringBuf(io.Discard, 0, "test", buf)
	}
	binarySerializer.Return(buf)
}

// BenchmarkWriteVarStrBuf10 performs a benchmark on how long it takes to write
// a ten byte variable length string.
func BenchmarkWriteVarStrBuf10(b *testing.B) {
	b.ReportAllocs()

	buf := binarySerializer.Borrow()
	for i := 0; i < b.N; i++ {
		writeVarStringBuf(io.Discard, 0, "test012345", buf)
	}
	binarySerializer.Return(buf)
}

// BenchmarkReadOutPoint performs a benchmark on how long it takes to read a
// transaction output point.
func BenchmarkReadOutPoint(b *testing.B) {
	b.ReportAllocs()

	buffer := binarySerializer.Borrow()
	buf := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Previous output hash
		0xff, 0xff, 0xff, 0xff, // Previous output index
	}
	r := bytes.NewReader(buf)
	var op OutPoint
	for i := 0; i < b.N; i++ {
		r.Seek(0, 0)
		readOutPointBuf(r, 0, 0, &op, buffer)
	}
	binarySerializer.Return(buffer)
}

// BenchmarkWriteOutPoint performs a benchmark on how long it takes to write a
// transaction output point.
func BenchmarkWriteOutPoint(b *testing.B) {
	b.ReportAllocs()

	op := &OutPoint{
		Hash:  chainhash.Hash{},
		Index: 0,
	}
	for i := 0; i < b.N; i++ {
		WriteOutPoint(io.Discard, 0, 0, op)
	}
}

// BenchmarkWriteOutPointBuf performs a benchmark on how long it takes to write a
// transaction output point.
func BenchmarkWriteOutPointBuf(b *testing.B) {
	b.ReportAllocs()

	buf := binarySerializer.Borrow()
	op := &OutPoint{
		Hash:  chainhash.Hash{},
		Index: 0,
	}
	for i := 0; i < b.N; i++ {
		writeOutPointBuf(io.Discard, 0, 0, op, buf)
	}
	binarySerializer.Return(buf)
}

// BenchmarkReadTxOut performs a benchmark on how long it takes to read a
// Handshake transaction output: value(8) + address + covenant.
func BenchmarkReadTxOut(b *testing.B) {
	b.ReportAllocs()

	buf := []byte{
		0x00, 0xf2, 0x05, 0x2a, 0x01, 0x00, 0x00, 0x00, // Transaction amount
		0x00,                                           // Address version 0
		0x14,                                           // Address hash length 20
		0x96, 0xb5, 0x38, 0xe8, 0x53, 0x51, 0x9c, 0x72, // Address hash
		0x6a, 0x2c, 0x91, 0xe6, 0x1e, 0xc1, 0x16, 0x00,
		0xae, 0x13, 0x90, 0x81,
		0x00, // Covenant type NONE
		0x00, // Covenant 0 items
	}
	r := bytes.NewReader(buf)
	var txOut TxOut
	for i := 0; i < b.N; i++ {
		r.Seek(0, 0)
		if err := ReadTxOut(r, 0, 0, &txOut); err != nil {
			b.Fatalf("ReadTxOut: %v", err)
		}
	}
}

// BenchmarkReadTxOutBuf performs a benchmark on how long it takes to read a
// Handshake transaction output using the internal buffer function.
func BenchmarkReadTxOutBuf(b *testing.B) {
	b.ReportAllocs()

	buffer := binarySerializer.Borrow()
	buf := []byte{
		0x00, 0xf2, 0x05, 0x2a, 0x01, 0x00, 0x00, 0x00, // Transaction amount
		0x00,                                           // Address version 0
		0x14,                                           // Address hash length 20
		0x96, 0xb5, 0x38, 0xe8, 0x53, 0x51, 0x9c, 0x72, // Address hash
		0x6a, 0x2c, 0x91, 0xe6, 0x1e, 0xc1, 0x16, 0x00,
		0xae, 0x13, 0x90, 0x81,
		0x00, // Covenant type NONE
		0x00, // Covenant 0 items
	}
	r := bytes.NewReader(buf)
	var txOut TxOut
	for i := 0; i < b.N; i++ {
		r.Seek(0, 0)
		if err := readTxOutBuf(r, 0, 0, &txOut, buffer); err != nil {
			b.Fatalf("readTxOutBuf: %v", err)
		}
	}
	binarySerializer.Return(buffer)
}

// BenchmarkWriteTxOut performs a benchmark on how long it takes to write
// a transaction output.
func BenchmarkWriteTxOut(b *testing.B) {
	b.ReportAllocs()

	txOut := blockOne.Transactions[0].TxOut[0]
	for i := 0; i < b.N; i++ {
		WriteTxOut(io.Discard, 0, 0, txOut)
	}
}

// BenchmarkWriteTxOutBuf performs a benchmark on how long it takes to write
// a transaction output.
func BenchmarkWriteTxOutBuf(b *testing.B) {
	b.ReportAllocs()

	buf := binarySerializer.Borrow()
	txOut := blockOne.Transactions[0].TxOut[0]
	for i := 0; i < b.N; i++ {
		WriteTxOutBuf(io.Discard, 0, 0, txOut, buf)
	}
	binarySerializer.Return(buf)
}

// BenchmarkReadTxIn performs a benchmark on how long it takes to read a
// Handshake transaction input: prevhash(32) + previndex(4) + sequence(4).
func BenchmarkReadTxIn(b *testing.B) {
	b.ReportAllocs()

	buffer := binarySerializer.Borrow()
	buf := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Previous output hash
		0xff, 0xff, 0xff, 0xff, // Previous output index
		0xff, 0xff, 0xff, 0xff, // Sequence
	}
	r := bytes.NewReader(buf)
	var txIn TxIn
	for i := 0; i < b.N; i++ {
		r.Seek(0, 0)
		if err := readTxInBuf(r, 0, 0, &txIn, buffer); err != nil {
			b.Fatalf("readTxInBuf failed: %v", err)
		}
	}
	binarySerializer.Return(buffer)
}

// BenchmarkWriteTxIn performs a benchmark on how long it takes to write
// a transaction input.
func BenchmarkWriteTxIn(b *testing.B) {
	b.ReportAllocs()

	buf := binarySerializer.Borrow()
	txIn := blockOne.Transactions[0].TxIn[0]
	for i := 0; i < b.N; i++ {
		writeTxInBuf(io.Discard, 0, 0, txIn, buf)
	}
	binarySerializer.Return(buf)
}

// BenchmarkDeserializeTxSmall performs a benchmark on how long it takes to
// deserialize a small Handshake transaction.
func BenchmarkDeserializeTxSmall(b *testing.B) {
	// Serialize the genesis coinbase tx to get valid Handshake wire bytes.
	var txBuf bytes.Buffer
	if err := genesisCoinbaseTx.Serialize(&txBuf); err != nil {
		b.Fatalf("Serialize: %v", err)
	}
	buf := txBuf.Bytes()

	b.ReportAllocs()
	b.ResetTimer()

	r := bytes.NewReader(buf)
	var tx MsgTx
	for i := 0; i < b.N; i++ {
		r.Seek(0, 0)
		tx.Deserialize(r)
	}
}

// BenchmarkDeserializeTxLarge performs a benchmark on how long it takes to
// deserialize a very large transaction.
func BenchmarkDeserializeTxLarge(b *testing.B) {

	// tx bb41a757f405890fb0f5856228e23b715702d714d59bf2b1feb70d8b2b4e3e08
	// from the main block chain.
	fi, err := os.Open("testdata/megatx.bin.bz2")
	if err != nil {
		b.Fatalf("Failed to read transaction data: %v", err)
	}
	defer fi.Close()
	buf, err := io.ReadAll(bzip2.NewReader(fi))
	if err != nil {
		b.Fatalf("Failed to read transaction data: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	r := bytes.NewReader(buf)
	var tx MsgTx
	for i := 0; i < b.N; i++ {
		r.Seek(0, 0)
		tx.Deserialize(r)
	}
}

func BenchmarkDeserializeBlock(b *testing.B) {
	buf, err := os.ReadFile(
		"testdata/block-00000000000000000021868c2cefc52a480d173c849412fe81c4e5ab806f94ab.blk",
	)
	if err != nil {
		b.Fatalf("Failed to read block data: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	r := bytes.NewReader(buf)
	var block MsgBlock
	for i := 0; i < b.N; i++ {
		r.Seek(0, 0)
		block.Deserialize(r)
	}
}

func BenchmarkSerializeBlock(b *testing.B) {
	buf, err := os.ReadFile(
		"testdata/block-00000000000000000021868c2cefc52a480d173c849412fe81c4e5ab806f94ab.blk",
	)
	if err != nil {
		b.Fatalf("Failed to read block data: %v", err)
	}

	var block MsgBlock
	err = block.Deserialize(bytes.NewReader(buf))
	if err != nil {
		panic(err.Error())
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		block.Serialize(io.Discard)
	}
}

// BenchmarkSerializeTx performs a benchmark on how long it takes to serialize
// a transaction.
func BenchmarkSerializeTx(b *testing.B) {
	b.ReportAllocs()

	tx := blockOne.Transactions[0]
	for i := 0; i < b.N; i++ {
		tx.Serialize(io.Discard)

	}
}

// BenchmarkSerializeTxSmall performs a benchmark on how long it takes to
// serialize a small Handshake transaction.
func BenchmarkSerializeTxSmall(b *testing.B) {
	tx := genesisCoinbaseTx

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		tx.Serialize(io.Discard)
	}
}

// BenchmarkSerializeTxLarge performs a benchmark on how long it takes to
// serialize a transaction.
func BenchmarkSerializeTxLarge(b *testing.B) {
	// tx bb41a757f405890fb0f5856228e23b715702d714d59bf2b1feb70d8b2b4e3e08
	// from the main block chain.
	fi, err := os.Open("testdata/megatx.bin.bz2")
	if err != nil {
		b.Fatalf("Failed to read transaction data: %v", err)
	}
	defer fi.Close()
	buf, err := io.ReadAll(bzip2.NewReader(fi))
	if err != nil {
		b.Fatalf("Failed to read transaction data: %v", err)
	}

	var tx MsgTx
	tx.Deserialize(bytes.NewReader(buf))

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		tx.Serialize(io.Discard)
	}
}

// BenchmarkReadBlockHeader performs a benchmark on how long it takes to
// deserialize a Handshake block header (236 bytes).
func BenchmarkReadBlockHeader(b *testing.B) {
	b.ReportAllocs()

	var hdrBuf bytes.Buffer
	if err := blockOne.Header.Serialize(&hdrBuf); err != nil {
		b.Fatalf("Serialize header: %v", err)
	}
	buf := hdrBuf.Bytes()
	r := bytes.NewReader(buf)
	var header BlockHeader
	for i := 0; i < b.N; i++ {
		r.Seek(0, 0)
		readBlockHeader(r, 0, &header)
	}
}

// BenchmarkReadBlockHeaderBuf performs a benchmark on how long it takes to
// deserialize a Handshake block header (236 bytes) using a scratch buffer.
func BenchmarkReadBlockHeaderBuf(b *testing.B) {
	b.ReportAllocs()

	buffer := binarySerializer.Borrow()
	var hdrBuf bytes.Buffer
	if err := blockOne.Header.Serialize(&hdrBuf); err != nil {
		b.Fatalf("Serialize header: %v", err)
	}
	buf := hdrBuf.Bytes()
	r := bytes.NewReader(buf)
	var header BlockHeader
	for i := 0; i < b.N; i++ {
		r.Seek(0, 0)
		readBlockHeaderBuf(r, 0, &header, buffer)
	}
	binarySerializer.Return(buffer)
}

// BenchmarkWriteBlockHeader performs a benchmark on how long it takes to
// serialize a block header.
func BenchmarkWriteBlockHeader(b *testing.B) {
	b.ReportAllocs()

	header := blockOne.Header
	for i := 0; i < b.N; i++ {
		writeBlockHeader(io.Discard, 0, &header)
	}
}

// BenchmarkWriteBlockHeaderBuf performs a benchmark on how long it takes to
// serialize a block header.
func BenchmarkWriteBlockHeaderBuf(b *testing.B) {
	b.ReportAllocs()

	buf := binarySerializer.Borrow()
	header := blockOne.Header
	for i := 0; i < b.N; i++ {
		writeBlockHeaderBuf(io.Discard, 0, &header, buf)
	}
	binarySerializer.Return(buf)
}

// BenchmarkDecodeGetHeaders performs a benchmark on how long it takes to
// decode a getheaders message with the maximum number of block locator hashes.
func BenchmarkDecodeGetHeaders(b *testing.B) {
	b.ReportAllocs()

	// Create a message with the maximum number of block locators.
	pver := ProtocolVersion
	var m MsgGetHeaders
	for i := 0; i < MaxBlockLocatorsPerMsg; i++ {
		hash, err := chainhash.NewHashFromStr(fmt.Sprintf("%x", i))
		if err != nil {
			b.Fatalf("NewHashFromStr: unexpected error: %v", err)
		}
		m.AddBlockLocatorHash(hash)
	}

	// Serialize it so the bytes are available to test the decode below.
	var bb bytes.Buffer
	if err := m.BtcEncode(&bb, pver, LatestEncoding); err != nil {
		b.Fatalf("MsgGetHeaders.BtcEncode: unexpected error: %v", err)
	}
	buf := bb.Bytes()

	r := bytes.NewReader(buf)
	var msg MsgGetHeaders
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Seek(0, 0)
		msg.BtcDecode(r, pver, LatestEncoding)
	}
}

// BenchmarkDecodeHeaders performs a benchmark on how long it takes to
// decode a headers message with the maximum number of headers.
func BenchmarkDecodeHeaders(b *testing.B) {
	b.ReportAllocs()

	// Create a message with the maximum number of headers.
	pver := ProtocolVersion
	var m MsgHeaders
	for i := 0; i < MaxBlockHeadersPerMsg; i++ {
		hash, err := chainhash.NewHashFromStr(fmt.Sprintf("%x", i))
		if err != nil {
			b.Fatalf("NewHashFromStr: unexpected error: %v", err)
		}
		m.AddBlockHeader(NewBlockHeader(1, hash, hash, &chainhash.Hash{}, &chainhash.Hash{}, 0, uint32(i)))
	}

	// Serialize it so the bytes are available to test the decode below.
	var bb bytes.Buffer
	if err := m.BtcEncode(&bb, pver, LatestEncoding); err != nil {
		b.Fatalf("MsgHeaders.BtcEncode: unexpected error: %v", err)
	}
	buf := bb.Bytes()

	r := bytes.NewReader(buf)
	var msg MsgHeaders
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Seek(0, 0)
		msg.BtcDecode(r, pver, LatestEncoding)
	}
}

// BenchmarkDecodeGetBlocks performs a benchmark on how long it takes to
// decode a getblocks message with the maximum number of block locator hashes.
func BenchmarkDecodeGetBlocks(b *testing.B) {
	b.ReportAllocs()

	// Create a message with the maximum number of block locators.
	pver := ProtocolVersion
	var m MsgGetBlocks
	for i := 0; i < MaxBlockLocatorsPerMsg; i++ {
		hash, err := chainhash.NewHashFromStr(fmt.Sprintf("%x", i))
		if err != nil {
			b.Fatalf("NewHashFromStr: unexpected error: %v", err)
		}
		m.AddBlockLocatorHash(hash)
	}

	// Serialize it so the bytes are available to test the decode below.
	var bb bytes.Buffer
	if err := m.BtcEncode(&bb, pver, LatestEncoding); err != nil {
		b.Fatalf("MsgGetBlocks.BtcEncode: unexpected error: %v", err)
	}
	buf := bb.Bytes()

	r := bytes.NewReader(buf)
	var msg MsgGetBlocks
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Seek(0, 0)
		msg.BtcDecode(r, pver, LatestEncoding)
	}
}

// BenchmarkDecodeAddr performs a benchmark on how long it takes to decode an
// addr message with the maximum number of addresses.
func BenchmarkDecodeAddr(b *testing.B) {
	b.ReportAllocs()

	// Create a message with the maximum number of addresses.
	pver := ProtocolVersion
	ip := net.ParseIP("127.0.0.1")
	ma := NewMsgAddr()
	for port := uint16(0); port < MaxAddrPerMsg; port++ {
		ma.AddAddress(NewNetAddressIPPort(ip, port, SFNodeNetwork))
	}

	// Serialize it so the bytes are available to test the decode below.
	var bb bytes.Buffer
	if err := ma.BtcEncode(&bb, pver, LatestEncoding); err != nil {
		b.Fatalf("MsgAddr.BtcEncode: unexpected error: %v", err)
	}
	buf := bb.Bytes()

	r := bytes.NewReader(buf)
	var msg MsgAddr
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Seek(0, 0)
		msg.BtcDecode(r, pver, LatestEncoding)
	}
}

// BenchmarkDecodeInv performs a benchmark on how long it takes to decode an inv
// message with the maximum number of entries.
func BenchmarkDecodeInv(b *testing.B) {
	// Create a message with the maximum number of entries.
	pver := ProtocolVersion
	var m MsgInv
	for i := 0; i < MaxInvPerMsg; i++ {
		hash, err := chainhash.NewHashFromStr(fmt.Sprintf("%x", i))
		if err != nil {
			b.Fatalf("NewHashFromStr: unexpected error: %v", err)
		}
		m.AddInvVect(NewInvVect(InvTypeBlock, hash))
	}

	// Serialize it so the bytes are available to test the decode below.
	var bb bytes.Buffer
	if err := m.BtcEncode(&bb, pver, LatestEncoding); err != nil {
		b.Fatalf("MsgInv.BtcEncode: unexpected error: %v", err)
	}
	buf := bb.Bytes()

	b.ReportAllocs()
	b.ResetTimer()

	r := bytes.NewReader(buf)
	var msg MsgInv
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Seek(0, 0)
		msg.BtcDecode(r, pver, LatestEncoding)
	}
}

// BenchmarkDecodeNotFound performs a benchmark on how long it takes to decode
// a notfound message with the maximum number of entries.
func BenchmarkDecodeNotFound(b *testing.B) {
	b.ReportAllocs()

	// Create a message with the maximum number of entries.
	pver := ProtocolVersion
	var m MsgNotFound
	for i := 0; i < MaxInvPerMsg; i++ {
		hash, err := chainhash.NewHashFromStr(fmt.Sprintf("%x", i))
		if err != nil {
			b.Fatalf("NewHashFromStr: unexpected error: %v", err)
		}
		m.AddInvVect(NewInvVect(InvTypeBlock, hash))
	}

	// Serialize it so the bytes are available to test the decode below.
	var bb bytes.Buffer
	if err := m.BtcEncode(&bb, pver, LatestEncoding); err != nil {
		b.Fatalf("MsgNotFound.BtcEncode: unexpected error: %v", err)
	}
	buf := bb.Bytes()

	r := bytes.NewReader(buf)
	var msg MsgNotFound
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Seek(0, 0)
		msg.BtcDecode(r, pver, LatestEncoding)
	}
}

// BenchmarkDecodeMerkleBlock performs a benchmark on how long it takes to
// decode a reasonably sized merkleblock message.
func BenchmarkDecodeMerkleBlock(b *testing.B) {
	b.ReportAllocs()

	// Create a message with random data.
	pver := ProtocolVersion
	var m MsgMerkleBlock
	hash, err := chainhash.NewHashFromStr(fmt.Sprintf("%x", 10000))
	if err != nil {
		b.Fatalf("NewHashFromStr: unexpected error: %v", err)
	}
	m.Header = *NewBlockHeader(1, hash, hash, &chainhash.Hash{}, &chainhash.Hash{}, 0, uint32(10000))
	for i := 0; i < 105; i++ {
		hash, err := chainhash.NewHashFromStr(fmt.Sprintf("%x", i))
		if err != nil {
			b.Fatalf("NewHashFromStr: unexpected error: %v", err)
		}
		m.AddTxHash(hash)
		if i%8 == 0 {
			m.Flags = append(m.Flags, uint8(i))
		}
	}

	// Serialize it so the bytes are available to test the decode below.
	var bb bytes.Buffer
	if err := m.BtcEncode(&bb, pver, LatestEncoding); err != nil {
		b.Fatalf("MsgMerkleBlock.BtcEncode: unexpected error: %v", err)
	}
	buf := bb.Bytes()

	r := bytes.NewReader(buf)
	var msg MsgMerkleBlock
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Seek(0, 0)
		msg.BtcDecode(r, pver, LatestEncoding)
	}
}

// BenchmarkTxHash performs a benchmark on how long it takes to hash a
// transaction.
func BenchmarkTxHash(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		genesisCoinbaseTx.TxHash()
	}
}

// BenchmarkDoubleHashB performs a benchmark on how long it takes to perform a
// double hash returning a byte slice.
func BenchmarkDoubleHashB(b *testing.B) {
	b.ReportAllocs()

	var buf bytes.Buffer
	if err := genesisCoinbaseTx.Serialize(&buf); err != nil {
		b.Errorf("Serialize: unexpected error: %v", err)
		return
	}
	txBytes := buf.Bytes()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = chainhash.DoubleHashB(txBytes)
	}
}

// BenchmarkDoubleHashH performs a benchmark on how long it takes to perform
// a double hash returning a chainhash.Hash.
func BenchmarkDoubleHashH(b *testing.B) {
	b.ReportAllocs()

	var buf bytes.Buffer
	if err := genesisCoinbaseTx.Serialize(&buf); err != nil {
		b.Errorf("Serialize: unexpected error: %v", err)
		return
	}
	txBytes := buf.Bytes()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = chainhash.DoubleHashH(txBytes)
	}
}
