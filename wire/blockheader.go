// Copyright (c) 2013-2016 The btcsuite developers
// Copyright (c) 2025-2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"io"
	"time"

	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"golang.org/x/crypto/blake2b"
)

// MaxBlockHeaderPayload is the maximum number of bytes a block header can be.
// Nonce(4) + Time(8) + PrevBlock(32) + NameRoot(32) + ExtraNonce(24) +
// ReservedRoot(32) + WitnessRoot(32) + MerkleRoot(32) + Version(4) + Bits(4) +
// Mask(32) = 236
const MaxBlockHeaderPayload = 236

// blockHeaderLen is a constant that represents the number of bytes for a block
// header.
const blockHeaderLen = 236

// BlockHeader defines information about a block and is used in the Handshake
// block (MsgBlock) and headers (MsgHeaders) messages.
type BlockHeader struct {
	// Version of the block.  This is not the same as the protocol version.
	Version int32

	// Hash of the previous block header in the block chain.
	PrevBlock chainhash.Hash

	// Merkle tree reference to hash of all transactions for the block.
	MerkleRoot chainhash.Hash

	// Time the block was created.  Encoded as uint64 on wire.
	Timestamp time.Time

	// Difficulty target for the block.
	Bits uint32

	// Nonce used to generate the block.
	Nonce uint32

	// Handshake-specific fields.

	// NameRoot is the root hash of the Urkel name trie.
	NameRoot chainhash.Hash

	// ExtraNonce provides additional nonce space for miners.
	ExtraNonce [24]byte

	// ReservedRoot is reserved for future use (e.g., soft-fork commitments).
	ReservedRoot chainhash.Hash

	// WitnessRoot is the root hash of the witness commitment tree.
	WitnessRoot chainhash.Hash

	// Mask is XORed with the share hash to produce the PoW hash.
	Mask chainhash.Hash
}

// BlockHash computes the block identifier hash for the given block header
// using the Handshake PoW hash chain (Blake2b + SHA3).
func (h *BlockHeader) BlockHash() chainhash.Hash {
	hash := h.powHash()
	return chainhash.Hash(hash)
}

// BtcDecode decodes r using the protocol encoding into the receiver.
// This is part of the Message interface implementation.
// See Deserialize for decoding block headers stored to disk, such as in a
// database, as opposed to decoding block headers from the wire.
func (h *BlockHeader) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	return readBlockHeader(r, pver, h)
}

// BtcEncode encodes the receiver to w using the protocol encoding.
// This is part of the Message interface implementation.
// See Serialize for encoding block headers to be stored to disk, such as in a
// database, as opposed to encoding block headers for the wire.
func (h *BlockHeader) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	return writeBlockHeader(w, pver, h)
}

// Deserialize decodes a block header from r into the receiver using a format
// that is suitable for long-term storage such as a database while respecting
// the Version field.
func (h *BlockHeader) Deserialize(r io.Reader) error {
	// At the current time, there is no difference between the wire encoding
	// at protocol version 0 and the stable long-term storage format.  As
	// a result, make use of readBlockHeader.
	return readBlockHeader(r, 0, h)
}

// Serialize encodes a block header from r into the receiver using a format
// that is suitable for long-term storage such as a database while respecting
// the Version field.
func (h *BlockHeader) Serialize(w io.Writer) error {
	// At the current time, there is no difference between the wire encoding
	// at protocol version 0 and the stable long-term storage format.  As
	// a result, make use of writeBlockHeader.
	return writeBlockHeader(w, 0, h)
}

// NewBlockHeader returns a new BlockHeader using the provided version, previous
// block hash, merkle root hash, name root, witness root, difficulty bits, and
// nonce used to generate the block with defaults for the remaining fields.
func NewBlockHeader(version int32, prevHash, merkleRootHash, nameRoot,
	witnessRoot *chainhash.Hash, bits uint32, nonce uint32) *BlockHeader {

	// Limit the timestamp to one second precision since the protocol
	// doesn't support better.
	return &BlockHeader{
		Version:     version,
		PrevBlock:   *prevHash,
		MerkleRoot:  *merkleRootHash,
		NameRoot:    *nameRoot,
		WitnessRoot: *witnessRoot,
		Timestamp:   time.Unix(time.Now().Unix(), 0),
		Bits:        bits,
		Nonce:       nonce,
	}
}

// readBlockHeader reads a Handshake block header from r.  See Deserialize for
// decoding block headers stored to disk, such as in a database, as opposed to
// decoding from the wire.
//
// DEPRECATED: Use readBlockHeaderBuf instead.
func readBlockHeader(r io.Reader, pver uint32, bh *BlockHeader) error {
	buf := binarySerializer.Borrow()
	err := readBlockHeaderBuf(r, pver, bh, buf)
	binarySerializer.Return(buf)
	return err
}

// readBlockHeaderBuf reads a Handshake block header from r.
//
// Wire order: Nonce(4) | Time(8) | PrevBlock(32) | NameRoot(32) |
// ExtraNonce(24) | ReservedRoot(32) | WitnessRoot(32) | MerkleRoot(32) |
// Version(4) | Bits(4) | Mask(32)
//
// NOTE: buf MUST either be nil or at least an 8-byte slice.
func readBlockHeaderBuf(r io.Reader, pver uint32, bh *BlockHeader,
	buf []byte) error {

	// Nonce — 4 bytes LE
	if _, err := io.ReadFull(r, buf[:4]); err != nil {
		return err
	}
	bh.Nonce = littleEndian.Uint32(buf[:4])

	// Time — 8 bytes LE (uint64)
	if _, err := io.ReadFull(r, buf[:8]); err != nil {
		return err
	}
	bh.Timestamp = time.Unix(int64(littleEndian.Uint64(buf[:8])), 0)

	// PrevBlock — 32 bytes
	if _, err := io.ReadFull(r, bh.PrevBlock[:]); err != nil {
		return err
	}

	// NameRoot — 32 bytes
	if _, err := io.ReadFull(r, bh.NameRoot[:]); err != nil {
		return err
	}

	// ExtraNonce — 24 bytes
	if _, err := io.ReadFull(r, bh.ExtraNonce[:]); err != nil {
		return err
	}

	// ReservedRoot — 32 bytes
	if _, err := io.ReadFull(r, bh.ReservedRoot[:]); err != nil {
		return err
	}

	// WitnessRoot — 32 bytes
	if _, err := io.ReadFull(r, bh.WitnessRoot[:]); err != nil {
		return err
	}

	// MerkleRoot — 32 bytes
	if _, err := io.ReadFull(r, bh.MerkleRoot[:]); err != nil {
		return err
	}

	// Version — 4 bytes LE
	if _, err := io.ReadFull(r, buf[:4]); err != nil {
		return err
	}
	bh.Version = int32(littleEndian.Uint32(buf[:4]))

	// Bits — 4 bytes LE
	if _, err := io.ReadFull(r, buf[:4]); err != nil {
		return err
	}
	bh.Bits = littleEndian.Uint32(buf[:4])

	// Mask — 32 bytes
	if _, err := io.ReadFull(r, bh.Mask[:]); err != nil {
		return err
	}

	return nil
}

// writeBlockHeader writes a Handshake block header to w.
//
// DEPRECATED: Use writeBlockHeaderBuf instead.
func writeBlockHeader(w io.Writer, pver uint32, bh *BlockHeader) error {
	buf := binarySerializer.Borrow()
	err := writeBlockHeaderBuf(w, pver, bh, buf)
	binarySerializer.Return(buf)
	return err
}

// writeBlockHeaderBuf writes a Handshake block header to w.
//
// Wire order: Nonce(4) | Time(8) | PrevBlock(32) | NameRoot(32) |
// ExtraNonce(24) | ReservedRoot(32) | WitnessRoot(32) | MerkleRoot(32) |
// Version(4) | Bits(4) | Mask(32)
//
// NOTE: buf MUST either be nil or at least an 8-byte slice.
func writeBlockHeaderBuf(w io.Writer, pver uint32, bh *BlockHeader,
	buf []byte) error {

	// Nonce — 4 bytes LE
	littleEndian.PutUint32(buf[:4], bh.Nonce)
	if _, err := w.Write(buf[:4]); err != nil {
		return err
	}

	// Time — 8 bytes LE (uint64)
	littleEndian.PutUint64(buf[:8], uint64(bh.Timestamp.Unix()))
	if _, err := w.Write(buf[:8]); err != nil {
		return err
	}

	// PrevBlock — 32 bytes
	if _, err := w.Write(bh.PrevBlock[:]); err != nil {
		return err
	}

	// NameRoot — 32 bytes
	if _, err := w.Write(bh.NameRoot[:]); err != nil {
		return err
	}

	// ExtraNonce — 24 bytes
	if _, err := w.Write(bh.ExtraNonce[:]); err != nil {
		return err
	}

	// ReservedRoot — 32 bytes
	if _, err := w.Write(bh.ReservedRoot[:]); err != nil {
		return err
	}

	// WitnessRoot — 32 bytes
	if _, err := w.Write(bh.WitnessRoot[:]); err != nil {
		return err
	}

	// MerkleRoot — 32 bytes
	if _, err := w.Write(bh.MerkleRoot[:]); err != nil {
		return err
	}

	// Version — 4 bytes LE
	littleEndian.PutUint32(buf[:4], uint32(bh.Version))
	if _, err := w.Write(buf[:4]); err != nil {
		return err
	}

	// Bits — 4 bytes LE
	littleEndian.PutUint32(buf[:4], bh.Bits)
	if _, err := w.Write(buf[:4]); err != nil {
		return err
	}

	// Mask — 32 bytes
	if _, err := w.Write(bh.Mask[:]); err != nil {
		return err
	}

	return nil
}

// PoW hash methods ported from cdnsd/handshake/block.go

// padding generates a padding buffer of the given size, where each byte is
// PrevBlock[i%32] XOR NameRoot[i%32].
func (h *BlockHeader) padding(size int) []byte {
	ret := make([]byte, size)
	for i := range size {
		ret[i] = h.PrevBlock[i%32] ^ h.NameRoot[i%32]
	}
	return ret
}

// subhead returns the serialized sub-header bytes used in the PoW hash chain.
func (h *BlockHeader) subhead() []byte {
	buf := new(bytes.Buffer)
	_, _ = buf.Write(h.ExtraNonce[:])
	_, _ = buf.Write(h.ReservedRoot[:])
	_, _ = buf.Write(h.WitnessRoot[:])
	_, _ = buf.Write(h.MerkleRoot[:])
	_ = binary.Write(buf, binary.LittleEndian, uint32(h.Version))
	_ = binary.Write(buf, binary.LittleEndian, h.Bits)
	return buf.Bytes()
}

// subHash returns blake2b-256 of the sub-header.
func (h *BlockHeader) subHash() [32]byte {
	return blake2b.Sum256(h.subhead())
}

// maskHash returns blake2b-256(PrevBlock || Mask).
func (h *BlockHeader) maskHash() [32]byte {
	buf := new(bytes.Buffer)
	_, _ = buf.Write(h.PrevBlock[:])
	_, _ = buf.Write(h.Mask[:])
	return blake2b.Sum256(buf.Bytes())
}

// commitHash returns blake2b-256(subHash || maskHash).
func (h *BlockHeader) commitHash() [32]byte {
	buf := new(bytes.Buffer)
	subHash := h.subHash()
	_, _ = buf.Write(subHash[:])
	maskHash := h.maskHash()
	_, _ = buf.Write(maskHash[:])
	return blake2b.Sum256(buf.Bytes())
}

// prehead returns the serialized pre-header bytes:
// Nonce(4) | Time(8) | padding(20) | PrevBlock(32) | NameRoot(32) | commitHash(32)
func (h *BlockHeader) prehead() []byte {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.LittleEndian, h.Nonce)
	_ = binary.Write(buf, binary.LittleEndian, uint64(h.Timestamp.Unix()))
	_, _ = buf.Write(h.padding(20))
	_, _ = buf.Write(h.PrevBlock[:])
	_, _ = buf.Write(h.NameRoot[:])
	commitHash := h.commitHash()
	_, _ = buf.Write(commitHash[:])
	return buf.Bytes()
}

// shareHash computes the share hash using the Blake2b+SHA3 chain:
//  1. left = blake2b-512(prehead)
//  2. right = sha3-256(prehead || padding(8))
//  3. result = blake2b-256(left || padding(32) || right)
func (h *BlockHeader) shareHash() [32]byte {
	data := h.prehead()
	left := blake2b.Sum512(data)
	sha3Hasher := sha3.New256()
	_, _ = sha3Hasher.Write(data)
	_, _ = sha3Hasher.Write(h.padding(8))
	right := sha3Hasher.Sum(nil)
	finalHasher, err := blake2b.New256(nil)
	if err != nil {
		panic("blake2b.New256 failed")
	}
	_, _ = finalHasher.Write(left[:])
	_, _ = finalHasher.Write(h.padding(32))
	_, _ = finalHasher.Write(right[:])
	return [32]byte(finalHasher.Sum(nil))
}

// powHash computes the final PoW hash: shareHash XOR Mask.
func (h *BlockHeader) powHash() [32]byte {
	hash := h.shareHash()
	for i := range 32 {
		hash[i] ^= h.Mask[i]
	}
	return hash
}
