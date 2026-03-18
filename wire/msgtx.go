// Copyright (c) 2013-2016 The btcsuite developers
// Copyright (c) 2024-2025 The blinklabs-io developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"golang.org/x/crypto/blake2b"
)

const (
	// TxVersion is the current latest supported transaction version.
	// Handshake uses version 0 for most transactions.
	TxVersion = 0

	// MaxTxInSequenceNum is the maximum sequence number the sequence field
	// of a transaction input can be.
	MaxTxInSequenceNum uint32 = 0xffffffff

	// MaxPrevOutIndex is the maximum index the index field of a previous
	// outpoint can be.
	MaxPrevOutIndex uint32 = 0xffffffff

	// SequenceLockTimeDisabled is a flag that if set on a transaction
	// input's sequence number, the sequence number will not be interpreted
	// as a relative locktime.
	SequenceLockTimeDisabled = 1 << 31

	// SequenceLockTimeIsSeconds is a flag that if set on a transaction
	// input's sequence number, the relative locktime has units of 512
	// seconds.
	SequenceLockTimeIsSeconds = 1 << 22

	// SequenceLockTimeMask is a mask that extracts the relative locktime
	// when masked against the transaction input sequence number.
	SequenceLockTimeMask = 0x0000ffff

	// SequenceLockTimeGranularity is the defined time based granularity
	// for seconds-based relative time locks. When converting from seconds
	// to a sequence number, the value is right shifted by this amount,
	// therefore the granularity of relative time locks in 512 or 2^9
	// seconds. Enforced relative lock times are multiples of 512 seconds.
	SequenceLockTimeGranularity = 9

	// defaultTxInOutAlloc is the default size used for the backing array for
	// transaction inputs and outputs.  The array will dynamically grow as needed,
	// but this figure is intended to provide enough space for the number of
	// inputs and outputs in a typical transaction without needing to grow the
	// backing array multiple times.
	defaultTxInOutAlloc = 15

	// minTxInPayload is the minimum payload size for a transaction input.
	// PreviousOutPoint.Hash (32 bytes) + PreviousOutPoint.Index (4 bytes)
	// + Sequence (4 bytes) = 40 bytes.
	minTxInPayload = 40

	// maxTxInPerMessage is the maximum number of transactions inputs that
	// a transaction which fits into a message could possibly have.
	maxTxInPerMessage = (MaxMessagePayload / minTxInPayload) + 1

	// MinTxOutPayload is the minimum payload size for a transaction output.
	// Value (8 bytes) + address version (1 byte) + address hash length (1 byte)
	// + covenant type (1 byte) + covenant items varint (1 byte) = 12 bytes.
	MinTxOutPayload = 12

	// maxTxOutPerMessage is the maximum number of transactions outputs that
	// a transaction which fits into a message could possibly have.
	maxTxOutPerMessage = (MaxMessagePayload / MinTxOutPayload) + 1

	// minTxPayload is the minimum payload size for a transaction.  Note
	// that any realistically usable transaction must have at least one
	// input or output, but that is a rule enforced at a higher layer, so
	// it is intentionally not included here.
	// Version 4 bytes + Varint number of transaction inputs 1 byte + Varint
	// number of transaction outputs 1 byte + LockTime 4 bytes + min input
	// payload + min output payload.
	minTxPayload = 10

	// freeListMaxItems is the number of buffers to keep in the free list
	// to use for script deserialization.  This value allows up to 100
	// scripts per transaction being simultaneously deserialized by 125
	// peers.  Thus, the peak usage of the free list is 12,500 * 512 =
	// 6,400,000 bytes.
	freeListMaxItems = 125

	// maxWitnessItemsPerInput is the maximum number of witness items to
	// be read for the witness data for a single TxIn. This number is
	// derived using a possible lower bound for the encoding of a witness
	// item: 1 byte for length + 1 byte for the witness item itself, or two
	// bytes. This value is then divided by the currently allowed maximum
	// "cost" for a transaction.
	maxWitnessItemsPerInput = 4_000_000

	// maxWitnessItemSize is the maximum allowed size for an item within
	// an input's witness data.
	maxWitnessItemSize = 4_000_000
)

const scriptSlabSize = 1 << 22

type scriptSlab [scriptSlabSize]byte

// scriptFreeList defines a free list of byte slices (up to the maximum number
// defined by the freeListMaxItems constant) that have a cap according to the
// scriptSlabSize constant.  It is used to provide temporary buffers for
// deserializing witness data in order to greatly reduce the number of
// allocations required.
//
// The caller can obtain a buffer from the free list by calling the Borrow
// function and should return it via the Return function when done using it.
type scriptFreeList chan *scriptSlab

// Borrow returns a byte slice from the free list.  A new buffer is allocated
// if there are no items available.
func (c scriptFreeList) Borrow() *scriptSlab {
	var buf *scriptSlab
	select {
	case buf = <-c:
	default:
		buf = new(scriptSlab)
	}
	return buf
}

// Return puts the provided byte slice back on the free list when it has a cap
// of the expected length.  The buffer is expected to have been obtained via
// the Borrow function.
func (c scriptFreeList) Return(buf *scriptSlab) {
	select {
	case c <- buf:
	default:
		// Let it go to the garbage collector.
	}
}

// Create the concurrent safe free list to use for witness deserialization.
var scriptPool = make(scriptFreeList, freeListMaxItems)

// OutPoint defines a transaction outpoint used to track previous
// transaction outputs.
type OutPoint struct {
	Hash  chainhash.Hash
	Index uint32
}

// NewOutPoint returns a new transaction outpoint with the provided hash and
// index.
func NewOutPoint(hash *chainhash.Hash, index uint32) *OutPoint {
	return &OutPoint{
		Hash:  *hash,
		Index: index,
	}
}

// NewOutPointFromString returns a new transaction outpoint parsed from the
// provided string, which should be in the format "hash:index".
func NewOutPointFromString(outpoint string) (*OutPoint, error) {
	parts := strings.Split(outpoint, ":")
	if len(parts) != 2 {
		return nil, errors.New("outpoint should be of the form txid:index")
	}

	if len(parts[0]) != chainhash.MaxHashStringSize {
		return nil, errors.New("outpoint txid should be 64 hex chars")
	}

	hash, err := chainhash.NewHashFromStr(parts[0])
	if err != nil {
		return nil, err
	}

	outputIndex, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid output index: %v", err)
	}

	return &OutPoint{
		Hash:  *hash,
		Index: uint32(outputIndex),
	}, nil
}

// String returns the OutPoint in the human-readable form "hash:index".
func (o OutPoint) String() string {
	// Allocate enough for hash string, colon, and 10 digits.  Although
	// at the time of writing, the number of digits can be no greater than
	// the length of the decimal representation of maxTxOutPerMessage, the
	// maximum message payload may increase in the future and this
	// optimization may go unnoticed, so allocate space for 10 decimal
	// digits, which will fit any uint32.
	buf := make([]byte, 2*chainhash.HashSize+1, 2*chainhash.HashSize+1+10)
	copy(buf, o.Hash.String())
	buf[2*chainhash.HashSize] = ':'
	buf = strconv.AppendUint(buf, uint64(o.Index), 10)
	return string(buf)
}

// TxIn defines a Handshake transaction input.  Unlike Bitcoin, Handshake
// inputs do not have a SignatureScript field; all witness data lives in the
// Witness field which is serialized after the locktime.
type TxIn struct {
	PreviousOutPoint OutPoint
	Sequence         uint32
	Witness          TxWitness
}

// SerializeSize returns the number of bytes it would take to serialize the
// transaction input (without witness, which is serialized separately).
func (t *TxIn) SerializeSize() int {
	// Outpoint Hash 32 bytes + Outpoint Index 4 bytes + Sequence 4 bytes.
	return 40
}

// NewTxIn returns a new Handshake transaction input with the provided previous
// outpoint and sequence number.  If witness is non-nil, it is set on the input.
func NewTxIn(prevOut *OutPoint, sequence uint32, witness [][]byte) *TxIn {
	return &TxIn{
		PreviousOutPoint: *prevOut,
		Sequence:         sequence,
		Witness:          witness,
	}
}

// TxWitness defines the witness for a TxIn. A witness is to be interpreted as
// a slice of byte slices, or a stack with one or many elements.
type TxWitness [][]byte

// SerializeSize returns the number of bytes it would take to serialize the
// transaction input's witness.
func (t TxWitness) SerializeSize() int {
	// A varint to signal the number of elements the witness has.
	n := VarIntSerializeSize(uint64(len(t)))

	// For each element in the witness, we'll need a varint to signal the
	// size of the element, then finally the number of bytes the element
	// itself comprises.
	for _, witItem := range t {
		n += VarIntSerializeSize(uint64(len(witItem)))
		n += len(witItem)
	}

	return n
}

// Encode serializes the witness to w.
//
// Wire format: varint(itemCount) + for each item: varint(itemLen) + itemBytes
func (t TxWitness) Encode(w io.Writer) error {
	err := WriteVarInt(w, 0, uint64(len(t)))
	if err != nil {
		return err
	}
	for _, item := range t {
		err = WriteVarBytes(w, 0, item)
		if err != nil {
			return err
		}
	}
	return nil
}

// ToHexStrings formats the witness stack as a slice of hex-encoded strings.
func (t TxWitness) ToHexStrings() []string {
	// Ensure nil is returned when there are no entries versus an empty
	// slice so it can properly be omitted as necessary.
	if len(t) == 0 {
		return nil
	}

	result := make([]string, len(t))
	for idx, wit := range t {
		result[idx] = hex.EncodeToString(wit)
	}

	return result
}

// TxOut defines a Handshake transaction output.  Unlike Bitcoin, outputs have
// an Address and Covenant instead of a PkScript.
type TxOut struct {
	Value    int64
	Address  Address
	Covenant Covenant
}

// SerializeSize returns the number of bytes it would take to serialize the
// transaction output.
func (t *TxOut) SerializeSize() int {
	// Value 8 bytes + Address serialized size + Covenant serialized size.
	return 8 + t.Address.SerializeSize() + t.Covenant.SerializeSize()
}

// NewTxOut returns a new Handshake transaction output with the provided
// transaction value, address, and covenant.
func NewTxOut(value int64, addr Address, covenant Covenant) *TxOut {
	return &TxOut{
		Value:    value,
		Address:  addr,
		Covenant: covenant,
	}
}

// MsgTx implements the Message interface and represents a Handshake tx message.
// It is used to deliver transaction information in response to a getdata
// message (MsgGetData) for a given transaction.
//
// Use the AddTxIn and AddTxOut functions to build up the list of transaction
// inputs and outputs.
type MsgTx struct {
	Version  uint32
	TxIn     []*TxIn
	TxOut    []*TxOut
	LockTime uint32
}

// AddTxIn adds a transaction input to the message.
func (msg *MsgTx) AddTxIn(ti *TxIn) {
	msg.TxIn = append(msg.TxIn, ti)
}

// AddTxOut adds a transaction output to the message.
func (msg *MsgTx) AddTxOut(to *TxOut) {
	msg.TxOut = append(msg.TxOut, to)
}

// TxHash generates the Hash for the transaction using Blake2b-256.
// The hash covers version through locktime (no witness data).
func (msg *MsgTx) TxHash() chainhash.Hash {
	var buf bytes.Buffer
	if err := msg.SerializeNoWitness(&buf); err != nil {
		// Panic on serialization failure — hashing truncated data
		// silently produces incorrect tx IDs.
		panic("MsgTx.TxHash: SerializeNoWitness failed: " + err.Error())
	}
	return chainhash.Hash(blake2b.Sum256(buf.Bytes()))
}

// TxID generates the transaction ID of the transaction.
func (msg *MsgTx) TxID() string {
	return msg.TxHash().String()
}

// WitnessHash generates the witness-committed hash of the transaction.
// It is Blake2b-256(txHash || Blake2b-256(witnessData)).
func (msg *MsgTx) WitnessHash() chainhash.Hash {
	txHash := msg.TxHash()

	// Serialize just witness bytes.
	var witBuf bytes.Buffer
	for _, txIn := range msg.TxIn {
		// Ignore errors.
		_ = txIn.Witness.Encode(&witBuf)
	}
	witHash := blake2b.Sum256(witBuf.Bytes())

	// Blake2b-256(txHash || witHash)
	h, _ := blake2b.New256(nil)
	h.Write(txHash[:])
	h.Write(witHash[:])
	var result chainhash.Hash
	copy(result[:], h.Sum(nil))
	return result
}

// Copy creates a deep copy of a transaction so that the original does not get
// modified when the copy is manipulated.
func (msg *MsgTx) Copy() *MsgTx {
	// Create new tx and start by copying primitive values and making space
	// for the transaction inputs and outputs.
	newTx := MsgTx{
		Version:  msg.Version,
		TxIn:     make([]*TxIn, 0, len(msg.TxIn)),
		TxOut:    make([]*TxOut, 0, len(msg.TxOut)),
		LockTime: msg.LockTime,
	}

	// Deep copy the old TxIn data.
	for _, oldTxIn := range msg.TxIn {
		// Deep copy the old previous outpoint.
		oldOutPoint := oldTxIn.PreviousOutPoint
		newOutPoint := OutPoint{}
		newOutPoint.Hash.SetBytes(oldOutPoint.Hash[:])
		newOutPoint.Index = oldOutPoint.Index

		// Create new txIn with the deep copied data.
		newTxIn := TxIn{
			PreviousOutPoint: newOutPoint,
			Sequence:         oldTxIn.Sequence,
		}

		// Deep copy witness data.
		if len(oldTxIn.Witness) != 0 {
			newTxIn.Witness = make([][]byte, len(oldTxIn.Witness))
			for i, oldItem := range oldTxIn.Witness {
				newItem := make([]byte, len(oldItem))
				copy(newItem, oldItem)
				newTxIn.Witness[i] = newItem
			}
		}

		newTx.TxIn = append(newTx.TxIn, &newTxIn)
	}

	// Deep copy the old TxOut data.
	for _, oldTxOut := range msg.TxOut {
		// Deep copy address hash.
		newAddrHash := make([]byte, len(oldTxOut.Address.Hash))
		copy(newAddrHash, oldTxOut.Address.Hash)

		// Deep copy covenant items.
		var newItems [][]byte
		if len(oldTxOut.Covenant.Items) > 0 {
			newItems = make([][]byte, len(oldTxOut.Covenant.Items))
			for i, item := range oldTxOut.Covenant.Items {
				newItem := make([]byte, len(item))
				copy(newItem, item)
				newItems[i] = newItem
			}
		}

		newTxOut := TxOut{
			Value: oldTxOut.Value,
			Address: Address{
				Version: oldTxOut.Address.Version,
				Hash:    newAddrHash,
			},
			Covenant: Covenant{
				Type:  oldTxOut.Covenant.Type,
				Items: newItems,
			},
		}
		newTx.TxOut = append(newTx.TxOut, &newTxOut)
	}

	return &newTx
}

// BtcDecode decodes r using the Handshake protocol encoding into the receiver.
// This is part of the Message interface implementation.
// See Deserialize for decoding transactions stored to disk, such as in a
// database, as opposed to decoding transactions from the wire.
func (msg *MsgTx) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	buf := binarySerializer.Borrow()
	defer binarySerializer.Return(buf)

	sbuf := scriptPool.Borrow()
	defer scriptPool.Return(sbuf)

	err := msg.btcDecode(r, pver, enc, buf, sbuf[:])
	return err
}

func (msg *MsgTx) btcDecode(r io.Reader, pver uint32, enc MessageEncoding,
	buf, sbuf []byte) error {

	// Read version (4 bytes LE uint32).
	if _, err := io.ReadFull(r, buf[:4]); err != nil {
		return err
	}
	msg.Version = littleEndian.Uint32(buf[:4])

	// Read input count.
	count, err := ReadVarIntBuf(r, pver, buf)
	if err != nil {
		return err
	}

	// Prevent more input transactions than could possibly fit into a
	// message.
	if count > uint64(maxTxInPerMessage) {
		str := fmt.Sprintf("too many input transactions to fit into "+
			"max message size [count %d, max %d]", count,
			maxTxInPerMessage)
		return messageError("MsgTx.BtcDecode", str)
	}

	// Deserialize the inputs.
	txIns := make([]TxIn, count)
	msg.TxIn = make([]*TxIn, count)
	for i := uint64(0); i < count; i++ {
		ti := &txIns[i]
		msg.TxIn[i] = ti
		err = readTxInBuf(r, pver, msg.Version, ti, buf)
		if err != nil {
			return err
		}
	}

	// Read output count.
	count, err = ReadVarIntBuf(r, pver, buf)
	if err != nil {
		return err
	}

	// Prevent more output transactions than could possibly fit into a
	// message.
	if count > uint64(maxTxOutPerMessage) {
		str := fmt.Sprintf("too many output transactions to fit into "+
			"max message size [count %d, max %d]", count,
			maxTxOutPerMessage)
		return messageError("MsgTx.BtcDecode", str)
	}

	// Deserialize the outputs.
	txOuts := make([]TxOut, count)
	msg.TxOut = make([]*TxOut, count)
	for i := uint64(0); i < count; i++ {
		to := &txOuts[i]
		msg.TxOut[i] = to
		err = readTxOutBuf(r, pver, msg.Version, to, buf)
		if err != nil {
			return err
		}
	}

	// Read locktime (4 bytes LE uint32).
	if _, err := io.ReadFull(r, buf[:4]); err != nil {
		return err
	}
	msg.LockTime = littleEndian.Uint32(buf[:4])

	// In Handshake, witness data is serialized after locktime
	// (no segwit flag bytes). Only read when using WitnessEncoding.
	if enc == WitnessEncoding {
		var totalWitnessSize uint64
		for _, txin := range msg.TxIn {
			witCount, err := ReadVarIntBuf(r, pver, buf)
			if err != nil {
				return err
			}

			if witCount > maxWitnessItemsPerInput {
				str := fmt.Sprintf("too many witness items to fit "+
					"into max message size [count %d, max %d]",
					witCount, maxWitnessItemsPerInput)
				return messageError("MsgTx.BtcDecode", str)
			}

			// Each witness item needs at least 1 byte in the slab,
			// so the slab must have at least witCount bytes
			// available up front.
			if uint64(len(sbuf)) < witCount {
				str := fmt.Sprintf("witness item count %d "+
					"exceeds slab size %d",
					witCount, len(sbuf))
				return messageError("MsgTx.BtcDecode", str)
			}

			txin.Witness = make([][]byte, witCount)
			for j := uint64(0); j < witCount; j++ {
				txin.Witness[j], err = readScriptBuf(
					r, pver, buf, sbuf, len(sbuf),
					"script witness item",
				)
				if err != nil {
					return err
				}
				totalWitnessSize += uint64(len(txin.Witness[j]))
				sbuf = sbuf[len(txin.Witness[j]):]
			}
		}

		// Consolidate witness data into a single contiguous allocation to
		// reduce GC pressure.
		if totalWitnessSize > 0 {
			var offset uint64
			scripts := make([]byte, totalWitnessSize)
			for i := 0; i < len(msg.TxIn); i++ {
				for j := 0; j < len(msg.TxIn[i].Witness); j++ {
					witnessElem := msg.TxIn[i].Witness[j]
					copy(scripts[offset:], witnessElem)
					witnessElemSize := uint64(len(witnessElem))
					end := offset + witnessElemSize
					msg.TxIn[i].Witness[j] = scripts[offset:end:end]
					offset += witnessElemSize
				}
			}
		}
	}

	return nil
}

// Deserialize decodes a transaction from r into the receiver using a format
// that is suitable for long-term storage such as a database while respecting
// the Version field in the transaction.
func (msg *MsgTx) Deserialize(r io.Reader) error {
	return msg.BtcDecode(r, 0, WitnessEncoding)
}

// DeserializeNoWitness decodes a transaction from r into the receiver, where
// the transaction encoding format within r MUST NOT include witness data.
func (msg *MsgTx) DeserializeNoWitness(r io.Reader) error {
	return msg.BtcDecode(r, 0, BaseEncoding)
}

// BtcEncode encodes the receiver to w using the Handshake protocol encoding.
// This is part of the Message interface implementation.
// See Serialize for encoding transactions to be stored to disk, such as in a
// database, as opposed to encoding transactions for the wire.
func (msg *MsgTx) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	buf := binarySerializer.Borrow()
	defer binarySerializer.Return(buf)

	err := msg.btcEncode(w, pver, enc, buf)
	return err
}

func (msg *MsgTx) btcEncode(w io.Writer, pver uint32, enc MessageEncoding,
	buf []byte) error {

	// Write version (4 bytes LE uint32).
	littleEndian.PutUint32(buf[:4], msg.Version)
	if _, err := w.Write(buf[:4]); err != nil {
		return err
	}

	// Write input count.
	count := uint64(len(msg.TxIn))
	err := WriteVarIntBuf(w, pver, count, buf)
	if err != nil {
		return err
	}

	// Write each input (prevhash + previndex + sequence).
	for _, ti := range msg.TxIn {
		err = writeTxInBuf(w, pver, msg.Version, ti, buf)
		if err != nil {
			return err
		}
	}

	// Write output count.
	count = uint64(len(msg.TxOut))
	err = WriteVarIntBuf(w, pver, count, buf)
	if err != nil {
		return err
	}

	// Write each output (value + address + covenant).
	for _, to := range msg.TxOut {
		err = WriteTxOutBuf(w, pver, msg.Version, to, buf)
		if err != nil {
			return err
		}
	}

	// Write locktime (4 bytes LE uint32).
	littleEndian.PutUint32(buf[:4], msg.LockTime)
	if _, err := w.Write(buf[:4]); err != nil {
		return err
	}

	// Write witness data for each input (only with WitnessEncoding).
	if enc == WitnessEncoding {
		for _, ti := range msg.TxIn {
			err = writeTxWitnessBuf(w, pver, ti.Witness, buf)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// HasWitness returns false if none of the inputs within the transaction
// contain witness data, true otherwise.
func (msg *MsgTx) HasWitness() bool {
	for _, txIn := range msg.TxIn {
		if len(txIn.Witness) != 0 {
			return true
		}
	}

	return false
}

// Serialize encodes the transaction to w using a format that is suitable for
// long-term storage such as a database while respecting the Version field in
// the transaction.
func (msg *MsgTx) Serialize(w io.Writer) error {
	return msg.BtcEncode(w, 0, WitnessEncoding)
}

// SerializeNoWitness encodes the transaction to w without witness data.
// This is used for computing the transaction hash (TxHash).
func (msg *MsgTx) SerializeNoWitness(w io.Writer) error {
	buf := binarySerializer.Borrow()
	defer binarySerializer.Return(buf)

	// Write version.
	littleEndian.PutUint32(buf[:4], msg.Version)
	if _, err := w.Write(buf[:4]); err != nil {
		return err
	}

	// Write input count.
	count := uint64(len(msg.TxIn))
	err := WriteVarIntBuf(w, 0, count, buf)
	if err != nil {
		return err
	}

	// Write each input (no witness).
	for _, ti := range msg.TxIn {
		err = writeTxInBuf(w, 0, msg.Version, ti, buf)
		if err != nil {
			return err
		}
	}

	// Write output count.
	count = uint64(len(msg.TxOut))
	err = WriteVarIntBuf(w, 0, count, buf)
	if err != nil {
		return err
	}

	// Write each output.
	for _, to := range msg.TxOut {
		err = WriteTxOutBuf(w, 0, msg.Version, to, buf)
		if err != nil {
			return err
		}
	}

	// Write locktime.
	littleEndian.PutUint32(buf[:4], msg.LockTime)
	_, err = w.Write(buf[:4])
	return err
}

// baseSize returns the serialized size of the transaction without accounting
// for any witness data.
func (msg *MsgTx) baseSize() int {
	// Version 4 bytes + LockTime 4 bytes + Serialized varint size for the
	// number of transaction inputs and outputs.
	n := 8 + VarIntSerializeSize(uint64(len(msg.TxIn))) +
		VarIntSerializeSize(uint64(len(msg.TxOut)))

	for _, txIn := range msg.TxIn {
		n += txIn.SerializeSize()
	}

	for _, txOut := range msg.TxOut {
		n += txOut.SerializeSize()
	}

	return n
}

// SerializeSize returns the number of bytes it would take to serialize the
// transaction (including witness data).
func (msg *MsgTx) SerializeSize() int {
	n := msg.baseSize()

	// Add witness size for each input.
	for _, txin := range msg.TxIn {
		n += txin.Witness.SerializeSize()
	}

	return n
}

// SerializeSizeStripped returns the number of bytes it would take to serialize
// the transaction, excluding any included witness data.
func (msg *MsgTx) SerializeSizeStripped() int {
	return msg.baseSize()
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgTx) Command() string {
	return CmdTx
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgTx) MaxPayloadLength(pver uint32) uint32 {
	return MaxBlockPayload
}

// NewMsgTx returns a new Handshake tx message that conforms to the Message
// interface.  The return instance has a default version of TxVersion and there
// are no transaction inputs or outputs.  Also, the lock time is set to zero
// to indicate the transaction is valid immediately as opposed to some time in
// future.
func NewMsgTx(version uint32) *MsgTx {
	return &MsgTx{
		Version: version,
		TxIn:    make([]*TxIn, 0, defaultTxInOutAlloc),
		TxOut:   make([]*TxOut, 0, defaultTxInOutAlloc),
	}
}

// readOutPointBuf reads the next sequence of bytes from r as an OutPoint.
//
// NOTE: buf MUST be at least an 8-byte slice.
func readOutPointBuf(r io.Reader, pver uint32, version uint32, op *OutPoint,
	buf []byte) error {

	_, err := io.ReadFull(r, op.Hash[:])
	if err != nil {
		return err
	}

	if _, err := io.ReadFull(r, buf[:4]); err != nil {
		return err
	}
	op.Index = littleEndian.Uint32(buf[:4])

	return nil
}

// WriteOutPoint encodes op to the Handshake protocol encoding for an OutPoint
// to w.
func WriteOutPoint(w io.Writer, pver uint32, version uint32, op *OutPoint) error {
	buf := binarySerializer.Borrow()
	defer binarySerializer.Return(buf)

	err := writeOutPointBuf(w, pver, version, op, buf)
	return err
}

// writeOutPointBuf encodes op to the Handshake protocol encoding for an
// OutPoint to w.
//
// NOTE: buf MUST be at least an 8-byte slice.
func writeOutPointBuf(w io.Writer, pver uint32, version uint32, op *OutPoint,
	buf []byte) error {

	_, err := w.Write(op.Hash[:])
	if err != nil {
		return err
	}

	littleEndian.PutUint32(buf[:4], op.Index)
	_, err = w.Write(buf[:4])
	return err
}

// readScriptBuf reads a variable length byte array that represents a witness
// item.  It is encoded as a varInt containing the length of the array followed
// by the bytes themselves.
//
// NOTE: buf MUST be at least an 8-byte slice.
func readScriptBuf(r io.Reader, pver uint32, buf, s []byte, slabRemaining int,
	fieldName string) ([]byte, error) {

	count, err := ReadVarIntBuf(r, pver, buf)
	if err != nil {
		return nil, err
	}

	if count > uint64(slabRemaining) {
		str := fmt.Sprintf("%s size %d exceeds remaining slab size %d",
			fieldName, count, slabRemaining)
		return nil, messageError("readScript", str)
	}

	// Prevent byte array larger than the max message size.
	if count > maxWitnessItemSize {
		str := fmt.Sprintf("%s is larger than the max allowed size "+
			"[count %d, max %d]", fieldName, count, maxWitnessItemSize)
		return nil, messageError("readScript", str)
	}

	_, err = io.ReadFull(r, s[:count])
	if err != nil {
		return nil, err
	}
	return s[:count], nil
}

// readTxInBuf reads the next sequence of bytes from r as a Handshake
// transaction input (TxIn): prevhash(32) + previndex(4) + sequence(4).
//
// NOTE: buf MUST be at least an 8-byte slice.
func readTxInBuf(r io.Reader, pver uint32, version uint32, ti *TxIn,
	buf []byte) error {

	err := readOutPointBuf(r, pver, version, &ti.PreviousOutPoint, buf)
	if err != nil {
		return err
	}

	if _, err := io.ReadFull(r, buf[:4]); err != nil {
		return err
	}

	ti.Sequence = littleEndian.Uint32(buf[:4])

	return nil
}

// writeTxInBuf encodes ti to the Handshake protocol encoding for a transaction
// input (TxIn) to w: prevhash(32) + previndex(4) + sequence(4).
func writeTxInBuf(w io.Writer, pver uint32, version uint32, ti *TxIn,
	buf []byte) error {

	err := writeOutPointBuf(w, pver, version, &ti.PreviousOutPoint, buf)
	if err != nil {
		return err
	}

	littleEndian.PutUint32(buf[:4], ti.Sequence)
	_, err = w.Write(buf[:4])

	return err
}

// ReadTxOut reads the next sequence of bytes from r as a Handshake transaction
// output (TxOut): value(8) + address + covenant.
func ReadTxOut(r io.Reader, pver uint32, version uint32, to *TxOut) error {
	buf := binarySerializer.Borrow()
	defer binarySerializer.Return(buf)

	err := readTxOutBuf(r, pver, version, to, buf)
	return err
}

// readTxOutBuf reads the next sequence of bytes from r as a Handshake
// transaction output (TxOut): value(8) + address + covenant.
func readTxOutBuf(r io.Reader, pver uint32, version uint32, to *TxOut,
	buf []byte) error {

	// Read value (8 bytes LE int64).
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	to.Value = int64(littleEndian.Uint64(buf))

	// Read address.
	if err := to.Address.Decode(r); err != nil {
		return err
	}

	// Read covenant.
	if err := to.Covenant.Decode(r); err != nil {
		return err
	}

	return nil
}

// WriteTxOut encodes to into the Handshake protocol encoding for a transaction
// output (TxOut) to w: value(8) + address + covenant.
//
// NOTE: This function is exported in order to allow txscript to compute
// sighashes.
func WriteTxOut(w io.Writer, pver uint32, version uint32, to *TxOut) error {
	buf := binarySerializer.Borrow()
	defer binarySerializer.Return(buf)

	err := WriteTxOutBuf(w, pver, version, to, buf)
	return err
}

// WriteTxOutBuf encodes to into the Handshake protocol encoding for a
// transaction output (TxOut) to w: value(8) + address + covenant.
//
// NOTE: This function is exported in order to allow txscript to compute
// sighashes.
func WriteTxOutBuf(w io.Writer, pver uint32, version uint32, to *TxOut,
	buf []byte) error {

	littleEndian.PutUint64(buf, uint64(to.Value))
	_, err := w.Write(buf)
	if err != nil {
		return err
	}

	// Write address.
	if err := to.Address.Encode(w); err != nil {
		return err
	}

	// Write covenant.
	return to.Covenant.Encode(w)
}

// writeTxWitnessBuf encodes the Handshake protocol encoding for a transaction
// input's witness to w.
func writeTxWitnessBuf(w io.Writer, pver uint32, wit [][]byte,
	buf []byte) error {

	err := WriteVarIntBuf(w, pver, uint64(len(wit)), buf)
	if err != nil {
		return err
	}
	for _, item := range wit {
		err = WriteVarBytesBuf(w, pver, item, buf)
		if err != nil {
			return err
		}
	}

	return nil
}
