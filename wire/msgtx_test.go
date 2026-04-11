// Copyright (c) 2013-2016 The btcsuite developers
// Copyright (c) 2024-2025 The blinklabs-io developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"reflect"
	"testing"

	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

// hnsTestTxHex is a real Handshake coinbase transaction from cdnsd.
// Parsed structure:
//
//	version(4): 00000000 = 0
//	input count: 01 = 1
//	input: prevhash(32 zeros) + previndex(ffffffff) + sequence(3b2cf814)
//	output count: 01 = 1
//	output: value(34369b3b00000000 LE = 1000027700) +
//	        address(version=00, hashLen=14=20,
//	                hash=98c8297a67eb81ec36253828b5621a601ba2328a) +
//	        covenant(type=00, items=00 = NONE with 0 items)
//	locktime: a6220400 = 271014
//	witness for input 0: count=03,
//	        item1(06 bytes: 566961425443),
//	        item2(08 bytes: 7c524fd539e1eab8),
//	        item3(08 bytes: 0000000000000000)
const hnsTestTxHex = "00000000" + // version
	"01" + // 1 input
	"0000000000000000000000000000000000000000000000000000000000000000" + // prev hash
	"ffffffff" + // prev index
	"3b2cf814" + // sequence (LE: 0x14f82c3b)
	"01" + // 1 output
	"34369b3b00000000" + // value (LE: 0x3b9b3634 = 1000027700)
	"00" + // address version 0
	"14" + // address hash length 20
	"98c8297a67eb81ec36253828b5621a601ba2328a" + // address hash
	"00" + // covenant type NONE
	"00" + // covenant 0 items
	"a6220400" + // locktime (LE: 0x000422a6 = 271014)
	"03" + // witness: 3 items for input 0
	"06" + "566961425443" + // item 1 (6 bytes)
	"08" + "7c524fd539e1eab8" + // item 2 (8 bytes)
	"08" + "0000000000000000" // item 3 (8 bytes)

// hnsTestTxHash is the TxHash in display order (byte-reversed hex, as used by
// chainhash.Hash.String() and chainhash.NewHashFromStr).
// Raw blake2b-256 bytes: 1881afbe757f9d433144edf49e29c7f6bbfdbc1941d06792dc5ee13020d63570
const hnsTestTxHash = "7035d62030e15edc9267d04119bcfdbbf6c7299ef4ed4431439d7f75beaf8118"

// hnsTestWitnessHash is the WitnessHash in display order.
// Raw bytes: d36b1e9861dd504629b053d14d9801b295667a4c7002c9d2836be502bfdb3b3a
const hnsTestWitnessHash = "3a3bdbbf02e56b83d2c902704c7a6695b201984dd153b0294650dd61981e6bd3"

// mustDecodeHex decodes a hex string and panics on error.
func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("mustDecodeHex: " + err.Error())
	}
	return b
}

// buildHnsTestTx constructs the Handshake test transaction as a MsgTx struct.
func buildHnsTestTx() *MsgTx {
	tx := NewMsgTx(0)

	// Input: coinbase (all-zeros hash, index 0xffffffff).
	prevOut := NewOutPoint(&chainhash.Hash{}, 0xffffffff)
	txIn := NewTxIn(prevOut, 0x14f82c3b, [][]byte{
		mustDecodeHex("566961425443"),
		mustDecodeHex("7c524fd539e1eab8"),
		mustDecodeHex("0000000000000000"),
	})
	tx.AddTxIn(txIn)

	// Output: value 1000027700 (0x3b9b3634 LE), version-0 address, NONE covenant.
	addr := Address{
		Version: 0,
		Hash:    mustDecodeHex("98c8297a67eb81ec36253828b5621a601ba2328a"),
	}
	cov := Covenant{Type: CovenantNone}
	txOut := NewTxOut(1000027700, addr, cov)
	tx.AddTxOut(txOut)

	tx.LockTime = 271014
	return tx
}

// TestTx tests the MsgTx API with Handshake transaction types.
func TestTx(t *testing.T) {
	pver := ProtocolVersion

	// Block 100000 hash.
	hashStr := "3ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506"
	hash, err := chainhash.NewHashFromStr(hashStr)
	if err != nil {
		t.Errorf("NewHashFromStr: %v", err)
	}

	// Ensure the command is expected value.
	wantCmd := "tx"
	msg := NewMsgTx(0)
	if cmd := msg.Command(); cmd != wantCmd {
		t.Errorf("NewMsgTx: wrong command - got %v want %v",
			cmd, wantCmd)
	}

	// Ensure max payload is expected value for latest protocol version.
	wantPayload := uint32(1000 * 4000)
	maxPayload := msg.MaxPayloadLength(pver)
	if maxPayload != wantPayload {
		t.Errorf("MaxPayloadLength: wrong max payload length for "+
			"protocol version %d - got %v, want %v", pver,
			maxPayload, wantPayload)
	}

	// Ensure we get the same transaction output point data back out.
	prevOutIndex := uint32(1)
	prevOut := NewOutPoint(hash, prevOutIndex)
	if !prevOut.Hash.IsEqual(hash) {
		t.Errorf("NewOutPoint: wrong hash - got %v, want %v",
			spew.Sprint(&prevOut.Hash), spew.Sprint(hash))
	}
	if prevOut.Index != prevOutIndex {
		t.Errorf("NewOutPoint: wrong index - got %v, want %v",
			prevOut.Index, prevOutIndex)
	}
	prevOutStr := fmt.Sprintf("%s:%d", hash.String(), prevOutIndex)
	if s := prevOut.String(); s != prevOutStr {
		t.Errorf("OutPoint.String: unexpected result - got %v, "+
			"want %v", s, prevOutStr)
	}

	// Ensure we get the same transaction input back out.
	witnessData := [][]byte{
		{0x04, 0x31},
		{0x01, 0x43},
	}
	txIn := NewTxIn(prevOut, MaxTxInSequenceNum, witnessData)
	if !reflect.DeepEqual(&txIn.PreviousOutPoint, prevOut) {
		t.Errorf("NewTxIn: wrong prev outpoint - got %v, want %v",
			spew.Sprint(&txIn.PreviousOutPoint),
			spew.Sprint(prevOut))
	}
	if txIn.Sequence != MaxTxInSequenceNum {
		t.Errorf("NewTxIn: wrong sequence - got %v, want %v",
			txIn.Sequence, MaxTxInSequenceNum)
	}
	if !reflect.DeepEqual(txIn.Witness, TxWitness(witnessData)) {
		t.Errorf("NewTxIn: wrong witness data - got %v, want %v",
			spew.Sdump(txIn.Witness),
			spew.Sdump(witnessData))
	}

	// Ensure we get the same transaction output back out.
	txValue := int64(5000000000)
	addr := Address{Version: 0, Hash: make([]byte, 20)}
	cov := Covenant{Type: CovenantNone}
	txOut := NewTxOut(txValue, addr, cov)
	if txOut.Value != txValue {
		t.Errorf("NewTxOut: wrong value - got %v, want %v",
			txOut.Value, txValue)
	}
	if txOut.Address.Version != 0 {
		t.Errorf("NewTxOut: wrong address version - got %v, want 0",
			txOut.Address.Version)
	}
	if txOut.Covenant.Type != CovenantNone {
		t.Errorf("NewTxOut: wrong covenant type - got %v, want %v",
			txOut.Covenant.Type, CovenantNone)
	}

	// Ensure transaction inputs are added properly.
	msg.AddTxIn(txIn)
	if !reflect.DeepEqual(msg.TxIn[0], txIn) {
		t.Errorf("AddTxIn: wrong transaction input added - got %v, want %v",
			spew.Sprint(msg.TxIn[0]), spew.Sprint(txIn))
	}

	// Ensure transaction outputs are added properly.
	msg.AddTxOut(txOut)
	if !reflect.DeepEqual(msg.TxOut[0], txOut) {
		t.Errorf("AddTxOut: wrong transaction output added - got %v, want %v",
			spew.Sprint(msg.TxOut[0]), spew.Sprint(txOut))
	}

	// Ensure the copy produced an identical transaction message.
	newMsg := msg.Copy()
	if !reflect.DeepEqual(newMsg, msg) {
		t.Errorf("Copy: mismatched tx messages - got %v, want %v",
			spew.Sdump(newMsg), spew.Sdump(msg))
	}
}

// TestTxHash tests the ability to generate the hash of a Handshake transaction
// accurately using the known cdnsd test vector.
func TestTxHash(t *testing.T) {
	wantHash, err := chainhash.NewHashFromStr(hnsTestTxHash)
	if err != nil {
		t.Fatalf("NewHashFromStr: %v", err)
	}

	msgTx := buildHnsTestTx()

	txHash := msgTx.TxHash()
	if !txHash.IsEqual(wantHash) {
		t.Errorf("TxHash: wrong hash - got %v, want %v",
			txHash.String(), wantHash.String())
	}
}

// TestWitnessHash tests the ability to generate the witness hash of a
// Handshake transaction.
func TestWitnessHash(t *testing.T) {
	wantHash, err := chainhash.NewHashFromStr(hnsTestWitnessHash)
	if err != nil {
		t.Fatalf("NewHashFromStr: %v", err)
	}

	msgTx := buildHnsTestTx()

	wtxHash := msgTx.WitnessHash()
	if !wtxHash.IsEqual(wantHash) {
		t.Errorf("WitnessHash: wrong hash - got %v, want %v",
			wtxHash.String(), wantHash.String())
	}
}

// TestMsgTxSerialize tests round-trip serialize/deserialize of a Handshake
// transaction.
func TestMsgTxSerialize(t *testing.T) {
	txBytes := mustDecodeHex(hnsTestTxHex)

	// Deserialize from known bytes.
	var gotTx MsgTx
	err := gotTx.Deserialize(bytes.NewReader(txBytes))
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}

	// Verify key fields.
	if gotTx.Version != 0 {
		t.Errorf("Version: got %d, want 0", gotTx.Version)
	}
	if len(gotTx.TxIn) != 1 {
		t.Fatalf("TxIn count: got %d, want 1", len(gotTx.TxIn))
	}
	if gotTx.TxIn[0].Sequence != 0x14f82c3b {
		t.Errorf("Sequence: got 0x%x, want 0x14f82c3b", gotTx.TxIn[0].Sequence)
	}
	if len(gotTx.TxOut) != 1 {
		t.Fatalf("TxOut count: got %d, want 1", len(gotTx.TxOut))
	}
	if gotTx.TxOut[0].Value != 1000027700 {
		t.Errorf("Value: got %d, want 1000027700", gotTx.TxOut[0].Value)
	}
	if gotTx.TxOut[0].Address.Version != 0 {
		t.Errorf("Address version: got %d, want 0", gotTx.TxOut[0].Address.Version)
	}
	if gotTx.TxOut[0].Covenant.Type != CovenantNone {
		t.Errorf("Covenant type: got %d, want %d", gotTx.TxOut[0].Covenant.Type, CovenantNone)
	}
	if gotTx.LockTime != 271014 {
		t.Errorf("LockTime: got %d, want 271014", gotTx.LockTime)
	}
	if len(gotTx.TxIn[0].Witness) != 3 {
		t.Errorf("Witness count: got %d, want 3", len(gotTx.TxIn[0].Witness))
	}

	// Re-serialize and compare bytes (round-trip test).
	var buf bytes.Buffer
	err = gotTx.Serialize(&buf)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), txBytes) {
		t.Errorf("Serialize: round-trip mismatch\n got: %x\nwant: %x",
			buf.Bytes(), txBytes)
	}

	// Also test that buildHnsTestTx serializes to the same bytes.
	wantTx := buildHnsTestTx()
	var buf2 bytes.Buffer
	err = wantTx.Serialize(&buf2)
	if err != nil {
		t.Fatalf("Serialize buildHnsTestTx: %v", err)
	}
	if !bytes.Equal(buf2.Bytes(), txBytes) {
		t.Errorf("buildHnsTestTx Serialize mismatch\n got: %x\nwant: %x",
			buf2.Bytes(), txBytes)
	}
}

// TestMsgTxSerializeSize tests that SerializeSize is accurate.
func TestMsgTxSerializeSize(t *testing.T) {
	tx := buildHnsTestTx()
	txBytes := mustDecodeHex(hnsTestTxHex)

	gotSize := tx.SerializeSize()
	if gotSize != len(txBytes) {
		t.Errorf("SerializeSize: got %d, want %d",
			gotSize, len(txBytes))
	}
}

// TestMsgTxSerializeSizeStripped tests stripped (no-witness) serialize size.
func TestMsgTxSerializeSizeStripped(t *testing.T) {
	tx := buildHnsTestTx()

	// No-witness portion: version(4) + inputCount(1) + input(40) +
	// outputCount(1) + output(8 + 22 + 2) + locktime(4) = 82
	// Input: prevhash(32) + previndex(4) + sequence(4) = 40
	// Output: value(8) + addr(1+1+20=22) + covenant(1+1=2) = 32
	// Total = 4 + 1 + 40 + 1 + 32 + 4 = 82
	wantStripped := 82
	gotStripped := tx.SerializeSizeStripped()
	if gotStripped != wantStripped {
		t.Errorf("SerializeSizeStripped: got %d, want %d",
			gotStripped, wantStripped)
	}
}

// TestMsgTxCopy tests that Copy() produces a deep copy.
func TestMsgTxCopy(t *testing.T) {
	orig := buildHnsTestTx()
	cp := orig.Copy()

	if !reflect.DeepEqual(orig, cp) {
		t.Fatal("Copy: copy does not equal original")
	}

	// Mutate copy and ensure original is unchanged.
	cp.Version = 99
	if orig.Version == cp.Version {
		t.Fatal("Copy: version mutation leaked to original")
	}

	cp.TxIn[0].Sequence = 0
	if orig.TxIn[0].Sequence == 0 {
		t.Fatal("Copy: TxIn mutation leaked to original")
	}

	cp.TxOut[0].Value = 0
	if orig.TxOut[0].Value == 0 {
		t.Fatal("Copy: TxOut mutation leaked to original")
	}

	cp.TxOut[0].Address.Hash[0] = 0xff
	if orig.TxOut[0].Address.Hash[0] == 0xff {
		t.Fatal("Copy: Address hash mutation leaked to original")
	}

	cp.TxIn[0].Witness[0][0] = 0xff
	if orig.TxIn[0].Witness[0][0] == 0xff {
		t.Fatal("Copy: witness mutation leaked to original")
	}
}

// TestMsgTxHasWitness tests HasWitness with and without witness data.
func TestMsgTxHasWitness(t *testing.T) {
	// Transaction with witness.
	tx := buildHnsTestTx()
	if !tx.HasWitness() {
		t.Error("HasWitness: expected true for tx with witness data")
	}

	// Transaction without witness.
	txNoWit := NewMsgTx(0)
	prevOut := NewOutPoint(&chainhash.Hash{}, 0)
	txNoWit.AddTxIn(NewTxIn(prevOut, MaxTxInSequenceNum, nil))
	addr := Address{Version: 0, Hash: make([]byte, 20)}
	cov := Covenant{Type: CovenantNone}
	txNoWit.AddTxOut(NewTxOut(100, addr, cov))
	if txNoWit.HasWitness() {
		t.Error("HasWitness: expected false for tx without witness data")
	}
}

// TestNewTxIn tests the NewTxIn constructor.
func TestNewTxIn(t *testing.T) {
	prevOut := NewOutPoint(&chainhash.Hash{}, 42)
	seq := uint32(0x12345678)
	wit := [][]byte{{0x01, 0x02}, {0x03}}
	txIn := NewTxIn(prevOut, seq, wit)

	if !reflect.DeepEqual(&txIn.PreviousOutPoint, prevOut) {
		t.Errorf("wrong PreviousOutPoint")
	}
	if txIn.Sequence != seq {
		t.Errorf("wrong Sequence: got %d, want %d", txIn.Sequence, seq)
	}
	if !reflect.DeepEqual(txIn.Witness, TxWitness(wit)) {
		t.Errorf("wrong Witness")
	}
}

// TestNewTxOut tests the NewTxOut constructor.
func TestNewTxOut(t *testing.T) {
	addr := Address{
		Version: 0,
		Hash:    mustDecodeHex("98c8297a67eb81ec36253828b5621a601ba2328a"),
	}
	cov := Covenant{
		Type:  CovenantOpen,
		Items: [][]byte{{0xaa, 0xbb}},
	}
	txOut := NewTxOut(42, addr, cov)

	if txOut.Value != 42 {
		t.Errorf("wrong Value: got %d, want 42", txOut.Value)
	}
	if txOut.Address.Version != addr.Version {
		t.Errorf("wrong Address.Version")
	}
	if !bytes.Equal(txOut.Address.Hash, addr.Hash) {
		t.Errorf("wrong Address.Hash")
	}
	if txOut.Covenant.Type != CovenantOpen {
		t.Errorf("wrong Covenant.Type")
	}
}

// TestTxInSerializeSize tests TxIn.SerializeSize.
func TestTxInSerializeSize(t *testing.T) {
	prevOut := NewOutPoint(&chainhash.Hash{}, 0)
	txIn := NewTxIn(prevOut, MaxTxInSequenceNum, nil)
	// prevhash(32) + previndex(4) + sequence(4) = 40
	if txIn.SerializeSize() != 40 {
		t.Errorf("TxIn.SerializeSize: got %d, want 40",
			txIn.SerializeSize())
	}
}

// TestTxOutSerializeSize tests TxOut.SerializeSize.
func TestTxOutSerializeSize(t *testing.T) {
	// value(8) + addr(1+1+20=22) + covenant(1+1=2) = 32
	addr := Address{Version: 0, Hash: make([]byte, 20)}
	cov := Covenant{Type: CovenantNone}
	txOut := NewTxOut(100, addr, cov)
	want := 32
	if txOut.SerializeSize() != want {
		t.Errorf("TxOut.SerializeSize: got %d, want %d",
			txOut.SerializeSize(), want)
	}

	// With a covenant that has items.
	cov2 := Covenant{
		Type:  CovenantOpen,
		Items: [][]byte{make([]byte, 10)},
	}
	txOut2 := NewTxOut(100, addr, cov2)
	// value(8) + addr(22) + covenant(1 + 1 + 1+10 = 13) = 43
	want2 := 43
	if txOut2.SerializeSize() != want2 {
		t.Errorf("TxOut.SerializeSize with covenant: got %d, want %d",
			txOut2.SerializeSize(), want2)
	}
}

// TestTxWire tests the MsgTx wire encode and decode for various protocol
// versions using Handshake transaction format.
func TestTxWire(t *testing.T) {
	// Empty tx message (no inputs, no outputs).
	noTx := NewMsgTx(0)
	noTxEncoded := []byte{
		0x00, 0x00, 0x00, 0x00, // Version 0
		0x00,                   // Varint for number of inputs
		0x00,                   // Varint for number of outputs
		0x00, 0x00, 0x00, 0x00, // Lock time
	}

	// Handshake test transaction.
	hnsTx := buildHnsTestTx()
	hnsTxEncoded := mustDecodeHex(hnsTestTxHex)

	tests := []struct {
		in   *MsgTx          // Message to encode
		buf  []byte          // Wire encoding
		pver uint32          // Protocol version for wire encoding
		enc  MessageEncoding // Message encoding format
	}{
		// Latest protocol version with no transactions.
		{noTx, noTxEncoded, ProtocolVersion, WitnessEncoding},
		// Latest protocol version with Handshake test tx.
		{hnsTx, hnsTxEncoded, ProtocolVersion, WitnessEncoding},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// Encode the message to wire format.
		var buf bytes.Buffer
		err := test.in.BtcEncode(&buf, test.pver, test.enc)
		if err != nil {
			t.Errorf("BtcEncode #%d error %v", i, err)
			continue
		}
		if !bytes.Equal(buf.Bytes(), test.buf) {
			t.Errorf("BtcEncode #%d\n got: %s want: %s", i,
				spew.Sdump(buf.Bytes()), spew.Sdump(test.buf))
			continue
		}

		// Decode the message from wire format and re-encode to verify
		// round-trip (avoids reflect.DeepEqual issues with slice capacities).
		var msg MsgTx
		rbuf := bytes.NewReader(test.buf)
		err = msg.BtcDecode(rbuf, test.pver, test.enc)
		if err != nil {
			t.Errorf("BtcDecode #%d error %v", i, err)
			continue
		}
		var rebuf bytes.Buffer
		err = msg.BtcEncode(&rebuf, test.pver, test.enc)
		if err != nil {
			t.Errorf("re-BtcEncode #%d error %v", i, err)
			continue
		}
		if !bytes.Equal(rebuf.Bytes(), test.buf) {
			t.Errorf("BtcDecode/BtcEncode round-trip #%d\n got: %s want: %s", i,
				spew.Sdump(rebuf.Bytes()), spew.Sdump(test.buf))
			continue
		}
	}
}

// TestTxWireErrors performs negative tests against wire encode and decode
// of MsgTx to confirm error paths work correctly.
func TestTxWireErrors(t *testing.T) {
	pver := ProtocolVersion
	hnsTx := buildHnsTestTx()
	hnsTxEncoded := mustDecodeHex(hnsTestTxHex)

	tests := []struct {
		in       *MsgTx          // Value to encode
		buf      []byte          // Wire encoding
		pver     uint32          // Protocol version for wire encoding
		enc      MessageEncoding // Message encoding format
		max      int             // Max size of fixed buffer to induce errors
		writeErr error           // Expected write error
		readErr  error           // Expected read error
	}{
		// Force error in version.
		{hnsTx, hnsTxEncoded, pver, WitnessEncoding, 0, io.ErrShortWrite, io.EOF},
		// Force error in number of transaction inputs.
		{hnsTx, hnsTxEncoded, pver, WitnessEncoding, 4, io.ErrShortWrite, io.EOF},
		// Force error in transaction input previous block hash.
		{hnsTx, hnsTxEncoded, pver, WitnessEncoding, 5, io.ErrShortWrite, io.EOF},
		// Force error in transaction input previous block output index.
		{hnsTx, hnsTxEncoded, pver, WitnessEncoding, 37, io.ErrShortWrite, io.EOF},
		// Force error in transaction input sequence.
		{hnsTx, hnsTxEncoded, pver, WitnessEncoding, 41, io.ErrShortWrite, io.EOF},
		// Force error in number of transaction outputs.
		{hnsTx, hnsTxEncoded, pver, WitnessEncoding, 45, io.ErrShortWrite, io.EOF},
		// Force error in transaction output value.
		{hnsTx, hnsTxEncoded, pver, WitnessEncoding, 46, io.ErrShortWrite, io.EOF},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// Encode to wire format.
		w := newFixedWriter(test.max)
		err := test.in.BtcEncode(w, test.pver, test.enc)
		if err != test.writeErr {
			t.Errorf("BtcEncode #%d wrong error got: %v, want: %v",
				i, err, test.writeErr)
			continue
		}

		// Decode from wire format.
		var msg MsgTx
		r := newFixedReader(test.max, test.buf)
		err = msg.BtcDecode(r, test.pver, test.enc)
		if err != test.readErr {
			t.Errorf("BtcDecode #%d wrong error got: %v, want: %v",
				i, err, test.readErr)
			continue
		}
	}
}

// TestTxSerialize tests MsgTx serialize and deserialize for Handshake
// transactions.
func TestTxSerialize(t *testing.T) {
	noTx := NewMsgTx(0)
	noTxEncoded := []byte{
		0x00, 0x00, 0x00, 0x00, // Version 0
		0x00,                   // Varint for number of inputs
		0x00,                   // Varint for number of outputs
		0x00, 0x00, 0x00, 0x00, // Lock time
	}

	hnsTx := buildHnsTestTx()
	hnsTxEncoded := mustDecodeHex(hnsTestTxHex)

	tests := []struct {
		in  *MsgTx // Message to encode
		buf []byte // Serialized data
	}{
		// No transactions.
		{noTx, noTxEncoded},
		// Handshake test transaction with witness.
		{hnsTx, hnsTxEncoded},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// Serialize the transaction.
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

		// Deserialize and re-serialize to verify round-trip.
		var tx MsgTx
		rbuf := bytes.NewReader(test.buf)
		err = tx.Deserialize(rbuf)
		if err != nil {
			t.Errorf("Deserialize #%d error %v", i, err)
			continue
		}
		var rebuf bytes.Buffer
		err = tx.Serialize(&rebuf)
		if err != nil {
			t.Errorf("re-Serialize #%d error %v", i, err)
			continue
		}
		if !bytes.Equal(rebuf.Bytes(), test.buf) {
			t.Errorf("Deserialize/Serialize round-trip #%d\n got: %s want: %s", i,
				spew.Sdump(rebuf.Bytes()), spew.Sdump(test.buf))
			continue
		}
	}
}

// TestTxSerializeErrors performs negative tests against serialize/deserialize
// of MsgTx.
func TestTxSerializeErrors(t *testing.T) {
	hnsTx := buildHnsTestTx()
	hnsTxEncoded := mustDecodeHex(hnsTestTxHex)

	tests := []struct {
		in       *MsgTx // Value to encode
		buf      []byte // Serialized data
		max      int    // Max size of fixed buffer to induce errors
		writeErr error  // Expected write error
		readErr  error  // Expected read error
	}{
		// Force error in version.
		{hnsTx, hnsTxEncoded, 0, io.ErrShortWrite, io.EOF},
		// Force error in number of transaction inputs.
		{hnsTx, hnsTxEncoded, 4, io.ErrShortWrite, io.EOF},
		// Force error in transaction input previous block hash.
		{hnsTx, hnsTxEncoded, 5, io.ErrShortWrite, io.EOF},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// Serialize the transaction.
		w := newFixedWriter(test.max)
		err := test.in.Serialize(w)
		if err != test.writeErr {
			t.Errorf("Serialize #%d wrong error got: %v, want: %v",
				i, err, test.writeErr)
			continue
		}

		// Deserialize the transaction.
		var tx MsgTx
		r := newFixedReader(test.max, test.buf)
		err = tx.Deserialize(r)
		if err != test.readErr {
			t.Errorf("Deserialize #%d wrong error got: %v, want: %v",
				i, err, test.readErr)
			continue
		}
	}
}

// TestTxOverflowErrors performs tests to ensure deserializing transactions
// which are intentionally crafted to use large values for the variable number
// of inputs and outputs are handled properly.
func TestTxOverflowErrors(t *testing.T) {
	pver := ProtocolVersion

	tests := []struct {
		buf     []byte          // Wire encoding
		pver    uint32          // Protocol version for wire encoding
		enc     MessageEncoding // Message encoding format
		version uint32          // Transaction version
		err     error           // Expected error
	}{
		// Transaction that claims to have ~uint64(0) inputs.
		{
			[]byte{
				0x00, 0x00, 0x00, 0x00, // Version
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, // Varint for number of input transactions
			}, pver, WitnessEncoding, 0, &MessageError{},
		},

		// Transaction that claims to have ~uint64(0) outputs.
		{
			[]byte{
				0x00, 0x00, 0x00, 0x00, // Version
				0x00, // Varint for number of input transactions
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, // Varint for number of output transactions
			}, pver, WitnessEncoding, 0, &MessageError{},
		},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		// Decode from wire format.
		var msg MsgTx
		r := bytes.NewReader(test.buf)
		err := msg.BtcDecode(r, test.pver, test.enc)
		if reflect.TypeOf(err) != reflect.TypeOf(test.err) {
			t.Errorf("BtcDecode #%d wrong error got: %v, want: %v",
				i, err, reflect.TypeOf(test.err))
			continue
		}

		// Decode from wire format via Deserialize.
		r = bytes.NewReader(test.buf)
		err = msg.Deserialize(r)
		if reflect.TypeOf(err) != reflect.TypeOf(test.err) {
			t.Errorf("Deserialize #%d wrong error got: %v, want: %v",
				i, err, reflect.TypeOf(test.err))
			continue
		}
	}
}

// TestTxSerializeSizeStripped performs tests to ensure the stripped serialize
// size for various transactions is accurate.
func TestTxSerializeSizeStripped(t *testing.T) {
	// Empty tx message.
	noTx := NewMsgTx(0)

	// Handshake test tx.
	hnsTx := buildHnsTestTx()

	tests := []struct {
		in   *MsgTx // Tx to encode
		size int    // Expected serialized size
	}{
		// No inputs or outputs: version(4) + inCount(1) + outCount(1) + locktime(4) = 10
		{noTx, 10},
		// Handshake test tx stripped: 82 bytes (see TestMsgTxSerializeSizeStripped)
		{hnsTx, 82},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		serializedSize := test.in.SerializeSizeStripped()
		if serializedSize != test.size {
			t.Errorf("SerializeSizeStripped #%d: got %d, want %d", i,
				serializedSize, test.size)
		}
	}
}

// TestTxID verifies the TxID string output.
func TestTxID(t *testing.T) {
	// Empty tx.
	noTx := NewMsgTx(0)

	// Handshake test tx.
	hnsTx := buildHnsTestTx()

	tests := []struct {
		in   *MsgTx // Tx to encode.
		txid string // Expected transaction ID.
	}{
		{hnsTx, hnsTestTxHash},
		// Note: noTx TxID will just be blake2b of its serialized form.
		{noTx, noTx.TxHash().String()},
	}

	for i, test := range tests {
		txid := test.in.TxID()
		require.Equal(t, test.txid, txid, "test #%d", i)
	}
}

// TestTxWitnessSize performs tests to ensure that the serialized size for
// transactions that include witness data is accurate.
func TestTxWitnessSize(t *testing.T) {
	hnsTx := buildHnsTestTx()
	hnsTxEncoded := mustDecodeHex(hnsTestTxHex)

	tests := []struct {
		in   *MsgTx // Tx to encode
		size int    // Expected serialized size w/ witnesses
	}{
		{hnsTx, len(hnsTxEncoded)},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		serializedSize := test.in.SerializeSize()
		if serializedSize != test.size {
			t.Errorf("SerializeSize #%d: got %d, want %d", i,
				serializedSize, test.size)
		}
	}
}

// TestTxOutPointFromString performs tests to ensure that the outpoint string
// parser works as expected.
func TestTxOutPointFromString(t *testing.T) {
	hashFromStr := func(hash string) chainhash.Hash {
		h, _ := chainhash.NewHashFromStr(hash)
		return *h
	}

	tests := []struct {
		name   string
		input  string
		result *OutPoint
		err    bool
	}{
		{
			name:  "normal outpoint 1",
			input: "2ebd15a7e758d5f4c7c74181b99e5b8586f88e0682dc13e09d92612a2b2bb0a2:1",
			result: &OutPoint{
				Hash:  hashFromStr("2ebd15a7e758d5f4c7c74181b99e5b8586f88e0682dc13e09d92612a2b2bb0a2"),
				Index: 1,
			},
			err: false,
		},
		{
			name:  "normal outpoint 2",
			input: "94c7762a68ff164352bd31fd95fa875204e811c09acef40ba781787eb28e3b55:42",
			result: &OutPoint{
				Hash:  hashFromStr("94c7762a68ff164352bd31fd95fa875204e811c09acef40ba781787eb28e3b55"),
				Index: 42,
			},
			err: false,
		},
		{
			name:  "big index outpoint",
			input: "94c7762a68ff164352bd31fd95fa875204e811c09acef40ba781787eb28e3b55:2147484242",
			result: &OutPoint{
				Hash:  hashFromStr("94c7762a68ff164352bd31fd95fa875204e811c09acef40ba781787eb28e3b55"),
				Index: 2147484242,
			},
			err: false,
		},
		{
			name:  "normal outpoint 2 with 31-byte txid",
			input: "c7762a68ff164352bd31fd95fa875204e811c09acef40ba781787eb28e3b55:42",
			result: &OutPoint{
				Hash:  hashFromStr("c7762a68ff164352bd31fd95fa875204e811c09acef40ba781787eb28e3b55"),
				Index: 42,
			},
			err: true,
		},
		{
			name:   "bad string",
			input:  "not_outpoint_not_outpoint_not_outpoint",
			result: nil,
			err:    true,
		},
		{
			name:   "empty string",
			input:  "",
			result: nil,
			err:    true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			outpoint, err := NewOutPointFromString(test.input)

			isErr := (err != nil)
			require.Equal(t, isErr, test.err)

			if !isErr {
				require.Equal(t, test.result, outpoint)
			}
		})

	}
}
