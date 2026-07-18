// Copyright (c) 2015-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"bytes"
	"errors"
	"math/big"
	"reflect"
	"testing"

	"github.com/blinklabs-io/handshake-node/database"
	"github.com/blinklabs-io/handshake-node/wire"
)

// TestErrNotInMainChain ensures the functions related to errNotInMainChain work
// as expected.
func TestErrNotInMainChain(t *testing.T) {
	errStr := "no block at height 1 exists"
	err := error(errNotInMainChain(errStr))

	// Ensure the stringized output for the error is as expected.
	if err.Error() != errStr {
		t.Fatalf("errNotInMainChain returned unexpected error string - "+
			"got %q, want %q", err.Error(), errStr)
	}

	// Ensure error is detected as the correct type.
	if !isNotInMainChainErr(err) {
		t.Fatalf("isNotInMainChainErr did not detect as expected type")
	}
	err = errors.New("something else")
	if isNotInMainChainErr(err) {
		t.Fatalf("isNotInMainChainErr detected incorrect type")
	}
}

// TestStxoSerialization ensures serializing and deserializing spent transaction
// output entries works as expected.
func TestStxoSerialization(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		stxo       SpentTxOut
		serialized []byte
	}{
		// From block 170 in main blockchain.
		{
			name: "Spends last output of coinbase",
			stxo: SpentTxOut{
				Amount:     5000000000,
				Address:    wire.Address{Hash: make([]byte, 20)},
				PkScript:   hexToBytes("00140000000000000000000000000000000000000000"),
				IsCoinBase: true,
				Height:     9,
			},
			serialized: hexToBytes("130032001400000000000000000000000000000000000000000000"),
		},
		// Adapted from block 100025 in main blockchain.
		{
			name: "Spends last output of non coinbase",
			stxo: SpentTxOut{
				Amount:     13761000000,
				Address:    wire.Address{Hash: make([]byte, 20)},
				PkScript:   hexToBytes("00140000000000000000000000000000000000000000"),
				IsCoinBase: false,
				Height:     100024,
			},
			serialized: hexToBytes("8b99700086c647001400000000000000000000000000000000000000000000"),
		},
		// Adapted from block 100025 in main blockchain.
		{
			name: "Does not spend last output, legacy format",
			stxo: SpentTxOut{
				Amount:   34405000000,
				Address:  wire.Address{Hash: make([]byte, 20)},
				PkScript: hexToBytes("00140000000000000000000000000000000000000000"),
			},
			serialized: hexToBytes("0091f20f001400000000000000000000000000000000000000000000"),
		},
	}

	for _, test := range tests {
		// Ensure the function to calculate the serialized size without
		// actually serializing it is calculated properly.
		gotSize := spentTxOutSerializeSize(&test.stxo)
		if gotSize != len(test.serialized) {
			t.Errorf("SpentTxOutSerializeSize (%s): did not get "+
				"expected size - got %d, want %d", test.name,
				gotSize, len(test.serialized))
			continue
		}

		// Ensure the stxo serializes to the expected value.
		gotSerialized := make([]byte, gotSize)
		gotBytesWritten := putSpentTxOut(gotSerialized, &test.stxo)
		if !bytes.Equal(gotSerialized, test.serialized) {
			t.Errorf("putSpentTxOut (%s): did not get expected "+
				"bytes - got %x, want %x", test.name,
				gotSerialized, test.serialized)
			continue
		}
		if gotBytesWritten != len(test.serialized) {
			t.Errorf("putSpentTxOut (%s): did not get expected "+
				"number of bytes written - got %d, want %d",
				test.name, gotBytesWritten,
				len(test.serialized))
			continue
		}

		// Ensure the serialized bytes are decoded back to the expected
		// stxo.
		var gotStxo SpentTxOut
		gotBytesRead, err := decodeSpentTxOut(test.serialized, &gotStxo)
		if err != nil {
			t.Errorf("decodeSpentTxOut (%s): unexpected error: %v",
				test.name, err)
			continue
		}
		if !reflect.DeepEqual(gotStxo, test.stxo) {
			t.Errorf("decodeSpentTxOut (%s) mismatched entries - "+
				"got %v, want %v", test.name, gotStxo, test.stxo)
			continue
		}
		if gotBytesRead != len(test.serialized) {
			t.Errorf("decodeSpentTxOut (%s): did not get expected "+
				"number of bytes read - got %d, want %d",
				test.name, gotBytesRead, len(test.serialized))
			continue
		}
	}
}

// TestStxoDecodeErrors performs negative tests against decoding spent
// transaction outputs to ensure error paths work as expected.
func TestStxoDecodeErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		stxo       SpentTxOut
		serialized []byte
		bytesRead  int // Expected number of bytes read.
		errType    error
	}{
		{
			name:       "nothing serialized",
			stxo:       SpentTxOut{},
			serialized: hexToBytes(""),
			errType:    errDeserialize(""),
			bytesRead:  0,
		},
		{
			name:       "no data after header code w/o reserved",
			stxo:       SpentTxOut{},
			serialized: hexToBytes("00"),
			errType:    errDeserialize(""),
			bytesRead:  1,
		},
		{
			name:       "no data after header code with reserved",
			stxo:       SpentTxOut{},
			serialized: hexToBytes("13"),
			errType:    errDeserialize(""),
			bytesRead:  1,
		},
		{
			name:       "no data after reserved",
			stxo:       SpentTxOut{},
			serialized: hexToBytes("1300"),
			errType:    errDeserialize(""),
			bytesRead:  2,
		},
		{
			name:       "incomplete compressed txout",
			stxo:       SpentTxOut{},
			serialized: hexToBytes("1332"),
			errType:    errDeserialize(""),
			bytesRead:  2,
		},
	}

	for _, test := range tests {
		// Ensure the expected error type is returned.
		gotBytesRead, err := decodeSpentTxOut(test.serialized,
			&test.stxo)
		if reflect.TypeOf(err) != reflect.TypeOf(test.errType) {
			t.Errorf("decodeSpentTxOut (%s): expected error type "+
				"does not match - got %T, want %T", test.name,
				err, test.errType)
			continue
		}

		// Ensure the expected number of bytes read is returned.
		if gotBytesRead != test.bytesRead {
			t.Errorf("decodeSpentTxOut (%s): unexpected number of "+
				"bytes read - got %d, want %d", test.name,
				gotBytesRead, test.bytesRead)
			continue
		}
	}
}

// TestSpendJournalSerialization ensures serializing and deserializing spend
// journal entries works as expected.
func TestSpendJournalSerialization(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		entry      []SpentTxOut
		blockTxns  []*wire.MsgTx
		serialized []byte
	}{
		// From block 2 in main blockchain.
		{
			name:       "No spends",
			entry:      nil,
			blockTxns:  nil,
			serialized: nil,
		},
		// From block 170 in main blockchain.
		{
			name: "One tx with one input spends last output of coinbase",
			entry: []SpentTxOut{{
				Amount:     5000000000,
				Address:    wire.Address{Hash: make([]byte, 20)},
				PkScript:   hexToBytes("00140000000000000000000000000000000000000000"),
				IsCoinBase: true,
				Height:     9,
			}},
			blockTxns: []*wire.MsgTx{{ // Coinbase omitted.
				Version: 1,
				TxIn: []*wire.TxIn{{
					PreviousOutPoint: wire.OutPoint{
						Hash:  *newHashFromStr("0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9"),
						Index: 0,
					},
					Witness:  wire.TxWitness{hexToBytes("47304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901")},
					Sequence: 0xffffffff,
				}},
				TxOut: []*wire.TxOut{{
					Value:    1000000000,
					Address:  wire.Address{},
					Covenant: wire.Covenant{},
				}, {
					Value:    4000000000,
					Address:  wire.Address{},
					Covenant: wire.Covenant{},
				}},
				LockTime: 0,
			}},
			serialized: hexToBytes("130032001400000000000000000000000000000000000000000000"),
		},
		// Adapted from block 100025 in main blockchain.
		{
			name: "Two txns when one spends last output, one doesn't",
			entry: []SpentTxOut{{
				Amount:     34405000000,
				Address:    wire.Address{Hash: make([]byte, 20)},
				PkScript:   hexToBytes("00140000000000000000000000000000000000000000"),
				IsCoinBase: false,
				Height:     100024,
			}, {
				Amount:     13761000000,
				Address:    wire.Address{Hash: make([]byte, 20)},
				PkScript:   hexToBytes("00140000000000000000000000000000000000000000"),
				IsCoinBase: false,
				Height:     100024,
			}},
			blockTxns: []*wire.MsgTx{{ // Coinbase omitted.
				Version: 1,
				TxIn: []*wire.TxIn{{
					PreviousOutPoint: wire.OutPoint{
						Hash:  *newHashFromStr("c0ed017828e59ad5ed3cf70ee7c6fb0f426433047462477dc7a5d470f987a537"),
						Index: 1,
					},
					Witness:  wire.TxWitness{hexToBytes("493046022100c167eead9840da4a033c9a56470d7794a9bb1605b377ebe5688499b39f94be59022100fb6345cab4324f9ea0b9ee9169337534834638d818129778370f7d378ee4a325014104d962cac5390f12ddb7539507065d0def320d68c040f2e73337c3a1aaaab7195cb5c4d02e0959624d534f3c10c3cf3d73ca5065ebd62ae986b04c6d090d32627c")},
					Sequence: 0xffffffff,
				}},
				TxOut: []*wire.TxOut{{
					Value:    5000000,
					Address:  wire.Address{},
					Covenant: wire.Covenant{},
				}, {
					Value:    34400000000,
					Address:  wire.Address{},
					Covenant: wire.Covenant{},
				}},
				LockTime: 0,
			}, {
				Version: 1,
				TxIn: []*wire.TxIn{{
					PreviousOutPoint: wire.OutPoint{
						Hash:  *newHashFromStr("92fbe1d4be82f765dfabc9559d4620864b05cc897c4db0e29adac92d294e52b7"),
						Index: 0,
					},
					Witness:  wire.TxWitness{hexToBytes("483045022100e256743154c097465cf13e89955e1c9ff2e55c46051b627751dee0144183157e02201d8d4f02cde8496aae66768f94d35ce54465bd4ae8836004992d3216a93a13f00141049d23ce8686fe9b802a7a938e8952174d35dd2c2089d4112001ed8089023ab4f93a3c9fcd5bfeaa9727858bf640dc1b1c05ec3b434bb59837f8640e8810e87742")},
					Sequence: 0xffffffff,
				}},
				TxOut: []*wire.TxOut{{
					Value:    5000000,
					Address:  wire.Address{},
					Covenant: wire.Covenant{},
				}, {
					Value:    13756000000,
					Address:  wire.Address{},
					Covenant: wire.Covenant{},
				}},
				LockTime: 0,
			}},
			serialized: hexToBytes("8b99700086c6470014000000000000000000000000000000000000000000008b99700091f20f001400000000000000000000000000000000000000000000"),
		},
	}

	for i, test := range tests {
		// Ensure the journal entry serializes to the expected value.
		gotBytes := serializeSpendJournalEntry(test.entry)
		if !bytes.Equal(gotBytes, test.serialized) {
			t.Errorf("serializeSpendJournalEntry #%d (%s): "+
				"mismatched bytes - got %x, want %x", i,
				test.name, gotBytes, test.serialized)
			continue
		}

		// Deserialize to a spend journal entry.
		gotEntry, err := deserializeSpendJournalEntry(test.serialized,
			test.blockTxns)
		if err != nil {
			t.Errorf("deserializeSpendJournalEntry #%d (%s) "+
				"unexpected error: %v", i, test.name, err)
			continue
		}

		// Ensure that the deserialized spend journal entry has the
		// correct properties.
		if !reflect.DeepEqual(gotEntry, test.entry) {
			t.Errorf("deserializeSpendJournalEntry #%d (%s) "+
				"mismatched entries - got %v, want %v",
				i, test.name, gotEntry, test.entry)
			continue
		}
	}
}

// TestSpendJournalErrors performs negative tests against deserializing spend
// journal entries to ensure error paths work as expected.
func TestSpendJournalErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		blockTxns  []*wire.MsgTx
		serialized []byte
		errType    error
	}{
		// Adapted from block 170 in main blockchain.
		{
			name: "Force assertion due to missing stxos",
			blockTxns: []*wire.MsgTx{{ // Coinbase omitted.
				Version: 1,
				TxIn: []*wire.TxIn{{
					PreviousOutPoint: wire.OutPoint{
						Hash:  *newHashFromStr("0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9"),
						Index: 0,
					},
					Witness:  wire.TxWitness{hexToBytes("47304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901")},
					Sequence: 0xffffffff,
				}},
				LockTime: 0,
			}},
			serialized: hexToBytes(""),
			errType:    AssertError(""),
		},
		{
			name: "Force deserialization error in stxos",
			blockTxns: []*wire.MsgTx{{ // Coinbase omitted.
				Version: 1,
				TxIn: []*wire.TxIn{{
					PreviousOutPoint: wire.OutPoint{
						Hash:  *newHashFromStr("0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9"),
						Index: 0,
					},
					Witness:  wire.TxWitness{hexToBytes("47304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901")},
					Sequence: 0xffffffff,
				}},
				LockTime: 0,
			}},
			serialized: hexToBytes("1301320511db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a"),
			errType:    errDeserialize(""),
		},
	}

	for _, test := range tests {
		// Ensure the expected error type is returned and the returned
		// slice is nil.
		stxos, err := deserializeSpendJournalEntry(test.serialized,
			test.blockTxns)
		if reflect.TypeOf(err) != reflect.TypeOf(test.errType) {
			t.Errorf("deserializeSpendJournalEntry (%s): expected "+
				"error type does not match - got %T, want %T",
				test.name, err, test.errType)
			continue
		}
		if stxos != nil {
			t.Errorf("deserializeSpendJournalEntry (%s): returned "+
				"slice of spent transaction outputs is not nil",
				test.name)
			continue
		}
	}
}

// TestUtxoSerialization ensures serializing and deserializing unspent
// transaction output entries works as expected.
func TestUtxoSerialization(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		entry      *UtxoEntry
		serialized []byte
	}{
		// From tx in main blockchain:
		// 0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098:0
		{
			name: "height 1, coinbase",
			entry: &UtxoEntry{
				amount:      5000000000,
				address:     wire.Address{Hash: make([]byte, 20)},
				pkScript:    hexToBytes("00140000000000000000000000000000000000000000"),
				blockHeight: 1,
				packedFlags: tfCoinBase,
			},
			serialized: hexToBytes("0332001400000000000000000000000000000000000000000000"),
		},
		// From tx in main blockchain:
		// 0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098:0
		{
			name: "height 1, coinbase, spent",
			entry: &UtxoEntry{
				amount:      5000000000,
				address:     wire.Address{Hash: make([]byte, 20)},
				pkScript:    hexToBytes("00140000000000000000000000000000000000000000"),
				blockHeight: 1,
				packedFlags: tfCoinBase | tfSpent,
			},
			serialized: nil,
		},
		// From tx in main blockchain:
		// 8131ffb0a2c945ecaf9b9063e59558784f9c3a74741ce6ae2a18d0571dac15bb:1
		{
			name: "height 100001, not coinbase",
			entry: &UtxoEntry{
				amount:      1000000,
				address:     wire.Address{Hash: make([]byte, 20)},
				pkScript:    hexToBytes("00140000000000000000000000000000000000000000"),
				blockHeight: 100001,
				packedFlags: 0,
			},
			serialized: hexToBytes("8b994207001400000000000000000000000000000000000000000000"),
		},
		// From tx in main blockchain:
		// 8131ffb0a2c945ecaf9b9063e59558784f9c3a74741ce6ae2a18d0571dac15bb:1
		{
			name: "height 100001, not coinbase, spent",
			entry: &UtxoEntry{
				amount:      1000000,
				address:     wire.Address{Hash: make([]byte, 20)},
				pkScript:    hexToBytes("00140000000000000000000000000000000000000000"),
				blockHeight: 100001,
				packedFlags: tfSpent,
			},
			serialized: nil,
		},
	}

	for i, test := range tests {
		// Ensure the utxo entry serializes to the expected value.
		gotBytes, err := serializeUtxoEntry(test.entry)
		if err != nil {
			t.Errorf("serializeUtxoEntry #%d (%s) unexpected "+
				"error: %v", i, test.name, err)
			continue
		}
		if !bytes.Equal(gotBytes, test.serialized) {
			t.Errorf("serializeUtxoEntry #%d (%s): mismatched "+
				"bytes - got %x, want %x", i, test.name,
				gotBytes, test.serialized)
			continue
		}

		// Don't try to deserialize if the test entry was spent since it
		// will have a nil serialization.
		if test.entry.IsSpent() {
			continue
		}

		// Deserialize to a utxo entry.
		utxoEntry, err := deserializeUtxoEntry(test.serialized)
		if err != nil {
			t.Errorf("deserializeUtxoEntry #%d (%s) unexpected "+
				"error: %v", i, test.name, err)
			continue
		}

		// The deserialized entry must not be marked spent since unspent
		// entries are not serialized.
		if utxoEntry.IsSpent() {
			t.Errorf("deserializeUtxoEntry #%d (%s) output should "+
				"not be marked spent", i, test.name)
			continue
		}

		// Ensure the deserialized entry has the same properties as the
		// ones in the test entry.
		if utxoEntry.Amount() != test.entry.Amount() {
			t.Errorf("deserializeUtxoEntry #%d (%s) mismatched "+
				"amounts: got %d, want %d", i, test.name,
				utxoEntry.Amount(), test.entry.Amount())
			continue
		}

		if !bytes.Equal(utxoEntry.PkScript(), test.entry.PkScript()) {
			t.Errorf("deserializeUtxoEntry #%d (%s) mismatched "+
				"scripts: got %x, want %x", i, test.name,
				utxoEntry.PkScript(), test.entry.PkScript())
			continue
		}
		if utxoEntry.BlockHeight() != test.entry.BlockHeight() {
			t.Errorf("deserializeUtxoEntry #%d (%s) mismatched "+
				"block height: got %d, want %d", i, test.name,
				utxoEntry.BlockHeight(), test.entry.BlockHeight())
			continue
		}
		if utxoEntry.IsCoinBase() != test.entry.IsCoinBase() {
			t.Errorf("deserializeUtxoEntry #%d (%s) mismatched "+
				"coinbase flag: got %v, want %v", i, test.name,
				utxoEntry.IsCoinBase(), test.entry.IsCoinBase())
			continue
		}
	}
}

func TestHandshakeUtxoSerializationPreservesAddressCovenant(t *testing.T) {
	t.Parallel()

	addr := wire.Address{
		Version: 0,
		Hash: hexToBytes(
			"00112233445566778899aabbccddeeff00112233",
		),
	}
	covenant := wire.Covenant{
		Type: wire.CovenantOpen,
		Items: [][]byte{
			[]byte("example"),
			hexToBytes("01020304"),
		},
	}
	txOut := wire.NewTxOut(123456789, addr, covenant)

	entry := NewUtxoEntry(txOut, 42, true)
	serializedEntry, err := serializeUtxoEntry(entry)
	if err != nil {
		t.Fatalf("serializeUtxoEntry: %v", err)
	}
	deserializedEntry, err := deserializeUtxoEntry(serializedEntry)
	if err != nil {
		t.Fatalf("deserializeUtxoEntry: %v", err)
	}
	if !reflect.DeepEqual(deserializedEntry.Address(), addr) {
		t.Fatalf("address mismatch: got %#v, want %#v",
			deserializedEntry.Address(), addr)
	}
	if !reflect.DeepEqual(deserializedEntry.Covenant(), covenant) {
		t.Fatalf("covenant mismatch: got %#v, want %#v",
			deserializedEntry.Covenant(), covenant)
	}

	stxo := SpentTxOut{
		Amount:     txOut.Value,
		Address:    addr,
		Covenant:   covenant,
		PkScript:   addr.WitnessProgram(),
		Height:     42,
		IsCoinBase: true,
	}
	serializedStxo := make([]byte, spentTxOutSerializeSize(&stxo))
	putSpentTxOut(serializedStxo, &stxo)

	var decodedStxo SpentTxOut
	if _, err := decodeSpentTxOut(serializedStxo, &decodedStxo); err != nil {
		t.Fatalf("decodeSpentTxOut: %v", err)
	}
	if !reflect.DeepEqual(decodedStxo, stxo) {
		t.Fatalf("stxo mismatch: got %#v, want %#v", decodedStxo, stxo)
	}
}

func TestLegacyUtxoV2SerializationConvertsToAddress(t *testing.T) {
	t.Parallel()

	addr := wire.Address{
		Version: 0,
		Hash: hexToBytes(
			"00112233445566778899aabbccddeeff00112233",
		),
	}
	entry := &UtxoEntry{
		amount:      123456789,
		pkScript:    addr.WitnessProgram(),
		blockHeight: 42,
		packedFlags: tfCoinBase,
	}

	serializedV2, err := serializeUtxoEntryV2(entry)
	if err != nil {
		t.Fatalf("serializeUtxoEntryV2: %v", err)
	}
	decodedV2, err := deserializeUtxoEntryV2(serializedV2)
	if err != nil {
		t.Fatalf("deserializeUtxoEntryV2: %v", err)
	}
	if !reflect.DeepEqual(decodedV2.Address(), addr) {
		t.Fatalf("address mismatch: got %#v, want %#v",
			decodedV2.Address(), addr)
	}
	if !bytes.Equal(decodedV2.PkScript(), addr.WitnessProgram()) {
		t.Fatalf("pkScript mismatch: got %x, want %x",
			decodedV2.PkScript(), addr.WitnessProgram())
	}

	serializedV3, err := serializeUtxoEntry(decodedV2)
	if err != nil {
		t.Fatalf("serializeUtxoEntry: %v", err)
	}
	decodedV3, err := deserializeUtxoEntry(serializedV3)
	if err != nil {
		t.Fatalf("deserializeUtxoEntry: %v", err)
	}
	if !reflect.DeepEqual(decodedV3.Address(), addr) {
		t.Fatalf("v3 address mismatch: got %#v, want %#v",
			decodedV3.Address(), addr)
	}
	covenant := decodedV3.Covenant()
	if covenant.Type != wire.CovenantNone || len(covenant.Items) != 0 {
		t.Fatalf("v3 covenant mismatch: got %#v, want empty", covenant)
	}
}

func TestLegacyUtxoV2NonWitnessScriptRejected(t *testing.T) {
	t.Parallel()

	pkScript := hexToBytes("76a9141018853670f9f3b0582c5b9ee8ce93764ac32b9388ac")
	entry := &UtxoEntry{
		amount:      546,
		pkScript:    pkScript,
		blockHeight: 42,
	}

	serializedV2, err := serializeUtxoEntryV2(entry)
	if err != nil {
		t.Fatalf("serializeUtxoEntryV2: %v", err)
	}
	if _, err := deserializeUtxoEntryV2(serializedV2); err == nil {
		t.Fatal("deserializeUtxoEntryV2 accepted non-witness pkScript")
	}
}

func TestSerializeUtxoEntryRejectsInvalidNativeFields(t *testing.T) {
	t.Parallel()

	validAddress := wire.Address{Hash: make([]byte, 20)}
	tests := []struct {
		name     string
		address  wire.Address
		covenant wire.Covenant
	}{
		{name: "empty address", address: wire.Address{}},
		{
			name:    "oversized covenant item",
			address: validAddress,
			covenant: wire.Covenant{
				Items: [][]byte{make([]byte, 586)},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entry := &UtxoEntry{
				amount:      1,
				address:     test.address,
				covenant:    test.covenant,
				blockHeight: 1,
			}
			if _, err := serializeUtxoEntry(entry); err == nil {
				t.Fatal("serializeUtxoEntry accepted invalid native fields")
			}
		})
	}
}

func TestLegacySpendJournalDecodeFallback(t *testing.T) {
	t.Parallel()

	addr := wire.Address{
		Version: 0,
		Hash: hexToBytes(
			"ffeeddccbbaa99887766554433221100ffeeddcc",
		),
	}
	want := SpentTxOut{
		Amount:     987654321,
		Address:    addr,
		Covenant:   wire.Covenant{},
		PkScript:   addr.WitnessProgram(),
		Height:     7,
		IsCoinBase: true,
	}

	size := serializeSizeVLQ(spentTxOutHeaderCode(&want)) +
		serializeSizeVLQ(0) +
		compressedTxOutSize(uint64(want.Amount), want.PkScript)
	serialized := make([]byte, size)
	offset := putVLQ(serialized, spentTxOutHeaderCode(&want))
	offset += putVLQ(serialized[offset:], 0)
	offset += putCompressedTxOut(
		serialized[offset:], uint64(want.Amount), want.PkScript,
	)
	serialized = serialized[:offset]

	var got SpentTxOut
	bytesRead, err := decodeSpentTxOut(serialized, &got)
	if err != nil {
		t.Fatalf("decodeSpentTxOut: %v", err)
	}
	if bytesRead != len(serialized) {
		t.Fatalf("bytes read mismatch: got %d, want %d",
			bytesRead, len(serialized))
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("stxo mismatch: got %#v, want %#v", got, want)
	}
}

func TestLegacySpendJournalNonWitnessScriptRejected(t *testing.T) {
	t.Parallel()

	stxos := []SpentTxOut{{
		Amount:   546,
		PkScript: hexToBytes("76a9141018853670f9f3b0582c5b9ee8ce93764ac32b9388ac"),
	}}
	serialized := serializeLegacySpendJournalEntry(stxos)
	blockTxns := []*wire.MsgTx{{TxIn: []*wire.TxIn{{}}}}

	if _, err := deserializeSpendJournalEntryV1(serialized, blockTxns); err == nil {
		t.Fatal("deserializeSpendJournalEntryV1 accepted non-witness pkScript")
	}
}

func TestLegacySpendJournalEntryDecodesWitnessProgram(t *testing.T) {
	t.Parallel()

	addr1 := wire.Address{
		Version: 0,
		Hash: hexToBytes(
			"00112233445566778899aabbccddeeff00112233",
		),
	}
	addr2 := wire.Address{
		Version: 0,
		Hash: hexToBytes(
			"ffeeddccbbaa99887766554433221100ffeeddcc",
		),
	}
	want := []SpentTxOut{
		{
			Address:  addr1,
			Covenant: wire.Covenant{},
			PkScript: addr1.WitnessProgram(),
		},
		{
			Address:  addr2,
			Covenant: wire.Covenant{},
			PkScript: addr2.WitnessProgram(),
		},
	}
	serialized := serializeLegacySpendJournalEntry(want)
	blockTxns := []*wire.MsgTx{{
		TxIn: []*wire.TxIn{{}, {}},
	}}

	got, err := deserializeSpendJournalEntryV1(serialized, blockTxns)
	if err != nil {
		t.Fatalf("deserializeSpendJournalEntryV1: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("stxos mismatch: got %#v, want %#v", got, want)
	}
}

func TestSpendJournalEntryUsesHnsDecoder(t *testing.T) {
	t.Parallel()

	addr := wire.Address{
		Version: 0,
		Hash: hexToBytes(
			"1411111111111111111111111111111111111111",
		),
	}
	covenant := wire.Covenant{
		Type:  wire.CovenantOpen,
		Items: [][]byte{[]byte("example")},
	}
	want := []SpentTxOut{{
		Amount:   12345,
		Address:  addr,
		Covenant: covenant,
		PkScript: addr.WitnessProgram(),
	}}
	serialized := serializeSpendJournalEntry(want)
	blockTxns := []*wire.MsgTx{{
		TxIn: []*wire.TxIn{{}},
	}}

	got, err := deserializeSpendJournalEntry(serialized, blockTxns)
	if err != nil {
		t.Fatalf("deserializeSpendJournalEntry: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("stxos mismatch: got %#v, want %#v", got, want)
	}
}

func legacySpentTxOutSerializeSize(stxo *SpentTxOut) int {
	size := serializeSizeVLQ(spentTxOutHeaderCode(stxo))
	if stxo.Height > 0 {
		size += serializeSizeVLQ(0)
	}
	return size + compressedTxOutSize(uint64(stxo.Amount), stxo.PkScript)
}

func putLegacySpentTxOut(target []byte, stxo *SpentTxOut) int {
	offset := putVLQ(target, spentTxOutHeaderCode(stxo))
	if stxo.Height > 0 {
		offset += putVLQ(target[offset:], 0)
	}
	return offset + putCompressedTxOut(
		target[offset:], uint64(stxo.Amount), stxo.PkScript,
	)
}

func serializeLegacySpendJournalEntry(stxos []SpentTxOut) []byte {
	var size int
	for i := range stxos {
		size += legacySpentTxOutSerializeSize(&stxos[i])
	}

	serialized := make([]byte, size)
	var offset int
	for i := len(stxos) - 1; i > -1; i-- {
		offset += putLegacySpentTxOut(serialized[offset:], &stxos[i])
	}
	return serialized
}

// TestUtxoEntryHeaderCodeErrors performs negative tests against unspent
// transaction output header codes to ensure error paths work as expected.
func TestUtxoEntryHeaderCodeErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		entry   *UtxoEntry
		code    uint64
		errType error
	}{
		{
			name:    "Force assertion due to spent output",
			entry:   &UtxoEntry{packedFlags: tfSpent},
			errType: AssertError(""),
		},
	}

	for _, test := range tests {
		// Ensure the expected error type is returned and the code is 0.
		code, err := utxoEntryHeaderCode(test.entry)
		if reflect.TypeOf(err) != reflect.TypeOf(test.errType) {
			t.Errorf("utxoEntryHeaderCode (%s): expected error "+
				"type does not match - got %T, want %T",
				test.name, err, test.errType)
			continue
		}
		if code != 0 {
			t.Errorf("utxoEntryHeaderCode (%s): unexpected code "+
				"on error - got %d, want 0", test.name, code)
			continue
		}
	}
}

// TestUtxoEntryDeserializeErrors performs negative tests against deserializing
// unspent transaction outputs to ensure error paths work as expected.
func TestUtxoEntryDeserializeErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		serialized []byte
		errType    error
	}{
		{
			name:       "no data after header code",
			serialized: hexToBytes("02"),
			errType:    errDeserialize(""),
		},
		{
			name:       "incomplete compressed txout",
			serialized: hexToBytes("0232"),
			errType:    errDeserialize(""),
		},
	}

	for _, test := range tests {
		// Ensure the expected error type is returned and the returned
		// entry is nil.
		entry, err := deserializeUtxoEntry(test.serialized)
		if reflect.TypeOf(err) != reflect.TypeOf(test.errType) {
			t.Errorf("deserializeUtxoEntry (%s): expected error "+
				"type does not match - got %T, want %T",
				test.name, err, test.errType)
			continue
		}
		if entry != nil {
			t.Errorf("deserializeUtxoEntry (%s): returned entry "+
				"is not nil", test.name)
			continue
		}
	}
}

// TestBestChainStateSerialization ensures serializing and deserializing the
// best chain state works as expected.
func TestBestChainStateSerialization(t *testing.T) {
	t.Parallel()

	workSum := new(big.Int)
	tests := []struct {
		name       string
		state      bestChainState
		serialized []byte
	}{
		{
			name: "genesis",
			state: bestChainState{
				hash:      *newHashFromStr("6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000"),
				height:    0,
				totalTxns: 1,
				workSum: func() *big.Int {
					workSum.Add(workSum, CalcWork(486604799))
					return new(big.Int).Set(workSum)
				}(), // 0x0100010001
			},
			serialized: hexToBytes("6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000000000000100000000000000050000000100010001"),
		},
		{
			name: "block 1",
			state: bestChainState{
				hash:      *newHashFromStr("4860eb18bf1b1620e37e9490fc8a427514416fd75159ab86688e9a8300000000"),
				height:    1,
				totalTxns: 2,
				workSum: func() *big.Int {
					workSum.Add(workSum, CalcWork(486604799))
					return new(big.Int).Set(workSum)
				}(), // 0x0200020002
			},
			serialized: hexToBytes("4860eb18bf1b1620e37e9490fc8a427514416fd75159ab86688e9a8300000000010000000200000000000000050000000200020002"),
		},
	}

	for i, test := range tests {
		// Ensure the state serializes to the expected value.
		gotBytes := serializeBestChainState(test.state)
		if !bytes.Equal(gotBytes, test.serialized) {
			t.Errorf("serializeBestChainState #%d (%s): mismatched "+
				"bytes - got %x, want %x", i, test.name,
				gotBytes, test.serialized)
			continue
		}

		// Ensure the serialized bytes are decoded back to the expected
		// state.
		state, err := deserializeBestChainState(test.serialized)
		if err != nil {
			t.Errorf("deserializeBestChainState #%d (%s) "+
				"unexpected error: %v", i, test.name, err)
			continue
		}
		if !reflect.DeepEqual(state, test.state) {
			t.Errorf("deserializeBestChainState #%d (%s) "+
				"mismatched state - got %v, want %v", i,
				test.name, state, test.state)
			continue

		}
	}
}

// TestBestChainStateDeserializeErrors performs negative tests against
// deserializing the chain state to ensure error paths work as expected.
func TestBestChainStateDeserializeErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		serialized []byte
		errType    error
	}{
		{
			name:       "nothing serialized",
			serialized: hexToBytes(""),
			errType:    database.Error{ErrorCode: database.ErrCorruption},
		},
		{
			name:       "short data in hash",
			serialized: hexToBytes("0000"),
			errType:    database.Error{ErrorCode: database.ErrCorruption},
		},
		{
			name:       "short data in work sum",
			serialized: hexToBytes("6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d61900000000000000000001000000000000000500000001000100"),
			errType:    database.Error{ErrorCode: database.ErrCorruption},
		},
	}

	for _, test := range tests {
		// Ensure the expected error type and code is returned.
		_, err := deserializeBestChainState(test.serialized)
		if reflect.TypeOf(err) != reflect.TypeOf(test.errType) {
			t.Errorf("deserializeBestChainState (%s): expected "+
				"error type does not match - got %T, want %T",
				test.name, err, test.errType)
			continue
		}
		if derr, ok := err.(database.Error); ok {
			tderr := test.errType.(database.Error)
			if derr.ErrorCode != tderr.ErrorCode {
				t.Errorf("deserializeBestChainState (%s): "+
					"wrong  error code got: %v, want: %v",
					test.name, derr.ErrorCode,
					tderr.ErrorCode)
				continue
			}
		}
	}
}
