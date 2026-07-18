// Copyright (c) 2013-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"fmt"
	"testing"

	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/hnsutil"
	"github.com/blinklabs-io/handshake-node/txscript"
	"github.com/blinklabs-io/handshake-node/wire"
)

func TestReservedAddressVersionScriptValidation(t *testing.T) {
	t.Parallel()

	addresses := []struct {
		name    string
		version uint8
		hash    []byte
	}{
		{name: "version 1", version: 1, hash: make([]byte, 32)},
		{name: "version 16", version: 16, hash: []byte{0x10, 0x16}},
		{name: "version 17", version: 17, hash: []byte{0x10, 0x17}},
		{name: "version 30", version: 30, hash: []byte{0x10, 0x30}},
	}
	witnesses := []struct {
		name             string
		witness          wire.TxWitness
		mandatoryRejects bool
	}{
		{name: "empty"},
		{name: "nonempty", witness: wire.TxWitness{{0x01}}},
		{name: "maximum stack items", witness: make(wire.TxWitness,
			txscript.MaxStackSize)},
		{name: "over maximum stack items", witness: make(wire.TxWitness,
			txscript.MaxStackSize+1), mandatoryRejects: true},
	}

	for _, addressTest := range addresses {
		t.Run(addressTest.name, func(t *testing.T) {
			t.Parallel()

			for witnessIndex, witnessTest := range witnesses {
				t.Run(witnessTest.name, func(t *testing.T) {
					outpoint := wire.OutPoint{
						Hash: chainhash.Hash{
							addressTest.version,
							byte(witnessIndex),
						},
						Index: 0,
					}
					view := NewUtxoViewpoint()
					view.entries[outpoint] = NewUtxoEntry(&wire.TxOut{
						Value: 1000,
						Address: wire.Address{
							Version: addressTest.version,
							Hash:    addressTest.hash,
						},
					}, 1, false)

					msgTx := wire.NewMsgTx(wire.TxVersion)
					msgTx.AddTxIn(wire.NewTxIn(&outpoint,
						wire.MaxTxInSequenceNum, witnessTest.witness))
					msgTx.AddTxOut(wire.NewTxOut(900, wire.Address{
						Version: 0,
						Hash:    make([]byte, 20),
					}, wire.Covenant{}))
					tx := hnsutil.NewTx(msgTx)

					sigOps, err := GetSigOpCost(tx, false, view, true, true)
					if err != nil {
						t.Fatalf("GetSigOpCost: %v", err)
					}
					if sigOps != 0 {
						t.Fatalf("GetSigOpCost = %d, want 0", sigOps)
					}

					sigCache := txscript.NewSigCache(1)
					hashCache := txscript.NewHashCache(1)
					err = ValidateTransactionScripts(tx, view,
						mandatoryScriptVerifyFlags(), sigCache, hashCache)
					if witnessTest.mandatoryRejects {
						ruleErr, ok := err.(RuleError)
						if !ok || ruleErr.ErrorCode != ErrScriptValidation {
							t.Fatalf("mandatory validation error = %T %v, "+
								"want ErrScriptValidation", err, err)
						}
					} else if err != nil {
						t.Fatalf("mandatory validation: %v", err)
					}

					err = ValidateTransactionScripts(tx, view,
						txscript.StandardVerifyFlags, sigCache, hashCache)
					ruleErr, ok := err.(RuleError)
					if !ok || ruleErr.ErrorCode != ErrScriptValidation {
						t.Fatalf("standard validation error = %T %v, "+
							"want ErrScriptValidation", err, err)
					}
				})
			}
		})
	}
}

func TestMalformedVersionZeroDoesNotUseReservedBypass(t *testing.T) {
	t.Parallel()

	outpoint := wire.OutPoint{Hash: chainhash.Hash{0xff}, Index: 0}
	view := NewUtxoViewpoint()
	view.entries[outpoint] = NewUtxoEntry(&wire.TxOut{
		Value:   1000,
		Address: wire.Address{Version: 0, Hash: []byte{0x01, 0x02}},
	}, 1, false)

	msgTx := wire.NewMsgTx(wire.TxVersion)
	msgTx.AddTxIn(wire.NewTxIn(&outpoint, wire.MaxTxInSequenceNum, nil))
	msgTx.AddTxOut(wire.NewTxOut(900, wire.Address{
		Version: 0,
		Hash:    make([]byte, 20),
	}, wire.Covenant{}))

	err := ValidateTransactionScripts(hnsutil.NewTx(msgTx), view,
		mandatoryScriptVerifyFlags(), txscript.NewSigCache(1),
		txscript.NewHashCache(1))
	ruleErr, ok := err.(RuleError)
	if !ok || ruleErr.ErrorCode != ErrScriptValidation {
		t.Fatalf("malformed version 0 validation error = %T %v, "+
			"want ErrScriptValidation", err, err)
	}
}

// TestCheckBlockScripts ensures that validating the all of the scripts in a
// known-good block doesn't return an error.
func TestCheckBlockScripts(t *testing.T) {
	t.Skip("Skipping: test data contains Bitcoin blocks with 80-byte headers; needs Handshake test fixtures")
	testBlockNum := 277647
	blockDataFile := fmt.Sprintf("%d.dat.bz2", testBlockNum)
	blocks, err := loadBlocks(blockDataFile)
	if err != nil {
		t.Errorf("Error loading file: %v\n", err)
		return
	}
	if len(blocks) > 1 {
		t.Errorf("The test block file must only have one block in it")
		return
	}
	if len(blocks) == 0 {
		t.Errorf("The test block file may not be empty")
		return
	}

	storeDataFile := fmt.Sprintf("%d.utxostore.bz2", testBlockNum)
	view, err := loadUtxoView(storeDataFile)
	if err != nil {
		t.Errorf("Error loading txstore: %v\n", err)
		return
	}

	scriptFlags := txscript.ScriptBip16
	err = checkBlockScripts(blocks[0], view, scriptFlags, nil, nil)
	if err != nil {
		t.Errorf("Transaction script validation failed: %v\n", err)
		return
	}
}
