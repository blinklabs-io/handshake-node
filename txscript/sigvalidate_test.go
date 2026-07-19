// Copyright (c) 2026 The Handshake node developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package txscript

import (
	"testing"

	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/wire"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// TestTaprootSigVerifierCacheMiss ensures a disabled or evicted shared cache
// cannot result in a nil sighash midstate dereference.
func TestTaprootSigVerifierCacheMiss(t *testing.T) {
	t.Parallel()

	prevOut := wire.OutPoint{
		Hash:  chainhash.Hash{0x01},
		Index: 0,
	}
	addr := wire.Address{Version: 1, Hash: make([]byte, 32)}
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(
		&prevOut, wire.MaxTxInSequenceNum, nil,
	))
	tx.AddTxOut(wire.NewTxOut(1, addr, wire.Covenant{}))

	prevOuts := NewMultiPrevOutFetcher(nil)
	prevOuts.AddPrevOut(prevOut, wire.NewTxOut(
		2, addr, wire.Covenant{},
	))

	sigHashes := NewTxSigHashes(tx, prevOuts)
	sigHash, err := calcTaprootSignatureHashRaw(
		sigHashes, SigHashDefault, tx, 0, prevOuts,
	)
	if err != nil {
		t.Fatalf("unable to compute taproot sighash: %v", err)
	}

	privKey, _ := btcec.PrivKeyFromBytes([]byte{0x01})
	sig, err := schnorr.Sign(privKey, sigHash)
	if err != nil {
		t.Fatalf("unable to sign taproot sighash: %v", err)
	}

	cache := NewHashCache(0)
	cache.AddSigHashes(tx, prevOuts)
	txid := tx.TxHash()
	missedHashes, ok := cache.GetSigHashes(&txid)
	if ok || missedHashes != nil {
		t.Fatal("zero-capacity cache unexpectedly retained sighashes")
	}

	verifier := &taprootSigVerifier{
		pubKey:       privKey.PubKey(),
		pkBytes:      schnorr.SerializePubKey(privKey.PubKey()),
		fullSigBytes: sig.Serialize(),
		sig:          sig,
		hashType:     SigHashDefault,
		hashCache:    missedHashes,
		tx:           tx,
		inputIndex:   0,
		prevOuts:     prevOuts,
	}
	if result := verifier.Verify(); !result.sigValid {
		t.Fatal("valid taproot signature failed after shared cache miss")
	}
}
