// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

//go:build rpctest
// +build rpctest

package integration

import (
	"bytes"
	"errors"
	"runtime"
	"testing"

	"github.com/blinklabs-io/handshake-node/chaincfg"
	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/hnsutil"
	"github.com/blinklabs-io/handshake-node/integration/rpctest"
	"github.com/blinklabs-io/handshake-node/txscript"
	"github.com/blinklabs-io/handshake-node/wire"
	"github.com/btcsuite/btcd/btcec/v2"
)

func testWitnessPubKeyHashAddress(t *testing.T, net *chaincfg.Params) wire.Address {
	t.Helper()

	key, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatalf("unable to create key: %v", err)
	}
	addr, err := hnsutil.NewAddressPubKeyHash(
		hnsutil.Blake160(key.PubKey().SerializeCompressed()), net,
	)
	if err != nil {
		t.Fatalf("unable to create address: %v", err)
	}
	script, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatalf("unable to create address script: %v", err)
	}
	wireAddr, err := txscript.AddressFromWitnessProgram(script)
	if err != nil {
		t.Fatalf("unable to convert address script: %v", err)
	}
	return wireAddr
}

// makeTestOutput creates an on-chain output paying to a freshly generated
// Handshake version-0 pubkey-hash output with the specified amount.
func makeTestOutput(r *rpctest.Harness, t *testing.T,
	amt hnsutil.Amount) (*btcec.PrivateKey, *wire.OutPoint, []byte, error) {

	// Create a fresh key, then send some coins to an address spendable by
	// that key.
	key, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, nil, nil, err
	}

	// Using the key created above, generate an address which it's able to
	// spend.
	witnessAddr, err := hnsutil.NewAddressPubKeyHash(
		hnsutil.Blake160(key.PubKey().SerializeCompressed()), r.ActiveNet,
	)
	if err != nil {
		return nil, nil, nil, err
	}
	selfAddrScript, err := txscript.PayToAddrScript(witnessAddr)
	if err != nil {
		return nil, nil, nil, err
	}
	selfAddr, err := txscript.AddressFromWitnessProgram(selfAddrScript)
	if err != nil {
		return nil, nil, nil, err
	}
	output := &wire.TxOut{Address: selfAddr, Value: int64(amt)}

	// Next, create and broadcast a transaction paying to the output.
	fundTx, err := r.CreateTransaction([]*wire.TxOut{output}, 10, true)
	if err != nil {
		return nil, nil, nil, err
	}
	txHash, err := r.Client.SendRawTransaction(fundTx, true)
	if err != nil {
		return nil, nil, nil, err
	}

	// The transaction created above should be included within the next
	// generated block.
	blockHash, err := r.Client.Generate(1)
	if err != nil {
		return nil, nil, nil, err
	}
	assertTxInBlock(r, t, blockHash[0], txHash)

	// Locate the output index of the coins spendable by the key we
	// generated above, this is needed in order to create a proper utxo for
	// this output.
	var outputIndex uint32
	if bytes.Equal(fundTx.TxOut[0].Address.WitnessProgram(), selfAddrScript) {
		outputIndex = 0
	} else {
		outputIndex = 1
	}

	utxo := &wire.OutPoint{
		Hash:  fundTx.TxHash(),
		Index: outputIndex,
	}

	return key, utxo, selfAddrScript, nil
}

func p2wpkhScriptCode(pkScript []byte, net *chaincfg.Params) ([]byte, error) {
	if !txscript.IsPayToWitnessPubKeyHash(pkScript) {
		return nil, errors.New("expected P2WPKH witness program")
	}

	addr, err := hnsutil.NewAddressPubKeyHash(pkScript[2:], net)
	if err != nil {
		return nil, err
	}
	return txscript.PayToAddrScript(addr)
}

func p2wpkhWitnessSignature(tx *wire.MsgTx, idx int, amount hnsutil.Amount,
	pkScript []byte, key *btcec.PrivateKey, net *chaincfg.Params) (wire.TxWitness, error) {

	prevAddr, err := txscript.AddressFromWitnessProgram(pkScript)
	if err != nil {
		return nil, err
	}

	prevOutputFetcher := txscript.NewCannedPrevOutputFetcher(
		prevAddr, int64(amount),
	)
	sigHashes := txscript.NewTxSigHashes(tx, prevOutputFetcher)

	scriptCode, err := p2wpkhScriptCode(pkScript, net)
	if err != nil {
		return nil, err
	}

	return txscript.WitnessSignature(tx, sigHashes, idx, int64(amount),
		scriptCode, txscript.SigHashAll, key, true)
}

func blockContainsTx(block *wire.MsgBlock, txid chainhash.Hash) bool {
	for _, txn := range block.Transactions {
		if txn.TxHash() == txid {
			return true
		}
	}
	return false
}

// assertTxInBlock asserts a transaction with the specified txid is found
// within the block with the passed block hash.
func assertTxInBlock(r *rpctest.Harness, t *testing.T, blockHash *chainhash.Hash,
	txid *chainhash.Hash) {

	block, err := r.Client.GetBlock(blockHash)
	if err != nil {
		t.Fatalf("unable to get block: %v", err)
	}
	if len(block.Transactions) < 2 {
		t.Fatal("target transaction was not mined")
	}

	if blockContainsTx(block, *txid) {
		return
	}

	_, _, line, _ := runtime.Caller(1)
	t.Fatalf("assertion failed at line %v: txid %v was not found in "+
		"block %v", line, txid, blockHash)
}

func TestBlockContainsTx(t *testing.T) {
	t.Parallel()

	first := wire.NewMsgTx(wire.TxVersion)
	second := wire.NewMsgTx(wire.TxVersion)
	second.LockTime = 1
	block := &wire.MsgBlock{
		Transactions: []*wire.MsgTx{first, second},
	}

	if !blockContainsTx(block, second.TxHash()) {
		t.Fatal("target transaction was not found")
	}

	missing := wire.NewMsgTx(wire.TxVersion)
	missing.LockTime = 2
	if blockContainsTx(block, missing.TxHash()) {
		t.Fatal("missing transaction was reported as present")
	}
}
