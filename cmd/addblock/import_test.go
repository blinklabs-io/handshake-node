// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"math"
	"path/filepath"
	"testing"
	"time"

	"github.com/blinklabs-io/handshake-node/blockchain"
	"github.com/blinklabs-io/handshake-node/chaincfg"
	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/database"
	_ "github.com/blinklabs-io/handshake-node/database/ffldb"
	"github.com/blinklabs-io/handshake-node/hnsutil"
	"github.com/blinklabs-io/handshake-node/txscript"
	"github.com/blinklabs-io/handshake-node/wire"
)

func solveImportTestBlock(t *testing.T, header *wire.BlockHeader,
	params *chaincfg.Params) {

	t.Helper()
	target := blockchain.CompactToBig(params.PowLimitBits)
	for nonce := uint32(0); nonce < math.MaxUint32; nonce++ {
		header.Nonce = nonce
		hash := header.BlockHash()
		if blockchain.HashToBig(&hash).Cmp(target) <= 0 {
			return
		}
	}
	t.Fatal("failed to solve import test block")
}

func invalidImportCoinbaseBlock(t *testing.T,
	params *chaincfg.Params) *hnsutil.Block {

	t.Helper()
	height := int32(1)
	coinbase := wire.NewMsgTx(wire.TxVersion)
	coinbase.LockTime = uint32(height + 1)
	heightScript, err := txscript.NewScriptBuilder().
		AddInt64(int64(height)).
		AddOp(txscript.OP_0).
		Script()
	if err != nil {
		t.Fatalf("coinbase height script: %v", err)
	}
	coinbase.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  chainhash.Hash{},
			Index: wire.MaxPrevOutIndex,
		},
		Sequence: wire.MaxTxInSequenceNum,
		Witness:  wire.TxWitness{heightScript},
	})
	coinbase.AddTxOut(&wire.TxOut{
		Value: blockchain.CalcBlockSubsidy(height, params),
		Address: wire.Address{
			Version: 0,
			Hash:    make([]byte, 20),
		},
	})

	txns := []*hnsutil.Tx{hnsutil.NewTx(coinbase)}
	header := wire.BlockHeader{
		Version:     2,
		PrevBlock:   *params.GenesisHash,
		MerkleRoot:  blockchain.CalcMerkleRoot(txns, false),
		WitnessRoot: blockchain.CalcMerkleRoot(txns, true),
		Timestamp:   params.GenesisBlock.Header.Timestamp.Add(time.Minute),
		Bits:        params.PowLimitBits,
	}
	solveImportTestBlock(t, &header, params)

	return hnsutil.NewBlock(&wire.MsgBlock{
		Header:       header,
		Transactions: []*wire.MsgTx{coinbase},
	})
}

func TestProcessBlockFullyValidatesImports(t *testing.T) {
	params := chaincfg.RegressionNetParams
	params.Checkpoints = nil
	dbPath := filepath.Join(t.TempDir(), "ffldb")
	db, err := database.Create("ffldb", dbPath, params.Net)
	if err != nil {
		t.Fatalf("database.Create: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("database close: %v", err)
		}
	})

	chain, err := blockchain.New(&blockchain.Config{
		DB:               db,
		ChainParams:      &params,
		TimeSource:       blockchain.NewMedianTime(),
		UtxoCacheMaxSize: 16 * 1024 * 1024,
	})
	if err != nil {
		t.Fatalf("blockchain.New: %v", err)
	}
	block := invalidImportCoinbaseBlock(t, &params)
	serialized, err := block.Bytes()
	if err != nil {
		t.Fatalf("serialize block: %v", err)
	}

	imported, err := (&blockImporter{chain: chain}).processBlock(serialized)
	if imported {
		t.Fatal("consensus-invalid block was imported")
	}
	var ruleErr blockchain.RuleError
	if !errors.As(err, &ruleErr) {
		t.Fatalf("processBlock error = %v, want blockchain.RuleError", err)
	}
	if ruleErr.ErrorCode != blockchain.ErrBadCoinbaseHeight {
		t.Fatalf("processBlock error code = %v, want %v",
			ruleErr.ErrorCode, blockchain.ErrBadCoinbaseHeight)
	}
}
