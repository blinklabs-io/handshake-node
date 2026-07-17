// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ffldb

import (
	"testing"
	"time"

	"github.com/blinklabs-io/handshake-node/chaincfg"
	"github.com/blinklabs-io/handshake-node/hnsutil"
)

// handshakeTestBlockCount is large enough to span the block files exercised
// by the pruning and injected write-failure tests while keeping the concurrent
// interface test bounded.
const handshakeTestBlockCount = 64

// TstHandshakeBlocks returns a deterministic chain of synthetic Handshake
// blocks for the database tests.  The first block is the canonical mainnet
// genesis block.  Later blocks retain its Handshake transaction, address, and
// covenant encoding while varying the full 236-byte Handshake header and
// linking each block to its predecessor.
//
// The database package stores opaque block bytes and does not perform
// consensus validation, so these blocks intentionally avoid the expensive
// proof-of-work and name-tree construction that belongs in blockchain tests.
func TstHandshakeBlocks(t *testing.T) []*hnsutil.Block {
	t.Helper()

	blocks := make([]*hnsutil.Block, 0, handshakeTestBlockCount)
	genesis := chaincfg.MainNetParams.GenesisBlock
	previousHash := genesis.Header.PrevBlock

	for i := 0; i < handshakeTestBlockCount; i++ {
		msgBlock := genesis.Copy()
		msgBlock.Header.PrevBlock = previousHash
		msgBlock.Header.Timestamp = genesis.Header.Timestamp.Add(
			time.Duration(i) * time.Second,
		)
		msgBlock.Header.Nonce = uint32(i)

		block := hnsutil.NewBlock(msgBlock)
		rawBlock, err := block.Bytes()
		if err != nil {
			t.Fatalf("serialize Handshake test block %d: %v", i, err)
		}
		block, err = hnsutil.NewBlockFromBytes(rawBlock)
		if err != nil {
			t.Fatalf("deserialize Handshake test block %d: %v", i, err)
		}

		blocks = append(blocks, block)
		previousHash = *block.Hash()
	}

	return blocks
}
