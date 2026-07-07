// Copyright (c) 2013-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/hnsutil"
	"github.com/blinklabs-io/handshake-node/wire"
	"github.com/stretchr/testify/require"
)

// TestMerkle tests the BuildMerkleTreeStore API.
func TestMerkle(t *testing.T) {
	block := hnsutil.NewBlock(&Block100000)
	calcMerkleRoot := CalcMerkleRoot(block.Transactions(), false)
	merkleStoreTree := BuildMerkleTreeStore(block.Transactions(), false)
	merkleStoreRoot := merkleStoreTree[len(merkleStoreTree)-1]

	require.Equal(t, *merkleStoreRoot, calcMerkleRoot)

	wantMerkle := &Block100000.Header.MerkleRoot
	if !wantMerkle.IsEqual(&calcMerkleRoot) {
		t.Errorf("BuildMerkleTreeStore: merkle root mismatch - "+
			"got %v, want %v", calcMerkleRoot, wantMerkle)
	}
}

func TestHandshakeMerkleRootHsdVector(t *testing.T) {
	// This is a one-transaction regtest block produced locally before the
	// hsd mrkl algorithm was wired in. Its header roots are intentionally
	// stale, but hsd parses the transaction and calculates these roots.
	const blockHex = "0300000016f64c6a00000000ae3895cf597eff05b19e02a70ceeeecb9dc72dbfe6504a50e9343a72f06a87c50000000000000000000000000000000000000000000000000000000000000000cc745a419550540a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004681c964f027e618b23a875cfb0a590c8d8e55fc5c2899a49f14cd6dc02b65500000020ffff7f2000000000000000000000000000000000000000000000000000000000000000000100000000010000000000000000000000000000000000000000000000000000000000000000ffffffffffffffff0100943577000000000014000000000000000000000000000000000000000000000100000001185100152f503253482f68616e647368616b652d6e6f64652f"

	blockBytes, err := hex.DecodeString(blockHex)
	require.NoError(t, err)

	block, err := hnsutil.NewBlockFromBytes(blockBytes)
	require.NoError(t, err)

	wantMerkle := mustRawHash(t,
		"5462c9d572575bf328213030a7812b4f338968df9c9299213061c44ffe4445eb",
	)
	wantWitness := mustRawHash(t,
		"006372ac82e16c288ef8639e1fbe9f44a730b23c53d7d28cd58085518bb574a0",
	)

	require.Equal(t, wantMerkle, CalcMerkleRoot(block.Transactions(), false))
	require.Equal(t, wantWitness, CalcMerkleRoot(block.Transactions(), true))
}

func mustRawHash(t *testing.T, hashHex string) chainhash.Hash {
	t.Helper()

	hashBytes, err := hex.DecodeString(hashHex)
	require.NoError(t, err)
	require.Len(t, hashBytes, chainhash.HashSize)

	var hash chainhash.Hash
	copy(hash[:], hashBytes)
	return hash
}

func makeHashes(size int) []*chainhash.Hash {
	var hashes = make([]*chainhash.Hash, size)
	for i := range hashes {
		hashes[i] = new(chainhash.Hash)
	}
	return hashes
}

func makeTxs(size int) []*hnsutil.Tx {
	var txs = make([]*hnsutil.Tx, size)
	for i := range txs {
		tx := hnsutil.NewTx(wire.NewMsgTx(2))
		tx.Hash()
		txs[i] = tx
	}
	return txs
}

// BenchmarkCalcMerkleRoot benches root calculation while varying the number of
// leaves pushed to the tree.
func BenchmarkCalcMerkleRoot(b *testing.B) {
	sizes := []int{
		1000,
		2000,
		4000,
		8000,
		16000,
		32000,
	}

	for _, size := range sizes {
		txs := makeTxs(size)
		name := fmt.Sprintf("%d", size)
		b.Run(name, func(b *testing.B) {
			benchmarkCalcMerkleRoot(b, txs)
		})
	}
}

// BenchmarkMerkle benches the BuildMerkleTreeStore while varying the number
// of leaves pushed to the tree.
func BenchmarkMerkle(b *testing.B) {
	sizes := []int{
		1000,
		2000,
		4000,
		8000,
		16000,
		32000,
	}

	for _, size := range sizes {
		txs := makeTxs(size)
		name := fmt.Sprintf("%d", size)
		b.Run(name, func(b *testing.B) {
			benchmarkMerkle(b, txs)
		})
	}
}

func benchmarkCalcMerkleRoot(b *testing.B, txs []*hnsutil.Tx) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		CalcMerkleRoot(txs, false)
	}
}

func benchmarkMerkle(b *testing.B, txs []*hnsutil.Tx) {
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		BuildMerkleTreeStore(txs, false)
	}
}
