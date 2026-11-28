// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package utxorpc

import (
	"github.com/blinklabs-io/handshake-node/blockchain"
	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/hnsutil"
	"github.com/blinklabs-io/handshake-node/mempool"
	"github.com/blinklabs-io/handshake-node/wire"
)

// Chain exposes the subset of blockchain.BlockChain the UTxO RPC
// services read from. *blockchain.BlockChain satisfies it.
type Chain interface {
	BestSnapshot() *blockchain.BestState
	BlockByHash(hash *chainhash.Hash) (*hnsutil.Block, error)
	BlockByHeight(blockHeight int32) (*hnsutil.Block, error)
	BlockHashByHeight(blockHeight int32) (*chainhash.Hash, error)
	BlockHeightByHash(hash *chainhash.Hash) (int32, error)
	MainChainHasBlock(hash *chainhash.Hash) bool
	FetchUtxoEntry(outpoint wire.OutPoint) (*blockchain.UtxoEntry, error)
}

// Mempool exposes the subset of mempool.TxMempool the UTxO RPC services
// read from. mempool.TxMempool satisfies it.
type Mempool interface {
	FetchTransaction(txHash *chainhash.Hash) (*hnsutil.Tx, error)
	HaveTransaction(hash *chainhash.Hash) bool
	TxDescs() []*mempool.TxDesc
}

// TxSubmitter hands a client-supplied transaction to the node, which
// validates it into the mempool and relays it to peers.
type TxSubmitter interface {
	// SubmitTransaction returns an error satisfying
	// errors.As(&mempool.RuleError{}) when the transaction was rejected
	// by policy or consensus rather than failing internally.
	SubmitTransaction(tx *hnsutil.Tx) error
}

// RawTxFetcher resolves a confirmed transaction to its raw wire
// encoding and the hash of the block containing it. It is backed by the
// optional transaction index, so it is nil when the node runs without
// --txindex.
type RawTxFetcher interface {
	// FetchRawTx returns a nil txBytes with a nil error when the
	// transaction is not in the index.
	FetchRawTx(hash *chainhash.Hash) (txBytes []byte,
		blockHash *chainhash.Hash, err error)
}
