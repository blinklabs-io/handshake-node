// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package utxorpc

import (
	"bytes"

	"github.com/blinklabs-io/handshake-node/blockchain"
	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/hnsutil"
	"github.com/blinklabs-io/handshake-node/wire"
	querypb "github.com/utxorpc/go-codegen/utxorpc/v1beta/query"
	syncpb "github.com/utxorpc/go-codegen/utxorpc/v1beta/sync"
)

// Handshake has no notion of slots, so block height fills the slot
// field as the spec permits ("Height or slot number, depending on the
// blockchain"). Both fields are populated so clients keyed on either
// one resolve the same block.

// blockRef describes a block by height, hash, and millisecond
// timestamp.
func blockRef(block *hnsutil.Block) *syncpb.BlockRef {
	height := uint64(block.Height()) //nolint:gosec // heights are non-negative
	return &syncpb.BlockRef{
		Slot:      height,
		Height:    height,
		Hash:      block.Hash().CloneBytes(),
		Timestamp: uint64(block.MsgBlock().Header.Timestamp.UnixMilli()), //nolint:gosec // timestamps are post-epoch
	}
}

// chainPointAt describes a block known only by height and hash, as the
// UTxO and transaction indexes report it. The timestamp is left unset
// rather than paying for a block read to fill it in.
func chainPointAt(height int32, hash *chainhash.Hash) *querypb.ChainPoint {
	blockHeight := uint64(height) //nolint:gosec // heights are non-negative
	return &querypb.ChainPoint{
		Slot:   blockHeight,
		Height: blockHeight,
		Hash:   hash.CloneBytes(),
	}
}

// tipChainPoint describes the current main chain tip. The best state
// carries no height for the genesis-only case that BestSnapshot cannot
// produce, so the height is always valid here.
func tipChainPoint(best *blockchain.BestState) *querypb.ChainPoint {
	if best == nil {
		return nil
	}
	height := uint64(best.Height) //nolint:gosec // heights are non-negative
	return &querypb.ChainPoint{
		Slot:      height,
		Height:    height,
		Hash:      best.Hash.CloneBytes(),
		Timestamp: uint64(best.Timestamp.UnixMilli()), //nolint:gosec // timestamps are post-epoch
	}
}

// tipBlockRef describes the current main chain tip for the sync
// service.
func tipBlockRef(best *blockchain.BestState) *syncpb.BlockRef {
	if best == nil {
		return nil
	}
	height := uint64(best.Height) //nolint:gosec // heights are non-negative
	return &syncpb.BlockRef{
		Slot:      height,
		Height:    height,
		Hash:      best.Hash.CloneBytes(),
		Timestamp: uint64(best.Timestamp.UnixMilli()), //nolint:gosec // timestamps are post-epoch
	}
}

// anyChainBlock wraps a block's Handshake wire encoding. The parsed
// oneof is left unset because the spec defines no Handshake arm; see
// the package documentation.
func anyChainBlock(block *hnsutil.Block) (*syncpb.AnyChainBlock, error) {
	raw, err := block.Bytes()
	if err != nil {
		return nil, err
	}
	return &syncpb.AnyChainBlock{NativeBytes: raw}, nil
}

// serializeTxOut encodes a single unspent output in the same form it
// takes inside a transaction: value, address, covenant.
func serializeTxOut(txOut *wire.TxOut) ([]byte, error) {
	var buf bytes.Buffer
	buf.Grow(txOut.SerializeSize())
	err := wire.WriteTxOut(&buf, wire.ProtocolVersion, wire.TxVersion, txOut)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// serializeTx encodes a transaction including its witness data.
func serializeTx(tx *wire.MsgTx) ([]byte, error) {
	var buf bytes.Buffer
	buf.Grow(tx.SerializeSize())
	if err := tx.Serialize(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
