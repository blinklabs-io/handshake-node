// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package utxorpc

import (
	"bytes"
	"testing"

	"github.com/blinklabs-io/handshake-node/blockchain"
	"github.com/blinklabs-io/handshake-node/hnsutil"
	"github.com/blinklabs-io/handshake-node/wire"
	"github.com/stretchr/testify/require"
)

func TestBlockRefCarriesHeightInBothFields(t *testing.T) {
	block := buildBlock(t, 7, [32]byte{})

	ref := blockRef(block)
	require.EqualValues(t, 7, ref.GetHeight())
	require.EqualValues(t, 7, ref.GetSlot())
	require.Equal(t, block.Hash().CloneBytes(), ref.GetHash())
	require.EqualValues(t,
		block.MsgBlock().Header.Timestamp.UnixMilli(),
		ref.GetTimestamp())
}

func TestChainPointAtCarriesHeightInBothFields(t *testing.T) {
	block := buildBlock(t, 7, [32]byte{})

	point := chainPointAt(block.Height(), block.Hash())
	require.EqualValues(t, 7, point.GetHeight())
	require.EqualValues(t, 7, point.GetSlot())
	require.Equal(t, block.Hash().CloneBytes(), point.GetHash())
}

func TestTipRefsHandleMissingBestState(t *testing.T) {
	require.Nil(t, tipBlockRef(nil))
	require.Nil(t, tipChainPoint(nil))
}

func TestTipRefsMatchBestState(t *testing.T) {
	block := buildBlock(t, 3, [32]byte{})
	best := &blockchain.BestState{
		Hash:      *block.Hash(),
		Height:    block.Height(),
		Timestamp: block.MsgBlock().Header.Timestamp,
	}

	ref := tipBlockRef(best)
	require.EqualValues(t, 3, ref.GetHeight())
	require.Equal(t, block.Hash().CloneBytes(), ref.GetHash())

	point := tipChainPoint(best)
	require.EqualValues(t, 3, point.GetHeight())
	require.Equal(t, block.Hash().CloneBytes(), point.GetHash())
}

func TestAnyChainBlockRoundTrips(t *testing.T) {
	block := buildBlock(t, 11, [32]byte{0x01})

	anyBlock, err := anyChainBlock(block)
	require.NoError(t, err)
	// No parsed arm exists for Handshake, so the payload must travel
	// in native_bytes.
	require.Nil(t, anyBlock.GetChain())
	require.NotEmpty(t, anyBlock.GetNativeBytes())

	decoded, err := hnsutil.NewBlockFromBytes(anyBlock.GetNativeBytes())
	require.NoError(t, err)
	require.Equal(t, block.Hash(), decoded.Hash())
	require.Len(t, decoded.MsgBlock().Transactions, 1)
}

func TestSerializeTxRoundTrips(t *testing.T) {
	tx := buildTx(42)

	raw, err := serializeTx(tx)
	require.NoError(t, err)

	var decoded wire.MsgTx
	require.NoError(t, decoded.Deserialize(bytes.NewReader(raw)))
	require.Equal(t, tx.TxHash(), decoded.TxHash())
}

func TestSerializeTxOutRoundTrips(t *testing.T) {
	txOut := buildTxOut(123456)

	raw, err := serializeTxOut(txOut)
	require.NoError(t, err)
	require.Len(t, raw, txOut.SerializeSize())

	var decoded wire.TxOut
	err = wire.ReadTxOut(bytes.NewReader(raw), wire.ProtocolVersion,
		wire.TxVersion, &decoded)
	require.NoError(t, err)
	require.Equal(t, txOut.Value, decoded.Value)
	require.Equal(t, txOut.Address.Version, decoded.Address.Version)
	require.Equal(t, txOut.Covenant.Type, decoded.Covenant.Type)
}
