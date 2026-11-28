// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package utxorpc

import (
	"bytes"
	"testing"

	"connectrpc.com/connect"
	"github.com/blinklabs-io/handshake-node/chaincfg"
	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/wire"
	"github.com/stretchr/testify/require"
	querypb "github.com/utxorpc/go-codegen/utxorpc/v1beta/query"
	"github.com/utxorpc/go-codegen/utxorpc/v1beta/query/queryconnect"
)

func newQueryClient(t *testing.T, cfg *Config) queryconnect.QueryServiceClient {
	t.Helper()
	server := newTestServer(t, cfg)
	return queryconnect.NewQueryServiceClient(server.client(), server.url)
}

func TestReadUtxosReturnsUnspentOutputs(t *testing.T) {
	chain := newFakeChain(t, 4)
	txOut := buildTxOut(5_000_000)
	outpoint := wire.OutPoint{Hash: chainhash.Hash{0x11}, Index: 2}
	chain.addUtxo(outpoint, txOut, 3)

	client := newQueryClient(t, &Config{Chain: chain})

	resp, err := client.ReadUtxos(t.Context(),
		connect.NewRequest(&querypb.ReadUtxosRequest{
			Keys: []*querypb.TxoRef{{
				Hash:  outpoint.Hash.CloneBytes(),
				Index: outpoint.Index,
			}},
		}))
	require.NoError(t, err)
	require.Len(t, resp.Msg.GetItems(), 1)
	require.EqualValues(t, 4, resp.Msg.GetLedgerTip().GetHeight())

	item := resp.Msg.GetItems()[0]
	require.Equal(t, outpoint.Hash.CloneBytes(), item.GetTxoRef().GetHash())
	require.EqualValues(t, 2, item.GetTxoRef().GetIndex())
	require.EqualValues(t, 3, item.GetBlockRef().GetHeight())

	var decoded wire.TxOut
	err = wire.ReadTxOut(bytes.NewReader(item.GetNativeBytes()),
		wire.ProtocolVersion, wire.TxVersion, &decoded)
	require.NoError(t, err)
	require.EqualValues(t, 5_000_000, decoded.Value)
}

// Probing many outpoints at once is the common case, so unknown ones
// are skipped instead of failing the whole batch.
func TestReadUtxosSkipsUnknownOutputs(t *testing.T) {
	chain := newFakeChain(t, 2)
	outpoint := wire.OutPoint{Hash: chainhash.Hash{0x22}, Index: 0}
	chain.addUtxo(outpoint, buildTxOut(1), 1)

	client := newQueryClient(t, &Config{Chain: chain})

	resp, err := client.ReadUtxos(t.Context(),
		connect.NewRequest(&querypb.ReadUtxosRequest{
			Keys: []*querypb.TxoRef{
				{Hash: hashBytes(chainhash.Hash{0x99})},
				{Hash: outpoint.Hash.CloneBytes()},
			},
		}))
	require.NoError(t, err)
	require.Len(t, resp.Msg.GetItems(), 1)
	require.Equal(t, outpoint.Hash.CloneBytes(),
		resp.Msg.GetItems()[0].GetTxoRef().GetHash())
}

func TestReadUtxosRejectsOversizedBatchAndBadHash(t *testing.T) {
	client := newQueryClient(t, &Config{
		Chain:       newFakeChain(t, 1),
		MaxUtxoKeys: 1,
	})

	_, err := client.ReadUtxos(t.Context(),
		connect.NewRequest(&querypb.ReadUtxosRequest{
			Keys: []*querypb.TxoRef{{}, {}},
		}))
	require.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))

	_, err = client.ReadUtxos(t.Context(),
		connect.NewRequest(&querypb.ReadUtxosRequest{
			Keys: []*querypb.TxoRef{{Hash: []byte{0x01}}},
		}))
	require.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestReadTxFindsMempoolTransaction(t *testing.T) {
	pool := newFakeMempool()
	tx := hnsutilTx(buildTx(77))
	pool.add(tx)

	client := newQueryClient(t, &Config{
		Chain:     newFakeChain(t, 2),
		TxMemPool: pool,
	})

	resp, err := client.ReadTx(t.Context(),
		connect.NewRequest(&querypb.ReadTxRequest{
			Hash: tx.Hash().CloneBytes(),
		}))
	require.NoError(t, err)

	var decoded wire.MsgTx
	err = decoded.Deserialize(
		bytes.NewReader(resp.Msg.GetTx().GetNativeBytes()))
	require.NoError(t, err)
	require.Equal(t, *tx.Hash(), decoded.TxHash())
	// An unconfirmed transaction has no containing block.
	require.Nil(t, resp.Msg.GetTx().GetBlockRef())
}

func TestReadTxFindsConfirmedTransaction(t *testing.T) {
	chain := newFakeChain(t, 3)
	block, err := chain.BlockByHeight(2)
	require.NoError(t, err)
	tx := block.Transactions()[0]

	raw, err := serializeTx(tx.MsgTx())
	require.NoError(t, err)

	client := newQueryClient(t, &Config{
		Chain: chain,
		TxFetcher: &fakeTxFetcher{
			txs:    map[chainhash.Hash][]byte{*tx.Hash(): raw},
			blocks: map[chainhash.Hash]chainhash.Hash{*tx.Hash(): *block.Hash()},
		},
	})

	resp, err := client.ReadTx(t.Context(),
		connect.NewRequest(&querypb.ReadTxRequest{
			Hash: tx.Hash().CloneBytes(),
		}))
	require.NoError(t, err)
	require.Equal(t, raw, resp.Msg.GetTx().GetNativeBytes())
	require.EqualValues(t, 2, resp.Msg.GetTx().GetBlockRef().GetHeight())
	require.Equal(t, block.Hash().CloneBytes(),
		resp.Msg.GetTx().GetBlockRef().GetHash())
}

func TestReadTxUnknownIsNotFound(t *testing.T) {
	client := newQueryClient(t, &Config{
		Chain:     newFakeChain(t, 1),
		TxFetcher: &fakeTxFetcher{txs: map[chainhash.Hash][]byte{}},
	})

	_, err := client.ReadTx(t.Context(),
		connect.NewRequest(&querypb.ReadTxRequest{
			Hash: hashBytes(chainhash.Hash{0x55}),
		}))
	require.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

// Without --txindex the node cannot answer, which is an operator
// configuration problem rather than a missing transaction.
func TestReadTxWithoutIndexIsFailedPrecondition(t *testing.T) {
	client := newQueryClient(t, &Config{Chain: newFakeChain(t, 1)})

	_, err := client.ReadTx(t.Context(),
		connect.NewRequest(&querypb.ReadTxRequest{
			Hash: hashBytes(chainhash.Hash{0x66}),
		}))
	require.Equal(t, connect.CodeFailedPrecondition, connect.CodeOf(err))
}

func TestReadGenesisIdentifiesNetwork(t *testing.T) {
	client := newQueryClient(t, &Config{
		Chain:       newFakeChain(t, 1),
		ChainParams: &chaincfg.MainNetParams,
	})

	resp, err := client.ReadGenesis(t.Context(),
		connect.NewRequest(&querypb.ReadGenesisRequest{}))
	require.NoError(t, err)
	require.Equal(t, chaincfg.MainNetParams.GenesisHash.CloneBytes(),
		resp.Msg.GetGenesis())
	require.Equal(t, "handshake:mainnet", resp.Msg.GetCaip2())
}

func TestReadGenesisReportsRegtest(t *testing.T) {
	client := newQueryClient(t, &Config{
		Chain:       newFakeChain(t, 1),
		ChainParams: &chaincfg.RegressionNetParams,
	})

	resp, err := client.ReadGenesis(t.Context(),
		connect.NewRequest(&querypb.ReadGenesisRequest{}))
	require.NoError(t, err)
	require.Equal(t, "handshake:regtest", resp.Msg.GetCaip2())
}

// These procedures have no Handshake representation in the UTxO RPC
// schema, so they must report that plainly instead of returning
// misleading empty results.
func TestQueryProceduresWithoutHandshakeSupport(t *testing.T) {
	client := newQueryClient(t, &Config{Chain: newFakeChain(t, 1)})
	ctx := t.Context()

	calls := map[string]func() error{
		"ReadParams": func() error {
			_, err := client.ReadParams(ctx,
				connect.NewRequest(&querypb.ReadParamsRequest{}))
			return err
		},
		"SearchUtxos": func() error {
			_, err := client.SearchUtxos(ctx,
				connect.NewRequest(&querypb.SearchUtxosRequest{}))
			return err
		},
		"ReadData": func() error {
			_, err := client.ReadData(ctx,
				connect.NewRequest(&querypb.ReadDataRequest{}))
			return err
		},
		"ReadEraSummary": func() error {
			_, err := client.ReadEraSummary(ctx,
				connect.NewRequest(&querypb.ReadEraSummaryRequest{}))
			return err
		},
		"ReadState": func() error {
			_, err := client.ReadState(ctx,
				connect.NewRequest(&querypb.ReadStateRequest{}))
			return err
		},
	}

	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			err := call()
			require.Equal(t, connect.CodeUnimplemented,
				connect.CodeOf(err))
			require.Contains(t, err.Error(), name)
		})
	}
}
