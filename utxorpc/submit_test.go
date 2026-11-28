// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package utxorpc

import (
	"bytes"
	"context"
	"testing"

	"connectrpc.com/connect"
	"errors"

	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/mempool"
	"github.com/blinklabs-io/handshake-node/wire"
	"github.com/stretchr/testify/require"
	submitpb "github.com/utxorpc/go-codegen/utxorpc/v1beta/submit"
	"github.com/utxorpc/go-codegen/utxorpc/v1beta/submit/submitconnect"
)

func newSubmitClient(t *testing.T, cfg *Config) (*testServer,
	submitconnect.SubmitServiceClient) {

	t.Helper()
	server := newTestServer(t, cfg)
	return server, submitconnect.NewSubmitServiceClient(
		server.client(), server.url)
}

func TestSubmitTxAcceptsRawTransaction(t *testing.T) {
	submitter := &fakeSubmitter{}
	_, client := newSubmitClient(t, &Config{
		Chain:     newFakeChain(t, 1),
		Submitter: submitter,
	})

	tx := buildTx(5)
	raw, err := serializeTx(tx)
	require.NoError(t, err)

	resp, err := client.SubmitTx(t.Context(),
		connect.NewRequest(&submitpb.SubmitTxRequest{
			Tx: &submitpb.AnyChainTx{
				Type: &submitpb.AnyChainTx_Raw{Raw: raw},
			},
		}))
	require.NoError(t, err)
	require.Equal(t, hashBytes(tx.TxHash()), resp.Msg.GetRef())
	require.Equal(t, 1, submitter.count())
}

func TestSubmitTxRejectsMalformedInput(t *testing.T) {
	_, client := newSubmitClient(t, &Config{
		Chain:     newFakeChain(t, 1),
		Submitter: &fakeSubmitter{},
	})

	_, err := client.SubmitTx(t.Context(),
		connect.NewRequest(&submitpb.SubmitTxRequest{}))
	require.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))

	_, err = client.SubmitTx(t.Context(),
		connect.NewRequest(&submitpb.SubmitTxRequest{
			Tx: &submitpb.AnyChainTx{
				Type: &submitpb.AnyChainTx_Raw{
					Raw: []byte{0xde, 0xad},
				},
			},
		}))
	require.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

// A policy rejection is the client's fault and must not be reported as
// a node failure.
func TestSubmitTxReportsRuleErrorsAsInvalidArgument(t *testing.T) {
	submitter := &fakeSubmitter{
		err: mempool.RuleError{Err: errors.New("transaction is too large")},
	}
	_, client := newSubmitClient(t, &Config{
		Chain:     newFakeChain(t, 1),
		Submitter: submitter,
	})

	raw, err := serializeTx(buildTx(6))
	require.NoError(t, err)

	_, err = client.SubmitTx(t.Context(),
		connect.NewRequest(&submitpb.SubmitTxRequest{
			Tx: &submitpb.AnyChainTx{
				Type: &submitpb.AnyChainTx_Raw{Raw: raw},
			},
		}))
	require.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestSubmitTxWithoutSubmitterIsUnimplemented(t *testing.T) {
	_, client := newSubmitClient(t, &Config{Chain: newFakeChain(t, 1)})

	raw, err := serializeTx(buildTx(7))
	require.NoError(t, err)

	_, err = client.SubmitTx(t.Context(),
		connect.NewRequest(&submitpb.SubmitTxRequest{
			Tx: &submitpb.AnyChainTx{
				Type: &submitpb.AnyChainTx_Raw{Raw: raw},
			},
		}))
	require.Equal(t, connect.CodeUnimplemented, connect.CodeOf(err))
}

func TestReadMempoolListsPendingTransactions(t *testing.T) {
	pool := newFakeMempool()
	tx := hnsutilTx(buildTx(8))
	pool.add(tx)

	_, client := newSubmitClient(t, &Config{
		Chain:     newFakeChain(t, 1),
		TxMemPool: pool,
	})

	resp, err := client.ReadMempool(t.Context(),
		connect.NewRequest(&submitpb.ReadMempoolRequest{}))
	require.NoError(t, err)
	require.Len(t, resp.Msg.GetItems(), 1)

	item := resp.Msg.GetItems()[0]
	require.Equal(t, tx.Hash().CloneBytes(), item.GetRef())
	require.Equal(t, submitpb.Stage_STAGE_MEMPOOL, item.GetStage())

	var decoded wire.MsgTx
	require.NoError(t, decoded.Deserialize(
		bytes.NewReader(item.GetNativeBytes())))
	require.Equal(t, *tx.Hash(), decoded.TxHash())
}

func TestReadMempoolWithoutMempoolIsUnimplemented(t *testing.T) {
	_, client := newSubmitClient(t, &Config{Chain: newFakeChain(t, 1)})

	_, err := client.ReadMempool(t.Context(),
		connect.NewRequest(&submitpb.ReadMempoolRequest{}))
	require.Equal(t, connect.CodeUnimplemented, connect.CodeOf(err))
}

func TestWatchMempoolStreamsArrivals(t *testing.T) {
	server, client := newSubmitClient(t, &Config{
		Chain:     newFakeChain(t, 1),
		TxMemPool: newFakeMempool(),
	})

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	tx := hnsutilTx(buildTx(10))
	publishWhenSubscribed(t, server.broker.mempoolSubscriberCount,
		func() { server.NotifyMempoolTx(tx) })

	stream, err := client.WatchMempool(ctx,
		connect.NewRequest(&submitpb.WatchMempoolRequest{}))
	require.NoError(t, err)

	require.True(t, stream.Receive())
	require.Equal(t, tx.Hash().CloneBytes(), stream.Msg().GetTx().GetRef())
	require.Equal(t, submitpb.Stage_STAGE_MEMPOOL,
		stream.Msg().GetTx().GetStage())
}

// Confirmations belong to WaitForTx and FollowTip, so they must not
// appear as fresh mempool arrivals.
func TestWatchMempoolIgnoresConfirmations(t *testing.T) {
	chain := newFakeChain(t, 2)
	server, client := newSubmitClient(t, &Config{
		Chain:     chain,
		TxMemPool: newFakeMempool(),
	})

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	arrival := hnsutilTx(buildTx(11))
	publishWhenSubscribed(t, server.broker.mempoolSubscriberCount, func() {
		// Confirming a block publishes its transactions as confirmed,
		// which this stream must pass over.
		server.NotifyBlockConnected(buildBlock(t, 3, *chain.tip().Hash()))
		server.NotifyMempoolTx(arrival)
	})

	stream, err := client.WatchMempool(ctx,
		connect.NewRequest(&submitpb.WatchMempoolRequest{}))
	require.NoError(t, err)

	require.True(t, stream.Receive())
	require.Equal(t, arrival.Hash().CloneBytes(),
		stream.Msg().GetTx().GetRef())
}

func TestWatchMempoolRejectsCardanoPredicate(t *testing.T) {
	_, client := newSubmitClient(t, &Config{
		Chain:     newFakeChain(t, 1),
		TxMemPool: newFakeMempool(),
	})

	stream, err := client.WatchMempool(t.Context(),
		connect.NewRequest(&submitpb.WatchMempoolRequest{
			Predicate: &submitpb.TxPredicate{},
		}))
	require.NoError(t, err)
	require.False(t, stream.Receive())
	require.Equal(t, connect.CodeUnimplemented,
		connect.CodeOf(stream.Err()))
}

func TestWaitForTxReportsMempoolThenConfirmed(t *testing.T) {
	chain := newFakeChain(t, 2)
	pool := newFakeMempool()
	tx := hnsutilTx(buildTx(12))
	pool.add(tx)

	server, client := newSubmitClient(t, &Config{
		Chain:     chain,
		TxMemPool: pool,
	})

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	stream, err := client.WaitForTx(ctx,
		connect.NewRequest(&submitpb.WaitForTxRequest{
			Ref: [][]byte{tx.Hash().CloneBytes()},
		}))
	require.NoError(t, err)

	// Already in the mempool, so that stage is reported immediately.
	require.True(t, stream.Receive())
	require.Equal(t, submitpb.Stage_STAGE_MEMPOOL, stream.Msg().GetStage())
	require.Equal(t, tx.Hash().CloneBytes(), stream.Msg().GetRef())

	server.NotifyTxStage(tx, submitpb.Stage_STAGE_CONFIRMED)

	require.True(t, stream.Receive())
	require.Equal(t, submitpb.Stage_STAGE_CONFIRMED, stream.Msg().GetStage())

	// Confirmation is terminal, so the stream ends once every watched
	// transaction has confirmed.
	require.False(t, stream.Receive())
	require.NoError(t, stream.Err())
}

func TestWaitForTxRejectsEmptyAndMalformedRefs(t *testing.T) {
	_, client := newSubmitClient(t, &Config{Chain: newFakeChain(t, 1)})

	stream, err := client.WaitForTx(t.Context(),
		connect.NewRequest(&submitpb.WaitForTxRequest{}))
	require.NoError(t, err)
	require.False(t, stream.Receive())
	require.Equal(t, connect.CodeInvalidArgument,
		connect.CodeOf(stream.Err()))

	stream, err = client.WaitForTx(t.Context(),
		connect.NewRequest(&submitpb.WaitForTxRequest{
			Ref: [][]byte{{0x01}},
		}))
	require.NoError(t, err)
	require.False(t, stream.Receive())
	require.Equal(t, connect.CodeInvalidArgument,
		connect.CodeOf(stream.Err()))
}

func TestEvalTxIsUnimplemented(t *testing.T) {
	_, client := newSubmitClient(t, &Config{Chain: newFakeChain(t, 1)})

	_, err := client.EvalTx(t.Context(),
		connect.NewRequest(&submitpb.EvalTxRequest{}))
	require.Equal(t, connect.CodeUnimplemented, connect.CodeOf(err))
	require.Contains(t, err.Error(), "EvalTx")
}

// A client that asks about a transaction which already confirmed must
// be answered rather than left waiting for an event that has passed.
func TestWaitForTxReportsAlreadyConfirmedTransaction(t *testing.T) {
	chain := newFakeChain(t, 3)
	block, err := chain.BlockByHeight(2)
	require.NoError(t, err)
	tx := block.Transactions()[0]

	raw, err := serializeTx(tx.MsgTx())
	require.NoError(t, err)

	_, client := newSubmitClient(t, &Config{
		Chain:     chain,
		TxMemPool: newFakeMempool(),
		TxFetcher: &fakeTxFetcher{
			txs: map[chainhash.Hash][]byte{*tx.Hash(): raw},
		},
	})

	stream, err := client.WaitForTx(t.Context(),
		connect.NewRequest(&submitpb.WaitForTxRequest{
			Ref: [][]byte{tx.Hash().CloneBytes()},
		}))
	require.NoError(t, err)

	require.True(t, stream.Receive())
	require.Equal(t, submitpb.Stage_STAGE_CONFIRMED, stream.Msg().GetStage())
	require.Equal(t, tx.Hash().CloneBytes(), stream.Msg().GetRef())

	// Nothing is left to wait for, so the stream ends cleanly.
	require.False(t, stream.Receive())
	require.NoError(t, stream.Err())
}

// A transaction the node has never seen leaves the stream open, since
// it may still arrive.
func TestWaitForTxKeepsWaitingForUnknownTransaction(t *testing.T) {
	server, client := newSubmitClient(t, &Config{
		Chain:     newFakeChain(t, 2),
		TxMemPool: newFakeMempool(),
	})

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	tx := hnsutilTx(buildTx(21))
	publishWhenSubscribed(t, server.broker.mempoolSubscriberCount,
		func() { server.NotifyMempoolTx(tx) })

	stream, err := client.WaitForTx(ctx,
		connect.NewRequest(&submitpb.WaitForTxRequest{
			Ref: [][]byte{tx.Hash().CloneBytes()},
		}))
	require.NoError(t, err)

	require.True(t, stream.Receive())
	require.Equal(t, submitpb.Stage_STAGE_MEMPOOL, stream.Msg().GetStage())
}
