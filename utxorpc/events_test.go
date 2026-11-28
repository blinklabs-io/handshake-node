// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package utxorpc

import (
	"testing"

	"github.com/blinklabs-io/handshake-node/hnsutil"

	"github.com/stretchr/testify/require"
	submitpb "github.com/utxorpc/go-codegen/utxorpc/v1beta/submit"
)

func TestBrokerFansOutToEverySubscriber(t *testing.T) {
	b := newBroker()
	first := b.subscribeBlocks()
	second := b.subscribeBlocks()
	require.Equal(t, 2, b.blockSubscriberCount())

	block := buildBlock(t, 1, [32]byte{})
	b.publishBlock(blockEventFor(t, chainApply, block))

	for _, sub := range []*subscription[blockEvent]{first, second} {
		ev := <-sub.events
		require.Equal(t, chainApply, ev.action)
		require.Equal(t, *block.Hash(), ev.hash)
	}
}

func TestBrokerStopsDeliveringAfterUnsubscribe(t *testing.T) {
	b := newBroker()
	sub := b.subscribeBlocks()
	b.unsubscribeBlocks(sub)
	require.Equal(t, 0, b.blockSubscriberCount())

	b.publishBlock(blockEventFor(t, chainApply, buildBlock(t, 1, [32]byte{})))
	require.Empty(t, sub.events)
}

func TestBrokerMempoolSubscriptions(t *testing.T) {
	b := newBroker()
	sub := b.subscribeMempool()
	require.Equal(t, 1, b.mempoolSubscriberCount())

	tx := buildTx(9)
	raw, err := serializeTx(tx)
	require.NoError(t, err)
	b.publishMempoolTx(mempoolEvent{
		stage: submitpb.Stage_STAGE_MEMPOOL,
		ref:   tx.TxHash(),
		raw:   raw,
	})

	ev := <-sub.events
	require.Equal(t, submitpb.Stage_STAGE_MEMPOOL, ev.stage)
	require.Equal(t, tx.TxHash(), ev.ref)

	b.unsubscribeMempool(sub)
	require.Equal(t, 0, b.mempoolSubscriberCount())
}

// A subscriber that stops draining must be told it fell behind rather
// than silently losing events, because a gap in a chain-following
// stream is undetectable by the client.
func TestSubscriptionReportsLagInsteadOfDropping(t *testing.T) {
	sub := newSubscription[int](2)

	require.True(t, sub.publish(1))
	require.True(t, sub.publish(2))
	require.False(t, sub.publish(3))

	select {
	case <-sub.lagged:
	default:
		t.Fatal("expected the subscription to be marked lagged")
	}

	// Draining does not revive a lagged subscription: the gap is
	// already there.
	<-sub.events
	require.False(t, sub.publish(4))
}

func TestPublishToLaggedSubscriberIsNotFatal(t *testing.T) {
	b := newBroker()
	sub := b.subscribeBlocks()
	close(sub.lagged)

	// Publishing must stay non-blocking and panic-free so the node's
	// notification path is never held up by a stuck client.
	b.publishBlock(blockEventFor(t, chainApply, buildBlock(t, 1, [32]byte{})))
	require.Empty(t, sub.events)
}

// blockEventFor reduces a block the way the server's publish path does.
func blockEventFor(t *testing.T, action chainAction,
	block *hnsutil.Block) blockEvent {

	t.Helper()
	raw, err := block.Bytes()
	require.NoError(t, err)
	return blockEvent{
		action: action,
		raw:    raw,
		hash:   *block.Hash(),
		prev:   block.MsgBlock().Header.PrevBlock,
		height: block.Height(),
	}
}
