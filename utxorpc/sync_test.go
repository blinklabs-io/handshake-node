// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package utxorpc

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/hnsutil"
	"github.com/stretchr/testify/require"
	syncpb "github.com/utxorpc/go-codegen/utxorpc/v1beta/sync"
	"github.com/utxorpc/go-codegen/utxorpc/v1beta/sync/syncconnect"
)

func newSyncClient(t *testing.T, chain Chain) syncconnect.SyncServiceClient {
	t.Helper()
	server := newTestServer(t, &Config{Chain: chain})
	return syncconnect.NewSyncServiceClient(server.client(), server.url)
}

func TestReadTipReturnsChainTip(t *testing.T) {
	chain := newFakeChain(t, 5)
	client := newSyncClient(t, chain)

	resp, err := client.ReadTip(t.Context(),
		connect.NewRequest(&syncpb.ReadTipRequest{}))
	require.NoError(t, err)
	require.EqualValues(t, 5, resp.Msg.GetTip().GetHeight())
	require.Equal(t, chain.tip().Hash().CloneBytes(),
		resp.Msg.GetTip().GetHash())
}

func TestReadTipWithoutTipIsUnavailable(t *testing.T) {
	client := newSyncClient(t, newEmptyChain())

	_, err := client.ReadTip(t.Context(),
		connect.NewRequest(&syncpb.ReadTipRequest{}))
	require.Equal(t, connect.CodeUnavailable, connect.CodeOf(err))
}

func TestFetchBlockByHashAndHeight(t *testing.T) {
	chain := newFakeChain(t, 4)
	client := newSyncClient(t, chain)

	target, err := chain.BlockByHeight(2)
	require.NoError(t, err)

	resp, err := client.FetchBlock(t.Context(),
		connect.NewRequest(&syncpb.FetchBlockRequest{
			Ref: []*syncpb.BlockRef{
				{Hash: target.Hash().CloneBytes()},
				{Height: 3},
				{Slot: 1},
			},
		}))
	require.NoError(t, err)
	require.Len(t, resp.Msg.GetBlock(), 3)

	heights := []int32{2, 3, 1}
	for i, anyBlock := range resp.Msg.GetBlock() {
		decoded, err := hnsutil.NewBlockFromBytes(anyBlock.GetNativeBytes())
		require.NoError(t, err)
		expected, err := chain.BlockByHeight(heights[i])
		require.NoError(t, err)
		require.Equal(t, expected.Hash(), decoded.Hash())
	}
}

// An empty reference list is the spec's way of asking for the tip.
func TestFetchBlockWithNoRefsReturnsTip(t *testing.T) {
	chain := newFakeChain(t, 6)
	client := newSyncClient(t, chain)

	resp, err := client.FetchBlock(t.Context(),
		connect.NewRequest(&syncpb.FetchBlockRequest{}))
	require.NoError(t, err)
	require.Len(t, resp.Msg.GetBlock(), 1)

	decoded, err := hnsutil.NewBlockFromBytes(
		resp.Msg.GetBlock()[0].GetNativeBytes())
	require.NoError(t, err)
	require.Equal(t, chain.tip().Hash(), decoded.Hash())
}

func TestFetchBlockRejectsOversizedBatch(t *testing.T) {
	server := newTestServer(t, &Config{
		Chain:        newFakeChain(t, 1),
		MaxBlockRefs: 2,
	})
	client := syncconnect.NewSyncServiceClient(server.client(), server.url)

	_, err := client.FetchBlock(t.Context(),
		connect.NewRequest(&syncpb.FetchBlockRequest{
			Ref: []*syncpb.BlockRef{{Height: 1}, {Height: 1}, {Height: 1}},
		}))
	require.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestFetchBlockUnknownRefIsNotFound(t *testing.T) {
	client := newSyncClient(t, newFakeChain(t, 1))

	_, err := client.FetchBlock(t.Context(),
		connect.NewRequest(&syncpb.FetchBlockRequest{
			Ref: []*syncpb.BlockRef{{Height: 99}},
		}))
	require.Equal(t, connect.CodeNotFound, connect.CodeOf(err))

	_, err = client.FetchBlock(t.Context(),
		connect.NewRequest(&syncpb.FetchBlockRequest{
			Ref: []*syncpb.BlockRef{{Hash: make([]byte, 7)}},
		}))
	require.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestDumpHistoryPagesThroughChain(t *testing.T) {
	chain := newFakeChain(t, 9)
	client := newSyncClient(t, chain)

	var seen []*chainhash.Hash
	var token *syncpb.BlockRef
	for {
		resp, err := client.DumpHistory(t.Context(),
			connect.NewRequest(&syncpb.DumpHistoryRequest{
				StartToken: token,
				MaxItems:   4,
			}))
		require.NoError(t, err)
		for _, anyBlock := range resp.Msg.GetBlock() {
			decoded, err := hnsutil.NewBlockFromBytes(
				anyBlock.GetNativeBytes())
			require.NoError(t, err)
			seen = append(seen, decoded.Hash())
		}
		token = resp.Msg.GetNextToken()
		if token == nil {
			break
		}
	}

	require.Len(t, seen, 10)
	for height, hash := range seen {
		expected, err := chain.BlockByHeight(int32(height))
		require.NoError(t, err)
		require.Equal(t, expected.Hash(), hash)
	}
}

func TestDumpHistoryClampsToConfiguredMax(t *testing.T) {
	server := newTestServer(t, &Config{
		Chain:           newFakeChain(t, 20),
		MaxHistoryItems: 3,
	})
	client := syncconnect.NewSyncServiceClient(server.client(), server.url)

	resp, err := client.DumpHistory(t.Context(),
		connect.NewRequest(&syncpb.DumpHistoryRequest{MaxItems: 100}))
	require.NoError(t, err)
	require.Len(t, resp.Msg.GetBlock(), 3)
	require.NotNil(t, resp.Msg.GetNextToken())
	require.EqualValues(t, 3, resp.Msg.GetNextToken().GetHeight())
}

func TestDumpHistoryStartTokenBeyondTipIsRejected(t *testing.T) {
	client := newSyncClient(t, newFakeChain(t, 2))

	_, err := client.DumpHistory(t.Context(),
		connect.NewRequest(&syncpb.DumpHistoryRequest{
			StartToken: &syncpb.BlockRef{Height: 50},
		}))
	require.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestFollowTipResetsToTipThenStreamsNewBlocks(t *testing.T) {
	chain := newFakeChain(t, 3)
	server := newTestServer(t, &Config{Chain: chain})
	client := syncconnect.NewSyncServiceClient(server.client(), server.url)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	stream, err := client.FollowTip(ctx,
		connect.NewRequest(&syncpb.FollowTipRequest{}))
	require.NoError(t, err)

	require.True(t, stream.Receive())
	require.Equal(t, chain.tip().Hash().CloneBytes(),
		stream.Msg().GetReset_().GetHash())

	// Wait for the handler to reach its event loop before publishing,
	// so the block is delivered live rather than through backfill.
	requireSubscribed(t, server.Server)

	next := buildBlock(t, 4, *chain.tip().Hash())
	chain.append(next)
	server.NotifyBlockConnected(next)

	require.True(t, stream.Receive())
	applied, err := hnsutil.NewBlockFromBytes(
		stream.Msg().GetApply().GetNativeBytes())
	require.NoError(t, err)
	require.Equal(t, next.Hash(), applied.Hash())
}

// A client resuming from an older point must be caught up to the tip
// before the live stream takes over.
func TestFollowTipBackfillsFromIntersect(t *testing.T) {
	chain := newFakeChain(t, 5)
	server := newTestServer(t, &Config{Chain: chain})
	client := syncconnect.NewSyncServiceClient(server.client(), server.url)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	intersect, err := chain.BlockByHeight(2)
	require.NoError(t, err)

	stream, err := client.FollowTip(ctx,
		connect.NewRequest(&syncpb.FollowTipRequest{
			Intersect: []*syncpb.BlockRef{
				{Hash: intersect.Hash().CloneBytes()},
			},
		}))
	require.NoError(t, err)

	require.True(t, stream.Receive())
	require.Equal(t, intersect.Hash().CloneBytes(),
		stream.Msg().GetReset_().GetHash())

	for height := int32(3); height <= 5; height++ {
		require.True(t, stream.Receive())
		applied, err := hnsutil.NewBlockFromBytes(
			stream.Msg().GetApply().GetNativeBytes())
		require.NoError(t, err)
		expected, err := chain.BlockByHeight(height)
		require.NoError(t, err)
		require.Equal(t, expected.Hash(), applied.Hash())
	}
}

// An unknown intersect falls back to the tip rather than replaying the
// whole chain.
func TestFollowTipUnknownIntersectStartsAtTip(t *testing.T) {
	chain := newFakeChain(t, 3)
	server := newTestServer(t, &Config{Chain: chain})
	client := syncconnect.NewSyncServiceClient(server.client(), server.url)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	stream, err := client.FollowTip(ctx,
		connect.NewRequest(&syncpb.FollowTipRequest{
			Intersect: []*syncpb.BlockRef{
				{Hash: make([]byte, chainhash.HashSize)},
			},
		}))
	require.NoError(t, err)

	require.True(t, stream.Receive())
	require.Equal(t, chain.tip().Hash().CloneBytes(),
		stream.Msg().GetReset_().GetHash())
}

func TestFollowTipStreamsUndoOnRollback(t *testing.T) {
	chain := newFakeChain(t, 3)
	server := newTestServer(t, &Config{Chain: chain})
	client := syncconnect.NewSyncServiceClient(server.client(), server.url)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	stream, err := client.FollowTip(ctx,
		connect.NewRequest(&syncpb.FollowTipRequest{}))
	require.NoError(t, err)
	require.True(t, stream.Receive())
	requireSubscribed(t, server.Server)

	detached := chain.rollback()
	server.NotifyBlockDisconnected(detached)

	require.True(t, stream.Receive())
	undone, err := hnsutil.NewBlockFromBytes(
		stream.Msg().GetUndo().GetNativeBytes())
	require.NoError(t, err)
	require.Equal(t, detached.Hash(), undone.Hash())
}

// Events for blocks that do not connect to what the client holds would
// corrupt its view, so they are discarded rather than forwarded.
func TestFollowTipSkipsUnconnectedBlocks(t *testing.T) {
	chain := newFakeChain(t, 3)
	server := newTestServer(t, &Config{Chain: chain})
	client := syncconnect.NewSyncServiceClient(server.client(), server.url)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	stream, err := client.FollowTip(ctx,
		connect.NewRequest(&syncpb.FollowTipRequest{}))
	require.NoError(t, err)
	require.True(t, stream.Receive())
	requireSubscribed(t, server.Server)

	// A block built on an unrelated parent, then the real next block.
	server.NotifyBlockConnected(buildBlock(t, 4, chainhash.Hash{0xab}))
	next := buildBlock(t, 4, *chain.tip().Hash())
	chain.append(next)
	server.NotifyBlockConnected(next)

	require.True(t, stream.Receive())
	applied, err := hnsutil.NewBlockFromBytes(
		stream.Msg().GetApply().GetNativeBytes())
	require.NoError(t, err)
	require.Equal(t, next.Hash(), applied.Hash())
}

// requireSubscribed waits until a FollowTip handler has registered with
// the broker, which it does before it reads the chain.
func requireSubscribed(t *testing.T, server *Server) {
	t.Helper()
	require.Eventually(t, func() bool {
		return server.broker.blockSubscriberCount() > 0
	}, 5*time.Second, 5*time.Millisecond)
}
