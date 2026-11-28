// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package utxorpc

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/hnsutil"
	syncpb "github.com/utxorpc/go-codegen/utxorpc/v1beta/sync"
)

// syncService implements syncconnect.SyncServiceHandler.
type syncService struct {
	server *Server
}

// cursor is the position a FollowTip stream has delivered up to. The
// stream only forwards a block that builds on this hash, and only rolls
// back this exact block, so events that predate the client's position
// are discarded rather than corrupting its view of the chain.
type cursor struct {
	hash   chainhash.Hash
	height int32
}

func (s *syncService) ReadTip(
	ctx context.Context,
	req *connect.Request[syncpb.ReadTipRequest],
) (*connect.Response[syncpb.ReadTipResponse], error) {
	best := s.server.cfg.Chain.BestSnapshot()
	if best == nil {
		return nil, connect.NewError(connect.CodeUnavailable,
			errors.New("chain tip is not available yet"))
	}
	return connect.NewResponse(&syncpb.ReadTipResponse{
		Tip: tipBlockRef(best),
	}), nil
}

func (s *syncService) FetchBlock(
	ctx context.Context,
	req *connect.Request[syncpb.FetchBlockRequest],
) (*connect.Response[syncpb.FetchBlockResponse], error) {
	refs := req.Msg.GetRef()
	if len(refs) > s.server.cfg.MaxBlockRefs {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("at most %d block references may be "+
				"requested, got %d", s.server.cfg.MaxBlockRefs,
				len(refs)))
	}

	// An empty request means "the current tip", which the nil ref
	// resolves to.
	if len(refs) == 0 {
		refs = []*syncpb.BlockRef{nil}
	}

	blocks := make([]*syncpb.AnyChainBlock, 0, len(refs))
	for _, ref := range refs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		block, err := s.resolveBlock(ref)
		if err != nil {
			return nil, err
		}
		anyBlock, err := anyChainBlock(block)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal,
				fmt.Errorf("serialize block %s: %w",
					block.Hash(), err))
		}
		blocks = append(blocks, anyBlock)
	}

	return connect.NewResponse(&syncpb.FetchBlockResponse{
		Block: blocks,
	}), nil
}

func (s *syncService) DumpHistory(
	ctx context.Context,
	req *connect.Request[syncpb.DumpHistoryRequest],
) (*connect.Response[syncpb.DumpHistoryResponse], error) {
	best := s.server.cfg.Chain.BestSnapshot()
	if best == nil {
		return nil, connect.NewError(connect.CodeUnavailable,
			errors.New("chain tip is not available yet"))
	}

	maxItems := s.server.cfg.MaxHistoryItems
	if requested := req.Msg.GetMaxItems(); requested > 0 &&
		int64(requested) < int64(maxItems) {

		maxItems = int(requested)
	}

	start := int32(0)
	if token := req.Msg.GetStartToken(); token != nil {
		height, err := s.refHeight(token)
		if err != nil {
			return nil, err
		}
		start = height
	}
	if start > best.Height {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("start token height %d is beyond the "+
				"chain tip at height %d", start, best.Height))
	}

	blocks := make([]*syncpb.AnyChainBlock, 0, maxItems)
	height := start
	for ; height <= best.Height && len(blocks) < maxItems; height++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		block, err := s.server.cfg.Chain.BlockByHeight(height)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal,
				fmt.Errorf("load block at height %d: %w",
					height, err))
		}
		anyBlock, err := anyChainBlock(block)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal,
				fmt.Errorf("serialize block at height %d: %w",
					height, err))
		}
		blocks = append(blocks, anyBlock)
	}

	resp := &syncpb.DumpHistoryResponse{Block: blocks}
	// height now points one past the last block returned, which is the
	// next page's start. It is only a valid token while it remains at
	// or below the tip observed for this page.
	if height <= best.Height {
		next, err := s.server.cfg.Chain.BlockByHeight(height)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal,
				fmt.Errorf("load block at height %d: %w",
					height, err))
		}
		resp.NextToken = blockRef(next)
	}

	return connect.NewResponse(resp), nil
}

func (s *syncService) FollowTip(
	ctx context.Context,
	req *connect.Request[syncpb.FollowTipRequest],
	stream *connect.ServerStream[syncpb.FollowTipResponse],
) error {
	// Subscribe before reading the chain so no block slips through
	// between choosing the starting point and the first live event.
	sub := s.server.broker.subscribeBlocks()
	defer s.server.broker.unsubscribeBlocks(sub)

	start, err := s.resolveIntersect(req.Msg.GetIntersect())
	if err != nil {
		return err
	}

	// The starting point was on the main chain a moment ago, so a
	// failure here means a reorg moved it. The client should retry.
	startBlock, err := s.server.cfg.Chain.BlockByHash(&start.hash)
	if err != nil {
		return connect.NewError(connect.CodeUnavailable,
			fmt.Errorf("starting block %s is no longer on the "+
				"main chain", start.hash))
	}
	err = stream.Send(&syncpb.FollowTipResponse{
		Action: &syncpb.FollowTipResponse_Reset_{
			Reset_: blockRef(startBlock),
		},
		Tip: s.tipRef(),
	})
	if err != nil {
		return err
	}

	pos := start
	if err := s.backfill(ctx, stream, &pos); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case <-sub.lagged:
			return connect.NewError(connect.CodeResourceExhausted,
				errors.New("client fell too far behind the "+
					"chain; reconnect with an intersect"))

		case ev := <-sub.events:
			if err := s.forwardBlockEvent(stream, ev, &pos); err != nil {
				return err
			}
		}
	}
}

// backfill streams the main chain from just past pos up to the current
// tip, advancing pos as it goes. Blocks that arrive during the walk are
// buffered by the subscription and chain onto pos naturally once the
// walk catches up.
func (s *syncService) backfill(ctx context.Context,
	stream *connect.ServerStream[syncpb.FollowTipResponse],
	pos *cursor) error {

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		best := s.server.cfg.Chain.BestSnapshot()
		if best == nil || pos.height >= best.Height {
			return nil
		}

		next := pos.height + 1
		block, err := s.server.cfg.Chain.BlockByHeight(next)
		if err != nil {
			return connect.NewError(connect.CodeInternal,
				fmt.Errorf("load block at height %d: %w",
					next, err))
		}
		// A reorg underneath the walk leaves the loaded block
		// unattached to the client's position. The live stream
		// delivers the undo events needed to recover, so stop here.
		if block.MsgBlock().Header.PrevBlock != pos.hash {
			return nil
		}
		if err := s.sendApply(stream, block, pos); err != nil {
			return err
		}
	}
}

// forwardBlockEvent sends ev when it connects to the client's position
// and discards it otherwise.
func (s *syncService) forwardBlockEvent(
	stream *connect.ServerStream[syncpb.FollowTipResponse],
	ev blockEvent, pos *cursor) error {

	switch ev.action {
	case chainApply:
		if ev.prev != pos.hash {
			return nil
		}
		err := stream.Send(&syncpb.FollowTipResponse{
			Action: &syncpb.FollowTipResponse_Apply{
				Apply: &syncpb.AnyChainBlock{NativeBytes: ev.raw},
			},
			Tip: s.tipRef(),
		})
		if err != nil {
			return err
		}
		pos.hash = ev.hash
		pos.height = ev.height
		return nil

	case chainUndo:
		if ev.hash != pos.hash {
			return nil
		}
		err := stream.Send(&syncpb.FollowTipResponse{
			Action: &syncpb.FollowTipResponse_Undo{
				Undo: &syncpb.AnyChainBlock{NativeBytes: ev.raw},
			},
			Tip: s.tipRef(),
		})
		if err != nil {
			return err
		}
		pos.hash = ev.prev
		pos.height = ev.height - 1
		return nil
	}

	return nil
}

func (s *syncService) sendApply(
	stream *connect.ServerStream[syncpb.FollowTipResponse],
	block *hnsutil.Block, pos *cursor) error {

	anyBlock, err := anyChainBlock(block)
	if err != nil {
		return connect.NewError(connect.CodeInternal,
			fmt.Errorf("serialize block %s: %w", block.Hash(), err))
	}
	err = stream.Send(&syncpb.FollowTipResponse{
		Action: &syncpb.FollowTipResponse_Apply{Apply: anyBlock},
		Tip:    s.tipRef(),
	})
	if err != nil {
		return err
	}
	pos.hash = *block.Hash()
	pos.height = block.Height()
	return nil
}

func (s *syncService) tipRef() *syncpb.BlockRef {
	return tipBlockRef(s.server.cfg.Chain.BestSnapshot())
}

// resolveIntersect picks the highest supplied reference that is still
// on the main chain. With no usable reference the stream starts at the
// current tip, which is what an empty intersect list requests.
func (s *syncService) resolveIntersect(refs []*syncpb.BlockRef) (cursor, error) {
	var best cursor
	var found bool

	for _, ref := range refs {
		hash, err := refHash(ref)
		if err != nil {
			return cursor{}, err
		}
		if hash == nil || !s.server.cfg.Chain.MainChainHasBlock(hash) {
			continue
		}
		height, err := s.server.cfg.Chain.BlockHeightByHash(hash)
		if err != nil {
			continue
		}
		if !found || height > best.height {
			best = cursor{hash: *hash, height: height}
			found = true
		}
	}
	if found {
		return best, nil
	}

	tip := s.server.cfg.Chain.BestSnapshot()
	if tip == nil {
		return cursor{}, connect.NewError(connect.CodeUnavailable,
			errors.New("chain tip is not available yet"))
	}
	return cursor{hash: tip.Hash, height: tip.Height}, nil
}

// resolveBlock loads the block a reference names. A nil reference
// resolves to the chain tip; a reference carrying neither a hash nor a
// non-zero height resolves to genesis.
func (s *syncService) resolveBlock(ref *syncpb.BlockRef) (*hnsutil.Block, error) {
	if ref == nil {
		best := s.server.cfg.Chain.BestSnapshot()
		if best == nil {
			return nil, connect.NewError(connect.CodeUnavailable,
				errors.New("chain tip is not available yet"))
		}
		return s.blockByHeight(uint64(best.Height)) //nolint:gosec // heights are non-negative
	}

	hash, err := refHash(ref)
	if err != nil {
		return nil, err
	}
	if hash != nil {
		block, err := s.server.cfg.Chain.BlockByHash(hash)
		if err != nil {
			return nil, connect.NewError(connect.CodeNotFound,
				fmt.Errorf("block %s not found", hash))
		}
		return block, nil
	}

	return s.blockByHeight(refHeightValue(ref))
}

func (s *syncService) blockByHeight(height uint64) (*hnsutil.Block, error) {
	if height > uint64(^uint32(0)>>1) {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("block height %d is out of range", height))
	}
	block, err := s.server.cfg.Chain.BlockByHeight(int32(height)) //nolint:gosec // bounded above
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound,
			fmt.Errorf("no block at height %d", height))
	}
	return block, nil
}

// refHeight resolves a reference to a main chain height, preferring the
// hash when one is present.
func (s *syncService) refHeight(ref *syncpb.BlockRef) (int32, error) {
	hash, err := refHash(ref)
	if err != nil {
		return 0, err
	}
	if hash != nil {
		height, err := s.server.cfg.Chain.BlockHeightByHash(hash)
		if err != nil {
			return 0, connect.NewError(connect.CodeNotFound,
				fmt.Errorf("block %s is not on the main chain",
					hash))
		}
		return height, nil
	}

	height := refHeightValue(ref)
	if height > uint64(^uint32(0)>>1) {
		return 0, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("block height %d is out of range", height))
	}
	return int32(height), nil //nolint:gosec // bounded above
}

// refHash extracts the block hash from a reference, or nil when it
// carries none.
func refHash(ref *syncpb.BlockRef) (*chainhash.Hash, error) {
	if ref == nil || len(ref.GetHash()) == 0 {
		return nil, nil
	}
	hash, err := chainhash.NewHash(ref.GetHash())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("invalid block hash: %w", err))
	}
	return hash, nil
}

// refHeightValue reads the height from a reference, falling back to the
// slot field that Handshake populates with the same value.
func refHeightValue(ref *syncpb.BlockRef) uint64 {
	if ref == nil {
		return 0
	}
	if height := ref.GetHeight(); height > 0 {
		return height
	}
	return ref.GetSlot()
}
