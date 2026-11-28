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
	"github.com/blinklabs-io/handshake-node/mempool"
	submitpb "github.com/utxorpc/go-codegen/utxorpc/v1beta/submit"
)

// submitService implements submitconnect.SubmitServiceHandler.
type submitService struct {
	server *Server
}

func (s *submitService) SubmitTx(
	ctx context.Context,
	req *connect.Request[submitpb.SubmitTxRequest],
) (*connect.Response[submitpb.SubmitTxResponse], error) {
	submitter := s.server.cfg.Submitter
	if submitter == nil {
		return nil, connect.NewError(connect.CodeUnimplemented,
			errors.New("transaction submission is not available"))
	}

	raw := req.Msg.GetTx().GetRaw()
	if len(raw) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("a raw transaction is required"))
	}

	tx, err := hnsutil.NewTxFromBytes(raw)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("decode transaction: %w", err))
	}

	if err := submitter.SubmitTransaction(tx); err != nil {
		// A rule error means the transaction was judged and rejected,
		// which is the client's fault; anything else is the node
		// failing to do its job.
		var ruleErr mempool.RuleError
		if errors.As(err, &ruleErr) {
			return nil, connect.NewError(connect.CodeInvalidArgument,
				fmt.Errorf("transaction rejected: %w", err))
		}
		log.Errorf("Failed to submit transaction %v: %v", tx.Hash(), err)
		return nil, connect.NewError(connect.CodeInternal,
			fmt.Errorf("submit transaction: %w", err))
	}

	return connect.NewResponse(&submitpb.SubmitTxResponse{
		Ref: tx.Hash().CloneBytes(),
	}), nil
}

func (s *submitService) ReadMempool(
	ctx context.Context,
	req *connect.Request[submitpb.ReadMempoolRequest],
) (*connect.Response[submitpb.ReadMempoolResponse], error) {
	pool := s.server.cfg.TxMemPool
	if pool == nil {
		return nil, connect.NewError(connect.CodeUnimplemented,
			errors.New("mempool access is not available"))
	}

	descs := pool.TxDescs()
	items := make([]*submitpb.TxInMempool, 0, len(descs))
	for _, desc := range descs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		item, err := mempoolTx(desc.Tx, submitpb.Stage_STAGE_MEMPOOL)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}

	return connect.NewResponse(&submitpb.ReadMempoolResponse{
		Items: items,
	}), nil
}

func (s *submitService) WatchMempool(
	ctx context.Context,
	req *connect.Request[submitpb.WatchMempoolRequest],
	stream *connect.ServerStream[submitpb.WatchMempoolResponse],
) error {
	if s.server.cfg.TxMemPool == nil {
		return connect.NewError(connect.CodeUnimplemented,
			errors.New("mempool access is not available"))
	}
	if req.Msg.GetPredicate() != nil {
		return unsupportedForHandshake("WatchMempool with a predicate",
			"its patterns describe Cardano transactions only")
	}

	sub := s.server.broker.subscribeMempool()
	defer s.server.broker.unsubscribeMempool(sub)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case <-sub.lagged:
			return connect.NewError(connect.CodeResourceExhausted,
				errors.New("client fell too far behind the "+
					"mempool"))

		case ev := <-sub.events:
			// Only arrivals belong on this stream; confirmations
			// are reported by WaitForTx and FollowTip.
			if ev.stage != submitpb.Stage_STAGE_MEMPOOL {
				continue
			}
			err := stream.Send(&submitpb.WatchMempoolResponse{
				Tx: &submitpb.TxInMempool{
					Ref:         ev.ref.CloneBytes(),
					NativeBytes: ev.raw,
					Stage:       ev.stage,
				},
			})
			if err != nil {
				return err
			}
		}
	}
}

func (s *submitService) WaitForTx(
	ctx context.Context,
	req *connect.Request[submitpb.WaitForTxRequest],
	stream *connect.ServerStream[submitpb.WaitForTxResponse],
) error {
	refs := req.Msg.GetRef()
	if len(refs) == 0 {
		return connect.NewError(connect.CodeInvalidArgument,
			errors.New("at least one transaction reference is required"))
	}

	pending := make(map[chainhash.Hash]struct{}, len(refs))
	for _, ref := range refs {
		hash, err := chainhash.NewHash(ref)
		if err != nil {
			return connect.NewError(connect.CodeInvalidArgument,
				fmt.Errorf("invalid transaction hash: %w", err))
		}
		pending[*hash] = struct{}{}
	}

	// Subscribe before inspecting current state so a transaction that
	// confirms during the inspection is still reported.
	sub := s.server.broker.subscribeMempool()
	defer s.server.broker.unsubscribeMempool(sub)

	for hash := range pending {
		stage, known, err := s.currentStage(hash)
		if err != nil {
			return err
		}
		if !known {
			continue
		}
		err = stream.Send(&submitpb.WaitForTxResponse{
			Ref:   hash.CloneBytes(),
			Stage: stage,
		})
		if err != nil {
			return err
		}
		if stage == submitpb.Stage_STAGE_CONFIRMED {
			delete(pending, hash)
		}
	}

	for len(pending) > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case <-sub.lagged:
			return connect.NewError(connect.CodeResourceExhausted,
				errors.New("client fell too far behind the "+
					"mempool"))

		case ev := <-sub.events:
			if _, watched := pending[ev.ref]; !watched {
				continue
			}
			err := stream.Send(&submitpb.WaitForTxResponse{
				Ref:   ev.ref.CloneBytes(),
				Stage: ev.stage,
			})
			if err != nil {
				return err
			}
			// Confirmation is the terminal stage, so the
			// transaction is no longer watched once it lands in a
			// block.
			if ev.stage == submitpb.Stage_STAGE_CONFIRMED {
				delete(pending, ev.ref)
			}
		}
	}

	return nil
}

// currentStage reports the stage a transaction has already reached, so
// a client waiting on something that happened before it connected is
// answered rather than left hanging. A transaction that is neither in
// the mempool nor confirmed is reported as unknown, and the caller
// waits for it to arrive.
func (s *submitService) currentStage(hash chainhash.Hash) (submitpb.Stage,
	bool, error) {

	if pool := s.server.cfg.TxMemPool; pool != nil &&
		pool.HaveTransaction(&hash) {

		return submitpb.Stage_STAGE_MEMPOOL, true, nil
	}

	// Confirmation can only be observed with a transaction index; a
	// node without one simply waits for the next block.
	fetcher := s.server.cfg.TxFetcher
	if fetcher == nil {
		return submitpb.Stage_STAGE_UNSPECIFIED, false, nil
	}
	raw, _, err := fetcher.FetchRawTx(&hash)
	if err != nil {
		return submitpb.Stage_STAGE_UNSPECIFIED, false,
			connect.NewError(connect.CodeInternal,
				fmt.Errorf("load transaction %s: %w", hash, err))
	}
	if raw == nil {
		return submitpb.Stage_STAGE_UNSPECIFIED, false, nil
	}
	return submitpb.Stage_STAGE_CONFIRMED, true, nil
}

func (s *submitService) EvalTx(
	ctx context.Context,
	req *connect.Request[submitpb.EvalTxRequest],
) (*connect.Response[submitpb.EvalTxResponse], error) {
	return nil, unsupportedForHandshake("EvalTx",
		"its report describes Cardano script execution only")
}

func mempoolTx(tx *hnsutil.Tx, stage submitpb.Stage) (*submitpb.TxInMempool, error) {
	raw, err := serializeTx(tx.MsgTx())
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal,
			fmt.Errorf("serialize transaction %s: %w", tx.Hash(), err))
	}
	return &submitpb.TxInMempool{
		Ref:         tx.Hash().CloneBytes(),
		NativeBytes: raw,
		Stage:       stage,
	}, nil
}
