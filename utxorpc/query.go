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
	"github.com/blinklabs-io/handshake-node/wire"
	querypb "github.com/utxorpc/go-codegen/utxorpc/v1beta/query"
)

// queryService implements queryconnect.QueryServiceHandler.
type queryService struct {
	server *Server
}

func (s *queryService) ReadUtxos(
	ctx context.Context,
	req *connect.Request[querypb.ReadUtxosRequest],
) (*connect.Response[querypb.ReadUtxosResponse], error) {
	keys := req.Msg.GetKeys()
	if len(keys) > s.server.cfg.MaxUtxoKeys {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("at most %d outputs may be requested, got %d",
				s.server.cfg.MaxUtxoKeys, len(keys)))
	}

	tip, err := s.server.bestState()
	if err != nil {
		return nil, err
	}

	items := make([]*querypb.AnyUtxoData, 0, len(keys))
	for _, key := range keys {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		item, err := s.readUtxo(key)
		if err != nil {
			return nil, err
		}
		// An absent or already-spent output is omitted rather than
		// failing the batch, so a client can probe many outpoints in
		// one call.
		if item != nil {
			items = append(items, item)
		}
	}

	return connect.NewResponse(&querypb.ReadUtxosResponse{
		Items:     items,
		LedgerTip: tip,
	}), nil
}

func (s *queryService) readUtxo(key *querypb.TxoRef) (*querypb.AnyUtxoData, error) {
	if key == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			errors.New("output reference is required"))
	}
	hash, err := chainhash.NewHash(key.GetHash())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("invalid transaction hash: %w", err))
	}

	outpoint := wire.OutPoint{Hash: *hash, Index: key.GetIndex()}
	entry, err := s.server.cfg.Chain.FetchUtxoEntry(outpoint)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal,
			fmt.Errorf("load output %s:%d: %w", hash,
				key.GetIndex(), err))
	}
	if entry == nil || entry.IsSpent() {
		return nil, nil
	}

	raw, err := serializeTxOut(entry.TxOut())
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal,
			fmt.Errorf("serialize output %s:%d: %w", hash,
				key.GetIndex(), err))
	}

	data := &querypb.AnyUtxoData{
		NativeBytes: raw,
		TxoRef: &querypb.TxoRef{
			Hash:  hash.CloneBytes(),
			Index: key.GetIndex(),
		},
	}
	// The creating block is only reported when its hash is still
	// resolvable; a pruned node may no longer have it.
	if blockHash, err := s.server.cfg.Chain.BlockHashByHeight(
		entry.BlockHeight()); err == nil {

		data.BlockRef = chainPointAt(entry.BlockHeight(), blockHash)
	}

	return data, nil
}

func (s *queryService) ReadTx(
	ctx context.Context,
	req *connect.Request[querypb.ReadTxRequest],
) (*connect.Response[querypb.ReadTxResponse], error) {
	hash, err := chainhash.NewHash(req.Msg.GetHash())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument,
			fmt.Errorf("invalid transaction hash: %w", err))
	}

	tip, err := s.server.bestState()
	if err != nil {
		return nil, err
	}

	// The mempool is checked first: an unconfirmed transaction is never
	// in the index, and one that confirmed in between is still returned
	// correctly, just without a block reference.
	if pool := s.server.cfg.TxMemPool; pool != nil {
		if tx, err := pool.FetchTransaction(hash); err == nil && tx != nil {
			raw, err := serializeTx(tx.MsgTx())
			if err != nil {
				return nil, connect.NewError(connect.CodeInternal,
					fmt.Errorf("serialize transaction %s: %w",
						hash, err))
			}
			return connect.NewResponse(&querypb.ReadTxResponse{
				Tx:        &querypb.AnyChainTx{NativeBytes: raw},
				LedgerTip: tip,
			}), nil
		}
	}

	fetcher := s.server.cfg.TxFetcher
	if fetcher == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition,
			errors.New("confirmed transaction lookup requires the "+
				"node to run with --txindex"))
	}

	raw, blockHash, err := fetcher.FetchRawTx(hash)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal,
			fmt.Errorf("load transaction %s: %w", hash, err))
	}
	if raw == nil {
		return nil, connect.NewError(connect.CodeNotFound,
			fmt.Errorf("transaction %s not found", hash))
	}

	tx := &querypb.AnyChainTx{NativeBytes: raw}
	if blockHash != nil {
		if height, err := s.server.cfg.Chain.BlockHeightByHash(
			blockHash); err == nil {

			tx.BlockRef = chainPointAt(height, blockHash)
		}
	}

	return connect.NewResponse(&querypb.ReadTxResponse{
		Tx:        tx,
		LedgerTip: tip,
	}), nil
}

func (s *queryService) ReadGenesis(
	ctx context.Context,
	req *connect.Request[querypb.ReadGenesisRequest],
) (*connect.Response[querypb.ReadGenesisResponse], error) {
	params := s.server.cfg.ChainParams
	return connect.NewResponse(&querypb.ReadGenesisResponse{
		Genesis: params.GenesisHash.CloneBytes(),
		Caip2:   caip2(params.Name),
	}), nil
}

// caip2 builds the chain identifier clients use to tell networks apart.
// Handshake has no registered CAIP-2 namespace, so the network name
// from the active chain parameters is used as the reference.
func caip2(network string) string {
	return "handshake:" + network
}

func (s *queryService) ReadParams(
	ctx context.Context,
	req *connect.Request[querypb.ReadParamsRequest],
) (*connect.Response[querypb.ReadParamsResponse], error) {
	return nil, unsupportedForHandshake("ReadParams",
		"its response carries no Handshake parameter type")
}

func (s *queryService) SearchUtxos(
	ctx context.Context,
	req *connect.Request[querypb.SearchUtxosRequest],
) (*connect.Response[querypb.SearchUtxosResponse], error) {
	return nil, unsupportedForHandshake("SearchUtxos",
		"its predicates describe Cardano outputs only")
}

func (s *queryService) ReadData(
	ctx context.Context,
	req *connect.Request[querypb.ReadDataRequest],
) (*connect.Response[querypb.ReadDataResponse], error) {
	return nil, unsupportedForHandshake("ReadData",
		"Handshake has no datum store")
}

func (s *queryService) ReadEraSummary(
	ctx context.Context,
	req *connect.Request[querypb.ReadEraSummaryRequest],
) (*connect.Response[querypb.ReadEraSummaryResponse], error) {
	return nil, unsupportedForHandshake("ReadEraSummary",
		"Handshake has no eras")
}

func (s *queryService) ReadState(
	ctx context.Context,
	req *connect.Request[querypb.ReadStateRequest],
) (*connect.Response[querypb.ReadStateResponse], error) {
	return nil, unsupportedForHandshake("ReadState",
		"its queries describe Cardano ledger state only")
}

// unsupportedForHandshake reports a procedure the UTxO RPC schema
// cannot express for Handshake, naming the reason so operators do not
// mistake it for a missing feature.
func unsupportedForHandshake(procedure, reason string) error {
	return connect.NewError(connect.CodeUnimplemented,
		fmt.Errorf("%s is not supported on Handshake because %s",
			procedure, reason))
}
