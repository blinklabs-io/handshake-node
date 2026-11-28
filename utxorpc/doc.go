// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

/*
Package utxorpc serves the UTxO RPC v1beta interface
(https://utxorpc.org) over Connect, gRPC, and gRPC-Web on a shared set
of listeners.

# Chain payload encoding

The UTxO RPC schema carries chain data in "any chain" envelopes that pair
a chain-agnostic native_bytes field with a oneof holding a parsed,
chain-specific message. As of spec v1beta the oneof arms are defined for
Cardano only, so every Handshake payload this package emits travels in
native_bytes, encoded exactly as it appears on the Handshake wire:
blocks as wire.MsgBlock, transactions as wire.MsgTx, and individual
unspent outputs as wire.TxOut. Clients decode those bytes with any
Handshake implementation.

That constraint also decides which procedures a Handshake node can
answer at all. Procedures whose response has no native_bytes escape
hatch have no way to describe a Handshake chain and return
CodeUnimplemented:

  - query.ReadParams, query.ReadEraSummary, query.ReadState — their
    responses are a bare Cardano-only oneof.
  - query.ReadData — Handshake has no datum store.
  - query.SearchUtxos — its predicates are Cardano-only patterns, so no
    Handshake query is expressible.
  - submit.EvalTx — scoped to Cardano script evaluation.

watch.WatchService is not registered for the same reason: its
AnyChainTx has no native_bytes field, so a Handshake transaction cannot
be represented in a WatchTx response. Use submit.WatchMempool for
mempool arrivals and sync.FollowTip for confirmed blocks.

# Security

The server is disabled unless listen addresses are configured, and it
performs no authentication. Bind it to a trusted interface.
*/
package utxorpc
