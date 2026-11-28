# UTxO RPC

handshake-node can serve the [UTxO RPC](https://utxorpc.org) v1beta interface,
a chain-agnostic gRPC API for UTxO blockchains. It is an optional server,
disabled unless listen addresses are configured.

## Enabling the server

```text
[Application Options]

utxorpclisten=127.0.0.1:12041
```

The default port is 12041 when the listen address omits one.

The endpoint is **not authenticated**. Binding it to a non-loopback interface
therefore requires `--utxorpcallowpublic` as an explicit acknowledgement, and
such a bind may not be combined with `--notls`.

TLS uses the same key pair as the JSON-RPC server (`--rpccert` and `--rpckey`),
generating one on first use if it does not exist, and is disabled by `--notls`.
A loopback-only deployment is usually simplest with `--notls`, which serves
cleartext HTTP/2 that gRPC clients connect to directly.

Each listener serves the Connect, gRPC, and gRPC-Web protocols, along with
gRPC health checking and server reflection, so `grpcurl` and similar tools work
without a local copy of the schema:

```sh
grpcurl -plaintext 127.0.0.1:12041 list
grpcurl -plaintext 127.0.0.1:12041 utxorpc.v1beta.sync.SyncService/ReadTip
```

## How Handshake data is carried

Every "any chain" message in the UTxO RPC schema pairs a chain-agnostic
`native_bytes` field with a `oneof` holding a parsed, chain-specific message.
As of spec v1beta those `oneof` arms are defined for Cardano only, so
handshake-node returns all chain data in `native_bytes`, encoded exactly as it
appears on the Handshake wire:

| Message | `native_bytes` contents |
|---------|-------------------------|
| `sync.AnyChainBlock` | A serialized block, including witness data |
| `query.AnyChainTx` | A serialized transaction, including witness data |
| `query.AnyUtxoData` | A serialized transaction output: value, address, covenant |
| `submit.TxInMempool` | A serialized transaction, including witness data |

Clients decode those bytes with any Handshake implementation. Transactions are
submitted the same way, through `submit.AnyChainTx`'s chain-agnostic `raw`
field.

Handshake has no slots, so block references report the block height in both the
`height` and `slot` fields, and `timestamp` is in milliseconds. Hashes are the
native Handshake byte order, the same order the JSON-RPC API prints.

## Supported procedures

### `utxorpc.v1beta.sync.SyncService`

| Procedure | Notes |
|-----------|-------|
| `ReadTip` | Current main chain tip |
| `FetchBlock` | By hash or height; an empty request returns the tip |
| `DumpHistory` | Pages forward through the main chain from `start_token` |
| `FollowTip` | Streams `reset`, then `apply`/`undo` as the chain moves |

`FollowTip` resolves the highest supplied `intersect` reference that is still on
the main chain, resets to it, streams the blocks between there and the tip, and
then follows live. With no usable reference it starts at the current tip. A
client that stops reading long enough to fall behind the server's buffer is
disconnected with `RESOURCE_EXHAUSTED` rather than silently skipping blocks; it
should reconnect with its last known block as the intersect.

### `utxorpc.v1beta.query.QueryService`

| Procedure | Notes |
|-----------|-------|
| `ReadUtxos` | Unknown or spent outputs are omitted rather than failing the batch |
| `ReadTx` | Checks the mempool, then the transaction index |
| `ReadGenesis` | Genesis hash and a `handshake:<network>` CAIP-2 identifier |

`ReadTx` can only resolve confirmed transactions when the node runs with
`--txindex`; without it, a transaction that is not in the mempool returns
`FAILED_PRECONDITION`.

### `utxorpc.v1beta.submit.SubmitService`

| Procedure | Notes |
|-----------|-------|
| `SubmitTx` | Validates into the mempool and relays, as `sendrawtransaction` does |
| `ReadMempool` | Current mempool contents |
| `WatchMempool` | Streams transactions as they are accepted into the mempool |
| `WaitForTx` | Streams stage changes for specific transactions until each confirms |

A transaction rejected by mempool policy or consensus returns
`INVALID_ARGUMENT`; `INTERNAL` means the node itself failed.

`WaitForTx` first reports the stage each transaction has already reached, so a
client that connects late is not left waiting on an event that has passed.
Recognising a transaction that confirmed before the call needs `--txindex`;
without it, a transaction that is not in the mempool is treated as not yet
seen. The stream ends once every requested transaction has confirmed.

## Unsupported procedures

These return `UNIMPLEMENTED` because the UTxO RPC schema has no way to express
them for Handshake, not because they are unfinished:

| Procedure | Reason |
|-----------|--------|
| `query.ReadParams` | Its response is a Cardano-only `oneof` with no `native_bytes` |
| `query.ReadEraSummary` | Handshake has no eras |
| `query.ReadState` | Its queries describe Cardano ledger state |
| `query.ReadData` | Handshake has no datum store |
| `query.SearchUtxos` | Its predicates describe Cardano outputs |
| `submit.EvalTx` | Scoped to Cardano script evaluation |
| `submit.WatchMempool` with a `predicate` | Its patterns describe Cardano transactions |

`utxorpc.v1beta.watch.WatchService` is not registered at all: its `AnyChainTx`
has no `native_bytes` field, so a Handshake transaction cannot be represented in
a `WatchTx` response. Use `submit.WatchMempool` for mempool arrivals and
`sync.FollowTip` for confirmed blocks.

## Logging

The server logs under the `UXRP` subsystem, so its level is set with
`--debuglevel=UXRP=debug`.
