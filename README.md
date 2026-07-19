handshake-node
==============

[![Build Status](https://github.com/blinklabs-io/handshake-node/actions/workflows/go-test.yml/badge.svg)](https://github.com/blinklabs-io/handshake-node/actions/workflows/go-test.yml)
[![ISC License](https://img.shields.io/badge/license-ISC-blue.svg)](http://copyfree.org)
[![GoDoc](https://img.shields.io/badge/godoc-reference-blue.svg)](https://pkg.go.dev/github.com/blinklabs-io/handshake-node)

handshake-node is a Handshake (HNS) blockchain full node written in Go. It is a
fork of [btcd](https://github.com/btcsuite/btcd), but its target behavior is the
Handshake network: Handshake block headers, proof-of-work, transactions,
covenants, name state, P2P transport, mining, and RPCs.

This is not a Bitcoin node, and it does not include a wallet. Wallet software
must manage keys, signing, coin selection, and wallet state externally.

## Current Status

The current release is 0.2.1-rc1, a mainnet release candidate. It includes:

- Handshake mainnet and regtest chain parameters.
- Blake2b/SHA3 Handshake proof-of-work and 236-byte block headers.
- Handshake transaction outputs with address and covenant data.
- Name covenant validation, Urkel-backed name state, and name proof RPCs.
- Brontide P2P transport with plaintext fallback for compatibility work.
- Mempool, mining, `getblocktemplate`, coinbase proof handling, and a Stratum
  v1 MVP server.
- Authenticated JSON-RPC, websocket notifications, unsigned covenant
  constructors, `hnsctl`, and `rpcclient` support.
- hsd-compatible claim and airdrop proof relay, submission RPCs, and expanded
  operational RPC coverage.
- Handshake bloom filtering and partial Merkle proofs compatible with hsd.
- A resumable hsd parity runner and pinned interoperability/recovery tests for
  mainnet-readiness validation.
- Full-block Handshake P2P service suitable for cdnsd indexing.

## Requirements

[Go](https://go.dev/doc/install) 1.26.5 or newer. The module toolchain
directive automatically selects a patched Go toolchain when supported.

## Build

```bash
git clone https://github.com/blinklabs-io/handshake-node.git
cd handshake-node
make build
```

To install the node and command-line tools into your Go binary directory:

```bash
go install -v . ./cmd/...
```

## Run

```bash
handshake-node
```

The daemon can start with no configuration, but production deployments should
set explicit RPC credentials and review listener settings:

```bash
handshake-node \
  --rpcuser=myuser \
  --rpcpass=mypassword \
  --rpclisten=127.0.0.1:12037
```

Environment variables use the `HANDSHAKE_NODE_` prefix, for example
`HANDSHAKE_NODE_RPCUSER` and `HANDSHAKE_NODE_RPCPASS`.

## Ports

| Port  | Purpose |
|-------|---------|
| 12038 | Mainnet P2P |
| 12037 | Mainnet RPC |
| 12039 | Prometheus metrics, disabled by default |
| 12040 | Stratum, disabled by default |

RPC is authenticated and TLS-enabled by default. Do not expose RPC, metrics, or
Stratum listeners publicly without reviewing the security options in
`docs/configuration.md`.

## Test

```bash
make unit
make lint
```

Integration tests are run serially because the daemon harness allocates local
ports:

```bash
go test -p 1 -v -tags=rpctest ./integration/...
```

## Documentation

- [Configuration](docs/configuration.md)
- [Controlling the node with hnsctl](docs/controlling.md)
- [JSON-RPC API](docs/json_rpc_api.md)
- [Mining](docs/mining.md)
- [Wallet integration](docs/wallet.md)
- [cdnsd integration](docs/cdnsd.md)
- [Docker](docs/using_docker.md)

## License

handshake-node is licensed under the [copyfree](http://copyfree.org) ISC
License. Upstream btcd-derived code is also ISC licensed.
