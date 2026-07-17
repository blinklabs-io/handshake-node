# handshake-node

[![Build Status](https://github.com/blinklabs-io/handshake-node/workflows/Build%20and%20Test/badge.svg)](https://github.com/blinklabs-io/handshake-node/actions)
[![ISC License](http://img.shields.io/badge/license-ISC-blue.svg)](http://copyfree.org)
[![GoDoc](https://img.shields.io/badge/godoc-reference-blue.svg)](https://pkg.go.dev/github.com/blinklabs-io/handshake-node)

handshake-node is a Handshake (HNS) blockchain full node implementation written
in Go, forked from [btcd](https://github.com/btcsuite/btcd).

The node implements Handshake mainnet and regtest chain parameters,
Handshake proof-of-work and 236-byte block headers, covenant-aware
transactions, Urkel-backed name state, Brontide P2P transport, mempool,
mining, JSON-RPC, websocket notifications, and command-line control through
`hnsctl`.

handshake-node does *not* include wallet functionality. Wallet signing and
wallet-facing state belong in external wallet software.

## Documentation

Documentation is a work-in-progress for the current 0.2.0-rc1 mainnet release
candidate.

## Contents

* [Installation](installation.md)
* [Update](update.md)
* [Configuration](configuration.md)
* [Configuring TOR](configuring_tor.md)
* [Docker](using_docker.md)
* [Controlling](controlling.md)
* [Mining](mining.md)
* [Wallet](wallet.md)
* [cdnsd integration](cdnsd.md)
* [Developer resources](developer_resources.md)
* [JSON RPC API](json_rpc_api.md)
* [Code contribution guidelines](code_contribution_guidelines.md)
* [Contact](contact.md)

## License

handshake-node is licensed under the [copyfree](http://copyfree.org) ISC License.
The upstream btcd project is also ISC licensed.
