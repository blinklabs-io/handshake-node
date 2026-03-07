# handshake-node

[![Build Status](https://github.com/blinklabs-io/handshake-node/workflows/Build%20and%20Test/badge.svg)](https://github.com/blinklabs-io/handshake-node/actions)
[![ISC License](http://img.shields.io/badge/license-ISC-blue.svg)](http://copyfree.org)
[![GoDoc](https://img.shields.io/badge/godoc-reference-blue.svg)](https://pkg.go.dev/github.com/blinklabs-io/handshake-node)

handshake-node is a Handshake (HNS) blockchain full node implementation written
in Go, forked from [btcd](https://github.com/btcsuite/btcd).

This project is currently under active development.

It properly downloads, validates, and serves the block chain using the exact
rules for block acceptance.

It also properly relays newly mined blocks, maintains a transaction pool, and
relays individual transactions that have not yet made it into a block.  It
ensures all individual transactions admitted to the pool follow the rules
required by the block chain and also includes more strict checks which filter
transactions based on miner requirements ("standard" transactions).

One key difference between handshake-node and Bitcoin Core is that handshake-node does *NOT* include
wallet functionality and this was a very intentional design decision.
This means you can't actually make or receive payments
directly with handshake-node.  That functionality is provided by the
[bursa](https://github.com/blinklabs-io/bursa) project
which is under active development.

## Documentation

Documentation is a work-in-progress.

## Contents

* [Installation](installation.md)
* [Update](update.md)
* [Configuration](configuration.md)
* [Configuring TOR](configuring_tor.md)
* [Docker](using_docker.md)
* [Controlling](controlling.md)
* [Mining](mining.md)
* [Wallet](wallet.md)
* [Developer resources](developer_resources.md)
* [JSON RPC API](json_rpc_api.md)
* [Code contribution guidelines](code_contribution_guidelines.md)
* [Contact](contact.md)

## License

handshake-node is licensed under the [copyfree](http://copyfree.org) ISC License.
The upstream btcd project is also ISC licensed.
