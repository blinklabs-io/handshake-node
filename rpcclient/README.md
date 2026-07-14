rpcclient
=========

[![Build Status](https://github.com/blinklabs-io/handshake-node/actions/workflows/go-test.yml/badge.svg)](https://github.com/blinklabs-io/handshake-node/actions/workflows/go-test.yml)
[![ISC License](https://img.shields.io/badge/license-ISC-blue.svg)](http://copyfree.org)
[![GoDoc](https://img.shields.io/badge/godoc-reference-blue.svg)](https://pkg.go.dev/github.com/blinklabs-io/handshake-node/rpcclient)

Package rpcclient provides synchronous and asynchronous clients for the
handshake-node JSON-RPC API. It supports HTTP POST and WebSocket transports,
automatic WebSocket reconnection, notification handlers, and conversion to the
repository's higher-level Go types.

handshake-node does not contain wallet state. Wallet implementations can use
chain RPCs from this package for UTXO lookup, unsigned covenant construction,
transaction broadcast, and notifications.

## Documentation

- [API reference](https://pkg.go.dev/github.com/blinklabs-io/handshake-node/rpcclient)
- [Handshake WebSocket example](examples/hnswebsockets)
- [Custom command example](examples/customcommand)

## Installation

```bash
go get github.com/blinklabs-io/handshake-node/rpcclient
```

## License

Package rpcclient is licensed under the ISC License.
