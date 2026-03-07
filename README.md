handshake-node
==============

[![Build Status](https://github.com/blinklabs-io/handshake-node/workflows/Build%20and%20Test/badge.svg)](https://github.com/blinklabs-io/handshake-node/actions)
[![ISC License](https://img.shields.io/badge/license-ISC-blue.svg)](http://copyfree.org)
[![GoDoc](https://img.shields.io/badge/godoc-reference-blue.svg)](https://pkg.go.dev/github.com/blinklabs-io/handshake-node)

handshake-node is a Handshake (HNS) blockchain full node implementation written
in Go, forked from [btcd](https://github.com/btcsuite/btcd).

This project is currently under active development.

## Requirements

[Go](http://golang.org) 1.23 or newer.

## Installation

#### Linux/BSD/MacOSX/POSIX - Build from Source

- Install Go according to the installation instructions here:
  http://golang.org/doc/install

- Run the following commands to obtain handshake-node, all dependencies, and install it:

```bash
$ git clone https://github.com/blinklabs-io/handshake-node.git
$ cd handshake-node
$ go install -v . ./cmd/...
```

- handshake-node and hnsctl will now be installed in `$GOPATH/bin`.

## Getting Started

handshake-node has several configuration options available to tweak how it runs, but all
of the basic operations work with zero configuration.

```bash
$ ./handshake-node
```

## Ports

| Port  | Purpose |
|-------|---------|
| 12038 | P2P     |
| 12037 | RPC     |

## Documentation

The documentation is a work-in-progress.  It is located in the
[docs](https://github.com/blinklabs-io/handshake-node/tree/master/docs) folder.

## License

handshake-node is licensed under the [copyfree](http://copyfree.org) ISC License.
The upstream btcd project is also ISC licensed.
