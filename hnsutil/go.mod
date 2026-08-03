module github.com/blinklabs-io/handshake-node/hnsutil

go 1.26.5

require (
	github.com/aead/siphash v1.0.1
	github.com/blinklabs-io/handshake-node v0.0.0-00010101000000-000000000000
	github.com/blinklabs-io/handshake-node/chaincfg/chainhash v0.0.0-00010101000000-000000000000
	github.com/btcsuite/btcd/btcec/v2 v2.5.0
	github.com/davecgh/go-spew v1.1.1
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1
	github.com/kkdai/bstream v1.0.0
	golang.org/x/crypto v0.54.0
)

require (
	github.com/btcsuite/btcd/chainhash/v2 v2.0.0 // indirect
	github.com/btcsuite/btclog v0.0.0-20170628155309-84c8d2346e9f // indirect
	github.com/deatil/go-cryptobin v1.1.1013 // indirect
	github.com/decred/dcrd/crypto/blake256 v1.1.0 // indirect
	github.com/miekg/dns v1.1.72 // indirect
	golang.org/x/mod v0.31.0 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/tools v0.40.0 // indirect
)

replace (
	github.com/blinklabs-io/handshake-node => ../
	github.com/blinklabs-io/handshake-node/chaincfg/chainhash => ../chaincfg/chainhash
)
