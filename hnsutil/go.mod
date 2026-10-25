module github.com/blinklabs-io/handshake-node/hnsutil

go 1.26.10

require (
	github.com/aead/siphash v1.0.1
	github.com/blinklabs-io/handshake-node v0.0.0-00010101000000-000000000000
	github.com/blinklabs-io/handshake-node/chaincfg/chainhash v0.0.0-00010101000000-000000000000
	github.com/btcsuite/btcd/btcec/v2 v2.5.1
	github.com/davecgh/go-spew v1.1.1
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1
	github.com/kkdai/bstream v1.0.0
	golang.org/x/crypto v0.58.0
)

require (
	github.com/btcsuite/btcd/chainhash/v2 v2.0.0 // indirect
	github.com/btcsuite/btclog v1.0.0 // indirect
	github.com/deatil/go-cryptobin v1.1.1022 // indirect
	github.com/decred/dcrd/crypto/blake256 v1.1.0 // indirect
	github.com/miekg/dns v1.1.73 // indirect
	golang.org/x/net v0.60.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
)

replace (
	github.com/blinklabs-io/handshake-node => ../
	github.com/blinklabs-io/handshake-node/chaincfg/chainhash => ../chaincfg/chainhash
)
