module github.com/blinklabs-io/handshake-node/hnsutil/psbt

go 1.24.0

require (
	github.com/blinklabs-io/handshake-node v0.0.0-00010101000000-000000000000
	github.com/blinklabs-io/handshake-node/chaincfg/chainhash v0.0.0-00010101000000-000000000000
	github.com/blinklabs-io/handshake-node/hnsutil v0.0.0-00010101000000-000000000000
	github.com/btcsuite/btcd/btcec/v2 v2.3.5
	github.com/davecgh/go-spew v1.1.1
	github.com/stretchr/testify v1.8.4
)

require (
	github.com/btcsuite/btcd/chaincfg/chainhash v1.1.0 // indirect
	github.com/btcsuite/btclog v1.0.0 // indirect
	github.com/decred/dcrd/crypto/blake256 v1.0.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/crypto v0.45.0 // indirect
	golang.org/x/sys v0.38.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace (
	github.com/blinklabs-io/handshake-node => ../../
	github.com/blinklabs-io/handshake-node/chaincfg/chainhash => ../../chaincfg/chainhash
	github.com/blinklabs-io/handshake-node/hnsutil => ../
)
