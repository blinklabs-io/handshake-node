module github.com/blinklabs-io/handshake-node

require (
	github.com/blinklabs-io/handshake-node/chaincfg/chainhash v0.0.0-00010101000000-000000000000
	github.com/blinklabs-io/handshake-node/hnsutil v0.0.0-00010101000000-000000000000
	github.com/btcsuite/btcd/btcec/v2 v2.5.0
	github.com/btcsuite/btclog v0.0.0-20170628155309-84c8d2346e9f
	github.com/btcsuite/go-socks v0.0.0-20170105172521-4720035b7bfd
	github.com/btcsuite/websocket v0.0.0-20150119174127-31079b680792
	github.com/cloudflare/circl v1.6.4
	github.com/davecgh/go-spew v1.1.1
	github.com/deatil/go-cryptobin v1.1.1013
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1
	github.com/decred/dcrd/lru v1.0.0
	github.com/gorilla/websocket v1.5.0
	github.com/jessevdk/go-flags v1.6.1
	github.com/jrick/logrotate v1.0.0
	github.com/miekg/dns v1.1.72
	github.com/stretchr/testify v1.11.1
	github.com/syndtr/goleveldb v1.0.1-0.20210819022825-2ae1ddf74ef7
	go.uber.org/automaxprocs v1.6.0
	golang.org/x/crypto v0.54.0
	golang.org/x/sys v0.47.0
	pgregory.net/rapid v1.2.0
)

require (
	github.com/aead/siphash v1.0.1 // indirect
	github.com/btcsuite/btcd/chainhash/v2 v2.0.0 // indirect
	github.com/decred/dcrd/crypto/blake256 v1.1.0 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/kkdai/bstream v1.0.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	golang.org/x/mod v0.31.0 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/tools v0.40.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace (
	github.com/blinklabs-io/handshake-node/chaincfg/chainhash => ./chaincfg/chainhash
	github.com/blinklabs-io/handshake-node/hnsutil => ./hnsutil
)

go 1.26.5
