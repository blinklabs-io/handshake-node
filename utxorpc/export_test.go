// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package utxorpc

import (
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/blinklabs-io/handshake-node/blockchain"
	"github.com/blinklabs-io/handshake-node/chaincfg"
	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/hnsutil"
	"github.com/blinklabs-io/handshake-node/mempool"
	"github.com/blinklabs-io/handshake-node/mining"
	"github.com/blinklabs-io/handshake-node/wire"
	"github.com/stretchr/testify/require"
)

// buildBlock produces a block at the given height whose header points
// at prev. Each block carries one transaction paying a single output,
// which is enough for every conversion the services perform.
func buildBlock(t *testing.T, height int32, prev chainhash.Hash) *hnsutil.Block {
	t.Helper()

	msgBlock := &wire.MsgBlock{
		Header: wire.BlockHeader{
			Version:   1,
			PrevBlock: prev,
			Timestamp: time.Unix(1700000000+int64(height), 0),
			Bits:      0x1d00ffff,
			Nonce:     uint32(height), //nolint:gosec // test heights are small
		},
		Transactions: []*wire.MsgTx{buildTx(uint32(height))}, //nolint:gosec // test heights are small
	}

	block := hnsutil.NewBlock(msgBlock)
	block.SetHeight(height)
	return block
}

// buildTx produces a transaction whose contents vary with seed, so
// distinct seeds yield distinct hashes.
func buildTx(seed uint32) *wire.MsgTx {
	return &wire.MsgTx{
		Version: 0,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{Index: seed},
			Sequence:         0xffffffff,
			Witness:          wire.TxWitness{{0x01}},
		}},
		TxOut:    []*wire.TxOut{buildTxOut(int64(seed) * 1000)},
		LockTime: 0,
	}
}

// hashBytes returns a copy of a hash's bytes.
func hashBytes(hash chainhash.Hash) []byte {
	return hash.CloneBytes()
}

// hnsutilTx wraps a wire transaction the way the node's notification
// paths deliver it.
func hnsutilTx(tx *wire.MsgTx) *hnsutil.Tx {
	return hnsutil.NewTx(tx)
}

func buildTxOut(value int64) *wire.TxOut {
	return &wire.TxOut{
		Value:    value,
		Address:  wire.Address{Version: 0, Hash: make([]byte, 20)},
		Covenant: wire.Covenant{Type: 0},
	}
}

// fakeChain is an in-memory main chain. Blocks are indexed by height in
// the order they were appended.
type fakeChain struct {
	mtx    sync.Mutex
	blocks []*hnsutil.Block
	byHash map[chainhash.Hash]*hnsutil.Block
	best   *blockchain.BestState
	utxos  map[wire.OutPoint]*blockchain.UtxoEntry
	empty  bool
}

// cloneBlock returns an independent copy of a block. hnsutil.Block
// memoizes its hash, serialization, and transaction list on first
// access without locking, so handing the same instance to two
// goroutines races. blockchain.BlockChain avoids this by deserializing
// a fresh block from the database on every lookup, and the fake has to
// do the same to stay faithful to it.
func cloneBlock(block *hnsutil.Block) *hnsutil.Block {
	clone := hnsutil.NewBlock(block.MsgBlock().Copy())
	clone.SetHeight(block.Height())
	return clone
}

// bestStateFor describes a block the way blockchain.BestState does, as
// values captured when the block was connected rather than lazily off
// the block itself.
func bestStateFor(block *hnsutil.Block) *blockchain.BestState {
	return &blockchain.BestState{
		Hash:      *block.Hash(),
		Height:    block.Height(),
		Timestamp: block.MsgBlock().Header.Timestamp,
	}
}

func newFakeChain(t *testing.T, height int32) *fakeChain {
	t.Helper()

	c := &fakeChain{
		byHash: make(map[chainhash.Hash]*hnsutil.Block),
		utxos:  make(map[wire.OutPoint]*blockchain.UtxoEntry),
	}
	var prev chainhash.Hash
	for h := int32(0); h <= height; h++ {
		block := buildBlock(t, h, prev)
		c.append(block)
		prev = *block.Hash()
	}
	return c
}

// newEmptyChain returns a chain with no tip, as a node reports before
// its database is loaded.
func newEmptyChain() *fakeChain {
	return &fakeChain{
		byHash: make(map[chainhash.Hash]*hnsutil.Block),
		utxos:  make(map[wire.OutPoint]*blockchain.UtxoEntry),
		empty:  true,
	}
}

func (c *fakeChain) append(block *hnsutil.Block) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.blocks = append(c.blocks, block)
	c.byHash[*block.Hash()] = block
	c.best = bestStateFor(block)
}

// rollback removes the current tip, leaving the block available by
// hash the way a detached block remains in the database.
func (c *fakeChain) rollback() *hnsutil.Block {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	tip := c.blocks[len(c.blocks)-1]
	c.blocks = c.blocks[:len(c.blocks)-1]
	c.best = nil
	if len(c.blocks) > 0 {
		c.best = bestStateFor(c.blocks[len(c.blocks)-1])
	}
	return cloneBlock(tip)
}

func (c *fakeChain) tip() *hnsutil.Block {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	if len(c.blocks) == 0 {
		return nil
	}
	return cloneBlock(c.blocks[len(c.blocks)-1])
}

func (c *fakeChain) addUtxo(outpoint wire.OutPoint, txOut *wire.TxOut,
	height int32) {

	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.utxos[outpoint] = blockchain.NewUtxoEntry(txOut, height, false)
}

func (c *fakeChain) BestSnapshot() *blockchain.BestState {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	if c.best == nil || c.empty {
		return nil
	}
	best := *c.best
	return &best
}

func (c *fakeChain) BlockByHash(hash *chainhash.Hash) (*hnsutil.Block, error) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	block, ok := c.byHash[*hash]
	if !ok {
		return nil, errNotFound
	}
	return cloneBlock(block), nil
}

func (c *fakeChain) BlockByHeight(height int32) (*hnsutil.Block, error) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	if height < 0 || int(height) >= len(c.blocks) {
		return nil, errNotFound
	}
	return cloneBlock(c.blocks[height]), nil
}

func (c *fakeChain) BlockHashByHeight(height int32) (*chainhash.Hash, error) {
	block, err := c.BlockByHeight(height)
	if err != nil {
		return nil, err
	}
	return block.Hash(), nil
}

func (c *fakeChain) BlockHeightByHash(hash *chainhash.Hash) (int32, error) {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	block, ok := c.byHash[*hash]
	if !ok {
		return 0, errNotFound
	}
	// Only main chain blocks have a height.
	if int(block.Height()) >= len(c.blocks) ||
		*c.blocks[block.Height()].Hash() != *hash {

		return 0, errNotFound
	}
	return block.Height(), nil
}

func (c *fakeChain) MainChainHasBlock(hash *chainhash.Hash) bool {
	_, err := c.BlockHeightByHash(hash)
	return err == nil
}

func (c *fakeChain) FetchUtxoEntry(outpoint wire.OutPoint) (
	*blockchain.UtxoEntry, error) {

	c.mtx.Lock()
	defer c.mtx.Unlock()
	return c.utxos[outpoint], nil
}

type notFoundError struct{}

func (notFoundError) Error() string { return "not found" }

var errNotFound = notFoundError{}

// fakeMempool is an in-memory mempool keyed by transaction hash.
type fakeMempool struct {
	mtx sync.Mutex
	txs map[chainhash.Hash]*hnsutil.Tx
}

func newFakeMempool() *fakeMempool {
	return &fakeMempool{txs: make(map[chainhash.Hash]*hnsutil.Tx)}
}

func (m *fakeMempool) add(tx *hnsutil.Tx) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.txs[*tx.Hash()] = tx
}

func (m *fakeMempool) FetchTransaction(hash *chainhash.Hash) (*hnsutil.Tx, error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	tx, ok := m.txs[*hash]
	if !ok {
		return nil, errNotFound
	}
	return tx, nil
}

func (m *fakeMempool) HaveTransaction(hash *chainhash.Hash) bool {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	_, ok := m.txs[*hash]
	return ok
}

func (m *fakeMempool) TxDescs() []*mempool.TxDesc {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	descs := make([]*mempool.TxDesc, 0, len(m.txs))
	for _, tx := range m.txs {
		descs = append(descs, &mempool.TxDesc{
			TxDesc: mining.TxDesc{Tx: tx},
		})
	}
	return descs
}

// fakeSubmitter records submissions and replays a configured error.
type fakeSubmitter struct {
	mtx       sync.Mutex
	submitted []*hnsutil.Tx
	err       error
}

func (s *fakeSubmitter) SubmitTransaction(tx *hnsutil.Tx) error {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	if s.err != nil {
		return s.err
	}
	s.submitted = append(s.submitted, tx)
	return nil
}

func (s *fakeSubmitter) count() int {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	return len(s.submitted)
}

// fakeTxFetcher resolves transactions from a fixed table.
type fakeTxFetcher struct {
	txs    map[chainhash.Hash][]byte
	blocks map[chainhash.Hash]chainhash.Hash
	err    error
}

func (f *fakeTxFetcher) FetchRawTx(hash *chainhash.Hash) ([]byte,
	*chainhash.Hash, error) {

	if f.err != nil {
		return nil, nil, f.err
	}
	raw, ok := f.txs[*hash]
	if !ok {
		return nil, nil, nil
	}
	if blockHash, ok := f.blocks[*hash]; ok {
		return raw, &blockHash, nil
	}
	return raw, nil, nil
}

// testServer runs a Server on a real loopback listener so the connect
// clients in these tests exercise the same cleartext HTTP/2 path a
// locally bound node serves.
type testServer struct {
	*Server
	url       string
	transport *http.Transport
}

func newTestServer(t *testing.T, cfg *Config) *testServer {
	t.Helper()

	if cfg.ChainParams == nil {
		cfg.ChainParams = &chaincfg.MainNetParams
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	cfg.Listeners = []net.Listener{listener}

	server, err := New(cfg)
	require.NoError(t, err)
	server.Start()
	t.Cleanup(server.Stop)

	// HTTP/1.1 is disabled because there is no protocol negotiation
	// over cleartext, so leaving it on makes the transport prefer it
	// and streaming calls then block until the handler's first
	// message.
	protocols := &http.Protocols{}
	protocols.SetUnencryptedHTTP2(true)
	transport := &http.Transport{Protocols: protocols}
	// Registered after the server's cleanup so it runs first: a
	// graceful shutdown waits on connections the client still holds
	// open.
	t.Cleanup(transport.CloseIdleConnections)

	return &testServer{
		Server:    server,
		url:       "http://" + listener.Addr().String(),
		transport: transport,
	}
}

// client returns an HTTP client that speaks cleartext HTTP/2 to the
// test server.
func (s *testServer) client() *http.Client {
	return &http.Client{Transport: s.transport}
}

// publishWhenSubscribed runs publish once a streaming handler has
// registered with the broker. Opening a stream blocks until the server
// responds, so a handler that only speaks when an event arrives has to
// be fed from another goroutine.
func publishWhenSubscribed(t *testing.T, count func() int, publish func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		deadline := time.Now().Add(10 * time.Second)
		for count() == 0 {
			if time.Now().After(deadline) {
				return
			}
			time.Sleep(time.Millisecond)
		}
		publish()
	}()
	t.Cleanup(func() { <-done })
}
