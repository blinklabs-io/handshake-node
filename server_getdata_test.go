// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"math"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blinklabs-io/handshake-node/blockchain"
	"github.com/blinklabs-io/handshake-node/chaincfg"
	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/database"
	_ "github.com/blinklabs-io/handshake-node/database/ffldb"
	"github.com/blinklabs-io/handshake-node/hnsutil"
	"github.com/blinklabs-io/handshake-node/netsync"
	"github.com/blinklabs-io/handshake-node/peer"
	"github.com/blinklabs-io/handshake-node/txscript"
	"github.com/blinklabs-io/handshake-node/wire"
	"github.com/btcsuite/btclog"
)

type serverMockTimeSource struct {
	adjustedTime time.Time
}

func (m *serverMockTimeSource) AdjustedTime() time.Time {
	return m.adjustedTime
}

func (*serverMockTimeSource) AddTimeSample(string, time.Time) {}
func (*serverMockTimeSource) Offset() time.Duration           { return 0 }

func newGetDataTestServer(t *testing.T) (*server, *serverPeer, func()) {
	t.Helper()

	blockchain.DisableLog()
	database.UseLogger(btclog.Disabled)
	netsync.DisableLog()
	peerLog = btclog.Disabled

	params := chaincfg.RegressionNetParams
	params.Checkpoints = nil

	dbPath := filepath.Join(t.TempDir(), "ffldb")
	db, err := database.Create("ffldb", dbPath, params.Net)
	if err != nil {
		t.Fatalf("database.Create: %v", err)
	}

	chain, err := blockchain.New(&blockchain.Config{
		DB:          db,
		ChainParams: &params,
		TimeSource: &serverMockTimeSource{
			adjustedTime: params.GenesisBlock.Header.Timestamp.
				Add(time.Hour),
		},
	})
	if err != nil {
		db.Close()
		t.Fatalf("blockchain.New: %v", err)
	}

	s := &server{
		db:    db,
		chain: chain,
	}
	sp := newServerPeer(s, false)
	sp.Peer = peer.NewInboundPeer(&peer.Config{})

	return s, sp, func() {
		db.Close()
	}
}

func requireDoneSignal(t *testing.T, done <-chan struct{}) {
	t.Helper()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("done channel was not signaled")
	}
}

func createServerTestCoinbase(t *testing.T, height int32,
	params *chaincfg.Params) *wire.MsgTx {

	t.Helper()

	tx := wire.NewMsgTx(wire.TxVersion)
	tx.LockTime = uint32(height)

	heightScript, err := txscript.NewScriptBuilder().
		AddInt64(int64(height)).
		AddOp(txscript.OP_0).
		Script()
	if err != nil {
		t.Fatalf("coinbase script: %v", err)
	}

	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  chainhash.Hash{},
			Index: wire.MaxPrevOutIndex,
		},
		Sequence: wire.MaxTxInSequenceNum,
		Witness:  wire.TxWitness{heightScript},
	})

	tx.AddTxOut(&wire.TxOut{
		Value:   blockchain.CalcBlockSubsidy(height, params),
		Address: wire.Address{Version: 0, Hash: make([]byte, 20)},
	})

	return tx
}

func solveServerTestBlock(header *wire.BlockHeader,
	params *chaincfg.Params) bool {

	target := blockchain.CompactToBig(params.PowLimitBits)
	for nonce := uint32(0); nonce < math.MaxUint32; nonce++ {
		header.Nonce = nonce
		hash := header.BlockHash()
		if blockchain.HashToBig(&hash).Cmp(target) <= 0 {
			return true
		}
	}

	return false
}

func addServerTestBlock(t *testing.T, chain *blockchain.BlockChain,
	params *chaincfg.Params) *hnsutil.Block {

	t.Helper()

	cb := createServerTestCoinbase(t, 1, params)
	txs := []*hnsutil.Tx{hnsutil.NewTx(cb)}
	header := wire.BlockHeader{
		Version:     2,
		PrevBlock:   *params.GenesisHash,
		MerkleRoot:  blockchain.CalcMerkleRoot(txs, false),
		WitnessRoot: blockchain.CalcMerkleRoot(txs, true),
		Timestamp:   params.GenesisBlock.Header.Timestamp.Add(time.Minute),
		Bits:        params.PowLimitBits,
	}
	if !solveServerTestBlock(&header, params) {
		t.Fatal("failed to solve test block")
	}

	block := hnsutil.NewBlock(&wire.MsgBlock{
		Header:       header,
		Transactions: []*wire.MsgTx{cb},
	})

	isMainChain, isOrphan, err := chain.ProcessBlock(block, blockchain.BFNone)
	if err != nil {
		t.Fatalf("ProcessBlock: %v", err)
	}
	if !isMainChain || isOrphan {
		t.Fatalf("ProcessBlock returned isMainChain=%v isOrphan=%v",
			isMainChain, isOrphan)
	}

	return block
}

func connectServerTestPeer(t *testing.T, sp *serverPeer) (net.Conn, func()) {
	t.Helper()
	return connectServerTestPeerWithWriteGate(t, sp, nil, 0)
}

type serverTestWriteGate struct {
	blocked   atomic.Bool
	closed    chan struct{}
	closeOnce sync.Once
}

func newServerTestWriteGate() *serverTestWriteGate {
	return &serverTestWriteGate{closed: make(chan struct{})}
}

type serverTestWriteGateConn struct {
	net.Conn
	gate *serverTestWriteGate
}

func (c *serverTestWriteGateConn) Write(data []byte) (int, error) {
	if c.gate.blocked.Load() {
		<-c.gate.closed
		return 0, net.ErrClosed
	}
	return c.Conn.Write(data)
}

func (c *serverTestWriteGateConn) Close() error {
	c.gate.closeOnce.Do(func() { close(c.gate.closed) })
	return c.Conn.Close()
}

func connectServerTestPeerWithWriteGate(t *testing.T, sp *serverPeer,
	gate *serverTestWriteGate, maxOutboundQueueBytes uint64) (net.Conn, func()) {

	t.Helper()

	verack := make(chan struct{}, 1)
	sp.Peer = peer.NewInboundPeer(&peer.Config{
		ChainParams:           &chaincfg.RegressionNetParams,
		AllowSelfConns:        true,
		MaxOutboundQueueBytes: maxOutboundQueueBytes,
		Listeners: peer.MessageListeners{
			OnVerAck: func(*peer.Peer, *wire.HnsMsgVerack) {
				verack <- struct{}{}
			},
			OnGetHeaders: sp.OnGetHeaders,
		},
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer listener.Close()

	accepted := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			accepted <- err
			return
		}
		if gate != nil {
			conn = &serverTestWriteGateConn{Conn: conn, gate: gate}
		}
		sp.Peer.AssociateConnection(conn)
		accepted <- nil
	}()

	remote, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("net.Dial: %v", err)
	}
	select {
	case err := <-accepted:
		if err != nil {
			remote.Close()
			t.Fatalf("listener.Accept: %v", err)
		}
	case <-time.After(time.Second):
		remote.Close()
		t.Fatal("timed out waiting for inbound peer connection")
	}

	remoteNA := wire.NewNetAddressIPPort(net.ParseIP("127.0.0.1"), 0,
		wire.SFNodeNetwork)
	remoteVersion := &wire.HnsMsgVersion{
		Version:  peer.MaxProtocolVersion,
		Services: uint64(wire.SFNodeNetwork),
		Time:     uint64(time.Now().Unix()),
		Remote:   wire.NewHnsNetAddress(remoteNA),
		Agent:    wire.DefaultUserAgent,
	}
	remoteVersion.SetNonce(1)

	if _, err := wire.WriteHnsMessageN(remote, remoteVersion,
		chaincfg.RegressionNetParams.Net); err != nil {
		remote.Close()
		t.Fatalf("write remote version: %v", err)
	}

	if _, ok := readServerTestPeerMessage(t, remote).(*wire.HnsMsgVersion); !ok {
		remote.Close()
		t.Fatal("expected local version during peer negotiation")
	}
	if _, ok := readServerTestPeerMessage(t, remote).(*wire.HnsMsgVerack); !ok {
		remote.Close()
		t.Fatal("expected local verack during peer negotiation")
	}
	if _, err := wire.WriteHnsMessageN(remote, &wire.HnsMsgVerack{},
		chaincfg.RegressionNetParams.Net); err != nil {
		remote.Close()
		t.Fatalf("write remote verack: %v", err)
	}

	select {
	case <-verack:
	case <-time.After(time.Second):
		remote.Close()
		t.Fatal("timed out waiting for peer negotiation")
	}

	cleanup := func() {
		sp.Disconnect()
		remote.Close()
	}

	return remote, cleanup
}

func readServerTestPeerMessage(t *testing.T,
	remote net.Conn) wire.HandshakeMessage {

	t.Helper()

	if err := remote.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	_, msg, _, err := wire.ReadHandshakeMessageN(remote,
		chaincfg.RegressionNetParams.Net)
	if err != nil {
		t.Fatalf("ReadHandshakeMessageN: %v", err)
	}

	return msg
}

func TestPushTxMsgNoMempool(t *testing.T) {
	s := &server{}
	sp := &serverPeer{}
	done := make(chan struct{}, 1)

	err := s.pushTxMsg(sp, &chainhash.Hash{}, done, wire.BaseEncoding)
	if err == nil {
		t.Fatal("pushTxMsg returned nil error with no mempool")
	}

	requireDoneSignal(t, done)
}

func TestBlockResponseWorkspaceRejectsBeforeDatabaseFetch(t *testing.T) {
	const budgetBytes = 128 * 1024 * 1024
	budget := peer.NewOutboundQueueBudget(budgetBytes)
	held, ok := budget.AcquireWorkspace(63 * 1024 * 1024)
	if !ok {
		t.Fatal("failed to reserve test workspace")
	}

	s := &server{outboundQueueBudget: budget}
	sp := newServerPeer(s, false)
	sp.Peer = peer.NewInboundPeer(&peer.Config{
		ChainParams: &chaincfg.RegressionNetParams,
	})
	done := make(chan struct{}, 1)
	if err := s.pushBlockMsg(
		sp, chaincfg.RegressionNetParams.GenesisHash, done,
		wire.BaseEncoding,
	); err != nil {
		t.Fatalf("pushBlockMsg workspace rejection: %v", err)
	}
	requireDoneSignal(t, done)

	held.Release()
	workspace, ok := budget.AcquireWorkspace(blockResponseWorkspaceBytes)
	if !ok {
		t.Fatal("response workspace was not released after rejection")
	}
	workspace.Release()
}

func TestOnGetBlocksServesLocatedBlockInventory(t *testing.T) {
	_, sp, teardown := newGetDataTestServer(t)
	defer teardown()

	block := addServerTestBlock(t, sp.server.chain, &chaincfg.RegressionNetParams)

	remote, cleanup := connectServerTestPeer(t, sp)
	defer cleanup()

	msg := &wire.HnsMsgGetBlocks{}
	if err := msg.AddBlockLocatorHash(chaincfg.RegressionNetParams.GenesisHash); err != nil {
		t.Fatalf("AddBlockLocatorHash: %v", err)
	}

	sp.OnGetBlocks(sp.Peer, msg)

	inv, ok := readServerTestPeerMessage(t, remote).(*wire.HnsMsgInv)
	if !ok {
		t.Fatal("expected inv response")
	}
	if len(inv.Inventory) != 1 {
		t.Fatalf("inventory length = %d, want 1", len(inv.Inventory))
	}
	invVect := inv.Inventory[0].InvVect()
	if invVect.Type != wire.InvTypeBlock {
		t.Fatalf("inventory type = %v, want %v", invVect.Type,
			wire.InvTypeBlock)
	}
	if !invVect.Hash.IsEqual(block.Hash()) {
		t.Fatalf("inventory hash = %v, want %v", invVect.Hash,
			block.Hash())
	}
}

func TestOnGetHeadersServesLocatedHeadersWhenCurrent(t *testing.T) {
	_, sp, teardown := newGetDataTestServer(t)
	defer teardown()

	block := addServerTestBlock(t, sp.server.chain, &chaincfg.RegressionNetParams)

	syncManager, err := netsync.New(&netsync.Config{
		PeerNotifier:       sp.server,
		Chain:              sp.server.chain,
		ChainParams:        &chaincfg.RegressionNetParams,
		DisableCheckpoints: true,
		MaxPeers:           1,
	})
	if err != nil {
		t.Fatalf("netsync.New: %v", err)
	}
	sp.server.syncManager = syncManager
	syncManager.Start()
	defer syncManager.Stop()

	remote, cleanup := connectServerTestPeer(t, sp)
	defer cleanup()

	msg := &wire.HnsMsgGetHeaders{}
	if err := msg.AddBlockLocatorHash(chaincfg.RegressionNetParams.GenesisHash); err != nil {
		t.Fatalf("AddBlockLocatorHash: %v", err)
	}

	sp.OnGetHeaders(sp.Peer, msg)

	headers, ok := readServerTestPeerMessage(t, remote).(*wire.HnsMsgHeaders)
	if !ok {
		t.Fatal("expected headers response")
	}
	if len(headers.Headers) != 1 {
		t.Fatalf("headers length = %d, want 1", len(headers.Headers))
	}
	gotHash := headers.Headers[0].BlockHash()
	if !gotHash.IsEqual(block.Hash()) {
		t.Fatalf("header hash = %v, want %v", gotHash, block.Hash())
	}
}

func TestGetHeadersFloodDisconnectsNonReadingPeer(t *testing.T) {
	_, sp, teardown := newGetDataTestServer(t)
	defer teardown()

	addServerTestBlock(t, sp.server.chain, &chaincfg.RegressionNetParams)

	syncManager, err := netsync.New(&netsync.Config{
		PeerNotifier:       sp.server,
		Chain:              sp.server.chain,
		ChainParams:        &chaincfg.RegressionNetParams,
		DisableCheckpoints: true,
		MaxPeers:           1,
	})
	if err != nil {
		t.Fatalf("netsync.New: %v", err)
	}
	sp.server.syncManager = syncManager
	syncManager.Start()
	defer func() {
		if err := syncManager.Stop(); err != nil {
			t.Errorf("syncManager.Stop: %v", err)
		}
	}()

	// Block writes in-process after negotiation so the real peer and server
	// handlers exercise deterministic backpressure without kernel buffering.
	writeGate := newServerTestWriteGate()
	remote, cleanup := connectServerTestPeerWithWriteGate(
		t, sp, writeGate, 16*1024,
	)
	defer cleanup()
	writeGate.blocked.Store(true)
	if err := remote.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}

	msg := &wire.HnsMsgGetHeaders{}
	if err := msg.AddBlockLocatorHash(chaincfg.RegressionNetParams.GenesisHash); err != nil {
		t.Fatalf("AddBlockLocatorHash: %v", err)
	}
	for i := 0; i < 512 && sp.Connected(); i++ {
		if _, err := wire.WriteHnsMessageN(remote, msg,
			chaincfg.RegressionNetParams.Net); err != nil {

			break
		}
	}

	disconnected := make(chan struct{})
	go func() {
		sp.WaitForDisconnect()
		close(disconnected)
	}()
	select {
	case <-disconnected:
	case <-time.After(2 * time.Second):
		t.Fatal("non-reading getheaders peer was not disconnected")
	}
}

func TestOnGetDataSendsNotFoundForMissingInventory(t *testing.T) {
	oldCfg := cfg
	cfg = &config{DisableBanning: true}
	defer func() {
		cfg = oldCfg
	}()

	_, sp, teardown := newGetDataTestServer(t)
	defer teardown()

	remote, cleanup := connectServerTestPeer(t, sp)
	defer cleanup()

	missingHash := chainhash.Hash{0x0f, 0x05}
	msg := wire.NewHnsMsgGetData()
	if err := msg.AddInvVect(wire.NewInvVect(
		wire.InvTypeBlock, &missingHash,
	)); err != nil {

		t.Fatalf("AddInvVect: %v", err)
	}

	done := make(chan struct{})
	go func() {
		sp.OnGetData(sp.Peer, msg)
		close(done)
	}()

	notFound, ok := readServerTestPeerMessage(t, remote).(*wire.HnsMsgNotFound)
	if !ok {
		t.Fatal("expected notfound response")
	}
	invVects := notFound.InvVects()
	if len(invVects) != 1 {
		t.Fatalf("notfound inventory length = %d, want 1", len(invVects))
	}
	if invVects[0].Type != wire.InvTypeBlock {
		t.Fatalf("notfound type = %v, want %v", invVects[0].Type,
			wire.InvTypeBlock)
	}
	if !invVects[0].Hash.IsEqual(&missingHash) {
		t.Fatalf("notfound hash = %v, want %v", invVects[0].Hash,
			missingHash)
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("OnGetData did not finish after sending notfound")
	}
}

func TestPushInventoryServesKnownBlock(t *testing.T) {
	_, sp, teardown := newGetDataTestServer(t)
	defer teardown()

	done := make(chan struct{}, 1)
	iv := wire.NewInvVect(wire.InvTypeBlock,
		chaincfg.RegressionNetParams.GenesisHash)

	if err := sp.server.pushInventory(sp, iv, done); err != nil {
		t.Fatalf("pushInventory known block: %v", err)
	}

	requireDoneSignal(t, done)
}

func TestPushInventoryMissingBlockSignalsDone(t *testing.T) {
	_, sp, teardown := newGetDataTestServer(t)
	defer teardown()

	missingHash := chainhash.Hash{0x01, 0x02, 0x03}
	done := make(chan struct{}, 1)
	iv := wire.NewInvVect(wire.InvTypeBlock, &missingHash)

	if err := sp.server.pushInventory(sp, iv, done); err == nil {
		t.Fatal("pushInventory missing block returned nil error")
	}

	requireDoneSignal(t, done)
}

func TestPushInventoryUnknownTypeSignalsDone(t *testing.T) {
	_, sp, teardown := newGetDataTestServer(t)
	defer teardown()

	done := make(chan struct{}, 1)
	iv := wire.NewInvVect(wire.InvType(0xffffffff), &chainhash.Hash{})

	if err := sp.server.pushInventory(sp, iv, done); err == nil {
		t.Fatal("pushInventory unknown type returned nil error")
	}

	requireDoneSignal(t, done)
}
