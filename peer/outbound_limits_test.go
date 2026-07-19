// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package peer

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blinklabs-io/handshake-node/blockchain"
	"github.com/blinklabs-io/handshake-node/chaincfg"
	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/wire"
)

type outboundLimitTestAddr string

func (a outboundLimitTestAddr) Network() string { return "tcp" }
func (a outboundLimitTestAddr) String() string  { return string(a) }

type customOnWriteMessage struct {
	payload []byte
}

func (*customOnWriteMessage) Type() wire.HnsMsgType {
	return wire.HnsMsgType(250)
}

func (m *customOnWriteMessage) Encode() []byte {
	return append([]byte(nil), m.payload...)
}

func (m *customOnWriteMessage) Decode(payload []byte) error {
	m.payload = append(m.payload[:0], payload...)
	return nil
}

type blockingWriteConn struct {
	started   chan struct{}
	closed    chan struct{}
	startOnce sync.Once
	closeOnce sync.Once
}

func newBlockingWriteConn() *blockingWriteConn {
	return &blockingWriteConn{
		started: make(chan struct{}),
		closed:  make(chan struct{}),
	}
}

func (c *blockingWriteConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, io.EOF
}

func (c *blockingWriteConn) Write([]byte) (int, error) {
	c.startOnce.Do(func() { close(c.started) })
	<-c.closed
	return 0, net.ErrClosed
}

func (c *blockingWriteConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (*blockingWriteConn) LocalAddr() net.Addr {
	return outboundLimitTestAddr("127.0.0.1:12038")
}

func (*blockingWriteConn) RemoteAddr() net.Addr {
	return outboundLimitTestAddr("192.0.2.1:12038")
}

func (*blockingWriteConn) SetDeadline(time.Time) error      { return nil }
func (*blockingWriteConn) SetReadDeadline(time.Time) error  { return nil }
func (*blockingWriteConn) SetWriteDeadline(time.Time) error { return nil }

type partialWriteConn struct {
	mu          sync.Mutex
	maxChunk    int
	writes      int
	written     []byte
	deadlines   []time.Time
	deadlineErr error
	closed      chan struct{}
	closeOnce   sync.Once
}

func newPartialWriteConn(maxChunk int) *partialWriteConn {
	return &partialWriteConn{
		maxChunk: maxChunk,
		closed:   make(chan struct{}),
	}
}

func (c *partialWriteConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, io.EOF
}

func (c *partialWriteConn) Write(data []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes++
	written := len(data)
	if written > c.maxChunk {
		written = c.maxChunk
	}
	c.written = append(c.written, data[:written]...)
	return written, nil
}

func (c *partialWriteConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (*partialWriteConn) LocalAddr() net.Addr {
	return outboundLimitTestAddr("127.0.0.1:12038")
}

func (*partialWriteConn) RemoteAddr() net.Addr {
	return outboundLimitTestAddr("192.0.2.1:12038")
}

func (*partialWriteConn) SetDeadline(time.Time) error     { return nil }
func (*partialWriteConn) SetReadDeadline(time.Time) error { return nil }
func (c *partialWriteConn) SetWriteDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.deadlines = append(c.deadlines, deadline)
	err := c.deadlineErr
	c.mu.Unlock()
	if !deadline.IsZero() {
		return err
	}
	return nil
}

func startOutboundLimitTestPeer(conn net.Conn, writeTimeout time.Duration,
	budget *OutboundQueueBudget) *Peer {
	return startOutboundLimitTestPeerWithConfig(conn, Config{
		WriteTimeout:        writeTimeout,
		OutboundQueueBudget: budget,
	})
}

func startOutboundLimitTestPeerWithConfig(conn net.Conn, cfg Config) *Peer {
	cfg.ChainParams = &chaincfg.RegressionNetParams

	p := newPeerBase(&cfg, true)
	p.conn = conn
	p.addr = conn.RemoteAddr().String()
	atomic.StoreInt32(&p.connected, 1)
	go p.queueHandler()
	go p.outHandler()
	return p
}

func outboundLimitTestMessageBytes(t *testing.T,
	msg wire.HandshakeMessage) uint64 {

	t.Helper()
	encoded, err := wire.EncodeHnsMessage(
		msg, uint32(chaincfg.RegressionNetParams.Net),
	)
	if err != nil {
		t.Fatalf("EncodeHnsMessage: %v", err)
	}
	return uint64(len(encoded)) + outboundMessageOverhead
}

func waitForOutboundQueueState(t *testing.T, p *Peer, messages,
	inventory int, bytes uint64) {

	t.Helper()
	deadline := time.After(time.Second)
	for {
		p.queueMtx.Lock()
		gotMessages := p.queuedMessages
		gotInventory := p.queuedInventory
		gotBytes := p.queuedBytes
		p.queueMtx.Unlock()
		if gotMessages == messages && gotInventory == inventory &&
			gotBytes == bytes {

			return
		}
		select {
		case <-deadline:
			t.Fatalf("outbound queue = %d messages, %d inventory, %d bytes; want %d, %d, %d",
				gotMessages, gotInventory, gotBytes, messages, inventory, bytes)
		case <-time.After(time.Millisecond):
		}
	}
}

func waitForOutboundLimitTestPeer(t *testing.T, p *Peer) {
	t.Helper()
	select {
	case <-p.quit:
	case <-time.After(time.Second):
		t.Fatal("peer did not disconnect")
	}
	select {
	case <-p.outQuit:
	case <-time.After(time.Second):
		t.Fatal("peer output handler did not stop")
	}

	p.queueMtx.Lock()
	defer p.queueMtx.Unlock()
	if p.queuedMessages != 0 || p.queuedInventory != 0 ||
		p.queuedBytes != 0 || p.queuedControlMsgs != 0 ||
		p.queuedControlBytes != 0 {

		t.Fatalf("outbound accounting after shutdown = %d messages, %d inventory, %d bytes, %d control messages, %d control bytes",
			p.queuedMessages, p.queuedInventory, p.queuedBytes,
			p.queuedControlMsgs, p.queuedControlBytes)
	}
}

func TestSlowPeerOutboundQueueLimits(t *testing.T) {
	conn := newBlockingWriteConn()
	const maxMessages = 128
	p := startOutboundLimitTestPeerWithConfig(conn, Config{
		WriteTimeout:             time.Hour,
		MaxOutboundQueueMessages: maxMessages,
	})
	p.QueueMessage(wire.NewHnsMsgPing(0), nil)
	select {
	case <-conn.started:
	case <-time.After(time.Second):
		t.Fatal("initial write did not start")
	}

	for i := 1; i <= maxMessages; i++ {
		p.QueueMessage(wire.NewHnsMsgPing(uint64(i)), nil)
	}
	waitForOutboundLimitTestPeer(t, p)
}

func TestSlowPeerWriteDeadline(t *testing.T) {
	local, remote := net.Pipe()
	t.Cleanup(func() { _ = remote.Close() })
	p := startOutboundLimitTestPeer(local, 25*time.Millisecond, nil)
	p.QueueMessage(wire.NewHnsMsgPing(1), nil)
	waitForOutboundLimitTestPeer(t, p)
}

func TestOutboundQueueExactSerializedByteBoundary(t *testing.T) {
	conn := newBlockingWriteConn()
	p := newPeerBase(&Config{
		ChainParams:  &chaincfg.RegressionNetParams,
		WriteTimeout: time.Hour,
	}, true)
	p.maxQueuedMessages = 10
	pingBytes := outboundLimitTestMessageBytes(t, wire.NewHnsMsgPing(1))
	p.maxQueuedBytes = 2 * pingBytes
	p.conn = conn
	p.addr = conn.RemoteAddr().String()
	atomic.StoreInt32(&p.connected, 1)
	go p.queueHandler()
	go p.outHandler()

	p.QueueMessage(wire.NewHnsMsgPing(1), nil)
	select {
	case <-conn.started:
	case <-time.After(time.Second):
		t.Fatal("initial write did not start")
	}
	p.QueueMessage(wire.NewHnsMsgPing(2), nil)
	waitForOutboundQueueState(t, p, 2, 0, p.maxQueuedBytes)
	if !p.Connected() {
		t.Fatal("peer disconnected at the exact serialized byte boundary")
	}
	p.QueueMessage(&wire.HnsMsgVerack{}, nil)
	waitForOutboundLimitTestPeer(t, p)
}

func TestHeadersResponseExactQueueBoundary(t *testing.T) {
	conn := newBlockingWriteConn()
	headers := &wire.HnsMsgHeaders{Headers: []*wire.BlockHeader{{}}}
	headerBytes := outboundLimitTestMessageBytes(t, headers)
	p := startOutboundLimitTestPeerWithConfig(conn, Config{
		WriteTimeout:          time.Hour,
		MaxOutboundQueueBytes: 4 * headerBytes,
	})
	p.QueueMessage(headers, nil)
	select {
	case <-conn.started:
	case <-time.After(time.Second):
		t.Fatal("initial headers write did not start")
	}
	p.QueueMessage(headers, nil)
	waitForOutboundQueueState(t, p, 2, 0, 2*headerBytes)
	if !p.Connected() {
		t.Fatal("peer disconnected at exact headers queue boundary")
	}
	if err := p.TryQueueMessage(&wire.HnsMsgVerack{}, nil); err != nil {
		t.Fatalf("queue control message at exact data boundary: %v", err)
	}
	p.Disconnect()
	waitForOutboundLimitTestPeer(t, p)
}

func TestValidSmallResponseBatchesRemainQueued(t *testing.T) {
	conn := newBlockingWriteConn()
	p := startOutboundLimitTestPeer(conn, time.Hour, nil)
	p.QueueMessage(wire.NewHnsMsgPing(0), nil)
	select {
	case <-conn.started:
	case <-time.After(time.Second):
		t.Fatal("initial write did not start")
	}

	p.QueueMessage(&wire.HnsMsgMerkleBlock{}, nil)
	for i := 0; i < 8; i++ {
		p.QueueMessage(&wire.HnsMsgTx{}, nil)
	}
	for i := 0; i < 100; i++ {
		p.QueueMessage(&wire.HnsMsgProof{Proof: make([]byte, 64)}, nil)
	}
	wantBytes := outboundLimitTestMessageBytes(t, wire.NewHnsMsgPing(0)) +
		outboundLimitTestMessageBytes(t, &wire.HnsMsgMerkleBlock{}) +
		8*outboundLimitTestMessageBytes(t, &wire.HnsMsgTx{}) +
		100*outboundLimitTestMessageBytes(t,
			&wire.HnsMsgProof{Proof: make([]byte, 64)})
	waitForOutboundQueueState(t, p, 110, 0, wantBytes)
	if !p.Connected() {
		t.Fatal("valid small filtered-block and proof batches disconnected peer")
	}
	p.Disconnect()
	waitForOutboundLimitTestPeer(t, p)
}

func TestSharedOutboundQueueBudget(t *testing.T) {
	pingBytes := outboundLimitTestMessageBytes(t, wire.NewHnsMsgPing(0))
	pingPreparationBytes := uint64(wire.HnsMessageHeaderSize+8)*
		outboundSerializationMemoryFactor + outboundMessageOverhead
	budgetBytes := 2*pingBytes + pingPreparationBytes
	budget := NewOutboundQueueBudget(budgetBytes)
	firstConn := newBlockingWriteConn()
	first := startOutboundLimitTestPeer(firstConn, time.Hour, budget)
	first.QueueMessage(wire.NewHnsMsgPing(1), nil)
	select {
	case <-firstConn.started:
	case <-time.After(time.Second):
		t.Fatal("first peer write did not start")
	}
	first.QueueMessage(wire.NewHnsMsgPing(2), nil)

	secondConn := newBlockingWriteConn()
	second := startOutboundLimitTestPeer(secondConn, time.Hour, budget)
	second.QueueMessage(wire.NewHnsMsgPing(3), nil)
	select {
	case <-secondConn.started:
	case <-time.After(time.Second):
		t.Fatal("second peer write did not start")
	}
	dropped := make(chan struct{}, 1)
	err := second.TryQueueMessage(wire.NewHnsMsgPing(4), dropped)
	if !errors.Is(err, ErrOutboundQueueBudget) {
		t.Fatalf("aggregate-budget enqueue error = %v, want %v",
			err, ErrOutboundQueueBudget)
	}
	select {
	case <-dropped:
	case <-time.After(time.Second):
		t.Fatal("aggregate-budget rejection did not notify sender")
	}
	if !second.Connected() {
		t.Fatal("aggregate exhaustion disconnected an unrelated peer")
	}
	waitForOutboundQueueState(t, second, 1, 0,
		outboundLimitTestMessageBytes(t, wire.NewHnsMsgPing(3)))

	second.Disconnect()
	waitForOutboundLimitTestPeer(t, second)
	first.Disconnect()
	waitForOutboundLimitTestPeer(t, first)
	budget.mu.Lock()
	used := budget.usedBytes
	budget.mu.Unlock()
	if used != 0 {
		t.Fatalf("shared outbound budget after shutdown = %d, want 0", used)
	}
}

func TestSaturatedPeerDoesNotBlockOtherPeerPreparation(t *testing.T) {
	budget := NewOutboundQueueBudget(64 * 1024 * 1024)
	newUnstartedPeer := func(address string) *Peer {
		conn := newBlockingWriteConn()
		p := newPeerBase(&Config{
			ChainParams:         &chaincfg.RegressionNetParams,
			WriteTimeout:        time.Hour,
			OutboundQueueBudget: budget,
		}, true)
		p.conn = conn
		p.addr = address
		atomic.StoreInt32(&p.connected, 1)
		return p
	}
	drainPeer := func(p *Peer) {
		p.Disconnect()
		p.queueEnqueueWg.Wait()
		for {
			select {
			case msg := <-p.outputQueue:
				p.releaseOutboundMessage(msg)
			default:
				return
			}
		}
	}

	first := newUnstartedPeer("192.0.2.1:12038")
	second := newUnstartedPeer("192.0.2.2:12038")
	t.Cleanup(func() {
		drainPeer(first)
		drainPeer(second)
	})

	for i := 0; i < cap(first.outputQueue); i++ {
		if err := first.TryQueueMessage(
			&wire.HnsMsgHeaders{}, nil,
		); err != nil {
			t.Fatalf("fill first peer output channel: %v", err)
		}
	}
	blockedResult := make(chan error, 1)
	go func() {
		blockedResult <- first.TryQueueMessage(&wire.HnsMsgHeaders{}, nil)
	}()
	waitForOutboundQueueState(
		t, first, cap(first.outputQueue)+1, 0,
		uint64(cap(first.outputQueue)+1)*outboundLimitTestMessageBytes(
			t, &wire.HnsMsgHeaders{},
		),
	)

	secondResult := make(chan error, 1)
	go func() {
		secondResult <- second.TryQueueMessage(wire.NewHnsMsgPing(1), nil)
	}()
	select {
	case err := <-secondResult:
		if err != nil {
			t.Fatalf("second peer enqueue: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("saturated peer blocked another peer's message preparation")
	}

	first.Disconnect()
	select {
	case err := <-blockedResult:
		if !errors.Is(err, ErrPeerDisconnected) {
			t.Fatalf("blocked enqueue error = %v, want %v",
				err, ErrPeerDisconnected)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked enqueue did not stop after disconnect")
	}
}

func TestRejectedLocatorRequestDoesNotPoisonDuplicateFilter(t *testing.T) {
	tests := []struct {
		name   string
		push   func(*Peer, blockchain.BlockLocator, *chainhash.Hash) error
		cached func(*Peer) bool
	}{
		{
			name: "getblocks",
			push: (*Peer).PushGetBlocksMsg,
			cached: func(p *Peer) bool {
				return p.prevGetBlocksBegin != nil || p.prevGetBlocksStop != nil
			},
		},
		{
			name: "getheaders",
			push: (*Peer).PushGetHeadersMsg,
			cached: func(p *Peer) bool {
				return p.prevGetHdrsBegin != nil || p.prevGetHdrsStop != nil
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conn := newBlockingWriteConn()
			p := newPeerBase(&Config{
				ChainParams:              &chaincfg.RegressionNetParams,
				MaxOutboundQueueMessages: 1,
			}, true)
			p.conn = conn
			p.addr = conn.RemoteAddr().String()
			atomic.StoreInt32(&p.connected, 1)
			if err := p.TryQueueMessage(wire.NewHnsMsgPing(1), nil); err != nil {
				t.Fatalf("fill peer queue: %v", err)
			}

			stop := *chaincfg.RegressionNetParams.GenesisHash
			locator := blockchain.BlockLocator{
				chaincfg.RegressionNetParams.GenesisHash,
			}
			err := test.push(p, locator, &stop)
			if !errors.Is(err, ErrOutboundQueueLimit) {
				t.Fatalf("request error = %v, want %v",
					err, ErrOutboundQueueLimit)
			}
			if test.cached(p) {
				t.Fatal("rejected request poisoned duplicate filter")
			}
			for {
				select {
				case msg := <-p.outputQueue:
					p.releaseOutboundMessage(msg)
				default:
					return
				}
			}
		})
	}
}

func TestOutboundInventoryQueueBound(t *testing.T) {
	conn := newBlockingWriteConn()
	p := newPeerBase(&Config{
		ChainParams:     &chaincfg.RegressionNetParams,
		TrickleInterval: time.Hour,
		WriteTimeout:    time.Hour,
	}, true)
	p.maxQueuedInventory = 3
	p.conn = conn
	p.addr = conn.RemoteAddr().String()
	p.flagsMtx.Lock()
	p.versionKnown = true
	p.flagsMtx.Unlock()
	atomic.StoreInt32(&p.connected, 1)
	go p.queueHandler()
	go p.outHandler()

	for i := byte(0); i < 3; i++ {
		hash := chaincfg.RegressionNetParams.GenesisHash
		copyHash := *hash
		copyHash[0] = i
		p.QueueInventory(wire.NewInvVect(wire.InvTypeTx, &copyHash))
	}
	waitForOutboundQueueState(t, p, 0, 3,
		3*(wire.HnsInvItemSize+outboundInventoryOverhead))
	hash := *chaincfg.RegressionNetParams.GenesisHash
	hash[0] = 4
	p.QueueInventory(wire.NewInvVect(wire.InvTypeTx, &hash))
	if !p.Connected() {
		t.Fatal("bounded optional inventory overflow disconnected peer")
	}
	waitForOutboundQueueState(t, p, 0, 3,
		3*(wire.HnsInvItemSize+outboundInventoryOverhead))
	p.Disconnect()
	waitForOutboundLimitTestPeer(t, p)
}

func TestOutboundInventoryDeduplicatesPendingAnnouncements(t *testing.T) {
	conn := newBlockingWriteConn()
	p := newPeerBase(&Config{
		ChainParams:     &chaincfg.RegressionNetParams,
		TrickleInterval: time.Hour,
		WriteTimeout:    time.Hour,
	}, true)
	p.conn = conn
	p.addr = conn.RemoteAddr().String()
	p.flagsMtx.Lock()
	p.versionKnown = true
	p.flagsMtx.Unlock()
	atomic.StoreInt32(&p.connected, 1)
	go p.queueHandler()
	go p.outHandler()

	inv := wire.NewInvVect(
		wire.InvTypeTx, chaincfg.RegressionNetParams.GenesisHash,
	)
	for i := 0; i < 100; i++ {
		p.QueueInventory(inv)
	}
	waitForOutboundQueueState(t, p, 0, 1,
		wire.HnsInvItemSize+outboundInventoryOverhead)
	if !p.Connected() {
		t.Fatal("duplicate inventory announcements disconnected peer")
	}
	p.Disconnect()
	waitForOutboundLimitTestPeer(t, p)
}

func TestRejectedInventoryBatchCanBeRetried(t *testing.T) {
	const budgetBytes = 16 * 1024 * 1024
	budget := NewOutboundQueueBudget(budgetBytes)
	invBytes := uint64(wire.HnsInvItemSize + outboundInventoryOverhead)
	workspace, ok := budget.AcquireWorkspace(
		budgetBytes - uint64(defaultControlReserve) - invBytes,
	)
	if !ok {
		t.Fatal("failed to reserve ordinary aggregate capacity")
	}

	conn := newBlockingWriteConn()
	p := startOutboundLimitTestPeerWithConfig(conn, Config{
		WriteTimeout:        time.Hour,
		TrickleInterval:     time.Millisecond,
		OutboundQueueBudget: budget,
	})
	p.flagsMtx.Lock()
	p.versionKnown = true
	p.flagsMtx.Unlock()
	inv := wire.NewInvVect(
		wire.InvTypeTx, chaincfg.RegressionNetParams.GenesisHash,
	)
	p.QueueInventory(inv)
	waitForOutboundQueueState(t, p, 0, 0, 0)
	if p.knownInventory.Contains(*inv) {
		t.Fatal("rejected inventory batch was marked as known")
	}

	workspace.Release()
	p.QueueInventory(inv)
	deadline := time.After(time.Second)
	for !p.knownInventory.Contains(*inv) {
		select {
		case <-deadline:
			t.Fatal("inventory was not admitted after aggregate capacity returned")
		case <-time.After(time.Millisecond):
		}
	}
	select {
	case <-conn.started:
	case <-time.After(time.Second):
		t.Fatal("retried inventory write did not start")
	}
	if !p.Connected() {
		t.Fatal("aggregate inventory backpressure disconnected peer")
	}
	p.Disconnect()
	waitForOutboundLimitTestPeer(t, p)
}

func TestRejectedBlockInventoryCanBeRetried(t *testing.T) {
	const budgetBytes = 16 * 1024 * 1024
	budget := NewOutboundQueueBudget(budgetBytes)
	invBytes := uint64(wire.HnsInvItemSize + outboundInventoryOverhead)
	workspace, ok := budget.AcquireWorkspace(
		budgetBytes - uint64(defaultControlReserve) - invBytes,
	)
	if !ok {
		t.Fatal("failed to reserve ordinary aggregate capacity")
	}

	conn := newBlockingWriteConn()
	p := startOutboundLimitTestPeerWithConfig(conn, Config{
		WriteTimeout:        time.Hour,
		OutboundQueueBudget: budget,
	})
	p.flagsMtx.Lock()
	p.versionKnown = true
	p.flagsMtx.Unlock()
	inv := wire.NewInvVect(
		wire.InvTypeBlock, chaincfg.RegressionNetParams.GenesisHash,
	)
	p.QueueInventory(inv)
	waitForOutboundQueueState(t, p, 0, 0, 0)
	if p.knownInventory.Contains(*inv) {
		t.Fatal("rejected block inventory was marked as known")
	}

	workspace.Release()
	p.QueueInventory(inv)
	deadline := time.After(time.Second)
	for !p.knownInventory.Contains(*inv) {
		select {
		case <-deadline:
			t.Fatal("block inventory was not admitted after capacity returned")
		case <-time.After(time.Millisecond):
		}
	}
	select {
	case <-conn.started:
	case <-time.After(time.Second):
		t.Fatal("retried block inventory write did not start")
	}
	p.Disconnect()
	waitForOutboundLimitTestPeer(t, p)
}

func TestPerPeerDataQueueReservesMandatoryControlCapacity(t *testing.T) {
	proof := &wire.HnsMsgProof{Proof: make([]byte, 64*1024)}
	proofBytes := outboundLimitTestMessageBytes(t, proof)
	conn := newBlockingWriteConn()
	p := startOutboundLimitTestPeerWithConfig(conn, Config{
		WriteTimeout:          time.Hour,
		MaxOutboundQueueBytes: 2 * proofBytes,
	})
	if got := outboundDataByteLimit(p.maxQueuedBytes); got != proofBytes {
		t.Fatalf("ordinary byte capacity = %d, want exact message size %d",
			got, proofBytes)
	}
	if err := p.TryQueueMessage(proof, nil); err != nil {
		t.Fatalf("queue data message: %v", err)
	}
	select {
	case <-conn.started:
	case <-time.After(time.Second):
		t.Fatal("initial data write did not start")
	}
	if err := p.TryQueueMessage(wire.NewHnsMsgPing(1), nil); err != nil {
		t.Fatalf("mandatory control enqueue after data saturation: %v", err)
	}
	if !p.Connected() {
		t.Fatal("data saturation disconnected peer before control enqueue")
	}
	p.Disconnect()
	waitForOutboundLimitTestPeer(t, p)
}

func TestPerPeerDataQueueReservesMandatoryControlMessageSlot(t *testing.T) {
	conn := newBlockingWriteConn()
	p := startOutboundLimitTestPeerWithConfig(conn, Config{
		WriteTimeout:             time.Hour,
		MaxOutboundQueueMessages: 8,
	})
	dataMessages := outboundDataMessageLimit(p.maxQueuedMessages)
	if dataMessages != 4 {
		t.Fatalf("ordinary message capacity = %d, want 4", dataMessages)
	}
	for i := 0; i < dataMessages; i++ {
		if err := p.TryQueueMessage(&wire.HnsMsgHeaders{}, nil); err != nil {
			t.Fatalf("queue data message %d: %v", i, err)
		}
		if i == 0 {
			select {
			case <-conn.started:
			case <-time.After(time.Second):
				t.Fatal("initial data write did not start")
			}
		}
	}
	if err := p.TryQueueMessage(wire.NewHnsMsgPing(1), nil); err != nil {
		t.Fatalf("mandatory control enqueue after slot saturation: %v", err)
	}
	if !p.Connected() {
		t.Fatal("data slot saturation disconnected peer before control enqueue")
	}
	p.Disconnect()
	waitForOutboundLimitTestPeer(t, p)
}

func TestAggregateBudgetReservesMandatoryControlCapacity(t *testing.T) {
	const budgetBytes = 16 * 1024 * 1024
	budget := NewOutboundQueueBudget(budgetBytes)
	workspace, ok := budget.AcquireWorkspace(
		budgetBytes - uint64(defaultControlReserve),
	)
	if !ok {
		t.Fatal("failed to reserve normal aggregate capacity")
	}
	defer workspace.Release()

	conn := newBlockingWriteConn()
	p := startOutboundLimitTestPeer(conn, time.Hour, budget)
	if err := p.TryQueueMessage(wire.NewHnsMsgPing(1), nil); err != nil {
		t.Fatalf("mandatory control enqueue using reserved capacity: %v", err)
	}
	select {
	case <-conn.started:
	case <-time.After(time.Second):
		t.Fatal("mandatory control write did not start")
	}
	if err := p.TryQueueMessage(&wire.HnsMsgHeaders{}, nil); !errors.Is(
		err, ErrOutboundQueueBudget,
	) {
		t.Fatalf("normal enqueue error = %v, want %v", err,
			ErrOutboundQueueBudget)
	}
	if !p.Connected() {
		t.Fatal("aggregate normal-data exhaustion disconnected peer")
	}
	p.Disconnect()
	waitForOutboundLimitTestPeer(t, p)
}

func TestLegacyOnWriteLargeBlockUsesBoundedTransientWorkspace(t *testing.T) {
	tx := wire.NewMsgTx(1)
	tx.AddTxIn(wire.NewTxIn(
		&wire.OutPoint{}, 0, [][]byte{make([]byte, 900*1024)},
	))
	block := wire.NewMsgBlock(&wire.BlockHeader{})
	if err := block.AddTransaction(tx); err != nil {
		t.Fatalf("AddTransaction: %v", err)
	}
	message := &wire.HnsMsgBlock{Block: *block}
	encoded, err := wire.EncodeHnsMessage(
		message, uint32(chaincfg.RegressionNetParams.Net),
	)
	if err != nil {
		t.Fatalf("EncodeHnsMessage: %v", err)
	}
	if len(encoded) < 900*1024 {
		t.Fatalf("large block encoding = %d bytes", len(encoded))
	}

	conn := newPartialWriteConn(len(encoded))
	written := make(chan bool, 1)
	p := startOutboundLimitTestPeerWithConfig(conn, Config{
		WriteTimeout: time.Minute,
		Listeners: MessageListeners{
			OnWrite: func(_ *Peer, _ int, msg wire.HandshakeMessage, _ error) {
				_, ok := msg.(*wire.HnsMsgBlock)
				written <- ok
			},
		},
	})
	done := make(chan struct{}, 1)
	if err := p.TryQueueMessage(message, done); err != nil {
		t.Fatalf("queue large block with legacy OnWrite: %v", err)
	}
	select {
	case ok := <-written:
		if !ok {
			t.Fatal("legacy OnWrite did not receive concrete block")
		}
	case <-time.After(time.Second):
		t.Fatal("legacy OnWrite callback did not run")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("large block write did not complete")
	}
	legacyOnWriteWorkspaceBudget.mu.Lock()
	used := legacyOnWriteWorkspaceBudget.usedBytes
	legacyOnWriteWorkspaceBudget.mu.Unlock()
	if used != 0 {
		t.Fatalf("legacy OnWrite workspace after callback = %d, want 0", used)
	}
	p.Disconnect()
	waitForOutboundLimitTestPeer(t, p)
}

func TestLegacyOnWritePreservesCustomConcreteMessage(t *testing.T) {
	message := &customOnWriteMessage{payload: []byte("custom payload")}
	encoded, err := wire.EncodeHnsMessage(
		message, uint32(chaincfg.RegressionNetParams.Net),
	)
	if err != nil {
		t.Fatalf("EncodeHnsMessage: %v", err)
	}

	conn := newPartialWriteConn(len(encoded))
	written := make(chan wire.HandshakeMessage, 1)
	p := startOutboundLimitTestPeerWithConfig(conn, Config{
		WriteTimeout: time.Minute,
		Listeners: MessageListeners{
			OnWrite: func(_ *Peer, _ int, msg wire.HandshakeMessage, _ error) {
				written <- msg
			},
		},
	})
	done := make(chan struct{}, 1)
	if err := p.TryQueueMessage(message, done); err != nil {
		t.Fatalf("queue custom message with legacy OnWrite: %v", err)
	}
	select {
	case got := <-written:
		if got != message {
			t.Fatalf("OnWrite message = %T %p, want original %T %p",
				got, got, message, message)
		}
	case <-time.After(time.Second):
		t.Fatal("legacy OnWrite callback did not run")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("custom message write did not complete")
	}
	if !p.Connected() {
		t.Fatal("custom message disconnected peer after successful write")
	}
	p.Disconnect()
	waitForOutboundLimitTestPeer(t, p)
}

func TestLegacyOnWriteWorkspaceExhaustionRollsBackQueueBudget(t *testing.T) {
	workspace, ok := legacyOnWriteWorkspaceBudget.AcquireWorkspace(
		legacyOnWriteWorkspaceBytes,
	)
	if !ok {
		t.Fatal("reserve legacy OnWrite workspace")
	}
	defer workspace.Release()

	conn := newBlockingWriteConn()
	budget := NewOutboundQueueBudget(64 * 1024 * 1024)
	p := startOutboundLimitTestPeerWithConfig(conn, Config{
		WriteTimeout:        time.Minute,
		OutboundQueueBudget: budget,
		Listeners: MessageListeners{
			OnWrite: func(_ *Peer, _ int, _ wire.HandshakeMessage, _ error) {},
		},
	})
	if err := p.TryQueueMessage(wire.NewHnsMsgPing(1), nil); !errors.Is(
		err, ErrOutboundQueueBudget,
	) {
		t.Fatalf("queue error = %v, want %v", err, ErrOutboundQueueBudget)
	}
	budget.mu.Lock()
	used := budget.usedBytes
	budget.mu.Unlock()
	if used != 0 {
		t.Fatalf("aggregate queue budget after callback rejection = %d, want 0",
			used)
	}
	if !p.Connected() {
		t.Fatal("callback workspace exhaustion disconnected peer")
	}
	p.Disconnect()
	waitForOutboundLimitTestPeer(t, p)
}

func TestBrontideTransientCopiesAreQueueAccounted(t *testing.T) {
	conn := newBlockingWriteConn()
	ping := wire.NewHnsMsgPing(1)
	encoded, err := wire.EncodeHnsMessage(
		ping, uint32(chaincfg.RegressionNetParams.Net),
	)
	if err != nil {
		t.Fatalf("EncodeHnsMessage: %v", err)
	}
	charge := uint64(len(encoded))*(1+brontideTransientCopies) +
		outboundMessageOverhead + brontideFrameOverhead
	p := newPeerBase(&Config{
		ChainParams:           &chaincfg.RegressionNetParams,
		WriteTimeout:          time.Hour,
		MaxOutboundQueueBytes: 2 * charge,
	}, true)
	p.SetBrontideConnection(true)
	p.conn = conn
	p.addr = conn.RemoteAddr().String()
	atomic.StoreInt32(&p.connected, 1)
	go p.queueHandler()
	go p.outHandler()

	p.QueueMessage(ping, nil)
	select {
	case <-conn.started:
	case <-time.After(time.Second):
		t.Fatal("initial Brontide-accounted write did not start")
	}
	p.QueueMessage(ping, nil)
	waitForOutboundQueueState(t, p, 2, 0, 2*charge)
	p.QueueMessage(ping, nil)
	waitForOutboundLimitTestPeer(t, p)
}

func TestMixedOutboundEnqueueMakesProgress(t *testing.T) {
	conn := newBlockingWriteConn()
	p := startOutboundLimitTestPeerWithConfig(conn, Config{
		TrickleInterval:          time.Hour,
		WriteTimeout:             time.Hour,
		MaxOutboundQueueMessages: 512,
		MaxOutboundInventory:     256,
	})
	p.flagsMtx.Lock()
	p.versionKnown = true
	p.flagsMtx.Unlock()
	p.QueueMessage(wire.NewHnsMsgPing(0), nil)
	select {
	case <-conn.started:
	case <-time.After(time.Second):
		t.Fatal("initial write did not start")
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 200; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			p.QueueMessage(&wire.HnsMsgHeaders{}, nil)
		}()
		go func(n int) {
			defer wg.Done()
			<-start
			hash := *chaincfg.RegressionNetParams.GenesisHash
			hash[0] = byte(n)
			hash[1] = byte(n >> 8)
			p.QueueInventory(wire.NewInvVect(wire.InvTypeTx, &hash))
		}(i)
	}
	close(start)
	finished := make(chan struct{})
	go func() {
		wg.Wait()
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("mixed message and inventory producers deadlocked")
	}
	if !p.Connected() {
		t.Fatal("valid mixed output burst disconnected peer")
	}
	p.Disconnect()
	waitForOutboundLimitTestPeer(t, p)
}

func TestConcurrentEnqueueAndDisconnectReleasesAccounting(t *testing.T) {
	for iteration := 0; iteration < 20; iteration++ {
		conn := newBlockingWriteConn()
		budget := NewOutboundQueueBudget(maxQueuedOutboundBytes)
		p := startOutboundLimitTestPeer(conn, time.Hour, budget)
		p.QueueMessage(wire.NewHnsMsgPing(0), nil)
		select {
		case <-conn.started:
		case <-time.After(time.Second):
			t.Fatal("initial write did not start")
		}

		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < 64; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				p.QueueMessage(&wire.HnsMsgHeaders{}, nil)
			}()
		}
		close(start)
		p.Disconnect()
		wg.Wait()
		waitForOutboundLimitTestPeer(t, p)
		budget.mu.Lock()
		used := budget.usedBytes
		budget.mu.Unlock()
		if used != 0 {
			t.Fatalf("iteration %d shared budget = %d, want 0", iteration, used)
		}
	}
}

func TestDefaultWriteTimeout(t *testing.T) {
	p := newPeerBase(&Config{}, true)
	if p.cfg.WriteTimeout != DefaultWriteTimeout {
		t.Fatalf("default write timeout = %v, want %v",
			p.cfg.WriteTimeout, DefaultWriteTimeout)
	}
	const custom = 7 * time.Minute
	p = newPeerBase(&Config{WriteTimeout: custom}, true)
	if p.cfg.WriteTimeout != custom {
		t.Fatalf("custom write timeout = %v, want %v", p.cfg.WriteTimeout, custom)
	}
}

func TestPartialWritesCompleteAndClearDeadline(t *testing.T) {
	conn := newPartialWriteConn(3)
	p := startOutboundLimitTestPeer(conn, time.Minute, nil)
	message := wire.NewHnsMsgPing(1)
	want, err := wire.EncodeHnsMessage(
		message, uint32(chaincfg.RegressionNetParams.Net),
	)
	if err != nil {
		t.Fatalf("EncodeHnsMessage: %v", err)
	}
	done := make(chan struct{}, 1)
	p.QueueMessage(message, done)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("partial write did not complete")
	}

	conn.mu.Lock()
	writes := conn.writes
	got := append([]byte(nil), conn.written...)
	deadlines := append([]time.Time(nil), conn.deadlines...)
	conn.mu.Unlock()
	if writes < 2 {
		t.Fatalf("write calls = %d, want multiple partial writes", writes)
	}
	if len(deadlines) != 2 || deadlines[0].IsZero() ||
		!deadlines[1].IsZero() {

		t.Fatalf("write deadlines = %v, want non-zero then cleared", deadlines)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("written stream = %x, want %x", got, want)
	}
	p.Disconnect()
	waitForOutboundLimitTestPeer(t, p)
}

func TestWriteDeadlineFailureNotifiesListener(t *testing.T) {
	wantErr := errors.New("test write deadline failure")
	conn := newPartialWriteConn(3)
	conn.deadlineErr = wantErr
	type writeResult struct {
		bytes        int
		err          error
		concretePing bool
	}
	written := make(chan writeResult, 1)
	p := startOutboundLimitTestPeerWithConfig(conn, Config{
		WriteTimeout: time.Minute,
		Listeners: MessageListeners{
			OnWrite: func(_ *Peer, bytes int, msg wire.HandshakeMessage,
				err error) {

				_, concretePing := msg.(*wire.HnsMsgPing)
				written <- writeResult{
					bytes:        bytes,
					err:          err,
					concretePing: concretePing,
				}
			},
		},
	})
	p.QueueMessage(wire.NewHnsMsgPing(1), nil)
	select {
	case result := <-written:
		if result.bytes != 0 || !errors.Is(result.err, wantErr) ||
			!result.concretePing {

			t.Fatalf("OnWrite = (%d, %v), want (0, %v)",
				result.bytes, result.err, wantErr)
		}
	case <-time.After(time.Second):
		t.Fatal("write deadline failure did not notify listener")
	}
	waitForOutboundLimitTestPeer(t, p)
}
