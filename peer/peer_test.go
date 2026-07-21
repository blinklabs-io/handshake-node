// Copyright (c) 2015-2016 The btcsuite developers
// Copyright (c) 2016-2018 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package peer_test

import (
	"errors"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/blinklabs-io/handshake-node/brontide"
	"github.com/blinklabs-io/handshake-node/chaincfg"
	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/peer"
	"github.com/blinklabs-io/handshake-node/wire"
	"github.com/btcsuite/go-socks/socks"
)

// conn mocks a network connection by implementing the net.Conn interface.  It
// is used to test peer connection without actually opening a network
// connection.
type conn struct {
	io.Reader
	io.Writer
	io.Closer

	// local network, address for the connection.
	lnet, laddr string

	// remote network, address for the connection.
	rnet, raddr string

	// mocks socks proxy if true
	proxy bool
}

// LocalAddr returns the local address for the connection.
func (c conn) LocalAddr() net.Addr {
	return &addr{c.lnet, c.laddr}
}

// Remote returns the remote address for the connection.
func (c conn) RemoteAddr() net.Addr {
	if !c.proxy {
		return &addr{c.rnet, c.raddr}
	}
	host, strPort, _ := net.SplitHostPort(c.raddr)
	port, _ := strconv.Atoi(strPort)
	return &socks.ProxiedAddr{
		Net:  c.rnet,
		Host: host,
		Port: port,
	}
}

// Close handles closing the connection.
func (c conn) Close() error {
	if c.Closer == nil {
		return nil
	}
	return c.Closer.Close()
}

func (c conn) SetDeadline(t time.Time) error      { return nil }
func (c conn) SetReadDeadline(t time.Time) error  { return nil }
func (c conn) SetWriteDeadline(t time.Time) error { return nil }

// addr mocks a network address
type addr struct {
	net, address string
}

func (m addr) Network() string { return m.net }
func (m addr) String() string  { return m.address }

// pipe turns two mock connections into a full-duplex connection similar to
// net.Pipe to allow pipe's with (fake) addresses.
func pipe(c1, c2 *conn) (*conn, *conn) {
	r1, w1 := io.Pipe()
	r2, w2 := io.Pipe()

	c1.Writer = w1
	c1.Closer = w1
	c2.Reader = r1
	c1.Reader = r2
	c2.Writer = w2
	c2.Closer = w2

	return c1, c2
}

// peerStats holds the expected peer stats used for testing peer.
type peerStats struct {
	wantUserAgent       string
	wantServices        wire.ServiceFlag
	wantProtocolVersion uint32
	wantConnected       bool
	wantVersionKnown    bool
	wantVerAckReceived  bool
	wantLastBlock       int32
	wantStartingHeight  int32
	wantLastPingTime    time.Time
	wantLastPingNonce   uint64
	wantLastPingMicros  int64
	wantTimeOffset      int64
	wantBytesSent       uint64
	wantBytesReceived   uint64
	wantWitnessEnabled  bool
}

// testPeer tests the given peer's flags and stats
func testPeer(t *testing.T, p *peer.Peer, s peerStats) {
	if p.UserAgent() != s.wantUserAgent {
		t.Errorf("testPeer: wrong UserAgent - got %v, want %v", p.UserAgent(), s.wantUserAgent)
		return
	}

	if p.Services() != s.wantServices {
		t.Errorf("testPeer: wrong Services - got %v, want %v", p.Services(), s.wantServices)
		return
	}

	if !p.LastPingTime().Equal(s.wantLastPingTime) {
		t.Errorf("testPeer: wrong LastPingTime - got %v, want %v", p.LastPingTime(), s.wantLastPingTime)
		return
	}

	if p.LastPingNonce() != s.wantLastPingNonce {
		t.Errorf("testPeer: wrong LastPingNonce - got %v, want %v", p.LastPingNonce(), s.wantLastPingNonce)
		return
	}

	if p.LastPingMicros() != s.wantLastPingMicros {
		t.Errorf("testPeer: wrong LastPingMicros - got %v, want %v", p.LastPingMicros(), s.wantLastPingMicros)
		return
	}

	if p.VerAckReceived() != s.wantVerAckReceived {
		t.Errorf("testPeer: wrong VerAckReceived - got %v, want %v", p.VerAckReceived(), s.wantVerAckReceived)
		return
	}

	if p.VersionKnown() != s.wantVersionKnown {
		t.Errorf("testPeer: wrong VersionKnown - got %v, want %v", p.VersionKnown(), s.wantVersionKnown)
		return
	}

	if p.ProtocolVersion() != s.wantProtocolVersion {
		t.Errorf("testPeer: wrong ProtocolVersion - got %v, want %v", p.ProtocolVersion(), s.wantProtocolVersion)
		return
	}

	if p.LastBlock() != s.wantLastBlock {
		t.Errorf("testPeer: wrong LastBlock - got %v, want %v", p.LastBlock(), s.wantLastBlock)
		return
	}

	// Allow for a deviation of 1s, as the second may tick when the message is
	// in transit and the protocol doesn't support any further precision.
	if p.TimeOffset() != s.wantTimeOffset && p.TimeOffset() != s.wantTimeOffset-1 {
		t.Errorf("testPeer: wrong TimeOffset - got %v, want %v or %v", p.TimeOffset(),
			s.wantTimeOffset, s.wantTimeOffset-1)
		return
	}

	if p.BytesSent() != s.wantBytesSent {
		t.Errorf("testPeer: wrong BytesSent - got %v, want %v", p.BytesSent(), s.wantBytesSent)
		return
	}

	if p.BytesReceived() != s.wantBytesReceived {
		t.Errorf("testPeer: wrong BytesReceived - got %v, want %v", p.BytesReceived(), s.wantBytesReceived)
		return
	}

	if p.StartingHeight() != s.wantStartingHeight {
		t.Errorf("testPeer: wrong StartingHeight - got %v, want %v", p.StartingHeight(), s.wantStartingHeight)
		return
	}

	if p.Connected() != s.wantConnected {
		t.Errorf("testPeer: wrong Connected - got %v, want %v", p.Connected(), s.wantConnected)
		return
	}

	if p.IsWitnessEnabled() != s.wantWitnessEnabled {
		t.Errorf("testPeer: wrong WitnessEnabled - got %v, want %v",
			p.IsWitnessEnabled(), s.wantWitnessEnabled)
		return
	}

	stats := p.StatsSnapshot()

	if p.ID() != stats.ID {
		t.Errorf("testPeer: wrong ID - got %v, want %v", p.ID(), stats.ID)
		return
	}

	if p.Addr() != stats.Addr {
		t.Errorf("testPeer: wrong Addr - got %v, want %v", p.Addr(), stats.Addr)
		return
	}

	if p.LastSend() != stats.LastSend {
		t.Errorf("testPeer: wrong LastSend - got %v, want %v", p.LastSend(), stats.LastSend)
		return
	}

	if p.LastRecv() != stats.LastRecv {
		t.Errorf("testPeer: wrong LastRecv - got %v, want %v", p.LastRecv(), stats.LastRecv)
		return
	}
}

// TestPeerConnection tests connection between inbound and outbound peers.
func TestPeerConnection(t *testing.T) {
	verack := make(chan struct{})
	peer1Cfg := &peer.Config{
		Listeners: peer.MessageListeners{
			OnVerAck: func(p *peer.Peer, msg *wire.HnsMsgVerack) {
				verack <- struct{}{}
			},
			OnWrite: func(p *peer.Peer, bytesWritten int,
				msg wire.HandshakeMessage, err error) {
				if _, ok := msg.(*wire.HnsMsgVerack); ok {
					verack <- struct{}{}
				}
			},
		},
		UserAgentName:     "peer",
		UserAgentVersion:  "1.0",
		UserAgentComments: []string{"comment"},
		ChainParams:       &chaincfg.MainNetParams,
		ProtocolVersion:   wire.HnsMinProtocolVersion,
		Services:          0,
		TrickleInterval:   time.Second * 10,
		AllowSelfConns:    true,
	}
	peer2Cfg := &peer.Config{
		Listeners:         peer1Cfg.Listeners,
		UserAgentName:     "peer",
		UserAgentVersion:  "1.0",
		UserAgentComments: []string{"comment"},
		ChainParams:       &chaincfg.MainNetParams,
		Services:          wire.SFNodeNetwork,
		TrickleInterval:   time.Second * 10,
		AllowSelfConns:    true,
	}

	wantStats1 := peerStats{
		wantUserAgent:       wire.DefaultUserAgent + "peer:1.0(comment)/",
		wantServices:        0,
		wantProtocolVersion: wire.HnsMinProtocolVersion,
		wantConnected:       true,
		wantVersionKnown:    true,
		wantVerAckReceived:  true,
		wantLastPingTime:    time.Time{},
		wantLastPingNonce:   uint64(0),
		wantLastPingMicros:  int64(0),
		wantTimeOffset:      int64(0),
		wantBytesSent:       180, // 171 version + 9 verack
		wantBytesReceived:   180,
		wantWitnessEnabled:  false,
	}
	wantStats2 := peerStats{
		wantUserAgent:       wire.DefaultUserAgent + "peer:1.0(comment)/",
		wantServices:        wire.SFNodeNetwork,
		wantProtocolVersion: wire.HnsMinProtocolVersion,
		wantConnected:       true,
		wantVersionKnown:    true,
		wantVerAckReceived:  true,
		wantLastPingTime:    time.Time{},
		wantLastPingNonce:   uint64(0),
		wantLastPingMicros:  int64(0),
		wantTimeOffset:      int64(0),
		wantBytesSent:       180, // 171 version + 9 verack
		wantBytesReceived:   180,
		wantWitnessEnabled:  false,
	}

	tests := []struct {
		name  string
		setup func() (*peer.Peer, *peer.Peer, error)
	}{
		{
			"basic handshake",
			func() (*peer.Peer, *peer.Peer, error) {
				inPeer := peer.NewInboundPeer(peer1Cfg)
				outPeer, err := peer.NewOutboundPeer(peer2Cfg, "10.0.0.2:8333")
				if err != nil {
					return nil, nil, err
				}

				err = setupPeerConnection(inPeer, outPeer)
				if err != nil {
					return nil, nil, err
				}

				for i := 0; i < 4; i++ {
					select {
					case <-verack:
					case <-time.After(time.Second):
						return nil, nil, errors.New("verack timeout")
					}
				}
				return inPeer, outPeer, nil
			},
		},
		{
			"socks proxy",
			func() (*peer.Peer, *peer.Peer, error) {
				inPeer := peer.NewInboundPeer(peer1Cfg)
				outPeer, err := peer.NewOutboundPeer(peer2Cfg, "10.0.0.2:8333")
				if err != nil {
					return nil, nil, err
				}

				err = setupPeerConnection(inPeer, outPeer)
				if err != nil {
					return nil, nil, err
				}

				for i := 0; i < 4; i++ {
					select {
					case <-verack:
					case <-time.After(time.Second):
						return nil, nil, errors.New("verack timeout")
					}
				}
				return inPeer, outPeer, nil
			},
		},
	}
	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		inPeer, outPeer, err := test.setup()
		if err != nil {
			t.Errorf("TestPeerConnection setup #%d: unexpected err %v", i, err)
			return
		}
		testPeer(t, inPeer, wantStats2)
		testPeer(t, outPeer, wantStats1)

		inPeer.Disconnect()
		outPeer.Disconnect()
		inPeer.WaitForDisconnect()
		outPeer.WaitForDisconnect()
	}
}

// TestPeerListeners tests that the peer listeners are called as expected.
func TestPeerListeners(t *testing.T) {
	verack := make(chan struct{}, 1)
	ok := make(chan wire.HandshakeMessage, 22)
	peerCfg := &peer.Config{
		Listeners: peer.MessageListeners{
			OnGetAddr: func(p *peer.Peer, msg *wire.HnsMsgGetAddr) {
				ok <- msg
			},
			OnAddr: func(p *peer.Peer, msg *wire.HnsMsgAddr) {
				ok <- msg
			},
			OnPing: func(p *peer.Peer, msg *wire.HnsMsgPing) {
				ok <- msg
			},
			OnPong: func(p *peer.Peer, msg *wire.HnsMsgPong) {
				ok <- msg
			},
			OnMemPool: func(p *peer.Peer, msg *wire.HnsMsgMemPool) {
				ok <- msg
			},
			OnTx: func(p *peer.Peer, msg *wire.HnsMsgTx) {
				ok <- msg
			},
			OnBlock: func(p *peer.Peer, msg *wire.HnsMsgBlock, buf []byte) {
				ok <- msg
			},
			OnInv: func(p *peer.Peer, msg *wire.HnsMsgInv) {
				ok <- msg
			},
			OnHeaders: func(p *peer.Peer, msg *wire.HnsMsgHeaders) {
				ok <- msg
			},
			OnNotFound: func(p *peer.Peer, msg *wire.HnsMsgNotFound) {
				ok <- msg
			},
			OnGetData: func(p *peer.Peer, msg *wire.HnsMsgGetData) {
				ok <- msg
			},
			OnGetBlocks: func(p *peer.Peer, msg *wire.HnsMsgGetBlocks) {
				ok <- msg
			},
			OnGetHeaders: func(p *peer.Peer, msg *wire.HnsMsgGetHeaders) {
				ok <- msg
			},
			OnFeeFilter: func(p *peer.Peer, msg *wire.HnsMsgFeeFilter) {
				ok <- msg
			},
			OnFilterAdd: func(p *peer.Peer, msg *wire.HnsMsgFilterAdd) {
				ok <- msg
			},
			OnFilterClear: func(p *peer.Peer, msg *wire.HnsMsgFilterClear) {
				ok <- msg
			},
			OnFilterLoad: func(p *peer.Peer, msg *wire.HnsMsgFilterLoad) {
				ok <- msg
			},
			OnMerkleBlock: func(p *peer.Peer, msg *wire.HnsMsgMerkleBlock) {
				ok <- msg
			},
			OnVersion: func(p *peer.Peer, msg *wire.HnsMsgVersion) *wire.HnsMsgReject {
				ok <- msg
				return nil
			},
			OnVerAck: func(p *peer.Peer, msg *wire.HnsMsgVerack) {
				verack <- struct{}{}
			},
			OnReject: func(p *peer.Peer, msg *wire.HnsMsgReject) {
				ok <- msg
			},
			OnSendHeaders: func(p *peer.Peer, msg *wire.HnsMsgSendHeaders) {
				ok <- msg
			},
		},
		UserAgentName:     "peer",
		UserAgentVersion:  "1.0",
		UserAgentComments: []string{"comment"},
		ChainParams:       &chaincfg.MainNetParams,
		Services:          wire.SFNodeBloom,
		TrickleInterval:   time.Second * 10,
		AllowSelfConns:    true,
	}
	inPeer := peer.NewInboundPeer(peerCfg)

	peerCfg.Listeners = peer.MessageListeners{
		OnVerAck: func(p *peer.Peer, msg *wire.HnsMsgVerack) {
			verack <- struct{}{}
		},
	}
	outPeer, err := peer.NewOutboundPeer(peerCfg, "10.0.0.1:8333")
	if err != nil {
		t.Errorf("NewOutboundPeer: unexpected err %v\n", err)
		return
	}

	err = setupPeerConnection(inPeer, outPeer)
	if err != nil {
		t.Errorf("setupPeerConnection: failed: %v\n", err)
		return
	}

	for i := 0; i < 2; i++ {
		select {
		case <-verack:
		case <-time.After(time.Second * 1):
			t.Errorf("TestPeerListeners: verack timeout\n")
			return
		}
	}
	select {
	case msg := <-ok:
		if _, ok := msg.(*wire.HnsMsgVersion); !ok {
			t.Fatalf("TestPeerListeners: got %T, want *wire.HnsMsgVersion", msg)
		}
	case <-time.After(time.Second):
		t.Fatal("TestPeerListeners: version callback timeout")
	}

	tests := []struct {
		listener string
		msg      wire.HandshakeMessage
	}{
		{
			"OnGetAddr",
			&wire.HnsMsgGetAddr{},
		},
		{
			"OnAddr",
			&wire.HnsMsgAddr{},
		},
		{
			"OnPing",
			wire.NewHnsMsgPing(42),
		},
		{
			"OnPong",
			&wire.HnsMsgPong{Nonce: [8]byte{42}},
		},
		{
			"OnMemPool",
			&wire.HnsMsgMemPool{},
		},
		{
			"OnTx",
			&wire.HnsMsgTx{Tx: *wire.NewMsgTx(wire.TxVersion)},
		},
		{
			"OnBlock",
			&wire.HnsMsgBlock{Block: *wire.NewMsgBlock(wire.NewBlockHeader(1,
				&chainhash.Hash{}, &chainhash.Hash{}, &chainhash.Hash{}, &chainhash.Hash{}, 1, 1))},
		},
		{
			"OnInv",
			wire.NewHnsMsgInv(),
		},
		{
			"OnHeaders",
			&wire.HnsMsgHeaders{},
		},
		{
			"OnNotFound",
			wire.NewHnsMsgNotFound(),
		},
		{
			"OnGetData",
			wire.NewHnsMsgGetData(),
		},
		{
			"OnGetBlocks",
			&wire.HnsMsgGetBlocks{},
		},
		{
			"OnGetHeaders",
			&wire.HnsMsgGetHeaders{},
		},
		{
			"OnFeeFilter",
			&wire.HnsMsgFeeFilter{Rate: 15000},
		},
		{
			"OnFilterAdd",
			&wire.HnsMsgFilterAdd{Data: []byte{0x01}},
		},
		{
			"OnFilterClear",
			&wire.HnsMsgFilterClear{},
		},
		{
			"OnFilterLoad",
			&wire.HnsMsgFilterLoad{Filter: []byte{0x01}, HashFuncs: 10, Flags: wire.BloomUpdateNone},
		},
		{
			"OnMerkleBlock",
			&wire.HnsMsgMerkleBlock{MerkleBlock: *testPeerMerkleBlock()},
		},
		// only one version message is allowed
		// only one verack message is allowed
		{
			"OnReject",
			&wire.HnsMsgReject{
				Message: wire.HnsMsgTypeVersion,
				Code:    wire.RejectDuplicate,
				Reason:  "dupe version",
			},
		},
		{
			"OnSendHeaders",
			&wire.HnsMsgSendHeaders{},
		},
	}
	t.Logf("Running %d tests", len(tests))
	for _, test := range tests {
		// Queue the test message
		outPeer.QueueHnsMessage(test.msg, nil)
		select {
		case <-ok:
		case <-time.After(time.Second * 1):
			t.Errorf("TestPeerListeners: %s timeout (in connected=%v, out connected=%v)",
				test.listener, inPeer.Connected(), outPeer.Connected())
			return
		}
	}
	inPeer.Disconnect()
	outPeer.Disconnect()
}

// TestOutboundPeer tests that the outbound peer works as expected.
func TestOutboundPeer(t *testing.T) {

	peerCfg := &peer.Config{
		NewestBlock: func() (*chainhash.Hash, int32, error) {
			return nil, 0, errors.New("newest block not found")
		},
		UserAgentName:     "peer",
		UserAgentVersion:  "1.0",
		UserAgentComments: []string{"comment"},
		ChainParams:       &chaincfg.MainNetParams,
		Services:          0,
		TrickleInterval:   time.Second * 10,
		AllowSelfConns:    true,
	}

	r, w := io.Pipe()
	c := &conn{raddr: "10.0.0.1:8333", Writer: w, Reader: r}

	p, err := peer.NewOutboundPeer(peerCfg, "10.0.0.1:8333")
	if err != nil {
		t.Errorf("NewOutboundPeer: unexpected err - %v\n", err)
		return
	}

	// Test trying to connect twice.
	p.AssociateConnection(c)
	p.AssociateConnection(c)

	disconnected := make(chan struct{})
	go func() {
		p.WaitForDisconnect()
		disconnected <- struct{}{}
	}()

	select {
	case <-disconnected:
		close(disconnected)
	case <-time.After(time.Second):
		t.Fatal("Peer did not automatically disconnect.")
	}

	if p.Connected() {
		t.Fatalf("Should not be connected as NewestBlock produces error.")
	}

	// Test Queue Inv
	fakeBlockHash := &chainhash.Hash{0: 0x00, 1: 0x01}
	fakeInv := wire.NewInvVect(wire.InvTypeBlock, fakeBlockHash)

	// Should be noops as the peer could not connect.
	p.QueueInventory(fakeInv)
	p.AddKnownInventory(fakeInv)
	p.QueueInventory(fakeInv)

	fakeMsg := &wire.HnsMsgVerack{}
	p.QueueMessage(fakeMsg, nil)
	done := make(chan struct{})
	p.QueueMessage(fakeMsg, done)
	<-done
	p.Disconnect()

	// Test NewestBlock
	var newestBlock = func() (*chainhash.Hash, int32, error) {
		hashStr := "14a0810ac680a3eb3f82edc878cea25ec41d6b790744e5daeef"
		hash, err := chainhash.NewHashFromStr(hashStr)
		if err != nil {
			return nil, 0, err
		}
		return hash, 234439, nil
	}

	peerCfg.NewestBlock = newestBlock
	r1, w1 := io.Pipe()
	c1 := &conn{raddr: "10.0.0.1:8333", Writer: w1, Reader: r1}
	p1, err := peer.NewOutboundPeer(peerCfg, "10.0.0.1:8333")
	if err != nil {
		t.Errorf("NewOutboundPeer: unexpected err - %v\n", err)
		return
	}
	p1.AssociateConnection(c1)

	// Test update latest block
	latestBlockHash, err := chainhash.NewHashFromStr("1a63f9cdff1752e6375c8c76e543a71d239e1a2e5c6db1aa679")
	if err != nil {
		t.Errorf("NewHashFromStr: unexpected err %v\n", err)
		return
	}
	p1.UpdateLastAnnouncedBlock(latestBlockHash)
	p1.UpdateLastBlockHeight(234440)
	if p1.LastAnnouncedBlock() != latestBlockHash {
		t.Errorf("LastAnnouncedBlock: wrong block - got %v, want %v",
			p1.LastAnnouncedBlock(), latestBlockHash)
		return
	}

	// Test Queue Inv after connection
	p1.QueueInventory(fakeInv)
	p1.Disconnect()

	// Test regression
	peerCfg.ChainParams = &chaincfg.RegressionNetParams
	peerCfg.Services = wire.SFNodeBloom
	r2, w2 := io.Pipe()
	c2 := &conn{raddr: "10.0.0.1:8333", Writer: w2, Reader: r2}
	p2, err := peer.NewOutboundPeer(peerCfg, "10.0.0.1:8333")
	if err != nil {
		t.Errorf("NewOutboundPeer: unexpected err - %v\n", err)
		return
	}
	p2.AssociateConnection(c2)

	// Test PushXXX
	var addrs []*wire.NetAddress
	for i := 0; i < 5; i++ {
		na := wire.NetAddress{}
		addrs = append(addrs, &na)
	}
	if _, err := p2.PushAddrMsg(addrs); err != nil {
		t.Errorf("PushAddrMsg: unexpected err %v\n", err)
		return
	}
	if err := p2.PushGetBlocksMsg(nil, &chainhash.Hash{}); err != nil {
		t.Errorf("PushGetBlocksMsg: unexpected err %v\n", err)
		return
	}
	if err := p2.PushGetHeadersMsg(nil, &chainhash.Hash{}); err != nil {
		t.Errorf("PushGetHeadersMsg: unexpected err %v\n", err)
		return
	}

	p2.PushRejectMsg(wire.HnsMsgTypeBlock, wire.RejectMalformed, "malformed", nil, false)
	p2.PushRejectMsg(wire.HnsMsgTypeBlock, wire.RejectInvalid, "invalid", nil, false)

	// Test Queue Messages
	p2.QueueMessage(&wire.HnsMsgGetAddr{}, nil)
	p2.QueueMessage(wire.NewHnsMsgPing(1), nil)
	p2.QueueMessage(&wire.HnsMsgMemPool{}, nil)
	p2.QueueMessage(wire.NewHnsMsgGetData(), nil)
	p2.QueueMessage(&wire.HnsMsgGetHeaders{}, nil)
	p2.QueueMessage(&wire.HnsMsgFeeFilter{Rate: 20000}, nil)

	p2.Disconnect()
}

// TestAssociateConnectionInvalidRemoteAddress ensures the inbound connection
// setup error path can disconnect without deadlocking peer lifecycle cleanup.
func TestAssociateConnectionInvalidRemoteAddress(t *testing.T) {
	p := peer.NewInboundPeer(&peer.Config{})
	p.AssociateConnection(&conn{raddr: "invalid-address"})
	p.WaitForDisconnect()

	if p.Connected() {
		t.Fatal("peer remained connected after rejecting its remote address")
	}
}

// Tests that the node disconnects from peers with an unsupported protocol
// version.
func TestUnsupportedVersionPeer(t *testing.T) {
	peerCfg := &peer.Config{
		UserAgentName:     "peer",
		UserAgentVersion:  "1.0",
		UserAgentComments: []string{"comment"},
		ChainParams:       &chaincfg.MainNetParams,
		Services:          0,
		TrickleInterval:   time.Second * 10,
		AllowSelfConns:    true,
	}

	remoteNA := wire.NewNetAddressIPPort(
		net.ParseIP("10.0.0.2"),
		uint16(8333),
		wire.SFNodeNetwork,
	)
	localConn, remoteConn := pipe(
		&conn{laddr: "10.0.0.1:8333", raddr: "10.0.0.2:8333"},
		&conn{laddr: "10.0.0.2:8333", raddr: "10.0.0.1:8333"},
	)

	p, err := peer.NewOutboundPeer(peerCfg, "10.0.0.1:8333")
	if err != nil {
		t.Fatalf("NewOutboundPeer: unexpected err - %v\n", err)
	}
	p.AssociateConnection(localConn)

	// Read outbound messages to peer into a channel.
	outboundMessages := make(chan wire.HandshakeMessage)
	go func() {
		for {
			_, msg, _, err := wire.ReadHandshakeMessageN(
				remoteConn,
				peerCfg.ChainParams.Net,
			)
			if err == io.EOF {
				close(outboundMessages)
				return
			}
			if err != nil {
				t.Errorf("Error reading message from local node: %v\n", err)
				return
			}

			outboundMessages <- msg
		}
	}()

	// Read version message sent to remote peer
	select {
	case msg := <-outboundMessages:
		if _, ok := msg.(*wire.HnsMsgVersion); !ok {
			t.Fatalf("Expected version message, got [%s]", msg.Type())
		}
	case <-time.After(time.Second):
		t.Fatal("Peer did not send version message")
	}

	// Remote peer writes version message advertising invalid protocol version 0.
	invalidVersionMsg := &wire.HnsMsgVersion{
		Version:  0,
		Services: uint64(peerCfg.Services),
		Time:     uint64(time.Now().Unix()),
		Remote:   wire.NewHnsNetAddress(remoteNA),
		Agent:    wire.DefaultUserAgent,
	}

	_, err = wire.WriteHnsMessageN(
		remoteConn.Writer,
		invalidVersionMsg,
		peerCfg.ChainParams.Net,
	)
	if err != nil {
		t.Fatalf("wire.WriteHnsMessageN: unexpected err - %v\n", err)
	}

	select {
	case msg := <-outboundMessages:
		reject, ok := msg.(*wire.HnsMsgReject)
		if !ok {
			t.Fatalf("Expected reject message, got [%s]", msg.Type())
		}
		if reject.Message != wire.HnsMsgTypeVersion {
			t.Fatalf("Reject message type: got %s, want %s",
				reject.Message, wire.HnsMsgTypeVersion)
		}
		if reject.Code != wire.RejectObsolete {
			t.Fatalf("Reject code: got %s, want %s",
				reject.Code, wire.RejectObsolete)
		}
	case <-time.After(time.Second):
		t.Fatal("Peer did not send reject message")
	}

	// Expect peer to disconnect automatically
	disconnected := make(chan struct{})
	go func() {
		p.WaitForDisconnect()
		disconnected <- struct{}{}
	}()

	select {
	case <-disconnected:
		close(disconnected)
	case <-time.After(time.Second):
		t.Fatal("Peer did not automatically disconnect")
	}

	// Expect no further outbound messages from peer
	select {
	case msg, chanOpen := <-outboundMessages:
		if chanOpen {
			t.Fatalf("Expected no further messages, received [%s]", msg.Type())
		}
	case <-time.After(time.Second):
		t.Fatal("Timeout waiting for remote reader to close")
	}
}

func TestOutboundPeerAcceptsVerAckBeforeVersion(t *testing.T) {
	type verackState struct {
		id           int32
		versionKnown bool
		services     wire.ServiceFlag
		lastBlock    int32
	}
	verack := make(chan verackState, 1)
	peerCfg := &peer.Config{
		Listeners: peer.MessageListeners{
			OnVerAck: func(p *peer.Peer, msg *wire.HnsMsgVerack) {
				verack <- verackState{
					id:           p.ID(),
					versionKnown: p.VersionKnown(),
					services:     p.Services(),
					lastBlock:    p.LastBlock(),
				}
			},
		},
		UserAgentName:    "peer",
		UserAgentVersion: "1.0",
		ChainParams:      &chaincfg.MainNetParams,
		Services:         wire.SFNodeNetwork,
		AllowSelfConns:   true,
	}

	localConn, remoteConn := pipe(
		&conn{laddr: "10.0.0.1:12038", raddr: "10.0.0.2:12038"},
		&conn{laddr: "10.0.0.2:12038", raddr: "10.0.0.1:12038"},
	)

	p, err := peer.NewOutboundPeer(peerCfg, "10.0.0.2:12038")
	if err != nil {
		t.Fatalf("NewOutboundPeer: unexpected err - %v", err)
	}
	p.AssociateConnection(localConn)
	defer func() {
		p.Disconnect()
		p.WaitForDisconnect()
	}()

	outboundMessages := make(chan wire.HandshakeMessage)
	go func() {
		for {
			_, msg, _, err := wire.ReadHandshakeMessageN(
				remoteConn,
				peerCfg.ChainParams.Net,
			)
			if err != nil {
				close(outboundMessages)
				return
			}
			outboundMessages <- msg
		}
	}()

	select {
	case msg := <-outboundMessages:
		if _, ok := msg.(*wire.HnsMsgVersion); !ok {
			t.Fatalf("expected version message, got %s", msg.Type())
		}
	case <-time.After(time.Second):
		t.Fatal("peer did not send version message")
	}

	if _, err := wire.WriteHnsMessageN(
		remoteConn.Writer,
		&wire.HnsMsgVerack{},
		peerCfg.ChainParams.Net,
	); err != nil {
		t.Fatalf("WriteHnsMessageN verack: %v", err)
	}

	remoteNA := wire.NewNetAddressIPPort(
		net.ParseIP("10.0.0.2"),
		uint16(12038),
		wire.SFNodeNetwork,
	)
	remoteVersionMsg := &wire.HnsMsgVersion{
		Version:  wire.HnsProtocolVersion,
		Services: uint64(peerCfg.Services),
		Time:     uint64(time.Now().Unix()),
		Remote:   wire.NewHnsNetAddress(remoteNA),
		Agent:    wire.DefaultUserAgent,
		Height:   123,
	}
	if _, err := wire.WriteHnsMessageN(
		remoteConn.Writer,
		remoteVersionMsg,
		peerCfg.ChainParams.Net,
	); err != nil {
		t.Fatalf("WriteHnsMessageN version: %v", err)
	}

	select {
	case msg := <-outboundMessages:
		if _, ok := msg.(*wire.HnsMsgVerack); !ok {
			t.Fatalf("expected verack message, got %s", msg.Type())
		}
	case <-time.After(time.Second):
		t.Fatal("peer did not send verack message")
	}

	select {
	case state := <-verack:
		if state.id == 0 {
			t.Fatal("verack callback fired before peer ID assignment")
		}
		if !state.versionKnown {
			t.Fatal("verack callback fired before version was known")
		}
		if state.services != wire.SFNodeNetwork {
			t.Fatalf("verack callback services = %v, want %v",
				state.services, wire.SFNodeNetwork)
		}
		if state.lastBlock != int32(remoteVersionMsg.Height) {
			t.Fatalf("verack callback last block = %d, want %d",
				state.lastBlock, remoteVersionMsg.Height)
		}
	case <-time.After(time.Second):
		t.Fatal("verack callback timeout")
	}

	if !p.VersionKnown() {
		t.Fatal("peer version was not known")
	}
	if !p.VerAckReceived() {
		t.Fatal("peer verack was not recorded")
	}
	if p.LastBlock() != int32(remoteVersionMsg.Height) {
		t.Fatalf("peer last block = %d, want %d",
			p.LastBlock(), remoteVersionMsg.Height)
	}
}

// TestDuplicateVersionMsg ensures that receiving a version message after one
// has already been received results in the peer being disconnected.
func TestDuplicateVersionMsg(t *testing.T) {
	// Create a pair of peers that are connected to each other using a fake
	// connection.
	verack := make(chan struct{})
	peerCfg := &peer.Config{
		Listeners: peer.MessageListeners{
			OnVerAck: func(p *peer.Peer, msg *wire.HnsMsgVerack) {
				verack <- struct{}{}
			},
		},
		UserAgentName:    "peer",
		UserAgentVersion: "1.0",
		ChainParams:      &chaincfg.MainNetParams,
		Services:         0,
		AllowSelfConns:   true,
	}
	outPeer, err := peer.NewOutboundPeer(peerCfg, "10.0.0.2:8333")
	if err != nil {
		t.Fatalf("NewOutboundPeer: unexpected err: %v\n", err)
	}
	inPeer := peer.NewInboundPeer(peerCfg)

	err = setupPeerConnection(inPeer, outPeer)
	if err != nil {
		t.Fatalf("setupPeerConnection failed to connect: %v\n", err)
	}

	// Wait for the veracks from the initial protocol version negotiation.
	for i := 0; i < 2; i++ {
		select {
		case <-verack:
		case <-time.After(time.Second):
			t.Fatal("verack timeout")
		}
	}
	// Queue a duplicate version message from the outbound peer and wait until
	// it is sent.
	done := make(chan struct{})
	outPeer.QueueMessage(&wire.HnsMsgVersion{}, done)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("send duplicate version timeout")
	}
	// Ensure the peer that is the recipient of the duplicate version closes the
	// connection.
	disconnected := make(chan struct{}, 1)
	go func() {
		inPeer.WaitForDisconnect()
		disconnected <- struct{}{}
	}()
	select {
	case <-disconnected:
	case <-time.After(time.Second):
		t.Fatal("peer did not disconnect")
	}
}

// TestUpdateLastBlockHeight ensures the last block height is set properly
// during the initial version negotiation and is only allowed to advance to
// higher values via the associated update function.
func TestUpdateLastBlockHeight(t *testing.T) {
	// Create a pair of peers that are connected to each other using a fake
	// connection and the remote peer starting at height 100.
	const remotePeerHeight = 100
	verack := make(chan struct{})
	peerCfg := peer.Config{
		Listeners: peer.MessageListeners{
			OnVerAck: func(p *peer.Peer, msg *wire.HnsMsgVerack) {
				verack <- struct{}{}
			},
		},
		UserAgentName:    "peer",
		UserAgentVersion: "1.0",
		ChainParams:      &chaincfg.MainNetParams,
		Services:         0,
		AllowSelfConns:   true,
	}
	remotePeerCfg := peerCfg
	remotePeerCfg.NewestBlock = func() (*chainhash.Hash, int32, error) {
		return &chainhash.Hash{}, remotePeerHeight, nil
	}
	localPeer, err := peer.NewOutboundPeer(&peerCfg, "10.0.0.2:8333")
	if err != nil {
		t.Fatalf("NewOutboundPeer: unexpected err: %v\n", err)
	}
	inPeer := peer.NewInboundPeer(&remotePeerCfg)

	err = setupPeerConnection(inPeer, localPeer)
	if err != nil {
		t.Fatalf("setupPeerConnection failed to connect: %v\n", err)
	}

	// Wait for the veracks from the initial protocol version negotiation.
	for i := 0; i < 2; i++ {
		select {
		case <-verack:
		case <-time.After(time.Second):
			t.Fatal("verack timeout")
		}
	}

	// Ensure the latest block height starts at the value reported by the remote
	// peer via its version message.
	if height := localPeer.LastBlock(); height != remotePeerHeight {
		t.Fatalf("wrong starting height - got %d, want %d", height,
			remotePeerHeight)
	}

	// Ensure the latest block height is not allowed to go backwards.
	localPeer.UpdateLastBlockHeight(remotePeerHeight - 1)
	if height := localPeer.LastBlock(); height != remotePeerHeight {
		t.Fatalf("height allowed to go backwards - got %d, want %d", height,
			remotePeerHeight)
	}

	// Ensure the latest block height is allowed to advance.
	localPeer.UpdateLastBlockHeight(remotePeerHeight + 1)
	if height := localPeer.LastBlock(); height != remotePeerHeight+1 {
		t.Fatalf("height not allowed to advance - got %d, want %d", height,
			remotePeerHeight+1)
	}
}

// setupPeerConnection initiates a tcp connection between two peers.
func setupPeerConnection(in, out *peer.Peer) error {
	// listenFunc is a function closure that listens for a tcp connection.
	// The tcp connection will be the one the inbound peer uses. This will
	// be run as a goroutine.
	listenFunc := func(l *net.TCPListener, errChan chan error,
		listenChan chan struct{}) {

		listenChan <- struct{}{}

		conn, err := l.Accept()
		if err != nil {
			errChan <- err
			return
		}

		in.AssociateConnection(conn)
		errChan <- nil
	}

	// dialFunc is a function closure that initiates the tcp connection.
	// The tcp connection will be the one the outbound peer uses.
	dialFunc := func(addr *net.TCPAddr) error {
		conn, err := net.Dial("tcp", addr.String())
		if err != nil {
			return err
		}

		out.AssociateConnection(conn)
		return nil
	}

	listenAddr := "localhost:0"

	addr, err := net.ResolveTCPAddr("tcp", listenAddr)
	if err != nil {
		return err
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return err
	}

	errChan := make(chan error, 1)
	listenChan := make(chan struct{}, 1)

	go listenFunc(l, errChan, listenChan)
	<-listenChan

	if err := dialFunc(l.Addr().(*net.TCPAddr)); err != nil {
		return err
	}

	select {
	case err = <-errChan:
		return err
	case <-time.After(time.Second * 2):
		return errors.New("failed to create connection")
	}
}

type brontidePeerConnResult struct {
	conn net.Conn
	err  error
}

func setupBrontidePeerConnection(t *testing.T, in, out *peer.Peer) {
	t.Helper()

	serverPriv, err := brontide.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey server: %v", err)
	}
	clientPriv, err := brontide.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey client: %v", err)
	}

	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ResolveTCPAddr: %v", err)
	}
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer l.Close()

	serverCh := make(chan brontidePeerConnResult, 1)
	go func() {
		rawConn, err := l.Accept()
		if err != nil {
			serverCh <- brontidePeerConnResult{err: err}
			return
		}

		conn, _, err := brontide.ServerHandshake(rawConn, serverPriv)
		if err != nil {
			_ = rawConn.Close()
			serverCh <- brontidePeerConnResult{err: err}
			return
		}
		serverCh <- brontidePeerConnResult{conn: conn}
	}()

	rawClient, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	clientConn, err := brontide.ClientHandshake(
		rawClient, clientPriv, serverPriv.PubKey().SerializeCompressed(),
	)
	if err != nil {
		_ = rawClient.Close()
		t.Fatalf("ClientHandshake: %v", err)
	}

	var server brontidePeerConnResult
	select {
	case server = <-serverCh:
	case <-time.After(2 * time.Second):
		_ = clientConn.Close()
		t.Fatal("ServerHandshake timed out")
	}
	if server.err != nil {
		_ = clientConn.Close()
		t.Fatalf("ServerHandshake: %v", server.err)
	}

	in.SetBrontideConnection(true)
	out.SetBrontideConnection(true)
	in.AssociateConnection(server.conn)
	out.AssociateConnection(clientConn)
}

func TestEncryptedPeerTransportFlow(t *testing.T) {
	verack := make(chan struct{}, 2)
	received := make(chan wire.HnsMsgType, 4)

	inCfg := &peer.Config{
		Listeners: peer.MessageListeners{
			OnVerAck: func(p *peer.Peer, msg *wire.HnsMsgVerack) {
				verack <- struct{}{}
			},
			OnInv: func(p *peer.Peer, msg *wire.HnsMsgInv) {
				received <- msg.Type()
			},
			OnBlock: func(p *peer.Peer, msg *wire.HnsMsgBlock, buf []byte) {
				received <- msg.Type()
			},
			OnTx: func(p *peer.Peer, msg *wire.HnsMsgTx) {
				received <- msg.Type()
			},
			OnHeaders: func(p *peer.Peer, msg *wire.HnsMsgHeaders) {
				received <- msg.Type()
			},
		},
		AllowSelfConns:      true,
		ChainParams:         &chaincfg.MainNetParams,
		DisableStallHandler: true,
		TrickleInterval:     time.Second * 10,
		UserAgentName:       "peer",
		UserAgentVersion:    "1.0",
	}
	outCfg := &peer.Config{
		Listeners: peer.MessageListeners{
			OnVerAck: func(p *peer.Peer, msg *wire.HnsMsgVerack) {
				verack <- struct{}{}
			},
		},
		AllowSelfConns:      true,
		ChainParams:         &chaincfg.MainNetParams,
		DisableStallHandler: true,
		TrickleInterval:     time.Second * 10,
		UserAgentName:       "peer",
		UserAgentVersion:    "1.0",
	}

	inPeer := peer.NewInboundPeer(inCfg)
	outPeer, err := peer.NewOutboundPeer(outCfg, "127.0.0.1:12038")
	if err != nil {
		t.Fatalf("NewOutboundPeer: %v", err)
	}
	setupBrontidePeerConnection(t, inPeer, outPeer)
	defer func() {
		inPeer.Disconnect()
		outPeer.Disconnect()
		inPeer.WaitForDisconnect()
		outPeer.WaitForDisconnect()
	}()

	for i := 0; i < 2; i++ {
		select {
		case <-verack:
		case <-time.After(time.Second):
			t.Fatal("verack timeout")
		}
	}
	if !inPeer.VerAckReceived() || !outPeer.VerAckReceived() {
		t.Fatalf("verack not recorded: inbound=%v outbound=%v",
			inPeer.VerAckReceived(), outPeer.VerAckReceived())
	}
	if !inPeer.StatsSnapshot().V2Connection || !outPeer.StatsSnapshot().V2Connection {
		t.Fatalf("encrypted connection not recorded: inbound=%v outbound=%v",
			inPeer.StatsSnapshot().V2Connection,
			outPeer.StatsSnapshot().V2Connection)
	}

	inv := wire.NewHnsMsgInv()
	if err := inv.AddInvVect(wire.NewInvVect(wire.InvTypeBlock, &chainhash.Hash{})); err != nil {
		t.Fatalf("AddInvVect: %v", err)
	}
	msgs := []wire.HandshakeMessage{
		inv,
		&wire.HnsMsgBlock{Block: *wire.NewMsgBlock(testPeerHeader())},
		&wire.HnsMsgTx{Tx: *wire.NewMsgTx(wire.TxVersion)},
		&wire.HnsMsgHeaders{Headers: []*wire.BlockHeader{testPeerHeader()}},
	}
	for _, msg := range msgs {
		done := make(chan struct{}, 1)
		outPeer.QueueHnsMessage(msg, done)
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatalf("send %s timeout", msg.Type())
		}
	}

	expected := map[wire.HnsMsgType]bool{
		wire.HnsMsgTypeInv:     true,
		wire.HnsMsgTypeBlock:   true,
		wire.HnsMsgTypeTx:      true,
		wire.HnsMsgTypeHeaders: true,
	}
	for i := 0; i < len(msgs); i++ {
		select {
		case msgType := <-received:
			if !expected[msgType] {
				t.Fatalf("unexpected message callback: %s", msgType)
			}
			delete(expected, msgType)
		case <-time.After(time.Second):
			t.Fatalf("message callback timeout; still waiting for %v", expected)
		}
	}
}

func testPeerHeader() *wire.BlockHeader {
	return wire.NewBlockHeader(1, &chainhash.Hash{}, &chainhash.Hash{},
		&chainhash.Hash{}, &chainhash.Hash{}, 1, 1)
}

func testPeerMerkleBlock() *wire.MsgMerkleBlock {
	msg := wire.NewMsgMerkleBlock(testPeerHeader())
	msg.Transactions = 1
	msg.Flags = []byte{0x01}
	return msg
}

// TestNoSendAddrV2Handshake tests that the Handshake version-verack exchange
// does not negotiate Bitcoin's sendaddrv2 message.
func TestNoSendAddrV2Handshake(t *testing.T) {
	verack := make(chan struct{}, 2)
	peer1Cfg := &peer.Config{
		Listeners: peer.MessageListeners{
			OnVerAck: func(p *peer.Peer, msg *wire.HnsMsgVerack) {
				verack <- struct{}{}
			},
		},
		AllowSelfConns: true,
		ChainParams:    &chaincfg.MainNetParams,
	}

	peer2Cfg := &peer.Config{
		Listeners:      peer1Cfg.Listeners,
		AllowSelfConns: true,
		ChainParams:    &chaincfg.MainNetParams,
	}
	newPeer1Cfg := func() *peer.Config {
		cfg := *peer1Cfg
		return &cfg
	}
	newPeer2Cfg := func() *peer.Config {
		cfg := *peer2Cfg
		return &cfg
	}

	verackErr := errors.New("verack timeout")

	tests := []struct {
		name  string
		setup func() (*peer.Peer, *peer.Peer, error)
	}{
		{
			"handshake without sendaddrv2",
			func() (*peer.Peer, *peer.Peer, error) {
				inPeer := peer.NewInboundPeer(newPeer1Cfg())
				outPeer, err := peer.NewOutboundPeer(
					newPeer2Cfg(), "10.0.0.2:8333",
				)
				if err != nil {
					return nil, nil, err
				}

				err = setupPeerConnection(inPeer, outPeer)
				if err != nil {
					return nil, nil, err
				}

				for i := 0; i < 2; i++ {
					select {
					case <-verack:
					case <-time.After(time.Second * 2):
						return nil, nil, verackErr
					}
				}

				return inPeer, outPeer, nil
			},
		},
		{
			"handshake with minimum-version inbound peer",
			func() (*peer.Peer, *peer.Peer, error) {
				inCfg := newPeer1Cfg()
				inCfg.ProtocolVersion = wire.HnsMinProtocolVersion
				inPeer := peer.NewInboundPeer(inCfg)
				outPeer, err := peer.NewOutboundPeer(
					newPeer2Cfg(), "10.0.0.2:8333",
				)
				if err != nil {
					return nil, nil, err
				}

				err = setupPeerConnection(inPeer, outPeer)
				if err != nil {
					return nil, nil, err
				}

				for i := 0; i < 2; i++ {
					select {
					case <-verack:
					case <-time.After(time.Second * 2):
						return nil, nil, verackErr
					}
				}

				return inPeer, outPeer, nil
			},
		},
		{
			"handshake with minimum-version outbound peer",
			func() (*peer.Peer, *peer.Peer, error) {
				inPeer := peer.NewInboundPeer(newPeer1Cfg())
				outCfg := newPeer2Cfg()
				outCfg.ProtocolVersion = wire.HnsMinProtocolVersion
				outPeer, err := peer.NewOutboundPeer(
					outCfg, "10.0.0.2:8333",
				)
				if err != nil {
					return nil, nil, err
				}

				err = setupPeerConnection(inPeer, outPeer)
				if err != nil {
					return nil, nil, err
				}

				for i := 0; i < 2; i++ {
					select {
					case <-verack:
					case <-time.After(time.Second * 2):
						return nil, nil, verackErr
					}
				}

				return inPeer, outPeer, nil
			},
		},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		inPeer, outPeer, err := test.setup()
		if err != nil {
			t.Fatalf("TestNoSendAddrV2Handshake setup #%d: "+
				"unexpected err: %v", i, err)
		}

		inPeer.Disconnect()
		outPeer.Disconnect()
		inPeer.WaitForDisconnect()
		outPeer.WaitForDisconnect()
	}
}
