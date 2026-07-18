// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/blinklabs-io/handshake-node/chaincfg"
	"github.com/blinklabs-io/handshake-node/connmgr"
	"github.com/blinklabs-io/handshake-node/peer"
	"github.com/blinklabs-io/handshake-node/wire"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btclog"
)

type inboundAdmissionTestConn struct {
	net.Conn
	remoteAddr net.Addr
}

type inboundAdmissionDeadlineErrorConn struct {
	*inboundAdmissionTestConn
}

func (*inboundAdmissionDeadlineErrorConn) SetReadDeadline(time.Time) error {
	return errors.New("test read deadline failure")
}

func init() {
	// The main package wires peer logging to the process log rotator, which is
	// intentionally not initialized by unit tests.
	peer.DisableLog()
	connmgr.DisableLog()
}

func (c *inboundAdmissionTestConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func waitForInboundSlots(t *testing.T, slots chan struct{}, want int) {
	t.Helper()
	deadline := time.After(time.Second)
	for len(slots) != want {
		select {
		case <-deadline:
			t.Fatalf("inbound slot count = %d, want %d", len(slots), want)
		case <-time.After(time.Millisecond):
		}
	}
}

func startStalledInboundPeerFrom(t *testing.T, s *server,
	remoteAddr *net.TCPAddr) net.Conn {

	t.Helper()
	client, serverConn := net.Pipe()
	wrapped := &inboundAdmissionTestConn{
		Conn:       serverConn,
		remoteAddr: remoteAddr,
	}
	if !s.admitInboundPeer(wrapped) {
		_ = wrapped.Close()
		t.Fatal("stalled inbound peer was unexpectedly rejected")
	}
	go s.inboundPeerConnected(wrapped)

	version := &wire.HnsMsgVersion{
		Version:  wire.HnsProtocolVersion,
		Services: uint64(wire.SFNodeNetwork),
		Agent:    wire.DefaultUserAgent,
	}
	encoded, err := wire.EncodeHnsMessage(version,
		uint32(chaincfg.RegressionNetParams.Net))
	if err != nil {
		t.Fatalf("EncodeHnsMessage: %v", err)
	}
	if _, err := client.Write(encoded[:wire.HnsMessageHeaderSize]); err != nil {
		t.Fatalf("write partial version: %v", err)
	}
	return client
}

func startStalledInboundPeer(t *testing.T, s *server, host byte) net.Conn {
	t.Helper()
	return startStalledInboundPeerFrom(t, s, &net.TCPAddr{
		IP:   net.IPv4(192, 0, 2, host),
		Port: 12038,
	})
}

func TestInboundAdmissionBoundsPartialVersionPeers(t *testing.T) {
	oldCfg := cfg
	oldSrvrLog := srvrLog
	cfg = &config{}
	srvrLog = btclog.Disabled
	t.Cleanup(func() {
		cfg = oldCfg
		srvrLog = oldSrvrLog
	})

	const maxPeers = 2
	s := &server{
		chainParams:      &chaincfg.RegressionNetParams,
		inboundSlots:     make(chan struct{}, maxPeers),
		inboundPeersByIP: make(map[string]int),
		maxInboundPerIP:  defaultMaxInboundPerIP,
		donePeers:        make(chan *serverPeer, maxPeers+1),
	}

	first := startStalledInboundPeer(t, s, 1)
	t.Cleanup(func() { _ = first.Close() })
	second := startStalledInboundPeer(t, s, 2)
	t.Cleanup(func() { _ = second.Close() })
	waitForInboundSlots(t, s.inboundSlots, maxPeers)

	// A connection above maxpeers is rejected before it can enter transport or
	// protocol negotiation.
	excessClient, excessServer := net.Pipe()
	excess := &inboundAdmissionTestConn{
		Conn: excessServer,
		remoteAddr: &net.TCPAddr{
			IP:   net.IPv4(192, 0, 2, 3),
			Port: 12038,
		},
	}
	if s.admitInboundPeer(excess) {
		t.Fatal("connection above maxpeers was admitted")
	}
	_ = excess.Close()
	if err := excessClient.SetReadDeadline(time.Now().Add(time.Second)); err == nil {
		if _, err := excessClient.Read(make([]byte, 1)); err == nil {
			t.Fatal("connection above maxpeers remained open")
		}
	}
	_ = excessClient.Close()
	if got := len(s.inboundSlots); got != maxPeers {
		t.Fatalf("inbound slot count after rejection = %d, want %d", got, maxPeers)
	}

	// Closing a stalled negotiation releases its slot so a replacement can be
	// admitted without waiting for the 30-second negotiation timeout.
	if err := first.Close(); err != nil {
		t.Fatalf("close first peer: %v", err)
	}
	waitForInboundSlots(t, s.inboundSlots, maxPeers-1)
	replacement := startStalledInboundPeer(t, s, 4)
	t.Cleanup(func() { _ = replacement.Close() })
	waitForInboundSlots(t, s.inboundSlots, maxPeers)

	_ = second.Close()
	_ = replacement.Close()
	waitForInboundSlots(t, s.inboundSlots, 0)

	// Transport setup failures also close the raw socket and release both
	// admission counters before returning.
	identity, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatalf("btcec.NewPrivateKey: %v", err)
	}
	cfg.BrontideTransport = true
	s.brontideIdentity = identity
	failureClient, failureServer := net.Pipe()
	failure := &inboundAdmissionDeadlineErrorConn{
		inboundAdmissionTestConn: &inboundAdmissionTestConn{
			Conn: failureServer,
			remoteAddr: &net.TCPAddr{
				IP:   net.IPv4(192, 0, 2, 5),
				Port: 12038,
			},
		},
	}
	if !s.admitInboundPeer(failure) {
		t.Fatal("transport failure connection was unexpectedly rejected")
	}
	s.inboundPeerConnected(failure)
	if err := failureClient.SetReadDeadline(time.Now().Add(time.Second)); err == nil {
		if _, err := failureClient.Read(make([]byte, 1)); err == nil {
			t.Fatal("connection remained open after transport setup failure")
		}
	}
	_ = failureClient.Close()
	if got := len(s.inboundSlots); got != 0 {
		t.Fatalf("inbound slots after transport setup failure = %d, want 0", got)
	}
	s.inboundPeersMtx.Lock()
	count := len(s.inboundPeersByIP)
	s.inboundPeersMtx.Unlock()
	if count != 0 {
		t.Fatalf("inbound per-IP entries after transport setup failure = %d, want 0",
			count)
	}
}

func TestInboundAdmissionLimitsSingleIP(t *testing.T) {
	oldCfg := cfg
	oldSrvrLog := srvrLog
	_, whitelistedNet, err := net.ParseCIDR("192.0.2.0/24")
	if err != nil {
		t.Fatalf("net.ParseCIDR: %v", err)
	}
	cfg = &config{whitelists: []*net.IPNet{whitelistedNet}}
	srvrLog = btclog.Disabled
	t.Cleanup(func() {
		cfg = oldCfg
		srvrLog = oldSrvrLog
	})

	const maxPeers = defaultMaxInboundPerIP + 1
	s := &server{
		chainParams:      &chaincfg.RegressionNetParams,
		inboundSlots:     make(chan struct{}, maxPeers),
		inboundPeersByIP: make(map[string]int),
		maxInboundPerIP:  defaultMaxInboundPerIP,
		donePeers:        make(chan *serverPeer, maxPeers),
	}

	clients := make([]net.Conn, 0, defaultMaxInboundPerIP)
	for i := 0; i < defaultMaxInboundPerIP; i++ {
		client := startStalledInboundPeerFrom(t, s,
			&net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 12038 + i})
		t.Cleanup(func() { _ = client.Close() })
		clients = append(clients, client)
	}
	waitForInboundSlots(t, s.inboundSlots, defaultMaxInboundPerIP)

	excessClient, excessServer := net.Pipe()
	excess := &inboundAdmissionTestConn{
		Conn: excessServer,
		remoteAddr: &net.TCPAddr{
			IP:   net.IPv4(192, 0, 2, 1),
			Port: 13000,
		},
	}
	if s.admitInboundPeer(excess) {
		t.Fatal("connection above per-IP limit was admitted for whitelisted source")
	}
	_ = excess.Close()
	if err := excessClient.SetReadDeadline(time.Now().Add(time.Second)); err == nil {
		if _, err := excessClient.Read(make([]byte, 1)); err == nil {
			t.Fatal("connection above per-IP limit remained open")
		}
	}
	_ = excessClient.Close()
	if got := len(s.inboundSlots); got != defaultMaxInboundPerIP {
		t.Fatalf("inbound slot count after per-IP rejection = %d, want %d",
			got, defaultMaxInboundPerIP)
	}

	for _, client := range clients {
		_ = client.Close()
	}
	waitForInboundSlots(t, s.inboundSlots, 0)
	s.inboundPeersMtx.Lock()
	count := len(s.inboundPeersByIP)
	s.inboundPeersMtx.Unlock()
	if count != 0 {
		t.Fatalf("inbound per-IP entries after disconnect = %d, want 0", count)
	}
}

func TestServerConnManagerWiresInboundPreflight(t *testing.T) {
	oldSrvrLog := srvrLog
	srvrLog = btclog.Disabled
	t.Cleanup(func() { srvrLog = oldSrvrLog })

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	s := &server{
		inboundSlots:     make(chan struct{}, 1),
		inboundPeersByIP: make(map[string]int),
		maxInboundPerIP:  defaultMaxInboundPerIP,
	}
	// Saturate the server admission gate before the connection manager sees
	// the test connection.
	s.inboundSlots <- struct{}{}
	managerConfig := s.connManagerConfig([]net.Listener{listener}, 1, nil)
	if managerConfig.OnAcceptPreflight == nil || managerConfig.OnAccept == nil {
		t.Fatal("server connection manager omitted inbound admission callbacks")
	}
	accepted := make(chan struct{}, 1)
	managerConfig.OnAccept = func(conn net.Conn) {
		accepted <- struct{}{}
		_ = conn.Close()
	}
	manager, err := connmgr.New(managerConfig)
	if err != nil {
		t.Fatalf("connmgr.New: %v", err)
	}
	manager.Start()
	t.Cleanup(func() {
		manager.Stop()
		manager.Wait()
	})

	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("net.Dial: %v", err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("client.Close: %v", err)
		}
	})
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("preflight-rejected connection remained open")
	}
	select {
	case <-accepted:
		t.Fatal("preflight-rejected connection reached OnAccept")
	default:
	}
	if got := len(s.inboundSlots); got != 1 {
		t.Fatalf("inbound slots after preflight rejection = %d, want 1", got)
	}
	s.inboundPeersMtx.Lock()
	perIP := len(s.inboundPeersByIP)
	s.inboundPeersMtx.Unlock()
	if perIP != 0 {
		t.Fatalf("per-IP entries after preflight rejection = %d, want 0", perIP)
	}
}

func TestNewPeerConfigUsesP2PResourceSettings(t *testing.T) {
	oldCfg := cfg
	const writeTimeout = 7 * time.Minute
	cfg = &config{P2PWriteTimeout: writeTimeout}
	t.Cleanup(func() { cfg = oldCfg })

	budget := peer.NewOutboundQueueBudget(1024)
	s := &server{outboundQueueBudget: budget}
	sp := newServerPeer(s, false)
	peerCfg := newPeerConfig(sp)
	if peerCfg.WriteTimeout != writeTimeout {
		t.Fatalf("peer write timeout = %v, want %v",
			peerCfg.WriteTimeout, writeTimeout)
	}
	if peerCfg.OutboundQueueBudget != budget {
		t.Fatal("peer did not receive server outbound queue budget")
	}
	if peerCfg.Listeners.OnWrite != nil {
		t.Fatal("server peer enabled allocation-heavy concrete OnWrite callback")
	}
	if peerCfg.Listeners.OnWriteType == nil {
		t.Fatal("server peer did not configure allocation-free write metrics")
	}
}
