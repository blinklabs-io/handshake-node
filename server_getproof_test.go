// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"net"
	"testing"
	"time"

	"github.com/blinklabs-io/handshake-node/chaincfg"
	"github.com/blinklabs-io/handshake-node/netsync"
	"github.com/blinklabs-io/handshake-node/wire"
)

func startGetProofTestSyncManager(t *testing.T, sp *serverPeer) {
	t.Helper()

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
	t.Cleanup(func() {
		if err := syncManager.Stop(); err != nil {
			t.Errorf("syncManager.Stop: %v", err)
		}
	})
}

func TestOnGetProofRateLimitRunsBeforeProofBuild(t *testing.T) {
	oldCfg := cfg
	cfg = &config{DisableBanning: true}
	t.Cleanup(func() {
		cfg = oldCfg
	})

	_, sp, teardown := newGetDataTestServer(t)
	t.Cleanup(teardown)
	sp.proofRequests = newProofRequestWindow(3)
	startGetProofTestSyncManager(t, sp)

	remote, cleanup := connectServerTestPeer(t, sp)
	t.Cleanup(cleanup)
	request := &wire.HnsMsgGetProof{}

	for i := 0; i < 2; i++ {
		request.Key[0] = byte(i)
		sp.OnGetProof(sp.Peer, request)
		if _, ok := readServerTestPeerMessage(t, remote).(*wire.HnsMsgProof); !ok {
			t.Fatalf("response %d was not a proof", i+1)
		}
	}

	// A rate-limited request must return before touching the chain. This
	// turns an ordering regression into a deterministic nil dereference.
	sp.server.chain = nil
	sp.OnGetProof(sp.Peer, request)

	if err := remote.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	_, _, _, err := wire.ReadHandshakeMessageN(remote,
		chaincfg.RegressionNetParams.Net)
	if err == nil {
		t.Fatal("rate-limited request received a response")
	}
	netErr, ok := err.(net.Error)
	if !ok || !netErr.Timeout() {
		t.Fatalf("reading rate-limited response: got %v, want timeout", err)
	}
}

func TestOnGetProofRateLimitBansPeer(t *testing.T) {
	oldCfg := cfg
	cfg = &config{}
	t.Cleanup(func() {
		cfg = oldCfg
	})

	_, sp, teardown := newGetDataTestServer(t)
	t.Cleanup(teardown)
	sp.server.banPeers = make(chan *serverPeer, 1)
	sp.proofRequests = newProofRequestWindow(1)
	startGetProofTestSyncManager(t, sp)

	_, cleanup := connectServerTestPeer(t, sp)
	t.Cleanup(cleanup)
	sp.OnGetProof(sp.Peer, &wire.HnsMsgGetProof{})

	select {
	case banned := <-sp.server.banPeers:
		if banned != sp {
			t.Fatalf("banned peer = %p, want %p", banned, sp)
		}
	case <-time.After(time.Second):
		t.Fatal("rate-limited peer was not banned")
	}
	if sp.Connected() {
		t.Fatal("rate-limited peer remained connected")
	}
}
