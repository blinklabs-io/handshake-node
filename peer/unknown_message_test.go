// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package peer_test

import (
	"testing"
	"time"

	"github.com/blinklabs-io/handshake-node/chaincfg"
	"github.com/blinklabs-io/handshake-node/peer"
	"github.com/blinklabs-io/handshake-node/wire"
)

type futureHnsMessage struct {
	payload []byte
}

func (*futureHnsMessage) Type() wire.HnsMsgType {
	return wire.HnsMsgType(31)
}

func (m *futureHnsMessage) Encode() []byte {
	return append([]byte(nil), m.payload...)
}

func (*futureHnsMessage) Decode([]byte) error {
	return nil
}

func TestPeerIgnoresFutureHnsMessage(t *testing.T) {
	verack := make(chan struct{}, 2)
	ping := make(chan uint64, 1)

	inCfg := &peer.Config{
		Listeners: peer.MessageListeners{
			OnVerAck: func(*peer.Peer, *wire.HnsMsgVerack) {
				verack <- struct{}{}
			},
			OnPing: func(_ *peer.Peer, msg *wire.HnsMsgPing) {
				ping <- msg.NonceUint64()
			},
		},
		UserAgentName:       "peer",
		UserAgentVersion:    "1.0",
		ChainParams:         &chaincfg.MainNetParams,
		Services:            wire.SFNodeNetwork,
		AllowSelfConns:      true,
		TrickleInterval:     10 * time.Second,
		DisableStallHandler: true,
	}
	outCfg := &peer.Config{
		Listeners: peer.MessageListeners{
			OnVerAck: func(*peer.Peer, *wire.HnsMsgVerack) {
				verack <- struct{}{}
			},
		},
		UserAgentName:       "peer",
		UserAgentVersion:    "1.0",
		ChainParams:         &chaincfg.MainNetParams,
		Services:            wire.SFNodeNetwork,
		AllowSelfConns:      true,
		TrickleInterval:     10 * time.Second,
		DisableStallHandler: true,
	}

	inPeer := peer.NewInboundPeer(inCfg)
	outPeer, err := peer.NewOutboundPeer(outCfg, "127.0.0.1:12038")
	if err != nil {
		t.Fatalf("NewOutboundPeer: %v", err)
	}
	if err := setupPeerConnection(inPeer, outPeer); err != nil {
		t.Fatalf("setupPeerConnection: %v", err)
	}
	t.Cleanup(func() {
		inPeer.Disconnect()
		outPeer.Disconnect()
		inPeer.WaitForDisconnect()
		outPeer.WaitForDisconnect()
	})

	for range 2 {
		select {
		case <-verack:
		case <-time.After(time.Second):
			t.Fatal("verack timeout")
		}
	}

	futureDone := make(chan struct{}, 1)
	outPeer.QueueHnsMessage(&futureHnsMessage{payload: []byte{1, 2, 3}}, futureDone)
	select {
	case <-futureDone:
	case <-time.After(time.Second):
		t.Fatal("future message send timeout")
	}

	const nonce = uint64(0x1122334455667788)
	pingDone := make(chan struct{}, 1)
	outPeer.QueueHnsMessage(wire.NewHnsMsgPing(nonce), pingDone)
	select {
	case <-pingDone:
	case <-time.After(time.Second):
		t.Fatal("ping send timeout")
	}

	select {
	case got := <-ping:
		if got != nonce {
			t.Fatalf("ping nonce: got %#x, want %#x", got, nonce)
		}
	case <-time.After(time.Second):
		t.Fatalf("ping timeout after future packet: inbound connected=%v",
			inPeer.Connected())
	}
}
