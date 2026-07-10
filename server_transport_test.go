// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"io"
	"net"
	"testing"

	"github.com/blinklabs-io/handshake-node/brontide"
	"github.com/blinklabs-io/handshake-node/chaincfg"
	"github.com/blinklabs-io/handshake-node/wire"
)

func TestWrapInboundConnPlaintext(t *testing.T) {
	oldCfg := cfg
	cfg = &config{BrontideTransport: true}
	defer func() {
		cfg = oldCfg
	}()

	priv, err := brontide.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	s := &server{
		chainParams:      &chaincfg.RegressionNetParams,
		brontideIdentity: priv,
	}

	local, remote := net.Pipe()
	defer local.Close()

	type result struct {
		conn      net.Conn
		encrypted bool
		err       error
	}
	resultChan := make(chan result, 1)
	go func() {
		conn, encrypted, err := s.wrapInboundConn(remote)
		resultChan <- result{conn: conn, encrypted: encrypted, err: err}
	}()

	msg := &wire.HnsMsgVersion{
		Version:  wire.HnsProtocolVersion,
		Services: uint64(wire.SFNodeNetwork),
		Agent:    wire.DefaultUserAgent,
	}
	writeErr := make(chan error, 1)
	go func() {
		_, err := wire.WriteHnsMessageN(local, msg, chaincfg.RegressionNetParams.Net)
		writeErr <- err
	}()

	res := <-resultChan
	if res.err != nil {
		t.Fatalf("wrapInboundConn: %v", res.err)
	}
	if res.encrypted {
		t.Fatal("plaintext connection reported as Brontide")
	}
	defer res.conn.Close()

	_, got, _, err := wire.ReadHnsMessageN(res.conn, chaincfg.RegressionNetParams.Net)
	if err != nil {
		t.Fatalf("ReadHnsMessageN: %v", err)
	}
	if _, ok := got.(*wire.HnsMsgVersion); !ok {
		t.Fatalf("message type: got %T, want *wire.HnsMsgVersion", got)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("WriteHnsMessageN: %v", err)
	}
}

func TestWithBrontideKey(t *testing.T) {
	addr := &net.TCPAddr{
		IP:   net.IPv4(203, 0, 113, 9),
		Port: 12038,
	}
	key := make([]byte, wire.HnsBrontideKeySize)
	for i := range key {
		key[i] = byte(i + 1)
	}

	wrapped := withBrontideKey(addr, key)
	keyed, ok := wrapped.(brontideKeyAddr)
	if !ok {
		t.Fatal("wrapped address does not expose a brontide key")
	}
	if !bytes.Equal(keyed.BrontideKey(), key) {
		t.Fatalf("key: got %x, want %x", keyed.BrontideKey(), key)
	}
	if wrapped.Network() != addr.Network() || wrapped.String() != addr.String() {
		t.Fatalf("wrapped address changed identity: got %s %s, want %s %s",
			wrapped.Network(), wrapped.String(), addr.Network(), addr.String())
	}

	key[0] ^= 0xff
	if bytes.Equal(keyed.BrontideKey(), key) {
		t.Fatal("wrapped address retained mutable key storage")
	}
}

func TestWrapInboundConnBrontide(t *testing.T) {
	oldCfg := cfg
	cfg = &config{BrontideTransport: true}
	defer func() {
		cfg = oldCfg
	}()

	serverPriv, err := brontide.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey server: %v", err)
	}
	clientPriv, err := brontide.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey client: %v", err)
	}
	serverPub, err := brontide.IdentityStaticKey(serverPriv)
	if err != nil {
		t.Fatalf("IdentityStaticKey: %v", err)
	}

	s := &server{
		chainParams:      &chaincfg.RegressionNetParams,
		brontideIdentity: serverPriv,
	}

	local, remote := net.Pipe()
	defer local.Close()

	type result struct {
		conn      net.Conn
		encrypted bool
		err       error
	}
	resultChan := make(chan result, 1)
	go func() {
		conn, encrypted, err := s.wrapInboundConn(remote)
		resultChan <- result{conn: conn, encrypted: encrypted, err: err}
	}()

	clientConn, err := brontide.ClientHandshake(local, clientPriv, serverPub)
	if err != nil {
		t.Fatalf("ClientHandshake: %v", err)
	}
	defer clientConn.Close()

	res := <-resultChan
	if res.err != nil {
		t.Fatalf("wrapInboundConn: %v", res.err)
	}
	if !res.encrypted {
		t.Fatal("Brontide connection reported as plaintext")
	}
	defer res.conn.Close()

	want := []byte("ping")
	readResult := make(chan []byte, 1)
	readErr := make(chan error, 1)
	go func() {
		got := make([]byte, len(want))
		_, err := io.ReadFull(res.conn, got)
		if err != nil {
			readErr <- err
			return
		}
		readResult <- got
	}()

	if _, err := clientConn.Write(want); err != nil {
		t.Fatalf("brontide client write: %v", err)
	}

	var got []byte
	select {
	case err := <-readErr:
		t.Fatalf("brontide server read: %v", err)
	case got = <-readResult:
	}
	if string(got) != string(want) {
		t.Fatalf("payload: got %q, want %q", got, want)
	}
}
