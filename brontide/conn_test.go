// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package brontide

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
)

func newTestConnPair(t *testing.T) (*Conn, *Conn) {
	t.Helper()

	initiator := NewSymmetricState()
	responder := NewSymmetricState()
	secret1 := testKey(0x11)
	secret2 := testKey(0x55)
	initiator.MixKey(secret1)
	responder.MixKey(secret1)
	initiator.MixKey(secret2)
	responder.MixKey(secret2)

	initSend, initRecv, err := initiator.Split(true)
	if err != nil {
		t.Fatalf("initiator Split: %v", err)
	}
	respSend, respRecv, err := responder.Split(false)
	if err != nil {
		t.Fatalf("responder Split: %v", err)
	}

	clientRaw, serverRaw := net.Pipe()
	t.Cleanup(func() {
		_ = clientRaw.Close()
		_ = serverRaw.Close()
	})

	client, err := NewConn(clientRaw, initSend, initRecv)
	if err != nil {
		t.Fatalf("NewConn client: %v", err)
	}
	server, err := NewConn(serverRaw, respSend, respRecv)
	if err != nil {
		t.Fatalf("NewConn server: %v", err)
	}
	return client, server
}

func TestConnRoundTrip(t *testing.T) {
	client, server := newTestConnPair(t)
	payload := []byte("hello over brontide")

	errc := make(chan error, 1)
	go func() {
		_, err := client.Write(payload)
		errc <- err
	}()

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatalf("server ReadFull: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("client Write: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload: got %x, want %x", got, payload)
	}
}

func TestConnBuffersPartialFrameReads(t *testing.T) {
	client, server := newTestConnPair(t)

	errc := make(chan error, 1)
	go func() {
		_, err := client.Write([]byte("abcdef"))
		errc <- err
	}()

	first := make([]byte, 2)
	n, err := server.Read(first)
	if err != nil {
		t.Fatalf("first Read: %v", err)
	}
	if n != 2 || string(first) != "ab" {
		t.Fatalf("first read: n=%d data=%q", n, first)
	}

	second := make([]byte, 4)
	n, err = server.Read(second)
	if err != nil {
		t.Fatalf("second Read: %v", err)
	}
	if n != 4 || string(second) != "cdef" {
		t.Fatalf("second read: n=%d data=%q", n, second)
	}

	if err := <-errc; err != nil {
		t.Fatalf("client Write: %v", err)
	}
}

func TestConnRejectsNilInputs(t *testing.T) {
	send := newTestCipher(t)
	recv := newTestCipher(t)
	rawClient, rawServer := net.Pipe()
	defer rawClient.Close()
	defer rawServer.Close()

	if _, err := NewConn(nil, send, recv); !errors.Is(err, ErrInvalidConn) {
		t.Fatalf("nil connection error: got %v, want %v", err, ErrInvalidConn)
	}
	if _, err := NewConn(rawClient, nil, recv); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("nil send cipher error: got %v, want %v", err, ErrInvalidKey)
	}
	if _, err := NewConn(rawServer, send, nil); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("nil receive cipher error: got %v, want %v", err, ErrInvalidKey)
	}
}

func TestConnWriteFailureClosesConnection(t *testing.T) {
	client, server := newTestConnPair(t)
	_ = server.Close()

	_, err := client.Write([]byte("payload"))
	if err == nil {
		t.Fatal("expected write failure")
	}
	if client.send.Nonce() != 2 {
		t.Fatalf("send nonce after failed frame write: got %d, want 2", client.send.Nonce())
	}

	_, secondErr := client.Write([]byte("retry"))
	if secondErr == nil {
		t.Fatal("expected second write to fail")
	}
	if client.send.Nonce() != 2 {
		t.Fatalf("send nonce advanced on retry after failure: got %d, want 2", client.send.Nonce())
	}
}

func TestConnBodyReadFailureClosesConnection(t *testing.T) {
	readerRaw, writerRaw := net.Pipe()
	defer writerRaw.Close()

	recv := newTestCipher(t)
	send := newTestCipher(t)
	reader, err := NewConn(readerRaw, newTestCipher(t), recv)
	if err != nil {
		t.Fatalf("NewConn: %v", err)
	}

	frame, err := WriteFrame(send, []byte("payload"))
	if err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	errc := make(chan error, 1)
	go func() {
		_, err := writerRaw.Write(frame[:HeaderSize])
		if err == nil {
			err = writerRaw.Close()
		}
		errc <- err
	}()

	buf := make([]byte, len("payload"))
	_, err = reader.Read(buf)
	if err == nil {
		t.Fatal("expected body read failure")
	}
	if err := <-errc; err != nil {
		t.Fatalf("writer: %v", err)
	}
	if recv.Nonce() != 1 {
		t.Fatalf("recv nonce after header decrypt: got %d, want 1", recv.Nonce())
	}

	_, secondErr := reader.Read(buf)
	if secondErr == nil {
		t.Fatal("expected second read to fail")
	}
	if recv.Nonce() != 1 {
		t.Fatalf("recv nonce advanced on retry after failure: got %d, want 1", recv.Nonce())
	}
}
