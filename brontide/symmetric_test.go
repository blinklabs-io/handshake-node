// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package brontide

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestSymmetricStateInitAndMixHash(t *testing.T) {
	s := NewSymmetricState()
	want := sha256.Sum256([]byte(ProtocolName))

	if s.Digest() != want {
		t.Fatalf("digest: got %x, want %x", s.Digest(), want)
	}
	if s.ChainKey() != want {
		t.Fatalf("chain key: got %x, want %x", s.ChainKey(), want)
	}

	s.MixHash([]byte(Prologue))
	h := sha256.New()
	_, _ = h.Write(want[:])
	_, _ = h.Write([]byte(Prologue))
	var expected [keySize]byte
	copy(expected[:], h.Sum(nil))

	if s.Digest() != expected {
		t.Fatalf("mixed digest: got %x, want %x", s.Digest(), expected)
	}
}

func TestSymmetricStateInitShortProtocolName(t *testing.T) {
	const protocolName = "Noise_NN_25519_AESGCM_SHA256"

	s := &SymmetricState{}
	s.InitSymmetric(protocolName)

	var want [keySize]byte
	copy(want[:], protocolName)

	if s.Digest() != want {
		t.Fatalf("digest: got %x, want zero-padded %x", s.Digest(), want)
	}
	if s.ChainKey() != want {
		t.Fatalf("chain key: got %x, want zero-padded %x", s.ChainKey(), want)
	}
}

func TestSymmetricStateEncryptDecryptHash(t *testing.T) {
	send := NewSymmetricState()
	recv := NewSymmetricState()
	secret := testKey(0x30)
	send.MixKey(secret)
	recv.MixKey(secret)

	ciphertext, tag, err := send.EncryptHash([]byte("handshake-data"))
	if err != nil {
		t.Fatalf("EncryptHash: %v", err)
	}
	if bytes.Equal(ciphertext, []byte("handshake-data")) {
		t.Fatal("ciphertext unexpectedly matches plaintext")
	}

	plaintext, err := recv.DecryptHash(ciphertext, tag)
	if err != nil {
		t.Fatalf("DecryptHash: %v", err)
	}
	if string(plaintext) != "handshake-data" {
		t.Fatalf("plaintext: got %q", plaintext)
	}
	if send.Digest() != recv.Digest() {
		t.Fatalf("digest mismatch: send %x recv %x", send.Digest(), recv.Digest())
	}
	if send.ChainKey() != recv.ChainKey() {
		t.Fatalf("chain mismatch: send %x recv %x", send.ChainKey(), recv.ChainKey())
	}
}

func TestSymmetricStateSplitCiphers(t *testing.T) {
	initiator := NewSymmetricState()
	responder := NewSymmetricState()

	secret1 := testKey(0x10)
	secret2 := testKey(0x50)
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

	frame, err := WriteFrame(initSend, []byte("from initiator"))
	if err != nil {
		t.Fatalf("WriteFrame initiator: %v", err)
	}
	got, err := ReadFrame(respRecv, frame)
	if err != nil {
		t.Fatalf("ReadFrame responder: %v", err)
	}
	if string(got) != "from initiator" {
		t.Fatalf("responder got %q", got)
	}

	frame, err = WriteFrame(respSend, []byte("from responder"))
	if err != nil {
		t.Fatalf("WriteFrame responder: %v", err)
	}
	got, err = ReadFrame(initRecv, frame)
	if err != nil {
		t.Fatalf("ReadFrame initiator: %v", err)
	}
	if string(got) != "from responder" {
		t.Fatalf("initiator got %q", got)
	}
}
