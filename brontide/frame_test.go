// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package brontide

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	send := newTestCipher(t)
	recv := newTestCipher(t)
	payload := []byte("encrypted handshake packet bytes")

	frame, err := WriteFrame(send, payload)
	if err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	wantLen := HeaderSize + len(payload) + tagSize
	if len(frame) != wantLen {
		t.Fatalf("frame length: got %d, want %d", len(frame), wantLen)
	}

	var plainLen [4]byte
	binary.LittleEndian.PutUint32(plainLen[:], uint32(len(payload)))
	if bytes.Equal(frame[:4], plainLen[:]) {
		t.Fatal("frame length prefix was not encrypted")
	}

	got, err := ReadFrame(recv, frame)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload: got %x, want %x", got, payload)
	}
	if send.Nonce() != 2 {
		t.Fatalf("send nonce: got %d, want 2", send.Nonce())
	}
	if recv.Nonce() != 2 {
		t.Fatalf("recv nonce: got %d, want 2", recv.Nonce())
	}
}

func TestFrameRejectsOversizedPayload(t *testing.T) {
	send := newTestCipher(t)
	payload := make([]byte, MaxMessageSize+1)

	_, err := WriteFrame(send, payload)
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("WriteFrame error: got %v, want %v", err, ErrFrameTooLarge)
	}
	if send.Nonce() != 0 {
		t.Fatalf("send nonce advanced after rejected write: got %d", send.Nonce())
	}
}

func TestFrameRejectsNilCipher(t *testing.T) {
	_, err := WriteFrame(nil, []byte("payload"))
	if !errors.Is(err, ErrInvalidCipher) {
		t.Fatalf("WriteFrame error: got %v, want %v", err, ErrInvalidCipher)
	}

	_, err = ReadFrame(nil, make([]byte, HeaderSize))
	if !errors.Is(err, ErrInvalidCipher) {
		t.Fatalf("ReadFrame error: got %v, want %v", err, ErrInvalidCipher)
	}
}

func TestFrameRejectsTamperedHeader(t *testing.T) {
	send := newTestCipher(t)
	recv := newTestCipher(t)

	frame, err := WriteFrame(send, []byte("payload"))
	if err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	frame[0] ^= 0x01

	_, err = ReadFrame(recv, frame)
	if !errors.Is(err, ErrDecrypt) {
		t.Fatalf("ReadFrame error: got %v, want %v", err, ErrDecrypt)
	}
	if recv.Nonce() != 0 {
		t.Fatalf("recv nonce advanced after failed header decrypt: got %d", recv.Nonce())
	}
}

func TestFrameRejectsTamperedPayload(t *testing.T) {
	send := newTestCipher(t)
	recv := newTestCipher(t)

	frame, err := WriteFrame(send, []byte("payload"))
	if err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	frame[HeaderSize] ^= 0x01

	_, err = ReadFrame(recv, frame)
	if !errors.Is(err, ErrDecrypt) {
		t.Fatalf("ReadFrame error: got %v, want %v", err, ErrDecrypt)
	}
	if recv.Nonce() != 1 {
		t.Fatalf("recv nonce after failed payload decrypt: got %d, want 1", recv.Nonce())
	}
}

func TestFrameRejectsSizeMismatch(t *testing.T) {
	send := newTestCipher(t)
	recv := newTestCipher(t)

	frame, err := WriteFrame(send, []byte("payload"))
	if err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	frame = frame[:len(frame)-1]

	_, err = ReadFrame(recv, frame)
	if !errors.Is(err, ErrFrameSizeMismatch) {
		t.Fatalf("ReadFrame error: got %v, want %v", err, ErrFrameSizeMismatch)
	}
}
