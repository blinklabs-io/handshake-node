// Copyright (c) 2025-2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"errors"
	"testing"
)

const testHnsMagic uint32 = 0x5b6ef2d3 // mainnet

func TestHnsMsgHeaderRoundTrip(t *testing.T) {
	in := hnsMsgHeader{
		NetworkMagic:  testHnsMagic,
		MessageType:   HnsMsgTypePing,
		PayloadLength: 8,
	}
	encoded := in.Encode()
	if len(encoded) != HnsMessageHeaderSize {
		t.Fatalf("header size: got %d, want %d", len(encoded), HnsMessageHeaderSize)
	}

	var out hnsMsgHeader
	if err := out.Decode(encoded); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if out != in {
		t.Fatalf("round-trip mismatch:\n got %+v\nwant %+v", out, in)
	}
}

func TestHnsMsgHeaderDecodeWrongSize(t *testing.T) {
	var h hnsMsgHeader
	if err := h.Decode(make([]byte, HnsMessageHeaderSize-1)); err == nil {
		t.Fatal("expected error for short header, got nil")
	}
	if err := h.Decode(make([]byte, HnsMessageHeaderSize+1)); err == nil {
		t.Fatal("expected error for long header, got nil")
	}
}

func TestHnsMsgEnvelopeRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		msg  HandshakeMessage
	}{
		{"verack", &HnsMsgVerack{}},
		{"ping", &HnsMsgPing{Nonce: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}}},
		{"pong", &HnsMsgPong{Nonce: [8]byte{8, 7, 6, 5, 4, 3, 2, 1}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := EncodeHnsMessage(tc.msg, testHnsMagic)
			if err != nil {
				t.Fatalf("EncodeHnsMessage: %v", err)
			}
			decoded, magic, err := DecodeHnsMessage(encoded)
			if err != nil {
				t.Fatalf("DecodeHnsMessage: %v", err)
			}
			if magic != testHnsMagic {
				t.Errorf("magic: got %#x, want %#x", magic, testHnsMagic)
			}
			if decoded.Type() != tc.msg.Type() {
				t.Errorf("type: got %d, want %d", decoded.Type(), tc.msg.Type())
			}
			a := tc.msg.Encode()
			b := decoded.Encode()
			if !bytes.Equal(a, b) {
				t.Errorf("payload mismatch:\n got % x\nwant % x", b, a)
			}
		})
	}
}

func TestHnsMsgEnvelopeOnTheWireLayout(t *testing.T) {
	// Verify the on-wire byte layout for a Ping with a known nonce. This
	// pins the envelope format so future refactors can't silently change
	// it.
	ping := &HnsMsgPing{Nonce: [8]byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04}}
	got, err := EncodeHnsMessage(ping, testHnsMagic)
	if err != nil {
		t.Fatalf("EncodeHnsMessage: %v", err)
	}
	want := []byte{
		// Network magic 0x5b6ef2d3, little-endian
		0xd3, 0xf2, 0x6e, 0x5b,
		// Message type: Ping = 2
		0x02,
		// Payload length: 8, little-endian
		0x08, 0x00, 0x00, 0x00,
		// Nonce
		0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("wire layout mismatch:\n got % x\nwant % x", got, want)
	}
}

func TestHnsMsgDecodeUnsupportedType(t *testing.T) {
	header := hnsMsgHeader{
		NetworkMagic:  testHnsMagic,
		MessageType:   HnsMsgTypeUnknown,
		PayloadLength: 0,
	}
	encoded := header.Encode()
	_, _, err := DecodeHnsMessage(encoded)
	var typErr UnsupportedHnsMsgTypeError
	if !errors.As(err, &typErr) {
		t.Fatalf("expected UnsupportedHnsMsgTypeError, got %v", err)
	}
	if typErr.MessageType != HnsMsgTypeUnknown {
		t.Errorf("error type: got %d, want %d", typErr.MessageType, HnsMsgTypeUnknown)
	}
}

func TestHnsMsgDecodeShortData(t *testing.T) {
	if _, _, err := DecodeHnsMessage(nil); err == nil {
		t.Fatal("expected error decoding nil data")
	}
	if _, _, err := DecodeHnsMessage(make([]byte, HnsMessageHeaderSize-1)); err == nil {
		t.Fatal("expected error decoding short data")
	}
}

func TestHnsMsgDecodePayloadLengthMismatch(t *testing.T) {
	// Header advertises 8-byte payload but we only supply 4 bytes.
	header := hnsMsgHeader{
		NetworkMagic:  testHnsMagic,
		MessageType:   HnsMsgTypePing,
		PayloadLength: 8,
	}
	short := append(header.Encode(), 0x01, 0x02, 0x03, 0x04)
	if _, _, err := DecodeHnsMessage(short); err == nil {
		t.Fatal("expected error for payload length mismatch")
	}
}

func TestHnsMsgEncodeRejectsOversizedPayload(t *testing.T) {
	// Construct a fake message whose payload exceeds the cap, to exercise
	// the encode-side bound check.
	big := &oversizedHnsMsg{size: HnsMaxMessagePayload + 1}
	if _, err := EncodeHnsMessage(big, testHnsMagic); err == nil {
		t.Fatal("expected error for oversized payload")
	}
}

type oversizedHnsMsg struct{ size int }

func (*oversizedHnsMsg) Type() HnsMsgType      { return HnsMsgTypeUnknown }
func (m *oversizedHnsMsg) Encode() []byte      { return make([]byte, m.size) }
func (*oversizedHnsMsg) Decode(_ []byte) error { return nil }
