// Copyright (c) 2025-2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"errors"
	"math"
	"net"
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
		{"getaddr", &HnsMsgGetAddr{}},
		{"addr", &HnsMsgAddr{Peers: testHnsAddrPeers()}},
		{"getdata", &HnsMsgGetData{Inventory: testHnsInventory()}},
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

func TestHnsMsgGetAddrRejectsPayload(t *testing.T) {
	var msg HnsMsgGetAddr
	if err := msg.Decode([]byte{0x00}); err == nil {
		t.Fatal("expected error for non-empty getaddr payload")
	}
}

func TestHnsMsgAddrRoundTrip(t *testing.T) {
	in := HnsMsgAddr{Peers: testHnsAddrPeers()}
	encoded := in.Encode()

	var out HnsMsgAddr
	if err := out.Decode(encoded); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(out.Encode(), encoded) {
		t.Fatalf("round-trip mismatch:\n got % x\nwant % x", out.Encode(), encoded)
	}
}

func TestHnsMsgAddrRoundTripEmpty(t *testing.T) {
	var msg HnsMsgAddr
	encoded := msg.Encode()
	if !bytes.Equal(encoded, []byte{0x00}) {
		t.Fatalf("empty addr encoding: got % x, want 00", encoded)
	}

	var out HnsMsgAddr
	if err := out.Decode(encoded); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(out.Peers) != 0 {
		t.Fatalf("decoded peers: got %d, want 0", len(out.Peers))
	}
}

func TestHnsMsgAddrOnTheWireLayout(t *testing.T) {
	peer := HnsNetAddress{
		Time:     0x0807060504030201,
		Services: 0x1716151413121110,
		Host:     net.IPv4(10, 0, 0, 1).To4(),
		Port:     0x2F06,
		Key:      keyOfBytes(0x55),
	}
	got := (&HnsMsgAddr{Peers: []HnsNetAddress{peer}}).Encode()
	want := append([]byte{0x01}, peer.Encode()...)
	if !bytes.Equal(got, want) {
		t.Fatalf("wire layout mismatch:\n got % x\nwant % x", got, want)
	}
}

func TestHnsMsgAddrDecodeErrors(t *testing.T) {
	var msg HnsMsgAddr
	if err := msg.Decode(nil); err == nil {
		t.Fatal("expected error for missing peer count")
	}
	if err := msg.Decode([]byte{0x01}); err == nil {
		t.Fatal("expected error for count without peer payload")
	}

	badPeerType := (&HnsMsgAddr{Peers: []HnsNetAddress{testHnsAddrPeers()[0]}}).Encode()
	badPeerType[1+16] = 1
	if err := msg.Decode(badPeerType); err == nil {
		t.Fatal("expected error for invalid peer address type")
	}
}

func TestHnsInvItemRoundTrip(t *testing.T) {
	in := testHnsInventory()[0]
	encoded := in.Encode()
	if len(encoded) != HnsInvItemSize {
		t.Fatalf("inventory item size: got %d, want %d", len(encoded), HnsInvItemSize)
	}

	var out HnsInvItem
	if err := out.Decode(encoded); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if out != in {
		t.Fatalf("round-trip mismatch:\n got %+v\nwant %+v", out, in)
	}
}

func TestHnsInvItemDecodeWrongSize(t *testing.T) {
	var item HnsInvItem
	if err := item.Decode(make([]byte, HnsInvItemSize-1)); err == nil {
		t.Fatal("expected error for short inventory item")
	}
	if err := item.Decode(make([]byte, HnsInvItemSize+1)); err == nil {
		t.Fatal("expected error for long inventory item")
	}
}

func TestHnsMsgGetDataRoundTrip(t *testing.T) {
	in := HnsMsgGetData{Inventory: testHnsInventory()}
	encoded := in.Encode()

	var out HnsMsgGetData
	if err := out.Decode(encoded); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(out.Encode(), encoded) {
		t.Fatalf("round-trip mismatch:\n got % x\nwant % x", out.Encode(), encoded)
	}
}

func TestHnsMsgGetDataRoundTripEmpty(t *testing.T) {
	var msg HnsMsgGetData
	encoded := msg.Encode()
	if !bytes.Equal(encoded, []byte{0x00}) {
		t.Fatalf("empty getdata encoding: got % x, want 00", encoded)
	}

	var out HnsMsgGetData
	if err := out.Decode(encoded); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(out.Inventory) != 0 {
		t.Fatalf("decoded inventory: got %d, want 0", len(out.Inventory))
	}
}

func TestHnsMsgGetDataOnTheWireLayout(t *testing.T) {
	item := HnsInvItem{
		Type: HnsInvTypeBlock,
		Hash: hashOfBytes(0xaa),
	}
	got := (&HnsMsgGetData{Inventory: []HnsInvItem{item}}).Encode()
	want := append([]byte{0x01}, item.Encode()...)
	if !bytes.Equal(got, want) {
		t.Fatalf("wire layout mismatch:\n got % x\nwant % x", got, want)
	}
}

func TestHnsMsgGetDataDecodeErrors(t *testing.T) {
	var msg HnsMsgGetData
	if err := msg.Decode(nil); err == nil {
		t.Fatal("expected error for missing inventory count")
	}
	if err := msg.Decode([]byte{0x01}); err == nil {
		t.Fatal("expected error for count without inventory payload")
	}
}

func TestHnsUvarintRoundTrip(t *testing.T) {
	tests := []struct {
		val uint64
		enc []byte
	}{
		{0, []byte{0x00}},
		{0xfc, []byte{0xfc}},
		{0xfd, []byte{0xfd, 0xfd, 0x00}},
		{0xffff, []byte{0xfd, 0xff, 0xff}},
		{0x10000, []byte{0xfe, 0x00, 0x00, 0x01, 0x00}},
		{math.MaxUint32 + 1, []byte{0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}},
	}
	for _, tc := range tests {
		encoded := hnsWriteUvarint(tc.val)
		if !bytes.Equal(encoded, tc.enc) {
			t.Fatalf("hnsWriteUvarint(%d): got % x, want % x", tc.val, encoded, tc.enc)
		}
		decoded, n, err := hnsReadUvarint(encoded)
		if err != nil {
			t.Fatalf("hnsReadUvarint(%x): %v", encoded, err)
		}
		if decoded != tc.val || n != len(encoded) {
			t.Fatalf(
				"hnsReadUvarint(%x): got val=%d n=%d, want val=%d n=%d",
				encoded, decoded, n, tc.val, len(encoded),
			)
		}
	}
}

func TestHnsUvarintShortEncodings(t *testing.T) {
	tests := [][]byte{
		{0xfd},
		{0xfd, 0x01},
		{0xfe},
		{0xfe, 0x01, 0x02, 0x03},
		{0xff},
		{0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
	}
	for _, tc := range tests {
		if _, _, err := hnsReadUvarint(tc); err == nil {
			t.Fatalf("expected error for short uvarint % x", tc)
		}
	}
}

func testHnsInventory() []HnsInvItem {
	return []HnsInvItem{
		{
			Type: HnsInvTypeTx,
			Hash: hashOfBytes(0x11),
		},
		{
			Type: HnsInvTypeBlock,
			Hash: hashOfBytes(0x22),
		},
	}
}

func hashOfBytes(b byte) [32]byte {
	var h [32]byte
	for i := range h {
		h[i] = b
	}
	return h
}

func testHnsAddrPeers() []HnsNetAddress {
	return []HnsNetAddress{
		{
			Time:     0x1122334455667788,
			Services: 0x0102030405060708,
			Host:     net.IPv4(192, 168, 1, 42).To4(),
			Reserved: [20]byte{1, 2, 3, 4, 5},
			Port:     12038,
			Key:      keyOfBytes(0xab),
		},
		{
			Time:     0x8877665544332211,
			Services: 0x0807060504030201,
			Host:     net.ParseIP("2001:db8::1"),
			Port:     12039,
			Key:      keyOfBytes(0xcd),
		},
	}
}
