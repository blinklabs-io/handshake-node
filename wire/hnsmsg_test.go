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
	"time"

	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
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
		{"inv", &HnsMsgInv{Inventory: testHnsInventory()}},
		{"getdata", &HnsMsgGetData{Inventory: testHnsInventory()}},
		{"notfound", &HnsMsgNotFound{Inventory: testHnsInventory()}},
		{"getblocks", &HnsMsgGetBlocks{Locator: testHnsLocators(), StopHash: hashOfBytes(0x22)}},
		{"getheaders", &HnsMsgGetHeaders{Locator: testHnsLocators(), StopHash: hashOfBytes(0x33)}},
		{"headers", &HnsMsgHeaders{Headers: []*BlockHeader{testHnsHeader()}}},
		{"sendheaders", &HnsMsgSendHeaders{}},
		{"block", &HnsMsgBlock{Block: *NewMsgBlock(testHnsHeader())}},
		{"tx", &HnsMsgTx{Tx: *buildHnsTestTx()}},
		{"reject", &HnsMsgReject{Message: HnsMsgTypeTx, Code: RejectInvalid, Reason: "bad tx", Hash: hashOfBytes(0x99)}},
		{"mempool", &HnsMsgMemPool{}},
		{"filterload", &HnsMsgFilterLoad{Filter: []byte{0x01, 0x02, 0x03}, HashFuncs: 10, Tweak: 20, Flags: BloomUpdateAll}},
		{"filteradd", &HnsMsgFilterAdd{Data: []byte{1, 2, 3}}},
		{"filterclear", &HnsMsgFilterClear{}},
		{"merkleblock", &HnsMsgMerkleBlock{MerkleBlock: *testHnsMerkleBlock()}},
		{"feefilter", &HnsMsgFeeFilter{Rate: 1000}},
		{"sendcmpct", &HnsMsgSendCmpct{Mode: 1, Version: 2}},
		{"cmpctblock", &HnsMsgCmpctBlock{Payload: []byte{0x01, 0x02}}},
		{"getblocktxn", &HnsMsgGetBlockTxn{Payload: []byte{0x03, 0x04}}},
		{"blocktxn", &HnsMsgBlockTxn{Payload: []byte{0x05, 0x06}}},
		{"getproof", &HnsMsgGetProof{Root: hashOfBytes(0x44), Key: hashOfBytes(0x55)}},
		{"proof", &HnsMsgProof{Root: hashOfBytes(0x66), Key: hashOfBytes(0x77), Proof: []byte{1, 2, 3, 4}}},
		{"claim", &HnsMsgClaim{Claim: []byte{0xca, 0xfe}}},
		{"airdrop", &HnsMsgAirDrop{Payload: []byte{0xda, 0x7a}}},
		{"unknown", &HnsMsgUnknown{Payload: []byte{0x7f}}},
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
		MessageType:   HnsMsgType(255),
		PayloadLength: 0,
	}
	encoded := header.Encode()
	_, _, err := DecodeHnsMessage(encoded)
	var typErr UnsupportedHnsMsgTypeError
	if !errors.As(err, &typErr) {
		t.Fatalf("expected UnsupportedHnsMsgTypeError, got %v", err)
	}
	if typErr.MessageType != HnsMsgType(255) {
		t.Errorf("error type: got %d, want %d", typErr.MessageType, HnsMsgType(255))
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

func TestHnsCoinbaseProofPayloadLimits(t *testing.T) {
	tests := []struct {
		name     string
		msgType  HnsMsgType
		maxSize  int
		validMsg HandshakeMessage
		largeMsg HandshakeMessage
	}{
		{
			name:     "claim",
			msgType:  HnsMsgTypeClaim,
			maxSize:  HnsMaxClaimPayload,
			validMsg: &HnsMsgClaim{Claim: make([]byte, HnsMaxClaimProofSize)},
			largeMsg: &HnsMsgClaim{Claim: make([]byte, HnsMaxClaimProofSize+1)},
		},
		{
			name:     "airdrop",
			msgType:  HnsMsgTypeAirDrop,
			maxSize:  HnsMaxAirdropProofSize,
			validMsg: &HnsMsgAirDrop{Payload: make([]byte, HnsMaxAirdropProofSize)},
			largeMsg: &HnsMsgAirDrop{Payload: make([]byte, HnsMaxAirdropProofSize+1)},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := int(maxHnsPayloadLength(test.msgType)); got != test.maxSize {
				t.Fatalf("max payload = %d, want %d", got, test.maxSize)
			}
			if _, err := EncodeHnsMessage(test.validMsg, testHnsMagic); err != nil {
				t.Fatalf("boundary payload rejected: %v", err)
			}
			if _, err := EncodeHnsMessage(test.largeMsg, testHnsMagic); err == nil {
				t.Fatal("oversized payload accepted by encoder")
			}

			payload := test.largeMsg.Encode()
			header := (&hnsMsgHeader{
				NetworkMagic:  testHnsMagic,
				MessageType:   test.msgType,
				PayloadLength: uint32(len(payload)),
			}).Encode()
			if _, _, err := DecodeHnsMessage(append(header, payload...)); err == nil {
				t.Fatal("oversized payload accepted by decoder")
			}
		})
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

func TestHnsMsgInvRoundTrip(t *testing.T) {
	in := HnsMsgInv{Inventory: testHnsInventory()}
	encoded := in.Encode()

	var out HnsMsgInv
	if err := out.Decode(encoded); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(out.Encode(), encoded) {
		t.Fatalf("round-trip mismatch:\n got % x\nwant % x", out.Encode(), encoded)
	}
}

func TestHnsMsgInvRoundTripEmpty(t *testing.T) {
	var msg HnsMsgInv
	encoded := msg.Encode()
	if !bytes.Equal(encoded, []byte{0x00}) {
		t.Fatalf("empty inv encoding: got % x, want 00", encoded)
	}

	var out HnsMsgInv
	if err := out.Decode(encoded); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(out.Inventory) != 0 {
		t.Fatalf("decoded inventory: got %d, want 0", len(out.Inventory))
	}
}

func TestHnsMsgInvOnTheWireLayout(t *testing.T) {
	item := HnsInvItem{
		Type: HnsInvTypeClaim,
		Hash: hashOfBytes(0xaa),
	}
	got := (&HnsMsgInv{Inventory: []HnsInvItem{item}}).Encode()
	want := append([]byte{0x01}, item.Encode()...)
	if !bytes.Equal(got, want) {
		t.Fatalf("wire layout mismatch:\n got % x\nwant % x", got, want)
	}
}

func TestHnsMsgInvDecodeErrors(t *testing.T) {
	var msg HnsMsgInv
	if err := msg.Decode(nil); err == nil {
		t.Fatal("expected error for missing inventory count")
	}
	if err := msg.Decode([]byte{0x01}); err == nil {
		t.Fatal("expected error for count without inventory payload")
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

func TestHnsMsgNotFoundRoundTrip(t *testing.T) {
	in := HnsMsgNotFound{Inventory: testHnsInventory()}
	encoded := in.Encode()

	var out HnsMsgNotFound
	if err := out.Decode(encoded); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(out.Encode(), encoded) {
		t.Fatalf("round-trip mismatch:\n got % x\nwant % x", out.Encode(), encoded)
	}
}

func TestHnsMsgNotFoundRoundTripEmpty(t *testing.T) {
	var msg HnsMsgNotFound
	encoded := msg.Encode()
	if !bytes.Equal(encoded, []byte{0x00}) {
		t.Fatalf("empty notfound encoding: got % x, want 00", encoded)
	}

	var out HnsMsgNotFound
	if err := out.Decode(encoded); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(out.Inventory) != 0 {
		t.Fatalf("decoded inventory: got %d, want 0", len(out.Inventory))
	}
}

func TestHnsMsgNotFoundOnTheWireLayout(t *testing.T) {
	item := HnsInvItem{
		Type: HnsInvTypeAirDrop,
		Hash: hashOfBytes(0xbb),
	}
	got := (&HnsMsgNotFound{Inventory: []HnsInvItem{item}}).Encode()
	want := append([]byte{0x01}, item.Encode()...)
	if !bytes.Equal(got, want) {
		t.Fatalf("wire layout mismatch:\n got % x\nwant % x", got, want)
	}
}

func TestHnsMsgNotFoundDecodeErrors(t *testing.T) {
	var msg HnsMsgNotFound
	if err := msg.Decode(nil); err == nil {
		t.Fatal("expected error for missing inventory count")
	}
	if err := msg.Decode([]byte{0x01}); err == nil {
		t.Fatal("expected error for count without inventory payload")
	}
}

func TestHnsMsgGetBlocksRoundTrip(t *testing.T) {
	in := HnsMsgGetBlocks{
		Locator:  testHnsLocators(),
		StopHash: hashOfBytes(0x33),
	}
	encoded := in.Encode()

	var out HnsMsgGetBlocks
	if err := out.Decode(encoded); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(out.Encode(), encoded) {
		t.Fatalf("round-trip mismatch:\n got % x\nwant % x", out.Encode(), encoded)
	}
}

func TestHnsMsgGetBlocksRoundTripEmptyLocators(t *testing.T) {
	in := HnsMsgGetBlocks{StopHash: hashOfBytes(0x44)}
	encoded := in.Encode()
	if len(encoded) != 33 {
		t.Fatalf("encoded length: got %d, want 33", len(encoded))
	}

	var out HnsMsgGetBlocks
	if err := out.Decode(encoded); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(out.Locator) != 0 {
		t.Fatalf("locators: got %d, want 0", len(out.Locator))
	}
	if out.StopHash != in.StopHash {
		t.Fatalf("stop hash mismatch")
	}
}

func TestHnsMsgGetBlocksOnTheWireLayout(t *testing.T) {
	locator := hashOfBytes(0x11)
	stop := hashOfBytes(0x22)
	got := (&HnsMsgGetBlocks{
		Locator:  [][32]byte{locator},
		StopHash: stop,
	}).Encode()
	want := append([]byte{0x01}, locator[:]...)
	want = append(want, stop[:]...)
	if !bytes.Equal(got, want) {
		t.Fatalf("wire layout mismatch:\n got % x\nwant % x", got, want)
	}
}

func TestHnsMsgGetBlocksDecodeErrors(t *testing.T) {
	var msg HnsMsgGetBlocks
	if err := msg.Decode(nil); err == nil {
		t.Fatal("expected error for missing locator count")
	}
	if err := msg.Decode([]byte{0x00}); err == nil {
		t.Fatal("expected error for missing stop hash")
	}
	locator := hashOfBytes(0x11)
	if err := msg.Decode(append([]byte{0x01}, locator[:]...)); err == nil {
		t.Fatal("expected error for locator count without stop hash")
	}
}

func TestHnsMsgGetHeadersRoundTrip(t *testing.T) {
	in := HnsMsgGetHeaders{
		Locator:  testHnsLocators(),
		StopHash: hashOfBytes(0x33),
	}
	encoded := in.Encode()

	var out HnsMsgGetHeaders
	if err := out.Decode(encoded); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(out.Encode(), encoded) {
		t.Fatalf("round-trip mismatch:\n got % x\nwant % x", out.Encode(), encoded)
	}
}

func TestHnsMsgGetHeadersRoundTripEmptyLocators(t *testing.T) {
	in := HnsMsgGetHeaders{StopHash: hashOfBytes(0x44)}
	encoded := in.Encode()
	if len(encoded) != 33 {
		t.Fatalf("encoded length: got %d, want 33", len(encoded))
	}

	var out HnsMsgGetHeaders
	if err := out.Decode(encoded); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(out.Locator) != 0 {
		t.Fatalf("locators: got %d, want 0", len(out.Locator))
	}
	if out.StopHash != in.StopHash {
		t.Fatalf("stop hash mismatch")
	}
}

func TestHnsMsgGetHeadersOnTheWireLayout(t *testing.T) {
	locator := hashOfBytes(0x11)
	stop := hashOfBytes(0x22)
	got := (&HnsMsgGetHeaders{
		Locator:  [][32]byte{locator},
		StopHash: stop,
	}).Encode()
	want := append([]byte{0x01}, locator[:]...)
	want = append(want, stop[:]...)
	if !bytes.Equal(got, want) {
		t.Fatalf("wire layout mismatch:\n got % x\nwant % x", got, want)
	}
}

func TestHnsMsgGetHeadersDecodeErrors(t *testing.T) {
	var msg HnsMsgGetHeaders
	if err := msg.Decode(nil); err == nil {
		t.Fatal("expected error for missing locator count")
	}
	if err := msg.Decode([]byte{0x00}); err == nil {
		t.Fatal("expected error for missing stop hash")
	}
	locator := hashOfBytes(0x11)
	if err := msg.Decode(append([]byte{0x01}, locator[:]...)); err == nil {
		t.Fatal("expected error for locator count without stop hash")
	}
}

func TestHnsMsgHeadersRoundTrip(t *testing.T) {
	in := HnsMsgHeaders{Headers: []*BlockHeader{testHnsHeader()}}
	encoded := in.Encode()

	var out HnsMsgHeaders
	if err := out.Decode(encoded); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(out.Encode(), encoded) {
		t.Fatalf("round-trip mismatch:\n got % x\nwant % x", out.Encode(), encoded)
	}
}

func TestHnsMsgHeadersRoundTripEmpty(t *testing.T) {
	var msg HnsMsgHeaders
	encoded := msg.Encode()
	if !bytes.Equal(encoded, []byte{0x00}) {
		t.Fatalf("empty headers encoding: got % x, want 00", encoded)
	}

	var out HnsMsgHeaders
	if err := out.Decode(encoded); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(out.Headers) != 0 {
		t.Fatalf("decoded headers: got %d, want 0", len(out.Headers))
	}
}

func TestHnsMsgHeadersOnTheWireLayout(t *testing.T) {
	header := testHnsHeader()
	got := (&HnsMsgHeaders{Headers: []*BlockHeader{header}}).Encode()
	want := append([]byte{0x01}, serializeHnsHeader(t, header)...)
	if !bytes.Equal(got, want) {
		t.Fatalf("wire layout mismatch:\n got % x\nwant % x", got, want)
	}
}

func TestHnsMsgHeadersDecodeErrors(t *testing.T) {
	var msg HnsMsgHeaders
	if err := msg.Decode(nil); err == nil {
		t.Fatal("expected error for missing header count")
	}
	if err := msg.Decode([]byte{0x01}); err == nil {
		t.Fatal("expected error for count without header payload")
	}
}

func TestHnsMsgSendHeadersRejectsPayload(t *testing.T) {
	var msg HnsMsgSendHeaders
	if err := msg.Decode([]byte{0x00}); err == nil {
		t.Fatal("expected error for non-empty sendheaders payload")
	}
}

func TestHnsMsgBlockRoundTrip(t *testing.T) {
	in := HnsMsgBlock{Block: *NewMsgBlock(testHnsHeader())}
	encoded := in.Encode()

	var out HnsMsgBlock
	if err := out.Decode(encoded); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(out.Encode(), encoded) {
		t.Fatalf("round-trip mismatch:\n got % x\nwant % x", out.Encode(), encoded)
	}
}

func TestHnsMsgBlockOnTheWireLayout(t *testing.T) {
	header := testHnsHeader()
	got := (&HnsMsgBlock{Block: *NewMsgBlock(header)}).Encode()
	want := append(serializeHnsHeader(t, header), 0x00)
	if !bytes.Equal(got, want) {
		t.Fatalf("wire layout mismatch:\n got % x\nwant % x", got, want)
	}
}

func TestHnsMsgBlockDecodeErrors(t *testing.T) {
	var msg HnsMsgBlock
	if err := msg.Decode(nil); err == nil {
		t.Fatal("expected error for empty block payload")
	}
	if err := msg.Decode([]byte{0x01, 0x02}); err == nil {
		t.Fatal("expected error for short block payload")
	}
	valid := (&HnsMsgBlock{Block: *NewMsgBlock(testHnsHeader())}).Encode()
	if err := msg.Decode(append(valid, 0x00)); err == nil {
		t.Fatal("expected error for trailing block payload")
	}
}

func TestHnsMsgTxRoundTrip(t *testing.T) {
	in := HnsMsgTx{Tx: *buildHnsTestTx()}
	encoded := in.Encode()

	var out HnsMsgTx
	if err := out.Decode(encoded); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(out.Encode(), encoded) {
		t.Fatalf("round-trip mismatch:\n got % x\nwant % x", out.Encode(), encoded)
	}
}

func TestHnsMsgTxOnTheWireLayout(t *testing.T) {
	tx := buildHnsTestTx()
	got := (&HnsMsgTx{Tx: *tx}).Encode()
	want := serializeHnsTx(t, tx)
	if !bytes.Equal(got, want) {
		t.Fatalf("wire layout mismatch:\n got % x\nwant % x", got, want)
	}
}

func TestHnsMsgTxDecodeErrors(t *testing.T) {
	var msg HnsMsgTx
	if err := msg.Decode(nil); err == nil {
		t.Fatal("expected error for empty tx payload")
	}
	if err := msg.Decode([]byte{0x01, 0x02}); err == nil {
		t.Fatal("expected error for short tx payload")
	}
	valid := (&HnsMsgTx{Tx: *buildHnsTestTx()}).Encode()
	if err := msg.Decode(append(valid, 0x00)); err == nil {
		t.Fatal("expected error for trailing tx payload")
	}
}

func TestHnsMsgRejectRoundTrip(t *testing.T) {
	in := HnsMsgReject{
		Message: HnsMsgTypeTx,
		Code:    RejectInvalid,
		Reason:  "bad tx",
		Hash:    hashOfBytes(0x99),
	}
	encoded := in.Encode()

	var out HnsMsgReject
	if err := out.Decode(encoded); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if out.Message != in.Message {
		t.Errorf("message: got %d, want %d", out.Message, in.Message)
	}
	if out.Code != in.Code {
		t.Errorf("code: got %d, want %d", out.Code, in.Code)
	}
	if out.Reason != in.Reason {
		t.Errorf("reason: got %q, want %q", out.Reason, in.Reason)
	}
	if out.Hash != in.Hash {
		t.Errorf("hash: got %x, want %x", out.Hash, in.Hash)
	}
}

func TestHnsMsgRejectNoHashRoundTrip(t *testing.T) {
	in := HnsMsgReject{
		Message: HnsMsgTypeVersion,
		Code:    RejectObsolete,
		Reason:  "old version",
	}
	encoded := in.Encode()

	var out HnsMsgReject
	if err := out.Decode(encoded); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if out.Message != in.Message {
		t.Errorf("message: got %d, want %d", out.Message, in.Message)
	}
	if out.Code != in.Code {
		t.Errorf("code: got %d, want %d", out.Code, in.Code)
	}
	if out.Reason != in.Reason {
		t.Errorf("reason: got %q, want %q", out.Reason, in.Reason)
	}
	if out.Hash != ([32]byte{}) {
		t.Errorf("hash: got %x, want zero hash", out.Hash)
	}
}

func TestHnsMsgRejectOnTheWireLayout(t *testing.T) {
	hash := hashOfBytes(0x99)
	got := (&HnsMsgReject{
		Message: HnsMsgTypeTx,
		Code:    RejectInvalid,
		Reason:  "bad tx",
		Hash:    hash,
	}).Encode()
	want := []byte{
		byte(HnsMsgTypeTx),
		byte(RejectInvalid),
		0x06,
		'b', 'a', 'd', ' ', 't', 'x',
	}
	want = append(want, hash[:]...)
	if !bytes.Equal(got, want) {
		t.Fatalf("wire layout mismatch:\n got % x\nwant % x", got, want)
	}
}

func TestHnsMsgRejectDecodeErrors(t *testing.T) {
	var msg HnsMsgReject
	if err := msg.Decode(nil); err == nil {
		t.Fatal("expected error for empty reject payload")
	}
	if err := msg.Decode([]byte{byte(HnsMsgTypeVersion), byte(RejectInvalid), 0x04, 'b'}); err == nil {
		t.Fatal("expected error for truncated reason")
	}
	if err := msg.Decode([]byte{byte(HnsMsgTypeTx), byte(RejectInvalid), 0x00}); err == nil {
		t.Fatal("expected error for missing hash")
	}
	if err := msg.Decode([]byte{byte(HnsMsgTypeVersion), byte(RejectInvalid), 0x00, 0x99}); err == nil {
		t.Fatal("expected error for trailing payload")
	}
}

func TestHnsMsgMemPoolRejectsPayload(t *testing.T) {
	var msg HnsMsgMemPool
	if err := msg.Decode([]byte{0x00}); err == nil {
		t.Fatal("expected error for non-empty mempool payload")
	}
}

func TestHnsMsgFilterLoadRoundTrip(t *testing.T) {
	in := HnsMsgFilterLoad{
		Filter:    []byte{0xaa, 0xbb, 0xcc},
		HashFuncs: 10,
		Tweak:     0x01020304,
		Flags:     BloomUpdateAll,
	}
	encoded := in.Encode()

	var out HnsMsgFilterLoad
	if err := out.Decode(encoded); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(out.Filter, in.Filter) {
		t.Errorf("filter: got % x, want % x", out.Filter, in.Filter)
	}
	if out.HashFuncs != in.HashFuncs {
		t.Errorf("hash funcs: got %d, want %d", out.HashFuncs, in.HashFuncs)
	}
	if out.Tweak != in.Tweak {
		t.Errorf("tweak: got %#x, want %#x", out.Tweak, in.Tweak)
	}
	if out.Flags != in.Flags {
		t.Errorf("flags: got %d, want %d", out.Flags, in.Flags)
	}
}

func TestHnsMsgFilterLoadOnTheWireLayout(t *testing.T) {
	got := (&HnsMsgFilterLoad{
		Filter:    []byte{0xaa, 0xbb},
		HashFuncs: 0x01020304,
		Tweak:     0x05060708,
		Flags:     BloomUpdateP2PubkeyOnly,
	}).Encode()
	want := []byte{
		0x02, 0xaa, 0xbb,
		0x04, 0x03, 0x02, 0x01,
		0x08, 0x07, 0x06, 0x05,
		byte(BloomUpdateP2PubkeyOnly),
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("wire layout mismatch:\n got % x\nwant % x", got, want)
	}
}

func TestHnsMsgFilterLoadDecodeErrors(t *testing.T) {
	var msg HnsMsgFilterLoad
	if err := msg.Decode(nil); err == nil {
		t.Fatal("expected error for missing filter length")
	}
	if err := msg.Decode([]byte{0x03, 0xaa}); err == nil {
		t.Fatal("expected error for truncated filter")
	}
	if err := msg.Decode([]byte{0x01, 0xaa}); err == nil {
		t.Fatal("expected error for missing filter parameters")
	}

	payload := (&HnsMsgFilterLoad{
		Filter:    []byte{0xaa},
		HashFuncs: MaxFilterLoadHashFuncs + 1,
	}).Encode()
	if err := msg.Decode(payload); err == nil {
		t.Fatal("expected error for too many hash functions")
	}
}

func TestHnsMsgFilterAddRoundTrip(t *testing.T) {
	in := HnsMsgFilterAdd{Data: []byte{0xaa, 0xbb, 0xcc}}
	encoded := in.Encode()

	var out HnsMsgFilterAdd
	if err := out.Decode(encoded); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(out.Encode(), encoded) {
		t.Fatalf("round-trip mismatch:\n got % x\nwant % x", out.Encode(), encoded)
	}
}

func TestHnsMsgFilterAddRoundTripEmpty(t *testing.T) {
	var msg HnsMsgFilterAdd
	encoded := msg.Encode()
	if !bytes.Equal(encoded, []byte{0x00}) {
		t.Fatalf("empty filteradd encoding: got % x, want 00", encoded)
	}

	var out HnsMsgFilterAdd
	if err := out.Decode(encoded); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(out.Data) != 0 {
		t.Fatalf("decoded data: got %d bytes, want 0", len(out.Data))
	}
}

func TestHnsMsgFilterAddOnTheWireLayout(t *testing.T) {
	got := (&HnsMsgFilterAdd{Data: []byte{0xaa, 0xbb}}).Encode()
	want := []byte{0x02, 0xaa, 0xbb}
	if !bytes.Equal(got, want) {
		t.Fatalf("wire layout mismatch:\n got % x\nwant % x", got, want)
	}
}

func TestHnsMsgFilterAddDecodeErrors(t *testing.T) {
	var msg HnsMsgFilterAdd
	if err := msg.Decode(nil); err == nil {
		t.Fatal("expected error for missing filteradd data length")
	}
	if err := msg.Decode([]byte{0x02, 0xaa}); err == nil {
		t.Fatal("expected error for truncated filteradd data")
	}
	if err := msg.Decode([]byte{0x01, 0xaa, 0xbb}); err == nil {
		t.Fatal("expected error for trailing filteradd data")
	}
}

func TestHnsMsgFilterClearRejectsPayload(t *testing.T) {
	var msg HnsMsgFilterClear
	if err := msg.Decode([]byte{0x00}); err == nil {
		t.Fatal("expected error for non-empty filterclear payload")
	}
}

func TestHnsMsgMerkleBlockRoundTrip(t *testing.T) {
	in := HnsMsgMerkleBlock{MerkleBlock: *testHnsMerkleBlock()}
	encoded := in.Encode()

	var out HnsMsgMerkleBlock
	if err := out.Decode(encoded); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(out.Encode(), encoded) {
		t.Fatalf("round-trip mismatch:\n got % x\nwant % x", out.Encode(), encoded)
	}
}

func TestHnsMsgMerkleBlockDecodeErrors(t *testing.T) {
	var msg HnsMsgMerkleBlock
	if err := msg.Decode(nil); err == nil {
		t.Fatal("expected error for empty merkleblock payload")
	}
	valid := (&HnsMsgMerkleBlock{MerkleBlock: *testHnsMerkleBlock()}).Encode()
	if err := msg.Decode(append(valid, 0x00)); err == nil {
		t.Fatal("expected error for trailing merkleblock payload")
	}
}

func TestHnsMsgFeeFilterRoundTrip(t *testing.T) {
	in := HnsMsgFeeFilter{Rate: -1000}
	encoded := in.Encode()

	var out HnsMsgFeeFilter
	if err := out.Decode(encoded); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if out != in {
		t.Fatalf("round-trip mismatch:\n got %+v\nwant %+v", out, in)
	}
}

func TestHnsMsgFeeFilterOnTheWireLayout(t *testing.T) {
	got := (&HnsMsgFeeFilter{Rate: 0x0102030405060708}).Encode()
	want := []byte{0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	if !bytes.Equal(got, want) {
		t.Fatalf("wire layout mismatch:\n got % x\nwant % x", got, want)
	}
}

func TestHnsMsgFeeFilterDecodeWrongSize(t *testing.T) {
	var msg HnsMsgFeeFilter
	if err := msg.Decode(make([]byte, 7)); err == nil {
		t.Fatal("expected error for short feefilter payload")
	}
	if err := msg.Decode(make([]byte, 9)); err == nil {
		t.Fatal("expected error for long feefilter payload")
	}
}

func TestHnsMsgSendCmpctRoundTrip(t *testing.T) {
	in := HnsMsgSendCmpct{Mode: 1, Version: 0x0102030405060708}
	encoded := in.Encode()

	var out HnsMsgSendCmpct
	if err := out.Decode(encoded); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if out != in {
		t.Fatalf("round-trip mismatch:\n got %+v\nwant %+v", out, in)
	}
}

func TestHnsMsgSendCmpctOnTheWireLayout(t *testing.T) {
	got := (&HnsMsgSendCmpct{Mode: 1, Version: 0x0102030405060708}).Encode()
	want := []byte{0x01, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	if !bytes.Equal(got, want) {
		t.Fatalf("wire layout mismatch:\n got % x\nwant % x", got, want)
	}
}

func TestHnsMsgSendCmpctDecodeWrongSize(t *testing.T) {
	var msg HnsMsgSendCmpct
	if err := msg.Decode(make([]byte, 8)); err == nil {
		t.Fatal("expected error for short sendcmpct payload")
	}
	if err := msg.Decode(make([]byte, 10)); err == nil {
		t.Fatal("expected error for long sendcmpct payload")
	}
}

func TestHnsMsgCompactRelayOpaquePayloads(t *testing.T) {
	tests := []struct {
		name string
		msg  HandshakeMessage
	}{
		{"cmpctblock", &HnsMsgCmpctBlock{Payload: []byte{0x01, 0x02}}},
		{"getblocktxn", &HnsMsgGetBlockTxn{Payload: []byte{0x03, 0x04}}},
		{"blocktxn", &HnsMsgBlockTxn{Payload: []byte{0x05, 0x06}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded := tc.msg.Encode()
			decoded, err := newEmptyHnsMessage(tc.msg.Type())
			if err != nil {
				t.Fatalf("newEmptyHnsMessage: %v", err)
			}
			if err := decoded.Decode(encoded); err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if !bytes.Equal(decoded.Encode(), encoded) {
				t.Fatalf("round-trip mismatch:\n got % x\nwant % x", decoded.Encode(), encoded)
			}
		})
	}
}

func TestHnsMsgGetProofRoundTrip(t *testing.T) {
	in := HnsMsgGetProof{Root: hashOfBytes(0x11), Key: hashOfBytes(0x22)}
	encoded := in.Encode()

	var out HnsMsgGetProof
	if err := out.Decode(encoded); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if out != in {
		t.Fatalf("round-trip mismatch:\n got %+v\nwant %+v", out, in)
	}
}

func TestHnsMsgGetProofOnTheWireLayout(t *testing.T) {
	root := hashOfBytes(0x11)
	key := hashOfBytes(0x22)
	got := (&HnsMsgGetProof{Root: root, Key: key}).Encode()
	want := append(root[:], key[:]...)
	if !bytes.Equal(got, want) {
		t.Fatalf("wire layout mismatch:\n got % x\nwant % x", got, want)
	}
}

func TestHnsMsgGetProofDecodeWrongSize(t *testing.T) {
	var msg HnsMsgGetProof
	if err := msg.Decode(make([]byte, 63)); err == nil {
		t.Fatal("expected error for short getproof payload")
	}
	if err := msg.Decode(make([]byte, 65)); err == nil {
		t.Fatal("expected error for long getproof payload")
	}
}

func TestHnsMsgProofRoundTrip(t *testing.T) {
	in := HnsMsgProof{
		Root:  hashOfBytes(0x33),
		Key:   hashOfBytes(0x44),
		Proof: []byte{0xaa, 0xbb, 0xcc},
	}
	encoded := in.Encode()

	var out HnsMsgProof
	if err := out.Decode(encoded); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(out.Encode(), encoded) {
		t.Fatalf("round-trip mismatch:\n got % x\nwant % x", out.Encode(), encoded)
	}
}

func TestHnsMsgProofOnTheWireLayout(t *testing.T) {
	root := hashOfBytes(0x11)
	key := hashOfBytes(0x22)
	proof := []byte{0x33, 0x44}
	got := (&HnsMsgProof{Root: root, Key: key, Proof: proof}).Encode()
	want := append(root[:], key[:]...)
	want = append(want, proof...)
	if !bytes.Equal(got, want) {
		t.Fatalf("wire layout mismatch:\n got % x\nwant % x", got, want)
	}
}

func TestHnsMsgProofDecodeErrors(t *testing.T) {
	var msg HnsMsgProof
	if err := msg.Decode(make([]byte, 63)); err == nil {
		t.Fatal("expected error for short proof payload")
	}
}

func TestHnsMsgClaimRoundTrip(t *testing.T) {
	in := HnsMsgClaim{Claim: []byte{0xca, 0xfe, 0xba, 0xbe}}
	encoded := in.Encode()

	var out HnsMsgClaim
	if err := out.Decode(encoded); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(out.Claim, in.Claim) {
		t.Fatalf("claim mismatch:\n got % x\nwant % x", out.Claim, in.Claim)
	}
}

func TestHnsMsgClaimOnTheWireLayout(t *testing.T) {
	got := (&HnsMsgClaim{Claim: []byte{0xca, 0xfe}}).Encode()
	want := []byte{0x02, 0x00, 0xca, 0xfe}
	if !bytes.Equal(got, want) {
		t.Fatalf("wire layout mismatch:\n got % x\nwant % x", got, want)
	}
}

func TestHnsMsgClaimDecodeErrors(t *testing.T) {
	var msg HnsMsgClaim
	if err := msg.Decode(nil); err == nil {
		t.Fatal("expected error for missing claim length")
	}
	if err := msg.Decode([]byte{0x02, 0x00, 0xca}); err == nil {
		t.Fatal("expected error for truncated claim")
	}
	if err := msg.Decode([]byte{0x01, 0x00, 0xca, 0xfe}); err == nil {
		t.Fatal("expected error for trailing claim data")
	}
}

func TestHnsMsgAirDropAndUnknownOpaquePayloads(t *testing.T) {
	tests := []struct {
		name string
		msg  HandshakeMessage
	}{
		{"airdrop", &HnsMsgAirDrop{Payload: []byte{0xda, 0x7a}}},
		{"unknown", &HnsMsgUnknown{Payload: []byte{0x7f, 0x80}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded := tc.msg.Encode()
			decoded, err := newEmptyHnsMessage(tc.msg.Type())
			if err != nil {
				t.Fatalf("newEmptyHnsMessage: %v", err)
			}
			if err := decoded.Decode(encoded); err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if !bytes.Equal(decoded.Encode(), encoded) {
				t.Fatalf("round-trip mismatch:\n got % x\nwant % x", decoded.Encode(), encoded)
			}
		})
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

func TestHnsUvarintNonCanonical(t *testing.T) {
	tests := [][]byte{
		{0xfd, 0x00, 0x00},
		{0xfd, 0xfc, 0x00},
		{0xfe, 0x00, 0x00, 0x00, 0x00},
		{0xfe, 0xff, 0xff, 0x00, 0x00},
		{0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		{0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00},
	}
	for _, tc := range tests {
		if _, _, err := hnsReadUvarint(tc); err == nil {
			t.Fatalf("expected error for non-canonical uvarint % x", tc)
		}
	}
}

func testHnsLocators() [][32]byte {
	return [][32]byte{
		hashOfBytes(0x11),
		hashOfBytes(0x22),
	}
}

func testHnsHeader() *BlockHeader {
	var extraNonce [24]byte
	for i := range extraNonce {
		extraNonce[i] = byte(i + 1)
	}
	return &BlockHeader{
		Version:      7,
		PrevBlock:    chainhash.Hash(hashOfBytes(0x01)),
		MerkleRoot:   chainhash.Hash(hashOfBytes(0x02)),
		Timestamp:    time.Unix(0x0102030405060708, 0),
		Bits:         0x1d00ffff,
		Nonce:        0x11223344,
		NameRoot:     chainhash.Hash(hashOfBytes(0x03)),
		ExtraNonce:   extraNonce,
		ReservedRoot: chainhash.Hash(hashOfBytes(0x04)),
		WitnessRoot:  chainhash.Hash(hashOfBytes(0x05)),
		Mask:         chainhash.Hash(hashOfBytes(0x06)),
	}
}

func testHnsMerkleBlock() *MsgMerkleBlock {
	msg := NewMsgMerkleBlock(testHnsHeader())
	msg.Transactions = 2
	hash := chainhash.Hash(hashOfBytes(0x33))
	_ = msg.AddTxHash(&hash)
	msg.Flags = []byte{0x01}
	return msg
}

func serializeHnsHeader(t *testing.T, header *BlockHeader) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := header.Serialize(&buf); err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	return buf.Bytes()
}

func serializeHnsTx(t *testing.T, tx *MsgTx) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	return buf.Bytes()
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
