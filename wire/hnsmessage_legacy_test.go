// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
)

func TestHnsLegacyVersionMessageStream(t *testing.T) {
	localNA := NewNetAddressTimestamp(
		time.Unix(11, 0), SFNodeNetwork, net.IPv4(10, 0, 0, 1), 12038,
	)
	remoteNA := NewNetAddressTimestamp(
		time.Unix(22, 0), SFNodeBloom, net.IPv4(10, 0, 0, 2), 12039,
	)
	msg := NewMsgVersion(localNA, remoteNA, 0x0807060504030201, 99)
	msg.ProtocolVersion = int32(ProtocolVersion)
	msg.Services = SFNodeNetwork | SFNodeWitness
	msg.Timestamp = time.Unix(123456789, 0)
	msg.UserAgent = "/handshake-node:0.1.0/"
	msg.DisableRelayTx = true

	var buf bytes.Buffer
	n, err := WriteHnsMessageN(&buf, msg, ProtocolVersion, MainNet)
	if err != nil {
		t.Fatalf("WriteHnsMessageN: %v", err)
	}
	if n != buf.Len() {
		t.Fatalf("bytes written: got %d, want %d", n, buf.Len())
	}

	wireBytes := buf.Bytes()
	if got := binary.LittleEndian.Uint32(wireBytes[0:4]); got != uint32(MainNet) {
		t.Fatalf("network magic: got %#x, want %#x", got, uint32(MainNet))
	}
	if got := HnsMsgType(wireBytes[4]); got != HnsMsgTypeVersion {
		t.Fatalf("message type: got %d, want %d", got, HnsMsgTypeVersion)
	}
	if got := binary.LittleEndian.Uint32(wireBytes[5:9]); got != uint32(len(wireBytes)-HnsMessageHeaderSize) {
		t.Fatalf("payload length: got %d, want %d", got, len(wireBytes)-HnsMessageHeaderSize)
	}

	n, decoded, payload, err := ReadHnsMessageN(
		bytes.NewReader(wireBytes), ProtocolVersion, MainNet,
	)
	if err != nil {
		t.Fatalf("ReadHnsMessageN: %v", err)
	}
	if n != len(wireBytes) {
		t.Fatalf("bytes read: got %d, want %d", n, len(wireBytes))
	}
	if len(payload) != len(wireBytes)-HnsMessageHeaderSize {
		t.Fatalf("payload bytes: got %d, want %d", len(payload), len(wireBytes)-HnsMessageHeaderSize)
	}

	got, ok := decoded.(*MsgVersion)
	if !ok {
		t.Fatalf("decoded message: got %T, want *MsgVersion", decoded)
	}
	if got.ProtocolVersion != msg.ProtocolVersion {
		t.Fatalf("protocol version: got %d, want %d", got.ProtocolVersion, msg.ProtocolVersion)
	}
	if got.Services != msg.Services {
		t.Fatalf("services: got %v, want %v", got.Services, msg.Services)
	}
	if !got.Timestamp.Equal(msg.Timestamp) {
		t.Fatalf("timestamp: got %v, want %v", got.Timestamp, msg.Timestamp)
	}
	if got.Nonce != msg.Nonce {
		t.Fatalf("nonce: got %#x, want %#x", got.Nonce, msg.Nonce)
	}
	if got.UserAgent != msg.UserAgent {
		t.Fatalf("user agent: got %q, want %q", got.UserAgent, msg.UserAgent)
	}
	if got.LastBlock != msg.LastBlock {
		t.Fatalf("last block: got %d, want %d", got.LastBlock, msg.LastBlock)
	}
	if got.DisableRelayTx != msg.DisableRelayTx {
		t.Fatalf("disable relay: got %v, want %v", got.DisableRelayTx, msg.DisableRelayTx)
	}
	if !got.AddrYou.IP.Equal(remoteNA.IP.To4()) {
		t.Fatalf("remote IP: got %v, want %v", got.AddrYou.IP, remoteNA.IP.To4())
	}
	if got.AddrYou.Port != remoteNA.Port {
		t.Fatalf("remote port: got %d, want %d", got.AddrYou.Port, remoteNA.Port)
	}
}

func TestHnsLegacyVersionAcceptsMaxLegacyUserAgent(t *testing.T) {
	localNA := NewNetAddressTimestamp(
		time.Unix(11, 0), SFNodeNetwork, net.IPv4(10, 0, 0, 1), 12038,
	)
	remoteNA := NewNetAddressTimestamp(
		time.Unix(22, 0), SFNodeBloom, net.IPv4(10, 0, 0, 2), 12039,
	)
	msg := NewMsgVersion(localNA, remoteNA, 0x0807060504030201, 99)
	msg.UserAgent = strings.Repeat("u", MaxUserAgentLen)

	var buf bytes.Buffer
	if _, err := WriteHnsMessageN(&buf, msg, ProtocolVersion, MainNet); err != nil {
		t.Fatalf("WriteHnsMessageN: %v", err)
	}

	wireBytes := buf.Bytes()
	wantPayloadLen := uint32(
		hnsMsgVersionFixedSize + HnsMaxUserAgentLen + 4 + 1,
	)
	if got := binary.LittleEndian.Uint32(wireBytes[5:9]); got != wantPayloadLen {
		t.Fatalf("payload length: got %d, want %d", got, wantPayloadLen)
	}

	_, decoded, _, err := ReadHnsMessageN(
		bytes.NewReader(wireBytes), ProtocolVersion, MainNet,
	)
	if err != nil {
		t.Fatalf("ReadHnsMessageN: %v", err)
	}
	got, ok := decoded.(*MsgVersion)
	if !ok {
		t.Fatalf("decoded message: got %T, want *MsgVersion", decoded)
	}
	if got.UserAgent != msg.UserAgent[:HnsMaxUserAgentLen] {
		t.Fatalf(
			"user agent: got len %d, want capped len %d",
			len(got.UserAgent), HnsMaxUserAgentLen,
		)
	}

	buf.Reset()
	msg.UserAgent = strings.Repeat("u", MaxUserAgentLen+1)
	_, err = WriteHnsMessageN(&buf, msg, ProtocolVersion, MainNet)
	if err == nil {
		t.Fatal("expected error for user agent above legacy max")
	}
	if buf.Len() != 0 {
		t.Fatalf("bytes written after invalid user agent: got %d, want 0", buf.Len())
	}
	var msgErr *MessageError
	if !errors.As(err, &msgErr) {
		t.Fatalf("error type: got %T, want *MessageError", err)
	}
}

func TestHnsLegacyMessageRoundTrips(t *testing.T) {
	hash := chainhash.Hash{0: 0x01, 1: 0x02}
	header := NewBlockHeader(
		1, &hash, &hash, &hash, &hash, 123456789, 0x1d00ffff,
	)
	addr := NewNetAddressTimestamp(
		time.Unix(33, 0), SFNodeNetwork, net.IPv4(127, 0, 0, 1), 12038,
	)
	inv := NewInvVect(InvTypeBlock, &hash)
	getBlocks := NewMsgGetBlocks(&hash)
	if err := getBlocks.AddBlockLocatorHash(&hash); err != nil {
		t.Fatalf("AddBlockLocatorHash: %v", err)
	}
	getHeaders := NewMsgGetHeaders()
	if err := getHeaders.AddBlockLocatorHash(&hash); err != nil {
		t.Fatalf("AddBlockLocatorHash: %v", err)
	}
	headers := NewMsgHeaders()
	if err := headers.AddBlockHeader(header); err != nil {
		t.Fatalf("AddBlockHeader: %v", err)
	}

	tests := []struct {
		name string
		msg  Message
	}{
		{"verack", &MsgVerAck{}},
		{"ping", NewMsgPing(42)},
		{"pong", NewMsgPong(42)},
		{"getaddr", NewMsgGetAddr()},
		{"addr", NewMsgAddr()},
		{"inv", NewMsgInvSizeHint(1)},
		{"getdata", NewMsgGetData()},
		{"notfound", NewMsgNotFound()},
		{"getblocks", getBlocks},
		{"getheaders", getHeaders},
		{"headers", headers},
		{"sendheaders", NewMsgSendHeaders()},
		{"block", NewMsgBlock(header)},
		{"tx", NewMsgTx(TxVersion)},
		{"reject", NewMsgReject(CmdBlock, RejectDuplicate, "duplicate")},
		{"mempool", NewMsgMemPool()},
		{"filterload", NewMsgFilterLoad([]byte{0x01}, 10, 0, BloomUpdateNone)},
		{"filteradd", NewMsgFilterAdd([]byte{0x02})},
		{"filterclear", NewMsgFilterClear()},
		{"merkleblock", NewMsgMerkleBlock(header)},
		{"feefilter", NewMsgFeeFilter(1000)},
	}
	if err := tests[4].msg.(*MsgAddr).AddAddress(addr); err != nil {
		t.Fatalf("AddAddress: %v", err)
	}
	if err := tests[5].msg.(*MsgInv).AddInvVect(inv); err != nil {
		t.Fatalf("AddInvVect: %v", err)
	}
	if err := tests[6].msg.(*MsgGetData).AddInvVect(inv); err != nil {
		t.Fatalf("AddInvVect: %v", err)
	}
	if err := tests[7].msg.(*MsgNotFound).AddInvVect(inv); err != nil {
		t.Fatalf("AddInvVect: %v", err)
	}

	for _, test := range tests {
		var buf bytes.Buffer
		if _, err := WriteHnsMessageN(&buf, test.msg, ProtocolVersion, TestNet); err != nil {
			t.Fatalf("%s: WriteHnsMessageN: %v", test.name, err)
		}

		_, decoded, _, err := ReadHnsMessageN(&buf, ProtocolVersion, TestNet)
		if err != nil {
			t.Fatalf("%s: ReadHnsMessageN: %v", test.name, err)
		}
		if decoded.Command() != test.msg.Command() {
			t.Fatalf("%s: command got %q, want %q",
				test.name, decoded.Command(), test.msg.Command())
		}
	}
}

func TestHnsLegacyMessageRejectsBitcoinOnlyPackets(t *testing.T) {
	var buf bytes.Buffer
	_, err := WriteHnsMessageN(&buf, NewMsgSendAddrV2(), ProtocolVersion, MainNet)
	if !errors.Is(err, ErrUnknownMessage) {
		t.Fatalf("WriteHnsMessageN error: got %v, want %v", err, ErrUnknownMessage)
	}

	encoded, err := EncodeHnsMessage(
		&HnsMsgSendCmpct{Mode: 1, Version: 1}, uint32(MainNet),
	)
	if err != nil {
		t.Fatalf("EncodeHnsMessage: %v", err)
	}
	_, _, _, err = ReadHnsMessageN(bytes.NewReader(encoded), ProtocolVersion, MainNet)
	if !errors.Is(err, ErrUnknownMessage) {
		t.Fatalf("ReadHnsMessageN error: got %v, want %v", err, ErrUnknownMessage)
	}
}

func TestHnsLegacyReadRejectsPayloadOverTypeMax(t *testing.T) {
	header := (&hnsMsgHeader{
		NetworkMagic:  uint32(MainNet),
		MessageType:   HnsMsgTypeGetAddr,
		PayloadLength: 1,
	}).Encode()
	encoded := append(header, 0x00)

	n, _, _, err := ReadHnsMessageN(
		bytes.NewReader(encoded), ProtocolVersion, MainNet,
	)
	if err == nil {
		t.Fatal("expected error for payload length above message type max")
	}
	var msgErr *MessageError
	if !errors.As(err, &msgErr) {
		t.Fatalf("error type: got %T, want *MessageError", err)
	}
	if n != len(encoded) {
		t.Fatalf("bytes read: got %d, want %d", n, len(encoded))
	}
}

func TestHnsLegacyReadDiscardsOversizedEnvelopePayload(t *testing.T) {
	nextMsg := NewMsgPing(0x0102030405060708)
	nextEncoded := bytes.Buffer{}
	if _, err := WriteHnsMessageN(
		&nextEncoded, nextMsg, ProtocolVersion, MainNet,
	); err != nil {
		t.Fatalf("WriteHnsMessageN: %v", err)
	}

	payloadLen := uint32(HnsMaxMessagePayload + 1)
	header := (&hnsMsgHeader{
		NetworkMagic:  uint32(MainNet),
		MessageType:   HnsMsgTypePing,
		PayloadLength: payloadLen,
	}).Encode()

	var stream bytes.Buffer
	stream.Write(header)
	stream.Write(bytes.Repeat([]byte{0xaa}, int(payloadLen)))
	stream.Write(nextEncoded.Bytes())

	n, _, _, err := ReadHnsMessageN(&stream, ProtocolVersion, MainNet)
	if err == nil {
		t.Fatal("expected error for payload length above envelope max")
	}
	var msgErr *MessageError
	if !errors.As(err, &msgErr) {
		t.Fatalf("error type: got %T, want *MessageError", err)
	}
	wantRead := HnsMessageHeaderSize + int(payloadLen)
	if n != wantRead {
		t.Fatalf("bytes read: got %d, want %d", n, wantRead)
	}

	n, decoded, _, err := ReadHnsMessageN(&stream, ProtocolVersion, MainNet)
	if err != nil {
		t.Fatalf("ReadHnsMessageN after oversized payload: %v", err)
	}
	got, ok := decoded.(*MsgPing)
	if !ok {
		t.Fatalf("decoded message: got %T, want *MsgPing", decoded)
	}
	if got.Nonce != nextMsg.Nonce {
		t.Fatalf("nonce: got %#x, want %#x", got.Nonce, nextMsg.Nonce)
	}
	if n != nextEncoded.Len() {
		t.Fatalf("bytes read after oversized payload: got %d, want %d", n, nextEncoded.Len())
	}
}

func TestHnsLegacyReadDiscardErrorsIncludePayloadBytes(t *testing.T) {
	tests := []struct {
		name   string
		header *hnsMsgHeader
		net    BitcoinNet
		errAs  any
	}{
		{
			name: "wrong network",
			header: &hnsMsgHeader{
				NetworkMagic:  uint32(TestNet),
				MessageType:   HnsMsgTypePing,
				PayloadLength: 8,
			},
			net:   MainNet,
			errAs: new(*MessageError),
		},
		{
			name: "unsupported message",
			header: &hnsMsgHeader{
				NetworkMagic:  uint32(MainNet),
				MessageType:   HnsMsgType(255),
				PayloadLength: 3,
			},
			net:   MainNet,
			errAs: new(UnsupportedHnsMsgTypeError),
		},
	}

	for _, test := range tests {
		encoded := append(test.header.Encode(), bytes.Repeat([]byte{0x00}, int(test.header.PayloadLength))...)
		n, _, _, err := ReadHnsMessageN(
			bytes.NewReader(encoded), ProtocolVersion, test.net,
		)
		if err == nil {
			t.Fatalf("%s: expected error", test.name)
		}
		if !errors.As(err, test.errAs) {
			t.Fatalf("%s: error type: got %T", test.name, err)
		}
		if n != len(encoded) {
			t.Fatalf("%s: bytes read: got %d, want %d", test.name, n, len(encoded))
		}
	}
}

func TestHnsLegacyRejectUnsupportedCommand(t *testing.T) {
	var buf bytes.Buffer
	_, err := WriteHnsMessageN(
		&buf, NewMsgReject("sendcmpct", RejectInvalid, "bad command"),
		ProtocolVersion, MainNet,
	)
	if err == nil {
		t.Fatal("expected unsupported reject command error")
	}
	var msgErr *MessageError
	if !errors.As(err, &msgErr) {
		t.Fatalf("error type: got %T, want *MessageError", err)
	}
	if !bytes.Contains([]byte(err.Error()), []byte(`unsupported reject command "sendcmpct"`)) {
		t.Fatalf("error text: %v", err)
	}
}

func TestHnsLegacyRejectRequiresRejectVersionOnRead(t *testing.T) {
	encoded, err := EncodeHnsMessage(&HnsMsgReject{
		Message: HnsMsgTypeVersion,
		Code:    RejectMalformed,
		Reason:  "bad version",
	}, uint32(MainNet))
	if err != nil {
		t.Fatalf("EncodeHnsMessage: %v", err)
	}

	_, _, _, err = ReadHnsMessageN(
		bytes.NewReader(encoded), RejectVersion-1, MainNet,
	)
	if err == nil {
		t.Fatal("expected reject message error below RejectVersion")
	}
	var msgErr *MessageError
	if !errors.As(err, &msgErr) {
		t.Fatalf("error type: got %T, want *MessageError", err)
	}
}
