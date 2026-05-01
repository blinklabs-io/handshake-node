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
//
// Portions of this file are derived from
// github.com/blinklabs-io/cdnsd/handshake/messages.go (MIT-licensed).

package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// HnsMessageHeaderSize is the size in bytes of the Handshake P2P message
// header: 4-byte network magic + 1-byte message type + 4-byte payload length.
// Handshake does not use the 4-byte SHA-256d checksum that Bitcoin appends.
const HnsMessageHeaderSize = 9

// HnsMaxMessagePayload is the maximum allowed Handshake P2P message payload
// size, matching hsd's `MAX_MESSAGE` (8 MB). This is independent of the
// btcd-derived MaxMessagePayload used elsewhere in this package while the
// migration to the Handshake envelope is in progress.
const HnsMaxMessagePayload = 8 * 1000 * 1000

// HnsMsgType identifies a Handshake P2P message in the wire envelope.
// Values match hsd's `lib/net/packets.js` `types` enum.
type HnsMsgType uint8

const (
	HnsMsgTypeVersion     HnsMsgType = 0
	HnsMsgTypeVerack      HnsMsgType = 1
	HnsMsgTypePing        HnsMsgType = 2
	HnsMsgTypePong        HnsMsgType = 3
	HnsMsgTypeGetAddr     HnsMsgType = 4
	HnsMsgTypeAddr        HnsMsgType = 5
	HnsMsgTypeInv         HnsMsgType = 6
	HnsMsgTypeGetData     HnsMsgType = 7
	HnsMsgTypeNotFound    HnsMsgType = 8
	HnsMsgTypeGetBlocks   HnsMsgType = 9
	HnsMsgTypeGetHeaders  HnsMsgType = 10
	HnsMsgTypeHeaders     HnsMsgType = 11
	HnsMsgTypeSendHeaders HnsMsgType = 12
	HnsMsgTypeBlock       HnsMsgType = 13
	HnsMsgTypeTx          HnsMsgType = 14
	HnsMsgTypeReject      HnsMsgType = 15
	HnsMsgTypeMempool     HnsMsgType = 16
	HnsMsgTypeFilterLoad  HnsMsgType = 17
	HnsMsgTypeFilterAdd   HnsMsgType = 18
	HnsMsgTypeFilterClear HnsMsgType = 19
	HnsMsgTypeMerkleBlock HnsMsgType = 20
	HnsMsgTypeFeeFilter   HnsMsgType = 21
	HnsMsgTypeSendCmpct   HnsMsgType = 22
	HnsMsgTypeCmpctBlock  HnsMsgType = 23
	HnsMsgTypeGetBlockTxn HnsMsgType = 24
	HnsMsgTypeBlockTxn    HnsMsgType = 25
	HnsMsgTypeGetProof    HnsMsgType = 26
	HnsMsgTypeProof       HnsMsgType = 27
	HnsMsgTypeClaim       HnsMsgType = 28
	HnsMsgTypeAirDrop     HnsMsgType = 29
	HnsMsgTypeUnknown     HnsMsgType = 30
)

// HandshakeMessage is the interface implemented by every Handshake P2P
// message. The byte-slice Encode/Decode shape mirrors cdnsd's reference
// implementation; it differs from btcd's `Message` interface by design while
// the wire package straddles both protocols.
type HandshakeMessage interface {
	Type() HnsMsgType
	Encode() []byte
	Decode([]byte) error
}

// UnsupportedHnsMsgTypeError is returned when a Handshake message of an
// unrecognized type is received over the wire.
type UnsupportedHnsMsgTypeError struct {
	MessageType HnsMsgType
}

func (e UnsupportedHnsMsgTypeError) Error() string {
	return fmt.Sprintf("unsupported handshake message type: %d", e.MessageType)
}

// hnsMsgHeader is the on-wire Handshake message header.
type hnsMsgHeader struct {
	NetworkMagic  uint32
	MessageType   HnsMsgType
	PayloadLength uint32
}

func (h *hnsMsgHeader) Encode() []byte {
	out := make([]byte, HnsMessageHeaderSize)
	binary.LittleEndian.PutUint32(out[0:4], h.NetworkMagic)
	out[4] = byte(h.MessageType)
	binary.LittleEndian.PutUint32(out[5:9], h.PayloadLength)
	return out
}

func (h *hnsMsgHeader) Decode(data []byte) error {
	if len(data) != HnsMessageHeaderSize {
		return fmt.Errorf(
			"handshake message header: expected %d bytes, got %d",
			HnsMessageHeaderSize, len(data),
		)
	}
	h.NetworkMagic = binary.LittleEndian.Uint32(data[0:4])
	h.MessageType = HnsMsgType(data[4])
	h.PayloadLength = binary.LittleEndian.Uint32(data[5:9])
	return nil
}

// EncodeHnsMessage serializes msg with the Handshake envelope (9-byte header
// followed by the encoded payload). Returns an error if the encoded payload
// exceeds HnsMaxMessagePayload.
func EncodeHnsMessage(msg HandshakeMessage, networkMagic uint32) ([]byte, error) {
	payload := msg.Encode()
	if len(payload) > HnsMaxMessagePayload {
		return nil, fmt.Errorf(
			"handshake message payload too large: %d > %d",
			len(payload), HnsMaxMessagePayload,
		)
	}
	header := &hnsMsgHeader{
		NetworkMagic:  networkMagic,
		MessageType:   msg.Type(),
		PayloadLength: uint32(len(payload)), //nolint:gosec
	}
	out := make([]byte, HnsMessageHeaderSize+len(payload))
	copy(out[:HnsMessageHeaderSize], header.Encode())
	copy(out[HnsMessageHeaderSize:], payload)
	return out, nil
}

// DecodeHnsMessage parses a complete Handshake message (header + payload)
// from data and returns the decoded message and the network magic from the
// header. Callers are responsible for verifying the magic against the
// expected network. The data slice must contain exactly one full message.
func DecodeHnsMessage(data []byte) (HandshakeMessage, uint32, error) {
	if len(data) < HnsMessageHeaderSize {
		return nil, 0, errors.New(
			"handshake message: data shorter than header",
		)
	}
	var header hnsMsgHeader
	if err := header.Decode(data[:HnsMessageHeaderSize]); err != nil {
		return nil, 0, err
	}
	if header.PayloadLength > HnsMaxMessagePayload {
		return nil, 0, fmt.Errorf(
			"handshake message payload too large: %d > %d",
			header.PayloadLength, HnsMaxMessagePayload,
		)
	}
	expected := HnsMessageHeaderSize + int(header.PayloadLength)
	if len(data) != expected {
		return nil, 0, fmt.Errorf(
			"handshake message: expected %d bytes total, got %d",
			expected, len(data),
		)
	}
	msg, err := newEmptyHnsMessage(header.MessageType)
	if err != nil {
		return nil, header.NetworkMagic, err
	}
	if err := msg.Decode(data[HnsMessageHeaderSize:]); err != nil {
		return nil, header.NetworkMagic, fmt.Errorf(
			"decode %T: %w", msg, err,
		)
	}
	return msg, header.NetworkMagic, nil
}

// newEmptyHnsMessage constructs an empty message of the given type, suitable
// for passing to Decode. Returns UnsupportedHnsMsgTypeError if the type is
// not yet implemented in this package.
func newEmptyHnsMessage(msgType HnsMsgType) (HandshakeMessage, error) {
	switch msgType {
	case HnsMsgTypeVerack:
		return &HnsMsgVerack{}, nil
	case HnsMsgTypePing:
		return &HnsMsgPing{}, nil
	case HnsMsgTypePong:
		return &HnsMsgPong{}, nil
	default:
		return nil, UnsupportedHnsMsgTypeError{MessageType: msgType}
	}
}

// HnsMsgVerack is the Handshake "verack" message, sent in response to a
// Version message to acknowledge the protocol handshake. It carries no
// payload.
type HnsMsgVerack struct{}

func (*HnsMsgVerack) Type() HnsMsgType { return HnsMsgTypeVerack }
func (*HnsMsgVerack) Encode() []byte   { return nil }
func (*HnsMsgVerack) Decode(data []byte) error {
	if len(data) != 0 {
		return fmt.Errorf("verack: expected empty payload, got %d bytes", len(data))
	}
	return nil
}

// HnsMsgPing is the Handshake "ping" message. The 8-byte nonce lets the
// receiver match a Pong response to the originating Ping.
type HnsMsgPing struct {
	Nonce [8]byte
}

func (*HnsMsgPing) Type() HnsMsgType { return HnsMsgTypePing }
func (m *HnsMsgPing) Encode() []byte {
	out := make([]byte, 8)
	copy(out, m.Nonce[:])
	return out
}

func (m *HnsMsgPing) Decode(data []byte) error {
	if len(data) != 8 {
		return fmt.Errorf("ping: expected 8-byte payload, got %d", len(data))
	}
	copy(m.Nonce[:], data)
	return nil
}

// HnsMsgPong is the Handshake "pong" message, echoing the nonce from a Ping.
type HnsMsgPong struct {
	Nonce [8]byte
}

func (*HnsMsgPong) Type() HnsMsgType { return HnsMsgTypePong }
func (m *HnsMsgPong) Encode() []byte {
	out := make([]byte, 8)
	copy(out, m.Nonce[:])
	return out
}

func (m *HnsMsgPong) Decode(data []byte) error {
	if len(data) != 8 {
		return fmt.Errorf("pong: expected 8-byte payload, got %d", len(data))
	}
	copy(m.Nonce[:], data)
	return nil
}
