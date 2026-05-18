// Copyright (c) 2025-2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.
//
// Portions of this file are derived from cdnsd
// (https://github.com/blinklabs-io/cdnsd) handshake/messages.go, which is
// Copyright 2025 Blink Labs Software and licensed under the MIT license.
// The cdnsd code was itself ported from hsd/hnsd.

package wire

import (
	"bytes"
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
	case HnsMsgTypeVersion:
		return &HnsMsgVersion{}, nil
	case HnsMsgTypeVerack:
		return &HnsMsgVerack{}, nil
	case HnsMsgTypePing:
		return &HnsMsgPing{}, nil
	case HnsMsgTypePong:
		return &HnsMsgPong{}, nil
	case HnsMsgTypeGetAddr:
		return &HnsMsgGetAddr{}, nil
	case HnsMsgTypeAddr:
		return &HnsMsgAddr{}, nil
	case HnsMsgTypeInv:
		return &HnsMsgInv{}, nil
	case HnsMsgTypeGetData:
		return &HnsMsgGetData{}, nil
	case HnsMsgTypeNotFound:
		return &HnsMsgNotFound{}, nil
	case HnsMsgTypeGetBlocks:
		return &HnsMsgGetBlocks{}, nil
	case HnsMsgTypeGetHeaders:
		return &HnsMsgGetHeaders{}, nil
	case HnsMsgTypeHeaders:
		return &HnsMsgHeaders{}, nil
	case HnsMsgTypeSendHeaders:
		return &HnsMsgSendHeaders{}, nil
	case HnsMsgTypeBlock:
		return &HnsMsgBlock{}, nil
	case HnsMsgTypeTx:
		return &HnsMsgTx{}, nil
	case HnsMsgTypeMempool:
		return &HnsMsgMemPool{}, nil
	case HnsMsgTypeFilterAdd:
		return &HnsMsgFilterAdd{}, nil
	case HnsMsgTypeFilterClear:
		return &HnsMsgFilterClear{}, nil
	case HnsMsgTypeFeeFilter:
		return &HnsMsgFeeFilter{}, nil
	case HnsMsgTypeSendCmpct:
		return &HnsMsgSendCmpct{}, nil
	case HnsMsgTypeGetProof:
		return &HnsMsgGetProof{}, nil
	case HnsMsgTypeProof:
		return &HnsMsgProof{}, nil
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

// HnsMsgGetAddr is the Handshake "getaddr" message, requesting known peers
// from the remote node. It carries no payload.
type HnsMsgGetAddr struct{}

func (*HnsMsgGetAddr) Type() HnsMsgType { return HnsMsgTypeGetAddr }
func (*HnsMsgGetAddr) Encode() []byte   { return nil }
func (*HnsMsgGetAddr) Decode(data []byte) error {
	if len(data) != 0 {
		return fmt.Errorf("getaddr: expected empty payload, got %d bytes", len(data))
	}
	return nil
}

// HnsMsgAddr is the Handshake "addr" message. It advertises peers using the
// Handshake 88-byte NetAddress shape, which includes each peer's static key.
type HnsMsgAddr struct {
	Peers []HnsNetAddress
}

func (*HnsMsgAddr) Type() HnsMsgType { return HnsMsgTypeAddr }
func (m *HnsMsgAddr) Encode() []byte {
	count := hnsWriteUvarint(uint64(len(m.Peers)))
	out := make([]byte, len(count)+(len(m.Peers)*HnsNetAddressSize))
	copy(out, count)
	off := len(count)
	for i := range m.Peers {
		copy(out[off:off+HnsNetAddressSize], m.Peers[i].Encode())
		off += HnsNetAddressSize
	}
	return out
}

func (m *HnsMsgAddr) Decode(data []byte) error {
	count, bytesRead, err := hnsReadUvarint(data)
	if err != nil {
		return fmt.Errorf("addr: peer count: %w", err)
	}
	data = data[bytesRead:]
	if count > uint64(len(data)/HnsNetAddressSize) {
		return fmt.Errorf(
			"addr: peer count %d exceeds payload length %d",
			count, len(data),
		)
	}
	wantLen := int(count) * HnsNetAddressSize
	if len(data) != wantLen {
		return fmt.Errorf(
			"addr: invalid payload length for %d peers: got %d, want %d",
			count, len(data), wantLen,
		)
	}
	m.Peers = make([]HnsNetAddress, int(count))
	for i := range m.Peers {
		if err := m.Peers[i].Decode(data[:HnsNetAddressSize]); err != nil {
			return fmt.Errorf("addr: peer %d: %w", i, err)
		}
		data = data[HnsNetAddressSize:]
	}
	return nil
}

const HnsInvItemSize = 36

const (
	HnsInvTypeTx            uint32 = 1
	HnsInvTypeBlock         uint32 = 2
	HnsInvTypeFilteredBlock uint32 = 3
	HnsInvTypeCmpctBlock    uint32 = 4
	HnsInvTypeClaim         uint32 = 5
	HnsInvTypeAirDrop       uint32 = 6
)

// HnsInvItem identifies an object by type and hash in Handshake inventory
// messages.
type HnsInvItem struct {
	Type uint32
	Hash [32]byte
}

func (i *HnsInvItem) Encode() []byte {
	out := make([]byte, HnsInvItemSize)
	binary.LittleEndian.PutUint32(out[0:4], i.Type)
	copy(out[4:36], i.Hash[:])
	return out
}

func (i *HnsInvItem) Decode(data []byte) error {
	if len(data) != HnsInvItemSize {
		return fmt.Errorf(
			"handshake inventory item: expected %d bytes, got %d",
			HnsInvItemSize, len(data),
		)
	}
	i.Type = binary.LittleEndian.Uint32(data[0:4])
	copy(i.Hash[:], data[4:36])
	return nil
}

// HnsMsgInv is the Handshake "inv" message. It announces inventory available
// from the peer.
type HnsMsgInv struct {
	Inventory []HnsInvItem
}

func (*HnsMsgInv) Type() HnsMsgType { return HnsMsgTypeInv }
func (m *HnsMsgInv) Encode() []byte {
	return hnsEncodeInvItems(m.Inventory)
}

func (m *HnsMsgInv) Decode(data []byte) error {
	inventory, err := hnsDecodeInvItems("inv", data)
	if err != nil {
		return err
	}
	m.Inventory = inventory
	return nil
}

// HnsMsgGetData is the Handshake "getdata" message. It requests inventory
// items previously announced by a peer.
type HnsMsgGetData struct {
	Inventory []HnsInvItem
}

func (*HnsMsgGetData) Type() HnsMsgType { return HnsMsgTypeGetData }
func (m *HnsMsgGetData) Encode() []byte {
	return hnsEncodeInvItems(m.Inventory)
}

func (m *HnsMsgGetData) Decode(data []byte) error {
	inventory, err := hnsDecodeInvItems("getdata", data)
	if err != nil {
		return err
	}
	m.Inventory = inventory
	return nil
}

// HnsMsgNotFound is the Handshake "notfound" message. It returns requested
// inventory items that the peer could not provide.
type HnsMsgNotFound struct {
	Inventory []HnsInvItem
}

func (*HnsMsgNotFound) Type() HnsMsgType { return HnsMsgTypeNotFound }
func (m *HnsMsgNotFound) Encode() []byte {
	return hnsEncodeInvItems(m.Inventory)
}

func (m *HnsMsgNotFound) Decode(data []byte) error {
	inventory, err := hnsDecodeInvItems("notfound", data)
	if err != nil {
		return err
	}
	m.Inventory = inventory
	return nil
}

func hnsEncodeInvItems(inventory []HnsInvItem) []byte {
	count := hnsWriteUvarint(uint64(len(inventory)))
	out := make([]byte, len(count)+(len(inventory)*HnsInvItemSize))
	copy(out, count)
	off := len(count)
	for i := range inventory {
		copy(out[off:off+HnsInvItemSize], inventory[i].Encode())
		off += HnsInvItemSize
	}
	return out
}

func hnsDecodeInvItems(msgName string, data []byte) ([]HnsInvItem, error) {
	count, bytesRead, err := hnsReadUvarint(data)
	if err != nil {
		return nil, fmt.Errorf("%s: inventory count: %w", msgName, err)
	}
	data = data[bytesRead:]
	if count > uint64(len(data)/HnsInvItemSize) {
		return nil, fmt.Errorf(
			"%s: inventory count %d exceeds payload length %d",
			msgName, count, len(data),
		)
	}
	wantLen := int(count) * HnsInvItemSize
	if len(data) != wantLen {
		return nil, fmt.Errorf(
			"%s: invalid payload length for %d inventory items: got %d, want %d",
			msgName, count, len(data), wantLen,
		)
	}
	inventory := make([]HnsInvItem, int(count))
	for i := range inventory {
		if err := inventory[i].Decode(data[:HnsInvItemSize]); err != nil {
			return nil, fmt.Errorf("%s: inventory %d: %w", msgName, i, err)
		}
		data = data[HnsInvItemSize:]
	}
	return inventory, nil
}

// HnsMsgGetBlocks is the Handshake "getblocks" message. It requests block
// inventory after one of the locator hashes, stopping at StopHash when set.
type HnsMsgGetBlocks struct {
	Locator  [][32]byte
	StopHash [32]byte
}

func (*HnsMsgGetBlocks) Type() HnsMsgType { return HnsMsgTypeGetBlocks }
func (m *HnsMsgGetBlocks) Encode() []byte {
	count := hnsWriteUvarint(uint64(len(m.Locator)))
	out := make([]byte, len(count)+(len(m.Locator)*32)+32)
	copy(out, count)
	off := len(count)
	for i := range m.Locator {
		copy(out[off:off+32], m.Locator[i][:])
		off += 32
	}
	copy(out[off:off+32], m.StopHash[:])
	return out
}

func (m *HnsMsgGetBlocks) Decode(data []byte) error {
	count, bytesRead, err := hnsReadUvarint(data)
	if err != nil {
		return fmt.Errorf("getblocks: locator count: %w", err)
	}
	data = data[bytesRead:]
	if len(data) < 32 {
		return fmt.Errorf("getblocks: payload missing stop hash")
	}
	locatorBytes := len(data) - 32
	if count > uint64(locatorBytes/32) {
		return fmt.Errorf(
			"getblocks: locator count %d exceeds payload length %d",
			count, len(data),
		)
	}
	wantLen := int(count)*32 + 32
	if len(data) != wantLen {
		return fmt.Errorf(
			"getblocks: invalid payload length for %d locators: got %d, want %d",
			count, len(data), wantLen,
		)
	}
	m.Locator = make([][32]byte, int(count))
	for i := range m.Locator {
		copy(m.Locator[i][:], data[:32])
		data = data[32:]
	}
	copy(m.StopHash[:], data[:32])
	return nil
}

// HnsMsgGetHeaders is the Handshake "getheaders" message. It requests a
// header chain after one of the locator hashes, stopping at StopHash when set.
type HnsMsgGetHeaders struct {
	Locator  [][32]byte
	StopHash [32]byte
}

func (*HnsMsgGetHeaders) Type() HnsMsgType { return HnsMsgTypeGetHeaders }
func (m *HnsMsgGetHeaders) Encode() []byte {
	count := hnsWriteUvarint(uint64(len(m.Locator)))
	out := make([]byte, len(count)+(len(m.Locator)*32)+32)
	copy(out, count)
	off := len(count)
	for i := range m.Locator {
		copy(out[off:off+32], m.Locator[i][:])
		off += 32
	}
	copy(out[off:off+32], m.StopHash[:])
	return out
}

func (m *HnsMsgGetHeaders) Decode(data []byte) error {
	count, bytesRead, err := hnsReadUvarint(data)
	if err != nil {
		return fmt.Errorf("getheaders: locator count: %w", err)
	}
	data = data[bytesRead:]
	if len(data) < 32 {
		return fmt.Errorf("getheaders: payload missing stop hash")
	}
	locatorBytes := len(data) - 32
	if count > uint64(locatorBytes/32) {
		return fmt.Errorf(
			"getheaders: locator count %d exceeds payload length %d",
			count, len(data),
		)
	}
	wantLen := int(count)*32 + 32
	if len(data) != wantLen {
		return fmt.Errorf(
			"getheaders: invalid payload length for %d locators: got %d, want %d",
			count, len(data), wantLen,
		)
	}
	m.Locator = make([][32]byte, int(count))
	for i := range m.Locator {
		copy(m.Locator[i][:], data[:32])
		data = data[32:]
	}
	copy(m.StopHash[:], data[:32])
	return nil
}

// HnsMsgHeaders is the Handshake "headers" message. It carries a count
// followed by raw 236-byte Handshake block headers.
type HnsMsgHeaders struct {
	Headers []*BlockHeader
}

func (*HnsMsgHeaders) Type() HnsMsgType { return HnsMsgTypeHeaders }
func (m *HnsMsgHeaders) Encode() []byte {
	count := hnsWriteUvarint(uint64(len(m.Headers)))
	out := make([]byte, 0, len(count)+(len(m.Headers)*MaxBlockHeaderPayload))
	out = append(out, count...)
	for _, header := range m.Headers {
		var buf bytes.Buffer
		_ = header.Serialize(&buf)
		out = append(out, buf.Bytes()...)
	}
	return out
}

func (m *HnsMsgHeaders) Decode(data []byte) error {
	count, bytesRead, err := hnsReadUvarint(data)
	if err != nil {
		return fmt.Errorf("headers: header count: %w", err)
	}
	data = data[bytesRead:]
	if count > uint64(len(data)/MaxBlockHeaderPayload) {
		return fmt.Errorf(
			"headers: header count %d exceeds payload length %d",
			count, len(data),
		)
	}
	wantLen := int(count) * MaxBlockHeaderPayload
	if len(data) != wantLen {
		return fmt.Errorf(
			"headers: invalid payload length for %d headers: got %d, want %d",
			count, len(data), wantLen,
		)
	}
	headers := make([]BlockHeader, int(count))
	m.Headers = make([]*BlockHeader, 0, int(count))
	for i := range headers {
		if err := headers[i].Deserialize(bytes.NewReader(data[:MaxBlockHeaderPayload])); err != nil {
			return fmt.Errorf("headers: header %d: %w", i, err)
		}
		m.Headers = append(m.Headers, &headers[i])
		data = data[MaxBlockHeaderPayload:]
	}
	return nil
}

// HnsMsgSendHeaders is the Handshake "sendheaders" message. It requests that
// peers announce new blocks with Headers messages instead of Inv messages.
type HnsMsgSendHeaders struct{}

func (*HnsMsgSendHeaders) Type() HnsMsgType { return HnsMsgTypeSendHeaders }
func (*HnsMsgSendHeaders) Encode() []byte   { return nil }
func (*HnsMsgSendHeaders) Decode(data []byte) error {
	if len(data) != 0 {
		return fmt.Errorf("sendheaders: expected empty payload, got %d bytes", len(data))
	}
	return nil
}

// HnsMsgBlock is the Handshake "block" message. It reuses the existing
// Handshake-shaped MsgBlock serializer from Phase 1.
type HnsMsgBlock struct {
	Block MsgBlock
}

func (*HnsMsgBlock) Type() HnsMsgType { return HnsMsgTypeBlock }
func (m *HnsMsgBlock) Encode() []byte {
	var buf bytes.Buffer
	_ = m.Block.Serialize(&buf)
	return buf.Bytes()
}

func (m *HnsMsgBlock) Decode(data []byte) error {
	if len(data) == 0 {
		return errors.New("block: empty payload")
	}
	if err := m.Block.Deserialize(bytes.NewReader(data)); err != nil {
		return fmt.Errorf("block: %w", err)
	}
	return nil
}

// HnsMsgTx is the Handshake "tx" message. It reuses the existing
// Handshake-shaped MsgTx serializer from Phase 1.
type HnsMsgTx struct {
	Tx MsgTx
}

func (*HnsMsgTx) Type() HnsMsgType { return HnsMsgTypeTx }
func (m *HnsMsgTx) Encode() []byte {
	var buf bytes.Buffer
	_ = m.Tx.Serialize(&buf)
	return buf.Bytes()
}

func (m *HnsMsgTx) Decode(data []byte) error {
	if len(data) == 0 {
		return errors.New("tx: empty payload")
	}
	if err := m.Tx.Deserialize(bytes.NewReader(data)); err != nil {
		return fmt.Errorf("tx: %w", err)
	}
	return nil
}

// HnsMsgMemPool is the Handshake "mempool" message. It requests the peer's
// mempool inventory and carries no payload.
type HnsMsgMemPool struct{}

func (*HnsMsgMemPool) Type() HnsMsgType { return HnsMsgTypeMempool }
func (*HnsMsgMemPool) Encode() []byte   { return nil }
func (*HnsMsgMemPool) Decode(data []byte) error {
	if len(data) != 0 {
		return fmt.Errorf("mempool: expected empty payload, got %d bytes", len(data))
	}
	return nil
}

// HnsMsgFilterAdd is the Handshake "filteradd" message. It appends one item
// to the peer's loaded bloom filter.
type HnsMsgFilterAdd struct {
	Data []byte
}

func (*HnsMsgFilterAdd) Type() HnsMsgType { return HnsMsgTypeFilterAdd }
func (m *HnsMsgFilterAdd) Encode() []byte {
	count := hnsWriteUvarint(uint64(len(m.Data)))
	out := make([]byte, len(count)+len(m.Data))
	copy(out, count)
	copy(out[len(count):], m.Data)
	return out
}

func (m *HnsMsgFilterAdd) Decode(data []byte) error {
	count, bytesRead, err := hnsReadUvarint(data)
	if err != nil {
		return fmt.Errorf("filteradd: data length: %w", err)
	}
	data = data[bytesRead:]
	if count > uint64(len(data)) {
		return fmt.Errorf(
			"filteradd: data length %d exceeds payload length %d",
			count, len(data),
		)
	}
	if len(data) != int(count) {
		return fmt.Errorf(
			"filteradd: invalid payload length: got %d, want %d",
			len(data), count,
		)
	}
	m.Data = append(m.Data[:0], data...)
	return nil
}

// HnsMsgFilterClear is the Handshake "filterclear" message. It clears the
// peer's loaded bloom filter and carries no payload.
type HnsMsgFilterClear struct{}

func (*HnsMsgFilterClear) Type() HnsMsgType { return HnsMsgTypeFilterClear }
func (*HnsMsgFilterClear) Encode() []byte   { return nil }
func (*HnsMsgFilterClear) Decode(data []byte) error {
	if len(data) != 0 {
		return fmt.Errorf("filterclear: expected empty payload, got %d bytes", len(data))
	}
	return nil
}

// HnsMsgFeeFilter is the Handshake "feefilter" message. Rate is encoded as a
// signed 64-bit fee rate in dollarydoos per kilobyte.
type HnsMsgFeeFilter struct {
	Rate int64
}

func (*HnsMsgFeeFilter) Type() HnsMsgType { return HnsMsgTypeFeeFilter }
func (m *HnsMsgFeeFilter) Encode() []byte {
	out := make([]byte, 8)
	binary.LittleEndian.PutUint64(out, uint64(m.Rate))
	return out
}

func (m *HnsMsgFeeFilter) Decode(data []byte) error {
	if len(data) != 8 {
		return fmt.Errorf("feefilter: expected 8-byte payload, got %d", len(data))
	}
	m.Rate = int64(binary.LittleEndian.Uint64(data))
	return nil
}

// HnsMsgSendCmpct is the Handshake "sendcmpct" message. It negotiates compact
// block announcements.
type HnsMsgSendCmpct struct {
	Mode    uint8
	Version uint64
}

func (*HnsMsgSendCmpct) Type() HnsMsgType { return HnsMsgTypeSendCmpct }
func (m *HnsMsgSendCmpct) Encode() []byte {
	out := make([]byte, 9)
	out[0] = m.Mode
	binary.LittleEndian.PutUint64(out[1:9], m.Version)
	return out
}

func (m *HnsMsgSendCmpct) Decode(data []byte) error {
	if len(data) != 9 {
		return fmt.Errorf("sendcmpct: expected 9-byte payload, got %d", len(data))
	}
	m.Mode = data[0]
	m.Version = binary.LittleEndian.Uint64(data[1:9])
	return nil
}

// HnsMsgGetProof is the Handshake "getproof" message. It requests an Urkel
// proof for Key at Root.
type HnsMsgGetProof struct {
	Root [32]byte
	Key  [32]byte
}

func (*HnsMsgGetProof) Type() HnsMsgType { return HnsMsgTypeGetProof }
func (m *HnsMsgGetProof) Encode() []byte {
	out := make([]byte, 64)
	copy(out[0:32], m.Root[:])
	copy(out[32:64], m.Key[:])
	return out
}

func (m *HnsMsgGetProof) Decode(data []byte) error {
	if len(data) != 64 {
		return fmt.Errorf("getproof: expected 64-byte payload, got %d", len(data))
	}
	copy(m.Root[:], data[0:32])
	copy(m.Key[:], data[32:64])
	return nil
}

// HnsMsgProof is the Handshake "proof" message. The Urkel proof body is kept
// opaque until the Phase 4 name-system implementation provides a native proof
// type and verifier.
type HnsMsgProof struct {
	Root  [32]byte
	Key   [32]byte
	Proof []byte
}

func (*HnsMsgProof) Type() HnsMsgType { return HnsMsgTypeProof }
func (m *HnsMsgProof) Encode() []byte {
	out := make([]byte, 64+len(m.Proof))
	copy(out[0:32], m.Root[:])
	copy(out[32:64], m.Key[:])
	copy(out[64:], m.Proof)
	return out
}

func (m *HnsMsgProof) Decode(data []byte) error {
	if len(data) < 64 {
		return fmt.Errorf("proof: expected at least 64 bytes, got %d", len(data))
	}
	copy(m.Root[:], data[0:32])
	copy(m.Key[:], data[32:64])
	m.Proof = append(m.Proof[:0], data[64:]...)
	return nil
}

func hnsReadUvarint(data []byte) (uint64, int, error) {
	if len(data) == 0 {
		return 0, 0, errors.New("data is empty")
	}
	switch data[0] {
	case 0xff:
		if len(data) < 9 {
			return 0, 0, errors.New("invalid length for uint64")
		}
		val := binary.LittleEndian.Uint64(data[1:9])
		min := uint64(0x100000000)
		if val < min {
			return 0, 0, fmt.Errorf(errNonCanonicalVarInt, val, data[0], min)
		}
		return val, 9, nil
	case 0xfe:
		if len(data) < 5 {
			return 0, 0, errors.New("invalid length for uint32")
		}
		val := uint64(binary.LittleEndian.Uint32(data[1:5]))
		min := uint64(0x10000)
		if val < min {
			return 0, 0, fmt.Errorf(errNonCanonicalVarInt, val, data[0], min)
		}
		return val, 5, nil
	case 0xfd:
		if len(data) < 3 {
			return 0, 0, errors.New("invalid length for uint16")
		}
		val := uint64(binary.LittleEndian.Uint16(data[1:3]))
		min := uint64(0xfd)
		if val < min {
			return 0, 0, fmt.Errorf(errNonCanonicalVarInt, val, data[0], min)
		}
		return val, 3, nil
	default:
		return uint64(data[0]), 1, nil
	}
}

func hnsWriteUvarint(val uint64) []byte {
	switch {
	case val < 0xfd:
		return []byte{uint8(val)}
	case val <= 0xffff:
		out := make([]byte, 3)
		out[0] = 0xfd
		binary.LittleEndian.PutUint16(out[1:3], uint16(val))
		return out
	case val <= 0xffffffff:
		out := make([]byte, 5)
		out[0] = 0xfe
		binary.LittleEndian.PutUint32(out[1:5], uint32(val))
		return out
	default:
		out := make([]byte, 9)
		out[0] = 0xff
		binary.LittleEndian.PutUint64(out[1:9], val)
		return out
	}
}
