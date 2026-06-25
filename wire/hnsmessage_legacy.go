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
	"fmt"
	"io"
	"time"

	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
)

const maxInt64Unix = int64(1<<63 - 1)

// WriteHnsMessageN writes msg using the Handshake 9-byte type-byte envelope.
// It returns the number of bytes written, including the envelope.
func WriteHnsMessageN(w io.Writer, msg Message, pver uint32,
	hnsnet BitcoinNet) (int, error) {

	return WriteHnsMessageWithEncodingN(w, msg, pver, hnsnet, WitnessEncoding)
}

// WriteHnsMessage writes msg using the Handshake 9-byte type-byte envelope.
func WriteHnsMessage(w io.Writer, msg Message, pver uint32,
	hnsnet BitcoinNet) error {

	_, err := WriteHnsMessageN(w, msg, pver, hnsnet)
	return err
}

// WriteHnsMessageWithEncodingN writes msg using the Handshake 9-byte type-byte
// envelope and converts the existing btcd-shaped Message structs into their
// Handshake packet equivalents. This compatibility layer lets active peer
// traffic move to the Handshake envelope before the broader peer listener API
// is renamed around Handshake packet structs.
func WriteHnsMessageWithEncodingN(w io.Writer, msg Message, pver uint32,
	hnsnet BitcoinNet, encoding MessageEncoding) (int, error) {

	hnsMsg, err := HnsMessageFromLegacy(msg, pver, encoding)
	if err != nil {
		return 0, err
	}
	return WriteHandshakeMessageN(w, hnsMsg, hnsnet)
}

// WriteHandshakeMessageN writes msg using the native Handshake 9-byte
// type-byte envelope. It returns the number of bytes written, including the
// envelope.
func WriteHandshakeMessageN(w io.Writer, msg HandshakeMessage,
	hnsnet BitcoinNet) (int, error) {

	encoded, err := EncodeHnsMessage(msg, uint32(hnsnet))
	if err != nil {
		return 0, err
	}
	return w.Write(encoded)
}

// ReadHnsMessageN reads a Handshake-envelope message and converts it into the
// existing btcd-shaped Message structs used by peer/netsync during the Phase 2
// cutover.
func ReadHnsMessageN(r io.Reader, pver uint32,
	hnsnet BitcoinNet) (int, Message, []byte, error) {

	return ReadHnsMessageWithEncodingN(r, pver, hnsnet, WitnessEncoding)
}

// ReadHnsMessage reads a Handshake-envelope message.
func ReadHnsMessage(r io.Reader, pver uint32,
	hnsnet BitcoinNet) (Message, []byte, error) {

	_, msg, buf, err := ReadHnsMessageN(r, pver, hnsnet)
	return msg, buf, err
}

// ReadHnsMessageWithEncodingN reads, validates, and parses the next Handshake
// message from r. It returns the number of bytes read, the compatibility
// Message, and the raw Handshake payload bytes.
func ReadHnsMessageWithEncodingN(r io.Reader, pver uint32,
	hnsnet BitcoinNet, enc MessageEncoding) (int, Message, []byte, error) {

	n, hnsMsg, payload, err := ReadHandshakeMessageN(r, hnsnet)
	if err != nil {
		return n, nil, nil, err
	}

	msg, err := LegacyMessageFromHns(hnsMsg, pver, enc)
	if err != nil {
		return n, nil, nil, err
	}

	return n, msg, payload, nil
}

// ReadHandshakeMessageN reads, validates, and parses the next native
// Handshake message from r. It returns the number of bytes read, the decoded
// Handshake message, and the raw Handshake payload bytes.
func ReadHandshakeMessageN(r io.Reader,
	hnsnet BitcoinNet) (int, HandshakeMessage, []byte, error) {

	totalBytes := 0
	var headerBytes [HnsMessageHeaderSize]byte
	n, err := io.ReadFull(r, headerBytes[:])
	totalBytes += n
	if err != nil {
		return totalBytes, nil, nil, err
	}

	var hdr hnsMsgHeader
	if err := hdr.Decode(headerBytes[:]); err != nil {
		return totalBytes, nil, nil, err
	}

	if hdr.PayloadLength > HnsMaxMessagePayload {
		discardInput(r, hdr.PayloadLength)
		totalBytes += int(hdr.PayloadLength)
		str := fmt.Sprintf("message payload is too large - header "+
			"indicates %d bytes, but max message payload is %d "+
			"bytes.", hdr.PayloadLength, HnsMaxMessagePayload)
		return totalBytes, nil, nil, messageError("ReadHnsMessage", str)
	}

	if BitcoinNet(hdr.NetworkMagic) != hnsnet {
		discardInput(r, hdr.PayloadLength)
		totalBytes += int(hdr.PayloadLength)
		str := fmt.Sprintf("message from other network [%v]",
			BitcoinNet(hdr.NetworkMagic))
		return totalBytes, nil, nil, messageError("ReadHnsMessage", str)
	}

	hnsMsg, err := newEmptyHnsMessage(hdr.MessageType)
	if err != nil {
		discardInput(r, hdr.PayloadLength)
		totalBytes += int(hdr.PayloadLength)
		return totalBytes, nil, nil, err
	}

	mpl := maxHnsPayloadLength(hnsMsg)
	if hdr.PayloadLength > mpl {
		discardInput(r, hdr.PayloadLength)
		totalBytes += int(hdr.PayloadLength)
		str := fmt.Sprintf("payload exceeds max length - header "+
			"indicates %v bytes, but max payload size for "+
			"messages of type [%v] is %v.", hdr.PayloadLength,
			hdr.MessageType, mpl)
		return totalBytes, nil, nil, messageError("ReadHnsMessage", str)
	}

	payload := make([]byte, hdr.PayloadLength)
	n, err = io.ReadFull(r, payload)
	totalBytes += n
	if err != nil {
		return totalBytes, nil, nil, err
	}

	if err := hnsMsg.Decode(payload); err != nil {
		return totalBytes, nil, nil, fmt.Errorf(
			"decode %T: %w", hnsMsg, err,
		)
	}

	return totalBytes, hnsMsg, payload, nil
}

// HnsMessageFromLegacy converts the btcd-shaped Message structs still used by
// callers during the Phase 2 migration into native Handshake packet structs.
func HnsMessageFromLegacy(msg Message, pver uint32,
	enc MessageEncoding) (HandshakeMessage, error) {

	switch m := msg.(type) {
	case *MsgVersion:
		if len(m.UserAgent) > MaxUserAgentLen {
			str := fmt.Sprintf("user agent too long [len %v, max %v]",
				len(m.UserAgent), MaxUserAgentLen)
			return nil, messageError("MsgVersion", str)
		}
		agent := m.UserAgent
		if len(agent) > HnsMaxUserAgentLen {
			// Legacy MsgVersion allows 256 bytes; the HNS packet can only
			// carry 255 because its agent length is a single byte.
			agent = agent[:HnsMaxUserAgentLen]
		}
		return &HnsMsgVersion{
			Version:  uint32(m.ProtocolVersion),
			Services: uint64(m.Services),
			Time:     hnsTimeFromTime(m.Timestamp),
			Remote:   hnsNetAddressFromLegacy(&m.AddrYou),
			Nonce:    hnsNonceFromUint64(m.Nonce),
			Agent:    agent,
			Height:   uint32(m.LastBlock),
			NoRelay:  m.DisableRelayTx,
		}, nil

	case *MsgVerAck:
		return &HnsMsgVerack{}, nil

	case *MsgPing:
		return &HnsMsgPing{Nonce: hnsNonceFromUint64(m.Nonce)}, nil

	case *MsgPong:
		return &HnsMsgPong{Nonce: hnsNonceFromUint64(m.Nonce)}, nil

	case *MsgGetAddr:
		return &HnsMsgGetAddr{}, nil

	case *MsgAddr:
		peers := make([]HnsNetAddress, len(m.AddrList))
		for i := range m.AddrList {
			peers[i] = hnsNetAddressFromLegacy(m.AddrList[i])
		}
		return &HnsMsgAddr{Peers: peers}, nil

	case *MsgInv:
		return &HnsMsgInv{Inventory: hnsInvItemsFromLegacy(m.InvList)}, nil

	case *MsgGetData:
		return &HnsMsgGetData{Inventory: hnsInvItemsFromLegacy(m.InvList)}, nil

	case *MsgNotFound:
		return &HnsMsgNotFound{Inventory: hnsInvItemsFromLegacy(m.InvList)}, nil

	case *MsgGetBlocks:
		return &HnsMsgGetBlocks{
			Locator:  hnsLocatorFromLegacy(m.BlockLocatorHashes),
			StopHash: hnsHashFromChainHash(&m.HashStop),
		}, nil

	case *MsgGetHeaders:
		return &HnsMsgGetHeaders{
			Locator:  hnsLocatorFromLegacy(m.BlockLocatorHashes),
			StopHash: hnsHashFromChainHash(&m.HashStop),
		}, nil

	case *MsgHeaders:
		return &HnsMsgHeaders{Headers: m.Headers}, nil

	case *MsgSendHeaders:
		return &HnsMsgSendHeaders{}, nil

	case *MsgBlock:
		return &HnsMsgBlock{Block: *m}, nil

	case *MsgTx:
		return &HnsMsgTx{Tx: *m}, nil

	case *MsgReject:
		if pver < RejectVersion {
			str := fmt.Sprintf("reject message invalid for protocol "+
				"version %d", pver)
			return nil, messageError("MsgReject", str)
		}
		msgType, ok := hnsMsgTypeFromCommand(m.Cmd)
		if !ok {
			str := fmt.Sprintf("unsupported reject command %q", m.Cmd)
			return nil, messageError("MsgReject", str)
		}
		return &HnsMsgReject{
			Message: msgType,
			Code:    m.Code,
			Reason:  m.Reason,
			Hash:    hnsHashFromChainHash(&m.Hash),
		}, nil

	case *MsgMemPool:
		return &HnsMsgMemPool{}, nil

	case *MsgFilterLoad:
		return &HnsMsgFilterLoad{
			Filter:    append([]byte(nil), m.Filter...),
			HashFuncs: m.HashFuncs,
			Tweak:     m.Tweak,
			Flags:     m.Flags,
		}, nil

	case *MsgFilterAdd:
		return &HnsMsgFilterAdd{Data: append([]byte(nil), m.Data...)}, nil

	case *MsgFilterClear:
		return &HnsMsgFilterClear{}, nil

	case *MsgMerkleBlock:
		payload, err := encodeLegacyPayload(m, pver, enc)
		if err != nil {
			return nil, err
		}
		return &HnsMsgMerkleBlock{Payload: payload}, nil

	case *MsgFeeFilter:
		return &HnsMsgFeeFilter{Rate: m.MinFee}, nil
	}

	return nil, ErrUnknownMessage
}

// LegacyMessageFromHns converts a native Handshake packet into the
// btcd-shaped Message structs used by legacy call sites during the Phase 2
// migration.
func LegacyMessageFromHns(hnsMsg HandshakeMessage, pver uint32,
	enc MessageEncoding) (Message, error) {

	switch m := hnsMsg.(type) {
	case *HnsMsgVersion:
		return &MsgVersion{
			ProtocolVersion: int32(m.Version),
			Services:        ServiceFlag(m.Services),
			Timestamp:       hnsTimeToTime(m.Time),
			AddrYou:         legacyNetAddressFromHns(&m.Remote),
			Nonce:           uint64FromHnsNonce(m.Nonce),
			UserAgent:       m.Agent,
			LastBlock:       int32(m.Height),
			DisableRelayTx:  m.NoRelay,
		}, nil

	case *HnsMsgVerack:
		return &MsgVerAck{}, nil

	case *HnsMsgPing:
		return &MsgPing{Nonce: uint64FromHnsNonce(m.Nonce)}, nil

	case *HnsMsgPong:
		return &MsgPong{Nonce: uint64FromHnsNonce(m.Nonce)}, nil

	case *HnsMsgGetAddr:
		return &MsgGetAddr{}, nil

	case *HnsMsgAddr:
		msg := NewMsgAddr()
		msg.AddrList = make([]*NetAddress, 0, len(m.Peers))
		for i := range m.Peers {
			addr := legacyNetAddressFromHns(&m.Peers[i])
			msg.AddrList = append(msg.AddrList, &addr)
		}
		return msg, nil

	case *HnsMsgInv:
		return &MsgInv{InvList: legacyInvVectsFromHns(m.Inventory)}, nil

	case *HnsMsgGetData:
		return &MsgGetData{InvList: legacyInvVectsFromHns(m.Inventory)}, nil

	case *HnsMsgNotFound:
		return &MsgNotFound{InvList: legacyInvVectsFromHns(m.Inventory)}, nil

	case *HnsMsgGetBlocks:
		return &MsgGetBlocks{
			ProtocolVersion:    pver,
			BlockLocatorHashes: legacyLocatorFromHns(m.Locator),
			HashStop:           *chainHashFromHns(m.StopHash),
		}, nil

	case *HnsMsgGetHeaders:
		return &MsgGetHeaders{
			ProtocolVersion:    pver,
			BlockLocatorHashes: legacyLocatorFromHns(m.Locator),
			HashStop:           *chainHashFromHns(m.StopHash),
		}, nil

	case *HnsMsgHeaders:
		return &MsgHeaders{Headers: m.Headers}, nil

	case *HnsMsgSendHeaders:
		return &MsgSendHeaders{}, nil

	case *HnsMsgBlock:
		return &m.Block, nil

	case *HnsMsgTx:
		return &m.Tx, nil

	case *HnsMsgReject:
		if pver < RejectVersion {
			str := fmt.Sprintf("reject message invalid for protocol "+
				"version %d", pver)
			return nil, messageError("MsgReject", str)
		}
		cmd, ok := hnsCommandFromMsgType(m.Message)
		if !ok {
			cmd = "unknown"
		}
		return &MsgReject{
			Cmd:    cmd,
			Code:   m.Code,
			Reason: m.Reason,
			Hash:   *chainHashFromHns(m.Hash),
		}, nil

	case *HnsMsgMemPool:
		return &MsgMemPool{}, nil

	case *HnsMsgFilterLoad:
		return &MsgFilterLoad{
			Filter:    append([]byte(nil), m.Filter...),
			HashFuncs: m.HashFuncs,
			Tweak:     m.Tweak,
			Flags:     m.Flags,
		}, nil

	case *HnsMsgFilterAdd:
		return &MsgFilterAdd{Data: append([]byte(nil), m.Data...)}, nil

	case *HnsMsgFilterClear:
		return &MsgFilterClear{}, nil

	case *HnsMsgMerkleBlock:
		msg := &MsgMerkleBlock{}
		if err := decodeLegacyPayload(msg, m.Payload, pver, enc); err != nil {
			return nil, err
		}
		return msg, nil

	case *HnsMsgFeeFilter:
		return &MsgFeeFilter{MinFee: m.Rate}, nil

	case *HnsMsgSendCmpct, *HnsMsgCmpctBlock, *HnsMsgGetBlockTxn,
		*HnsMsgBlockTxn, *HnsMsgGetProof, *HnsMsgProof, *HnsMsgClaim,
		*HnsMsgAirDrop, *HnsMsgUnknown:
		return nil, ErrUnknownMessage
	}

	return nil, ErrUnknownMessage
}

func maxHnsPayloadLength(msg HandshakeMessage) uint32 {
	switch msg.(type) {
	case *HnsMsgVersion:
		return uint32(hnsMsgVersionFixedSize + HnsMaxUserAgentLen + 4 + 1)
	case *HnsMsgVerack, *HnsMsgGetAddr, *HnsMsgSendHeaders,
		*HnsMsgMemPool, *HnsMsgFilterClear:
		return 0
	case *HnsMsgPing, *HnsMsgPong, *HnsMsgFeeFilter:
		return 8
	case *HnsMsgAddr:
		return uint32(MaxVarIntPayload + (MaxAddrPerMsg * HnsNetAddressSize))
	case *HnsMsgInv, *HnsMsgGetData, *HnsMsgNotFound:
		return uint32(MaxVarIntPayload + (MaxInvPerMsg * HnsInvItemSize))
	case *HnsMsgGetBlocks, *HnsMsgGetHeaders:
		return uint32(MaxVarIntPayload +
			(MaxBlockLocatorsPerMsg * chainhash.HashSize) +
			chainhash.HashSize)
	case *HnsMsgHeaders:
		return uint32(MaxVarIntPayload +
			(MaxBlockHeadersPerMsg * MaxBlockHeaderPayload))
	case *HnsMsgBlock, *HnsMsgTx, *HnsMsgMerkleBlock:
		return MaxBlockPayload
	case *HnsMsgReject:
		return uint32(3 + HnsMaxUserAgentLen + chainhash.HashSize)
	case *HnsMsgFilterLoad:
		return uint32(MaxVarIntPayload + MaxFilterLoadFilterSize + 9)
	case *HnsMsgFilterAdd:
		return uint32(MaxVarIntPayload + MaxFilterAddDataSize)
	case *HnsMsgSendCmpct:
		return 9
	case *HnsMsgGetProof:
		return chainhash.HashSize * 2
	case *HnsMsgClaim:
		return 2 + 0xffff
	default:
		return HnsMaxMessagePayload
	}
}

func hnsMsgTypeFromCommand(command string) (HnsMsgType, bool) {
	switch command {
	case CmdVersion:
		return HnsMsgTypeVersion, true
	case CmdVerAck:
		return HnsMsgTypeVerack, true
	case CmdPing:
		return HnsMsgTypePing, true
	case CmdPong:
		return HnsMsgTypePong, true
	case CmdGetAddr:
		return HnsMsgTypeGetAddr, true
	case CmdAddr:
		return HnsMsgTypeAddr, true
	case CmdInv:
		return HnsMsgTypeInv, true
	case CmdGetData:
		return HnsMsgTypeGetData, true
	case CmdNotFound:
		return HnsMsgTypeNotFound, true
	case CmdGetBlocks:
		return HnsMsgTypeGetBlocks, true
	case CmdGetHeaders:
		return HnsMsgTypeGetHeaders, true
	case CmdHeaders:
		return HnsMsgTypeHeaders, true
	case CmdSendHeaders:
		return HnsMsgTypeSendHeaders, true
	case CmdBlock:
		return HnsMsgTypeBlock, true
	case CmdTx:
		return HnsMsgTypeTx, true
	case CmdReject:
		return HnsMsgTypeReject, true
	case CmdMemPool:
		return HnsMsgTypeMempool, true
	case CmdFilterLoad:
		return HnsMsgTypeFilterLoad, true
	case CmdFilterAdd:
		return HnsMsgTypeFilterAdd, true
	case CmdFilterClear:
		return HnsMsgTypeFilterClear, true
	case CmdMerkleBlock:
		return HnsMsgTypeMerkleBlock, true
	case CmdFeeFilter:
		return HnsMsgTypeFeeFilter, true
	}
	return 0, false
}

func hnsCommandFromMsgType(msgType HnsMsgType) (string, bool) {
	switch msgType {
	case HnsMsgTypeVersion:
		return CmdVersion, true
	case HnsMsgTypeVerack:
		return CmdVerAck, true
	case HnsMsgTypePing:
		return CmdPing, true
	case HnsMsgTypePong:
		return CmdPong, true
	case HnsMsgTypeGetAddr:
		return CmdGetAddr, true
	case HnsMsgTypeAddr:
		return CmdAddr, true
	case HnsMsgTypeInv:
		return CmdInv, true
	case HnsMsgTypeGetData:
		return CmdGetData, true
	case HnsMsgTypeNotFound:
		return CmdNotFound, true
	case HnsMsgTypeGetBlocks:
		return CmdGetBlocks, true
	case HnsMsgTypeGetHeaders:
		return CmdGetHeaders, true
	case HnsMsgTypeHeaders:
		return CmdHeaders, true
	case HnsMsgTypeSendHeaders:
		return CmdSendHeaders, true
	case HnsMsgTypeBlock:
		return CmdBlock, true
	case HnsMsgTypeTx:
		return CmdTx, true
	case HnsMsgTypeReject:
		return CmdReject, true
	case HnsMsgTypeMempool:
		return CmdMemPool, true
	case HnsMsgTypeFilterLoad:
		return CmdFilterLoad, true
	case HnsMsgTypeFilterAdd:
		return CmdFilterAdd, true
	case HnsMsgTypeFilterClear:
		return CmdFilterClear, true
	case HnsMsgTypeMerkleBlock:
		return CmdMerkleBlock, true
	case HnsMsgTypeFeeFilter:
		return CmdFeeFilter, true
	}
	return "", false
}

func hnsNetAddressFromLegacy(na *NetAddress) HnsNetAddress {
	if na == nil {
		return HnsNetAddress{}
	}
	return HnsNetAddress{
		Time:     hnsTimeFromTime(na.Timestamp),
		Services: uint64(na.Services),
		Host:     append([]byte(nil), na.IP...),
		Port:     na.Port,
	}
}

func legacyNetAddressFromHns(na *HnsNetAddress) NetAddress {
	if na == nil {
		return NetAddress{}
	}
	return NetAddress{
		Timestamp: hnsTimeToTime(na.Time),
		Services:  ServiceFlag(na.Services),
		IP:        append([]byte(nil), na.Host...),
		Port:      na.Port,
	}
}

func hnsInvItemsFromLegacy(invList []*InvVect) []HnsInvItem {
	inventory := make([]HnsInvItem, len(invList))
	for i := range invList {
		if invList[i] == nil {
			continue
		}
		inventory[i].Type = uint32(invList[i].Type)
		copy(inventory[i].Hash[:], invList[i].Hash[:])
	}
	return inventory
}

func legacyInvVectsFromHns(inventory []HnsInvItem) []*InvVect {
	invList := make([]*InvVect, len(inventory))
	for i := range inventory {
		hash := chainhash.Hash{}
		copy(hash[:], inventory[i].Hash[:])
		invList[i] = &InvVect{
			Type: InvType(inventory[i].Type),
			Hash: hash,
		}
	}
	return invList
}

func hnsLocatorFromLegacy(locator []*chainhash.Hash) [][32]byte {
	hashes := make([][32]byte, len(locator))
	for i := range locator {
		if locator[i] != nil {
			copy(hashes[i][:], locator[i][:])
		}
	}
	return hashes
}

func legacyLocatorFromHns(locator [][32]byte) []*chainhash.Hash {
	hashes := make([]*chainhash.Hash, len(locator))
	for i := range locator {
		hashes[i] = chainHashFromHns(locator[i])
	}
	return hashes
}

func hnsHashFromChainHash(hash *chainhash.Hash) [32]byte {
	var out [32]byte
	if hash != nil {
		copy(out[:], hash[:])
	}
	return out
}

func chainHashFromHns(hash [32]byte) *chainhash.Hash {
	var out chainhash.Hash
	copy(out[:], hash[:])
	return &out
}

func hnsNonceFromUint64(nonce uint64) [8]byte {
	var out [8]byte
	binary.LittleEndian.PutUint64(out[:], nonce)
	return out
}

func uint64FromHnsNonce(nonce [8]byte) uint64 {
	return binary.LittleEndian.Uint64(nonce[:])
}

func hnsTimeFromTime(t time.Time) uint64 {
	sec := t.Unix()
	if sec < 0 {
		return 0
	}
	return uint64(sec)
}

func hnsTimeToTime(sec uint64) time.Time {
	if sec > uint64(maxInt64Unix) {
		sec = uint64(maxInt64Unix)
	}
	return time.Unix(int64(sec), 0)
}

func encodeLegacyPayload(msg Message, pver uint32,
	enc MessageEncoding) ([]byte, error) {

	var buf bytes.Buffer
	if err := msg.BtcEncode(&buf, pver, enc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decodeLegacyPayload(msg Message, payload []byte, pver uint32,
	enc MessageEncoding) error {

	return msg.BtcDecode(bytes.NewBuffer(payload), pver, enc)
}
