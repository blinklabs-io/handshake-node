// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"fmt"
	"io"

	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
)

// WriteHnsMessageN writes a Handshake message to w using the 9-byte Handshake
// envelope and returns the number of bytes written, including the envelope.
func WriteHnsMessageN(w io.Writer, msg HandshakeMessage,
	hnsnet BitcoinNet) (int, error) {

	encoded, err := EncodeHnsMessage(msg, uint32(hnsnet))
	if err != nil {
		return 0, err
	}

	payloadLen := uint32(len(encoded) - HnsMessageHeaderSize) //nolint:gosec
	if mpl := maxHnsPayloadLength(msg.Type()); payloadLen > mpl {
		str := fmt.Sprintf("message payload is too large - encoded "+
			"%d bytes, but maximum message payload size for "+
			"messages of type [%v] is %d.", payloadLen, msg.Type(), mpl)
		return 0, messageError("WriteHnsMessage", str)
	}

	return w.Write(encoded)
}

// WriteHnsMessage writes a Handshake message to w using the 9-byte Handshake
// envelope.
func WriteHnsMessage(w io.Writer, msg HandshakeMessage,
	hnsnet BitcoinNet) error {

	_, err := WriteHnsMessageN(w, msg, hnsnet)
	return err
}

// WriteHandshakeMessageN is retained as a compatibility alias while callers
// migrate to WriteHnsMessageN.
func WriteHandshakeMessageN(w io.Writer, msg HandshakeMessage,
	hnsnet BitcoinNet) (int, error) {

	return WriteHnsMessageN(w, msg, hnsnet)
}

// ReadHnsMessageN reads, validates, and parses the next Handshake message
// from r. It returns the number of bytes read, the parsed message, and the
// raw payload bytes which comprise the message body.
func ReadHnsMessageN(r io.Reader,
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

	msg, err := newEmptyHnsMessage(hdr.MessageType)
	if err != nil {
		discardInput(r, hdr.PayloadLength)
		totalBytes += int(hdr.PayloadLength)
		return totalBytes, nil, nil, err
	}

	mpl := maxHnsPayloadLength(hdr.MessageType)
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

	if err := msg.Decode(payload); err != nil {
		return totalBytes, nil, nil, fmt.Errorf(
			"decode %T: %w", msg, err,
		)
	}

	return totalBytes, msg, payload, nil
}

// ReadHnsMessage reads, validates, and parses the next Handshake message from
// r. It is the same as ReadHnsMessageN except it does not return the number
// of bytes read.
func ReadHnsMessage(r io.Reader,
	hnsnet BitcoinNet) (HandshakeMessage, []byte, error) {

	_, msg, buf, err := ReadHnsMessageN(r, hnsnet)
	return msg, buf, err
}

// ReadHandshakeMessageN is retained as a compatibility alias while callers
// migrate to ReadHnsMessageN.
func ReadHandshakeMessageN(r io.Reader,
	hnsnet BitcoinNet) (int, HandshakeMessage, []byte, error) {

	return ReadHnsMessageN(r, hnsnet)
}

func maxHnsPayloadLength(msgType HnsMsgType) uint32 {
	switch msgType {
	case HnsMsgTypeVersion:
		return uint32(hnsMsgVersionFixedSize + HnsMaxUserAgentLen + 4 + 1)
	case HnsMsgTypeVerack, HnsMsgTypeGetAddr, HnsMsgTypeSendHeaders,
		HnsMsgTypeMempool, HnsMsgTypeFilterClear:
		return 0
	case HnsMsgTypePing, HnsMsgTypePong, HnsMsgTypeFeeFilter:
		return 8
	case HnsMsgTypeAddr:
		return uint32(MaxVarIntPayload + (MaxAddrPerMsg * HnsNetAddressSize))
	case HnsMsgTypeInv, HnsMsgTypeGetData, HnsMsgTypeNotFound:
		return uint32(MaxVarIntPayload + (MaxInvPerMsg * HnsInvItemSize))
	case HnsMsgTypeGetBlocks, HnsMsgTypeGetHeaders:
		return uint32(MaxVarIntPayload +
			(MaxBlockLocatorsPerMsg * chainhash.HashSize) +
			chainhash.HashSize)
	case HnsMsgTypeHeaders:
		return uint32(MaxVarIntPayload +
			(MaxBlockHeadersPerMsg * MaxBlockHeaderPayload))
	case HnsMsgTypeBlock, HnsMsgTypeTx, HnsMsgTypeMerkleBlock:
		return MaxBlockPayload
	case HnsMsgTypeReject:
		return uint32(3 + HnsMaxUserAgentLen + chainhash.HashSize)
	case HnsMsgTypeFilterLoad:
		return uint32(MaxVarIntPayload + MaxFilterLoadFilterSize + 9)
	case HnsMsgTypeFilterAdd:
		return uint32(MaxVarIntPayload + MaxFilterAddDataSize)
	case HnsMsgTypeSendCmpct:
		return 9
	case HnsMsgTypeGetProof:
		return chainhash.HashSize * 2
	case HnsMsgTypeClaim:
		return HnsMaxClaimPayload
	case HnsMsgTypeAirDrop:
		return HnsMaxAirdropProofSize
	default:
		return HnsMaxMessagePayload
	}
}
