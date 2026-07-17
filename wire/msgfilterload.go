// Copyright (c) 2014-2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"fmt"
	"io"
)

// BloomUpdateType is the legacy BIP-37 update selector carried by Handshake's
// filterload payload.  hsd preserves the value for wire compatibility but does
// not use it to gate updates: every matched Handshake output adds its outpoint
// to the filter.
type BloomUpdateType uint8

const (
	// BloomUpdateNone is the legacy no-update selector value.
	BloomUpdateNone BloomUpdateType = 0

	// BloomUpdateAll is the legacy update-all selector value.
	BloomUpdateAll BloomUpdateType = 1

	// BloomUpdateP2PubkeyOnly is the legacy pubkey-only selector value.
	BloomUpdateP2PubkeyOnly BloomUpdateType = 2
)

const (
	// MaxFilterLoadHashFuncs is the maximum number of hash functions to
	// load into the Bloom filter.
	MaxFilterLoadHashFuncs = 50

	// MaxFilterLoadFilterSize is the maximum size in bytes a filter may be.
	MaxFilterLoadFilterSize = 36000
)

// MsgFilterLoad implements the Message interface and represents a bitcoin
// filterload message which is used to reset a Bloom filter.
//
// This message was not added until protocol version BIP0037Version.
type MsgFilterLoad struct {
	Filter    []byte
	HashFuncs uint32
	Tweak     uint32
	Flags     BloomUpdateType
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgFilterLoad) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	if pver < BIP0037Version {
		str := fmt.Sprintf("filterload message invalid for protocol "+
			"version %d", pver)
		return messageError("MsgFilterLoad.BtcDecode", str)
	}

	var err error
	msg.Filter, err = ReadVarBytes(r, pver, MaxFilterLoadFilterSize,
		"filterload filter size")
	if err != nil {
		return err
	}

	err = readElements(r, &msg.HashFuncs, &msg.Tweak, &msg.Flags)
	if err != nil {
		return err
	}

	if msg.HashFuncs > MaxFilterLoadHashFuncs {
		str := fmt.Sprintf("too many filter hash functions for message "+
			"[count %v, max %v]", msg.HashFuncs, MaxFilterLoadHashFuncs)
		return messageError("MsgFilterLoad.BtcDecode", str)
	}

	return nil
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgFilterLoad) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	if pver < BIP0037Version {
		str := fmt.Sprintf("filterload message invalid for protocol "+
			"version %d", pver)
		return messageError("MsgFilterLoad.BtcEncode", str)
	}

	size := len(msg.Filter)
	if size > MaxFilterLoadFilterSize {
		str := fmt.Sprintf("filterload filter size too large for message "+
			"[size %v, max %v]", size, MaxFilterLoadFilterSize)
		return messageError("MsgFilterLoad.BtcEncode", str)
	}

	if msg.HashFuncs > MaxFilterLoadHashFuncs {
		str := fmt.Sprintf("too many filter hash functions for message "+
			"[count %v, max %v]", msg.HashFuncs, MaxFilterLoadHashFuncs)
		return messageError("MsgFilterLoad.BtcEncode", str)
	}

	err := WriteVarBytes(w, pver, msg.Filter)
	if err != nil {
		return err
	}

	return writeElements(w, msg.HashFuncs, msg.Tweak, msg.Flags)
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgFilterLoad) Command() string {
	return CmdFilterLoad
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgFilterLoad) MaxPayloadLength(pver uint32) uint32 {
	// Num filter bytes (varInt) + filter + 4 bytes hash funcs +
	// 4 bytes tweak + 1 byte flags.
	return uint32(VarIntSerializeSize(MaxFilterLoadFilterSize)) +
		MaxFilterLoadFilterSize + 9
}

// NewMsgFilterLoad returns a new bitcoin filterload message that conforms to
// the Message interface.  See MsgFilterLoad for details.
func NewMsgFilterLoad(filter []byte, hashFuncs uint32, tweak uint32, flags BloomUpdateType) *MsgFilterLoad {
	return &MsgFilterLoad{
		Filter:    filter,
		HashFuncs: hashFuncs,
		Tweak:     tweak,
		Flags:     flags,
	}
}
