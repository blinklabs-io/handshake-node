// Copyright (c) 2025-2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.
//
// Portions of this file are derived from cdnsd
// (https://github.com/blinklabs-io/cdnsd) handshake/messages.go, Copyright (c) 2025
// Blink Labs Software. The cdnsd code was itself ported from hsd/hnsd.

package wire

import (
	"encoding/binary"
	"fmt"
	"math"
)

// hnsMsgVersionFixedSize is the size of the fixed-width fields preceding the
// variable-length user-agent: Version(4) + Services(8) + Time(8) + Remote(88)
// + Nonce(8) + agent length byte(1).
const hnsMsgVersionFixedSize = 4 + 8 + 8 + HnsNetAddressSize + 8 + 1

// HnsMaxUserAgentLen is the maximum on-wire length of the Agent field. The
// length is encoded as a single byte.
const HnsMaxUserAgentLen = math.MaxUint8

// HnsMsgVersion is the Handshake "version" message exchanged at the start of
// every peer connection to negotiate protocol version, services, and node
// identity. It is type 0 in the Handshake message-type table.
type HnsMsgVersion struct {
	Version  uint32
	Services uint64
	Time     uint64
	Remote   HnsNetAddress
	Nonce    [8]byte
	Agent    string
	Height   uint32
	NoRelay  bool
}

func (*HnsMsgVersion) Type() HnsMsgType { return HnsMsgTypeVersion }

// NonceUint64 returns the connection nonce as a little-endian uint64.
func (m *HnsMsgVersion) NonceUint64() uint64 {
	return binary.LittleEndian.Uint64(m.Nonce[:])
}

// SetNonce stores the given nonce in the little-endian byte order used on the
// wire.
func (m *HnsMsgVersion) SetNonce(nonce uint64) {
	binary.LittleEndian.PutUint64(m.Nonce[:], nonce)
}

// Encode serializes the message. Agent is capped to HnsMaxUserAgentLen because
// the Handshake packet stores its length in one byte.
func (m *HnsMsgVersion) Encode() []byte {
	agent := m.Agent
	if len(agent) > HnsMaxUserAgentLen {
		agent = agent[:HnsMaxUserAgentLen]
	}
	out := make([]byte, hnsMsgVersionFixedSize+len(agent)+4+1)
	binary.LittleEndian.PutUint32(out[0:4], m.Version)
	binary.LittleEndian.PutUint64(out[4:12], m.Services)
	binary.LittleEndian.PutUint64(out[12:20], m.Time)
	copy(out[20:20+HnsNetAddressSize], m.Remote.Encode())
	off := 20 + HnsNetAddressSize
	copy(out[off:off+8], m.Nonce[:])
	off += 8
	out[off] = byte(len(agent))
	off++
	copy(out[off:off+len(agent)], agent)
	off += len(agent)
	binary.LittleEndian.PutUint32(out[off:off+4], m.Height)
	off += 4
	if m.NoRelay {
		out[off] = 1
	}
	return out
}

func (m *HnsMsgVersion) Decode(data []byte) error {
	if len(data) < hnsMsgVersionFixedSize {
		return fmt.Errorf(
			"version: payload shorter than fixed header (%d < %d)",
			len(data), hnsMsgVersionFixedSize,
		)
	}
	m.Version = binary.LittleEndian.Uint32(data[0:4])
	m.Services = binary.LittleEndian.Uint64(data[4:12])
	m.Time = binary.LittleEndian.Uint64(data[12:20])
	if err := m.Remote.Decode(data[20 : 20+HnsNetAddressSize]); err != nil {
		return fmt.Errorf("version: remote address: %w", err)
	}
	off := 20 + HnsNetAddressSize
	copy(m.Nonce[:], data[off:off+8])
	off += 8
	agentLen := int(data[off])
	off++
	if len(data) < off+agentLen+4+1 {
		return fmt.Errorf(
			"version: payload too short for agent length %d (have %d bytes after header)",
			agentLen, len(data)-off,
		)
	}
	m.Agent = string(data[off : off+agentLen])
	off += agentLen
	m.Height = binary.LittleEndian.Uint32(data[off : off+4])
	off += 4
	switch data[off] {
	case 0:
		m.NoRelay = false
	case 1:
		m.NoRelay = true
	default:
		return fmt.Errorf(
			"version: invalid no-relay byte %d", data[off],
		)
	}
	off++
	if off != len(data) {
		return fmt.Errorf(
			"version: %d trailing bytes after payload",
			len(data)-off,
		)
	}
	return nil
}
