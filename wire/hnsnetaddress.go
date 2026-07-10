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
	"net"
	"time"
)

// HnsBrontideKeySize is the compressed secp256k1 static key size carried in a
// Handshake NetAddress for Brontide transport.
const HnsBrontideKeySize = 33

// HnsNetAddressSize is the on-wire size in bytes of a Handshake NetAddress.
// Layout (little-endian unless noted):
//
//	[0:8]   Time     uint64
//	[8:16]  Services uint64
//	[16]    address type byte (always 0)
//	[17:33] Host     16 bytes (IPv4-mapped or IPv6)
//	[33:53] Reserved 20 bytes
//	[53:55] Port     uint16 big-endian
//	[55:88] Key      33 bytes (compressed secp256k1)
const HnsNetAddressSize = 88

// hnsIPv4MappedPrefix is the 12-byte prefix used to encode an IPv4 address
// inside the 16-byte address field, matching RFC 4291 IPv4-mapped IPv6.
var hnsIPv4MappedPrefix = [12]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff}

// HnsNetAddress is a Handshake P2P network address. Unlike btcd's NetAddress
// it always carries the peer's static identity key and a 20-byte reserved
// region, totaling 88 bytes on the wire.
type HnsNetAddress struct {
	Time     uint64
	Services uint64
	Host     net.IP
	Reserved [20]byte
	Port     uint16
	Key      [HnsBrontideKeySize]byte
}

// Encode serializes the address into HnsNetAddressSize bytes. IPv4 hosts are
// written as IPv4-mapped IPv6; nil or zero-length hosts are written as the
// IPv6 unspecified address.
func (n *HnsNetAddress) Encode() []byte {
	out := make([]byte, HnsNetAddressSize)
	binary.LittleEndian.PutUint64(out[0:8], n.Time)
	binary.LittleEndian.PutUint64(out[8:16], n.Services)
	// out[16] is the address type and is always zero in this format.
	if v4 := n.Host.To4(); v4 != nil {
		copy(out[17:29], hnsIPv4MappedPrefix[:])
		copy(out[29:33], v4)
	} else if v6 := n.Host.To16(); v6 != nil {
		copy(out[17:33], v6)
	}
	copy(out[33:53], n.Reserved[:])
	binary.BigEndian.PutUint16(out[53:55], n.Port)
	copy(out[55:88], n.Key[:])
	return out
}

// Decode parses an HnsNetAddressSize-byte payload into n. IPv4-mapped hosts
// are normalized to their 4-byte representation so encode/decode round-trips
// are byte-equal.
func (n *HnsNetAddress) Decode(data []byte) error {
	if len(data) != HnsNetAddressSize {
		return fmt.Errorf(
			"handshake netaddress: expected %d bytes, got %d",
			HnsNetAddressSize, len(data),
		)
	}
	n.Time = binary.LittleEndian.Uint64(data[0:8])
	n.Services = binary.LittleEndian.Uint64(data[8:16])
	// data[16] is the address type; only type 0 is defined.
	if data[16] != 0 {
		return fmt.Errorf(
			"handshake netaddress: unsupported address type %d",
			data[16],
		)
	}
	host := make(net.IP, net.IPv6len)
	copy(host, data[17:33])
	if isHnsIPv4Mapped(host) {
		n.Host = host.To4()
	} else {
		n.Host = host
	}
	copy(n.Reserved[:], data[33:53])
	n.Port = binary.BigEndian.Uint16(data[53:55])
	copy(n.Key[:], data[55:88])
	return nil
}

// NewHnsNetAddress converts the in-memory NetAddress representation into a
// Handshake wire address. The reserved region and identity key are zeroed;
// nodes that have not learned a peer's key advertise it as all zeroes.
func NewHnsNetAddress(na *NetAddress) HnsNetAddress {
	if na == nil {
		return HnsNetAddress{}
	}
	sec := na.Timestamp.Unix()
	if sec < 0 {
		sec = 0
	}
	return HnsNetAddress{
		Time:     uint64(sec),
		Services: uint64(na.Services),
		Host:     append(net.IP(nil), na.IP...),
		Port:     na.Port,
	}
}

// NetAddress converts the Handshake wire address into the in-memory
// NetAddress representation shared with the address manager.
func (n *HnsNetAddress) NetAddress() *NetAddress {
	sec := n.Time
	if sec > uint64(1<<63-1) {
		sec = uint64(1<<63 - 1)
	}
	return &NetAddress{
		Timestamp: time.Unix(int64(sec), 0),
		Services:  ServiceFlag(n.Services),
		IP:        append(net.IP(nil), n.Host...),
		Port:      n.Port,
	}
}

// NetAddressV2 converts the Handshake wire address into the in-memory
// NetAddressV2 representation while preserving the advertised Brontide static
// key.
func (n *HnsNetAddress) NetAddressV2() *NetAddressV2 {
	sec := n.Time
	if sec > uint64(1<<63-1) {
		sec = uint64(1<<63 - 1)
	}
	host := n.Host
	if host == nil || host.To16() == nil {
		host = net.IPv6zero
	}

	na := NetAddressV2FromBytes(
		time.Unix(int64(sec), 0),
		ServiceFlag(n.Services),
		host,
		n.Port,
	)
	na.SetBrontideKey(n.Key[:])
	return na
}

func isHnsIPv4Mapped(ip net.IP) bool {
	if len(ip) != net.IPv6len {
		return false
	}
	for i, b := range hnsIPv4MappedPrefix {
		if ip[i] != b {
			return false
		}
	}
	return true
}
