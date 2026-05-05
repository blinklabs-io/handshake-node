// Copyright (c) 2025-2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"net"
	"reflect"
	"testing"
)

func TestHnsNetAddressRoundTripIPv4(t *testing.T) {
	in := HnsNetAddress{
		Time:     0x1122334455667788,
		Services: 0x0102030405060708,
		Host:     net.IPv4(192, 168, 1, 42).To4(),
		Reserved: [20]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
		Port:     12038,
		Key:      keyOfBytes(0xab),
	}
	encoded := in.Encode()
	if len(encoded) != HnsNetAddressSize {
		t.Fatalf("length: got %d, want %d", len(encoded), HnsNetAddressSize)
	}

	var out HnsNetAddress
	if err := out.Decode(encoded); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("round-trip mismatch:\n got %+v\nwant %+v", out, in)
	}
}

func TestHnsNetAddressRoundTripIPv6(t *testing.T) {
	host := net.ParseIP("2001:db8::1")
	in := HnsNetAddress{
		Time:     1,
		Services: 2,
		Host:     host,
		Port:     12038,
		Key:      keyOfBytes(0xcd),
	}
	encoded := in.Encode()

	var out HnsNetAddress
	if err := out.Decode(encoded); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !out.Host.Equal(host) {
		t.Errorf("host: got %v, want %v", out.Host, host)
	}
	// Port and key must round-trip exactly.
	if out.Port != in.Port {
		t.Errorf("port: got %d, want %d", out.Port, in.Port)
	}
	if out.Key != in.Key {
		t.Errorf("key mismatch")
	}
}

func TestHnsNetAddressOnTheWireLayout(t *testing.T) {
	in := HnsNetAddress{
		Time:     0x0807060504030201,
		Services: 0x1716151413121110,
		Host:     net.IPv4(10, 0, 0, 1).To4(),
		Port:     0x2F06, // 12038
		Key:      keyOfBytes(0x55),
	}
	in.Reserved[0] = 0xaa
	got := in.Encode()
	want := bytes.Join([][]byte{
		// Time, little-endian
		{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		// Services, little-endian
		{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17},
		// Address type byte, always 0
		{0x00},
		// Address: IPv4-mapped IPv6 form for 10.0.0.1
		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x0a, 0x00, 0x00, 0x01},
		// Reserved: first byte set, rest zero
		{0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		// Port, big-endian
		{0x2f, 0x06},
		// Key (33 bytes of 0x55)
		bytes.Repeat([]byte{0x55}, 33),
	}, nil)
	if !bytes.Equal(got, want) {
		t.Fatalf("wire layout mismatch:\n got % x\nwant % x", got, want)
	}
}

func TestHnsNetAddressDecodeWrongSize(t *testing.T) {
	var n HnsNetAddress
	if err := n.Decode(make([]byte, HnsNetAddressSize-1)); err == nil {
		t.Fatal("expected error for short data")
	}
	if err := n.Decode(make([]byte, HnsNetAddressSize+1)); err == nil {
		t.Fatal("expected error for long data")
	}
}

func TestHnsNetAddressDecodeRejectsNonZeroType(t *testing.T) {
	in := HnsNetAddress{
		Time:     1,
		Services: 2,
		Host:     net.IPv4(10, 0, 0, 1).To4(),
		Port:     12038,
		Key:      keyOfBytes(0x77),
	}
	encoded := in.Encode()
	encoded[16] = 1

	var out HnsNetAddress
	if err := out.Decode(encoded); err == nil {
		t.Fatal("expected error for non-zero address type byte")
	}
}

func keyOfBytes(b byte) [33]byte {
	var k [33]byte
	for i := range k {
		k[i] = b
	}
	return k
}
