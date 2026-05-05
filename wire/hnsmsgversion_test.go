// Copyright (c) 2025-2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"net"
	"reflect"
	"strings"
	"testing"
)

func newTestVersion() HnsMsgVersion {
	return HnsMsgVersion{
		Version:  3,
		Services: 1,
		Time:     0x1234567890abcdef,
		Remote: HnsNetAddress{
			Time:     0,
			Services: 1,
			Host:     net.IPv4(127, 0, 0, 1).To4(),
			Port:     12038,
			Key:      keyOfBytes(0xaa),
		},
		Nonce:   [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
		Agent:   "/handshake-node:0.1.0/",
		Height:  42,
		NoRelay: true,
	}
}

func TestHnsMsgVersionRoundTrip(t *testing.T) {
	in := newTestVersion()
	encoded := in.Encode()

	var out HnsMsgVersion
	if err := out.Decode(encoded); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("round-trip mismatch:\n got %+v\nwant %+v", out, in)
	}
}

func TestHnsMsgVersionRoundTripEmptyAgent(t *testing.T) {
	in := newTestVersion()
	in.Agent = ""
	in.NoRelay = false

	var out HnsMsgVersion
	if err := out.Decode(in.Encode()); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if out.Agent != "" {
		t.Errorf("agent: got %q, want empty", out.Agent)
	}
	if out.NoRelay {
		t.Errorf("no-relay: got true, want false")
	}
}

func TestHnsMsgVersionEnvelopeRoundTrip(t *testing.T) {
	in := newTestVersion()
	encoded, err := EncodeHnsMessage(&in, testHnsMagic)
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
	got, ok := decoded.(*HnsMsgVersion)
	if !ok {
		t.Fatalf("decoded type: got %T, want *HnsMsgVersion", decoded)
	}
	if !reflect.DeepEqual(in, *got) {
		t.Fatalf("envelope round-trip mismatch:\n got %+v\nwant %+v", *got, in)
	}
}

func TestHnsMsgVersionEncodeTruncatesOversizedAgent(t *testing.T) {
	in := newTestVersion()
	in.Agent = strings.Repeat("x", HnsMaxUserAgentLen+50)
	encoded := in.Encode()

	var out HnsMsgVersion
	if err := out.Decode(encoded); err != nil {
		t.Fatalf("Decode after truncation: %v", err)
	}
	if len(out.Agent) != HnsMaxUserAgentLen {
		t.Errorf("agent length: got %d, want %d", len(out.Agent), HnsMaxUserAgentLen)
	}
}

func TestHnsMsgVersionDecodeShortPayload(t *testing.T) {
	var v HnsMsgVersion
	if err := v.Decode(make([]byte, hnsMsgVersionFixedSize-1)); err == nil {
		t.Fatal("expected error decoding short payload")
	}
}

func TestHnsMsgVersionDecodeAgentLengthOverflow(t *testing.T) {
	in := newTestVersion()
	in.Agent = "abc"
	encoded := in.Encode()
	// Corrupt the agent-length byte to claim more bytes than are present.
	agentLenOffset := 4 + 8 + 8 + HnsNetAddressSize + 8
	encoded[agentLenOffset] = 100

	var v HnsMsgVersion
	if err := v.Decode(encoded); err == nil {
		t.Fatal("expected error for overflowing agent length")
	}
}

func TestHnsMsgVersionDecodeRejectsTrailingBytes(t *testing.T) {
	in := newTestVersion()
	encoded := append(in.Encode(), 0xff)

	var v HnsMsgVersion
	if err := v.Decode(encoded); err == nil {
		t.Fatal("expected error for trailing bytes")
	}
}

func TestHnsMsgVersionDecodeRejectsInvalidNoRelay(t *testing.T) {
	in := newTestVersion()
	encoded := in.Encode()
	encoded[len(encoded)-1] = 0x42

	var v HnsMsgVersion
	if err := v.Decode(encoded); err == nil {
		t.Fatal("expected error for invalid no-relay byte")
	}
}

func TestHnsMsgVersionOnTheWireLayout(t *testing.T) {
	// Pin the on-wire layout for a minimal version message: empty agent,
	// no-relay = 0, IPv4 remote 127.0.0.1, all-zero key/reserved.
	v := HnsMsgVersion{
		Version:  3,
		Services: 1,
		Time:     0x0807060504030201,
		Remote: HnsNetAddress{
			Time:     0,
			Services: 0,
			Host:     net.IPv4(127, 0, 0, 1).To4(),
			Port:     0x2F06,
			Key:      [33]byte{},
		},
		Nonce:   [8]byte{0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce},
		Agent:   "",
		Height:  0x11223344,
		NoRelay: false,
	}
	got := v.Encode()
	want := bytes.Join([][]byte{
		// Version
		{0x03, 0x00, 0x00, 0x00},
		// Services
		{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		// Time
		{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		// NetAddress (88 bytes): Time(0), Services(0), type byte, IPv4-mapped 127.0.0.1, reserved, port BE, zero key
		make([]byte, 8), make([]byte, 8), {0x00},
		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x7f, 0x00, 0x00, 0x01},
		make([]byte, 20),
		{0x2f, 0x06},
		make([]byte, 33),
		// Nonce
		{0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce},
		// Agent length
		{0x00},
		// Height
		{0x44, 0x33, 0x22, 0x11},
		// NoRelay
		{0x00},
	}, nil)
	if !bytes.Equal(got, want) {
		t.Fatalf("wire layout mismatch:\n got % x\nwant % x", got, want)
	}
}
