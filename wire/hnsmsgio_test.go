// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"errors"
	"math"
	"testing"
)

func TestReadHnsMessageRejectsInvalidHeaderImmediately(t *testing.T) {
	valid, err := EncodeHnsMessage(&HnsMsgVerack{}, testHnsMagic)
	if err != nil {
		t.Fatalf("EncodeHnsMessage: %v", err)
	}

	tests := []struct {
		name   string
		header hnsMsgHeader
	}{
		{
			name: "oversized payload",
			header: hnsMsgHeader{
				NetworkMagic:  testHnsMagic,
				MessageType:   HnsMsgTypeUnknown,
				PayloadLength: math.MaxUint32,
			},
		},
		{
			name: "wrong network",
			header: hnsMsgHeader{
				NetworkMagic:  testHnsMagic + 1,
				MessageType:   HnsMsgTypeUnknown,
				PayloadLength: 4,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stream := bytes.NewBuffer(test.header.Encode())
			stream.Write(valid)

			n, msg, payload, err := ReadHnsMessageN(stream,
				BitcoinNet(testHnsMagic))
			var messageErr *MessageError
			if !errors.As(err, &messageErr) {
				t.Fatalf("error type: got %T, want *MessageError", err)
			}
			if n != HnsMessageHeaderSize {
				t.Fatalf("bytes read: got %d, want %d", n, HnsMessageHeaderSize)
			}
			if msg != nil || payload != nil {
				t.Fatalf("rejected header returned message %T or payload %x", msg, payload)
			}
			if stream.Len() != len(valid) {
				t.Fatalf("invalid header consumed %d bytes of following frame",
					len(valid)-stream.Len())
			}

			_, next, _, err := ReadHnsMessageN(stream, BitcoinNet(testHnsMagic))
			if err != nil {
				t.Fatalf("read following frame: %v", err)
			}
			if _, ok := next.(*HnsMsgVerack); !ok {
				t.Fatalf("following message type: got %T, want *HnsMsgVerack", next)
			}
		})
	}
}

func TestReadHnsMessageCountsDiscardedBytes(t *testing.T) {
	header := (&hnsMsgHeader{
		NetworkMagic:  testHnsMagic,
		MessageType:   HnsMsgType(255),
		PayloadLength: 5,
	}).Encode()
	stream := bytes.NewReader(append(header, 0x01, 0x02))

	n, _, _, err := ReadHnsMessageN(stream, BitcoinNet(testHnsMagic))
	var typeErr UnsupportedHnsMsgTypeError
	if !errors.As(err, &typeErr) {
		t.Fatalf("error type: got %T, want UnsupportedHnsMsgTypeError", err)
	}
	want := HnsMessageHeaderSize + 2
	if n != want {
		t.Fatalf("bytes read: got %d, want %d", n, want)
	}
}
