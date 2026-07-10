// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package brontide

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// HeaderSize is the size of an encrypted hsd Brontide frame header:
	// 4-byte little-endian payload length plus a 16-byte authentication tag.
	HeaderSize = 4 + tagSize

	// MaxMessageSize is hsd's MAX_MESSAGE plus the 9-byte Handshake packet
	// envelope that is encrypted inside Brontide frames.
	MaxMessageSize = 8*1000*1000 + 9
)

var (
	// ErrFrameTooLarge is returned when a Brontide frame payload exceeds
	// hsd's maximum encrypted message size.
	ErrFrameTooLarge = errors.New("brontide: frame too large")

	// ErrShortFrame is returned when a complete-frame helper receives too
	// few bytes to contain a valid Brontide frame.
	ErrShortFrame = errors.New("brontide: short frame")

	// ErrFrameSizeMismatch is returned when the authenticated frame length
	// does not match the bytes supplied to a complete-frame helper.
	ErrFrameSizeMismatch = errors.New("brontide: frame size mismatch")
)

// WriteFrame encrypts payload into one hsd Brontide stream frame. A frame
// consumes two cipher nonces: one for the length header and one for the body.
func WriteFrame(send *CipherState, payload []byte) ([]byte, error) {
	if send == nil {
		return nil, fmt.Errorf("%w: nil cipher", ErrInvalidCipher)
	}
	if len(payload) > MaxMessageSize {
		return nil, fmt.Errorf("%w: got %d bytes, max %d",
			ErrFrameTooLarge, len(payload), MaxMessageSize)
	}

	var length [4]byte
	binary.LittleEndian.PutUint32(length[:], uint32(len(payload)))

	encLength, lengthTag, err := send.Encrypt(length[:], nil)
	if err != nil {
		return nil, err
	}
	encPayload, payloadTag, err := send.Encrypt(payload, nil)
	if err != nil {
		return nil, err
	}

	frame := make([]byte, 0, HeaderSize+len(payload)+tagSize)
	frame = append(frame, encLength...)
	frame = append(frame, lengthTag...)
	frame = append(frame, encPayload...)
	frame = append(frame, payloadTag...)
	return frame, nil
}

// ReadFrame decrypts a complete hsd Brontide stream frame and returns its
// payload. A frame consumes two cipher nonces when both the header and payload
// authenticate successfully.
func ReadFrame(recv *CipherState, frame []byte) ([]byte, error) {
	if recv == nil {
		return nil, fmt.Errorf("%w: nil cipher", ErrInvalidCipher)
	}
	if len(frame) < HeaderSize {
		return nil, fmt.Errorf("%w: got %d bytes, need at least %d",
			ErrShortFrame, len(frame), HeaderSize)
	}

	length, err := recv.Decrypt(frame[:4], frame[4:HeaderSize], nil)
	if err != nil {
		return nil, err
	}
	if len(length) != 4 {
		return nil, fmt.Errorf("%w: decrypted length is %d bytes",
			ErrFrameSizeMismatch, len(length))
	}

	size := binary.LittleEndian.Uint32(length)
	if size > MaxMessageSize {
		return nil, fmt.Errorf("%w: got %d bytes, max %d",
			ErrFrameTooLarge, size, MaxMessageSize)
	}

	expected := HeaderSize + int(size) + tagSize
	if len(frame) != expected {
		return nil, fmt.Errorf("%w: got %d bytes, want %d",
			ErrFrameSizeMismatch, len(frame), expected)
	}

	payloadStart := HeaderSize
	payloadEnd := payloadStart + int(size)
	return recv.Decrypt(frame[payloadStart:payloadEnd], frame[payloadEnd:], nil)
}
