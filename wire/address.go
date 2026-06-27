// Copyright (c) 2024-2025 The blinklabs-io developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"fmt"
	"io"
)

const (
	// maxAddressVersion is the maximum allowed address version (0-16).
	// WitnessProgram() uses 0x50+version for the opcode, which is only
	// valid for versions 0 through 16 (OP_0 through OP_16).
	maxAddressVersion = 16

	// minAddressHashLen is the minimum hash length for an address.
	minAddressHashLen = 2

	// maxAddressHashLen is the maximum hash length for an address.
	maxAddressHashLen = 40
)

// Address represents a Handshake output address consisting of a witness
// program version and hash.  Version 0 addresses use 20-byte (P2WPKH) or
// 32-byte (P2WSH) hashes.
//
// Wire format: version(1 byte) + hashLen(1 byte) + hash(N bytes)
type Address struct {
	Version uint8
	Hash    []byte
}

// validateAddressFields validates the version/hash combination for an
// address.  The zero-value Address{} (version 0, empty hash) is accepted as
// an empty/placeholder address; every other combination must satisfy the
// standard version, hash-length, and version-0 length constraints.
func validateAddressFields(version uint8, hashLen int, op string) error {
	if version == 0 && hashLen == 0 {
		return nil
	}

	if version > maxAddressVersion {
		return messageError(op, fmt.Sprintf(
			"address version %d exceeds max %d",
			version, maxAddressVersion,
		))
	}

	if hashLen < minAddressHashLen || hashLen > maxAddressHashLen {
		return messageError(op, fmt.Sprintf(
			"address hash length %d outside valid range [%d, %d]",
			hashLen, minAddressHashLen, maxAddressHashLen,
		))
	}

	if version == 0 && hashLen != 20 && hashLen != 32 {
		return messageError(op, fmt.Sprintf(
			"version 0 address requires hash length 20 or 32, got %d",
			hashLen,
		))
	}
	return nil
}

// Encode serializes the address to w.
//
// Wire format: version(1) + hashLen(1) + hash
func (a *Address) Encode(w io.Writer) error {
	hashLen := len(a.Hash)
	if err := validateAddressFields(a.Version, hashLen, "Address.Encode"); err != nil {
		return err
	}

	err := binarySerializer.PutUint8(w, a.Version)
	if err != nil {
		return err
	}

	err = binarySerializer.PutUint8(w, uint8(hashLen))
	if err != nil {
		return err
	}

	_, err = w.Write(a.Hash)
	return err
}

// Decode deserializes an address from r.
func (a *Address) Decode(r io.Reader) error {
	version, err := binarySerializer.Uint8(r)
	if err != nil {
		return err
	}
	a.Version = version

	hashLen, err := binarySerializer.Uint8(r)
	if err != nil {
		return err
	}

	if err := validateAddressFields(version, int(hashLen), "Address.Decode"); err != nil {
		return err
	}

	if hashLen == 0 {
		a.Hash = nil
		return nil
	}
	a.Hash = make([]byte, hashLen)
	_, err = io.ReadFull(r, a.Hash)
	return err
}

// SerializeSize returns the number of bytes needed to serialize the address.
func (a *Address) SerializeSize() int {
	// version(1) + hashLen(1) + hash
	return 2 + len(a.Hash)
}

// WitnessProgram returns the Bitcoin-style witness program script for this
// address.  For version 0, the result is [OP_0, len(hash), hash...].  For
// version N (1-16), the result is [OP_N (0x50+N), len(hash), hash...].
func (a *Address) WitnessProgram() []byte {
	program := make([]byte, 2+len(a.Hash))

	if a.Version == 0 {
		program[0] = 0x00 // OP_0
	} else {
		program[0] = 0x50 + a.Version // OP_1 through OP_16
	}
	program[1] = byte(len(a.Hash))
	copy(program[2:], a.Hash)

	return program
}

// NewAddress creates a new Address with validation.  It returns an error if
// the version or hash length is invalid.  The zero-value address (version 0,
// empty hash) is rejected by this constructor; callers wanting a placeholder
// should construct the literal directly.
func NewAddress(version uint8, hash []byte) (*Address, error) {
	hashLen := len(hash)
	if version == 0 && hashLen == 0 {
		return nil, messageError("NewAddress",
			"zero-value address may not be constructed via NewAddress")
	}
	if err := validateAddressFields(version, hashLen, "NewAddress"); err != nil {
		return nil, err
	}
	return &Address{
		Version: version,
		Hash:    hash,
	}, nil
}
