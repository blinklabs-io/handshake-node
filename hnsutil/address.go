// Copyright (c) 2013-2017 The btcsuite developers
// Copyright (c) 2024-2026 The blinklabs-io developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package hnsutil

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/blinklabs-io/handshake-node/chaincfg"
	"github.com/blinklabs-io/handshake-node/hnsutil/bech32"
)

const (
	// MinAddressVersion is the lowest valid version for a Handshake
	// address.
	MinAddressVersion = 0

	// MaxAddressVersion is the highest valid version for a Handshake
	// address.  bech32 allows 5 bits for the version field so the maximum
	// representable version is 31.
	MaxAddressVersion = 31

	// MinAddressHashLen is the minimum hash length for a Handshake
	// address.
	MinAddressHashLen = 2

	// MaxAddressHashLen is the maximum hash length for a Handshake
	// address.
	MaxAddressHashLen = 40
)

var (
	// ErrChecksumMismatch describes an error where decoding failed due
	// to a bad checksum.  It is kept as a package-level variable so
	// callers such as the WIF decoder can continue to return it.
	ErrChecksumMismatch = errors.New("checksum mismatch")

	// ErrUnknownAddressType is returned when an address can not be
	// decoded as a specific address type.
	ErrUnknownAddressType = errors.New("unknown address type")

	// ErrUnknownHRP is returned when an address is decoded with a HRP
	// that does not match any known network.
	ErrUnknownHRP = errors.New("unknown address HRP")

	// ErrInvalidAddressVersion is returned when an address version is
	// outside the valid [0, 31] range.
	ErrInvalidAddressVersion = errors.New("invalid address version")

	// ErrInvalidAddressHashLen is returned when the hash portion of an
	// address has an invalid length.
	ErrInvalidAddressHashLen = errors.New("invalid address hash length")
)

// Address is the interface satisfied by any Handshake address.  Handshake
// uses a single unified address format consisting of a version (0-31) and
// a hash (2-40 bytes), encoded as bech32 (BIP-173) with a network-specific
// HRP:
//
//	mainnet  -> "hs"
//	testnet  -> "ts"
//	regtest  -> "rs"
//	simnet   -> "ss"
//
// There is therefore only a single concrete implementation, which can be
// constructed via NewAddress, NewAddressPubKeyHash, NewAddressScriptHash,
// DecodeAddress, or DecodeAddressAnyNet.  The interface exists primarily to
// preserve the shape of the btcd-era API so call sites in the wider code
// base do not have to be rewritten.
type Address interface {
	// EncodeAddress returns the bech32 string encoding of the payment
	// address.
	EncodeAddress() string

	// ScriptAddress returns the raw hash bytes to be embedded in an
	// output script.  For Handshake this is identical to the address
	// hash.
	ScriptAddress() []byte

	// IsForNet returns whether or not the address is associated with the
	// passed Handshake network parameters.
	IsForNet(*chaincfg.Params) bool

	// String returns a human-readable form of the address, which for
	// Handshake is always the bech32 encoding.
	String() string

	// Version returns the witness-program version of the address.
	Version() uint8

	// Hash returns a copy of the raw hash bytes of the address.
	Hash() []byte

	// HRP returns the network-specific human-readable prefix of the
	// address.
	HRP() string
}

// handshakeAddress is the sole concrete implementation of Address.
type handshakeAddress struct {
	version uint8
	hash    []byte
	hrp     string
}

// NewAddress constructs a new Address from a version and hash using the HRP
// associated with the supplied chain parameters.  It validates the version
// and hash-length constraints.
func NewAddress(version uint8, hash []byte, net *chaincfg.Params) (Address, error) {
	if net == nil {
		return nil, errors.New("nil chain params")
	}
	return newAddress(version, hash, net.Bech32HRPSegwit)
}

// NewAddressPubKeyHash constructs a version 0 Address wrapping a 20-byte
// pubkey hash.  This is the Handshake equivalent of Bitcoin's P2WPKH.
func NewAddressPubKeyHash(pkHash []byte, net *chaincfg.Params) (Address, error) {
	if len(pkHash) != 20 {
		return nil, fmt.Errorf("%w: pkhash must be 20 bytes, got %d",
			ErrInvalidAddressHashLen, len(pkHash))
	}
	return NewAddress(0, pkHash, net)
}

// NewAddressScriptHash constructs a version 0 Address from a 32-byte script
// hash (the SHA3-256 of the redeem script).  This is the Handshake equivalent
// of Bitcoin's P2WSH.
func NewAddressScriptHash(scriptHash []byte, net *chaincfg.Params) (Address, error) {
	if len(scriptHash) != 32 {
		return nil, fmt.Errorf("%w: scripthash must be 32 bytes, got %d",
			ErrInvalidAddressHashLen, len(scriptHash))
	}
	return NewAddress(0, scriptHash, net)
}

// newAddress is the internal constructor that creates an Address with a
// known HRP, bypassing chain parameter lookup.
func newAddress(version uint8, hash []byte, hrp string) (*handshakeAddress, error) {
	if err := validateAddress(version, hash); err != nil {
		return nil, err
	}
	// Take a defensive copy of the hash so callers can't mutate the
	// address state.
	hashCopy := make([]byte, len(hash))
	copy(hashCopy, hash)
	return &handshakeAddress{
		version: version,
		hash:    hashCopy,
		hrp:     strings.ToLower(hrp),
	}, nil
}

// validateAddress enforces the Handshake address rules: version must be in
// [0, 31], hash length must be in [2, 40], and a version-0 hash must be
// exactly 20 or 32 bytes long.
func validateAddress(version uint8, hash []byte) error {
	if version > MaxAddressVersion {
		return fmt.Errorf("%w: version %d exceeds max %d",
			ErrInvalidAddressVersion, version, MaxAddressVersion)
	}

	hashLen := len(hash)
	if hashLen < MinAddressHashLen || hashLen > MaxAddressHashLen {
		return fmt.Errorf("%w: hash length %d outside [%d, %d]",
			ErrInvalidAddressHashLen, hashLen,
			MinAddressHashLen, MaxAddressHashLen)
	}

	if version == 0 && hashLen != 20 && hashLen != 32 {
		return fmt.Errorf("%w: version 0 requires hash length 20 or 32, got %d",
			ErrInvalidAddressHashLen, hashLen)
	}
	return nil
}

// DecodeAddress parses a bech32-encoded Handshake address string.  The HRP
// of the encoded address must match the HRP of the supplied chain params.
// A nil net is treated as an error; callers that intend to decode without
// enforcing a particular network must use DecodeAddressAnyNet explicitly.
func DecodeAddress(addr string, net *chaincfg.Params) (Address, error) {
	if net == nil {
		return nil, fmt.Errorf(
			"DecodeAddress: nil chain params; use DecodeAddressAnyNet " +
				"to decode without network enforcement")
	}
	decoded, err := DecodeAddressAnyNet(addr)
	if err != nil {
		return nil, err
	}
	if decoded.HRP() != strings.ToLower(net.Bech32HRPSegwit) {
		return nil, fmt.Errorf("%w: address HRP %q does not match network %q",
			ErrUnknownHRP, decoded.HRP(), net.Bech32HRPSegwit)
	}
	return decoded, nil
}

// DecodeAddressAnyNet parses a bech32-encoded Handshake address without
// enforcing a particular network.  Callers may inspect the returned
// Address.HRP() to determine the network.
func DecodeAddressAnyNet(addr string) (Address, error) {
	hrp, data, err := bech32.Decode(addr)
	if err != nil {
		return nil, err
	}
	if len(data) < 1 {
		return nil, errors.New("address missing witness version")
	}

	version := data[0]
	if version > MaxAddressVersion {
		return nil, fmt.Errorf("%w: version %d exceeds max %d",
			ErrInvalidAddressVersion, version, MaxAddressVersion)
	}

	hash, err := bech32.ConvertBits(data[1:], 5, 8, false)
	if err != nil {
		return nil, err
	}

	if err := validateAddress(version, hash); err != nil {
		return nil, err
	}

	return &handshakeAddress{
		version: version,
		hash:    hash,
		hrp:     strings.ToLower(hrp),
	}, nil
}

// Version returns the witness-program version for the address.
func (a *handshakeAddress) Version() uint8 {
	return a.version
}

// Hash returns a defensive copy of the raw hash bytes of the address so
// callers cannot mutate the internal state.
func (a *handshakeAddress) Hash() []byte {
	return append([]byte(nil), a.hash...)
}

// HRP returns the human-readable part (network prefix) of the address.
func (a *handshakeAddress) HRP() string {
	return a.hrp
}

// EncodeAddress returns the bech32 string encoding of the address.
func (a *handshakeAddress) EncodeAddress() string {
	converted, err := bech32.ConvertBits(a.hash, 8, 5, true)
	if err != nil {
		return ""
	}
	combined := make([]byte, len(converted)+1)
	combined[0] = a.version
	copy(combined[1:], converted)

	encoded, err := bech32.Encode(a.hrp, combined)
	if err != nil {
		return ""
	}
	return encoded
}

// ScriptAddress returns a defensive copy of the raw hash bytes to be
// embedded in a txout script.  For Handshake this is identical to Hash().
func (a *handshakeAddress) ScriptAddress() []byte {
	return append([]byte(nil), a.hash...)
}

// IsForNet returns whether or not the address is associated with the passed
// Handshake network.
func (a *handshakeAddress) IsForNet(net *chaincfg.Params) bool {
	return net != nil && a.hrp == strings.ToLower(net.Bech32HRPSegwit)
}

// String returns a human-readable string for the address and satisfies the
// fmt.Stringer interface.  It is equivalent to calling EncodeAddress.
func (a *handshakeAddress) String() string {
	return a.EncodeAddress()
}

// AddressEqual reports whether two Addresses are identical.
func AddressEqual(a, b Address) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Version() == b.Version() &&
		a.HRP() == b.HRP() &&
		bytes.Equal(a.Hash(), b.Hash())
}
