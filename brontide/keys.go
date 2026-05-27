// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package brontide

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
)

const (
	// PrivateKeySize is the size of a serialized secp256k1 private key.
	PrivateKeySize = btcec.PrivKeyBytesLen

	// PublicKeySize is the size of a compressed secp256k1 public key.
	PublicKeySize = btcec.PubKeyBytesLenCompressed
)

var (
	// ErrInvalidKey is returned when Brontide key material is nil or invalid.
	ErrInvalidKey = errors.New("brontide: invalid key")
)

// GenerateKey creates a secp256k1 private key suitable for Brontide static or
// ephemeral key material.
func GenerateKey() (*btcec.PrivateKey, error) {
	return btcec.NewPrivateKey()
}

// PublicKeyBytes returns the compressed public key for priv.
func PublicKeyBytes(priv *btcec.PrivateKey) []byte {
	if priv == nil {
		return nil
	}
	return priv.PubKey().SerializeCompressed()
}

// ParsePublicKey parses a compressed secp256k1 public key.
func ParsePublicKey(serialized []byte) (*btcec.PublicKey, error) {
	if !btcec.IsCompressedPubKey(serialized) {
		return nil, fmt.Errorf("%w: public key is not compressed", ErrInvalidKey)
	}
	pub, err := btcec.ParsePubKey(serialized)
	if err != nil {
		return nil, err
	}
	if !pub.IsOnCurve() {
		return nil, fmt.Errorf("%w: public key is not on secp256k1", ErrInvalidKey)
	}
	return pub, nil
}

// ECDH returns hsd's Brontide ECDH secret: SHA256(compressed shared point).
func ECDH(pub *btcec.PublicKey, priv *btcec.PrivateKey) ([keySize]byte, error) {
	if pub == nil {
		return [keySize]byte{}, fmt.Errorf("%w: nil public key", ErrInvalidKey)
	}
	if priv == nil {
		return [keySize]byte{}, fmt.Errorf("%w: nil private key", ErrInvalidKey)
	}
	if !pub.IsOnCurve() {
		return [keySize]byte{}, fmt.Errorf("%w: public key is not on secp256k1", ErrInvalidKey)
	}

	var point btcec.JacobianPoint
	pub.AsJacobian(&point)

	var shared btcec.JacobianPoint
	btcec.ScalarMultNonConst(&priv.Key, &point, &shared)
	shared.ToAffine()

	sharedPub := btcec.NewPublicKey(&shared.X, &shared.Y)
	return sha256.Sum256(sharedPub.SerializeCompressed()), nil
}

// ECDHBytes parses pub and returns hsd's Brontide ECDH secret:
// SHA256(compressed shared point).
func ECDHBytes(pub []byte, priv *btcec.PrivateKey) ([keySize]byte, error) {
	parsed, err := ParsePublicKey(pub)
	if err != nil {
		return [keySize]byte{}, err
	}
	return ECDH(parsed, priv)
}
