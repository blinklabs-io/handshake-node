// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package brontide implements Handshake's Brontide P2P transport primitives.
package brontide

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	// ProtocolName is hsd's Noise protocol name for Handshake Brontide.
	ProtocolName = "Noise_XK_secp256k1_ChaChaPoly_SHA256+SVDW_Squared"

	// Prologue is mixed into the Handshake Brontide handshake hash.
	Prologue = "hns"

	// RotationInterval is hsd's cipher key rotation interval. The cipher
	// rotates after this many successful encryptions or decryptions.
	RotationInterval = 1000

	keySize   = chacha20poly1305.KeySize
	nonceSize = chacha20poly1305.NonceSize
	tagSize   = chacha20poly1305.Overhead
)

var (
	// ErrInvalidCipher is returned when a Brontide cipher state is nil.
	ErrInvalidCipher = errors.New("brontide: invalid cipher")

	// ErrInvalidKeySize is returned when a cipher key or salt is not 32 bytes.
	ErrInvalidKeySize = errors.New("brontide: invalid key size")

	// ErrDecrypt is returned when ChaCha20-Poly1305 authentication fails.
	ErrDecrypt = errors.New("brontide: decrypt failed")
)

// CipherState is hsd's Brontide ChaCha20-Poly1305 cipher state. It keeps a
// key, a salt used for key rotation, and a monotonically increasing nonce.
type CipherState struct {
	key   [keySize]byte
	salt  [keySize]byte
	nonce uint32
}

// NewCipherState returns a cipher initialized with the all-zero key and salt,
// matching hsd's initial Brontide cipher state.
func NewCipherState() *CipherState {
	return &CipherState{}
}

// InitKey replaces the cipher key and resets the nonce.
func (c *CipherState) InitKey(key []byte) error {
	if len(key) != keySize {
		return fmt.Errorf("%w: key is %d bytes, want %d",
			ErrInvalidKeySize, len(key), keySize)
	}
	copy(c.key[:], key)
	c.nonce = 0
	return nil
}

// InitSalt replaces the cipher salt, then initializes the key.
func (c *CipherState) InitSalt(key, salt []byte) error {
	if len(salt) != keySize {
		return fmt.Errorf("%w: salt is %d bytes, want %d",
			ErrInvalidKeySize, len(salt), keySize)
	}
	copy(c.salt[:], salt)
	return c.InitKey(key)
}

// Nonce returns the current message nonce. It is exposed for tests and for
// future transport diagnostics.
func (c *CipherState) Nonce() uint32 {
	return c.nonce
}

// Encrypt encrypts plaintext with optional associated data. It returns the
// ciphertext and detached authentication tag.
func (c *CipherState) Encrypt(plaintext, ad []byte) ([]byte, []byte, error) {
	if c == nil {
		return nil, nil, fmt.Errorf("%w: nil cipher", ErrInvalidCipher)
	}

	aead, err := chacha20poly1305.New(c.key[:])
	if err != nil {
		return nil, nil, err
	}

	var nonce [nonceSize]byte
	c.putNonce(&nonce)
	sealed := aead.Seal(nil, nonce[:], plaintext, ad)
	c.advance()

	ciphertext := append([]byte(nil), sealed[:len(plaintext)]...)
	tag := append([]byte(nil), sealed[len(plaintext):]...)
	return ciphertext, tag, nil
}

// Decrypt authenticates and decrypts ciphertext with a detached tag and
// optional associated data.
func (c *CipherState) Decrypt(ciphertext, tag, ad []byte) ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("%w: nil cipher", ErrInvalidCipher)
	}
	if len(tag) != tagSize {
		return nil, fmt.Errorf("%w: tag is %d bytes, want %d",
			ErrDecrypt, len(tag), tagSize)
	}

	aead, err := chacha20poly1305.New(c.key[:])
	if err != nil {
		return nil, err
	}

	sealed := make([]byte, 0, len(ciphertext)+len(tag))
	sealed = append(sealed, ciphertext...)
	sealed = append(sealed, tag...)

	var nonce [nonceSize]byte
	c.putNonce(&nonce)
	plaintext, err := aead.Open(nil, nonce[:], sealed, ad)
	if err != nil {
		return nil, ErrDecrypt
	}
	c.advance()

	return plaintext, nil
}

func (c *CipherState) putNonce(nonce *[nonceSize]byte) {
	binary.LittleEndian.PutUint32(nonce[4:8], c.nonce)
}

func (c *CipherState) advance() {
	c.nonce++
	if c.nonce == RotationInterval {
		c.rotateKey()
	}
}

func (c *CipherState) rotateKey() {
	salt, next := hkdfExpand(c.key[:], c.salt[:], nil)
	copy(c.salt[:], salt)
	copy(c.key[:], next)
	c.nonce = 0
}

func hkdfExpand(secret, salt, info []byte) ([]byte, []byte) {
	prk := hkdf.Extract(sha256.New, secret, salt)
	out := make([]byte, keySize*2)
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, prk, info), out); err != nil {
		panic(fmt.Sprintf("brontide hkdf expand failed: %v", err))
	}
	return out[:keySize], out[keySize:]
}
