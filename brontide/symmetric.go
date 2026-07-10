// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package brontide

import "crypto/sha256"

// SymmetricState is the Noise symmetric state used by Handshake Brontide.
type SymmetricState struct {
	cipher CipherState
	chain  [keySize]byte
	digest [keySize]byte
	temp   [keySize]byte
}

// NewSymmetricState initializes a symmetric state with hsd's protocol name.
func NewSymmetricState() *SymmetricState {
	s := &SymmetricState{}
	s.InitSymmetric(ProtocolName)
	return s
}

// InitSymmetric initializes the handshake digest, chaining key, and zero-key
// cipher state for a Noise protocol name.
func (s *SymmetricState) InitSymmetric(protocolName string) {
	if len(protocolName) <= keySize {
		s.digest = [keySize]byte{}
		copy(s.digest[:], protocolName)
	} else {
		s.digest = sha256.Sum256([]byte(protocolName))
	}
	s.chain = s.digest
	s.temp = [keySize]byte{}
	s.cipher = *NewCipherState()
}

// ChainKey returns the current chaining key.
func (s *SymmetricState) ChainKey() [keySize]byte {
	return s.chain
}

// Digest returns the current handshake digest.
func (s *SymmetricState) Digest() [keySize]byte {
	return s.digest
}

// MixKey mixes input key material into the chaining key and reinitializes the
// handshake cipher with the derived temporary key.
func (s *SymmetricState) MixKey(input []byte) {
	chain, temp := hkdfExpand(input, s.chain[:], nil)
	copy(s.chain[:], chain)
	copy(s.temp[:], temp)
	if err := s.cipher.InitKey(s.temp[:]); err != nil {
		panic(err)
	}
}

// MixHash updates the handshake digest with one or more byte slices.
func (s *SymmetricState) MixHash(parts ...[]byte) {
	h := sha256.New()
	_, _ = h.Write(s.digest[:])
	for _, part := range parts {
		_, _ = h.Write(part)
	}
	copy(s.digest[:], h.Sum(nil))
}

// EncryptHash encrypts plaintext with the current digest as associated data
// and mixes the resulting ciphertext and tag into the digest.
func (s *SymmetricState) EncryptHash(plaintext []byte) ([]byte, []byte, error) {
	ciphertext, tag, err := s.cipher.Encrypt(plaintext, s.digest[:])
	if err != nil {
		return nil, nil, err
	}
	s.MixHash(ciphertext, tag)
	return ciphertext, tag, nil
}

// DecryptHash authenticates and decrypts ciphertext with the current digest as
// associated data, then mixes the ciphertext and tag into the digest.
func (s *SymmetricState) DecryptHash(ciphertext, tag []byte) ([]byte, error) {
	nextDigest := hashDigest(s.digest[:], ciphertext, tag)
	plaintext, err := s.cipher.Decrypt(ciphertext, tag, s.digest[:])
	if err != nil {
		return nil, err
	}
	s.digest = nextDigest
	return plaintext, nil
}

// Split derives send and receive ciphers from the final chaining key. The
// initiator uses the first derived key for sending; the responder uses it for
// receiving, matching hsd.
func (s *SymmetricState) Split(initiator bool) (*CipherState, *CipherState, error) {
	k1, k2 := hkdfExpand(nil, s.chain[:], nil)

	send := NewCipherState()
	recv := NewCipherState()
	if initiator {
		if err := send.InitSalt(k1, s.chain[:]); err != nil {
			return nil, nil, err
		}
		if err := recv.InitSalt(k2, s.chain[:]); err != nil {
			return nil, nil, err
		}
		return send, recv, nil
	}

	if err := recv.InitSalt(k1, s.chain[:]); err != nil {
		return nil, nil, err
	}
	if err := send.InitSalt(k2, s.chain[:]); err != nil {
		return nil, nil, err
	}
	return send, recv, nil
}

func hashDigest(parts ...[]byte) [keySize]byte {
	h := sha256.New()
	for _, part := range parts {
		_, _ = h.Write(part)
	}
	var out [keySize]byte
	copy(out[:], h.Sum(nil))
	return out
}
