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
	"bytes"
	"errors"
	"testing"
)

func testKey(start byte) []byte {
	key := make([]byte, keySize)
	for i := range key {
		key[i] = start + byte(i)
	}
	return key
}

func newTestCipher(t *testing.T) *CipherState {
	t.Helper()

	c := NewCipherState()
	if err := c.InitSalt(testKey(0x10), testKey(0x80)); err != nil {
		t.Fatalf("InitSalt: %v", err)
	}
	return c
}

func TestCipherStateRoundTrip(t *testing.T) {
	send := newTestCipher(t)
	recv := newTestCipher(t)

	plaintext := []byte("handshake brontide payload")
	ad := []byte("associated data")

	ciphertext, tag, err := send.Encrypt(plaintext, ad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("ciphertext unexpectedly matches plaintext")
	}
	if len(tag) != tagSize {
		t.Fatalf("tag length: got %d, want %d", len(tag), tagSize)
	}

	got, err := recv.Decrypt(ciphertext, tag, ad)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext: got %x, want %x", got, plaintext)
	}
	if send.Nonce() != 1 {
		t.Fatalf("send nonce: got %d, want 1", send.Nonce())
	}
	if recv.Nonce() != 1 {
		t.Fatalf("recv nonce: got %d, want 1", recv.Nonce())
	}
}

func TestCipherStateRejectsBadTag(t *testing.T) {
	send := newTestCipher(t)
	recv := newTestCipher(t)

	ciphertext, tag, err := send.Encrypt([]byte("payload"), nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	tag[0] ^= 0x01

	_, err = recv.Decrypt(ciphertext, tag, nil)
	if !errors.Is(err, ErrDecrypt) {
		t.Fatalf("Decrypt error: got %v, want %v", err, ErrDecrypt)
	}
	if recv.Nonce() != 0 {
		t.Fatalf("recv nonce advanced after failed decrypt: got %d", recv.Nonce())
	}
}

func TestCipherStateRotatesAtHsdInterval(t *testing.T) {
	send := newTestCipher(t)
	recv := newTestCipher(t)

	for i := 0; i < RotationInterval; i++ {
		plaintext := []byte{byte(i)}
		ciphertext, tag, err := send.Encrypt(plaintext, nil)
		if err != nil {
			t.Fatalf("Encrypt #%d: %v", i, err)
		}
		got, err := recv.Decrypt(ciphertext, tag, nil)
		if err != nil {
			t.Fatalf("Decrypt #%d: %v", i, err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("plaintext #%d: got %x, want %x", i, got, plaintext)
		}
	}

	if send.Nonce() != 0 {
		t.Fatalf("send nonce after rotation: got %d, want 0", send.Nonce())
	}
	if recv.Nonce() != 0 {
		t.Fatalf("recv nonce after rotation: got %d, want 0", recv.Nonce())
	}

	ciphertext, tag, err := send.Encrypt([]byte("post-rotation"), nil)
	if err != nil {
		t.Fatalf("Encrypt after rotation: %v", err)
	}
	got, err := recv.Decrypt(ciphertext, tag, nil)
	if err != nil {
		t.Fatalf("Decrypt after rotation: %v", err)
	}
	if string(got) != "post-rotation" {
		t.Fatalf("post-rotation plaintext: got %q", got)
	}
}

func TestCipherStateRejectsInvalidKeySizes(t *testing.T) {
	c := NewCipherState()

	if err := c.InitKey(make([]byte, keySize-1)); !errors.Is(err, ErrInvalidKeySize) {
		t.Fatalf("InitKey error: got %v, want %v", err, ErrInvalidKeySize)
	}
	if err := c.InitSalt(testKey(0x10), make([]byte, keySize-1)); !errors.Is(err, ErrInvalidKeySize) {
		t.Fatalf("InitSalt error: got %v, want %v", err, ErrInvalidKeySize)
	}
}

func TestCipherStateRejectsNilCipher(t *testing.T) {
	var c *CipherState

	_, _, err := c.Encrypt([]byte("payload"), nil)
	if !errors.Is(err, ErrInvalidCipher) {
		t.Fatalf("Encrypt error: got %v, want %v", err, ErrInvalidCipher)
	}

	_, err = c.Decrypt([]byte("payload"), make([]byte, tagSize), nil)
	if !errors.Is(err, ErrInvalidCipher) {
		t.Fatalf("Decrypt error: got %v, want %v", err, ErrInvalidCipher)
	}
}
