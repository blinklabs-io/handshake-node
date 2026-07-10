// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

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

// hsdCipherKey and hsdCipherSalt are the CipherState fixtures from hsd's
// test/brontide-test.js.
func hsdCipherKey(t *testing.T) (*CipherState, []byte, []byte) {
	t.Helper()

	key := mustHex(t,
		"2121212121212121212121212121212121212121212121212121212121212121")
	salt := mustHex(t,
		"1111111111111111111111111111111111111111111111111111111111111111")

	c := NewCipherState()
	if err := c.InitSalt(key, salt); err != nil {
		t.Fatalf("InitSalt: %v", err)
	}
	return c, key, salt
}

func TestCipherStateHsdRotationVector(t *testing.T) {
	c, key, salt := hsdCipherKey(t)
	if !bytes.Equal(c.key[:], key) {
		t.Fatalf("key: got %x, want %x", c.key, key)
	}
	if !bytes.Equal(c.salt[:], salt) {
		t.Fatalf("salt: got %x, want %x", c.salt, salt)
	}

	c.rotateKey()

	wantKey := mustHex(t,
		"0b579ba44366e4d49ac7a44a8203925cb6d610e950aee7a23c47a5448173af11")
	wantSalt := mustHex(t,
		"be23775b41e7c67d1ec6dcfc21299f32461e145d4164f65943b4b99fcaff6dee")
	if !bytes.Equal(c.key[:], wantKey) {
		t.Fatalf("rotated key: got %x, want %x", c.key, wantKey)
	}
	if !bytes.Equal(c.salt[:], wantSalt) {
		t.Fatalf("rotated salt: got %x, want %x", c.salt, wantSalt)
	}
	if c.Nonce() != 0 {
		t.Fatalf("nonce after rotation: got %d, want 0", c.Nonce())
	}
}

func TestCipherStateHsdEncryptVectors(t *testing.T) {
	tests := []struct {
		name string
		ad   string
		tag1 string
		tag2 string
	}{
		{
			name: "empty ad",
			tag1: "f11ae60b9df4c6ea25aea58ce1b6df83",
			tag2: "d840242a1e817cd8374d45fb5621a5fc",
		},
		{
			name: "with ad",
			ad:   "222222222222222222222222222222222222",
			tag1: "81ad416f62157481c8af8ace16b64e15",
			tag2: "df3f8257977dfb8d283c6fb149d2d49d",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c, _, _ := hsdCipherKey(t)

			var ad []byte
			if test.ad != "" {
				ad = mustHex(t, test.ad)
			}

			ct1, tag1, err := c.Encrypt([]byte("hello"), ad)
			if err != nil {
				t.Fatalf("Encrypt #1: %v", err)
			}
			if !bytes.Equal(ct1, mustHex(t, "0935b4c530")) {
				t.Fatalf("ciphertext #1: got %x", ct1)
			}
			if !bytes.Equal(tag1, mustHex(t, test.tag1)) {
				t.Fatalf("tag #1: got %x, want %s", tag1, test.tag1)
			}

			ct2, tag2, err := c.Encrypt([]byte("hello"), ad)
			if err != nil {
				t.Fatalf("Encrypt #2: %v", err)
			}
			if !bytes.Equal(ct2, mustHex(t, "74898781da")) {
				t.Fatalf("ciphertext #2: got %x", ct2)
			}
			if !bytes.Equal(tag2, mustHex(t, test.tag2)) {
				t.Fatalf("tag #2: got %x, want %s", tag2, test.tag2)
			}
		})
	}
}

func TestCipherStateHsdRotateAfterEncrypt(t *testing.T) {
	c, _, _ := hsdCipherKey(t)
	c.nonce = RotationInterval - 1

	if _, _, err := c.Encrypt([]byte("hello"), nil); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if c.Nonce() != 0 {
		t.Fatalf("nonce: got %d, want 0", c.Nonce())
	}

	wantKey := mustHex(t,
		"0b579ba44366e4d49ac7a44a8203925cb6d610e950aee7a23c47a5448173af11")
	wantSalt := mustHex(t,
		"be23775b41e7c67d1ec6dcfc21299f32461e145d4164f65943b4b99fcaff6dee")
	if !bytes.Equal(c.key[:], wantKey) {
		t.Fatalf("rotated key: got %x, want %x", c.key, wantKey)
	}
	if !bytes.Equal(c.salt[:], wantSalt) {
		t.Fatalf("rotated salt: got %x, want %x", c.salt, wantSalt)
	}
}
