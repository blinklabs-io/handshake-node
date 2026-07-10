// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package brontide

import (
	"bytes"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
)

func TestKeyGenerationAndParsing(t *testing.T) {
	priv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	pub := PublicKeyBytes(priv)
	if len(pub) != PublicKeySize {
		t.Fatalf("public key size: got %d, want %d", len(pub), PublicKeySize)
	}
	if !btcec.IsCompressedPubKey(pub) {
		t.Fatalf("public key is not compressed: %x", pub)
	}

	parsed, err := ParsePublicKey(pub)
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	if !bytes.Equal(parsed.SerializeCompressed(), pub) {
		t.Fatalf("parsed public key: got %x, want %x",
			parsed.SerializeCompressed(), pub)
	}
}

func TestParsePublicKeyRejectsNonCompressedKey(t *testing.T) {
	priv, _ := btcec.PrivKeyFromBytes(testKey(0x01))

	_, err := ParsePublicKey(priv.PubKey().SerializeUncompressed())
	if !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("ParsePublicKey error: got %v, want %v", err, ErrInvalidKey)
	}
}

func TestECDHMatchesFromBothSides(t *testing.T) {
	alice, _ := btcec.PrivKeyFromBytes(testKey(0x01))
	bob, _ := btcec.PrivKeyFromBytes(testKey(0x40))

	aliceSecret, err := ECDH(bob.PubKey(), alice)
	if err != nil {
		t.Fatalf("alice ECDH: %v", err)
	}
	bobSecret, err := ECDH(alice.PubKey(), bob)
	if err != nil {
		t.Fatalf("bob ECDH: %v", err)
	}

	if aliceSecret != bobSecret {
		t.Fatalf("ECDH secrets differ: alice %x bob %x", aliceSecret, bobSecret)
	}
	if aliceSecret == ([keySize]byte{}) {
		t.Fatal("ECDH secret is zero")
	}

	got, err := ECDHBytes(PublicKeyBytes(bob), alice)
	if err != nil {
		t.Fatalf("ECDHBytes: %v", err)
	}
	if got != aliceSecret {
		t.Fatalf("ECDHBytes secret: got %x, want %x", got, aliceSecret)
	}
}

func TestECDHRejectsNilKeys(t *testing.T) {
	priv, _ := btcec.PrivKeyFromBytes(testKey(0x01))

	if _, err := ECDH(nil, priv); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("nil public key error: got %v, want %v", err, ErrInvalidKey)
	}
	if _, err := ECDH(priv.PubKey(), nil); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("nil private key error: got %v, want %v", err, ErrInvalidKey)
	}
}

func TestECDHRejectsPointOffCurve(t *testing.T) {
	priv, _ := btcec.PrivKeyFromBytes(testKey(0x01))

	var x, y btcec.FieldVal
	pub := btcec.NewPublicKey(&x, &y)
	if pub.IsOnCurve() {
		t.Fatal("test point unexpectedly lies on secp256k1")
	}

	if _, err := ECDH(pub, priv); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("ECDH error: got %v, want %v", err, ErrInvalidKey)
	}
}
