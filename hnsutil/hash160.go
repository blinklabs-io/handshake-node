// Copyright (c) 2013-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package hnsutil

import (
	"crypto/sha256"
	"hash"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/ripemd160"
)

// Calculate the hash of hasher over buf.
func calcHash(buf []byte, hasher hash.Hash) []byte {
	_, _ = hasher.Write(buf)
	return hasher.Sum(nil)
}

// Hash160 calculates the hash ripemd160(sha256(b)).
func Hash160(buf []byte) []byte {
	return calcHash(calcHash(buf, sha256.New()), ripemd160.New())
}

// Blake160 calculates the Handshake pubkey hash blake2b-160(b).
func Blake160(buf []byte) []byte {
	hasher, err := blake2b.New(20, nil)
	if err != nil {
		panic("invalid blake2b-160 size")
	}
	return calcHash(buf, hasher)
}
