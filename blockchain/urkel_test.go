// Copyright (c) 2024-2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/blinklabs-io/handshake-node/chaincfg"
	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/database"
	"golang.org/x/crypto/blake2b"
)

func TestCalcUrkelRootEmpty(t *testing.T) {
	root := calcUrkelRoot(nil)
	if root != zeroHash {
		t.Fatalf("empty root = %v, want zero hash", root)
	}
}

func TestCalcUrkelRootSingleLeaf(t *testing.T) {
	key := chainhash.Hash{0x01}
	value := []byte("alpha")
	root := calcUrkelRoot([]urkelLeaf{{key: key, value: value}})

	valueHash := blake2b.Sum256(value)
	preimage := make([]byte, 1+chainhash.HashSize+chainhash.HashSize)
	preimage[0] = 0x00
	copy(preimage[1:], key[:])
	copy(preimage[1+chainhash.HashSize:], valueHash[:])
	want := chainhash.Hash(blake2b.Sum256(preimage))

	if root != want {
		t.Fatalf("single leaf root = %v, want %v", root, want)
	}
}

func TestCalcUrkelRootCompressedInternal(t *testing.T) {
	var leftKey, rightKey chainhash.Hash
	leftKey[31] = 0x01
	rightKey[31] = 0x03
	leftValue := []byte("alpha")
	rightValue := []byte("beta")

	root := calcUrkelRoot([]urkelLeaf{
		{key: rightKey, value: rightValue},
		{key: leftKey, value: leftValue},
	})

	leftHash := urkelLeafDigest(leftKey, leftValue)
	rightHash := urkelLeafDigest(rightKey, rightValue)
	prefix := make([]byte, chainhash.HashSize)
	preimage := make([]byte, 1+2+len(prefix)+chainhash.HashSize*2)
	preimage[0] = 0x02
	binary.LittleEndian.PutUint16(preimage[1:3], 254)
	copy(preimage[3:], prefix)
	offset := 3 + len(prefix)
	copy(preimage[offset:], leftHash[:])
	copy(preimage[offset+chainhash.HashSize:], rightHash[:])
	want := chainhash.Hash(blake2b.Sum256(preimage))

	if root != want {
		t.Fatalf("compressed internal root = %v, want %v", root, want)
	}
}

func TestCalcUrkelRootInsertionOrderIndependent(t *testing.T) {
	var a, b, c chainhash.Hash
	a[0] = 0x20
	b[0] = 0x80
	c[0] = 0xe0

	forward := []urkelLeaf{
		{key: a, value: []byte("a")},
		{key: b, value: []byte("b")},
		{key: c, value: []byte("c")},
	}
	reverse := []urkelLeaf{
		{key: c, value: []byte("c")},
		{key: b, value: []byte("b")},
		{key: a, value: []byte("a")},
	}

	want := calcUrkelRoot(forward)
	got := calcUrkelRoot(reverse)
	if got != want {
		t.Fatalf("root depends on insertion order: got %v, want %v", got, want)
	}
}

func TestUrkelProofExistsRoundTrip(t *testing.T) {
	var key, other chainhash.Hash
	key[0] = 0x20
	other[0] = 0x80
	value := []byte("alpha")

	tree := buildUrkelTree([]urkelLeaf{
		{key: key, value: value},
		{key: other, value: []byte("beta")},
	})
	root := tree.hash()
	proof := proveUrkel(tree, key)
	encoded, err := proof.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	got, exists, err := VerifyUrkelProof(root, key, encoded)
	if err != nil {
		t.Fatalf("VerifyUrkelProof: %v", err)
	}
	if !exists {
		t.Fatal("VerifyUrkelProof returned exclusion proof")
	}
	if !bytes.Equal(got, value) {
		t.Fatalf("proof value = %q, want %q", got, value)
	}

	decoded, err := DecodeUrkelProof(encoded)
	if err != nil {
		t.Fatalf("DecodeUrkelProof: %v", err)
	}
	reencoded, err := decoded.Encode()
	if err != nil {
		t.Fatalf("decoded Encode: %v", err)
	}
	if !bytes.Equal(reencoded, encoded) {
		t.Fatalf("proof reencode mismatch:\n got %x\nwant %x",
			reencoded, encoded)
	}
}

func TestUrkelProofCollisionRoundTrip(t *testing.T) {
	var key, query chainhash.Hash
	key[0] = 0x20
	query[0] = 0x21

	tree := buildUrkelTree([]urkelLeaf{{key: key, value: []byte("alpha")}})
	root := tree.hash()
	encoded, err := proveUrkel(tree, query).Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	value, exists, err := VerifyUrkelProof(root, query, encoded)
	if err != nil {
		t.Fatalf("VerifyUrkelProof: %v", err)
	}
	if exists || value != nil {
		t.Fatalf("collision proof returned value %x, exists=%v",
			value, exists)
	}
}

func TestUrkelProofShortRoundTrip(t *testing.T) {
	var leftKey, rightKey, query chainhash.Hash
	leftKey[31] = 0x01
	rightKey[31] = 0x03
	query[0] = 0x80

	tree := buildUrkelTree([]urkelLeaf{
		{key: leftKey, value: []byte("alpha")},
		{key: rightKey, value: []byte("beta")},
	})
	root := tree.hash()
	encoded, err := proveUrkel(tree, query).Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	value, exists, err := VerifyUrkelProof(root, query, encoded)
	if err != nil {
		t.Fatalf("VerifyUrkelProof: %v", err)
	}
	if exists || value != nil {
		t.Fatalf("short proof returned value %x, exists=%v",
			value, exists)
	}
}

func TestUrkelProofDeadendRoundTrip(t *testing.T) {
	var key chainhash.Hash
	key[0] = 0x20

	encoded, err := proveUrkel(nil, key).Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	value, exists, err := VerifyUrkelProof(chainhash.Hash{}, key, encoded)
	if err != nil {
		t.Fatalf("VerifyUrkelProof: %v", err)
	}
	if exists || value != nil {
		t.Fatalf("deadend proof returned value %x, exists=%v",
			value, exists)
	}
}

func TestUrkelProofRejectsWrongRoot(t *testing.T) {
	var key chainhash.Hash
	key[0] = 0x20
	tree := buildUrkelTree([]urkelLeaf{{key: key, value: []byte("alpha")}})
	encoded, err := proveUrkel(tree, key).Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	var wrongRoot chainhash.Hash
	wrongRoot[0] = 0xff
	if _, _, err := VerifyUrkelProof(wrongRoot, key, encoded); err == nil {
		t.Fatal("VerifyUrkelProof accepted wrong root")
	}
}

func TestFetchNameProofUsesStoredSnapshot(t *testing.T) {
	chain, teardown, err := chainSetup("nameproof",
		&chaincfg.RegressionNetParams)
	if err != nil {
		t.Fatalf("chainSetup: %v", err)
	}
	defer teardown()

	key := hashName([]byte("alpha"))
	ns := newNameState(key)
	ns.set([]byte("alpha"), 1)
	ns.data = []byte("old-resource")
	oldValue, err := ns.encode()
	if err != nil {
		t.Fatalf("old encode: %v", err)
	}

	var oldRoot chainhash.Hash
	err = chain.db.Update(func(dbTx database.Tx) error {
		if err := dbPutNameState(dbTx, ns); err != nil {
			return err
		}
		var err error
		oldRoot, err = dbStoreCurrentNameSnapshot(dbTx)
		if err != nil {
			return err
		}

		updated := ns.clone()
		updated.data = []byte("new-resource")
		if err := dbPutNameState(dbTx, updated); err != nil {
			return err
		}
		_, err = dbStoreCurrentNameSnapshot(dbTx)
		return err
	})
	if err != nil {
		t.Fatalf("db update: %v", err)
	}

	encoded, err := chain.FetchNameProof(oldRoot, key)
	if err != nil {
		t.Fatalf("FetchNameProof: %v", err)
	}
	got, exists, err := VerifyUrkelProof(oldRoot, key, encoded)
	if err != nil {
		t.Fatalf("VerifyUrkelProof: %v", err)
	}
	if !exists {
		t.Fatal("FetchNameProof returned exclusion proof")
	}
	if !bytes.Equal(got, oldValue) {
		t.Fatalf("snapshot proof value = %x, want %x", got, oldValue)
	}
}

func urkelLeafDigest(key chainhash.Hash, value []byte) chainhash.Hash {
	valueHash := blake2b.Sum256(value)
	preimage := make([]byte, 1+chainhash.HashSize+chainhash.HashSize)
	preimage[0] = 0x00
	copy(preimage[1:], key[:])
	copy(preimage[1+chainhash.HashSize:], valueHash[:])
	return chainhash.Hash(blake2b.Sum256(preimage))
}
