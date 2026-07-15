// Copyright (c) 2024-2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"testing"

	"github.com/blinklabs-io/handshake-node/chaincfg"
	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/database"
	"github.com/blinklabs-io/handshake-node/wire"
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

func TestMainnetNameRootFixtures(t *testing.T) {
	const emptyNameRoot = "0000000000000000000000000000000000000000000000000000000000000000"
	tests := []struct {
		file string
		root string
	}{
		{file: "block_0.raw", root: emptyNameRoot},
		{file: "block_1.raw", root: emptyNameRoot},
		{file: "block_2.raw", root: emptyNameRoot},
		{file: "block_3.raw", root: emptyNameRoot},
		{file: "block_4.raw", root: emptyNameRoot},
	}

	for _, test := range tests {
		t.Run(test.file, func(t *testing.T) {
			want, err := chainhash.NewHashFromStr(test.root)
			if err != nil {
				t.Fatalf("NewHashFromStr: %v", err)
			}
			rawBlock, err := os.ReadFile("testdata/handshake/" +
				test.file)
			if err != nil {
				t.Fatalf("ReadFile: %v", err)
			}

			var block wire.MsgBlock
			if err := block.Deserialize(bytes.NewReader(rawBlock)); err != nil {
				t.Fatalf("Deserialize: %v", err)
			}
			if got := block.Header.NameRoot; got != *want {
				t.Fatalf("NameRoot = %v, want %v", got,
					*want)
			}
		})
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
		leaves, root, err := dbCalcNameTree(dbTx)
		if err != nil {
			return err
		}
		oldRoot = root
		if err := dbPutNameRoot(dbTx, oldRoot); err != nil {
			return err
		}
		if err := dbPutNameSnapshot(dbTx, oldRoot, leaves); err != nil {
			return err
		}

		updated := ns.clone()
		updated.data = []byte("new-resource")
		if err := dbPutNameState(dbTx, updated); err != nil {
			return err
		}
		_, err = dbStoreCurrentNameRoot(dbTx)
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

func TestFetchNameProofRewindsToCommittedRoot(t *testing.T) {
	chain, teardown, err := chainSetup("nameproofrewind",
		&chaincfg.RegressionNetParams)
	if err != nil {
		t.Fatalf("chainSetup: %v", err)
	}
	defer teardown()

	key := hashName([]byte("alpha"))
	committed := newNameState(key)
	committed.set([]byte("alpha"), 1)
	committed.data = []byte("committed-resource")
	committedValue, err := committed.encode()
	if err != nil {
		t.Fatalf("committed encode: %v", err)
	}
	committedRoot := calcUrkelRoot([]urkelLeaf{{
		key:   key,
		value: committedValue,
	}})

	intermediate := committed.clone()
	intermediate.data = []byte("intermediate-resource")
	live := committed.clone()
	live.data = []byte("live-resource")
	createdKey := hashName([]byte("created-after-commit"))
	created := newNameState(createdKey)
	created.set([]byte("created-after-commit"), 2)

	firstHash := chainhash.Hash{0x41}
	secondHash := chainhash.Hash{0x42}
	err = chain.db.Update(func(dbTx database.Tx) error {
		if err := dbPutNameState(dbTx, live); err != nil {
			return err
		}
		if err := dbPutNameState(dbTx, created); err != nil {
			return err
		}
		if err := dbPutNameRoot(dbTx, committedRoot); err != nil {
			return err
		}
		if err := dbPutNameUndo(dbTx, &firstHash, []nameUndoEntry{
			{
				nameHash: key,
				existed:  true,
				state:    committed,
			},
			{
				nameHash: createdKey,
				existed:  false,
			},
		}); err != nil {
			return err
		}
		return dbPutNameUndo(dbTx, &secondHash, []nameUndoEntry{{
			nameHash: key,
			existed:  true,
			state:    intermediate,
		}})
	})
	if err != nil {
		t.Fatalf("db setup: %v", err)
	}

	// Model two active-chain blocks after the latest tree commitment. The
	// database contains the live state and each block's normal undo journal.
	chain.chainLock.Lock()
	genesis := chain.bestChain.Tip()
	first := &blockNode{
		hash:   firstHash,
		height: genesis.height + 1,
		parent: genesis,
	}
	second := &blockNode{
		hash:   secondHash,
		height: first.height + 1,
		parent: first,
	}
	chain.bestChain.SetTip(second)
	chain.chainLock.Unlock()

	encoded, err := chain.FetchNameProof(committedRoot, key)
	if err != nil {
		t.Fatalf("FetchNameProof: %v", err)
	}
	got, exists, err := VerifyUrkelProof(committedRoot, key, encoded)
	if err != nil {
		t.Fatalf("VerifyUrkelProof: %v", err)
	}
	if !exists {
		t.Fatal("FetchNameProof returned exclusion proof")
	}
	if !bytes.Equal(got, committedValue) {
		t.Fatalf("rewound proof value = %x, want %x", got, committedValue)
	}

	encoded, err = chain.FetchNameProof(committedRoot, createdKey)
	if err != nil {
		t.Fatalf("created-after-commit FetchNameProof: %v", err)
	}
	if _, exists, err := VerifyUrkelProof(committedRoot, createdKey, encoded); err != nil {
		t.Fatalf("created-after-commit VerifyUrkelProof: %v", err)
	} else if exists {
		t.Fatal("rewound proof retained a name created after the commitment")
	}

	// The immutable committed tree is cached after reconstruction. A second
	// key lookup must not depend on rescanning the live state or undo journal.
	err = chain.db.Update(func(dbTx database.Tx) error {
		if err := dbRemoveNameUndo(dbTx, &firstHash); err != nil {
			return err
		}
		return dbRemoveNameUndo(dbTx, &secondHash)
	})
	if err != nil {
		t.Fatalf("remove undo: %v", err)
	}

	missingKey := hashName([]byte("missing"))
	encoded, err = chain.FetchNameProof(committedRoot, missingKey)
	if err != nil {
		t.Fatalf("cached FetchNameProof: %v", err)
	}
	if _, exists, err := VerifyUrkelProof(committedRoot, missingKey, encoded); err != nil {
		t.Fatalf("cached VerifyUrkelProof: %v", err)
	} else if exists {
		t.Fatal("cached FetchNameProof returned inclusion proof for missing key")
	}
}

func TestVerifyNameUsesStoredSnapshot(t *testing.T) {
	chain, teardown, err := chainSetup("verifyname",
		&chaincfg.RegressionNetParams)
	if err != nil {
		t.Fatalf("chainSetup: %v", err)
	}
	defer teardown()

	key := hashName([]byte("alpha"))
	ns := newNameState(key)
	ns.set([]byte("alpha"), 1)
	ns.data = []byte("resource")

	var root chainhash.Hash
	err = chain.db.Update(func(dbTx database.Tx) error {
		if err := dbPutNameState(dbTx, ns); err != nil {
			return err
		}
		leaves, treeRoot, err := dbCalcNameTree(dbTx)
		if err != nil {
			return err
		}
		root = treeRoot
		if err := dbPutNameRoot(dbTx, root); err != nil {
			return err
		}
		return dbPutNameSnapshot(dbTx, root, leaves)
	})
	if err != nil {
		t.Fatalf("db update: %v", err)
	}

	state, proof, err := chain.VerifyName([]byte("alpha"), root)
	if err != nil {
		t.Fatalf("VerifyName: %v", err)
	}
	if proof == nil {
		t.Fatal("VerifyName returned nil proof")
	}
	assertNameStateView(t, state, ns)

	state, proof, err = chain.VerifyName([]byte("missing"), root)
	if err != nil {
		t.Fatalf("VerifyName missing: %v", err)
	}
	if state != nil {
		t.Fatalf("VerifyName missing state = %+v, want nil", state)
	}
	if proof == nil {
		t.Fatal("VerifyName missing returned nil proof")
	}
}

func TestStoreCurrentNameRootDoesNotWriteSnapshot(t *testing.T) {
	chain, teardown, err := chainSetup("namerootonly",
		&chaincfg.RegressionNetParams)
	if err != nil {
		t.Fatalf("chainSetup: %v", err)
	}
	defer teardown()

	key := hashName([]byte("alpha"))
	ns := newNameState(key)
	ns.set([]byte("alpha"), 1)
	ns.data = []byte("resource")

	err = chain.db.Update(func(dbTx database.Tx) error {
		if err := dbPutNameState(dbTx, ns); err != nil {
			return err
		}
		root, err := dbStoreCurrentNameRoot(dbTx)
		if err != nil {
			return err
		}

		bucket := dbTx.Metadata().Bucket(nameSnapshotBucketName)
		if bucket == nil {
			return fmt.Errorf("name snapshot bucket missing")
		}
		if snapshot := bucket.Get(root[:]); snapshot != nil {
			return fmt.Errorf("dbStoreCurrentNameRoot wrote snapshot of %d bytes",
				len(snapshot))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("db update: %v", err)
	}
}

func TestPruneNameSnapshotsRetainsCurrentAndRequestedRoots(t *testing.T) {
	chain, teardown, err := chainSetup("nameprunesnapshots",
		&chaincfg.RegressionNetParams)
	if err != nil {
		t.Fatalf("chainSetup: %v", err)
	}
	defer teardown()

	currentRoot := chainhash.Hash{0x01}
	retainedRoot := chainhash.Hash{0x02}
	prunedRoot := chainhash.Hash{0x03}
	leaves := []urkelLeaf{{
		key:   hashName([]byte("alpha")),
		value: []byte("resource"),
	}}

	err = chain.db.Update(func(dbTx database.Tx) error {
		if err := dbPutNameRoot(dbTx, currentRoot); err != nil {
			return err
		}
		for _, root := range []chainhash.Hash{
			currentRoot,
			retainedRoot,
			prunedRoot,
		} {
			if err := dbPutNameSnapshot(dbTx, root, leaves); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("db setup: %v", err)
	}

	pruned, err := chain.PruneNameSnapshots(retainedRoot)
	if err != nil {
		t.Fatalf("PruneNameSnapshots: %v", err)
	}
	if pruned != 1 {
		t.Fatalf("PruneNameSnapshots pruned %d snapshots, want 1",
			pruned)
	}

	err = chain.db.View(func(dbTx database.Tx) error {
		for _, root := range []chainhash.Hash{currentRoot, retainedRoot} {
			if _, found, err := dbFetchNameSnapshot(dbTx, root); err != nil {
				return err
			} else if !found {
				return fmt.Errorf("snapshot %v was pruned", root)
			}
		}

		if _, found, err := dbFetchNameSnapshot(dbTx, prunedRoot); err != nil {
			return err
		} else if found {
			return fmt.Errorf("snapshot %v was retained", prunedRoot)
		}

		return nil
	})
	if err != nil {
		t.Fatalf("db verify: %v", err)
	}
}

func TestNameRootCacheTracksViewChanges(t *testing.T) {
	chain, teardown, err := chainSetup("namerootcache",
		&chaincfg.RegressionNetParams)
	if err != nil {
		t.Fatalf("chainSetup: %v", err)
	}
	defer teardown()

	key := hashName([]byte("alpha"))
	ns := newNameState(key)
	ns.set([]byte("alpha"), 1)
	ns.data = []byte("old-resource")

	updated := ns.clone()
	updated.data = []byte("new-resource")
	updatedValue, err := updated.encode()
	if err != nil {
		t.Fatalf("updated encode: %v", err)
	}
	wantUpdatedRoot := calcUrkelRoot([]urkelLeaf{{
		key:   key,
		value: updatedValue,
	}})

	err = chain.db.Update(func(dbTx database.Tx) error {
		if err := dbPutNameState(dbTx, ns); err != nil {
			return err
		}

		cache, err := newNameRootCache(dbTx)
		if err != nil {
			return err
		}
		_, dbRoot, err := dbCalcNameTree(dbTx)
		if err != nil {
			return err
		}
		got, err := cache.root(dbTx)
		if err != nil {
			return err
		}
		if got != dbRoot {
			return fmt.Errorf("initial cached root = %v, want %v",
				got, dbRoot)
		}

		view := &nameBlockView{
			states: map[chainhash.Hash]*nameState{
				key: updated,
			},
			dirty: map[chainhash.Hash]struct{}{
				key: {},
			},
		}
		if err := cache.applyView(view); err != nil {
			return err
		}
		got, err = cache.root(dbTx)
		if err != nil {
			return err
		}
		if got != wantUpdatedRoot {
			return fmt.Errorf("updated cached root = %v, want %v",
				got, wantUpdatedRoot)
		}

		deleted := newNameState(key)
		if err := dbPutNameState(dbTx, deleted); err != nil {
			return err
		}
		deleteView := &nameBlockView{
			states: map[chainhash.Hash]*nameState{
				key: deleted,
			},
			dirty: map[chainhash.Hash]struct{}{
				key: {},
			},
		}
		if err := cache.applyView(deleteView); err != nil {
			return err
		}
		got, err = cache.root(dbTx)
		if err != nil {
			return err
		}
		if got != (chainhash.Hash{}) {
			return fmt.Errorf("deleted cached root = %v, want empty root",
				got)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("db update: %v", err)
	}
}

func TestFetchNameProofUnknownRootIsNotBlockNotFound(t *testing.T) {
	chain, teardown, err := chainSetup("nameproofunknown",
		&chaincfg.RegressionNetParams)
	if err != nil {
		t.Fatalf("chainSetup: %v", err)
	}
	defer teardown()

	root := chainhash.Hash{0xff}
	_, err = chain.FetchNameProof(root, chainhash.Hash{})
	if err == nil {
		t.Fatal("FetchNameProof: expected unknown root error")
	}
	if dbErr, ok := err.(database.Error); ok &&
		dbErr.ErrorCode == database.ErrBlockNotFound {

		t.Fatalf("FetchNameProof returned block-not-found error: %v", err)
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
