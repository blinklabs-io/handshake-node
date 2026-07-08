// Copyright (c) 2024-2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"bytes"
	"fmt"
	"io"

	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/database"
	"github.com/blinklabs-io/handshake-node/wire"
)

const latestNameStateBucketVersion = 2

var (
	nameStateVersionKeyName = []byte("namestateversion")
	nameStateBucketName     = []byte("namestatev1")
	nameUndoBucketName      = []byte("nameundov1")
	nameSnapshotBucketName  = []byte("namesnapshotv1")
	nameRootKeyName         = []byte("nameroot")
)

const (
	maxNameSnapshotLeaves  = 1 << 24
	maxSerializedNameState = 2048
)

type nameUndoEntry struct {
	nameHash chainhash.Hash
	existed  bool
	state    *nameState
}

type nameRootCache struct {
	rootNode  urkelNode
	rootDirty bool
}

func newNameRootCache(dbTx database.Tx) (*nameRootCache, error) {
	leaves, err := dbFetchNameLeaves(dbTx)
	if err != nil {
		return nil, err
	}

	cache := &nameRootCache{}
	cache.rootNode = buildUrkelRootTree(leaves)
	return cache, nil
}

func (c *nameRootCache) applyView(view *nameBlockView) error {
	for nameHash := range view.dirty {
		ns := view.states[nameHash]
		if ns == nil || ns.isNull() {
			c.rootDirty = true
			continue
		}

		serialized, err := ns.encode()
		if err != nil {
			return err
		}
		c.put(nameHash, serialized)
	}
	return nil
}

func (c *nameRootCache) applyUndo(entries []nameUndoEntry) error {
	for _, entry := range entries {
		if !entry.existed {
			c.rootDirty = true
			continue
		}

		serialized, err := entry.state.encode()
		if err != nil {
			return err
		}
		c.put(entry.nameHash, serialized)
	}
	return nil
}

func (c *nameRootCache) put(nameHash chainhash.Hash, serialized []byte) {
	if c.rootDirty {
		return
	}
	c.rootNode = insertUrkelRoot(c.rootNode, nameHash, serialized, 0)
}

func (c *nameRootCache) rebuildRoot(dbTx database.Tx) error {
	leaves, err := dbFetchNameLeaves(dbTx)
	if err != nil {
		return err
	}
	c.rootNode = buildUrkelRootTree(leaves)
	c.rootDirty = false
	return nil
}

func (c *nameRootCache) root(dbTx database.Tx) (chainhash.Hash, error) {
	if c.rootDirty {
		if dbTx == nil {
			return chainhash.Hash{}, AssertError("dirty name root cache " +
				"requires a database transaction")
		}
		if err := c.rebuildRoot(dbTx); err != nil {
			return chainhash.Hash{}, err
		}
	}
	if c.rootNode == nil {
		return chainhash.Hash{}, nil
	}
	return c.rootNode.hash(), nil
}

func dbFetchNameRoot(dbTx database.Tx) (chainhash.Hash, error) {
	rootBytes := dbTx.Metadata().Get(nameRootKeyName)
	if rootBytes == nil {
		return chainhash.Hash{}, nil
	}
	if len(rootBytes) != chainhash.HashSize {
		return chainhash.Hash{}, database.Error{
			ErrorCode:   database.ErrCorruption,
			Description: "corrupt name root",
		}
	}

	var root chainhash.Hash
	copy(root[:], rootBytes)
	return root, nil
}

// NameRoot returns the currently committed Urkel name tree root.
func (b *BlockChain) NameRoot() (chainhash.Hash, error) {
	var root chainhash.Hash
	err := b.db.View(func(dbTx database.Tx) error {
		var err error
		root, err = dbFetchNameRoot(dbTx)
		return err
	})
	return root, err
}

func dbPutNameRoot(dbTx database.Tx, root chainhash.Hash) error {
	return dbTx.Metadata().Put(nameRootKeyName, root[:])
}

func dbFetchAllNameStates(dbTx database.Tx) (map[chainhash.Hash]*nameState, error) {
	states := make(map[chainhash.Hash]*nameState)
	bucket := dbTx.Metadata().Bucket(nameStateBucketName)
	if bucket == nil {
		return states, nil
	}

	err := bucket.ForEach(func(k, v []byte) error {
		if len(k) != chainhash.HashSize {
			return database.Error{
				ErrorCode: database.ErrCorruption,
				Description: fmt.Sprintf("corrupt name state key "+
					"length %d", len(k)),
			}
		}

		var nameHash chainhash.Hash
		copy(nameHash[:], k)
		ns, err := decodeNameState(nameHash, v)
		if err != nil {
			return err
		}
		states[nameHash] = ns
		return nil
	})
	if err != nil {
		return nil, err
	}

	return states, nil
}

func dbFetchNameState(dbTx database.Tx, nameHash chainhash.Hash) (
	*nameState, bool, error) {

	bucket := dbTx.Metadata().Bucket(nameStateBucketName)
	if bucket == nil {
		return nil, false, nil
	}

	serialized := bucket.Get(nameHash[:])
	if serialized == nil {
		return nil, false, nil
	}

	ns, err := decodeNameState(nameHash, serialized)
	if err != nil {
		return nil, false, err
	}
	return ns, true, nil
}

func dbPutNameState(dbTx database.Tx, ns *nameState) error {
	bucket := dbTx.Metadata().Bucket(nameStateBucketName)
	if bucket == nil {
		return database.Error{
			ErrorCode:   database.ErrBucketNotFound,
			Description: "name state bucket missing",
		}
	}

	if ns.isNull() {
		return bucket.Delete(ns.nameHash[:])
	}

	serialized, err := ns.encode()
	if err != nil {
		return err
	}
	return bucket.Put(ns.nameHash[:], serialized)
}

func dbFetchNameLeaves(dbTx database.Tx) ([]urkelLeaf, error) {
	bucket := dbTx.Metadata().Bucket(nameStateBucketName)
	if bucket == nil {
		return nil, nil
	}

	leaves := make([]urkelLeaf, 0)
	err := bucket.ForEach(func(k, v []byte) error {
		if len(k) != chainhash.HashSize {
			return database.Error{
				ErrorCode: database.ErrCorruption,
				Description: fmt.Sprintf("corrupt name state key "+
					"length %d", len(k)),
			}
		}

		var leaf urkelLeaf
		copy(leaf.key[:], k)
		leaf.value = append([]byte(nil), v...)
		leaves = append(leaves, leaf)
		return nil
	})
	if err != nil {
		return nil, err
	}

	return leaves, nil
}

func dbSerializeNameLeaves(leaves []urkelLeaf) ([]byte, error) {
	var buf bytes.Buffer
	if err := wire.WriteVarInt(&buf, 0, uint64(len(leaves))); err != nil {
		return nil, err
	}

	for _, leaf := range leaves {
		buf.Write(leaf.key[:])
		if err := wire.WriteVarBytes(&buf, 0, leaf.value); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

func dbDeserializeNameLeaves(serialized []byte) ([]urkelLeaf, error) {
	r := bytes.NewReader(serialized)
	count, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return nil, err
	}
	if count > maxNameSnapshotLeaves {
		return nil, errDeserialize("too many name snapshot leaves")
	}

	leaves := make([]urkelLeaf, 0, int(count))
	for i := uint64(0); i < count; i++ {
		var leaf urkelLeaf
		if _, err := io.ReadFull(r, leaf.key[:]); err != nil {
			return nil, err
		}
		leaf.value, err = wire.ReadVarBytes(r, 0,
			maxSerializedNameState, "name state")
		if err != nil {
			return nil, err
		}
		leaves = append(leaves, leaf)
	}

	if r.Len() != 0 {
		return nil, errDeserialize("trailing bytes in name snapshot")
	}

	return leaves, nil
}

func dbPutNameSnapshot(dbTx database.Tx, root chainhash.Hash,
	leaves []urkelLeaf) error {

	bucket := dbTx.Metadata().Bucket(nameSnapshotBucketName)
	if bucket == nil {
		return database.Error{
			ErrorCode:   database.ErrBucketNotFound,
			Description: "name snapshot bucket missing",
		}
	}

	serialized, err := dbSerializeNameLeaves(leaves)
	if err != nil {
		return err
	}
	return bucket.Put(root[:], serialized)
}

func dbFetchNameSnapshot(dbTx database.Tx, root chainhash.Hash) (
	[]urkelLeaf, bool, error) {

	bucket := dbTx.Metadata().Bucket(nameSnapshotBucketName)
	if bucket == nil {
		return nil, false, nil
	}

	serialized := bucket.Get(root[:])
	if serialized == nil {
		return nil, false, nil
	}

	leaves, err := dbDeserializeNameLeaves(serialized)
	if err != nil {
		return nil, false, err
	}
	return leaves, true, nil
}

func dbSerializeNameUndo(entries []nameUndoEntry) ([]byte, error) {
	var buf bytes.Buffer
	if err := wire.WriteVarInt(&buf, 0, uint64(len(entries))); err != nil {
		return nil, err
	}

	for _, entry := range entries {
		buf.Write(entry.nameHash[:])
		if entry.existed {
			buf.WriteByte(1)
			serialized, err := entry.state.encode()
			if err != nil {
				return nil, err
			}
			if err := wire.WriteVarBytes(&buf, 0, serialized); err != nil {
				return nil, err
			}
		} else {
			buf.WriteByte(0)
		}
	}

	return buf.Bytes(), nil
}

func dbDeserializeNameUndo(serialized []byte) ([]nameUndoEntry, error) {
	r := bytes.NewReader(serialized)
	count, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return nil, err
	}
	if count > maxBlockNameUpdates+maxBlockNameRenewals+maxBlockNameOpens {
		return nil, errDeserialize("too many name undo entries")
	}

	entries := make([]nameUndoEntry, 0, count)
	for i := uint64(0); i < count; i++ {
		var entry nameUndoEntry
		if _, err := io.ReadFull(r, entry.nameHash[:]); err != nil {
			return nil, err
		}

		existed, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		switch existed {
		case 0:
			entry.existed = false
		case 1:
			entry.existed = true
			stateBytes, err := wire.ReadVarBytes(r, 0,
				maxSerializedNameState, "name undo state")
			if err != nil {
				return nil, err
			}
			entry.state, err = decodeNameState(entry.nameHash, stateBytes)
			if err != nil {
				return nil, err
			}
		default:
			return nil, errDeserialize("corrupt name undo entry")
		}
		entries = append(entries, entry)
	}

	if r.Len() != 0 {
		return nil, errDeserialize("trailing bytes in name undo")
	}

	return entries, nil
}

func dbPutNameUndo(dbTx database.Tx, blockHash *chainhash.Hash,
	entries []nameUndoEntry) error {

	bucket := dbTx.Metadata().Bucket(nameUndoBucketName)
	if bucket == nil {
		return database.Error{
			ErrorCode:   database.ErrBucketNotFound,
			Description: "name undo bucket missing",
		}
	}

	if len(entries) == 0 {
		return bucket.Delete(blockHash[:])
	}

	serialized, err := dbSerializeNameUndo(entries)
	if err != nil {
		return err
	}
	return bucket.Put(blockHash[:], serialized)
}

func dbFetchNameUndo(dbTx database.Tx, blockHash *chainhash.Hash) (
	[]nameUndoEntry, error) {

	bucket := dbTx.Metadata().Bucket(nameUndoBucketName)
	if bucket == nil {
		return nil, database.Error{
			ErrorCode:   database.ErrBucketNotFound,
			Description: "name undo bucket missing",
		}
	}

	serialized := bucket.Get(blockHash[:])
	if serialized == nil {
		return nil, nil
	}

	return dbDeserializeNameUndo(serialized)
}

func dbRemoveNameUndo(dbTx database.Tx, blockHash *chainhash.Hash) error {
	bucket := dbTx.Metadata().Bucket(nameUndoBucketName)
	if bucket == nil {
		return nil
	}
	return bucket.Delete(blockHash[:])
}

func dbCalcNameTree(dbTx database.Tx) ([]urkelLeaf, chainhash.Hash, error) {
	leaves, err := dbFetchNameLeaves(dbTx)
	if err != nil {
		return nil, chainhash.Hash{}, err
	}
	return leaves, calcUrkelRoot(leaves), nil
}

func dbStoreCurrentNameRoot(dbTx database.Tx) (chainhash.Hash, error) {
	_, root, err := dbCalcNameTree(dbTx)
	if err != nil {
		return chainhash.Hash{}, err
	}
	if err := dbPutNameRoot(dbTx, root); err != nil {
		return chainhash.Hash{}, err
	}
	return root, nil
}

func dbBuildNameProof(dbTx database.Tx, root, key chainhash.Hash) (
	[]byte, error) {

	leaves, found, err := dbFetchNameSnapshot(dbTx, root)
	if err != nil {
		return nil, err
	}
	if !found {
		committedRoot, err := dbFetchNameRoot(dbTx)
		if err != nil {
			return nil, err
		}
		if committedRoot != root {
			return nil, fmt.Errorf("name root snapshot %v not found",
				root)
		}

		currentLeaves, currentRoot, err := dbCalcNameTree(dbTx)
		if err != nil {
			return nil, err
		}
		if currentRoot != root {
			return nil, database.Error{
				ErrorCode: database.ErrCorruption,
				Description: fmt.Sprintf("name root snapshot "+
					"%v not found", root),
			}
		}
		leaves = currentLeaves
	}

	tree := buildUrkelTree(leaves)
	treeRoot := chainhash.Hash{}
	if tree != nil {
		treeRoot = tree.hash()
	}
	if treeRoot != root {
		return nil, database.Error{
			ErrorCode: database.ErrCorruption,
			Description: fmt.Sprintf("name snapshot root mismatch: "+
				"got %v, want %v", treeRoot, root),
		}
	}

	proof := proveUrkel(tree, key)
	return proof.Encode()
}

// FetchNameState returns a read-only snapshot of the current state for the
// provided raw name.  Invalid names are rejected before lookup.  Missing names
// return found=false and a nil error.
func (b *BlockChain) FetchNameState(name []byte) (*NameState, bool, error) {
	if !verifyName(name) {
		return nil, false, fmt.Errorf("invalid Handshake name %q", name)
	}

	return b.FetchNameStateByHash(hashName(name))
}

// FetchNameStateByHash returns a read-only snapshot of the current state for
// the provided name hash.  Missing names return found=false and a nil error.
func (b *BlockChain) FetchNameStateByHash(nameHash chainhash.Hash) (
	*NameState, bool, error) {

	var state *NameState
	var found bool
	err := b.db.View(func(dbTx database.Tx) error {
		ns, ok, err := dbFetchNameState(dbTx, nameHash)
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		state = newNameStateView(ns)
		found = true
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	return state, found, nil
}

// FetchNameProof returns an hsd-compatible Urkel proof for the provided name
// tree root and key.
func (b *BlockChain) FetchNameProof(root, key chainhash.Hash) ([]byte, error) {
	var proof []byte
	err := b.db.View(func(dbTx database.Tx) error {
		var err error
		proof, err = dbBuildNameProof(dbTx, root, key)
		return err
	})
	if err != nil {
		return nil, err
	}
	return proof, nil
}
