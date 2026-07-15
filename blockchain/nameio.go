// Copyright (c) 2024-2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"bytes"
	"fmt"
	"io"
	"sort"

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

func dbPruneNameSnapshots(dbTx database.Tx,
	retain map[chainhash.Hash]struct{}) (int, error) {

	bucket := dbTx.Metadata().Bucket(nameSnapshotBucketName)
	if bucket == nil {
		return 0, nil
	}

	var keys [][]byte
	err := bucket.ForEach(func(k, v []byte) error {
		if len(k) != chainhash.HashSize {
			return database.Error{
				ErrorCode: database.ErrCorruption,
				Description: fmt.Sprintf("corrupt name snapshot key "+
					"length %d", len(k)),
			}
		}

		var root chainhash.Hash
		copy(root[:], k)
		if _, ok := retain[root]; ok {
			return nil
		}

		keys = append(keys, append([]byte(nil), k...))
		return nil
	})
	if err != nil {
		return 0, err
	}

	for _, key := range keys {
		if err := bucket.Delete(key); err != nil {
			return 0, err
		}
	}

	return len(keys), nil
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

func dbBuildNameProofTree(dbTx database.Tx, root chainhash.Hash,
	rollbackHashes []chainhash.Hash) (urkelNode, error) {

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

		leaves, err = dbFetchNameLeaves(dbTx)
		if err != nil {
			return nil, err
		}

		leavesByKey := make(map[chainhash.Hash][]byte, len(leaves))
		for _, leaf := range leaves {
			leavesByKey[leaf.key] = leaf.value
		}

		// The committed name root only advances at tree intervals, while the
		// live name-state bucket advances after every block. Rewind the live
		// leaves through the per-block undo journal to reconstruct the exact
		// state committed by the current root.
		for _, blockHash := range rollbackHashes {
			entries, err := dbFetchNameUndo(dbTx, &blockHash)
			if err != nil {
				return nil, err
			}
			for _, entry := range entries {
				if !entry.existed {
					delete(leavesByKey, entry.nameHash)
					continue
				}

				serialized, err := entry.state.encode()
				if err != nil {
					return nil, err
				}
				leavesByKey[entry.nameHash] = serialized
			}
		}

		leaves = make([]urkelLeaf, 0, len(leavesByKey))
		for key, value := range leavesByKey {
			leaves = append(leaves, urkelLeaf{key: key, value: value})
		}
	}

	tree := buildUrkelTree(leaves)
	treeRoot := chainhash.Hash{}
	if tree != nil {
		treeRoot = tree.hash()
	}
	if treeRoot != root {
		return nil, database.Error{
			ErrorCode: database.ErrCorruption,
			Description: fmt.Sprintf("committed name root mismatch: "+
				"got %v, want %v", treeRoot, root),
		}
	}

	return tree, nil
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

// FetchNamesInAuction returns all persisted names that are currently in the
// OPEN, BID, or REVEAL auction phases at the provided height.
func (b *BlockChain) FetchNamesInAuction(height uint32) ([]*NameState, error) {
	var states []*NameState
	err := b.db.View(func(dbTx database.Tx) error {
		allStates, err := dbFetchAllNameStates(dbTx)
		if err != nil {
			return err
		}

		for _, ns := range allStates {
			if ns.inAuction(height, b.chainParams) {
				states = append(states, newNameStateView(ns))
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	sortNameStateViews(states)
	return states, nil
}

// FetchExpiringNameStates returns all persisted names that are not expired at
// height but would expire within the provided block window.
func (b *BlockChain) FetchExpiringNameStates(height, within uint32) (
	[]*NameState, error) {

	var states []*NameState
	err := b.db.View(func(dbTx database.Tx) error {
		allStates, err := dbFetchAllNameStates(dbTx)
		if err != nil {
			return err
		}

		for _, ns := range allStates {
			if ns.expiresBy(height, within, b.chainParams) {
				states = append(states, newNameStateView(ns))
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	sortNameStateViews(states)
	return states, nil
}

// FetchAllNameStates returns read-only snapshots for all currently persisted
// Handshake name states.  Results are sorted by name hash for deterministic
// RPC responses.
func (b *BlockChain) FetchAllNameStates() ([]*NameState, error) {
	var states []*NameState
	err := b.db.View(func(dbTx database.Tx) error {
		allStates, err := dbFetchAllNameStates(dbTx)
		if err != nil {
			return err
		}
		states = make([]*NameState, 0, len(allStates))
		for _, ns := range allStates {
			states = append(states, newNameStateView(ns))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	sortNameStateViews(states)
	return states, nil
}

func sortNameStateViews(states []*NameState) {
	sort.Slice(states, func(i, j int) bool {
		left := states[i].NameHash()
		right := states[j].NameHash()
		return bytes.Compare(left[:], right[:]) < 0
	})
}

// FetchNameProof returns an hsd-compatible Urkel proof for the provided name
// tree root and key.
func (b *BlockChain) FetchNameProof(root, key chainhash.Hash) ([]byte, error) {
	tree, err := b.fetchNameProofTree(root)
	if err != nil {
		return nil, err
	}

	proof := proveUrkel(tree, key)
	return proof.Encode()
}

func (b *BlockChain) fetchNameProofTree(root chainhash.Hash) (urkelNode, error) {
	b.nameProofCacheMtx.Lock()
	defer b.nameProofCacheMtx.Unlock()

	if b.nameProofCacheValid && b.nameProofCacheRoot == root {
		return b.nameProofCacheTree, nil
	}

	// Keep the active-chain tip and its name undo journal stable only while
	// reconstructing a cache miss. Cache waiters must not retain a chain read
	// lock because doing so could delay block connection and reorganization.
	b.chainLock.RLock()
	defer b.chainLock.RUnlock()

	rollbackHashes := b.nameProofRollbackHashes()
	var tree urkelNode
	err := b.db.View(func(dbTx database.Tx) error {
		var err error
		tree, err = dbBuildNameProofTree(dbTx, root, rollbackHashes)
		return err
	})
	if err != nil {
		return nil, err
	}

	b.nameProofCacheRoot = root
	b.nameProofCacheTree = tree
	b.nameProofCacheValid = true
	return tree, nil
}

// nameProofRollbackHashes returns active-chain block hashes after the latest
// name-tree commitment, ordered newest to oldest for undo application. The
// caller must hold at least a read lock on chainLock.
func (b *BlockChain) nameProofRollbackHashes() []chainhash.Hash {
	interval := int32(b.chainParams.NameTreeInterval)
	if interval <= 0 {
		return nil
	}

	tip := b.bestChain.Tip()
	commitHeight := tip.height - tip.height%interval
	hashes := make([]chainhash.Hash, 0, tip.height-commitHeight)
	for node := tip; node != nil && node.height > commitHeight; node = node.parent {
		hashes = append(hashes, node.hash)
	}
	return hashes
}

// VerifyName verifies an hsd-compatible Urkel proof for the provided raw name
// at the provided tree root.  It returns the immutable name state and decoded
// proof for inclusion proofs, or nil state plus a valid exclusion proof when
// the name is absent at that root.
func (b *BlockChain) VerifyName(name []byte, root chainhash.Hash) (
	*NameState, *UrkelProof, error) {

	if !verifyName(name) {
		return nil, nil, fmt.Errorf("invalid Handshake name %q", name)
	}

	key := hashName(name)
	serialized, err := b.FetchNameProof(root, key)
	if err != nil {
		return nil, nil, err
	}

	proof, err := DecodeUrkelProof(serialized)
	if err != nil {
		return nil, nil, err
	}
	value, exists, err := proof.Verify(root, key)
	if err != nil {
		return nil, nil, err
	}
	if !exists {
		return nil, proof, nil
	}

	ns, err := decodeNameState(key, value)
	if err != nil {
		return nil, nil, err
	}
	return newNameStateView(ns), proof, nil
}

// PruneNameSnapshots deletes historical Urkel proof snapshots except for the
// current committed name root and any roots explicitly retained by the caller.
//
// The current Urkel implementation stores the live tree as compact name-state
// leaves, so there are no internal tree nodes to garbage collect.  This helper
// bounds optional historical proof snapshots without touching current name
// state, name undo data, or the committed root.
func (b *BlockChain) PruneNameSnapshots(retainRoots ...chainhash.Hash) (
	int, error) {

	var pruned int
	err := b.db.Update(func(dbTx database.Tx) error {
		currentRoot, err := dbFetchNameRoot(dbTx)
		if err != nil {
			return err
		}

		retain := make(map[chainhash.Hash]struct{},
			len(retainRoots)+1)
		retain[currentRoot] = struct{}{}
		for _, root := range retainRoots {
			retain[root] = struct{}{}
		}

		pruned, err = dbPruneNameSnapshots(dbTx, retain)
		return err
	})
	if err != nil {
		return 0, err
	}
	return pruned, nil
}
