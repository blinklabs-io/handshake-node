// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ffldb

import (
	"errors"
	"fmt"
	"hash/crc32"
	"sort"

	"github.com/blinklabs-io/handshake-node/database"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

// prunePhysicalCleanupError marks failures to unlink block files or sync the
// block directory.  The metadata transaction is already durable in these
// cases, so startup may safely tolerate the error and retry later.  Metadata
// read, decode, and write failures are intentionally not wrapped in this type.
type prunePhysicalCleanupError struct {
	err error
}

func (e *prunePhysicalCleanupError) Error() string {
	return e.err.Error()
}

func (e *prunePhysicalCleanupError) Unwrap() error {
	return e.err
}

func isPrunePhysicalCleanupError(err error) bool {
	var physicalErr *prunePhysicalCleanupError
	return errors.As(err, &physicalErr)
}

const pruneStateVersion = 1

var (
	// pruneStateKey tracks block files whose metadata has been durably
	// removed, but whose files might not have been deleted yet.  Keeping the
	// deletion intent in the same atomic metadata commit as the block index
	// removals makes interrupted pruning safe to retry.
	pruneStateKey = bucketizedKey(metadataBucketID, []byte("ffldb-prune-state"))
	prunedKey     = bucketizedKey(metadataBucketID, []byte("ffldb-pruned"))
	prunedValue   = []byte{1}

	syncWriteOptions = &opt.WriteOptions{Sync: true}
)

// pruneStage identifies the durability boundaries in a pruning commit.  The
// callback on db is nil outside white-box tests.
type pruneStage string

const (
	pruneStageBlocksSynced      pruneStage = "blocks-synced"
	pruneStageMetadataCommitted pruneStage = "metadata-committed"
	pruneStageFileDeleted       pruneStage = "file-deleted"
	pruneStageDeletionsComplete pruneStage = "deletions-complete"
	pruneStageDirectorySynced   pruneStage = "directory-synced"
	pruneStageTombstoneCleared  pruneStage = "tombstone-cleared"
)

func (db *db) signalPruneStage(stage pruneStage) {
	if db.pruneFailpoint != nil {
		db.pruneFailpoint(stage)
	}
}

// serializePruneState serializes a sorted list of block file numbers together
// with a version, count, and checksum.
func serializePruneState(fileNums []uint32) []byte {
	serialized := make([]byte, 12+len(fileNums)*4)
	byteOrder.PutUint32(serialized[0:4], pruneStateVersion)
	byteOrder.PutUint32(serialized[4:8], uint32(len(fileNums)))
	for i, fileNum := range fileNums {
		byteOrder.PutUint32(serialized[8+i*4:12+i*4], fileNum)
	}

	checksumOffset := len(serialized) - 4
	checksum := crc32.Checksum(serialized[:checksumOffset], castagnoli)
	byteOrder.PutUint32(serialized[checksumOffset:], checksum)
	return serialized
}

// deserializePruneState deserializes and validates a pending prune record.
func deserializePruneState(serialized []byte) ([]uint32, error) {
	if len(serialized) < 12 {
		str := fmt.Sprintf("pending prune record has invalid length %d", len(serialized))
		return nil, makeDbErr(database.ErrCorruption, str, nil)
	}

	version := byteOrder.Uint32(serialized[0:4])
	if version != pruneStateVersion {
		str := fmt.Sprintf("pending prune record has unsupported version %d", version)
		return nil, makeDbErr(database.ErrCorruption, str, nil)
	}

	count := uint64(byteOrder.Uint32(serialized[4:8]))
	if count == 0 {
		str := "pending prune record contains no files"
		return nil, makeDbErr(database.ErrCorruption, str, nil)
	}
	wantLen := uint64(12) + count*4
	if wantLen != uint64(len(serialized)) {
		str := fmt.Sprintf("pending prune record has invalid length %d for %d files",
			len(serialized), count)
		return nil, makeDbErr(database.ErrCorruption, str, nil)
	}

	checksumOffset := len(serialized) - 4
	gotChecksum := crc32.Checksum(serialized[:checksumOffset], castagnoli)
	wantChecksum := byteOrder.Uint32(serialized[checksumOffset:])
	if gotChecksum != wantChecksum {
		str := fmt.Sprintf("pending prune record checksum mismatch - got %d, want %d",
			gotChecksum, wantChecksum)
		return nil, makeDbErr(database.ErrCorruption, str, nil)
	}

	fileNums := make([]uint32, int(count))
	for i := range fileNums {
		fileNums[i] = byteOrder.Uint32(serialized[8+i*4 : 12+i*4])
		if i > 0 && fileNums[i] <= fileNums[i-1] {
			str := "pending prune record file numbers are not strictly increasing"
			return nil, makeDbErr(database.ErrCorruption, str, nil)
		}
	}
	return fileNums, nil
}

// mergePruneFileNums returns a sorted, de-duplicated union of the existing
// durable deletion intent and the files selected by the current transaction.
func mergePruneFileNums(existing []uint32, pending []uint32) []uint32 {
	merged := make([]uint32, 0, len(existing)+len(pending))
	merged = append(merged, existing...)
	merged = append(merged, pending...)
	sort.Slice(merged, func(i, j int) bool {
		return merged[i] < merged[j]
	})

	result := merged[:0]
	for _, fileNum := range merged {
		if len(result) == 0 || result[len(result)-1] != fileNum {
			result = append(result, fileNum)
		}
	}
	return result
}

// pendingPruneFileNums returns the durable pending prune state, if any.
func (db *db) pendingPruneFileNums() ([]uint32, error) {
	serialized, err := db.cache.ldb.Get(pruneStateKey, nil)
	if err == leveldb.ErrNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, convertErr("failed to load pending prune record", err)
	}
	return deserializePruneState(serialized)
}

// finishPendingPruneLocked deletes files whose metadata has already been
// durably removed.  The caller must hold pruneLock for writing.  The durable
// record is only cleared after every deletion and the directory sync succeed.
// Missing files are treated as already deleted, which makes recovery
// idempotent after a crash during the deletion loop.
func (db *db) finishPendingPruneLocked() error {
	fileNums, err := db.pendingPruneFileNums()
	if err != nil || len(fileNums) == 0 {
		return err
	}

	for _, fileNum := range fileNums {
		db.store.closeFile(fileNum)
		if err := db.store.deleteFileFunc(fileNum); err != nil {
			return &prunePhysicalCleanupError{err: fmt.Errorf(
				"failed to delete pruned block file %d: %w", fileNum, err,
			)}
		}
		db.signalPruneStage(pruneStageFileDeleted)
	}
	db.signalPruneStage(pruneStageDeletionsComplete)
	if err := db.store.syncDirFunc(); err != nil {
		return &prunePhysicalCleanupError{err: err}
	}
	db.signalPruneStage(pruneStageDirectorySynced)

	if err := db.cache.ldb.Delete(pruneStateKey, syncWriteOptions); err != nil {
		return convertErr("failed to clear pending prune record", err)
	}
	db.signalPruneStage(pruneStageTombstoneCleared)
	return nil
}

// finishPendingPrune waits for all older read snapshots and completes pending
// physical cleanup.  It is used during startup, before the database is exposed
// to callers.
func (db *db) finishPendingPrune() error {
	db.pruneLock.Lock()
	defer db.pruneLock.Unlock()
	return db.finishPendingPruneLocked()
}

// tryFinishPendingPrune attempts cleanup without waiting for older readers.
// A pruning commit must not block on a read transaction which might be owned
// by the same caller.  When readers are active, the durable marker is retained
// and cleanup is retried by a later prune or on the next open.
func (db *db) tryFinishPendingPrune() error {
	if !db.pruneLock.TryLock() {
		return nil
	}
	defer db.pruneLock.Unlock()
	return db.finishPendingPruneLocked()
}
