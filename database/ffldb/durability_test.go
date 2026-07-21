// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ffldb

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blinklabs-io/handshake-node/database"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

type rollbackFailureFile struct {
	*mockFile
	writeErr    error
	closeErr    error
	truncateErr error
	syncErr     error
}

func (f *rollbackFailureFile) WriteAt(data []byte, offset int64) (int, error) {
	if f.writeErr != nil {
		return 1, f.writeErr
	}
	return f.mockFile.WriteAt(data, offset)
}

func (f *rollbackFailureFile) Close() error {
	if f.closeErr != nil {
		return f.closeErr
	}
	return f.mockFile.Close()
}

func (f *rollbackFailureFile) Truncate(size int64) error {
	if f.truncateErr != nil {
		return f.truncateErr
	}
	return f.mockFile.Truncate(size)
}

func (f *rollbackFailureFile) Sync() error {
	if f.syncErr != nil {
		return f.syncErr
	}
	return f.mockFile.Sync()
}

func TestReconcileDBReturnsRollbackFailures(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*blockStore, error)
	}{
		{
			name: "delete",
			setup: func(store *blockStore, injectedErr error) {
				store.writeCursor.curFileNum = 1
				store.deleteFileFunc = func(uint32) error {
					return injectedErr
				}
			},
		},
		{
			name: "close",
			setup: func(store *blockStore, injectedErr error) {
				store.writeCursor.curFileNum = 1
				store.writeCursor.curFile.file = &rollbackFailureFile{
					mockFile: &mockFile{maxSize: -1},
					closeErr: injectedErr,
				}
			},
		},
		{
			name: "open",
			setup: func(store *blockStore, injectedErr error) {
				store.writeCursor.curOffset = 1
				store.openWriteFileFunc = func(uint32) (filer, error) {
					return nil, injectedErr
				}
			},
		},
		{
			name: "truncate",
			setup: func(store *blockStore, injectedErr error) {
				store.writeCursor.curOffset = 1
				store.writeCursor.curFile.file = &rollbackFailureFile{
					mockFile:    &mockFile{data: []byte{0}, maxSize: -1},
					truncateErr: injectedErr,
				}
			},
		},
		{
			name: "sync",
			setup: func(store *blockStore, injectedErr error) {
				store.writeCursor.curOffset = 1
				store.writeCursor.curFile.file = &rollbackFailureFile{
					mockFile: &mockFile{data: []byte{0}, maxSize: -1},
					syncErr:  injectedErr,
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "ffldb")
			idb, err := openDB(dbPath, blockDataNet, true)
			if err != nil {
				t.Fatalf("create database: %v", err)
			}
			pdb := idb.(*db)
			store := pdb.store
			originalOpen := store.openWriteFileFunc
			originalDelete := store.deleteFileFunc
			injectedErr := errors.New("injected rollback failure")
			test.setup(store, injectedErr)

			reconciled, err := reconcileDB(pdb, false)
			if !errors.Is(err, injectedErr) {
				t.Fatalf("reconcile error = %v, want %v", err, injectedErr)
			}
			if reconciled != nil {
				t.Fatal("reconcile returned a database after rollback failure")
			}

			// Restore the empty database's real block store before closing it.
			store.openWriteFileFunc = originalOpen
			store.deleteFileFunc = originalDelete
			wc := store.writeCursor
			wc.Lock()
			wc.curFile.Lock()
			wc.curFile.file = nil
			wc.curFile.Unlock()
			wc.curFileNum = 0
			wc.curOffset = 0
			wc.Unlock()
			if err := idb.Close(); err != nil {
				t.Fatalf("close database: %v", err)
			}
		})
	}
}

func TestRollbackCloseFailureStopsPhysicalCleanup(t *testing.T) {
	injectedErr := errors.New("injected rollback close failure")
	file := &rollbackFailureFile{
		mockFile: &mockFile{maxSize: -1},
		closeErr: injectedErr,
	}
	var deleteCalls, openCalls int
	store := &blockStore{
		writeCursor: &writeCursor{
			curFile:    &lockableFile{file: file},
			curFileNum: 1,
			curOffset:  42,
		},
		deleteFileFunc: func(uint32) error {
			deleteCalls++
			return nil
		},
		openWriteFileFunc: func(uint32) (filer, error) {
			openCalls++
			return &mockFile{maxSize: -1}, nil
		},
	}

	err := store.handleRollback(0, 0)
	if !errors.Is(err, injectedErr) {
		t.Fatalf("rollback error = %v, want %v", err, injectedErr)
	}
	if _, ok := err.(database.Error); !ok {
		t.Fatalf("rollback error type = %T, want database.Error", err)
	}
	if store.writeCursor.curFileNum != 0 || store.writeCursor.curOffset != 0 {
		t.Fatalf("rollback cursor = (%d, %d), want (0, 0)",
			store.writeCursor.curFileNum, store.writeCursor.curOffset)
	}
	if store.writeCursor.curFile.file != nil {
		t.Fatal("rollback retained an unusable current file handle")
	}
	if deleteCalls != 0 || openCalls != 0 {
		t.Fatalf("rollback continued after close failure: deletes=%d opens=%d",
			deleteCalls, openCalls)
	}
}

func TestRuntimeRollbackFailureRequiresReopen(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "ffldb")
	idb, err := openDB(dbPath, blockDataNet, true)
	if err != nil {
		t.Fatalf("create database: %v", err)
	}
	pdb := idb.(*db)
	store := pdb.store
	wc := store.writeCursor
	writeErr := errors.New("injected block write failure")
	rollbackErr := errors.New("injected rollback failure")
	wc.curFile.file = &rollbackFailureFile{
		mockFile:    &mockFile{maxSize: -1},
		writeErr:    writeErr,
		truncateErr: rollbackErr,
	}

	err = idb.Update(func(tx database.Tx) error {
		return tx.StoreBlock(TstHandshakeBlocks(t)[0])
	})
	if !errors.Is(err, writeErr) {
		t.Fatalf("update error = %v, want %v", err, writeErr)
	}
	if !errors.Is(err, rollbackErr) {
		t.Fatalf("update error = %v, want rollback cause %v", err, rollbackErr)
	}
	if _, ok := err.(database.Error); !ok {
		t.Fatalf("update error type = %T, want database.Error", err)
	}
	if !pdb.recoveryRequired.Load() {
		t.Fatal("database did not require reopen after rollback failure")
	}
	if err := idb.View(func(database.Tx) error { return nil }); err == nil {
		t.Fatal("database accepted a transaction after rollback failure")
	}

	// Remove the injected file so Close can finish its own durability work.
	wc.Lock()
	wc.curFile.Lock()
	wc.curFile.file = nil
	wc.curFile.Unlock()
	wc.curFileNum = 0
	wc.curOffset = 0
	wc.Unlock()
	if err := idb.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}
}

type recordingBatchWriter struct {
	writes  int
	batch   *leveldb.Batch
	options *opt.WriteOptions
	err     error
}

func (w *recordingBatchWriter) Write(batch *leveldb.Batch,
	options *opt.WriteOptions) error {

	w.writes++
	w.batch = batch
	w.options = options
	return w.err
}

func TestInitializationMetadataWriteIsDurable(t *testing.T) {
	writer := new(recordingBatchWriter)
	err := initDBWithWriter(writer)
	if err != nil {
		t.Fatalf("initialize metadata: %v", err)
	}
	if writer.writes != 1 {
		t.Fatalf("initialization metadata writes = %d, want 1", writer.writes)
	}
	if writer.batch == nil {
		t.Fatal("initialization writer received a nil batch")
	}
	if writer.batch.Len() != 3 {
		t.Fatalf("initialization batch entries = %d, want 3",
			writer.batch.Len())
	}
	if writer.options == nil || !writer.options.Sync {
		t.Fatalf("initialization write options = %#v, want Sync=true",
			writer.options)
	}

	injectedErr := errors.New("injected initialization write failure")
	writer = &recordingBatchWriter{err: injectedErr}
	err = initDBWithWriter(writer)
	if !errors.Is(err, injectedErr) {
		t.Fatalf("initialization error = %v, want %v", err, injectedErr)
	}
	if _, ok := err.(database.Error); !ok {
		t.Fatalf("initialization error type = %T, want database.Error", err)
	}
}

func TestCloseUsesNormalDurableMetadataWriter(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "ffldb")
	idb, err := openDB(dbPath, blockDataNet, true)
	if err != nil {
		t.Fatalf("create database: %v", err)
	}
	pdb := idb.(*db)
	if err := idb.Update(func(tx database.Tx) error {
		return tx.Metadata().Put([]byte("durable"), []byte("value"))
	}); err != nil {
		_ = idb.Close()
		t.Fatalf("cache metadata: %v", err)
	}

	originalWrite := pdb.cache.writeBatchFunc
	var normalWrites, pruningWrites int
	pdb.cache.writeBatchFunc = func(batch *leveldb.Batch) error {
		normalWrites++
		return originalWrite(batch)
	}
	pdb.cache.writeBatchSyncFunc = func(*leveldb.Batch) error {
		pruningWrites++
		return errors.New("pruning metadata writer used during close")
	}

	if err := idb.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}
	if normalWrites != 1 {
		t.Fatalf("normal durable metadata writes = %d, want 1", normalWrites)
	}
	if pruningWrites != 0 {
		t.Fatalf("pruning metadata writes = %d, want 0", pruningWrites)
	}

	reopened, err := openDB(dbPath, blockDataNet, false)
	if err != nil {
		t.Fatalf("reopen database: %v", err)
	}
	if err := reopened.View(func(tx database.Tx) error {
		if got := tx.Metadata().Get([]byte("durable")); string(got) != "value" {
			t.Fatalf("durable metadata = %q, want %q", got, "value")
		}
		return nil
	}); err != nil {
		_ = reopened.Close()
		t.Fatalf("read durable metadata: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatalf("close reopened database: %v", err)
	}
}

func TestNormalMetadataFlushesUseDurableWriter(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "ffldb")
	idb, err := openDB(dbPath, blockDataNet, true)
	if err != nil {
		t.Fatalf("create database: %v", err)
	}
	pdb := idb.(*db)
	originalWrite := pdb.cache.writeBatchFunc
	var normalWrites, pruningWrites int
	pdb.cache.writeBatchFunc = func(batch *leveldb.Batch) error {
		normalWrites++
		return originalWrite(batch)
	}
	pdb.cache.writeBatchSyncFunc = func(*leveldb.Batch) error {
		pruningWrites++
		return errors.New("pruning metadata writer used for normal flush")
	}
	if err := idb.Update(func(tx database.Tx) error {
		return tx.Metadata().Put([]byte("first"), []byte("value"))
	}); err != nil {
		_ = idb.Close()
		t.Fatalf("cache first metadata: %v", err)
	}
	pdb.cache.maxSize = 1
	if err := idb.Update(func(tx database.Tx) error {
		return tx.Metadata().Put([]byte("second"), []byte("value"))
	}); err != nil {
		_ = idb.Close()
		t.Fatalf("flush metadata: %v", err)
	}
	if pdb.cache.cachedKeys.Len() != 0 || pdb.cache.cachedRemove.Len() != 0 {
		_ = idb.Close()
		t.Fatal("metadata cache was not empty after forced flush")
	}

	if err := idb.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}
	if normalWrites != 2 {
		t.Fatalf("normal durable metadata writes = %d, want 2", normalWrites)
	}
	if pruningWrites != 0 {
		t.Fatalf("pruning metadata writes = %d, want 0", pruningWrites)
	}
}

func TestPruningFlushUsesDedicatedDurableWriter(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "ffldb")
	idb, err := openDB(dbPath, blockDataNet, true)
	if err != nil {
		t.Fatalf("create database: %v", err)
	}
	pdb := idb.(*db)
	if err := idb.Update(func(tx database.Tx) error {
		return tx.Metadata().Put([]byte("pruning"), []byte("value"))
	}); err != nil {
		_ = idb.Close()
		t.Fatalf("cache metadata: %v", err)
	}

	originalPruningWrite := pdb.cache.writeBatchSyncFunc
	var normalWrites, pruningWrites int
	pdb.cache.writeBatchFunc = func(*leveldb.Batch) error {
		normalWrites++
		return errors.New("normal metadata writer used for pruning flush")
	}
	pdb.cache.writeBatchSyncFunc = func(batch *leveldb.Batch) error {
		pruningWrites++
		return originalPruningWrite(batch)
	}

	pdb.writeLock.Lock()
	err = pdb.cache.flushForPrune()
	pdb.writeLock.Unlock()
	if err != nil {
		_ = idb.Close()
		t.Fatalf("flush pruning metadata: %v", err)
	}
	if err := idb.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}
	if pruningWrites != 1 {
		t.Fatalf("pruning metadata writes = %d, want 1", pruningWrites)
	}
	if normalWrites != 0 {
		t.Fatalf("normal metadata writes = %d, want 0", normalWrites)
	}
}

func TestCloseReturnsDurableMetadataWriteFailure(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "ffldb")
	idb, err := openDB(dbPath, blockDataNet, true)
	if err != nil {
		t.Fatalf("create database: %v", err)
	}
	pdb := idb.(*db)
	if err := idb.Update(func(tx database.Tx) error {
		return tx.Metadata().Put([]byte("durable"), []byte("value"))
	}); err != nil {
		_ = idb.Close()
		t.Fatalf("cache metadata: %v", err)
	}

	injectedErr := errors.New("injected synchronous metadata write failure")
	pdb.cache.writeBatchFunc = func(*leveldb.Batch) error {
		return injectedErr
	}
	if err := idb.Close(); !errors.Is(err, injectedErr) {
		t.Fatalf("close error = %v, want %v", err, injectedErr)
	}
}

func TestOpenDBClosesMetadataAfterBlockStoreError(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "ffldb")
	idb, err := openDB(dbPath, blockDataNet, true)
	if err != nil {
		t.Fatalf("create database: %v", err)
	}
	if err := idb.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}

	malformedBlockFile := filepath.Join(dbPath, "malformed.fdb")
	if err := os.WriteFile(malformedBlockFile, nil, 0o600); err != nil {
		t.Fatalf("create malformed block file: %v", err)
	}
	failedDB, err := openDB(dbPath, blockDataNet, false)
	if err == nil {
		_ = failedDB.Close()
		t.Fatal("open database with malformed block file succeeded")
	}
	if err := os.Remove(malformedBlockFile); err != nil {
		t.Fatalf("remove malformed block file: %v", err)
	}

	// Reopening immediately must succeed without waiting for a finalizer to
	// release LevelDB's process lock.
	reopened, err := openDB(dbPath, blockDataNet, false)
	if err != nil {
		t.Fatalf("reopen database after block store failure: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatalf("close reopened database: %v", err)
	}
}

func TestCombinedBlockStoreOpenErrorRemainsDatabaseError(t *testing.T) {
	storeCause := errors.New("injected block store setup failure")
	closeCause := errors.New("injected metadata cleanup failure")
	storeErr := convertErr("failed to set up block store", storeCause)

	err := combineBlockStoreOpenErrors(storeErr, closeCause)
	errInterface := error(err)
	got, ok := errInterface.(database.Error)
	if !ok {
		t.Fatalf("combined error type = %T, want database.Error", errInterface)
	}
	if got.ErrorCode != storeErr.ErrorCode ||
		got.Description != storeErr.Description {

		t.Fatalf("combined database error = %#v, want primary %#v",
			got, storeErr)
	}
	if !errors.Is(errInterface, storeCause) {
		t.Fatalf("combined error does not retain block store cause: %v",
			errInterface)
	}
	if !errors.Is(errInterface, closeCause) {
		t.Fatalf("combined error does not retain cleanup cause: %v",
			errInterface)
	}
	if !strings.Contains(errInterface.Error(), storeCause.Error()) ||
		!strings.Contains(errInterface.Error(), closeCause.Error()) {

		t.Fatalf("combined error omits a diagnostic cause: %v", errInterface)
	}
}
