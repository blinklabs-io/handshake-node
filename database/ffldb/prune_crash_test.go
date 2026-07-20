// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ffldb

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/blinklabs-io/handshake-node/chaincfg"
	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/database"
	"github.com/blinklabs-io/handshake-node/hnsutil"
	"github.com/syndtr/goleveldb/leveldb"
)

type syncTrackingFile struct {
	filer
	fileNum uint32
	onWrite func(uint32)
	onSync  func(uint32)
}

func (f *syncTrackingFile) WriteAt(data []byte, offset int64) (int, error) {
	written, err := f.filer.WriteAt(data, offset)
	if written != 0 {
		f.onWrite(f.fileNum)
	}
	return written, err
}

func (f *syncTrackingFile) Sync() error {
	err := f.filer.Sync()
	if err == nil {
		f.onSync(f.fileNum)
	}
	return err
}

const (
	pruneCrashExitCode      = 86
	pruneCrashHelperEnv     = "FFLDB_PRUNE_CRASH_HELPER"
	pruneCrashDBPathEnv     = "FFLDB_PRUNE_CRASH_DB_PATH"
	pruneCrashStageEnv      = "FFLDB_PRUNE_CRASH_STAGE"
	pruneCrashBlockFileSize = uint32(2048)
	pruneCrashTarget        = uint64(pruneCrashBlockFileSize) * 3
)

func makePruneContinuationBlock(t *testing.T, previous *hnsutil.Block,
	nonce uint32) *hnsutil.Block {

	t.Helper()
	msgBlock := chaincfg.MainNetParams.GenesisBlock.Copy()
	msgBlock.Header.PrevBlock = *previous.Hash()
	msgBlock.Header.Timestamp = msgBlock.Header.Timestamp.Add(
		time.Duration(nonce) * time.Second,
	)
	msgBlock.Header.Nonce = nonce

	block := hnsutil.NewBlock(msgBlock)
	rawBlock, err := block.Bytes()
	if err != nil {
		t.Fatalf("serialize continuation block: %v", err)
	}
	block, err = hnsutil.NewBlockFromBytes(rawBlock)
	if err != nil {
		t.Fatalf("deserialize continuation block: %v", err)
	}
	return block
}

func requireBlockPresent(t *testing.T, idb database.DB, hash *chainhash.Hash) {
	t.Helper()
	err := idb.View(func(tx database.Tx) error {
		_, err := tx.FetchBlock(hash)
		return err
	})
	if err != nil {
		t.Fatalf("expected block %s to be present: %v", hash, err)
	}
}

func requireBlockMissing(t *testing.T, idb database.DB, hash *chainhash.Hash) {
	t.Helper()
	err := idb.View(func(tx database.Tx) error {
		_, err := tx.FetchBlock(hash)
		return err
	})
	var dbErr database.Error
	if !errors.As(err, &dbErr) || dbErr.ErrorCode != database.ErrBlockNotFound {
		t.Fatalf("expected block %s to be missing, got %v", hash, err)
	}
}

func setupPrunableDB(t *testing.T) (string, database.DB, []*hnsutil.Block,
	[]chainhash.Hash, []uint32) {

	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "ffldb-prune")
	idb, err := openDB(dbPath, blockDataNet, true)
	if err != nil {
		t.Fatalf("create prunable database: %v", err)
	}
	idb.(*db).store.maxBlockFileSize = pruneCrashBlockFileSize

	blocks := TstHandshakeBlocks(t)
	err = idb.Update(func(tx database.Tx) error {
		for _, block := range blocks {
			if err := tx.StoreBlock(block); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		_ = idb.Close()
		t.Fatalf("store prunable blocks: %v", err)
	}

	// Discover the exact hashes and files selected by pruning without
	// committing the dry-run transaction.
	tx, err := idb.Begin(true)
	if err != nil {
		_ = idb.Close()
		t.Fatalf("begin prune dry run: %v", err)
	}
	deletedHashes, err := tx.PruneBlocks(pruneCrashTarget)
	if err != nil {
		_ = tx.Rollback()
		_ = idb.Close()
		t.Fatalf("prune dry run: %v", err)
	}
	pendingFiles := append([]uint32(nil), tx.(*transaction).pendingDelFileNums...)
	if err := tx.Rollback(); err != nil {
		_ = idb.Close()
		t.Fatalf("roll back prune dry run: %v", err)
	}
	if len(deletedHashes) == 0 || len(pendingFiles) < 2 {
		_ = idb.Close()
		t.Fatalf("fixture did not select enough prune data: %d hashes, %d files",
			len(deletedHashes), len(pendingFiles))
	}
	return dbPath, idb, blocks, deletedHashes, pendingFiles
}

func requirePruneMarker(t *testing.T, pdb *db, want bool) {
	t.Helper()
	_, err := pdb.cache.ldb.Get(pruneStateKey, nil)
	if want && err != nil {
		t.Fatalf("expected pending prune marker: %v", err)
	}
	if !want && err != leveldb.ErrNotFound {
		t.Fatalf("unexpected pending prune marker: %v", err)
	}
}

func requirePrunedFlag(t *testing.T, pdb *db) {
	t.Helper()
	value, err := pdb.cache.ldb.Get(prunedKey, nil)
	if err != nil {
		t.Fatalf("expected durable pruned flag: %v", err)
	}
	if !slices.Equal(value, prunedValue) {
		t.Fatalf("unexpected durable pruned flag value %x", value)
	}
}

func requireBeenPruned(t *testing.T, idb database.DB) {
	t.Helper()
	err := idb.View(func(tx database.Tx) error {
		pruned, err := tx.BeenPruned()
		if err != nil {
			return err
		}
		if !pruned {
			return errors.New("database reported unpruned")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("expected database to report pruned: %v", err)
	}
}

// TestPruneCrashHelper is run in a child copy of the test binary.  It exits
// without running defers at the selected pruning durability boundary.
func TestPruneCrashHelper(t *testing.T) {
	if os.Getenv(pruneCrashHelperEnv) == "" {
		return
	}

	dbPath := os.Getenv(pruneCrashDBPathEnv)
	wantStage := pruneStage(os.Getenv(pruneCrashStageEnv))
	knownStage := false
	for _, stage := range []pruneStage{
		pruneStageBlocksSynced,
		pruneStageMetadataCommitted,
		pruneStageFileDeleted,
		pruneStageDeletionsComplete,
		pruneStageDirectorySynced,
		pruneStageTombstoneCleared,
	} {
		if wantStage == stage {
			knownStage = true
			break
		}
	}
	if !knownStage {
		t.Fatalf("unknown prune crash stage %q", wantStage)
	}

	idb, err := openDB(dbPath, blockDataNet, false)
	if err != nil {
		t.Fatalf("open crash test database: %v", err)
	}
	pdb := idb.(*db)
	pdb.store.maxBlockFileSize = pruneCrashBlockFileSize
	pdb.pruneFailpoint = func(stage pruneStage) {
		if stage == wantStage {
			os.Exit(pruneCrashExitCode)
		}
	}

	blocks := TstHandshakeBlocks(t)
	continuation := makePruneContinuationBlock(t, blocks[len(blocks)-1], 1000)
	err = idb.Update(func(tx database.Tx) error {
		if err := tx.StoreBlock(continuation); err != nil {
			return err
		}
		_, err := tx.PruneBlocks(pruneCrashTarget)
		return err
	})
	if err != nil {
		t.Fatalf("prune crash transaction: %v", err)
	}
	t.Fatalf("prune crash stage %q was not reached", wantStage)
}

// TestPruneCrashRecovery verifies the database after process termination at
// every pruning durability boundary.  Before the metadata commit, recovery
// retains every old block and rolls back the pending block write.  At and after
// the metadata commit, startup completes the idempotent file deletion and the
// newly committed block remains readable.
func TestPruneCrashRecovery(t *testing.T) {
	tests := []struct {
		stage             pruneStage
		metadataCommitted bool
	}{
		{stage: pruneStageBlocksSynced},
		{stage: pruneStageMetadataCommitted, metadataCommitted: true},
		{stage: pruneStageFileDeleted, metadataCommitted: true},
		{stage: pruneStageDeletionsComplete, metadataCommitted: true},
		{stage: pruneStageDirectorySynced, metadataCommitted: true},
		{stage: pruneStageTombstoneCleared, metadataCommitted: true},
	}

	for _, test := range tests {
		t.Run(string(test.stage), func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "ffldb-prune-crash")
			idb, err := openDB(dbPath, blockDataNet, true)
			if err != nil {
				t.Fatalf("create crash test database: %v", err)
			}
			pdb := idb.(*db)
			pdb.store.maxBlockFileSize = pruneCrashBlockFileSize

			blocks := TstHandshakeBlocks(t)
			err = idb.Update(func(tx database.Tx) error {
				for _, block := range blocks {
					if err := tx.StoreBlock(block); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				_ = idb.Close()
				t.Fatalf("store crash test blocks: %v", err)
			}

			// Select the exact files and hashes that the child transaction
			// will prune without committing the dry-run transaction.
			tx, err := idb.Begin(true)
			if err != nil {
				_ = idb.Close()
				t.Fatalf("begin prune dry run: %v", err)
			}
			deletedHashes, err := tx.PruneBlocks(pruneCrashTarget)
			if err != nil {
				_ = tx.Rollback()
				_ = idb.Close()
				t.Fatalf("prune dry run: %v", err)
			}
			pendingFiles := append([]uint32(nil),
				tx.(*transaction).pendingDelFileNums...)
			if err := tx.Rollback(); err != nil {
				_ = idb.Close()
				t.Fatalf("roll back prune dry run: %v", err)
			}
			if len(deletedHashes) == 0 || len(pendingFiles) < 2 {
				_ = idb.Close()
				t.Fatalf("fixture did not select enough prune data: %d hashes, %d files",
					len(deletedHashes), len(pendingFiles))
			}

			if err := idb.Close(); err != nil {
				t.Fatalf("close crash test database: %v", err)
			}

			cmd := exec.Command(os.Args[0], "-test.run=^TestPruneCrashHelper$")
			cmd.Env = append(os.Environ(),
				pruneCrashHelperEnv+"=1",
				pruneCrashDBPathEnv+"="+dbPath,
				pruneCrashStageEnv+"="+string(test.stage),
			)
			output, err := cmd.CombinedOutput()
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != pruneCrashExitCode {
				t.Fatalf("crash helper at %q: got error %v, output:\n%s",
					test.stage, err, output)
			}

			recovered, err := openDB(dbPath, blockDataNet, false)
			if err != nil {
				t.Fatalf("reopen after crash at %q: %v", test.stage, err)
			}
			pdb = recovered.(*db)
			pdb.store.maxBlockFileSize = pruneCrashBlockFileSize
			if _, err := pdb.cache.ldb.Get(pruneStateKey, nil); err != leveldb.ErrNotFound {
				_ = recovered.Close()
				t.Fatalf("pending prune marker remains after recovery: %v", err)
			}

			deletedSet := make(map[chainhash.Hash]struct{}, len(deletedHashes))
			for _, hash := range deletedHashes {
				deletedSet[hash] = struct{}{}
			}
			for _, block := range blocks {
				_, wasPruned := deletedSet[*block.Hash()]
				if test.metadataCommitted && wasPruned {
					requireBlockMissing(t, recovered, block.Hash())
					continue
				}
				requireBlockPresent(t, recovered, block.Hash())
			}

			continuation := makePruneContinuationBlock(t,
				blocks[len(blocks)-1], 1000)
			if test.metadataCommitted {
				requireBlockPresent(t, recovered, continuation.Hash())
			} else {
				requireBlockMissing(t, recovered, continuation.Hash())
			}

			for _, fileNum := range pendingFiles {
				_, statErr := os.Stat(blockFilePath(dbPath, fileNum))
				if test.metadataCommitted {
					if !os.IsNotExist(statErr) {
						_ = recovered.Close()
						t.Fatalf("pruned file %d remains after recovery: %v",
							fileNum, statErr)
					}
				} else if statErr != nil {
					_ = recovered.Close()
					t.Fatalf("file %d disappeared before metadata commit: %v",
						fileNum, statErr)
				}
			}

			// Continue writing after recovery, then close and reopen once more
			// to verify the recovered database remains durable and usable.
			nextBlock := makePruneContinuationBlock(t, continuation, 1001)
			err = recovered.Update(func(tx database.Tx) error {
				return tx.StoreBlock(nextBlock)
			})
			if err != nil {
				_ = recovered.Close()
				t.Fatalf("store block after recovery: %v", err)
			}
			if err := recovered.Close(); err != nil {
				t.Fatalf("close recovered database: %v", err)
			}

			reopened, err := openDB(dbPath, blockDataNet, false)
			if err != nil {
				t.Fatalf("second reopen after crash at %q: %v", test.stage, err)
			}
			requireBlockPresent(t, reopened, nextBlock.Hash())
			if err := reopened.Close(); err != nil {
				t.Fatalf("close database after second reopen: %v", err)
			}
		})
	}
}

func TestPruneCleanupFailures(t *testing.T) {
	t.Run("delete failure", func(t *testing.T) {
		dbPath, idb, _, deletedHashes, pendingFiles := setupPrunableDB(t)
		pdb := idb.(*db)
		originalDelete := pdb.store.deleteFileFunc
		pdb.store.deleteFileFunc = func(uint32) error {
			return errors.New("injected block deletion failure")
		}

		err := idb.Update(func(tx database.Tx) error {
			_, err := tx.PruneBlocks(pruneCrashTarget)
			return err
		})
		if err != nil {
			_ = idb.Close()
			t.Fatalf("durably committed prune returned cleanup error: %v", err)
		}
		requirePruneMarker(t, pdb, true)
		requirePrunedFlag(t, pdb)
		requireBeenPruned(t, idb)
		if pdb.recoveryRequired.Load() {
			_ = idb.Close()
			t.Fatal("physical delete failure incorrectly poisoned database")
		}
		requireBlockMissing(t, idb, &deletedHashes[0])
		if _, err := os.Stat(blockFilePath(dbPath, pendingFiles[0])); err != nil {
			_ = idb.Close()
			t.Fatalf("delete failure removed file %d: %v", pendingFiles[0], err)
		}

		pdb.store.deleteFileFunc = originalDelete
		if err := pdb.finishPendingPrune(); err != nil {
			_ = idb.Close()
			t.Fatalf("retry block file cleanup: %v", err)
		}
		requirePruneMarker(t, pdb, false)
		if err := idb.Close(); err != nil {
			t.Fatalf("close database: %v", err)
		}
	})

	t.Run("directory sync failure", func(t *testing.T) {
		dbPath, idb, _, _, pendingFiles := setupPrunableDB(t)
		pdb := idb.(*db)
		originalSyncDir := pdb.store.syncDirFunc
		syncCalls := 0
		pdb.store.syncDirFunc = func() error {
			syncCalls++
			if syncCalls == 2 {
				return errors.New("injected block directory sync failure")
			}
			return originalSyncDir()
		}
		var stages []pruneStage
		pdb.pruneFailpoint = func(stage pruneStage) {
			stages = append(stages, stage)
		}

		err := idb.Update(func(tx database.Tx) error {
			_, err := tx.PruneBlocks(pruneCrashTarget)
			return err
		})
		if err != nil {
			_ = idb.Close()
			t.Fatalf("durably committed prune returned directory sync error: %v", err)
		}
		requirePruneMarker(t, pdb, true)
		requirePrunedFlag(t, pdb)
		requireBeenPruned(t, idb)
		if pdb.recoveryRequired.Load() {
			_ = idb.Close()
			t.Fatal("physical directory sync failure incorrectly poisoned database")
		}
		for _, fileNum := range pendingFiles {
			if _, err := os.Stat(blockFilePath(dbPath, fileNum)); !os.IsNotExist(err) {
				_ = idb.Close()
				t.Fatalf("pruned file %d still exists before directory sync retry: %v",
					fileNum, err)
			}
		}
		if !slices.Contains(stages, pruneStageDeletionsComplete) ||
			slices.Contains(stages, pruneStageDirectorySynced) {
			_ = idb.Close()
			t.Fatalf("unexpected stages before directory sync retry: %v", stages)
		}

		pdb.store.syncDirFunc = originalSyncDir
		if err := pdb.finishPendingPrune(); err != nil {
			_ = idb.Close()
			t.Fatalf("retry directory sync cleanup: %v", err)
		}
		requirePruneMarker(t, pdb, false)
		if !slices.Contains(stages, pruneStageDirectorySynced) ||
			!slices.Contains(stages, pruneStageTombstoneCleared) {
			_ = idb.Close()
			t.Fatalf("missing durable cleanup stages after retry: %v", stages)
		}
		if err := idb.Close(); err != nil {
			t.Fatalf("close database: %v", err)
		}
	})
}

func TestBeenPrunedWithSingleRemainingFile(t *testing.T) {
	dbPath, idb, _, _, _ := setupPrunableDB(t)
	pdb := idb.(*db)
	err := idb.Update(func(tx database.Tx) error {
		_, err := tx.PruneBlocks(uint64(pruneCrashBlockFileSize))
		return err
	})
	if err != nil {
		_ = idb.Close()
		t.Fatalf("prune to one file: %v", err)
	}
	requirePruneMarker(t, pdb, false)
	requirePrunedFlag(t, pdb)
	requireBeenPruned(t, idb)

	first, last, _, hasFiles, err := scanBlockFiles(dbPath)
	if err != nil {
		_ = idb.Close()
		t.Fatalf("scan pruned files: %v", err)
	}
	if !hasFiles || first == 0 || first != last {
		_ = idb.Close()
		t.Fatalf("expected one nonzero block file, got first=%d last=%d hasFiles=%v",
			first, last, hasFiles)
	}
	if err := idb.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}

	reopened, err := openDB(dbPath, blockDataNet, false)
	if err != nil {
		t.Fatalf("reopen single-file pruned database: %v", err)
	}
	requireBeenPruned(t, reopened)
	if err := reopened.Close(); err != nil {
		t.Fatalf("close reopened database: %v", err)
	}
}

func TestPruneSyncsAllBlockFilesBeforeMetadata(t *testing.T) {
	dbPath, idb, blocks, _, _ := setupPrunableDB(t)
	if err := idb.Close(); err != nil {
		t.Fatalf("close fixture database: %v", err)
	}
	idb, err := openDB(dbPath, blockDataNet, false)
	if err != nil {
		t.Fatalf("reopen fixture database: %v", err)
	}
	pdb := idb.(*db)
	pdb.store.maxBlockFileSize = 512

	dirtyFiles := make(map[uint32]bool)
	syncedFiles := make(map[uint32]bool)
	originalOpenWrite := pdb.store.openWriteFileFunc
	pdb.store.openWriteFileFunc = func(fileNum uint32) (filer, error) {
		file, err := originalOpenWrite(fileNum)
		if err != nil {
			return nil, err
		}
		return &syncTrackingFile{
			filer:   file,
			fileNum: fileNum,
			onWrite: func(fileNum uint32) {
				dirtyFiles[fileNum] = true
			},
			onSync: func(fileNum uint32) {
				syncedFiles[fileNum] = true
			},
		}, nil
	}

	directorySynced := false
	originalSyncDir := pdb.store.syncDirFunc
	pdb.store.syncDirFunc = func() error {
		if err := originalSyncDir(); err != nil {
			return err
		}
		directorySynced = true
		return nil
	}

	metadataCommitted := false
	var orderingErr error
	originalWriteBatchSync := pdb.cache.writeBatchSyncFunc
	pdb.cache.writeBatchSyncFunc = func(batch *leveldb.Batch) error {
		if len(dirtyFiles) < 3 {
			orderingErr = fmt.Errorf("expected at least 3 dirty block files, got %d",
				len(dirtyFiles))
		}
		for fileNum := range dirtyFiles {
			if !syncedFiles[fileNum] && orderingErr == nil {
				orderingErr = fmt.Errorf("dirty block file %d was not synced", fileNum)
			}
		}
		if !directorySynced && orderingErr == nil {
			orderingErr = errors.New("block directory was not synced")
		}
		metadataCommitted = true
		return originalWriteBatchSync(batch)
	}

	previous := blocks[len(blocks)-1]
	err = idb.Update(func(tx database.Tx) error {
		for nonce := uint32(2000); nonce < 2006; nonce++ {
			block := makePruneContinuationBlock(t, previous, nonce)
			if err := tx.StoreBlock(block); err != nil {
				return err
			}
			previous = block
		}
		_, err := tx.PruneBlocks(pruneCrashTarget)
		return err
	})
	if err != nil {
		_ = idb.Close()
		t.Fatalf("multi-file pruning transaction: %v", err)
	}
	if orderingErr != nil {
		_ = idb.Close()
		t.Fatalf("durability ordering: %v", orderingErr)
	}
	if !metadataCommitted {
		_ = idb.Close()
		t.Fatal("synchronous metadata commit was not observed")
	}
	if err := idb.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}
}

func TestPruneAmbiguousMetadataCommit(t *testing.T) {
	dbPath, idb, blocks, deletedHashes, pendingFiles := setupPrunableDB(t)
	if err := idb.Close(); err != nil {
		t.Fatalf("close fixture database: %v", err)
	}
	idb, err := openDB(dbPath, blockDataNet, false)
	if err != nil {
		t.Fatalf("reopen fixture database: %v", err)
	}
	pdb := idb.(*db)
	pdb.store.maxBlockFileSize = pruneCrashBlockFileSize

	continuation := makePruneContinuationBlock(t, blocks[len(blocks)-1], 3000)
	injectedErr := errors.New("injected error after durable batch write")
	originalWriteBatchSync := pdb.cache.writeBatchSyncFunc
	wroteBatch := false
	pdb.cache.writeBatchSyncFunc = func(batch *leveldb.Batch) error {
		if err := originalWriteBatchSync(batch); err != nil {
			return err
		}
		wroteBatch = true
		return injectedErr
	}

	err = idb.Update(func(tx database.Tx) error {
		if err := tx.StoreBlock(continuation); err != nil {
			return err
		}
		_, err := tx.PruneBlocks(pruneCrashTarget)
		return err
	})
	var dbErr database.Error
	if !errors.As(err, &dbErr) || dbErr.ErrorCode != database.ErrDriverSpecific {
		_ = idb.Close()
		t.Fatalf("expected ambiguous commit error, got %v", err)
	}
	innerErr, innerOK := dbErr.Err.(database.Error)
	if !innerOK || innerErr.Err != injectedErr {
		_ = idb.Close()
		t.Fatalf("ambiguous commit did not retain storage error: %v", err)
	}
	if !wroteBatch || !pdb.recoveryRequired.Load() {
		_ = idb.Close()
		t.Fatal("database did not fail closed after ambiguous metadata commit")
	}
	for _, fileNum := range pendingFiles {
		if _, err := os.Stat(blockFilePath(dbPath, fileNum)); err != nil {
			_ = idb.Close()
			t.Fatalf("ambiguous commit deleted file %d: %v", fileNum, err)
		}
	}
	if err := idb.View(func(database.Tx) error { return nil }); err == nil {
		_ = idb.Close()
		t.Fatal("database accepted a transaction while recovery was required")
	}
	if err := idb.Close(); err != nil {
		t.Fatalf("close ambiguous database: %v", err)
	}

	reopened, err := openDB(dbPath, blockDataNet, false)
	if err != nil {
		t.Fatalf("reopen after ambiguous persisted commit: %v", err)
	}
	requireBlockPresent(t, reopened, continuation.Hash())
	for _, hash := range deletedHashes {
		requireBlockMissing(t, reopened, &hash)
	}
	requirePruneMarker(t, reopened.(*db), false)
	if err := reopened.Close(); err != nil {
		t.Fatalf("close recovered database: %v", err)
	}
}

func TestPruneAmbiguousCachedMetadataFlush(t *testing.T) {
	dbPath, idb, blocks, deletedHashes, pendingFiles := setupPrunableDB(t)
	if err := idb.Close(); err != nil {
		t.Fatalf("close fixture database: %v", err)
	}
	idb, err := openDB(dbPath, blockDataNet, false)
	if err != nil {
		t.Fatalf("reopen fixture database: %v", err)
	}
	pdb := idb.(*db)
	pdb.store.maxBlockFileSize = pruneCrashBlockFileSize

	// Leave a completed transaction in the metadata cache.  It precedes the
	// pruning transaction and therefore must survive recovery even when its
	// synchronous flush reports an ambiguous result.
	cachedBlock := makePruneContinuationBlock(t, blocks[len(blocks)-1], 3100)
	err = idb.Update(func(tx database.Tx) error {
		return tx.StoreBlock(cachedBlock)
	})
	if err != nil {
		_ = idb.Close()
		t.Fatalf("cache preceding block: %v", err)
	}
	if pdb.cache.cachedKeys.Len() == 0 && pdb.cache.cachedRemove.Len() == 0 {
		_ = idb.Close()
		t.Fatal("preceding transaction was not retained in metadata cache")
	}

	currentBlock := makePruneContinuationBlock(t, cachedBlock, 3101)
	injectedErr := errors.New("injected error after durable cached batch write")
	originalWriteBatchSync := pdb.cache.writeBatchSyncFunc
	wroteCachedBatch := false
	pdb.cache.writeBatchSyncFunc = func(batch *leveldb.Batch) error {
		if err := originalWriteBatchSync(batch); err != nil {
			return err
		}
		wroteCachedBatch = true
		return injectedErr
	}

	err = idb.Update(func(tx database.Tx) error {
		if err := tx.StoreBlock(currentBlock); err != nil {
			return err
		}
		_, err := tx.PruneBlocks(pruneCrashTarget)
		return err
	})
	var dbErr database.Error
	if !errors.As(err, &dbErr) || dbErr.ErrorCode != database.ErrDriverSpecific {
		_ = idb.Close()
		t.Fatalf("expected ambiguous cached metadata error, got %v", err)
	}
	if !wroteCachedBatch || !pdb.recoveryRequired.Load() {
		_ = idb.Close()
		t.Fatal("database did not fail closed after ambiguous cached metadata flush")
	}
	cachedHash := cachedBlock.Hash()
	if _, err := pdb.cache.ldb.Get(
		bucketizedKey(blockIdxBucketID, cachedHash[:]), nil,
	); err != nil {
		_ = idb.Close()
		t.Fatalf("cached batch was not persisted before injected error: %v", err)
	}
	currentHash := currentBlock.Hash()
	if _, err := pdb.cache.ldb.Get(
		bucketizedKey(blockIdxBucketID, currentHash[:]), nil,
	); err != leveldb.ErrNotFound {
		_ = idb.Close()
		t.Fatalf("current pruning block metadata unexpectedly persisted: %v", err)
	}
	requirePruneMarker(t, pdb, false)
	for _, fileNum := range pendingFiles {
		if _, err := os.Stat(blockFilePath(dbPath, fileNum)); err != nil {
			_ = idb.Close()
			t.Fatalf("ambiguous cached flush deleted file %d: %v", fileNum, err)
		}
	}
	if err := idb.View(func(database.Tx) error { return nil }); err == nil {
		_ = idb.Close()
		t.Fatal("database accepted a transaction while recovery was required")
	}
	if err := idb.Close(); err != nil {
		t.Fatalf("close ambiguous cached database: %v", err)
	}

	reopened, err := openDB(dbPath, blockDataNet, false)
	if err != nil {
		t.Fatalf("reopen after ambiguous cached metadata flush: %v", err)
	}
	requireBlockPresent(t, reopened, cachedBlock.Hash())
	requireBlockMissing(t, reopened, currentBlock.Hash())
	for _, hash := range deletedHashes {
		requireBlockPresent(t, reopened, &hash)
	}
	requirePruneMarker(t, reopened.(*db), false)
	if err := reopened.Close(); err != nil {
		t.Fatalf("close recovered database: %v", err)
	}
}

func TestPrunePreMetadataDirectorySyncFailure(t *testing.T) {
	dbPath, idb, blocks, deletedHashes, pendingFiles := setupPrunableDB(t)
	if err := idb.Close(); err != nil {
		t.Fatalf("close fixture database: %v", err)
	}
	idb, err := openDB(dbPath, blockDataNet, false)
	if err != nil {
		t.Fatalf("reopen fixture database: %v", err)
	}
	pdb := idb.(*db)
	pdb.store.maxBlockFileSize = pruneCrashBlockFileSize

	cachedBlock := makePruneContinuationBlock(t, blocks[len(blocks)-1], 3200)
	if err := idb.Update(func(tx database.Tx) error {
		return tx.StoreBlock(cachedBlock)
	}); err != nil {
		_ = idb.Close()
		t.Fatalf("cache preceding block: %v", err)
	}
	currentBlock := makePruneContinuationBlock(t, cachedBlock, 3201)

	injectedErr := errors.New("injected pre-metadata directory sync failure")
	originalSyncDir := pdb.store.syncDirFunc
	pdb.store.syncDirFunc = func() error {
		return injectedErr
	}
	err = idb.Update(func(tx database.Tx) error {
		if err := tx.StoreBlock(currentBlock); err != nil {
			return err
		}
		_, err := tx.PruneBlocks(pruneCrashTarget)
		return err
	})
	if !errors.Is(err, injectedErr) {
		_ = idb.Close()
		t.Fatalf("expected directory sync error, got %v", err)
	}
	if pdb.recoveryRequired.Load() {
		_ = idb.Close()
		t.Fatal("pre-metadata directory sync failure incorrectly poisoned database")
	}
	requirePruneMarker(t, pdb, false)
	for _, fileNum := range pendingFiles {
		if _, err := os.Stat(blockFilePath(dbPath, fileNum)); err != nil {
			_ = idb.Close()
			t.Fatalf("pre-metadata sync failure deleted file %d: %v", fileNum, err)
		}
	}
	requireBlockPresent(t, idb, cachedBlock.Hash())
	requireBlockMissing(t, idb, currentBlock.Hash())

	pdb.store.syncDirFunc = originalSyncDir
	if err := idb.Close(); err != nil {
		t.Fatalf("close database after directory sync failure: %v", err)
	}
	reopened, err := openDB(dbPath, blockDataNet, false)
	if err != nil {
		t.Fatalf("reopen after directory sync failure: %v", err)
	}
	requireBlockPresent(t, reopened, cachedBlock.Hash())
	requireBlockMissing(t, reopened, currentBlock.Hash())
	for _, hash := range deletedHashes {
		requireBlockPresent(t, reopened, &hash)
	}
	requirePruneMarker(t, reopened.(*db), false)
	if err := reopened.Close(); err != nil {
		t.Fatalf("close recovered database: %v", err)
	}
}

func TestOpenRejectsCorruptPruneMarker(t *testing.T) {
	dbPath, idb, _, _, _ := setupPrunableDB(t)
	pdb := idb.(*db)
	if err := pdb.cache.ldb.Put(pruneStateKey, []byte{0x01, 0x02},
		syncWriteOptions); err != nil {
		_ = idb.Close()
		t.Fatalf("write corrupt prune marker: %v", err)
	}
	if err := idb.Close(); err != nil {
		t.Fatalf("close corrupt marker database: %v", err)
	}

	_, err := openDB(dbPath, blockDataNet, false)
	var dbErr database.Error
	if !errors.As(err, &dbErr) || dbErr.ErrorCode != database.ErrCorruption {
		t.Fatalf("expected corrupt marker reopen failure, got %v", err)
	}
}

func TestPruneDoesNotWaitForReadTransactions(t *testing.T) {
	_, idb, _, deletedHashes, _ := setupPrunableDB(t)
	pdb := idb.(*db)

	readTx, err := idb.Begin(false)
	if err != nil {
		_ = idb.Close()
		t.Fatalf("begin read transaction: %v", err)
	}
	metadataCommitted := false
	pdb.pruneFailpoint = func(stage pruneStage) {
		if stage == pruneStageMetadataCommitted {
			metadataCommitted = true
		}
	}

	// Keep the older read transaction open while committing the prune.  The
	// cleanup path uses TryLock, so this returns without waiting for the reader
	// regardless of how long the preceding durability work takes.  A blocking
	// lock regression is a real deadlock and is handled by the suite timeout.
	err = idb.Update(func(tx database.Tx) error {
		_, err := tx.PruneBlocks(pruneCrashTarget)
		return err
	})
	if err != nil {
		_ = readTx.Rollback()
		_ = idb.Close()
		t.Fatalf("prune with older read transaction: %v", err)
	}
	if !metadataCommitted {
		_ = readTx.Rollback()
		_ = idb.Close()
		t.Fatal("prune returned before durable metadata commit")
	}
	requirePruneMarker(t, pdb, true)
	if _, err := readTx.FetchBlock(&deletedHashes[0]); err != nil {
		_ = readTx.Rollback()
		_ = idb.Close()
		t.Fatalf("older read snapshot lost its block file: %v", err)
	}
	if err := readTx.Rollback(); err != nil {
		_ = idb.Close()
		t.Fatalf("close read transaction: %v", err)
	}

	if err := idb.Update(func(tx database.Tx) error {
		return tx.Metadata().Put([]byte("post-reader-cleanup"), []byte{1})
	}); err != nil {
		_ = idb.Close()
		t.Fatalf("later write did not finish prune cleanup: %v", err)
	}
	requirePruneMarker(t, pdb, false)
	requireBlockMissing(t, idb, &deletedHashes[0])
	if err := idb.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}
}

func TestPruneStateSerialization(t *testing.T) {
	want := []uint32{1, 4, 9}
	serialized := serializePruneState(want)
	got, err := deserializePruneState(serialized)
	if err != nil {
		t.Fatalf("deserialize valid prune state: %v", err)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("prune state round trip mismatch: got %v, want %v", got, want)
	}

	tests := []struct {
		name       string
		serialized []byte
	}{
		{name: "short", serialized: serialized[:8]},
		{name: "empty", serialized: serializePruneState(nil)},
		{name: "wrong version", serialized: func() []byte {
			value := append([]byte(nil), serialized...)
			byteOrder.PutUint32(value[0:4], pruneStateVersion+1)
			return value
		}()},
		{name: "wrong count", serialized: func() []byte {
			value := append([]byte(nil), serialized...)
			byteOrder.PutUint32(value[4:8], uint32(len(want)+1))
			return value
		}()},
		{name: "bad checksum", serialized: func() []byte {
			value := append([]byte(nil), serialized...)
			value[len(value)-1] ^= 0xff
			return value
		}()},
		{name: "unsorted", serialized: serializePruneState([]uint32{4, 1})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := deserializePruneState(test.serialized)
			var dbErr database.Error
			if !errors.As(err, &dbErr) || dbErr.ErrorCode != database.ErrCorruption {
				t.Fatalf("expected corruption error, got %v", err)
			}
		})
	}
}

func TestMergePruneFileNums(t *testing.T) {
	got := mergePruneFileNums([]uint32{1, 3, 5}, []uint32{2, 3, 4})
	want := []uint32{1, 2, 3, 4, 5}
	if !slices.Equal(got, want) {
		t.Fatalf("merged file numbers mismatch: got %v, want %v", got, want)
	}
}
