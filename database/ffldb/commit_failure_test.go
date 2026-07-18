// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ffldb

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"

	"github.com/blinklabs-io/handshake-node/database"
	"github.com/syndtr/goleveldb/leveldb"
)

func TestMetadataCommitErrorRequiresRecovery(t *testing.T) {
	tests := []struct {
		name              string
		commitBeforeError bool
	}{
		{name: "metadata absent", commitBeforeError: false},
		{name: "metadata committed", commitBeforeError: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "ffldb")
			idb, err := openDB(dbPath, blockDataNet, true)
			if err != nil {
				t.Fatalf("create database: %v", err)
			}
			pdb := idb.(*db)
			if err := idb.Update(func(tx database.Tx) error {
				return tx.Metadata().Put([]byte("cached"), []byte("value"))
			}); err != nil {
				_ = idb.Close()
				t.Fatalf("seed metadata cache: %v", err)
			}
			pdb.cache.maxSize = 1

			block := TstHandshakeBlocks(t)[0]
			injectedErr := errors.New("injected metadata commit error")
			originalWrite := pdb.cache.writeBatchFunc
			commitCalls := 0
			pdb.cache.writeBatchFunc = func(batch *leveldb.Batch) error {
				commitCalls++
				if commitCalls == 1 {
					return originalWrite(batch)
				}
				if test.commitBeforeError {
					if err := originalWrite(batch); err != nil {
						return err
					}
				}
				return injectedErr
			}

			err = idb.Update(func(tx database.Tx) error {
				return tx.StoreBlock(block)
			})
			var dbErr database.Error
			if !errors.As(err, &dbErr) ||
				dbErr.ErrorCode != database.ErrDriverSpecific ||
				!errors.Is(err, injectedErr) {

				_ = idb.Close()
				t.Fatalf("expected wrapped ambiguous commit error, got %v", err)
			}
			if !pdb.recoveryRequired.Load() {
				_ = idb.Close()
				t.Fatal("database did not require recovery after metadata commit error")
			}
			if commitCalls != 2 {
				_ = idb.Close()
				t.Fatalf("metadata commit calls = %d, want 2", commitCalls)
			}
			if err := idb.View(func(database.Tx) error { return nil }); err == nil {
				_ = idb.Close()
				t.Fatal("database accepted a transaction while recovery was required")
			}

			pdb.cache.writeBatchFunc = originalWrite
			if err := idb.Close(); err != nil {
				t.Fatalf("close database: %v", err)
			}

			reopened, err := openDB(dbPath, blockDataNet, false)
			if err != nil {
				t.Fatalf("reopen database: %v", err)
			}
			if test.commitBeforeError {
				requireBlockPresent(t, reopened, block.Hash())
			} else {
				requireBlockMissing(t, reopened, block.Hash())
			}
			if err := reopened.Close(); err != nil {
				t.Fatalf("close reopened database: %v", err)
			}
		})
	}
}

func TestMetadataDBDisablesLargeBatchTransactions(t *testing.T) {
	t.Parallel()

	if !metadataDBOptions(false).DisableLargeBatchTransaction {
		t.Fatal("metadata database permits unsafe large-batch transactions")
	}
}

func TestLargeMetadataBatchUsesWriteAheadLog(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "ffldb")
	idb, err := openDB(dbPath, blockDataNet, true)
	if err != nil {
		t.Fatalf("create database: %v", err)
	}
	pdb := idb.(*db)

	key := []byte("large-metadata-value")
	value := bytes.Repeat([]byte{0x5a}, 5<<20)
	if err := idb.Update(func(tx database.Tx) error {
		return tx.Metadata().Put(key, value)
	}); err != nil {
		_ = idb.Close()
		t.Fatalf("cache large metadata value: %v", err)
	}
	pdb.cache.maxSize = 1
	if err := idb.Update(func(tx database.Tx) error {
		return tx.Metadata().Put([]byte("flush-trigger"), []byte{1})
	}); err != nil {
		_ = idb.Close()
		t.Fatalf("flush large metadata batch: %v", err)
	}
	if err := idb.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}

	reopened, err := openDB(dbPath, blockDataNet, false)
	if err != nil {
		t.Fatalf("reopen database: %v", err)
	}
	err = reopened.View(func(tx database.Tx) error {
		got := tx.Metadata().Get(key)
		if !bytes.Equal(got, value) {
			t.Fatalf("large metadata value mismatch: got %d bytes, want %d",
				len(got), len(value))
		}
		return nil
	})
	if err != nil {
		_ = reopened.Close()
		t.Fatalf("read large metadata value: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatalf("close reopened database: %v", err)
	}
}

func TestPreMetadataSyncErrorRollsBack(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "ffldb")
	idb, err := openDB(dbPath, blockDataNet, true)
	if err != nil {
		t.Fatalf("create database: %v", err)
	}
	pdb := idb.(*db)
	if err := idb.Update(func(tx database.Tx) error {
		return tx.Metadata().Put([]byte("cached"), []byte("value"))
	}); err != nil {
		_ = idb.Close()
		t.Fatalf("seed metadata cache: %v", err)
	}
	pdb.cache.maxSize = 1

	block := TstHandshakeBlocks(t)[0]
	injectedErr := errors.New("injected block directory sync error")
	originalSyncDir := pdb.store.syncDirFunc
	pdb.store.syncDirFunc = func() error {
		return injectedErr
	}

	err = idb.Update(func(tx database.Tx) error {
		return tx.StoreBlock(block)
	})
	if !errors.Is(err, injectedErr) {
		_ = idb.Close()
		t.Fatalf("expected block sync error, got %v", err)
	}
	if pdb.recoveryRequired.Load() {
		_ = idb.Close()
		t.Fatal("pre-metadata sync error incorrectly required recovery")
	}
	requireBlockMissing(t, idb, block.Hash())

	pdb.store.syncDirFunc = originalSyncDir
	if err := idb.Close(); err != nil {
		t.Fatalf("close database: %v", err)
	}
	reopened, err := openDB(dbPath, blockDataNet, false)
	if err != nil {
		t.Fatalf("reopen database: %v", err)
	}
	requireBlockMissing(t, reopened, block.Hash())
	if err := reopened.Close(); err != nil {
		t.Fatalf("close reopened database: %v", err)
	}
}
