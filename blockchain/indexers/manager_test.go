// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package indexers

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/blinklabs-io/handshake-node/database"
	_ "github.com/blinklabs-io/handshake-node/database/ffldb"
	"github.com/blinklabs-io/handshake-node/wire"
)

type failingViewDB struct {
	database.DB
	failAt    int
	viewCalls int
	err       error
}

func (db *failingViewDB) View(fn func(database.Tx) error) error {
	db.viewCalls++
	if db.viewCalls == db.failAt {
		return db.err
	}
	return db.DB.View(fn)
}

func TestDropIndexPropagatesBucketCatalogError(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "index-drop")
	db, err := database.Create("ffldb", dbPath, wire.MainNet)
	if err != nil {
		t.Fatalf("create test database: %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			t.Errorf("close test database: %v", err)
		}
	}()

	indexKey := []byte("catalog-error-index")
	err = db.Update(func(tx database.Tx) error {
		metadata := tx.Metadata()
		tips, err := metadata.CreateBucketIfNotExists(indexTipsBucketName)
		if err != nil {
			return err
		}
		if err := tips.Put(indexKey, []byte("tip")); err != nil {
			return err
		}
		index, err := metadata.CreateBucket(indexKey)
		if err != nil {
			return err
		}
		return index.Put([]byte("entry"), []byte("value"))
	})
	if err != nil {
		t.Fatalf("initialize test index: %v", err)
	}

	injectedErr := errors.New("injected bucket catalog error")
	failingDB := &failingViewDB{
		DB:     db,
		failAt: 2,
		err:    injectedErr,
	}
	err = dropIndex(failingDB, indexKey, "test index", nil)
	if !errors.Is(err, injectedErr) {
		t.Fatalf("drop error: got %v, want %v", err, injectedErr)
	}
	if failingDB.viewCalls != failingDB.failAt {
		t.Fatalf("view calls: got %d, want %d",
			failingDB.viewCalls, failingDB.failAt)
	}

	err = db.View(func(tx database.Tx) error {
		tips := tx.Metadata().Bucket(indexTipsBucketName)
		if tips.Get(indexDropKey(indexKey)) == nil {
			t.Fatal("drop-in-progress marker was not retained")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("check drop marker: %v", err)
	}
}
