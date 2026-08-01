// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

//go:build hsdinterop

package ffldb

import (
	"fmt"

	"github.com/blinklabs-io/handshake-node/database"
)

// TstSetMaxBlockFileSize changes the flat-file rollover size for a live
// throwaway database used by the pinned-hsd recovery tests.
func TstSetMaxBlockFileSize(idb database.DB, size uint32) error {
	ffldb, ok := idb.(*db)
	if !ok {
		return fmt.Errorf("database is %T, not ffldb", idb)
	}
	if size == 0 {
		return fmt.Errorf("max block file size must be positive")
	}
	ffldb.store.maxBlockFileSize = size
	return nil
}
