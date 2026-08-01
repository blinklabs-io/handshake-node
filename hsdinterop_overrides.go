// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

//go:build !hsdinterop

package main

import "github.com/blinklabs-io/handshake-node/database"

func applyHsdInteropDatabaseOverrides(database.DB) error {
	return nil
}

func hsdInteropPruneTarget(_ database.DB, pruneMiB uint64) (uint64, error) {
	return pruneMiB * 1024 * 1024, nil
}
