// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

//go:build hsdinterop

package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/blinklabs-io/handshake-node/database"
	"github.com/blinklabs-io/handshake-node/database/ffldb"
)

const (
	hsdInteropMaxBlockFileSizeEnv = "HNS_HSDINTEROP_MAX_BLOCK_FILE_SIZE"
	hsdInteropPruneTargetEnv      = "HNS_HSDINTEROP_PRUNE_TARGET"
)

func applyHsdInteropDatabaseOverrides(db database.DB) error {
	value := strings.TrimSpace(os.Getenv(hsdInteropMaxBlockFileSizeEnv))
	if value == "" {
		return nil
	}
	size, err := strconv.ParseUint(value, 10, 32)
	if err != nil || size == 0 {
		return fmt.Errorf("%s must be a positive uint32: %q",
			hsdInteropMaxBlockFileSizeEnv, value)
	}
	if err := ffldb.TstSetMaxBlockFileSize(db, uint32(size)); err != nil {
		return fmt.Errorf("%s: %w", hsdInteropMaxBlockFileSizeEnv, err)
	}
	return nil
}

func hsdInteropPruneTarget(db database.DB, pruneMiB uint64) (uint64, error) {
	if pruneMiB == 0 {
		return 0, nil
	}
	target := pruneMiB * 1024 * 1024

	// The test override is specified in raw bytes, while pruneMiB is MiB.
	value := strings.TrimSpace(os.Getenv(hsdInteropPruneTargetEnv))
	if value != "" {
		override, err := strconv.ParseUint(value, 10, 64)
		if err != nil || override == 0 {
			return 0, fmt.Errorf("%s must be a positive uint64 byte count: %q",
				hsdInteropPruneTargetEnv, value)
		}
		target = override
	}
	if err := ffldb.TstValidatePruneTarget(db, target); err != nil {
		return 0, fmt.Errorf("%s: %w", hsdInteropPruneTargetEnv, err)
	}
	return target, nil
}
