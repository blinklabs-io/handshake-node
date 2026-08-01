// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import "fmt"

const bytesPerMiB uint64 = 1024 * 1024

func pruneMiBToBytes(pruneMiB uint64) (uint64, error) {
	if pruneMiB > ^uint64(0)/bytesPerMiB {
		return 0, fmt.Errorf("--prune value %d MiB exceeds the maximum size",
			pruneMiB)
	}
	return pruneMiB * bytesPerMiB, nil
}
