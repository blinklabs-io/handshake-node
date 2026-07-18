// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package ffldb

import (
	"fmt"
	"runtime"

	"github.com/blinklabs-io/handshake-node/database"
)

const directorySyncSupported = false

// syncDir fails closed on platforms where Go cannot durably synchronize a
// directory.  PruneBlocks rejects pruning on these platforms before metadata
// changes are queued.  This method can still be reached when opening a data
// directory moved from a supported platform with pending deletion intent; the
// intent is retained rather than unsafely cleared.
func (s *blockStore) syncDir() error {
	str := fmt.Sprintf("durable directory synchronization is unsupported on %s", runtime.GOOS)
	return makeDbErr(database.ErrDriverSpecific, str, nil)
}
