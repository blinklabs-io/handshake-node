// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package ffldb

import (
	"fmt"
	"os"

	"github.com/blinklabs-io/handshake-node/database"
)

const directorySyncSupported = true

// syncDir synchronizes block file directory updates to stable storage.  This
// is required both after creating block files and after pruning unlinks them.
func (s *blockStore) syncDir() error {
	dir, err := os.Open(s.basePath)
	if err != nil {
		str := fmt.Sprintf("failed to open block directory %q: %v", s.basePath, err)
		return makeDbErr(database.ErrDriverSpecific, str, err)
	}

	syncErr := dir.Sync()
	closeErr := dir.Close()
	if syncErr != nil {
		str := fmt.Sprintf("failed to sync block directory %q: %v", s.basePath, syncErr)
		return makeDbErr(database.ErrDriverSpecific, str, syncErr)
	}
	if closeErr != nil {
		str := fmt.Sprintf("failed to close block directory %q: %v", s.basePath, closeErr)
		return makeDbErr(database.ErrDriverSpecific, str, closeErr)
	}
	return nil
}
