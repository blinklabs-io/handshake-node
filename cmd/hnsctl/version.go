// Copyright (c) 2013 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import buildversion "github.com/blinklabs-io/handshake-node/internal/version"

func version() string {
	return buildversion.String()
}
