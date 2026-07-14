// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"github.com/blinklabs-io/handshake-node/chaincfg"
)

// activeNetParams is a pointer to the parameters specific to the
// currently active Handshake network.
var activeNetParams = &mainNetParams

// params is used to group parameters for various networks such as the main
// network and test networks.
type params struct {
	*chaincfg.Params
	rpcPort string
}

// mainNetParams contains parameters specific to the main network
// (wire.MainNet).
var mainNetParams = params{
	Params:  &chaincfg.MainNetParams,
	rpcPort: "12037",
}

// regressionNetParams contains parameters specific to the regression test
// network (wire.TestNet).
var regressionNetParams = params{
	Params:  &chaincfg.RegressionNetParams,
	rpcPort: "14037",
}

// netName returns the name used when referring to a Handshake network.
func netName(chainParams *params) string {
	return chainParams.Name
}
