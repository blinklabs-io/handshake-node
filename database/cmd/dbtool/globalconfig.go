// Copyright (c) 2015-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/blinklabs-io/handshake-node/hnsutil"
	"github.com/blinklabs-io/handshake-node/chaincfg"
	"github.com/blinklabs-io/handshake-node/database"
	_ "github.com/blinklabs-io/handshake-node/database/ffldb"
)

var (
	hnsNodeHomeDir  = hnsutil.AppDataDir("handshake-node", false)
	knownDbTypes    = database.SupportedDrivers()
	activeNetParams = &chaincfg.MainNetParams

	// Default global config.
	cfg = &config{
		DataDir: filepath.Join(hnsNodeHomeDir, "data"),
		DbType:  "ffldb",
	}
)

// config defines the global configuration options.
type config struct {
	DataDir        string `short:"b" long:"datadir" description:"Location of the handshake-node data directory"`
	DbType         string `long:"dbtype" description:"Database backend to use for the Block Chain"`
	RegressionTest bool   `long:"regtest" description:"Use the regression test network"`
}

// fileExists reports whether the named file or directory exists.
func fileExists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// validDbType returns whether or not dbType is a supported database type.
func validDbType(dbType string) bool {
	return slices.Contains(knownDbTypes, dbType)
}

// netName returns the name used when referring to a Handshake network.
func netName(chainParams *chaincfg.Params) string {
	return chainParams.Name
}

// setupGlobalConfig examine the global configuration options for any conditions
// which are invalid as well as performs any addition setup necessary after the
// initial parse.
func setupGlobalConfig() error {
	// Use the regression test network if specified.
	if cfg.RegressionTest {
		activeNetParams = &chaincfg.RegressionNetParams
	}

	// Validate database type.
	if !validDbType(cfg.DbType) {
		str := "The specified database type [%v] is invalid -- " +
			"supported types %v"
		return fmt.Errorf(str, cfg.DbType, knownDbTypes)
	}

	// Append the network type to the data directory so it is "namespaced"
	// per network.  In addition to the block database, there are other
	// pieces of data that are saved to disk such as address manager state.
	// All data is specific to a network, so namespacing the data directory
	// means each individual piece of serialized data does not have to
	// worry about changing names per network and such.
	cfg.DataDir = filepath.Join(cfg.DataDir, netName(activeNetParams))

	return nil
}
