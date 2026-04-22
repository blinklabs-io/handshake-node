// Copyright (c) 2013-2016 The btcsuite developers
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
	flags "github.com/jessevdk/go-flags"
)

const (
	defaultDbType   = "ffldb"
	defaultDataFile = "bootstrap.dat"
	defaultProgress = 10
)

var (
	hnsNodeHomeDir  = hnsutil.AppDataDir("handshake-node", false)
	defaultDataDir  = filepath.Join(hnsNodeHomeDir, "data")
	knownDbTypes    = database.SupportedDrivers()
	activeNetParams = &chaincfg.MainNetParams
)

// config defines the configuration options for addblock.
//
// See loadConfig for details on the configuration load process.
type config struct {
	AddrIndex      bool   `long:"addrindex" description:"Build a full address-based transaction index which makes the searchrawtransactions RPC available"`
	DataDir        string `short:"b" long:"datadir" description:"Location of the handshake-node data directory"`
	DbType         string `long:"dbtype" description:"Database backend to use for the Block Chain"`
	InFile         string `short:"i" long:"infile" description:"File containing the block(s)"`
	Progress       int    `short:"p" long:"progress" description:"Show a progress message each time this number of seconds have passed -- Use 0 to disable progress announcements"`
	RegressionTest bool   `long:"regtest" description:"Use the regression test network"`
	TxIndex        bool   `long:"txindex" description:"Build a full hash-based transaction index which makes all transactions available via the getrawtransaction RPC"`
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

// loadConfig initializes and parses the config using command line options.
func loadConfig() (*config, []string, error) {
	// Default config.
	cfg := config{
		DataDir:  defaultDataDir,
		DbType:   defaultDbType,
		InFile:   defaultDataFile,
		Progress: defaultProgress,
	}

	// Parse command line options.
	parser := flags.NewParser(&cfg, flags.Default)
	remainingArgs, err := parser.Parse()
	if err != nil {
		if e, ok := err.(*flags.Error); !ok || e.Type != flags.ErrHelp {
			parser.WriteHelp(os.Stderr)
		}
		return nil, nil, err
	}

	// Use the regression test network if specified.
	if cfg.RegressionTest {
		activeNetParams = &chaincfg.RegressionNetParams
	}

	// Validate database type.
	if !validDbType(cfg.DbType) {
		str := "%s: The specified database type [%v] is invalid -- " +
			"supported types %v"
		err := fmt.Errorf(str, "loadConfig", cfg.DbType, knownDbTypes)
		fmt.Fprintln(os.Stderr, err)
		parser.WriteHelp(os.Stderr)
		return nil, nil, err
	}

	// Append the network type to the data directory so it is "namespaced"
	// per network.  In addition to the block database, there are other
	// pieces of data that are saved to disk such as address manager state.
	// All data is specific to a network, so namespacing the data directory
	// means each individual piece of serialized data does not have to
	// worry about changing names per network and such.
	cfg.DataDir = filepath.Join(cfg.DataDir, netName(activeNetParams))

	// Ensure the specified block file exists.
	if !fileExists(cfg.InFile) {
		str := "%s: The specified block file [%v] does not exist"
		err := fmt.Errorf(str, "loadConfig", cfg.InFile)
		fmt.Fprintln(os.Stderr, err)
		parser.WriteHelp(os.Stderr)
		return nil, nil, err
	}

	return &cfg, remainingArgs, nil
}
