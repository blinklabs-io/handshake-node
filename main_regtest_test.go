// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/btcsuite/btclog"
)

func TestRemoveRegressionDBPersistence(t *testing.T) {
	originalCfg := cfg
	originalHNSLog := hnsLog
	hnsLog = btclog.Disabled
	t.Cleanup(func() {
		cfg = originalCfg
		hnsLog = originalHNSLog
	})

	tests := []struct {
		name    string
		config  config
		removed bool
	}{
		{
			name:   "mainnet preserved",
			config: config{},
		},
		{
			name: "persistent regtest preserved",
			config: config{
				RegressionTest: true,
				PersistRegtest: true,
			},
		},
		{
			name: "default regtest reset",
			config: config{
				RegressionTest: true,
			},
			removed: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "blocks_ffldb")
			if err := os.Mkdir(dbPath, 0o700); err != nil {
				t.Fatalf("create regression database: %v", err)
			}
			if err := os.WriteFile(
				filepath.Join(dbPath, "sentinel"),
				[]byte("database"),
				0o600,
			); err != nil {
				t.Fatalf("write regression database sentinel: %v", err)
			}

			cfg = &test.config
			if err := removeRegressionDB(dbPath); err != nil {
				t.Fatalf("removeRegressionDB: %v", err)
			}
			_, err := os.Stat(dbPath)
			if test.removed {
				if !os.IsNotExist(err) {
					t.Fatalf("database stat: got %v, want not-exist", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("persistent database stat: %v", err)
			}
		})
	}
}
