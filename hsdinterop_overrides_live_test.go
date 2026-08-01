// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

//go:build hsdinterop

package main

import (
	"path/filepath"
	"testing"

	"github.com/blinklabs-io/handshake-node/chaincfg"
	"github.com/blinklabs-io/handshake-node/database"
	_ "github.com/blinklabs-io/handshake-node/database/ffldb"
)

func TestHsdInteropPruneTarget(t *testing.T) {
	db, err := database.Create(
		"ffldb",
		filepath.Join(t.TempDir(), "blocks"),
		chaincfg.MainNetParams.Net,
	)
	if err != nil {
		t.Fatalf("database.Create: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("database.Close: %v", err)
		}
	})

	tests := []struct {
		name     string
		pruneMiB uint64
		value    string
		want     uint64
		wantErr  bool
	}{
		{
			name:     "default calculation",
			pruneMiB: 1536,
			want:     1536 * 1024 * 1024,
		},
		{
			name:     "disabled pruning ignores override",
			pruneMiB: 0,
			value:    "invalid",
		},
		{
			name:     "test override",
			pruneMiB: 1536,
			value:    "536870912",
			want:     536870912,
		},
		{
			name:     "override below block file size",
			pruneMiB: 1536,
			value:    "536870911",
			wantErr:  true,
		},
		{
			name:     "zero override",
			pruneMiB: 1536,
			value:    "0",
			wantErr:  true,
		},
		{
			name:     "invalid override",
			pruneMiB: 1536,
			value:    "invalid",
			wantErr:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(hsdInteropPruneTargetEnv, test.value)
			got, err := hsdInteropPruneTarget(db, test.pruneMiB)
			if test.wantErr {
				if err == nil {
					t.Fatalf("hsdInteropPruneTarget returned nil error")
				}
				return
			}
			if err != nil {
				t.Fatalf("hsdInteropPruneTarget: %v", err)
			}
			if got != test.want {
				t.Fatalf("hsdInteropPruneTarget = %d, want %d", got, test.want)
			}
		})
	}
}

func TestApplyHsdInteropDatabaseOverridesValidation(t *testing.T) {
	t.Setenv(hsdInteropMaxBlockFileSizeEnv, "invalid")
	if err := applyHsdInteropDatabaseOverrides(nil); err == nil {
		t.Fatal("invalid max block file size returned nil error")
	}
}

func TestHsdInteropPruneTargetUsesActiveRolloverSize(t *testing.T) {
	db, err := database.Create(
		"ffldb",
		filepath.Join(t.TempDir(), "blocks"),
		chaincfg.MainNetParams.Net,
	)
	if err != nil {
		t.Fatalf("database.Create: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("database.Close: %v", err)
		}
	})

	t.Setenv(hsdInteropMaxBlockFileSizeEnv, "1073741824")
	if err := applyHsdInteropDatabaseOverrides(db); err != nil {
		t.Fatalf("applyHsdInteropDatabaseOverrides: %v", err)
	}
	t.Setenv(hsdInteropPruneTargetEnv, "536870912")
	if _, err := hsdInteropPruneTarget(db, 1536); err == nil {
		t.Fatal("prune target below active rollover size returned nil error")
	}
}
