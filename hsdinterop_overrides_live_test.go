// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

//go:build hsdinterop

package main

import "testing"

func TestHsdInteropPruneTarget(t *testing.T) {
	tests := []struct {
		name     string
		pruneMiB uint64
		value    string
		want     uint64
		wantErr  bool
	}{
		{
			name:     "default calculation",
			pruneMiB: 2,
			want:     2 * 1024 * 1024,
		},
		{
			name:     "disabled pruning ignores override",
			pruneMiB: 0,
			value:    "invalid",
		},
		{
			name:     "test override",
			pruneMiB: 1536,
			value:    "8192",
			want:     8192,
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
			got, err := hsdInteropPruneTarget(test.pruneMiB)
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
