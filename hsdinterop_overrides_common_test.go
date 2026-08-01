// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import "testing"

func TestPruneMiBToBytes(t *testing.T) {
	maxMiB := ^uint64(0) / bytesPerMiB
	tests := []struct {
		name     string
		pruneMiB uint64
		want     uint64
		wantErr  bool
	}{
		{
			name:     "disabled",
			pruneMiB: 0,
		},
		{
			name:     "typical",
			pruneMiB: 1536,
			want:     1536 * bytesPerMiB,
		},
		{
			name:     "maximum",
			pruneMiB: maxMiB,
			want:     maxMiB * bytesPerMiB,
		},
		{
			name:     "overflow",
			pruneMiB: maxMiB + 1,
			wantErr:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := pruneMiBToBytes(test.pruneMiB)
			if test.wantErr {
				if err == nil {
					t.Fatal("pruneMiBToBytes returned nil error")
				}
				return
			}
			if err != nil {
				t.Fatalf("pruneMiBToBytes: %v", err)
			}
			if got != test.want {
				t.Fatalf("pruneMiBToBytes = %d, want %d", got, test.want)
			}
		})
	}
}
