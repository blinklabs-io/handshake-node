// Copyright (c) 2024-2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"testing"

	"github.com/blinklabs-io/handshake-node/chaincfg"
	"github.com/blinklabs-io/handshake-node/hnsutil"
)

func TestCalcBlockSubsidyMainNet(t *testing.T) {
	const interval = int32(170000)

	tests := []struct {
		name   string
		height int32
		want   int64
	}{
		{
			name:   "genesis",
			height: 0,
			want:   2000 * hnsutil.DooPerHNS,
		},
		{
			name:   "first post genesis block",
			height: 1,
			want:   2000 * hnsutil.DooPerHNS,
		},
		{
			name:   "last block before first halving",
			height: 169999,
			want:   2000 * hnsutil.DooPerHNS,
		},
		{
			name:   "first halving",
			height: 170000,
			want:   1000 * hnsutil.DooPerHNS,
		},
		{
			name:   "first block after first halving",
			height: 170001,
			want:   1000 * hnsutil.DooPerHNS,
		},
		{
			name:   "second halving",
			height: 2 * interval,
			want:   500 * hnsutil.DooPerHNS,
		},
		{
			name:   "last positive dollarydoo",
			height: 30 * interval,
			want:   1,
		},
		{
			name:   "zero after enough halvings",
			height: 31 * interval,
			want:   0,
		},
		{
			name:   "zero with shift count at int64 width",
			height: 64 * interval,
			want:   0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := CalcBlockSubsidy(test.height, &chaincfg.MainNetParams)
			if got != test.want {
				t.Fatalf("CalcBlockSubsidy(%d) = %d, want %d",
					test.height, got, test.want)
			}
		})
	}
}

func TestCalcBlockSubsidyRegressionNet(t *testing.T) {
	const interval = int32(2500)

	tests := []struct {
		name   string
		height int32
		want   int64
	}{
		{
			name:   "genesis",
			height: 0,
			want:   2000 * hnsutil.DooPerHNS,
		},
		{
			name:   "first post genesis block",
			height: 1,
			want:   2000 * hnsutil.DooPerHNS,
		},
		{
			name:   "last block before first halving",
			height: 2499,
			want:   2000 * hnsutil.DooPerHNS,
		},
		{
			name:   "first halving",
			height: 2500,
			want:   1000 * hnsutil.DooPerHNS,
		},
		{
			name:   "first block after first halving",
			height: 2501,
			want:   1000 * hnsutil.DooPerHNS,
		},
		{
			name:   "second halving",
			height: 2 * interval,
			want:   500 * hnsutil.DooPerHNS,
		},
		{
			name:   "last positive dollarydoo",
			height: 30 * interval,
			want:   1,
		},
		{
			name:   "zero after enough halvings",
			height: 31 * interval,
			want:   0,
		},
		{
			name:   "zero with shift count at int64 width",
			height: 64 * interval,
			want:   0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := CalcBlockSubsidy(test.height, &chaincfg.RegressionNetParams)
			if got != test.want {
				t.Fatalf("CalcBlockSubsidy(%d) = %d, want %d",
					test.height, got, test.want)
			}
		})
	}
}
