// Copyright (c) 2024-2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"testing"

	"github.com/blinklabs-io/handshake-node/chaincfg"
)

func TestNormalizeAddressDefaultPorts(t *testing.T) {
	tests := []struct {
		name      string
		addr      string
		chain     *chaincfg.Params
		useWallet bool
		want      string
		wantErr   bool
	}{
		{
			name:  "mainnet node",
			addr:  "localhost",
			chain: &chaincfg.MainNetParams,
			want:  "localhost:12037",
		},
		{
			name:      "mainnet wallet",
			addr:      "localhost",
			chain:     &chaincfg.MainNetParams,
			useWallet: true,
			want:      "localhost:8332",
		},
		{
			name:  "regtest node",
			addr:  "localhost",
			chain: &chaincfg.RegressionNetParams,
			want:  "localhost:18334",
		},
		{
			name:    "explicit port",
			addr:    "localhost:1234",
			chain:   &chaincfg.MainNetParams,
			want:    "localhost:1234",
			wantErr: false,
		},
		{
			name:      "regtest wallet unsupported",
			addr:      "localhost",
			chain:     &chaincfg.RegressionNetParams,
			useWallet: true,
			wantErr:   true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := normalizeAddress(test.addr, test.chain, test.useWallet)
			if test.wantErr {
				if err == nil {
					t.Fatal("normalizeAddress: expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeAddress: %v", err)
			}
			if got != test.want {
				t.Fatalf("normalizeAddress: got %q, want %q",
					got, test.want)
			}
		})
	}
}
