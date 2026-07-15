// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"testing"

	"github.com/blinklabs-io/handshake-node/hnsutil"
	"github.com/blinklabs-io/handshake-node/wire"
)

func TestIsNonstandardTransactionNativeAddresses(t *testing.T) {
	tests := []struct {
		name        string
		address     wire.Address
		covenant    wire.Covenant
		nonstandard bool
	}{
		{
			name:    "version 0 pubkey hash",
			address: wire.Address{Version: 0, Hash: make([]byte, 20)},
		},
		{
			name:    "version 0 script hash",
			address: wire.Address{Version: 0, Hash: make([]byte, 32)},
		},
		{
			name:        "invalid version 0 length",
			address:     wire.Address{Version: 0, Hash: make([]byte, 2)},
			nonstandard: true,
		},
		{
			name:        "reserved version 1",
			address:     wire.Address{Version: 1, Hash: make([]byte, 20)},
			nonstandard: true,
		},
		{
			name:        "reserved version 17",
			address:     wire.Address{Version: 17, Hash: make([]byte, 20)},
			nonstandard: true,
		},
		{
			name:    "version 31 nulldata",
			address: wire.Address{Version: 31, Hash: make([]byte, 2)},
		},
		{
			name:        "unknown covenant",
			address:     wire.Address{Version: 0, Hash: make([]byte, 20)},
			covenant:    wire.Covenant{Type: wire.CovenantRevoke + 1},
			nonstandard: true,
		},
		{
			name:     "nulldata ignores unknown covenant",
			address:  wire.Address{Version: 31, Hash: make([]byte, 2)},
			covenant: wire.Covenant{Type: wire.CovenantRevoke + 1},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			msgTx := wire.NewMsgTx(1)
			msgTx.AddTxOut(wire.NewTxOut(1, test.address, test.covenant))
			got := isNonstandardTransaction(hnsutil.NewTx(msgTx))
			if got != test.nonstandard {
				t.Fatalf("isNonstandardTransaction() = %v, want %v", got,
					test.nonstandard)
			}
		})
	}
}
