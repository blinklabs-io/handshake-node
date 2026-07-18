// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mining

import (
	"encoding/hex"
	"testing"

	"github.com/blinklabs-io/handshake-node/blockchain"
	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/hnsutil"
	"github.com/blinklabs-io/handshake-node/wire"
)

// hexToBytes converts the passed hex string into bytes and will panic if there
// is an error.  This is only provided for the hard-coded constants so errors in
// the source code can be detected. It will only (and must only) be called with
// hard-coded values.
func hexToBytes(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("invalid hex in source file: " + s)
	}
	return b
}

// newUtxoViewpoint returns a new utxo view populated with outputs of the
// provided source transactions as if there were available at the respective
// block height specified in the heights slice.  The length of the source txns
// and source tx heights must match or it will panic.
func newUtxoViewpoint(sourceTxns []*wire.MsgTx, sourceTxHeights []int32) *blockchain.UtxoViewpoint {
	if len(sourceTxns) != len(sourceTxHeights) {
		panic("each transaction must have its block height specified")
	}

	view := blockchain.NewUtxoViewpoint()
	for i, tx := range sourceTxns {
		view.AddTxOuts(hnsutil.NewTx(tx), sourceTxHeights[i])
	}
	return view
}

// TestCalcPriority ensures the priority calculations work as intended.
func TestCalcPriority(t *testing.T) {
	// commonSourceTx1 is a valid transaction used in the tests below as an
	// input to transactions that are having their priority calculated.
	//
	// From block 7 in main blockchain.
	// tx 0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9
	commonSourceTx1 := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{
				Hash:  chainhash.Hash{},
				Index: wire.MaxPrevOutIndex,
			},
			Sequence: 0xffffffff,
			Witness:  [][]byte{hexToBytes("04ffff001d0134")},
		}},
		TxOut: []*wire.TxOut{{
			Value:   5000000000,
			Address: wire.Address{Version: 1, Hash: []byte{0x00, 0x00}},
		}},
		LockTime: 0,
	}

	// commonRedeemTx1 is a valid transaction used in the tests below as the
	// transaction to calculate the priority for.
	//
	// It originally came from block 170 in main blockchain.
	commonRedeemTx1 := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{
				Hash:  commonSourceTx1.TxHash(),
				Index: 0,
			},
			Sequence: 0xffffffff,
		}},
		TxOut: []*wire.TxOut{{
			Value:   1000000000,
			Address: wire.Address{Version: 1, Hash: []byte{0x00, 0x00}},
		}, {
			Value:   4000000000,
			Address: wire.Address{Version: 1, Hash: []byte{0x00, 0x00}},
		}},
		LockTime: 0,
	}

	priorityDenom := commonRedeemTx1.SerializeSize() -
		41*len(commonRedeemTx1.TxIn)
	expectedPriority := func(inputHeight, nextHeight int32) float64 {
		age := nextHeight - inputHeight
		return float64(commonSourceTx1.TxOut[0].Value*int64(age)) /
			float64(priorityDenom)
	}

	tests := []struct {
		name       string                    // test description
		tx         *wire.MsgTx               // tx to calc priority for
		utxoView   *blockchain.UtxoViewpoint // inputs to tx
		nextHeight int32                     // height for priority calc
		want       float64                   // expected priority
	}{
		{
			name: "one height 7 input, prio tx height 169",
			tx:   commonRedeemTx1,
			utxoView: newUtxoViewpoint([]*wire.MsgTx{commonSourceTx1},
				[]int32{7}),
			nextHeight: 169,
			want:       expectedPriority(7, 169),
		},
		{
			name: "one height 100 input, prio tx height 169",
			tx:   commonRedeemTx1,
			utxoView: newUtxoViewpoint([]*wire.MsgTx{commonSourceTx1},
				[]int32{100}),
			nextHeight: 169,
			want:       expectedPriority(100, 169),
		},
		{
			name: "one height 7 input, prio tx height 100000",
			tx:   commonRedeemTx1,
			utxoView: newUtxoViewpoint([]*wire.MsgTx{commonSourceTx1},
				[]int32{7}),
			nextHeight: 100000,
			want:       expectedPriority(7, 100000),
		},
		{
			name: "one height 100 input, prio tx height 100000",
			tx:   commonRedeemTx1,
			utxoView: newUtxoViewpoint([]*wire.MsgTx{commonSourceTx1},
				[]int32{100}),
			nextHeight: 100000,
			want:       expectedPriority(100, 100000),
		},
	}

	for i, test := range tests {
		got := CalcPriority(test.tx, test.utxoView, test.nextHeight)
		if got != test.want {
			t.Errorf("CalcPriority #%d (%q): unexpected priority "+
				"got %v want %v", i, test.name, got, test.want)
			continue
		}
	}
}
