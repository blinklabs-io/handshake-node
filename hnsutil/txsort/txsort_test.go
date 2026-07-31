// Copyright (c) 2015-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package txsort_test

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/hnsutil/txsort"
	"github.com/blinklabs-io/handshake-node/wire"
)

func TestSortHighVersionAddressOutputs(t *testing.T) {
	lowAddr := wire.Address{Version: 17, Hash: []byte{0x01, 0x01}}
	highAddr := wire.Address{Version: 17, Hash: []byte{0x02, 0x02}}

	tx := wire.MsgTx{
		Version: 1,
		TxOut: []*wire.TxOut{
			wire.NewTxOut(1000, highAddr, wire.Covenant{}),
			wire.NewTxOut(1000, lowAddr, wire.Covenant{}),
		},
	}

	if txsort.IsSorted(&tx) {
		t.Fatal("IsSorted returned true for reverse v17 address order")
	}

	sortedTx := txsort.Sort(&tx)
	if !bytes.Equal(sortedTx.TxOut[0].Address.Hash, lowAddr.Hash) {
		t.Fatalf("Sort first output hash = %x, want %x",
			sortedTx.TxOut[0].Address.Hash, lowAddr.Hash)
	}
	if !bytes.Equal(tx.TxOut[0].Address.Hash, highAddr.Hash) {
		t.Fatalf("Sort mutated original first output hash to %x",
			tx.TxOut[0].Address.Hash)
	}

	txsort.InPlaceSort(&tx)
	if !txsort.IsSorted(&tx) {
		t.Fatal("InPlaceSort did not sort v17 address outputs")
	}
	if !bytes.Equal(tx.TxOut[0].Address.Hash, lowAddr.Hash) {
		t.Fatalf("InPlaceSort first output hash = %x, want %x",
			tx.TxOut[0].Address.Hash, lowAddr.Hash)
	}
}

func testHash(t *testing.T, value string) chainhash.Hash {
	t.Helper()

	hash, err := chainhash.NewHashFromStr(value)
	if err != nil {
		t.Fatalf("invalid test hash %q: %v", value, err)
	}
	return *hash
}

func testInput(hash chainhash.Hash, index uint32) *wire.TxIn {
	return wire.NewTxIn(wire.NewOutPoint(&hash, index), 0, nil)
}

func testOutput(value int64, addrByte, covenantByte byte) *wire.TxOut {
	return wire.NewTxOut(
		value,
		wire.Address{
			Version: 0,
			Hash:    bytes.Repeat([]byte{addrByte}, 20),
		},
		wire.Covenant{
			Type:  wire.CovenantOpen,
			Items: [][]byte{{covenantByte}},
		},
	)
}

// TestSort ensures transaction inputs and Handshake outputs are sorted
// deterministically by outpoint, value, address, and covenant.
func TestSort(t *testing.T) {
	hashA := testHash(t,
		"0000000000000000000000000000000000000000000000000000000000000001",
	)
	hashB := testHash(t,
		"0000000000000000000000000000000000000000000000000000000000000002",
	)

	want := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			testInput(hashA, 1),
			testInput(hashA, 2),
			testInput(hashB, 1),
		},
		TxOut: []*wire.TxOut{
			testOutput(100, 1, 1),
			testOutput(100, 1, 2),
			testOutput(100, 2, 1),
			testOutput(200, 1, 1),
		},
	}
	unsorted := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			testInput(hashB, 1),
			testInput(hashA, 2),
			testInput(hashA, 1),
		},
		TxOut: []*wire.TxOut{
			testOutput(200, 1, 1),
			testOutput(100, 2, 1),
			testOutput(100, 1, 2),
			testOutput(100, 1, 1),
		},
	}
	original := unsorted.Copy()

	if !txsort.IsSorted(want) {
		t.Fatal("IsSorted returned false for sorted Handshake transaction")
	}
	if txsort.IsSorted(unsorted) {
		t.Fatal("IsSorted returned true for unsorted Handshake transaction")
	}

	sorted := txsort.Sort(unsorted)
	if !reflect.DeepEqual(sorted, want) {
		t.Fatalf("Sort result does not match expected transaction:\ngot:  %#v\nwant: %#v",
			sorted, want)
	}
	if !reflect.DeepEqual(unsorted, original) {
		t.Fatal("Sort mutated the original transaction")
	}

	txsort.InPlaceSort(unsorted)
	if !reflect.DeepEqual(unsorted, want) {
		t.Fatalf("InPlaceSort result does not match expected transaction:\ngot:  %#v\nwant: %#v",
			unsorted, want)
	}
}
