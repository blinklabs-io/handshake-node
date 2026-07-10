// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package hnsutil_test

import (
	"bytes"
	"io"
	"reflect"
	"testing"

	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/hnsutil"
	"github.com/blinklabs-io/handshake-node/wire"
	"github.com/davecgh/go-spew/spew"
)

// TestTx tests the API for Tx.
func TestTx(t *testing.T) {
	testTx := Block100000.Transactions[0]
	tx := hnsutil.NewTx(testTx)

	// Ensure we get the same data back out.
	if msgTx := tx.MsgTx(); !reflect.DeepEqual(msgTx, testTx) {
		t.Errorf("MsgTx: mismatched MsgTx - got %v, want %v",
			spew.Sdump(msgTx), spew.Sdump(testTx))
	}

	// Ensure transaction index set and get work properly.
	wantIndex := 0
	tx.SetIndex(0)
	if gotIndex := tx.Index(); gotIndex != wantIndex {
		t.Errorf("Index: mismatched index - got %v, want %v",
			gotIndex, wantIndex)
	}

	// Hash for block 100,000 transaction 0 using the Handshake tx hash.
	wantHashStr := "81001784062977be7635ae5333ab0d6fc014a1dc0ff1928968f7365ef4f8810c"
	wantHash, err := chainhash.NewHashFromStr(wantHashStr)
	if err != nil {
		t.Errorf("NewHashFromStr: %v", err)
	}

	// Request the hash multiple times to test generation and caching.
	for i := 0; i < 2; i++ {
		hash := tx.Hash()
		if !hash.IsEqual(wantHash) {
			t.Errorf("Hash #%d mismatched hash - got %v, want %v", i,
				hash, wantHash)
		}
	}
}

// TestNewTxFromBytes tests creation of a Tx from serialized bytes.
func TestNewTxFromBytes(t *testing.T) {
	// Serialize the test transaction.
	testTx := Block100000.Transactions[0]
	var testTxBuf bytes.Buffer
	err := testTx.Serialize(&testTxBuf)
	if err != nil {
		t.Errorf("Serialize: %v", err)
	}
	testTxBytes := testTxBuf.Bytes()

	// Create a new transaction from the serialized bytes.
	tx, err := hnsutil.NewTxFromBytes(testTxBytes)
	if err != nil {
		t.Errorf("NewTxFromBytes: %v", err)
		return
	}

	// Ensure the generated MsgTx is correct.
	if msgTx := tx.MsgTx(); !reflect.DeepEqual(msgTx, testTx) {
		t.Errorf("MsgTx: mismatched MsgTx - got %v, want %v",
			spew.Sdump(msgTx), spew.Sdump(testTx))
	}

	assertCachedTxHashes(t, tx, testTx)
}

func TestNewTxFromBytesRejectsTrailingBytesAndCachesCopy(t *testing.T) {
	testTx := Block100000.Transactions[0]
	var testTxBuf bytes.Buffer
	if err := testTx.Serialize(&testTxBuf); err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	serializedTx := append([]byte(nil), testTxBuf.Bytes()...)
	tx, err := hnsutil.NewTxFromBytes(serializedTx)
	if err != nil {
		t.Fatalf("NewTxFromBytes: %v", err)
	}

	for i := range serializedTx {
		serializedTx[i] ^= 0xff
	}

	assertCachedTxHashes(t, tx, testTx)

	trailingTx := append(testTxBuf.Bytes(), 0xff, 0x00, 0x01)
	if _, err := hnsutil.NewTxFromBytes(trailingTx); err == nil {
		t.Fatalf("expected trailing bytes to be rejected")
	}
}

func assertCachedTxHashes(t *testing.T, tx *hnsutil.Tx, msgTx *wire.MsgTx) {
	t.Helper()

	wantHash := msgTx.TxHash()
	for i := 0; i < 2; i++ {
		if gotHash := tx.Hash(); !gotHash.IsEqual(&wantHash) {
			t.Fatalf("Hash #%d: got %v, want %v",
				i, gotHash, wantHash)
		}
	}

	wantWitnessHash := msgTx.WitnessHash()
	for i := 0; i < 2; i++ {
		if gotHash := tx.WitnessHash(); !gotHash.IsEqual(&wantWitnessHash) {
			t.Fatalf("WitnessHash #%d: got %v, want %v",
				i, gotHash, wantWitnessHash)
		}
	}
}

// TestTxErrors tests the error paths for the Tx API.
func TestTxErrors(t *testing.T) {
	// Serialize the test transaction.
	testTx := Block100000.Transactions[0]
	var testTxBuf bytes.Buffer
	err := testTx.Serialize(&testTxBuf)
	if err != nil {
		t.Errorf("Serialize: %v", err)
	}
	testTxBytes := testTxBuf.Bytes()

	// Truncate the transaction byte buffer to force errors.
	shortBytes := testTxBytes[:4]
	_, err = hnsutil.NewTxFromBytes(shortBytes)
	if err != io.EOF {
		t.Errorf("NewTxFromBytes: did not get expected error - "+
			"got %v, want %v", err, io.EOF)
	}
}

// TestTxHasWitness tests the HasWitness() method.
func TestTxHasWitness(t *testing.T) {
	for i, msgTx := range Block100000.Transactions {
		tx := hnsutil.NewTx(msgTx)

		tx.WitnessHash() // Populate the witness hash cache.
		got := tx.HasWitness()
		want := msgTx.HasWitness()
		if got != want {
			t.Errorf("HasWitness #%d: got %v, want %v", i, got, want)
		}
	}
}

// TestTxWitnessHash tests the WitnessHash() method.
func TestTxWitnessHash(t *testing.T) {
	for i, msgTx := range Block100000.Transactions {
		tx := hnsutil.NewTx(msgTx)
		want := msgTx.WitnessHash()
		if !tx.WitnessHash().IsEqual(&want) {
			t.Errorf("WitnessHash #%d: got %v, want %v",
				i, tx.WitnessHash(), want)
		}
	}
}
