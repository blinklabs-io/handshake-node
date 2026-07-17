// Copyright (c) 2013-2016 The btcsuite developers
// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package bloom_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/hnsutil"
	"github.com/blinklabs-io/handshake-node/hnsutil/bloom"
	"github.com/blinklabs-io/handshake-node/wire"
)

var (
	testAddressHash = bytes.Repeat([]byte{0x11}, 20)
	testNameHash    = bytes.Repeat([]byte{0x22}, chainhash.HashSize)
	testRawName     = []byte("mainnet-ready")
	testWitnessItem = []byte("witness-only-data")
)

func newTestFilter(flags wire.BloomUpdateType) *bloom.Filter {
	return bloom.NewFilter(20, 0x12345678, 1e-9, flags)
}

func newTestTx() *hnsutil.Tx {
	var prevHash chainhash.Hash
	copy(prevHash[:], bytes.Repeat([]byte{0x33}, chainhash.HashSize))

	msgTx := wire.NewMsgTx(wire.TxVersion)
	msgTx.AddTxIn(wire.NewTxIn(
		wire.NewOutPoint(&prevHash, 7),
		wire.MaxTxInSequenceNum,
		[][]byte{testWitnessItem},
	))
	msgTx.AddTxOut(wire.NewTxOut(
		1_000_000,
		wire.Address{Version: 0, Hash: testAddressHash},
		wire.Covenant{
			Type: wire.CovenantOpen,
			Items: [][]byte{
				testNameHash,
				{0x00, 0x00, 0x00, 0x00},
				testRawName,
			},
		},
	))
	return hnsutil.NewTx(msgTx)
}

func newSpendingTx(outpoint *wire.OutPoint) *hnsutil.Tx {
	msgTx := wire.NewMsgTx(wire.TxVersion)
	msgTx.AddTxIn(wire.NewTxIn(
		outpoint,
		wire.MaxTxInSequenceNum,
		nil,
	))
	msgTx.AddTxOut(wire.NewTxOut(
		900_000,
		wire.Address{Version: 0, Hash: bytes.Repeat([]byte{0x44}, 20)},
		wire.Covenant{Type: wire.CovenantNone},
	))
	return hnsutil.NewTx(msgTx)
}

// TestFilterLarge ensures a maximum sized filter can be created.
func TestFilterLarge(t *testing.T) {
	f := bloom.NewFilter(100000000, 0, 0.01, wire.BloomUpdateNone)
	if len(f.MsgFilterLoad().Filter) > wire.MaxFilterLoadFilterSize {
		t.Fatalf(
			"filter size %d exceeds maximum %d",
			len(f.MsgFilterLoad().Filter),
			wire.MaxFilterLoadFilterSize,
		)
	}
}

// TestFilterLoad ensures loading and unloading filters preserves the wire
// representation and follows hsd's zero-hash-function behavior.
func TestFilterLoad(t *testing.T) {
	tests := []struct {
		name      string
		filter    *wire.MsgFilterLoad
		wantMatch bool
	}{
		{
			name: "normal filter",
			filter: &wire.MsgFilterLoad{
				Filter:    []byte{0x00},
				HashFuncs: 1,
			},
		},
		{
			name: "empty filter with funcs",
			filter: &wire.MsgFilterLoad{
				Filter:    []byte{},
				HashFuncs: 1,
			},
		},
		{
			name: "empty filter without funcs",
			filter: &wire.MsgFilterLoad{
				Filter:    []byte{},
				HashFuncs: 0,
			},
			wantMatch: true,
		},
		{
			name: "non-empty filter without funcs",
			filter: &wire.MsgFilterLoad{
				Filter:    []byte{0x00},
				HashFuncs: 0,
			},
			wantMatch: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wantHashFuncs := test.filter.HashFuncs
			f := bloom.LoadFilter(test.filter)
			if !f.IsLoaded() {
				t.Fatal("filter is not loaded")
			}
			for _, data := range [][]byte{nil, []byte("test")} {
				if got := f.Matches(data); got != test.wantMatch {
					t.Fatalf(
						"match result for %x = %v, want %v",
						data,
						got,
						test.wantMatch,
					)
				}
			}
			if got := f.MsgFilterLoad().HashFuncs; got != wantHashFuncs {
				t.Fatalf("hash funcs = %d, want preserved value %d", got, wantHashFuncs)
			}

			f.Unload()
			if f.IsLoaded() {
				t.Fatal("filter remains loaded after Unload")
			}
			if f.Matches([]byte("test")) {
				t.Fatal("unloaded filter matched data")
			}
		})
	}
}

// TestFilterInsert ensures inserted data matches and preserves the expected
// filterload wire representation.
func TestFilterInsert(t *testing.T) {
	tests := []struct {
		hex    string
		insert bool
	}{
		{"99108ad8ed9bb6274d3980bab5a85c048f0950c8", true},
		{"19108ad8ed9bb6274d3980bab5a85c048f0950c8", false},
		{"b5a2c786d9ef4658287ced5914b37a1b4aa32eee", true},
		{"b9300670b4c5366e95b2699e8b18bc75e5f729c5", true},
	}

	f := bloom.NewFilter(3, 0, 0.01, wire.BloomUpdateAll)
	for i, test := range tests {
		data, err := hex.DecodeString(test.hex)
		if err != nil {
			t.Fatalf("vector %d: decode: %v", i, err)
		}
		if test.insert {
			f.Add(data)
		}
		if got := f.Matches(data); got != test.insert {
			t.Fatalf("vector %d: match = %v, want %v", i, got, test.insert)
		}
	}

	assertFilterEncoding(t, f, "03614e9b050000000000000001")
}

// TestFilterFPRange checks that out-of-range false positive targets are
// clamped to the supported range.
func TestFilterFPRange(t *testing.T) {
	tests := []struct {
		name   string
		hash   string
		want   string
		filter *bloom.Filter
	}{
		{
			name:   "above one",
			hash:   "41c05bdf71643267ded2cf037af2105a036621fcf46858bc1d48f052a01f9802",
			want:   "00000000000000000001",
			filter: bloom.NewFilter(1, 0, 20.9999999769, wire.BloomUpdateAll),
		},
		{
			name:   "zero",
			hash:   "41c05bdf71643267ded2cf037af2105a036621fcf46858bc1d48f052a01f9802",
			want:   "0566d97a91a91b0000000000000001",
			filter: bloom.NewFilter(1, 0, 0, wire.BloomUpdateAll),
		},
		{
			name:   "negative",
			hash:   "41c05bdf71643267ded2cf037af2105a036621fcf46858bc1d48f052a01f9802",
			want:   "0566d97a91a91b0000000000000001",
			filter: bloom.NewFilter(1, 0, -1, wire.BloomUpdateAll),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			hash, err := chainhash.NewHashFromStr(test.hash)
			if err != nil {
				t.Fatalf("parse hash: %v", err)
			}
			test.filter.AddHash(hash)
			assertFilterEncoding(t, test.filter, test.want)
		})
	}
}

// TestFilterInsertWithTweak checks deterministic filtering with a non-zero
// tweak.
func TestFilterInsertWithTweak(t *testing.T) {
	tests := []struct {
		hex    string
		insert bool
	}{
		{"99108ad8ed9bb6274d3980bab5a85c048f0950c8", true},
		{"19108ad8ed9bb6274d3980bab5a85c048f0950c8", false},
		{"b5a2c786d9ef4658287ced5914b37a1b4aa32eee", true},
		{"b9300670b4c5366e95b2699e8b18bc75e5f729c5", true},
	}

	f := bloom.NewFilter(3, 2147483649, 0.01, wire.BloomUpdateAll)
	for i, test := range tests {
		data, err := hex.DecodeString(test.hex)
		if err != nil {
			t.Fatalf("vector %d: decode: %v", i, err)
		}
		if test.insert {
			f.Add(data)
		}
		if got := f.Matches(data); got != test.insert {
			t.Fatalf("vector %d: match = %v, want %v", i, got, test.insert)
		}
	}

	assertFilterEncoding(t, f, "03ce4299050000000100008001")
}

// TestFilterInsertKey ensures public keys and their hashes can be inserted.
func TestFilterInsertKey(t *testing.T) {
	wif, err := hnsutil.DecodeWIF(
		"5Kg1gnAjaLfKiwhhPpGS3QfRg2m6awQvaj98JCZBZQ5SuS2F15C",
	)
	if err != nil {
		t.Fatalf("decode WIF: %v", err)
	}

	f := bloom.NewFilter(2, 0, 0.001, wire.BloomUpdateAll)
	f.Add(wif.SerializePubKey())
	f.Add(hnsutil.Hash160(wif.SerializePubKey()))
	assertFilterEncoding(t, f, "038fc16b080000000000000001")
}

// TestFilterMatchTxAndUpdate exercises the elements used by hsd's
// TX.testAndMaybeUpdate at commit 9f013c1cb7f92edf94db69fbd69daf34adf655fb:
// transaction hashes, native address hashes, non-empty covenant items, and
// serialized previous outpoints.  Witness items are not filter elements.
func TestFilterMatchTxAndUpdate(t *testing.T) {
	tx := newTestTx()

	t.Run("transaction hash", func(t *testing.T) {
		f := newTestFilter(wire.BloomUpdateNone)
		f.AddHash(tx.Hash())
		if !f.MatchTxAndUpdate(tx) {
			t.Fatal("transaction hash did not match")
		}
	})

	t.Run("native address and spending outpoint", func(t *testing.T) {
		f := newTestFilter(wire.BloomUpdateNone)
		f.Add(testAddressHash)
		if !f.MatchTxAndUpdate(tx) {
			t.Fatal("native address hash did not match")
		}

		outpoint := wire.NewOutPoint(tx.Hash(), 0)
		if !f.MatchesOutPoint(outpoint) {
			t.Fatal("matched output outpoint was not added")
		}
		if !f.MatchTxAndUpdate(newSpendingTx(outpoint)) {
			t.Fatal("transaction spending matched output did not match")
		}
	})

	t.Run("multiple matching output outpoints", func(t *testing.T) {
		multiOutputTx := newTestTx()
		multiOutputTx.MsgTx().AddTxOut(wire.NewTxOut(
			2_000_000,
			wire.Address{Version: 0, Hash: testAddressHash},
			wire.Covenant{Type: wire.CovenantNone},
		))
		f := newTestFilter(wire.BloomUpdateNone)
		f.Add(testAddressHash)
		if !f.MatchTxAndUpdate(multiOutputTx) {
			t.Fatal("native address hash did not match")
		}

		for i := uint32(0); i < 2; i++ {
			outpoint := wire.NewOutPoint(multiOutputTx.Hash(), i)
			if !f.MatchesOutPoint(outpoint) {
				t.Fatalf("matched output %d outpoint was not added", i)
			}
		}
	})

	t.Run("covenant item", func(t *testing.T) {
		f := newTestFilter(wire.BloomUpdateNone)
		f.Add(testRawName)
		if !f.MatchTxAndUpdate(tx) {
			t.Fatal("covenant item did not match")
		}
		if !f.MatchesOutPoint(wire.NewOutPoint(tx.Hash(), 0)) {
			t.Fatal("covenant-matched output outpoint was not added")
		}
	})

	t.Run("previous outpoint", func(t *testing.T) {
		f := newTestFilter(wire.BloomUpdateNone)
		f.AddOutPoint(&tx.MsgTx().TxIn[0].PreviousOutPoint)
		if !f.MatchTxAndUpdate(tx) {
			t.Fatal("previous outpoint did not match")
		}
	})

	t.Run("witness item excluded", func(t *testing.T) {
		f := newTestFilter(wire.BloomUpdateNone)
		f.Add(testWitnessItem)
		if f.MatchTxAndUpdate(tx) {
			t.Fatal("witness-only data matched")
		}
	})

	t.Run("empty covenant item excluded", func(t *testing.T) {
		emptyItemTx := newTestTx()
		emptyItemTx.MsgTx().TxOut[0].Covenant.Items = [][]byte{nil}
		f := newTestFilter(wire.BloomUpdateNone)
		f.Add(nil)
		if f.MatchTxAndUpdate(emptyItemTx) {
			t.Fatal("empty covenant item matched")
		}
	})

	t.Run("unrelated data", func(t *testing.T) {
		f := newTestFilter(wire.BloomUpdateNone)
		f.Add([]byte("not-in-transaction"))
		if f.MatchTxAndUpdate(tx) {
			t.Fatal("unrelated data matched")
		}
	})
}

// TestFilterOutputUpdateFlags documents hsd's mainnet behavior: all three
// legacy wire update values add a matched Handshake output's outpoint.
func TestFilterOutputUpdateFlags(t *testing.T) {
	tx := newTestTx()
	tests := []struct {
		name  string
		flags wire.BloomUpdateType
	}{
		{"none", wire.BloomUpdateNone},
		{"all", wire.BloomUpdateAll},
		{"pubkey only", wire.BloomUpdateP2PubkeyOnly},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newTestFilter(test.flags)
			f.Add(testAddressHash)
			if !f.MatchTxAndUpdate(tx) {
				t.Fatal("address hash did not match")
			}
			if !f.MatchesOutPoint(wire.NewOutPoint(tx.Hash(), 0)) {
				t.Fatal("matched outpoint was not added")
			}
			if got := f.MsgFilterLoad().Flags; got != test.flags {
				t.Fatalf("wire update flag = %d, want %d", got, test.flags)
			}
		})
	}
}

func TestFilterReload(t *testing.T) {
	f := bloom.NewFilter(10, 0, 0.000001, wire.BloomUpdateAll)
	bFilter := bloom.LoadFilter(f.MsgFilterLoad())
	if bFilter.MsgFilterLoad() == nil {
		t.Fatal("loaded filter is nil")
	}

	tests := []struct {
		name      string
		filter    *wire.MsgFilterLoad
		wantMatch bool
	}{
		{name: "nil filter"},
		{
			name: "empty filter with funcs",
			filter: &wire.MsgFilterLoad{
				Filter:    []byte{},
				HashFuncs: 3,
			},
		},
		{
			name: "empty filter without funcs",
			filter: &wire.MsgFilterLoad{
				Filter:    []byte{},
				HashFuncs: 0,
			},
			wantMatch: true,
		},
		{
			name: "non-empty filter without funcs",
			filter: &wire.MsgFilterLoad{
				Filter:    []byte{0x00},
				HashFuncs: 0,
			},
			wantMatch: true,
		},
		{
			name: "normal filter",
			filter: &wire.MsgFilterLoad{
				Filter:    []byte{0x00},
				HashFuncs: 1,
			},
			wantMatch: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var wantHashFuncs uint32
			if test.filter != nil {
				wantHashFuncs = test.filter.HashFuncs
			}
			bFilter.Reload(test.filter)
			if test.filter == nil {
				if bFilter.MsgFilterLoad() != nil {
					t.Fatal("expected nil filter")
				}
				if bFilter.Matches([]byte("test data")) {
					t.Fatal("unloaded filter matched data")
				}
				return
			}

			bFilter.Add([]byte("test data"))
			if got := bFilter.Matches([]byte("test data")); got != test.wantMatch {
				t.Fatalf("match result = %v, want %v", got, test.wantMatch)
			}
			if got := bFilter.MsgFilterLoad().HashFuncs; got != wantHashFuncs {
				t.Fatalf("hash funcs = %d, want preserved value %d", got, wantHashFuncs)
			}
		})
	}
}

func assertFilterEncoding(t *testing.T, f *bloom.Filter, wantHex string) {
	t.Helper()

	want, err := hex.DecodeString(wantHex)
	if err != nil {
		t.Fatalf("decode expected filter: %v", err)
	}

	var got bytes.Buffer
	if err := f.MsgFilterLoad().BtcEncode(
		&got,
		wire.ProtocolVersion,
		wire.LatestEncoding,
	); err != nil {
		t.Fatalf("encode filter: %v", err)
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatalf("encoded filter = %x, want %x", got.Bytes(), want)
	}
}
