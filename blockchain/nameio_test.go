// Copyright (c) 2024-2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"bytes"
	"testing"

	"github.com/blinklabs-io/handshake-node/chaincfg"
	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/database"
	"github.com/blinklabs-io/handshake-node/wire"
)

func TestFetchNameStateFound(t *testing.T) {
	chain := setupNameStateQueryChain(t, "namestatequeryfound")
	want := testNameStateForQuery("query")
	storeNameStateForQuery(t, chain, want)

	got, found, err := chain.FetchNameState([]byte("query"))
	if err != nil {
		t.Fatalf("FetchNameState: %v", err)
	}
	if !found {
		t.Fatal("FetchNameState: got found=false, want true")
	}
	if got == nil {
		t.Fatal("FetchNameState: got nil state")
	}
	assertNameStateView(t, got, want)
}

func TestFetchNameStateMissing(t *testing.T) {
	chain := setupNameStateQueryChain(t, "namestatequerymissing")

	got, found, err := chain.FetchNameState([]byte("missing"))
	if err != nil {
		t.Fatalf("FetchNameState: %v", err)
	}
	if found || got != nil {
		t.Fatalf("FetchNameState: got state=%+v, found=%v, want nil, false",
			got, found)
	}
}

func TestFetchNameStateInvalidName(t *testing.T) {
	chain := setupNameStateQueryChain(t, "namestatequeryinvalid")

	got, found, err := chain.FetchNameState([]byte("Invalid"))
	if err == nil {
		t.Fatal("FetchNameState: expected invalid name error")
	}
	if found || got != nil {
		t.Fatalf("FetchNameState: got state=%+v, found=%v, want nil, false",
			got, found)
	}
}

func TestNameStateViewImmutableCopies(t *testing.T) {
	ns := testNameStateForQuery("mutable")
	view := newNameStateView(ns)

	wantName := []byte("mutable")
	wantData := []byte{0x01, 0x02, 0x03, 0x04}

	ns.name[0] = 'x'
	ns.data[0] = 0xff
	if got := view.NameBytes(); !bytes.Equal(got, wantName) {
		t.Fatalf("NameBytes after source mutation = %q, want %q",
			got, wantName)
	}
	if got := view.Data(); !bytes.Equal(got, wantData) {
		t.Fatalf("Data after source mutation = %x, want %x",
			got, wantData)
	}

	nameCopy := view.NameBytes()
	nameCopy[0] = 'y'
	if got := view.NameBytes(); !bytes.Equal(got, wantName) {
		t.Fatalf("NameBytes after copy mutation = %q, want %q",
			got, wantName)
	}

	dataCopy := view.Data()
	dataCopy[0] = 0xee
	if got := view.Data(); !bytes.Equal(got, wantData) {
		t.Fatalf("Data after copy mutation = %x, want %x",
			got, wantData)
	}
}

func TestFetchNameStateByHash(t *testing.T) {
	chain := setupNameStateQueryChain(t, "namestatequeryhash")
	nameHash := chainhash.Hash{0x2a, 0x7f}
	ns := newNameState(nameHash)
	ns.height = 101
	ns.renewal = 102
	ns.data = []byte("hash-only")
	storeNameStateForQuery(t, chain, ns)

	got, found, err := chain.FetchNameStateByHash(nameHash)
	if err != nil {
		t.Fatalf("FetchNameStateByHash: %v", err)
	}
	if !found {
		t.Fatal("FetchNameStateByHash: got found=false, want true")
	}
	if got.NameHash() != nameHash {
		t.Fatalf("NameHash = %v, want %v", got.NameHash(), nameHash)
	}
	if got.Name() != "" {
		t.Fatalf("Name = %q, want empty", got.Name())
	}
	if got.Height() != ns.height || got.Renewal() != ns.renewal {
		t.Fatalf("heights = (%d, %d), want (%d, %d)",
			got.Height(), got.Renewal(), ns.height, ns.renewal)
	}
	if !bytes.Equal(got.Data(), ns.data) {
		t.Fatalf("Data = %x, want %x", got.Data(), ns.data)
	}
}

func setupNameStateQueryChain(t *testing.T, dbName string) *BlockChain {
	t.Helper()

	chain, teardown, err := chainSetup(dbName, &chaincfg.RegressionNetParams)
	if err != nil {
		t.Fatalf("chainSetup: %v", err)
	}
	t.Cleanup(teardown)
	return chain
}

func storeNameStateForQuery(t *testing.T, chain *BlockChain, ns *nameState) {
	t.Helper()

	err := chain.db.Update(func(dbTx database.Tx) error {
		return dbPutNameState(dbTx, ns)
	})
	if err != nil {
		t.Fatalf("dbPutNameState: %v", err)
	}
}

func testNameStateForQuery(name string) *nameState {
	ns := newNameState(HashName([]byte(name)))
	ns.name = []byte(name)
	ns.height = 12
	ns.renewal = 34
	ns.owner = wire.OutPoint{
		Hash:  chainhash.Hash{0x01, 0x02, 0x03},
		Index: 4,
	}
	ns.value = 100
	ns.highest = 200
	ns.data = []byte{0x01, 0x02, 0x03, 0x04}
	ns.transfer = 40
	ns.revoked = 50
	ns.claimed = 60
	ns.renewals = 7
	ns.registered = true
	ns.expired = true
	ns.weak = true
	return ns
}

func assertNameStateView(t *testing.T, got *NameState, want *nameState) {
	t.Helper()

	if got.NameHash() != want.nameHash {
		t.Fatalf("NameHash = %v, want %v", got.NameHash(), want.nameHash)
	}
	if got.Name() != string(want.name) {
		t.Fatalf("Name = %q, want %q", got.Name(), want.name)
	}
	if !bytes.Equal(got.NameBytes(), want.name) {
		t.Fatalf("NameBytes = %q, want %q", got.NameBytes(), want.name)
	}
	if got.Height() != want.height {
		t.Fatalf("Height = %d, want %d", got.Height(), want.height)
	}
	if got.Renewal() != want.renewal {
		t.Fatalf("Renewal = %d, want %d", got.Renewal(), want.renewal)
	}
	if got.Owner() != want.owner {
		t.Fatalf("Owner = %v, want %v", got.Owner(), want.owner)
	}
	if got.Value() != want.value {
		t.Fatalf("Value = %d, want %d", got.Value(), want.value)
	}
	if got.Highest() != want.highest {
		t.Fatalf("Highest = %d, want %d", got.Highest(), want.highest)
	}
	if !bytes.Equal(got.Data(), want.data) {
		t.Fatalf("Data = %x, want %x", got.Data(), want.data)
	}
	if got.Transfer() != want.transfer {
		t.Fatalf("Transfer = %d, want %d", got.Transfer(), want.transfer)
	}
	if got.Revoked() != want.revoked {
		t.Fatalf("Revoked = %d, want %d", got.Revoked(), want.revoked)
	}
	if got.Claimed() != want.claimed {
		t.Fatalf("Claimed = %d, want %d", got.Claimed(), want.claimed)
	}
	if got.Renewals() != want.renewals {
		t.Fatalf("Renewals = %d, want %d", got.Renewals(), want.renewals)
	}
	if got.Registered() != want.registered {
		t.Fatalf("Registered = %v, want %v", got.Registered(),
			want.registered)
	}
	if got.Expired() != want.expired {
		t.Fatalf("Expired = %v, want %v", got.Expired(), want.expired)
	}
	if got.Weak() != want.weak {
		t.Fatalf("Weak = %v, want %v", got.Weak(), want.weak)
	}
}
