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

func TestNameStateDBAccessors(t *testing.T) {
	chain := setupNameStateQueryChain(t, "namestatequery")

	all, err := chain.FetchAllNameStates()
	if err != nil {
		t.Fatalf("FetchAllNameStates empty: %v", err)
	}
	if len(all) != 0 {
		t.Fatalf("FetchAllNameStates empty len = %d, want 0", len(all))
	}

	root, err := chain.NameRoot()
	if err != nil {
		t.Fatalf("NameRoot empty: %v", err)
	}
	if root != (chainhash.Hash{}) {
		t.Fatalf("NameRoot before store = %v, want zero hash", root)
	}

	missing, found, err := chain.FetchNameState([]byte("missing"))
	if err != nil {
		t.Fatalf("FetchNameState missing: %v", err)
	}
	if found || missing != nil {
		t.Fatalf("FetchNameState missing got state=%+v, found=%v, want nil, false",
			missing, found)
	}

	query := testNameStateForQuery("query")
	hashOnly := newNameState(chainhash.Hash{0x2a, 0x7f})
	hashOnly.height = 101
	hashOnly.renewal = 102
	hashOnly.data = []byte("hash-only")
	first := testNameStateForQuery("first")
	second := testNameStateForQuery("second")
	storeNameStateForQuery(t, chain, query)
	storeNameStateForQuery(t, chain, hashOnly)
	storeNameStateForQuery(t, chain, second)
	storeNameStateForQuery(t, chain, first)

	got, found, err := chain.FetchNameState([]byte("query"))
	if err != nil {
		t.Fatalf("FetchNameState query: %v", err)
	}
	if !found {
		t.Fatal("FetchNameState query got found=false, want true")
	}
	if got == nil {
		t.Fatal("FetchNameState query got nil state")
	}
	assertNameStateView(t, got, query)

	got, found, err = chain.FetchNameStateByHash(hashOnly.nameHash)
	if err != nil {
		t.Fatalf("FetchNameStateByHash: %v", err)
	}
	if !found {
		t.Fatal("FetchNameStateByHash got found=false, want true")
	}
	assertNameStateView(t, got, hashOnly)

	all, err = chain.FetchAllNameStates()
	if err != nil {
		t.Fatalf("FetchAllNameStates: %v", err)
	}
	if len(all) != 4 {
		t.Fatalf("FetchAllNameStates len = %d, want 4", len(all))
	}
	for i := 1; i < len(all); i++ {
		prevHash := all[i-1].NameHash()
		nextHash := all[i].NameHash()
		if bytes.Compare(prevHash[:], nextHash[:]) > 0 {
			t.Fatalf("FetchAllNameStates returned unsorted hashes: %v > %v",
				prevHash, nextHash)
		}
	}

	wantByHash := map[chainhash.Hash]*nameState{
		query.nameHash:    query,
		hashOnly.nameHash: hashOnly,
		first.nameHash:    first,
		second.nameHash:   second,
	}
	for _, state := range all {
		want, ok := wantByHash[state.NameHash()]
		if !ok {
			t.Fatalf("unexpected name state hash %v", state.NameHash())
		}
		assertNameStateView(t, state, want)
	}

	view := newLazyNameBlockView(chain)
	err = chain.db.View(func(dbTx database.Tx) error {
		got, err := view.get(dbTx, query.nameHash)
		if err != nil {
			return err
		}
		if !nameStatesEqual(got, query) {
			t.Fatalf("loaded state mismatch")
		}
		if _, ok := view.states[second.nameHash]; ok {
			t.Fatalf("lazy view loaded untouched state")
		}

		missingHash := chainhash.Hash{0x42}
		missing, err := view.get(dbTx, missingHash)
		if err != nil {
			return err
		}
		if !missing.isNull() {
			t.Fatalf("missing state is not null: %+v", missing)
		}
		if _, ok := view.loaded[missingHash]; !ok {
			t.Fatalf("missing state was not marked loaded")
		}

		return nil
	})
	if err != nil {
		t.Fatalf("lazy get: %v", err)
	}

	wantRoot := chainhash.Hash{0x5a, 0xc3}
	err = chain.db.Update(func(dbTx database.Tx) error {
		return dbPutNameRoot(dbTx, wantRoot)
	})
	if err != nil {
		t.Fatalf("dbPutNameRoot: %v", err)
	}

	root, err = chain.NameRoot()
	if err != nil {
		t.Fatalf("NameRoot after store: %v", err)
	}
	if root != wantRoot {
		t.Fatalf("NameRoot after store = %v, want %v", root, wantRoot)
	}
}

func TestFetchNameStateInvalidName(t *testing.T) {
	chain := &BlockChain{}

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

func TestLazyNameBlockViewRequiresDBForUnloadedState(t *testing.T) {
	chain := &BlockChain{}
	view := newLazyNameBlockView(chain)

	if _, err := view.get(nil, chainhash.Hash{0x99}); err == nil {
		t.Fatal("lazy get without dbTx: expected error")
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
