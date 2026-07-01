// Copyright (c) 2024-2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"testing"

	"github.com/blinklabs-io/handshake-node/chaincfg"
)

func TestReservedNameDBLookup(t *testing.T) {
	comHash := hashName([]byte("com"))
	entry, ok := reservedNameDB.get(comHash)
	if !ok {
		t.Fatal("reservedNameDB missing com")
	}
	if entry.name != "com" || entry.target != "com." || !entry.root {
		t.Fatalf("unexpected com entry: %+v", entry)
	}
	if entry.value != 30585353787 {
		t.Fatalf("com value = %d, want 30585353787", entry.value)
	}

	googleHash := hashName([]byte("google"))
	entry, ok = reservedNameDB.get(googleHash)
	if !ok {
		t.Fatal("reservedNameDB missing google")
	}
	if !entry.root || !entry.top100 {
		t.Fatalf("google flags not parsed: %+v", entry)
	}
	if entry.value != 660214983416 {
		t.Fatalf("google value = %d, want 660214983416", entry.value)
	}

	if reservedNameDB.has(hashName([]byte("zzzznotreserved"))) {
		t.Fatal("reservedNameDB unexpectedly contains zzzznotreserved")
	}
}

func TestReservedNameConsensusWindow(t *testing.T) {
	params := chaincfg.MainNetParams
	comHash := hashName([]byte("com"))

	if !isReservedNameHash(comHash, 1, &params) {
		t.Fatal("com should be reserved during claim period")
	}
	if isReservedNameHash(comHash, params.NameClaimPeriod, &params) {
		t.Fatal("com should not be claim-reserved after claim period")
	}

	params.NameNoReserved = true
	if isReservedNameHash(comHash, 1, &params) {
		t.Fatal("NameNoReserved should disable reserved lookup")
	}
}

func TestLockedNameDBLookup(t *testing.T) {
	params := chaincfg.MainNetParams
	comHash := hashName([]byte("com"))

	entry, ok := lockedNameDB.get(comHash)
	if !ok {
		t.Fatal("lockedNameDB missing com")
	}
	if entry.name != "com" || entry.target != "com." || !entry.root {
		t.Fatalf("unexpected com lockup entry: %+v", entry)
	}

	if isLockedUpNameHash(comHash, params.NameClaimPeriod-1, &params) {
		t.Fatal("lockup should not apply before claim period ends")
	}
	if !isLockedUpNameHash(comHash, params.NameClaimPeriod, &params) {
		t.Fatal("com should be locked after claim period")
	}
	if isLockedUpNameHash(hashName([]byte("zzzznotreserved")),
		params.NameClaimPeriod, &params) {

		t.Fatal("unlisted name should not be locked")
	}
}
