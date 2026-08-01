// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"fmt"
	"testing"
	"unsafe"

	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
)

func requireUrkelRootTreeMatches(t *testing.T, tree *urkelRootTree,
	values map[chainhash.Hash][]byte) {

	t.Helper()
	leaves := make([]urkelLeaf, 0, len(values))
	for key, value := range values {
		leaves = append(leaves, urkelLeaf{key: key, value: value})
	}
	want := calcUrkelRoot(leaves)
	if got := tree.rootHash(); got != want {
		t.Fatalf("compact root = %v, want %v", got, want)
	}
}

func TestUrkelRootTreeDifferential(t *testing.T) {
	const keyCount = 512

	keys := make([]chainhash.Hash, keyCount)
	order := make([]int, keyCount)
	state := uint64(0x9e3779b97f4a7c15)
	for i := range keys {
		for j := range keys[i] {
			state ^= state << 13
			state ^= state >> 7
			state ^= state << 17
			keys[i][j] = byte(state)
		}
		order[i] = i
	}
	for i := len(order) - 1; i > 0; i-- {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		j := int(state % uint64(i+1))
		order[i], order[j] = order[j], order[i]
	}

	var tree urkelRootTree
	values := make(map[chainhash.Hash][]byte, keyCount)
	for _, index := range order {
		value := []byte(fmt.Sprintf("value-%d", index))
		if err := tree.put(keys[index], value); err != nil {
			t.Fatalf("put key %d: %v", index, err)
		}
		values[keys[index]] = value
		requireUrkelRootTreeMatches(t, &tree, values)
	}

	if got := tree.leaves.len(); got != keyCount {
		t.Fatalf("leaf count = %d, want %d", got, keyCount)
	}
	if got := tree.internals.len(); got != keyCount-1 {
		t.Fatalf("internal count = %d, want %d", got, keyCount-1)
	}

	for index := 0; index < keyCount; index += 7 {
		value := []byte(fmt.Sprintf("updated-%d", index))
		if err := tree.put(keys[index], value); err != nil {
			t.Fatalf("update key %d: %v", index, err)
		}
		values[keys[index]] = value
		requireUrkelRootTreeMatches(t, &tree, values)
	}
	if got := tree.leaves.len(); got != keyCount {
		t.Fatalf("leaf count after updates = %d, want %d", got, keyCount)
	}
	if got := tree.internals.len(); got != keyCount-1 {
		t.Fatalf("internal count after updates = %d, want %d",
			got, keyCount-1)
	}
}

func TestUrkelRootTreeCollisionDepths(t *testing.T) {
	for _, bit := range []int{0, 7, 8, 127, 254, 255} {
		t.Run(fmt.Sprintf("bit_%d", bit), func(t *testing.T) {
			var first, second chainhash.Hash
			urkelSetBit(second[:], bit)

			var tree urkelRootTree
			if err := tree.put(first, []byte("first")); err != nil {
				t.Fatalf("put first: %v", err)
			}
			if err := tree.put(second, []byte("second")); err != nil {
				t.Fatalf("put second: %v", err)
			}
			requireUrkelRootTreeMatches(t, &tree,
				map[chainhash.Hash][]byte{
					first:  []byte("first"),
					second: []byte("second"),
				},
			)
		})
	}
}

func TestUrkelRootTreeRebuildReusesStorage(t *testing.T) {
	leaves := make([]urkelLeaf, 128)
	for i := range leaves {
		leaves[i].key[0] = byte(i)
		leaves[i].value = []byte{byte(i)}
	}

	var tree urkelRootTree
	if err := tree.rebuild(leaves); err != nil {
		t.Fatalf("first rebuild: %v", err)
	}
	leafStorage := unsafe.SliceData(tree.leaves.chunks[0])
	internalStorage := unsafe.SliceData(tree.internals.chunks[0])
	want := tree.rootHash()

	for i, j := 0, len(leaves)-1; i < j; i, j = i+1, j-1 {
		leaves[i], leaves[j] = leaves[j], leaves[i]
	}
	if err := tree.rebuild(leaves); err != nil {
		t.Fatalf("second rebuild: %v", err)
	}
	if unsafe.SliceData(tree.leaves.chunks[0]) != leafStorage {
		t.Fatal("rebuild replaced sufficient leaf storage")
	}
	if unsafe.SliceData(tree.internals.chunks[0]) != internalStorage {
		t.Fatal("rebuild replaced sufficient internal storage")
	}
	if got := tree.rootHash(); got != want {
		t.Fatalf("rebuilt root = %v, want %v", got, want)
	}
}

func TestUrkelRootStoreGrowthPreservesChunks(t *testing.T) {
	var store urkelRootStore[urkelRootLeaf]
	for range urkelRootChunkSize {
		store.append(urkelRootLeaf{})
	}
	firstChunk := unsafe.SliceData(store.chunks[0])

	store.append(urkelRootLeaf{})
	if got := len(store.chunks); got != 2 {
		t.Fatalf("chunk count = %d, want 2", got)
	}
	if unsafe.SliceData(store.chunks[0]) != firstChunk {
		t.Fatal("growth replaced existing node chunk")
	}
}

func TestUrkelRootTreeNodeSizes(t *testing.T) {
	if got := unsafe.Sizeof(urkelRootLeaf{}); got != 64 {
		t.Fatalf("urkelRootLeaf size = %d, want 64", got)
	}
	if got := unsafe.Sizeof(urkelRootInternal{}); got != 48 {
		t.Fatalf("urkelRootInternal size = %d, want 48", got)
	}
}
