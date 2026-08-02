// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"fmt"

	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
)

type urkelRootRef uint32

const (
	urkelRootLeafFlag  urkelRootRef = 1 << 31
	urkelRootIndexMask urkelRootRef = urkelRootLeafFlag - 1
	urkelRootChunkBits              = 16
	urkelRootChunkSize              = 1 << urkelRootChunkBits
	urkelRootChunkMask              = urkelRootChunkSize - 1
)

type urkelRootLeaf struct {
	key  chainhash.Hash
	hash chainhash.Hash
}

// urkelRootInternal stores only the prefix length.  The prefix bits are
// derived from representativeLeaf at the node's traversal depth.  All fields
// are pointer-free so the Go garbage collector does not scan the backing
// array.
type urkelRootInternal struct {
	hash               chainhash.Hash
	left               urkelRootRef
	right              urkelRootRef
	representativeLeaf urkelRootRef
	prefixBits         uint16
}

// urkelRootStore grows in fixed-size chunks so adding a name never copies and
// briefly retains an entire multi-hundred-MiB node array.  The instantiated
// chunk backing arrays are pointer-free.
type urkelRootStore[T any] struct {
	chunks [][]T
	count  int
}

func (s *urkelRootStore[T]) len() int {
	return s.count
}

func (s *urkelRootStore[T]) get(index int) T {
	return s.chunks[index>>urkelRootChunkBits][index&urkelRootChunkMask]
}

func (s *urkelRootStore[T]) set(index int, value T) {
	s.chunks[index>>urkelRootChunkBits][index&urkelRootChunkMask] = value
}

func (s *urkelRootStore[T]) append(value T) {
	index := s.count
	chunkIndex := index >> urkelRootChunkBits
	if chunkIndex == len(s.chunks) {
		s.chunks = append(s.chunks, make([]T, urkelRootChunkSize))
	}
	s.set(index, value)
	s.count++
}

func (s *urkelRootStore[T]) reset() {
	s.count = 0
}

// urkelRootTree is a compact mutable Urkel trie used only to maintain the
// current name root.  Proof construction continues to use the immutable
// urkelNode implementation.
type urkelRootTree struct {
	root      urkelRootRef
	leaves    urkelRootStore[urkelRootLeaf]
	internals urkelRootStore[urkelRootInternal]
}

func (r urkelRootRef) isLeaf() bool {
	return r&urkelRootLeafFlag != 0
}

func (r urkelRootRef) index() int {
	return int(r&urkelRootIndexMask) - 1
}

func makeUrkelRootRef(index int, leaf bool) (urkelRootRef, error) {
	if index < 0 || uint64(index) >= uint64(urkelRootIndexMask) {
		return 0, fmt.Errorf("compact Urkel node index %d exceeds limit", index)
	}
	ref := urkelRootRef(index + 1)
	if leaf {
		ref |= urkelRootLeafFlag
	}
	return ref, nil
}

func (t *urkelRootTree) leaf(ref urkelRootRef) urkelRootLeaf {
	return t.leaves.get(ref.index())
}

func (t *urkelRootTree) internal(ref urkelRootRef) urkelRootInternal {
	return t.internals.get(ref.index())
}

func (t *urkelRootTree) nodeHash(ref urkelRootRef) chainhash.Hash {
	if ref == 0 {
		return chainhash.Hash{}
	}
	if ref.isLeaf() {
		return t.leaf(ref).hash
	}
	return t.internal(ref).hash
}

func (t *urkelRootTree) representativeLeaf(ref urkelRootRef) urkelRootRef {
	if ref.isLeaf() {
		return ref
	}
	return t.internal(ref).representativeLeaf
}

func (t *urkelRootTree) internalPrefix(node urkelRootInternal,
	depth int) urkelBits {

	key := t.leaf(node.representativeLeaf).key
	return urkelBitsFromKey(key).slice(depth, depth+int(node.prefixBits))
}

func (t *urkelRootTree) addLeaf(key chainhash.Hash,
	value []byte) (urkelRootRef, error) {

	ref, err := makeUrkelRootRef(t.leaves.len(), true)
	if err != nil {
		return 0, err
	}
	t.leaves.append(urkelRootLeaf{
		key:  key,
		hash: hashUrkelValue(key, value),
	})
	return ref, nil
}

func (t *urkelRootTree) addInternal(prefix urkelBits, left,
	right urkelRootRef) (urkelRootRef, error) {

	if left == 0 || right == 0 {
		return 0, AssertError("compact Urkel internal has nil child")
	}
	if prefix.size < 0 || prefix.size >= urkelKeyBits {
		return 0, AssertError(fmt.Sprintf(
			"compact Urkel prefix length %d is invalid", prefix.size,
		))
	}
	ref, err := makeUrkelRootRef(t.internals.len(), false)
	if err != nil {
		return 0, err
	}
	t.internals.append(urkelRootInternal{
		hash:               hashUrkelInternal(prefix, t.nodeHash(left), t.nodeHash(right)),
		left:               left,
		right:              right,
		representativeLeaf: t.representativeLeaf(left),
		prefixBits:         uint16(prefix.size),
	})
	return ref, nil
}

func (t *urkelRootTree) addBranch(prefix urkelBits, x, y urkelRootRef,
	bit int) (urkelRootRef, error) {

	if bit == 0 {
		return t.addInternal(prefix, x, y)
	}
	return t.addInternal(prefix, y, x)
}

func (t *urkelRootTree) put(key chainhash.Hash, value []byte) error {
	root, err := t.putAt(t.root, key, value, 0)
	if err != nil {
		return err
	}
	t.root = root
	return nil
}

func (t *urkelRootTree) putAt(ref urkelRootRef, key chainhash.Hash,
	value []byte, depth int) (urkelRootRef, error) {

	if ref == 0 {
		return t.addLeaf(key, value)
	}

	if ref.isLeaf() {
		index := ref.index()
		leaf := t.leaves.get(index)
		if leaf.key == key {
			leaf.hash = hashUrkelValue(key, value)
			t.leaves.set(index, leaf)
			return ref, nil
		}

		prefix := urkelBitsFromKey(leaf.key).collide(key[:], depth)
		nextDepth := depth + prefix.size
		newLeaf, err := t.addLeaf(key, value)
		if err != nil {
			return 0, err
		}
		return t.addBranch(prefix, newLeaf, ref,
			urkelHasBit(key[:], nextDepth))
	}

	index := ref.index()
	node := t.internals.get(index)
	prefix := t.internalPrefix(node, depth)
	bits := prefix.count(key[:], depth)
	nextDepth := depth + bits
	bit := urkelHasBit(key[:], nextDepth)

	if bits != prefix.size {
		front, back := prefix.split(bits)
		node.prefixBits = uint16(back.size)
		node.hash = hashUrkelInternal(
			back,
			t.nodeHash(node.left),
			t.nodeHash(node.right),
		)
		t.internals.set(index, node)

		newLeaf, err := t.addLeaf(key, value)
		if err != nil {
			return 0, err
		}
		return t.addBranch(front, newLeaf, ref, bit)
	}

	var err error
	if bit == 0 {
		node.left, err = t.putAt(node.left, key, value, nextDepth+1)
	} else {
		node.right, err = t.putAt(node.right, key, value, nextDepth+1)
	}
	if err != nil {
		return 0, err
	}
	node.hash = hashUrkelInternal(
		prefix,
		t.nodeHash(node.left),
		t.nodeHash(node.right),
	)
	t.internals.set(index, node)
	return ref, nil
}

func (t *urkelRootTree) rebuild(leaves []urkelLeaf) error {
	t.leaves.reset()
	t.internals.reset()
	t.root = 0

	for _, leaf := range leaves {
		if err := t.put(leaf.key, leaf.value); err != nil {
			return err
		}
	}
	return nil
}

func (t *urkelRootTree) rootHash() chainhash.Hash {
	return t.nodeHash(t.root)
}
