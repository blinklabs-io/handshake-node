// Copyright (c) 2024-2026 Blink Labs Software
// Portions Copyright (c) 2018 Christopher Jeffrey (MIT License).
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"

	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"golang.org/x/crypto/blake2b"
)

const (
	urkelKeyBits       = chainhash.HashSize * 8
	maxUrkelProofValue = 0xffff
)

const (
	urkelProofTypeDeadend uint8 = iota
	urkelProofTypeShort
	urkelProofTypeCollision
	urkelProofTypeExists
	urkelProofTypeUnknown
)

type urkelLeaf struct {
	key   chainhash.Hash
	value []byte
}

type urkelBits struct {
	size int
	data chainhash.Hash
}

type urkelNode interface {
	hash() chainhash.Hash
}

type urkelLeafNode struct {
	key       chainhash.Hash
	value     []byte
	hashValue chainhash.Hash
}

type urkelInternalNode struct {
	prefix    urkelBits
	left      urkelNode
	right     urkelNode
	hashValue chainhash.Hash
}

type urkelProofNode struct {
	prefix urkelBits
	node   chainhash.Hash
}

// UrkelProof is an hsd-compatible inclusion or exclusion proof for the
// Handshake name tree.
type UrkelProof struct {
	typ       uint8
	depth     int
	nodes     []urkelProofNode
	prefix    urkelBits
	left      chainhash.Hash
	right     chainhash.Hash
	key       chainhash.Hash
	valueHash chainhash.Hash
	value     []byte
}

func buildUrkelTree(leaves []urkelLeaf) urkelNode {
	return buildUrkelTreeWithValues(leaves, true)
}

func buildUrkelRootTree(leaves []urkelLeaf) urkelNode {
	return buildUrkelTreeWithValues(leaves, false)
}

func buildUrkelTreeWithValues(leaves []urkelLeaf, keepValues bool) urkelNode {
	if len(leaves) == 0 {
		return nil
	}

	ordered := make([]urkelLeaf, len(leaves))
	copy(ordered, leaves)
	sort.Slice(ordered, func(i, j int) bool {
		return bytes.Compare(ordered[i].key[:], ordered[j].key[:]) < 0
	})

	var root urkelNode
	for _, leaf := range ordered {
		root = insertUrkelWithValues(root, leaf.key, leaf.value, 0, keepValues)
	}
	return root
}

func calcUrkelRoot(leaves []urkelLeaf) chainhash.Hash {
	root := buildUrkelTree(leaves)
	if root == nil {
		return chainhash.Hash{}
	}
	return root.hash()
}

func insertUrkel(node urkelNode, key chainhash.Hash, value []byte, depth int) urkelNode {
	return insertUrkelWithValues(node, key, value, depth, true)
}

func insertUrkelRoot(node urkelNode, key chainhash.Hash, value []byte, depth int) urkelNode {
	return insertUrkelWithValues(node, key, value, depth, false)
}

func insertUrkelWithValues(node urkelNode, key chainhash.Hash, value []byte, depth int, keepValue bool) urkelNode {
	if node == nil {
		return newUrkelLeaf(key, value, keepValue)
	}

	switch n := node.(type) {
	case *urkelInternalNode:
		bits := n.prefix.count(key[:], depth)
		nextDepth := depth + bits
		bit := urkelHasBit(key[:], nextDepth)

		if bits != n.prefix.size {
			leaf := newUrkelLeaf(key, value, keepValue)
			front, back := n.prefix.split(bits)
			child := newUrkelInternalDirect(back, n.left, n.right)
			return newUrkelInternal(front, leaf, child, bit)
		}

		if bit == 0 {
			return newUrkelInternalDirect(n.prefix,
				insertUrkelWithValues(n.left, key, value, nextDepth+1, keepValue),
				n.right)
		}
		return newUrkelInternalDirect(n.prefix, n.left,
			insertUrkelWithValues(n.right, key, value, nextDepth+1, keepValue))

	case *urkelLeafNode:
		if n.key == key {
			return newUrkelLeaf(key, value, keepValue)
		}

		prefix := urkelBitsFromKey(n.key).collide(key[:], depth)
		nextDepth := depth + prefix.size
		leaf := newUrkelLeaf(key, value, keepValue)
		bit := urkelHasBit(key[:], nextDepth)
		return newUrkelInternal(prefix, leaf, n, bit)

	default:
		panic("unknown urkel node type")
	}
}

func newUrkelLeaf(key chainhash.Hash, value []byte, keepValue bool) *urkelLeafNode {
	var valueCopy []byte
	if keepValue {
		valueCopy = append([]byte(nil), value...)
	}
	return &urkelLeafNode{
		key:       key,
		value:     valueCopy,
		hashValue: hashUrkelValue(key, value),
	}
}

func newUrkelInternalDirect(prefix urkelBits, left, right urkelNode) *urkelInternalNode {
	return &urkelInternalNode{
		prefix:    prefix,
		left:      left,
		right:     right,
		hashValue: hashUrkelInternal(prefix, left.hash(), right.hash()),
	}
}

func newUrkelInternal(prefix urkelBits, x, y urkelNode, bit int) *urkelInternalNode {
	if bit == 0 {
		return newUrkelInternalDirect(prefix, x, y)
	}
	return newUrkelInternalDirect(prefix, y, x)
}

func (n *urkelInternalNode) child(bit int) urkelNode {
	if bit == 0 {
		return n.left
	}
	return n.right
}

func (n *urkelInternalNode) sibling(bit int) urkelNode {
	if bit == 0 {
		return n.right
	}
	return n.left
}

func (n *urkelLeafNode) hash() chainhash.Hash {
	return n.hashValue
}

func hashUrkelValue(key chainhash.Hash, value []byte) chainhash.Hash {
	valueHash := blake2b.Sum256(value)
	return hashUrkelLeaf(key, chainhash.Hash(valueHash))
}

func hashUrkelLeaf(key, valueHash chainhash.Hash) chainhash.Hash {
	preimage := make([]byte, 1+chainhash.HashSize+chainhash.HashSize)
	preimage[0] = 0x00
	copy(preimage[1:], key[:])
	copy(preimage[1+chainhash.HashSize:], valueHash[:])
	return chainhash.Hash(blake2b.Sum256(preimage))
}

func (n *urkelInternalNode) hash() chainhash.Hash {
	return n.hashValue
}

func hashUrkelInternal(prefix urkelBits, left, right chainhash.Hash) chainhash.Hash {
	if prefix.size == 0 {
		preimage := make([]byte, 1+chainhash.HashSize*2)
		preimage[0] = 0x01
		copy(preimage[1:], left[:])
		copy(preimage[1+chainhash.HashSize:], right[:])
		return chainhash.Hash(blake2b.Sum256(preimage))
	}

	prefixBytes := prefix.byteSize()
	preimage := make([]byte, 1+2+prefixBytes+chainhash.HashSize*2)
	preimage[0] = 0x02
	binary.LittleEndian.PutUint16(preimage[1:3], uint16(prefix.size))
	copy(preimage[3:], prefix.data[:prefixBytes])
	offset := 3 + prefixBytes
	copy(preimage[offset:], left[:])
	copy(preimage[offset+chainhash.HashSize:], right[:])
	return chainhash.Hash(blake2b.Sum256(preimage))
}

func urkelBitsFromKey(key chainhash.Hash) urkelBits {
	return urkelBits{
		size: urkelKeyBits,
		data: key,
	}
}

func (b urkelBits) get(index int) int {
	return urkelHasBit(b.data[:], index)
}

func (b urkelBits) clone() urkelBits {
	return b
}

func (b urkelBits) byteSize() int {
	return (b.size + 7) / 8
}

func (b urkelBits) has(key []byte, depth int) bool {
	return b.count(key, depth) == b.size
}

func (b urkelBits) count(key []byte, depth int) int {
	remainingPrefix := b.size
	remainingKey := len(key)*8 - depth
	limit := remainingPrefix
	if remainingKey < limit {
		limit = remainingKey
	}

	var matched int
	for matched < limit {
		if b.get(matched) != urkelHasBit(key, depth+matched) {
			break
		}
		matched++
	}
	return matched
}

func (b urkelBits) collide(key []byte, depth int) urkelBits {
	size := b.countFrom(depth, key, depth)
	return b.slice(depth, depth+size)
}

func (b urkelBits) countFrom(index int, key []byte, depth int) int {
	remainingPrefix := b.size - index
	remainingKey := len(key)*8 - depth
	limit := remainingPrefix
	if remainingKey < limit {
		limit = remainingKey
	}

	var matched int
	for matched < limit {
		if b.get(index+matched) != urkelHasBit(key, depth+matched) {
			break
		}
		matched++
	}
	return matched
}

func (b urkelBits) split(index int) (urkelBits, urkelBits) {
	return b.slice(0, index), b.slice(index+1, b.size)
}

func (b urkelBits) slice(start, end int) urkelBits {
	size := end - start
	if size == 0 {
		return urkelBits{}
	}

	out := urkelBits{
		size: size,
	}
	for i := 0; i < size; i++ {
		if b.get(start+i) != 0 {
			urkelSetBit(out.data[:], i)
		}
	}
	return out
}

func urkelHasBit(key []byte, index int) int {
	oct := index >> 3
	bit := index & 7
	return int((key[oct] >> (7 - bit)) & 1)
}

func urkelSetBit(key []byte, index int) {
	oct := index >> 3
	bit := index & 7
	key[oct] |= 1 << (7 - bit)
}

func proveUrkel(root urkelNode, key chainhash.Hash) *UrkelProof {
	proof := &UrkelProof{}
	node := root
	depth := 0

	for {
		switch n := node.(type) {
		case nil:
			proof.typ = urkelProofTypeDeadend
			proof.depth = depth
			return proof

		case *urkelInternalNode:
			if !n.prefix.has(key[:], depth) {
				proof.typ = urkelProofTypeShort
				proof.depth = depth
				proof.prefix = n.prefix.clone()
				proof.left = n.left.hash()
				proof.right = n.right.hash()
				return proof
			}

			depth += n.prefix.size
			bit := urkelHasBit(key[:], depth)
			proof.nodes = append(proof.nodes, urkelProofNode{
				prefix: n.prefix.clone(),
				node:   n.sibling(bit).hash(),
			})
			node = n.child(bit)
			depth++

		case *urkelLeafNode:
			proof.depth = depth
			if n.key == key {
				proof.typ = urkelProofTypeExists
				proof.value = append([]byte(nil), n.value...)
				return proof
			}

			proof.typ = urkelProofTypeCollision
			proof.key = n.key
			proof.valueHash = chainhash.Hash(blake2b.Sum256(n.value))
			return proof

		default:
			panic("unknown urkel node type")
		}
	}
}

// DecodeUrkelProof decodes an hsd-compatible Urkel proof.
func DecodeUrkelProof(serialized []byte) (*UrkelProof, error) {
	proof := &UrkelProof{}
	offset := 0

	if len(serialized) < 4 {
		return nil, errors.New("urkel proof is truncated")
	}

	field := binary.LittleEndian.Uint16(serialized[offset:])
	offset += 2
	proof.typ = uint8(field >> 14)
	proof.depth = int(field & ^uint16(3<<14))
	if proof.depth > urkelKeyBits {
		return nil, errors.New("urkel proof depth is too large")
	}

	count := int(binary.LittleEndian.Uint16(serialized[offset:]))
	offset += 2
	if count > urkelKeyBits {
		return nil, errors.New("urkel proof node count is too large")
	}

	bitMapSize := (count + 7) / 8
	if len(serialized[offset:]) < bitMapSize {
		return nil, errors.New("urkel proof node bitmap is truncated")
	}
	bitMap := serialized[offset : offset+bitMapSize]
	offset += bitMapSize

	proof.nodes = make([]urkelProofNode, 0, count)
	for i := 0; i < count; i++ {
		node := urkelProofNode{}
		if urkelHasBit(bitMap, i) != 0 {
			var err error
			node.prefix, err = readUrkelProofBits(serialized, &offset)
			if err != nil {
				return nil, err
			}
			if node.prefix.size == 0 {
				return nil, errors.New("urkel proof node prefix is empty")
			}
		}
		if len(serialized[offset:]) < chainhash.HashSize {
			return nil, errors.New("urkel proof node hash is truncated")
		}
		copy(node.node[:], serialized[offset:offset+chainhash.HashSize])
		offset += chainhash.HashSize
		proof.nodes = append(proof.nodes, node)
	}

	switch proof.typ {
	case urkelProofTypeDeadend:
	case urkelProofTypeShort:
		var err error
		proof.prefix, err = readUrkelProofBits(serialized, &offset)
		if err != nil {
			return nil, err
		}
		if proof.prefix.size == 0 {
			return nil, errors.New("urkel short proof prefix is empty")
		}
		if len(serialized[offset:]) < chainhash.HashSize*2 {
			return nil, errors.New("urkel short proof is truncated")
		}
		copy(proof.left[:], serialized[offset:offset+chainhash.HashSize])
		offset += chainhash.HashSize
		copy(proof.right[:], serialized[offset:offset+chainhash.HashSize])
		offset += chainhash.HashSize

	case urkelProofTypeCollision:
		if len(serialized[offset:]) < chainhash.HashSize*2 {
			return nil, errors.New("urkel collision proof is truncated")
		}
		copy(proof.key[:], serialized[offset:offset+chainhash.HashSize])
		offset += chainhash.HashSize
		copy(proof.valueHash[:], serialized[offset:offset+chainhash.HashSize])
		offset += chainhash.HashSize

	case urkelProofTypeExists:
		if len(serialized[offset:]) < 2 {
			return nil, errors.New("urkel exists proof value length is truncated")
		}
		valueSize := int(binary.LittleEndian.Uint16(serialized[offset:]))
		offset += 2
		if len(serialized[offset:]) < valueSize {
			return nil, errors.New("urkel exists proof value is truncated")
		}
		proof.value = append([]byte(nil), serialized[offset:offset+valueSize]...)
		offset += valueSize

	default:
		return nil, errors.New("unknown urkel proof type")
	}

	if offset != len(serialized) {
		return nil, errors.New("trailing urkel proof data")
	}
	if !proof.isSane() {
		return nil, errors.New("urkel proof is not sane")
	}

	return proof, nil
}

func readUrkelProofBits(serialized []byte, offset *int) (urkelBits, error) {
	if len(serialized[*offset:]) < 1 {
		return urkelBits{}, errors.New("urkel prefix length is truncated")
	}

	size := int(serialized[*offset])
	*offset += 1
	if size&0x80 != 0 {
		if len(serialized[*offset:]) < 1 {
			return urkelBits{}, errors.New("urkel prefix length is truncated")
		}
		size &= ^0x80
		size <<= 8
		size |= int(serialized[*offset])
		*offset += 1
	}
	if size > urkelKeyBits {
		return urkelBits{}, errors.New("urkel prefix is too large")
	}

	byteSize := (size + 7) / 8
	if len(serialized[*offset:]) < byteSize {
		return urkelBits{}, errors.New("urkel prefix data is truncated")
	}

	bits := urkelBits{size: size}
	copy(bits.data[:], serialized[*offset:*offset+byteSize])
	*offset += byteSize
	return bits, nil
}

// Encode serializes the proof in the hsd-compatible Urkel proof format.
func (p *UrkelProof) Encode() ([]byte, error) {
	if !p.isSane() {
		return nil, errors.New("urkel proof is not sane")
	}

	size := p.serializedSize()
	out := make([]byte, size)
	offset := 0

	field := uint16(p.typ)<<14 | uint16(p.depth)
	binary.LittleEndian.PutUint16(out[offset:], field)
	offset += 2
	binary.LittleEndian.PutUint16(out[offset:], uint16(len(p.nodes)))
	offset += 2

	bitMapSize := (len(p.nodes) + 7) / 8
	bitMap := out[offset : offset+bitMapSize]
	offset += bitMapSize

	for i, node := range p.nodes {
		if node.prefix.size != 0 {
			urkelSetBit(bitMap, i)
			offset = appendUrkelProofBits(out, offset, node.prefix)
		}
		copy(out[offset:], node.node[:])
		offset += chainhash.HashSize
	}

	switch p.typ {
	case urkelProofTypeDeadend:
	case urkelProofTypeShort:
		offset = appendUrkelProofBits(out, offset, p.prefix)
		copy(out[offset:], p.left[:])
		offset += chainhash.HashSize
		copy(out[offset:], p.right[:])
		offset += chainhash.HashSize

	case urkelProofTypeCollision:
		copy(out[offset:], p.key[:])
		offset += chainhash.HashSize
		copy(out[offset:], p.valueHash[:])
		offset += chainhash.HashSize

	case urkelProofTypeExists:
		binary.LittleEndian.PutUint16(out[offset:], uint16(len(p.value)))
		offset += 2
		copy(out[offset:], p.value)
		offset += len(p.value)
	}

	if offset != len(out) {
		return nil, AssertError("urkel proof size mismatch")
	}
	return out, nil
}

func (p *UrkelProof) serializedSize() int {
	size := 4 + (len(p.nodes)+7)/8
	for _, node := range p.nodes {
		if node.prefix.size != 0 {
			size += urkelProofBitsSize(node.prefix)
		}
		size += chainhash.HashSize
	}

	switch p.typ {
	case urkelProofTypeShort:
		size += urkelProofBitsSize(p.prefix) + chainhash.HashSize*2
	case urkelProofTypeCollision:
		size += chainhash.HashSize * 2
	case urkelProofTypeExists:
		size += 2 + len(p.value)
	}

	return size
}

func appendUrkelProofBits(out []byte, offset int, bits urkelBits) int {
	if bits.size >= 0x80 {
		out[offset] = 0x80 | byte(bits.size>>8)
		offset++
	}
	out[offset] = byte(bits.size)
	offset++
	byteSize := bits.byteSize()
	copy(out[offset:], bits.data[:byteSize])
	return offset + byteSize
}

func urkelProofBitsSize(bits urkelBits) int {
	size := 1 + bits.byteSize()
	if bits.size >= 0x80 {
		size++
	}
	return size
}

func (p *UrkelProof) isSane() bool {
	if p == nil || p.depth < 0 || p.depth > urkelKeyBits ||
		len(p.nodes) > urkelKeyBits {

		return false
	}
	for _, node := range p.nodes {
		if node.prefix.size < 0 || node.prefix.size > urkelKeyBits {

			return false
		}
	}

	switch p.typ {
	case urkelProofTypeDeadend:
		return true
	case urkelProofTypeShort:
		return p.prefix.size > 0 &&
			p.prefix.size <= urkelKeyBits
	case urkelProofTypeCollision:
		return true
	case urkelProofTypeExists:
		return p.value != nil && len(p.value) <= maxUrkelProofValue
	default:
		return false
	}
}

// VerifyUrkelProof verifies a serialized hsd-compatible Urkel proof against
// the provided root and key.  It returns the leaf value and true for inclusion
// proofs, or nil and false for valid exclusion proofs.
func VerifyUrkelProof(root, key chainhash.Hash, serialized []byte) (
	[]byte, bool, error) {

	proof, err := DecodeUrkelProof(serialized)
	if err != nil {
		return nil, false, err
	}
	return proof.Verify(root, key)
}

// Verify verifies the proof against the provided root and key.  It returns the
// leaf value and true for inclusion proofs, or nil and false for valid
// exclusion proofs.
func (p *UrkelProof) Verify(root, key chainhash.Hash) ([]byte, bool, error) {
	if !p.isSane() {
		return nil, false, errors.New("urkel proof is not sane")
	}

	var next chainhash.Hash
	switch p.typ {
	case urkelProofTypeDeadend:
	case urkelProofTypeShort:
		if p.prefix.has(key[:], p.depth) {
			return nil, false, errors.New("urkel proof follows same path")
		}
		next = hashUrkelInternal(p.prefix, p.left, p.right)

	case urkelProofTypeCollision:
		if p.key == key {
			return nil, false, errors.New("urkel proof has same key")
		}
		next = hashUrkelLeaf(p.key, p.valueHash)

	case urkelProofTypeExists:
		next = hashUrkelValue(key, p.value)

	default:
		return nil, false, errors.New("unknown urkel proof type")
	}

	depth := p.depth
	for i := len(p.nodes) - 1; i >= 0; i-- {
		node := p.nodes[i]
		if depth < node.prefix.size+1 {
			return nil, false, errors.New("urkel proof depth underflow")
		}

		depth--
		if urkelHasBit(key[:], depth) != 0 {
			next = hashUrkelInternal(node.prefix, node.node, next)
		} else {
			next = hashUrkelInternal(node.prefix, next, node.node)
		}

		depth -= node.prefix.size
		if !node.prefix.has(key[:], depth) {
			return nil, false, errors.New("urkel proof path mismatch")
		}
	}

	if depth != 0 {
		return nil, false, errors.New("urkel proof is too deep")
	}
	if next != root {
		return nil, false, fmt.Errorf("urkel proof root mismatch: "+
			"got %v, want %v", next, root)
	}

	if p.typ != urkelProofTypeExists {
		return nil, false, nil
	}
	return append([]byte(nil), p.value...), true, nil
}
