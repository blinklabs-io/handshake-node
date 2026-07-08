// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/hnsutil"
	"golang.org/x/crypto/blake2b"
)

const (
	merkleLeafPrefix     = 0x00
	merkleInternalPrefix = 0x01

	// CoinbaseWitnessDataLen is the length of the legacy witness nonce that can
	// appear before the coinbase height script in compatibility fixtures.
	CoinbaseWitnessDataLen = 32
)

func hashPtr(hash chainhash.Hash) *chainhash.Hash {
	return &hash
}

// HashMerkleEmpty returns the hsd mrkl sentinel hash for empty leaves and
// missing right branches.
func HashMerkleEmpty() chainhash.Hash {
	return chainhash.Hash(blake2b.Sum256(nil))
}

// HashMerkleLeaf returns the hsd mrkl leaf hash for the provided transaction
// hash.
func HashMerkleLeaf(hash *chainhash.Hash) chainhash.Hash {
	var preimage [1 + chainhash.HashSize]byte
	preimage[0] = merkleLeafPrefix
	copy(preimage[1:], hash[:])
	return chainhash.Hash(blake2b.Sum256(preimage[:]))
}

// HashMerkleBranches takes two hashes, treated as the left and right tree
// nodes, and returns the hsd mrkl internal hash.
func HashMerkleBranches(left, right *chainhash.Hash) chainhash.Hash {
	var preimage [1 + chainhash.HashSize*2]byte
	preimage[0] = merkleInternalPrefix
	copy(preimage[1:1+chainhash.HashSize], left[:])
	copy(preimage[1+chainhash.HashSize:], right[:])
	return chainhash.Hash(blake2b.Sum256(preimage[:]))
}

// BuildMerkleTreeStore creates an hsd mrkl tree from a slice of transactions,
// stores it using a linear array, and returns a slice of the backing array. A
// linear array was chosen as opposed to an actual tree structure since it uses
// about half as much memory. The following describes a merkle tree and how it is
// stored in a linear array.
//
// A merkle tree is a tree in which every non-leaf node is the hash of its
// children nodes. A diagram depicting how this works for transactions where
// h(x) is the hsd mrkl node hash follows:
//
//	         root = h1234 = h(h12 + h34)
//	        /                           \
//	  h12 = h(h1 + h2)            h34 = h(h3 + h4)
//	   /            \              /            \
//	h1 = h(tx1)  h2 = h(tx2)    h3 = h(tx3)  h4 = h(tx4)
//
// The above stored as a linear array is as follows:
//
//	[h1 h2 h3 h4 h12 h34 root]
//
// As the above shows, the merkle root is always the last element in the array.
//
// The number of inputs is not always a power of two which results in a balanced
// tree structure as above. In that case, parent nodes with only a single left
// node use hsd's empty sentinel hash as the missing right branch.
//
// The additional bool parameter indicates if we are generating the merkle tree
// using witness transaction id's rather than regular transaction id's.
func BuildMerkleTreeStore(transactions []*hnsutil.Tx, witness bool) []*chainhash.Hash {
	if len(transactions) == 0 {
		return []*chainhash.Hash{hashPtr(HashMerkleEmpty())}
	}

	merkles := make([]*chainhash.Hash, 0, len(transactions)*2)
	for _, tx := range transactions {
		var txHash chainhash.Hash
		if witness {
			txHash = tx.MsgTx().WitnessHash()
		} else {
			txHash = *tx.Hash()
		}
		merkles = append(merkles, hashPtr(HashMerkleLeaf(&txHash)))
	}

	sentinel := HashMerkleEmpty()
	offset := 0
	size := len(transactions)
	for size > 1 {
		for i := 0; i < size; i += 2 {
			left := merkles[offset+i]
			right := &sentinel
			if i+1 < size {
				right = merkles[offset+i+1]
			}
			merkles = append(merkles, hashPtr(HashMerkleBranches(left, right)))
		}
		offset += size
		size = (size + 1) / 2
	}

	return merkles
}

// CalcMerkleRoot computes the hsd mrkl root for the provided transactions.
//
// A merkle tree is a tree in which every non-leaf node is the hash of its
// children nodes. A diagram depicting how this works for transactions where
// h(x) is the hsd mrkl node hash follows:
//
//	         root = h1234 = h(h12 + h34)
//	        /                           \
//	  h12 = h(h1 + h2)            h34 = h(h3 + h4)
//	   /            \              /            \
//	h1 = h(tx1)  h2 = h(tx2)    h3 = h(tx3)  h4 = h(tx4)
//
// The additional bool parameter indicates if we are generating the merkle tree
// using witness transaction id's rather than regular transaction id's.
func CalcMerkleRoot(transactions []*hnsutil.Tx, witness bool) chainhash.Hash {
	merkles := BuildMerkleTreeStore(transactions, witness)
	return *merkles[len(merkles)-1]
}
