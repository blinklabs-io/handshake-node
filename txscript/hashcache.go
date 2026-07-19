// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package txscript

import (
	"bytes"
	"encoding/binary"
	"io"
	"maps"
	"math"
	"sync"

	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/wire"
	"golang.org/x/crypto/blake2b"
)

func hnsHashH(b []byte) chainhash.Hash {
	return chainhash.Hash(blake2b.Sum256(b))
}

func hnsHashB(b []byte) []byte {
	hash := blake2b.Sum256(b)
	return hash[:]
}

func hnsHashRaw(serialize func(w io.Writer) error) chainhash.Hash {
	h, err := blake2b.New256(nil)
	if err != nil {
		panic("blake2b.New256 failed")
	}
	if err := serialize(h); err != nil {
		panic("hnsHashRaw: " + err.Error())
	}

	var ret chainhash.Hash
	copy(ret[:], h.Sum(nil))
	return ret
}

// calcHashPrevOuts calculates a single hash of all the previous outputs
// (txid:index) referenced within the passed transaction. This calculated hash
// can be re-used when validating all inputs spending segwit outputs, with a
// signature hash type of SigHashAll. This allows validation to re-use previous
// hashing computation, reducing the complexity of validating SigHashAll inputs
// from  O(N^2) to O(N).
func calcHashPrevOuts(tx *wire.MsgTx) chainhash.Hash {
	var b bytes.Buffer
	for _, in := range tx.TxIn {
		// First write out the 32-byte transaction ID one of whose
		// outputs are being referenced by this input.
		b.Write(in.PreviousOutPoint.Hash[:])

		// Next, we'll encode the index of the referenced output as a
		// little endian integer.
		var buf [4]byte
		binary.LittleEndian.PutUint32(buf[:], in.PreviousOutPoint.Index)
		b.Write(buf[:])
	}

	return hnsHashH(b.Bytes())
}

// calcHashSequence computes an aggregated hash of each of the sequence numbers
// within the inputs of the passed transaction. This single hash can be re-used
// when validating all inputs spending segwit outputs, which include signatures
// using the SigHashAll sighash type. This allows validation to re-use previous
// hashing computation, reducing the complexity of validating SigHashAll inputs
// from O(N^2) to O(N).
func calcHashSequence(tx *wire.MsgTx) chainhash.Hash {
	var b bytes.Buffer
	for _, in := range tx.TxIn {
		var buf [4]byte
		binary.LittleEndian.PutUint32(buf[:], in.Sequence)
		b.Write(buf[:])
	}

	return hnsHashH(b.Bytes())
}

// calcHashOutputs computes a hash digest of all outputs created by the
// transaction encoded using the wire format. This single hash can be re-used
// when validating all inputs spending witness programs, which include
// signatures using the SigHashAll sighash type. This allows computation to be
// cached, reducing the total hashing complexity from O(N^2) to O(N).
func calcHashOutputs(tx *wire.MsgTx) chainhash.Hash {
	var b bytes.Buffer
	for _, out := range tx.TxOut {
		if err := wire.WriteTxOut(&b, 0, 0, out); err != nil {
			panic("calcHashOutputs: " + err.Error())
		}
	}

	return hnsHashH(b.Bytes())
}

// PrevOutputFetcher is an interface used to supply the sighash cache with the
// previous output information needed to calculate the pre-computed sighash
// midstate for taproot transactions.
type PrevOutputFetcher interface {
	// FetchPrevOutput attempts to fetch the previous output referenced by
	// the passed outpoint. A nil value will be returned if the passed
	// outpoint doesn't exist.
	FetchPrevOutput(wire.OutPoint) *wire.TxOut
}

// CannedPrevOutputFetcher is an implementation of PrevOutputFetcher that only
// is able to return information for a single previous output.
type CannedPrevOutputFetcher struct {
	addr wire.Address
	amt  int64
}

// NewCannedPrevOutputFetcher returns an instance of a CannedPrevOutputFetcher
// that can only return the TxOut defined by the passed address and amount.
func NewCannedPrevOutputFetcher(addr wire.Address, amt int64) *CannedPrevOutputFetcher {
	return &CannedPrevOutputFetcher{
		addr: addr,
		amt:  amt,
	}
}

// FetchPrevOutput attempts to fetch the previous output referenced by the
// passed outpoint.
//
// NOTE: This is a part of the PrevOutputFetcher interface.
func (c *CannedPrevOutputFetcher) FetchPrevOutput(wire.OutPoint) *wire.TxOut {
	return &wire.TxOut{
		Value:   c.amt,
		Address: c.addr,
	}
}

// A compile-time assertion to ensure that CannedPrevOutputFetcher matches the
// PrevOutputFetcher interface.
var _ PrevOutputFetcher = (*CannedPrevOutputFetcher)(nil)

// MultiPrevOutFetcher is a custom implementation of the PrevOutputFetcher
// backed by a key-value map of prevouts to outputs.
type MultiPrevOutFetcher struct {
	prevOuts map[wire.OutPoint]*wire.TxOut
}

// NewMultiPrevOutFetcher returns an instance of a PrevOutputFetcher that's
// backed by an optional map which is used as an input source. The
func NewMultiPrevOutFetcher(prevOuts map[wire.OutPoint]*wire.TxOut) *MultiPrevOutFetcher {
	if prevOuts == nil {
		prevOuts = make(map[wire.OutPoint]*wire.TxOut)
	}

	return &MultiPrevOutFetcher{
		prevOuts: prevOuts,
	}
}

// FetchPrevOutput attempts to fetch the previous output referenced by the
// passed outpoint.
//
// NOTE: This is a part of the CannedPrevOutputFetcher interface.
func (m *MultiPrevOutFetcher) FetchPrevOutput(op wire.OutPoint) *wire.TxOut {
	return m.prevOuts[op]
}

// AddPrevOut adds a new prev out, tx out pair to the backing map.
func (m *MultiPrevOutFetcher) AddPrevOut(op wire.OutPoint, txOut *wire.TxOut) {
	m.prevOuts[op] = txOut
}

// Merge merges two instances of a MultiPrevOutFetcher into a single source.
func (m *MultiPrevOutFetcher) Merge(other *MultiPrevOutFetcher) {
	maps.Copy(m.prevOuts, other.prevOuts)
}

// A compile-time assertion to ensure that MultiPrevOutFetcher matches the
// PrevOutputFetcher interface.
var _ PrevOutputFetcher = (*MultiPrevOutFetcher)(nil)

// calcHashInputAmounts computes a hash digest of the input amounts of all
// inputs referenced in the passed transaction. This hash pre computation is only
// used for validating taproot inputs.
func calcHashInputAmounts(tx *wire.MsgTx, inputFetcher PrevOutputFetcher) chainhash.Hash {
	var b bytes.Buffer
	for _, txIn := range tx.TxIn {
		prevOut := inputFetcher.FetchPrevOutput(txIn.PreviousOutPoint)

		if err := binary.Write(&b, binary.LittleEndian, prevOut.Value); err != nil {
			panic("calcHashInputAmounts: " + err.Error())
		}
	}

	return hnsHashH(b.Bytes())
}

// calcHashInputAmts computes the hash digest of all the previous input scripts
// referenced by the passed transaction. This hash pre computation is only used
// for validating taproot inputs.
func calcHashInputScripts(tx *wire.MsgTx, inputFetcher PrevOutputFetcher) chainhash.Hash {
	var b bytes.Buffer
	for _, txIn := range tx.TxIn {
		prevOut := inputFetcher.FetchPrevOutput(txIn.PreviousOutPoint)

		if err := wire.WriteVarBytes(&b, 0, prevOut.Address.WitnessProgram()); err != nil {
			panic("calcHashInputScripts: " + err.Error())
		}
	}

	return hnsHashH(b.Bytes())
}

// SegwitSigHashMidstate is the sighash midstate used in the base segwit
// sighash calculation as defined in BIP 143.
type SegwitSigHashMidstate struct {
	HashPrevOutsV0 chainhash.Hash
	HashSequenceV0 chainhash.Hash
	HashOutputsV0  chainhash.Hash
}

// TaprootSigHashMidState is the sighash midstate used to compute taproot and
// tapscript signatures as defined in BIP 341.
type TaprootSigHashMidState struct {
	HashPrevOutsV1     chainhash.Hash
	HashSequenceV1     chainhash.Hash
	HashOutputsV1      chainhash.Hash
	HashInputScriptsV1 chainhash.Hash
	HashInputAmountsV1 chainhash.Hash
}

// TxSigHashes houses the partial set of sighashes introduced within BIP0143.
// This partial set of sighashes may be re-used within each input across a
// transaction when validating all inputs. As a result, validation complexity
// for SigHashAll can be reduced by a polynomial factor.
type TxSigHashes struct {
	SegwitSigHashMidstate

	TaprootSigHashMidState
}

// NewTxSigHashes computes, and returns the cached sighashes of the given
// transaction.
func NewTxSigHashes(tx *wire.MsgTx,
	inputFetcher PrevOutputFetcher) *TxSigHashes {

	var (
		sigHashes TxSigHashes
		zeroHash  chainhash.Hash
	)

	// Base segwit (witness version v0), and taproot (witness version v1)
	// differ in how the set of pre-computed cached sighash midstate is
	// computed. For taproot, the prevouts, sequence, and outputs are
	// computed as normal, but a single sha256 hash invocation is used. In
	// addition, the hashes of all the previous input amounts and scripts
	// are included as well.
	//
	// Based on the above distinction, we'll run through all the referenced
	// inputs to determine what we need to compute.
	var hasV0Inputs, hasV1Inputs bool
	for _, txIn := range tx.TxIn {
		// If this is a coinbase input, then we know that we only need
		// the v0 midstate (though it won't be used) in this instance.
		outpoint := txIn.PreviousOutPoint
		if outpoint.Index == math.MaxUint32 && outpoint.Hash == zeroHash {
			hasV0Inputs = true
			continue
		}

		prevOut := inputFetcher.FetchPrevOutput(outpoint)

		// If this is spending a script that looks like a taproot output,
		// then we'll need to pre-compute the extra taproot data.
		if IsPayToTaproot(prevOut.Address.WitnessProgram()) {
			hasV1Inputs = true
		} else {
			// Otherwise, we'll assume we need the v0 sighash midstate.
			hasV0Inputs = true
		}

		// If the transaction has _both_ v0 and v1 inputs, then we can stop
		// here.
		if hasV0Inputs && hasV1Inputs {
			break
		}
	}

	// Now that we know which cached midstate we need to calculate, we can
	// go ahead and do so.
	//
	// First, we can calculate the information that both segwit v0 and v1
	// need: the prevout, sequence and output hashes. For v1 the only
	// difference is that this is a single instead of a double hash.
	//
	// Both v0 and v1 share this base data computed using a sha256 single
	// hash.
	sigHashes.HashPrevOutsV1 = calcHashPrevOuts(tx)
	sigHashes.HashSequenceV1 = calcHashSequence(tx)
	sigHashes.HashOutputsV1 = calcHashOutputs(tx)

	// Handshake uses Blake2b-256 for the v0 sighash midstates.
	if hasV0Inputs {
		sigHashes.HashPrevOutsV0 = sigHashes.HashPrevOutsV1
		sigHashes.HashSequenceV0 = sigHashes.HashSequenceV1
		sigHashes.HashOutputsV0 = sigHashes.HashOutputsV1
	}

	// Finally, we'll compute the taproot specific data if needed.
	if hasV1Inputs {
		sigHashes.HashInputAmountsV1 = calcHashInputAmounts(
			tx, inputFetcher,
		)
		sigHashes.HashInputScriptsV1 = calcHashInputScripts(
			tx, inputFetcher,
		)
	}

	return &sigHashes
}

// hashCacheEntry houses a cached set of partial sighashes and the links needed
// to evict entries in insertion order.
type hashCacheEntry struct {
	txid      chainhash.Hash
	sigHashes *TxSigHashes
	prev      *hashCacheEntry
	next      *hashCacheEntry
}

// HashCache houses a bounded set of partial sighashes keyed by txid. The set of
// partial sighashes are those introduced within BIP0143 by the new more
// efficient sighash digest calculation algorithm. Using this threadsafe shared
// cache, multiple goroutines can safely re-use the pre-computed partial
// sighashes speeding up validation time amongst all inputs found within a
// block. Entries are evicted in insertion order once the configured maximum is
// reached. Updating an existing entry does not change its eviction position.
type HashCache struct {
	sync.RWMutex
	sigHashes  map[chainhash.Hash]*hashCacheEntry
	oldest     *hashCacheEntry
	newest     *hashCacheEntry
	maxEntries uint
}

// NewHashCache returns a new instance of the HashCache given a maximum number
// of entries which may exist within it at anytime.
func NewHashCache(maxSize uint) *HashCache {
	return &HashCache{
		sigHashes:  make(map[chainhash.Hash]*hashCacheEntry),
		maxEntries: maxSize,
	}
}

// removeEntry removes the provided entry from the cache and eviction list. The
// caller must hold the cache write lock.
func (h *HashCache) removeEntry(entry *hashCacheEntry) {
	if entry.prev != nil {
		entry.prev.next = entry.next
	} else {
		h.oldest = entry.next
	}
	if entry.next != nil {
		entry.next.prev = entry.prev
	} else {
		h.newest = entry.prev
	}
	delete(h.sigHashes, entry.txid)
	entry.prev = nil
	entry.next = nil
}

// addEntry adds the provided sighashes to the cache. The caller must hold the
// cache write lock. A zero-capacity cache intentionally does not retain the
// entry.
func (h *HashCache) addEntry(txid chainhash.Hash, sigHashes *TxSigHashes) {
	if h.maxEntries == 0 {
		return
	}

	if entry, ok := h.sigHashes[txid]; ok {
		entry.sigHashes = sigHashes
		return
	}

	if uint(len(h.sigHashes)) >= h.maxEntries {
		h.removeEntry(h.oldest)
	}

	entry := &hashCacheEntry{
		txid:      txid,
		sigHashes: sigHashes,
		prev:      h.newest,
	}
	if h.newest != nil {
		h.newest.next = entry
	} else {
		h.oldest = entry
	}
	h.newest = entry
	h.sigHashes[txid] = entry
}

// AddSigHashes computes and stores the partial sighashes for the passed
// transaction when the cache has nonzero capacity. Callers that need the
// computed value should use GetOrAddSigHashes to avoid a lookup race.
func (h *HashCache) AddSigHashes(tx *wire.MsgTx,
	inputFetcher PrevOutputFetcher) {

	if h.maxEntries == 0 {
		return
	}

	txid := tx.TxHash()
	sigHashes := NewTxSigHashes(tx, inputFetcher)

	h.Lock()
	defer h.Unlock()
	h.addEntry(txid, sigHashes)
}

// GetOrAddSigHashes returns the cached partial sighashes for the transaction,
// computing them when they are not already present. Hashing is performed
// outside the cache lock. A write-lock double-check ensures concurrent callers
// use the value that won insertion, while later eviction cannot invalidate the
// returned value. A zero-capacity cache still returns the computed sighashes
// without retaining them.
func (h *HashCache) GetOrAddSigHashes(tx *wire.MsgTx,
	inputFetcher PrevOutputFetcher) *TxSigHashes {

	txid := tx.TxHash()
	h.RLock()
	if entry, ok := h.sigHashes[txid]; ok {
		h.RUnlock()
		return entry.sigHashes
	}
	h.RUnlock()

	sigHashes := NewTxSigHashes(tx, inputFetcher)

	h.Lock()
	defer h.Unlock()
	if entry, ok := h.sigHashes[txid]; ok {
		return entry.sigHashes
	}
	h.addEntry(txid, sigHashes)
	return sigHashes
}

// ContainsHashes returns true if the partial sighashes for the passed
// transaction currently exist within the HashCache, and false otherwise.
func (h *HashCache) ContainsHashes(txid *chainhash.Hash) bool {
	h.RLock()
	_, found := h.sigHashes[*txid]
	h.RUnlock()

	return found
}

// GetSigHashes possibly returns the previously cached partial sighashes for
// the passed transaction. This function also returns an additional boolean
// value indicating if the sighashes for the passed transaction were found to
// be present within the HashCache.
func (h *HashCache) GetSigHashes(txid *chainhash.Hash) (*TxSigHashes, bool) {
	h.RLock()
	entry, found := h.sigHashes[*txid]
	var item *TxSigHashes
	if found {
		item = entry.sigHashes
	}
	h.RUnlock()

	return item, found
}

// PurgeSigHashes removes all partial sighashes from the HashCache belonging to
// the passed transaction.
func (h *HashCache) PurgeSigHashes(txid *chainhash.Hash) {
	h.Lock()
	if entry, ok := h.sigHashes[*txid]; ok {
		h.removeEntry(entry)
	}
	h.Unlock()
}
