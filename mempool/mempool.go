// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mempool

import (
	"bytes"
	"container/list"
	"encoding/binary"
	"fmt"
	"maps"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blinklabs-io/handshake-node/blockchain"
	"github.com/blinklabs-io/handshake-node/blockchain/indexers"
	"github.com/blinklabs-io/handshake-node/chaincfg"
	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/hnsjson"
	"github.com/blinklabs-io/handshake-node/hnsutil"
	"github.com/blinklabs-io/handshake-node/mining"
	"github.com/blinklabs-io/handshake-node/txscript"
	"github.com/blinklabs-io/handshake-node/wire"
	"github.com/davecgh/go-spew/spew"
)

const (
	// DefaultBlockPrioritySize is the default size in bytes for high-
	// priority / low-fee transactions.  It is used to help determine which
	// are allowed into the mempool and consequently affects their relay and
	// inclusion when generating block templates.
	DefaultBlockPrioritySize = 50000

	// orphanTTL is the maximum amount of time an orphan is allowed to
	// stay in the orphan pool before it expires and is evicted during the
	// next scan.
	orphanTTL = time.Minute * 15

	// orphanExpireScanInterval is the minimum amount of time in between
	// scans of the orphan pool to evict expired transactions.
	orphanExpireScanInterval = time.Minute * 5

	// MaxRBFSequence is the maximum sequence number an input can use to
	// signal that the transaction spending it can be replaced using the
	// Replace-By-Fee (RBF) policy.
	MaxRBFSequence = 0xfffffffd

	// MaxReplacementEvictions is the maximum number of transactions that
	// can be evicted from the mempool when accepting a transaction
	// replacement.
	MaxReplacementEvictions = 100

	// Transactions smaller than 65 non-witness bytes are not relayed to
	// mitigate CVE-2017-12842.
	MinStandardTxNonWitnessSize = 65
)

// Tag represents an identifier to use for tagging orphan transactions.  The
// caller may choose any scheme it desires, however it is common to use peer IDs
// so that orphans can be identified by which peer first relayed them.
type Tag uint64

// Config is a descriptor containing the memory pool configuration.
type Config struct {
	// Policy defines the various mempool configuration options related
	// to policy.
	Policy Policy

	// ChainParams identifies which chain parameters the txpool is
	// associated with.
	ChainParams *chaincfg.Params

	// FetchUtxoView defines the function to use to fetch unspent
	// transaction output information.
	FetchUtxoView func(*hnsutil.Tx) (*blockchain.UtxoViewpoint, error)

	// BestHeight defines the function to use to access the block height of
	// the current best chain.
	BestHeight func() int32

	// MedianTimePast defines the function to use in order to access the
	// median time past calculated from the point-of-view of the current
	// chain tip within the best chain.
	MedianTimePast func() time.Time

	// CalcSequenceLock defines the function to use in order to generate
	// the current sequence lock for the given transaction using the passed
	// utxo view.
	CalcSequenceLock func(*hnsutil.Tx, *blockchain.UtxoViewpoint) (*blockchain.SequenceLock, error)

	// CheckTransactionNames validates Handshake name covenant transitions
	// against the current chain name state and the provided UTXO view.
	CheckTransactionNames func(*hnsutil.Tx, int32, int64, *blockchain.UtxoViewpoint) error

	// NewNameValidationView returns a stateful Handshake name-validation
	// view initialized from the current chain state.  When provided, the
	// mempool uses it to replay existing unconfirmed name transactions in
	// dependency order before validating a new transaction.
	NewNameValidationView func() (NameValidationView, error)

	// IsDeploymentActive returns true if the target deploymentID is
	// active, and false otherwise. The mempool uses this function to gauge
	// if transactions using new to be soft-forked rules should be allowed
	// into the mempool or not.
	IsDeploymentActive func(deploymentID uint32) (bool, error)

	// IsAirdropSpent returns true if the airdrop bitfield position has
	// already been consumed by the active chain.  It is optional because
	// tests and non-chain-backed pools can still rely on block validation.
	IsAirdropSpent func(position uint32) (bool, error)

	// SigCache defines a signature cache to use.
	SigCache *txscript.SigCache

	// HashCache defines the transaction hash mid-state cache to use.
	HashCache *txscript.HashCache

	// AddrIndex defines the optional address index instance to use for
	// indexing the unconfirmed transactions in the memory pool.
	// This can be nil if the address index is not enabled.
	AddrIndex *indexers.AddrIndex

	// FeeEstimator provides a feeEstimator. If it is not nil, the mempool
	// records all new transactions it observes into the feeEstimator.
	FeeEstimator *FeeEstimator
}

// Policy houses the policy (configuration parameters) which is used to
// control the mempool.
type Policy struct {
	// MaxTxVersion is the transaction version that the mempool should
	// accept.  All transactions above this version are rejected as
	// non-standard.
	MaxTxVersion int32

	// DisableRelayPriority defines whether to relay free or low-fee
	// transactions that do not have enough priority to be relayed.
	DisableRelayPriority bool

	// AcceptNonStd defines whether to accept non-standard transactions. If
	// true, non-standard transactions will be accepted into the mempool.
	// Otherwise, all non-standard transactions will be rejected.
	AcceptNonStd bool

	// FreeTxRelayLimit defines the given amount in thousands of bytes
	// per minute that transactions with no fee are rate limited to.
	FreeTxRelayLimit float64

	// MaxOrphanTxs is the maximum number of orphan transactions
	// that can be queued.
	MaxOrphanTxs int

	// MaxOrphanTxSize is the maximum size allowed for orphan transactions.
	// This helps prevent memory exhaustion attacks from sending a lot of
	// of big orphans.
	MaxOrphanTxSize int

	// MaxSigOpCostPerTx is the cumulative maximum cost of all the signature
	// operations in a single transaction we will relay or mine.  It is a
	// fraction of the max signature operations for a block.
	MaxSigOpCostPerTx int

	// MinRelayTxFee defines the minimum transaction fee in HNS/kB
	// (expressed in dollarydoos) to be considered a non-zero fee.
	MinRelayTxFee hnsutil.Amount

	// RejectReplacement, if true, rejects accepting replacement
	// transactions using the Replace-By-Fee (RBF) signaling policy into
	// the mempool.
	RejectReplacement bool
}

// TxDesc is a descriptor containing a transaction in the mempool along with
// additional metadata.
type TxDesc struct {
	mining.TxDesc

	// StartingPriority is the priority of the transaction when it was added
	// to the pool.
	StartingPriority float64
}

// NameValidationView validates ordered Handshake name covenant transitions
// against a shared chain+mempool state view.
type NameValidationView interface {
	ApplyTransaction(*hnsutil.Tx, int32, int64, *blockchain.UtxoViewpoint) error
}

type coinbaseProofEntry struct {
	hash   chainhash.Hash
	proof  mining.CoinbaseProof
	policy coinbaseProofPolicy
}

type coinbaseProofKind uint8

const (
	coinbaseProofKindUnknown coinbaseProofKind = iota
	coinbaseProofKindClaim
	coinbaseProofKindAirdrop
)

type coinbaseProofPolicy struct {
	kind            coinbaseProofKind
	claimNameHash   chainhash.Hash
	claimHeight     uint32
	claimInception  uint32
	claimExpiration uint32
	airdropPosition uint32
	airdropWeak     bool
	airdropGooSig   bool
	hasClaimHeight  bool
	hasClaimWindow  bool
	hasClaimExpiry  bool
}

// orphanTx is normal transaction that references an ancestor transaction
// that is not yet available.  It also contains additional information related
// to it such as an expiration time to help prevent caching the orphan forever.
type orphanTx struct {
	tx         *hnsutil.Tx
	tag        Tag
	expiration time.Time
}

// TxPool is used as a source of transactions that need to be mined into blocks
// and relayed to other peers.  It is safe for concurrent access from multiple
// peers.
type TxPool struct {
	// The following variables must only be used atomically.
	lastUpdated int64 // last time pool was updated

	mtx              sync.RWMutex
	cfg              Config
	pool             map[chainhash.Hash]*TxDesc
	orphans          map[chainhash.Hash]*orphanTx
	orphansByPrev    map[wire.OutPoint]map[chainhash.Hash]*hnsutil.Tx
	outpoints        map[wire.OutPoint]*hnsutil.Tx
	nameActions      map[chainhash.Hash]*hnsutil.Tx
	coinbaseProofs   []coinbaseProofEntry
	coinbaseClaims   map[chainhash.Hash]chainhash.Hash
	coinbaseAirdrops map[uint32]chainhash.Hash
	pennyTotal       float64 // exponentially decaying total for penny spends.
	lastPennyUnix    int64   // unix time of last ``penny spend''

	// nextExpireScan is the time after which the orphan pool will be
	// scanned in order to evict orphans.  This is NOT a hard deadline as
	// the scan will only run when an orphan is added to the pool as opposed
	// to on an unconditional timer.
	nextExpireScan time.Time
}

// Ensure the TxPool type implements the mining.TxSource interface.
var _ mining.TxSource = (*TxPool)(nil)

// Ensure the TxPool type implements the optional mining.CoinbaseProofSource
// interface.
var _ mining.CoinbaseProofSource = (*TxPool)(nil)

// Ensure the TxPool type implements the TxMemPool interface.
var _ TxMempool = (*TxPool)(nil)

// removeOrphan is the internal function which implements the public
// RemoveOrphan.  See the comment for RemoveOrphan for more details.
//
// This function MUST be called with the mempool lock held (for writes).
func (mp *TxPool) removeOrphan(tx *hnsutil.Tx, removeRedeemers bool) {
	// Nothing to do if passed tx is not an orphan.
	txHash := tx.Hash()
	otx, exists := mp.orphans[*txHash]
	if !exists {
		return
	}

	// Remove the reference from the previous orphan index.
	for _, txIn := range otx.tx.MsgTx().TxIn {
		orphans, exists := mp.orphansByPrev[txIn.PreviousOutPoint]
		if exists {
			delete(orphans, *txHash)

			// Remove the map entry altogether if there are no
			// longer any orphans which depend on it.
			if len(orphans) == 0 {
				delete(mp.orphansByPrev, txIn.PreviousOutPoint)
			}
		}
	}

	// Remove any orphans that redeem outputs from this one if requested.
	if removeRedeemers {
		prevOut := wire.OutPoint{Hash: *txHash}
		for txOutIdx := range tx.MsgTx().TxOut {
			prevOut.Index = uint32(txOutIdx)
			for _, orphan := range mp.orphansByPrev[prevOut] {
				mp.removeOrphan(orphan, true)
			}
		}
	}

	// Remove the transaction from the orphan pool.
	delete(mp.orphans, *txHash)
}

// RemoveOrphan removes the passed orphan transaction from the orphan pool and
// previous orphan index.
//
// This function is safe for concurrent access.
func (mp *TxPool) RemoveOrphan(tx *hnsutil.Tx) {
	mp.mtx.Lock()
	mp.removeOrphan(tx, false)
	mp.mtx.Unlock()
}

// RemoveOrphansByTag removes all orphan transactions tagged with the provided
// identifier.
//
// This function is safe for concurrent access.
func (mp *TxPool) RemoveOrphansByTag(tag Tag) uint64 {
	var numEvicted uint64
	mp.mtx.Lock()
	for _, otx := range mp.orphans {
		if otx.tag == tag {
			mp.removeOrphan(otx.tx, true)
			numEvicted++
		}
	}
	mp.mtx.Unlock()
	return numEvicted
}

// limitNumOrphans limits the number of orphan transactions by evicting a random
// orphan if adding a new one would cause it to overflow the max allowed.
//
// This function MUST be called with the mempool lock held (for writes).
func (mp *TxPool) limitNumOrphans() error {
	// Scan through the orphan pool and remove any expired orphans when it's
	// time.  This is done for efficiency so the scan only happens
	// periodically instead of on every orphan added to the pool.
	if now := time.Now(); now.After(mp.nextExpireScan) {
		origNumOrphans := len(mp.orphans)
		for _, otx := range mp.orphans {
			if now.After(otx.expiration) {
				// Remove redeemers too because the missing
				// parents are very unlikely to ever materialize
				// since the orphan has already been around more
				// than long enough for them to be delivered.
				mp.removeOrphan(otx.tx, true)
			}
		}

		// Set next expiration scan to occur after the scan interval.
		mp.nextExpireScan = now.Add(orphanExpireScanInterval)

		numOrphans := len(mp.orphans)
		if numExpired := origNumOrphans - numOrphans; numExpired > 0 {
			log.Debugf("Expired %d %s (remaining: %d)", numExpired,
				pickNoun(numExpired, "orphan", "orphans"),
				numOrphans)
		}
	}

	// Nothing to do if adding another orphan will not cause the pool to
	// exceed the limit.
	if len(mp.orphans)+1 <= mp.cfg.Policy.MaxOrphanTxs {
		return nil
	}

	// Remove a random entry from the map.  For most compilers, Go's
	// range statement iterates starting at a random item although
	// that is not 100% guaranteed by the spec.  The iteration order
	// is not important here because an adversary would have to be
	// able to pull off preimage attacks on the hashing function in
	// order to target eviction of specific entries anyways.
	for _, otx := range mp.orphans {
		// Don't remove redeemers in the case of a random eviction since
		// it is quite possible it might be needed again shortly.
		mp.removeOrphan(otx.tx, false)
		break
	}

	return nil
}

// addOrphan adds an orphan transaction to the orphan pool.
//
// This function MUST be called with the mempool lock held (for writes).
func (mp *TxPool) addOrphan(tx *hnsutil.Tx, tag Tag) {
	// Nothing to do if no orphans are allowed.
	if mp.cfg.Policy.MaxOrphanTxs <= 0 {
		return
	}

	// Limit the number orphan transactions to prevent memory exhaustion.
	// This will periodically remove any expired orphans and evict a random
	// orphan if space is still needed.
	mp.limitNumOrphans()

	mp.orphans[*tx.Hash()] = &orphanTx{
		tx:         tx,
		tag:        tag,
		expiration: time.Now().Add(orphanTTL),
	}
	for _, txIn := range tx.MsgTx().TxIn {
		if _, exists := mp.orphansByPrev[txIn.PreviousOutPoint]; !exists {
			mp.orphansByPrev[txIn.PreviousOutPoint] =
				make(map[chainhash.Hash]*hnsutil.Tx)
		}
		mp.orphansByPrev[txIn.PreviousOutPoint][*tx.Hash()] = tx
	}

	log.Debugf("Stored orphan transaction %v (total: %d)", tx.Hash(),
		len(mp.orphans))
}

// maybeAddOrphan potentially adds an orphan to the orphan pool.
//
// This function MUST be called with the mempool lock held (for writes).
func (mp *TxPool) maybeAddOrphan(tx *hnsutil.Tx, tag Tag) error {
	// Ignore orphan transactions that are too large.  This helps avoid
	// a memory exhaustion attack based on sending a lot of really large
	// orphans.  In the case there is a valid transaction larger than this,
	// it will ultimtely be rebroadcast after the parent transactions
	// have been mined or otherwise received.
	//
	// Note that the number of orphan transactions in the orphan pool is
	// also limited, so this equates to a maximum memory used of
	// mp.cfg.Policy.MaxOrphanTxSize * mp.cfg.Policy.MaxOrphanTxs (which is ~5MB
	// using the default values at the time this comment was written).
	serializedLen := tx.MsgTx().SerializeSize()
	if serializedLen > mp.cfg.Policy.MaxOrphanTxSize {
		str := fmt.Sprintf("orphan transaction size of %d bytes is "+
			"larger than max allowed size of %d bytes",
			serializedLen, mp.cfg.Policy.MaxOrphanTxSize)
		return txRuleError(wire.RejectNonstandard, str)
	}

	// Add the orphan if the none of the above disqualified it.
	mp.addOrphan(tx, tag)

	return nil
}

// removeOrphanDoubleSpends removes all orphans which spend outputs spent by the
// passed transaction from the orphan pool.  Removing those orphans then leads
// to removing all orphans which rely on them, recursively.  This is necessary
// when a transaction is added to the main pool because it may spend outputs
// that orphans also spend.
//
// This function MUST be called with the mempool lock held (for writes).
func (mp *TxPool) removeOrphanDoubleSpends(tx *hnsutil.Tx) {
	msgTx := tx.MsgTx()
	for _, txIn := range msgTx.TxIn {
		for _, orphan := range mp.orphansByPrev[txIn.PreviousOutPoint] {
			mp.removeOrphan(orphan, true)
		}
	}
}

// isTransactionInPool returns whether or not the passed transaction already
// exists in the main pool.
//
// This function MUST be called with the mempool lock held (for reads).
func (mp *TxPool) isTransactionInPool(hash *chainhash.Hash) bool {
	if _, exists := mp.pool[*hash]; exists {
		return true
	}

	return false
}

// IsTransactionInPool returns whether or not the passed transaction already
// exists in the main pool.
//
// This function is safe for concurrent access.
func (mp *TxPool) IsTransactionInPool(hash *chainhash.Hash) bool {
	// Protect concurrent access.
	mp.mtx.RLock()
	inPool := mp.isTransactionInPool(hash)
	mp.mtx.RUnlock()

	return inPool
}

// isOrphanInPool returns whether or not the passed transaction already exists
// in the orphan pool.
//
// This function MUST be called with the mempool lock held (for reads).
func (mp *TxPool) isOrphanInPool(hash *chainhash.Hash) bool {
	if _, exists := mp.orphans[*hash]; exists {
		return true
	}

	return false
}

// IsOrphanInPool returns whether or not the passed transaction already exists
// in the orphan pool.
//
// This function is safe for concurrent access.
func (mp *TxPool) IsOrphanInPool(hash *chainhash.Hash) bool {
	// Protect concurrent access.
	mp.mtx.RLock()
	inPool := mp.isOrphanInPool(hash)
	mp.mtx.RUnlock()

	return inPool
}

// haveTransaction returns whether or not the passed transaction already exists
// in the main pool or in the orphan pool.
//
// This function MUST be called with the mempool lock held (for reads).
func (mp *TxPool) haveTransaction(hash *chainhash.Hash) bool {
	return mp.isTransactionInPool(hash) || mp.isOrphanInPool(hash)
}

// HaveTransaction returns whether or not the passed transaction already exists
// in the main pool or in the orphan pool.
//
// This function is safe for concurrent access.
func (mp *TxPool) HaveTransaction(hash *chainhash.Hash) bool {
	// Protect concurrent access.
	mp.mtx.RLock()
	haveTx := mp.haveTransaction(hash)
	mp.mtx.RUnlock()

	return haveTx
}

// removeTransaction is the internal function which implements the public
// RemoveTransaction.  See the comment for RemoveTransaction for more details.
//
// This function MUST be called with the mempool lock held (for writes).
func (mp *TxPool) removeTransaction(tx *hnsutil.Tx, removeRedeemers bool) {
	txHash := tx.Hash()
	if removeRedeemers {
		// Remove any transactions which rely on this one.
		for i := uint32(0); i < uint32(len(tx.MsgTx().TxOut)); i++ {
			prevOut := wire.OutPoint{Hash: *txHash, Index: i}
			if txRedeemer, exists := mp.outpoints[prevOut]; exists {
				mp.removeTransaction(txRedeemer, true)
			}
		}
	}

	// Remove the transaction if needed.
	if txDesc, exists := mp.pool[*txHash]; exists {
		// Remove unconfirmed address index entries associated with the
		// transaction if enabled.
		if mp.cfg.AddrIndex != nil {
			mp.cfg.AddrIndex.RemoveUnconfirmedTx(txHash)
		}

		// Mark the referenced outpoints as unspent by the pool.
		for _, txIn := range txDesc.Tx.MsgTx().TxIn {
			delete(mp.outpoints, txIn.PreviousOutPoint)
		}
		delete(mp.pool, *txHash)
		mp.removeNameOperationIndexes(txDesc.Tx)
		atomic.StoreInt64(&mp.lastUpdated, time.Now().Unix())
	}
}

// RemoveTransaction removes the passed transaction from the mempool. When the
// removeRedeemers flag is set, any transactions that redeem outputs from the
// removed transaction will also be removed recursively from the mempool, as
// they would otherwise become orphans.
//
// This function is safe for concurrent access.
func (mp *TxPool) RemoveTransaction(tx *hnsutil.Tx, removeRedeemers bool) {
	// Protect concurrent access.
	mp.mtx.Lock()
	mp.removeTransaction(tx, removeRedeemers)
	mp.mtx.Unlock()
}

// RemoveDoubleSpends removes all transactions which spend outputs spent by the
// passed transaction from the memory pool.  Removing those transactions then
// leads to removing all transactions which rely on them, recursively.  This is
// necessary when a block is connected to the main chain because the block may
// contain transactions which were previously unknown to the memory pool.
//
// This function is safe for concurrent access.
func (mp *TxPool) RemoveDoubleSpends(tx *hnsutil.Tx) {
	// Protect concurrent access.
	mp.mtx.Lock()
	for _, txIn := range tx.MsgTx().TxIn {
		if txRedeemer, ok := mp.outpoints[txIn.PreviousOutPoint]; ok {
			if !txRedeemer.Hash().IsEqual(tx.Hash()) {
				mp.removeTransaction(txRedeemer, true)
			}
		}
	}
	mp.mtx.Unlock()
}

// RemoveNameConflicts removes transactions from the mempool which mutate the
// same Handshake name as the passed transaction. This is necessary when a block
// is connected to the main chain because name operations such as OPEN do not
// necessarily conflict by input outpoint.
func (mp *TxPool) RemoveNameConflicts(tx *hnsutil.Tx) {
	txHash := tx.Hash()

	// Protect concurrent access.
	mp.mtx.Lock()
	for _, nameHash := range mutableNameActions(tx) {
		for {
			conflict, ok := mp.nameActions[nameHash]
			if !ok || conflict.Hash().IsEqual(txHash) {
				break
			}
			if txSpendsTransaction(conflict, tx) {
				break
			}
			mp.removeTransaction(conflict, true)
		}
	}
	mp.mtx.Unlock()
}

// addTransaction adds the passed transaction to the memory pool.  It should
// not be called directly as it doesn't perform any validation.  This is a
// helper for maybeAcceptTransaction.
//
// This function MUST be called with the mempool lock held (for writes).
func (mp *TxPool) addTransaction(utxoView *blockchain.UtxoViewpoint, tx *hnsutil.Tx, height int32, fee int64) *TxDesc {
	// Add the transaction to the pool and mark the referenced outpoints
	// as spent by the pool.
	txD := &TxDesc{
		TxDesc: mining.TxDesc{
			Tx:       tx,
			Added:    time.Now(),
			Height:   height,
			Fee:      fee,
			FeePerKB: fee * 1000 / GetTxVirtualSize(tx),
		},
		StartingPriority: mining.CalcPriority(tx.MsgTx(), utxoView, height),
	}

	mp.pool[*tx.Hash()] = txD
	for _, txIn := range tx.MsgTx().TxIn {
		mp.outpoints[txIn.PreviousOutPoint] = tx
	}
	mp.addNameOperationIndexes(tx)
	atomic.StoreInt64(&mp.lastUpdated, time.Now().Unix())

	// Add unconfirmed address index entries associated with the transaction
	// if enabled.
	if mp.cfg.AddrIndex != nil {
		mp.cfg.AddrIndex.AddUnconfirmedTx(tx, utxoView)
	}

	// Record this tx for fee estimation if enabled.
	if mp.cfg.FeeEstimator != nil {
		mp.cfg.FeeEstimator.ObserveTransaction(txD)
	}

	return txD
}

// AddCoinbaseProof adds or replaces a linked claim or airdrop proof for future
// block templates. The proof is cloned before it is stored.
func (mp *TxPool) AddCoinbaseProof(proof mining.CoinbaseProof) (
	chainhash.Hash, error) {

	hash, err := coinbaseProofHash(proof)
	if err != nil {
		return chainhash.Hash{}, err
	}
	policy, err := mp.coinbaseProofPolicy(proof)
	if err != nil {
		return chainhash.Hash{}, err
	}
	if err := mp.validateCoinbaseProofAdmission(policy); err != nil {
		return chainhash.Hash{}, err
	}
	cloned := cloneCoinbaseProof(proof)
	witnessHash := coinbaseProofWitnessHash(proof)

	mp.mtx.Lock()
	defer mp.mtx.Unlock()
	mp.ensureCoinbaseProofIndexes()

	for i := range mp.coinbaseProofs {
		if mp.coinbaseProofs[i].hash == hash {
			if mp.coinbaseProofs[i].proof.Fee != proof.Fee {
				return chainhash.Hash{}, fmt.Errorf("coinbase "+
					"proof fee metadata changed for %v; "+
					"remove the old proof first", hash)
			}
			mp.coinbaseProofs[i].proof = cloned
			mp.coinbaseProofs[i].policy = policy
			atomic.StoreInt64(&mp.lastUpdated, time.Now().Unix())
			return hash, nil
		}
		if coinbaseProofWitnessHash(mp.coinbaseProofs[i].proof) ==
			witnessHash {

			return chainhash.Hash{}, fmt.Errorf("coinbase proof " +
				"witness already exists in pool")
		}
	}
	if err := mp.checkCoinbaseProofIndexConflict(hash, policy); err != nil {
		return chainhash.Hash{}, err
	}

	mp.coinbaseProofs = append(mp.coinbaseProofs, coinbaseProofEntry{
		hash:   hash,
		proof:  cloned,
		policy: policy,
	})
	mp.indexCoinbaseProof(hash, policy)
	atomic.StoreInt64(&mp.lastUpdated, time.Now().Unix())
	return hash, nil
}

// RemoveCoinbaseProof removes the proof with the provided proof hash from the
// pool. It returns whether a proof was removed.
func (mp *TxPool) RemoveCoinbaseProof(hash chainhash.Hash) bool {
	mp.mtx.Lock()
	defer mp.mtx.Unlock()

	return mp.removeCoinbaseProof(hash)
}

func (mp *TxPool) removeCoinbaseProof(hash chainhash.Hash) bool {
	for i := range mp.coinbaseProofs {
		if mp.coinbaseProofs[i].hash != hash {
			continue
		}

		mp.removeCoinbaseProofAt(i)
		return true
	}
	return false
}

func (mp *TxPool) removeCoinbaseProofAt(i int) {
	mp.unindexCoinbaseProof(mp.coinbaseProofs[i])
	copy(mp.coinbaseProofs[i:], mp.coinbaseProofs[i+1:])
	mp.coinbaseProofs[len(mp.coinbaseProofs)-1] = coinbaseProofEntry{}
	mp.coinbaseProofs = mp.coinbaseProofs[:len(mp.coinbaseProofs)-1]
	atomic.StoreInt64(&mp.lastUpdated, time.Now().Unix())
}

// RemoveCoinbaseProofs removes claim and airdrop proofs consumed by the passed
// coinbase transaction. It returns the number of stored proofs removed.
func (mp *TxPool) RemoveCoinbaseProofs(coinbaseTx *hnsutil.Tx) int {
	if coinbaseTx == nil || !blockchain.IsCoinBase(coinbaseTx) {
		return 0
	}

	msgTx := coinbaseTx.MsgTx()
	remove := make(map[chainhash.Hash]struct{})
	for i := 1; i < len(msgTx.TxIn) && i < len(msgTx.TxOut); i++ {
		txIn := msgTx.TxIn[i]
		if len(txIn.Witness) != 1 {
			continue
		}

		hash, err := coinbaseProofHash(mining.CoinbaseProof{
			Witness: txIn.Witness[0],
			Output:  msgTx.TxOut[i],
		})
		if err != nil {
			continue
		}
		remove[hash] = struct{}{}
	}
	if len(remove) == 0 {
		return 0
	}

	mp.mtx.Lock()
	defer mp.mtx.Unlock()

	removed := 0
	for hash := range remove {
		if mp.removeCoinbaseProof(hash) {
			removed++
		}
	}
	return removed
}

// CoinbaseProofs returns claim and airdrop proofs to include in a block
// template at the provided height. Claim proofs are height-bound by their CLAIM
// covenant height; airdrop proofs are available until removed.
func (mp *TxPool) CoinbaseProofs(nextBlockHeight int32) (
	[]mining.CoinbaseProof, error) {

	mp.mtx.Lock()
	defer mp.mtx.Unlock()

	proofs := make([]mining.CoinbaseProof, 0, len(mp.coinbaseProofs))
	for i := 0; i < len(mp.coinbaseProofs); {
		entry := mp.coinbaseProofs[i]
		if err := mp.validateCoinbaseProofForHeight(entry.policy,
			nextBlockHeight); err != nil {

			if coinbaseProofErrorPrunable(err) {
				mp.removeCoinbaseProofAt(i)
				continue
			}
			return nil, err
		}
		if !coinbaseProofMatchesHeight(entry.policy, nextBlockHeight) {
			i++
			continue
		}
		proofs = append(proofs, cloneCoinbaseProof(entry.proof))
		i++
	}
	return proofs, nil
}

// PruneCoinbaseProofs removes stored coinbase proofs that are no longer
// eligible to be mined at the current chain tip.
func (mp *TxPool) PruneCoinbaseProofs() (int, error) {
	nextBlockHeight, ok := mp.nextBlockHeight()
	if !ok {
		return 0, nil
	}

	mp.mtx.Lock()
	defer mp.mtx.Unlock()

	removed := 0
	for i := 0; i < len(mp.coinbaseProofs); {
		entry := mp.coinbaseProofs[i]
		err := mp.validateCoinbaseProofForHeight(entry.policy,
			nextBlockHeight)
		if err == nil {
			i++
			continue
		}
		if !coinbaseProofErrorPrunable(err) {
			return removed, err
		}

		mp.removeCoinbaseProofAt(i)
		removed++
	}
	return removed, nil
}

func coinbaseProofHash(proof mining.CoinbaseProof) (chainhash.Hash, error) {
	if err := validateCoinbaseProofShape(proof); err != nil {
		return chainhash.Hash{}, err
	}

	var buf bytes.Buffer
	if err := wire.WriteVarBytes(&buf, 0, proof.Witness); err != nil {
		return chainhash.Hash{}, err
	}
	if err := wire.WriteTxOut(&buf, 0, wire.TxVersion, proof.Output); err != nil {
		return chainhash.Hash{}, err
	}
	return chainhash.HashH(buf.Bytes()), nil
}

func validateCoinbaseProofShape(proof mining.CoinbaseProof) error {
	if err := mining.ValidateCoinbaseProofShape(proof); err != nil {
		return fmt.Errorf("coinbase proof %w", err)
	}
	return nil
}

func coinbaseProofWitnessHash(proof mining.CoinbaseProof) chainhash.Hash {
	return blockchain.RawProofHash(proof.Witness)
}

// HaveCoinbaseProof returns whether the pool has a claim or airdrop proof with
// the provided hsd proof hash.
func (mp *TxPool) HaveCoinbaseProof(hash *chainhash.Hash) bool {
	if hash == nil {
		return false
	}

	mp.mtx.RLock()
	defer mp.mtx.RUnlock()

	for _, entry := range mp.coinbaseProofs {
		if coinbaseProofWitnessHash(entry.proof) == *hash {
			return true
		}
	}
	return false
}

// FetchCoinbaseProof returns a cloned claim or airdrop proof by hsd proof hash.
func (mp *TxPool) FetchCoinbaseProof(hash *chainhash.Hash) (
	mining.CoinbaseProof, bool) {

	if hash == nil {
		return mining.CoinbaseProof{}, false
	}

	mp.mtx.RLock()
	defer mp.mtx.RUnlock()

	for _, entry := range mp.coinbaseProofs {
		if coinbaseProofWitnessHash(entry.proof) == *hash {
			return cloneCoinbaseProof(entry.proof), true
		}
	}
	return mining.CoinbaseProof{}, false
}

func cloneCoinbaseProof(proof mining.CoinbaseProof) mining.CoinbaseProof {
	return mining.CoinbaseProof{
		Witness: append([]byte(nil), proof.Witness...),
		Output:  cloneCoinbaseProofOutput(proof.Output),
		Fee:     proof.Fee,
	}
}

func cloneCoinbaseProofOutput(output *wire.TxOut) *wire.TxOut {
	if output == nil {
		return nil
	}

	return wire.NewTxOut(output.Value,
		wire.Address{
			Version: output.Address.Version,
			Hash:    append([]byte(nil), output.Address.Hash...),
		},
		cloneCoinbaseProofCovenant(output.Covenant),
	)
}

func cloneCoinbaseProofCovenant(covenant wire.Covenant) wire.Covenant {
	items := make([][]byte, len(covenant.Items))
	for i, item := range covenant.Items {
		items[i] = append([]byte(nil), item...)
	}
	return wire.Covenant{
		Type:  covenant.Type,
		Items: items,
	}
}

type coinbaseProofPolicyError struct {
	msg      string
	prunable bool
}

func (e *coinbaseProofPolicyError) Error() string {
	return e.msg
}

func coinbaseProofErrorPrunable(err error) bool {
	policyErr, ok := err.(*coinbaseProofPolicyError)
	return ok && policyErr.prunable
}

func coinbaseProofReject(format string, args ...interface{}) error {
	return &coinbaseProofPolicyError{
		msg: fmt.Sprintf(format, args...),
	}
}

func coinbaseProofPrune(format string, args ...interface{}) error {
	return &coinbaseProofPolicyError{
		msg:      fmt.Sprintf(format, args...),
		prunable: true,
	}
}

func (mp *TxPool) coinbaseProofPolicy(proof mining.CoinbaseProof) (
	coinbaseProofPolicy, error) {

	if err := validateCoinbaseProofShape(proof); err != nil {
		return coinbaseProofPolicy{}, err
	}

	switch proof.Output.Covenant.Type {
	case wire.CovenantNone:
		return coinbaseAirdropPolicy(proof)

	case wire.CovenantClaim:
		return mp.coinbaseClaimPolicy(proof)

	default:
		return coinbaseProofPolicy{}, fmt.Errorf("coinbase proof has "+
			"unsupported covenant type %d", proof.Output.Covenant.Type)
	}
}

func coinbaseAirdropPolicy(proof mining.CoinbaseProof) (
	coinbaseProofPolicy, error) {

	meta, err := blockchain.DecodeAirdropProofMetadata(proof.Witness)
	if err != nil {
		return coinbaseProofPolicy{}, fmt.Errorf("airdrop proof: %w", err)
	}
	if proof.Fee != int64(meta.Fee) {
		return coinbaseProofPolicy{}, fmt.Errorf("airdrop proof fee "+
			"metadata = %d, want %d", proof.Fee, meta.Fee)
	}
	if proof.Output.Value != int64(meta.Value-meta.Fee) {
		return coinbaseProofPolicy{}, fmt.Errorf("airdrop proof output "+
			"value = %d, want %d", proof.Output.Value,
			meta.Value-meta.Fee)
	}
	if proof.Output.Address.Version != meta.Version ||
		!bytes.Equal(proof.Output.Address.Hash, meta.Address) {

		return coinbaseProofPolicy{}, fmt.Errorf("airdrop proof output " +
			"address mismatch")
	}

	return coinbaseProofPolicy{
		kind:            coinbaseProofKindAirdrop,
		airdropPosition: meta.Position,
		airdropWeak:     meta.Weak,
		airdropGooSig:   meta.GooSig,
	}, nil
}

func (mp *TxPool) coinbaseClaimPolicy(proof mining.CoinbaseProof) (
	coinbaseProofPolicy, error) {

	covenant := proof.Output.Covenant
	policy := coinbaseProofPolicy{
		kind: coinbaseProofKindClaim,
	}
	copy(policy.claimNameHash[:], covenant.Items[0])
	policy.claimHeight = binary.LittleEndian.Uint32(covenant.Items[1])
	policy.hasClaimHeight = true

	params := mp.cfg.ChainParams
	if params == nil || params.NameClaimPrefix == "" {
		return policy, nil
	}

	meta, err := blockchain.DecodeClaimProofMetadata(proof.Witness, params)
	if err != nil {
		return coinbaseProofPolicy{}, fmt.Errorf("CLAIM proof: %w", err)
	}
	if err := validateCoinbaseClaimMetadata(proof, policy, meta); err != nil {
		return coinbaseProofPolicy{}, err
	}

	policy.claimInception = meta.Inception
	policy.claimExpiration = meta.Expiration
	policy.hasClaimWindow = true
	policy.hasClaimExpiry = true
	return policy, nil
}

func validateCoinbaseClaimMetadata(proof mining.CoinbaseProof,
	policy coinbaseProofPolicy, meta blockchain.ClaimProofMetadata) error {

	covenant := proof.Output.Covenant
	if meta.NameHash != policy.claimNameHash ||
		!bytes.Equal(covenant.Items[2], []byte(meta.Name)) {

		return fmt.Errorf("CLAIM proof name metadata mismatch")
	}
	flags := covenant.Items[3][0]
	if (flags&1 != 0) != meta.Weak {
		return fmt.Errorf("CLAIM proof weak metadata mismatch")
	}
	var commitHash chainhash.Hash
	copy(commitHash[:], covenant.Items[4])
	if commitHash != meta.CommitHash ||
		binary.LittleEndian.Uint32(covenant.Items[5]) !=
			meta.CommitHeight {

		return fmt.Errorf("CLAIM proof commit metadata mismatch")
	}
	if proof.Fee != int64(meta.Fee) {
		return fmt.Errorf("CLAIM proof fee metadata = %d, want %d",
			proof.Fee, meta.Fee)
	}
	if proof.Output.Value != int64(meta.Value-meta.Fee) {
		return fmt.Errorf("CLAIM proof output value = %d, want %d",
			proof.Output.Value, meta.Value-meta.Fee)
	}
	if proof.Output.Address.Version != meta.Version ||
		!bytes.Equal(proof.Output.Address.Hash, meta.Address) {

		return fmt.Errorf("CLAIM proof output address mismatch")
	}
	return nil
}

func (mp *TxPool) validateCoinbaseProofAdmission(
	policy coinbaseProofPolicy) error {

	nextBlockHeight, hasHeight := mp.nextBlockHeight()
	if !hasHeight {
		return nil
	}
	if err := mp.validateCoinbaseProofForHeight(policy,
		nextBlockHeight); err != nil {

		return err
	}
	if policy.kind == coinbaseProofKindClaim && policy.hasClaimHeight &&
		policy.claimHeight != uint32(nextBlockHeight) {

		return coinbaseProofReject("CLAIM proof height = %d, want %d",
			policy.claimHeight, nextBlockHeight)
	}
	return nil
}

func (mp *TxPool) validateCoinbaseProofForHeight(
	policy coinbaseProofPolicy, nextBlockHeight int32) error {

	if nextBlockHeight < 0 {
		return nil
	}

	switch policy.kind {
	case coinbaseProofKindAirdrop:
		return mp.validateAirdropProofForHeight(policy, nextBlockHeight)

	case coinbaseProofKindClaim:
		return mp.validateClaimProofForHeight(policy, nextBlockHeight)

	default:
		return nil
	}
}

func (mp *TxPool) validateAirdropProofForHeight(
	policy coinbaseProofPolicy, nextBlockHeight int32) error {

	if mp.cfg.IsDeploymentActive != nil {
		active, err := mp.cfg.IsDeploymentActive(
			chaincfg.DeploymentAirstop)
		if err != nil {
			return err
		}
		if active {
			return coinbaseProofPrune("airdrop proofs are disabled")
		}

		active, err = mp.cfg.IsDeploymentActive(chaincfg.DeploymentHardening)
		if err != nil {
			return err
		}
		if active && policy.airdropWeak {
			return coinbaseProofPrune("weak RSA airdrop proof is disabled")
		}
	}

	if mp.cfg.ChainParams != nil &&
		uint32(nextBlockHeight) >= mp.cfg.ChainParams.AirdropGooSigStop &&
		policy.airdropGooSig {

		return coinbaseProofPrune("GooSig airdrop proof is disabled")
	}

	if mp.cfg.IsAirdropSpent != nil {
		spent, err := mp.cfg.IsAirdropSpent(policy.airdropPosition)
		if err != nil {
			return err
		}
		if spent {
			return coinbaseProofPrune("airdrop proof position %d is "+
				"already spent", policy.airdropPosition)
		}
	}

	return nil
}

func (mp *TxPool) validateClaimProofForHeight(
	policy coinbaseProofPolicy, nextBlockHeight int32) error {

	nextHeight := uint32(nextBlockHeight)
	if mp.cfg.ChainParams != nil &&
		nextHeight >= mp.cfg.ChainParams.NameClaimPeriod {

		return coinbaseProofPrune("CLAIM proof period has ended")
	}
	if policy.hasClaimHeight && policy.claimHeight < nextHeight {
		return coinbaseProofPrune("CLAIM proof height = %d, before %d",
			policy.claimHeight, nextBlockHeight)
	}
	if mp.cfg.MedianTimePast != nil {
		medianTime := mp.cfg.MedianTimePast().Unix()
		if policy.hasClaimWindow &&
			medianTime < int64(policy.claimInception) {

			return coinbaseProofPrune("CLAIM proof is not active")
		}
		if policy.hasClaimExpiry &&
			medianTime > int64(policy.claimExpiration) {

			return coinbaseProofPrune("CLAIM proof is expired")
		}
	}

	return nil
}

func (mp *TxPool) nextBlockHeight() (int32, bool) {
	if mp.cfg.BestHeight == nil {
		return 0, false
	}
	return mp.cfg.BestHeight() + 1, true
}

func (mp *TxPool) ensureCoinbaseProofIndexes() {
	if mp.coinbaseClaims == nil {
		mp.coinbaseClaims = make(map[chainhash.Hash]chainhash.Hash)
	}
	if mp.coinbaseAirdrops == nil {
		mp.coinbaseAirdrops = make(map[uint32]chainhash.Hash)
	}
}

func (mp *TxPool) checkCoinbaseProofIndexConflict(hash chainhash.Hash,
	policy coinbaseProofPolicy) error {

	switch policy.kind {
	case coinbaseProofKindAirdrop:
		if existing, ok := mp.coinbaseAirdrops[policy.airdropPosition]; ok &&
			existing != hash {

			return fmt.Errorf("airdrop proof position %d already "+
				"exists in pool", policy.airdropPosition)
		}

	case coinbaseProofKindClaim:
		if existing, ok := mp.coinbaseClaims[policy.claimNameHash]; ok &&
			existing != hash {

			return fmt.Errorf("CLAIM proof name already exists in pool")
		}
	}
	return nil
}

func (mp *TxPool) indexCoinbaseProof(hash chainhash.Hash,
	policy coinbaseProofPolicy) {

	switch policy.kind {
	case coinbaseProofKindAirdrop:
		mp.coinbaseAirdrops[policy.airdropPosition] = hash
	case coinbaseProofKindClaim:
		mp.coinbaseClaims[policy.claimNameHash] = hash
	}
}

func (mp *TxPool) unindexCoinbaseProof(entry coinbaseProofEntry) {
	switch entry.policy.kind {
	case coinbaseProofKindAirdrop:
		if hash, ok := mp.coinbaseAirdrops[entry.policy.airdropPosition]; ok && hash == entry.hash {

			delete(mp.coinbaseAirdrops, entry.policy.airdropPosition)
		}
	case coinbaseProofKindClaim:
		if hash, ok := mp.coinbaseClaims[entry.policy.claimNameHash]; ok && hash == entry.hash {

			delete(mp.coinbaseClaims, entry.policy.claimNameHash)
		}
	}
}

func coinbaseProofMatchesHeight(policy coinbaseProofPolicy,
	nextBlockHeight int32) bool {

	if policy.kind != coinbaseProofKindClaim {
		return true
	}
	if nextBlockHeight < 0 || !policy.hasClaimHeight {
		return false
	}

	return policy.claimHeight == uint32(nextBlockHeight)
}

func isMempoolMutableNameCovenant(covenantType uint8) bool {
	switch covenantType {
	case wire.CovenantClaim, wire.CovenantOpen, wire.CovenantRegister,
		wire.CovenantUpdate, wire.CovenantRenew, wire.CovenantTransfer,
		wire.CovenantFinalize, wire.CovenantRevoke:

		return true
	default:
		return false
	}
}

func covenantNameHash(covenant wire.Covenant) (chainhash.Hash, bool) {
	if len(covenant.Items) == 0 ||
		len(covenant.Items[0]) != chainhash.HashSize {

		return chainhash.Hash{}, false
	}

	var nameHash chainhash.Hash
	copy(nameHash[:], covenant.Items[0])
	return nameHash, true
}

func mutableNameActions(tx *hnsutil.Tx) []chainhash.Hash {
	var actions []chainhash.Hash
	for _, txOut := range tx.MsgTx().TxOut {
		covenant := txOut.Covenant
		if !isMempoolMutableNameCovenant(covenant.Type) {
			continue
		}

		nameHash, ok := covenantNameHash(covenant)
		if !ok {
			continue
		}
		actions = append(actions, nameHash)
	}

	return actions
}

func hasNameCovenant(tx *hnsutil.Tx) bool {
	for _, txOut := range tx.MsgTx().TxOut {
		if txOut.Covenant.Type != wire.CovenantNone {
			return true
		}
	}
	return false
}

func (mp *TxPool) addNameOperationIndexes(tx *hnsutil.Tx) {
	actions := mutableNameActions(tx)
	if len(actions) == 0 {
		return
	}

	if mp.nameActions == nil {
		mp.nameActions = make(map[chainhash.Hash]*hnsutil.Tx)
	}
	for _, nameHash := range actions {
		mp.nameActions[nameHash] = tx
	}
}

func (mp *TxPool) removeNameOperationIndexes(tx *hnsutil.Tx) {
	if len(mp.nameActions) == 0 {
		return
	}

	txHash := tx.Hash()
	for _, nameHash := range mutableNameActions(tx) {
		indexedTx, ok := mp.nameActions[nameHash]
		if !ok || !indexedTx.Hash().IsEqual(txHash) {
			continue
		}
		delete(mp.nameActions, nameHash)
		mp.rebuildNameOperationIndex(nameHash)
	}
}

func (mp *TxPool) rebuildNameOperationIndex(nameHash chainhash.Hash) {
	var tip *hnsutil.Tx
	for _, txDesc := range mp.pool {
		tx := txDesc.Tx
		if !txMutatesName(tx, nameHash) ||
			hasSpentMutableNameOutput(mp, tx, nameHash) {

			continue
		}
		tip = tx
		break
	}

	if tip != nil {
		mp.nameActions[nameHash] = tip
	}
}

func txMutatesName(tx *hnsutil.Tx, nameHash chainhash.Hash) bool {
	for _, txOut := range tx.MsgTx().TxOut {
		covenant := txOut.Covenant
		if !isMempoolMutableNameCovenant(covenant.Type) {
			continue
		}
		outputNameHash, ok := covenantNameHash(covenant)
		if ok && outputNameHash == nameHash {
			return true
		}
	}
	return false
}

func hasSpentMutableNameOutput(mp *TxPool, tx *hnsutil.Tx,
	nameHash chainhash.Hash) bool {

	txHash := tx.Hash()
	for outputIndex, txOut := range tx.MsgTx().TxOut {
		covenant := txOut.Covenant
		if !isMempoolMutableNameCovenant(covenant.Type) {
			continue
		}
		outputNameHash, ok := covenantNameHash(covenant)
		if !ok || outputNameHash != nameHash {
			continue
		}
		prevOut := wire.OutPoint{
			Hash:  *txHash,
			Index: uint32(outputIndex),
		}
		if _, spent := mp.outpoints[prevOut]; spent {
			return true
		}
	}
	return false
}

func txSpendsTransaction(spender, spent *hnsutil.Tx) bool {
	spentHash := spent.Hash()
	for _, txIn := range spender.MsgTx().TxIn {
		if txIn.PreviousOutPoint.Hash == *spentHash {
			return true
		}
	}
	return false
}

func (mp *TxPool) checkNameOperationConflicts(tx *hnsutil.Tx,
	replacementConflicts map[chainhash.Hash]*hnsutil.Tx) error {

	txHash := tx.Hash()
	txActions := make(map[chainhash.Hash]struct{})
	for _, nameHash := range mutableNameActions(tx) {
		if _, exists := txActions[nameHash]; exists {
			str := fmt.Sprintf("transaction %v has duplicate name "+
				"covenant action for %v", txHash, nameHash)
			return txRuleError(wire.RejectInvalid, str)
		}
		txActions[nameHash] = struct{}{}

		conflict, exists := mp.nameActions[nameHash]
		if !exists || conflict.Hash().IsEqual(txHash) {
			continue
		}
		if _, replaced := replacementConflicts[*conflict.Hash()]; replaced {
			continue
		}
		if txSpendsTransaction(tx, conflict) {
			continue
		}

		str := fmt.Sprintf("name covenant action for %v already "+
			"exists in mempool as transaction %v", nameHash,
			conflict.Hash())
		return txRuleError(wire.RejectDuplicate, str)
	}

	return nil
}

// PruneInvalidNameTransactions removes mempool transactions whose Handshake
// covenant transitions are no longer valid against the current chain state.
func (mp *TxPool) PruneInvalidNameTransactions() []*TxDesc {
	if mp.cfg.CheckTransactionNames == nil &&
		mp.cfg.NewNameValidationView == nil {

		return nil
	}

	mp.mtx.Lock()
	defer mp.mtx.Unlock()

	var removed []*TxDesc
	nextBlockHeight := mp.cfg.BestHeight() + 1
	prevTime := mp.cfg.MedianTimePast().Unix()
	if mp.cfg.NewNameValidationView != nil {
		for {
			_, invalid, err := mp.nameValidationViewForMempool(
				nextBlockHeight, prevTime, nil,
			)
			if err == nil || invalid == nil {
				return removed
			}

			removed = append(removed, invalid)
			mp.removeTransaction(invalid.Tx, true)
		}
	}

	for _, txDesc := range mp.pool {
		tx := txDesc.Tx
		if !hasNameCovenant(tx) {
			continue
		}

		utxoView, err := mp.fetchInputUtxos(tx)
		if err == nil {
			err = mp.cfg.CheckTransactionNames(tx, nextBlockHeight,
				prevTime, utxoView)
		}
		if err == nil {
			continue
		}

		removed = append(removed, txDesc)
		mp.removeTransaction(tx, true)
	}

	return removed
}

func (mp *TxPool) checkTransactionNames(tx *hnsutil.Tx,
	nextBlockHeight int32, prevTime int64,
	utxoView *blockchain.UtxoViewpoint,
	excluded map[chainhash.Hash]*hnsutil.Tx) error {

	if !hasNameCovenant(tx) {
		if mp.cfg.NewNameValidationView == nil &&
			mp.cfg.CheckTransactionNames != nil {

			return mp.cfg.CheckTransactionNames(tx,
				nextBlockHeight, prevTime, utxoView)
		}
		return nil
	}

	if mp.cfg.NewNameValidationView != nil {
		nameView, invalid, err := mp.nameValidationViewForMempool(
			nextBlockHeight, prevTime, excluded,
		)
		if err != nil {
			if invalid != nil {
				return fmt.Errorf("mempool name transaction %v "+
					"is invalid: %w", invalid.Tx.Hash(), err)
			}
			return err
		}
		return nameView.ApplyTransaction(tx, nextBlockHeight,
			prevTime, utxoView)
	}

	if mp.cfg.CheckTransactionNames == nil {
		return nil
	}

	return mp.cfg.CheckTransactionNames(tx, nextBlockHeight, prevTime,
		utxoView)
}

func (mp *TxPool) nameValidationViewForMempool(nextBlockHeight int32,
	prevTime int64, excluded map[chainhash.Hash]*hnsutil.Tx) (
	NameValidationView, *TxDesc, error) {

	nameView, err := mp.cfg.NewNameValidationView()
	if err != nil {
		return nil, nil, err
	}

	invalid, err := mp.applyMempoolNameTransactions(
		nameView, nextBlockHeight, prevTime, excluded,
	)
	if err != nil {
		return nil, invalid, err
	}

	return nameView, nil, nil
}

func (mp *TxPool) applyMempoolNameTransactions(nameView NameValidationView,
	nextBlockHeight int32, prevTime int64,
	excluded map[chainhash.Hash]*hnsutil.Tx) (*TxDesc, error) {

	visited := make(map[chainhash.Hash]struct{}, len(mp.pool))
	visiting := make(map[chainhash.Hash]struct{}, len(mp.pool))

	var visit func(chainhash.Hash) (*TxDesc, error)
	visit = func(txHash chainhash.Hash) (*TxDesc, error) {
		if _, done := visited[txHash]; done {
			return nil, nil
		}
		if _, skip := excluded[txHash]; skip {
			visited[txHash] = struct{}{}
			return nil, nil
		}

		txDesc, exists := mp.pool[txHash]
		if !exists {
			visited[txHash] = struct{}{}
			return nil, nil
		}
		if _, cycle := visiting[txHash]; cycle {
			return txDesc, fmt.Errorf("mempool transaction "+
				"dependency cycle involving %v", txHash)
		}

		visiting[txHash] = struct{}{}
		for _, txIn := range txDesc.Tx.MsgTx().TxIn {
			parentHash := txIn.PreviousOutPoint.Hash
			if _, exists := mp.pool[parentHash]; !exists {
				continue
			}
			invalid, err := visit(parentHash)
			if err != nil {
				return invalid, err
			}
		}
		delete(visiting, txHash)
		visited[txHash] = struct{}{}

		if !hasNameCovenant(txDesc.Tx) {
			return nil, nil
		}

		utxoView, err := mp.fetchInputUtxos(txDesc.Tx)
		if err != nil {
			return txDesc, err
		}
		if err := nameView.ApplyTransaction(txDesc.Tx,
			nextBlockHeight, prevTime, utxoView); err != nil {

			return txDesc, err
		}

		return nil, nil
	}

	for txHash := range mp.pool {
		invalid, err := visit(txHash)
		if err != nil {
			return invalid, err
		}
	}

	return nil, nil
}

// checkPoolDoubleSpend checks whether or not the passed transaction is
// attempting to spend coins already spent by other transactions in the pool.
// If it does, we'll check whether each of those transactions are signaling for
// replacement. If just one of them isn't, an error is returned. Otherwise, a
// boolean is returned signaling that the transaction is a replacement. Note it
// does not check for double spends against transactions already in the main
// chain.
//
// This function MUST be called with the mempool lock held (for reads).
func (mp *TxPool) checkPoolDoubleSpend(tx *hnsutil.Tx) (bool, error) {
	var isReplacement bool
	for _, txIn := range tx.MsgTx().TxIn {
		conflict, ok := mp.outpoints[txIn.PreviousOutPoint]
		if !ok {
			continue
		}

		// Reject the transaction if we don't accept replacement
		// transactions or if it doesn't signal replacement.
		if mp.cfg.Policy.RejectReplacement ||
			!mp.signalsReplacement(conflict, nil) {
			str := fmt.Sprintf("output already spent in mempool: "+
				"output=%v, tx=%v", txIn.PreviousOutPoint,
				conflict.Hash())
			return false, txRuleError(wire.RejectDuplicate, str)
		}

		isReplacement = true
	}

	return isReplacement, nil
}

// signalsReplacement determines if a transaction is signaling that it can be
// replaced using the Replace-By-Fee (RBF) policy. This policy specifies two
// ways a transaction can signal that it is replaceable:
//
// Explicit signaling: A transaction is considered to have opted in to allowing
// replacement of itself if any of its inputs have a sequence number less than
// 0xfffffffe.
//
// Inherited signaling: Transactions that don't explicitly signal replaceability
// are replaceable under this policy for as long as any one of their ancestors
// signals replaceability and remains unconfirmed.
//
// The cache is optional and serves as an optimization to avoid visiting
// transactions we've already determined don't signal replacement.
//
// This function MUST be called with the mempool lock held (for reads).
func (mp *TxPool) signalsReplacement(tx *hnsutil.Tx,
	cache map[chainhash.Hash]struct{}) bool {

	// If a cache was not provided, we'll initialize one now to use for the
	// recursive calls.
	if cache == nil {
		cache = make(map[chainhash.Hash]struct{})
	}

	for _, txIn := range tx.MsgTx().TxIn {
		if txIn.Sequence <= MaxRBFSequence {
			return true
		}

		hash := txIn.PreviousOutPoint.Hash
		unconfirmedAncestor, ok := mp.pool[hash]
		if !ok {
			continue
		}

		// If we've already determined the transaction doesn't signal
		// replacement, we can avoid visiting it again.
		if _, ok := cache[hash]; ok {
			continue
		}

		if mp.signalsReplacement(unconfirmedAncestor.Tx, cache) {
			return true
		}

		// Since the transaction doesn't signal replacement, we'll cache
		// its result to ensure we don't attempt to determine so again.
		cache[hash] = struct{}{}
	}

	return false
}

// txAncestors returns all of the unconfirmed ancestors of the given
// transaction. Given transactions A, B, and C where C spends B and B spends A,
// A and B are considered ancestors of C.
//
// The cache is optional and serves as an optimization to avoid visiting
// transactions we've already determined ancestors of.
//
// This function MUST be called with the mempool lock held (for reads).
func (mp *TxPool) txAncestors(tx *hnsutil.Tx,
	cache map[chainhash.Hash]map[chainhash.Hash]*hnsutil.Tx) map[chainhash.Hash]*hnsutil.Tx {

	// If a cache was not provided, we'll initialize one now to use for the
	// recursive calls.
	if cache == nil {
		cache = make(map[chainhash.Hash]map[chainhash.Hash]*hnsutil.Tx)
	}

	ancestors := make(map[chainhash.Hash]*hnsutil.Tx)
	for _, txIn := range tx.MsgTx().TxIn {
		parent, ok := mp.pool[txIn.PreviousOutPoint.Hash]
		if !ok {
			continue
		}
		ancestors[*parent.Tx.Hash()] = parent.Tx

		// Determine if the ancestors of this ancestor have already been
		// computed. If they haven't, we'll do so now and cache them to
		// use them later on if necessary.
		moreAncestors, ok := cache[*parent.Tx.Hash()]
		if !ok {
			moreAncestors = mp.txAncestors(parent.Tx, cache)
			cache[*parent.Tx.Hash()] = moreAncestors
		}

		maps.Copy(ancestors, moreAncestors)
	}

	return ancestors
}

// txDescendants returns all of the unconfirmed descendants of the given
// transaction. Given transactions A, B, and C where C spends B and B spends A,
// B and C are considered descendants of A. A cache can be provided in order to
// easily retrieve the descendants of transactions we've already determined the
// descendants of.
//
// This function MUST be called with the mempool lock held (for reads).
func (mp *TxPool) txDescendants(tx *hnsutil.Tx,
	cache map[chainhash.Hash]map[chainhash.Hash]*hnsutil.Tx) map[chainhash.Hash]*hnsutil.Tx {

	// If a cache was not provided, we'll initialize one now to use for the
	// recursive calls.
	if cache == nil {
		cache = make(map[chainhash.Hash]map[chainhash.Hash]*hnsutil.Tx)
	}

	// We'll go through all of the outputs of the transaction to determine
	// if they are spent by any other mempool transactions.
	descendants := make(map[chainhash.Hash]*hnsutil.Tx)
	op := wire.OutPoint{Hash: *tx.Hash()}
	for i := range tx.MsgTx().TxOut {
		op.Index = uint32(i)
		descendant, ok := mp.outpoints[op]
		if !ok {
			continue
		}
		descendants[*descendant.Hash()] = descendant

		// Determine if the descendants of this descendant have already
		// been computed. If they haven't, we'll do so now and cache
		// them to use them later on if necessary.
		moreDescendants, ok := cache[*descendant.Hash()]
		if !ok {
			moreDescendants = mp.txDescendants(descendant, cache)
			cache[*descendant.Hash()] = moreDescendants
		}

		for _, moreDescendant := range moreDescendants {
			descendants[*moreDescendant.Hash()] = moreDescendant
		}
	}

	return descendants
}

// txConflicts returns all of the unconfirmed transactions that would become
// conflicts if we were to accept the given transaction into the mempool. An
// unconfirmed conflict is known as a transaction that spends an output already
// spent by a different transaction within the mempool. Any descendants of these
// transactions are also considered conflicts as they would no longer exist.
// These are generally not allowed except for transactions that signal RBF
// support.
//
// This function MUST be called with the mempool lock held (for reads).
func (mp *TxPool) txConflicts(tx *hnsutil.Tx) map[chainhash.Hash]*hnsutil.Tx {
	conflicts := make(map[chainhash.Hash]*hnsutil.Tx)
	for _, txIn := range tx.MsgTx().TxIn {
		conflict, ok := mp.outpoints[txIn.PreviousOutPoint]
		if !ok {
			continue
		}
		conflicts[*conflict.Hash()] = conflict
		descendants := mp.txDescendants(conflict, nil)
		maps.Copy(conflicts, descendants)
	}
	return conflicts
}

// CheckSpend checks whether the passed outpoint is already spent by a
// transaction in the mempool. If that's the case the spending transaction will
// be returned, if not nil will be returned.
func (mp *TxPool) CheckSpend(op wire.OutPoint) *hnsutil.Tx {
	mp.mtx.RLock()
	txR := mp.outpoints[op]
	mp.mtx.RUnlock()

	return txR
}

// fetchInputUtxos loads utxo details about the input transactions referenced by
// the passed transaction.  First, it loads the details form the viewpoint of
// the main chain, then it adjusts them based upon the contents of the
// transaction pool.
//
// This function MUST be called with the mempool lock held (for reads).
func (mp *TxPool) fetchInputUtxos(tx *hnsutil.Tx) (*blockchain.UtxoViewpoint, error) {
	utxoView, err := mp.cfg.FetchUtxoView(tx)
	if err != nil {
		return nil, err
	}

	// Attempt to populate any missing inputs from the transaction pool.
	for _, txIn := range tx.MsgTx().TxIn {
		prevOut := &txIn.PreviousOutPoint
		entry := utxoView.LookupEntry(*prevOut)
		if entry != nil && !entry.IsSpent() {
			continue
		}

		if poolTxDesc, exists := mp.pool[prevOut.Hash]; exists {
			// AddTxOut ignores out of range index values, so it is
			// safe to call without bounds checking here.
			utxoView.AddTxOut(poolTxDesc.Tx, prevOut.Index,
				mining.UnminedHeight)
		}
	}

	return utxoView, nil
}

// FetchTransaction returns the requested transaction from the transaction pool.
// This only fetches from the main transaction pool and does not include
// orphans.
//
// This function is safe for concurrent access.
func (mp *TxPool) FetchTransaction(txHash *chainhash.Hash) (*hnsutil.Tx, error) {
	// Protect concurrent access.
	mp.mtx.RLock()
	txDesc, exists := mp.pool[*txHash]
	mp.mtx.RUnlock()

	if exists {
		return txDesc.Tx, nil
	}

	return nil, fmt.Errorf("transaction is not in the pool")
}

// validateReplacement determines whether a transaction is deemed as a valid
// replacement of all of its conflicts according to the RBF policy. If it is
// valid, no error is returned. Otherwise, an error is returned indicating what
// went wrong.
//
// This function MUST be called with the mempool lock held (for reads).
func (mp *TxPool) validateReplacement(tx *hnsutil.Tx,
	txFee int64) (map[chainhash.Hash]*hnsutil.Tx, error) {

	// First, we'll make sure the set of conflicting transactions doesn't
	// exceed the maximum allowed.
	conflicts := mp.txConflicts(tx)
	if len(conflicts) > MaxReplacementEvictions {
		str := fmt.Sprintf("%v: replacement transaction evicts more "+
			"transactions than permitted: max is %v, evicts %v",
			tx.Hash(), MaxReplacementEvictions, len(conflicts))
		return nil, txRuleError(wire.RejectNonstandard, str)
	}

	// The set of conflicts (transactions we'll replace) and ancestors
	// should not overlap, otherwise the replacement would be spending an
	// output that no longer exists.
	for ancestorHash := range mp.txAncestors(tx, nil) {
		if _, ok := conflicts[ancestorHash]; !ok {
			continue
		}
		str := fmt.Sprintf("%v: replacement transaction spends parent "+
			"transaction %v", tx.Hash(), ancestorHash)
		return nil, txRuleError(wire.RejectInvalid, str)
	}

	// The replacement should have a higher fee rate than each of the
	// conflicting transactions and a higher absolute fee than the fee sum
	// of all the conflicting transactions.
	//
	// We usually don't want to accept replacements with lower fee rates
	// than what they replaced as that would lower the fee rate of the next
	// block. Requiring that the fee rate always be increased is also an
	// easy-to-reason about way to prevent DoS attacks via replacements.
	var (
		txSize           = GetTxVirtualSize(tx)
		txFeeRate        = txFee * 1000 / txSize
		conflictsFee     int64
		conflictsParents = make(map[chainhash.Hash]struct{})
	)
	for hash, conflict := range conflicts {
		if txFeeRate <= mp.pool[hash].FeePerKB {
			str := fmt.Sprintf("%v: replacement transaction has an "+
				"insufficient fee rate: needs more than %v, "+
				"has %v", tx.Hash(), mp.pool[hash].FeePerKB,
				txFeeRate)
			return nil, txRuleError(wire.RejectInsufficientFee, str)
		}

		conflictsFee += mp.pool[hash].Fee

		// We'll track each conflict's parents to ensure the replacement
		// isn't spending any new unconfirmed inputs.
		for _, txIn := range conflict.MsgTx().TxIn {
			conflictsParents[txIn.PreviousOutPoint.Hash] = struct{}{}
		}
	}

	// It should also have an absolute fee greater than all of the
	// transactions it intends to replace and pay for its own bandwidth,
	// which is determined by our minimum relay fee.
	minFee := calcMinRequiredTxRelayFee(txSize, mp.cfg.Policy.MinRelayTxFee)
	if txFee < conflictsFee+minFee {
		str := fmt.Sprintf("%v: replacement transaction has an "+
			"insufficient absolute fee: needs %v, has %v",
			tx.Hash(), conflictsFee+minFee, txFee)
		return nil, txRuleError(wire.RejectInsufficientFee, str)
	}

	// Finally, it should not spend any new unconfirmed outputs, other than
	// the ones already included in the parents of the conflicting
	// transactions it'll replace.
	for _, txIn := range tx.MsgTx().TxIn {
		if _, ok := conflictsParents[txIn.PreviousOutPoint.Hash]; ok {
			continue
		}
		// Confirmed outputs are valid to spend in the replacement.
		if _, ok := mp.pool[txIn.PreviousOutPoint.Hash]; !ok {
			continue
		}
		str := fmt.Sprintf("replacement transaction spends new "+
			"unconfirmed input %v not found in conflicting "+
			"transactions", txIn.PreviousOutPoint)
		return nil, txRuleError(wire.RejectInvalid, str)
	}

	return conflicts, nil
}

// maybeAcceptTransaction is the internal function which implements the public
// MaybeAcceptTransaction.  See the comment for MaybeAcceptTransaction for
// more details.
//
// This function MUST be called with the mempool lock held (for writes).
func (mp *TxPool) maybeAcceptTransaction(tx *hnsutil.Tx, isNew, rateLimit,
	rejectDupOrphans bool) ([]*chainhash.Hash, *TxDesc, error) {

	txHash := tx.Hash()

	// Check for mempool acceptance.
	r, err := mp.checkMempoolAcceptance(
		tx, isNew, rateLimit, rejectDupOrphans,
	)
	if err != nil {
		return nil, nil, err
	}

	// Exit early if this transaction is missing parents.
	if len(r.MissingParents) > 0 {
		return r.MissingParents, nil, nil
	}

	// Now that we've deemed the transaction as valid, we can add it to the
	// mempool. If it ended up replacing any transactions, we'll remove them
	// first.
	for _, conflict := range r.Conflicts {
		log.Debugf("Replacing transaction %v (fee_rate=%v doo/kb) "+
			"with %v (fee_rate=%v doo/kb)\n", conflict.Hash(),
			mp.pool[*conflict.Hash()].FeePerKB, tx.Hash(),
			int64(r.TxFee)*1000/r.TxSize)

		// The conflict set should already include the descendants for
		// each one, so we don't need to remove the redeemers within
		// this call as they'll be removed eventually.
		mp.removeTransaction(conflict, false)
	}
	txD := mp.addTransaction(r.utxoView, tx, r.bestHeight, int64(r.TxFee))

	log.Debugf("Accepted transaction %v (pool size: %v)", txHash,
		len(mp.pool))

	return nil, txD, nil
}

// MaybeAcceptTransaction is the main workhorse for handling insertion of new
// free-standing transactions into a memory pool.  It includes functionality
// such as rejecting duplicate transactions, ensuring transactions follow all
// rules, detecting orphan transactions, and insertion into the memory pool.
//
// If the transaction is an orphan (missing parent transactions), the
// transaction is NOT added to the orphan pool, but each unknown referenced
// parent is returned.  Use ProcessTransaction instead if new orphans should
// be added to the orphan pool.
//
// This function is safe for concurrent access.
func (mp *TxPool) MaybeAcceptTransaction(tx *hnsutil.Tx, isNew, rateLimit bool) ([]*chainhash.Hash, *TxDesc, error) {
	// Protect concurrent access.
	mp.mtx.Lock()
	hashes, txD, err := mp.maybeAcceptTransaction(tx, isNew, rateLimit, true)
	mp.mtx.Unlock()

	return hashes, txD, err
}

// processOrphans is the internal function which implements the public
// ProcessOrphans.  See the comment for ProcessOrphans for more details.
//
// This function MUST be called with the mempool lock held (for writes).
func (mp *TxPool) processOrphans(acceptedTx *hnsutil.Tx) []*TxDesc {
	var acceptedTxns []*TxDesc

	// Start with processing at least the passed transaction.
	processList := list.New()
	processList.PushBack(acceptedTx)
	for processList.Len() > 0 {
		// Pop the transaction to process from the front of the list.
		firstElement := processList.Remove(processList.Front())
		processItem := firstElement.(*hnsutil.Tx)

		prevOut := wire.OutPoint{Hash: *processItem.Hash()}
		for txOutIdx := range processItem.MsgTx().TxOut {
			// Look up all orphans that redeem the output that is
			// now available.  This will typically only be one, but
			// it could be multiple if the orphan pool contains
			// double spends.  While it may seem odd that the orphan
			// pool would allow this since there can only possibly
			// ultimately be a single redeemer, it's important to
			// track it this way to prevent malicious actors from
			// being able to purposely constructing orphans that
			// would otherwise make outputs unspendable.
			//
			// Skip to the next available output if there are none.
			prevOut.Index = uint32(txOutIdx)
			orphans, exists := mp.orphansByPrev[prevOut]
			if !exists {
				continue
			}

			// Potentially accept an orphan into the tx pool.
			for _, tx := range orphans {
				missing, txD, err := mp.maybeAcceptTransaction(
					tx, true, true, false)
				if err != nil {
					// The orphan is now invalid, so there
					// is no way any other orphans which
					// redeem any of its outputs can be
					// accepted.  Remove them.
					mp.removeOrphan(tx, true)
					break
				}

				// Transaction is still an orphan.  Try the next
				// orphan which redeems this output.
				if len(missing) > 0 {
					continue
				}

				// Transaction was accepted into the main pool.
				//
				// Add it to the list of accepted transactions
				// that are no longer orphans, remove it from
				// the orphan pool, and add it to the list of
				// transactions to process so any orphans that
				// depend on it are handled too.
				acceptedTxns = append(acceptedTxns, txD)
				mp.removeOrphan(tx, false)
				processList.PushBack(tx)

				// Only one transaction for this outpoint can be
				// accepted, so the rest are now double spends
				// and are removed later.
				break
			}
		}
	}

	// Recursively remove any orphans that also redeem any outputs redeemed
	// by the accepted transactions since those are now definitive double
	// spends.
	mp.removeOrphanDoubleSpends(acceptedTx)
	for _, txD := range acceptedTxns {
		mp.removeOrphanDoubleSpends(txD.Tx)
	}

	return acceptedTxns
}

// ProcessOrphans determines if there are any orphans which depend on the passed
// transaction hash (it is possible that they are no longer orphans) and
// potentially accepts them to the memory pool.  It repeats the process for the
// newly accepted transactions (to detect further orphans which may no longer be
// orphans) until there are no more.
//
// It returns a slice of transactions added to the mempool.  A nil slice means
// no transactions were moved from the orphan pool to the mempool.
//
// This function is safe for concurrent access.
func (mp *TxPool) ProcessOrphans(acceptedTx *hnsutil.Tx) []*TxDesc {
	mp.mtx.Lock()
	acceptedTxns := mp.processOrphans(acceptedTx)
	mp.mtx.Unlock()

	return acceptedTxns
}

// ProcessTransaction is the main workhorse for handling insertion of new
// free-standing transactions into the memory pool.  It includes functionality
// such as rejecting duplicate transactions, ensuring transactions follow all
// rules, orphan transaction handling, and insertion into the memory pool.
//
// It returns a slice of transactions added to the mempool.  When the
// error is nil, the list will include the passed transaction itself along
// with any additional orphan transactions that were added as a result of
// the passed one being accepted.
//
// This function is safe for concurrent access.
func (mp *TxPool) ProcessTransaction(tx *hnsutil.Tx, allowOrphan, rateLimit bool, tag Tag) ([]*TxDesc, error) {
	log.Tracef("Processing transaction %v", tx.Hash())

	// Protect concurrent access.
	mp.mtx.Lock()
	defer mp.mtx.Unlock()

	// Potentially accept the transaction to the memory pool.
	missingParents, txD, err := mp.maybeAcceptTransaction(tx, true, rateLimit,
		true)
	if err != nil {
		return nil, err
	}

	if len(missingParents) == 0 {
		// Accept any orphan transactions that depend on this
		// transaction (they may no longer be orphans if all inputs
		// are now available) and repeat for those accepted
		// transactions until there are no more.
		newTxs := mp.processOrphans(tx)
		acceptedTxs := make([]*TxDesc, len(newTxs)+1)

		// Add the parent transaction first so remote nodes
		// do not add orphans.
		acceptedTxs[0] = txD
		copy(acceptedTxs[1:], newTxs)

		return acceptedTxs, nil
	}

	// The transaction is an orphan (has inputs missing).  Reject
	// it if the flag to allow orphans is not set.
	if !allowOrphan {
		// Only use the first missing parent transaction in
		// the error message.
		//
		// NOTE: RejectDuplicate is really not an accurate
		// reject code here, but it matches the reference
		// implementation and there isn't a better choice due
		// to the limited number of reject codes.  Missing
		// inputs is assumed to mean they are already spent
		// which is not really always the case.
		str := fmt.Sprintf("orphan transaction %v references "+
			"outputs of unknown or fully-spent "+
			"transaction %v", tx.Hash(), missingParents[0])
		return nil, txRuleError(wire.RejectDuplicate, str)
	}

	// Potentially add the orphan transaction to the orphan pool.
	err = mp.maybeAddOrphan(tx, tag)
	return nil, err
}

// Count returns the number of transactions in the main pool.  It does not
// include the orphan pool.
//
// This function is safe for concurrent access.
func (mp *TxPool) Count() int {
	mp.mtx.RLock()
	count := len(mp.pool)
	mp.mtx.RUnlock()

	return count
}

// TxHashes returns a slice of hashes for all the transactions in the memory
// pool.
//
// This function is safe for concurrent access.
func (mp *TxPool) TxHashes() []*chainhash.Hash {
	mp.mtx.RLock()
	hashes := make([]*chainhash.Hash, len(mp.pool))
	i := 0
	for hash := range mp.pool {
		hashCopy := hash
		hashes[i] = &hashCopy
		i++
	}
	mp.mtx.RUnlock()

	return hashes
}

// TxDescs returns a slice of descriptors for all the transactions in the pool.
// The descriptors are to be treated as read only.
//
// This function is safe for concurrent access.
func (mp *TxPool) TxDescs() []*TxDesc {
	mp.mtx.RLock()
	descs := make([]*TxDesc, len(mp.pool))
	i := 0
	for _, desc := range mp.pool {
		descs[i] = desc
		i++
	}
	mp.mtx.RUnlock()

	return descs
}

// MiningDescs returns a slice of mining descriptors for all the transactions
// in the pool.
//
// This is part of the mining.TxSource interface implementation and is safe for
// concurrent access as required by the interface contract.
func (mp *TxPool) MiningDescs() []*mining.TxDesc {
	mp.mtx.RLock()
	descs := make([]*mining.TxDesc, len(mp.pool))
	i := 0
	for _, desc := range mp.pool {
		descs[i] = &desc.TxDesc
		i++
	}
	mp.mtx.RUnlock()

	return descs
}

// RawMempoolVerbose returns all the entries in the mempool as a fully
// populated hnsjson result.
//
// This function is safe for concurrent access.
func (mp *TxPool) RawMempoolVerbose() map[string]*hnsjson.GetRawMempoolVerboseResult {
	mp.mtx.RLock()
	defer mp.mtx.RUnlock()

	result := make(map[string]*hnsjson.GetRawMempoolVerboseResult,
		len(mp.pool))
	bestHeight := mp.cfg.BestHeight()

	for _, desc := range mp.pool {
		// Calculate the current priority based on the inputs to
		// the transaction.  Use zero if one or more of the
		// input transactions can't be found for some reason.
		tx := desc.Tx
		var currentPriority float64
		utxos, err := mp.fetchInputUtxos(tx)
		if err == nil {
			currentPriority = mining.CalcPriority(tx.MsgTx(), utxos,
				bestHeight+1)
		}

		mpd := &hnsjson.GetRawMempoolVerboseResult{
			Size:             int32(tx.MsgTx().SerializeSize()),
			Vsize:            int32(GetTxVirtualSize(tx)),
			Weight:           int32(blockchain.GetTransactionWeight(tx)),
			Fee:              hnsutil.Amount(desc.Fee).ToHNS(),
			Time:             desc.Added.Unix(),
			Height:           int64(desc.Height),
			StartingPriority: desc.StartingPriority,
			CurrentPriority:  currentPriority,
			Depends:          make([]string, 0),
		}
		for _, txIn := range tx.MsgTx().TxIn {
			hash := &txIn.PreviousOutPoint.Hash
			if mp.haveTransaction(hash) {
				mpd.Depends = append(mpd.Depends,
					hash.String())
			}
		}

		result[tx.Hash().String()] = mpd
	}

	return result
}

// LastUpdated returns the last time a transaction was added to or removed from
// the main pool.  It does not include the orphan pool.
//
// This function is safe for concurrent access.
func (mp *TxPool) LastUpdated() time.Time {
	return time.Unix(atomic.LoadInt64(&mp.lastUpdated), 0)
}

// MempoolAcceptResult holds the result from mempool acceptance check.
type MempoolAcceptResult struct {
	// TxFee is the fees paid in dollarydoos.
	TxFee hnsutil.Amount

	// TxSize is the virtual size(vb) of the tx.
	TxSize int64

	// conflicts is a set of transactions whose inputs are spent by this
	// transaction(RBF).
	Conflicts map[chainhash.Hash]*hnsutil.Tx

	// MissingParents is a set of outpoints that are used by this
	// transaction which cannot be found. Transaction is an orphan if any
	// of the referenced transaction outputs don't exist or are already
	// spent.
	//
	// NOTE: this field is mutually exclusive with other fields. If this
	// field is not nil, then other fields must be empty.
	MissingParents []*chainhash.Hash

	// utxoView is a set of the unspent transaction outputs referenced by
	// the inputs to this transaction.
	utxoView *blockchain.UtxoViewpoint

	// bestHeight is the best known height by the mempool.
	bestHeight int32
}

// CheckMempoolAcceptance behaves similarly to bitcoind's `testmempoolaccept`
// RPC method. It will perform a series of checks to decide whether this
// transaction can be accepted to the mempool. If not, the specific error is
// returned and the caller needs to take actions based on it.
func (mp *TxPool) CheckMempoolAcceptance(tx *hnsutil.Tx) (
	*MempoolAcceptResult, error) {

	mp.mtx.RLock()
	defer mp.mtx.RUnlock()

	// Call checkMempoolAcceptance with isNew=true and rateLimit=true,
	// which has the effect that we always check the fee paid from this tx
	// is greater than min relay fee. We also reject this tx if it's
	// already an orphan.
	result, err := mp.checkMempoolAcceptance(tx, true, true, true)
	if err != nil {
		log.Errorf("CheckMempoolAcceptance: %v", err)
		return nil, err
	}

	log.Tracef("Tx %v passed mempool acceptance check: %v", tx.Hash(),
		spew.Sdump(result))

	return result, nil
}

// checkMempoolAcceptance performs a series of validations on the given
// transaction. It returns an error when the transaction fails to meet the
// mempool policy, otherwise a `mempoolAcceptResult` is returned.
func (mp *TxPool) checkMempoolAcceptance(tx *hnsutil.Tx,
	isNew, rateLimit, rejectDupOrphans bool) (*MempoolAcceptResult, error) {

	txHash := tx.Hash()

	// Check for segwit activeness.
	if err := mp.validateSegWitDeployment(tx); err != nil {
		return nil, err
	}

	// Don't accept the transaction if it already exists in the pool. This
	// applies to orphan transactions as well when the reject duplicate
	// orphans flag is set. This check is intended to be a quick check to
	// weed out duplicates.
	if mp.isTransactionInPool(txHash) || (rejectDupOrphans &&
		mp.isOrphanInPool(txHash)) {

		str := fmt.Sprintf("already have transaction in mempool %v",
			txHash)
		return nil, txRuleError(wire.RejectDuplicate, str)
	}

	// Disallow transactions under the minimum standardness size.
	if tx.MsgTx().SerializeSizeStripped() < MinStandardTxNonWitnessSize {
		str := fmt.Sprintf("tx %v is too small", txHash)
		return nil, txRuleError(wire.RejectNonstandard, str)
	}

	// Perform preliminary sanity checks on the transaction. This makes use
	// of blockchain which contains the invariant rules for what
	// transactions are allowed into blocks.
	err := blockchain.CheckTransactionSanity(tx)
	if err != nil {
		if cerr, ok := err.(blockchain.RuleError); ok {
			return nil, chainRuleError(cerr)
		}

		return nil, err
	}

	// A standalone transaction must not be a coinbase transaction.
	if blockchain.IsCoinBase(tx) {
		str := fmt.Sprintf("transaction is an individual coinbase %v",
			txHash)

		return nil, txRuleError(wire.RejectInvalid, str)
	}

	// Get the current height of the main chain. A standalone transaction
	// will be mined into the next block at best, so its height is at least
	// one more than the current height.
	bestHeight := mp.cfg.BestHeight()
	nextBlockHeight := bestHeight + 1

	medianTimePast := mp.cfg.MedianTimePast()

	// The transaction may not use any of the same outputs as other
	// transactions already in the pool as that would ultimately result in
	// a double spend, unless those transactions signal for RBF. This check
	// is intended to be quick and therefore only detects double spends
	// within the transaction pool itself. The transaction could still be
	// double spending coins from the main chain at this point. There is a
	// more in-depth check that happens later after fetching the referenced
	// transaction inputs from the main chain which examines the actual
	// spend data and prevents double spends.
	isReplacement, err := mp.checkPoolDoubleSpend(tx)
	if err != nil {
		return nil, err
	}

	// Fetch all of the unspent transaction outputs referenced by the
	// inputs to this transaction. This function also attempts to fetch the
	// transaction itself to be used for detecting a duplicate transaction
	// without needing to do a separate lookup.
	utxoView, err := mp.fetchInputUtxos(tx)
	if err != nil {
		if cerr, ok := err.(blockchain.RuleError); ok {
			return nil, chainRuleError(cerr)
		}

		return nil, err
	}

	// Don't allow the transaction if it exists in the main chain and is
	// already fully spent.
	prevOut := wire.OutPoint{Hash: *txHash}
	for txOutIdx := range tx.MsgTx().TxOut {
		prevOut.Index = uint32(txOutIdx)

		entry := utxoView.LookupEntry(prevOut)
		if entry != nil && !entry.IsSpent() {
			return nil, txRuleError(wire.RejectDuplicate,
				"transaction already exists in blockchain")
		}

		utxoView.RemoveEntry(prevOut)
	}

	// Transaction is an orphan if any of the referenced transaction
	// outputs don't exist or are already spent. Adding orphans to the
	// orphan pool is not handled by this function, and the caller should
	// use maybeAddOrphan if this behavior is desired.
	var missingParents []*chainhash.Hash
	for outpoint, entry := range utxoView.Entries() {
		if entry == nil || entry.IsSpent() {
			// Must make a copy of the hash here since the iterator
			// is replaced and taking its address directly would
			// result in all the entries pointing to the same
			// memory location and thus all be the final hash.
			hashCopy := outpoint.Hash
			missingParents = append(missingParents, &hashCopy)
		}
	}

	// Exit early if this transaction is missing parents.
	if len(missingParents) > 0 {
		log.Debugf("Tx %v is an orphan with missing parents: %v",
			txHash, missingParents)

		return &MempoolAcceptResult{
			MissingParents: missingParents,
		}, nil
	}

	// Perform several checks on the transaction inputs using the invariant
	// rules in blockchain for what transactions are allowed into blocks.
	// Also returns the fees associated with the transaction which will be
	// used later.
	//
	// NOTE: this check must be performed before `validateStandardness` to
	// make sure a nil entry is not returned from `utxoView.LookupEntry`.
	txFee, err := blockchain.CheckTransactionInputs(
		tx, nextBlockHeight, utxoView, mp.cfg.ChainParams,
	)
	if err != nil {
		if cerr, ok := err.(blockchain.RuleError); ok {
			return nil, chainRuleError(cerr)
		}
		return nil, err
	}

	// If the transaction has any conflicts, then we're processing a
	// potential replacement.  Determine the full replacement set before
	// name validation so replaced transactions are not replayed into the
	// speculative mempool name state.
	var conflicts map[chainhash.Hash]*hnsutil.Tx
	if isReplacement {
		conflicts, err = mp.validateReplacement(tx, txFee)
		if err != nil {
			return nil, err
		}
	}
	if err := mp.checkNameOperationConflicts(tx, conflicts); err != nil {
		return nil, err
	}
	err = mp.checkTransactionNames(tx, nextBlockHeight,
		medianTimePast.Unix(), utxoView, conflicts)
	if err != nil {
		if cerr, ok := err.(blockchain.RuleError); ok {
			return nil, chainRuleError(cerr)
		}
		return nil, err
	}

	// Don't allow non-standard transactions or non-standard inputs if the
	// network parameters forbid their acceptance.
	err = mp.validateStandardness(
		tx, nextBlockHeight, medianTimePast, utxoView,
	)
	if err != nil {
		return nil, err
	}

	// Don't allow the transaction into the mempool unless its sequence
	// lock is active, meaning that it'll be allowed into the next block
	// with respect to its defined relative lock times.
	sequenceLock, err := mp.cfg.CalcSequenceLock(tx, utxoView)
	if err != nil {
		if cerr, ok := err.(blockchain.RuleError); ok {
			return nil, chainRuleError(cerr)
		}

		return nil, err
	}

	if !blockchain.SequenceLockActive(
		sequenceLock, nextBlockHeight, medianTimePast,
	) {

		return nil, txRuleError(wire.RejectNonstandard,
			"transaction's sequence locks on inputs not met")
	}

	// Don't allow transactions with an excessive number of signature
	// operations which would result in making it impossible to mine.
	if err := mp.validateSigCost(tx, utxoView); err != nil {
		return nil, err
	}

	txSize := GetTxVirtualSize(tx)

	// Don't allow transactions with fees too low to get into a mined
	// block.
	err = mp.validateRelayFeeMet(
		tx, txFee, txSize, utxoView, nextBlockHeight, isNew, rateLimit,
	)
	if err != nil {
		return nil, err
	}

	// Verify crypto signatures for each input and reject the transaction
	// if any don't verify.
	err = blockchain.ValidateTransactionScripts(tx, utxoView,
		txscript.StandardVerifyFlags, mp.cfg.SigCache,
		mp.cfg.HashCache)
	if err != nil {
		if cerr, ok := err.(blockchain.RuleError); ok {
			return nil, chainRuleError(cerr)
		}
		return nil, err
	}

	result := &MempoolAcceptResult{
		TxFee:      hnsutil.Amount(txFee),
		TxSize:     txSize,
		Conflicts:  conflicts,
		utxoView:   utxoView,
		bestHeight: bestHeight,
	}

	return result, nil
}

// validateSegWitDeployment checks that when a transaction has witness data,
// segwit must be active.
func (mp *TxPool) validateSegWitDeployment(tx *hnsutil.Tx) error {
	// In Handshake, witness is always part of the transaction format
	// (there is no segwit soft fork deployment). Always accept witness data.
	return nil
}

// validateStandardness checks the transaction passes both transaction standard
// and input standard.
func (mp *TxPool) validateStandardness(tx *hnsutil.Tx, nextBlockHeight int32,
	medianTimePast time.Time, utxoView *blockchain.UtxoViewpoint) error {

	// Exit early if we accept non-standard transactions.
	//
	// NOTE: if you modify this code to accept non-standard transactions,
	// you should add code here to check that the transaction does a
	// reasonable number of ECDSA signature verifications.
	if mp.cfg.Policy.AcceptNonStd {
		return nil
	}

	// Check the transaction standard.
	err := CheckTransactionStandard(
		tx, nextBlockHeight, medianTimePast,
		mp.cfg.Policy.MinRelayTxFee, mp.cfg.Policy.MaxTxVersion,
	)
	if err != nil {
		// Attempt to extract a reject code from the error so it can be
		// retained. When not possible, fall back to a non standard
		// error.
		rejectCode, found := extractRejectCode(err)
		if !found {
			rejectCode = wire.RejectNonstandard
		}
		str := fmt.Sprintf("transaction %v is not standard: %v",
			tx.Hash(), err)

		return txRuleError(rejectCode, str)
	}

	// Check the inputs standard.
	err = checkInputsStandard(tx, utxoView)
	if err != nil {
		// Attempt to extract a reject code from the error so it can be
		// retained. When not possible, fall back to a non-standard
		// error.
		rejectCode, found := extractRejectCode(err)
		if !found {
			rejectCode = wire.RejectNonstandard
		}
		str := fmt.Sprintf("transaction %v has a non-standard "+
			"input: %v", tx.Hash(), err)

		return txRuleError(rejectCode, str)
	}

	return nil
}

// validateSigCost checks the cost to run the signature operations to make sure
// the number of signatures are sane.
func (mp *TxPool) validateSigCost(tx *hnsutil.Tx,
	utxoView *blockchain.UtxoViewpoint) error {

	// Since the coinbase address itself can contain signature operations,
	// the maximum allowed signature operations per transaction is less
	// than the maximum allowed signature operations per block.
	//
	// TODO(roasbeef): last bool should be conditional on segwit activation
	sigOpCost, err := blockchain.GetSigOpCost(
		tx, false, utxoView, true, true,
	)
	if err != nil {
		if cerr, ok := err.(blockchain.RuleError); ok {
			return chainRuleError(cerr)
		}

		return err
	}

	// Exit early if the sig cost is under limit.
	if sigOpCost <= mp.cfg.Policy.MaxSigOpCostPerTx {
		return nil
	}

	str := fmt.Sprintf("transaction %v sigop cost is too high: %d > %d",
		tx.Hash(), sigOpCost, mp.cfg.Policy.MaxSigOpCostPerTx)

	return txRuleError(wire.RejectNonstandard, str)
}

// validateRelayFeeMet checks that the min relay fee is covered by this
// transaction.
func (mp *TxPool) validateRelayFeeMet(tx *hnsutil.Tx, txFee, txSize int64,
	utxoView *blockchain.UtxoViewpoint, nextBlockHeight int32,
	isNew, rateLimit bool) error {

	txHash := tx.Hash()

	// Most miners allow a free transaction area in blocks they mine to go
	// alongside the area used for high-priority transactions as well as
	// transactions with fees. A transaction size of up to 1000 bytes is
	// considered safe to go into this section. Further, the minimum fee
	// calculated below on its own would encourage several small
	// transactions to avoid fees rather than one single larger transaction
	// which is more desirable. Therefore, as long as the size of the
	// transaction does not exceed 1000 less than the reserved space for
	// high-priority transactions, don't require a fee for it.
	minFee := calcMinRequiredTxRelayFee(txSize, mp.cfg.Policy.MinRelayTxFee)

	if txSize >= (DefaultBlockPrioritySize-1000) && txFee < minFee {
		str := fmt.Sprintf("transaction %v has %d fees which is under "+
			"the required amount of %d", txHash, txFee, minFee)

		return txRuleError(wire.RejectInsufficientFee, str)
	}

	// Exit early if the min relay fee is met.
	if txFee >= minFee {
		return nil
	}

	// Exit early if this is neither a new tx or rate limited.
	if !isNew && !rateLimit {
		return nil
	}

	// Require that free transactions have sufficient priority to be mined
	// in the next block. Transactions which are being added back to the
	// memory pool from blocks that have been disconnected during a reorg
	// are exempted.
	if isNew && !mp.cfg.Policy.DisableRelayPriority {
		currentPriority := mining.CalcPriority(
			tx.MsgTx(), utxoView, nextBlockHeight,
		)
		if currentPriority <= mining.MinHighPriority {
			str := fmt.Sprintf("transaction %v has insufficient "+
				"priority (%g <= %g)", txHash,
				currentPriority, mining.MinHighPriority)

			return txRuleError(wire.RejectInsufficientFee, str)
		}
	}

	// We can only end up here when the rateLimit is true. Free-to-relay
	// transactions are rate limited here to prevent penny-flooding with
	// tiny transactions as a form of attack.
	nowUnix := time.Now().Unix()

	// Decay passed data with an exponentially decaying ~10 minute window -
	// matches bitcoind handling.
	mp.pennyTotal *= math.Pow(
		1.0-1.0/600.0, float64(nowUnix-mp.lastPennyUnix),
	)
	mp.lastPennyUnix = nowUnix

	// Are we still over the limit?
	if mp.pennyTotal >= mp.cfg.Policy.FreeTxRelayLimit*10*1000 {
		str := fmt.Sprintf("transaction %v has been rejected "+
			"by the rate limiter due to low fees", txHash)

		return txRuleError(wire.RejectInsufficientFee, str)
	}

	oldTotal := mp.pennyTotal
	mp.pennyTotal += float64(txSize)
	log.Tracef("rate limit: curTotal %v, nextTotal: %v, limit %v",
		oldTotal, mp.pennyTotal, mp.cfg.Policy.FreeTxRelayLimit*10*1000)

	return nil
}

// New returns a new memory pool for validating and storing standalone
// transactions until they are mined into a block.
func New(cfg *Config) *TxPool {
	return &TxPool{
		cfg:              *cfg,
		pool:             make(map[chainhash.Hash]*TxDesc),
		orphans:          make(map[chainhash.Hash]*orphanTx),
		orphansByPrev:    make(map[wire.OutPoint]map[chainhash.Hash]*hnsutil.Tx),
		nextExpireScan:   time.Now().Add(orphanExpireScanInterval),
		outpoints:        make(map[wire.OutPoint]*hnsutil.Tx),
		nameActions:      make(map[chainhash.Hash]*hnsutil.Tx),
		coinbaseClaims:   make(map[chainhash.Hash]chainhash.Hash),
		coinbaseAirdrops: make(map[uint32]chainhash.Hash),
	}
}
