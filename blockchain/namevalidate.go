// Copyright (c) 2024-2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/blinklabs-io/handshake-node/chaincfg"
	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/database"
	"github.com/blinklabs-io/handshake-node/hnsutil"
	"github.com/blinklabs-io/handshake-node/wire"
	"golang.org/x/crypto/blake2b"
)

type namePrevOutput struct {
	outpoint wire.OutPoint
	amount   int64
	address  wire.Address
	covenant wire.Covenant
}

type nameOwnerCoinLookup func(database.Tx, wire.OutPoint) (int64, bool, error)

type nameBlockView struct {
	chain           *BlockChain
	states          map[chainhash.Hash]*nameState
	loaded          map[chainhash.Hash]struct{}
	dirty           map[chainhash.Hash]struct{}
	undo            []nameUndoEntry
	seen            map[chainhash.Hash]struct{}
	mainChainHeight func(chainhash.Hash) (int32, error)
	ownerCoinValue  nameOwnerCoinLookup
}

// NameValidationView validates a sequence of transactions against a shared
// snapshot of the committed name state.  It is intended for block-template
// assembly and other ordered transaction views where earlier accepted
// transactions can update the name state seen by later transactions.
//
// NameValidationView is not safe for concurrent use.
type NameValidationView struct {
	chain           *BlockChain
	view            *nameBlockView
	deploymentFlags handshakeDeploymentFlags
}

func newNameBlockView(dbTx database.Tx, chain *BlockChain) (*nameBlockView, error) {
	states, err := dbFetchAllNameStates(dbTx)
	if err != nil {
		return nil, err
	}

	return newNameBlockViewFromStates(chain, states), nil
}

func newNameBlockViewFromStates(chain *BlockChain,
	states map[chainhash.Hash]*nameState) *nameBlockView {

	return &nameBlockView{
		chain:  chain,
		states: states,
		dirty:  make(map[chainhash.Hash]struct{}),
		seen:   make(map[chainhash.Hash]struct{}),
	}
}

func newLazyNameBlockView(chain *BlockChain) *nameBlockView {
	return &nameBlockView{
		chain:  chain,
		states: make(map[chainhash.Hash]*nameState),
		loaded: make(map[chainhash.Hash]struct{}),
		dirty:  make(map[chainhash.Hash]struct{}),
		seen:   make(map[chainhash.Hash]struct{}),
	}
}

// NewNameValidationView returns a stateful name validation view initialized
// from the current committed name state.
func (b *BlockChain) NewNameValidationView() (*NameValidationView, error) {
	deploymentFlags, err := b.currentHandshakeDeploymentFlags()
	if err != nil {
		return nil, err
	}

	return &NameValidationView{
		chain:           b,
		view:            newLazyNameBlockView(b),
		deploymentFlags: deploymentFlags,
	}, nil
}

// ApplyTransaction validates the Handshake name covenant transitions in tx
// against the view's current name state and advances the view when validation
// succeeds.  If validation fails, the view is restored to its prior state.
func (v *NameValidationView) ApplyTransaction(tx *hnsutil.Tx, height int32,
	prevTime int64, utxoView *UtxoViewpoint) error {

	snapshot := v.view.snapshot()
	err := v.chain.db.View(func(dbTx database.Tx) error {
		prevOutputs, err := prevOutputsFromView(tx, utxoView)
		if err != nil {
			return err
		}
		v.view.ownerCoinValue = v.chain.nameOwnerCoinLookup(utxoView)
		return v.view.applyTx(dbTx, tx, uint32(height), prevTime,
			prevOutputs, v.deploymentFlags)
	})
	if err != nil {
		v.view.restore(snapshot)
		return err
	}

	return nil
}

type nameBlockViewSnapshot struct {
	states map[chainhash.Hash]*nameState
	loaded map[chainhash.Hash]struct{}
	dirty  map[chainhash.Hash]struct{}
	undo   []nameUndoEntry
	seen   map[chainhash.Hash]struct{}
}

func (v *nameBlockView) snapshot() nameBlockViewSnapshot {
	return nameBlockViewSnapshot{
		states: cloneNameStateMap(v.states),
		loaded: cloneHashSet(v.loaded),
		dirty:  cloneHashSet(v.dirty),
		undo:   cloneNameUndoEntries(v.undo),
		seen:   cloneHashSet(v.seen),
	}
}

func (v *nameBlockView) restore(snapshot nameBlockViewSnapshot) {
	v.states = snapshot.states
	v.loaded = snapshot.loaded
	v.dirty = snapshot.dirty
	v.undo = snapshot.undo
	v.seen = snapshot.seen
}

func cloneNameStateMap(states map[chainhash.Hash]*nameState) map[chainhash.Hash]*nameState {
	cloned := make(map[chainhash.Hash]*nameState, len(states))
	for nameHash, ns := range states {
		if ns != nil {
			cloned[nameHash] = ns.clone()
		}
	}
	return cloned
}

func cloneHashSet(set map[chainhash.Hash]struct{}) map[chainhash.Hash]struct{} {
	if set == nil {
		return nil
	}

	cloned := make(map[chainhash.Hash]struct{}, len(set))
	for hash := range set {
		cloned[hash] = struct{}{}
	}
	return cloned
}

func cloneNameUndoEntries(entries []nameUndoEntry) []nameUndoEntry {
	if entries == nil {
		return nil
	}

	cloned := make([]nameUndoEntry, len(entries))
	for i, entry := range entries {
		cloned[i] = entry
		if entry.state != nil {
			cloned[i].state = entry.state.clone()
		}
	}
	return cloned
}

func (v *nameBlockView) needsDB() bool {
	return v.loaded != nil
}

func (v *nameBlockView) get(dbTx database.Tx, nameHash chainhash.Hash) (
	*nameState, error) {

	ns := v.states[nameHash]
	if ns == nil {
		if v.needsDB() {
			if dbTx == nil {
				return nil, AssertError("lazy name block view requires " +
					"a database transaction")
			}

			var err error
			var found bool
			ns, found, err = dbFetchNameState(dbTx, nameHash)
			if err != nil {
				return nil, err
			}
			if !found {
				ns = newNameState(nameHash)
			}
			v.loaded[nameHash] = struct{}{}
		} else {
			ns = newNameState(nameHash)
		}
		v.states[nameHash] = ns
	}
	return ns, nil
}

func (v *nameBlockView) recordChange(before, after *nameState) error {
	if nameStatesEqual(before, after) {
		return nil
	}

	nameHash := after.nameHash
	if _, exists := v.seen[nameHash]; !exists {
		v.undo = append(v.undo, nameUndoEntry{
			nameHash: nameHash,
			existed:  !before.isNull(),
			state:    before.clone(),
		})
		v.seen[nameHash] = struct{}{}
	}
	v.dirty[nameHash] = struct{}{}
	return nil
}

func (v *nameBlockView) nameOwnerCoinValue(dbTx database.Tx, owner wire.OutPoint) (
	int64, bool, error) {

	if v.ownerCoinValue == nil {
		return 0, false, nil
	}
	return v.ownerCoinValue(dbTx, owner)
}

func (b *BlockChain) nameOwnerCoinLookup(
	view *UtxoViewpoint) nameOwnerCoinLookup {

	return func(dbTx database.Tx, owner wire.OutPoint) (int64, bool, error) {
		if view != nil {
			entry := view.LookupEntry(owner)
			if entry != nil {
				if entry.IsSpent() {
					return 0, false, nil
				}
				return entry.Amount(), true, nil
			}
		}

		if b == nil || b.utxoCache == nil {
			return 0, false, nil
		}

		entry, cached := b.utxoCache.cachedEntries.get(owner)
		if cached {
			if entry == nil || entry.IsSpent() {
				return 0, false, nil
			}
			return entry.Amount(), true, nil
		}

		if dbTx != nil {
			utxoBucket := dbTx.Metadata().Bucket(utxoSetBucketName)
			entry, err := dbFetchUtxoEntry(dbTx, utxoBucket, owner)
			if err != nil {
				return 0, false, err
			}
			if entry == nil || entry.IsSpent() {
				return 0, false, nil
			}
			return entry.Amount(), true, nil
		}

		entries, err := b.utxoCache.fetchEntries([]wire.OutPoint{owner})
		if err != nil {
			return 0, false, err
		}
		entry = entries[0]
		if entry == nil || entry.IsSpent() {
			return 0, false, nil
		}
		return entry.Amount(), true, nil
	}
}

func nameStatesEqual(a, b *nameState) bool {
	if a == nil || b == nil {
		return a == b
	}

	encodedA, err := a.encode()
	if err != nil {
		return false
	}
	encodedB, err := b.encode()
	if err != nil {
		return false
	}
	return bytes.Equal(encodedA, encodedB)
}

func calcNameRootFromStates(states map[chainhash.Hash]*nameState) (
	chainhash.Hash, error) {

	leaves := make([]urkelLeaf, 0, len(states))
	for nameHash, ns := range states {
		if ns == nil || ns.isNull() {
			continue
		}
		value, err := ns.encode()
		if err != nil {
			return chainhash.Hash{}, err
		}
		leaves = append(leaves, urkelLeaf{
			key:   nameHash,
			value: value,
		})
	}

	return calcUrkelRoot(leaves), nil
}

func checkNameRootAgainst(root chainhash.Hash, block *hnsutil.Block) error {
	headerRoot := block.MsgBlock().Header.NameRoot
	if !headerRoot.IsEqual(&root) {
		str := fmt.Sprintf("block name root is invalid - block "+
			"header indicates %v, but current committed root is %v",
			headerRoot, root)
		return ruleError(ErrBadNameRoot, str)
	}

	return nil
}

func checkNameRoot(dbTx database.Tx, block *hnsutil.Block) error {
	root, err := dbFetchNameRoot(dbTx)
	if err != nil {
		return err
	}

	return checkNameRootAgainst(root, block)
}

func (v *nameBlockView) applyTx(dbTx database.Tx, tx *hnsutil.Tx,
	height uint32, prevTime int64, prevOutputs []namePrevOutput,
	deploymentFlags handshakeDeploymentFlags) error {

	if !IsCoinBase(tx) {
		if err := verifyCovenantSpends(tx, prevOutputs); err != nil {
			return err
		}
	}

	for outputIndex, txOut := range tx.MsgTx().TxOut {
		covenant := txOut.Covenant
		if !isNameCovenant(covenant.Type) {
			continue
		}

		if err := v.applyCovenantOutput(dbTx, tx, outputIndex, txOut,
			height, prevTime, prevOutputs, deploymentFlags); err != nil {

			return err
		}
	}

	return nil
}

func txHasNameCovenantOutput(tx *hnsutil.Tx) bool {
	for _, txOut := range tx.MsgTx().TxOut {
		if isNameCovenant(txOut.Covenant.Type) {
			return true
		}
	}
	return false
}

func (b *BlockChain) applyTxToNameView(view *nameBlockView, tx *hnsutil.Tx,
	height uint32, prevTime int64, prevOutputs []namePrevOutput,
	deploymentFlags handshakeDeploymentFlags) error {

	if view.needsDB() && txHasNameCovenantOutput(tx) {
		return b.db.View(func(dbTx database.Tx) error {
			return view.applyTx(dbTx, tx, height, prevTime,
				prevOutputs, deploymentFlags)
		})
	}

	return view.applyTx(nil, tx, height, prevTime, prevOutputs,
		deploymentFlags)
}

// CheckTransactionNames validates the Handshake name covenant transitions in a
// standalone transaction against the current committed name state.
func (b *BlockChain) CheckTransactionNames(tx *hnsutil.Tx, height int32,
	prevTime int64, view *UtxoViewpoint) error {

	nameView, err := b.NewNameValidationView()
	if err != nil {
		return err
	}
	return nameView.ApplyTransaction(tx, height, prevTime, view)
}

func (v *nameBlockView) applyCovenantOutput(dbTx database.Tx, tx *hnsutil.Tx,
	outputIndex int, txOut *wire.TxOut, height uint32,
	prevTime int64, prevOutputs []namePrevOutput,
	deploymentFlags handshakeDeploymentFlags) error {

	covenant := txOut.Covenant
	nameHash, ok := covenantHash(covenant, 0)
	if !ok {
		return badCovenant("missing covenant name hash")
	}

	ns, err := v.get(dbTx, nameHash)
	if err != nil {
		return err
	}
	before := ns.clone()

	if ns.isNull() {
		if covenant.Type != wire.CovenantClaim &&
			covenant.Type != wire.CovenantOpen {

			return ruleError(ErrInvalidCovenant,
				"name state is missing for covenant")
		}

		name := covenantItem(covenant, 2)
		ns.set(name, height)
	}

	ns.maybeExpire(height, v.chain.chainParams)
	state := ns.state(height, v.chain.chainParams)
	start, _ := covenantU32(covenant, 1)

	switch covenant.Type {
	case wire.CovenantClaim:
		if err := v.applyClaim(dbTx, ns, covenant, tx, outputIndex,
			height, prevTime, state, txOut.Value, deploymentFlags); err != nil {
			return err
		}
	case wire.CovenantOpen:
		if state != nameStateOpening {
			return badCovenant("OPEN covenant in invalid name state")
		}
		if ns.height != height {
			return badCovenant("duplicate OPEN covenant")
		}
		if !v.chain.chainParams.NameNoReserved &&
			isReservedNameHash(nameHash, height, v.chain.chainParams) {

			return badCovenant("OPEN covenant for reserved name")
		}
		if deploymentFlags.icannLockupActive &&
			isLockedUpNameHash(nameHash, height, v.chain.chainParams) {

			return badCovenant("OPEN covenant for locked name")
		}
		if !hasNameRollout(nameHash, height, v.chain.chainParams) {
			return badCovenant("OPEN covenant before rollout")
		}
	case wire.CovenantBid:
		if state != nameStateBidding {
			return badCovenant("BID covenant in invalid name state")
		}
		if start != ns.height {
			return badCovenant("BID covenant has nonlocal height")
		}
	case wire.CovenantReveal:
		if start != ns.height {
			return badCovenant("REVEAL covenant has nonlocal height")
		}
		if state != nameStateReveal {
			return badCovenant("REVEAL covenant in invalid name state")
		}
		if _, err := linkedPrevOutput(prevOutputs, outputIndex,
			"REVEAL"); err != nil {
			return err
		}
		if isNullNameOwner(ns.owner) || txOut.Value > ns.highest {
			ns.value = ns.highest
			ns.owner = txOutpoint(tx, outputIndex)
			ns.highest = txOut.Value
		} else if txOut.Value > ns.value {
			ns.value = txOut.Value
		}
	case wire.CovenantRedeem:
		if start != ns.height {
			return badCovenant("REDEEM covenant has nonlocal height")
		}
		if state < nameStateClosed {
			return badCovenant("REDEEM covenant before close")
		}
		prevOutput, err := linkedPrevOutput(prevOutputs, outputIndex,
			"REDEEM")
		if err != nil {
			return err
		}
		if prevOutput.outpoint == ns.owner {
			return badCovenant("winning REVEAL cannot be redeemed")
		}
	case wire.CovenantRegister:
		if err := v.applyRegister(dbTx, ns, covenant, tx, outputIndex,
			txOut, height, state, prevOutputs, deploymentFlags); err != nil {
			return err
		}
	case wire.CovenantUpdate:
		if err := v.applyUpdate(ns, covenant, tx, outputIndex, height,
			state, prevOutputs); err != nil {
			return err
		}
	case wire.CovenantRenew:
		if err := v.applyRenew(dbTx, ns, covenant, tx, outputIndex,
			height, state, prevOutputs); err != nil {
			return err
		}
	case wire.CovenantTransfer:
		if start != ns.height {
			return badCovenant("TRANSFER covenant has nonlocal height")
		}
		if state != nameStateClosed {
			return badCovenant("TRANSFER covenant before close")
		}
		if ns.transfer != 0 {
			return badCovenant("name is already transferring")
		}
		if err := requireCurrentNameOwner(prevOutputs, outputIndex,
			ns, "TRANSFER"); err != nil {

			return err
		}
		ns.owner = txOutpoint(tx, outputIndex)
		ns.transfer = height
	case wire.CovenantFinalize:
		if err := v.applyFinalize(dbTx, ns, covenant, tx, outputIndex,
			height, state, prevOutputs); err != nil {
			return err
		}
	case wire.CovenantRevoke:
		if start != ns.height {
			return badCovenant("REVOKE covenant has nonlocal height")
		}
		if state != nameStateClosed {
			return badCovenant("REVOKE covenant before close")
		}
		if ns.revoked != 0 {
			return badCovenant("name is already revoked")
		}
		if err := requireCurrentNameOwner(prevOutputs, outputIndex,
			ns, "REVOKE"); err != nil {

			return err
		}
		ns.revoked = height
		ns.transfer = 0
		ns.data = nil
	default:
		return badCovenant("unknown name covenant")
	}

	return v.recordChange(before, ns)
}

func (v *nameBlockView) applyClaim(dbTx database.Tx, ns *nameState,
	covenant wire.Covenant, tx *hnsutil.Tx, outputIndex int, height uint32,
	prevTime int64, state nameStateKind, value int64,
	deploymentFlags handshakeDeploymentFlags) error {

	validState := state == nameStateOpening ||
		state == nameStateLocked ||
		(state == nameStateClosed && !ns.registered)
	if !validState {
		return badCovenant("CLAIM covenant in invalid name state")
	}

	if ns.expired ||
		!isReservedNameHash(ns.nameHash, height, v.chain.chainParams) {

		return badCovenant("CLAIM covenant for unreserved name")
	}

	if _, err := verifyCoinbaseClaimProof(tx, outputIndex, height,
		prevTime, v.chain.chainParams, deploymentFlags); err != nil {

		return err
	}

	flags, _ := covenantU8(covenant, 3)
	weak := flags&1 != 0
	if deploymentFlags.hardeningActive && weak {
		return badCovenant("CLAIM ownership proof uses weak algorithm")
	}
	blockHash, _ := covenantHash(covenant, 4)
	claimed, err := v.mainChainHeightForHash(dbTx, blockHash)
	if err != nil {
		return err
	}
	claimHeight, _ := covenantU32(covenant, 5)
	if claimed < 0 || uint32(claimed) != claimHeight {
		return badCovenant("CLAIM covenant commit height mismatch")
	}
	if uint32(claimed) <= ns.claimed {
		return badCovenant("CLAIM covenant commit is not newer")
	}

	if height >= v.chain.chainParams.NameDeflationHeight {
		if isNullNameOwner(ns.owner) && claimed != 1 {
			return badCovenant("initial CLAIM must commit to height 1")
		}
		if !isNullNameOwner(ns.owner) &&
			height < ns.height+v.chain.chainParams.NameClaimFrequency {

			return badCovenant("CLAIM covenant before frequency")
		}
		if !isNullNameOwner(ns.owner) {
			coinValue, ok, err := v.nameOwnerCoinValue(dbTx, ns.owner)
			if err != nil {
				return err
			}
			if !ok || value != coinValue {
				return badCovenant("CLAIM covenant has invalid replacement value")
			}
		}
	}

	ns.height = height
	ns.renewal = height
	ns.claimed = uint32(claimed)
	ns.value = 0
	ns.owner = txOutpoint(tx, outputIndex)
	ns.highest = 0
	ns.weak = weak
	_ = value
	return nil
}

func (v *nameBlockView) applyRegister(dbTx database.Tx, ns *nameState,
	covenant wire.Covenant, tx *hnsutil.Tx, outputIndex int,
	txOut *wire.TxOut, height uint32, state nameStateKind,
	prevOutputs []namePrevOutput,
	deploymentFlags handshakeDeploymentFlags) error {

	start, _ := covenantU32(covenant, 1)
	if start != ns.height {
		return badCovenant("REGISTER covenant has nonlocal height")
	}
	if state != nameStateClosed {
		return badCovenant("REGISTER covenant before close")
	}
	hash, _ := covenantHash(covenant, 3)
	ok, err := v.verifyNameRenewalHash(dbTx, hash, height)
	if err != nil {
		return err
	}
	if !ok {
		return badCovenant("REGISTER covenant has invalid renewal hash")
	}
	prevOutput, err := linkedPrevOutput(prevOutputs, outputIndex,
		"REGISTER")
	if err != nil {
		return err
	}
	if prevOutput.outpoint != ns.owner {
		return badCovenant("REGISTER covenant does not spend winner")
	}
	if txOut.Value != ns.value {
		return badCovenant("REGISTER covenant has invalid value")
	}
	if ns.isClaimable(height, v.chain.chainParams) &&
		deploymentFlags.hardeningActive && ns.weak {

		return badCovenant("REGISTER covenant in invalid name state")
	}

	ns.registered = true
	ns.owner = txOutpoint(tx, outputIndex)
	data := covenantItem(covenant, 2)
	if len(data) > 0 {
		ns.data = append(ns.data[:0], data...)
	}
	ns.renewal = height
	return nil
}

func (v *nameBlockView) applyUpdate(ns *nameState, covenant wire.Covenant,
	tx *hnsutil.Tx, outputIndex int, height uint32,
	state nameStateKind, prevOutputs []namePrevOutput) error {

	start, _ := covenantU32(covenant, 1)
	if start != ns.height {
		return badCovenant("UPDATE covenant has nonlocal height")
	}
	if state != nameStateClosed {
		return badCovenant("UPDATE covenant before close")
	}
	if err := requireCurrentNameOwner(prevOutputs, outputIndex, ns,
		"UPDATE"); err != nil {

		return err
	}

	ns.owner = txOutpoint(tx, outputIndex)
	data := covenantItem(covenant, 2)
	if len(data) > 0 {
		ns.data = append(ns.data[:0], data...)
	}
	ns.transfer = 0
	_ = height
	return nil
}

func (v *nameBlockView) applyRenew(dbTx database.Tx, ns *nameState,
	covenant wire.Covenant, tx *hnsutil.Tx, outputIndex int,
	height uint32, state nameStateKind,
	prevOutputs []namePrevOutput) error {

	start, _ := covenantU32(covenant, 1)
	if start != ns.height {
		return badCovenant("RENEW covenant has nonlocal height")
	}
	if state != nameStateClosed {
		return badCovenant("RENEW covenant before close")
	}
	if height < ns.renewal+v.chain.chainParams.NameTreeInterval {
		return badCovenant("RENEW covenant is premature")
	}

	hash, _ := covenantHash(covenant, 2)
	ok, err := v.verifyNameRenewalHash(dbTx, hash, height)
	if err != nil {
		return err
	}
	if !ok {
		return badCovenant("RENEW covenant has invalid renewal hash")
	}
	if err := requireCurrentNameOwner(prevOutputs, outputIndex, ns,
		"RENEW"); err != nil {

		return err
	}

	ns.owner = txOutpoint(tx, outputIndex)
	ns.transfer = 0
	ns.renewal = height
	ns.renewals++
	return nil
}

func (v *nameBlockView) applyFinalize(dbTx database.Tx, ns *nameState,
	covenant wire.Covenant, tx *hnsutil.Tx, outputIndex int,
	height uint32, state nameStateKind,
	prevOutputs []namePrevOutput) error {

	start, _ := covenantU32(covenant, 1)
	if start != ns.height {
		return badCovenant("FINALIZE covenant has nonlocal height")
	}
	if state != nameStateClosed {
		return badCovenant("FINALIZE covenant before close")
	}
	if ns.transfer == 0 {
		return badCovenant("FINALIZE covenant without transfer")
	}
	if height < ns.transfer+v.chain.chainParams.NameTransferLockup {
		return badCovenant("FINALIZE covenant before transfer maturity")
	}

	flags, _ := covenantU8(covenant, 3)
	weak := flags&1 != 0
	claimed, _ := covenantU32(covenant, 4)
	renewals, _ := covenantU32(covenant, 5)
	if weak != ns.weak || claimed != ns.claimed || renewals != ns.renewals {
		return badCovenant("FINALIZE covenant state transfer mismatch")
	}

	hash, _ := covenantHash(covenant, 6)
	ok, err := v.verifyNameRenewalHash(dbTx, hash, height)
	if err != nil {
		return err
	}
	if !ok {
		return badCovenant("FINALIZE covenant has invalid renewal hash")
	}
	if err := requireCurrentNameOwner(prevOutputs, outputIndex, ns,
		"FINALIZE"); err != nil {

		return err
	}

	ns.owner = txOutpoint(tx, outputIndex)
	ns.transfer = 0
	ns.renewal = height
	ns.renewals++
	return nil
}

func requireCurrentNameOwner(prevOutputs []namePrevOutput, outputIndex int,
	ns *nameState, covenant string) error {

	prevOutput, err := linkedPrevOutput(prevOutputs, outputIndex, covenant)
	if err != nil {
		return err
	}
	if prevOutput.outpoint != ns.owner {
		return badCovenant(covenant +
			" covenant does not spend current owner")
	}
	return nil
}

func linkedPrevOutput(prevOutputs []namePrevOutput, outputIndex int,
	covenant string) (namePrevOutput, error) {
	if outputIndex < 0 || outputIndex >= len(prevOutputs) {
		return namePrevOutput{}, badCovenant(covenant +
			" covenant is not linked")
	}

	return prevOutputs[outputIndex], nil
}

func verifyCovenantSpends(tx *hnsutil.Tx, prevOutputs []namePrevOutput) error {
	msgTx := tx.MsgTx()
	if len(prevOutputs) != len(msgTx.TxIn) {
		return AssertError("missing covenant previous outputs")
	}

	for inputIndex, prev := range prevOutputs {
		var output *wire.TxOut
		if inputIndex < len(msgTx.TxOut) {
			output = msgTx.TxOut[inputIndex]
		}

		if err := verifyCovenantSpend(prev, output); err != nil {
			return err
		}
	}

	return nil
}

func verifyCovenantSpend(prev namePrevOutput, output *wire.TxOut) error {
	uc := prev.covenant
	if output == nil {
		switch uc.Type {
		case wire.CovenantNone, wire.CovenantOpen, wire.CovenantRedeem:
			return nil
		default:
			return badCovenant("linked covenant missing output")
		}
	}

	covenant := output.Covenant
	switch uc.Type {
	case wire.CovenantNone, wire.CovenantOpen, wire.CovenantRedeem:
		switch covenant.Type {
		case wire.CovenantNone, wire.CovenantOpen, wire.CovenantBid:
			return nil
		default:
			return badCovenant("invalid covenant after NONE/OPEN/REDEEM")
		}
	case wire.CovenantBid:
		if covenant.Type != wire.CovenantReveal {
			return badCovenant("BID must spend to REVEAL")
		}
		if !sameNameAndHeight(uc, covenant) {
			return badCovenant("REVEAL does not match BID")
		}
		nonce, _ := covenantHash(covenant, 2)
		blind := blindBid(output.Value, nonce)
		wantBlind, _ := covenantHash(uc, 3)
		if blind != wantBlind {
			return badCovenant("REVEAL value does not match BID blind")
		}
		if prev.amount < output.Value {
			return badCovenant("REVEAL value exceeds BID coin")
		}
	case wire.CovenantClaim, wire.CovenantReveal:
		switch covenant.Type {
		case wire.CovenantRegister:
			if !sameNameAndHeight(uc, covenant) {
				return badCovenant("REGISTER does not match REVEAL")
			}
			if !equalAddress(output.Address, prev.address) {
				return badCovenant("REGISTER address changed")
			}
		case wire.CovenantRedeem:
			if uc.Type == wire.CovenantClaim {
				return badCovenant("CLAIM cannot spend to REDEEM")
			}
			if !sameNameAndHeight(uc, covenant) {
				return badCovenant("REDEEM does not match REVEAL")
			}
		default:
			return badCovenant("invalid covenant after CLAIM/REVEAL")
		}
	case wire.CovenantRegister, wire.CovenantUpdate, wire.CovenantRenew,
		wire.CovenantFinalize:

		if output.Value != prev.amount {
			return badCovenant("name value changed")
		}
		if !equalAddress(output.Address, prev.address) {
			return badCovenant("name address changed")
		}
		switch covenant.Type {
		case wire.CovenantUpdate, wire.CovenantRenew,
			wire.CovenantTransfer, wire.CovenantRevoke:
			if !sameNameAndHeight(uc, covenant) {
				return badCovenant("name covenant is nonlocal")
			}
		default:
			return badCovenant("invalid covenant after name owner")
		}
	case wire.CovenantTransfer:
		if output.Value != prev.amount {
			return badCovenant("transfer value changed")
		}
		switch covenant.Type {
		case wire.CovenantUpdate, wire.CovenantRenew, wire.CovenantRevoke:
			if !sameNameAndHeight(uc, covenant) {
				return badCovenant("transfer covenant is nonlocal")
			}
			if !equalAddress(output.Address, prev.address) {
				return badCovenant("transfer address changed")
			}
		case wire.CovenantFinalize:
			if !sameNameAndHeight(uc, covenant) {
				return badCovenant("FINALIZE covenant is nonlocal")
			}
			version, _ := covenantU8(uc, 2)
			hash := covenantItem(uc, 3)
			if output.Address.Version != version ||
				!bytes.Equal(output.Address.Hash, hash) {
				return badCovenant("FINALIZE address mismatch")
			}
		default:
			return badCovenant("invalid covenant after TRANSFER")
		}
	case wire.CovenantRevoke:
		return badCovenant("REVOKE covenant is unspendable")
	default:
		if isNameCovenant(covenant.Type) {
			return badCovenant("unknown covenant spends to name covenant")
		}
	}

	return nil
}

func sameNameAndHeight(a, b wire.Covenant) bool {
	aHash, ok := covenantHash(a, 0)
	if !ok {
		return false
	}
	bHash, ok := covenantHash(b, 0)
	if !ok || aHash != bHash {
		return false
	}

	aHeight, ok := covenantU32(a, 1)
	if !ok {
		return false
	}
	bHeight, ok := covenantU32(b, 1)
	return ok && aHeight == bHeight
}

func equalAddress(a, b wire.Address) bool {
	return a.Version == b.Version && bytes.Equal(a.Hash, b.Hash)
}

func blindBid(value int64, nonce chainhash.Hash) chainhash.Hash {
	var preimage [8 + chainhash.HashSize]byte
	binary.LittleEndian.PutUint64(preimage[:8], uint64(value))
	copy(preimage[8:], nonce[:])
	return chainhash.Hash(blake2b.Sum256(preimage[:]))
}

func txOutpoint(tx *hnsutil.Tx, outputIndex int) wire.OutPoint {
	return wire.OutPoint{
		Hash:  *tx.Hash(),
		Index: uint32(outputIndex),
	}
}

func prevOutputsFromView(tx *hnsutil.Tx, view *UtxoViewpoint) (
	[]namePrevOutput, error) {

	if IsCoinBase(tx) {
		return nil, nil
	}

	msgTx := tx.MsgTx()
	prevOutputs := make([]namePrevOutput, len(msgTx.TxIn))
	for i, txIn := range msgTx.TxIn {
		entry := view.LookupEntry(txIn.PreviousOutPoint)
		if entry == nil || entry.IsSpent() {
			str := fmt.Sprintf("output %v referenced from "+
				"transaction %s:%d either does not exist or "+
				"has already been spent", txIn.PreviousOutPoint,
				tx.Hash(), i)
			return nil, ruleError(ErrMissingTxOut, str)
		}

		prevOutputs[i] = namePrevOutput{
			outpoint: txIn.PreviousOutPoint,
			amount:   entry.Amount(),
			address:  entry.Address(),
			covenant: entry.Covenant(),
		}
	}

	return prevOutputs, nil
}

func prevOutputsFromStxos(tx *hnsutil.Tx, stxos []SpentTxOut,
	offset *int) ([]namePrevOutput, error) {

	if IsCoinBase(tx) {
		return nil, nil
	}

	msgTx := tx.MsgTx()
	prevOutputs := make([]namePrevOutput, len(msgTx.TxIn))
	for i, txIn := range msgTx.TxIn {
		if *offset >= len(stxos) {
			return nil, AssertError("missing spent txout for name validation")
		}
		stxo := stxos[*offset]
		prevOutputs[i] = namePrevOutput{
			outpoint: txIn.PreviousOutPoint,
			amount:   stxo.Amount,
			address:  cloneAddress(stxo.Address),
			covenant: cloneCovenant(stxo.Covenant),
		}
		*offset = *offset + 1
	}

	return prevOutputs, nil
}

func (b *BlockChain) checkNameBlockForBestChain(block *hnsutil.Block) (
	*nameBlockView, error) {

	parentHash := &block.MsgBlock().Header.PrevBlock
	if !parentHash.IsEqual(&b.bestChain.Tip().hash) {
		return nil, nil
	}

	err := b.db.View(func(dbTx database.Tx) error {
		return checkNameRoot(dbTx, block)
	})
	if err != nil {
		return nil, err
	}

	return newLazyNameBlockView(b), nil
}

// nameReorgView mirrors the name state, committed root, and active chain used
// while verifyReorganizationValidity replays detach and attach blocks.
type nameReorgView struct {
	view      *nameBlockView
	root      chainhash.Hash
	mainChain *chainView
}

func newNameReorgView(dbTx database.Tx, chain *BlockChain) (*nameReorgView, error) {
	root, err := dbFetchNameRoot(dbTx)
	if err != nil {
		return nil, err
	}

	view, err := newNameBlockView(dbTx, chain)
	if err != nil {
		return nil, err
	}

	reorgView := &nameReorgView{
		view:      view,
		root:      root,
		mainChain: newChainView(chain.bestChain.Tip()),
	}
	view.mainChainHeight = reorgView.mainChainHeightForHash
	return reorgView, nil
}

func (v *nameReorgView) mainChainHeightForHash(hash chainhash.Hash) (
	int32, error) {

	node := v.view.chain.index.LookupNode(&hash)
	if node == nil || !v.mainChain.Contains(node) {
		return -1, nil
	}
	return node.height, nil
}

func (v *nameReorgView) disconnectBlock(node *blockNode,
	block *hnsutil.Block, undo []nameUndoEntry) error {

	for _, entry := range undo {
		if entry.existed {
			v.view.states[entry.nameHash] = entry.state.clone()
			continue
		}
		delete(v.view.states, entry.nameHash)
	}

	if v.view.chain.chainParams.NameTreeInterval != 0 &&
		uint32(node.height)%v.view.chain.chainParams.NameTreeInterval == 0 {

		v.root = block.MsgBlock().Header.NameRoot
	}

	v.mainChain.SetTip(node.parent)
	return nil
}

func (v *nameReorgView) checkConnectBlock(block *hnsutil.Block) (
	*nameBlockView, error) {

	if err := checkNameRootAgainst(v.root, block); err != nil {
		return nil, err
	}
	return v.view, nil
}

func (v *nameReorgView) connectBlock(node *blockNode) error {
	if v.view.chain.chainParams.NameTreeInterval != 0 &&
		uint32(node.height)%v.view.chain.chainParams.NameTreeInterval == 0 {

		root, err := calcNameRootFromStates(v.view.states)
		if err != nil {
			return err
		}
		v.root = root
	}

	v.view.undo = nil
	v.view.dirty = make(map[chainhash.Hash]struct{})
	v.view.seen = make(map[chainhash.Hash]struct{})
	v.mainChain.SetTip(node)
	return nil
}

func (b *BlockChain) connectNames(dbTx database.Tx, node *blockNode,
	block *hnsutil.Block, stxos []SpentTxOut) error {

	if err := checkNameRoot(dbTx, block); err != nil {
		return err
	}

	deploymentFlags, err := b.handshakeDeploymentFlags(node.parent)
	if err != nil {
		return err
	}

	view := newLazyNameBlockView(b)
	view.ownerCoinValue = b.nameOwnerCoinLookup(nil)

	stxoOffset := 0
	for _, tx := range block.Transactions() {
		prevOutputs, err := prevOutputsFromStxos(tx, stxos, &stxoOffset)
		if err != nil {
			return err
		}
		if err := view.applyTx(dbTx, tx, uint32(node.height),
			node.parent.timestamp,
			prevOutputs, deploymentFlags); err != nil {
			return err
		}
	}
	if stxoOffset != len(stxos) {
		return AssertError("unused spent txouts during name validation")
	}

	for nameHash := range view.dirty {
		if err := dbPutNameState(dbTx, view.states[nameHash]); err != nil {
			return err
		}
	}

	if err := dbPutNameUndo(dbTx, block.Hash(), view.undo); err != nil {
		return err
	}

	if b.nameRootCache != nil {
		if err := b.nameRootCache.applyView(view); err != nil {
			return err
		}
	}

	if b.chainParams.NameTreeInterval != 0 &&
		uint32(node.height)%b.chainParams.NameTreeInterval == 0 {

		if err := b.dbPutCachedNameRoot(dbTx); err != nil {
			return err
		}
	}

	return nil
}

func (b *BlockChain) disconnectNames(dbTx database.Tx, node *blockNode,
	block *hnsutil.Block) error {

	undo, err := dbFetchNameUndo(dbTx, block.Hash())
	if err != nil {
		return err
	}

	for _, entry := range undo {
		if entry.existed {
			if err := dbPutNameState(dbTx, entry.state); err != nil {
				return err
			}
			continue
		}

		bucket := dbTx.Metadata().Bucket(nameStateBucketName)
		if bucket != nil {
			if err := bucket.Delete(entry.nameHash[:]); err != nil {
				return err
			}
		}
	}

	if err := dbRemoveNameUndo(dbTx, block.Hash()); err != nil {
		return err
	}

	if b.nameRootCache != nil {
		if err := b.nameRootCache.applyUndo(undo); err != nil {
			return err
		}
	}

	if b.chainParams.NameTreeInterval != 0 &&
		uint32(node.height)%b.chainParams.NameTreeInterval == 0 {

		root, err := b.cachedNameRoot(dbTx)
		if err != nil {
			return err
		}
		headerRoot := block.MsgBlock().Header.NameRoot
		if root != headerRoot {
			return AssertError(fmt.Sprintf("name root after "+
				"disconnect is %v, want %v", root, headerRoot))
		}
		if err := dbPutNameRoot(dbTx, headerRoot); err != nil {
			return err
		}
	}

	return nil
}

func (b *BlockChain) cachedNameRoot(dbTx database.Tx) (chainhash.Hash, error) {
	if b.nameRootCache == nil {
		cache, err := newNameRootCache(dbTx)
		if err != nil {
			return chainhash.Hash{}, err
		}
		b.nameRootCache = cache
	}
	return b.nameRootCache.root(dbTx)
}

func (b *BlockChain) dbPutCachedNameRoot(dbTx database.Tx) error {
	root, err := b.cachedNameRoot(dbTx)
	if err != nil {
		return err
	}
	return dbPutNameRoot(dbTx, root)
}

func (v *nameBlockView) mainChainHeightForHash(dbTx database.Tx,
	hash chainhash.Hash) (int32, error) {

	if v.mainChainHeight != nil {
		return v.mainChainHeight(hash)
	}
	return v.chain.mainChainHeight(dbTx, hash)
}

func (v *nameBlockView) verifyNameRenewalHash(dbTx database.Tx,
	hash chainhash.Hash, height uint32) (bool, error) {

	if height < v.chain.chainParams.NameRenewalMaturity {
		return true, nil
	}

	blockHeight, err := v.mainChainHeightForHash(dbTx, hash)
	if err != nil {
		return false, err
	}
	if blockHeight < 0 {
		return false, nil
	}

	maxHeight := int64(height) - int64(v.chain.chainParams.NameRenewalMaturity)
	if int64(blockHeight) > maxHeight {
		return false, nil
	}

	minHeight := int64(height) - int64(v.chain.chainParams.NameRenewalPeriod)
	if minHeight < 0 {
		minHeight = 0
	}
	return int64(blockHeight) >= minHeight, nil
}

func (b *BlockChain) mainChainHeight(dbTx database.Tx,
	hash chainhash.Hash) (int32, error) {

	var height int32
	var err error
	fetch := func(tx database.Tx) error {
		height, err = dbFetchHeightByHash(tx, &hash)
		if err != nil {
			if isNotInMainChainErr(err) {
				height = -1
				return nil
			}
			return err
		}
		return nil
	}

	if dbTx != nil {
		if err := fetch(dbTx); err != nil {
			return -1, err
		}
		return height, nil
	}

	if err := b.db.View(fetch); err != nil {
		return -1, err
	}
	return height, nil
}

func hasNameRollout(nameHash chainhash.Hash, height uint32,
	params *chaincfg.Params) bool {

	if params.NameNoRollout {
		return true
	}

	week := modNameHash(nameHash, 52)
	start := params.NameAuctionStart + week*params.NameRolloutInterval
	return height >= start
}

func modNameHash(nameHash chainhash.Hash, mod uint32) uint32 {
	p := uint32(256) % mod
	var acc uint32
	for _, b := range nameHash[:] {
		acc = (p*acc + uint32(b)) % mod
	}
	return acc
}
