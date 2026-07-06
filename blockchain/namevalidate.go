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

type nameBlockView struct {
	chain           *BlockChain
	states          map[chainhash.Hash]*nameState
	dirty           map[chainhash.Hash]struct{}
	undo            []nameUndoEntry
	seen            map[chainhash.Hash]struct{}
	mainChainHeight func(chainhash.Hash) (int32, error)
}

func newNameBlockView(dbTx database.Tx, chain *BlockChain) (*nameBlockView, error) {
	states, err := dbFetchAllNameStates(dbTx)
	if err != nil {
		return nil, err
	}

	return &nameBlockView{
		chain:  chain,
		states: states,
		dirty:  make(map[chainhash.Hash]struct{}),
		seen:   make(map[chainhash.Hash]struct{}),
	}, nil
}

func (v *nameBlockView) get(nameHash chainhash.Hash) *nameState {
	ns := v.states[nameHash]
	if ns == nil {
		ns = newNameState(nameHash)
		v.states[nameHash] = ns
	}
	return ns
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
	height uint32, prevTime int64, prevOutputs []namePrevOutput) error {

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
			height, prevTime, prevOutputs); err != nil {

			return err
		}
	}

	return nil
}

func (v *nameBlockView) applyCovenantOutput(dbTx database.Tx, tx *hnsutil.Tx,
	outputIndex int, txOut *wire.TxOut, height uint32,
	prevTime int64, prevOutputs []namePrevOutput) error {

	covenant := txOut.Covenant
	nameHash, ok := covenantHash(covenant, 0)
	if !ok {
		return badCovenant("missing covenant name hash")
	}

	ns := v.get(nameHash)
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
			height, prevTime, state, txOut.Value); err != nil {
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
			txOut, height, state, prevOutputs); err != nil {
			return err
		}
	case wire.CovenantUpdate:
		if err := v.applyUpdate(ns, covenant, tx, outputIndex, height,
			state); err != nil {
			return err
		}
	case wire.CovenantRenew:
		if err := v.applyRenew(dbTx, ns, covenant, tx, outputIndex,
			height, state); err != nil {
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
		ns.owner = txOutpoint(tx, outputIndex)
		ns.transfer = height
	case wire.CovenantFinalize:
		if err := v.applyFinalize(dbTx, ns, covenant, tx, outputIndex,
			height, state); err != nil {
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
	prevTime int64, state nameStateKind, value int64) error {

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
		prevTime, v.chain.chainParams); err != nil {

		return err
	}

	flags, _ := covenantU8(covenant, 3)
	weak := flags&1 != 0
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
	prevOutputs []namePrevOutput) error {

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

	ns.registered = true
	ns.owner = txOutpoint(tx, outputIndex)
	data := covenantItem(covenant, 2)
	if len(data) == 0 {
		ns.data = nil
	} else {
		ns.data = append(ns.data[:0], data...)
	}
	ns.renewal = height
	return nil
}

func (v *nameBlockView) applyUpdate(ns *nameState, covenant wire.Covenant,
	tx *hnsutil.Tx, outputIndex int, height uint32,
	state nameStateKind) error {

	start, _ := covenantU32(covenant, 1)
	if start != ns.height {
		return badCovenant("UPDATE covenant has nonlocal height")
	}
	if state != nameStateClosed {
		return badCovenant("UPDATE covenant before close")
	}

	ns.owner = txOutpoint(tx, outputIndex)
	data := covenantItem(covenant, 2)
	if len(data) == 0 {
		ns.data = nil
	} else {
		ns.data = append(ns.data[:0], data...)
	}
	ns.transfer = 0
	_ = height
	return nil
}

func (v *nameBlockView) applyRenew(dbTx database.Tx, ns *nameState,
	covenant wire.Covenant, tx *hnsutil.Tx, outputIndex int,
	height uint32, state nameStateKind) error {

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

	ns.owner = txOutpoint(tx, outputIndex)
	ns.transfer = 0
	ns.renewal = height
	ns.renewals++
	return nil
}

func (v *nameBlockView) applyFinalize(dbTx database.Tx, ns *nameState,
	covenant wire.Covenant, tx *hnsutil.Tx, outputIndex int,
	height uint32, state nameStateKind) error {

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

	ns.owner = txOutpoint(tx, outputIndex)
	ns.transfer = 0
	ns.renewal = height
	ns.renewals++
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

	var view *nameBlockView
	err := b.db.View(func(dbTx database.Tx) error {
		if err := checkNameRoot(dbTx, block); err != nil {
			return err
		}

		var err error
		view, err = newNameBlockView(dbTx, b)
		return err
	})
	if err != nil {
		return nil, err
	}

	return view, nil
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

	view, err := newNameBlockView(dbTx, b)
	if err != nil {
		return err
	}

	stxoOffset := 0
	for _, tx := range block.Transactions() {
		prevOutputs, err := prevOutputsFromStxos(tx, stxos, &stxoOffset)
		if err != nil {
			return err
		}
		if err := view.applyTx(dbTx, tx, uint32(node.height),
			node.parent.timestamp,
			prevOutputs); err != nil {
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

	if b.chainParams.NameTreeInterval != 0 &&
		uint32(node.height)%b.chainParams.NameTreeInterval == 0 {

		if _, err := dbStoreCurrentNameSnapshot(dbTx); err != nil {
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

	if b.chainParams.NameTreeInterval != 0 &&
		uint32(node.height)%b.chainParams.NameTreeInterval == 0 {

		leaves, root, err := dbCalcNameTree(dbTx)
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
		if err := dbPutNameSnapshot(dbTx, headerRoot, leaves); err != nil {
			return err
		}
	}

	return nil
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
