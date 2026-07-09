// Copyright (c) 2024-2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"bytes"
	"testing"
	"time"

	"github.com/blinklabs-io/handshake-node/chaincfg"
	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/database"
	"github.com/blinklabs-io/handshake-node/hnsutil"
	"github.com/blinklabs-io/handshake-node/wire"
)

type nameFixtureTx struct {
	tx          *hnsutil.Tx
	prevOutputs []namePrevOutput
}

type connectedNameBlock struct {
	label    string
	node     *blockNode
	block    *hnsutil.Block
	nameHash *chainhash.Hash
	before   *nameState
}

type nameLifecycleFixture struct {
	t            *testing.T
	chain        *BlockChain
	parent       *blockNode
	ownerAddr    wire.Address
	transferAddr wire.Address
	nextTag      uint32
	connected    []connectedNameBlock
}

func TestNameAuctionTransferLifecycleFixtureAndReorg(t *testing.T) {
	fixture := newNameLifecycleFixture(t, "namelifecycle")
	name := "lifecyc"
	start := uint32(1)
	value := int64(7)
	nonce := chainhash.Hash{0x0a, 0x0b}

	openTx := fixture.spend(fixture.fundingPrev(1), 1,
		fixture.ownerAddr, openCovenant(name))
	fixture.connectNameTx("OPEN", name, openTx)
	fixture.assertNameState(name, func(ns *nameState) {
		if ns.height != start || string(ns.name) != name {
			t.Fatalf("OPEN state = %+v, want height %d name %q",
				ns, start, name)
		}
	})

	bidHeight := int32(start + fixture.chain.chainParams.NameTreeInterval + 1)
	fixture.advanceTo(bidHeight)
	blind := blindBid(value, nonce)
	bidTx := fixture.spend(fixture.fundingPrev(value), value,
		fixture.ownerAddr, bidCovenant(name, start, blind))
	fixture.connectNameTx("BID", name, bidTx)

	revealHeight := bidHeight + int32(fixture.chain.chainParams.NameBiddingPeriod)
	fixture.advanceTo(revealHeight)
	revealTx := fixture.spend(prevOutputFromNameTx(bidTx.tx, 0), value,
		fixture.ownerAddr, revealCovenantWithNonce(name, start, nonce))
	fixture.connectNameTx("REVEAL", name, revealTx)
	revealOwner := txOutpoint(revealTx.tx, 0)
	fixture.assertNameState(name, func(ns *nameState) {
		if ns.owner != revealOwner || ns.value != 0 || ns.highest != value {

			t.Fatalf("REVEAL state = %+v, want owner %v value 0 highest %d",
				ns, revealOwner, value)
		}
	})

	registerHeight := revealHeight +
		int32(fixture.chain.chainParams.NameRevealPeriod)
	registeredValue := int64(0)
	fixture.advanceTo(registerHeight)
	registerTx := fixture.spend(prevOutputFromNameTx(revealTx.tx, 0),
		registeredValue, fixture.ownerAddr,
		registerCovenantWithData(name, start, []byte("registered")))
	fixture.connectNameTx("REGISTER", name, registerTx)
	registerOwner := txOutpoint(registerTx.tx, 0)
	fixture.assertNameState(name, func(ns *nameState) {
		if !ns.registered || ns.owner != registerOwner ||
			!bytes.Equal(ns.data, []byte("registered")) {

			t.Fatalf("REGISTER state = %+v, want owner %v data registered",
				ns, registerOwner)
		}
	})

	updateTx := fixture.spend(prevOutputFromNameTx(registerTx.tx, 0),
		registeredValue, fixture.ownerAddr,
		updateCovenantWithData(name, start, []byte("updated")))
	fixture.connectNameTx("UPDATE", name, updateTx)
	updateOwner := txOutpoint(updateTx.tx, 0)
	fixture.assertNameState(name, func(ns *nameState) {
		if ns.owner != updateOwner || !bytes.Equal(ns.data,
			[]byte("updated")) {

			t.Fatalf("UPDATE state = %+v, want owner %v data updated",
				ns, updateOwner)
		}
	})

	renewTx := fixture.spend(prevOutputFromNameTx(updateTx.tx, 0),
		registeredValue, fixture.ownerAddr,
		renewCovenant(name, start, chainhash.Hash{}))
	fixture.connectNameTx("RENEW", name, renewTx)
	renewOwner := txOutpoint(renewTx.tx, 0)
	fixture.assertNameState(name, func(ns *nameState) {
		if ns.owner != renewOwner || ns.renewals != 1 ||
			ns.renewal != uint32(fixture.parent.height) {

			t.Fatalf("RENEW state = %+v, want owner %v renewal height %d",
				ns, renewOwner, fixture.parent.height)
		}
	})

	transferTx := fixture.spend(prevOutputFromNameTx(renewTx.tx, 0),
		registeredValue, fixture.ownerAddr,
		transferCovenant(name, start, fixture.transferAddr))
	fixture.connectNameTx("TRANSFER", name, transferTx)
	transferHeight := uint32(fixture.parent.height)
	transferOwner := txOutpoint(transferTx.tx, 0)
	fixture.assertNameState(name, func(ns *nameState) {
		if ns.owner != transferOwner || ns.transfer != transferHeight {
			t.Fatalf("TRANSFER state = %+v, want owner %v transfer %d",
				ns, transferOwner, transferHeight)
		}
	})

	finalizeTx := fixture.spend(prevOutputFromNameTx(transferTx.tx, 0),
		registeredValue, fixture.transferAddr,
		finalizeCovenantWithName(name, start, 1, chainhash.Hash{}))
	fixture.connectNameTx("FINALIZE", name, finalizeTx)
	finalizeOwner := txOutpoint(finalizeTx.tx, 0)
	fixture.assertNameState(name, func(ns *nameState) {
		if ns.owner != finalizeOwner || ns.transfer != 0 ||
			ns.renewals != 2 || ns.renewal != uint32(fixture.parent.height) {

			t.Fatalf("FINALIZE state = %+v, want owner %v finalized at %d",
				ns, finalizeOwner, fixture.parent.height)
		}
	})

	fixture.disconnectAll()
	fixture.assertNameMissing(name)
}

func TestNameRevokeReopenFixtureAndReorg(t *testing.T) {
	fixture := newNameLifecycleFixture(t, "namerevokereopen")
	name := "revival"
	start, registerTx := fixture.registerName(name, 9,
		chainhash.Hash{0x0c}, []byte("registered"))
	registerPrev := prevOutputFromNameTx(registerTx, 0)

	revokeTx := fixture.spend(registerPrev, registerPrev.amount,
		fixture.ownerAddr, revokeCovenant(name, start))
	fixture.connectNameTx("REVOKE", name, revokeTx)
	revokeHeight := uint32(fixture.parent.height)
	fixture.assertNameState(name, func(ns *nameState) {
		if ns.revoked != revokeHeight || len(ns.data) != 0 {
			t.Fatalf("REVOKE state = %+v, want revoked at %d with no data",
				ns, revokeHeight)
		}
	})

	reopenHeight := int32(revokeHeight +
		fixture.chain.chainParams.NameAuctionMaturity)
	fixture.advanceTo(reopenHeight)
	reopenTx := fixture.spend(fixture.fundingPrev(1), 1,
		fixture.ownerAddr, openCovenant(name))
	fixture.connectNameTx("REOPEN", name, reopenTx)
	fixture.assertNameState(name, func(ns *nameState) {
		if ns.height != uint32(fixture.parent.height) ||
			ns.revoked != 0 || !isNullNameOwner(ns.owner) ||
			ns.state(uint32(fixture.parent.height),
				fixture.chain.chainParams) != nameStateOpening {

			t.Fatalf("REOPEN state = %+v, want fresh opening at %d",
				ns, fixture.parent.height)
		}
	})

	fixture.disconnectAll()
	fixture.assertNameMissing(name)
}

func newNameLifecycleFixture(t *testing.T, dbName string) *nameLifecycleFixture {
	t.Helper()

	params := chaincfg.RegressionNetParams
	params.NameNoRollout = true
	params.NameNoReserved = true
	params.NameTreeInterval = 1
	params.NameBiddingPeriod = 1
	params.NameRevealPeriod = 1
	params.NameTransferLockup = 1
	params.NameAuctionMaturity = 2
	params.NameRenewalWindow = 20
	params.NameRenewalMaturity = 1000

	chain, teardown, err := chainSetup(dbName, &params)
	if err != nil {
		t.Fatalf("chainSetup: %v", err)
	}
	t.Cleanup(teardown)

	return &nameLifecycleFixture{
		t:      t,
		chain:  chain,
		parent: chain.bestChain.Tip(),
		ownerAddr: wire.Address{
			Version: 0,
			Hash:    bytes.Repeat([]byte{0x01}, 20),
		},
		transferAddr: wire.Address{
			Version: 0,
			Hash:    bytes.Repeat([]byte{0x02}, 20),
		},
		nextTag: 100,
	}
}

func (f *nameLifecycleFixture) registerName(name string, value int64,
	nonce chainhash.Hash, data []byte) (uint32, *hnsutil.Tx) {

	start := uint32(f.parent.height + 1)
	openTx := f.spend(f.fundingPrev(1), 1, f.ownerAddr,
		openCovenant(name))
	f.connectNameTx("OPEN", name, openTx)

	bidHeight := int32(start + f.chain.chainParams.NameTreeInterval + 1)
	f.advanceTo(bidHeight)
	blind := blindBid(value, nonce)
	bidTx := f.spend(f.fundingPrev(value), value, f.ownerAddr,
		bidCovenant(name, start, blind))
	f.connectNameTx("BID", name, bidTx)

	revealHeight := bidHeight + int32(f.chain.chainParams.NameBiddingPeriod)
	f.advanceTo(revealHeight)
	revealTx := f.spend(prevOutputFromNameTx(bidTx.tx, 0), value,
		f.ownerAddr, revealCovenantWithNonce(name, start, nonce))
	f.connectNameTx("REVEAL", name, revealTx)

	registerHeight := revealHeight +
		int32(f.chain.chainParams.NameRevealPeriod)
	f.advanceTo(registerHeight)
	registerTx := f.spend(prevOutputFromNameTx(revealTx.tx, 0), 0,
		f.ownerAddr, registerCovenantWithData(name, start, data))
	f.connectNameTx("REGISTER", name, registerTx)
	return start, registerTx.tx
}

func (f *nameLifecycleFixture) advanceTo(height int32) {
	f.t.Helper()

	for f.parent.height+1 < height {
		f.connectBlock("EMPTY", nil)
	}
}

func (f *nameLifecycleFixture) connectNameTx(label, name string,
	tx nameFixtureTx) {

	f.t.Helper()

	nameHash := hashName([]byte(name))
	f.connectBlock(label, &nameHash, tx)
}

func (f *nameLifecycleFixture) connectBlock(label string,
	nameHash *chainhash.Hash, txs ...nameFixtureTx) {

	f.t.Helper()

	var before *nameState
	var blockNameHash *chainhash.Hash
	if nameHash != nil {
		before = f.fetchNameState(*nameHash)
		hashCopy := *nameHash
		blockNameHash = &hashCopy
	}

	root := f.nameRoot()
	msgTxs := make([]*wire.MsgTx, 0, len(txs))
	stxos := make([]SpentTxOut, 0, len(txs))
	for _, tx := range txs {
		msgTx := tx.tx.MsgTx()
		if len(msgTx.TxIn) != len(tx.prevOutputs) {
			f.t.Fatalf("%s tx input count = %d, prev outputs = %d",
				label, len(msgTx.TxIn), len(tx.prevOutputs))
		}

		for i, prevOutput := range tx.prevOutputs {
			if msgTx.TxIn[i].PreviousOutPoint != prevOutput.outpoint {
				f.t.Fatalf("%s input %d prevout = %v, want %v",
					label, i, msgTx.TxIn[i].PreviousOutPoint,
					prevOutput.outpoint)
			}
			stxos = append(stxos, spentTxOutFromNamePrev(prevOutput))
		}
		msgTxs = append(msgTxs, msgTx)
	}

	header := wire.BlockHeader{
		Version:    1,
		PrevBlock:  f.parent.hash,
		NameRoot:   root,
		MerkleRoot: calcMerkleRoot(msgTxs),
		Bits:       f.chain.chainParams.PowLimitBits,
		Timestamp:  time.Unix(f.parent.timestamp+1, 0),
		Nonce:      uint32(f.parent.height + 1),
	}
	msgBlock := &wire.MsgBlock{
		Header:       header,
		Transactions: msgTxs,
	}
	block := hnsutil.NewBlock(msgBlock)
	node := newBlockNode(&msgBlock.Header, f.parent)
	block.SetHeight(node.height)

	err := f.chain.db.Update(func(dbTx database.Tx) error {
		return f.chain.connectNames(dbTx, node, block, stxos)
	})
	if err != nil {
		f.t.Fatalf("connectNames %s height %d: %v", label,
			node.height, err)
	}

	f.connected = append(f.connected, connectedNameBlock{
		label:    label,
		node:     node,
		block:    block,
		nameHash: blockNameHash,
		before:   before,
	})
	f.parent = node
}

func (f *nameLifecycleFixture) disconnectAll() {
	f.t.Helper()

	for i := len(f.connected) - 1; i >= 0; i-- {
		connected := f.connected[i]
		err := f.chain.db.Update(func(dbTx database.Tx) error {
			return f.chain.disconnectNames(dbTx, connected.node,
				connected.block)
		})
		if err != nil {
			f.t.Fatalf("disconnectNames %s height %d: %v",
				connected.label, connected.node.height, err)
		}

		root := f.nameRoot()
		headerRoot := connected.block.MsgBlock().Header.NameRoot
		if root != headerRoot {
			f.t.Fatalf("disconnectNames %s root = %v, want %v",
				connected.label, root, headerRoot)
		}

		if connected.nameHash != nil {
			f.assertNameStateEquals(*connected.nameHash,
				connected.before, connected.label)
		}
		f.parent = connected.node.parent
	}
	f.connected = nil
}

func (f *nameLifecycleFixture) fundingPrev(amount int64) namePrevOutput {
	f.t.Helper()

	outpoint := *testOutPoint(f.nextTag)
	f.nextTag++
	return namePrevOutput{
		outpoint: outpoint,
		amount:   amount,
		address:  cloneAddress(f.ownerAddr),
		covenant: wire.Covenant{},
	}
}

func (f *nameLifecycleFixture) spend(prevOutput namePrevOutput,
	value int64, address wire.Address, covenant wire.Covenant) nameFixtureTx {

	f.t.Helper()

	tx := wire.NewMsgTx(1)
	tx.AddTxIn(wire.NewTxIn(&prevOutput.outpoint,
		wire.MaxTxInSequenceNum, nil))
	tx.AddTxOut(wire.NewTxOut(value, address, covenant))

	if err := CheckTransactionSanity(hnsutil.NewTx(tx)); err != nil {
		f.t.Fatalf("CheckTransactionSanity: %v", err)
	}

	return nameFixtureTx{
		tx: hnsutil.NewTx(tx),
		prevOutputs: []namePrevOutput{
			prevOutput,
		},
	}
}

func (f *nameLifecycleFixture) nameRoot() chainhash.Hash {
	f.t.Helper()

	var root chainhash.Hash
	err := f.chain.db.View(func(dbTx database.Tx) error {
		var err error
		root, err = dbFetchNameRoot(dbTx)
		return err
	})
	if err != nil {
		f.t.Fatalf("dbFetchNameRoot: %v", err)
	}
	return root
}

func (f *nameLifecycleFixture) fetchNameState(
	nameHash chainhash.Hash) *nameState {

	f.t.Helper()

	var state *nameState
	err := f.chain.db.View(func(dbTx database.Tx) error {
		ns, found, err := dbFetchNameState(dbTx, nameHash)
		if err != nil || !found {
			return err
		}
		state = ns.clone()
		return nil
	})
	if err != nil {
		f.t.Fatalf("dbFetchNameState: %v", err)
	}
	return state
}

func (f *nameLifecycleFixture) assertNameState(name string,
	check func(*nameState)) {

	f.t.Helper()

	nameHash := hashName([]byte(name))
	ns := f.fetchNameState(nameHash)
	if ns == nil {
		f.t.Fatalf("name %q state missing", name)
	}
	check(ns)
}

func (f *nameLifecycleFixture) assertNameMissing(name string) {
	f.t.Helper()

	ns := f.fetchNameState(hashName([]byte(name)))
	if ns != nil {
		f.t.Fatalf("name %q state = %+v, want missing", name, ns)
	}
}

func (f *nameLifecycleFixture) assertNameStateEquals(
	nameHash chainhash.Hash, want *nameState, label string) {

	f.t.Helper()

	got := f.fetchNameState(nameHash)
	if want == nil {
		if got != nil {
			f.t.Fatalf("after disconnect %s state = %+v, want missing",
				label, got)
		}
		return
	}

	if got == nil {
		f.t.Fatalf("after disconnect %s state missing, want %+v",
			label, want)
	}
	if !nameStatesEqual(got, want) {
		f.t.Fatalf("after disconnect %s state = %+v, want %+v",
			label, got, want)
	}
}

func prevOutputFromNameTx(tx *hnsutil.Tx, index uint32) namePrevOutput {
	txOut := tx.MsgTx().TxOut[index]
	return namePrevOutput{
		outpoint: wire.OutPoint{
			Hash:  *tx.Hash(),
			Index: index,
		},
		amount:   txOut.Value,
		address:  cloneAddress(txOut.Address),
		covenant: cloneCovenant(txOut.Covenant),
	}
}

func spentTxOutFromNamePrev(prevOutput namePrevOutput) SpentTxOut {
	return SpentTxOut{
		Amount:   prevOutput.amount,
		Address:  cloneAddress(prevOutput.address),
		Covenant: cloneCovenant(prevOutput.covenant),
		Height:   1,
	}
}

func registerCovenantWithData(name string, height uint32,
	data []byte) wire.Covenant {

	return wire.Covenant{
		Type: wire.CovenantRegister,
		Items: [][]byte{
			hashItem(name),
			u32Item(height),
			append([]byte(nil), data...),
			hashBytes(chainhash.Hash{}),
		},
	}
}

func updateCovenantWithData(name string, height uint32,
	data []byte) wire.Covenant {

	return wire.Covenant{
		Type: wire.CovenantUpdate,
		Items: [][]byte{
			hashItem(name),
			u32Item(height),
			append([]byte(nil), data...),
		},
	}
}

func finalizeCovenantWithName(name string, height, renewals uint32,
	renewalHash chainhash.Hash) wire.Covenant {

	return wire.Covenant{
		Type: wire.CovenantFinalize,
		Items: [][]byte{
			hashItem(name),
			u32Item(height),
			[]byte(name),
			{0},
			u32Item(0),
			u32Item(renewals),
			hashBytes(renewalHash),
		},
	}
}
