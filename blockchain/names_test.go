// Copyright (c) 2024-2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"bytes"
	"encoding/binary"
	"math"
	"strconv"
	"testing"

	"github.com/blinklabs-io/handshake-node/chaincfg"
	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/database"
	"github.com/blinklabs-io/handshake-node/hnsutil"
	"github.com/blinklabs-io/handshake-node/wire"
)

func TestNameStateEncodeRoundTrip(t *testing.T) {
	nameHash := hashName([]byte("handshake"))
	ns := newNameState(nameHash)
	ns.name = []byte("handshake")
	ns.height = 12
	ns.renewal = 34
	ns.owner = wire.OutPoint{Hash: chainhash.Hash{0x01, 0x02}, Index: 3}
	ns.value = 100
	ns.highest = 200
	ns.data = []byte{0x01, 0x02, 0x03}
	ns.transfer = 40
	ns.revoked = 50
	ns.claimed = 60
	ns.renewals = 7
	ns.registered = true
	ns.expired = true
	ns.weak = true

	encoded, err := ns.encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := decodeNameState(nameHash, encoded)
	if err != nil {
		t.Fatalf("decodeNameState: %v", err)
	}
	if !nameStatesEqual(ns, decoded) {
		t.Fatalf("round trip mismatch: got %+v, want %+v", decoded, ns)
	}
}

func TestVerifyName(t *testing.T) {
	valid := [][]byte{
		[]byte("abc"),
		[]byte("a-b"),
		[]byte("a_b"),
		[]byte("a0"),
	}
	for _, name := range valid {
		if !verifyName(name) {
			t.Fatalf("verifyName(%q) = false, want true", name)
		}
	}

	invalid := [][]byte{
		nil,
		[]byte("ABC"),
		[]byte("-abc"),
		[]byte("abc-"),
		[]byte("local"),
		[]byte("hello.world"),
	}
	for _, name := range invalid {
		if verifyName(name) {
			t.Fatalf("verifyName(%q) = true, want false", name)
		}
	}
}

func TestCheckCovenantSanityOpenRejectsHashMismatch(t *testing.T) {
	tx := wire.NewMsgTx(1)
	tx.AddTxIn(wire.NewTxIn(testOutPoint(1), math.MaxUint32, nil))
	tx.AddTxOut(wire.NewTxOut(1, wire.Address{}, wire.Covenant{
		Type: wire.CovenantOpen,
		Items: [][]byte{
			hashItem("wrong"),
			u32Item(0),
			[]byte("right"),
		},
	}))

	err := CheckTransactionSanity(hnsutil.NewTx(tx))
	if err == nil {
		t.Fatal("CheckTransactionSanity: expected error")
	}
	if ruleErr, ok := err.(RuleError); !ok ||
		ruleErr.ErrorCode != ErrInvalidCovenant {

		t.Fatalf("CheckTransactionSanity error = %T %v, want ErrInvalidCovenant",
			err, err)
	}
}

func TestCheckBlockNameLimitsDuplicateAcrossTransactions(t *testing.T) {
	block := &wire.MsgBlock{}
	for i := 0; i < 2; i++ {
		tx := wire.NewMsgTx(1)
		tx.AddTxIn(wire.NewTxIn(testOutPoint(uint32(i+1)),
			math.MaxUint32, nil))
		tx.AddTxOut(wire.NewTxOut(1, wire.Address{},
			openCovenant("dup")))
		block.AddTransaction(tx)
	}

	err := checkBlockNameLimits(hnsutil.NewBlock(block))
	if err == nil {
		t.Fatal("checkBlockNameLimits: expected error")
	}
	if ruleErr, ok := err.(RuleError); !ok ||
		ruleErr.ErrorCode != ErrInvalidCovenant {

		t.Fatalf("checkBlockNameLimits error = %T %v, want ErrInvalidCovenant",
			err, err)
	}
}

func TestCheckBlockNameLimitsAllowsDuplicateWithinTransaction(t *testing.T) {
	tx := wire.NewMsgTx(1)
	tx.AddTxIn(wire.NewTxIn(testOutPoint(1), math.MaxUint32, nil))
	tx.AddTxOut(wire.NewTxOut(1, wire.Address{}, openCovenant("dup")))
	tx.AddTxOut(wire.NewTxOut(1, wire.Address{}, openCovenant("dup")))

	block := &wire.MsgBlock{}
	block.AddTransaction(tx)

	err := checkBlockNameLimits(hnsutil.NewBlock(block))
	if err != nil {
		t.Fatalf("checkBlockNameLimits: %v", err)
	}
}

func TestCoinbaseAllowsLinkedClaimInputs(t *testing.T) {
	tx := wire.NewMsgTx(1)
	tx.AddTxIn(wire.NewTxIn(nullOutPoint(), math.MaxUint32,
		wire.TxWitness{[]byte{0x02, 0x01}}))
	tx.AddTxIn(wire.NewTxIn(nullOutPoint(), math.MaxUint32,
		wire.TxWitness{testOwnershipProof(t, "com", false,
			"not-a-claim-payload", 1, 2)}))
	tx.AddTxOut(wire.NewTxOut(1, wire.Address{}, wire.Covenant{}))
	tx.AddTxOut(wire.NewTxOut(1, wire.Address{}, claimCovenant("com")))

	if !IsCoinBaseTx(tx) {
		t.Fatal("IsCoinBaseTx: got false for linked claim coinbase")
	}
	if err := CheckTransactionSanity(hnsutil.NewTx(tx)); err != nil {
		t.Fatalf("CheckTransactionSanity linked claim coinbase: %v", err)
	}
}

func TestCoinbaseAllowsLinkedAirdropInput(t *testing.T) {
	tx := wire.NewMsgTx(1)
	addr := wire.Address{Version: 0, Hash: testAddressHash()}
	tx.AddTxIn(wire.NewTxIn(nullOutPoint(), math.MaxUint32,
		wire.TxWitness{[]byte{0x02, 0x01}}))
	tx.AddTxIn(wire.NewTxIn(nullOutPoint(), math.MaxUint32,
		wire.TxWitness{testAirdropProof(t, addr, 100, 1)}))
	tx.AddTxOut(wire.NewTxOut(1, wire.Address{}, wire.Covenant{}))
	tx.AddTxOut(wire.NewTxOut(99, addr, wire.Covenant{}))

	if err := CheckTransactionSanity(hnsutil.NewTx(tx)); err != nil {
		t.Fatalf("CheckTransactionSanity linked airdrop coinbase: %v", err)
	}
}

func TestCoinbaseClaimInputRequiresLinkedOutput(t *testing.T) {
	tx := wire.NewMsgTx(1)
	tx.AddTxIn(wire.NewTxIn(nullOutPoint(), math.MaxUint32,
		wire.TxWitness{[]byte{0x02, 0x01}}))
	tx.AddTxIn(wire.NewTxIn(nullOutPoint(), math.MaxUint32,
		wire.TxWitness{[]byte{0x01}}))
	tx.AddTxOut(wire.NewTxOut(1, wire.Address{}, wire.Covenant{}))

	err := CheckTransactionSanity(hnsutil.NewTx(tx))
	if err == nil {
		t.Fatal("CheckTransactionSanity: expected error")
	}
	if ruleErr, ok := err.(RuleError); !ok ||
		ruleErr.ErrorCode != ErrInvalidCovenant {

		t.Fatalf("CheckTransactionSanity error = %T %v, want ErrInvalidCovenant",
			err, err)
	}
}

func TestCoinbaseProofInputRequiresLinkedOutput(t *testing.T) {
	tx := wire.NewMsgTx(1)
	tx.AddTxIn(wire.NewTxIn(nullOutPoint(), math.MaxUint32,
		wire.TxWitness{[]byte{0x02, 0x01}}))
	tx.AddTxIn(wire.NewTxIn(nullOutPoint(), math.MaxUint32,
		wire.TxWitness{[]byte{0x00}}))
	tx.AddTxOut(wire.NewTxOut(1, wire.Address{}, wire.Covenant{}))

	err := CheckTransactionSanity(hnsutil.NewTx(tx))
	if err == nil {
		t.Fatal("CheckTransactionSanity: expected error")
	}
	if ruleErr, ok := err.(RuleError); !ok ||
		ruleErr.ErrorCode != ErrInvalidCovenant {

		t.Fatalf("CheckTransactionSanity error = %T %v, want ErrInvalidCovenant",
			err, err)
	}
}

func TestCheckTransactionNameLimitsRejectsTooManyOpens(t *testing.T) {
	tx := wire.NewMsgTx(1)
	tx.AddTxIn(wire.NewTxIn(testOutPoint(1), math.MaxUint32, nil))
	for i := 0; i < maxBlockNameOpens+1; i++ {
		name := "name" + strconv.Itoa(i)
		tx.AddTxOut(wire.NewTxOut(1, wire.Address{}, openCovenant(name)))
	}

	err := CheckTransactionSanity(hnsutil.NewTx(tx))
	if err == nil {
		t.Fatal("CheckTransactionSanity: expected error")
	}
	if ruleErr, ok := err.(RuleError); !ok ||
		ruleErr.ErrorCode != ErrInvalidCovenant {

		t.Fatalf("CheckTransactionSanity error = %T %v, want ErrInvalidCovenant",
			err, err)
	}
}

func TestVerifyCovenantSpendBidRevealBlind(t *testing.T) {
	nonce := chainhash.Hash{0x01, 0x02, 0x03}
	nameHash := hashName([]byte("bidtest"))
	blind := blindBid(7, nonce)

	prev := namePrevOutput{
		outpoint: *testOutPoint(1),
		amount:   10,
		covenant: wire.Covenant{
			Type: wire.CovenantBid,
			Items: [][]byte{
				hashBytes(nameHash),
				u32Item(5),
				[]byte("bidtest"),
				hashBytes(blind),
			},
		},
	}
	output := wire.NewTxOut(7, wire.Address{}, wire.Covenant{
		Type: wire.CovenantReveal,
		Items: [][]byte{
			hashBytes(nameHash),
			u32Item(5),
			hashBytes(nonce),
		},
	})

	if err := verifyCovenantSpend(prev, output); err != nil {
		t.Fatalf("verifyCovenantSpend valid reveal: %v", err)
	}

	output.Value = 8
	if err := verifyCovenantSpend(prev, output); err == nil {
		t.Fatal("verifyCovenantSpend: expected blind mismatch")
	}
}

func TestNameBlockViewOpenLifecycle(t *testing.T) {
	params := chaincfg.RegressionNetParams
	params.NameNoRollout = true
	chain := &BlockChain{chainParams: &params}
	view := &nameBlockView{
		chain:  chain,
		states: make(map[chainhash.Hash]*nameState),
		dirty:  make(map[chainhash.Hash]struct{}),
		seen:   make(map[chainhash.Hash]struct{}),
	}

	tx := wire.NewMsgTx(1)
	tx.AddTxIn(wire.NewTxIn(testOutPoint(1), math.MaxUint32, nil))
	tx.AddTxOut(wire.NewTxOut(1, wire.Address{}, openCovenant("opened")))
	prevOutputs := []namePrevOutput{{
		outpoint: *testOutPoint(1),
		amount:   1,
		covenant: wire.Covenant{},
	}}

	if err := view.applyTx(nil, hnsutil.NewTx(tx), 1, 0,
		prevOutputs); err != nil {

		t.Fatalf("applyTx OPEN: %v", err)
	}

	ns := view.states[hashName([]byte("opened"))]
	if ns == nil {
		t.Fatal("name state was not created")
	}
	if ns.height != 1 || string(ns.name) != "opened" {
		t.Fatalf("unexpected name state: %+v", ns)
	}
	if _, ok := view.dirty[ns.nameHash]; !ok {
		t.Fatal("name state was not marked dirty")
	}
}

func TestNameBlockViewRejectsUnlinkedRevealWithoutPanic(t *testing.T) {
	params := chaincfg.RegressionNetParams
	chain := &BlockChain{chainParams: &params}
	name := "opened"
	nameHash := hashName([]byte(name))
	ns := newNameState(nameHash)
	ns.set([]byte(name), 1)

	view := &nameBlockView{
		chain: chain,
		states: map[chainhash.Hash]*nameState{
			nameHash: ns,
		},
		dirty: make(map[chainhash.Hash]struct{}),
		seen:  make(map[chainhash.Hash]struct{}),
	}

	tx := wire.NewMsgTx(1)
	tx.AddTxIn(wire.NewTxIn(testOutPoint(1), math.MaxUint32, nil))
	tx.AddTxOut(wire.NewTxOut(1, wire.Address{}, wire.Covenant{}))
	tx.AddTxOut(wire.NewTxOut(1, wire.Address{}, revealCovenant(name, 1)))

	prevOutputs := []namePrevOutput{{
		outpoint: *testOutPoint(1),
		amount:   1,
		covenant: wire.Covenant{},
	}}
	height := ns.height + params.NameTreeInterval + 1 +
		params.NameBiddingPeriod

	err := view.applyTx(nil, hnsutil.NewTx(tx), height, 0, prevOutputs)
	if err == nil {
		t.Fatal("applyTx REVEAL: expected unlinked covenant error")
	}
	if _, ok := err.(RuleError); !ok {
		t.Fatalf("applyTx REVEAL error type = %T, want RuleError", err)
	}
}

func TestNameBlockViewBidAcceptanceWindow(t *testing.T) {
	params := chaincfg.RegressionNetParams
	chain := &BlockChain{chainParams: &params}
	name := "bidwindow"
	nameHash := hashName([]byte(name))
	ns := newNameState(nameHash)
	ns.set([]byte(name), 1)

	tx := wire.NewMsgTx(1)
	tx.AddTxIn(wire.NewTxIn(testOutPoint(1), math.MaxUint32, nil))
	tx.AddTxOut(wire.NewTxOut(1, wire.Address{}, bidCovenant(
		name, ns.height, chainhash.Hash{0x01},
	)))
	prevOutputs := []namePrevOutput{{
		outpoint: *testOutPoint(1),
		amount:   1,
		covenant: wire.Covenant{},
	}}

	openingHeight := ns.height + params.NameTreeInterval
	view := nameBlockViewWithStates(chain, ns)
	err := view.applyTx(nil, hnsutil.NewTx(tx), openingHeight, 0,
		prevOutputs)
	if err == nil {
		t.Fatal("applyTx BID before bidding period: expected error")
	}

	biddingHeight := ns.height + params.NameTreeInterval + 1
	view = nameBlockViewWithStates(chain, ns)
	err = view.applyTx(nil, hnsutil.NewTx(tx), biddingHeight, 0,
		prevOutputs)
	if err != nil {
		t.Fatalf("applyTx BID during bidding period: %v", err)
	}

	revealHeight := biddingHeight + params.NameBiddingPeriod
	view = nameBlockViewWithStates(chain, ns)
	err = view.applyTx(nil, hnsutil.NewTx(tx), revealHeight, 0,
		prevOutputs)
	if err == nil {
		t.Fatal("applyTx BID during reveal period: expected error")
	}
}

func TestNameBlockViewRevealAcceptanceWindowAndBlind(t *testing.T) {
	params := chaincfg.RegressionNetParams
	chain := &BlockChain{chainParams: &params}
	name := "revealwindow"
	nameHash := hashName([]byte(name))
	ns := newNameState(nameHash)
	ns.set([]byte(name), 1)

	nonce := chainhash.Hash{0x02, 0x03}
	value := int64(7)
	blind := blindBid(value, nonce)
	prevOut := *testOutPoint(2)
	prevCovenant := bidCovenant(name, ns.height, blind)
	prevOutputs := []namePrevOutput{{
		outpoint: prevOut,
		amount:   10,
		covenant: prevCovenant,
	}}
	tx := wire.NewMsgTx(1)
	tx.AddTxIn(wire.NewTxIn(&prevOut, math.MaxUint32, nil))
	tx.AddTxOut(wire.NewTxOut(value, wire.Address{},
		revealCovenantWithNonce(name, ns.height, nonce)))

	biddingHeight := ns.height + params.NameTreeInterval + 1
	view := nameBlockViewWithStates(chain, ns)
	err := view.applyTx(nil, hnsutil.NewTx(tx), biddingHeight, 0,
		prevOutputs)
	if err == nil {
		t.Fatal("applyTx REVEAL before reveal period: expected error")
	}

	revealHeight := biddingHeight + params.NameBiddingPeriod
	view = nameBlockViewWithStates(chain, ns)
	err = view.applyTx(nil, hnsutil.NewTx(tx), revealHeight, 0,
		prevOutputs)
	if err != nil {
		t.Fatalf("applyTx REVEAL during reveal period: %v", err)
	}

	badTx := tx.Copy()
	badTx.TxOut[0].Value = value + 1
	view = nameBlockViewWithStates(chain, ns)
	err = view.applyTx(nil, hnsutil.NewTx(badTx), revealHeight, 0,
		prevOutputs)
	if err == nil {
		t.Fatal("applyTx REVEAL with wrong blind value: expected error")
	}
}

func TestNameBlockViewUpdatePreservesDataOnEmptyResource(t *testing.T) {
	name := "clearme"
	nameHash := hashName([]byte(name))
	ns := newNameState(nameHash)
	ns.set([]byte(name), 1)
	owner := *testOutPoint(8)
	ns.owner = owner
	ns.data = []byte("old-resource")

	tx := wire.NewMsgTx(1)
	tx.AddTxOut(wire.NewTxOut(1, wire.Address{}, wire.Covenant{}))
	covenant := wire.Covenant{
		Type: wire.CovenantUpdate,
		Items: [][]byte{
			hashItem(name),
			u32Item(ns.height),
			nil,
		},
	}

	view := &nameBlockView{}
	prevOutputs := []namePrevOutput{{outpoint: owner}}
	err := view.applyUpdate(ns, covenant, hnsutil.NewTx(tx), 0, 10,
		nameStateClosed, prevOutputs)
	if err != nil {
		t.Fatalf("applyUpdate: %v", err)
	}
	if got, want := string(ns.data), "old-resource"; got != want {
		t.Fatalf("UPDATE data = %q, want %q", got, want)
	}
}

func TestNameBlockViewOwnerOperationsRequireCurrentOwner(t *testing.T) {
	params := chaincfg.RegressionNetParams
	chain := &BlockChain{chainParams: &params}
	name := "ownerops"
	nameHash := hashName([]byte(name))
	height := uint32(30)
	currentOwner := *testOutPoint(10)
	staleOwner := *testOutPoint(11)
	ownerAddr := wire.Address{
		Version: 0,
		Hash:    bytes.Repeat([]byte{0x01}, 20),
	}

	baseState := func() *nameState {
		ns := newNameState(nameHash)
		ns.set([]byte(name), 1)
		ns.owner = currentOwner
		ns.value = 100
		ns.highest = 100
		ns.registered = true
		ns.renewal = 1
		return ns
	}

	ownerPrev := func(outpoint wire.OutPoint,
		covenant wire.Covenant) []namePrevOutput {

		return []namePrevOutput{{
			outpoint: outpoint,
			amount:   100,
			address:  ownerAddr,
			covenant: covenant,
		}}
	}

	tests := []struct {
		name      string
		state     func() *nameState
		prev      wire.Covenant
		covenant  wire.Covenant
		outAddr   wire.Address
		shouldSet func(*nameState)
	}{
		{
			name:     "UPDATE",
			state:    baseState,
			prev:     registerCovenant(name, 1),
			covenant: updateCovenant(name, 1),
			outAddr:  ownerAddr,
		},
		{
			name:     "RENEW",
			state:    baseState,
			prev:     registerCovenant(name, 1),
			covenant: renewCovenant(name, 1, chainhash.Hash{}),
			outAddr:  ownerAddr,
		},
		{
			name:     "TRANSFER",
			state:    baseState,
			prev:     registerCovenant(name, 1),
			covenant: transferCovenant(name, 1, ownerAddr),
			outAddr:  ownerAddr,
		},
		{
			name:     "REVOKE",
			state:    baseState,
			prev:     registerCovenant(name, 1),
			covenant: revokeCovenant(name, 1),
			outAddr:  ownerAddr,
		},
		{
			name: "FINALIZE",
			state: func() *nameState {
				ns := baseState()
				ns.transfer = height - params.NameTransferLockup
				return ns
			},
			prev:     transferCovenant(name, 1, ownerAddr),
			covenant: finalizeCovenant(name, 1, chainhash.Hash{}),
			outAddr:  ownerAddr,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tx := wire.NewMsgTx(1)
			tx.AddTxIn(wire.NewTxIn(&staleOwner,
				wire.MaxTxInSequenceNum, nil))
			tx.AddTxOut(wire.NewTxOut(100, test.outAddr,
				test.covenant))

			view := nameBlockViewWithStates(chain, test.state())
			err := view.applyTx(nil, hnsutil.NewTx(tx), height, 0,
				ownerPrev(staleOwner, test.prev))
			if err == nil {
				t.Fatalf("%s with stale owner unexpectedly succeeded",
					test.name)
			}

			tx.TxIn[0].PreviousOutPoint = currentOwner
			view = nameBlockViewWithStates(chain, test.state())
			err = view.applyTx(nil, hnsutil.NewTx(tx), height, 0,
				ownerPrev(currentOwner, test.prev))
			if err != nil {
				t.Fatalf("%s with current owner: %v", test.name,
					err)
			}
		})
	}
}

func TestCheckTransactionNamesRejectsMissingState(t *testing.T) {
	chain := setupNameStateQueryChain(t, "checktxnamesmissing")
	name := "missingstate"
	covenant := wire.Covenant{
		Type: wire.CovenantUpdate,
		Items: [][]byte{
			hashItem(name),
			u32Item(1),
			nil,
		},
	}

	prevTx := wire.NewMsgTx(1)
	prevTx.AddTxIn(wire.NewTxIn(testOutPoint(1),
		wire.MaxTxInSequenceNum, nil))
	prevTx.AddTxOut(wire.NewTxOut(1, wire.Address{}, covenant))
	prev := hnsutil.NewTx(prevTx)

	prevOut := wire.OutPoint{Hash: *prev.Hash(), Index: 0}
	tx := wire.NewMsgTx(1)
	tx.AddTxIn(wire.NewTxIn(&prevOut, wire.MaxTxInSequenceNum, nil))
	tx.AddTxOut(wire.NewTxOut(1, wire.Address{}, covenant))

	view := NewUtxoViewpoint()
	view.AddTxOut(prev, 0, 1)

	err := chain.CheckTransactionNames(hnsutil.NewTx(tx), 2, 0, view)
	if err == nil {
		t.Fatal("CheckTransactionNames: expected missing state error")
	}
	if ruleErr, ok := err.(RuleError); !ok ||
		ruleErr.ErrorCode != ErrInvalidCovenant {

		t.Fatalf("CheckTransactionNames error = %T %v, want ErrInvalidCovenant",
			err, err)
	}
}

func TestNameValidationViewRollsBackFailedTransaction(t *testing.T) {
	chain := setupNameStateQueryChain(t, "namevalidationrollback")
	name := "rollback"
	height := int32(30)
	ownerAddr := wire.Address{
		Version: 0,
		Hash:    bytes.Repeat([]byte{0x01}, 20),
	}
	ownerTx := nameOwnerTx(100, ownerAddr, registerCovenant(name, 1))
	ownerOut := wire.OutPoint{Hash: *ownerTx.Hash(), Index: 0}
	storeNameStateForQuery(t, chain, closedNameState(name, ownerOut, 100))

	utxoView := NewUtxoViewpoint()
	utxoView.AddTxOut(ownerTx, 0, height-1)

	badTx := wire.NewMsgTx(1)
	badTx.AddTxIn(wire.NewTxIn(&ownerOut, wire.MaxTxInSequenceNum, nil))
	badTx.AddTxOut(wire.NewTxOut(100, ownerAddr,
		updateCovenant(name, 1)))
	badTx.AddTxOut(wire.NewTxOut(100, ownerAddr,
		updateCovenant(name, 1)))

	nameView, err := chain.NewNameValidationView()
	if err != nil {
		t.Fatalf("NewNameValidationView: %v", err)
	}
	err = nameView.ApplyTransaction(hnsutil.NewTx(badTx), height, 0,
		utxoView)
	if err == nil {
		t.Fatal("ApplyTransaction bad tx: expected error")
	}

	validUpdate := nameSpendTx(ownerOut, 100, ownerAddr,
		updateCovenant(name, 1))
	err = nameView.ApplyTransaction(validUpdate, height, 0, utxoView)
	if err != nil {
		t.Fatalf("ApplyTransaction after rollback: %v", err)
	}
}

func TestNameValidationViewSequencesOwnerOperations(t *testing.T) {
	chain := setupNameStateQueryChain(t, "namevalidationsequence")
	name := "sequence"
	height := int32(30)
	ownerAddr := wire.Address{
		Version: 0,
		Hash:    bytes.Repeat([]byte{0x02}, 20),
	}
	transferAddr := wire.Address{
		Version: 0,
		Hash:    bytes.Repeat([]byte{0x03}, 20),
	}
	ownerTx := nameOwnerTx(100, ownerAddr, registerCovenant(name, 1))
	ownerOut := wire.OutPoint{Hash: *ownerTx.Hash(), Index: 0}
	storeNameStateForQuery(t, chain, closedNameState(name, ownerOut, 100))

	utxoView := NewUtxoViewpoint()
	utxoView.AddTxOut(ownerTx, 0, height-1)

	update := nameSpendTx(ownerOut, 100, ownerAddr,
		updateCovenant(name, 1))
	updateOut := wire.OutPoint{Hash: *update.Hash(), Index: 0}
	transfer := nameSpendTx(updateOut, 100, ownerAddr,
		transferCovenant(name, 1, transferAddr))

	nameView, err := chain.NewNameValidationView()
	if err != nil {
		t.Fatalf("NewNameValidationView: %v", err)
	}
	err = nameView.ApplyTransaction(update, height, 0, utxoView)
	if err != nil {
		t.Fatalf("ApplyTransaction UPDATE: %v", err)
	}
	if err := utxoView.connectTransaction(update, height, nil); err != nil {
		t.Fatalf("connectTransaction UPDATE: %v", err)
	}

	err = chain.CheckTransactionNames(transfer, height, 0, utxoView)
	if err == nil {
		t.Fatal("CheckTransactionNames TRANSFER: expected stale owner error")
	}
	if ruleErr, ok := err.(RuleError); !ok ||
		ruleErr.ErrorCode != ErrInvalidCovenant {

		t.Fatalf("CheckTransactionNames error = %T %v, want ErrInvalidCovenant",
			err, err)
	}

	err = nameView.ApplyTransaction(transfer, height, 0, utxoView)
	if err != nil {
		t.Fatalf("ApplyTransaction TRANSFER: %v", err)
	}
}

func TestNameBlockViewEmptyResourcePreservesData(t *testing.T) {
	params := chaincfg.RegressionNetParams
	name := "emptyresource"
	nameHash := hashName([]byte(name))
	owner := *testOutPoint(7)
	ns := newNameState(nameHash)
	ns.set([]byte(name), 1)
	ns.owner = owner
	ns.value = 1
	ns.highest = 1
	ns.data = []byte("old-resource")

	registerTx := wire.NewMsgTx(1)
	registerCovenant := wire.Covenant{
		Type: wire.CovenantRegister,
		Items: [][]byte{
			hashItem(name),
			u32Item(ns.height),
			nil,
			hashBytes(chainhash.Hash{}),
		},
	}
	registerTx.AddTxOut(wire.NewTxOut(ns.value, wire.Address{},
		registerCovenant))
	registerTxOut := registerTx.TxOut[0]
	prevOutputs := []namePrevOutput{{
		outpoint: owner,
		amount:   ns.value,
	}}

	view := &nameBlockView{
		chain: &BlockChain{chainParams: &params},
	}
	err := view.applyRegister(nil, ns, registerCovenant,
		hnsutil.NewTx(registerTx), 0, registerTxOut, 1,
		nameStateClosed, prevOutputs)
	if err != nil {
		t.Fatalf("applyRegister: %v", err)
	}
	if got, want := string(ns.data), "old-resource"; got != want {
		t.Fatalf("REGISTER data = %q, want %q", got, want)
	}

	updateTx := wire.NewMsgTx(1)
	updateCovenant := wire.Covenant{
		Type: wire.CovenantUpdate,
		Items: [][]byte{
			hashItem(name),
			u32Item(ns.height),
			nil,
		},
	}
	updateTx.AddTxOut(wire.NewTxOut(ns.value, wire.Address{},
		updateCovenant))
	updateOut := wire.OutPoint{Hash: *hnsutil.NewTx(registerTx).Hash(),
		Index: 0}
	prevOutputs = []namePrevOutput{{
		outpoint: updateOut,
		amount:   ns.value,
	}}
	ns.owner = updateOut

	err = view.applyUpdate(ns, updateCovenant, hnsutil.NewTx(updateTx), 0,
		2, nameStateClosed, prevOutputs)
	if err != nil {
		t.Fatalf("applyUpdate: %v", err)
	}
	if got, want := string(ns.data), "old-resource"; got != want {
		t.Fatalf("UPDATE data = %q, want %q", got, want)
	}
}

func TestNameRootReorgPreflightRejectsMismatchedRoot(t *testing.T) {
	params := chaincfg.RegressionNetParams
	chain, teardown, err := chainSetup("namerootreorgpreflight", &params)
	if err != nil {
		t.Fatalf("chainSetup: %v", err)
	}
	defer teardown()

	tip := chain.bestChain.Tip()
	block := hnsutil.NewBlock(&wire.MsgBlock{
		Header: wire.BlockHeader{
			PrevBlock: tip.hash,
			NameRoot:  chainhash.Hash{0x01},
		},
	})

	err = chain.db.View(func(dbTx database.Tx) error {
		nameReorg, err := newNameReorgView(dbTx, chain)
		if err != nil {
			return err
		}
		_, err = nameReorg.checkConnectBlock(block)
		return err
	})
	if err == nil {
		t.Fatal("checkConnectBlock: expected ErrBadNameRoot")
	}
	if ruleErr, ok := err.(RuleError); !ok ||
		ruleErr.ErrorCode != ErrBadNameRoot {

		t.Fatalf("checkConnectBlock error = %T %v, want ErrBadNameRoot",
			err, err)
	}
	if chain.bestChain.Tip() != tip {
		t.Fatal("preflight mutated the best chain tip")
	}

	var root chainhash.Hash
	err = chain.db.View(func(dbTx database.Tx) error {
		var err error
		root, err = dbFetchNameRoot(dbTx)
		return err
	})
	if err != nil {
		t.Fatalf("dbFetchNameRoot: %v", err)
	}
	if root != (chainhash.Hash{}) {
		t.Fatalf("preflight mutated name root to %v", root)
	}
}

func testOutPoint(tag uint32) *wire.OutPoint {
	hash := chainhash.Hash{byte(tag)}
	return wire.NewOutPoint(&hash, tag)
}

func openCovenant(name string) wire.Covenant {
	return wire.Covenant{
		Type: wire.CovenantOpen,
		Items: [][]byte{
			hashItem(name),
			u32Item(0),
			[]byte(name),
		},
	}
}

func bidCovenant(name string, height uint32, blind chainhash.Hash) wire.Covenant {
	return wire.Covenant{
		Type: wire.CovenantBid,
		Items: [][]byte{
			hashItem(name),
			u32Item(height),
			[]byte(name),
			hashBytes(blind),
		},
	}
}

func registerCovenant(name string, height uint32) wire.Covenant {
	return wire.Covenant{
		Type: wire.CovenantRegister,
		Items: [][]byte{
			hashItem(name),
			u32Item(height),
			nil,
			hashBytes(chainhash.Hash{}),
		},
	}
}

func updateCovenant(name string, height uint32) wire.Covenant {
	return wire.Covenant{
		Type: wire.CovenantUpdate,
		Items: [][]byte{
			hashItem(name),
			u32Item(height),
			nil,
		},
	}
}

func renewCovenant(name string, height uint32,
	renewalHash chainhash.Hash) wire.Covenant {

	return wire.Covenant{
		Type: wire.CovenantRenew,
		Items: [][]byte{
			hashItem(name),
			u32Item(height),
			hashBytes(renewalHash),
		},
	}
}

func transferCovenant(name string, height uint32,
	addr wire.Address) wire.Covenant {

	return wire.Covenant{
		Type: wire.CovenantTransfer,
		Items: [][]byte{
			hashItem(name),
			u32Item(height),
			{addr.Version},
			append([]byte(nil), addr.Hash...),
		},
	}
}

func finalizeCovenant(name string, height uint32,
	renewalHash chainhash.Hash) wire.Covenant {

	return wire.Covenant{
		Type: wire.CovenantFinalize,
		Items: [][]byte{
			hashItem(name),
			u32Item(height),
			nil,
			{0},
			u32Item(0),
			u32Item(0),
			hashBytes(renewalHash),
		},
	}
}

func revokeCovenant(name string, height uint32) wire.Covenant {
	return wire.Covenant{
		Type: wire.CovenantRevoke,
		Items: [][]byte{
			hashItem(name),
			u32Item(height),
		},
	}
}

func closedNameState(name string, owner wire.OutPoint, value int64) *nameState {
	ns := newNameState(HashName([]byte(name)))
	ns.set([]byte(name), 1)
	ns.registered = true
	ns.owner = owner
	ns.value = value
	ns.highest = value
	ns.renewal = 1
	return ns
}

func nameOwnerTx(value int64, addr wire.Address,
	covenant wire.Covenant) *hnsutil.Tx {

	tx := wire.NewMsgTx(1)
	tx.AddTxIn(wire.NewTxIn(testOutPoint(250),
		wire.MaxTxInSequenceNum, nil))
	tx.AddTxOut(wire.NewTxOut(value, addr, covenant))
	return hnsutil.NewTx(tx)
}

func nameSpendTx(prevOut wire.OutPoint, value int64, addr wire.Address,
	covenant wire.Covenant) *hnsutil.Tx {

	tx := wire.NewMsgTx(1)
	tx.AddTxIn(wire.NewTxIn(&prevOut, wire.MaxTxInSequenceNum, nil))
	tx.AddTxOut(wire.NewTxOut(value, addr, covenant))
	return hnsutil.NewTx(tx)
}

func revealCovenant(name string, height uint32) wire.Covenant {
	return revealCovenantWithNonce(name, height, chainhash.Hash{0x01})
}

func revealCovenantWithNonce(name string, height uint32,
	nonce chainhash.Hash) wire.Covenant {

	return wire.Covenant{
		Type: wire.CovenantReveal,
		Items: [][]byte{
			hashItem(name),
			u32Item(height),
			hashBytes(nonce),
		},
	}
}

func claimCovenant(name string) wire.Covenant {
	return claimCovenantAt(name, 0, chainhash.Hash{0x01}, 1, false)
}

func claimCovenantAt(name string, height uint32, commitHash chainhash.Hash,
	commitHeight uint32, weak bool) wire.Covenant {

	flags := byte(0)
	if weak {
		flags = 1
	}
	return wire.Covenant{
		Type: wire.CovenantClaim,
		Items: [][]byte{
			hashItem(name),
			u32Item(height),
			[]byte(name),
			{flags},
			hashBytes(commitHash),
			u32Item(commitHeight),
		},
	}
}

func hashItem(name string) []byte {
	return hashBytes(hashName([]byte(name)))
}

func hashBytes(hash chainhash.Hash) []byte {
	bytes := make([]byte, chainhash.HashSize)
	copy(bytes, hash[:])
	return bytes
}

func u32Item(value uint32) []byte {
	var item [4]byte
	binary.LittleEndian.PutUint32(item[:], value)
	return item[:]
}

func nameBlockViewWithStates(chain *BlockChain,
	states ...*nameState) *nameBlockView {

	stateMap := make(map[chainhash.Hash]*nameState, len(states))
	for _, ns := range states {
		stateMap[ns.nameHash] = ns.clone()
	}

	return &nameBlockView{
		chain:  chain,
		states: stateMap,
		dirty:  make(map[chainhash.Hash]struct{}),
		seen:   make(map[chainhash.Hash]struct{}),
	}
}

func nullOutPoint() *wire.OutPoint {
	return wire.NewOutPoint(&zeroHash, math.MaxUint32)
}
