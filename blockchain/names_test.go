// Copyright (c) 2024-2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"encoding/binary"
	"math"
	"strconv"
	"testing"

	"github.com/blinklabs-io/handshake-node/chaincfg"
	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
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

func TestCheckBlockNameLimitsDuplicateWithinTransaction(t *testing.T) {
	tx := wire.NewMsgTx(1)
	tx.AddTxIn(wire.NewTxIn(testOutPoint(1), math.MaxUint32, nil))
	tx.AddTxOut(wire.NewTxOut(1, wire.Address{}, openCovenant("dup")))
	tx.AddTxOut(wire.NewTxOut(1, wire.Address{}, openCovenant("dup")))

	block := &wire.MsgBlock{}
	block.AddTransaction(tx)

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

func TestNameBlockViewUpdateClearsData(t *testing.T) {
	name := "clearme"
	nameHash := hashName([]byte(name))
	ns := newNameState(nameHash)
	ns.set([]byte(name), 1)
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
	err := view.applyUpdate(ns, covenant, hnsutil.NewTx(tx), 0, 10,
		nameStateClosed)
	if err != nil {
		t.Fatalf("applyUpdate: %v", err)
	}
	if len(ns.data) != 0 {
		t.Fatalf("UPDATE preserved data %x, want empty", ns.data)
	}
}

func TestNameBlockViewRegisterClearsData(t *testing.T) {
	params := chaincfg.RegressionNetParams
	name := "registerclear"
	nameHash := hashName([]byte(name))
	owner := *testOutPoint(7)
	ns := newNameState(nameHash)
	ns.set([]byte(name), 1)
	ns.owner = owner
	ns.value = 1
	ns.highest = 1
	ns.data = []byte("old-resource")

	tx := wire.NewMsgTx(1)
	covenant := wire.Covenant{
		Type: wire.CovenantRegister,
		Items: [][]byte{
			hashItem(name),
			u32Item(ns.height),
			nil,
			hashBytes(chainhash.Hash{}),
		},
	}
	tx.AddTxOut(wire.NewTxOut(ns.value, wire.Address{}, covenant))
	txOut := tx.TxOut[0]
	prevOutputs := []namePrevOutput{{
		outpoint: owner,
		amount:   ns.value,
	}}

	view := &nameBlockView{
		chain: &BlockChain{chainParams: &params},
	}
	err := view.applyRegister(nil, ns, covenant, hnsutil.NewTx(tx), 0,
		txOut, 1, nameStateClosed, prevOutputs)
	if err != nil {
		t.Fatalf("applyRegister: %v", err)
	}
	if len(ns.data) != 0 {
		t.Fatalf("REGISTER preserved data %x, want empty", ns.data)
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

func revealCovenant(name string, height uint32) wire.Covenant {
	return wire.Covenant{
		Type: wire.CovenantReveal,
		Items: [][]byte{
			hashItem(name),
			u32Item(height),
			hashBytes(chainhash.Hash{0x01}),
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

func nullOutPoint() *wire.OutPoint {
	return wire.NewOutPoint(&zeroHash, math.MaxUint32)
}
