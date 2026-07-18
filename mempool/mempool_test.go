// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mempool

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blinklabs-io/handshake-node/blockchain"
	"github.com/blinklabs-io/handshake-node/chaincfg"
	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/hnsutil"
	"github.com/blinklabs-io/handshake-node/mining"
	"github.com/blinklabs-io/handshake-node/txscript"
	"github.com/blinklabs-io/handshake-node/wire"
	"github.com/btcsuite/btcd/btcec/v2"
)

// fakeChain is used by the pool harness to provide generated test utxos and
// a current faked chain height to the pool callbacks.  This, in turn, allows
// transactions to appear as though they are spending completely valid utxos.
type fakeChain struct {
	sync.RWMutex
	utxos          *blockchain.UtxoViewpoint
	currentHeight  int32
	medianTimePast time.Time
}

// FetchUtxoView loads utxo details about the inputs referenced by the passed
// transaction from the point of view of the fake chain.  It also attempts to
// fetch the utxos for the outputs of the transaction itself so the returned
// view can be examined for duplicate transactions.
//
// This function is safe for concurrent access however the returned view is NOT.
func (s *fakeChain) FetchUtxoView(tx *hnsutil.Tx) (*blockchain.UtxoViewpoint, error) {
	s.RLock()
	defer s.RUnlock()

	// All entries are cloned to ensure modifications to the returned view
	// do not affect the fake chain's view.

	// Add an entry for the tx itself to the new view.
	viewpoint := blockchain.NewUtxoViewpoint()
	prevOut := wire.OutPoint{Hash: *tx.Hash()}
	for txOutIdx := range tx.MsgTx().TxOut {
		prevOut.Index = uint32(txOutIdx)
		entry := s.utxos.LookupEntry(prevOut)
		if entry != nil {
			viewpoint.Entries()[prevOut] = entry.Clone()
		} else {
			viewpoint.Entries()[prevOut] = nil
		}
	}

	// Add entries for all of the inputs to the tx to the new view.
	for _, txIn := range tx.MsgTx().TxIn {
		entry := s.utxos.LookupEntry(txIn.PreviousOutPoint)
		if entry != nil {
			viewpoint.Entries()[txIn.PreviousOutPoint] = entry.Clone()
		} else {
			viewpoint.Entries()[txIn.PreviousOutPoint] = nil
		}
	}

	return viewpoint, nil
}

// BestHeight returns the current height associated with the fake chain
// instance.
func (s *fakeChain) BestHeight() int32 {
	s.RLock()
	height := s.currentHeight
	s.RUnlock()
	return height
}

// SetHeight sets the current height associated with the fake chain instance.
func (s *fakeChain) SetHeight(height int32) {
	s.Lock()
	s.currentHeight = height
	s.Unlock()
}

// MedianTimePast returns the current median time past associated with the fake
// chain instance.
func (s *fakeChain) MedianTimePast() time.Time {
	s.RLock()
	mtp := s.medianTimePast
	s.RUnlock()
	return mtp
}

// SetMedianTimePast sets the current median time past associated with the fake
// chain instance.
func (s *fakeChain) SetMedianTimePast(mtp time.Time) {
	s.Lock()
	s.medianTimePast = mtp
	s.Unlock()
}

// CalcSequenceLock returns the current sequence lock for the passed
// transaction associated with the fake chain instance.
func (s *fakeChain) CalcSequenceLock(tx *hnsutil.Tx,
	view *blockchain.UtxoViewpoint) (*blockchain.SequenceLock, error) {

	return &blockchain.SequenceLock{
		Seconds:     -1,
		BlockHeight: -1,
	}, nil
}

// spendableOutput is a convenience type that houses a particular utxo and the
// amount associated with it.
type spendableOutput struct {
	outPoint wire.OutPoint
	amount   hnsutil.Amount
}

// txOutToSpendableOut returns a spendable output given a transaction and index
// of the output to use.  This is useful as a convenience when creating test
// transactions.
func txOutToSpendableOut(tx *hnsutil.Tx, outputNum uint32) spendableOutput {
	return spendableOutput{
		outPoint: wire.OutPoint{Hash: *tx.Hash(), Index: outputNum},
		amount:   hnsutil.Amount(tx.MsgTx().TxOut[outputNum].Value),
	}
}

// poolHarness provides a harness that includes functionality for creating and
// signing transactions as well as a fake chain that provides utxos for use in
// generating valid transactions.
type poolHarness struct {
	// signKey is the signing key used for creating transactions throughout
	// the tests.
	//
	// payAddr is the p2sh address for the signing key and is used for the
	// payment address throughout the tests.
	signKey     *btcec.PrivateKey
	payAddr     hnsutil.Address
	payScript   []byte
	payWireAddr wire.Address
	chainParams *chaincfg.Params

	chain  *fakeChain
	txPool *TxPool
}

// CreateCoinbaseTx returns a coinbase transaction with the requested number of
// outputs paying an appropriate subsidy based on the passed block height to the
// address associated with the harness.  It automatically uses a standard
// signature script that starts with the block height that is required by
// version 2 blocks.
func (p *poolHarness) CreateCoinbaseTx(blockHeight int32, numOutputs uint32) (*hnsutil.Tx, error) {
	// Create standard coinbase script.
	extraNonce := int64(0)
	coinbaseScript, err := txscript.NewScriptBuilder().
		AddInt64(int64(blockHeight)).AddInt64(extraNonce).Script()
	if err != nil {
		return nil, err
	}

	tx := wire.NewMsgTx(wire.TxVersion)
	tx.LockTime = uint32(blockHeight)
	tx.AddTxIn(&wire.TxIn{
		// Coinbase transactions have no inputs, so previous outpoint is
		// zero hash and max index.
		PreviousOutPoint: *wire.NewOutPoint(&chainhash.Hash{},
			wire.MaxPrevOutIndex),
		Sequence: wire.MaxTxInSequenceNum,
		Witness:  [][]byte{coinbaseScript},
	})
	totalInput := blockchain.CalcBlockSubsidy(blockHeight, p.chainParams)
	amountPerOutput := totalInput / int64(numOutputs)
	remainder := totalInput - amountPerOutput*int64(numOutputs)
	for i := uint32(0); i < numOutputs; i++ {
		// Ensure the final output accounts for any remainder that might
		// be left from splitting the input amount.
		amount := amountPerOutput
		if i == numOutputs-1 {
			amount = amountPerOutput + remainder
		}
		tx.AddTxOut(&wire.TxOut{
			Address: p.payWireAddr,
			Value:   amount,
		})
	}

	return hnsutil.NewTx(tx), nil
}

// CreateSignedTx creates a new signed transaction that consumes the provided
// inputs and generates the provided number of outputs by evenly splitting the
// total input amount.  All outputs will be to the payment script associated
// with the harness and all inputs are assumed to do the same.
func (p *poolHarness) CreateSignedTx(inputs []spendableOutput,
	numOutputs uint32, fee hnsutil.Amount,
	signalsReplacement bool) (*hnsutil.Tx, error) {

	// Calculate the total input amount and split it amongst the requested
	// number of outputs.
	var totalInput hnsutil.Amount
	for _, input := range inputs {
		totalInput += input.amount
	}
	totalInput -= fee
	amountPerOutput := int64(totalInput) / int64(numOutputs)
	remainder := int64(totalInput) - amountPerOutput*int64(numOutputs)

	tx := wire.NewMsgTx(wire.TxVersion)
	sequence := wire.MaxTxInSequenceNum
	if signalsReplacement {
		sequence = MaxRBFSequence
	}
	for _, input := range inputs {
		tx.AddTxIn(&wire.TxIn{
			PreviousOutPoint: input.outPoint,
			Sequence:         sequence,
		})
	}
	for i := uint32(0); i < numOutputs; i++ {
		// Ensure the final output accounts for any remainder that might
		// be left from splitting the input amount.
		amount := amountPerOutput
		if i == numOutputs-1 {
			amount = amountPerOutput + remainder
		}
		tx.AddTxOut(&wire.TxOut{
			Address: p.payWireAddr,
			Value:   amount,
		})
	}

	// Sign the new transaction using witness signing (BIP-143 sighash).
	for i := range tx.TxIn {
		// Use the input amount directly from the caller-provided spendable
		// outputs.  Looking it up via p.chain.utxos.LookupEntry would panic
		// with a nil pointer for unconfirmed or orphan prevouts that are not
		// yet in the UTXO set.
		inputAmt := int64(inputs[i].amount)

		sigHashes := txscript.NewTxSigHashes(tx,
			txscript.NewCannedPrevOutputFetcher(
				p.payWireAddr, inputAmt,
			),
		)
		witness, err := txscript.WitnessSignature(tx, sigHashes,
			i, inputAmt, p.payScript, txscript.SigHashAll,
			p.signKey, true)
		if err != nil {
			return nil, err
		}
		tx.TxIn[i].Witness = witness
	}

	return hnsutil.NewTx(tx), nil
}

func (p *poolHarness) CreateSignedTxWithCovenant(input spendableOutput,
	fee hnsutil.Amount, covenant wire.Covenant,
	signalsReplacement bool) (*hnsutil.Tx, error) {

	tx := wire.NewMsgTx(wire.TxVersion)
	sequence := wire.MaxTxInSequenceNum
	if signalsReplacement {
		sequence = MaxRBFSequence
	}
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: input.outPoint,
		Sequence:         sequence,
	})
	tx.AddTxOut(&wire.TxOut{
		Address:  p.payWireAddr,
		Value:    int64(input.amount - fee),
		Covenant: covenant,
	})

	sigHashes := txscript.NewTxSigHashes(tx,
		txscript.NewCannedPrevOutputFetcher(
			p.payWireAddr, int64(input.amount),
		),
	)
	witness, err := txscript.WitnessSignature(tx, sigHashes, 0,
		int64(input.amount), p.payScript, txscript.SigHashAll,
		p.signKey, true)
	if err != nil {
		return nil, err
	}
	tx.TxIn[0].Witness = witness

	return hnsutil.NewTx(tx), nil
}

// CreateTxChain creates a chain of zero-fee transactions (each subsequent
// transaction spends the entire amount from the previous one) with the first
// one spending the provided outpoint.  Each transaction spends the entire
// amount of the previous one and as such does not include any fees.
func (p *poolHarness) CreateTxChain(firstOutput spendableOutput, numTxns uint32) ([]*hnsutil.Tx, error) {
	txChain := make([]*hnsutil.Tx, 0, numTxns)
	prevOutPoint := firstOutput.outPoint
	spendableAmount := firstOutput.amount
	for i := uint32(0); i < numTxns; i++ {
		// Create the transaction using the previous transaction output
		// and paying the full amount to the payment address associated
		// with the harness.
		tx := wire.NewMsgTx(wire.TxVersion)
		tx.AddTxIn(&wire.TxIn{
			PreviousOutPoint: prevOutPoint,
			Sequence:         wire.MaxTxInSequenceNum,
		})
		tx.AddTxOut(&wire.TxOut{
			Address: p.payWireAddr,
			Value:   int64(spendableAmount),
		})

		// Sign the new transaction using witness signing (BIP-143 sighash).
		sigHashes := txscript.NewTxSigHashes(tx,
			txscript.NewCannedPrevOutputFetcher(
				p.payWireAddr, int64(spendableAmount),
			),
		)
		witness, err := txscript.WitnessSignature(tx, sigHashes,
			0, int64(spendableAmount), p.payScript,
			txscript.SigHashAll, p.signKey, true)
		if err != nil {
			return nil, err
		}
		tx.TxIn[0].Witness = witness

		txChain = append(txChain, hnsutil.NewTx(tx))

		// Next transaction uses outputs from this one.
		prevOutPoint = wire.OutPoint{Hash: tx.TxHash(), Index: 0}
	}

	return txChain, nil
}

// newPoolHarness returns a new instance of a pool harness initialized with a
// fake chain and a TxPool bound to it that is configured with a policy suitable
// for testing.  Also, the fake chain is populated with the returned spendable
// outputs so the caller can easily create new valid transactions which build
// off of it.
func newPoolHarness(chainParams *chaincfg.Params) (*poolHarness, []spendableOutput, error) {
	// Use a hard coded key pair for deterministic results.
	keyBytes, err := hex.DecodeString("700868df1838811ffbdf918fb482c1f7e" +
		"ad62db4b97bd7012c23e726485e577d")
	if err != nil {
		return nil, nil, err
	}
	signKey, signPub := btcec.PrivKeyFromBytes(keyBytes)

	// Generate associated pay-to-pubkey-hash address and resulting payment
	// script.  Handshake only has a single unified address type, so we
	// hash the compressed pubkey down to 20 bytes directly.
	pubKeyBytes := signPub.SerializeCompressed()
	payAddr, err := hnsutil.NewAddressPubKeyHash(
		hnsutil.Blake160(pubKeyBytes), chainParams,
	)
	if err != nil {
		return nil, nil, err
	}
	pkScript, err := txscript.PayToAddrScript(payAddr)
	if err != nil {
		return nil, nil, err
	}

	// Build the wire.Address that corresponds to a version-0 witness
	// program (P2WPKH) for the test key's pubkey hash.
	payWireAddr := wire.Address{
		Version: 0,
		Hash:    payAddr.ScriptAddress(),
	}

	// Create a new fake chain and harness bound to it.
	chain := &fakeChain{utxos: blockchain.NewUtxoViewpoint()}
	harness := poolHarness{
		signKey:     signKey,
		payAddr:     payAddr,
		payScript:   pkScript,
		payWireAddr: payWireAddr,
		chainParams: chainParams,

		chain: chain,
		txPool: New(&Config{
			Policy: Policy{
				DisableRelayPriority: true,
				FreeTxRelayLimit:     15.0,
				MaxOrphanTxs:         5,
				MaxOrphanTxSize:      1000,
				MaxSigOpCostPerTx:    blockchain.MaxBlockSigOpsCost / 4,
				MinRelayTxFee:        1000, // 1 doo per byte
				MaxTxVersion:         1,
			},
			ChainParams:      chainParams,
			FetchUtxoView:    chain.FetchUtxoView,
			BestHeight:       chain.BestHeight,
			MedianTimePast:   chain.MedianTimePast,
			CalcSequenceLock: chain.CalcSequenceLock,
			SigCache:         nil,
			HashCache:        txscript.NewHashCache(10),
			AddrIndex:        nil,
		}),
	}

	// Create a single coinbase transaction and add it to the harness
	// chain's utxo set and set the harness chain height such that the
	// coinbase will mature in the next block.  This ensures the txpool
	// accepts transactions which spend immature coinbases that will become
	// mature in the next block.
	numOutputs := uint32(1)
	outputs := make([]spendableOutput, 0, numOutputs)
	curHeight := harness.chain.BestHeight()
	coinbase, err := harness.CreateCoinbaseTx(curHeight+1, numOutputs)
	if err != nil {
		return nil, nil, err
	}
	harness.chain.utxos.AddTxOuts(coinbase, curHeight+1)
	for i := uint32(0); i < numOutputs; i++ {
		outputs = append(outputs, txOutToSpendableOut(coinbase, i))
	}
	harness.chain.SetHeight(int32(chainParams.CoinbaseMaturity) + curHeight)
	harness.chain.SetMedianTimePast(time.Now())

	return &harness, outputs, nil
}

// testContext houses a test-related state that is useful to pass to helper
// functions as a single argument.
type testContext struct {
	t       *testing.T
	harness *poolHarness
}

// addCoinbaseTx adds a spendable coinbase transaction to the test context's
// mock chain.
func (ctx *testContext) addCoinbaseTx(numOutputs uint32) *hnsutil.Tx {
	ctx.t.Helper()

	coinbaseHeight := ctx.harness.chain.BestHeight() + 1
	coinbase, err := ctx.harness.CreateCoinbaseTx(coinbaseHeight, numOutputs)
	if err != nil {
		ctx.t.Fatalf("unable to create coinbase: %v", err)
	}

	ctx.harness.chain.utxos.AddTxOuts(coinbase, coinbaseHeight)
	maturity := int32(ctx.harness.chainParams.CoinbaseMaturity)
	ctx.harness.chain.SetHeight(coinbaseHeight + maturity)
	ctx.harness.chain.SetMedianTimePast(time.Now())

	return coinbase
}

// addSignedTx creates a transaction that spends the inputs with the given fee.
// It can be added to the test context's mempool or mock chain based on the
// confirmed boolean.
func (ctx *testContext) addSignedTx(inputs []spendableOutput,
	numOutputs uint32, fee hnsutil.Amount,
	signalsReplacement, confirmed bool) *hnsutil.Tx {

	ctx.t.Helper()

	tx, err := ctx.harness.CreateSignedTx(
		inputs, numOutputs, fee, signalsReplacement,
	)
	if err != nil {
		ctx.t.Fatalf("unable to create transaction: %v", err)
	}

	if confirmed {
		newHeight := ctx.harness.chain.BestHeight() + 1
		ctx.harness.chain.utxos.AddTxOuts(tx, newHeight)
		ctx.harness.chain.SetHeight(newHeight)
		ctx.harness.chain.SetMedianTimePast(time.Now())
	} else {
		acceptedTxns, err := ctx.harness.txPool.ProcessTransaction(
			tx, true, false, 0,
		)
		if err != nil {
			ctx.t.Fatalf("unable to process transaction: %v", err)
		}
		if len(acceptedTxns) != 1 {
			ctx.t.Fatalf("expected one accepted transaction, got %d",
				len(acceptedTxns))
		}
		testPoolMembership(ctx, tx, false, true)
	}

	return tx
}

// testPoolMembership tests the transaction pool associated with the provided
// test context to determine if the passed transaction matches the provided
// orphan pool and transaction pool status.  It also further determines if it
// should be reported as available by the HaveTransaction function based upon
// the two flags and tests that condition as well.
func testPoolMembership(tc *testContext, tx *hnsutil.Tx, inOrphanPool, inTxPool bool) {
	tc.t.Helper()

	txHash := tx.Hash()
	gotOrphanPool := tc.harness.txPool.IsOrphanInPool(txHash)
	if inOrphanPool != gotOrphanPool {
		tc.t.Fatalf("IsOrphanInPool: want %v, got %v", inOrphanPool,
			gotOrphanPool)
	}

	gotTxPool := tc.harness.txPool.IsTransactionInPool(txHash)
	if inTxPool != gotTxPool {
		tc.t.Fatalf("IsTransactionInPool: want %v, got %v", inTxPool,
			gotTxPool)
	}

	gotHaveTx := tc.harness.txPool.HaveTransaction(txHash)
	wantHaveTx := inOrphanPool || inTxPool
	if wantHaveTx != gotHaveTx {
		tc.t.Fatalf("HaveTransaction: want %v, got %v", wantHaveTx,
			gotHaveTx)
	}
}

func TestMempoolAcceptanceRunsValidationPipeline(t *testing.T) {
	t.Parallel()

	harness, outputs, err := newPoolHarness(&chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("unable to create test pool: %v", err)
	}
	tc := &testContext{t, harness}

	fetchUtxoView := harness.txPool.cfg.FetchUtxoView
	calcSequenceLock := harness.txPool.cfg.CalcSequenceLock
	var fetchCalls, sequenceCalls, nameCalls int

	harness.txPool.cfg.FetchUtxoView = func(tx *hnsutil.Tx) (
		*blockchain.UtxoViewpoint, error) {

		fetchCalls++
		return fetchUtxoView(tx)
	}
	harness.txPool.cfg.CalcSequenceLock = func(tx *hnsutil.Tx,
		view *blockchain.UtxoViewpoint) (*blockchain.SequenceLock, error) {

		sequenceCalls++
		if entry := view.LookupEntry(outputs[0].outPoint); entry == nil ||
			entry.IsSpent() {

			t.Fatalf("CalcSequenceLock saw missing input view entry")
		}
		return calcSequenceLock(tx, view)
	}
	harness.txPool.cfg.CheckTransactionNames = func(tx *hnsutil.Tx,
		height int32, prevTime int64,
		view *blockchain.UtxoViewpoint) error {

		nameCalls++
		if height != harness.chain.BestHeight()+1 {
			t.Fatalf("CheckTransactionNames height = %d, want %d",
				height, harness.chain.BestHeight()+1)
		}
		if prevTime != harness.chain.MedianTimePast().Unix() {
			t.Fatalf("CheckTransactionNames prevTime = %d, want %d",
				prevTime, harness.chain.MedianTimePast().Unix())
		}
		if entry := view.LookupEntry(outputs[0].outPoint); entry == nil ||
			entry.IsSpent() {

			t.Fatalf("CheckTransactionNames saw missing input view entry")
		}
		return nil
	}

	tx, err := harness.CreateSignedTx(outputs, 1, 1000, false)
	if err != nil {
		t.Fatalf("unable to create transaction: %v", err)
	}
	acceptedTxns, err := harness.txPool.ProcessTransaction(tx, true,
		false, 0)
	if err != nil {
		t.Fatalf("ProcessTransaction: %v", err)
	}
	if len(acceptedTxns) != 1 {
		t.Fatalf("accepted transactions = %d, want 1", len(acceptedTxns))
	}
	if fetchCalls != 1 {
		t.Fatalf("FetchUtxoView calls = %d, want 1", fetchCalls)
	}
	if sequenceCalls != 1 {
		t.Fatalf("CalcSequenceLock calls = %d, want 1", sequenceCalls)
	}
	if nameCalls != 1 {
		t.Fatalf("CheckTransactionNames calls = %d, want 1", nameCalls)
	}
	testPoolMembership(tc, tx, false, true)
}

func TestMempoolAcceptanceRejectsContextFreeSanityFailure(t *testing.T) {
	t.Parallel()

	harness, _, err := newPoolHarness(&chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("unable to create test pool: %v", err)
	}

	fetchUtxoView := harness.txPool.cfg.FetchUtxoView
	var fetchCalls int
	harness.txPool.cfg.FetchUtxoView = func(tx *hnsutil.Tx) (
		*blockchain.UtxoViewpoint, error) {

		fetchCalls++
		return fetchUtxoView(tx)
	}

	msgTx := wire.NewMsgTx(wire.TxVersion)
	for i := 0; i < 3; i++ {
		msgTx.AddTxOut(&wire.TxOut{
			Value:   1000,
			Address: harness.payWireAddr,
		})
	}
	tx := hnsutil.NewTx(msgTx)

	_, err = harness.txPool.CheckMempoolAcceptance(tx)
	if err == nil {
		t.Fatal("CheckMempoolAcceptance: expected no-input rejection")
	}
	if code, ok := extractRejectCode(err); !ok || code != wire.RejectInvalid {
		t.Fatalf("reject code = %v, %v; want %v", code, ok,
			wire.RejectInvalid)
	}
	if !strings.Contains(err.Error(), "no inputs") {
		t.Fatalf("error = %q, want no-input sanity error", err)
	}
	if fetchCalls != 0 {
		t.Fatalf("FetchUtxoView calls = %d, want 0", fetchCalls)
	}
	testPoolMembership(&testContext{t, harness}, tx, false, false)
}

func TestMempoolAcceptanceRejectsImmatureCoinbaseSpend(t *testing.T) {
	t.Parallel()

	harness, _, err := newPoolHarness(&chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("unable to create test pool: %v", err)
	}
	tc := &testContext{t, harness}

	coinbaseHeight := harness.chain.BestHeight() + 1
	coinbase, err := harness.CreateCoinbaseTx(coinbaseHeight, 1)
	if err != nil {
		t.Fatalf("unable to create coinbase: %v", err)
	}
	harness.chain.utxos.AddTxOuts(coinbase, coinbaseHeight)
	harness.chain.SetHeight(coinbaseHeight)
	harness.chain.SetMedianTimePast(time.Now())

	tx, err := harness.CreateSignedTx(
		[]spendableOutput{txOutToSpendableOut(coinbase, 0)},
		1, 1000, false,
	)
	if err != nil {
		t.Fatalf("unable to create transaction: %v", err)
	}

	if _, err := harness.txPool.ProcessTransaction(
		tx, true, false, 0,
	); err == nil {

		t.Fatal("ProcessTransaction immature coinbase: expected rejection")
	} else if code, ok := extractRejectCode(err); !ok ||
		code != wire.RejectInvalid {

		t.Fatalf("reject code = %v, %v; want %v", code, ok,
			wire.RejectInvalid)
	}
	testPoolMembership(tc, tx, false, false)
}

func TestMempoolAcceptanceRejectsNonstandardWeight(t *testing.T) {
	t.Parallel()

	harness, outputs, err := newPoolHarness(&chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("unable to create test pool: %v", err)
	}
	tc := &testContext{t, harness}

	const numOutputs = 4000
	tx, err := harness.CreateSignedTx(outputs, numOutputs, 1000, false)
	if err != nil {
		t.Fatalf("unable to create transaction: %v", err)
	}
	if weight := blockchain.GetTransactionWeight(tx); weight <= maxStandardTxWeight {
		t.Fatalf("test tx weight = %d, want > %d", weight,
			maxStandardTxWeight)
	}

	if _, err := harness.txPool.ProcessTransaction(
		tx, true, false, 0,
	); err == nil {

		t.Fatal("ProcessTransaction oversized tx: expected rejection")
	} else if code, ok := extractRejectCode(err); !ok ||
		code != wire.RejectNonstandard {

		t.Fatalf("reject code = %v, %v; want %v", code, ok,
			wire.RejectNonstandard)
	}
	testPoolMembership(tc, tx, false, false)
}

func TestMempoolAcceptanceRejectsInvalidWitnessScript(t *testing.T) {
	t.Parallel()

	harness, outputs, err := newPoolHarness(&chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("unable to create test pool: %v", err)
	}
	tc := &testContext{t, harness}

	tx, err := harness.CreateSignedTx(outputs, 1, 1000, false)
	if err != nil {
		t.Fatalf("unable to create transaction: %v", err)
	}
	witness := tx.MsgTx().TxIn[0].Witness
	if len(witness) == 0 || len(witness[0]) == 0 {
		t.Fatal("test transaction has no witness signature to corrupt")
	}
	witness[0][len(witness[0])-1] ^= 0x01

	if _, err := harness.txPool.ProcessTransaction(
		tx, true, false, 0,
	); err == nil {

		t.Fatal("ProcessTransaction invalid witness: expected rejection")
	} else if code, ok := extractRejectCode(err); !ok ||
		code != wire.RejectInvalid {

		t.Fatalf("reject code = %v, %v; want %v", code, ok,
			wire.RejectInvalid)
	}
	testPoolMembership(tc, tx, false, false)
}

func TestNameOperationMempoolConflicts(t *testing.T) {
	t.Parallel()

	harness, _, err := newPoolHarness(&chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("unable to create test pool: %v", err)
	}
	tc := &testContext{t, harness}

	fundingTx := tc.addCoinbaseTx(2)
	inputA := txOutToSpendableOut(fundingTx, 0)
	inputB := txOutToSpendableOut(fundingTx, 1)

	openA, err := harness.CreateSignedTxWithCovenant(
		inputA, 1000, mempoolOpenCovenant("phasefive"), false,
	)
	if err != nil {
		t.Fatalf("unable to create first OPEN transaction: %v", err)
	}
	acceptedTxns, err := harness.txPool.ProcessTransaction(
		openA, true, false, 0,
	)
	if err != nil {
		t.Fatalf("ProcessTransaction first OPEN: %v", err)
	}
	if len(acceptedTxns) != 1 {
		t.Fatalf("accepted transactions = %d, want 1", len(acceptedTxns))
	}
	testPoolMembership(tc, openA, false, true)

	openB, err := harness.CreateSignedTxWithCovenant(
		inputB, 1000, mempoolOpenCovenant("phasefive"), false,
	)
	if err != nil {
		t.Fatalf("unable to create second OPEN transaction: %v", err)
	}
	if _, err := harness.txPool.ProcessTransaction(
		openB, true, false, 0,
	); err == nil {
		t.Fatal("ProcessTransaction second OPEN: expected conflict")
	} else if code, ok := extractRejectCode(err); !ok ||
		code != wire.RejectDuplicate {

		t.Fatalf("second OPEN reject code = %v, %v; want %v",
			code, ok, wire.RejectDuplicate)
	}
	testPoolMembership(tc, openB, false, false)

	harness.txPool.RemoveTransaction(openA, true)
	acceptedTxns, err = harness.txPool.ProcessTransaction(
		openB, true, false, 0,
	)
	if err != nil {
		t.Fatalf("ProcessTransaction after removing conflict: %v", err)
	}
	if len(acceptedTxns) != 1 {
		t.Fatalf("accepted transactions = %d, want 1", len(acceptedTxns))
	}
	testPoolMembership(tc, openB, false, true)
}

func TestRemoveNameConflicts(t *testing.T) {
	t.Parallel()

	harness, _, err := newPoolHarness(&chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("unable to create test pool: %v", err)
	}
	tc := &testContext{t, harness}

	fundingTx := tc.addCoinbaseTx(3)
	inputA := txOutToSpendableOut(fundingTx, 0)
	inputB := txOutToSpendableOut(fundingTx, 1)
	inputC := txOutToSpendableOut(fundingTx, 2)

	openA, err := harness.CreateSignedTxWithCovenant(
		inputA, 1000, mempoolOpenCovenant("phasefive"), false,
	)
	if err != nil {
		t.Fatalf("unable to create mempool OPEN transaction: %v", err)
	}
	if _, err := harness.txPool.ProcessTransaction(
		openA, true, false, 0,
	); err != nil {

		t.Fatalf("ProcessTransaction mempool OPEN: %v", err)
	}
	testPoolMembership(tc, openA, false, true)

	staleOpen, err := harness.CreateSignedTxWithCovenant(
		inputB, 1000, mempoolOpenCovenant("phasefive"), false,
	)
	if err != nil {
		t.Fatalf("unable to create second stale OPEN transaction: %v", err)
	}
	harness.txPool.mtx.Lock()
	harness.txPool.addTransaction(blockchain.NewUtxoViewpoint(),
		staleOpen, 0, 0)
	harness.txPool.mtx.Unlock()
	testPoolMembership(tc, staleOpen, false, true)

	minedOpen, err := harness.CreateSignedTxWithCovenant(
		inputC, 1000, mempoolOpenCovenant("phasefive"), false,
	)
	if err != nil {
		t.Fatalf("unable to create mined OPEN transaction: %v", err)
	}

	harness.txPool.RemoveNameConflicts(minedOpen)
	testPoolMembership(tc, openA, false, false)
	testPoolMembership(tc, staleOpen, false, false)
	testPoolMembership(tc, minedOpen, false, false)

	nameHash := blockchain.HashName([]byte("phasefive"))
	harness.txPool.mtx.RLock()
	_, indexed := harness.txPool.nameActions[nameHash]
	harness.txPool.mtx.RUnlock()
	if indexed {
		t.Fatal("RemoveNameConflicts left stale name action index")
	}
}

func TestNameConflictReorgReinsertOlderTransaction(t *testing.T) {
	t.Parallel()

	harness, _, err := newPoolHarness(&chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("unable to create test pool: %v", err)
	}
	tc := &testContext{t, harness}

	fundingTx := tc.addCoinbaseTx(2)
	inputA := txOutToSpendableOut(fundingTx, 0)
	inputB := txOutToSpendableOut(fundingTx, 1)

	disconnectedOpen, err := harness.CreateSignedTxWithCovenant(
		inputA, 1000, mempoolOpenCovenant("phasefive"), false,
	)
	if err != nil {
		t.Fatalf("unable to create disconnected OPEN: %v", err)
	}
	newerOpen, err := harness.CreateSignedTxWithCovenant(
		inputB, 1000, mempoolOpenCovenant("phasefive"), false,
	)
	if err != nil {
		t.Fatalf("unable to create newer OPEN: %v", err)
	}

	if _, err := harness.txPool.ProcessTransaction(
		newerOpen, true, false, 0,
	); err != nil {

		t.Fatalf("ProcessTransaction newer OPEN: %v", err)
	}
	testPoolMembership(tc, newerOpen, false, true)

	harness.txPool.RemoveNameConflicts(disconnectedOpen)
	_, txDesc, err := harness.txPool.MaybeAcceptTransaction(
		disconnectedOpen, false, false,
	)
	if err != nil {
		t.Fatalf("MaybeAcceptTransaction disconnected OPEN: %v", err)
	}
	if txDesc == nil {
		t.Fatal("MaybeAcceptTransaction disconnected OPEN returned nil descriptor")
	}

	testPoolMembership(tc, newerOpen, false, false)
	testPoolMembership(tc, disconnectedOpen, false, true)
}

func TestNameValidationUsesUnconfirmedMempoolState(t *testing.T) {
	t.Parallel()

	harness, _, err := newPoolHarness(&chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("unable to create test pool: %v", err)
	}
	harness.txPool.cfg.NewNameValidationView = func() (NameValidationView, error) {
		return &orderedNameValidationView{}, nil
	}
	tc := &testContext{t, harness}

	fundingTx := tc.addCoinbaseTx(2)
	inputA := txOutToSpendableOut(fundingTx, 0)
	inputB := txOutToSpendableOut(fundingTx, 1)

	updateTx, err := harness.CreateSignedTxWithCovenant(
		inputA, 1000, mempoolUpdateCovenant("phasefive", 1), false,
	)
	if err != nil {
		t.Fatalf("unable to create UPDATE transaction: %v", err)
	}
	if _, err := harness.txPool.ProcessTransaction(
		updateTx, true, false, 0,
	); err != nil {

		t.Fatalf("ProcessTransaction UPDATE: %v", err)
	}

	transferTx, err := harness.CreateSignedTxWithCovenant(
		txOutToSpendableOut(updateTx, 0), 1000,
		mempoolTransferCovenant("phasefive", 1,
			harness.payWireAddr), false,
	)
	if err != nil {
		t.Fatalf("unable to create dependent TRANSFER: %v", err)
	}
	if _, err := harness.txPool.ProcessTransaction(
		transferTx, true, false, 0,
	); err != nil {

		t.Fatalf("ProcessTransaction dependent TRANSFER: %v", err)
	}
	testPoolMembership(tc, updateTx, false, true)
	testPoolMembership(tc, transferTx, false, true)

	nameHash := blockchain.HashName([]byte("phasefive"))
	harness.txPool.mtx.RLock()
	indexed := harness.txPool.nameActions[nameHash]
	harness.txPool.mtx.RUnlock()
	if indexed == nil || !indexed.Hash().IsEqual(transferTx.Hash()) {
		t.Fatalf("name action index = %v, want dependent TRANSFER",
			indexed)
	}

	harness.txPool.RemoveTransaction(transferTx, false)
	testPoolMembership(tc, transferTx, false, false)
	harness.txPool.mtx.RLock()
	indexed = harness.txPool.nameActions[nameHash]
	harness.txPool.mtx.RUnlock()
	if indexed == nil || !indexed.Hash().IsEqual(updateTx.Hash()) {
		t.Fatalf("name action index after removal = %v, want UPDATE",
			indexed)
	}

	unrelatedTransfer, err := harness.CreateSignedTxWithCovenant(
		inputB, 1000, mempoolTransferCovenant("phasefive", 1,
			harness.payWireAddr), false,
	)
	if err != nil {
		t.Fatalf("unable to create unrelated TRANSFER: %v", err)
	}
	if _, err := harness.txPool.ProcessTransaction(
		unrelatedTransfer, true, false, 0,
	); err == nil {
		t.Fatal("ProcessTransaction unrelated TRANSFER: expected conflict")
	} else if code, ok := extractRejectCode(err); !ok ||
		code != wire.RejectDuplicate {

		t.Fatalf("unrelated TRANSFER reject code = %v, %v; want %v",
			code, ok, wire.RejectDuplicate)
	}
}

type orderedNameValidationView struct {
	seenUpdate     bool
	rejectTransfer *bool
}

func (v *orderedNameValidationView) ApplyTransaction(tx *hnsutil.Tx,
	height int32, prevTime int64, view *blockchain.UtxoViewpoint) error {

	_ = height
	_ = prevTime
	_ = view

	for _, txOut := range tx.MsgTx().TxOut {
		switch txOut.Covenant.Type {
		case wire.CovenantUpdate:
			v.seenUpdate = true
		case wire.CovenantTransfer:
			if v.rejectTransfer != nil && *v.rejectTransfer {
				return errors.New("stale transfer")
			}
			if !v.seenUpdate {
				return errors.New("TRANSFER before UPDATE")
			}
		}
	}
	return nil
}

func TestPruneInvalidNameTransactions(t *testing.T) {
	t.Parallel()

	harness, _, err := newPoolHarness(&chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("unable to create test pool: %v", err)
	}
	tc := &testContext{t, harness}

	rejectNames := false
	harness.txPool.cfg.CheckTransactionNames = func(tx *hnsutil.Tx,
		height int32, prevTime int64,
		view *blockchain.UtxoViewpoint) error {

		if rejectNames {
			return errors.New("stale name transition")
		}
		return nil
	}

	fundingTx := tc.addCoinbaseTx(3)
	nameInput := txOutToSpendableOut(fundingTx, 0)
	normalInput := txOutToSpendableOut(fundingTx, 1)

	openTx, err := harness.CreateSignedTxWithCovenant(
		nameInput, 1000, mempoolOpenCovenant("phasefive"), false,
	)
	if err != nil {
		t.Fatalf("unable to create OPEN transaction: %v", err)
	}
	normalTx, err := harness.CreateSignedTx(
		[]spendableOutput{normalInput}, 1, 1000, false,
	)
	if err != nil {
		t.Fatalf("unable to create normal transaction: %v", err)
	}

	if _, err := harness.txPool.ProcessTransaction(
		openTx, true, false, 0,
	); err != nil {

		t.Fatalf("ProcessTransaction OPEN: %v", err)
	}
	if _, err := harness.txPool.ProcessTransaction(
		normalTx, true, false, 0,
	); err != nil {

		t.Fatalf("ProcessTransaction normal: %v", err)
	}
	testPoolMembership(tc, openTx, false, true)
	testPoolMembership(tc, normalTx, false, true)

	rejectNames = true
	removed := harness.txPool.PruneInvalidNameTransactions()
	if len(removed) != 1 {
		t.Fatalf("removed transactions = %d, want 1", len(removed))
	}
	if !removed[0].Tx.Hash().IsEqual(openTx.Hash()) {
		t.Fatalf("removed tx = %v, want %v", removed[0].Tx.Hash(),
			openTx.Hash())
	}

	testPoolMembership(tc, openTx, false, false)
	testPoolMembership(tc, normalTx, false, true)
}

func TestPruneInvalidNameTransactionsUsesStatefulView(t *testing.T) {
	t.Parallel()

	harness, _, err := newPoolHarness(&chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("unable to create test pool: %v", err)
	}
	tc := &testContext{t, harness}

	rejectTransfer := false
	harness.txPool.cfg.NewNameValidationView = func() (NameValidationView, error) {
		return &orderedNameValidationView{
			rejectTransfer: &rejectTransfer,
		}, nil
	}

	fundingTx := tc.addCoinbaseTx(1)
	input := txOutToSpendableOut(fundingTx, 0)
	updateTx, err := harness.CreateSignedTxWithCovenant(
		input, 1000, mempoolUpdateCovenant("phasefive", 1), false,
	)
	if err != nil {
		t.Fatalf("unable to create UPDATE transaction: %v", err)
	}
	if _, err := harness.txPool.ProcessTransaction(
		updateTx, true, false, 0,
	); err != nil {

		t.Fatalf("ProcessTransaction UPDATE: %v", err)
	}

	transferTx, err := harness.CreateSignedTxWithCovenant(
		txOutToSpendableOut(updateTx, 0), 1000,
		mempoolTransferCovenant("phasefive", 1,
			harness.payWireAddr), false,
	)
	if err != nil {
		t.Fatalf("unable to create TRANSFER transaction: %v", err)
	}
	if _, err := harness.txPool.ProcessTransaction(
		transferTx, true, false, 0,
	); err != nil {

		t.Fatalf("ProcessTransaction TRANSFER: %v", err)
	}
	testPoolMembership(tc, updateTx, false, true)
	testPoolMembership(tc, transferTx, false, true)

	rejectTransfer = true
	removed := harness.txPool.PruneInvalidNameTransactions()
	if len(removed) != 1 {
		t.Fatalf("removed transactions = %d, want 1", len(removed))
	}
	if !removed[0].Tx.Hash().IsEqual(transferTx.Hash()) {
		t.Fatalf("removed tx = %v, want %v", removed[0].Tx.Hash(),
			transferTx.Hash())
	}

	testPoolMembership(tc, updateTx, false, true)
	testPoolMembership(tc, transferTx, false, false)

	nameHash := blockchain.HashName([]byte("phasefive"))
	harness.txPool.mtx.RLock()
	indexed := harness.txPool.nameActions[nameHash]
	harness.txPool.mtx.RUnlock()
	if indexed == nil || !indexed.Hash().IsEqual(updateTx.Hash()) {
		t.Fatalf("name action index after prune = %v, want UPDATE",
			indexed)
	}
}

func TestCoinbaseProofSourceStoresClonesAndFiltersClaims(t *testing.T) {
	t.Parallel()

	mp := New(&Config{})
	addrHash := make([]byte, 20)
	addrHash[0] = 0x01
	addrHash[1] = 0x02
	addr := wire.Address{Version: 0, Hash: addrHash}
	airdropOutput := wire.NewTxOut(90, addr, wire.Covenant{})
	airdropProof := mining.CoinbaseProof{
		Witness: mempoolAirdropProof(t, 0, addr, 100, 10),
		Output:  airdropOutput,
		Fee:     10,
	}
	airdropWitness := append([]byte(nil), airdropProof.Witness...)

	airdropHash, err := mp.AddCoinbaseProof(airdropProof)
	if err != nil {
		t.Fatalf("AddCoinbaseProof airdrop: %v", err)
	}
	airdropRawHash := blockchain.RawProofHash(airdropWitness)
	if !mp.HaveCoinbaseProof(&airdropRawHash) {
		t.Fatal("HaveCoinbaseProof did not find airdrop by hsd hash")
	}
	fetchedProof, ok := mp.FetchCoinbaseProof(&airdropRawHash)
	if !ok {
		t.Fatal("FetchCoinbaseProof did not find airdrop by hsd hash")
	}
	if !reflect.DeepEqual(fetchedProof.Witness, airdropWitness) {
		t.Fatalf("FetchCoinbaseProof witness = %x, want %x",
			fetchedProof.Witness, airdropWitness)
	}
	if mp.LastUpdated().Unix() == 0 {
		t.Fatal("AddCoinbaseProof did not update LastUpdated")
	}

	// Mutate the caller-owned proof after adding it.  The source must keep
	// its own copy.
	airdropProof.Witness[0] = 0xff
	airdropProof.Output.Value = 1
	airdropProof.Output.Address.Hash[0] = 0xff

	proofs, err := mp.CoinbaseProofs(10)
	if err != nil {
		t.Fatalf("CoinbaseProofs: %v", err)
	}
	if len(proofs) != 1 {
		t.Fatalf("proof count = %d, want 1", len(proofs))
	}
	if !bytes.Equal(proofs[0].Witness, airdropWitness) ||
		proofs[0].Output.Value != 90 ||
		proofs[0].Output.Address.Hash[0] != 0x01 ||
		proofs[0].Fee != 10 {

		t.Fatalf("stored proof was mutated: %+v", proofs[0])
	}

	// Mutate the returned proof.  Future calls must still return a clean
	// clone.
	proofs[0].Witness[0] = 0xee
	proofs[0].Output.Value = 2
	proofs, err = mp.CoinbaseProofs(10)
	if err != nil {
		t.Fatalf("CoinbaseProofs after returned mutation: %v", err)
	}
	if !bytes.Equal(proofs[0].Witness, airdropWitness) ||
		proofs[0].Output.Value != 90 {

		t.Fatalf("returned proof was not cloned: %+v", proofs[0])
	}

	replacementHashBytes := make([]byte, 20)
	replacementHashBytes[0] = 0x01
	replacementHashBytes[1] = 0x02
	replacementAddr := wire.Address{
		Version: 0,
		Hash:    replacementHashBytes,
	}
	replacement := mining.CoinbaseProof{
		Witness: mempoolAirdropProof(t, 0, replacementAddr, 100, 10),
		Output:  wire.NewTxOut(90, replacementAddr, wire.Covenant{}),
		Fee:     10,
	}
	replacementHash, err := mp.AddCoinbaseProof(replacement)
	if err != nil {
		t.Fatalf("AddCoinbaseProof replacement: %v", err)
	}
	if replacementHash != airdropHash {
		t.Fatalf("replacement hash = %v, want %v",
			replacementHash, airdropHash)
	}
	proofs, err = mp.CoinbaseProofs(10)
	if err != nil {
		t.Fatalf("CoinbaseProofs replacement: %v", err)
	}
	if len(proofs) != 1 || proofs[0].Fee != 10 {
		t.Fatalf("replacement proofs = %+v, want one proof with fee 10",
			proofs)
	}

	if _, err := mp.AddCoinbaseProof(mining.CoinbaseProof{
		Witness: mempoolAirdropProof(t, 0, replacementAddr, 100, 10),
		Output:  wire.NewTxOut(90, replacementAddr, wire.Covenant{}),
		Fee:     11,
	}); err == nil {

		t.Fatal("AddCoinbaseProof fee mutation: expected error")
	}
	duplicateOutput := wire.NewTxOut(91, replacementAddr, wire.Covenant{})
	if _, err := mp.AddCoinbaseProof(mining.CoinbaseProof{
		Witness: mempoolAirdropProof(t, 0, replacementAddr, 100, 10),
		Output:  duplicateOutput,
		Fee:     10,
	}); err == nil {

		t.Fatal("AddCoinbaseProof duplicate witness: expected error")
	}
	otherAddrHash := make([]byte, 20)
	otherAddrHash[0] = 0x03
	otherAddr := wire.Address{Version: 0, Hash: otherAddrHash}
	if _, err := mp.AddCoinbaseProof(mining.CoinbaseProof{
		Witness: mempoolAirdropProof(t, 0, otherAddr, 100, 10),
		Output:  wire.NewTxOut(90, otherAddr, wire.Covenant{}),
		Fee:     10,
	}); err == nil {

		t.Fatal("AddCoinbaseProof duplicate position: expected error")
	}
	if _, err := mp.AddCoinbaseProof(mining.CoinbaseProof{
		Witness: []byte{0x05},
		Output: wire.NewTxOut(1, replacementAddr, wire.Covenant{
			Type: wire.CovenantOpen,
		}),
	}); err == nil {

		t.Fatal("AddCoinbaseProof unsupported covenant: expected error")
	}

	claimOutput := wire.NewTxOut(50, addr, mempoolClaimCovenant(11))
	if _, err := mp.AddCoinbaseProof(mining.CoinbaseProof{
		Witness: []byte{0x04},
		Output:  claimOutput,
		Fee:     5,
	}); err != nil {

		t.Fatalf("AddCoinbaseProof claim: %v", err)
	}

	malformedClaim := wire.NewTxOut(50, addr, wire.Covenant{
		Type: wire.CovenantClaim,
		Items: [][]byte{
			mempoolHashItem("phasefive"),
			mempoolU32Item(11),
		},
	})
	if _, err := mp.AddCoinbaseProof(mining.CoinbaseProof{
		Witness: []byte{0x06},
		Output:  malformedClaim,
		Fee:     5,
	}); err == nil {

		t.Fatal("AddCoinbaseProof malformed claim: expected error")
	}

	proofs, err = mp.CoinbaseProofs(10)
	if err != nil {
		t.Fatalf("CoinbaseProofs height 10: %v", err)
	}
	if len(proofs) != 1 {
		t.Fatalf("height 10 proof count = %d, want only airdrop",
			len(proofs))
	}
	proofs, err = mp.CoinbaseProofs(11)
	if err != nil {
		t.Fatalf("CoinbaseProofs height 11: %v", err)
	}
	if len(proofs) != 2 {
		t.Fatalf("height 11 proof count = %d, want airdrop and claim",
			len(proofs))
	}

	if !mp.RemoveCoinbaseProof(airdropHash) {
		t.Fatal("RemoveCoinbaseProof returned false")
	}
	if mp.HaveCoinbaseProof(&airdropRawHash) {
		t.Fatal("HaveCoinbaseProof found removed airdrop")
	}
	proofs, err = mp.CoinbaseProofs(11)
	if err != nil {
		t.Fatalf("CoinbaseProofs after remove: %v", err)
	}
	if len(proofs) != 1 ||
		proofs[0].Output.Covenant.Type != wire.CovenantClaim {

		t.Fatalf("proofs after remove = %+v, want only claim", proofs)
	}
}

func TestAddCoinbaseProofRejectsStaleAndDisabledProofs(t *testing.T) {
	t.Parallel()

	addrHash := make([]byte, 20)
	addrHash[0] = 0x01
	addr := wire.Address{Version: 0, Hash: addrHash}
	params := chaincfg.RegressionNetParams
	params.AirdropGooSigStop = 1
	bestHeight := func() int32 { return 0 }
	inactive := func(uint32) (bool, error) { return false, nil }

	spentPool := New(&Config{
		ChainParams:        &params,
		BestHeight:         bestHeight,
		IsDeploymentActive: inactive,
		IsAirdropSpent: func(uint32) (bool, error) {
			return true, nil
		},
	})
	if _, err := spentPool.AddCoinbaseProof(mining.CoinbaseProof{
		Witness: mempoolAirdropProof(t, 0, addr, 100, 10),
		Output:  wire.NewTxOut(90, addr, wire.Covenant{}),
		Fee:     10,
	}); err == nil {
		t.Fatal("AddCoinbaseProof spent airdrop: expected error")
	}

	airstopPool := New(&Config{
		ChainParams: &params,
		BestHeight:  bestHeight,
		IsDeploymentActive: func(deploymentID uint32) (bool, error) {
			return deploymentID == chaincfg.DeploymentAirstop, nil
		},
	})
	if _, err := airstopPool.AddCoinbaseProof(mining.CoinbaseProof{
		Witness: mempoolAirdropProof(t, 0, addr, 100, 10),
		Output:  wire.NewTxOut(90, addr, wire.Covenant{}),
		Fee:     10,
	}); err == nil {
		t.Fatal("AddCoinbaseProof airstop airdrop: expected error")
	}

	gooKey := append([]byte{1}, make([]byte, 256)...)
	gooPool := New(&Config{
		ChainParams:        &params,
		BestHeight:         bestHeight,
		IsDeploymentActive: inactive,
	})
	if _, err := gooPool.AddCoinbaseProof(mining.CoinbaseProof{
		Witness: mempoolAirdropProofWithKey(t, 0, gooKey, addr, 10),
		Output: wire.NewTxOut(int64(mempoolAirdropReward-10), addr,
			wire.Covenant{}),
		Fee: 10,
	}); err == nil {
		t.Fatal("AddCoinbaseProof GooSig airdrop: expected error")
	}

	weakPool := New(&Config{
		ChainParams: &params,
		BestHeight:  bestHeight,
		IsDeploymentActive: func(deploymentID uint32) (bool, error) {
			return deploymentID == chaincfg.DeploymentHardening, nil
		},
	})
	if _, err := weakPool.AddCoinbaseProof(mining.CoinbaseProof{
		Witness: mempoolAirdropProofWithKey(t, 0,
			mempoolWeakRSAKey(), addr, 10),
		Output: wire.NewTxOut(int64(mempoolAirdropReward-10), addr,
			wire.Covenant{}),
		Fee: 10,
	}); err == nil {
		t.Fatal("AddCoinbaseProof weak airdrop: expected error")
	}

	claimPool := New(&Config{
		BestHeight: func() int32 { return 1 },
	})
	if _, err := claimPool.AddCoinbaseProof(mining.CoinbaseProof{
		Witness: []byte{0x01},
		Output:  wire.NewTxOut(10, addr, mempoolClaimCovenant(1)),
		Fee:     1,
	}); err == nil {
		t.Fatal("AddCoinbaseProof stale claim: expected error")
	}
}

func TestValidateClaimProofForHeightChecksDNSSECWindow(t *testing.T) {
	t.Parallel()

	medianTime := int64(99)
	mp := New(&Config{
		MedianTimePast: func() time.Time {
			return time.Unix(medianTime, 0)
		},
	})
	policy := coinbaseProofPolicy{
		kind:            coinbaseProofKindClaim,
		claimInception:  100,
		claimExpiration: 200,
		hasClaimWindow:  true,
		hasClaimExpiry:  true,
	}

	err := mp.validateClaimProofForHeight(policy, 1)
	if err == nil || !coinbaseProofErrorPrunable(err) {
		t.Fatalf("future CLAIM error = %v, want prunable error", err)
	}

	medianTime = 100
	if err := mp.validateClaimProofForHeight(policy, 1); err != nil {
		t.Fatalf("active CLAIM: %v", err)
	}

	medianTime = 201
	err = mp.validateClaimProofForHeight(policy, 1)
	if err == nil || !coinbaseProofErrorPrunable(err) {
		t.Fatalf("expired CLAIM error = %v, want prunable error", err)
	}
}

func TestRemoveCoinbaseProofsRemovesMinedProofs(t *testing.T) {
	t.Parallel()

	mp := New(&Config{})
	addrHash := make([]byte, 20)
	addrHash[0] = 0x01
	addrHash[1] = 0x02
	addr := wire.Address{Version: 0, Hash: addrHash}
	proof := mining.CoinbaseProof{
		Witness: []byte{0xaa, 0xbb},
		Output:  wire.NewTxOut(100, addr, mempoolClaimCovenant(1)),
		Fee:     7,
	}
	if _, err := mp.AddCoinbaseProof(proof); err != nil {
		t.Fatalf("AddCoinbaseProof: %v", err)
	}

	coinbase := wire.NewMsgTx(wire.TxVersion)
	coinbase.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Index: wire.MaxPrevOutIndex,
		},
		Sequence: wire.MaxTxInSequenceNum,
		Witness:  wire.TxWitness{[]byte{0x01}},
	})
	coinbase.AddTxOut(wire.NewTxOut(1, addr, wire.Covenant{}))
	coinbase.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Index: wire.MaxPrevOutIndex,
		},
		Sequence: wire.MaxTxInSequenceNum,
		Witness:  wire.TxWitness{proof.Witness},
	})
	coinbase.AddTxOut(proof.Output)

	removed := mp.RemoveCoinbaseProofs(hnsutil.NewTx(coinbase))
	if removed != 1 {
		t.Fatalf("removed proofs = %d, want 1", removed)
	}
	proofs, err := mp.CoinbaseProofs(1)
	if err != nil {
		t.Fatalf("CoinbaseProofs: %v", err)
	}
	if len(proofs) != 0 {
		t.Fatalf("proof count after mined remove = %d, want 0",
			len(proofs))
	}
}

func TestNameOperationIndexAllowsAuctionFanout(t *testing.T) {
	t.Parallel()

	mp := New(&Config{})
	bidA := mempoolCovenantTx(1, mempoolBidCovenant("phasefive", 1))
	bidB := mempoolCovenantTx(2, mempoolBidCovenant("phasefive", 1))
	mp.addNameOperationIndexes(bidA)
	if err := mp.checkNameOperationConflicts(bidB, nil); err != nil {
		t.Fatalf("BID conflict check: %v", err)
	}

	updateA := mempoolCovenantTx(3,
		mempoolUpdateCovenant("phasefive", 1))
	updateB := mempoolCovenantTx(4,
		mempoolUpdateCovenant("phasefive", 1))
	mp.addNameOperationIndexes(updateA)
	if err := mp.checkNameOperationConflicts(updateB, nil); err == nil {
		t.Fatal("UPDATE conflict check: expected duplicate name action")
	} else if code, ok := extractRejectCode(err); !ok ||
		code != wire.RejectDuplicate {

		t.Fatalf("UPDATE reject code = %v, %v; want %v",
			code, ok, wire.RejectDuplicate)
	}

	mp.removeNameOperationIndexes(updateA)
	if err := mp.checkNameOperationConflicts(updateB, nil); err != nil {
		t.Fatalf("UPDATE after removal: %v", err)
	}
}

func mempoolCovenantTx(tag uint32, covenant wire.Covenant) *hnsutil.Tx {
	tx := wire.NewMsgTx(wire.TxVersion)
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  chainhash.Hash{byte(tag)},
			Index: tag,
		},
		Sequence: wire.MaxTxInSequenceNum,
	})
	tx.AddTxOut(wire.NewTxOut(1, wire.Address{
		Version: 0,
		Hash:    make([]byte, 20),
	}, covenant))
	return hnsutil.NewTx(tx)
}

func mempoolOpenCovenant(name string) wire.Covenant {
	return wire.Covenant{
		Type: wire.CovenantOpen,
		Items: [][]byte{
			mempoolHashItem(name),
			mempoolU32Item(0),
			[]byte(name),
		},
	}
}

func mempoolBidCovenant(name string, height uint32) wire.Covenant {
	return wire.Covenant{
		Type: wire.CovenantBid,
		Items: [][]byte{
			mempoolHashItem(name),
			mempoolU32Item(height),
			[]byte(name),
			mempoolHashBytes(chainhash.Hash{0x01}),
		},
	}
}

func mempoolClaimCovenant(height uint32) wire.Covenant {
	return wire.Covenant{
		Type: wire.CovenantClaim,
		Items: [][]byte{
			mempoolHashItem("phasefive"),
			mempoolU32Item(height),
			[]byte("phasefive"),
			{0},
			mempoolHashBytes(chainhash.Hash{0x01}),
			mempoolU32Item(1),
		},
	}
}

const mempoolAirdropReward = uint64(4246994314)

func mempoolAirdropProof(t *testing.T, index uint32, addr wire.Address,
	value, fee uint64) []byte {

	t.Helper()

	var key bytes.Buffer
	key.WriteByte(4) // ADDRESS airdrop key.
	key.WriteByte(addr.Version)
	key.WriteByte(byte(len(addr.Hash)))
	key.Write(addr.Hash)
	var scratch [8]byte
	binary.LittleEndian.PutUint64(scratch[:], value)
	key.Write(scratch[:])
	key.WriteByte(0)

	return mempoolAirdropProofWithKey(t, index, key.Bytes(), addr, fee)
}

func mempoolAirdropProofWithKey(t *testing.T, index uint32, key []byte,
	addr wire.Address, fee uint64) []byte {

	t.Helper()

	var proof bytes.Buffer
	proof.Write(mempoolU32Item(index))
	proof.WriteByte(0)
	proof.WriteByte(0)
	proof.WriteByte(0)
	if err := wire.WriteVarInt(&proof, 0, uint64(len(key))); err != nil {
		t.Fatalf("WriteVarInt key length: %v", err)
	}
	proof.Write(key)
	proof.WriteByte(addr.Version)
	proof.WriteByte(byte(len(addr.Hash)))
	proof.Write(addr.Hash)
	if err := wire.WriteVarInt(&proof, 0, fee); err != nil {
		t.Fatalf("WriteVarInt fee: %v", err)
	}
	if err := wire.WriteVarInt(&proof, 0, 0); err != nil {
		t.Fatalf("WriteVarInt signature length: %v", err)
	}
	return proof.Bytes()
}

func mempoolWeakRSAKey() []byte {
	var key bytes.Buffer
	key.WriteByte(0)
	var size [2]byte
	binary.LittleEndian.PutUint16(size[:], 128)
	key.Write(size[:])
	modulus := make([]byte, 128)
	modulus[0] = 0x80
	key.Write(modulus)
	key.WriteByte(1)
	key.WriteByte(3)
	key.Write(make([]byte, 32))
	return key.Bytes()
}

func mempoolUpdateCovenant(name string, height uint32) wire.Covenant {
	return wire.Covenant{
		Type: wire.CovenantUpdate,
		Items: [][]byte{
			mempoolHashItem(name),
			mempoolU32Item(height),
			nil,
		},
	}
}

func mempoolTransferCovenant(name string, height uint32,
	addr wire.Address) wire.Covenant {

	return wire.Covenant{
		Type: wire.CovenantTransfer,
		Items: [][]byte{
			mempoolHashItem(name),
			mempoolU32Item(height),
			{addr.Version},
			append([]byte(nil), addr.Hash...),
		},
	}
}

func mempoolHashItem(name string) []byte {
	return mempoolHashBytes(blockchain.HashName([]byte(name)))
}

func mempoolHashBytes(hash chainhash.Hash) []byte {
	item := make([]byte, chainhash.HashSize)
	copy(item, hash[:])
	return item
}

func mempoolU32Item(value uint32) []byte {
	var item [4]byte
	binary.LittleEndian.PutUint32(item[:], value)
	return item[:]
}

// TestSimpleOrphanChain ensures that a simple chain of orphans is handled
// properly.  In particular, it generates a chain of single input, single output
// transactions and inserts them while skipping the first linking transaction so
// they are all orphans.  Finally, it adds the linking transaction and ensures
// the entire orphan chain is moved to the transaction pool.
func TestSimpleOrphanChain(t *testing.T) {
	t.Parallel()

	harness, spendableOuts, err := newPoolHarness(&chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("unable to create test pool: %v", err)
	}
	tc := &testContext{t, harness}

	// Create a chain of transactions rooted with the first spendable output
	// provided by the harness.
	maxOrphans := uint32(harness.txPool.cfg.Policy.MaxOrphanTxs)
	chainedTxns, err := harness.CreateTxChain(spendableOuts[0], maxOrphans+1)
	if err != nil {
		t.Fatalf("unable to create transaction chain: %v", err)
	}

	// Ensure the orphans are accepted (only up to the maximum allowed so
	// none are evicted).
	for _, tx := range chainedTxns[1 : maxOrphans+1] {
		acceptedTxns, err := harness.txPool.ProcessTransaction(tx, true,
			false, 0)
		if err != nil {
			t.Fatalf("ProcessTransaction: failed to accept valid "+
				"orphan %v", err)
		}

		// Ensure no transactions were reported as accepted.
		if len(acceptedTxns) != 0 {
			t.Fatalf("ProcessTransaction: reported %d accepted "+
				"transactions from what should be an orphan",
				len(acceptedTxns))
		}

		// Ensure the transaction is in the orphan pool, is not in the
		// transaction pool, and is reported as available.
		testPoolMembership(tc, tx, true, false)
	}

	// Add the transaction which completes the orphan chain and ensure they
	// all get accepted.  Notice the accept orphans flag is also false here
	// to ensure it has no bearing on whether or not already existing
	// orphans in the pool are linked.
	acceptedTxns, err := harness.txPool.ProcessTransaction(chainedTxns[0],
		false, false, 0)
	if err != nil {
		t.Fatalf("ProcessTransaction: failed to accept valid "+
			"orphan %v", err)
	}
	if len(acceptedTxns) != len(chainedTxns) {
		t.Fatalf("ProcessTransaction: reported accepted transactions "+
			"length does not match expected -- got %d, want %d",
			len(acceptedTxns), len(chainedTxns))
	}
	for _, txD := range acceptedTxns {
		// Ensure the transaction is no longer in the orphan pool, is
		// now in the transaction pool, and is reported as available.
		testPoolMembership(tc, txD.Tx, false, true)
	}
}

// TestOrphanReject ensures that orphans are properly rejected when the allow
// orphans flag is not set on ProcessTransaction.
func TestOrphanReject(t *testing.T) {
	t.Parallel()

	harness, outputs, err := newPoolHarness(&chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("unable to create test pool: %v", err)
	}
	tc := &testContext{t, harness}

	// Create a chain of transactions rooted with the first spendable output
	// provided by the harness.
	maxOrphans := uint32(harness.txPool.cfg.Policy.MaxOrphanTxs)
	chainedTxns, err := harness.CreateTxChain(outputs[0], maxOrphans+1)
	if err != nil {
		t.Fatalf("unable to create transaction chain: %v", err)
	}

	// Ensure orphans are rejected when the allow orphans flag is not set.
	for _, tx := range chainedTxns[1:] {
		acceptedTxns, err := harness.txPool.ProcessTransaction(tx, false,
			false, 0)
		if err == nil {
			t.Fatalf("ProcessTransaction: did not fail on orphan "+
				"%v when allow orphans flag is false", tx.Hash())
		}
		expectedErr := RuleError{}
		if reflect.TypeOf(err) != reflect.TypeOf(expectedErr) {
			t.Fatalf("ProcessTransaction: wrong error got: <%T> %v, "+
				"want: <%T>", err, err, expectedErr)
		}
		code, extracted := extractRejectCode(err)
		if !extracted {
			t.Fatalf("ProcessTransaction: failed to extract reject "+
				"code from error %q", err)
		}
		if code != wire.RejectDuplicate {
			t.Fatalf("ProcessTransaction: unexpected reject code "+
				"-- got %v, want %v", code, wire.RejectDuplicate)
		}

		// Ensure no transactions were reported as accepted.
		if len(acceptedTxns) != 0 {
			t.Fatalf("ProcessTransaction: reported %d accepted "+
				"transactions from failed orphan attempt",
				len(acceptedTxns))
		}

		// Ensure the transaction is not in the orphan pool, not in the
		// transaction pool, and not reported as available
		testPoolMembership(tc, tx, false, false)
	}
}

// TestOrphanEviction ensures that exceeding the maximum number of orphans
// evicts entries to make room for the new ones.
func TestOrphanEviction(t *testing.T) {
	t.Parallel()

	harness, outputs, err := newPoolHarness(&chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("unable to create test pool: %v", err)
	}
	tc := &testContext{t, harness}

	// Create a chain of transactions rooted with the first spendable output
	// provided by the harness that is long enough to be able to force
	// several orphan evictions.
	maxOrphans := uint32(harness.txPool.cfg.Policy.MaxOrphanTxs)
	chainedTxns, err := harness.CreateTxChain(outputs[0], maxOrphans+5)
	if err != nil {
		t.Fatalf("unable to create transaction chain: %v", err)
	}

	// Add enough orphans to exceed the max allowed while ensuring they are
	// all accepted.  This will cause an eviction.
	for _, tx := range chainedTxns[1:] {
		acceptedTxns, err := harness.txPool.ProcessTransaction(tx, true,
			false, 0)
		if err != nil {
			t.Fatalf("ProcessTransaction: failed to accept valid "+
				"orphan %v", err)
		}

		// Ensure no transactions were reported as accepted.
		if len(acceptedTxns) != 0 {
			t.Fatalf("ProcessTransaction: reported %d accepted "+
				"transactions from what should be an orphan",
				len(acceptedTxns))
		}

		// Ensure the transaction is in the orphan pool, is not in the
		// transaction pool, and is reported as available.
		testPoolMembership(tc, tx, true, false)
	}

	// Figure out which transactions were evicted and make sure the number
	// evicted matches the expected number.
	var evictedTxns []*hnsutil.Tx
	for _, tx := range chainedTxns[1:] {
		if !harness.txPool.IsOrphanInPool(tx.Hash()) {
			evictedTxns = append(evictedTxns, tx)
		}
	}
	expectedEvictions := len(chainedTxns) - 1 - int(maxOrphans)
	if len(evictedTxns) != expectedEvictions {
		t.Fatalf("unexpected number of evictions -- got %d, want %d",
			len(evictedTxns), expectedEvictions)
	}

	// Ensure none of the evicted transactions ended up in the transaction
	// pool.
	for _, tx := range evictedTxns {
		testPoolMembership(tc, tx, false, false)
	}
}

// TestBasicOrphanRemoval ensure that orphan removal works as expected when an
// orphan that doesn't exist is removed  both when there is another orphan that
// redeems it and when there is not.
func TestBasicOrphanRemoval(t *testing.T) {
	t.Parallel()

	const maxOrphans = 4
	harness, spendableOuts, err := newPoolHarness(&chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("unable to create test pool: %v", err)
	}
	harness.txPool.cfg.Policy.MaxOrphanTxs = maxOrphans
	tc := &testContext{t, harness}

	// Create a chain of transactions rooted with the first spendable output
	// provided by the harness.
	chainedTxns, err := harness.CreateTxChain(spendableOuts[0], maxOrphans+1)
	if err != nil {
		t.Fatalf("unable to create transaction chain: %v", err)
	}

	// Ensure the orphans are accepted (only up to the maximum allowed so
	// none are evicted).
	for _, tx := range chainedTxns[1 : maxOrphans+1] {
		acceptedTxns, err := harness.txPool.ProcessTransaction(tx, true,
			false, 0)
		if err != nil {
			t.Fatalf("ProcessTransaction: failed to accept valid "+
				"orphan %v", err)
		}

		// Ensure no transactions were reported as accepted.
		if len(acceptedTxns) != 0 {
			t.Fatalf("ProcessTransaction: reported %d accepted "+
				"transactions from what should be an orphan",
				len(acceptedTxns))
		}

		// Ensure the transaction is in the orphan pool, not in the
		// transaction pool, and reported as available.
		testPoolMembership(tc, tx, true, false)
	}

	// Attempt to remove an orphan that has no redeemers and is not present,
	// and ensure the state of all other orphans are unaffected.
	nonChainedOrphanTx, err := harness.CreateSignedTx([]spendableOutput{{
		amount:   hnsutil.Amount(5000000000),
		outPoint: wire.OutPoint{Hash: chainhash.Hash{}, Index: 0},
	}}, 1, 0, false)
	if err != nil {
		t.Fatalf("unable to create signed tx: %v", err)
	}

	harness.txPool.RemoveOrphan(nonChainedOrphanTx)
	testPoolMembership(tc, nonChainedOrphanTx, false, false)
	for _, tx := range chainedTxns[1 : maxOrphans+1] {
		testPoolMembership(tc, tx, true, false)
	}

	// Attempt to remove an orphan that has a existing redeemer but itself
	// is not present and ensure the state of all other orphans (including
	// the one that redeems it) are unaffected.
	harness.txPool.RemoveOrphan(chainedTxns[0])
	testPoolMembership(tc, chainedTxns[0], false, false)
	for _, tx := range chainedTxns[1 : maxOrphans+1] {
		testPoolMembership(tc, tx, true, false)
	}

	// Remove each orphan one-by-one and ensure they are removed as
	// expected.
	for _, tx := range chainedTxns[1 : maxOrphans+1] {
		harness.txPool.RemoveOrphan(tx)
		testPoolMembership(tc, tx, false, false)
	}
}

// TestOrphanChainRemoval ensure that orphan chains (orphans that spend outputs
// from other orphans) are removed as expected.
func TestOrphanChainRemoval(t *testing.T) {
	t.Parallel()

	const maxOrphans = 10
	harness, spendableOuts, err := newPoolHarness(&chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("unable to create test pool: %v", err)
	}
	harness.txPool.cfg.Policy.MaxOrphanTxs = maxOrphans
	tc := &testContext{t, harness}

	// Create a chain of transactions rooted with the first spendable output
	// provided by the harness.
	chainedTxns, err := harness.CreateTxChain(spendableOuts[0], maxOrphans+1)
	if err != nil {
		t.Fatalf("unable to create transaction chain: %v", err)
	}

	// Ensure the orphans are accepted (only up to the maximum allowed so
	// none are evicted).
	for _, tx := range chainedTxns[1 : maxOrphans+1] {
		acceptedTxns, err := harness.txPool.ProcessTransaction(tx, true,
			false, 0)
		if err != nil {
			t.Fatalf("ProcessTransaction: failed to accept valid "+
				"orphan %v", err)
		}

		// Ensure no transactions were reported as accepted.
		if len(acceptedTxns) != 0 {
			t.Fatalf("ProcessTransaction: reported %d accepted "+
				"transactions from what should be an orphan",
				len(acceptedTxns))
		}

		// Ensure the transaction is in the orphan pool, not in the
		// transaction pool, and reported as available.
		testPoolMembership(tc, tx, true, false)
	}

	// Remove the first orphan that starts the orphan chain without the
	// remove redeemer flag set and ensure that only the first orphan was
	// removed.
	harness.txPool.mtx.Lock()
	harness.txPool.removeOrphan(chainedTxns[1], false)
	harness.txPool.mtx.Unlock()
	testPoolMembership(tc, chainedTxns[1], false, false)
	for _, tx := range chainedTxns[2 : maxOrphans+1] {
		testPoolMembership(tc, tx, true, false)
	}

	// Remove the first remaining orphan that starts the orphan chain with
	// the remove redeemer flag set and ensure they are all removed.
	harness.txPool.mtx.Lock()
	harness.txPool.removeOrphan(chainedTxns[2], true)
	harness.txPool.mtx.Unlock()
	for _, tx := range chainedTxns[2 : maxOrphans+1] {
		testPoolMembership(tc, tx, false, false)
	}
}

// TestMultiInputOrphanDoubleSpend ensures that orphans that spend from an
// output that is spend by another transaction entering the pool are removed.
func TestMultiInputOrphanDoubleSpend(t *testing.T) {
	t.Parallel()

	const maxOrphans = 4
	harness, outputs, err := newPoolHarness(&chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("unable to create test pool: %v", err)
	}
	harness.txPool.cfg.Policy.MaxOrphanTxs = maxOrphans
	tc := &testContext{t, harness}

	// Create a chain of transactions rooted with the first spendable output
	// provided by the harness.
	chainedTxns, err := harness.CreateTxChain(outputs[0], maxOrphans+1)
	if err != nil {
		t.Fatalf("unable to create transaction chain: %v", err)
	}

	// Start by adding the orphan transactions from the generated chain
	// except the final one.
	for _, tx := range chainedTxns[1:maxOrphans] {
		acceptedTxns, err := harness.txPool.ProcessTransaction(tx, true,
			false, 0)
		if err != nil {
			t.Fatalf("ProcessTransaction: failed to accept valid "+
				"orphan %v", err)
		}
		if len(acceptedTxns) != 0 {
			t.Fatalf("ProcessTransaction: reported %d accepted transactions "+
				"from what should be an orphan", len(acceptedTxns))
		}
		testPoolMembership(tc, tx, true, false)
	}

	// Ensure a transaction that contains a double spend of the same output
	// as the second orphan that was just added as well as a valid spend
	// from that last orphan in the chain generated above (and is not in the
	// orphan pool) is accepted to the orphan pool.  This must be allowed
	// since it would otherwise be possible for a malicious actor to disrupt
	// tx chains.
	doubleSpendTx, err := harness.CreateSignedTx([]spendableOutput{
		txOutToSpendableOut(chainedTxns[1], 0),
		txOutToSpendableOut(chainedTxns[maxOrphans], 0),
	}, 1, 0, false)
	if err != nil {
		t.Fatalf("unable to create signed tx: %v", err)
	}
	acceptedTxns, err := harness.txPool.ProcessTransaction(doubleSpendTx,
		true, false, 0)
	if err != nil {
		t.Fatalf("ProcessTransaction: failed to accept valid orphan %v",
			err)
	}
	if len(acceptedTxns) != 0 {
		t.Fatalf("ProcessTransaction: reported %d accepted transactions "+
			"from what should be an orphan", len(acceptedTxns))
	}
	testPoolMembership(tc, doubleSpendTx, true, false)

	// Add the transaction which completes the orphan chain and ensure the
	// chain gets accepted.  Notice the accept orphans flag is also false
	// here to ensure it has no bearing on whether or not already existing
	// orphans in the pool are linked.
	//
	// This will cause the shared output to become a concrete spend which
	// will in turn must cause the double spending orphan to be removed.
	acceptedTxns, err = harness.txPool.ProcessTransaction(chainedTxns[0],
		false, false, 0)
	if err != nil {
		t.Fatalf("ProcessTransaction: failed to accept valid tx %v", err)
	}
	if len(acceptedTxns) != maxOrphans {
		t.Fatalf("ProcessTransaction: reported accepted transactions "+
			"length does not match expected -- got %d, want %d",
			len(acceptedTxns), maxOrphans)
	}
	for _, txD := range acceptedTxns {
		// Ensure the transaction is no longer in the orphan pool, is
		// in the transaction pool, and is reported as available.
		testPoolMembership(tc, txD.Tx, false, true)
	}

	// Ensure the double spending orphan is no longer in the orphan pool and
	// was not moved to the transaction pool.
	testPoolMembership(tc, doubleSpendTx, false, false)
}

// TestCheckSpend tests that CheckSpend returns the expected spends found in
// the mempool.
func TestCheckSpend(t *testing.T) {
	t.Parallel()

	harness, outputs, err := newPoolHarness(&chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("unable to create test pool: %v", err)
	}

	// The mempool is empty, so none of the spendable outputs should have a
	// spend there.
	for _, op := range outputs {
		spend := harness.txPool.CheckSpend(op.outPoint)
		if spend != nil {
			t.Fatalf("Unexpeced spend found in pool: %v", spend)
		}
	}

	// Create a chain of transactions rooted with the first spendable
	// output provided by the harness.
	const txChainLength = 5
	chainedTxns, err := harness.CreateTxChain(outputs[0], txChainLength)
	if err != nil {
		t.Fatalf("unable to create transaction chain: %v", err)
	}
	for _, tx := range chainedTxns {
		_, err := harness.txPool.ProcessTransaction(tx, true,
			false, 0)
		if err != nil {
			t.Fatalf("ProcessTransaction: failed to accept "+
				"tx: %v", err)
		}
	}

	// The first tx in the chain should be the spend of the spendable
	// output.
	op := outputs[0].outPoint
	spend := harness.txPool.CheckSpend(op)
	if spend != chainedTxns[0] {
		t.Fatalf("expected %v to be spent by %v, instead "+
			"got %v", op, chainedTxns[0], spend)
	}

	// Now all but the last tx should be spent by the next.
	for i := 0; i < len(chainedTxns)-1; i++ {
		op = wire.OutPoint{
			Hash:  *chainedTxns[i].Hash(),
			Index: 0,
		}
		expSpend := chainedTxns[i+1]
		spend = harness.txPool.CheckSpend(op)
		if spend != expSpend {
			t.Fatalf("expected %v to be spent by %v, instead "+
				"got %v", op, expSpend, spend)
		}
	}

	// The last tx should have no spend.
	op = wire.OutPoint{
		Hash:  *chainedTxns[txChainLength-1].Hash(),
		Index: 0,
	}
	spend = harness.txPool.CheckSpend(op)
	if spend != nil {
		t.Fatalf("Unexpeced spend found in pool: %v", spend)
	}
}

func TestTxPoolObservesAcceptedTransactionsForFeeEstimation(t *testing.T) {
	t.Parallel()

	harness, outputs, err := newPoolHarness(&chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("unable to create test pool: %v", err)
	}

	feeEstimator := NewFeeEstimator(DefaultEstimateFeeMaxRollback, 0)
	feeEstimator.lastKnownHeight = harness.chain.BestHeight()
	harness.txPool.cfg.FeeEstimator = feeEstimator

	tx, err := harness.CreateSignedTx(outputs[:1], 1, 1000, false)
	if err != nil {
		t.Fatalf("unable to create signed tx: %v", err)
	}
	if _, err := harness.txPool.ProcessTransaction(tx, true, false, 0); err != nil {
		t.Fatalf("ProcessTransaction: %v", err)
	}

	txHash := *tx.Hash()
	feeEstimator.mtx.RLock()
	observed := feeEstimator.observed[txHash]
	feeEstimator.mtx.RUnlock()
	if observed == nil {
		t.Fatalf("fee estimator did not observe accepted tx %v", tx.Hash())
	}
	if observed.feeRate <= 0 {
		t.Fatalf("observed fee rate = %v, want positive", observed.feeRate)
	}
}

// TestSignalsReplacement tests that transactions properly signal they can be
// replaced using RBF.
func TestSignalsReplacement(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name               string
		setup              func(ctx *testContext) *hnsutil.Tx
		signalsReplacement bool
	}{
		{
			// Transactions can signal replacement through
			// inheritance if any of its ancestors does.
			name: "non-signaling with unconfirmed non-signaling parent",
			setup: func(ctx *testContext) *hnsutil.Tx {
				coinbase := ctx.addCoinbaseTx(1)

				coinbaseOut := txOutToSpendableOut(coinbase, 0)
				outs := []spendableOutput{coinbaseOut}
				parent := ctx.addSignedTx(outs, 1, 0, false, false)

				parentOut := txOutToSpendableOut(parent, 0)
				outs = []spendableOutput{parentOut}
				return ctx.addSignedTx(outs, 1, 0, false, false)
			},
			signalsReplacement: false,
		},
		{
			// Transactions can signal replacement through
			// inheritance if any of its ancestors does, but they
			// must be unconfirmed.
			name: "non-signaling with confirmed signaling parent",
			setup: func(ctx *testContext) *hnsutil.Tx {
				coinbase := ctx.addCoinbaseTx(1)

				coinbaseOut := txOutToSpendableOut(coinbase, 0)
				outs := []spendableOutput{coinbaseOut}
				parent := ctx.addSignedTx(outs, 1, 0, true, true)

				parentOut := txOutToSpendableOut(parent, 0)
				outs = []spendableOutput{parentOut}
				return ctx.addSignedTx(outs, 1, 0, false, false)
			},
			signalsReplacement: false,
		},
		{
			name: "inherited signaling",
			setup: func(ctx *testContext) *hnsutil.Tx {
				coinbase := ctx.addCoinbaseTx(1)

				// We'll create a chain of transactions
				// A -> B -> C where C is the transaction we'll
				// be checking for replacement signaling. The
				// transaction can signal replacement through
				// any of its ancestors as long as they also
				// signal replacement.
				coinbaseOut := txOutToSpendableOut(coinbase, 0)
				outs := []spendableOutput{coinbaseOut}
				a := ctx.addSignedTx(outs, 1, 0, true, false)

				aOut := txOutToSpendableOut(a, 0)
				outs = []spendableOutput{aOut}
				b := ctx.addSignedTx(outs, 1, 0, false, false)

				bOut := txOutToSpendableOut(b, 0)
				outs = []spendableOutput{bOut}
				return ctx.addSignedTx(outs, 1, 0, false, false)
			},
			signalsReplacement: true,
		},
		{
			name: "explicit signaling",
			setup: func(ctx *testContext) *hnsutil.Tx {
				coinbase := ctx.addCoinbaseTx(1)
				coinbaseOut := txOutToSpendableOut(coinbase, 0)
				outs := []spendableOutput{coinbaseOut}
				return ctx.addSignedTx(outs, 1, 0, true, false)
			},
			signalsReplacement: true,
		},
	}

	for _, testCase := range testCases {
		success := t.Run(testCase.name, func(t *testing.T) {
			// We'll start each test by creating our mempool
			// harness.
			harness, _, err := newPoolHarness(&chaincfg.MainNetParams)
			if err != nil {
				t.Fatalf("unable to create test pool: %v", err)
			}
			ctx := &testContext{t, harness}

			// Each test includes a setup method, which will set up
			// its required dependencies. The transaction returned
			// is the one we'll be using to determine if it signals
			// replacement support.
			tx := testCase.setup(ctx)

			// Each test should match the expected response.
			signalsReplacement := ctx.harness.txPool.signalsReplacement(
				tx, nil,
			)
			if signalsReplacement && !testCase.signalsReplacement {
				ctx.t.Fatalf("expected transaction %v to not "+
					"signal replacement", tx.Hash())
			}
			if !signalsReplacement && testCase.signalsReplacement {
				ctx.t.Fatalf("expected transaction %v to "+
					"signal replacement", tx.Hash())
			}
		})
		if !success {
			break
		}
	}
}

// TestCheckPoolDoubleSpend ensures that the mempool can properly detect
// unconfirmed double spends in the case of replacement and non-replacement
// transactions.
func TestCheckPoolDoubleSpend(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		setup         func(ctx *testContext) *hnsutil.Tx
		isReplacement bool
	}{
		{
			// Transactions that don't double spend any inputs,
			// regardless of whether they signal replacement or not,
			// are valid.
			name: "no double spend",
			setup: func(ctx *testContext) *hnsutil.Tx {
				coinbase := ctx.addCoinbaseTx(1)

				coinbaseOut := txOutToSpendableOut(coinbase, 0)
				outs := []spendableOutput{coinbaseOut}
				parent := ctx.addSignedTx(outs, 1, 0, false, false)

				parentOut := txOutToSpendableOut(parent, 0)
				outs = []spendableOutput{parentOut}
				return ctx.addSignedTx(outs, 2, 0, false, false)
			},
			isReplacement: false,
		},
		{
			// Transactions that don't signal replacement and double
			// spend inputs are invalid.
			name: "non-replacement double spend",
			setup: func(ctx *testContext) *hnsutil.Tx {
				coinbase1 := ctx.addCoinbaseTx(1)
				coinbaseOut1 := txOutToSpendableOut(coinbase1, 0)
				outs := []spendableOutput{coinbaseOut1}
				ctx.addSignedTx(outs, 1, 0, true, false)

				coinbase2 := ctx.addCoinbaseTx(1)
				coinbaseOut2 := txOutToSpendableOut(coinbase2, 0)
				outs = []spendableOutput{coinbaseOut2}
				ctx.addSignedTx(outs, 1, 0, false, false)

				// Create a transaction that spends both
				// coinbase outputs that were spent above. This
				// should be detected as a double spend as one
				// of the transactions doesn't signal
				// replacement.
				outs = []spendableOutput{coinbaseOut1, coinbaseOut2}
				tx, err := ctx.harness.CreateSignedTx(
					outs, 1, 0, false,
				)
				if err != nil {
					ctx.t.Fatalf("unable to create "+
						"transaction: %v", err)
				}

				return tx
			},
			isReplacement: false,
		},
		{
			// Transactions that double spend inputs and signal
			// replacement are invalid if the mempool's policy
			// rejects replacements.
			name: "reject replacement policy",
			setup: func(ctx *testContext) *hnsutil.Tx {
				// Set the mempool's policy to reject
				// replacements. Even if we have a transaction
				// that spends inputs that signal replacement,
				// it should still be rejected.
				ctx.harness.txPool.cfg.Policy.RejectReplacement = true

				coinbase := ctx.addCoinbaseTx(1)

				// Create a replaceable parent that spends the
				// coinbase output.
				coinbaseOut := txOutToSpendableOut(coinbase, 0)
				outs := []spendableOutput{coinbaseOut}
				parent := ctx.addSignedTx(outs, 1, 0, true, false)

				parentOut := txOutToSpendableOut(parent, 0)
				outs = []spendableOutput{parentOut}
				ctx.addSignedTx(outs, 1, 0, false, false)

				// Create another transaction that spends the
				// same coinbase output. Since the original
				// spender of this output, all of its spends
				// should also be conflicts.
				outs = []spendableOutput{coinbaseOut}
				tx, err := ctx.harness.CreateSignedTx(
					outs, 2, 0, false,
				)
				if err != nil {
					ctx.t.Fatalf("unable to create "+
						"transaction: %v", err)
				}

				return tx
			},
			isReplacement: false,
		},
		{
			// Transactions that double spend inputs and signal
			// replacement are valid as long as the mempool's policy
			// accepts them.
			name: "replacement double spend",
			setup: func(ctx *testContext) *hnsutil.Tx {
				coinbase := ctx.addCoinbaseTx(1)

				// Create a replaceable parent that spends the
				// coinbase output.
				coinbaseOut := txOutToSpendableOut(coinbase, 0)
				outs := []spendableOutput{coinbaseOut}
				parent := ctx.addSignedTx(outs, 1, 0, true, false)

				parentOut := txOutToSpendableOut(parent, 0)
				outs = []spendableOutput{parentOut}
				ctx.addSignedTx(outs, 1, 0, false, false)

				// Create another transaction that spends the
				// same coinbase output. Since the original
				// spender of this output, all of its spends
				// should also be conflicts.
				outs = []spendableOutput{coinbaseOut}
				tx, err := ctx.harness.CreateSignedTx(
					outs, 2, 0, false,
				)
				if err != nil {
					ctx.t.Fatalf("unable to create "+
						"transaction: %v", err)
				}

				return tx
			},
			isReplacement: true,
		},
	}

	for _, testCase := range testCases {
		success := t.Run(testCase.name, func(t *testing.T) {
			// We'll start each test by creating our mempool
			// harness.
			harness, _, err := newPoolHarness(&chaincfg.MainNetParams)
			if err != nil {
				t.Fatalf("unable to create test pool: %v", err)
			}
			ctx := &testContext{t, harness}

			// Each test includes a setup method, which will set up
			// its required dependencies. The transaction returned
			// is the one we'll be querying for the expected
			// conflicts.
			tx := testCase.setup(ctx)

			// Ensure that the mempool properly detected the double
			// spend unless this is a replacement transaction.
			isReplacement, err :=
				ctx.harness.txPool.checkPoolDoubleSpend(tx)
			if testCase.isReplacement && err != nil {
				t.Fatalf("expected no error for replacement "+
					"transaction, got: %v", err)
			}
			if isReplacement && !testCase.isReplacement {
				t.Fatalf("expected replacement transaction")
			}
			if !isReplacement && testCase.isReplacement {
				t.Fatalf("expected non-replacement transaction")
			}
		})
		if !success {
			break
		}
	}
}

// TestConflicts ensures that the mempool can properly detect conflicts when
// processing new incoming transactions.
func TestConflicts(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string

		// setup sets up the required dependencies for each test. It
		// returns the transaction we'll check for conflicts and its
		// expected unique conflicts.
		setup func(ctx *testContext) (*hnsutil.Tx, []*hnsutil.Tx)
	}{
		{
			// Create a transaction that would introduce no
			// conflicts in the mempool. This is done by not
			// spending any outputs that are currently being spent
			// within the mempool.
			name: "no conflicts",
			setup: func(ctx *testContext) (*hnsutil.Tx, []*hnsutil.Tx) {
				coinbase := ctx.addCoinbaseTx(1)

				coinbaseOut := txOutToSpendableOut(coinbase, 0)
				outs := []spendableOutput{coinbaseOut}
				parent := ctx.addSignedTx(outs, 1, 0, false, false)

				parentOut := txOutToSpendableOut(parent, 0)
				outs = []spendableOutput{parentOut}
				tx, err := ctx.harness.CreateSignedTx(
					outs, 2, 0, false,
				)
				if err != nil {
					ctx.t.Fatalf("unable to create "+
						"transaction: %v", err)
				}

				return tx, nil
			},
		},
		{
			// Create a transaction that would introduce two
			// conflicts in the mempool by spending two outputs
			// which are each already being spent by a different
			// transaction within the mempool.
			name: "conflicts",
			setup: func(ctx *testContext) (*hnsutil.Tx, []*hnsutil.Tx) {
				coinbase1 := ctx.addCoinbaseTx(1)
				coinbaseOut1 := txOutToSpendableOut(coinbase1, 0)
				outs := []spendableOutput{coinbaseOut1}
				conflict1 := ctx.addSignedTx(
					outs, 1, 0, false, false,
				)

				coinbase2 := ctx.addCoinbaseTx(1)
				coinbaseOut2 := txOutToSpendableOut(coinbase2, 0)
				outs = []spendableOutput{coinbaseOut2}
				conflict2 := ctx.addSignedTx(
					outs, 1, 0, false, false,
				)

				// Create a transaction that spends both
				// coinbase outputs that were spent above.
				outs = []spendableOutput{coinbaseOut1, coinbaseOut2}
				tx, err := ctx.harness.CreateSignedTx(
					outs, 1, 0, false,
				)
				if err != nil {
					ctx.t.Fatalf("unable to create "+
						"transaction: %v", err)
				}

				return tx, []*hnsutil.Tx{conflict1, conflict2}
			},
		},
		{
			// Create a transaction that would introduce two
			// conflicts in the mempool by spending an output
			// already being spent in the mempool by a different
			// transaction. The second conflict stems from spending
			// the transaction that spends the original spender of
			// the output, i.e., a descendant of the original
			// spender.
			name: "descendant conflicts",
			setup: func(ctx *testContext) (*hnsutil.Tx, []*hnsutil.Tx) {
				coinbase := ctx.addCoinbaseTx(1)

				// Create a replaceable parent that spends the
				// coinbase output.
				coinbaseOut := txOutToSpendableOut(coinbase, 0)
				outs := []spendableOutput{coinbaseOut}
				parent := ctx.addSignedTx(outs, 1, 0, false, false)

				parentOut := txOutToSpendableOut(parent, 0)
				outs = []spendableOutput{parentOut}
				child := ctx.addSignedTx(outs, 1, 0, false, false)

				// Create another transaction that spends the
				// same coinbase output. Since the original
				// spender of this output has descendants, they
				// should also be conflicts.
				outs = []spendableOutput{coinbaseOut}
				tx, err := ctx.harness.CreateSignedTx(
					outs, 2, 0, false,
				)
				if err != nil {
					ctx.t.Fatalf("unable to create "+
						"transaction: %v", err)
				}

				return tx, []*hnsutil.Tx{parent, child}
			},
		},
	}

	for _, testCase := range testCases {
		success := t.Run(testCase.name, func(t *testing.T) {
			// We'll start each test by creating our mempool
			// harness.
			harness, _, err := newPoolHarness(&chaincfg.MainNetParams)
			if err != nil {
				t.Fatalf("unable to create test pool: %v", err)
			}
			ctx := &testContext{t, harness}

			// Each test includes a setup method, which will set up
			// its required dependencies. The transaction returned
			// is the one we'll be querying for the expected
			// conflicts.
			tx, conflicts := testCase.setup(ctx)

			// Assert the expected conflicts are returned.
			txConflicts := ctx.harness.txPool.txConflicts(tx)
			if len(txConflicts) != len(conflicts) {
				ctx.t.Fatalf("expected %d conflicts, got %d",
					len(conflicts), len(txConflicts))
			}
			for _, conflict := range conflicts {
				conflictHash := *conflict.Hash()
				if _, ok := txConflicts[conflictHash]; !ok {
					ctx.t.Fatalf("expected %v to be found "+
						"as a conflict", conflictHash)
				}
			}
		})
		if !success {
			break
		}
	}
}

// TestAncestorsDescendants ensures that we can properly retrieve the
// unconfirmed ancestors and descendants of a transaction.
func TestAncestorsDescendants(t *testing.T) {
	t.Parallel()

	// We'll start the test by initializing our mempool harness.
	harness, outputs, err := newPoolHarness(&chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("unable to create test pool: %v", err)
	}
	ctx := &testContext{t, harness}

	// We'll be creating the following chain of unconfirmed transactions:
	//
	//       B ----
	//     /        \
	//   A            E
	//     \        /
	//       C -- D
	//
	// where B and C spend A, D spends C, and E spends B and D. We set up a
	// chain like so to properly detect ancestors and descendants past a
	// single parent/child.
	aInputs := outputs[:1]
	a := ctx.addSignedTx(aInputs, 2, 0, false, false)

	bInputs := []spendableOutput{txOutToSpendableOut(a, 0)}
	b := ctx.addSignedTx(bInputs, 1, 0, false, false)

	cInputs := []spendableOutput{txOutToSpendableOut(a, 1)}
	c := ctx.addSignedTx(cInputs, 1, 0, false, false)

	dInputs := []spendableOutput{txOutToSpendableOut(c, 0)}
	d := ctx.addSignedTx(dInputs, 1, 0, false, false)

	eInputs := []spendableOutput{
		txOutToSpendableOut(b, 0), txOutToSpendableOut(d, 0),
	}
	e := ctx.addSignedTx(eInputs, 1, 0, false, false)

	// We'll be querying for the ancestors of E. We should expect to see all
	// of the transactions that it depends on.
	expectedAncestors := map[chainhash.Hash]struct{}{
		*a.Hash(): {}, *b.Hash(): {},
		*c.Hash(): {}, *d.Hash(): {},
	}
	ancestors := ctx.harness.txPool.txAncestors(e, nil)
	if len(ancestors) != len(expectedAncestors) {
		ctx.t.Fatalf("expected %d ancestors, got %d",
			len(expectedAncestors), len(ancestors))
	}
	for ancestorHash := range ancestors {
		if _, ok := expectedAncestors[ancestorHash]; !ok {
			ctx.t.Fatalf("found unexpected ancestor %v",
				ancestorHash)
		}
	}

	// Then, we'll query for the descendants of A. We should expect to see
	// all of the transactions that depend on it.
	expectedDescendants := map[chainhash.Hash]struct{}{
		*b.Hash(): {}, *c.Hash(): {},
		*d.Hash(): {}, *e.Hash(): {},
	}
	descendants := ctx.harness.txPool.txDescendants(a, nil)
	if len(descendants) != len(expectedDescendants) {
		ctx.t.Fatalf("expected %d descendants, got %d",
			len(expectedDescendants), len(descendants))
	}
	for descendantHash := range descendants {
		if _, ok := expectedDescendants[descendantHash]; !ok {
			ctx.t.Fatalf("found unexpected descendant %v",
				descendantHash)
		}
	}
}

// TestRBF tests the different cases required for a transaction to properly
// replace its conflicts given that they all signal replacement.
func TestRBF(t *testing.T) {
	t.Parallel()

	const defaultFee = hnsutil.DooPerHNS

	testCases := []struct {
		name  string
		setup func(ctx *testContext) (*hnsutil.Tx, []*hnsutil.Tx)
		err   string
	}{
		{
			// A transaction cannot replace another if it doesn't
			// signal replacement.
			name: "non-replaceable parent",
			setup: func(ctx *testContext) (*hnsutil.Tx, []*hnsutil.Tx) {
				coinbase := ctx.addCoinbaseTx(1)

				// Create a transaction that spends the coinbase
				// output and doesn't signal for replacement.
				coinbaseOut := txOutToSpendableOut(coinbase, 0)
				outs := []spendableOutput{coinbaseOut}
				ctx.addSignedTx(outs, 1, defaultFee, false, false)

				// Attempting to create another transaction that
				// spends the same output should fail since the
				// original transaction spending it doesn't
				// signal replacement.
				tx, err := ctx.harness.CreateSignedTx(
					outs, 2, defaultFee, false,
				)
				if err != nil {
					ctx.t.Fatalf("unable to create "+
						"transaction: %v", err)
				}

				return tx, nil
			},
			err: "already spent in mempool",
		},
		{
			// A transaction cannot replace another if we don't
			// allow accepting replacement transactions.
			name: "reject replacement policy",
			setup: func(ctx *testContext) (*hnsutil.Tx, []*hnsutil.Tx) {
				ctx.harness.txPool.cfg.Policy.RejectReplacement = true

				coinbase := ctx.addCoinbaseTx(1)

				// Create a transaction that spends the coinbase
				// output and doesn't signal for replacement.
				coinbaseOut := txOutToSpendableOut(coinbase, 0)
				outs := []spendableOutput{coinbaseOut}
				ctx.addSignedTx(outs, 1, defaultFee, true, false)

				// Attempting to create another transaction that
				// spends the same output should fail since the
				// original transaction spending it doesn't
				// signal replacement.
				tx, err := ctx.harness.CreateSignedTx(
					outs, 2, defaultFee, false,
				)
				if err != nil {
					ctx.t.Fatalf("unable to create "+
						"transaction: %v", err)
				}

				return tx, nil
			},
			err: "already spent in mempool",
		},
		{
			// A transaction cannot replace another if doing so
			// would cause more than 100 transactions being
			// replaced.
			name: "exceeds maximum conflicts",
			setup: func(ctx *testContext) (*hnsutil.Tx, []*hnsutil.Tx) {
				const numDescendants = 100
				coinbaseOuts := make(
					[]spendableOutput, numDescendants,
				)
				for i := 0; i < numDescendants; i++ {
					tx := ctx.addCoinbaseTx(1)
					coinbaseOuts[i] = txOutToSpendableOut(tx, 0)
				}
				parent := ctx.addSignedTx(
					coinbaseOuts, numDescendants,
					defaultFee, true, false,
				)

				// We'll then spend each output of the parent
				// transaction with a distinct transaction.
				for i := uint32(0); i < numDescendants; i++ {
					out := txOutToSpendableOut(parent, i)
					outs := []spendableOutput{out}
					ctx.addSignedTx(
						outs, 1, defaultFee, false, false,
					)
				}

				// We'll then create a replacement transaction
				// by spending one of the coinbase outputs.
				// Replacing the original spender of the
				// coinbase output would evict the maximum
				// number of transactions from the mempool,
				// however, so we should reject it.
				tx, err := ctx.harness.CreateSignedTx(
					coinbaseOuts[:1], 1, defaultFee, false,
				)
				if err != nil {
					ctx.t.Fatalf("unable to create "+
						"transaction: %v", err)
				}

				return tx, nil
			},
			err: "evicts more transactions than permitted",
		},
		{
			// A transaction cannot replace another if the
			// replacement ends up spending an output that belongs
			// to one of the transactions it replaces.
			name: "replacement spends parent transaction",
			setup: func(ctx *testContext) (*hnsutil.Tx, []*hnsutil.Tx) {
				coinbase := ctx.addCoinbaseTx(1)

				// Create a transaction that spends the coinbase
				// output and signals replacement.
				coinbaseOut := txOutToSpendableOut(coinbase, 0)
				outs := []spendableOutput{coinbaseOut}
				parent := ctx.addSignedTx(
					outs, 1, defaultFee, true, false,
				)

				// Attempting to create another transaction that
				// spends it, but also replaces it, should be
				// invalid.
				parentOut := txOutToSpendableOut(parent, 0)
				outs = []spendableOutput{coinbaseOut, parentOut}
				tx, err := ctx.harness.CreateSignedTx(
					outs, 2, defaultFee, false,
				)
				if err != nil {
					ctx.t.Fatalf("unable to create "+
						"transaction: %v", err)
				}

				return tx, nil
			},
			err: "spends parent transaction",
		},
		{
			// A transaction cannot replace another if it has a
			// lower fee rate than any of the transactions it
			// intends to replace.
			name: "insufficient fee rate",
			setup: func(ctx *testContext) (*hnsutil.Tx, []*hnsutil.Tx) {
				coinbase1 := ctx.addCoinbaseTx(1)
				coinbase2 := ctx.addCoinbaseTx(1)

				// We'll create two transactions that each spend
				// one of the coinbase outputs. The first will
				// have a higher fee rate than the second.
				coinbaseOut1 := txOutToSpendableOut(coinbase1, 0)
				outs := []spendableOutput{coinbaseOut1}
				ctx.addSignedTx(outs, 1, defaultFee*2, true, false)

				coinbaseOut2 := txOutToSpendableOut(coinbase2, 0)
				outs = []spendableOutput{coinbaseOut2}
				ctx.addSignedTx(outs, 1, defaultFee, true, false)

				// We'll then create the replacement transaction
				// by spending the coinbase outputs. It will be
				// an invalid one however, since it won't have a
				// higher fee rate than the first transaction.
				outs = []spendableOutput{coinbaseOut1, coinbaseOut2}
				tx, err := ctx.harness.CreateSignedTx(
					outs, 1, defaultFee*2, false,
				)
				if err != nil {
					ctx.t.Fatalf("unable to create "+
						"transaction: %v", err)
				}

				return tx, nil
			},
			err: "insufficient fee rate",
		},
		{
			// A transaction cannot replace another if it doesn't
			// have an absolute greater than the transactions its
			// replacing _plus_ the replacement transaction's
			// minimum relay fee.
			name: "insufficient absolute fee",
			setup: func(ctx *testContext) (*hnsutil.Tx, []*hnsutil.Tx) {
				coinbase := ctx.addCoinbaseTx(1)

				// We'll create a transaction with two outputs
				// and the default fee.
				coinbaseOut := txOutToSpendableOut(coinbase, 0)
				outs := []spendableOutput{coinbaseOut}
				ctx.addSignedTx(outs, 2, defaultFee, true, false)

				// We'll create a replacement transaction with
				// one output, which should cause the
				// transaction's absolute fee to be lower than
				// the above's, so it'll be invalid.
				tx, err := ctx.harness.CreateSignedTx(
					outs, 1, defaultFee, false,
				)
				if err != nil {
					ctx.t.Fatalf("unable to create "+
						"transaction: %v", err)
				}

				return tx, nil
			},
			err: "insufficient absolute fee",
		},
		{
			// A transaction cannot replace another if it introduces
			// a new unconfirmed input that was not already in any
			// of the transactions it's directly replacing.
			name: "spends new unconfirmed input",
			setup: func(ctx *testContext) (*hnsutil.Tx, []*hnsutil.Tx) {
				coinbase1 := ctx.addCoinbaseTx(1)
				coinbase2 := ctx.addCoinbaseTx(1)

				// We'll create two unconfirmed transactions
				// from our coinbase transactions.
				coinbaseOut1 := txOutToSpendableOut(coinbase1, 0)
				outs := []spendableOutput{coinbaseOut1}
				ctx.addSignedTx(outs, 1, defaultFee, true, false)

				coinbaseOut2 := txOutToSpendableOut(coinbase2, 0)
				outs = []spendableOutput{coinbaseOut2}
				newTx := ctx.addSignedTx(
					outs, 1, defaultFee, false, false,
				)

				// We should not be able to accept a replacement
				// transaction that spends an unconfirmed input
				// that was not previously included.
				newTxOut := txOutToSpendableOut(newTx, 0)
				outs = []spendableOutput{coinbaseOut1, newTxOut}
				tx, err := ctx.harness.CreateSignedTx(
					outs, 1, defaultFee*2, false,
				)
				if err != nil {
					ctx.t.Fatalf("unable to create "+
						"transaction: %v", err)
				}

				return tx, nil
			},
			err: "spends new unconfirmed input",
		},
		{
			// A transaction can replace another with a higher fee.
			name: "higher fee",
			setup: func(ctx *testContext) (*hnsutil.Tx, []*hnsutil.Tx) {
				coinbase := ctx.addCoinbaseTx(1)

				// Create a transaction that we'll directly
				// replace.
				coinbaseOut := txOutToSpendableOut(coinbase, 0)
				outs := []spendableOutput{coinbaseOut}
				parent := ctx.addSignedTx(
					outs, 1, defaultFee, true, false,
				)

				// Spend the parent transaction to create a
				// descendant that will be indirectly replaced.
				parentOut := txOutToSpendableOut(parent, 0)
				outs = []spendableOutput{parentOut}
				child := ctx.addSignedTx(
					outs, 1, defaultFee, false, false,
				)

				// The replacement transaction should replace
				// both transactions above since it has a higher
				// fee and doesn't violate any other conditions
				// within the RBF policy.
				outs = []spendableOutput{coinbaseOut}
				tx, err := ctx.harness.CreateSignedTx(
					outs, 1, defaultFee*3, false,
				)
				if err != nil {
					ctx.t.Fatalf("unable to create "+
						"transaction: %v", err)
				}

				return tx, []*hnsutil.Tx{parent, child}
			},
			err: "",
		},
		{
			// A transaction that doesn't signal replacement, can
			// be replaced if the parent signals replacement.
			name: "inherited replacement",
			setup: func(ctx *testContext) (*hnsutil.Tx, []*hnsutil.Tx) {
				coinbase := ctx.addCoinbaseTx(1)

				// Create an initial parent transaction that
				// marks replacement, we won't be replacing
				// this directly however.
				coinbaseOut := txOutToSpendableOut(coinbase, 0)
				outs := []spendableOutput{coinbaseOut}
				parent := ctx.addSignedTx(
					outs, 1, defaultFee, true, false,
				)

				// Now create a transaction that spends that
				// parent transaction, which is marked as NOT
				// being RBF-able.
				parentOut := txOutToSpendableOut(parent, 0)
				parentOuts := []spendableOutput{parentOut}
				childNoReplace := ctx.addSignedTx(
					parentOuts, 1, defaultFee, false, false,
				)

				// Now we'll create another transaction that
				// replaces the *child* only. This should work
				// as the parent has been marked for RBF, even
				// though the child hasn't.
				respendOuts := []spendableOutput{parentOut}
				childReplace, err := ctx.harness.CreateSignedTx(
					respendOuts, 1, defaultFee*3, false,
				)
				if err != nil {
					ctx.t.Fatalf("unable to create child tx: %v", err)
				}

				return childReplace, []*hnsutil.Tx{childNoReplace}
			},
			err: "",
		},
	}

	for _, testCase := range testCases {
		success := t.Run(testCase.name, func(t *testing.T) {
			// We'll start each test by creating our mempool
			// harness.
			harness, _, err := newPoolHarness(&chaincfg.MainNetParams)
			if err != nil {
				t.Fatalf("unable to create test pool: %v", err)
			}

			// We'll enable relay priority to ensure we can properly
			// test fees between replacement transactions and the
			// transactions it replaces.
			harness.txPool.cfg.Policy.DisableRelayPriority = false

			// Each test includes a setup method, which will set up
			// its required dependencies. The transaction returned
			// is the intended replacement, which should replace the
			// expected list of transactions.
			ctx := &testContext{t, harness}
			replacementTx, replacedTxs := testCase.setup(ctx)

			// Attempt to process the replacement transaction. If
			// it's not a valid one, we should see the error
			// expected by the test.
			_, err = ctx.harness.txPool.ProcessTransaction(
				replacementTx, false, false, 0,
			)
			if testCase.err == "" && err != nil {
				ctx.t.Fatalf("expected no error when "+
					"processing replacement transaction, "+
					"got: %v", err)
			}
			if testCase.err != "" && err == nil {
				ctx.t.Fatalf("expected error when processing "+
					"replacement transaction: %v",
					testCase.err)
			}
			if testCase.err != "" && err != nil {
				if !strings.Contains(err.Error(), testCase.err) {
					ctx.t.Fatalf("expected error: %v\n"+
						"got: %v", testCase.err, err)
				}
			}

			// If the replacement transaction is valid, we'll check
			// that it has been included in the mempool and its
			// conflicts have been removed. Otherwise, the conflicts
			// should remain in the mempool.
			valid := testCase.err == ""
			for _, tx := range replacedTxs {
				testPoolMembership(ctx, tx, false, !valid)
			}
			testPoolMembership(ctx, replacementTx, false, valid)
		})
		if !success {
			break
		}
	}
}
