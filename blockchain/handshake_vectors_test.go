// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/blinklabs-io/handshake-node/chaincfg"
	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/hnsutil"
	"github.com/blinklabs-io/handshake-node/txscript"
	"github.com/blinklabs-io/handshake-node/wire"
)

func loadHandshakeRawBlock(t *testing.T, name string) *hnsutil.Block {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join("testdata", "handshake", name))
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", name, err)
	}
	block, err := hnsutil.NewBlockFromBytes(raw)
	if err != nil {
		t.Fatalf("NewBlockFromBytes(%s): %v", name, err)
	}
	return block
}

func TestHandshakeRawBlockMerkleRootVectors(t *testing.T) {
	tests := []struct {
		name        string
		merkleRoot  string
		witnessRoot string
	}{
		{
			name:        "block_0.raw",
			merkleRoot:  "8e4c9756fef2ad10375f360e0560fcc7587eb5223ddf8cd7c7e06e60a1140b15",
			witnessRoot: "1a2c60b9439206938f8d7823782abdb8b211a57431e9c9b6a6365d8d42893351",
		},
		{
			name:        "block_4.raw",
			merkleRoot:  "cbbd330a7c25573789764181a792e40335c09263e2171e60cb476fac4df2ddeb",
			witnessRoot: "99a6e9b87498807c9787fd0731d75e8c6dd018ba0aacc731dc4a42d54ccec618",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			block := loadHandshakeRawBlock(t, test.name)
			header := &block.MsgBlock().Header

			wantMerkle := mustRawHash(t, test.merkleRoot)
			wantWitness := mustRawHash(t, test.witnessRoot)
			if header.MerkleRoot != wantMerkle {
				t.Fatalf("fixture merkle root = %s, want %s",
					header.MerkleRoot, wantMerkle)
			}
			if header.WitnessRoot != wantWitness {
				t.Fatalf("fixture witness root = %s, want %s",
					header.WitnessRoot, wantWitness)
			}

			gotMerkle := CalcMerkleRoot(block.Transactions(), false)
			if gotMerkle != wantMerkle {
				t.Fatalf("CalcMerkleRoot = %s, want %s",
					gotMerkle, wantMerkle)
			}
			gotWitness := CalcMerkleRoot(block.Transactions(), true)
			if gotWitness != wantWitness {
				t.Fatalf("CalcWitnessRoot = %s, want %s",
					gotWitness, wantWitness)
			}
		})
	}
}

func TestHandshakeMalformedBlockRejection(t *testing.T) {
	block := loadHandshakeRawBlock(t, "block_0.raw")
	timeSource := NewMedianTime()

	if err := checkBlockSanity(block, chaincfg.MainNetParams.PowLimit,
		timeSource, BFNoPoWCheck); err != nil {

		t.Fatalf("valid genesis CheckBlockSanity: %v", err)
	}

	badMerkle := block.MsgBlock().Copy()
	badMerkle.Transactions[0].TxOut[0].Value++
	err := checkBlockSanity(hnsutil.NewBlock(badMerkle),
		chaincfg.MainNetParams.PowLimit, timeSource, BFNoPoWCheck)
	if rerr, ok := err.(RuleError); !ok ||
		rerr.ErrorCode != ErrBadMerkleRoot {

		t.Fatalf("bad merkle error = %v, want %v", err, ErrBadMerkleRoot)
	}

	noTx := block.MsgBlock().Copy()
	noTx.ClearTransactions()
	err = checkBlockSanity(hnsutil.NewBlock(noTx),
		chaincfg.MainNetParams.PowLimit, timeSource, BFNoPoWCheck)
	if rerr, ok := err.(RuleError); !ok ||
		rerr.ErrorCode != ErrNoTransactions {

		t.Fatalf("no tx error = %v, want %v", err, ErrNoTransactions)
	}

	secondCoinbase := block.MsgBlock().Copy()
	secondCoinbase.Transactions = append(secondCoinbase.Transactions,
		secondCoinbase.Transactions[0].Copy())
	err = checkBlockSanity(hnsutil.NewBlock(secondCoinbase),
		chaincfg.MainNetParams.PowLimit, timeSource, BFNoPoWCheck)
	if rerr, ok := err.(RuleError); !ok ||
		rerr.ErrorCode != ErrMultipleCoinbases {

		t.Fatalf("second coinbase error = %v, want %v", err,
			ErrMultipleCoinbases)
	}
}

func extendSyntheticHeaders(chain *BlockChain, bits uint32,
	spacing time.Duration, count int) *blockNode {

	node := chain.bestChain.Tip()
	blockTime := node.Header().Timestamp
	for i := 0; i < count; i++ {
		blockTime = blockTime.Add(spacing)
		node = newFakeNode(node, 0, bits, blockTime)
		chain.index.AddNode(node)
		chain.bestChain.SetTip(node)
	}
	return node
}

func TestMainNetDifficultyTransitionVectors(t *testing.T) {
	const (
		powLimitBits = uint32(0x1c00ffff)
		fastBits     = uint32(0x1b3fffc0)
	)

	targetSpacing := chaincfg.MainNetParams.TargetTimePerBlock

	tests := []struct {
		name    string
		bits    uint32
		count   int
		spacing time.Duration
		want    uint32
	}{
		{
			name:    "before first rolling retarget",
			bits:    powLimitBits,
			count:   145,
			spacing: targetSpacing,
			want:    powLimitBits,
		},
		{
			name:    "target spacing unchanged",
			bits:    powLimitBits,
			count:   146,
			spacing: targetSpacing,
			want:    powLimitBits,
		},
		{
			name:    "minimum timespan clamp",
			bits:    powLimitBits,
			count:   146,
			spacing: time.Second,
			want:    fastBits,
		},
		{
			name:    "maximum timespan clamps to pow limit",
			bits:    fastBits,
			count:   146,
			spacing: targetSpacing * 4,
			want:    powLimitBits,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			chain := newFakeChain(&chaincfg.MainNetParams)
			tip := extendSyntheticHeaders(chain, test.bits,
				test.spacing, test.count)

			nextTime := time.Unix(tip.Timestamp(), 0).Add(test.spacing)
			got, err := calcNextRequiredDifficulty(tip, nextTime, chain)
			if err != nil {
				t.Fatalf("calcNextRequiredDifficulty: %v", err)
			}
			if got != test.want {
				t.Fatalf("difficulty bits = 0x%08x, want 0x%08x",
					got, test.want)
			}
		})
	}
}

func TestHandshakeBlockVersionBits(t *testing.T) {
	mainChain := newFakeChain(&chaincfg.MainNetParams)
	got, err := mainChain.calcNextBlockVersion(mainChain.bestChain.Tip())
	if err != nil {
		t.Fatalf("mainnet calcNextBlockVersion: %v", err)
	}
	if got != 0 {
		t.Fatalf("mainnet next version = 0x%08x, want 0", uint32(got))
	}

	regChain := newFakeChain(&chaincfg.RegressionNetParams)
	extendSyntheticHeaders(regChain, chaincfg.RegressionNetParams.PowLimitBits,
		chaincfg.RegressionNetParams.TargetTimePerBlock,
		int(chaincfg.RegressionNetParams.MinerConfirmationWindow))
	got, err = regChain.calcNextBlockVersion(regChain.bestChain.Tip())
	if err != nil {
		t.Fatalf("regtest calcNextBlockVersion: %v", err)
	}

	const wantRegtest = uint32(0x10400003)
	if uint32(got) != wantRegtest {
		t.Fatalf("regtest next version = 0x%08x, want 0x%08x",
			uint32(got), wantRegtest)
	}
	if uint32(got)&0xe0000000 != 0 {
		t.Fatalf("regtest next version includes Bitcoin top bits: 0x%08x",
			uint32(got))
	}
}

func TestHandshakeMandatoryScriptFlags(t *testing.T) {
	flags := mandatoryScriptVerifyFlags()
	required := []txscript.ScriptFlags{
		txscript.ScriptVerifyCheckLockTimeVerify,
		txscript.ScriptVerifyCheckSequenceVerify,
		txscript.ScriptVerifyDERSignatures,
		txscript.ScriptVerifyLowS,
		txscript.ScriptVerifyMinimalData,
		txscript.ScriptVerifyMinimalIf,
		txscript.ScriptVerifyNullFail,
		txscript.ScriptVerifyStrictEncoding,
		txscript.ScriptVerifyWitness,
	}
	for _, flag := range required {
		if flags&flag == 0 {
			t.Fatalf("mandatory script flags missing %v", flag)
		}
	}
	if flags&txscript.ScriptVerifyTaproot != 0 {
		t.Fatal("mandatory script flags must not enable Taproot")
	}
}

func TestSequenceLocksActiveWithoutBIP9Deployment(t *testing.T) {
	chain := newFakeChain(&chaincfg.MainNetParams)
	tip := extendSyntheticHeaders(chain, chaincfg.MainNetParams.PowLimitBits,
		chaincfg.MainNetParams.TargetTimePerBlock, 10)

	targetTx := hnsutil.NewTx(&wire.MsgTx{
		TxOut: []*wire.TxOut{{
			Value: 10,
		}},
	})
	utxoView := NewUtxoViewpoint()
	utxoView.AddTxOuts(targetTx, 6)
	utxoView.SetBestHash(&tip.hash)

	spend := wire.NewMsgTx(2)
	spend.AddTxIn(wire.NewTxIn(&wire.OutPoint{
		Hash:  *targetTx.Hash(),
		Index: 0,
	}, LockTimeToSequence(false, 5), nil))

	sequenceLock, err := chain.calcSequenceLock(tip, hnsutil.NewTx(spend),
		utxoView, false)
	if err != nil {
		t.Fatalf("calcSequenceLock: %v", err)
	}
	if sequenceLock.BlockHeight != 10 {
		t.Fatalf("sequence lock block height = %d, want 10",
			sequenceLock.BlockHeight)
	}
	medianTime := CalcPastMedianTime(tip)
	if SequenceLockActive(sequenceLock, 10, medianTime) {
		t.Fatal("sequence lock active at locked height")
	}
	if !SequenceLockActive(sequenceLock, 11, medianTime) {
		t.Fatal("sequence lock inactive after locked height")
	}
}

func TestCoinbaseSubsidyUtxoHeightVector(t *testing.T) {
	height := int32(170000)
	subsidy := CalcBlockSubsidy(height, &chaincfg.MainNetParams)

	coinbaseOutpoint := wire.NewOutPoint(&chainhash.Hash{}, ^uint32(0))
	coinbase := wire.NewMsgTx(0)
	coinbase.LockTime = uint32(height)
	coinbase.AddTxIn(wire.NewTxIn(coinbaseOutpoint,
		wire.MaxTxInSequenceNum, wire.TxWitness{[]byte{0x51, 0x51}}))
	coinbase.AddTxOut(wire.NewTxOut(subsidy, wire.Address{
		Version: 0,
		Hash:    bytes20(0x01),
	}, wire.Covenant{}))

	view := NewUtxoViewpoint()
	tx := hnsutil.NewTx(coinbase)
	view.AddTxOuts(tx, height)

	entry := view.LookupEntry(wire.OutPoint{Hash: *tx.Hash(), Index: 0})
	if entry == nil {
		t.Fatal("coinbase utxo missing")
	}
	if !entry.IsCoinBase() {
		t.Fatal("coinbase utxo did not retain coinbase flag")
	}
	if entry.BlockHeight() != height {
		t.Fatalf("coinbase utxo height = %d, want %d",
			entry.BlockHeight(), height)
	}
	if entry.Amount() != subsidy {
		t.Fatalf("coinbase utxo amount = %d, want %d",
			entry.Amount(), subsidy)
	}

	spend := wire.NewMsgTx(2)
	spend.AddTxIn(wire.NewTxIn(&wire.OutPoint{
		Hash:  *tx.Hash(),
		Index: 0,
	}, wire.MaxTxInSequenceNum, nil))
	spend.AddTxOut(wire.NewTxOut(subsidy, wire.Address{
		Version: 0,
		Hash:    bytes20(0x02),
	}, wire.Covenant{}))

	_, err := CheckTransactionInputs(hnsutil.NewTx(spend), height+99, view,
		&chaincfg.MainNetParams)
	if rerr, ok := err.(RuleError); !ok || rerr.ErrorCode != ErrImmatureSpend {
		t.Fatalf("immature spend error = %v, want %v", err, ErrImmatureSpend)
	}

	if _, err := CheckTransactionInputs(hnsutil.NewTx(spend), height+100,
		view, &chaincfg.MainNetParams); err != nil {

		t.Fatalf("mature spend: %v", err)
	}
}

func bytes20(fill byte) []byte {
	buf := make([]byte, 20)
	for i := range buf {
		buf[i] = fill
	}
	return buf
}
