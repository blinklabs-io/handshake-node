// Copyright (c) 2014-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package coinset_test

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/hnsutil"
	"github.com/blinklabs-io/handshake-node/hnsutil/coinset"
	"github.com/blinklabs-io/handshake-node/wire"
)

type TestCoin struct {
	TxHash     *chainhash.Hash
	TxIndex    uint32
	TxValue    hnsutil.Amount
	TxNumConfs int64
}

func (c *TestCoin) Hash() *chainhash.Hash { return c.TxHash }
func (c *TestCoin) Index() uint32         { return c.TxIndex }
func (c *TestCoin) Value() hnsutil.Amount { return c.TxValue }
func (c *TestCoin) PkScript() []byte      { return nil }
func (c *TestCoin) NumConfs() int64       { return c.TxNumConfs }
func (c *TestCoin) ValueAge() int64       { return int64(c.TxValue) * c.TxNumConfs }

func NewCoin(index int64, value hnsutil.Amount, numConfs int64) coinset.Coin {
	h := sha256.New()
	_, _ = h.Write([]byte(fmt.Sprintf("%d", index)))
	hash, _ := chainhash.NewHash(h.Sum(nil))
	c := &TestCoin{
		TxHash:     hash,
		TxIndex:    0,
		TxValue:    value,
		TxNumConfs: numConfs,
	}
	return coinset.Coin(c)
}

type coinSelectTest struct {
	selector      coinset.CoinSelector
	inputCoins    []coinset.Coin
	targetValue   hnsutil.Amount
	expectedCoins []coinset.Coin
	expectedError error
}

func testCoinSelector(tests []coinSelectTest, t *testing.T) {
	for testIndex, test := range tests {
		cs, err := test.selector.CoinSelect(test.targetValue, test.inputCoins)
		if err != test.expectedError {
			t.Errorf("[%d] expected a different error: got=%v, expected=%v", testIndex, err, test.expectedError)
			continue
		}
		if test.expectedCoins != nil {
			if cs == nil {
				t.Errorf("[%d] expected non-nil coinset", testIndex)
				continue
			}
			coins := cs.Coins()
			if len(coins) != len(test.expectedCoins) {
				t.Errorf("[%d] expected different number of coins: got=%d, expected=%d", testIndex, len(coins), len(test.expectedCoins))
				continue
			}
			for n := 0; n < len(test.expectedCoins); n++ {
				if coins[n] != test.expectedCoins[n] {
					t.Errorf("[%d] expected different coins at coin index %d: got=%#v, expected=%#v", testIndex, n, coins[n], test.expectedCoins[n])
					continue
				}
			}
			coinSet := coinset.NewCoinSet(coins)
			if coinSet.TotalValue() < test.targetValue {
				t.Errorf("[%d] targetValue not satistifed", testIndex)
				continue
			}
		}
	}
}

var coins = []coinset.Coin{
	NewCoin(1, 100000000, 1),
	NewCoin(2, 10000000, 20),
	NewCoin(3, 50000000, 0),
	NewCoin(4, 25000000, 6),
}

func TestCoinSet(t *testing.T) {
	cs := coinset.NewCoinSet(nil)
	if cs.PopCoin() != nil {
		t.Error("Expected popCoin of empty to be nil")
	}
	if cs.ShiftCoin() != nil {
		t.Error("Expected shiftCoin of empty to be nil")
	}

	cs.PushCoin(coins[0])
	cs.PushCoin(coins[1])
	cs.PushCoin(coins[2])
	if cs.PopCoin() != coins[2] {
		t.Error("Expected third coin")
	}
	if cs.ShiftCoin() != coins[0] {
		t.Error("Expected first coin")
	}

	mtx := coinset.NewMsgTxWithInputCoins(wire.TxVersion, cs)
	if len(mtx.TxIn) != 1 {
		t.Errorf("Expected only 1 TxIn, got %d", len(mtx.TxIn))
	}
	op := mtx.TxIn[0].PreviousOutPoint
	if !op.Hash.IsEqual(coins[1].Hash()) || op.Index != coins[1].Index() {
		t.Errorf("Expected the second coin to be added as input to mtx")
	}
}

var minIndexSelectors = []coinset.MinIndexCoinSelector{
	{MaxInputs: 10, MinChangeAmount: 10000},
	{MaxInputs: 2, MinChangeAmount: 10000},
}

var minIndexTests = []coinSelectTest{
	{minIndexSelectors[0], coins, coins[0].Value() - minIndexSelectors[0].MinChangeAmount, []coinset.Coin{coins[0]}, nil},
	{minIndexSelectors[0], coins, coins[0].Value() - minIndexSelectors[0].MinChangeAmount + 1, []coinset.Coin{coins[0], coins[1]}, nil},
	{minIndexSelectors[0], coins, 100000000, []coinset.Coin{coins[0]}, nil},
	{minIndexSelectors[0], coins, 110000000, []coinset.Coin{coins[0], coins[1]}, nil},
	{minIndexSelectors[0], coins, 140000000, []coinset.Coin{coins[0], coins[1], coins[2]}, nil},
	{minIndexSelectors[0], coins, 200000000, nil, coinset.ErrCoinsNoSelectionAvailable},
	{minIndexSelectors[1], coins, 10000000, []coinset.Coin{coins[0]}, nil},
	{minIndexSelectors[1], coins, 110000000, []coinset.Coin{coins[0], coins[1]}, nil},
	{minIndexSelectors[1], coins, 140000000, nil, coinset.ErrCoinsNoSelectionAvailable},
}

func TestMinIndexSelector(t *testing.T) {
	testCoinSelector(minIndexTests, t)
}

var minNumberSelectors = []coinset.MinNumberCoinSelector{
	{MaxInputs: 10, MinChangeAmount: 10000},
	{MaxInputs: 2, MinChangeAmount: 10000},
}

var minNumberTests = []coinSelectTest{
	{minNumberSelectors[0], coins, coins[0].Value() - minNumberSelectors[0].MinChangeAmount, []coinset.Coin{coins[0]}, nil},
	{minNumberSelectors[0], coins, coins[0].Value() - minNumberSelectors[0].MinChangeAmount + 1, []coinset.Coin{coins[0], coins[2]}, nil},
	{minNumberSelectors[0], coins, 100000000, []coinset.Coin{coins[0]}, nil},
	{minNumberSelectors[0], coins, 110000000, []coinset.Coin{coins[0], coins[2]}, nil},
	{minNumberSelectors[0], coins, 160000000, []coinset.Coin{coins[0], coins[2], coins[3]}, nil},
	{minNumberSelectors[0], coins, 184990000, []coinset.Coin{coins[0], coins[2], coins[3], coins[1]}, nil},
	{minNumberSelectors[0], coins, 184990001, nil, coinset.ErrCoinsNoSelectionAvailable},
	{minNumberSelectors[0], coins, 200000000, nil, coinset.ErrCoinsNoSelectionAvailable},
	{minNumberSelectors[1], coins, 10000000, []coinset.Coin{coins[0]}, nil},
	{minNumberSelectors[1], coins, 110000000, []coinset.Coin{coins[0], coins[2]}, nil},
	{minNumberSelectors[1], coins, 140000000, []coinset.Coin{coins[0], coins[2]}, nil},
}

func TestMinNumberSelector(t *testing.T) {
	testCoinSelector(minNumberTests, t)
}

var maxValueAgeSelectors = []coinset.MaxValueAgeCoinSelector{
	{MaxInputs: 10, MinChangeAmount: 10000},
	{MaxInputs: 2, MinChangeAmount: 10000},
}

var maxValueAgeTests = []coinSelectTest{
	{maxValueAgeSelectors[0], coins, 100000, []coinset.Coin{coins[1]}, nil},
	{maxValueAgeSelectors[0], coins, 10000000, []coinset.Coin{coins[1]}, nil},
	{maxValueAgeSelectors[0], coins, 10000001, []coinset.Coin{coins[1], coins[3]}, nil},
	{maxValueAgeSelectors[0], coins, 35000000, []coinset.Coin{coins[1], coins[3]}, nil},
	{maxValueAgeSelectors[0], coins, 135000000, []coinset.Coin{coins[1], coins[3], coins[0]}, nil},
	{maxValueAgeSelectors[0], coins, 185000000, []coinset.Coin{coins[1], coins[3], coins[0], coins[2]}, nil},
	{maxValueAgeSelectors[0], coins, 200000000, nil, coinset.ErrCoinsNoSelectionAvailable},
	{maxValueAgeSelectors[1], coins, 40000000, nil, coinset.ErrCoinsNoSelectionAvailable},
	{maxValueAgeSelectors[1], coins, 35000000, []coinset.Coin{coins[1], coins[3]}, nil},
	{maxValueAgeSelectors[1], coins, 34990001, nil, coinset.ErrCoinsNoSelectionAvailable},
}

func TestMaxValueAgeSelector(t *testing.T) {
	testCoinSelector(maxValueAgeTests, t)
}

var minPrioritySelectors = []coinset.MinPriorityCoinSelector{
	{MaxInputs: 10, MinChangeAmount: 10000, MinAvgValueAgePerInput: 100000000},
	{MaxInputs: 02, MinChangeAmount: 10000, MinAvgValueAgePerInput: 200000000},
	{MaxInputs: 02, MinChangeAmount: 10000, MinAvgValueAgePerInput: 150000000},
	{MaxInputs: 03, MinChangeAmount: 10000, MinAvgValueAgePerInput: 150000000},
	{MaxInputs: 10, MinChangeAmount: 10000, MinAvgValueAgePerInput: 1000000000},
	{MaxInputs: 10, MinChangeAmount: 10000, MinAvgValueAgePerInput: 175000000},
	{MaxInputs: 02, MinChangeAmount: 10000, MinAvgValueAgePerInput: 125000000},
}

var connectedCoins = []coinset.Coin{coins[0], coins[1], coins[3]}

var minPriorityTests = []coinSelectTest{
	{minPrioritySelectors[0], connectedCoins, 100000000, []coinset.Coin{coins[0]}, nil},
	{minPrioritySelectors[0], connectedCoins, 125000000, []coinset.Coin{coins[0], coins[3]}, nil},
	{minPrioritySelectors[0], connectedCoins, 135000000, []coinset.Coin{coins[0], coins[3], coins[1]}, nil},
	{minPrioritySelectors[0], connectedCoins, 140000000, nil, coinset.ErrCoinsNoSelectionAvailable},
	{minPrioritySelectors[1], connectedCoins, 100000000, nil, coinset.ErrCoinsNoSelectionAvailable},
	{minPrioritySelectors[1], connectedCoins, 10000000, []coinset.Coin{coins[1]}, nil},
	{minPrioritySelectors[1], connectedCoins, 100000000, nil, coinset.ErrCoinsNoSelectionAvailable},
	{minPrioritySelectors[2], connectedCoins, 11000000, []coinset.Coin{coins[3]}, nil},
	{minPrioritySelectors[2], connectedCoins, 25000001, []coinset.Coin{coins[3], coins[1]}, nil},
	{minPrioritySelectors[3], connectedCoins, 25000001, []coinset.Coin{coins[3], coins[1], coins[0]}, nil},
	{minPrioritySelectors[3], connectedCoins, 100000000, []coinset.Coin{coins[3], coins[1], coins[0]}, nil},
	{minPrioritySelectors[3], []coinset.Coin{coins[1], coins[2]}, 10000000, []coinset.Coin{coins[1]}, nil},
	{minPrioritySelectors[4], connectedCoins, 1, nil, coinset.ErrCoinsNoSelectionAvailable},
	{minPrioritySelectors[5], connectedCoins, 20000000, []coinset.Coin{coins[1], coins[3]}, nil},
	{minPrioritySelectors[6], connectedCoins, 25000000, []coinset.Coin{coins[3], coins[0]}, nil},
}

func TestMinPrioritySelector(t *testing.T) {
	testCoinSelector(minPriorityTests, t)
}

func TestSimpleCoin(t *testing.T) {
	const confirmations = int64(7)
	addresses := []wire.Address{
		{Version: 0, Hash: bytes.Repeat([]byte{0x11}, 20)},
		{Version: 0, Hash: bytes.Repeat([]byte{0x22}, 32)},
	}
	values := []hnsutil.Amount{3_500_000, 8_750_000}
	msgTx := wire.NewMsgTx(wire.TxVersion)
	for i := range addresses {
		msgTx.AddTxOut(wire.NewTxOut(
			int64(values[i]),
			addresses[i],
			wire.Covenant{},
		))
	}
	tx := hnsutil.NewTx(msgTx)

	for i := range msgTx.TxOut {
		coin := &coinset.SimpleCoin{
			Tx:         tx,
			TxIndex:    uint32(i),
			TxNumConfs: confirmations,
		}

		if !coin.Hash().IsEqual(tx.Hash()) {
			t.Fatalf("output %d: Hash returned a different transaction hash", i)
		}
		if coin.Index() != uint32(i) {
			t.Fatalf("output %d: Index = %d", i, coin.Index())
		}
		if coin.Value() != values[i] {
			t.Fatalf("output %d: Value = %d, want %d",
				i, coin.Value(), values[i])
		}
		if !bytes.Equal(coin.PkScript(), addresses[i].WitnessProgram()) {
			t.Fatalf("output %d: PkScript = %x, want %x",
				i, coin.PkScript(), addresses[i].WitnessProgram())
		}
		if coin.NumConfs() != confirmations {
			t.Fatalf("output %d: NumConfs = %d, want %d",
				i, coin.NumConfs(), confirmations)
		}
		wantValueAge := int64(values[i]) * confirmations
		if coin.ValueAge() != wantValueAge {
			t.Fatalf("output %d: ValueAge = %d, want %d",
				i, coin.ValueAge(), wantValueAge)
		}
	}
}
