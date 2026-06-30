// Copyright (c) 2013-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"math/big"
	"time"

	"github.com/blinklabs-io/handshake-node/blockchain/internal/workmath"
	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
)

// HashToBig converts a chainhash.Hash into a big.Int that can be used to
// perform math comparisons.
func HashToBig(hash *chainhash.Hash) *big.Int {
	return workmath.HashToBig(hash)
}

// CompactToBig converts a compact representation of a whole number N to an
// unsigned 32-bit number.  The representation is similar to IEEE754 floating
// point numbers.
//
// Like IEEE754 floating point, there are three basic components: the sign,
// the exponent, and the mantissa.  They are broken out as follows:
//
// - the most significant 8 bits represent the unsigned base 256 exponent
// - bit 23 (the 24th bit) represents the sign bit
// - the least significant 23 bits represent the mantissa
//
//	-------------------------------------------------
//	|   Exponent     |    Sign    |    Mantissa     |
//	-------------------------------------------------
//	| 8 bits [31-24] | 1 bit [23] | 23 bits [22-00] |
//	-------------------------------------------------
//
// The formula to calculate N is:
//
//	N = (-1^sign) * mantissa * 256^(exponent-3)
//
// This compact form is only used in bitcoin to encode unsigned 256-bit numbers
// which represent difficulty targets, thus there really is not a need for a
// sign bit, but it is implemented here to stay consistent with bitcoind.
func CompactToBig(compact uint32) *big.Int {
	return workmath.CompactToBig(compact)
}

// BigToCompact converts a whole number N to a compact representation using
// an unsigned 32-bit number.  The compact representation only provides 23 bits
// of precision, so values larger than (2^23 - 1) only encode the most
// significant digits of the number.  See CompactToBig for details.
func BigToCompact(n *big.Int) uint32 {
	return workmath.BigToCompact(n)
}

// CalcWork calculates a work value from difficulty bits.  Bitcoin increases
// the difficulty for generating a block by decreasing the value which the
// generated hash must be less than.  This difficulty target is stored in each
// block header using a compact representation as described in the documentation
// for CompactToBig.  The main chain is selected by choosing the chain that has
// the most proof of work (highest difficulty).  Since a lower target difficulty
// value equates to higher actual difficulty, the work value which will be
// accumulated must be the inverse of the difficulty.  Also, in order to avoid
// potential division by zero and really small floating point numbers, the
// result adds 1 to the denominator and multiplies the numerator by 2^256.
func CalcWork(bits uint32) *big.Int {
	return workmath.CalcWork(bits)
}

// calcEasiestDifficulty calculates the easiest possible difficulty that a block
// can have given starting difficulty bits and a duration.  It is mainly used to
// verify that claimed proof of work by a block is sane as compared to a
// known good checkpoint.
func (b *BlockChain) calcEasiestDifficulty(bits uint32, duration time.Duration) uint32 {
	// Convert types used in the calculations below.
	durationVal := int64(duration / time.Second)
	adjustmentFactor := big.NewInt(b.chainParams.RetargetAdjustmentFactor)

	// The test network rules allow minimum difficulty blocks after more
	// than twice the desired amount of time needed to generate a block has
	// elapsed.
	if b.chainParams.ReduceMinDifficulty {
		reductionTime := int64(b.chainParams.MinDiffReductionTime /
			time.Second)
		if durationVal > reductionTime {
			return b.chainParams.PowLimitBits
		}
	}

	// Since easier difficulty equates to higher numbers, the easiest
	// difficulty for a given duration is the largest value possible given
	// the number of retargets for the duration and starting difficulty
	// multiplied by the max adjustment factor.
	newTarget := CompactToBig(bits)
	for durationVal > 0 && newTarget.Cmp(b.chainParams.PowLimit) < 0 {
		newTarget.Mul(newTarget, adjustmentFactor)
		durationVal -= b.maxRetargetTimespan
	}

	// Limit new value to the proof of work limit.
	if newTarget.Cmp(b.chainParams.PowLimit) > 0 {
		newTarget.Set(b.chainParams.PowLimit)
	}

	return BigToCompact(newTarget)
}

// suitableBlock returns the median timestamp block among node and its two
// parents, matching Handshake's difficulty retarget endpoint selection.
func suitableBlock(node HeaderCtx) HeaderCtx {
	z := node
	if z == nil {
		return nil
	}
	y := z.Parent()
	if y == nil {
		return nil
	}
	x := y.Parent()
	if x == nil {
		return nil
	}

	if x.Timestamp() > z.Timestamp() {
		x, z = z, x
	}
	if x.Timestamp() > y.Timestamp() {
		x, y = y, x
	}
	if y.Timestamp() > z.Timestamp() {
		y, z = z, y
	}

	return y
}

// calcNextRequiredDifficulty calculates the required difficulty for the block
// after the passed previous HeaderCtx based on the difficulty retarget rules.
// This function differs from the exported CalcNextRequiredDifficulty in that
// the exported version uses the current best chain as the previous HeaderCtx
// while this function accepts any block node. This function accepts a ChainCtx
// parameter that gives the necessary difficulty context variables.
func calcNextRequiredDifficulty(lastNode HeaderCtx, newBlockTime time.Time,
	c ChainCtx) (uint32, error) {

	// Emulate the same behavior as Bitcoin Core that for regtest there is
	// no difficulty retargeting.
	if c.ChainParams().PoWNoRetargeting {
		return c.ChainParams().PowLimitBits, nil
	}

	// Genesis block.
	if lastNode == nil {
		return c.ChainParams().PowLimitBits, nil
	}

	// For networks that support it, allow special reduction of the required
	// difficulty once too much time has elapsed without mining a block.
	if c.ChainParams().ReduceMinDifficulty {
		reductionTime := int64(c.ChainParams().MinDiffReductionTime /
			time.Second)
		allowMinTime := lastNode.Timestamp() + reductionTime
		if newBlockTime.Unix() > allowMinTime {
			return c.ChainParams().PowLimitBits, nil
		}
	}

	window := c.BlocksPerRetarget()
	if lastNode.Height() < window+2 {
		return c.ChainParams().PowLimitBits, nil
	}

	last := suitableBlock(lastNode)
	if last == nil {
		return 0, AssertError("unable to obtain suitable retarget tip")
	}

	firstNode := lastNode.RelativeAncestorCtx(window)
	if firstNode == nil {
		return 0, AssertError("unable to obtain difficulty retarget window")
	}
	first := suitableBlock(firstNode)
	if first == nil {
		return 0, AssertError("unable to obtain suitable retarget ancestor")
	}

	// Limit the amount of adjustment that can occur to the previous
	// difficulty.
	actualTimespan := last.Timestamp() - first.Timestamp()
	adjustedTimespan := actualTimespan
	if actualTimespan < c.MinRetargetTimespan() {
		adjustedTimespan = c.MinRetargetTimespan()
	} else if actualTimespan > c.MaxRetargetTimespan() {
		adjustedTimespan = c.MaxRetargetTimespan()
	}

	// Handshake retargets every block after the first window using the total
	// work accumulated over the rolling window, not the previous block's
	// compact target.
	windowWork := new(big.Int).Sub(last.WorkSum(), first.WorkSum())
	if windowWork.Sign() <= 0 {
		return c.ChainParams().PowLimitBits, nil
	}

	targetTimePerBlock := int64(c.ChainParams().TargetTimePerBlock / time.Second)
	adjustedWork := new(big.Int).Mul(windowWork, big.NewInt(targetTimePerBlock))
	adjustedWork.Div(adjustedWork, big.NewInt(adjustedTimespan))
	if adjustedWork.Sign() <= 0 {
		return c.ChainParams().PowLimitBits, nil
	}

	oneLsh256 := new(big.Int).Lsh(big.NewInt(1), 256)
	newTarget := new(big.Int).Div(oneLsh256, adjustedWork)
	newTarget.Sub(newTarget, big.NewInt(1))

	// Limit new value to the proof of work limit.
	if newTarget.Cmp(c.ChainParams().PowLimit) > 0 {
		newTarget.Set(c.ChainParams().PowLimit)
	}

	// Log new target difficulty and return it.  The new target logging is
	// intentionally converting the bits back to a number instead of using
	// newTarget since conversion to the compact representation loses
	// precision.
	newTargetBits := BigToCompact(newTarget)
	log.Debugf("Difficulty retarget at block height %d", lastNode.Height()+1)
	log.Debugf("Window work %064x", windowWork)
	log.Debugf("New target %08x (%064x)", newTargetBits, CompactToBig(newTargetBits))
	log.Debugf("Actual timespan %v, adjusted timespan %v, target spacing %v",
		time.Duration(actualTimespan)*time.Second,
		time.Duration(adjustedTimespan)*time.Second,
		c.ChainParams().TargetTimePerBlock)

	return newTargetBits, nil
}

// CalcNextRequiredDifficulty calculates the required difficulty for the block
// after the end of the current best chain based on the difficulty retarget
// rules.
//
// This function is safe for concurrent access.
func (b *BlockChain) CalcNextRequiredDifficulty(timestamp time.Time) (uint32, error) {
	b.chainLock.Lock()
	difficulty, err := calcNextRequiredDifficulty(b.bestChain.Tip(), timestamp, b)
	b.chainLock.Unlock()
	return difficulty, err
}
