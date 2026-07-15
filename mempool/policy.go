// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mempool

import (
	"fmt"
	"time"

	"github.com/blinklabs-io/handshake-node/blockchain"
	"github.com/blinklabs-io/handshake-node/hnsutil"
	"github.com/blinklabs-io/handshake-node/txscript"
	"github.com/blinklabs-io/handshake-node/wire"
)

const (
	// maxStandardP2SHSigOps is the maximum number of signature operations
	// that are considered standard in a pay-to-script-hash script.
	maxStandardP2SHSigOps = 15

	// maxStandardTxCost is the max weight permitted by any transaction
	// according to the current default policy.
	maxStandardTxWeight = 400000

	// maxStandardSigScriptSize is the maximum size allowed for a
	// transaction input signature script to be considered standard.  This
	// value allows for a 15-of-15 CHECKMULTISIG pay-to-script-hash with
	// compressed keys.
	//
	// The form of the overall script is: OP_0 <15 signatures> OP_PUSHDATA2
	// <2 bytes len> [OP_15 <15 pubkeys> OP_15 OP_CHECKMULTISIG]
	//
	// For the p2sh script portion, each of the 15 compressed pubkeys are
	// 33 bytes (plus one for the OP_DATA_33 opcode), and the thus it totals
	// to (15*34)+3 = 513 bytes.  Next, each of the 15 signatures is a max
	// of 73 bytes (plus one for the OP_DATA_73 opcode).  Also, there is one
	// extra byte for the initial extra OP_0 push and 3 bytes for the
	// OP_PUSHDATA2 needed to specify the 513 bytes for the script push.
	// That brings the total to 1+(15*74)+3+513 = 1627.  This value also
	// adds a few extra bytes to provide a little buffer.
	// (1 + 15*74 + 3) + (15*34 + 3) + 23 = 1650
	maxStandardSigScriptSize = 1650

	// DefaultMinRelayTxFee is the minimum fee in satoshi that is required
	// for a transaction to be treated as free for relay and mining
	// purposes.  It is also used to help determine if a transaction is
	// considered dust and as a base for calculating minimum required fees
	// for larger transactions.  This value is in Satoshi/1000 bytes.
	DefaultMinRelayTxFee = hnsutil.Amount(1000)

	// maxStandardMultiSigKeys is the maximum number of public keys allowed
	// in a multi-signature transaction output script for it to be
	// considered standard.
	maxStandardMultiSigKeys = 3
)

// calcMinRequiredTxRelayFee returns the minimum transaction fee required for a
// transaction with the passed serialized size to be accepted into the memory
// pool and relayed.
func calcMinRequiredTxRelayFee(serializedSize int64, minRelayTxFee hnsutil.Amount) int64 {
	// Calculate the minimum fee for a transaction to be allowed into the
	// mempool and relayed by scaling the base fee (which is the minimum
	// free transaction relay fee).  minRelayTxFee is in doo/kB so multiply
	// by serializedSize (which is in bytes) and divide by 1000 to get the
	// minimum number of dollarydoos.
	if serializedSize <= 0 || minRelayTxFee <= 0 {
		return 0
	}

	// Guard against int64 overflow before multiplying.  Since fees are
	// clamped to MaxDoo, compare against the largest scaled product that can
	// produce an in-range fee before performing the multiplication.
	maxScaledFee := int64(hnsutil.MaxDoo) * 1000
	if serializedSize > maxScaledFee/int64(minRelayTxFee) {
		return hnsutil.MaxDoo
	}
	minFee := (serializedSize * int64(minRelayTxFee)) / 1000

	if minFee == 0 {
		minFee = int64(minRelayTxFee)
	}

	// Set the minimum fee to the maximum possible value if the calculated
	// fee is not in the valid range for monetary amounts.
	if minFee < 0 || minFee > hnsutil.MaxDoo {
		minFee = hnsutil.MaxDoo
	}

	return minFee
}

// checkInputsStandard performs a series of checks on a transaction's inputs
// to ensure they are "standard".  A standard transaction input within the
// context of this function is one whose referenced public key script is of a
// standard form and, for pay-to-script-hash, does not have more than
// maxStandardP2SHSigOps signature operations.  However, it should also be noted
// that standard inputs also are those which have a clean stack after execution
// and only contain pushed data in their signature scripts.  This function does
// not perform those checks because the script engine already does this more
// accurately and concisely via the txscript.ScriptVerifyCleanStack and
// txscript.ScriptVerifySigPushOnly flags.
func checkInputsStandard(tx *hnsutil.Tx, utxoView *blockchain.UtxoViewpoint) error {
	// NOTE: The reference implementation also does a coinbase check here,
	// but coinbases have already been rejected prior to calling this
	// function so no need to recheck.

	for i, txIn := range tx.MsgTx().TxIn {
		// It is safe to elide existence and index checks here since
		// they have already been checked prior to calling this
		// function.
		entry := utxoView.LookupEntry(txIn.PreviousOutPoint)
		originPkScript := entry.PkScript()
		switch txscript.GetScriptClass(originPkScript) {
		case txscript.ScriptHashTy:
			// Handshake inputs have no SignatureScript; pass nil.
			numSigOps := txscript.GetPreciseSigOpCount(
				nil, originPkScript, true)
			if numSigOps > maxStandardP2SHSigOps {
				str := fmt.Sprintf("transaction input #%d has "+
					"%d signature operations which is more "+
					"than the allowed max amount of %d",
					i, numSigOps, maxStandardP2SHSigOps)
				return txRuleError(wire.RejectNonstandard, str)
			}

		case txscript.NonStandardTy:
			str := fmt.Sprintf("transaction input #%d has a "+
				"non-standard script form", i)
			return txRuleError(wire.RejectNonstandard, str)
		}
	}

	return nil
}

// checkPkScriptStandard performs a series of checks on a transaction output
// script (public key script) to ensure it is a "standard" public key script.
// A standard public key script is one that is a recognized form, and for
// multi-signature scripts, only contains from 1 to maxStandardMultiSigKeys
// public keys.
func checkPkScriptStandard(pkScript []byte, scriptClass txscript.ScriptClass) error {
	switch scriptClass {
	case txscript.MultiSigTy:
		numPubKeys, numSigs, err := txscript.CalcMultiSigStats(pkScript)
		if err != nil {
			str := fmt.Sprintf("multi-signature script parse "+
				"failure: %v", err)
			return txRuleError(wire.RejectNonstandard, str)
		}

		// A standard multi-signature public key script must contain
		// from 1 to maxStandardMultiSigKeys public keys.
		if numPubKeys < 1 {
			str := "multi-signature script with no pubkeys"
			return txRuleError(wire.RejectNonstandard, str)
		}
		if numPubKeys > maxStandardMultiSigKeys {
			str := fmt.Sprintf("multi-signature script with %d "+
				"public keys which is more than the allowed "+
				"max of %d", numPubKeys, maxStandardMultiSigKeys)
			return txRuleError(wire.RejectNonstandard, str)
		}

		// A standard multi-signature public key script must have at
		// least 1 signature and no more signatures than available
		// public keys.
		if numSigs < 1 {
			return txRuleError(wire.RejectNonstandard,
				"multi-signature script with no signatures")
		}
		if numSigs > numPubKeys {
			str := fmt.Sprintf("multi-signature script with %d "+
				"signatures which is more than the available "+
				"%d public keys", numSigs, numPubKeys)
			return txRuleError(wire.RejectNonstandard, str)
		}

	case txscript.NonStandardTy:
		return txRuleError(wire.RejectNonstandard,
			"non-standard script form")
	}

	return nil
}

// GetDustThreshold calculates the size component of the dust limit for a
// *wire.TxOut by taking the size of a typical spending transaction and
// multiplying it by 3.  Handshake name covenants that carry protocol state,
// and native nulldata outputs, are exempt from dust policy and return zero.
func GetDustThreshold(txOut *wire.TxOut) int64 {
	if !txOut.Covenant.IsDustworthy() || txOut.Address.IsUnspendable() {
		return 0
	}

	// Match hsd's typical-spend estimate: a 32-byte transaction hash,
	// 4-byte output index, 1-byte witness-vector length, a 107-byte witness
	// discounted by the witness scale factor, and a 4-byte sequence.
	totalSize := txOut.SerializeSize() + 32 + 4 + 1 +
		(107 / blockchain.WitnessScaleFactor) + 4

	return 3 * int64(totalSize)
}

// IsDust returns whether or not the passed transaction output amount is
// considered dust or not based on the passed minimum transaction relay fee.
// Dust is defined in terms of the minimum transaction relay fee.  In
// particular, if the cost to the network to spend coins is more than 1/3 of the
// minimum transaction relay fee, it is considered dust.
func IsDust(txOut *wire.TxOut, minRelayTxFee hnsutil.Amount) bool {
	// The output is considered dust if the cost to the network to spend the
	// coins is more than 1/3 of the minimum transaction relay fee.  The fee
	// rate is expressed in dollarydoos per 1000 bytes.  At the default rate,
	// a native 20-byte witness pubkey-hash output is dust below 297 doo.
	//
	// Match hsd's order of operations: calculate the minimum fee for the
	// typical spend size first, then multiply that fee by three.  This order
	// matters for non-default relay fee rates because fee calculation uses
	// integer rounding and a non-zero minimum.
	dustSize := GetDustThreshold(txOut)
	if dustSize == 0 {
		return false
	}
	spendFee := calcMinRequiredTxRelayFee(dustSize/3, minRelayTxFee)
	return txOut.Value < 3*spendFee
}

// CheckTransactionStandard performs a series of checks on a transaction to
// ensure it is a "standard" transaction.  A standard transaction is one that
// conforms to several additional limiting cases over what is considered a
// "sane" transaction such as having a version in the supported range, being
// finalized, conforming to more stringent size constraints, having scripts
// of recognized forms, and not containing "dust" outputs (those that are
// so small it costs more to process them than they are worth).
func CheckTransactionStandard(tx *hnsutil.Tx, height int32,
	medianTimePast time.Time, minRelayTxFee hnsutil.Amount,
	maxTxVersion int32) error {

	// The transaction must be a currently supported version.
	msgTx := tx.MsgTx()
	if msgTx.Version > uint32(maxTxVersion) {
		str := fmt.Sprintf("transaction version %d is not in the "+
			"valid range of %d-%d", msgTx.Version, 1,
			maxTxVersion)
		return txRuleError(wire.RejectNonstandard, str)
	}

	// The transaction must be finalized to be standard and therefore
	// considered for inclusion in a block.
	if !blockchain.IsFinalizedTransaction(tx, height, medianTimePast) {
		return txRuleError(wire.RejectNonstandard,
			"transaction is not finalized")
	}

	// Since extremely large transactions with a lot of inputs can cost
	// almost as much to process as the sender fees, limit the maximum
	// size of a transaction.  This also helps mitigate CPU exhaustion
	// attacks.
	txWeight := blockchain.GetTransactionWeight(tx)
	if txWeight > maxStandardTxWeight {
		str := fmt.Sprintf("weight of transaction is larger than max "+
			"allowed: %v > %v", txWeight, maxStandardTxWeight)
		return txRuleError(wire.RejectNonstandard, str)
	}

	// Handshake inputs carry signatures in witness data, so there is no
	// legacy signature-script standardness check here.

	// Outputs must use a defined native Handshake address and covenant type.
	// Nulldata outputs are exempt from covenant and dust checks, matching hsd.
	numNullDataOutputs := 0
	for i, txOut := range msgTx.TxOut {
		if txOut.Address.IsUnknown() {
			str := fmt.Sprintf("transaction output %d: unknown address "+
				"version %d", i, txOut.Address.Version)
			return txRuleError(wire.RejectNonstandard, str)
		}

		if txOut.Address.IsNulldata() {
			numNullDataOutputs++
			continue
		}

		if txOut.Covenant.IsUnknown() {
			str := fmt.Sprintf("transaction output %d: unknown covenant "+
				"type %d", i, txOut.Covenant.Type)
			return txRuleError(wire.RejectNonstandard, str)
		}

		script := txOut.Address.WitnessProgram()
		scriptClass := txscript.GetScriptClass(script)
		err := checkPkScriptStandard(script, scriptClass)
		if err != nil {
			// Attempt to extract a reject code from the error so
			// it can be retained.  When not possible, fall back to
			// a non standard error.
			rejectCode := wire.RejectNonstandard
			if rejCode, found := extractRejectCode(err); found {
				rejectCode = rejCode
			}
			str := fmt.Sprintf("transaction output %d: %v", i, err)
			return txRuleError(rejectCode, str)
		}

		if IsDust(txOut, minRelayTxFee) {
			str := fmt.Sprintf("transaction output %d: payment is "+
				"dust: %v", i, txOut.Value)
			return txRuleError(wire.RejectDust, str)
		}
	}

	// A standard transaction must not have more than one output script that
	// only carries data.
	if numNullDataOutputs > 1 {
		str := "more than one transaction output in a nulldata script"
		return txRuleError(wire.RejectNonstandard, str)
	}

	return nil
}

// GetTxVirtualSize computes the virtual size of a given transaction. A
// transaction's virtual size is based off its weight, creating a discount for
// any witness data it contains, proportional to the current
// blockchain.WitnessScaleFactor value.
func GetTxVirtualSize(tx *hnsutil.Tx) int64 {
	// vSize := (weight(tx) + 3) / 4
	//       := (((baseSize * 3) + totalSize) + 3) / 4
	// We add 3 here as a way to compute the ceiling of the prior arithmetic
	// to 4. The division by 4 creates a discount for wit witness data.
	return (blockchain.GetTransactionWeight(tx) + (blockchain.WitnessScaleFactor - 1)) /
		blockchain.WitnessScaleFactor
}
