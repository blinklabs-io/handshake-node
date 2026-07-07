// Copyright (c) 2013-2023 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package txscript

import (
	"crypto/sha3"
	"testing"

	"github.com/blinklabs-io/handshake-node/wire"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

// TestDebugEngine checks that the StepCallback called during debug script
// execution contains the expected data.
func TestDebugEngine(t *testing.T) {
	t.Parallel()

	// We'll generate a private key and a signature for the tx.
	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	internalKey := privKey.PubKey()

	// We use a simple script that will utilize both the stack and alt
	// stack in order to test the step callback, and wrap it in a v0 witness
	// script.
	builder := NewScriptBuilder()
	builder.AddData([]byte{0xab})
	builder.AddOp(OP_TOALTSTACK)
	builder.AddData(internalKey.SerializeCompressed())
	builder.AddOp(OP_CHECKSIG)
	builder.AddOp(OP_VERIFY)
	builder.AddOp(OP_1)
	witnessScript, err := builder.Script()
	require.NoError(t, err)

	scriptHash := sha3.Sum256(witnessScript)
	p2wshScript, err := NewScriptBuilder().
		AddOp(OP_0).
		AddData(scriptHash[:]).
		Script()
	require.NoError(t, err)

	testTx := wire.NewMsgTx(2)
	testTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Index: 1,
		},
	})
	debugAddr, err := AddressFromWitnessProgram(p2wshScript)
	if err != nil {
		t.Fatalf("AddressFromWitnessProgram: %v", err)
	}
	txOut := &wire.TxOut{
		Value:   1e8,
		Address: debugAddr,
	}
	testTx.AddTxOut(txOut)

	prevFetcher := NewCannedPrevOutputFetcher(
		debugAddr, txOut.Value,
	)
	sigHashes := NewTxSigHashes(testTx, prevFetcher)

	sig, err := RawTxInWitnessSignature(
		testTx, sigHashes, 0, txOut.Value,
		witnessScript, SigHashAll, privKey,
	)
	require.NoError(t, err)

	txCopy := testTx.Copy()
	txCopy.TxIn[0].Witness = wire.TxWitness{
		sig, witnessScript,
	}

	var callbacks []StepInfo
	callback := func(s *StepInfo) error {
		callbacks = append(callbacks, cloneStepInfo(*s))
		return nil
	}

	// Run the debug engine.
	vm, err := NewDebugEngine(
		p2wshScript, txCopy, 0, StandardVerifyFlags,
		nil, sigHashes, txOut.Value, prevFetcher,
		callback,
	)
	require.NoError(t, err)
	require.NoError(t, vm.Execute())

	require.NotEmpty(t, callbacks)
	require.Equal(t, [][]byte{{0x01}}, callbacks[len(callbacks)-1].Stack)
	require.Empty(t, callbacks[len(callbacks)-1].AltStack)

	var sawAltStack, sawCheckSigResult bool
	for _, step := range callbacks {
		if len(step.AltStack) == 1 && string(step.AltStack[0]) == "\xab" {
			sawAltStack = true
		}
		if len(step.Stack) == 1 && len(step.Stack[0]) == 1 &&
			step.Stack[0][0] == 0x01 {

			sawCheckSigResult = true
		}
	}
	require.True(t, sawAltStack)
	require.True(t, sawCheckSigResult)
}

func cloneStepInfo(step StepInfo) StepInfo {
	step.Stack = cloneStack(step.Stack)
	step.AltStack = cloneStack(step.AltStack)
	return step
}

func cloneStack(stack [][]byte) [][]byte {
	clone := make([][]byte, len(stack))
	for i := range stack {
		clone[i] = append([]byte(nil), stack[i]...)
	}
	return clone
}
