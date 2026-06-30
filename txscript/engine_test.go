// Copyright (c) 2013-2017 The btcsuite developers
// Copyright (c) 2015-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package txscript

import (
	"errors"
	"testing"

	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/wire"
)

// TestBadPC sets the pc to a deliberately bad result then confirms that Step
// and Disasm fail correctly.
func TestBadPC(t *testing.T) {
	t.Parallel()

	tests := []struct {
		scriptIdx int
	}{
		{scriptIdx: 2},
		{scriptIdx: 3},
	}

	// tx with almost empty scripts.
	tx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{
					Hash: chainhash.Hash([32]byte{
						0xc9, 0x97, 0xa5, 0xe5,
						0x6e, 0x10, 0x41, 0x02,
						0xfa, 0x20, 0x9c, 0x6a,
						0x85, 0x2d, 0xd9, 0x06,
						0x60, 0xa2, 0x0b, 0x2d,
						0x9c, 0x35, 0x24, 0x23,
						0xed, 0xce, 0x25, 0x85,
						0x7f, 0xcd, 0x37, 0x04,
					}),
					Index: 0,
				},
				Sequence: 4294967295,
			},
		},
		TxOut: []*wire.TxOut{{
			Value: 1000000000,
		}},
		LockTime: 0,
	}
	pkScript := mustParseShortForm("NOP")

	for _, test := range tests {
		vm, err := NewEngine(pkScript, tx, 0, 0, nil, nil, -1, nil)
		if err != nil {
			t.Errorf("Failed to create script: %v", err)
		}

		// Set to after all scripts.
		vm.scriptIdx = test.scriptIdx

		// Ensure attempting to step fails.
		_, err = vm.Step()
		if err == nil {
			t.Errorf("Step with invalid pc (%v) succeeds!", test)
			continue
		}

		// Ensure attempting to disassemble the current program counter fails.
		_, err = vm.DisasmPC()
		if err == nil {
			t.Errorf("DisasmPC with invalid pc (%v) succeeds!", test)
		}
	}
}

// TestCheckErrorCondition tests the execute early test in CheckErrorCondition()
// since most code paths are tested elsewhere.
func TestCheckErrorCondition(t *testing.T) {
	t.Parallel()

	// tx with almost empty scripts.
	tx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{{
			PreviousOutPoint: wire.OutPoint{
				Hash: chainhash.Hash([32]byte{
					0xc9, 0x97, 0xa5, 0xe5,
					0x6e, 0x10, 0x41, 0x02,
					0xfa, 0x20, 0x9c, 0x6a,
					0x85, 0x2d, 0xd9, 0x06,
					0x60, 0xa2, 0x0b, 0x2d,
					0x9c, 0x35, 0x24, 0x23,
					0xed, 0xce, 0x25, 0x85,
					0x7f, 0xcd, 0x37, 0x04,
				}),
				Index: 0,
			},
			Sequence: 4294967295,
		}},
		TxOut: []*wire.TxOut{{
			Value: 1000000000,
		}},
		LockTime: 0,
	}
	pkScript := mustParseShortForm("NOP NOP NOP NOP NOP NOP NOP NOP NOP" +
		" NOP TRUE")

	vm, err := NewEngine(pkScript, tx, 0, 0, nil, nil, 0, nil)
	if err != nil {
		t.Errorf("failed to create script: %v", err)
	}

	for i := 0; i < len(pkScript)-1; i++ {
		done, err := vm.Step()
		if err != nil {
			t.Fatalf("failed to step %dth time: %v", i, err)
		}
		if done {
			t.Fatalf("finished early on %dth time", i)
		}

		err = vm.CheckErrorCondition(false)
		if !IsErrorCode(err, ErrScriptUnfinished) {
			t.Fatalf("got unexpected error %v on %dth iteration",
				err, i)
		}
	}
	done, err := vm.Step()
	if err != nil {
		t.Fatalf("final step failed %v", err)
	}
	if !done {
		t.Fatalf("final step isn't done!")
	}

	err = vm.CheckErrorCondition(false)
	if err != nil {
		t.Errorf("unexpected error %v on final check", err)
	}
}

// TestInvalidFlagCombinations ensures the script engine returns the expected
// error when disallowed flag combinations are specified.
func TestInvalidFlagCombinations(t *testing.T) {
	t.Parallel()

	tests := []ScriptFlags{
		ScriptVerifyCleanStack,
	}

	// tx with almost empty scripts.
	tx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{
					Hash: chainhash.Hash([32]byte{
						0xc9, 0x97, 0xa5, 0xe5,
						0x6e, 0x10, 0x41, 0x02,
						0xfa, 0x20, 0x9c, 0x6a,
						0x85, 0x2d, 0xd9, 0x06,
						0x60, 0xa2, 0x0b, 0x2d,
						0x9c, 0x35, 0x24, 0x23,
						0xed, 0xce, 0x25, 0x85,
						0x7f, 0xcd, 0x37, 0x04,
					}),
					Index: 0,
				},
				Sequence: 4294967295,
			},
		},
		TxOut: []*wire.TxOut{
			{
				Value: 1000000000,
			},
		},
		LockTime: 0,
	}
	pkScript := []byte{OP_NOP}

	for i, test := range tests {
		_, err := NewEngine(pkScript, tx, 0, test, nil, nil, -1, nil)
		if !IsErrorCode(err, ErrInvalidFlags) {
			t.Fatalf("TestInvalidFlagCombinations #%d unexpected "+
				"error: %v", i, err)
		}
	}
}

// TestCheckPubKeyEncoding ensures the internal checkPubKeyEncoding function
// works as expected.
func TestCheckPubKeyEncoding(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		key     []byte
		isValid bool
	}{
		{
			name: "uncompressed ok",
			key: hexToBytes("0411db93e1dcdb8a016b49840f8c53bc1eb68" +
				"a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf" +
				"9744464f82e160bfa9b8b64f9d4c03f999b8643f656b" +
				"412a3"),
			isValid: true,
		},
		{
			name: "compressed ok",
			key: hexToBytes("02ce0b14fb842b1ba549fdd675c98075f12e9" +
				"c510f8ef52bd021a9a1f4809d3b4d"),
			isValid: true,
		},
		{
			name: "compressed ok",
			key: hexToBytes("032689c7c2dab13309fb143e0e8fe39634252" +
				"1887e976690b6b47f5b2a4b7d448e"),
			isValid: true,
		},
		{
			name: "hybrid",
			key: hexToBytes("0679be667ef9dcbbac55a06295ce870b07029" +
				"bfcdb2dce28d959f2815b16f81798483ada7726a3c46" +
				"55da4fbfc0e1108a8fd17b448a68554199c47d08ffb1" +
				"0d4b8"),
			isValid: false,
		},
		{
			name:    "empty",
			key:     nil,
			isValid: false,
		},
	}

	vm := Engine{flags: ScriptVerifyStrictEncoding}
	for _, test := range tests {
		err := vm.checkPubKeyEncoding(test.key)
		if err != nil && test.isValid {
			t.Errorf("checkSignatureEncoding test '%s' failed "+
				"when it should have succeeded: %v", test.name,
				err)
		} else if err == nil && !test.isValid {
			t.Errorf("checkSignatureEncooding test '%s' succeeded "+
				"when it should have failed", test.name)
		}
	}

}

// TestCheckSignatureEncoding ensures the internal checkSignatureEncoding
// function works as expected.
func TestCheckSignatureEncoding(t *testing.T) {
	t.Parallel()

	validSig := hexToBytes("4e45e16932b8af514961a1d3a1a25fdf3" +
		"f4f7732e9d624c6c61548ab5fb8cd41181522ec8e" +
		"ca07de4860a4acdd12909d831cc56cbbac4622082" +
		"221a8768d1d09")
	groupOrder := hexToBytes("fffffffffffffffffffffffffffffffebaae" +
		"dce6af48a03bbfd25e8cd0364141")
	highS := hexToBytes("fffffffffffffffffffffffffffffffebaae" +
		"dce6af48a03bbfd25e8cd0364140")
	zeroScalar := make([]byte, 32)

	withR := func(r []byte) []byte {
		sig := append([]byte(nil), validSig...)
		copy(sig[:32], r)
		return sig
	}
	withS := func(s []byte) []byte {
		sig := append([]byte(nil), validSig...)
		copy(sig[32:], s)
		return sig
	}

	tests := []struct {
		name    string
		sig     []byte
		isValid bool
	}{
		{
			name:    "valid signature",
			sig:     validSig,
			isValid: true,
		},
		{
			name:    "empty.",
			sig:     nil,
			isValid: false,
		},
		{
			name:    "short signature",
			sig:     validSig[:len(validSig)-1],
			isValid: false,
		},
		{
			name:    "long signature",
			sig:     append(append([]byte(nil), validSig...), 0x00),
			isValid: false,
		},
		{
			name:    "R is zero",
			sig:     withR(zeroScalar),
			isValid: false,
		},
		{
			name:    "S is zero",
			sig:     withS(zeroScalar),
			isValid: false,
		},
		{
			name:    "R equals group order",
			sig:     withR(groupOrder),
			isValid: false,
		},
		{
			name:    "S equals group order",
			sig:     withS(groupOrder),
			isValid: false,
		},
		{
			name:    "S is high",
			sig:     withS(highS),
			isValid: false,
		},
	}

	vm := Engine{flags: ScriptVerifyStrictEncoding}
	for _, test := range tests {
		err := vm.checkSignatureEncoding(test.sig)
		if err != nil && test.isValid {
			t.Errorf("checkSignatureEncoding test '%s' failed "+
				"when it should have succeeded: %v", test.name,
				err)
		} else if err == nil && !test.isValid {
			t.Errorf("checkSignatureEncooding test '%s' succeeded "+
				"when it should have failed", test.name)
		}
	}
}

func TestParseBaseSigAndPubkeyInvalidSignatureStrictness(t *testing.T) {
	t.Parallel()

	pubKey := hexToBytes("02ce0b14fb842b1ba549fdd675c98075f12e9" +
		"c510f8ef52bd021a9a1f4809d3b4d")
	fullSig := append([]byte{0x01, 0x02}, byte(SigHashAll))

	_, _, _, err := parseBaseSigAndPubkey(pubKey, fullSig, &Engine{})
	if err == nil {
		t.Fatalf("expected malformed signature error")
	}
	var scriptErr Error
	if errors.As(err, &scriptErr) {
		t.Fatalf("non-strict malformed signature returned script error: %v",
			err)
	}

	strictVM := &Engine{flags: ScriptVerifyStrictEncoding}
	_, _, _, err = parseBaseSigAndPubkey(pubKey, fullSig, strictVM)
	if err == nil {
		t.Fatalf("expected strict malformed signature error")
	}
	if !errors.As(err, &scriptErr) {
		t.Fatalf("strict malformed signature returned non-script error: %v",
			err)
	}
}

func TestParseBaseSigAndPubkeyInvalidSignatureNullFail(t *testing.T) {
	t.Parallel()

	pubKey := hexToBytes("02ce0b14fb842b1ba549fdd675c98075f12e9" +
		"c510f8ef52bd021a9a1f4809d3b4d")
	fullSig := append([]byte{0x01, 0x02}, byte(SigHashAll))
	vm := &Engine{flags: ScriptVerifyNullFail}

	_, _, _, err := parseBaseSigAndPubkey(pubKey, fullSig, vm)
	if !IsErrorCode(err, ErrNullFail) {
		t.Fatalf("expected ErrNullFail, got %v", err)
	}
}
