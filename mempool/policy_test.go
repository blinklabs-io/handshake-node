// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mempool

import (
	"bytes"
	"testing"
	"time"

	"github.com/blinklabs-io/handshake-node/blockchain"
	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/hnsutil"
	"github.com/blinklabs-io/handshake-node/txscript"
	"github.com/blinklabs-io/handshake-node/wire"
	"github.com/btcsuite/btcd/btcec/v2"
)

func TestMaxStandardTxSigOpsCost(t *testing.T) {
	const want = 16000
	if MaxStandardTxSigOpsCost != want {
		t.Fatalf("MaxStandardTxSigOpsCost = %d, want %d",
			MaxStandardTxSigOpsCost, want)
	}
}

func TestCheckInputsStandardWitnessPolicy(t *testing.T) {
	t.Parallel()

	pubKey := bytes.Repeat([]byte{0x02}, standardCompressedKeySize)
	pubKeyScript, err := txscript.NewScriptBuilder().
		AddData(pubKey).
		AddOp(txscript.OP_CHECKSIG).
		Script()
	if err != nil {
		t.Fatalf("create pubkey script: %v", err)
	}
	pubKeyHashScript, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_DUP).
		AddOp(txscript.OP_BLAKE160).
		AddData(make([]byte, 20)).
		AddOp(txscript.OP_EQUALVERIFY).
		AddOp(txscript.OP_CHECKSIG).
		Script()
	if err != nil {
		t.Fatalf("create pubkey-hash script: %v", err)
	}
	multisigScript, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_1).
		AddData(pubKey).
		AddOp(txscript.OP_1).
		AddOp(txscript.OP_CHECKMULTISIG).
		Script()
	if err != nil {
		t.Fatalf("create multisig script: %v", err)
	}

	signature := make([]byte, standardSignatureSize)
	genericScript := []byte{txscript.OP_TRUE}
	maxStack := make(wire.TxWitness, maxStandardP2WSHStackItems)
	for i := range maxStack {
		maxStack[i] = make([]byte, maxStandardP2WSHItemSize)
	}

	tests := []struct {
		name        string
		version     uint8
		programSize int
		witness     wire.TxWitness
		wantErr     bool
	}{
		{
			name:        "pubkey hash",
			programSize: 20,
			witness:     wire.TxWitness{signature, pubKey},
		},
		{
			name:        "pubkey hash wrong item count",
			programSize: 20,
			witness:     wire.TxWitness{signature},
			wantErr:     true,
		},
		{
			name:        "pubkey hash wrong signature size",
			programSize: 20,
			witness: wire.TxWitness{
				make([]byte, standardSignatureSize-1),
				pubKey,
			},
			wantErr: true,
		},
		{
			name:        "pubkey hash uncompressed key",
			programSize: 20,
			witness: wire.TxWitness{
				signature,
				make([]byte, 65),
			},
			wantErr: true,
		},
		{
			name:        "script hash max generic stack",
			programSize: 32,
			witness:     append(maxStack, genericScript),
		},
		{
			name:        "script hash too many stack items",
			programSize: 32,
			witness: append(
				append(wire.TxWitness{}, maxStack...),
				[]byte{}, genericScript,
			),
			wantErr: true,
		},
		{
			name:        "script hash oversized stack item",
			programSize: 32,
			witness: wire.TxWitness{
				make([]byte, maxStandardP2WSHItemSize+1),
				genericScript,
			},
			wantErr: true,
		},
		{
			name:        "script hash oversized script",
			programSize: 32,
			witness: wire.TxWitness{
				make([]byte, maxStandardP2WSHScriptSize+1),
			},
			wantErr: true,
		},
		{
			name:        "script hash pubkey",
			programSize: 32,
			witness:     wire.TxWitness{signature, pubKeyScript},
		},
		{
			name:        "script hash pubkey wrong signature size",
			programSize: 32,
			witness: wire.TxWitness{
				make([]byte, standardSignatureSize-1),
				pubKeyScript,
			},
			wantErr: true,
		},
		{
			name:        "script hash pubkey hash",
			programSize: 32,
			witness: wire.TxWitness{
				signature, pubKey, pubKeyHashScript,
			},
		},
		{
			name:        "script hash pubkey hash wrong item count",
			programSize: 32,
			witness:     wire.TxWitness{signature, pubKeyHashScript},
			wantErr:     true,
		},
		{
			name:        "script hash multisig",
			programSize: 32,
			witness: wire.TxWitness{
				{}, signature, multisigScript,
			},
		},
		{
			name:        "script hash multisig missing dummy",
			programSize: 32,
			witness:     wire.TxWitness{signature, multisigScript},
			wantErr:     true,
		},
		{
			name:        "script hash multisig wrong signature size",
			programSize: 32,
			witness: wire.TxWitness{
				{}, make([]byte, standardSignatureSize-1),
				multisigScript,
			},
			wantErr: true,
		},
		{
			name:        "unknown witness max stack",
			version:     1,
			programSize: 20,
			witness:     maxStack,
		},
		{
			name:        "unknown witness too many stack items",
			version:     1,
			programSize: 20,
			witness: append(
				append(wire.TxWitness{}, maxStack...),
				[]byte{},
			),
			wantErr: true,
		},
		{
			name:        "unknown witness oversized stack item",
			version:     1,
			programSize: 20,
			witness: wire.TxWitness{
				make([]byte, maxStandardP2WSHItemSize+1),
			},
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			originMsg := wire.NewMsgTx(wire.TxVersion)
			originMsg.AddTxOut(wire.NewTxOut(
				1,
				wire.Address{
					Version: test.version,
					Hash:    make([]byte, test.programSize),
				},
				wire.Covenant{},
			))
			origin := hnsutil.NewTx(originMsg)

			view := blockchain.NewUtxoViewpoint()
			view.AddTxOut(origin, 0, 1)

			spendMsg := wire.NewMsgTx(wire.TxVersion)
			spendMsg.AddTxIn(&wire.TxIn{
				PreviousOutPoint: wire.OutPoint{
					Hash:  *origin.Hash(),
					Index: 0,
				},
				Witness: test.witness,
			})

			err := checkInputsStandard(hnsutil.NewTx(spendMsg), view)
			if test.wantErr {
				if err == nil {
					t.Fatal("expected non-standard witness rejection")
				}
				if code, ok := extractRejectCode(err); !ok ||
					code != wire.RejectNonstandard {

					t.Fatalf("reject code = %v, %v; want %v",
						code, ok, wire.RejectNonstandard)
				}
				return
			}
			if err != nil {
				t.Fatalf("standard witness rejected: %v", err)
			}
		})
	}
}

// TestCalcMinRequiredTxRelayFee tests the calcMinRequiredTxRelayFee API.
func TestCalcMinRequiredTxRelayFee(t *testing.T) {
	tests := []struct {
		name     string         // test description.
		size     int64          // Transaction size in bytes.
		relayFee hnsutil.Amount // minimum relay transaction fee.
		want     int64          // Expected fee.
	}{
		{
			// Ensure combination of size and fee that are less than 1000
			// produce a non-zero fee.
			"250 bytes with relay fee of 3",
			250,
			3,
			3,
		},
		{
			"zero-size transaction has zero fee",
			0,
			DefaultMinRelayTxFee,
			0,
		},
		{
			"100 bytes with default minimum relay fee",
			100,
			DefaultMinRelayTxFee,
			100,
		},
		{
			"max standard tx size with default minimum relay fee",
			maxStandardTxWeight / 4,
			DefaultMinRelayTxFee,
			100000,
		},
		{
			"max standard tx size with max satoshi relay fee",
			maxStandardTxWeight / 4,
			hnsutil.MaxDoo,
			hnsutil.MaxDoo,
		},
		{
			"1500 bytes with 5000 relay fee",
			1500,
			5000,
			7500,
		},
		{
			"1500 bytes with 3000 relay fee",
			1500,
			3000,
			4500,
		},
		{
			"782 bytes with 5000 relay fee",
			782,
			5000,
			3910,
		},
		{
			"782 bytes with 3000 relay fee",
			782,
			3000,
			2346,
		},
		{
			"782 bytes with 2550 relay fee",
			782,
			2550,
			1994,
		},
		{
			"small size with maximum int64 relay fee",
			99,
			hnsutil.Amount(1<<63 - 1),
			hnsutil.MaxDoo,
		},
	}

	for _, test := range tests {
		got := calcMinRequiredTxRelayFee(test.size, test.relayFee)
		if got != test.want {
			t.Errorf("TestCalcMinRequiredTxRelayFee test '%s' "+
				"failed: got %v want %v", test.name, got,
				test.want)
			continue
		}
	}
}

// TestCheckPkScriptStandard tests the checkPkScriptStandard API.
func TestCheckPkScriptStandard(t *testing.T) {
	var pubKeys [][]byte
	for i := 0; i < 4; i++ {
		pk, err := btcec.NewPrivateKey()
		if err != nil {
			t.Fatalf("TestCheckPkScriptStandard NewPrivateKey failed: %v",
				err)
			return
		}
		pubKeys = append(pubKeys, pk.PubKey().SerializeCompressed())
	}

	tests := []struct {
		name       string // test description.
		script     *txscript.ScriptBuilder
		isStandard bool
	}{
		{
			"key1 and key2",
			txscript.NewScriptBuilder().AddOp(txscript.OP_2).
				AddData(pubKeys[0]).AddData(pubKeys[1]).
				AddOp(txscript.OP_2).AddOp(txscript.OP_CHECKMULTISIG),
			true,
		},
		{
			"key1 or key2",
			txscript.NewScriptBuilder().AddOp(txscript.OP_1).
				AddData(pubKeys[0]).AddData(pubKeys[1]).
				AddOp(txscript.OP_2).AddOp(txscript.OP_CHECKMULTISIG),
			true,
		},
		{
			"escrow",
			txscript.NewScriptBuilder().AddOp(txscript.OP_2).
				AddData(pubKeys[0]).AddData(pubKeys[1]).
				AddData(pubKeys[2]).
				AddOp(txscript.OP_3).AddOp(txscript.OP_CHECKMULTISIG),
			true,
		},
		{
			"one of four",
			txscript.NewScriptBuilder().AddOp(txscript.OP_1).
				AddData(pubKeys[0]).AddData(pubKeys[1]).
				AddData(pubKeys[2]).AddData(pubKeys[3]).
				AddOp(txscript.OP_4).AddOp(txscript.OP_CHECKMULTISIG),
			false,
		},
		{
			"malformed1",
			txscript.NewScriptBuilder().AddOp(txscript.OP_3).
				AddData(pubKeys[0]).AddData(pubKeys[1]).
				AddOp(txscript.OP_2).AddOp(txscript.OP_CHECKMULTISIG),
			false,
		},
		{
			"malformed2",
			txscript.NewScriptBuilder().AddOp(txscript.OP_2).
				AddData(pubKeys[0]).AddData(pubKeys[1]).
				AddOp(txscript.OP_3).AddOp(txscript.OP_CHECKMULTISIG),
			false,
		},
		{
			"malformed3",
			txscript.NewScriptBuilder().AddOp(txscript.OP_0).
				AddData(pubKeys[0]).AddData(pubKeys[1]).
				AddOp(txscript.OP_2).AddOp(txscript.OP_CHECKMULTISIG),
			false,
		},
		{
			"malformed4",
			txscript.NewScriptBuilder().AddOp(txscript.OP_1).
				AddData(pubKeys[0]).AddData(pubKeys[1]).
				AddOp(txscript.OP_0).AddOp(txscript.OP_CHECKMULTISIG),
			false,
		},
		{
			"malformed5",
			txscript.NewScriptBuilder().AddOp(txscript.OP_1).
				AddData(pubKeys[0]).AddData(pubKeys[1]).
				AddOp(txscript.OP_CHECKMULTISIG),
			false,
		},
		{
			"malformed6",
			txscript.NewScriptBuilder().AddOp(txscript.OP_1).
				AddData(pubKeys[0]).AddData(pubKeys[1]),
			false,
		},
	}

	for _, test := range tests {
		script, err := test.script.Script()
		if err != nil {
			t.Fatalf("TestCheckPkScriptStandard test '%s' "+
				"failed: %v", test.name, err)
		}
		scriptClass := txscript.GetScriptClass(script)
		got := checkPkScriptStandard(script, scriptClass)
		if (test.isStandard && got != nil) ||
			(!test.isStandard && got == nil) {

			t.Fatalf("TestCheckPkScriptStandard test '%s' failed",
				test.name)
			return
		}
	}
}

// TestDust tests the IsDust API.
func TestDust(t *testing.T) {
	// Standard P2WPKH address (version 0, 20-byte hash).
	// Handshake TxOut size: 8 (value) + 22 (address: 1 ver + 1 hashlen + 20 hash)
	// + 2 (covenant: 1 type + 1 varint(0)) = 32 bytes.
	// Dust threshold for P2WPKH: 3 * (32 + 41 + 107/4) = 3 * 99 = 297.
	stdAddr := wire.Address{Version: 0, Hash: make([]byte, 20)}

	tests := []struct {
		name     string // test description
		txOut    wire.TxOut
		relayFee hnsutil.Amount // minimum relay transaction fee.
		isDust   bool
	}{
		{
			// Any value is allowed with a zero relay fee.
			"zero value with zero relay fee",
			wire.TxOut{Value: 0, Address: stdAddr},
			0,
			false,
		},
		{
			// Zero value is dust with any relay fee"
			"zero value with very small tx fee",
			wire.TxOut{Value: 0, Address: stdAddr},
			1,
			true,
		},
		{
			"standard P2WPKH output with value 296",
			wire.TxOut{Value: 296, Address: stdAddr},
			1000,
			true,
		},
		{
			"standard P2WPKH output with value 297",
			wire.TxOut{Value: 297, Address: stdAddr},
			1000,
			false,
		},
		{
			// Maximum allowed value is never dust.
			"max satoshi amount is never dust",
			wire.TxOut{Value: hnsutil.MaxDoo, Address: stdAddr},
			hnsutil.MaxDoo,
			false,
		},
		{
			"maximum int64 value and relay fee do not overflow",
			wire.TxOut{Value: 1<<63 - 1, Address: stdAddr},
			1<<63 - 1,
			false,
		},
		{
			"custom relay fee rounds before dust multiplier",
			wire.TxOut{Value: 147, Address: stdAddr},
			500,
			false,
		},
		{
			"custom relay fee boundary below threshold",
			wire.TxOut{Value: 146, Address: stdAddr},
			500,
			true,
		},
		{
			"native nulldata output is exempt",
			wire.TxOut{
				Value:   0,
				Address: wire.Address{Version: 31, Hash: []byte{0x00, 0x00}},
			},
			DefaultMinRelayTxFee,
			false,
		},
		{
			"OPEN covenant is exempt",
			wire.TxOut{
				Value:    0,
				Address:  stdAddr,
				Covenant: wire.Covenant{Type: wire.CovenantOpen},
			},
			DefaultMinRelayTxFee,
			false,
		},
		{
			"BID covenant remains dustworthy",
			wire.TxOut{
				Value:    0,
				Address:  stdAddr,
				Covenant: wire.Covenant{Type: wire.CovenantBid},
			},
			DefaultMinRelayTxFee,
			true,
		},
		{
			"REVOKE covenant is exempt",
			wire.TxOut{
				Value:    0,
				Address:  stdAddr,
				Covenant: wire.Covenant{Type: wire.CovenantRevoke},
			},
			DefaultMinRelayTxFee,
			false,
		},
		{
			"unknown covenant remains dustworthy",
			wire.TxOut{
				Value:    0,
				Address:  stdAddr,
				Covenant: wire.Covenant{Type: wire.CovenantRevoke + 1},
			},
			DefaultMinRelayTxFee,
			true,
		},
	}
	for _, test := range tests {
		res := IsDust(&test.txOut, test.relayFee)
		if res != test.isDust {
			t.Fatalf("Dust test '%s' failed: want %v got %v",
				test.name, test.isDust, res)
		}
	}
}

// TestCheckTransactionStandard tests the CheckTransactionStandard API.
func TestCheckTransactionStandard(t *testing.T) {
	// maxTxVersion is the max transaction version the test Policy
	// accepts.
	const maxTxVersion = wire.TxVersion

	// nulldataAddr constructs a native Handshake nulldata address.
	nulldataAddr := func(data []byte) wire.Address {
		return wire.Address{Version: 31, Hash: data}
	}

	// Create some dummy, but otherwise standard, data for transactions.
	prevOutHash, err := chainhash.NewHashFromStr("01")
	if err != nil {
		t.Fatalf("NewShaHashFromStr: unexpected error: %v", err)
	}
	dummyPrevOut := wire.OutPoint{Hash: *prevOutHash, Index: 1}
	dummyWitness := wire.TxWitness{bytes.Repeat([]byte{0x00}, 65)}
	dummyTxIn := wire.TxIn{
		PreviousOutPoint: dummyPrevOut,
		Sequence:         wire.MaxTxInSequenceNum,
		Witness:          dummyWitness,
	}
	// Standard P2WPKH address (version 0, 20-byte hash).
	dummyAddr := wire.Address{Version: 0, Hash: make([]byte, 20)}
	dummyAddr.Hash[0] = 0x01
	dummyTxOut := wire.TxOut{
		Value:   100000000, // 1 HNS
		Address: dummyAddr,
	}

	tests := []struct {
		name       string
		tx         wire.MsgTx
		height     int32
		isStandard bool
		code       wire.RejectCode
	}{
		{
			name: "Typical witness pubkey hash transaction",
			tx: wire.MsgTx{
				Version:  maxTxVersion,
				TxIn:     []*wire.TxIn{&dummyTxIn},
				TxOut:    []*wire.TxOut{&dummyTxOut},
				LockTime: 0,
			},
			height:     300000,
			isStandard: true,
		},
		{
			name: "Transaction version too high",
			tx: wire.MsgTx{
				Version:  maxTxVersion + 1,
				TxIn:     []*wire.TxIn{&dummyTxIn},
				TxOut:    []*wire.TxOut{&dummyTxOut},
				LockTime: 0,
			},
			height:     300000,
			isStandard: false,
			code:       wire.RejectNonstandard,
		},
		{
			name: "Transaction is not finalized",
			tx: wire.MsgTx{
				Version: maxTxVersion,
				TxIn: []*wire.TxIn{{
					PreviousOutPoint: dummyPrevOut,
					Sequence:         0,
					Witness:          dummyWitness,
				}},
				TxOut:    []*wire.TxOut{&dummyTxOut},
				LockTime: 300001,
			},
			height:     300000,
			isStandard: false,
			code:       wire.RejectNonstandard,
		},
		{
			name: "Transaction size is too large",
			tx: wire.MsgTx{
				Version: maxTxVersion,
				TxIn:    []*wire.TxIn{&dummyTxIn},
				TxOut: []*wire.TxOut{{
					Value: 0,
					Address: wire.Address{
						Version: 0,
						Hash: bytes.Repeat([]byte{0x00},
							(maxStandardTxWeight/4)+1),
					},
				}},
				LockTime: 0,
			},
			height:     300000,
			isStandard: false,
			code:       wire.RejectNonstandard,
		},
		// Handshake has no SignatureScript; signature script size and
		// push-data-only checks are not applicable (witness-only model).
		{
			name: "Valid but non standard public key script",
			tx: wire.MsgTx{
				Version: maxTxVersion,
				TxIn:    []*wire.TxIn{&dummyTxIn},
				TxOut: []*wire.TxOut{{
					Value:   100000000,
					Address: wire.Address{Version: 1, Hash: []byte{0x01, 0x01}},
				}},
				LockTime: 0,
			},
			height:     300000,
			isStandard: false,
			code:       wire.RejectNonstandard,
		},
		{
			name: "Unknown covenant type",
			tx: wire.MsgTx{
				Version: maxTxVersion,
				TxIn:    []*wire.TxIn{&dummyTxIn},
				TxOut: []*wire.TxOut{{
					Value:   100000000,
					Address: dummyAddr,
					Covenant: wire.Covenant{
						Type: wire.CovenantRevoke + 1,
					},
				}},
				LockTime: 0,
			},
			height:     300000,
			isStandard: false,
			code:       wire.RejectNonstandard,
		},
		{
			name: "More than one nulldata output",
			tx: wire.MsgTx{
				Version: maxTxVersion,
				TxIn:    []*wire.TxIn{&dummyTxIn},
				TxOut: []*wire.TxOut{{
					Value:   0,
					Address: nulldataAddr([]byte{0x00, 0x00}),
				}, {
					Value:   0,
					Address: nulldataAddr([]byte{0x00, 0x00}),
				}},
				LockTime: 0,
			},
			height:     300000,
			isStandard: false,
			code:       wire.RejectNonstandard,
		},
		{
			name: "Dust output",
			tx: wire.MsgTx{
				Version: maxTxVersion,
				TxIn:    []*wire.TxIn{&dummyTxIn},
				TxOut: []*wire.TxOut{{
					Value:   0,
					Address: dummyAddr,
				}},
				LockTime: 0,
			},
			height:     300000,
			isStandard: false,
			code:       wire.RejectDust,
		},
		{
			name: "One nulldata output with 0 amount (standard)",
			tx: wire.MsgTx{
				Version: maxTxVersion,
				TxIn:    []*wire.TxIn{&dummyTxIn},
				TxOut: []*wire.TxOut{{
					Value:   0,
					Address: nulldataAddr([]byte{0x00, 0x00}),
				}},
				LockTime: 0,
			},
			height:     300000,
			isStandard: true,
		},
		{
			name: "Nulldata ignores unknown covenant",
			tx: wire.MsgTx{
				Version: maxTxVersion,
				TxIn:    []*wire.TxIn{&dummyTxIn},
				TxOut: []*wire.TxOut{{
					Value:   0,
					Address: nulldataAddr([]byte{0x00, 0x00}),
					Covenant: wire.Covenant{
						Type: wire.CovenantRevoke + 1,
					},
				}},
				LockTime: 0,
			},
			height:     300000,
			isStandard: true,
		},
		{
			name: "Zero-value OPEN covenant is standard",
			tx: wire.MsgTx{
				Version: maxTxVersion,
				TxIn:    []*wire.TxIn{&dummyTxIn},
				TxOut: []*wire.TxOut{{
					Value:    0,
					Address:  dummyAddr,
					Covenant: wire.Covenant{Type: wire.CovenantOpen},
				}},
				LockTime: 0,
			},
			height:     300000,
			isStandard: true,
		},
	}

	pastMedianTime := time.Now()
	for _, test := range tests {
		// Ensure standardness is as expected.
		err := CheckTransactionStandard(hnsutil.NewTx(&test.tx),
			test.height, pastMedianTime, DefaultMinRelayTxFee, maxTxVersion)
		if err == nil && test.isStandard {
			// Test passes since function returned standard for a
			// transaction which is intended to be standard.
			continue
		}
		if err == nil && !test.isStandard {
			t.Errorf("CheckTransactionStandard (%s): standard when "+
				"it should not be", test.name)
			continue
		}
		if err != nil && test.isStandard {
			t.Errorf("CheckTransactionStandard (%s): nonstandard "+
				"when it should not be: %v", test.name, err)
			continue
		}

		// Ensure error type is a TxRuleError inside of a RuleError.
		rerr, ok := err.(RuleError)
		if !ok {
			t.Errorf("CheckTransactionStandard (%s): unexpected "+
				"error type - got %T", test.name, err)
			continue
		}
		txrerr, ok := rerr.Err.(TxRuleError)
		if !ok {
			t.Errorf("CheckTransactionStandard (%s): unexpected "+
				"error type - got %T", test.name, rerr.Err)
			continue
		}

		// Ensure the reject code is the expected one.
		if txrerr.RejectCode != test.code {
			t.Errorf("CheckTransactionStandard (%s): unexpected "+
				"error code - got %v, want %v", test.name,
				txrerr.RejectCode, test.code)
			continue
		}
	}
}
