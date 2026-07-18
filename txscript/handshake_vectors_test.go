// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package txscript

import (
	"bytes"
	"crypto/sha3"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/wire"
	"github.com/btcsuite/btcd/btcec/v2"
)

func TestHandshakeWitnessSighashSignedVector(t *testing.T) {
	keyBytes, err := hex.DecodeString(
		"0000000000000000000000000000000000000000000000000000000000000001",
	)
	if err != nil {
		t.Fatal(err)
	}
	privKey, pubKey := btcec.PrivKeyFromBytes(keyBytes)

	witnessScript, err := NewScriptBuilder().
		AddData(pubKey.SerializeCompressed()).
		AddOp(OP_CHECKSIG).
		Script()
	if err != nil {
		t.Fatalf("witness script: %v", err)
	}
	scriptHash := sha3.Sum256(witnessScript)
	p2wshScript, err := NewScriptBuilder().
		AddOp(OP_0).
		AddData(scriptHash[:]).
		Script()
	if err != nil {
		t.Fatalf("p2wsh script: %v", err)
	}
	prevAddr, err := AddressFromWitnessProgram(p2wshScript)
	if err != nil {
		t.Fatalf("AddressFromWitnessProgram: %v", err)
	}

	var prevHash chainhash.Hash
	for i := range prevHash {
		prevHash[i] = byte(i + 1)
	}
	tx := wire.NewMsgTx(2)
	tx.LockTime = LockTimeFlag | 777
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&prevHash, 7), 0xfffffffe,
		nil))
	tx.AddTxOut(wire.NewTxOut(123456789, wire.Address{
		Version: 0,
		Hash:    repeatBytes(0x42, 20),
	}, wire.Covenant{}))

	const inputAmount = 987654321
	prevFetcher := NewCannedPrevOutputFetcher(prevAddr, inputAmount)
	sigHashes := NewTxSigHashes(tx, prevFetcher)

	digest, err := CalcWitnessSigHash(witnessScript, sigHashes, SigHashAll,
		tx, 0, inputAmount)
	if err != nil {
		t.Fatalf("CalcWitnessSigHash: %v", err)
	}
	const wantDigest = "f8e0b26450c0805b07b37780fe292f7822eeba9981b102520101f04e01d511f6"
	if got := hex.EncodeToString(digest); got != wantDigest {
		t.Fatalf("witness sighash = %s, want %s", got, wantDigest)
	}

	sig, err := RawTxInWitnessSignature(tx, sigHashes, 0, inputAmount,
		witnessScript, SigHashAll, privKey)
	if err != nil {
		t.Fatalf("RawTxInWitnessSignature: %v", err)
	}
	const wantSig = "95b97684e5bbb8db5691a955850a86362189db4b159b6ab4cbf6cfc377bce7ab16500f91a96ee6b2b0bdf45d19e5a7fa6cbb9217c5f7ef497cac8e1548f8b91b01"
	if got := hex.EncodeToString(sig); got != wantSig {
		t.Fatalf("witness signature = %s, want %s", got, wantSig)
	}

	tx.TxIn[0].Witness = wire.TxWitness{sig, witnessScript}
	vm, err := NewEngine(p2wshScript, tx, 0, StandardVerifyFlags, nil,
		sigHashes, inputAmount, prevFetcher)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if err := vm.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
}

func TestPrivateLegacySigHashNullOutputEncoding(t *testing.T) {
	t.Parallel()

	var prevHash chainhash.Hash
	prevHash[0] = 0x01
	tx := wire.NewMsgTx(1)
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&prevHash, 0),
		wire.MaxTxInSequenceNum, nil))
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&prevHash, 1),
		wire.MaxTxInSequenceNum, nil))
	for i := byte(1); i <= 2; i++ {
		tx.AddTxOut(wire.NewTxOut(int64(i), wire.Address{
			Version: 0,
			Hash:    repeatBytes(i, 20),
		}, wire.Covenant{}))
	}
	var wireEncoding bytes.Buffer
	if err := tx.SerializeNoWitness(&wireEncoding); err != nil {
		t.Fatalf("SerializeNoWitness: %v", err)
	}
	var privateEncoding bytes.Buffer
	if err := serializeLegacySigHashTx(&privateEncoding, tx); err != nil {
		t.Fatalf("serializeLegacySigHashTx: %v", err)
	}
	if !bytes.Equal(privateEncoding.Bytes(), wireEncoding.Bytes()) {
		t.Fatal("private legacy serializer differs for valid transaction")
	}
	invalidTx := tx.Copy()
	invalidTx.TxOut[0].Address = wire.Address{}
	privateEncoding.Reset()
	if err := serializeLegacySigHashTx(&privateEncoding, invalidTx); err == nil {
		t.Fatal("private legacy serializer accepted a real empty address")
	}

	// SigHashSingle for input one replaces output zero with the inherited
	// synthetic 0000 address.  That encoding must remain private to this
	// unreachable compatibility path and must not rely on Address.Encode.
	hash := calcSignatureHash(nil, SigHashSingle, tx, 1)
	if len(hash) != chainhash.HashSize {
		t.Fatalf("calcSignatureHash length = %d, want %d",
			len(hash), chainhash.HashSize)
	}
}

func TestTaprootPublicHelpersQuarantined(t *testing.T) {
	keyBytes, err := hex.DecodeString(
		"0000000000000000000000000000000000000000000000000000000000000001",
	)
	if err != nil {
		t.Fatal(err)
	}
	privKey, pubKey := btcec.PrivKeyFromBytes(keyBytes)

	if _, err := PayToTaprootScript(pubKey); !errors.Is(err,
		errTaprootUnsupported) {

		t.Fatalf("PayToTaprootScript error = %v", err)
	}

	tx := wire.NewMsgTx(2)
	var zeroHash chainhash.Hash
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&zeroHash, 0), 0, nil))
	prevFetcher := NewCannedPrevOutputFetcher(wire.Address{
		Version: 1,
		Hash:    repeatBytes(0x11, 32),
	}, 1)
	sigHashes := NewTxSigHashes(tx, prevFetcher)

	if _, err := CalcTaprootSignatureHash(sigHashes, SigHashDefault, tx, 0,
		prevFetcher); !errors.Is(err, errTaprootUnsupported) {

		t.Fatalf("CalcTaprootSignatureHash error = %v", err)
	}
	if _, err := RawTxInTaprootSignature(tx, sigHashes, 0, 1, nil, nil,
		SigHashDefault, privKey); !errors.Is(err, errTaprootUnsupported) {

		t.Fatalf("RawTxInTaprootSignature error = %v", err)
	}
	if _, err := CalcTapscriptSignaturehash(sigHashes, SigHashDefault, tx, 0,
		prevFetcher, TapLeaf{}); !errors.Is(err, errTaprootUnsupported) {

		t.Fatalf("CalcTapscriptSignaturehash error = %v", err)
	}
	if _, err := TaprootWitnessSignature(tx, sigHashes, 0, 1, nil,
		SigHashDefault, privKey); !errors.Is(err, errTaprootUnsupported) {

		t.Fatalf("TaprootWitnessSignature error = %v", err)
	}
	if _, err := RawTxInTapscriptSignature(tx, sigHashes, 0, 1, nil,
		TapLeaf{}, SigHashDefault, privKey); !errors.Is(err,
		errTaprootUnsupported) {

		t.Fatalf("RawTxInTapscriptSignature error = %v", err)
	}

	_, err = CalcSignatureHash(nil, SigHashAll, tx, 0)
	if err == nil {
		t.Fatal("CalcSignatureHash unexpectedly succeeded")
	}
	if strings.Contains(strings.ToLower(err.Error()), "taproot") {
		t.Fatalf("legacy sighash error still points callers at Taproot: %v",
			err)
	}
}

func repeatBytes(fill byte, n int) []byte {
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = fill
	}
	return buf
}
