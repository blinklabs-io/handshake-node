// Copyright (c) 2024-2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/blinklabs-io/handshake-node/hnsutil"
	"github.com/blinklabs-io/handshake-node/wire"
)

const hsdFaucetProofBase64 = "MAEAAAsk88I7Sy9q89bcBYyQgm1M22vxwC7++XJxyVdqpVvJ8oH32lPurCMb4gg+GRREgJ26Bd23tf1+pDvj8JpGugxrfzWtzF3cRzdXfR64/rndCh1ABd/yjvgKYEOB/yxgN/TTzYcaHLlI/CR33j3OmHfS+e0ktRSb4Yv+fdmBrzJ4XjzbnZcrYBfyhc4QgqN8wM3fuvkNOuviuZsAJYkc3hdngxVZFQX0qQg87SuVDFbUT2GicLlmSwxE3b4Wk2EKthfNrdSa/8r2d0qbA7dyYtSd5Q+IrBLly4N8E2UTweIc8I5xBB7ssWEDGb3VQfroHulv+D0OIINjky32tDnbKYesCsOXdfD+5vDp8dg288NsZacFIpmy6El/ri58E31liXkU2qyvcyA+V+E4wqkPE4CShHqBaAzAbSxddiHnFvAfAFsKPkkdrkOQBJuxX0ZlXjHj2jJTspzwEE9Z0MYwuu2HAAAgBAAU3IMpICLzdoj4PQF5aBqkkHXqaK8U+0f6AQAAAAAAFNyDKSAi83aI+D0BeWgapJB16miv/gDh9QUA"

const hsdGooProofBase64 = "" +
	"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"

func TestAirdropProofFixtureVerifiesMerkleAndSignature(t *testing.T) {
	proof := testHsdFaucetAirdrop(t)
	if !proof.isSane() {
		t.Fatal("hsd faucet proof is not sane")
	}
	if !proof.verifyMerkle() {
		t.Fatal("hsd faucet proof merkle verification failed")
	}
	if !proof.verifySignature() {
		t.Fatal("hsd faucet proof signature verification failed")
	}

	position, err := proof.position()
	if err != nil {
		t.Fatalf("position: %v", err)
	}
	if position != airdropLeaves+proof.index {
		t.Fatalf("position = %d, want %d", position,
			airdropLeaves+proof.index)
	}
}

func TestAirdropProofHsdGooFixtureVerifiesMerkleAndSignature(t *testing.T) {
	proof := testHsdGooAirdrop(t)
	if !proof.isSane() {
		t.Fatal("hsd GooSig proof is not sane")
	}
	if !proof.verifyMerkle() {
		t.Fatal("hsd GooSig proof merkle verification failed")
	}
	key, err := parseAirdropKey(proof.key)
	if err != nil {
		t.Fatalf("parseAirdropKey hsd GooSig proof: %v", err)
	}
	if key.keyType != airdropKeyGoo {
		t.Fatalf("key type = %d, want %d", key.keyType, airdropKeyGoo)
	}
	if len(key.c1) != airdropGooKeySize {
		t.Fatalf("GooSig C1 size = %d, want %d", len(key.c1),
			airdropGooKeySize)
	}
	if !proof.verifySignature() {
		t.Fatal("hsd GooSig proof signature verification failed")
	}
	proof.signature[0] ^= 0x01
	if proof.verifySignature() {
		t.Fatal("tampered hsd GooSig proof passed signature verification")
	}
}

func TestAirdropProofRejectsTamperedMerklePath(t *testing.T) {
	proof := testHsdFaucetAirdrop(t)
	proof.proof[0][0] ^= 0x01
	if proof.verifyMerkle() {
		t.Fatal("tampered hsd faucet proof passed merkle verification")
	}
}

func TestAirdropProofVerifiesRSASignature(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	proof := testAirdropSignatureProof(testAirdropRSAKey(t, privKey))
	msg := proof.signatureHash()
	proof.signature, err = rsa.SignPKCS1v15(rand.Reader, privKey,
		crypto.SHA256, msg[:])
	if err != nil {
		t.Fatalf("SignPKCS1v15: %v", err)
	}
	if !proof.verifySignature() {
		t.Fatal("verifySignature rejected RSA proof")
	}
	proof.signature[0] ^= 0x01
	if proof.verifySignature() {
		t.Fatal("verifySignature accepted tampered RSA proof")
	}
}

func TestAirdropProofVerifiesP256Signature(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	proof := testAirdropSignatureProof(testAirdropP256Key(privKey))
	msg := proof.signatureHash()
	r, s, err := ecdsa.Sign(rand.Reader, privKey, msg[:])
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	proof.signature = append(testPaddedScalar(t, r),
		testPaddedScalar(t, s)...)
	if !proof.verifySignature() {
		t.Fatal("verifySignature rejected P256 proof")
	}
	proof.signature[0] ^= 0x01
	if proof.verifySignature() {
		t.Fatal("verifySignature accepted tampered P256 proof")
	}
}

func TestAirdropProofVerifiesED25519Signature(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	proof := testAirdropSignatureProof(testAirdropED25519Key(pubKey))
	msg := proof.signatureHash()
	proof.signature = ed25519.Sign(privKey, msg[:])
	if !proof.verifySignature() {
		t.Fatal("verifySignature rejected ED25519 proof")
	}
	proof.signature[0] ^= 0x01
	if proof.verifySignature() {
		t.Fatal("verifySignature accepted tampered ED25519 proof")
	}
}

func TestAirdropSpentFieldSpendAndUndo(t *testing.T) {
	proof := testHsdFaucetProof(t)
	block := hnsutil.NewBlock(&wire.MsgBlock{
		Transactions: []*wire.MsgTx{
			testCoinbaseAirdropTx(t, proof),
		},
	})
	field := &airdropSpentField{
		bits: make([]byte, airdropSpentFieldSize),
	}

	if err := field.spendBlock(block); err != nil {
		t.Fatalf("spendBlock: %v", err)
	}
	if err := field.spendBlock(block); err == nil {
		t.Fatal("spendBlock: expected duplicate spend error")
	}
	if err := field.unspendBlock(block); err != nil {
		t.Fatalf("unspendBlock: %v", err)
	}
	if err := field.spendBlock(block); err != nil {
		t.Fatalf("spendBlock after undo: %v", err)
	}
}

func testAirdropSignatureProof(key []byte) *airdropProof {
	return &airdropProof{
		index:   0,
		key:     key,
		version: 0,
		address: bytes.Repeat([]byte{0x42}, 20),
		fee:     100000,
		size:    1,
	}
}

func testAirdropRSAKey(t *testing.T, privKey *rsa.PrivateKey) []byte {
	t.Helper()

	n := privKey.N.Bytes()
	if len(n) > 0xffff {
		t.Fatalf("RSA modulus too large: %d", len(n))
	}
	e := big.NewInt(int64(privKey.E)).Bytes()
	if len(e) > 0xff {
		t.Fatalf("RSA exponent too large: %d", len(e))
	}

	var key bytes.Buffer
	key.WriteByte(airdropKeyRSA)
	var size [2]byte
	binary.LittleEndian.PutUint16(size[:], uint16(len(n)))
	key.Write(size[:])
	key.Write(n)
	key.WriteByte(byte(len(e)))
	key.Write(e)
	key.Write(make([]byte, 32))
	return key.Bytes()
}

func testAirdropP256Key(privKey *ecdsa.PrivateKey) []byte {
	var key bytes.Buffer
	key.WriteByte(airdropKeyP256)
	key.Write(elliptic.MarshalCompressed(elliptic.P256(),
		privKey.PublicKey.X, privKey.PublicKey.Y))
	key.Write(make([]byte, 32))
	return key.Bytes()
}

func testAirdropED25519Key(pubKey ed25519.PublicKey) []byte {
	var key bytes.Buffer
	key.WriteByte(airdropKeyED25519)
	key.Write(pubKey)
	key.Write(make([]byte, 32))
	return key.Bytes()
}

func testPaddedScalar(t *testing.T, scalar *big.Int) []byte {
	t.Helper()

	encoded := scalar.Bytes()
	if len(encoded) > 32 {
		t.Fatalf("scalar length = %d, want <= 32", len(encoded))
	}
	padded := make([]byte, 32)
	copy(padded[32-len(encoded):], encoded)
	return padded
}

func testHsdFaucetProof(t *testing.T) []byte {
	t.Helper()

	proof, err := base64.StdEncoding.DecodeString(hsdFaucetProofBase64)
	if err != nil {
		t.Fatalf("DecodeString hsd faucet proof: %v", err)
	}
	return proof
}

func testHsdFaucetAirdrop(t *testing.T) *airdropProof {
	t.Helper()

	proof, err := parseAirdropProof(testHsdFaucetProof(t))
	if err != nil {
		t.Fatalf("parseAirdropProof hsd faucet proof: %v", err)
	}
	return proof
}

func testHsdGooAirdrop(t *testing.T) *airdropProof {
	t.Helper()

	serialized, err := base64.StdEncoding.DecodeString(hsdGooProofBase64)
	if err != nil {
		t.Fatalf("DecodeString hsd GooSig proof: %v", err)
	}
	proof, err := parseAirdropProof(serialized)
	if err != nil {
		t.Fatalf("parseAirdropProof hsd GooSig proof: %v", err)
	}
	return proof
}

func testCoinbaseAirdropTxFromProof(t *testing.T, proof []byte) (*wire.MsgTx,
	uint64) {

	t.Helper()

	airdrop, err := parseAirdropProof(proof)
	if err != nil {
		t.Fatalf("parseAirdropProof: %v", err)
	}

	value := airdrop.value()
	if value < airdrop.fee {
		t.Fatalf("airdrop value %d below fee %d", value, airdrop.fee)
	}

	tx := wire.NewMsgTx(1)
	tx.AddTxIn(wire.NewTxIn(nullOutPoint(), ^uint32(0),
		wire.TxWitness{[]byte{0x02, 0x01}}))
	tx.AddTxIn(wire.NewTxIn(nullOutPoint(), ^uint32(0),
		wire.TxWitness{proof}))
	tx.AddTxOut(wire.NewTxOut(1, wire.Address{}, wire.Covenant{}))
	tx.AddTxOut(wire.NewTxOut(int64(value-airdrop.fee), wire.Address{
		Version: airdrop.version,
		Hash:    append([]byte(nil), airdrop.address...),
	}, wire.Covenant{}))

	return tx, value
}

func testCoinbaseAirdropTx(t *testing.T, proof []byte) *wire.MsgTx {
	t.Helper()

	tx, _ := testCoinbaseAirdropTxFromProof(t, proof)
	return tx
}
