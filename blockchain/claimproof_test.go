// Copyright (c) 2024-2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/blinklabs-io/handshake-node/chaincfg"
	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/hnsutil"
	"github.com/blinklabs-io/handshake-node/wire"
	"github.com/miekg/dns"
	"golang.org/x/crypto/blake2b"
)

func TestCoinbaseClaimConjuredValue(t *testing.T) {
	params := chaincfg.MainNetParams
	height := uint32(10)
	prevTime := int64(100)
	commitHash := chainhash.Hash{0x44}
	commitHeight := uint32(1)
	addr := wire.Address{
		Version: 0,
		Hash:    testAddressHash(),
	}
	value, ok := reservedNameValue(hashName([]byte("com")))
	if !ok {
		t.Fatal("missing reserved value for com")
	}
	fee := uint64(1000)

	txt := testClaimTXT(t, &params, addr, fee, commitHash, commitHeight)
	proof := testOwnershipProof(t, "com", false, txt, 50, 150)
	tx := testCoinbaseClaimTx(t, height, addr, value-fee, commitHash,
		commitHeight, proof)

	got, err := coinbaseConjuredValue(hnsutil.NewTx(tx), height, prevTime,
		&params)
	if err != nil {
		t.Fatalf("coinbaseConjuredValue: %v", err)
	}
	if got != value {
		t.Fatalf("coinbaseConjuredValue got %d, want %d", got, value)
	}
}

func TestCoinbaseClaimProofFromRaw(t *testing.T) {
	params := chaincfg.MainNetParams
	height := uint32(10)
	prevTime := int64(100)
	commitHash := chainhash.Hash{0x44}
	commitHeight := uint32(1)
	addr := wire.Address{
		Version: 0,
		Hash:    testAddressHash(),
	}
	value, ok := reservedNameValue(hashName([]byte("com")))
	if !ok {
		t.Fatal("missing reserved value for com")
	}
	fee := uint64(1000)

	txt := testClaimTXT(t, &params, addr, fee, commitHash, commitHeight)
	serialized := testOwnershipProof(t, "com", false, txt, 50, 150)
	proof, err := CoinbaseClaimProofFromRaw(serialized, height, prevTime,
		&params)
	if err != nil {
		t.Fatalf("CoinbaseClaimProofFromRaw: %v", err)
	}

	wantHash := chainhash.Hash(blake2b.Sum256(serialized))
	if proof.Hash != wantHash {
		t.Fatalf("proof hash = %x, want %x", proof.Hash[:],
			wantHash[:])
	}
	if !bytes.Equal(proof.Witness, serialized) {
		t.Fatal("proof witness does not match serialized claim")
	}
	if proof.Fee != int64(fee) {
		t.Fatalf("proof fee = %d, want %d", proof.Fee, fee)
	}
	if proof.Output.Value != int64(value-fee) {
		t.Fatalf("output value = %d, want %d", proof.Output.Value,
			value-fee)
	}
	if proof.Output.Covenant.Type != wire.CovenantClaim {
		t.Fatalf("covenant type = %d, want CLAIM",
			proof.Output.Covenant.Type)
	}
	if got := binary.LittleEndian.Uint32(
		proof.Output.Covenant.Items[1]); got != height {

		t.Fatalf("claim height = %d, want %d", got, height)
	}
}

func TestVerifyCoinbaseClaimProofDataRejectsNullData(t *testing.T) {
	txOut := wire.NewTxOut(0, wire.Address{Version: 31}, wire.Covenant{
		Type: wire.CovenantClaim,
	})
	_, err := verifyCoinbaseClaimProofData(txOut, txOut.Covenant, 10,
		&chaincfg.MainNetParams, &claimProofData{version: 31})
	if err == nil || !strings.Contains(err.Error(), "nulldata") {
		t.Fatalf("verifyCoinbaseClaimProofData error = %v, want nulldata rejection",
			err)
	}
}

func TestCoinbaseAirdropProofFromRaw(t *testing.T) {
	serialized := testHsdFaucetProof(t)
	if _, err := CoinbaseAirdropProofFromRaw(serialized, 10, nil); err == nil ||
		!strings.Contains(err.Error(), "missing chain parameters") {

		t.Fatalf("CoinbaseAirdropProofFromRaw nil params error = %v", err)
	}

	proof, err := CoinbaseAirdropProofFromRaw(serialized, 10,
		&chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("CoinbaseAirdropProofFromRaw: %v", err)
	}

	airdrop, err := parseAirdropProof(serialized)
	if err != nil {
		t.Fatalf("parseAirdropProof: %v", err)
	}
	wantHash := chainhash.Hash(blake2b.Sum256(serialized))
	if proof.Hash != wantHash {
		t.Fatalf("proof hash = %x, want %x", proof.Hash[:],
			wantHash[:])
	}
	if !bytes.Equal(proof.Witness, serialized) {
		t.Fatal("proof witness does not match serialized airdrop")
	}
	if proof.Fee != int64(airdrop.fee) {
		t.Fatalf("proof fee = %d, want %d", proof.Fee, airdrop.fee)
	}
	if proof.Output.Value != int64(airdrop.value()-airdrop.fee) {
		t.Fatalf("output value = %d, want %d", proof.Output.Value,
			airdrop.value()-airdrop.fee)
	}
	if proof.Output.Covenant.Type != wire.CovenantNone {
		t.Fatalf("covenant type = %d, want NONE",
			proof.Output.Covenant.Type)
	}
}

func TestCoinbaseClaimConjuredValueRejectsMismatch(t *testing.T) {
	params := chaincfg.MainNetParams
	height := uint32(10)
	commitHash := chainhash.Hash{0x44}
	commitHeight := uint32(1)
	addr := wire.Address{
		Version: 0,
		Hash:    testAddressHash(),
	}
	value, ok := reservedNameValue(hashName([]byte("com")))
	if !ok {
		t.Fatal("missing reserved value for com")
	}
	fee := uint64(1000)

	txt := testClaimTXT(t, &params, addr, fee, commitHash, commitHeight)
	proof := testOwnershipProof(t, "com", false, txt, 50, 150)
	tx := testCoinbaseClaimTx(t, height, addr, value-fee-1, commitHash,
		commitHeight, proof)

	if _, err := coinbaseConjuredValue(hnsutil.NewTx(tx), height, 100,
		&params); err == nil {

		t.Fatal("coinbaseConjuredValue: expected output value error")
	}
}

func TestCoinbaseClaimConjuredValueRejectsExpiredProof(t *testing.T) {
	params := chaincfg.MainNetParams
	height := uint32(10)
	commitHash := chainhash.Hash{0x44}
	commitHeight := uint32(1)
	addr := wire.Address{
		Version: 0,
		Hash:    testAddressHash(),
	}
	value, ok := reservedNameValue(hashName([]byte("com")))
	if !ok {
		t.Fatal("missing reserved value for com")
	}
	fee := uint64(1000)

	txt := testClaimTXT(t, &params, addr, fee, commitHash, commitHeight)
	proof := testOwnershipProof(t, "com", false, txt, 50, 75)
	tx := testCoinbaseClaimTx(t, height, addr, value-fee, commitHash,
		commitHeight, proof)

	if _, err := coinbaseConjuredValue(hnsutil.NewTx(tx), height, 100,
		&params); err == nil {

		t.Fatal("coinbaseConjuredValue: expected expired proof error")
	}
}

func TestCoinbaseClaimConjuredValueRejectsWeakAfterHardening(t *testing.T) {
	params := chaincfg.MainNetParams
	height := uint32(10)
	prevTime := int64(100)
	commitHash := chainhash.Hash{0x44}
	commitHeight := uint32(1)
	addr := wire.Address{
		Version: 0,
		Hash:    testAddressHash(),
	}
	value, ok := reservedNameValue(hashName([]byte("com")))
	if !ok {
		t.Fatal("missing reserved value for com")
	}
	fee := uint64(1000)

	txt := testClaimTXT(t, &params, addr, fee, commitHash, commitHeight)
	proof := testOwnershipProof(t, "com", true, txt, 50, 150)
	tx := testCoinbaseClaimTxWithWeak(t, height, addr, value-fee,
		commitHash, commitHeight, proof, true)

	got, err := coinbaseConjuredValue(hnsutil.NewTx(tx), height, prevTime,
		&params)
	if err != nil {
		t.Fatalf("coinbaseConjuredValue before hardening: %v", err)
	}
	if got != value {
		t.Fatalf("coinbaseConjuredValue got %d, want %d", got, value)
	}

	_, err = coinbaseConjuredValue(hnsutil.NewTx(tx), height, prevTime,
		&params, handshakeDeploymentFlags{hardeningActive: true})
	if err == nil {
		t.Fatal("coinbaseConjuredValue: expected weak CLAIM error")
	}
	if !strings.Contains(err.Error(), "weak algorithm") {
		t.Fatalf("coinbaseConjuredValue weak CLAIM error = %v", err)
	}
}

func TestCoinbaseAirdropConjuredValue(t *testing.T) {
	proof := testHsdFaucetProof(t)
	tx, value := testCoinbaseAirdropTxFromProof(t, proof)

	got, err := coinbaseConjuredValue(hnsutil.NewTx(tx), 10, 0,
		&chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("coinbaseConjuredValue: %v", err)
	}
	if got != value {
		t.Fatalf("coinbaseConjuredValue got %d, want %d", got, value)
	}
}

func TestCoinbaseAirdropConjuredValueRejectsAirstop(t *testing.T) {
	proof := testHsdFaucetProof(t)
	tx, _ := testCoinbaseAirdropTxFromProof(t, proof)

	if _, err := coinbaseConjuredValue(hnsutil.NewTx(tx), 10, 0,
		&chaincfg.MainNetParams,
		handshakeDeploymentFlags{airstopActive: true}); err == nil {

		t.Fatal("coinbaseConjuredValue: expected airstop error")
	}
}

func TestCoinbaseAirdropConjuredValueRejectsWeakAfterHardening(t *testing.T) {
	proof := testWeakRSAAirdropProof(t)
	tx, _ := testCoinbaseAirdropTxFromProof(t, proof)

	_, err := coinbaseConjuredValue(hnsutil.NewTx(tx), 10, 0,
		&chaincfg.MainNetParams,
		handshakeDeploymentFlags{hardeningActive: true})
	if err == nil {
		t.Fatal("coinbaseConjuredValue: expected weak airdrop error")
	}
	if !strings.Contains(err.Error(), "weak algorithm") {
		t.Fatalf("coinbaseConjuredValue weak airdrop error = %v", err)
	}
}

func TestCoinbaseAirdropConjuredValueRejectsGooSigCutoff(t *testing.T) {
	params := chaincfg.MainNetParams
	proof, err := base64.StdEncoding.DecodeString(hsdGooProofBase64)
	if err != nil {
		t.Fatalf("DecodeString hsd GooSig proof: %v", err)
	}
	tx, value := testCoinbaseAirdropTxFromProof(t, proof)

	got, err := coinbaseConjuredValue(hnsutil.NewTx(tx),
		params.AirdropGooSigStop-1, 0, &params)
	if err != nil {
		t.Fatalf("coinbaseConjuredValue before cutoff: %v", err)
	}
	if got != value {
		t.Fatalf("coinbaseConjuredValue got %d, want %d", got, value)
	}

	if _, err := coinbaseConjuredValue(hnsutil.NewTx(tx),
		params.AirdropGooSigStop, 0, &params); err == nil {

		t.Fatal("coinbaseConjuredValue: expected GooSig cutoff error")
	}
	if _, err := coinbaseConjuredValue(hnsutil.NewTx(tx),
		params.AirdropGooSigStop-1, 0, nil); err == nil {

		t.Fatal("coinbaseConjuredValue: expected nil params GooSig error")
	}
}

func TestCoinbaseAirdropConjuredValueRejectsDuplicateProof(t *testing.T) {
	proof := testHsdFaucetProof(t)
	airdrop, err := parseAirdropProof(proof)
	if err != nil {
		t.Fatalf("parseAirdropProof: %v", err)
	}
	value := airdrop.value()
	outputValue := value - airdrop.fee
	addr := wire.Address{
		Version: airdrop.version,
		Hash:    append([]byte(nil), airdrop.address...),
	}

	tx := wire.NewMsgTx(1)
	tx.AddTxIn(wire.NewTxIn(nullOutPoint(), ^uint32(0),
		wire.TxWitness{[]byte{0x02, 0x01}}))
	tx.AddTxIn(wire.NewTxIn(nullOutPoint(), ^uint32(0),
		wire.TxWitness{proof}))
	tx.AddTxIn(wire.NewTxIn(nullOutPoint(), ^uint32(0),
		wire.TxWitness{proof}))
	tx.AddTxOut(wire.NewTxOut(1, wire.Address{}, wire.Covenant{}))
	tx.AddTxOut(wire.NewTxOut(int64(outputValue), addr, wire.Covenant{}))
	tx.AddTxOut(wire.NewTxOut(int64(outputValue), addr, wire.Covenant{}))

	if _, err := coinbaseConjuredValue(hnsutil.NewTx(tx), 10, 0,
		&chaincfg.MainNetParams); err == nil {

		t.Fatal("coinbaseConjuredValue: expected duplicate proof error")
	}
}

func TestCoinbaseAirdropConjuredValueRejectsMismatch(t *testing.T) {
	proof := testHsdFaucetProof(t)
	tx, _ := testCoinbaseAirdropTxFromProof(t, proof)
	tx.TxOut[1].Value--

	if _, err := coinbaseConjuredValue(hnsutil.NewTx(tx), 10, 0,
		&chaincfg.MainNetParams); err == nil {

		t.Fatal("coinbaseConjuredValue: expected airdrop value error")
	}
}

func TestCoinbaseClaimProofSanityRejectsNameMismatch(t *testing.T) {
	tx := wire.NewMsgTx(1)
	tx.AddTxIn(wire.NewTxIn(nullOutPoint(), ^uint32(0),
		wire.TxWitness{[]byte{0x02, 0x01}}))
	tx.AddTxIn(wire.NewTxIn(nullOutPoint(), ^uint32(0),
		wire.TxWitness{testOwnershipProof(t, "net", false,
			"not-a-claim-payload", 1, 2)}))
	tx.AddTxOut(wire.NewTxOut(1, wire.Address{}, wire.Covenant{}))
	tx.AddTxOut(wire.NewTxOut(1, wire.Address{}, claimCovenant("com")))

	if err := CheckTransactionSanity(hnsutil.NewTx(tx)); err == nil {
		t.Fatal("CheckTransactionSanity: expected proof name mismatch")
	}
}

func testAirdropProof(t *testing.T, addr wire.Address, value, fee uint64) []byte {
	t.Helper()

	var key bytes.Buffer
	key.WriteByte(airdropKeyAddress)
	key.WriteByte(addr.Version)
	key.WriteByte(byte(len(addr.Hash)))
	key.Write(addr.Hash)
	var valueBytes [8]byte
	binary.LittleEndian.PutUint64(valueBytes[:], value)
	key.Write(valueBytes[:])
	key.WriteByte(0)

	var proof bytes.Buffer
	var index [4]byte
	proof.Write(index[:])
	proof.WriteByte(0)
	proof.WriteByte(0)
	proof.WriteByte(0)
	if err := wire.WriteVarInt(&proof, 0, uint64(key.Len())); err != nil {
		t.Fatalf("WriteVarInt key: %v", err)
	}
	proof.Write(key.Bytes())
	proof.WriteByte(addr.Version)
	proof.WriteByte(byte(len(addr.Hash)))
	proof.Write(addr.Hash)
	if err := wire.WriteVarInt(&proof, 0, fee); err != nil {
		t.Fatalf("WriteVarInt fee: %v", err)
	}
	proof.WriteByte(0)

	return proof.Bytes()
}

func testWeakRSAAirdropProof(t *testing.T) []byte {
	t.Helper()

	var key bytes.Buffer
	key.WriteByte(airdropKeyRSA)
	var sizeBytes [2]byte
	binary.LittleEndian.PutUint16(sizeBytes[:], 128)
	key.Write(sizeBytes[:])
	n := make([]byte, 128)
	n[0] = 0x80
	key.Write(n)
	key.WriteByte(3)
	key.Write([]byte{0x01, 0x00, 0x01})
	key.Write(bytes.Repeat([]byte{0x11}, 32))

	var proof bytes.Buffer
	var index [4]byte
	proof.Write(index[:])
	proof.WriteByte(0)
	proof.WriteByte(0)
	proof.WriteByte(0)
	writeAirdropVarBytes(&proof, key.Bytes())
	proof.WriteByte(0)
	proof.WriteByte(20)
	proof.Write(bytes.Repeat([]byte{0xbb}, 20))
	if err := wire.WriteVarInt(&proof, 0, 0); err != nil {
		t.Fatalf("WriteVarInt fee: %v", err)
	}
	writeAirdropVarBytes(&proof, nil)

	return proof.Bytes()
}

func testAddressHash() []byte {
	return bytes.Repeat([]byte{0xaa}, 20)
}

func testCoinbaseClaimTx(t *testing.T, height uint32, addr wire.Address,
	outputValue uint64, commitHash chainhash.Hash, commitHeight uint32,
	proof []byte) *wire.MsgTx {

	return testCoinbaseClaimTxWithWeak(t, height, addr, outputValue,
		commitHash, commitHeight, proof, false)
}

func testCoinbaseClaimTxWithWeak(t *testing.T, height uint32,
	addr wire.Address, outputValue uint64, commitHash chainhash.Hash,
	commitHeight uint32, proof []byte, weak bool) *wire.MsgTx {

	t.Helper()
	if outputValue > uint64(hnsutil.MaxDoo) {
		t.Fatalf("output value %d exceeds max money", outputValue)
	}

	tx := wire.NewMsgTx(1)
	tx.AddTxIn(wire.NewTxIn(nullOutPoint(), ^uint32(0),
		wire.TxWitness{[]byte{0x02, 0x01}}))
	tx.AddTxIn(wire.NewTxIn(nullOutPoint(), ^uint32(0),
		wire.TxWitness{proof}))
	tx.AddTxOut(wire.NewTxOut(1, wire.Address{}, wire.Covenant{}))
	tx.AddTxOut(wire.NewTxOut(int64(outputValue), addr,
		claimCovenantAt("com", height, commitHash, commitHeight, weak)))
	return tx
}

func testClaimTXT(t *testing.T, params *chaincfg.Params, addr wire.Address,
	fee uint64, commitHash chainhash.Hash, commitHeight uint32) string {

	t.Helper()
	var buf bytes.Buffer
	buf.WriteByte(addr.Version)
	buf.WriteByte(byte(len(addr.Hash)))
	buf.Write(addr.Hash)
	if err := wire.WriteVarInt(&buf, 0, fee); err != nil {
		t.Fatalf("WriteVarInt: %v", err)
	}
	buf.Write(commitHash[:])
	var scratch [4]byte
	binary.LittleEndian.PutUint32(scratch[:], commitHeight)
	buf.Write(scratch[:])
	sum := blake2b.Sum256(buf.Bytes())
	buf.Write(sum[:4])

	return params.NameClaimPrefix + strings.ToLower(
		claimBase32.EncodeToString(buf.Bytes()))
}

func testOwnershipProof(t *testing.T, name string, weak bool, txt string,
	inception, expiration uint32) []byte {

	t.Helper()
	keyBits := 2048
	if weak {
		keyBits = 1024
	}

	rootKey := testDNSKEY(".", keyBits)
	rootSig := testRRSIG(".", ".", dns.TypeDNSKEY, rootKey, inception,
		expiration)
	dsName := dns.Fqdn(name)
	rootDS := &dns.DS{
		Hdr: dns.RR_Header{
			Name:   dsName,
			Rrtype: dns.TypeDS,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		KeyTag:     1,
		Algorithm:  dns.RSASHA256,
		DigestType: dns.SHA256,
		Digest:     strings.Repeat("00", 32),
	}
	rootDSSig := testRRSIG(dsName, ".", dns.TypeDS, rootKey, inception,
		expiration)

	claimKey := testDNSKEY(dsName, keyBits)
	claimKeySig := testRRSIG(dsName, dsName, dns.TypeDNSKEY, claimKey,
		inception, expiration)
	claimTXT := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   dsName,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Txt: []string{txt},
	}
	claimTXTSig := testRRSIG(dsName, dsName, dns.TypeTXT, claimKey,
		inception, expiration)

	var proof []byte
	proof = append(proof, 2)
	proof = appendProofZone(t, proof,
		[]dns.RR{rootKey, rootSig},
		[]dns.RR{rootDS, rootDSSig},
		nil)
	proof = appendProofZone(t, proof,
		[]dns.RR{claimKey, claimKeySig},
		nil,
		[]dns.RR{claimTXT, claimTXTSig})
	return proof
}

func testDNSKEY(name string, keyBits int) *dns.DNSKEY {
	return &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(name),
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Flags:     dns.ZONE,
		Protocol:  3,
		Algorithm: dns.RSASHA256,
		PublicKey: testRSAPublicKey(keyBits),
	}
}

func testRRSIG(name, signer string, covered uint16, key *dns.DNSKEY,
	inception, expiration uint32) *dns.RRSIG {

	fqdnName := dns.Fqdn(name)
	return &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   fqdnName,
			Rrtype: dns.TypeRRSIG,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		TypeCovered: covered,
		Algorithm:   dns.RSASHA256,
		Labels:      uint8(dns.CountLabel(fqdnName)),
		OrigTtl:     3600,
		Expiration:  expiration,
		Inception:   inception,
		KeyTag:      key.KeyTag(),
		SignerName:  dns.Fqdn(signer),
		Signature:   "AQID",
	}
}

func appendProofZone(t *testing.T, proof []byte, keys, referral,
	claim []dns.RR) []byte {

	t.Helper()
	for _, set := range [][]dns.RR{keys, referral, claim} {
		if len(set) > 255 {
			t.Fatal("proof set too large")
		}
		proof = append(proof, byte(len(set)))
		for _, rr := range set {
			proof = appendPackedRR(t, proof, rr)
		}
	}
	return proof
}

func appendPackedRR(t *testing.T, proof []byte, rr dns.RR) []byte {
	t.Helper()
	var scratch [4096]byte
	n, err := dns.PackRR(rr, scratch[:], 0, nil, false)
	if err != nil {
		t.Fatalf("PackRR(%T): %v", rr, err)
	}
	return append(proof, scratch[:n]...)
}

func testRSAPublicKey(keyBits int) string {
	modulus := make([]byte, keyBits/8)
	modulus[0] = 0x80
	raw := append([]byte{3, 0x01, 0x00, 0x01}, modulus...)
	return base64.StdEncoding.EncodeToString(raw)
}
