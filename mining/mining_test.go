// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mining

import (
	"bytes"
	"container/heap"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"io"
	"math/rand"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blinklabs-io/handshake-node/blockchain"
	"github.com/blinklabs-io/handshake-node/chaincfg"
	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/database"
	_ "github.com/blinklabs-io/handshake-node/database/ffldb"
	"github.com/blinklabs-io/handshake-node/hnsutil"
	"github.com/blinklabs-io/handshake-node/txscript"
	"github.com/blinklabs-io/handshake-node/wire"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/miekg/dns"
	"golang.org/x/crypto/blake2b"
)

var miningTestClaimBase32 = base32.StdEncoding.WithPadding(base32.NoPadding)

var bitcoinWitnessMagicBytes = []byte{
	txscript.OP_RETURN,
	txscript.OP_DATA_36,
	0xaa,
	0x21,
	0xa9,
	0xed,
}

type emptyTestTxSource struct{}

func (emptyTestTxSource) LastUpdated() time.Time { return time.Time{} }
func (emptyTestTxSource) MiningDescs() []*TxDesc { return nil }
func (emptyTestTxSource) HaveTransaction(*chainhash.Hash) bool {
	return false
}

type staticTestTxSource struct {
	txs            []*TxDesc
	updated        time.Time
	have           map[chainhash.Hash]struct{}
	coinbaseProofs []CoinbaseProof
}

func newStaticTestTxSource(txs ...*TxDesc) staticTestTxSource {
	have := make(map[chainhash.Hash]struct{}, len(txs))
	for _, tx := range txs {
		have[*tx.Tx.Hash()] = struct{}{}
	}
	return staticTestTxSource{
		txs:     txs,
		updated: time.Now(),
		have:    have,
	}
}

func (s staticTestTxSource) LastUpdated() time.Time { return s.updated }
func (s staticTestTxSource) MiningDescs() []*TxDesc { return s.txs }
func (s staticTestTxSource) HaveTransaction(hash *chainhash.Hash) bool {
	if hash == nil {
		return false
	}
	_, ok := s.have[*hash]
	return ok
}
func (s staticTestTxSource) CoinbaseProofs(int32) ([]CoinbaseProof, error) {
	return s.coinbaseProofs, nil
}

type rejectingNameView struct {
	t            *testing.T
	forbidden    chainhash.Hash
	wantPrevTime int64
	applied      []chainhash.Hash
}

func (v *rejectingNameView) ApplyTransaction(tx *hnsutil.Tx, height int32,
	prevTime int64, view *blockchain.UtxoViewpoint) error {

	v.t.Helper()

	_ = height
	_ = view

	if v.wantPrevTime != 0 && prevTime != v.wantPrevTime {
		v.t.Fatalf("name validation prevTime = %d, want %d",
			prevTime, v.wantPrevTime)
	}

	txHash := tx.Hash()
	if txHash.IsEqual(&v.forbidden) {
		v.t.Fatalf("name validation ran before script validation for %v",
			txHash)
	}
	v.applied = append(v.applied, *txHash)
	return nil
}

func newMiningTestChain(t *testing.T, params *chaincfg.Params) (
	*blockchain.BlockChain, blockchain.MedianTimeSource,
	*txscript.SigCache, *txscript.HashCache, func()) {

	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "ffldb")
	db, err := database.Create("ffldb", dbPath, params.Net)
	if err != nil {
		t.Fatalf("database.Create: %v", err)
	}

	timeSource := blockchain.NewMedianTime()
	sigCache := txscript.NewSigCache(1000)
	hashCache := txscript.NewHashCache(1000)
	chain, err := blockchain.New(&blockchain.Config{
		DB:          db,
		ChainParams: params,
		TimeSource:  timeSource,
		SigCache:    sigCache,
	})
	if err != nil {
		db.Close()
		t.Fatalf("blockchain.New: %v", err)
	}

	return chain, timeSource, sigCache, hashCache, func() {
		db.Close()
	}
}

func miningTestKeyAddress(t *testing.T, params *chaincfg.Params) (
	*btcec.PrivateKey, hnsutil.Address, wire.Address, []byte) {

	t.Helper()

	keyBytes := make([]byte, 32)
	keyBytes[31] = 1
	privKey, pubKey := btcec.PrivKeyFromBytes(keyBytes)
	payAddr, err := hnsutil.NewAddressPubKeyHash(
		hnsutil.Blake160(pubKey.SerializeCompressed()), params,
	)
	if err != nil {
		t.Fatalf("NewAddressPubKeyHash: %v", err)
	}
	payScript, err := txscript.PayToAddrScript(payAddr)
	if err != nil {
		t.Fatalf("PayToAddrScript: %v", err)
	}
	payWireAddr := wire.Address{
		Version: payAddr.Version(),
		Hash:    payAddr.ScriptAddress(),
	}

	return privKey, payAddr, payWireAddr, payScript
}

func solveMiningTestBlock(t *testing.T, msgBlock *wire.MsgBlock) {
	t.Helper()

	targetDifficulty := blockchain.CompactToBig(msgBlock.Header.Bits)
	for nonce := uint32(0); ; nonce++ {
		msgBlock.Header.Nonce = nonce
		hash := msgBlock.Header.BlockHash()
		if blockchain.HashToBig(&hash).Cmp(targetDifficulty) <= 0 {
			return
		}
		if nonce == ^uint32(0) {
			break
		}
	}

	t.Fatalf("unable to solve block at difficulty %08x", msgBlock.Header.Bits)
}

func connectMiningTestTemplate(t *testing.T, chain *blockchain.BlockChain,
	template *BlockTemplate) {

	t.Helper()

	solveMiningTestBlock(t, template.Block)
	block := hnsutil.NewBlock(template.Block)
	block.SetHeight(template.Height)
	isMainChain, isOrphan, err := chain.ProcessBlock(block, blockchain.BFNone)
	if err != nil {
		t.Fatalf("ProcessBlock height %d: %v", template.Height, err)
	}
	if !isMainChain || isOrphan {
		t.Fatalf("ProcessBlock height %d main=%v orphan=%v, want main "+
			"chain non-orphan", template.Height, isMainChain,
			isOrphan)
	}
	if best := chain.BestSnapshot(); best.Height != template.Height {
		t.Fatalf("best height = %d, want %d", best.Height,
			template.Height)
	}
}

func miningTestSpend(t *testing.T, prevHash chainhash.Hash, value, fee int64,
	privKey *btcec.PrivateKey, payWireAddr wire.Address,
	payScript []byte) *hnsutil.Tx {

	t.Helper()

	if fee >= value {
		t.Fatalf("fee %d must be below input value %d", fee, value)
	}

	spendTx := wire.NewMsgTx(wire.TxVersion)
	spendTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  prevHash,
			Index: 0,
		},
		Sequence: wire.MaxTxInSequenceNum,
	})
	spendTx.AddTxOut(&wire.TxOut{
		Value:   value - fee,
		Address: payWireAddr,
	})

	sigHashes := txscript.NewTxSigHashes(spendTx,
		txscript.NewCannedPrevOutputFetcher(payWireAddr, value))
	witness, err := txscript.WitnessSignature(spendTx, sigHashes, 0,
		value, payScript, txscript.SigHashAll, privKey, true)
	if err != nil {
		t.Fatalf("WitnessSignature: %v", err)
	}
	spendTx.TxIn[0].Witness = witness

	return hnsutil.NewTx(spendTx)
}

func miningTestTxDesc(tx *hnsutil.Tx, fee int64, height int32) *TxDesc {
	return &TxDesc{
		Tx:       tx,
		Added:    time.Now(),
		Height:   height,
		Fee:      fee,
		FeePerKB: fee * 1000 / int64(tx.MsgTx().SerializeSize()),
	}
}

func miningTestHighSigOpAddress(t *testing.T,
	params *chaincfg.Params) (hnsutil.Address, []byte) {

	t.Helper()

	witnessScript := bytes.Repeat([]byte{txscript.OP_CHECKSIG},
		blockchain.MaxBlockSigOpsCost+1)
	scriptHash := sha256.Sum256(witnessScript)
	addr, err := hnsutil.NewAddress(0, scriptHash[:], params)
	if err != nil {
		t.Fatalf("NewAddress P2WSH: %v", err)
	}

	return addr, witnessScript
}

const miningTestHsdFaucetProofBase64 = "MAEAAAsk88I7Sy9q89bcBYyQgm1M22vxwC7++XJxyVdqpVvJ8oH32lPurCMb4gg+GRREgJ26Bd23tf1+pDvj8JpGugxrfzWtzF3cRzdXfR64/rndCh1ABd/yjvgKYEOB/yxgN/TTzYcaHLlI/CR33j3OmHfS+e0ktRSb4Yv+fdmBrzJ4XjzbnZcrYBfyhc4QgqN8wM3fuvkNOuviuZsAJYkc3hdngxVZFQX0qQg87SuVDFbUT2GicLlmSwxE3b4Wk2EKthfNrdSa/8r2d0qbA7dyYtSd5Q+IrBLly4N8E2UTweIc8I5xBB7ssWEDGb3VQfroHulv+D0OIINjky32tDnbKYesCsOXdfD+5vDp8dg288NsZacFIpmy6El/ri58E31liXkU2qyvcyA+V+E4wqkPE4CShHqBaAzAbSxddiHnFvAfAFsKPkkdrkOQBJuxX0ZlXjHj2jJTspzwEE9Z0MYwuu2HAAAgBAAU3IMpICLzdoj4PQF5aBqkkHXqaK8U+0f6AQAAAAAAFNyDKSAi83aI+D0BeWgapJB16miv/gDh9QUA"

func miningTestAirdropProof(t *testing.T) ([]byte, *wire.TxOut, uint64) {

	t.Helper()

	proof, err := base64.StdEncoding.DecodeString(
		miningTestHsdFaucetProofBase64)
	if err != nil {
		t.Fatalf("DecodeString hsd faucet proof: %v", err)
	}

	r := bytes.NewReader(proof)
	if _, err := r.Seek(4, io.SeekCurrent); err != nil {
		t.Fatalf("seek index: %v", err)
	}

	proofCount, err := r.ReadByte()
	if err != nil {
		t.Fatalf("read proof count: %v", err)
	}
	if _, err := r.Seek(int64(proofCount)*32, io.SeekCurrent); err != nil {
		t.Fatalf("seek proof path: %v", err)
	}
	if _, err := r.ReadByte(); err != nil {
		t.Fatalf("read subindex: %v", err)
	}
	subproofCount, err := r.ReadByte()
	if err != nil {
		t.Fatalf("read subproof count: %v", err)
	}
	if _, err := r.Seek(int64(subproofCount)*32, io.SeekCurrent); err != nil {
		t.Fatalf("seek subproof path: %v", err)
	}

	keySize, err := wire.ReadVarInt(r, 0)
	if err != nil {
		t.Fatalf("ReadVarInt key: %v", err)
	}
	key := make([]byte, keySize)
	if _, err := io.ReadFull(r, key); err != nil {
		t.Fatalf("read key: %v", err)
	}
	if len(key) < 32 || key[0] != 4 {
		t.Fatalf("unexpected hsd faucet key length/type %d/%d",
			len(key), key[0])
	}
	keyAddressSize := int(key[2])
	valueOffset := 3 + keyAddressSize
	value := binary.LittleEndian.Uint64(key[valueOffset : valueOffset+8])

	version, err := r.ReadByte()
	if err != nil {
		t.Fatalf("read output version: %v", err)
	}
	addressSize, err := r.ReadByte()
	if err != nil {
		t.Fatalf("read output address size: %v", err)
	}
	address := make([]byte, addressSize)
	if _, err := io.ReadFull(r, address); err != nil {
		t.Fatalf("read output address: %v", err)
	}

	fee, err := wire.ReadVarInt(r, 0)
	if err != nil {
		t.Fatalf("ReadVarInt fee: %v", err)
	}
	if value < fee {
		t.Fatalf("airdrop value %d below fee %d", value, fee)
	}

	output := wire.NewTxOut(int64(value-fee), wire.Address{
		Version: version,
		Hash:    address,
	}, wire.Covenant{})
	return proof, output, fee
}

func miningTestClaimProof(t *testing.T, params *chaincfg.Params,
	name string, addr wire.Address, value, fee uint64,
	claimHeight uint32, commitHash chainhash.Hash,
	commitHeight uint32) ([]byte, *wire.TxOut) {

	t.Helper()

	if value < fee {
		t.Fatalf("claim value %d below fee %d", value, fee)
	}
	txt := miningTestClaimTXT(t, params, addr, fee, commitHash,
		commitHeight)
	proof := miningTestOwnershipProof(t, name, false, txt, 1,
		^uint32(0))
	output := wire.NewTxOut(int64(value-fee), addr,
		miningTestClaimCovenant(name, claimHeight, commitHash,
			commitHeight, false))
	return proof, output
}

func miningTestClaimTXT(t *testing.T, params *chaincfg.Params,
	addr wire.Address, fee uint64, commitHash chainhash.Hash,
	commitHeight uint32) string {

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
		miningTestClaimBase32.EncodeToString(buf.Bytes()))
}

func miningTestClaimCovenant(name string, height uint32,
	commitHash chainhash.Hash, commitHeight uint32, weak bool) wire.Covenant {

	flags := byte(0)
	if weak {
		flags = 1
	}

	return wire.Covenant{
		Type: wire.CovenantClaim,
		Items: [][]byte{
			miningTestHashBytes(blockchain.HashName([]byte(name))),
			miningTestU32Item(height),
			[]byte(name),
			{flags},
			miningTestHashBytes(commitHash),
			miningTestU32Item(commitHeight),
		},
	}
}

func miningTestOwnershipProof(t *testing.T, name string, weak bool,
	txt string, inception, expiration uint32) []byte {

	t.Helper()

	keyBits := 2048
	if weak {
		keyBits = 1024
	}

	rootKey := miningTestDNSKEY(".", keyBits)
	rootSig := miningTestRRSIG(".", ".", dns.TypeDNSKEY, rootKey,
		inception, expiration)
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
	rootDSSig := miningTestRRSIG(dsName, ".", dns.TypeDS, rootKey,
		inception, expiration)

	claimKey := miningTestDNSKEY(dsName, keyBits)
	claimKeySig := miningTestRRSIG(dsName, dsName, dns.TypeDNSKEY,
		claimKey, inception, expiration)
	claimTXT := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   dsName,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Txt: []string{txt},
	}
	claimTXTSig := miningTestRRSIG(dsName, dsName, dns.TypeTXT,
		claimKey, inception, expiration)

	var proof []byte
	proof = append(proof, 2)
	proof = miningTestAppendProofZone(t, proof,
		[]dns.RR{rootKey, rootSig},
		[]dns.RR{rootDS, rootDSSig},
		nil)
	proof = miningTestAppendProofZone(t, proof,
		[]dns.RR{claimKey, claimKeySig},
		nil,
		[]dns.RR{claimTXT, claimTXTSig})
	return proof
}

func miningTestDNSKEY(name string, keyBits int) *dns.DNSKEY {
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
		PublicKey: miningTestRSAPublicKey(keyBits),
	}
}

func miningTestRRSIG(name, signer string, covered uint16, key *dns.DNSKEY,
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

func miningTestAppendProofZone(t *testing.T, proof []byte, keys,
	referral, claim []dns.RR) []byte {

	t.Helper()

	for _, set := range [][]dns.RR{keys, referral, claim} {
		if len(set) > 255 {
			t.Fatal("proof set too large")
		}
		proof = append(proof, byte(len(set)))
		for _, rr := range set {
			proof = miningTestAppendPackedRR(t, proof, rr)
		}
	}
	return proof
}

func miningTestAppendPackedRR(t *testing.T, proof []byte, rr dns.RR) []byte {
	t.Helper()

	var scratch [4096]byte
	n, err := dns.PackRR(rr, scratch[:], 0, nil, false)
	if err != nil {
		t.Fatalf("PackRR(%T): %v", rr, err)
	}
	return append(proof, scratch[:n]...)
}

func miningTestRSAPublicKey(keyBits int) string {
	modulus := make([]byte, keyBits/8)
	modulus[0] = 0x80
	raw := append([]byte{3, 0x01, 0x00, 0x01}, modulus...)
	return base64.StdEncoding.EncodeToString(raw)
}

func miningTestHashBytes(hash chainhash.Hash) []byte {
	item := make([]byte, chainhash.HashSize)
	copy(item, hash[:])
	return item
}

func miningTestU32Item(value uint32) []byte {
	var item [4]byte
	binary.LittleEndian.PutUint32(item[:], value)
	return item[:]
}

// TestTxFeePrioHeap ensures the priority queue for transaction fees and
// priorities works as expected.
func TestTxFeePrioHeap(t *testing.T) {
	// Create some fake priority items that exercise the expected sort
	// edge conditions.
	testItems := []*txPrioItem{
		{feePerKB: 5678, priority: 3},
		{feePerKB: 5678, priority: 1},
		{feePerKB: 5678, priority: 1}, // Duplicate fee and prio
		{feePerKB: 5678, priority: 5},
		{feePerKB: 5678, priority: 2},
		{feePerKB: 1234, priority: 3},
		{feePerKB: 1234, priority: 1},
		{feePerKB: 1234, priority: 5},
		{feePerKB: 1234, priority: 5}, // Duplicate fee and prio
		{feePerKB: 1234, priority: 2},
		{feePerKB: 10000, priority: 0}, // Higher fee, smaller prio
		{feePerKB: 0, priority: 10000}, // Higher prio, lower fee
	}

	// Add random data in addition to the edge conditions already manually
	// specified.
	randSeed := rand.Int63()
	defer func() {
		if t.Failed() {
			t.Logf("Random numbers using seed: %v", randSeed)
		}
	}()
	prng := rand.New(rand.NewSource(randSeed))
	for i := 0; i < 1000; i++ {
		testItems = append(testItems, &txPrioItem{
			feePerKB: int64(prng.Float64() * hnsutil.DooPerHNS),
			priority: prng.Float64() * 100,
		})
	}

	// Test sorting by fee per KB then priority.
	var highest *txPrioItem
	priorityQueue := newTxPriorityQueue(len(testItems), true)
	for i := 0; i < len(testItems); i++ {
		prioItem := testItems[i]
		if highest == nil {
			highest = prioItem
		}
		if prioItem.feePerKB >= highest.feePerKB &&
			prioItem.priority > highest.priority {

			highest = prioItem
		}
		heap.Push(priorityQueue, prioItem)
	}

	for i := 0; i < len(testItems); i++ {
		prioItem := heap.Pop(priorityQueue).(*txPrioItem)
		if prioItem.feePerKB >= highest.feePerKB &&
			prioItem.priority > highest.priority {

			t.Fatalf("fee sort: item (fee per KB: %v, "+
				"priority: %v) higher than than prev "+
				"(fee per KB: %v, priority %v)",
				prioItem.feePerKB, prioItem.priority,
				highest.feePerKB, highest.priority)
		}
		highest = prioItem
	}

	// Test sorting by priority then fee per KB.
	highest = nil
	priorityQueue = newTxPriorityQueue(len(testItems), false)
	for i := 0; i < len(testItems); i++ {
		prioItem := testItems[i]
		if highest == nil {
			highest = prioItem
		}
		if prioItem.priority >= highest.priority &&
			prioItem.feePerKB > highest.feePerKB {

			highest = prioItem
		}
		heap.Push(priorityQueue, prioItem)
	}

	for i := 0; i < len(testItems); i++ {
		prioItem := heap.Pop(priorityQueue).(*txPrioItem)
		if prioItem.priority >= highest.priority &&
			prioItem.feePerKB > highest.feePerKB {

			t.Fatalf("priority sort: item (fee per KB: %v, "+
				"priority: %v) higher than than prev "+
				"(fee per KB: %v, priority %v)",
				prioItem.feePerKB, prioItem.priority,
				highest.feePerKB, highest.priority)
		}
		highest = prioItem
	}
}

func TestNewBlockTemplateConstructsHandshakeHeader(t *testing.T) {
	params := chaincfg.RegressionNetParams
	params.Checkpoints = nil

	chain, timeSource, sigCache, hashCache, cleanup :=
		newMiningTestChain(t, &params)
	defer cleanup()

	addr, err := hnsutil.NewAddressPubKeyHash(make([]byte, 20), &params)
	if err != nil {
		t.Fatalf("NewAddressPubKeyHash: %v", err)
	}

	policy := Policy{
		BlockMaxWeight: blockchain.MaxBlockWeight,
		BlockMaxSize:   blockchain.MaxBlockBaseSize,
	}
	generator := NewBlkTmplGenerator(&policy, &params,
		emptyTestTxSource{}, chain, timeSource, sigCache, hashCache)

	template, err := generator.NewBlockTemplate(addr)
	if err != nil {
		t.Fatalf("NewBlockTemplate: %v", err)
	}

	msgBlock := template.Block
	if len(msgBlock.Transactions) != 1 {
		t.Fatalf("template tx count = %d, want 1", len(msgBlock.Transactions))
	}
	if msgBlock.Header.PrevBlock != chain.BestSnapshot().Hash {
		t.Fatalf("PrevBlock = %v, want %v", msgBlock.Header.PrevBlock,
			chain.BestSnapshot().Hash)
	}

	blockTxns := []*hnsutil.Tx{hnsutil.NewTx(msgBlock.Transactions[0])}
	wantMerkleRoot := blockchain.CalcMerkleRoot(blockTxns, false)
	wantWitnessRoot := blockchain.CalcMerkleRoot(blockTxns, true)
	if msgBlock.Header.MerkleRoot != wantMerkleRoot {
		t.Fatalf("MerkleRoot = %v, want %v", msgBlock.Header.MerkleRoot,
			wantMerkleRoot)
	}
	if msgBlock.Header.WitnessRoot != wantWitnessRoot {
		t.Fatalf("WitnessRoot = %v, want %v", msgBlock.Header.WitnessRoot,
			wantWitnessRoot)
	}

	wantNameRoot, err := chain.NameRoot()
	if err != nil {
		t.Fatalf("NameRoot: %v", err)
	}
	if msgBlock.Header.NameRoot != wantNameRoot {
		t.Fatalf("NameRoot = %v, want %v", msgBlock.Header.NameRoot,
			wantNameRoot)
	}

	for _, txOut := range msgBlock.Transactions[0].TxOut {
		if bytes.HasPrefix(txOut.Address.Hash, bitcoinWitnessMagicBytes) {
			t.Fatal("template included Bitcoin-style witness commitment output")
		}
	}
}

func TestNewBlockTemplateSelectsMempoolTransaction(t *testing.T) {
	params := chaincfg.RegressionNetParams
	params.Checkpoints = nil
	params.CoinbaseMaturity = 1

	chain, timeSource, sigCache, hashCache, cleanup :=
		newMiningTestChain(t, &params)
	defer cleanup()

	privKey, payAddr, payWireAddr, payScript :=
		miningTestKeyAddress(t, &params)
	policy := Policy{
		BlockMaxWeight: blockchain.MaxBlockWeight,
		BlockMaxSize:   blockchain.MaxBlockBaseSize,
	}
	generator := NewBlkTmplGenerator(&policy, &params,
		emptyTestTxSource{}, chain, timeSource, sigCache, hashCache)

	firstTemplate, err := generator.NewBlockTemplate(payAddr)
	if err != nil {
		t.Fatalf("NewBlockTemplate height 1: %v", err)
	}
	firstCoinbase := firstTemplate.Block.Transactions[0]
	firstCoinbaseHash := firstCoinbase.TxHash()

	connectMiningTestTemplate(t, chain, firstTemplate)

	const fee = int64(5000)
	spend := miningTestSpend(t, firstCoinbaseHash,
		firstCoinbase.TxOut[0].Value, fee, privKey, payWireAddr,
		payScript)

	txSource := newStaticTestTxSource(miningTestTxDesc(
		spend, fee, chain.BestSnapshot().Height,
	))
	generator = NewBlkTmplGenerator(&policy, &params,
		txSource, chain, timeSource, sigCache, hashCache)

	template, err := generator.NewBlockTemplate(payAddr)
	if err != nil {
		t.Fatalf("NewBlockTemplate height 2: %v", err)
	}
	if len(template.Block.Transactions) != 2 {
		t.Fatalf("template tx count = %d, want 2",
			len(template.Block.Transactions))
	}
	if got, want := template.Block.Transactions[1].TxHash(), *spend.Hash(); got != want {
		t.Fatalf("selected tx hash = %v, want %v", got, want)
	}
	if got, want := template.Fees, []int64{-fee, fee}; !int64sEqual(got, want) {
		t.Fatalf("template fees = %v, want %v", got, want)
	}

	wantCoinbaseValue := blockchain.CalcBlockSubsidy(template.Height,
		&params) + fee
	if got := template.Block.Transactions[0].TxOut[0].Value; got != wantCoinbaseValue {
		t.Fatalf("coinbase value = %d, want subsidy+fee %d", got,
			wantCoinbaseValue)
	}
	if secondCoinbaseHash := template.Block.Transactions[0].TxHash(); secondCoinbaseHash == firstCoinbaseHash {
		t.Fatal("height 2 coinbase reused height 1 txid")
	}

	blockTxns := []*hnsutil.Tx{
		hnsutil.NewTx(template.Block.Transactions[0]),
		hnsutil.NewTx(template.Block.Transactions[1]),
	}
	if got, want := template.Block.Header.MerkleRoot,
		blockchain.CalcMerkleRoot(blockTxns, false); got != want {

		t.Fatalf("MerkleRoot = %v, want %v", got, want)
	}
	if got, want := template.Block.Header.WitnessRoot,
		blockchain.CalcMerkleRoot(blockTxns, true); got != want {

		t.Fatalf("WitnessRoot = %v, want %v", got, want)
	}

	connectMiningTestTemplate(t, chain, template)
}

func TestNewBlockTemplateSortsTransactionsByFeeRate(t *testing.T) {
	params := chaincfg.RegressionNetParams
	params.Checkpoints = nil
	params.CoinbaseMaturity = 1

	chain, timeSource, sigCache, hashCache, cleanup :=
		newMiningTestChain(t, &params)
	defer cleanup()

	privKey, payAddr, payWireAddr, payScript :=
		miningTestKeyAddress(t, &params)
	policy := Policy{
		BlockMaxWeight: blockchain.MaxBlockWeight,
		BlockMaxSize:   blockchain.MaxBlockBaseSize,
	}
	generator := NewBlkTmplGenerator(&policy, &params,
		emptyTestTxSource{}, chain, timeSource, sigCache, hashCache)

	firstTemplate, err := generator.NewBlockTemplate(payAddr)
	if err != nil {
		t.Fatalf("NewBlockTemplate height 1: %v", err)
	}
	firstCoinbase := firstTemplate.Block.Transactions[0]
	firstCoinbaseHash := firstCoinbase.TxHash()
	connectMiningTestTemplate(t, chain, firstTemplate)

	secondTemplate, err := generator.NewBlockTemplate(payAddr)
	if err != nil {
		t.Fatalf("NewBlockTemplate height 2: %v", err)
	}
	secondCoinbase := secondTemplate.Block.Transactions[0]
	secondCoinbaseHash := secondCoinbase.TxHash()
	connectMiningTestTemplate(t, chain, secondTemplate)

	const (
		lowFee  = int64(1000)
		highFee = int64(5000)
	)
	lowFeeSpend := miningTestSpend(t, firstCoinbaseHash,
		firstCoinbase.TxOut[0].Value, lowFee, privKey, payWireAddr,
		payScript)
	highFeeSpend := miningTestSpend(t, secondCoinbaseHash,
		secondCoinbase.TxOut[0].Value, highFee, privKey, payWireAddr,
		payScript)

	txSource := newStaticTestTxSource(
		miningTestTxDesc(lowFeeSpend, lowFee,
			chain.BestSnapshot().Height),
		miningTestTxDesc(highFeeSpend, highFee,
			chain.BestSnapshot().Height),
	)
	generator = NewBlkTmplGenerator(&policy, &params,
		txSource, chain, timeSource, sigCache, hashCache)

	template, err := generator.NewBlockTemplate(payAddr)
	if err != nil {
		t.Fatalf("NewBlockTemplate height 3: %v", err)
	}
	if len(template.Block.Transactions) != 3 {
		t.Fatalf("template tx count = %d, want 3",
			len(template.Block.Transactions))
	}
	if got, want := template.Block.Transactions[1].TxHash(),
		*highFeeSpend.Hash(); got != want {

		t.Fatalf("first selected tx hash = %v, want high-fee %v",
			got, want)
	}
	if got, want := template.Block.Transactions[2].TxHash(),
		*lowFeeSpend.Hash(); got != want {

		t.Fatalf("second selected tx hash = %v, want low-fee %v",
			got, want)
	}
	if got, want := template.Fees,
		[]int64{-(lowFee + highFee), highFee, lowFee}; !int64sEqual(got, want) {

		t.Fatalf("template fees = %v, want %v", got, want)
	}
}

func TestNewBlockTemplateSkipsTransactionOverPolicyWeight(t *testing.T) {
	params := chaincfg.RegressionNetParams
	params.Checkpoints = nil
	params.CoinbaseMaturity = 1

	chain, timeSource, sigCache, hashCache, cleanup :=
		newMiningTestChain(t, &params)
	defer cleanup()

	privKey, payAddr, payWireAddr, payScript :=
		miningTestKeyAddress(t, &params)
	policy := Policy{
		BlockMaxWeight: blockchain.MaxBlockWeight,
		BlockMaxSize:   blockchain.MaxBlockBaseSize,
	}
	generator := NewBlkTmplGenerator(&policy, &params,
		emptyTestTxSource{}, chain, timeSource, sigCache, hashCache)

	firstTemplate, err := generator.NewBlockTemplate(payAddr)
	if err != nil {
		t.Fatalf("NewBlockTemplate height 1: %v", err)
	}
	firstCoinbase := firstTemplate.Block.Transactions[0]
	firstCoinbaseHash := firstCoinbase.TxHash()
	connectMiningTestTemplate(t, chain, firstTemplate)

	const fee = int64(5000)
	spend := miningTestSpend(t, firstCoinbaseHash,
		firstCoinbase.TxOut[0].Value, fee, privKey, payWireAddr,
		payScript)
	txSource := newStaticTestTxSource(miningTestTxDesc(
		spend, fee, chain.BestSnapshot().Height,
	))

	// Use a deliberately tiny mining policy limit to exercise template
	// transaction selection.  Consensus validation still allows the
	// resulting coinbase-only block because it remains below the real
	// network maximum.
	limitedPolicy := Policy{
		BlockMaxWeight: 1,
		BlockMaxSize:   blockchain.MaxBlockBaseSize,
	}
	generator = NewBlkTmplGenerator(&limitedPolicy, &params,
		txSource, chain, timeSource, sigCache, hashCache)

	template, err := generator.NewBlockTemplate(payAddr)
	if err != nil {
		t.Fatalf("NewBlockTemplate height 2: %v", err)
	}
	if len(template.Block.Transactions) != 1 {
		t.Fatalf("template tx count = %d, want coinbase only",
			len(template.Block.Transactions))
	}
	if got, want := template.Fees, []int64{0}; !int64sEqual(got, want) {
		t.Fatalf("template fees = %v, want %v", got, want)
	}
	wantCoinbaseValue := blockchain.CalcBlockSubsidy(template.Height,
		&params)
	if got := template.Block.Transactions[0].TxOut[0].Value; got != wantCoinbaseValue {
		t.Fatalf("coinbase value = %d, want subsidy %d", got,
			wantCoinbaseValue)
	}

	connectMiningTestTemplate(t, chain, template)
}

func TestNewBlockTemplateSkipsTransactionOverSigOps(t *testing.T) {
	params := chaincfg.RegressionNetParams
	params.Checkpoints = nil
	params.CoinbaseMaturity = 1

	chain, timeSource, sigCache, hashCache, cleanup :=
		newMiningTestChain(t, &params)
	defer cleanup()

	payAddr, witnessScript := miningTestHighSigOpAddress(t, &params)
	policy := Policy{
		BlockMaxWeight: blockchain.MaxBlockWeight,
		BlockMaxSize:   blockchain.MaxBlockBaseSize,
	}
	generator := NewBlkTmplGenerator(&policy, &params,
		emptyTestTxSource{}, chain, timeSource, sigCache, hashCache)

	firstTemplate, err := generator.NewBlockTemplate(payAddr)
	if err != nil {
		t.Fatalf("NewBlockTemplate height 1: %v", err)
	}
	firstCoinbase := firstTemplate.Block.Transactions[0]
	firstCoinbaseHash := firstCoinbase.TxHash()
	connectMiningTestTemplate(t, chain, firstTemplate)

	const fee = int64(5000)
	spend := wire.NewMsgTx(wire.TxVersion)
	spend.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  firstCoinbaseHash,
			Index: 0,
		},
		Sequence: wire.MaxTxInSequenceNum,
		Witness:  wire.TxWitness{witnessScript},
	})
	spend.AddTxOut(wire.NewTxOut(
		firstCoinbase.TxOut[0].Value-fee, wire.Address{}, wire.Covenant{},
	))
	tx := hnsutil.NewTx(spend)

	txSource := newStaticTestTxSource(miningTestTxDesc(
		tx, fee, chain.BestSnapshot().Height,
	))
	generator = NewBlkTmplGenerator(&policy, &params,
		txSource, chain, timeSource, sigCache, hashCache)

	template, err := generator.NewBlockTemplate(payAddr)
	if err != nil {
		t.Fatalf("NewBlockTemplate height 2: %v", err)
	}
	if len(template.Block.Transactions) != 1 {
		t.Fatalf("template tx count = %d, want coinbase only",
			len(template.Block.Transactions))
	}
	if got, want := template.Fees, []int64{0}; !int64sEqual(got, want) {
		t.Fatalf("template fees = %v, want %v", got, want)
	}

	connectMiningTestTemplate(t, chain, template)
}

func TestNewBlockTemplateValidatesScriptsBeforeNameState(t *testing.T) {
	params := chaincfg.RegressionNetParams
	params.Checkpoints = nil
	params.CoinbaseMaturity = 1

	chain, timeSource, sigCache, hashCache, cleanup :=
		newMiningTestChain(t, &params)
	defer cleanup()

	privKey, payAddr, payWireAddr, payScript :=
		miningTestKeyAddress(t, &params)
	policy := Policy{
		BlockMaxWeight: blockchain.MaxBlockWeight,
		BlockMaxSize:   blockchain.MaxBlockBaseSize,
	}
	generator := NewBlkTmplGenerator(&policy, &params,
		emptyTestTxSource{}, chain, timeSource, sigCache, hashCache)

	firstTemplate, err := generator.NewBlockTemplate(payAddr)
	if err != nil {
		t.Fatalf("NewBlockTemplate height 1: %v", err)
	}
	firstCoinbase := firstTemplate.Block.Transactions[0]
	firstCoinbaseHash := firstCoinbase.TxHash()
	connectMiningTestTemplate(t, chain, firstTemplate)

	secondTemplate, err := generator.NewBlockTemplate(payAddr)
	if err != nil {
		t.Fatalf("NewBlockTemplate height 2: %v", err)
	}
	secondCoinbase := secondTemplate.Block.Transactions[0]
	secondCoinbaseHash := secondCoinbase.TxHash()
	connectMiningTestTemplate(t, chain, secondTemplate)

	const (
		invalidFee = int64(9000)
		validFee   = int64(1000)
	)
	invalidSpend := miningTestSpend(t, firstCoinbaseHash,
		firstCoinbase.TxOut[0].Value, invalidFee, privKey,
		payWireAddr, payScript)
	invalidSpend.MsgTx().TxIn[0].Witness[0][0] ^= 0x01
	validSpend := miningTestSpend(t, secondCoinbaseHash,
		secondCoinbase.TxOut[0].Value, validFee, privKey,
		payWireAddr, payScript)

	txSource := newStaticTestTxSource(
		miningTestTxDesc(invalidSpend, invalidFee,
			chain.BestSnapshot().Height),
		miningTestTxDesc(validSpend, validFee,
			chain.BestSnapshot().Height),
	)
	generator = NewBlkTmplGenerator(&policy, &params,
		txSource, chain, timeSource, sigCache, hashCache)

	nameView := &rejectingNameView{
		t:            t,
		forbidden:    *invalidSpend.Hash(),
		wantPrevTime: chain.BestBlockTimestamp().Unix(),
	}
	generator.newNameValidationView = func() (nameValidationView, error) {
		return nameView, nil
	}

	template, err := generator.NewBlockTemplate(payAddr)
	if err != nil {
		t.Fatalf("NewBlockTemplate height 3: %v", err)
	}
	if len(template.Block.Transactions) != 2 {
		t.Fatalf("template tx count = %d, want coinbase plus valid spend",
			len(template.Block.Transactions))
	}
	if got, want := template.Block.Transactions[1].TxHash(), *validSpend.Hash(); got != want {
		t.Fatalf("selected tx hash = %v, want valid spend %v", got,
			want)
	}
	if len(nameView.applied) != 1 || nameView.applied[0] != *validSpend.Hash() {
		t.Fatalf("name validation applied to %v, want only %v",
			nameView.applied, validSpend.Hash())
	}
}

func TestNewBlockTemplateIncludesCoinbaseAirdropProof(t *testing.T) {
	params := chaincfg.RegressionNetParams
	params.Checkpoints = nil

	chain, timeSource, sigCache, hashCache, cleanup :=
		newMiningTestChain(t, &params)
	defer cleanup()

	_, payAddr, _, _ := miningTestKeyAddress(t, &params)
	proof, proofOutput, airdropFee := miningTestAirdropProof(t)
	txSource := staticTestTxSource{
		updated: time.Now(),
		have:    make(map[chainhash.Hash]struct{}),
		coinbaseProofs: []CoinbaseProof{{
			Witness: proof,
			Output:  proofOutput,
			Fee:     int64(airdropFee),
		}},
	}
	policy := Policy{
		BlockMaxWeight: blockchain.MaxBlockWeight,
		BlockMaxSize:   blockchain.MaxBlockBaseSize,
	}
	generator := NewBlkTmplGenerator(&policy, &params,
		txSource, chain, timeSource, sigCache, hashCache)

	template, err := generator.NewBlockTemplate(payAddr)
	if err != nil {
		t.Fatalf("NewBlockTemplate: %v", err)
	}

	coinbase := template.Block.Transactions[0]
	if len(coinbase.TxIn) != 2 {
		t.Fatalf("coinbase input count = %d, want 2", len(coinbase.TxIn))
	}
	if len(coinbase.TxOut) != 2 {
		t.Fatalf("coinbase output count = %d, want 2", len(coinbase.TxOut))
	}
	if got := coinbase.TxIn[1].PreviousOutPoint.Index; got != wire.MaxPrevOutIndex {
		t.Fatalf("proof input index = %d, want max prevout", got)
	}
	if !bytes.Equal(coinbase.TxIn[1].Witness[0], proof) {
		t.Fatal("coinbase proof witness mismatch")
	}
	if got := coinbase.TxOut[1].Value; got != proofOutput.Value {
		t.Fatalf("proof output value = %d, want %d", got,
			proofOutput.Value)
	}
	if len(template.CoinbaseProofs) != 1 {
		t.Fatalf("template coinbase proof count = %d, want 1",
			len(template.CoinbaseProofs))
	}
	if !bytes.Equal(template.CoinbaseProofs[0].Witness, proof) {
		t.Fatal("template coinbase proof witness mismatch")
	}
	txSource.coinbaseProofs[0].Witness[0] ^= 0xff
	if bytes.Equal(template.CoinbaseProofs[0].Witness,
		txSource.coinbaseProofs[0].Witness) {

		t.Fatal("template coinbase proof witness was not cloned")
	}
	if got := coinbase.TxOut[1].Address; !bytes.Equal(got.Hash,
		proofOutput.Address.Hash) ||
		got.Version != proofOutput.Address.Version {

		t.Fatalf("proof output address = %+v, want %+v", got,
			proofOutput.Address)
	}

	wantPayout := blockchain.CalcBlockSubsidy(template.Height, &params) +
		int64(airdropFee)
	if got := coinbase.TxOut[0].Value; got != wantPayout {
		t.Fatalf("coinbase payout = %d, want subsidy plus proof fee %d",
			got, wantPayout)
	}
	if got, want := template.Fees, []int64{0}; !int64sEqual(got, want) {
		t.Fatalf("template fees = %v, want %v", got, want)
	}

	connectMiningTestTemplate(t, chain, template)
}

func TestNewBlockTemplateTrimsCoinbaseProofOverPolicyWeight(t *testing.T) {
	params := chaincfg.RegressionNetParams
	params.Checkpoints = nil

	chain, timeSource, sigCache, hashCache, cleanup :=
		newMiningTestChain(t, &params)
	defer cleanup()

	_, payAddr, _, _ := miningTestKeyAddress(t, &params)
	proof, proofOutput, airdropFee := miningTestAirdropProof(t)
	txSource := staticTestTxSource{
		updated: time.Now(),
		have:    make(map[chainhash.Hash]struct{}),
		coinbaseProofs: []CoinbaseProof{{
			Witness: proof,
			Output:  proofOutput,
			Fee:     int64(airdropFee),
		}},
	}
	policy := Policy{
		BlockMaxWeight: 1,
		BlockMaxSize:   blockchain.MaxBlockBaseSize,
	}
	generator := NewBlkTmplGenerator(&policy, &params,
		txSource, chain, timeSource, sigCache, hashCache)

	template, err := generator.NewBlockTemplate(payAddr)
	if err != nil {
		t.Fatalf("NewBlockTemplate: %v", err)
	}
	if len(template.CoinbaseProofs) != 0 {
		t.Fatalf("template coinbase proof count = %d, want 0",
			len(template.CoinbaseProofs))
	}
	if got := len(template.Block.Transactions[0].TxIn); got != 1 {
		t.Fatalf("coinbase input count = %d, want only base input", got)
	}
}

func TestAddCoinbaseProofsRejectsDuplicateWitness(t *testing.T) {
	addrHash := make([]byte, 20)
	for i := range addrHash {
		addrHash[i] = 0x01
	}
	addr := wire.Address{
		Version: 0,
		Hash:    addrHash,
	}
	proof := CoinbaseProof{
		Witness: []byte{0x01, 0x02, 0x03},
		Output:  wire.NewTxOut(10, addr, wire.Covenant{}),
	}
	coinbaseTx := hnsutil.NewTx(wire.NewMsgTx(wire.TxVersion))

	if _, err := addCoinbaseProofs(coinbaseTx,
		[]CoinbaseProof{proof, proof}, 0, nil); err == nil {

		t.Fatal("addCoinbaseProofs: expected duplicate proof error")
	}
}

func TestCoinbaseProofRateUsesMinerFeeAfterDeflation(t *testing.T) {
	params := chaincfg.RegressionNetParams
	params.NameDeflationHeight = 1

	addr := wire.Address{
		Version: 0,
		Hash:    bytes.Repeat([]byte{0x01}, 20),
	}
	coinbaseTx := hnsutil.NewTx(wire.NewMsgTx(wire.TxVersion))
	commitHash := chainhash.Hash{0x02}
	proof := CoinbaseProof{
		Witness: []byte{0x01, 0x02, 0x03},
		Output: wire.NewTxOut(10, addr,
			miningTestClaimCovenant("com", 1, commitHash, 2,
				false)),
		Fee: 1000,
	}

	rate, err := coinbaseProofRate(coinbaseTx, proof, 1, &params)
	if err != nil {
		t.Fatalf("coinbaseProofRate non-initial claim: %v", err)
	}
	if rate != 0 {
		t.Fatalf("non-initial post-deflation rate = %d, want 0", rate)
	}

	proof.Output = wire.NewTxOut(10, addr,
		miningTestClaimCovenant("com", 1, commitHash, 1, false))
	rate, err = coinbaseProofRate(coinbaseTx, proof, 1, &params)
	if err != nil {
		t.Fatalf("coinbaseProofRate initial claim: %v", err)
	}
	if rate <= 0 {
		t.Fatalf("initial post-deflation rate = %d, want positive", rate)
	}
}

func TestCoinbaseProofRateUsesIncrementalCoinbaseWeight(t *testing.T) {
	coinbaseTx := hnsutil.NewTx(wire.NewMsgTx(wire.TxVersion))
	witness := bytes.Repeat([]byte{0xaa}, 16)
	smallProof := CoinbaseProof{
		Witness: witness,
		Output: wire.NewTxOut(1, wire.Address{
			Version: 0,
			Hash:    bytes.Repeat([]byte{0x01}, 20),
		}, wire.Covenant{}),
		Fee: 1000,
	}
	largeProof := CoinbaseProof{
		Witness: witness,
		Output: wire.NewTxOut(1, wire.Address{
			Version: 0,
			Hash:    bytes.Repeat([]byte{0x02}, 64),
		}, wire.Covenant{}),
		Fee: 1000,
	}

	smallRate, err := coinbaseProofRate(coinbaseTx, smallProof, 0, nil)
	if err != nil {
		t.Fatalf("coinbaseProofRate small proof: %v", err)
	}
	largeRate, err := coinbaseProofRate(coinbaseTx, largeProof, 0, nil)
	if err != nil {
		t.Fatalf("coinbaseProofRate large proof: %v", err)
	}
	if smallRate <= largeRate {
		t.Fatalf("proof rates small=%d large=%d, want small higher",
			smallRate, largeRate)
	}
}

func TestNewBlockTemplateIncludesCoinbaseClaimProof(t *testing.T) {
	params := chaincfg.RegressionNetParams
	params.Checkpoints = nil

	chain, timeSource, sigCache, hashCache, cleanup :=
		newMiningTestChain(t, &params)
	defer cleanup()

	_, payAddr, payWireAddr, _ := miningTestKeyAddress(t, &params)
	policy := Policy{
		BlockMaxWeight: blockchain.MaxBlockWeight,
		BlockMaxSize:   blockchain.MaxBlockBaseSize,
	}
	generator := NewBlkTmplGenerator(&policy, &params,
		emptyTestTxSource{}, chain, timeSource, sigCache, hashCache)

	firstTemplate, err := generator.NewBlockTemplate(payAddr)
	if err != nil {
		t.Fatalf("NewBlockTemplate height 1: %v", err)
	}
	connectMiningTestTemplate(t, chain, firstTemplate)
	commitHash := firstTemplate.Block.BlockHash()

	const (
		claimValue = uint64(30585353787)
		claimFee   = uint64(1000)
	)
	claimHeight := uint32(chain.BestSnapshot().Height + 1)
	proof, proofOutput := miningTestClaimProof(t, &params, "com",
		payWireAddr, claimValue, claimFee, claimHeight, commitHash, 1)
	txSource := staticTestTxSource{
		updated: time.Now(),
		have:    make(map[chainhash.Hash]struct{}),
		coinbaseProofs: []CoinbaseProof{{
			Witness: proof,
			Output:  proofOutput,
			Fee:     int64(claimFee),
		}},
	}
	generator = NewBlkTmplGenerator(&policy, &params,
		txSource, chain, timeSource, sigCache, hashCache)

	template, err := generator.NewBlockTemplate(payAddr)
	if err != nil {
		t.Fatalf("NewBlockTemplate height 2: %v", err)
	}

	coinbase := template.Block.Transactions[0]
	if len(coinbase.TxIn) != 2 {
		t.Fatalf("coinbase input count = %d, want 2", len(coinbase.TxIn))
	}
	if len(coinbase.TxOut) != 2 {
		t.Fatalf("coinbase output count = %d, want 2", len(coinbase.TxOut))
	}
	if !bytes.Equal(coinbase.TxIn[1].Witness[0], proof) {
		t.Fatal("coinbase CLAIM witness mismatch")
	}
	if got := coinbase.TxOut[1].Covenant.Type; got != wire.CovenantClaim {
		t.Fatalf("proof covenant = %d, want CLAIM", got)
	}
	if got := coinbase.TxOut[1].Value; got != proofOutput.Value {
		t.Fatalf("proof output value = %d, want %d", got,
			proofOutput.Value)
	}
	if len(template.CoinbaseProofs) != 1 {
		t.Fatalf("template coinbase proof count = %d, want 1",
			len(template.CoinbaseProofs))
	}
	if !bytes.Equal(template.CoinbaseProofs[0].Witness, proof) {
		t.Fatal("template CLAIM proof witness mismatch")
	}
	txSource.coinbaseProofs[0].Witness[0] ^= 0xff
	if bytes.Equal(template.CoinbaseProofs[0].Witness,
		txSource.coinbaseProofs[0].Witness) {

		t.Fatal("template CLAIM proof witness was not cloned")
	}

	wantPayout := blockchain.CalcBlockSubsidy(template.Height, &params) +
		int64(claimFee)
	if got := coinbase.TxOut[0].Value; got != wantPayout {
		t.Fatalf("coinbase payout = %d, want subsidy plus proof fee %d",
			got, wantPayout)
	}
	if got, want := template.Fees, []int64{0}; !int64sEqual(got, want) {
		t.Fatalf("template fees = %v, want %v", got, want)
	}

	connectMiningTestTemplate(t, chain, template)
}

func TestCreateCoinbaseTxRejectsTaprootShapedPayout(t *testing.T) {
	params := chaincfg.RegressionNetParams
	addr, err := hnsutil.NewAddress(1, make([]byte, 32), &params)
	if err != nil {
		t.Fatalf("NewAddress: %v", err)
	}
	coinbaseScript, err := standardCoinbaseScript(1, 0)
	if err != nil {
		t.Fatalf("standardCoinbaseScript: %v", err)
	}

	_, err = createCoinbaseTx(&params, coinbaseScript, 1, addr)
	if err == nil {
		t.Fatal("createCoinbaseTx accepted taproot-shaped payout")
	}
}

func TestUpdateExtraNonceUsesHeaderField(t *testing.T) {
	coinbaseScript, err := standardCoinbaseScript(1, 0)
	if err != nil {
		t.Fatalf("standardCoinbaseScript: %v", err)
	}
	coinbaseTx, err := createCoinbaseTx(
		&chaincfg.RegressionNetParams, coinbaseScript, 1, nil,
	)
	if err != nil {
		t.Fatalf("createCoinbaseTx: %v", err)
	}

	msgBlock := &wire.MsgBlock{
		Header: wire.BlockHeader{
			MerkleRoot:  chainhash.Hash{0x01},
			WitnessRoot: chainhash.Hash{0x02},
		},
	}
	if err := msgBlock.AddTransaction(coinbaseTx.MsgTx()); err != nil {
		t.Fatalf("AddTransaction: %v", err)
	}
	beforeHash := msgBlock.Header.BlockHash()
	beforeWitness := cloneWitness(msgBlock.Transactions[0].TxIn[0].Witness)
	beforeMerkleRoot := msgBlock.Header.MerkleRoot
	beforeWitnessRoot := msgBlock.Header.WitnessRoot

	g := &BlkTmplGenerator{}
	const extraNonce = uint64(0x0102030405060708)
	if err := g.UpdateExtraNonce(msgBlock, 1, extraNonce); err != nil {
		t.Fatalf("UpdateExtraNonce: %v", err)
	}
	if got := binary.LittleEndian.Uint64(
		msgBlock.Header.ExtraNonce[:8],
	); got != extraNonce {
		t.Fatalf("header extra nonce = %x, want %x", got, extraNonce)
	}
	for i, b := range msgBlock.Header.ExtraNonce[8:] {
		if b != 0 {
			t.Fatalf("extra nonce byte %d = %x, want 0", i+8, b)
		}
	}
	if msgBlock.Header.MerkleRoot != beforeMerkleRoot {
		t.Fatalf("MerkleRoot changed to %v, want %v",
			msgBlock.Header.MerkleRoot, beforeMerkleRoot)
	}
	if msgBlock.Header.WitnessRoot != beforeWitnessRoot {
		t.Fatalf("WitnessRoot changed to %v, want %v",
			msgBlock.Header.WitnessRoot, beforeWitnessRoot)
	}
	if !witnessEqual(msgBlock.Transactions[0].TxIn[0].Witness,
		beforeWitness) {

		t.Fatal("UpdateExtraNonce mutated coinbase witness")
	}
	afterHash := msgBlock.Header.BlockHash()
	if afterHash == beforeHash {
		t.Fatal("UpdateExtraNonce did not change block hash")
	}
}

func cloneWitness(witness wire.TxWitness) wire.TxWitness {
	clone := make(wire.TxWitness, len(witness))
	for i, item := range witness {
		clone[i] = append([]byte(nil), item...)
	}
	return clone
}

func witnessEqual(a, b wire.TxWitness) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

func int64sEqual(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
