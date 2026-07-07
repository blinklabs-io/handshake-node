package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/blinklabs-io/handshake-node/blockchain"
	"github.com/blinklabs-io/handshake-node/chaincfg"
	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/database"
	_ "github.com/blinklabs-io/handshake-node/database/ffldb"
	"github.com/blinklabs-io/handshake-node/hnsjson"
	"github.com/blinklabs-io/handshake-node/hnsutil"
	"github.com/blinklabs-io/handshake-node/mempool"
	"github.com/blinklabs-io/handshake-node/mining"
	"github.com/blinklabs-io/handshake-node/txscript"
	"github.com/blinklabs-io/handshake-node/wire"
	"github.com/btcsuite/btclog"
	"github.com/stretchr/testify/require"
)

func TestHnsutilAddressToWireRejectsTaprootShapedAddress(t *testing.T) {
	addr, err := hnsutil.NewAddress(1, make([]byte, 32),
		&chaincfg.RegressionNetParams)
	if err != nil {
		t.Fatalf("NewAddress: %v", err)
	}

	if _, err := hnsutilAddressToWire(addr); err == nil {
		t.Fatal("hnsutilAddressToWire accepted taproot-shaped address")
	}
}

type gbtTestTxSource struct {
	updated time.Time
}

func (s *gbtTestTxSource) LastUpdated() time.Time { return s.updated }
func (*gbtTestTxSource) MiningDescs() []*mining.TxDesc {
	return nil
}
func (*gbtTestTxSource) HaveTransaction(*chainhash.Hash) bool {
	return false
}

func newGBTTestRPCServer(t *testing.T, txSource *gbtTestTxSource) (
	*rpcServer, *blockchain.BlockChain) {

	t.Helper()

	blockchain.DisableLog()
	database.UseLogger(btclog.Disabled)

	params := chaincfg.RegressionNetParams
	params.Checkpoints = nil

	dbPath := filepath.Join(t.TempDir(), "ffldb")
	db, err := database.Create("ffldb", dbPath, params.Net)
	if err != nil {
		t.Fatalf("database.Create: %v", err)
	}
	t.Cleanup(func() {
		db.Close()
	})

	timeSource := blockchain.NewMedianTime()
	sigCache := txscript.NewSigCache(1000)
	hashCache := txscript.NewHashCache(1000)
	chain, err := blockchain.New(&blockchain.Config{
		DB:          db,
		ChainParams: &params,
		TimeSource:  timeSource,
		SigCache:    sigCache,
	})
	if err != nil {
		t.Fatalf("blockchain.New: %v", err)
	}

	policy := mining.Policy{
		BlockMaxWeight: blockchain.MaxBlockWeight,
		BlockMaxSize:   blockchain.MaxBlockBaseSize,
	}
	generator := mining.NewBlkTmplGenerator(&policy, &params,
		txSource, chain, timeSource, sigCache, hashCache)
	server := &rpcServer{
		cfg: rpcserverConfig{
			TimeSource:  timeSource,
			Chain:       chain,
			ChainParams: &params,
			Generator:   generator,
		},
		gbtWorkState: newGbtWorkState(timeSource),
	}

	return server, chain
}

func newGBTTestResult(t *testing.T, server *rpcServer,
	useCoinbaseValue bool) (*hnsjson.GetBlockTemplateResult, *mining.BlockTemplate) {

	t.Helper()

	var payAddr hnsutil.Address
	if !useCoinbaseValue {
		var err error
		payAddr, err = hnsutil.NewAddressPubKeyHash(make([]byte, 20),
			server.cfg.ChainParams)
		if err != nil {
			t.Fatalf("NewAddressPubKeyHash: %v", err)
		}
	}

	template, err := server.cfg.Generator.NewBlockTemplate(payAddr)
	if err != nil {
		t.Fatalf("NewBlockTemplate: %v", err)
	}

	state := server.gbtWorkState
	state.Lock()
	defer state.Unlock()

	best := server.cfg.Chain.BestSnapshot()
	prevHash := best.Hash
	state.template = template
	state.prevHash = &prevHash
	state.lastGenerated = time.Now()
	state.lastTxUpdate = server.cfg.Generator.TxSource().LastUpdated()
	if state.lastTxUpdate.IsZero() {
		state.lastTxUpdate = time.Now()
	}
	state.minTimestamp = mining.MinimumMedianTime(best)

	result, err := state.blockTemplateResult(useCoinbaseValue, nil)
	if err != nil {
		t.Fatalf("blockTemplateResult: %v", err)
	}

	return result, template
}

func solveGBTTestBlock(t *testing.T, msgBlock *wire.MsgBlock) {
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

	t.Fatalf("unable to solve block at difficulty %08x",
		msgBlock.Header.Bits)
}

func hasString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func requireMutableField(t *testing.T, fields []string, want string) {
	t.Helper()
	if !hasString(fields, want) {
		t.Fatalf("mutable fields %v missing %q", fields, want)
	}
}

func requireNoMutableField(t *testing.T, fields []string, unwanted string) {
	t.Helper()
	if hasString(fields, unwanted) {
		t.Fatalf("mutable fields %v unexpectedly include %q", fields,
			unwanted)
	}
}

func requireGBTHandshakeHeaderFields(t *testing.T,
	result *hnsjson.GetBlockTemplateResult, template *mining.BlockTemplate) {

	t.Helper()

	header := &template.Block.Header
	if got, want := result.TreeRoot, header.NameRoot.String(); got != want {
		t.Fatalf("treeroot = %q, want %q", got, want)
	}
	if got, want := result.ReservedRoot, header.ReservedRoot.String(); got != want {
		t.Fatalf("reservedroot = %q, want %q", got, want)
	}
	if got, want := result.Mask, header.Mask.String(); got != want {
		t.Fatalf("mask = %q, want %q", got, want)
	}
}

func gbtTestAirdropWitness(t *testing.T, index uint32, version uint8,
	address []byte, value, fee uint64) []byte {

	t.Helper()

	var buf bytes.Buffer
	var scratch [8]byte
	binary.LittleEndian.PutUint32(scratch[:4], index)
	buf.Write(scratch[:4])
	buf.WriteByte(0) // proof path count
	buf.WriteByte(0) // subindex
	buf.WriteByte(0) // subproof path count

	var key bytes.Buffer
	key.WriteByte(gbtAirdropKeyAddress)
	key.WriteByte(version)
	key.WriteByte(byte(len(address)))
	key.Write(address)
	binary.LittleEndian.PutUint64(scratch[:], value)
	key.Write(scratch[:])
	key.WriteByte(0)
	if err := wire.WriteVarBytes(&buf, 0, key.Bytes()); err != nil {
		t.Fatalf("WriteVarBytes key: %v", err)
	}

	buf.WriteByte(version)
	buf.WriteByte(byte(len(address)))
	buf.Write(address)
	if err := wire.WriteVarInt(&buf, 0, fee); err != nil {
		t.Fatalf("WriteVarInt fee: %v", err)
	}
	if err := wire.WriteVarBytes(&buf, 0, nil); err != nil {
		t.Fatalf("WriteVarBytes signature: %v", err)
	}

	return buf.Bytes()
}

func TestBlockTemplateResultHandshakeFieldsForCoinbaseValue(t *testing.T) {
	txSource := &gbtTestTxSource{updated: time.Now()}
	server, _ := newGBTTestRPCServer(t, txSource)

	result, template := newGBTTestResult(t, server, true)
	requireGBTHandshakeHeaderFields(t, result, template)

	if result.CoinbaseValue == nil {
		t.Fatal("coinbasevalue missing")
	}
	if result.CoinbaseTxn != nil {
		t.Fatal("coinbasetxn included for coinbasevalue template")
	}
	if result.MerkleRoot != "" {
		t.Fatalf("merkleroot = %q, want empty for external coinbase",
			result.MerkleRoot)
	}
	if result.WitnessRoot != "" {
		t.Fatalf("witnessroot = %q, want empty for external coinbase",
			result.WitnessRoot)
	}

	requireMutableField(t, result.Mutable, "time")
	requireMutableField(t, result.Mutable, "transactions")
	requireMutableField(t, result.Mutable, "prevblock")
	requireNoMutableField(t, result.Mutable, "transactions/add")
	requireNoMutableField(t, result.Mutable, "coinbase")
	requireNoMutableField(t, result.Mutable, "coinbase/append")
	requireNoMutableField(t, result.Mutable, "generation")
}

func TestBlockTemplateResultHandshakeFieldsForCoinbaseTxn(t *testing.T) {
	txSource := &gbtTestTxSource{updated: time.Now()}
	server, _ := newGBTTestRPCServer(t, txSource)

	result, template := newGBTTestResult(t, server, false)
	requireGBTHandshakeHeaderFields(t, result, template)

	if result.CoinbaseTxn == nil {
		t.Fatal("coinbasetxn missing")
	}
	if result.CoinbaseValue != nil {
		t.Fatal("coinbasevalue included for coinbasetxn template")
	}

	header := &template.Block.Header
	if got, want := result.MerkleRoot, header.MerkleRoot.String(); got != want {
		t.Fatalf("merkleroot = %q, want %q", got, want)
	}
	if got, want := result.WitnessRoot, header.WitnessRoot.String(); got != want {
		t.Fatalf("witnessroot = %q, want %q", got, want)
	}

	requireMutableField(t, result.Mutable, "time")
	requireMutableField(t, result.Mutable, "transactions")
	requireMutableField(t, result.Mutable, "prevblock")
	requireMutableField(t, result.Mutable, "coinbase")
	requireMutableField(t, result.Mutable, "coinbase/append")
	requireMutableField(t, result.Mutable, "generation")
	requireNoMutableField(t, result.Mutable, "transactions/add")
}

func TestBlockTemplateResultIncludesCoinbaseProofMetadata(t *testing.T) {
	txSource := &gbtTestTxSource{updated: time.Now()}
	server, _ := newGBTTestRPCServer(t, txSource)

	_, template := newGBTTestResult(t, server, true)

	nameHash := bytes.Repeat([]byte{0x11}, chainhash.HashSize)
	commitHash := bytes.Repeat([]byte{0x22}, chainhash.HashSize)
	claimHeight := make([]byte, 4)
	commitHeight := make([]byte, 4)
	binary.LittleEndian.PutUint32(claimHeight, uint32(template.Height))
	binary.LittleEndian.PutUint32(commitHeight, 2)
	claimAddrHash := bytes.Repeat([]byte{0x33}, 20)
	claimProof := mining.CoinbaseProof{
		Witness: []byte{0xaa, 0xbb, 0xcc},
		Output: wire.NewTxOut(4_900, wire.Address{
			Version: 0,
			Hash:    claimAddrHash,
		}, wire.Covenant{
			Type: wire.CovenantClaim,
			Items: [][]byte{
				nameHash,
				claimHeight,
				[]byte("com"),
				[]byte{0x01},
				commitHash,
				commitHeight,
			},
		}),
		Fee: 100,
	}

	airdropAddrHash := bytes.Repeat([]byte{0x44}, 20)
	airdropWitness := gbtTestAirdropWitness(t, 7, 0,
		airdropAddrHash, 7_000, 200)
	airdropProof := mining.CoinbaseProof{
		Witness: airdropWitness,
		Output: wire.NewTxOut(6_800, wire.Address{
			Version: 0,
			Hash:    airdropAddrHash,
		}, wire.Covenant{}),
		Fee: 200,
	}

	template.CoinbaseProofs = []mining.CoinbaseProof{
		claimProof,
		airdropProof,
	}
	template.NameDeflationHeight = uint32(template.Height)

	state := server.gbtWorkState
	state.Lock()
	result, err := state.blockTemplateResult(true, nil)
	state.Unlock()
	if err != nil {
		t.Fatalf("blockTemplateResult: %v", err)
	}

	if len(result.Claims) != 1 {
		t.Fatalf("claims count = %d, want 1", len(result.Claims))
	}
	claim := result.Claims[0]
	if claim.Data != hex.EncodeToString(claimProof.Witness) {
		t.Fatalf("claim data = %q, want %q", claim.Data,
			hex.EncodeToString(claimProof.Witness))
	}
	if claim.Name != "com" {
		t.Fatalf("claim name = %q, want com", claim.Name)
	}
	if claim.NameHash != hex.EncodeToString(nameHash) {
		t.Fatalf("claim namehash = %q, want %q", claim.NameHash,
			hex.EncodeToString(nameHash))
	}
	if claim.Hash != hex.EncodeToString(claimAddrHash) {
		t.Fatalf("claim hash = %q, want %q", claim.Hash,
			hex.EncodeToString(claimAddrHash))
	}
	if claim.Value != claimProof.Output.Value || claim.Fee != 0 {
		t.Fatalf("deflated claim value/fee = %d/%d, want %d/0",
			claim.Value, claim.Fee, claimProof.Output.Value)
	}
	if !claim.Weak {
		t.Fatal("claim weak = false, want true")
	}
	if claim.CommitHash != hex.EncodeToString(commitHash) {
		t.Fatalf("claim commitHash = %q, want %q", claim.CommitHash,
			hex.EncodeToString(commitHash))
	}
	if claim.CommitHeight != 2 {
		t.Fatalf("claim commitHeight = %d, want 2", claim.CommitHeight)
	}
	wantClaimWeight := int64(1 +
		wire.VarIntSerializeSize(uint64(len(claimProof.Witness))) +
		len(claimProof.Witness) +
		(1+8+claimProof.Output.Address.SerializeSize()+90+len("com"))*
			blockchain.WitnessScaleFactor)
	if claim.Weight != wantClaimWeight {
		t.Fatalf("claim weight = %d, want %d", claim.Weight,
			wantClaimWeight)
	}

	if len(result.Airdrops) != 1 {
		t.Fatalf("airdrops count = %d, want 1", len(result.Airdrops))
	}
	airdrop := result.Airdrops[0]
	if airdrop.Data != hex.EncodeToString(airdropWitness) {
		t.Fatalf("airdrop data = %q, want %q", airdrop.Data,
			hex.EncodeToString(airdropWitness))
	}
	if airdrop.Position != gbtAirdropLeaves+7 {
		t.Fatalf("airdrop position = %d, want %d", airdrop.Position,
			gbtAirdropLeaves+7)
	}
	if airdrop.Address != hex.EncodeToString(airdropAddrHash) {
		t.Fatalf("airdrop address = %q, want %q", airdrop.Address,
			hex.EncodeToString(airdropAddrHash))
	}
	if airdrop.Value != 7_000 || airdrop.Fee != 200 {
		t.Fatalf("airdrop value/fee = %d/%d, want 7000/200",
			airdrop.Value, airdrop.Fee)
	}
	wantRate := int64(200 * 1000 / ((len(airdropWitness) +
		blockchain.WitnessScaleFactor - 1) /
		blockchain.WitnessScaleFactor))
	if airdrop.Rate != wantRate {
		t.Fatalf("airdrop rate = %d, want %d", airdrop.Rate,
			wantRate)
	}
	if airdrop.Weak {
		t.Fatal("airdrop weak = true, want false")
	}
}

func connectGBTTestTemplate(t *testing.T, chain *blockchain.BlockChain,
	template *mining.BlockTemplate) {

	t.Helper()

	solveGBTTestBlock(t, template.Block)
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
}

func TestGBTWorkStateRegeneratesTemplateAfterTipChange(t *testing.T) {
	txSource := &gbtTestTxSource{updated: time.Now()}
	server, chain := newGBTTestRPCServer(t, txSource)
	state := server.gbtWorkState

	state.Lock()
	if err := state.updateBlockTemplate(server, true); err != nil {
		state.Unlock()
		t.Fatalf("updateBlockTemplate first: %v", err)
	}
	firstTemplate := state.template
	state.Unlock()

	connectGBTTestTemplate(t, chain, firstTemplate)
	connectedHash := firstTemplate.Block.BlockHash()

	state.Lock()
	defer state.Unlock()
	if err := state.updateBlockTemplate(server, true); err != nil {
		t.Fatalf("updateBlockTemplate second: %v", err)
	}
	if state.template == firstTemplate {
		t.Fatal("template was reused after best chain tip changed")
	}
	if got, want := state.template.Height, firstTemplate.Height+1; got != want {
		t.Fatalf("template height = %d, want %d", got, want)
	}
	if got := state.template.Block.Header.PrevBlock; !got.IsEqual(&connectedHash) {
		t.Fatalf("template prev block = %v, want %v", got, connectedHash)
	}
}

func TestGBTWorkStateRegeneratesTemplateAfterMempoolUpdateWindow(t *testing.T) {
	firstUpdate := time.Now().Add(-2 * time.Minute)
	txSource := &gbtTestTxSource{updated: firstUpdate}
	server, _ := newGBTTestRPCServer(t, txSource)
	state := server.gbtWorkState

	state.Lock()
	if err := state.updateBlockTemplate(server, true); err != nil {
		state.Unlock()
		t.Fatalf("updateBlockTemplate first: %v", err)
	}
	firstTemplate := state.template
	state.lastGenerated = time.Now().Add(-(gbtRegenerateSeconds + 1) *
		time.Second)
	txSource.updated = time.Now()

	if err := state.updateBlockTemplate(server, true); err != nil {
		state.Unlock()
		t.Fatalf("updateBlockTemplate second: %v", err)
	}
	defer state.Unlock()

	if state.template == firstTemplate {
		t.Fatal("template was reused after stale mempool update")
	}
	if !state.lastTxUpdate.Equal(txSource.updated) {
		t.Fatalf("last tx update = %v, want %v", state.lastTxUpdate,
			txSource.updated)
	}
	if got, want := state.template.Height, firstTemplate.Height; got != want {
		t.Fatalf("template height = %d, want %d", got, want)
	}
}

// TestHandleTestMempoolAcceptFailDecode checks that when invalid hex string is
// used as the raw txns, the corresponding error is returned.
func TestHandleTestMempoolAcceptFailDecode(t *testing.T) {
	t.Parallel()

	require := require.New(t)

	// Create a testing server.
	s := &rpcServer{}

	testCases := []struct {
		name            string
		txns            []string
		expectedErrCode hnsjson.RPCErrorCode
	}{
		{
			name:            "hex decode fail",
			txns:            []string{"invalid"},
			expectedErrCode: hnsjson.ErrRPCDecodeHexString,
		},
		{
			name:            "tx decode fail",
			txns:            []string{"696e76616c6964"},
			expectedErrCode: hnsjson.ErrRPCDeserialization,
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Create a request that uses invalid raw txns.
			cmd := hnsjson.NewTestMempoolAcceptCmd(tc.txns, 0)

			// Call the method under test.
			closeChan := make(chan struct{})
			result, err := handleTestMempoolAccept(
				s, cmd, closeChan,
			)

			// Ensure the expected error is returned.
			require.Error(err)
			rpcErr, ok := err.(*hnsjson.RPCError)
			require.True(ok)
			require.Equal(tc.expectedErrCode, rpcErr.Code)

			// No result should be returned.
			require.Nil(result)
		})
	}
}

var (
	// Handshake-format test transactions: version(4) + input_count(1) +
	// prevhash(32) + previndex(4) + sequence(4) + output_count(1) +
	// value(8) + address(version+hashlen+hash) + covenant(type+items) +
	// locktime(4) + witness_count(1) + witness_items...
	//
	// txHex1: 1 input, 1 output (version-0, 20-byte zero hash), 1 witness item.
	txHex1 = "0100000001b14bdcbc3e01bdaad36cc08e81e69c82e1060bc14e518db2b49aa4" +
		"3ad90ba02600000000ffffffff0140420f000000000000140000000000000000" +
		"000000000000000000000000000000000000010430440220"

	// txHex2: same structure, different witness bytes.
	txHex2 = "0100000001b14bdcbc3e01bdaad36cc08e81e69c82e1060bc14e518db2b49aa4" +
		"3ad90ba02600000000ffffffff0140420f000000000000140000000000000000" +
		"000000000000000000000000000000000000010530440220ab"

	// txHex3: same structure, yet another witness variant.
	txHex3 = "0100000001b14bdcbc3e01bdaad36cc08e81e69c82e1060bc14e518db2b49aa4" +
		"3ad90ba02600000000ffffffff0140420f000000000000140000000000000000" +
		"000000000000000000000000000000000000010630440220ff47"
)

// decodeTxHex decodes the given hex string into a transaction.
func decodeTxHex(t *testing.T, txHex string) *hnsutil.Tx {
	rawBytes, err := hex.DecodeString(txHex)
	require.NoError(t, err)
	tx, err := hnsutil.NewTxFromBytes(rawBytes)
	require.NoError(t, err)

	return tx
}

// TestHandleTestMempoolAcceptMixedResults checks that when different txns get
// different responses from calling the mempool method `CheckMempoolAcceptance`
// their results are correctly returned.
func TestHandleTestMempoolAcceptMixedResults(t *testing.T) {
	t.Parallel()

	require := require.New(t)

	// Create a mock mempool.
	mm := &mempool.MockTxMempool{}

	// Create a testing server with the mock mempool.
	s := &rpcServer{cfg: rpcserverConfig{
		TxMemPool: mm,
	}}

	// Decode the hex so we can assert the mock mempool is called with it.
	tx1 := decodeTxHex(t, txHex1)
	tx2 := decodeTxHex(t, txHex2)
	tx3 := decodeTxHex(t, txHex3)

	// Create a slice to hold the expected results. We will use three txns
	// so we expect threeresults.
	expectedResults := make([]*hnsjson.TestMempoolAcceptResult, 3)

	// We now mock the first call to `CheckMempoolAcceptance` to return an
	// error.
	dummyErr := errors.New("dummy error")
	mm.On("CheckMempoolAcceptance", tx1).Return(nil, dummyErr).Once()

	// Since the call failed, we expect the first result to give us the
	// error.
	expectedResults[0] = &hnsjson.TestMempoolAcceptResult{
		Txid:         tx1.Hash().String(),
		Wtxid:        tx1.WitnessHash().String(),
		Allowed:      false,
		RejectReason: dummyErr.Error(),
	}

	// We mock the second call to `CheckMempoolAcceptance` to return a
	// result saying the tx is missing inputs.
	mm.On("CheckMempoolAcceptance", tx2).Return(
		&mempool.MempoolAcceptResult{
			MissingParents: []*chainhash.Hash{},
		}, nil,
	).Once()

	// We expect the second result to give us the missing-inputs error.
	expectedResults[1] = &hnsjson.TestMempoolAcceptResult{
		Txid:         tx2.Hash().String(),
		Wtxid:        tx2.WitnessHash().String(),
		Allowed:      false,
		RejectReason: "missing-inputs",
	}

	// We mock the third call to `CheckMempoolAcceptance` to return a
	// result saying the tx allowed.
	const feeDoo = hnsutil.Amount(1000)
	mm.On("CheckMempoolAcceptance", tx3).Return(
		&mempool.MempoolAcceptResult{
			TxFee:  feeDoo,
			TxSize: 100,
		}, nil,
	).Once()

	// We expect the third result to give us the fee details.
	expectedResults[2] = &hnsjson.TestMempoolAcceptResult{
		Txid:    tx3.Hash().String(),
		Wtxid:   tx3.WitnessHash().String(),
		Allowed: true,
		Vsize:   100,
		Fees: &hnsjson.TestMempoolAcceptFees{
			Base:             feeDoo.ToHNS(),
			EffectiveFeeRate: feeDoo.ToHNS() * 1e3 / 100,
		},
	}

	// Create a mock request with default max fee rate of 0.1 HNS/KvB.
	cmd := hnsjson.NewTestMempoolAcceptCmd(
		[]string{txHex1, txHex2, txHex3}, 0.1,
	)

	// Call the method handler and assert the expected results are
	// returned.
	closeChan := make(chan struct{})
	results, err := handleTestMempoolAccept(s, cmd, closeChan)
	require.NoError(err)
	require.Equal(expectedResults, results)

	// Assert the mocked method is called as expected.
	mm.AssertExpectations(t)
}

// TestValidateFeeRate checks that `validateFeeRate` behaves as expected.
func TestValidateFeeRate(t *testing.T) {
	t.Parallel()

	const (
		// testFeeRate is in HNS/kvB.
		testFeeRate = 0.1

		// testTxSize is in vb.
		testTxSize = 100

		// testFeeDoo is in dollarydoos (1 HNS = 1e6 doo).
		// We have 0.1 HNS/kvB =
		//   0.1 * 1e6 doo/kvB =
		//   0.1 * 1e6 / 1e3 doo/vb = 0.1 * 1e3 doo/vb.
		testFeeDoo = hnsutil.Amount(testFeeRate * 1e3 * testTxSize)
	)

	testCases := []struct {
		name         string
		feeDoo       hnsutil.Amount
		txSize       int64
		maxFeeRate   float64
		expectedFees *hnsjson.TestMempoolAcceptFees
		allowed      bool
	}{
		{
			// When the fee rate(0.1) is above the max fee
			// rate(0.01), we expect a nil result and false.
			name:         "fee rate above max",
			feeDoo:       testFeeDoo,
			txSize:       testTxSize,
			maxFeeRate:   testFeeRate / 10,
			expectedFees: nil,
			allowed:      false,
		},
		{
			// When the fee rate(0.1) is no greater than the max
			// fee rate(0.1), we expect a result and true.
			name:       "fee rate below max",
			feeDoo:     testFeeDoo,
			txSize:     testTxSize,
			maxFeeRate: testFeeRate,
			expectedFees: &hnsjson.TestMempoolAcceptFees{
				Base:             testFeeDoo.ToHNS(),
				EffectiveFeeRate: testFeeRate,
			},
			allowed: true,
		},
		{
			// When the fee rate(1) is above the default max fee
			// rate(0.1), we expect a nil result and false.
			name:         "fee rate above default max",
			feeDoo:       testFeeDoo,
			txSize:       testTxSize / 10,
			expectedFees: nil,
			allowed:      false,
		},
		{
			// When the fee rate(0.1) is no greater than the
			// default max fee rate(0.1), we expect a result and
			// true.
			name:   "fee rate below default max",
			feeDoo: testFeeDoo,
			txSize: testTxSize,
			expectedFees: &hnsjson.TestMempoolAcceptFees{
				Base:             testFeeDoo.ToHNS(),
				EffectiveFeeRate: testFeeRate,
			},
			allowed: true,
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)

			result, allowed := validateFeeRate(
				tc.feeDoo, tc.txSize, tc.maxFeeRate,
			)

			require.Equal(tc.expectedFees, result)
			require.Equal(tc.allowed, allowed)
		})
	}
}

// TestHandleTestMempoolAcceptFees checks that the `Fees` field is correctly
// populated based on the max fee rate and the tx being checked.
func TestHandleTestMempoolAcceptFees(t *testing.T) {
	t.Parallel()

	// Create a mock mempool.
	mm := &mempool.MockTxMempool{}

	// Create a testing server with the mock mempool.
	s := &rpcServer{cfg: rpcserverConfig{
		TxMemPool: mm,
	}}

	const (
		// Set transaction's fee rate to be 0.2 HNS/kvB.
		feeRate = defaultMaxFeeRate * 2

		// txSize is 100vb.
		txSize = 100

		// feeDoo is the fee expressed in dollarydoos
		// (feeRate [HNS/kvB] * 1e6 doo/HNS * txSize / 1e3 vb/kvB).
		feeDoo = feeRate * 1e6 * txSize / 1e3
	)

	testCases := []struct {
		name         string
		maxFeeRate   float64
		txHex        string
		rejectReason string
		allowed      bool
	}{
		{
			// When the fee rate(0.2) used by the tx is below the
			// max fee rate(2) specified, the result should allow
			// it.
			name:       "below max fee rate",
			maxFeeRate: feeRate * 10,
			txHex:      txHex1,
			allowed:    true,
		},
		{
			// When the fee rate(0.2) used by the tx is above the
			// max fee rate(0.02) specified, the result should
			// disallow it.
			name:         "above max fee rate",
			maxFeeRate:   feeRate / 10,
			txHex:        txHex1,
			allowed:      false,
			rejectReason: "max-fee-exceeded",
		},
		{
			// When the max fee rate is not set, the default
			// 0.1 HNS/kvB is used and the fee rate(0.2) used by the
			// tx is above it, the result should disallow it.
			name:         "above default max fee rate",
			txHex:        txHex1,
			allowed:      false,
			rejectReason: "max-fee-exceeded",
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)

			// Decode the hex so we can assert the mock mempool is
			// called with it.
			tx := decodeTxHex(t, txHex1)

			// We mock the call to `CheckMempoolAcceptance` to
			// return the result.
			mm.On("CheckMempoolAcceptance", tx).Return(
				&mempool.MempoolAcceptResult{
					TxFee:  feeDoo,
					TxSize: txSize,
				}, nil,
			).Once()

			// We expect the third result to give us the fee
			// details.
			expected := &hnsjson.TestMempoolAcceptResult{
				Txid:    tx.Hash().String(),
				Wtxid:   tx.WitnessHash().String(),
				Allowed: tc.allowed,
			}

			if tc.allowed {
				expected.Vsize = txSize
				expected.Fees = &hnsjson.TestMempoolAcceptFees{
					Base:             feeDoo / 1e6,
					EffectiveFeeRate: feeRate,
				}
			} else {
				expected.RejectReason = tc.rejectReason
			}

			// Create a mock request with specified max fee rate.
			cmd := hnsjson.NewTestMempoolAcceptCmd(
				[]string{txHex1}, tc.maxFeeRate,
			)

			// Call the method handler and assert the expected
			// result is returned.
			closeChan := make(chan struct{})
			r, err := handleTestMempoolAccept(s, cmd, closeChan)
			require.NoError(err)

			// Check the interface type.
			results, ok := r.([]*hnsjson.TestMempoolAcceptResult)
			require.True(ok)

			// Expect exactly one result.
			require.Len(results, 1)

			// Check the result is returned as expected.
			require.Equal(expected, results[0])

			// Assert the mocked method is called as expected.
			mm.AssertExpectations(t)
		})
	}
}

// TestGetTxSpendingPrevOut checks that handleGetTxSpendingPrevOut handles the
// cmd as expected.
func TestGetTxSpendingPrevOut(t *testing.T) {
	t.Parallel()

	require := require.New(t)

	// Create a mock mempool.
	mm := &mempool.MockTxMempool{}
	defer mm.AssertExpectations(t)

	// Create a testing server with the mock mempool.
	s := &rpcServer{cfg: rpcserverConfig{
		TxMemPool: mm,
	}}

	// First, check the error case.
	//
	// Create a request that will cause an error.
	cmd := &hnsjson.GetTxSpendingPrevOutCmd{
		Outputs: []*hnsjson.GetTxSpendingPrevOutCmdOutput{
			{Txid: "invalid"},
		},
	}

	// Call the method handler and assert the error is returned.
	closeChan := make(chan struct{})
	results, err := handleGetTxSpendingPrevOut(s, cmd, closeChan)
	require.Error(err)
	require.Nil(results)

	// We now check the normal case. Two outputs will be tested - one found
	// in mempool and other not.
	//
	// Decode the hex so we can assert the mock mempool is called with it.
	tx := decodeTxHex(t, txHex1)

	// Create testing outpoints.
	opInMempool := wire.OutPoint{Hash: chainhash.Hash{1}, Index: 1}
	opNotInMempool := wire.OutPoint{Hash: chainhash.Hash{2}, Index: 1}

	// We only expect to see one output being found as spent in mempool.
	expectedResults := []*hnsjson.GetTxSpendingPrevOutResult{
		{
			Txid:         opInMempool.Hash.String(),
			Vout:         opInMempool.Index,
			SpendingTxid: tx.Hash().String(),
		},
		{
			Txid: opNotInMempool.Hash.String(),
			Vout: opNotInMempool.Index,
		},
	}

	// We mock the first call to `CheckSpend` to return a result saying the
	// output is found.
	mm.On("CheckSpend", opInMempool).Return(tx).Once()

	// We mock the second call to `CheckSpend` to return a result saying the
	// output is NOT found.
	mm.On("CheckSpend", opNotInMempool).Return(nil).Once()

	// Create a request with the above outputs.
	cmd = &hnsjson.GetTxSpendingPrevOutCmd{
		Outputs: []*hnsjson.GetTxSpendingPrevOutCmdOutput{
			{
				Txid: opInMempool.Hash.String(),
				Vout: opInMempool.Index,
			},
			{
				Txid: opNotInMempool.Hash.String(),
				Vout: opNotInMempool.Index,
			},
		},
	}

	// Call the method handler and assert the expected result is returned.
	closeChan = make(chan struct{})
	results, err = handleGetTxSpendingPrevOut(s, cmd, closeChan)
	require.NoError(err)
	require.Equal(expectedResults, results)
}
