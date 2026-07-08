package blockchain

import (
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/blinklabs-io/handshake-node/blockchain/internal/testhelper"
	"github.com/blinklabs-io/handshake-node/chaincfg"
	"github.com/blinklabs-io/handshake-node/hnsutil"
	"github.com/blinklabs-io/handshake-node/wire"
	"github.com/stretchr/testify/require"
)

// chainedHeaders returns desired amount of connected headers from the parentHeight.
func chainedHeaders(parent *wire.BlockHeader, chainParams *chaincfg.Params,
	parentHeight int32, numHeaders int) []*wire.BlockHeader {

	headers := make([]*wire.BlockHeader, 0, numHeaders)
	tip := parent

	for i := 0; i < numHeaders; i++ {
		blockHeight := parentHeight + int32(i) + 1

		// Use a timestamp that is one second after the previous block unless
		// this is the first block in which case the current time is used.
		var ts time.Time
		if blockHeight == 1 {
			ts = time.Unix(time.Now().Unix(), 0)
		} else {
			ts = tip.Timestamp.Add(time.Second)
		}

		coinbase := testhelper.CreateCoinbaseTx(
			blockHeight, CalcBlockSubsidy(blockHeight, chainParams),
		)
		extraNonce := uint64(parentHeight)<<32 | uint64(i)
		coinbaseScript, err := testhelper.StandardCoinbaseScript(
			blockHeight, extraNonce,
		)
		if err != nil {
			panic(fmt.Sprintf("Unable to create coinbase script at height %d: %v",
				blockHeight, err))
		}
		coinbase.TxIn[0].Witness = wire.TxWitness{coinbaseScript}
		uniquePayload := make([]byte, 8)
		binary.LittleEndian.PutUint64(uniquePayload, extraNonce)
		coinbase.AddTxOut(wire.NewTxOut(0,
			wire.Address{Version: 1, Hash: uniquePayload}, wire.Covenant{}))
		txs := []*hnsutil.Tx{hnsutil.NewTx(coinbase)}

		header := wire.BlockHeader{
			Version:     2,
			PrevBlock:   tip.BlockHash(),
			MerkleRoot:  CalcMerkleRoot(txs, false),
			WitnessRoot: CalcMerkleRoot(txs, true),
			Bits:        chainParams.PowLimitBits,
			Timestamp:   ts,
			Nonce:       0,
		}
		if !testhelper.SolveBlock(&header) {
			panic(fmt.Sprintf("Unable to solve block at height %d",
				blockHeight))
		}
		headers = append(headers, &header)
		tip = &header
	}

	return headers
}

func TestProcessBlockHeader(t *testing.T) {
	chain, params, tearDown := utxoCacheTestChain("TestProcessBlockHeader")
	defer tearDown()

	// Generate and process the intial 10 block headers.
	//
	// genesis -> 1  -> 2  -> ...  -> 10 (active)
	headers := chainedHeaders(&params.GenesisBlock.Header, params, 0, 10)

	// Set checkpoint at block 4.
	fourthHeader := headers[3]
	fourthHeaderHash := fourthHeader.BlockHash()
	checkpoint := chaincfg.Checkpoint{
		Height: 4,
		Hash:   &fourthHeaderHash,
	}
	chain.checkpoints = append(chain.checkpoints, checkpoint)
	chain.checkpointsByHeight = make(map[int32]*chaincfg.Checkpoint)
	chain.checkpointsByHeight[checkpoint.Height] = &checkpoint

	for _, header := range headers {
		isMainChain, err := chain.ProcessBlockHeader(header, BFNone, false)
		require.NoError(t, err)
		require.True(t, isMainChain)
	}

	// Check that the tip is correct.
	lastHeader := headers[len(headers)-1]
	lastHeaderHash := lastHeader.BlockHash()
	tipNode := chain.bestHeader.Tip()
	require.Equal(t, lastHeaderHash, tipNode.hash)
	require.Equal(t, statusHeaderStored, tipNode.status)
	require.Equal(t, int32(len(headers)), tipNode.height)

	// Create invalid header at the checkpoint.
	thirdHeaderHash := headers[2].BlockHash()
	thirdNode := chain.index.LookupNode(&thirdHeaderHash)
	invalidForkHeight := thirdNode.height
	invalidHeaders := chainedHeaders(headers[2], params, invalidForkHeight, 1)

	// Check that the header fails validation.
	_, err := chain.ProcessBlockHeader(invalidHeaders[0], BFNone, false)
	require.Errorf(t, err,
		"invalidHeader %v passed verification but "+
			"should've failed verification "+
			"as the header doesn't match the checkpoint",
		invalidHeaders[0].BlockHash().String(),
	)

	// Create sidechain block headers.
	//
	// genesis -> 1  -> 2  -> 3  -> 4  -> 5  -> ... -> 10 (active)
	//                                      \-> 6  -> ... -> 8 (valid-fork)
	blockHash := headers[4].BlockHash()
	node := chain.index.LookupNode(&blockHash)
	forkHeight := node.height
	sideChainHeaders := chainedHeaders(headers[4], params, node.height, 3)
	sidechainTip := sideChainHeaders[len(sideChainHeaders)-1]

	// Test that the last block header fails as it's missing the previous block
	// header.
	_, err = chain.ProcessBlockHeader(sidechainTip, BFNone, false)
	require.Errorf(t, err,
		"sideChainHeader %v passed verification but "+
			"should've failed verification"+
			"as the previous header is not known",
		sideChainHeaders[len(sideChainHeaders)-1].BlockHash().String(),
	)

	// Verify that the side-chain headers verify.
	for _, header := range sideChainHeaders {
		isMainChain, err := chain.ProcessBlockHeader(header, BFNone, false)
		require.NoError(t, err)
		require.False(t, isMainChain)
	}

	// Check that the tip is still the same as before.
	tipNode = chain.bestHeader.Tip()
	require.Equal(t, lastHeaderHash, tipNode.hash)
	require.Equal(t, statusHeaderStored, tipNode.status)
	require.Equal(t, int32(len(headers)), tipNode.height)

	// Verify that the side-chain extending headers verify.
	sidechainExtendingHeaders := chainedHeaders(
		sidechainTip, params, forkHeight+int32(len(sideChainHeaders)), 10)
	for _, header := range sidechainExtendingHeaders {
		isMainChain, err := chain.ProcessBlockHeader(header, BFNone, false)
		require.NoError(t, err)

		blockHash := header.BlockHash()
		node := chain.index.LookupNode(&blockHash)
		if node.height <= 10 {
			require.False(t, isMainChain)
		} else {
			require.True(t, isMainChain)
		}
	}

	// Create more sidechain block headers so that it becomes the active chain.
	//
	// 	genesis -> 1  -> 2  -> 3  -> 4  -> 5  -> ... -> 10 (valid-fork)
	//                                            \-> 6  -> ... -> 18 (active)
	lastSideChainHeaderIdx := len(sidechainExtendingHeaders) - 1
	lastSidechainHeader := sidechainExtendingHeaders[lastSideChainHeaderIdx]
	lastSidechainHeaderHash := lastSidechainHeader.BlockHash()

	// Check that the tip is now different.
	tipNode = chain.bestHeader.Tip()
	require.Equal(t, lastSidechainHeaderHash, tipNode.hash)
	require.Equal(t, statusHeaderStored, tipNode.status)
	require.Equal(t,
		int32(len(sideChainHeaders)+len(sidechainExtendingHeaders))+forkHeight,
		tipNode.height)

	// Extend the original headers and check it still verifies.
	extendedOrigHdrs := chainedHeaders(lastHeader, params, int32(len(headers)), 2)
	for _, header := range extendedOrigHdrs {
		isMainChain, err := chain.ProcessBlockHeader(header, BFNone, false)
		require.NoError(t, err)
		require.False(t, isMainChain)
	}

	// Check that the tip didn't change.
	tipNode = chain.bestHeader.Tip()
	require.Equal(t, lastSidechainHeaderHash, tipNode.hash)
}

func TestAssumeValidScriptValidationPath(t *testing.T) {
	chain, params, tearDown := utxoCacheTestChain(
		"TestAssumeValidScriptValidationPath")
	defer tearDown()

	headers := chainedHeaders(&params.GenesisBlock.Header, params, 0, 3)
	firstHash := headers[0].BlockHash()
	assumeValidHash := headers[1].BlockHash()

	chain.assumeValid = &assumeValidHash

	_, err := chain.ProcessBlockHeader(headers[0], BFNone, false)
	require.NoError(t, err)
	firstNode := chain.index.LookupNode(&firstHash)
	require.NotNil(t, firstNode)

	// The trusted block hash is not known yet, so even an ancestor height
	// must still run scripts.
	require.True(t, chain.shouldValidateScripts(firstNode))

	_, err = chain.ProcessBlockHeader(headers[1], BFNone, false)
	require.NoError(t, err)
	assumeValidNode := chain.index.LookupNode(&assumeValidHash)
	require.NotNil(t, assumeValidNode)
	require.False(t, chain.shouldValidateScripts(firstNode))
	require.False(t, chain.shouldValidateScripts(assumeValidNode))

	_, err = chain.ProcessBlockHeader(headers[2], BFNone, false)
	require.NoError(t, err)
	thirdHash := headers[2].BlockHash()
	thirdNode := chain.index.LookupNode(&thirdHash)
	require.NotNil(t, thirdNode)
	require.True(t, chain.shouldValidateScripts(thirdNode))

	sideHeader := *headers[1]
	sideHeader.Timestamp = sideHeader.Timestamp.Add(time.Second)
	sideHeader.Nonce = 0
	require.True(t, testhelper.SolveBlock(&sideHeader))
	sideHash := sideHeader.BlockHash()
	require.NotEqual(t, assumeValidHash, sideHash)
	_, err = chain.ProcessBlockHeader(&sideHeader, BFNone, false)
	require.NoError(t, err)
	sideNode := chain.index.LookupNode(&sideHash)
	require.NotNil(t, sideNode)
	require.True(t, chain.shouldValidateScripts(sideNode))

	chain.index.SetStatusFlags(assumeValidNode, statusValidateFailed)
	require.True(t, chain.shouldValidateScripts(firstNode))
	require.True(t, chain.shouldValidateScripts(assumeValidNode))
}
