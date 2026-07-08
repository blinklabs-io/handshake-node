// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// This file is ignored during the regular tests due to the following build tag.
//go:build rpctest
// +build rpctest

package integration

import (
	"bytes"
	"fmt"
	"os"
	"runtime/debug"
	"testing"
	"time"

	"github.com/blinklabs-io/handshake-node/blockchain"
	"github.com/blinklabs-io/handshake-node/chaincfg"
	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/integration/rpctest"
	"github.com/blinklabs-io/handshake-node/rpcclient"
)

func testGetBestBlock(r *rpctest.Harness, t *testing.T) {
	_, prevbestHeight, err := r.Client.GetBestBlock()
	if err != nil {
		t.Fatalf("Call to `getbestblock` failed: %v", err)
	}

	// Create a new block connecting to the current tip.
	generatedBlockHashes, err := r.Client.Generate(1)
	if err != nil {
		t.Fatalf("Unable to generate block: %v", err)
	}

	bestHash, bestHeight, err := r.Client.GetBestBlock()
	if err != nil {
		t.Fatalf("Call to `getbestblock` failed: %v", err)
	}

	// Hash should be the same as the newly submitted block.
	if !bytes.Equal(bestHash[:], generatedBlockHashes[0][:]) {
		t.Fatalf("Block hashes do not match. Returned hash %v, wanted "+
			"hash %v", bestHash, generatedBlockHashes[0][:])
	}

	// Block height should now reflect newest height.
	if bestHeight != prevbestHeight+1 {
		t.Fatalf("Block heights do not match. Got %v, wanted %v",
			bestHeight, prevbestHeight+1)
	}
}

func testGetBlockCount(r *rpctest.Harness, t *testing.T) {
	// Save the current count.
	currentCount, err := r.Client.GetBlockCount()
	if err != nil {
		t.Fatalf("Unable to get block count: %v", err)
	}

	if _, err := r.Client.Generate(1); err != nil {
		t.Fatalf("Unable to generate block: %v", err)
	}

	// Count should have increased by one.
	newCount, err := r.Client.GetBlockCount()
	if err != nil {
		t.Fatalf("Unable to get block count: %v", err)
	}
	if newCount != currentCount+1 {
		t.Fatalf("Block count incorrect. Got %v should be %v",
			newCount, currentCount+1)
	}
}

func testGetBlockHash(r *rpctest.Harness, t *testing.T) {
	// Create a new block connecting to the current tip.
	generatedBlockHashes, err := r.Client.Generate(1)
	if err != nil {
		t.Fatalf("Unable to generate block: %v", err)
	}

	info, err := r.Client.GetInfo()
	if err != nil {
		t.Fatalf("call to getinfo cailed: %v", err)
	}

	blockHash, err := r.Client.GetBlockHash(int64(info.Blocks))
	if err != nil {
		t.Fatalf("Call to `getblockhash` failed: %v", err)
	}

	// Block hashes should match newly created block.
	if !bytes.Equal(generatedBlockHashes[0][:], blockHash[:]) {
		t.Fatalf("Block hashes do not match. Returned hash %v, wanted "+
			"hash %v", blockHash, generatedBlockHashes[0][:])
	}
}

func testBulkClient(r *rpctest.Harness, t *testing.T) {
	// Create a new block connecting to the current tip.
	generatedBlockHashes, err := r.Client.Generate(20)
	if err != nil {
		t.Fatalf("Unable to generate block: %v", err)
	}

	var futureBlockResults []rpcclient.FutureGetBlockResult
	for _, hash := range generatedBlockHashes {
		futureBlockResults = append(futureBlockResults, r.BatchClient.GetBlockAsync(hash))
	}

	err = r.BatchClient.Send()
	if err != nil {
		t.Fatal(err)
	}

	isKnownBlockHash := func(blockHash chainhash.Hash) bool {
		for _, hash := range generatedBlockHashes {
			if blockHash.IsEqual(hash) {
				return true
			}
		}
		return false
	}

	for _, block := range futureBlockResults {
		msgBlock, err := block.Receive()
		if err != nil {
			t.Fatal(err)
		}
		blockHash := msgBlock.Header.BlockHash()
		if !isKnownBlockHash(blockHash) {
			t.Fatalf("expected hash %s  to be in generated hash list", blockHash)
		}
	}

}

func calculateHashesPerSecBetweenBlockHeights(r *rpctest.Harness, t *testing.T, startHeight, endHeight int64) float64 {
	var totalWork int64 = 0
	var minTimestamp, maxTimestamp time.Time

	if endHeight <= startHeight {
		return 0
	}

	for curHeight := startHeight; curHeight <= endHeight; curHeight++ {
		hash, err := r.Client.GetBlockHash(curHeight)

		if err != nil {
			t.Fatal(err)
		}

		blockHeader, err := r.Client.GetBlockHeader(hash)

		if err != nil {
			t.Fatal(err)
		}

		if curHeight == startHeight {
			minTimestamp = blockHeader.Timestamp
			maxTimestamp = minTimestamp
			continue
		}

		totalWork += blockchain.CalcWork(blockHeader.Bits).Int64()

		if minTimestamp.After(blockHeader.Timestamp) {
			minTimestamp = blockHeader.Timestamp
		}
		if maxTimestamp.Before(blockHeader.Timestamp) {
			maxTimestamp = blockHeader.Timestamp
		}
	}

	timeDiff := maxTimestamp.Sub(minTimestamp).Seconds()

	if timeDiff == 0 {
		return 0
	}

	return float64(totalWork) / timeDiff
}

func expectedNetworkHashesPerSec(r *rpctest.Harness, t *testing.T,
	blocks, height *int) float64 {
	bestHeight, err := r.Client.GetBlockCount()
	if err != nil {
		t.Fatal(err)
	}

	endHeight := int64(-1)
	if height != nil {
		endHeight = int64(*height)
	}
	if endHeight > bestHeight || endHeight == 0 {
		return 0
	}
	if endHeight < 0 {
		endHeight = bestHeight
	}

	blocksPerRetarget := int64(r.ActiveNet.TargetTimespan /
		r.ActiveNet.TargetTimePerBlock)
	numBlocks := int64(120)
	if blocks != nil {
		numBlocks = int64(*blocks)
	}
	var startHeight int64
	if numBlocks <= 0 {
		startHeight = endHeight - ((endHeight % blocksPerRetarget) + 1)
	} else {
		startHeight = endHeight - numBlocks
	}
	if startHeight < 0 {
		startHeight = 0
	}

	return calculateHashesPerSecBetweenBlockHeights(r, t, startHeight,
		endHeight)
}

func testGetNetworkHashPS(r *rpctest.Harness, t *testing.T) {
	networkHashPS, err := r.Client.GetNetworkHashPS()

	if err != nil {
		t.Fatal(err)
	}

	expectedNetworkHashPS := expectedNetworkHashesPerSec(r, t, nil, nil)

	if networkHashPS != expectedNetworkHashPS {
		t.Fatalf("Network hashes per second should be %f but received: %f", expectedNetworkHashPS, networkHashPS)
	}
}

func testGetNetworkHashPS2(r *rpctest.Harness, t *testing.T) {
	networkHashPS2BlockTests := []int{-200, 0, 10, 100, 200}

	for _, blocks := range networkHashPS2BlockTests {
		networkHashPS, err := r.Client.GetNetworkHashPS2(blocks)

		if err != nil {
			t.Fatal(err)
		}

		expectedNetworkHashPS := expectedNetworkHashesPerSec(r, t,
			&blocks, nil)

		if networkHashPS != expectedNetworkHashPS {
			t.Fatalf("Network hashes per second should be %f but received: %f", expectedNetworkHashPS, networkHashPS)
		}
	}
}

func testGetNetworkHashPS3(r *rpctest.Harness, t *testing.T) {
	bestHeight, err := r.Client.GetBlockCount()
	if err != nil {
		t.Fatal(err)
	}
	validHeight := int(bestHeight / 2)
	if validHeight < 1 {
		validHeight = 1
	}
	futureHeight := int(bestHeight + 50)
	networkHashPS3BlockTests := []struct {
		height int
		blocks int
	}{
		{height: -200, blocks: -120},
		{height: -200, blocks: 0},
		{height: -200, blocks: 10},
		{height: -200, blocks: 100},
		{height: -200, blocks: 250},
		{height: 0, blocks: 120},
		{height: validHeight, blocks: -120},
		{height: validHeight, blocks: 0},
		{height: validHeight, blocks: 10},
		{height: validHeight, blocks: 100},
		{height: validHeight, blocks: 200},
		{height: futureHeight, blocks: 120},
	}

	for _, networkHashPS3BlockTest := range networkHashPS3BlockTests {
		blocks := networkHashPS3BlockTest.blocks
		height := networkHashPS3BlockTest.height

		networkHashPS, err := r.Client.GetNetworkHashPS3(blocks, height)

		if err != nil {
			t.Fatal(err)
		}

		expectedNetworkHashPS := expectedNetworkHashesPerSec(r, t, &blocks,
			&height)

		if networkHashPS != expectedNetworkHashPS {
			t.Fatalf("Network hashes per second should be %f but received: %f", expectedNetworkHashPS, networkHashPS)
		}
	}
}

var rpcTestCases = []rpctest.HarnessTestCase{
	testGetBestBlock,
	testGetBlockCount,
	testGetBlockHash,
	testBulkClient,
	testGetNetworkHashPS,
	testGetNetworkHashPS2,
	testGetNetworkHashPS3,
}

var primaryHarness *rpctest.Harness

func TestMain(m *testing.M) {
	var err error

	// In order to properly test scenarios on as if we were on mainnet,
	// ensure that non-standard transactions aren't accepted into the
	// mempool or relayed.
	hnsCfg := []string{"--rejectnonstd"}
	primaryHarness, err = rpctest.New(
		&chaincfg.RegressionNetParams, nil, hnsCfg, "",
	)
	if err != nil {
		fmt.Println("unable to create primary harness: ", err)
		os.Exit(1)
	}

	// Initialize the primary mining node with a chain of length 125,
	// providing 25 mature coinbases to allow spending from for testing
	// purposes.
	if err := primaryHarness.SetUp(true, 25); err != nil {
		fmt.Println("unable to setup test chain: ", err)

		// Even though the harness was not fully setup, it still needs
		// to be torn down to ensure all resources such as temp
		// directories are cleaned up.  The error is intentionally
		// ignored since this is already an error path and nothing else
		// could be done about it anyways.
		_ = primaryHarness.TearDown()
		os.Exit(1)
	}

	exitCode := m.Run()

	// Clean up any active harnesses that are still currently running.This
	// includes removing all temporary directories, and shutting down any
	// created processes.
	if err := rpctest.TearDownAll(); err != nil {
		fmt.Println("unable to tear down all harnesses: ", err)
		os.Exit(1)
	}

	os.Exit(exitCode)
}

func TestRpcServer(t *testing.T) {
	var currentTestNum int
	defer func() {
		// If one of the integration tests caused a panic within the main
		// goroutine, then tear down all the harnesses in order to avoid
		// any leaked handshake-node processes.
		if r := recover(); r != nil {
			fmt.Println("recovering from test panic: ", r)
			if err := rpctest.TearDownAll(); err != nil {
				fmt.Println("unable to tear down all harnesses: ", err)
			}
			t.Fatalf("test #%v panicked: %s", currentTestNum, debug.Stack())
		}
	}()

	for _, testCase := range rpcTestCases {
		testCase(primaryHarness, t)

		currentTestNum++
	}
}
