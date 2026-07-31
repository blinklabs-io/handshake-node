// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

//go:build hsdinterop

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPinnedHsdIndexRebuild(t *testing.T) {
	const blockCount = 5

	hsdDir := requirePinnedHsd(t)
	ports, releasePorts := reserveLoopbackPorts(t, 4)
	hsdP2PPort, hsdBrontidePort := ports[0], ports[1]
	hsdHTTPPort, nodeRPCPort := ports[2], ports[3]

	testDir := t.TempDir()
	hsdPrefix := filepath.Join(testDir, "hsd")
	nodeDataDir := filepath.Join(testDir, "handshake-node-data")
	nodeLogDir := filepath.Join(testDir, "handshake-node-logs")
	nodeConfigFile := filepath.Join(testDir, "handshake-node.conf")
	if err := os.WriteFile(nodeConfigFile, nil, 0o600); err != nil {
		t.Fatalf("create isolated node config: %v", err)
	}
	nodeBinary := buildHandshakeNode(t, testDir)

	hsd := &liveProcess{name: "pinned hsd"}
	node := &liveProcess{name: "handshake-node"}
	t.Cleanup(func() {
		node.stop(t, true)
		hsd.stop(t, true)
	})

	hsdCommand := func() *exec.Cmd {
		return exec.Command("node",
			filepath.Join(hsdDir, "bin", "hsd"),
			"--network=regtest",
			"--prefix="+hsdPrefix,
			"--workers=false",
			"--listen",
			"--host=127.0.0.1",
			fmt.Sprintf("--port=%d", hsdP2PPort),
			fmt.Sprintf("--brontide-port=%d", hsdBrontidePort),
			"--http-host=127.0.0.1",
			fmt.Sprintf("--http-port=%d", hsdHTTPPort),
			"--no-auth",
			"--no-wallet",
			"--no-dns",
			"--log-console",
			"--log-level=debug",
			"--coinbase-address="+hsdRegtestMiningAddress,
			"--identity-key="+hsdIdentityKey,
		)
	}
	nodeCommand := func() *exec.Cmd {
		return exec.Command(nodeBinary,
			"--regtest",
			"--regtestpersist",
			"--configfile="+nodeConfigFile,
			"--datadir="+nodeDataDir,
			"--logdir="+nodeLogDir,
			fmt.Sprintf("--rpclisten=127.0.0.1:%d", nodeRPCPort),
			"--rpcuser="+interopRPCUser,
			"--rpcpass="+interopRPCPass,
			"--notls",
			fmt.Sprintf("--connect=127.0.0.1:%d", hsdP2PPort),
			"--txindex",
			"--addrindex",
			"--debuglevel=debug",
		)
	}

	releasePorts()
	hsd.start(t, hsdCommand)
	node.start(t, nodeCommand)

	hsdRPC := &liveRPCClient{
		url:  fmt.Sprintf("http://127.0.0.1:%d/", hsdHTTPPort),
		http: &http.Client{},
	}
	nodeRPC := &liveRPCClient{
		url:  fmt.Sprintf("http://127.0.0.1:%d/", nodeRPCPort),
		user: interopRPCUser,
		pass: interopRPCPass,
		http: &http.Client{},
	}
	t.Cleanup(hsdRPC.closeIdleConnections)
	t.Cleanup(nodeRPC.closeIdleConnections)

	waitForLiveRPC(t, hsdRPC, hsd, 15*time.Second)
	waitForLiveRPC(t, nodeRPC, node, 30*time.Second)
	waitForPeerCount(t, nodeRPC, node, 1, 15*time.Second)

	hashes := generateHsdBlocks(t, hsdRPC, blockCount)
	tipHash := hashes[len(hashes)-1]
	waitForMatchingTip(t, nodeRPC, node, blockCount, tipHash,
		30*time.Second)
	txHash := blockCoinbaseHash(t, nodeRPC, tipHash)
	assertRebuiltIndexes(t, nodeRPC, tipHash, txHash)

	node.stop(t, false)
	nodeRPC.closeIdleConnections()
	for _, flag := range []string{
		"--dropaddrindex",
		"--droptxindex",
		"--dropcfindex",
	} {
		dropNodeIndex(t, nodeBinary, nodeConfigFile, nodeDataDir,
			nodeLogDir, flag)
	}

	logOffset := len(node.logs.String())
	node.start(t, nodeCommand)
	waitForLiveRPC(t, nodeRPC, node, 30*time.Second)
	waitForPeerCount(t, nodeRPC, node, 1, 15*time.Second)
	waitForMatchingTip(t, nodeRPC, node, blockCount, tipHash,
		10*time.Second)
	restartLogs := node.logs.String()[logOffset:]
	if !strings.Contains(restartLogs,
		fmt.Sprintf("Catching up indexes from height -1 to %d", blockCount)) ||
		!strings.Contains(restartLogs,
			fmt.Sprintf("Indexes caught up to height %d", blockCount)) {

		t.Fatalf("node did not report rebuilding indexes:\n%s", restartLogs)
	}
	assertRebuiltIndexes(t, nodeRPC, tipHash, txHash)

	continued := generateHsdBlocks(t, hsdRPC, 1)
	waitForMatchingTip(t, nodeRPC, node, blockCount+1, continued[0],
		20*time.Second)
	continuedTxHash := blockCoinbaseHash(t, nodeRPC, continued[0])
	assertRebuiltIndexes(t, nodeRPC, continued[0], continuedTxHash)

	node.stop(t, false)
	hsd.stop(t, false)
}

func dropNodeIndex(t *testing.T, nodeBinary, configFile, dataDir, logDir,
	flag string) {
	t.Helper()

	cmd := exec.Command(nodeBinary,
		"--regtest",
		"--regtestpersist",
		"--configfile="+configFile,
		"--datadir="+dataDir,
		"--logdir="+logDir,
		flag,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\nhandshake-node output:\n%s",
			flag, err, output)
	}
}

func blockCoinbaseHash(t *testing.T, client *liveRPCClient,
	blockHash string) string {

	t.Helper()
	result := callLiveRPC(t, client, "getblock", blockHash, 1)
	var block struct {
		Tx []string `json:"tx"`
	}
	if err := json.Unmarshal(result, &block); err != nil {
		t.Fatalf("decode block %s: %v", blockHash, err)
	}
	if len(block.Tx) == 0 {
		t.Fatalf("block %s has no transactions", blockHash)
	}
	return block.Tx[0]
}

func assertRebuiltIndexes(t *testing.T, client *liveRPCClient,
	blockHash, txHash string) {

	t.Helper()

	result := callLiveRPC(t, client, "getrawtransaction", txHash, 1)
	var tx struct {
		TxID      string `json:"txid"`
		BlockHash string `json:"blockhash"`
	}
	if err := json.Unmarshal(result, &tx); err != nil {
		t.Fatalf("decode indexed transaction %s: %v", txHash, err)
	}
	if !strings.EqualFold(tx.TxID, txHash) ||
		!strings.EqualFold(tx.BlockHash, blockHash) {

		t.Fatalf("unexpected transaction index result: txid=%s block=%s",
			tx.TxID, tx.BlockHash)
	}

	result = callLiveRPC(t, client, "searchrawtransactions",
		hsdRegtestMiningAddress)
	var addressTxs []struct {
		TxID string `json:"txid"`
	}
	if err := json.Unmarshal(result, &addressTxs); err != nil {
		t.Fatalf("decode address index result: %v", err)
	}
	found := false
	for _, addressTx := range addressTxs {
		if strings.EqualFold(addressTx.TxID, txHash) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("address index did not return transaction %s", txHash)
	}

	result = callLiveRPC(t, client, "getcfilter", blockHash, 0)
	var filter string
	if err := json.Unmarshal(result, &filter); err != nil {
		t.Fatalf("decode committed filter for %s: %v", blockHash, err)
	}
	if filter == "" {
		t.Fatalf("committed filter for %s is empty", blockHash)
	}
}
