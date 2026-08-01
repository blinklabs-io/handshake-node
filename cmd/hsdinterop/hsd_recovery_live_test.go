// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

//go:build hsdinterop

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/blinklabs-io/handshake-node/chaincfg"
)

const (
	recoveryBlockCount       = 80
	recoveryMaxBlockFileSize = 2048
	recoveryPruneTarget      = 8192
)

func TestPinnedHsdPruneAndCorruptionRecovery(t *testing.T) {
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
	blockDBPath := filepath.Join(nodeDataDir, "regtest", "blocks_ffldb")

	hsd := &liveProcess{name: "pinned hsd"}
	node := &liveProcess{name: "pruned handshake-node"}
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
		cmd := exec.Command(nodeBinary,
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
			"--prune=1536",
			"--debuglevel=debug",
		)
		cmd.Env = append(os.Environ(),
			fmt.Sprintf("HNS_HSDINTEROP_MAX_BLOCK_FILE_SIZE=%d",
				recoveryMaxBlockFileSize),
			fmt.Sprintf("HNS_HSDINTEROP_PRUNE_TARGET=%d",
				recoveryPruneTarget),
		)
		return cmd
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

	hashes := generateHsdBlocks(t, hsdRPC, recoveryBlockCount)
	tipHash := hashes[len(hashes)-1]
	waitForMatchingTip(t, nodeRPC, node, recoveryBlockCount, tipHash,
		60*time.Second)
	waitForPhysicalPrune(t, nodeRPC, node, blockDBPath, 30*time.Second)
	assertConfiguredPruned(t, nodeRPC)
	assertGenesisPruned(t, nodeRPC)

	continued := generateHsdBlocks(t, hsdRPC, 1)
	tipHash = continued[0]
	waitForMatchingTip(t, nodeRPC, node, recoveryBlockCount+1, tipHash,
		20*time.Second)

	node.stop(t, false)
	nodeRPC.closeIdleConnections()
	corruptLevelDBCurrent(t, blockDBPath)

	logOffset := len(node.logs.String())
	node.start(t, nodeCommand)
	waitForProcessFailure(t, node, 30*time.Second)
	corruptionLogs := strings.ToLower(node.logs.String()[logOffset:])
	if !strings.Contains(corruptionLogs, "corrupt") ||
		!strings.Contains(corruptionLogs, "blocks_ffldb") {

		t.Fatalf("node did not fail closed on the corrupted database:\n%s",
			node.logs.String()[logOffset:])
	}
	node.stop(t, true)
	nodeRPC.closeIdleConnections()

	if err := os.RemoveAll(blockDBPath); err != nil {
		t.Fatalf("remove corrupted block database: %v", err)
	}
	node.start(t, nodeCommand)
	waitForLiveRPC(t, nodeRPC, node, 30*time.Second)
	waitForPeerCount(t, nodeRPC, node, 1, 15*time.Second)
	waitForMatchingTip(t, nodeRPC, node, recoveryBlockCount+1, tipHash,
		90*time.Second)
	waitForPhysicalPrune(t, nodeRPC, node, blockDBPath, 30*time.Second)
	assertConfiguredPruned(t, nodeRPC)
	assertGenesisPruned(t, nodeRPC)

	afterRecovery := generateHsdBlocks(t, hsdRPC, 1)
	waitForMatchingTip(t, nodeRPC, node, recoveryBlockCount+2,
		afterRecovery[0], 20*time.Second)

	node.stop(t, false)
	hsd.stop(t, false)
}

func waitForPhysicalPrune(t *testing.T, client *liveRPCClient,
	process *liveProcess, blockDBPath string, timeout time.Duration) {

	t.Helper()
	waitForCondition(t, process, timeout, "physical block-file pruning",
		func(context.Context) (bool, error) {
			fileNumbers, err := blockFileNumbers(blockDBPath)
			if err != nil || len(fileNumbers) == 0 {
				return false, err
			}
			return fileNumbers[0] > 0, nil
		})

	fileNumbers, err := blockFileNumbers(blockDBPath)
	if err != nil {
		t.Fatalf("list pruned block files: %v", err)
	}
	if len(fileNumbers) == 0 || fileNumbers[0] == 0 {
		t.Fatalf("block files were not physically pruned: %v", fileNumbers)
	}

	result := callLiveRPC(t, client, "getblockcount")
	var height int64
	if err := json.Unmarshal(result, &height); err != nil {
		t.Fatalf("decode pruned node height: %v", err)
	}
	if height <= 0 {
		t.Fatalf("pruned node has invalid height %d", height)
	}
}

func blockFileNumbers(blockDBPath string) ([]uint64, error) {
	paths, err := filepath.Glob(filepath.Join(blockDBPath, "*.fdb"))
	if err != nil {
		return nil, err
	}
	numbers := make([]uint64, 0, len(paths))
	for _, path := range paths {
		name := strings.TrimSuffix(filepath.Base(path), ".fdb")
		number, err := strconv.ParseUint(name, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("parse block file %s: %w", path, err)
		}
		numbers = append(numbers, number)
	}
	sort.Slice(numbers, func(i, j int) bool { return numbers[i] < numbers[j] })
	return numbers, nil
}

func assertConfiguredPruned(t *testing.T, client *liveRPCClient) {
	t.Helper()
	result := callLiveRPC(t, client, "getblockchaininfo")
	var info struct {
		Pruned bool `json:"pruned"`
	}
	if err := json.Unmarshal(result, &info); err != nil {
		t.Fatalf("decode pruned chain info: %v", err)
	}
	if !info.Pruned {
		t.Fatal("node did not report pruning enabled")
	}
}

func assertGenesisPruned(t *testing.T, client *liveRPCClient) {
	t.Helper()
	_, err := client.call(t.Context(), "getblock",
		chaincfg.RegressionNetParams.GenesisHash.String(), 0)
	if err == nil {
		t.Fatal("regtest genesis block remains available after physical prune")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "block not found") {
		t.Fatalf("get pruned regtest genesis: got %v, want block-not-found RPC error",
			err)
	}
}

func corruptLevelDBCurrent(t *testing.T, blockDBPath string) {
	t.Helper()
	currentPath := filepath.Join(blockDBPath, "metadata", "CURRENT")
	if _, err := os.Stat(currentPath); err != nil {
		t.Fatalf("locate metadata CURRENT file: %v", err)
	}
	if err := os.WriteFile(currentPath, []byte("CORRUPTED\n"), 0o600); err != nil {
		t.Fatalf("corrupt metadata CURRENT file: %v", err)
	}
}

func waitForProcessFailure(t *testing.T, process *liveProcess,
	timeout time.Duration) {

	t.Helper()
	if process.result == nil {
		t.Fatalf("%s was not started", process.name)
	}
	select {
	case <-process.result.done:
		if err := process.result.Err(); err == nil {
			t.Fatalf("%s exited successfully after database corruption",
				process.name)
		}
	case <-time.After(timeout):
		t.Fatalf("%s did not reject the corrupted database\n%s log:\n%s",
			process.name, process.name, process.logs.String())
	}
}
