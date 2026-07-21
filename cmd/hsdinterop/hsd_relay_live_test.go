// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

//go:build hsdinterop

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	hsdRegtestMiningAddress = "rs1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqn6kda"
	hsdShortForkAddress     = "rs1qjjpnmnrzfvxgqlqf5j48j50jmq9pyqjz0a7ytz"
	hsdLongForkAddress      = "rs1q4rvs9pp9496qawp2zyqpz3s90fjfk362q92vq8"
	interopRPCUser          = "hsd-interop"
	interopRPCPass          = "hsd-interop-password"
)

type liveRPCClient struct {
	url  string
	user string
	pass string
	http *http.Client
}

type liveRPCResponse struct {
	Result json.RawMessage `json:"result"`
	Error  json.RawMessage `json:"error"`
}

func (c *liveRPCClient) call(ctx context.Context, method string,
	params ...any) (json.RawMessage, error) {

	requestBody, err := json.Marshal(map[string]any{
		"jsonrpc": "1.0",
		"id":      "hsd-interop",
		"method":  method,
		"params":  params,
	})
	if err != nil {
		return nil, fmt.Errorf("encode %s request: %w", method, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url,
		bytes.NewReader(requestBody))
	if err != nil {
		return nil, fmt.Errorf("create %s request: %w", method, err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.user != "" || c.pass != "" {
		req.SetBasicAuth(c.user, c.pass)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s request: %w", method, err)
	}
	defer func() { _ = resp.Body.Close() }()

	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("read %s response: %w", method, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned HTTP %s: %s", method,
			resp.Status, strings.TrimSpace(string(responseBody)))
	}

	var decoded liveRPCResponse
	if err := json.Unmarshal(responseBody, &decoded); err != nil {
		return nil, fmt.Errorf("decode %s response: %w", method, err)
	}
	if len(decoded.Error) != 0 && string(decoded.Error) != "null" {
		return nil, fmt.Errorf("%s RPC error: %s", method, decoded.Error)
	}
	return decoded.Result, nil
}

func (c *liveRPCClient) closeIdleConnections() {
	c.http.CloseIdleConnections()
}

type liveProcess struct {
	name   string
	logs   lockedBuffer
	cmd    *exec.Cmd
	result *commandResult
}

func (p *liveProcess) start(t *testing.T, command func() *exec.Cmd) {
	t.Helper()
	if p.result != nil {
		t.Fatalf("%s is already running", p.name)
	}

	p.cmd = command()
	p.cmd.Stdout = &p.logs
	p.cmd.Stderr = &p.logs
	if err := p.cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", p.name, err)
	}
	p.result = newCommandResult(p.cmd)
}

func (p *liveProcess) stop(t *testing.T, force bool) {
	t.Helper()
	if p.result == nil {
		return
	}

	result := p.result
	cmd := p.cmd
	defer func() {
		p.result = nil
		p.cmd = nil
	}()

	select {
	case <-result.done:
		if err := result.Err(); err != nil && !force {
			t.Fatalf("%s exited unexpectedly: %v\n%s log:\n%s",
				p.name, err, p.name, p.logs.String())
		}
		return
	default:
	}

	if force {
		if err := cmd.Process.Kill(); err != nil &&
			!errors.Is(err, os.ErrProcessDone) {

			t.Fatalf("kill %s: %v", p.name, err)
		}
		<-result.done
		return
	}

	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatalf("interrupt %s: %v", p.name, err)
	}
	select {
	case <-result.done:
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		<-result.done
		t.Fatalf("%s did not stop after interrupt\n%s log:\n%s",
			p.name, p.name, p.logs.String())
	}
	if err := result.Err(); err != nil {
		t.Fatalf("%s shutdown: %v\n%s log:\n%s",
			p.name, err, p.name, p.logs.String())
	}
}

func (p *liveProcess) runningError() error {
	if p.result == nil {
		return fmt.Errorf("%s is not running", p.name)
	}
	select {
	case <-p.result.done:
		if err := p.result.Err(); err != nil {
			return fmt.Errorf("%s exited: %w", p.name, err)
		}
		return fmt.Errorf("%s exited", p.name)
	default:
		return nil
	}
}

func TestPinnedHsdRelayReorgAndRecovery(t *testing.T) {
	const (
		commonBlockCount = 3
		reorgDepth       = 32
		longBranchCount  = reorgDepth + 1
	)

	commonHeight := int64(commonBlockCount)
	shortTipHeight := commonHeight + reorgDepth
	longTipHeight := commonHeight + longBranchCount

	hsdDir := requirePinnedHsd(t)
	ports, releasePorts := reserveLoopbackPorts(t, 4)
	hsdP2PPort, hsdBrontidePort := ports[0], ports[1]
	hsdHTTPPort, nodeRPCPort := ports[2], ports[3]

	testDir := t.TempDir()
	hsdPrefix := filepath.Join(testDir, "hsd")
	nodeDataDir := filepath.Join(testDir, "handshake-node-data")
	nodeLogDir := filepath.Join(testDir, "handshake-node-logs")
	nodeBinary := buildHandshakeNode(t, testDir)

	hsd := &liveProcess{name: "pinned hsd"}
	node := &liveProcess{name: "handshake-node"}
	t.Cleanup(func() {
		node.stop(t, true)
		hsd.stop(t, true)
	})

	hsdCommand := func() *exec.Cmd {
		args := []string{
			filepath.Join(hsdDir, "bin", "hsd"),
			"--network=regtest",
			"--prefix=" + hsdPrefix,
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
			"--coinbase-address=" + hsdRegtestMiningAddress,
			"--identity-key=" + hsdIdentityKey,
		}
		return exec.Command("node", args...)
	}
	nodeCommand := func() *exec.Cmd {
		args := []string{
			"--regtest",
			"--datadir=" + nodeDataDir,
			"--logdir=" + nodeLogDir,
			fmt.Sprintf("--rpclisten=127.0.0.1:%d", nodeRPCPort),
			"--rpcuser=" + interopRPCUser,
			"--rpcpass=" + interopRPCPass,
			"--notls",
			fmt.Sprintf("--connect=127.0.0.1:%d", hsdP2PPort),
			"--debuglevel=debug",
		}
		return exec.Command(nodeBinary, args...)
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

	common := generateHsdBlocks(t, hsdRPC, commonBlockCount)
	waitForMatchingTip(t, nodeRPC, node, commonHeight,
		common[len(common)-1],
		20*time.Second)
	assertBlockHashes(t, nodeRPC, 1, common)

	shortBranch := generateHsdBlocksToAddress(t, hsdRPC, reorgDepth,
		hsdShortForkAddress)
	shortTip := shortBranch[len(shortBranch)-1]
	waitForMatchingTip(t, nodeRPC, node, shortTipHeight, shortTip,
		30*time.Second)
	assertBlockHashes(t, nodeRPC, commonHeight+1, shortBranch)

	callLiveRPC(t, hsdRPC, "invalidateblock", shortBranch[0])
	waitForMatchingTip(t, hsdRPC, hsd, commonHeight,
		common[len(common)-1],
		5*time.Second)

	longBranch := generateHsdBlocksToAddress(t, hsdRPC, longBranchCount,
		hsdLongForkAddress)
	longTip := longBranch[len(longBranch)-1]
	if strings.EqualFold(shortBranch[0], longBranch[0]) {
		t.Fatal("hsd competing branches did not diverge")
	}
	waitForMatchingTip(t, nodeRPC, node, longTipHeight, longTip,
		45*time.Second)
	assertBlockHashes(t, nodeRPC, commonHeight+1, longBranch)
	assertNodeChainTips(t, nodeRPC, longTip, longTipHeight, shortTip,
		shortTipHeight, reorgDepth)

	node.stop(t, false)
	nodeRPC.closeIdleConnections()
	node.start(t, nodeCommand)
	waitForLiveRPC(t, nodeRPC, node, 30*time.Second)
	waitForPeerCount(t, nodeRPC, node, 1, 15*time.Second)
	waitForMatchingTip(t, nodeRPC, node, longTipHeight, longTip,
		10*time.Second)
	assertBlockHashes(t, nodeRPC, commonHeight+1, longBranch)

	afterCleanRestart := generateHsdBlocks(t, hsdRPC, 1)
	afterCleanHeight := longTipHeight + 1
	waitForMatchingTip(t, nodeRPC, node, afterCleanHeight,
		afterCleanRestart[0],
		20*time.Second)
	assertBlockHashes(t, nodeRPC, afterCleanHeight, afterCleanRestart)

	node.stop(t, true)
	nodeRPC.closeIdleConnections()
	node.start(t, nodeCommand)
	waitForLiveRPC(t, nodeRPC, node, 30*time.Second)
	waitForPeerCount(t, nodeRPC, node, 1, 15*time.Second)
	waitForMatchingTip(t, nodeRPC, node, afterCleanHeight,
		afterCleanRestart[0],
		10*time.Second)
	assertBlockHashes(t, nodeRPC, afterCleanHeight, afterCleanRestart)

	afterForcedRestart := generateHsdBlocks(t, hsdRPC, 1)
	afterForcedHeight := afterCleanHeight + 1
	waitForMatchingTip(t, nodeRPC, node, afterForcedHeight,
		afterForcedRestart[0],
		20*time.Second)
	assertBlockHashes(t, nodeRPC, afterForcedHeight, afterForcedRestart)

	node.stop(t, false)
	hsd.stop(t, false)
}

func buildHandshakeNode(t *testing.T, outputDir string) string {
	t.Helper()

	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	binary := filepath.Join(outputDir, "handshake-node")
	cmd := exec.Command("go", "build", "-trimpath", "-o", binary, ".")
	cmd.Dir = repoRoot
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build handshake-node: %v\n%s", err, output)
	}
	return binary
}

func waitForLiveRPC(t *testing.T, client *liveRPCClient,
	process *liveProcess, timeout time.Duration) {

	t.Helper()
	waitForCondition(t, process, timeout, "RPC readiness",
		func(ctx context.Context) (bool, error) {
			_, err := client.call(ctx, "getblockcount")
			return err == nil, err
		})
}

func waitForPeerCount(t *testing.T, client *liveRPCClient,
	process *liveProcess, want int, timeout time.Duration) {

	t.Helper()
	waitForCondition(t, process, timeout,
		fmt.Sprintf("%d connected peer(s)", want),
		func(ctx context.Context) (bool, error) {
			result, err := client.call(ctx, "getpeerinfo")
			if err != nil {
				return false, err
			}
			var peers []json.RawMessage
			if err := json.Unmarshal(result, &peers); err != nil {
				return false, err
			}
			return len(peers) == want, nil
		})
}

func generateHsdBlocks(t *testing.T, client *liveRPCClient,
	count int) []string {

	t.Helper()
	result := callLiveRPC(t, client, "generate", count)
	return decodeGeneratedHashes(t, result, count)
}

func generateHsdBlocksToAddress(t *testing.T, client *liveRPCClient,
	count int, address string) []string {

	t.Helper()
	result := callLiveRPC(t, client, "generatetoaddress", count, address)
	return decodeGeneratedHashes(t, result, count)
}

func decodeGeneratedHashes(t *testing.T, result json.RawMessage,
	count int) []string {

	t.Helper()
	var hashes []string
	if err := json.Unmarshal(result, &hashes); err != nil {
		t.Fatalf("decode generated hsd block hashes: %v", err)
	}
	if len(hashes) != count {
		t.Fatalf("generated hsd block count: got %d, want %d",
			len(hashes), count)
	}
	return hashes
}

func assertBlockHashes(t *testing.T, client *liveRPCClient,
	startHeight int64, want []string) {

	t.Helper()
	for i, wantHash := range want {
		height := startHeight + int64(i)
		result := callLiveRPC(t, client, "getblockhash", height)
		var gotHash string
		if err := json.Unmarshal(result, &gotHash); err != nil {
			t.Fatalf("decode node block hash at height %d: %v", height, err)
		}
		if !strings.EqualFold(gotHash, wantHash) {
			t.Fatalf("node block hash at height %d: got %s, want %s",
				height, gotHash, wantHash)
		}
	}
}

func callLiveRPC(t *testing.T, client *liveRPCClient, method string,
	params ...any) json.RawMessage {

	t.Helper()
	result, err := client.call(t.Context(), method, params...)
	if err != nil {
		t.Fatalf("%s: %v", method, err)
	}
	return result
}

func waitForMatchingTip(t *testing.T, client *liveRPCClient,
	process *liveProcess, wantHeight int64, wantHash string,
	timeout time.Duration) {

	t.Helper()
	waitForCondition(t, process, timeout,
		fmt.Sprintf("tip %d:%s", wantHeight, wantHash),
		func(ctx context.Context) (bool, error) {
			heightResult, err := client.call(ctx, "getblockcount")
			if err != nil {
				return false, err
			}
			var height int64
			if err := json.Unmarshal(heightResult, &height); err != nil {
				return false, err
			}
			if height != wantHeight {
				return false, nil
			}

			hashResult, err := client.call(ctx, "getblockhash", wantHeight)
			if err != nil {
				return false, err
			}
			var hash string
			if err := json.Unmarshal(hashResult, &hash); err != nil {
				return false, err
			}
			return strings.EqualFold(hash, wantHash), nil
		})
}

func waitForCondition(t *testing.T, process *liveProcess,
	timeout time.Duration, description string,
	condition func(context.Context) (bool, error)) {

	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()
	poll := time.NewTicker(50 * time.Millisecond)
	defer poll.Stop()

	var lastErr error
	for {
		if err := process.runningError(); err != nil {
			t.Fatalf("waiting for %s: %v\n%s log:\n%s",
				description, err, process.name, process.logs.String())
		}

		ok, err := condition(ctx)
		if err != nil {
			ctxErr := ctx.Err()
			if lastErr == nil || ctxErr == nil || !errors.Is(err, ctxErr) {
				lastErr = err
			}
		} else {
			lastErr = nil
			if ok {
				return
			}
		}

		select {
		case <-ctx.Done():
			if lastErr != nil {
				t.Fatalf("timed out waiting for %s: %v\n%s log:\n%s",
					description, lastErr, process.name,
					process.logs.String())
			}
			t.Fatalf("timed out waiting for %s\n%s log:\n%s",
				description, process.name, process.logs.String())
		case <-poll.C:
		}
	}
}

func assertNodeChainTips(t *testing.T, client *liveRPCClient,
	activeHash string, activeHeight int64, forkHash string, forkHeight,
	forkBranchLen int64) {

	t.Helper()
	result := callLiveRPC(t, client, "getchaintips")
	var tips []struct {
		Hash      string `json:"hash"`
		Height    int64  `json:"height"`
		BranchLen int64  `json:"branchlen"`
		Status    string `json:"status"`
	}
	if err := json.Unmarshal(result, &tips); err != nil {
		t.Fatalf("decode node chain tips: %v", err)
	}

	var active, fork bool
	for _, tip := range tips {
		switch {
		case strings.EqualFold(tip.Hash, activeHash):
			active = tip.Status == "active" &&
				tip.Height == activeHeight &&
				tip.BranchLen == 0
		case strings.EqualFold(tip.Hash, forkHash):
			fork = tip.Status == "valid-fork" &&
				tip.Height == forkHeight &&
				tip.BranchLen == forkBranchLen
		}
	}
	if !active || !fork {
		t.Fatalf("unexpected node chain tips after reorg: %+v", tips)
	}
}
