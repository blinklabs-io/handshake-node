// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

//go:build hsdinterop

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blinklabs-io/handshake-node/chaincfg"
	"github.com/blinklabs-io/handshake-node/wire"
)

const (
	malformedMiningAddress = "rs1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqn6kda"
	malformedRPCUser       = "hsd-malformed"
	malformedRPCPass       = "hsd-malformed-password"
)

type malformedRPCClient struct {
	url  string
	user string
	pass string
	http *http.Client
}

type malformedRPCResponse struct {
	Result json.RawMessage `json:"result"`
	Error  json.RawMessage `json:"error"`
}

func (c *malformedRPCClient) call(ctx context.Context, method string,
	params ...any) (json.RawMessage, error) {

	body, err := json.Marshal(map[string]any{
		"jsonrpc": "1.0",
		"id":      "hsd-malformed",
		"method":  method,
		"params":  params,
	})
	if err != nil {
		return nil, fmt.Errorf("encode %s request: %w", method, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url,
		bytes.NewReader(body))
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

	var decoded malformedRPCResponse
	if err := json.Unmarshal(responseBody, &decoded); err != nil {
		return nil, fmt.Errorf("decode %s response: %w", method, err)
	}
	if len(decoded.Error) != 0 && string(decoded.Error) != "null" {
		return nil, fmt.Errorf("%s RPC error: %s", method, decoded.Error)
	}
	return decoded.Result, nil
}

func (c *malformedRPCClient) closeIdleConnections() {
	c.http.CloseIdleConnections()
}

type malformedProcess struct {
	name   string
	logs   lockedBuffer
	cmd    *exec.Cmd
	result *commandResult
}

func (p *malformedProcess) start(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	if p.result != nil {
		t.Fatalf("%s is already running", p.name)
	}

	p.cmd = cmd
	p.cmd.Stdout = &p.logs
	p.cmd.Stderr = &p.logs
	if err := p.cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", p.name, err)
	}
	p.result = newCommandResult(p.cmd)
}

func (p *malformedProcess) stop(t *testing.T, force bool) {
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

func (p *malformedProcess) runningError() error {
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

func TestPinnedHsdMalformedPeerRecovery(t *testing.T) {
	hsdDir := requirePinnedHsd(t)
	ports, releasePorts := reserveLoopbackPorts(t, 5)
	hsdP2PPort, hsdBrontidePort, hsdHTTPPort := ports[0], ports[1], ports[2]
	nodeP2PPort, nodeRPCPort := ports[3], ports[4]

	testDir := t.TempDir()
	nodeBinary := buildMalformedTestNode(t, testDir)
	hsd := &malformedProcess{name: "pinned hsd"}
	node := &malformedProcess{name: "handshake-node"}
	t.Cleanup(func() {
		node.stop(t, true)
		hsd.stop(t, true)
	})

	hsdArgs := []string{
		filepath.Join(hsdDir, "bin", "hsd"),
		"--network=regtest",
		"--prefix=" + filepath.Join(testDir, "hsd"),
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
		"--coinbase-address=" + malformedMiningAddress,
		"--identity-key=" + hsdIdentityKey,
	}
	nodeArgs := []string{
		"--regtest",
		"--datadir=" + filepath.Join(testDir, "handshake-node-data"),
		"--logdir=" + filepath.Join(testDir, "handshake-node-logs"),
		fmt.Sprintf("--listen=127.0.0.1:%d", nodeP2PPort),
		fmt.Sprintf("--rpclisten=127.0.0.1:%d", nodeRPCPort),
		"--rpcuser=" + malformedRPCUser,
		"--rpcpass=" + malformedRPCPass,
		"--notls",
		fmt.Sprintf("--connect=127.0.0.1:%d", hsdP2PPort),
		"--debuglevel=debug",
	}

	releasePorts()
	hsd.start(t, exec.Command("node", hsdArgs...))

	hsdRPC := &malformedRPCClient{
		url:  fmt.Sprintf("http://127.0.0.1:%d/", hsdHTTPPort),
		http: &http.Client{Timeout: 2 * time.Second},
	}
	nodeRPC := &malformedRPCClient{
		url:  fmt.Sprintf("http://127.0.0.1:%d/", nodeRPCPort),
		user: malformedRPCUser,
		pass: malformedRPCPass,
		http: &http.Client{Timeout: 2 * time.Second},
	}
	t.Cleanup(hsdRPC.closeIdleConnections)
	t.Cleanup(nodeRPC.closeIdleConnections)

	waitForMalformedRPC(t, hsdRPC, hsd, 15*time.Second)
	node.start(t, exec.Command(nodeBinary, nodeArgs...))
	waitForMalformedRPC(t, nodeRPC, node, 30*time.Second)
	waitForMalformedHealthyPeer(t, nodeRPC, node, 20*time.Second)

	firstHash := generateMalformedTestBlock(t, hsdRPC)
	waitForMalformedTip(t, nodeRPC, node, 1, firstHash, 20*time.Second)

	t.Run("unknown future packet preserves stream", func(t *testing.T) {
		conn := openMalformedTestPeer(t, nodeP2PPort)
		defer func() { _ = conn.Close() }()
		negotiateMalformedTestPeer(t, conn)

		writeMalformedFrame(t, conn, uint32(chaincfg.RegressionNetParams.Net),
			wire.HnsMsgType(255), []byte{0x01, 0x02, 0x03})

		var nonce [8]byte
		binary.LittleEndian.PutUint64(nonce[:], 0x0123456789abcdef)
		if err := wire.WriteHnsMessage(conn, &wire.HnsMsgPing{Nonce: nonce},
			chaincfg.RegressionNetParams.Net); err != nil {

			t.Fatalf("write ping after unknown packet: %v", err)
		}
		waitForMalformedPong(t, conn, nonce)
	})
	waitForMalformedHealthyPeer(t, nodeRPC, node, 10*time.Second)

	invalidVersion := malformedTestVersion().Encode()
	invalidVersion[len(invalidVersion)-1] = 2
	testCases := []struct {
		name   string
		attack func(*testing.T, net.Conn)
	}{
		{
			name: "invalid version payload",
			attack: func(t *testing.T, conn net.Conn) {
				writeMalformedFrame(t, conn,
					uint32(chaincfg.RegressionNetParams.Net),
					wire.HnsMsgTypeVersion, invalidVersion)
			},
		},
		{
			name: "type-specific oversized version",
			attack: func(t *testing.T, conn net.Conn) {
				writeMalformedFrame(t, conn,
					uint32(chaincfg.RegressionNetParams.Net),
					wire.HnsMsgTypeVersion, make([]byte, 1024))
			},
		},
		{
			name: "global oversized header",
			attack: func(t *testing.T, conn net.Conn) {
				writeMalformedHeader(t, conn,
					uint32(chaincfg.RegressionNetParams.Net),
					wire.HnsMsgTypeVersion,
					wire.HnsMaxMessagePayload+1)
			},
		},
		{
			name: "truncated version payload",
			attack: func(t *testing.T, conn net.Conn) {
				payload := malformedTestVersion().Encode()
				writeMalformedHeader(t, conn,
					uint32(chaincfg.RegressionNetParams.Net),
					wire.HnsMsgTypeVersion, uint32(len(payload)))
				writeMalformedBytes(t, conn, payload[:10])
				closeMalformedWrite(t, conn)
			},
		},
		{
			name: "post-handshake malformed ping",
			attack: func(t *testing.T, conn net.Conn) {
				negotiateMalformedTestPeer(t, conn)
				writeMalformedFrame(t, conn,
					uint32(chaincfg.RegressionNetParams.Net),
					wire.HnsMsgTypePing, make([]byte, 7))
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			conn := openMalformedTestPeer(t, nodeP2PPort)
			defer func() { _ = conn.Close() }()
			testCase.attack(t, conn)
			waitForMalformedDisconnect(t, conn)
		})
		waitForMalformedHealthyPeer(t, nodeRPC, node, 10*time.Second)
	}

	secondHash := generateMalformedTestBlock(t, hsdRPC)
	waitForMalformedTip(t, nodeRPC, node, 2, secondHash, 20*time.Second)

	node.stop(t, false)
	hsd.stop(t, false)
}

func buildMalformedTestNode(t *testing.T, outputDir string) string {
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

func waitForMalformedRPC(t *testing.T, client *malformedRPCClient,
	process *malformedProcess, timeout time.Duration) {

	t.Helper()
	waitForMalformedCondition(t, process, timeout, "RPC readiness",
		func() (bool, error) {
			_, err := client.call(context.Background(), "getblockcount")
			return err == nil, err
		})
}

func waitForMalformedHealthyPeer(t *testing.T, client *malformedRPCClient,
	process *malformedProcess, timeout time.Duration) {

	t.Helper()
	waitForMalformedCondition(t, process, timeout, "sole healthy hsd peer",
		func() (bool, error) {
			result, err := client.call(context.Background(), "getpeerinfo")
			if err != nil {
				return false, err
			}
			var peers []struct {
				SubVer  string `json:"subver"`
				Inbound bool   `json:"inbound"`
				Version uint32 `json:"version"`
			}
			if err := json.Unmarshal(result, &peers); err != nil {
				return false, err
			}
			if len(peers) != 1 {
				return false, nil
			}
			peer := peers[0]
			return !peer.Inbound &&
				peer.Version == wire.HnsProtocolVersion &&
				strings.Contains(peer.SubVer, "/hsd:8.0.0/"), nil
		})
}

func generateMalformedTestBlock(t *testing.T,
	client *malformedRPCClient) string {

	t.Helper()
	result := callMalformedRPC(t, client, "generate", 1)
	var hashes []string
	if err := json.Unmarshal(result, &hashes); err != nil {
		t.Fatalf("decode generated hsd block hashes: %v", err)
	}
	if len(hashes) != 1 {
		t.Fatalf("generated hsd block count: got %d, want 1", len(hashes))
	}
	return hashes[0]
}

func waitForMalformedTip(t *testing.T, client *malformedRPCClient,
	process *malformedProcess, wantHeight int64, wantHash string,
	timeout time.Duration) {

	t.Helper()
	waitForMalformedCondition(t, process, timeout,
		fmt.Sprintf("tip %d:%s", wantHeight, wantHash),
		func() (bool, error) {
			heightResult, err := client.call(context.Background(),
				"getblockcount")
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

			hashResult, err := client.call(context.Background(),
				"getblockhash", wantHeight)
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

func waitForMalformedCondition(t *testing.T, process *malformedProcess,
	timeout time.Duration, description string,
	condition func() (bool, error)) {

	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if err := process.runningError(); err != nil {
			t.Fatalf("waiting for %s: %v\n%s log:\n%s",
				description, err, process.name, process.logs.String())
		}

		ok, err := condition()
		if err != nil {
			lastErr = err
		} else if ok {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}

	if lastErr != nil {
		t.Fatalf("timed out waiting for %s: %v\n%s log:\n%s",
			description, lastErr, process.name, process.logs.String())
	}
	t.Fatalf("timed out waiting for %s\n%s log:\n%s",
		description, process.name, process.logs.String())
}

func callMalformedRPC(t *testing.T, client *malformedRPCClient,
	method string, params ...any) json.RawMessage {

	t.Helper()
	result, err := client.call(context.Background(), method, params...)
	if err != nil {
		t.Fatalf("%s: %v", method, err)
	}
	return result
}

func openMalformedTestPeer(t *testing.T, port int) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp4",
		fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if err != nil {
		t.Fatalf("connect malformed test peer: %v", err)
	}
	return conn
}

func malformedTestVersion() *wire.HnsMsgVersion {
	msg := &wire.HnsMsgVersion{
		Version:  wire.HnsProtocolVersion,
		Services: uint64(wire.SFNodeNetwork),
		Time:     uint64(time.Now().Unix()), //nolint:gosec
		Remote: wire.HnsNetAddress{
			Host: net.ParseIP("127.0.0.1"),
		},
		Agent: "/hsd-malformed-test:1.0.0/",
	}
	msg.SetNonce(uint64(time.Now().UnixNano())) //nolint:gosec
	return msg
}

func negotiateMalformedTestPeer(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set malformed peer handshake deadline: %v", err)
	}
	if err := wire.WriteHnsMessage(conn, malformedTestVersion(),
		chaincfg.RegressionNetParams.Net); err != nil {

		t.Fatalf("write malformed peer version: %v", err)
	}

	gotVersion := false
	gotVerack := false
	sentVerack := false
	for !gotVersion || !gotVerack {
		msg, _, err := wire.ReadHnsMessage(conn,
			chaincfg.RegressionNetParams.Net)
		if err != nil {
			t.Fatalf("read malformed peer handshake: %v", err)
		}
		switch msg.(type) {
		case *wire.HnsMsgVersion:
			gotVersion = true
			if !sentVerack {
				if err := wire.WriteHnsMessage(conn, &wire.HnsMsgVerack{},
					chaincfg.RegressionNetParams.Net); err != nil {

					t.Fatalf("write malformed peer verack: %v", err)
				}
				sentVerack = true
			}
		case *wire.HnsMsgVerack:
			gotVerack = true
		}
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		t.Fatalf("clear malformed peer handshake deadline: %v", err)
	}
}

func waitForMalformedPong(t *testing.T, conn net.Conn, want [8]byte) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set malformed peer pong deadline: %v", err)
	}
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	for {
		msg, _, err := wire.ReadHnsMessage(conn,
			chaincfg.RegressionNetParams.Net)
		if err != nil {
			t.Fatalf("read pong after unknown packet: %v", err)
		}
		pong, ok := msg.(*wire.HnsMsgPong)
		if !ok {
			continue
		}
		if pong.Nonce != want {
			t.Fatalf("pong nonce: got %x, want %x", pong.Nonce, want)
		}
		return
	}
}

func writeMalformedFrame(t *testing.T, conn net.Conn, magic uint32,
	msgType wire.HnsMsgType, payload []byte) {

	t.Helper()
	writeMalformedHeader(t, conn, magic, msgType, uint32(len(payload)))
	writeMalformedBytes(t, conn, payload)
}

func writeMalformedHeader(t *testing.T, conn net.Conn, magic uint32,
	msgType wire.HnsMsgType, payloadLength uint32) {

	t.Helper()
	header := make([]byte, wire.HnsMessageHeaderSize)
	binary.LittleEndian.PutUint32(header[0:4], magic)
	header[4] = byte(msgType)
	binary.LittleEndian.PutUint32(header[5:9], payloadLength)
	writeMalformedBytes(t, conn, header)
}

func writeMalformedBytes(t *testing.T, conn net.Conn, data []byte) {
	t.Helper()
	if _, err := io.Copy(conn, bytes.NewReader(data)); err != nil {
		t.Fatalf("write malformed peer bytes: %v", err)
	}
}

func closeMalformedWrite(t *testing.T, conn net.Conn) {
	t.Helper()
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		t.Fatalf("malformed peer connection type: got %T, want *net.TCPConn",
			conn)
	}
	if err := tcpConn.CloseWrite(); err != nil {
		t.Fatalf("close malformed peer write side: %v", err)
	}
}

func waitForMalformedDisconnect(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set malformed peer disconnect deadline: %v", err)
	}

	var buf [1024]byte
	for {
		_, err := conn.Read(buf[:])
		if err == nil {
			continue
		}
		if errors.Is(err, io.EOF) {
			return
		}
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			t.Fatal("node did not disconnect malformed peer")
		}
		return
	}
}
