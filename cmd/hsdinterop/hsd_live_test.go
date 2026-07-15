// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

//go:build hsdinterop

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blinklabs-io/handshake-node/chaincfg"
)

const (
	pinnedHsdCommit = "9f013c1cb7f92edf94db69fbd69daf34adf655fb"
	hsdIdentityKey  = "0000000000000000000000000000000000000000000000000000000000000001"
	hsdPublicKey    = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	hsdPublicKeyB32 = "aj434zt67holxlcvubrjltuhbmdqfg743mw44kgzlhzicwyw7alzq"
)

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

type commandResult struct {
	done chan struct{}
	mu   sync.Mutex
	err  error
}

func newCommandResult(cmd *exec.Cmd) *commandResult {
	r := &commandResult{done: make(chan struct{})}
	go func() {
		err := cmd.Wait()
		r.mu.Lock()
		r.err = err
		r.mu.Unlock()
		close(r.done)
	}()
	return r
}

func (r *commandResult) Err() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
}

func TestPinnedHsdTransports(t *testing.T) {
	hsdDir := requirePinnedHsd(t)
	ports, releasePorts := reserveLoopbackPorts(t, 3)

	args := []string{
		filepath.Join(hsdDir, "bin", "hsd"),
		"--network=regtest",
		"--prefix=" + filepath.Join(t.TempDir(), "hsd"),
		"--workers=false",
		"--listen",
		"--host=127.0.0.1",
		fmt.Sprintf("--port=%d", ports[0]),
		fmt.Sprintf("--brontide-port=%d", ports[1]),
		"--http-host=127.0.0.1",
		fmt.Sprintf("--http-port=%d", ports[2]),
		"--no-auth",
		"--no-wallet",
		"--no-dns",
		"--log-console",
		"--log-level=debug",
		"--identity-key=" + hsdIdentityKey,
	}

	cmd := exec.Command("node", args...)
	var logs lockedBuffer
	cmd.Stdout = &logs
	cmd.Stderr = &logs

	releasePorts()
	if err := cmd.Start(); err != nil {
		t.Fatalf("start pinned hsd: %v", err)
	}
	result := newCommandResult(cmd)
	stop := func() {
		select {
		case <-result.done:
			return
		default:
		}

		_ = cmd.Process.Signal(os.Interrupt)
		select {
		case <-result.done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-result.done
		}
	}
	t.Cleanup(stop)

	waitForHsd(t, ports[2], result, &logs)

	tests := []struct {
		name      string
		transport transportMode
		port      int
	}{
		{name: "plaintext", transport: transportPlaintext, port: ports[0]},
		{name: "brontide", transport: transportBrontide, port: ports[1]},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config{
				addr:        fmt.Sprintf("127.0.0.1:%d", tc.port),
				networkName: "regtest",
				chainParams: &chaincfg.RegressionNetParams,
				timeout:     5 * time.Second,
				transport:   tc.transport,
			}
			if tc.transport == transportBrontide {
				cfg.remoteKey = mustDecodeHex(t, hsdPublicKey)
				cfg.identityKeyPath = filepath.Join(t.TempDir(), "client.key")
			}

			var stdout, stderr bytes.Buffer
			if err := execute(cfg, &stdout, &stderr); err != nil {
				t.Fatalf("execute: %v\nstderr:\n%s\nhsd log:\n%s",
					err, stderr.String(), logs.String())
			}
			if !strings.Contains(stdout.String(), `agent="/hsd:8.0.0/"`) {
				t.Fatalf("missing pinned hsd agent in output:\n%s", stdout.String())
			}
			if !strings.Contains(stdout.String(), "transport="+string(tc.transport)) {
				t.Fatalf("missing transport in output:\n%s", stdout.String())
			}
		})
	}

	stop()
	if err := result.Err(); err != nil {
		t.Fatalf("pinned hsd shutdown: %v\nhsd log:\n%s", err, logs.String())
	}
}

func requirePinnedHsd(t *testing.T) string {
	t.Helper()

	hsdDir := strings.TrimSpace(os.Getenv("HSD_DIR"))
	if hsdDir == "" {
		t.Fatal("HSD_DIR must point to an installed hsd v8.0.0 source checkout")
	}
	absDir, err := filepath.Abs(hsdDir)
	if err != nil {
		t.Fatalf("resolve HSD_DIR: %v", err)
	}
	for _, path := range []string{
		filepath.Join(absDir, "bin", "hsd"),
		filepath.Join(absDir, "node_modules"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("required pinned hsd path %s: %v", path, err)
		}
	}

	head, err := exec.Command("git", "-C", absDir, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatalf("read hsd commit: %v", err)
	}
	if got := strings.TrimSpace(string(head)); got != pinnedHsdCommit {
		t.Fatalf("hsd commit: got %s, want %s", got, pinnedHsdCommit)
	}
	if err := exec.Command("git", "-C", absDir, "diff", "--quiet", "HEAD", "--").Run(); err != nil {
		t.Fatalf("hsd checkout has modified tracked files: %v", err)
	}
	return absDir
}

func reserveLoopbackPorts(t *testing.T, count int) ([]int, func()) {
	t.Helper()

	listeners := make([]net.Listener, 0, count)
	ports := make([]int, 0, count)
	for range count {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			for _, openListener := range listeners {
				_ = openListener.Close()
			}
			t.Fatalf("reserve loopback port: %v", err)
		}
		listeners = append(listeners, listener)
		ports = append(ports, listener.Addr().(*net.TCPAddr).Port)
	}

	var once sync.Once
	release := func() {
		once.Do(func() {
			for _, listener := range listeners {
				_ = listener.Close()
			}
		})
	}
	t.Cleanup(release)
	return ports, release
}

func waitForHsd(t *testing.T, httpPort int, result *commandResult,
	logs *lockedBuffer) {

	t.Helper()
	client := &http.Client{Timeout: 500 * time.Millisecond}
	url := fmt.Sprintf("http://127.0.0.1:%d/", httpPort)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-result.done:
			t.Fatalf("pinned hsd exited before readiness: %v\nhsd log:\n%s",
				result.Err(), logs.String())
		default:
		}

		resp, err := client.Get(url)
		if err == nil {
			data, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			_ = resp.Body.Close()
			if readErr == nil && resp.StatusCode == http.StatusOK {
				var info struct {
					Version string `json:"version"`
					Network string `json:"network"`
					Pool    struct {
						IdentityKey string `json:"identitykey"`
					} `json:"pool"`
				}
				if json.Unmarshal(data, &info) == nil &&
					info.Version == "8.0.0" &&
					info.Network == "regtest" &&
					info.Pool.IdentityKey == hsdPublicKeyB32 {

					return
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("pinned hsd did not become ready at %s\nhsd log:\n%s", url, logs.String())
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := parseRemoteKey(value)
	if err != nil {
		t.Fatalf("parse remote key: %v", err)
	}
	return decoded
}
