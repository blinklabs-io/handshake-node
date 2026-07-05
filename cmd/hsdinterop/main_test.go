// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blinklabs-io/handshake-node/chaincfg"
)

const validRemoteKeyHex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

func TestNetworkParams(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantName string
		wantNet  uint32
	}{
		{
			name:     "mainnet",
			input:    "mainnet",
			wantName: "mainnet",
			wantNet:  uint32(chaincfg.MainNetParams.Net),
		},
		{
			name:     "mainnet mixed case",
			input:    "MaInNeT",
			wantName: "mainnet",
			wantNet:  uint32(chaincfg.MainNetParams.Net),
		},
		{
			name:     "regtest",
			input:    "regtest",
			wantName: "regtest",
			wantNet:  uint32(chaincfg.RegressionNetParams.Net),
		},
		{
			name:     "regtest surrounding spaces",
			input:    "  regtest\t",
			wantName: "regtest",
			wantNet:  uint32(chaincfg.RegressionNetParams.Net),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, gotName, err := networkParams(tc.input)
			if err != nil {
				t.Fatalf("networkParams: %v", err)
			}
			if gotName != tc.wantName {
				t.Fatalf("name: got %q, want %q", gotName, tc.wantName)
			}
			if uint32(got.Net) != tc.wantNet {
				t.Fatalf("net: got %#x, want %#x", uint32(got.Net), tc.wantNet)
			}
		})
	}
}

func TestNetworkParamsUnsupported(t *testing.T) {
	for _, network := range []string{"testnet", "simnet"} {
		t.Run(network, func(t *testing.T) {
			_, _, err := networkParams(network)
			if err == nil {
				t.Fatal("expected unsupported network error")
			}
			if !strings.Contains(err.Error(), "not available") {
				t.Fatalf("error: got %q", err)
			}
		})
	}
}

func TestParseConfigPlaintextDefaults(t *testing.T) {
	cfg, err := parseConfig([]string{"--addr", "127.0.0.1:12038"}, io.Discard)
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}

	if cfg.addr != "127.0.0.1:12038" {
		t.Fatalf("addr: got %q", cfg.addr)
	}
	if cfg.networkName != "mainnet" {
		t.Fatalf("network: got %q", cfg.networkName)
	}
	if cfg.chainParams != &chaincfg.MainNetParams {
		t.Fatalf("chain params: got %p, want %p", cfg.chainParams, &chaincfg.MainNetParams)
	}
	if cfg.timeout != defaultTimeout {
		t.Fatalf("timeout: got %s, want %s", cfg.timeout, defaultTimeout)
	}
	if cfg.transport != transportPlaintext {
		t.Fatalf("transport: got %q", cfg.transport)
	}
	if len(cfg.remoteKey) != 0 {
		t.Fatalf("remote key: got %x, want empty", cfg.remoteKey)
	}
	if cfg.identityKeyPath != "" {
		t.Fatalf("identity key path: got %q, want empty", cfg.identityKeyPath)
	}
	if cfg.height != 0 {
		t.Fatalf("height: got %d, want 0", cfg.height)
	}
	if cfg.noRelay {
		t.Fatal("noRelay: got true, want false")
	}
}

func TestParseConfigBrontide(t *testing.T) {
	args := []string{
		"--addr", "[::1]:14038",
		"--network", "regtest",
		"--timeout", "2s",
		"--transport", "brontide",
		"--remote-key", validRemoteKeyHex,
		"--identity-key", "/tmp/hsdinterop.key",
		"--height", "42",
		"--no-relay",
	}
	cfg, err := parseConfig(args, io.Discard)
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}

	wantKey, err := hex.DecodeString(validRemoteKeyHex)
	if err != nil {
		t.Fatalf("DecodeString: %v", err)
	}
	if cfg.addr != "[::1]:14038" {
		t.Fatalf("addr: got %q", cfg.addr)
	}
	if cfg.networkName != "regtest" {
		t.Fatalf("network: got %q", cfg.networkName)
	}
	if cfg.chainParams != &chaincfg.RegressionNetParams {
		t.Fatalf("chain params: got %p, want %p", cfg.chainParams, &chaincfg.RegressionNetParams)
	}
	if cfg.timeout != 2*time.Second {
		t.Fatalf("timeout: got %s", cfg.timeout)
	}
	if cfg.transport != transportBrontide {
		t.Fatalf("transport: got %q", cfg.transport)
	}
	if !bytes.Equal(cfg.remoteKey, wantKey) {
		t.Fatalf("remote key: got %x, want %x", cfg.remoteKey, wantKey)
	}
	if cfg.identityKeyPath != "/tmp/hsdinterop.key" {
		t.Fatalf("identity key path: got %q", cfg.identityKeyPath)
	}
	if cfg.height != 42 {
		t.Fatalf("height: got %d, want 42", cfg.height)
	}
	if !cfg.noRelay {
		t.Fatal("noRelay: got false, want true")
	}
}

func TestParseConfigBrontideDefaultIdentityPath(t *testing.T) {
	cfg, err := parseConfig([]string{
		"--addr", "127.0.0.1:12038",
		"--transport", "brontide",
		"--remote-key", validRemoteKeyHex,
	}, io.Discard)
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}

	configDir, err := os.UserConfigDir()
	if err != nil {
		t.Fatalf("UserConfigDir: %v", err)
	}
	want := filepath.Join(configDir, "hsdinterop", defaultIdentityKeyFile)
	if cfg.identityKeyPath != want {
		t.Fatalf("identity key path: got %q, want %q", cfg.identityKeyPath, want)
	}
}

func TestParseConfigRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "missing addr",
			args: nil,
			want: "addr is required",
		},
		{
			name: "bad addr",
			args: []string{"--addr", "127.0.0.1"},
			want: "host:port",
		},
		{
			name: "bad port",
			args: []string{"--addr", "127.0.0.1:http"},
			want: "numeric uint16",
		},
		{
			name: "zero timeout",
			args: []string{"--addr", "127.0.0.1:12038", "--timeout", "0s"},
			want: "timeout",
		},
		{
			name: "unknown network",
			args: []string{"--addr", "127.0.0.1:12038", "--network", "unknown"},
			want: "unknown network",
		},
		{
			name: "unsupported network",
			args: []string{"--addr", "127.0.0.1:12038", "--network", "testnet"},
			want: "not available",
		},
		{
			name: "unknown transport",
			args: []string{"--addr", "127.0.0.1:12038", "--transport", "noise"},
			want: "unknown transport",
		},
		{
			name: "brontide missing remote key",
			args: []string{"--addr", "127.0.0.1:12038", "--transport", "brontide"},
			want: "remote-key is required",
		},
		{
			name: "plaintext remote key",
			args: []string{"--addr", "127.0.0.1:12038", "--remote-key", validRemoteKeyHex},
			want: "remote-key requires",
		},
		{
			name: "plaintext identity key",
			args: []string{"--addr", "127.0.0.1:12038", "--identity-key", "/tmp/key"},
			want: "identity-key requires",
		},
		{
			name: "bad remote key",
			args: []string{
				"--addr", "127.0.0.1:12038",
				"--transport", "brontide",
				"--remote-key", "abcd",
			},
			want: "compressed secp256k1",
		},
		{
			name: "positional args",
			args: []string{"--addr", "127.0.0.1:12038", "extra"},
			want: "unexpected positional",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseConfig(tc.args, io.Discard)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error: got %q, want substring %q", err, tc.want)
			}
		})
	}
}

func TestRunParseFailure(t *testing.T) {
	var stderr bytes.Buffer
	code := run(nil, io.Discard, &stderr)
	if code != 1 {
		t.Fatalf("exit code: got %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "addr is required") {
		t.Fatalf("stderr: got %q", stderr.String())
	}
}

func TestRunHelp(t *testing.T) {
	var stderr bytes.Buffer
	code := run([]string{"--help"}, io.Discard, &stderr)
	if code != 0 {
		t.Fatalf("exit code: got %d, want 0", code)
	}
	output := stderr.String()
	if strings.Contains(output, "hsdinterop:") {
		t.Fatalf("stderr: got failure output %q", output)
	}
	if !strings.Contains(output, "Handshake network: mainnet|regtest") {
		t.Fatalf("stderr: missing supported network help in %q", output)
	}
	if strings.Contains(output, "testnet") || strings.Contains(output, "simnet") {
		t.Fatalf("stderr: advertised unsupported network in %q", output)
	}
}
