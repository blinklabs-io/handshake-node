// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParityRunAndResume(t *testing.T) {
	var requestedHeights []int64
	originalFactory := newHTTPClient
	t.Cleanup(func() { newHTTPClient = originalFactory })
	newHTTPClient = func(_ time.Duration) *http.Client {
		return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			var req struct {
				Method string `json:"method"`
				Params []any  `json:"params"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				return nil, err
			}
			var result any
			switch req.Method {
			case "getblockcount":
				result = int64(2)
			case "getblockhash":
				height := int64(req.Params[0].(float64))
				requestedHeights = append(requestedHeights, height)
				result = fmt.Sprintf("%064x", height+1)
			case "getblockheader":
				result = strings.Repeat("ab", 236)
			case "getblock":
				isRaw := req.Params[1] == false
				if number, ok := req.Params[1].(float64); ok && number == 0 {
					isRaw = true
				}
				if isRaw {
					result = "deadbeef"
				} else {
					result = map[string]any{"hash": req.Params[0], "height": 2, "version": 0, "merkleroot": "aa", "time": 1, "bits": "207fffff", "nonce": 0}
				}
			case "getblockchaininfo":
				result = map[string]any{"chain": "mainnet", "bip9_softforks": map[string]any{"hardening": map[string]any{"status": "active"}}}
			case "getnetworkinfo":
				result = map[string]any{"version": 1}
			default:
				return nil, fmt.Errorf("unexpected RPC method %s", req.Method)
			}
			var body bytes.Buffer
			_ = json.NewEncoder(&body).Encode(map[string]any{"result": result, "error": nil, "id": "hnsparity"})
			return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header), Body: io.NopCloser(&body)}, nil
		})}
	}

	dir := t.TempDir()
	state := filepath.Join(dir, "state.json")
	reportPath := filepath.Join(dir, "report.json")
	markdown := filepath.Join(dir, "report.md")
	args := []string{"--node-url", "http://node.invalid", "--hsd-url", "http://hsd.invalid", "--target", "2", "--sample-interval", "1", "--state", state, "--report", reportPath, "--markdown", markdown}
	if code := run(args, os.Stdout, os.Stderr); code != 0 {
		t.Fatalf("run returned %d", code)
	}
	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	var got report
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Status != "pass" || got.LastVerifiedHeight != 2 || got.HSDCommit != hsdCommit {
		t.Fatalf("unexpected report: %+v", got)
	}
	if _, err := os.Stat(markdown); err != nil {
		t.Fatal(err)
	}

	requestedHeights = nil
	if code := run(args, os.Stdout, os.Stderr); code != 0 {
		t.Fatalf("resume returned %d", code)
	}
	for _, height := range requestedHeights {
		if height < 2 {
			t.Fatalf("resume repeated completed height %d", height)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRedactURL(t *testing.T) {
	got := redactURL("https://secret-user:secret-pass@example.com:1234/rpc")
	if got != "https://example.com:1234/rpc" {
		t.Fatalf("redactURL = %q", got)
	}
}

func TestParseConfigDoesNotExposeCredentials(t *testing.T) {
	t.Setenv("HNSPARITY_NODE_USER", "alice")
	t.Setenv("HNSPARITY_NODE_PASS", "secret")
	cfg, err := parseConfig([]string{"--target", "1"}, os.Stderr)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.nodeUser != "alice" || cfg.nodePass != "secret" {
		t.Fatal("credentials not loaded from environment")
	}
}
