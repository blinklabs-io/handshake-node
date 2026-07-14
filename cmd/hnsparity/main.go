// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// hnsparity performs a resumable, read-only comparison of handshake-node and
// the pinned hsd mainnet oracle. It intentionally does not start or stop either
// daemon; operators retain control of datadirs and restart testing.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	hsdVersion = "v8.0.0"
	hsdCommit  = "9f013c1cb7f92edf94db69fbd69daf34adf655fb"
)

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("value must not be empty")
	}
	*s = append(*s, value)
	return nil
}

type config struct {
	nodeURL        string
	hsdURL         string
	nodeUser       string
	nodePass       string
	hsdUser        string
	hsdPass        string
	network        string
	target         int64
	sampleEvery    int64
	statePath      string
	reportPath     string
	markdownPath   string
	poll           time.Duration
	requestTimeout time.Duration
	names          stringList
	outpoints      stringList
	restarts       stringList
}

type checkpoint struct {
	Schema       int    `json:"schema"`
	Network      string `json:"network"`
	TargetHeight int64  `json:"target_height"`
	TargetHash   string `json:"target_hash"`
	LastVerified int64  `json:"last_verified_height"`
	LastHash     string `json:"last_verified_hash"`
	StartedAt    string `json:"started_at"`
	UpdatedAt    string `json:"updated_at"`
}

type mismatch struct {
	Height int64  `json:"height,omitempty"`
	Check  string `json:"check"`
	Node   string `json:"node,omitempty"`
	HSD    string `json:"hsd,omitempty"`
}

type report struct {
	Schema             int        `json:"schema"`
	Status             string     `json:"status"`
	Network            string     `json:"network"`
	HSDPin             string     `json:"hsd_pin"`
	HSDCommit          string     `json:"hsd_commit"`
	NodeURL            string     `json:"node_url"`
	HSDURL             string     `json:"hsd_url"`
	NodeVersion        any        `json:"node_version,omitempty"`
	HSDVersionInfo     any        `json:"hsd_version_info,omitempty"`
	TargetHeight       int64      `json:"target_height"`
	TargetHash         string     `json:"target_hash"`
	FinalNodeHeight    int64      `json:"final_node_height"`
	FinalHSDHeight     int64      `json:"final_hsd_height"`
	FinalNodeError     string     `json:"final_node_error,omitempty"`
	FinalHSDError      string     `json:"final_hsd_error,omitempty"`
	DeploymentCheck    string     `json:"deployment_check"`
	LastVerifiedHeight int64      `json:"last_verified_height"`
	SampleInterval     int64      `json:"sample_interval"`
	StartedAt          string     `json:"started_at"`
	FinishedAt         string     `json:"finished_at"`
	Duration           string     `json:"duration"`
	ResumedFrom        int64      `json:"resumed_from"`
	RestartHistory     []string   `json:"restart_history"`
	Mismatches         []mismatch `json:"mismatches"`
}

type rpcClient struct {
	url, user, pass string
	http            *http.Client
}

type rpcResponse struct {
	Result json.RawMessage `json:"result"`
	Error  json.RawMessage `json:"error"`
}

var newHTTPClient = func(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout}
}

func (c *rpcClient) call(ctx context.Context, method string, params ...any) (json.RawMessage, error) {
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "1.0", "id": "hnsparity", "method": method, "params": params,
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.user != "" || c.pass != "" {
		req.SetBasicAuth(c.user, c.pass)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	var decoded rpcResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if len(decoded.Error) != 0 && string(decoded.Error) != "null" {
		return nil, fmt.Errorf("RPC error: %s", decoded.Error)
	}
	return decoded.Result, nil
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	cfg, err := parseConfig(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		_, _ = fmt.Fprintf(stderr, "hnsparity: %v\n", err)
		return 2
	}
	if err := execute(cfg, stdout); err != nil {
		_, _ = fmt.Fprintf(stderr, "hnsparity: %v\n", err)
		return 1
	}
	return 0
}

func parseConfig(args []string, output io.Writer) (*config, error) {
	fs := flag.NewFlagSet("hnsparity", flag.ContinueOnError)
	fs.SetOutput(output)
	cfg := &config{}
	fs.StringVar(&cfg.nodeURL, "node-url", env("HNSPARITY_NODE_URL", "http://127.0.0.1:12037"), "handshake-node RPC URL")
	fs.StringVar(&cfg.hsdURL, "hsd-url", env("HNSPARITY_HSD_URL", "http://127.0.0.1:13037"), "hsd RPC URL")
	fs.StringVar(&cfg.network, "network", "mainnet", "network name")
	fs.Int64Var(&cfg.target, "target", 0, "target height; 0 captures the hsd tip at startup")
	fs.Int64Var(&cfg.sampleEvery, "sample-interval", 1000, "interval for full block and state comparisons")
	fs.StringVar(&cfg.statePath, "state", "hnsparity-state.json", "resumable checkpoint path")
	fs.StringVar(&cfg.reportPath, "report", "hnsparity-report.json", "JSON report path")
	fs.StringVar(&cfg.markdownPath, "markdown", "hnsparity-report.md", "Markdown report path")
	fs.DurationVar(&cfg.poll, "poll", 10*time.Second, "node synchronization poll interval")
	fs.DurationVar(&cfg.requestTimeout, "request-timeout", 30*time.Second, "per-RPC timeout")
	fs.Var(&cfg.names, "name", "name to compare at sample heights (repeatable)")
	fs.Var(&cfg.outpoints, "outpoint", "txid:index to compare with gettxout (repeatable)")
	fs.Var(&cfg.restarts, "restart", "restart timestamp/note to include in the report (repeatable)")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() != 0 {
		return nil, fmt.Errorf("unexpected positional arguments: %s", strings.Join(fs.Args(), " "))
	}
	cfg.nodeUser, cfg.nodePass = os.Getenv("HNSPARITY_NODE_USER"), os.Getenv("HNSPARITY_NODE_PASS")
	cfg.hsdUser, cfg.hsdPass = os.Getenv("HNSPARITY_HSD_USER"), os.Getenv("HNSPARITY_HSD_PASS")
	if cfg.target < 0 || cfg.sampleEvery < 1 || cfg.poll <= 0 || cfg.requestTimeout <= 0 {
		return nil, errors.New("target, intervals, and timeouts must be positive")
	}
	if cfg.statePath == "" || cfg.reportPath == "" || cfg.markdownPath == "" {
		return nil, errors.New("state and report paths must not be empty")
	}
	if strings.TrimRight(cfg.nodeURL, "/") == strings.TrimRight(cfg.hsdURL, "/") {
		return nil, errors.New("node-url and hsd-url must identify different RPC endpoints")
	}
	return cfg, nil
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func execute(cfg *config, stdout io.Writer) error {
	started := time.Now().UTC()
	httpClient := newHTTPClient(cfg.requestTimeout)
	node := &rpcClient{url: cfg.nodeURL, user: cfg.nodeUser, pass: cfg.nodePass, http: httpClient}
	hsd := &rpcClient{url: cfg.hsdURL, user: cfg.hsdUser, pass: cfg.hsdPass, http: httpClient}
	ctx := context.Background()
	existing, stateErr := loadCheckpoint(cfg.statePath)
	if stateErr != nil && !errors.Is(stateErr, os.ErrNotExist) {
		return fmt.Errorf("load checkpoint: %w", stateErr)
	}
	hsdHeight, err := blockCount(ctx, hsd)
	if err != nil {
		return fmt.Errorf("read hsd tip: %w", err)
	}
	target := cfg.target
	if target == 0 && existing != nil {
		target = existing.TargetHeight
	} else if target == 0 {
		target = hsdHeight
	}
	if target > hsdHeight {
		return fmt.Errorf("target %d is above captured hsd tip %d", target, hsdHeight)
	}
	targetHash, err := blockHash(ctx, hsd, target)
	if err != nil {
		return fmt.Errorf("read hsd target hash: %w", err)
	}

	cp := checkpoint{Schema: 1, Network: cfg.network, TargetHeight: target, TargetHash: targetHash, LastVerified: -1, StartedAt: started.Format(time.RFC3339)}
	resumed := int64(-1)
	if existing != nil {
		if existing.Network != cfg.network || existing.TargetHeight != target || !equalHex(existing.TargetHash, targetHash) {
			return errors.New("checkpoint does not match network or captured target")
		}
		cp = *existing
		resumed = cp.LastVerified
		if cp.LastVerified >= 0 {
			nodeAnchor, nodeErr := blockHash(ctx, node, cp.LastVerified)
			hsdAnchor, hsdErr := blockHash(ctx, hsd, cp.LastVerified)
			if nodeErr != nil || hsdErr != nil || !equalHex(nodeAnchor, cp.LastHash) || !equalHex(hsdAnchor, cp.LastHash) {
				return fmt.Errorf("checkpoint anchor at height %d is no longer on both chains", cp.LastVerified)
			}
		}
	}

	rep := &report{Schema: 1, Status: "running", Network: cfg.network, HSDPin: hsdVersion, HSDCommit: hsdCommit, NodeURL: redactURL(cfg.nodeURL), HSDURL: redactURL(cfg.hsdURL), TargetHeight: target, TargetHash: targetHash, SampleInterval: cfg.sampleEvery, StartedAt: started.Format(time.RFC3339), ResumedFrom: resumed, LastVerifiedHeight: cp.LastVerified, RestartHistory: append([]string(nil), cfg.restarts...)}
	rep.NodeVersion = optionalCall(ctx, node, "getnetworkinfo")
	rep.HSDVersionInfo = optionalCall(ctx, hsd, "getnetworkinfo")

	for height := cp.LastVerified + 1; height <= target; height++ {
		for {
			nodeHeight, err := blockCount(ctx, node)
			if err == nil && nodeHeight >= height {
				break
			}
			_, _ = fmt.Fprintf(stdout, "waiting for handshake-node height=%d target=%d\n", nodeHeight, target)
			time.Sleep(cfg.poll)
		}
		if err := compareHeight(ctx, node, hsd, height, cfg, rep); err != nil {
			rep.Status = "failed"
			finishReport(rep, node, hsd, cp.LastVerified, started)
			_ = writeReports(cfg, rep)
			return err
		}
		verifiedHash, err := blockHash(ctx, node, height)
		if err != nil {
			return fmt.Errorf("re-read verified hash at height %d: %w", height, err)
		}
		cp.LastVerified, cp.LastHash, cp.UpdatedAt = height, verifiedHash, time.Now().UTC().Format(time.RFC3339)
		rep.LastVerifiedHeight = height
		if err := writeJSONAtomic(cfg.statePath, &cp); err != nil {
			return fmt.Errorf("write checkpoint: %w", err)
		}
		if height%1000 == 0 || height == target {
			_, _ = fmt.Fprintf(stdout, "verified height=%d target=%d\n", height, target)
		}
	}
	rep.Status = "pass"
	if err := compareTipDeployments(ctx, node, hsd, target, rep); err != nil {
		rep.Status = "failed"
		finishReport(rep, node, hsd, cp.LastVerified, started)
		_ = writeReports(cfg, rep)
		return err
	}
	finishReport(rep, node, hsd, cp.LastVerified, started)
	return writeReports(cfg, rep)
}

func compareHeight(ctx context.Context, node, hsd *rpcClient, height int64, cfg *config, rep *report) error {
	nh, err := blockHash(ctx, node, height)
	if err != nil {
		return err
	}
	hh, err := blockHash(ctx, hsd, height)
	if err != nil {
		return err
	}
	if !equalHex(nh, hh) {
		return addMismatch(rep, height, "block_hash", nh, hh)
	}
	nHeader, err := rpcString(ctx, node, "getblockheader", nh, false)
	if err != nil {
		return err
	}
	hHeader, err := rpcString(ctx, hsd, "getblockheader", hh, false)
	if err != nil {
		return err
	}
	if !equalHex(nHeader, hHeader) {
		return addMismatch(rep, height, "serialized_header", digest(nHeader), digest(hHeader))
	}
	if height%cfg.sampleEvery != 0 && height != cfg.target {
		return nil
	}
	nBlock, err := rpcString(ctx, node, "getblock", nh, 0)
	if err != nil {
		return err
	}
	// hsd uses separate verbose and transaction-detail booleans while
	// handshake-node exposes a Bitcoin-style numeric verbosity.
	hBlock, err := rpcString(ctx, hsd, "getblock", hh, false, false)
	if err != nil {
		return err
	}
	if !equalHex(nBlock, hBlock) {
		return addMismatch(rep, height, "serialized_block", digest(nBlock), digest(hBlock))
	}
	if err := compareSelected(ctx, node, hsd, height, "decoded_block", "getblock", []any{nh, 2}, []any{hh, true, true}, []string{"hash", "height", "version", "merkleroot", "witnessroot", "treeroot", "reservedroot", "time", "bits", "nonce", "tx", "rawtx"}, rep); err != nil {
		return err
	}
	for _, name := range cfg.names {
		if err := compareRaw(ctx, node, hsd, height, "name:"+name, "getnameinfo", rep, name); err != nil {
			return err
		}
	}
	for _, outpoint := range cfg.outpoints {
		parts := strings.Split(outpoint, ":")
		if len(parts) != 2 {
			return fmt.Errorf("invalid outpoint %q", outpoint)
		}
		index, err := strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			return fmt.Errorf("invalid outpoint %q", outpoint)
		}
		if err := compareRaw(ctx, node, hsd, height, "utxo:"+outpoint, "gettxout", rep, parts[0], index); err != nil {
			return err
		}
	}
	return nil
}

func compareTipDeployments(ctx context.Context, node, hsd *rpcClient, target int64, rep *report) error {
	nodeHeight, nodeErr := blockCount(ctx, node)
	hsdHeight, hsdErr := blockCount(ctx, hsd)
	if nodeErr != nil || hsdErr != nil || nodeHeight != target || hsdHeight != target {
		rep.DeploymentCheck = "not-run: endpoints are not both pinned to the captured target"
		return nil
	}
	nodeHash, err := blockHash(ctx, node, target)
	if err != nil {
		return err
	}
	hsdHash, err := blockHash(ctx, hsd, target)
	if err != nil {
		return err
	}
	if !equalHex(nodeHash, hsdHash) {
		return addMismatch(rep, target, "deployment_tip_hash", nodeHash, hsdHash)
	}
	if err := compareSelected(ctx, node, hsd, target, "deployments", "getblockchaininfo", nil, nil, []string{"chain", "softforks", "bip9_softforks"}, rep); err != nil {
		return err
	}
	rep.DeploymentCheck = "pass at captured target"
	return nil
}

func compareSelected(ctx context.Context, a, b *rpcClient, height int64, check, method string, aParams, bParams []any, keys []string, rep *report) error {
	ar, err := a.call(ctx, method, aParams...)
	if err != nil {
		return err
	}
	br, err := b.call(ctx, method, bParams...)
	if err != nil {
		return err
	}
	var am, bm map[string]any
	if json.Unmarshal(ar, &am) != nil || json.Unmarshal(br, &bm) != nil {
		return fmt.Errorf("%s returned a non-object", method)
	}
	selected := func(m map[string]any) map[string]any {
		result := make(map[string]any)
		for _, k := range keys {
			if v, ok := m[k]; ok {
				result[k] = v
			}
		}
		return result
	}
	aj, _ := json.Marshal(selected(am))
	bj, _ := json.Marshal(selected(bm))
	if !bytes.Equal(aj, bj) {
		return addMismatch(rep, height, check, digest(string(aj)), digest(string(bj)))
	}
	return nil
}

func compareRaw(ctx context.Context, a, b *rpcClient, height int64, check, method string, rep *report, params ...any) error {
	ar, err := a.call(ctx, method, params...)
	if err != nil {
		return err
	}
	br, err := b.call(ctx, method, params...)
	if err != nil {
		return err
	}
	var av, bv any
	if err := json.Unmarshal(ar, &av); err != nil {
		return fmt.Errorf("decode handshake-node %s result: %w", method, err)
	}
	if err := json.Unmarshal(br, &bv); err != nil {
		return fmt.Errorf("decode hsd %s result: %w", method, err)
	}
	aj, _ := json.Marshal(av)
	bj, _ := json.Marshal(bv)
	if !bytes.Equal(aj, bj) {
		return addMismatch(rep, height, check, digest(string(aj)), digest(string(bj)))
	}
	return nil
}

func addMismatch(rep *report, height int64, check, node, hsd string) error {
	rep.Mismatches = append(rep.Mismatches, mismatch{Height: height, Check: check, Node: node, HSD: hsd})
	return fmt.Errorf("parity mismatch at height %d (%s)", height, check)
}
func blockCount(ctx context.Context, c *rpcClient) (int64, error) {
	raw, err := c.call(ctx, "getblockcount")
	if err != nil {
		return 0, err
	}
	var n int64
	err = json.Unmarshal(raw, &n)
	return n, err
}
func blockHash(ctx context.Context, c *rpcClient, h int64) (string, error) {
	return rpcString(ctx, c, "getblockhash", h)
}
func rpcString(ctx context.Context, c *rpcClient, method string, params ...any) (string, error) {
	raw, err := c.call(ctx, method, params...)
	if err != nil {
		return "", fmt.Errorf("%s: %w", method, err)
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", err
	}
	return value, nil
}
func optionalCall(ctx context.Context, c *rpcClient, method string) any {
	raw, err := c.call(ctx, method)
	if err != nil {
		return map[string]string{"error": err.Error()}
	}
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return nil
	}
	return value
}
func equalHex(a, b string) bool { return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b)) }
func digest(value string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(value))))
	return fmt.Sprintf("sha256:%x", sum[:])
}
func redactURL(value string) string {
	if at := strings.LastIndex(value, "@"); at >= 0 {
		if scheme := strings.Index(value, "://"); scheme >= 0 {
			return value[:scheme+3] + value[at+1:]
		}
	}
	return value
}

func loadCheckpoint(path string) (*checkpoint, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cp checkpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		return nil, err
	}
	return &cp, nil
}
func writeJSONAtomic(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
func finishReport(rep *report, node, hsd *rpcClient, last int64, started time.Time) {
	rep.LastVerifiedHeight = last
	var err error
	rep.FinalNodeHeight, err = blockCount(context.Background(), node)
	if err != nil {
		rep.FinalNodeError = err.Error()
	}
	rep.FinalHSDHeight, err = blockCount(context.Background(), hsd)
	if err != nil {
		rep.FinalHSDError = err.Error()
	}
	now := time.Now().UTC()
	rep.FinishedAt, rep.Duration = now.Format(time.RFC3339), now.Sub(started).Round(time.Millisecond).String()
}
func writeReports(cfg *config, rep *report) error {
	if err := writeJSONAtomic(cfg.reportPath, rep); err != nil {
		return err
	}
	return writeMarkdown(cfg.markdownPath, rep)
}
func writeMarkdown(path string, rep *report) error {
	var b strings.Builder
	_, _ = fmt.Fprintf(&b, "# Handshake mainnet parity report\n\n- Status: **%s**\n- Network: `%s`\n- hsd oracle: `%s` (`%s`)\n- Target: `%d` (`%s`)\n- Last verified: `%d`\n- Deployment check: `%s`\n- Duration: `%s`\n- Started: `%s`\n- Finished: `%s`\n- Resumed from: `%d`\n- Mismatches: `%d`\n", rep.Status, rep.Network, rep.HSDPin, rep.HSDCommit, rep.TargetHeight, rep.TargetHash, rep.LastVerifiedHeight, rep.DeploymentCheck, rep.Duration, rep.StartedAt, rep.FinishedAt, rep.ResumedFrom, len(rep.Mismatches))
	if rep.FinalNodeError != "" || rep.FinalHSDError != "" {
		_, _ = fmt.Fprintf(&b, "- Final handshake-node height error: `%s`\n- Final hsd height error: `%s`\n", rep.FinalNodeError, rep.FinalHSDError)
	}
	if len(rep.Mismatches) > 0 {
		b.WriteString("\n## Mismatches\n\n| Height | Check | Node | hsd |\n|---:|---|---|---|\n")
		for _, m := range rep.Mismatches {
			_, _ = fmt.Fprintf(&b, "| %d | %s | `%s` | `%s` |\n", m.Height, m.Check, m.Node, m.HSD)
		}
	}
	if len(rep.RestartHistory) > 0 {
		b.WriteString("\n## Restart history\n\n")
		for _, restart := range rep.RestartHistory {
			_, _ = fmt.Fprintf(&b, "- %s\n", restart)
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return err
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}
