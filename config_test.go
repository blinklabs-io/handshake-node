// Copyright (c) 2024-2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/blinklabs-io/handshake-node/mempool"
	"github.com/blinklabs-io/handshake-node/wire"
)

func TestDefaultRPCPorts(t *testing.T) {
	if mainNetParams.rpcPort != "12037" {
		t.Fatalf("mainnet RPC port: got %q, want %q",
			mainNetParams.rpcPort, "12037")
	}

	if regressionNetParams.rpcPort != "14037" {
		t.Fatalf("regtest RPC port: got %q, want %q",
			regressionNetParams.rpcPort, "14037")
	}

	if defaultMetricsPort != "12039" {
		t.Fatalf("metrics port: got %q, want %q",
			defaultMetricsPort, "12039")
	}

	if defaultStratumPort != "12040" {
		t.Fatalf("stratum port: got %q, want %q",
			defaultStratumPort, "12040")
	}
}

func TestLoadConfigWithoutFile(t *testing.T) {
	const helperEnv = "HANDSHAKE_NODE_TEST_CONFIG_DEFAULTS"

	if os.Getenv(helperEnv) == "1" {
		os.Args = []string{"handshake-node"}
		setConfigTestDefaultPaths(os.Getenv("HOME"))

		cfg, remainingArgs, err := loadConfig()
		if err != nil {
			t.Fatalf("loadConfig: %v", err)
		}
		if len(remainingArgs) != 0 {
			t.Fatalf("remaining arguments: got %v, want none",
				remainingArgs)
		}
		if activeNetParams.Net != wire.MainNet {
			t.Fatalf("network: got %v, want mainnet",
				activeNetParams.Net)
		}
		if cfg.Prune != 0 {
			t.Fatalf("prune: got %d, want archival mode", cfg.Prune)
		}
		if cfg.DisableDNSSeed {
			t.Fatal("DNS peer discovery is disabled")
		}
		if cfg.DisableCheckpoints {
			t.Fatal("built-in checkpoints are disabled")
		}
		if !cfg.BrontideTransport {
			t.Fatal("Brontide transport is disabled")
		}
		if cfg.MaxMempoolSize != mempool.DefaultMaxMempoolSize {
			t.Fatalf("max mempool size: got %d, want %d",
				cfg.MaxMempoolSize, mempool.DefaultMaxMempoolSize)
		}
		if cfg.MempoolExpiry != mempool.DefaultMempoolExpiry {
			t.Fatalf("mempool expiry: got %v, want %v",
				cfg.MempoolExpiry, mempool.DefaultMempoolExpiry)
		}
		if !cfg.DisableRPC {
			t.Fatal("RPC is enabled without credentials")
		}
		wantListener := net.JoinHostPort("", mainNetParams.DefaultPort)
		if !slices.Equal(cfg.Listeners, []string{wantListener}) {
			t.Fatalf("listeners: got %v, want [%s]",
				cfg.Listeners, wantListener)
		}
		if _, err := os.Stat(defaultConfigFile); !os.IsNotExist(err) {
			t.Fatalf("default config stat: got %v, want not-exist",
				err)
		}
		return
	}

	tempDir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestLoadConfigWithoutFile$")
	cmd.Env = configTestEnvironment(tempDir, helperEnv+"=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("configurationless startup: %v\n%s", err, output)
	}
	if strings.Contains(strings.ToLower(string(output)), "config file") {
		t.Fatalf("configurationless startup reported a config-file error:\n%s",
			output)
	}
}

func TestLoadConfigRejectsInvalidMempoolLimits(t *testing.T) {
	const helperEnv = "HANDSHAKE_NODE_TEST_INVALID_MEMPOOL_LIMIT"

	mode := os.Getenv(helperEnv)
	if mode != "" {
		setConfigTestDefaultPaths(os.Getenv("HOME"))
		switch mode {
		case "size":
			os.Args = []string{"handshake-node", "--maxmempoolsize=0"}
		case "expiry":
			os.Args = []string{"handshake-node", "--mempoolexpiry=0s"}
		default:
			t.Fatalf("unknown helper mode %q", mode)
		}

		_, _, err := loadConfig()
		if err == nil {
			t.Fatalf("loadConfig accepted invalid mempool %s", mode)
		}
		if !strings.Contains(err.Error(), "must be greater than 0") {
			t.Fatalf("loadConfig error = %q, want positive-limit error", err)
		}
		return
	}

	for _, mode := range []string{"size", "expiry"} {
		t.Run(mode, func(t *testing.T) {
			tempDir := t.TempDir()
			cmd := exec.Command(
				os.Args[0],
				"-test.run=^TestLoadConfigRejectsInvalidMempoolLimits$",
			)
			cmd.Env = configTestEnvironment(
				tempDir,
				helperEnv+"="+mode,
			)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("invalid mempool %s: %v\n%s",
					mode, err, output)
			}
		})
	}
}

func TestLoadConfigRejectsMissingExplicitFile(t *testing.T) {
	const helperEnv = "HANDSHAKE_NODE_TEST_MISSING_CONFIG"

	if os.Getenv(helperEnv) == "1" {
		homeDir := os.Getenv("HOME")
		setConfigTestDefaultPaths(homeDir)
		missingPath := filepath.Join(homeDir, "missing.conf")
		os.Args = []string{
			"handshake-node",
			"--configfile=" + missingPath,
		}

		_, _, err := loadConfig()
		if !os.IsNotExist(err) {
			t.Fatalf("loadConfig error: got %v, want not-exist", err)
		}
		return
	}

	tempDir := t.TempDir()
	cmd := exec.Command(os.Args[0],
		"-test.run=^TestLoadConfigRejectsMissingExplicitFile$")
	cmd.Env = configTestEnvironment(tempDir, helperEnv+"=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("missing explicit config: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "Error loading config file:") {
		t.Fatalf("missing explicit config did not report a clear error:\n%s",
			output)
	}
}

func TestLoadConfigRejectsRegtestPersistWithoutRegtest(t *testing.T) {
	const helperEnv = "HANDSHAKE_NODE_TEST_REGTEST_PERSIST"

	if os.Getenv(helperEnv) == "1" {
		setConfigTestDefaultPaths(os.Getenv("HOME"))
		os.Args = []string{"handshake-node", "--regtestpersist"}

		_, _, err := loadConfig()
		if err == nil ||
			!strings.Contains(err.Error(), "--regtestpersist requires --regtest") {

			t.Fatalf("loadConfig error: got %v, want regtest requirement", err)
		}
		return
	}

	tempDir := t.TempDir()
	cmd := exec.Command(os.Args[0],
		"-test.run=^TestLoadConfigRejectsRegtestPersistWithoutRegtest$")
	cmd.Env = configTestEnvironment(tempDir, helperEnv+"=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("regtest persistence validation: %v\n%s", err, output)
	}
}

func TestLoadConfigDefaultFile(t *testing.T) {
	const helperEnv = "HANDSHAKE_NODE_TEST_DEFAULT_CONFIG_FILE"

	mode := os.Getenv(helperEnv)
	if mode != "" {
		setConfigTestDefaultPaths(os.Getenv("HOME"))
		if err := os.MkdirAll(defaultHomeDir, 0700); err != nil {
			t.Fatalf("create default home: %v", err)
		}

		var configContents string
		switch mode {
		case "valid":
			configContents = "[Application Options]\nmaxpeers=17\n"
		case "malformed":
			configContents = "[Application Options\n"
		default:
			t.Fatalf("unknown helper mode %q", mode)
		}
		if err := os.WriteFile(
			defaultConfigFile,
			[]byte(configContents),
			0600,
		); err != nil {
			t.Fatalf("write default config: %v", err)
		}

		os.Args = []string{"handshake-node"}
		cfg, remainingArgs, err := loadConfig()
		if mode == "malformed" {
			if err == nil {
				t.Fatal("loadConfig accepted malformed default config")
			}
			return
		}
		if err != nil {
			t.Fatalf("loadConfig: %v", err)
		}
		if len(remainingArgs) != 0 {
			t.Fatalf("remaining arguments: got %v, want none",
				remainingArgs)
		}
		if cfg.MaxPeers != 17 {
			t.Fatalf("max peers: got %d, want 17", cfg.MaxPeers)
		}
		return
	}

	for _, test := range []struct {
		name        string
		mode        string
		wantMessage string
	}{
		{
			name: "valid",
			mode: "valid",
		},
		{
			name:        "malformed",
			mode:        "malformed",
			wantMessage: "Error parsing config file:",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			tempDir := t.TempDir()
			cmd := exec.Command(
				os.Args[0],
				"-test.run=^TestLoadConfigDefaultFile$",
			)
			cmd.Env = configTestEnvironment(
				tempDir,
				helperEnv+"="+test.mode,
			)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("default config %s: %v\n%s",
					test.mode, err, output)
			}
			if test.wantMessage != "" &&
				!strings.Contains(string(output), test.wantMessage) {

				t.Fatalf(
					"default config %s did not report %q:\n%s",
					test.mode,
					test.wantMessage,
					output,
				)
			}
		})
	}
}

func setConfigTestDefaultPaths(homeDir string) {
	defaultHomeDir = filepath.Join(homeDir, ".handshake-node")
	defaultConfigFile = filepath.Join(defaultHomeDir, defaultConfigFilename)
	defaultDataDir = filepath.Join(defaultHomeDir, defaultDataDirname)
	defaultRPCKeyFile = filepath.Join(defaultHomeDir, "rpc.key")
	defaultRPCCertFile = filepath.Join(defaultHomeDir, "rpc.cert")
	defaultLogDir = filepath.Join(defaultHomeDir, defaultLogDirname)
}

func configTestEnvironment(homeDir string, extra ...string) []string {
	env := make([]string, 0, len(os.Environ())+len(extra)+4)
	for _, item := range os.Environ() {
		if strings.HasPrefix(item, "HANDSHAKE_NODE_") ||
			strings.HasPrefix(item, "HOME=") ||
			strings.HasPrefix(item, "USERPROFILE=") ||
			strings.HasPrefix(item, "LOCALAPPDATA=") ||
			strings.HasPrefix(item, "APPDATA=") {

			continue
		}
		env = append(env, item)
	}
	env = append(env,
		"HOME="+homeDir,
		"USERPROFILE="+homeDir,
		"LOCALAPPDATA="+homeDir,
		"APPDATA="+homeDir,
	)
	return append(env, extra...)
}

func TestApplyConfigEnvOverrides(t *testing.T) {
	cfg := config{
		RPCUser:             "fileuser",
		Generate:            false,
		BanDuration:         time.Second,
		AddPeers:            []string{"from-file"},
		BlockMaxSize:        1,
		MaxProofRPS:         100,
		MaxInboundPerIP:     8,
		MaxOutboundQueueMiB: 128,
		MaxMempoolSize:      100_000_000,
		MempoolExpiry:       72 * time.Hour,
		P2PWriteTimeout:     2 * time.Minute,
		Prune:               1,
		ConfigFile:          "from-file.conf",
	}
	env := map[string]string{
		"HANDSHAKE_NODE_RPCUSER":             "envuser",
		"HANDSHAKE_NODE_GENERATE":            "true",
		"HANDSHAKE_NODE_BANDURATION":         "2m",
		"HANDSHAKE_NODE_ADDPEER":             "127.0.0.1,127.0.0.2",
		"HANDSHAKE_NODE_BLOCKMAXSIZE":        "010",
		"HANDSHAKE_NODE_MAXPROOFRPS":         "25",
		"HANDSHAKE_NODE_MAXINBOUNDPERIP":     "12",
		"HANDSHAKE_NODE_MAXOUTBOUNDQUEUEMIB": "256",
		"HANDSHAKE_NODE_MAXMEMPOOLSIZE":      "50000000",
		"HANDSHAKE_NODE_MEMPOOLEXPIRY":       "24h",
		"HANDSHAKE_NODE_P2PWRITETIMEOUT":     "7m",
		"HANDSHAKE_NODE_PRUNE":               "010",
		"HANDSHAKE_NODE_CONFIGFILE":          "from-env.conf",
		"HANDSHAKE_NODE_VERSION":             "true",
	}
	lookup := func(key string) (string, bool) {
		value, ok := env[key]
		return value, ok
	}

	if err := applyConfigEnvOverrides(&cfg, lookup); err != nil {
		t.Fatalf("applyConfigEnvOverrides: %v", err)
	}

	if cfg.RPCUser != "envuser" {
		t.Fatalf("RPCUser: got %q, want %q", cfg.RPCUser, "envuser")
	}
	if !cfg.Generate {
		t.Fatalf("Generate: got false, want true")
	}
	if cfg.BanDuration != 2*time.Minute {
		t.Fatalf("BanDuration: got %v, want %v", cfg.BanDuration,
			2*time.Minute)
	}
	if got, want := cfg.AddPeers, []string{"127.0.0.1", "127.0.0.2"}; !slices.Equal(got, want) {
		t.Fatalf("AddPeers: got %v, want %v", got, want)
	}
	if cfg.BlockMaxSize != 10 {
		t.Fatalf("BlockMaxSize: got %d, want %d", cfg.BlockMaxSize,
			10)
	}
	if cfg.MaxProofRPS != 25 {
		t.Fatalf("MaxProofRPS: got %d, want %d", cfg.MaxProofRPS, 25)
	}
	if cfg.MaxInboundPerIP != 12 {
		t.Fatalf("MaxInboundPerIP: got %d, want %d", cfg.MaxInboundPerIP, 12)
	}
	if cfg.MaxOutboundQueueMiB != 256 {
		t.Fatalf("MaxOutboundQueueMiB: got %d, want %d",
			cfg.MaxOutboundQueueMiB, 256)
	}
	if cfg.MaxMempoolSize != 50_000_000 {
		t.Fatalf("MaxMempoolSize: got %d, want %d",
			cfg.MaxMempoolSize, uint64(50_000_000))
	}
	if cfg.MempoolExpiry != 24*time.Hour {
		t.Fatalf("MempoolExpiry: got %v, want %v",
			cfg.MempoolExpiry, 24*time.Hour)
	}
	if cfg.P2PWriteTimeout != 7*time.Minute {
		t.Fatalf("P2PWriteTimeout: got %v, want %v",
			cfg.P2PWriteTimeout, 7*time.Minute)
	}
	if cfg.Prune != 10 {
		t.Fatalf("Prune: got %d, want %d", cfg.Prune, uint64(10))
	}
	if cfg.ConfigFile != "from-file.conf" {
		t.Fatalf("ConfigFile: got %q, want %q", cfg.ConfigFile,
			"from-file.conf")
	}
	if cfg.ShowVersion {
		t.Fatalf("ShowVersion: got true, want false")
	}
}

func TestParseIPNets(t *testing.T) {
	nets, err := parseIPNets([]string{"127.0.0.1", "10.0.0.0/8"},
		"rpcallowip")
	if err != nil {
		t.Fatalf("parseIPNets: %v", err)
	}
	if len(nets) != 2 {
		t.Fatalf("parseIPNets len: got %d, want %d", len(nets), 2)
	}
	if !nets[0].Contains(net.ParseIP("127.0.0.1")) {
		t.Fatalf("single-IP net does not contain 127.0.0.1")
	}
	if !nets[1].Contains(net.ParseIP("10.1.2.3")) {
		t.Fatalf("CIDR net does not contain 10.1.2.3")
	}

	if _, err := parseIPNets([]string{"not-an-ip"}, "rpcallowip"); err == nil {
		t.Fatalf("parseIPNets accepted invalid IP")
	}
}

func TestParseAssumeValid(t *testing.T) {
	assumeValid := "5b6ef2d3c1f3cdcadfd9a030ba1811efdd17740f14e166489760741d075992e0"
	hash, err := parseAssumeValid(assumeValid)
	if err != nil {
		t.Fatalf("parseAssumeValid: %v", err)
	}
	if hash == nil {
		t.Fatalf("parseAssumeValid returned nil hash")
	}
	if hash.String() != assumeValid {
		t.Fatalf("parseAssumeValid hash: got %q, want %q",
			hash.String(), assumeValid)
	}

	hash, err = parseAssumeValid("")
	if err != nil {
		t.Fatalf("parseAssumeValid empty: %v", err)
	}
	if hash != nil {
		t.Fatalf("parseAssumeValid empty: got %v, want nil", hash)
	}

	if _, err := parseAssumeValid("not-a-hash"); err == nil {
		t.Fatalf("parseAssumeValid malformed hash unexpectedly succeeded")
	}
}

func TestParseCheckpointHashOrder(t *testing.T) {
	const (
		checkpoint = "1008:0000000000001013c28fa079b545fb805f04c496687799b98e35e83cbbb8953e"
		wantHash   = "0000000000001013c28fa079b545fb805f04c496687799b98e35e83cbbb8953e"
	)

	got, err := newCheckpointFromStr(checkpoint)
	if err != nil {
		t.Fatalf("newCheckpointFromStr: %v", err)
	}
	if got.Height != 1008 {
		t.Fatalf("checkpoint height: got %d, want %d", got.Height, 1008)
	}
	if got.Hash.String() != wantHash {
		t.Fatalf("checkpoint hash: got %q, want %q", got.Hash.String(), wantHash)
	}
}
