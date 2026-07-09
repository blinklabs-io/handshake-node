package main

import (
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"testing"
	"time"
)

var (
	rpcuserRegexp = regexp.MustCompile("(?m)^rpcuser=.+$")
	rpcpassRegexp = regexp.MustCompile("(?m)^rpcpass=.+$")
)

func TestCreateDefaultConfigFile(t *testing.T) {
	// find out where the sample config lives
	_, path, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("Failed finding config file path")
	}
	sampleConfigFile := filepath.Join(filepath.Dir(path), "sample-handshake-node.conf")

	// Setup a temporary directory
	tmpDir := t.TempDir()
	testpath := filepath.Join(tmpDir, "test.conf")

	// copy config file to location of handshake-node binary
	data, err := os.ReadFile(sampleConfigFile)
	if err != nil {
		t.Fatalf("Failed reading sample config file: %v", err)
	}
	appPath, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		t.Fatalf("Failed obtaining app path: %v", err)
	}
	tmpConfigFile := filepath.Join(appPath, "sample-handshake-node.conf")
	err = os.WriteFile(tmpConfigFile, data, 0644)
	if err != nil {
		t.Fatalf("Failed copying sample config file: %v", err)
	}

	err = createDefaultConfigFile(testpath)

	if err != nil {
		t.Fatalf("Failed to create a default config file: %v", err)
	}

	content, err := os.ReadFile(testpath)
	if err != nil {
		t.Fatalf("Failed to read generated default config file: %v", err)
	}

	if !rpcuserRegexp.Match(content) {
		t.Error("Could not find rpcuser in generated default config file.")
	}

	if !rpcpassRegexp.Match(content) {
		t.Error("Could not find rpcpass in generated default config file.")
	}
}

func TestDefaultRPCPorts(t *testing.T) {
	if mainNetParams.rpcPort != "12037" {
		t.Fatalf("mainnet RPC port: got %q, want %q",
			mainNetParams.rpcPort, "12037")
	}

	if regressionNetParams.rpcPort != "18334" {
		t.Fatalf("regtest RPC port: got %q, want %q",
			regressionNetParams.rpcPort, "18334")
	}
}

func TestApplyConfigEnvOverrides(t *testing.T) {
	cfg := config{
		RPCUser:      "fileuser",
		Generate:     false,
		BanDuration:  time.Second,
		AddPeers:     []string{"from-file"},
		BlockMaxSize: 1,
		Prune:        1,
		ConfigFile:   "from-file.conf",
	}
	env := map[string]string{
		"HANDSHAKE_NODE_RPCUSER":      "envuser",
		"HANDSHAKE_NODE_GENERATE":     "true",
		"HANDSHAKE_NODE_BANDURATION":  "2m",
		"HANDSHAKE_NODE_ADDPEER":      "127.0.0.1,127.0.0.2",
		"HANDSHAKE_NODE_BLOCKMAXSIZE": "010",
		"HANDSHAKE_NODE_PRUNE":        "010",
		"HANDSHAKE_NODE_CONFIGFILE":   "from-env.conf",
		"HANDSHAKE_NODE_VERSION":      "true",
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
	assumeValid := "0000000000000000000000000000000000000000000000000000000000000000"
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
