package main

import (
	"path/filepath"
	"testing"
)

func TestUpgradeDBPathsIgnoresMissingLegacyRoot(t *testing.T) {
	origCfg := cfg
	t.Cleanup(func() {
		cfg = origCfg
	})
	t.Setenv("HOME", t.TempDir())

	cfg = &config{
		DataDir: filepath.Join(t.TempDir(), "data", "mainnet"),
	}

	if err := upgradeDBPaths(); err != nil {
		t.Fatalf("upgradeDBPaths returned error for missing legacy db root: %v", err)
	}
}
