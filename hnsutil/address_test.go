// Copyright (c) 2013-2017 The btcsuite developers
// Copyright (c) 2024-2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package hnsutil_test

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/blinklabs-io/handshake-node/chaincfg"
	"github.com/blinklabs-io/handshake-node/hnsutil"
)

// mainNetParamsWithHRP returns a copy of the mainnet params with the
// Handshake "hs" HRP patched in.  Phase 1.5 will flip the real
// chaincfg.MainNetParams to use "hs"; in the meantime this test fixture
// lets us verify the address encoder/decoder against the final HRPs.
func mainNetParamsWithHRP(t *testing.T, hrp string) *chaincfg.Params {
	t.Helper()
	params := chaincfg.MainNetParams
	params.Bech32HRPSegwit = hrp
	return &params
}

// TestAddressRoundTrip exercises NewAddress, EncodeAddress, and
// DecodeAddress across a spread of valid versions and hash lengths.
func TestAddressRoundTrip(t *testing.T) {
	params := mainNetParamsWithHRP(t, "hs")

	tests := []struct {
		name    string
		version uint8
		hashHex string
	}{
		{
			name:    "v0 pubkey hash (all zeros)",
			version: 0,
			hashHex: "0000000000000000000000000000000000000000",
		},
		{
			name:    "v0 pubkey hash (hsd test vector)",
			version: 0,
			hashHex: "6d5571fdbca1019cd0f0cd792d1b0bdfa7651c7e",
		},
		{
			name:    "v0 script hash (32 bytes)",
			version: 0,
			hashHex: "0101010101010101010101010101010101010101010101010101010101010101",
		},
		{
			name:    "v1 minimum length",
			version: 1,
			hashHex: "0102",
		},
		{
			name:    "v2 odd length",
			version: 2,
			hashHex: "deadbeefcafe",
		},
		{
			name:    "v31 maximum length",
			version: 31,
			// 40 bytes (the maximum hash length allowed by the
			// Handshake address format).
			hashHex: "000102030405060708090a0b0c0d0e0f" +
				"101112131415161718191a1b1c1d1e1f" +
				"2021222324252627",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			hash, err := hex.DecodeString(test.hashHex)
			if err != nil {
				t.Fatalf("decode hash: %v", err)
			}

			addr, err := hnsutil.NewAddress(test.version, hash, params)
			if err != nil {
				t.Fatalf("NewAddress(version=%d, hash=%x): %v",
					test.version, hash, err)
			}

			encoded := addr.EncodeAddress()
			if !strings.HasPrefix(encoded, "hs1") {
				t.Errorf("encoded address %q missing hs1 prefix",
					encoded)
			}
			if encoded != strings.ToLower(encoded) {
				t.Errorf("encoded address %q is not lowercase",
					encoded)
			}

			decoded, err := hnsutil.DecodeAddress(encoded, params)
			if err != nil {
				t.Fatalf("DecodeAddress(%q): %v", encoded, err)
			}

			if decoded.Version() != test.version {
				t.Errorf("decoded version = %d, want %d",
					decoded.Version(), test.version)
			}
			if !bytes.Equal(decoded.Hash(), hash) {
				t.Errorf("decoded hash = %x, want %x",
					decoded.Hash(), hash)
			}
			if decoded.HRP() != "hs" {
				t.Errorf("decoded hrp = %q, want %q",
					decoded.HRP(), "hs")
			}
			if !decoded.IsForNet(params) {
				t.Error("decoded IsForNet(mainnet) = false")
			}
			if decoded.EncodeAddress() != encoded {
				t.Errorf("decoded re-encoded = %q, want %q",
					decoded.EncodeAddress(), encoded)
			}
			if !hnsutil.AddressEqual(decoded, addr) {
				t.Error("decoded address not Equal to original")
			}
		})
	}
}

// TestAddressKnownVector verifies the single concrete string-to-hash
// mapping we sourced from hsd's own address tests.
func TestAddressKnownVector(t *testing.T) {
	params := mainNetParamsWithHRP(t, "hs")

	const (
		knownHashHex = "6d5571fdbca1019cd0f0cd792d1b0bdfa7651c7e"
		knownAddr    = "hs1qd42hrldu5yqee58se4uj6xctm7nk28r70e84vx"
	)

	hash, err := hex.DecodeString(knownHashHex)
	if err != nil {
		t.Fatalf("decode hash: %v", err)
	}

	addr, err := hnsutil.NewAddressPubKeyHash(hash, params)
	if err != nil {
		t.Fatalf("NewAddressPubKeyHash: %v", err)
	}

	got := addr.EncodeAddress()
	if got != knownAddr {
		t.Fatalf("encoded address = %q, want %q", got, knownAddr)
	}

	decoded, err := hnsutil.DecodeAddress(knownAddr, params)
	if err != nil {
		t.Fatalf("DecodeAddress(%q): %v", knownAddr, err)
	}
	if decoded.Version() != 0 {
		t.Errorf("decoded version = %d, want 0", decoded.Version())
	}
	if !bytes.Equal(decoded.Hash(), hash) {
		t.Errorf("decoded hash = %x, want %x", decoded.Hash(), hash)
	}
}

// TestAddressHRPPerNetwork makes sure the decoder rejects addresses whose
// HRP does not match the caller-requested network.
func TestAddressHRPPerNetwork(t *testing.T) {
	mainParams := mainNetParamsWithHRP(t, "hs")
	regtestParams := mainNetParamsWithHRP(t, "rs")

	hash := bytes.Repeat([]byte{0x42}, 20)

	mainAddr, err := hnsutil.NewAddressPubKeyHash(hash, mainParams)
	if err != nil {
		t.Fatalf("NewAddressPubKeyHash mainnet: %v", err)
	}
	regAddr, err := hnsutil.NewAddressPubKeyHash(hash, regtestParams)
	if err != nil {
		t.Fatalf("NewAddressPubKeyHash regtest: %v", err)
	}

	mainStr := mainAddr.EncodeAddress()
	regStr := regAddr.EncodeAddress()
	if !strings.HasPrefix(mainStr, "hs1") {
		t.Errorf("mainnet address missing hs1 prefix: %q", mainStr)
	}
	if !strings.HasPrefix(regStr, "rs1") {
		t.Errorf("regtest address missing rs1 prefix: %q", regStr)
	}
	if mainStr == regStr {
		t.Error("mainnet and regtest addresses must differ by HRP")
	}

	// Cross-network decode should fail.
	if _, err := hnsutil.DecodeAddress(regStr, mainParams); err == nil {
		t.Error("expected cross-network decode to fail (rs1 vs hs)")
	}
	if _, err := hnsutil.DecodeAddress(mainStr, regtestParams); err == nil {
		t.Error("expected cross-network decode to fail (hs1 vs rs)")
	}

	// DecodeAddressAnyNet accepts both.
	if _, err := hnsutil.DecodeAddressAnyNet(regStr); err != nil {
		t.Errorf("DecodeAddressAnyNet(regtest): %v", err)
	}
	if _, err := hnsutil.DecodeAddressAnyNet(mainStr); err != nil {
		t.Errorf("DecodeAddressAnyNet(mainnet): %v", err)
	}
}

// TestAddressInvalidInputs asserts that the constructors reject values
// that violate Handshake's version and hash-length rules.
func TestAddressInvalidInputs(t *testing.T) {
	params := mainNetParamsWithHRP(t, "hs")

	tests := []struct {
		name    string
		version uint8
		hashLen int
	}{
		{name: "version > 31", version: 32, hashLen: 20},
		{name: "version > 31 max", version: 255, hashLen: 20},
		{name: "v0 hash too short", version: 0, hashLen: 2},
		{name: "v0 hash wrong mid length", version: 0, hashLen: 21},
		{name: "v0 hash wrong long length", version: 0, hashLen: 40},
		{name: "v1 hash below min", version: 1, hashLen: 1},
		{name: "v1 hash above max", version: 1, hashLen: 41},
		{name: "v31 hash below min", version: 31, hashLen: 1},
		{name: "v31 hash above max", version: 31, hashLen: 41},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			hash := bytes.Repeat([]byte{0xaa}, test.hashLen)
			if _, err := hnsutil.NewAddress(test.version, hash, params); err == nil {
				t.Errorf("NewAddress(version=%d, hashLen=%d) succeeded, want error",
					test.version, test.hashLen)
			}
		})
	}
}

// TestDecodeAddressRejectsGarbage ensures obviously-malformed strings are
// rejected by the decoder.
func TestDecodeAddressRejectsGarbage(t *testing.T) {
	params := mainNetParamsWithHRP(t, "hs")

	invalid := []string{
		"",
		"not an address",
		"hs1",                         // no data
		"hs1qqqqqqqqqqqqqqqqqqqqqqqq", // wrong checksum
		"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", // Bitcoin mainnet segwit address - wrong HRP
	}

	for _, s := range invalid {
		t.Run(s, func(t *testing.T) {
			if _, err := hnsutil.DecodeAddress(s, params); err == nil {
				t.Errorf("DecodeAddress(%q) succeeded, want error", s)
			}
		})
	}
}

// TestAddressPubKeyAndScriptHashConstructors verifies the length checks in
// the legacy helper constructors.
func TestAddressPubKeyAndScriptHashConstructors(t *testing.T) {
	params := mainNetParamsWithHRP(t, "hs")

	if _, err := hnsutil.NewAddressPubKeyHash(make([]byte, 19), params); err == nil {
		t.Error("NewAddressPubKeyHash accepted 19-byte hash")
	}
	if _, err := hnsutil.NewAddressPubKeyHash(make([]byte, 21), params); err == nil {
		t.Error("NewAddressPubKeyHash accepted 21-byte hash")
	}
	if _, err := hnsutil.NewAddressPubKeyHash(make([]byte, 20), params); err != nil {
		t.Errorf("NewAddressPubKeyHash rejected 20-byte hash: %v", err)
	}

	if _, err := hnsutil.NewAddressScriptHash(make([]byte, 31), params); err == nil {
		t.Error("NewAddressScriptHash accepted 31-byte hash")
	}
	if _, err := hnsutil.NewAddressScriptHash(make([]byte, 33), params); err == nil {
		t.Error("NewAddressScriptHash accepted 33-byte hash")
	}
	if _, err := hnsutil.NewAddressScriptHash(make([]byte, 32), params); err != nil {
		t.Errorf("NewAddressScriptHash rejected 32-byte hash: %v", err)
	}
}
