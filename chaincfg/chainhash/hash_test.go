// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package chainhash

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

const mainNetGenesisHashString = "5b6ef2d3c1f3cdcadfd9a030ba1811efdd17740f14e166489760741d075992e0"

func mustHashFromHex(hash string) Hash {
	decoded, err := hex.DecodeString(hash)
	if err != nil {
		panic(err)
	}
	if len(decoded) != HashSize {
		panic("invalid test hash length")
	}
	return Hash(decoded)
}

// mainNetGenesisHash is hsd's canonical Handshake mainnet genesis hash in
// native byte order.
var mainNetGenesisHash = mustHashFromHex(mainNetGenesisHashString)

// TestHash tests the Hash API.
func TestHash(t *testing.T) {
	// hsd mainnet checkpoint at height 1008.
	blockHashStr := "0000000000001013c28fa079b545fb805f04c496687799b98e35e83cbbb8953e"
	blockHash, err := NewHashFromStr(blockHashStr)
	if err != nil {
		t.Errorf("NewHashFromStr: %v", err)
	}

	// Mainnet genesis hash as raw bytes.
	buf := mainNetGenesisHash[:]

	hash, err := NewHash(buf)
	if err != nil {
		t.Errorf("NewHash: unexpected error %v", err)
	}

	// Ensure proper size.
	if len(hash) != HashSize {
		t.Errorf("NewHash: hash length mismatch - got: %v, want: %v",
			len(hash), HashSize)
	}

	// Ensure contents match.
	if !bytes.Equal(hash[:], buf) {
		t.Errorf("NewHash: hash contents mismatch - got: %v, want: %v",
			hash[:], buf)
	}

	// Ensure contents of hash of block 234440 don't match 234439.
	if hash.IsEqual(blockHash) {
		t.Errorf("IsEqual: hash contents should not match - got: %v, want: %v",
			hash, blockHash)
	}

	// Set hash from byte slice and ensure contents match.
	err = hash.SetBytes(blockHash.CloneBytes())
	if err != nil {
		t.Errorf("SetBytes: %v", err)
	}
	if !hash.IsEqual(blockHash) {
		t.Errorf("IsEqual: hash contents mismatch - got: %v, want: %v",
			hash, blockHash)
	}

	// Ensure nil hashes are handled properly.
	if !(*Hash)(nil).IsEqual(nil) {
		t.Error("IsEqual: nil hashes should match")
	}
	if hash.IsEqual(nil) {
		t.Error("IsEqual: non-nil hash matches nil hash")
	}

	// Invalid size for SetBytes.
	err = hash.SetBytes([]byte{0x00})
	if err == nil {
		t.Errorf("SetBytes: failed to received expected err - got: nil")
	}

	// Invalid size for NewHash.
	invalidHash := make([]byte, HashSize+1)
	_, err = NewHash(invalidHash)
	if err == nil {
		t.Errorf("NewHash: failed to received expected err - got: nil")
	}
}

// TestHashString  tests the stringized output for hashes.
func TestHashString(t *testing.T) {
	wantStr := mainNetGenesisHashString
	hash := mainNetGenesisHash

	hashStr := hash.String()
	if hashStr != wantStr {
		t.Errorf("String: wrong hash string - got %v, want %v",
			hashStr, wantStr)
	}
}

// TestNewHashFromStr executes compatibility tests against the lenient
// NewHashFromStr function.
func TestNewHashFromStr(t *testing.T) {
	tests := []struct {
		in   string
		want Hash
		err  error
	}{
		// Handshake mainnet genesis hash.
		{
			mainNetGenesisHashString,
			mainNetGenesisHash,
			nil,
		},

		// hsd checkpoint hash with stripped leading zeros.
		{
			"1013c28fa079b545fb805f04c496687799b98e35e83cbbb8953e",
			mustHashFromHex("0000000000001013c28fa079b545fb805f04c496687799b98e35e83cbbb8953e"),
			nil,
		},

		// Empty string.
		{
			"",
			Hash{},
			nil,
		},

		// Single digit hash.
		{
			"1",
			Hash{HashSize - 1: 0x01},
			nil,
		},

		// Another value with stripped leading zeros.
		{
			"3264bc2ac36a60840790ba1d475d01367e7c723da941069e9dc",
			mustHashFromHex("00000000000003264bc2ac36a60840790ba1d475d01367e7c723da941069e9dc"),
			nil,
		},

		// Hash string that is too long.
		{
			"01234567890123456789012345678901234567890123456789012345678912345",
			Hash{},
			ErrHashStrSize,
		},

		// Hash string that is contains non-hex chars.
		{
			"abcdefg",
			Hash{},
			hex.InvalidByteError('g'),
		},
	}

	unexpectedErrStr := "NewHashFromStr #%d failed to detect expected error - got: %v want: %v"
	unexpectedResultStr := "NewHashFromStr #%d got: %v want: %v"
	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		result, err := NewHashFromStr(test.in)
		if err != test.err {
			t.Errorf(unexpectedErrStr, i, err, test.err)
			continue
		} else if err != nil {
			// Got expected error. Move on to the next test.
			continue
		}
		if !test.want.IsEqual(result) {
			t.Errorf(unexpectedResultStr, i, result, &test.want)
			continue
		}
	}
}

// TestNewHashFromStrStrict executes tests against the NewHashFromStrStrict
// function.
func TestNewHashFromStrStrict(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want Hash
		err  error
	}{
		{
			name: "genesis hash",
			in:   mainNetGenesisHashString,
			want: mainNetGenesisHash,
			err:  nil,
		},
		{
			name: "stripped leading zeros",
			in:   "6ef2d3c1f3cdcadfd9a030ba1811efdd17740f14e166489760741d075992e0",
			want: Hash{},
			err:  ErrHashStrSizeMismatch,
		},
		{
			name: "odd length hash",
			in:   "1",
			want: Hash{},
			err:  ErrHashStrSizeMismatch,
		},
		{
			name: "empty string",
			in:   "",
			want: Hash{},
			err:  ErrHashStrSizeMismatch,
		},
		{
			name: "hash string that is too long",
			in:   "01234567890123456789012345678901234567890123456789012345678912345",
			want: Hash{},
			err:  ErrHashStrSizeMismatch,
		},
		{
			name: "hash string that contains non-hex chars",
			in:   "5b6ef2d3c1f3cdcadfd9a030ba1811efdd17740f14e166489760741d075992eg",
			want: Hash{},
			err:  hex.InvalidByteError('g'),
		},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			result, err := NewHashFromStrStrict(test.in)
			if err != test.err {
				t.Errorf("NewHashFromStrStrict #%d failed to "+
					"detect expected error - got: %v want: %v",
					i, err, test.err)
				return
			} else if err != nil {
				return
			}
			if !test.want.IsEqual(result) {
				t.Errorf("NewHashFromStrStrict #%d got: %v "+
					"want: %v", i, result, &test.want)
			}
		})
	}
}

// TestDecodeStrict executes tests against the DecodeStrict function.
func TestDecodeStrict(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want Hash
		err  error
	}{
		{
			name: "genesis hash",
			in:   mainNetGenesisHashString,
			want: mainNetGenesisHash,
			err:  nil,
		},
		{
			name: "odd length hash",
			in:   "1",
			want: Hash{},
			err:  ErrHashStrSizeMismatch,
		},
		{
			name: "even length hash that is too short",
			in:   "deadbeef" + strings.Repeat("0", 24),
			want: Hash{},
			err:  ErrHashStrSizeMismatch,
		},
		{
			name: "hash string that contains non-hex chars",
			in:   "5b6ef2d3c1f3cdcadfd9a030ba1811efdd17740f14e166489760741d075992eg",
			want: Hash{},
			err:  hex.InvalidByteError('g'),
		},
		{
			name: "hash string that is too long",
			in:   "01234567890123456789012345678901234567890123456789012345678912345",
			want: Hash{},
			err:  ErrHashStrSizeMismatch,
		},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			var result Hash
			err := DecodeStrict(&result, test.in)
			if err != test.err {
				t.Errorf("DecodeStrict #%d failed to detect "+
					"expected error - got: %v want: %v",
					i, err, test.err)
				return
			} else if err != nil {
				return
			}
			if !test.want.IsEqual(&result) {
				t.Errorf("DecodeStrict #%d got: %v want: %v",
					i, &result, &test.want)
			}
		})
	}
}

// TestDecodeErrorPreservesDestination ensures malformed input does not
// partially overwrite an existing hash.
func TestDecodeErrorPreservesDestination(t *testing.T) {
	tests := []struct {
		name   string
		decode func(*Hash, string) error
		in     string
	}{
		{
			name:   "lenient",
			decode: Decode,
			in:     "abcdefg",
		},
		{
			name:   "strict",
			decode: DecodeStrict,
			in:     "5b6ef2d3c1f3cdcadfd9a030ba1811efdd17740f14e166489760741d075992eg",
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			got := mainNetGenesisHash
			if err := test.decode(&got, test.in); err == nil {
				t.Fatal("Decode unexpectedly succeeded")
			}
			if got != mainNetGenesisHash {
				t.Fatalf("Decode modified destination on error: got %v, want %v",
					got, mainNetGenesisHash)
			}
		})
	}
}

// TestHashJsonMarshal tests json marshal and unmarshal.
func TestHashJsonMarshal(t *testing.T) {
	hashStr := mainNetGenesisHashString

	hash, err := NewHashFromStr(hashStr)
	if err != nil {
		t.Errorf("NewHashFromStr error:%v, hashStr:%s", err, hashStr)
	}

	hashBytes, err := json.Marshal(hash)
	if err != nil {
		t.Errorf("Marshal json error:%v, hash:%v", err, hashBytes)
	}

	var newHash Hash
	err = json.Unmarshal(hashBytes, &newHash)
	if err != nil {
		t.Errorf("Unmarshal json error:%v, hash:%v", err, hashBytes)
	}

	if !hash.IsEqual(&newHash) {
		t.Errorf("String: wrong hash string - got %v, want %v", newHash.String(), hashStr)
	}

	legacyHashStr, err := json.Marshal([HashSize]byte(*hash))
	if err != nil {
		t.Errorf("Marshal legacy json error: %v", err)
	}
	err = newHash.UnmarshalJSON(legacyHashStr)
	if err != nil {
		t.Errorf("Unmarshal legacy json error:%v, hash:%v", err, legacyHashStr)
	}

	if !hash.IsEqual(&newHash) {
		t.Errorf("String: wrong hash string - got %v, want %v", newHash.String(), hashStr)
	}
}
