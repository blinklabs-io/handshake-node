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

package brontide

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
)

func TestIdentityKeyPath(t *testing.T) {
	got := IdentityKeyPath(filepath.Join("data", "mainnet"))
	want := filepath.Join("data", "mainnet", IdentityKeyFile)
	if got != want {
		t.Fatalf("path: got %q, want %q", got, want)
	}
}

func TestLoadOrCreateIdentityKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys", IdentityKeyFile)

	createdKey, created, err := LoadOrCreateIdentityKey(path)
	if err != nil {
		t.Fatalf("LoadOrCreateIdentityKey create: %v", err)
	}
	if !created {
		t.Fatal("created flag: got false, want true")
	}
	if createdKey == nil {
		t.Fatal("created key is nil")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat identity key: %v", err)
	}
	if info.Mode().Perm() != identityKeyFileMode {
		t.Fatalf("mode: got %v, want %v", info.Mode().Perm(), identityKeyFileMode)
	}

	loadedKey, created, err := LoadOrCreateIdentityKey(path)
	if err != nil {
		t.Fatalf("LoadOrCreateIdentityKey load: %v", err)
	}
	if created {
		t.Fatal("created flag on reload: got true, want false")
	}
	if !bytes.Equal(loadedKey.Serialize(), createdKey.Serialize()) {
		t.Fatalf("loaded key: got %x, want %x",
			loadedKey.Serialize(), createdKey.Serialize())
	}
}

func TestLoadAndSaveIdentityKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, IdentityKeyFile)
	priv, _ := btcec.PrivKeyFromBytes(testKey(0x03))

	if err := SaveIdentityKey(path, priv); err != nil {
		t.Fatalf("SaveIdentityKey: %v", err)
	}
	assertIdentityKeyMode(t, path)

	got, err := LoadIdentityKey(path)
	if err != nil {
		t.Fatalf("LoadIdentityKey: %v", err)
	}
	if !bytes.Equal(got.Serialize(), priv.Serialize()) {
		t.Fatalf("loaded key: got %x, want %x", got.Serialize(), priv.Serialize())
	}
	assertNoIdentityTempFiles(t, dir)
}

func TestSaveIdentityKeyReplacesExistingKeyAtomically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, IdentityKeyFile)
	oldKey, _ := btcec.PrivKeyFromBytes(testKey(0x03))
	newKey, _ := btcec.PrivKeyFromBytes(testKey(0x13))

	if err := SaveIdentityKey(path, oldKey); err != nil {
		t.Fatalf("SaveIdentityKey old: %v", err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatalf("chmod old key: %v", err)
	}

	if err := SaveIdentityKey(path, newKey); err != nil {
		t.Fatalf("SaveIdentityKey new: %v", err)
	}
	assertIdentityKeyMode(t, path)

	got, err := LoadIdentityKey(path)
	if err != nil {
		t.Fatalf("LoadIdentityKey: %v", err)
	}
	if !bytes.Equal(got.Serialize(), newKey.Serialize()) {
		t.Fatalf("loaded key: got %x, want %x", got.Serialize(), newKey.Serialize())
	}
	assertNoIdentityTempFiles(t, dir)
}

func TestSaveIdentityKeyCleansTempFileOnRenameFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, IdentityKeyFile)
	priv, _ := btcec.PrivKeyFromBytes(testKey(0x03))

	if err := os.Mkdir(path, identityDirMode); err != nil {
		t.Fatalf("mkdir destination: %v", err)
	}

	if err := SaveIdentityKey(path, priv); err == nil {
		t.Fatal("expected save to fail when destination is a directory")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat destination: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("destination directory was replaced")
	}
	assertNoIdentityTempFiles(t, dir)
}

func TestIdentityStaticKey(t *testing.T) {
	priv, _ := btcec.PrivKeyFromBytes(testKey(0x04))

	got, err := IdentityStaticKey(priv)
	if err != nil {
		t.Fatalf("IdentityStaticKey: %v", err)
	}
	want := PublicKeyBytes(priv)
	if !bytes.Equal(got, want) {
		t.Fatalf("static key: got %x, want %x", got, want)
	}
}

func TestIdentityKeyRejectsInvalidInputs(t *testing.T) {
	if _, err := LoadIdentityKey(""); !errors.Is(err, ErrInvalidIdentityPath) {
		t.Fatalf("empty load path: got %v, want %v", err, ErrInvalidIdentityPath)
	}
	if err := SaveIdentityKey("", nil); !errors.Is(err, ErrInvalidIdentityPath) {
		t.Fatalf("empty save path: got %v, want %v", err, ErrInvalidIdentityPath)
	}

	path := filepath.Join(t.TempDir(), IdentityKeyFile)
	if err := os.WriteFile(path, []byte{0x01, 0x02}, identityKeyFileMode); err != nil {
		t.Fatalf("write short key: %v", err)
	}
	if _, err := LoadIdentityKey(path); !errors.Is(err, ErrInvalidIdentityKey) {
		t.Fatalf("short key error: got %v, want %v", err, ErrInvalidIdentityKey)
	}

	if err := os.WriteFile(path, make([]byte, PrivateKeySize), identityKeyFileMode); err != nil {
		t.Fatalf("write zero key: %v", err)
	}
	if _, err := LoadIdentityKey(path); !errors.Is(err, ErrInvalidIdentityKey) {
		t.Fatalf("zero key error: got %v, want %v", err, ErrInvalidIdentityKey)
	}

	overflowKey := bytes.Repeat([]byte{0xff}, PrivateKeySize)
	if err := os.WriteFile(path, overflowKey, identityKeyFileMode); err != nil {
		t.Fatalf("write overflow key: %v", err)
	}
	if _, err := LoadIdentityKey(path); !errors.Is(err, ErrInvalidIdentityKey) {
		t.Fatalf("overflow key error: got %v, want %v", err, ErrInvalidIdentityKey)
	}

	if _, err := IdentityStaticKey(nil); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("nil static key error: got %v, want %v", err, ErrInvalidKey)
	}
}

func TestLoadIdentityKeyRejectsInsecurePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), IdentityKeyFile)
	priv, _ := btcec.PrivKeyFromBytes(testKey(0x03))

	if err := os.WriteFile(path, priv.Serialize(), 0644); err != nil {
		t.Fatalf("write identity key: %v", err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatalf("chmod identity key: %v", err)
	}

	_, err := LoadIdentityKey(path)
	if !errors.Is(err, ErrInsecureIdentityKeyPermissions) {
		t.Fatalf("LoadIdentityKey error: got %v, want %v",
			err, ErrInsecureIdentityKeyPermissions)
	}

	if err := os.Chmod(path, 0400); err != nil {
		t.Fatalf("chmod identity key secure read-only: %v", err)
	}
	if _, err := LoadIdentityKey(path); err != nil {
		t.Fatalf("LoadIdentityKey secure read-only: %v", err)
	}
}

func assertIdentityKeyMode(t *testing.T, path string) {
	t.Helper()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat identity key: %v", err)
	}
	if info.Mode().Perm() != identityKeyFileMode {
		t.Fatalf("mode: got %v, want %v", info.Mode().Perm(), identityKeyFileMode)
	}
}

func assertNoIdentityTempFiles(t *testing.T, dir string) {
	t.Helper()

	matches, err := filepath.Glob(filepath.Join(dir, "."+IdentityKeyFile+".*.tmp"))
	if err != nil {
		t.Fatalf("glob temp files: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("unexpected temp files: %v", matches)
	}
}
