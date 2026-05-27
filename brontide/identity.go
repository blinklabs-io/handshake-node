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
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/btcsuite/btcd/btcec/v2"
)

const (
	// IdentityKeyFile is the default file name for a Brontide node identity key.
	IdentityKeyFile = "brontide.key"

	identityKeyFileMode os.FileMode = 0600
	identityDirMode     os.FileMode = 0700
)

var (
	// ErrInvalidIdentityPath is returned when an identity-key path is empty.
	ErrInvalidIdentityPath = errors.New("brontide: invalid identity path")

	// ErrInvalidIdentityKey is returned when stored identity-key bytes are
	// malformed or outside the secp256k1 private key range.
	ErrInvalidIdentityKey = errors.New("brontide: invalid identity key")

	// ErrInsecureIdentityKeyPermissions is returned when a stored identity
	// key is readable or writable by group or other users.
	ErrInsecureIdentityKeyPermissions = errors.New(
		"brontide: insecure identity key permissions",
	)
)

// IdentityKeyPath returns the default Brontide identity-key path under dataDir.
func IdentityKeyPath(dataDir string) string {
	return filepath.Join(dataDir, IdentityKeyFile)
}

// LoadOrCreateIdentityKey loads the node Brontide identity key at path, or
// generates and persists a new key when none exists. The returned bool is true
// when a new key was created.
func LoadOrCreateIdentityKey(path string) (*btcec.PrivateKey, bool, error) {
	priv, err := LoadIdentityKey(path)
	if err == nil {
		return priv, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, err
	}

	priv, err = GenerateKey()
	if err != nil {
		return nil, false, err
	}
	if err := createIdentityKey(path, priv); err != nil {
		if errors.Is(err, os.ErrExist) {
			priv, err := LoadIdentityKey(path)
			return priv, false, err
		}
		return nil, false, err
	}
	return priv, true, nil
}

// LoadIdentityKey loads a serialized secp256k1 Brontide identity key from path.
func LoadIdentityKey(path string) (*btcec.PrivateKey, error) {
	if path == "" {
		return nil, ErrInvalidIdentityPath
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if err := checkIdentityKeyFileMode(info.Mode()); err != nil {
		return nil, err
	}

	keyBytes, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	return parsePrivateKeyBytes(keyBytes)
}

// SaveIdentityKey writes a Brontide identity key to path using owner-only file
// permissions. Existing files are replaced.
func SaveIdentityKey(path string, priv *btcec.PrivateKey) error {
	if path == "" {
		return ErrInvalidIdentityPath
	}
	if priv == nil {
		return fmt.Errorf("%w: nil private key", ErrInvalidKey)
	}
	return writeIdentityKeyFile(path, priv.Serialize(), false)
}

// IdentityStaticKey returns the compressed secp256k1 public key advertised as
// the node's Brontide static identity key.
func IdentityStaticKey(priv *btcec.PrivateKey) ([]byte, error) {
	if priv == nil {
		return nil, fmt.Errorf("%w: nil private key", ErrInvalidKey)
	}
	return PublicKeyBytes(priv), nil
}

func createIdentityKey(path string, priv *btcec.PrivateKey) error {
	if path == "" {
		return ErrInvalidIdentityPath
	}
	if priv == nil {
		return fmt.Errorf("%w: nil private key", ErrInvalidKey)
	}
	return writeIdentityKeyFile(path, priv.Serialize(), true)
}

func writeIdentityKeyFile(path string, keyBytes []byte, exclusive bool) error {
	if err := os.MkdirAll(filepath.Dir(path), identityDirMode); err != nil {
		return err
	}

	file, tempPath, err := createTempIdentityKey(path)
	if err != nil {
		return err
	}
	renamed := false
	defer func() {
		if !renamed {
			_ = os.Remove(tempPath)
		}
	}()

	if err := writeAndCloseIdentityKey(file, keyBytes); err != nil {
		return err
	}

	if exclusive {
		linked, err := linkIdentityKey(tempPath, path)
		if err != nil {
			return err
		}
		renamed = linked
		return nil
	}

	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	renamed = true
	return nil
}

func createTempIdentityKey(path string) (*os.File, string, error) {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	temp, err := os.CreateTemp(dir, "."+base+".*.tmp")
	if err != nil {
		return nil, "", err
	}
	tempPath := temp.Name()
	if err := temp.Chmod(identityKeyFileMode); err != nil {
		_ = temp.Close()
		_ = os.Remove(tempPath)
		return nil, "", err
	}
	return temp, tempPath, nil
}

func linkIdentityKey(tempPath, path string) (bool, error) {
	if err := os.Link(tempPath, path); err != nil {
		return false, err
	}
	_ = os.Remove(tempPath)
	return true, nil
}

func writeAndCloseIdentityKey(file *os.File, keyBytes []byte) error {
	closed := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
	}()

	n, err := file.Write(keyBytes)
	if err != nil {
		return err
	}
	if n != len(keyBytes) {
		return io.ErrShortWrite
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	closed = true
	return nil
}

func checkIdentityKeyFileMode(mode os.FileMode) error {
	if !mode.IsRegular() {
		return fmt.Errorf("%w: not a regular file", ErrInvalidIdentityKey)
	}
	if mode.Perm()&0077 != 0 {
		return fmt.Errorf(
			"%w: got %v, want no group/other permissions",
			ErrInsecureIdentityKeyPermissions, mode.Perm(),
		)
	}
	return nil
}

func parsePrivateKeyBytes(keyBytes []byte) (*btcec.PrivateKey, error) {
	if len(keyBytes) != PrivateKeySize {
		return nil, fmt.Errorf("%w: got %d bytes, want %d",
			ErrInvalidIdentityKey, len(keyBytes), PrivateKeySize)
	}

	var serialized [PrivateKeySize]byte
	copy(serialized[:], keyBytes)

	var scalar btcec.ModNScalar
	overflow := scalar.SetBytes(&serialized)
	if overflow != 0 || scalar.IsZero() {
		return nil, ErrInvalidIdentityKey
	}

	return btcec.PrivKeyFromScalar(&scalar), nil
}
