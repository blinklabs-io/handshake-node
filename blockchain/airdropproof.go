// Copyright (c) 2024-2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	"github.com/blinklabs-io/handshake-node/hnsutil"
	"github.com/blinklabs-io/handshake-node/wire"
)

const (
	airdropReward     = uint64(4246994314)
	maxAirdropProof   = 3400
	airdropDepth      = 18
	airdropSubDepth   = 3
	airdropLeaves     = 216199
	airdropSubLeaves  = 8
	faucetDepth       = 11
	faucetLeaves      = 1358
	airdropKeyAddress = 4
)

type airdropProof struct {
	index     uint32
	proof     [][32]byte
	subindex  uint8
	subproof  [][32]byte
	key       []byte
	version   uint8
	address   []byte
	fee       uint64
	signature []byte
	size      int
}

type airdropKey struct {
	keyType uint8
	version uint8
	address []byte
	value   uint64
	sponsor bool
}

func checkCoinbaseAirdropProofSanity(tx *hnsutil.Tx, outputIndex int) error {
	msgTx := tx.MsgTx()
	if outputIndex >= len(msgTx.TxIn) ||
		len(msgTx.TxIn[outputIndex].Witness) != 1 {

		return badCovenant("coinbase airdrop witness is missing")
	}

	proof, err := parseAirdropProof(msgTx.TxIn[outputIndex].Witness[0])
	if err != nil {
		return badCovenant("airdrop proof is invalid")
	}
	if !proof.isSane() {
		return badCovenant("airdrop proof is not sane")
	}

	return nil
}

func verifyCoinbaseAirdropProof(tx *hnsutil.Tx, outputIndex int) (uint64,
	error) {

	msgTx := tx.MsgTx()
	if outputIndex >= len(msgTx.TxIn) ||
		outputIndex >= len(msgTx.TxOut) {

		return 0, badCovenant("coinbase airdrop proof is unlinked")
	}

	txIn := msgTx.TxIn[outputIndex]
	if len(txIn.Witness) != 1 {
		return 0, badCovenant("coinbase airdrop witness is invalid")
	}

	txOut := msgTx.TxOut[outputIndex]
	if txOut.Covenant.Type != wire.CovenantNone {
		return 0, badCovenant("coinbase airdrop output is invalid")
	}

	proof, err := parseAirdropProof(txIn.Witness[0])
	if err != nil {
		return 0, badCovenant("airdrop proof is invalid")
	}
	if !proof.isSane() {
		return 0, badCovenant("airdrop proof is not sane")
	}

	value := proof.value()
	if value < proof.fee {
		return 0, badCovenant("airdrop fee exceeds value")
	}

	outputValue := value - proof.fee
	if outputValue > uint64(hnsutil.MaxDoo) ||
		txOut.Value != int64(outputValue) {

		return 0, badCovenant("airdrop output value mismatch")
	}

	if txOut.Address.Version != proof.version ||
		!bytes.Equal(txOut.Address.Hash, proof.address) {

		return 0, badCovenant("airdrop output address mismatch")
	}

	return value, nil
}

func parseAirdropProof(serialized []byte) (*airdropProof, error) {
	if len(serialized) > maxAirdropProof {
		return nil, errors.New("airdrop proof too large")
	}

	r := bytes.NewReader(serialized)
	proof := &airdropProof{size: len(serialized)}

	index, err := readAirdropU32(r)
	if err != nil {
		return nil, err
	}
	proof.index = index
	if proof.index >= airdropLeaves {
		return nil, errors.New("airdrop proof index is invalid")
	}

	count, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	if count > airdropDepth {
		return nil, errors.New("airdrop proof path is too deep")
	}
	proof.proof, err = readAirdropHashes(r, int(count))
	if err != nil {
		return nil, err
	}

	subindex, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	proof.subindex = subindex
	if proof.subindex >= airdropSubLeaves {
		return nil, errors.New("airdrop subindex is invalid")
	}

	total, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	if total > airdropSubDepth {
		return nil, errors.New("airdrop subproof path is too deep")
	}
	proof.subproof, err = readAirdropHashes(r, int(total))
	if err != nil {
		return nil, err
	}

	proof.key, err = readAirdropVarBytes(r)
	if err != nil {
		return nil, err
	}
	if len(proof.key) == 0 {
		return nil, errors.New("airdrop key is empty")
	}

	version, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	proof.version = version
	if proof.version > 31 {
		return nil, errors.New("airdrop address version is invalid")
	}

	addressSize, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	if addressSize < 2 || addressSize > 40 {
		return nil, errors.New("airdrop address size is invalid")
	}
	proof.address = make([]byte, addressSize)
	if _, err := io.ReadFull(r, proof.address); err != nil {
		return nil, err
	}

	proof.fee, err = wire.ReadVarInt(r, 0)
	if err != nil {
		return nil, err
	}
	proof.signature, err = readAirdropVarBytes(r)
	if err != nil {
		return nil, err
	}

	if r.Len() != 0 {
		return nil, errors.New("trailing airdrop proof data")
	}

	return proof, nil
}

func (p *airdropProof) isSane() bool {
	if len(p.key) == 0 {
		return false
	}
	if p.version > 31 || len(p.address) < 2 || len(p.address) > 40 {
		return false
	}

	value := p.value()
	if value > uint64(hnsutil.MaxDoo) || p.fee > value {
		return false
	}

	if p.isAddress() {
		if len(p.subproof) != 0 || p.subindex != 0 {
			return false
		}
		if len(p.proof) > faucetDepth || p.index >= faucetLeaves {
			return false
		}
		return true
	}

	if len(p.subproof) > airdropSubDepth ||
		p.subindex >= airdropSubLeaves ||
		len(p.proof) > airdropDepth ||
		p.index >= airdropLeaves ||
		p.size > maxAirdropProof {

		return false
	}

	return true
}

func (p *airdropProof) isAddress() bool {
	return len(p.key) > 0 && p.key[0] == airdropKeyAddress
}

func (p *airdropProof) value() uint64 {
	if !p.isAddress() {
		return airdropReward
	}

	key, err := parseAirdropKey(p.key)
	if err != nil {
		return 0
	}
	return key.value
}

func parseAirdropKey(serialized []byte) (*airdropKey, error) {
	if len(serialized) == 0 {
		return nil, errors.New("empty airdrop key")
	}

	r := bytes.NewReader(serialized)
	keyType, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	key := &airdropKey{keyType: keyType}
	switch key.keyType {
	case airdropKeyAddress:
		version, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		key.version = version

		addressSize, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		key.address = make([]byte, addressSize)
		if _, err := io.ReadFull(r, key.address); err != nil {
			return nil, err
		}

		value, err := readAirdropU64(r)
		if err != nil {
			return nil, err
		}
		key.value = value

		sponsor, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		key.sponsor = sponsor == 1
	default:
		return nil, errors.New("unsupported airdrop key type")
	}

	if r.Len() != 0 {
		return nil, errors.New("trailing airdrop key data")
	}
	return key, nil
}

func readAirdropHashes(r *bytes.Reader, count int) ([][32]byte, error) {
	hashes := make([][32]byte, count)
	for i := range hashes {
		if _, err := io.ReadFull(r, hashes[i][:]); err != nil {
			return nil, err
		}
	}
	return hashes, nil
}

func readAirdropVarBytes(r *bytes.Reader) ([]byte, error) {
	size, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return nil, err
	}
	if size > uint64(r.Len()) {
		return nil, errors.New("truncated var bytes")
	}

	data := make([]byte, size)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}
	return data, nil
}

func readAirdropU32(r *bytes.Reader) (uint32, error) {
	var raw [4]byte
	if _, err := io.ReadFull(r, raw[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(raw[:]), nil
}

func readAirdropU64(r *bytes.Reader) (uint64, error) {
	var raw [8]byte
	if _, err := io.ReadFull(r, raw[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(raw[:]), nil
}
