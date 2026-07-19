// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"encoding/binary"
	"fmt"

	"github.com/blinklabs-io/handshake-node/chaincfg"
	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/hnsutil"
	"github.com/blinklabs-io/handshake-node/wire"
	"golang.org/x/crypto/blake2b"
)

// RawCoinbaseProof describes a raw hsd claim or airdrop proof converted into
// the output metadata needed by the coinbase proof source.
type RawCoinbaseProof struct {
	Hash    chainhash.Hash
	Witness []byte
	Output  *wire.TxOut
	Fee     int64
}

// RawProofHash returns hsd's proof hash: blake2b-256 over the raw proof blob.
func RawProofHash(serialized []byte) chainhash.Hash {
	return chainhash.Hash(blake2b.Sum256(serialized))
}

// CoinbaseClaimProofFromRaw validates an hsd raw claim blob and converts it
// into the linked coinbase proof metadata for the provided next block height.
func CoinbaseClaimProofFromRaw(serialized []byte, height uint32, prevTime int64,
	params *chaincfg.Params) (RawCoinbaseProof, error) {

	if params == nil {
		return RawCoinbaseProof{}, fmt.Errorf("missing chain parameters")
	}

	proof, err := parseOwnershipProof(serialized)
	if err != nil {
		return RawCoinbaseProof{}, badCovenant("CLAIM ownership proof is invalid")
	}
	if !proof.isSane() {
		return RawCoinbaseProof{}, badCovenant("CLAIM ownership proof is not sane")
	}
	if !proof.verifyTimes(prevTime) {
		return RawCoinbaseProof{}, badCovenant("CLAIM ownership proof time is invalid")
	}
	if !proof.verifySignatures() {
		return RawCoinbaseProof{}, badCovenant("CLAIM ownership proof signature is invalid")
	}

	data, err := proof.claimData(params)
	if err != nil {
		return RawCoinbaseProof{}, err
	}
	if data == nil {
		return RawCoinbaseProof{}, badCovenant("CLAIM ownership proof data is invalid")
	}
	if data.commitHeight == 0 {
		return RawCoinbaseProof{}, badCovenant("CLAIM ownership proof height mismatch")
	}
	if data.value < data.fee {
		return RawCoinbaseProof{}, badCovenant("CLAIM ownership proof fee exceeds value")
	}

	outputValue := data.value - data.fee
	if outputValue > uint64(hnsutil.MaxDoo) {
		return RawCoinbaseProof{}, badCovenant("CLAIM output value exceeds max money")
	}
	if height >= params.NameDeflationHeight && data.commitHeight == 1 {
		maxFee := uint64(1000 * hnsutil.DooPerHNS)
		if data.fee > maxFee {
			return RawCoinbaseProof{}, badCovenant("CLAIM fee exceeds deflation cap")
		}
	}

	name := []byte(data.name)
	nameHash := HashName(name)
	flags := byte(0)
	if data.weak {
		flags = 1
	}

	output := wire.NewTxOut(int64(outputValue), wire.Address{
		Version: data.version,
		Hash:    append([]byte(nil), data.hash...),
	}, wire.Covenant{
		Type: wire.CovenantClaim,
		Items: [][]byte{
			proofRelayHashItem(nameHash),
			proofRelayU32Item(height),
			append([]byte(nil), name...),
			[]byte{flags},
			proofRelayHashItem(data.commitHash),
			proofRelayU32Item(data.commitHeight),
		},
	})

	if _, err := verifyCoinbaseClaimProofData(output, output.Covenant,
		height, params, data); err != nil {

		return RawCoinbaseProof{}, err
	}

	return RawCoinbaseProof{
		Hash:    RawProofHash(serialized),
		Witness: append([]byte(nil), serialized...),
		Output:  output,
		Fee:     int64(data.fee),
	}, nil
}

// CoinbaseAirdropProofFromRaw validates an hsd raw airdrop proof blob and
// converts it into linked coinbase proof metadata.
func CoinbaseAirdropProofFromRaw(serialized []byte, height uint32,
	params *chaincfg.Params) (RawCoinbaseProof, error) {

	if params == nil {
		return RawCoinbaseProof{}, fmt.Errorf("missing chain parameters")
	}

	proof, err := parseAirdropProof(serialized)
	if err != nil {
		return RawCoinbaseProof{}, badCovenant("airdrop proof is invalid")
	}

	value := proof.value()
	if value < proof.fee {
		return RawCoinbaseProof{}, badCovenant("airdrop fee exceeds value")
	}
	outputValue := value - proof.fee
	if outputValue > uint64(hnsutil.MaxDoo) {
		return RawCoinbaseProof{}, badCovenant("airdrop output value exceeds max money")
	}

	output := wire.NewTxOut(int64(outputValue), wire.Address{
		Version: proof.version,
		Hash:    append([]byte(nil), proof.address...),
	}, wire.Covenant{})

	if _, err := verifyCoinbaseAirdropProofData(output, height, params, proof,
		handshakeDeploymentFlags{}); err != nil {

		return RawCoinbaseProof{}, err
	}

	return RawCoinbaseProof{
		Hash:    RawProofHash(serialized),
		Witness: append([]byte(nil), serialized...),
		Output:  output,
		Fee:     int64(proof.fee),
	}, nil
}

func proofRelayHashItem(hash chainhash.Hash) []byte {
	return append([]byte(nil), hash[:]...)
}

func proofRelayU32Item(value uint32) []byte {
	var raw [4]byte
	binary.LittleEndian.PutUint32(raw[:], value)
	return append([]byte(nil), raw[:]...)
}
