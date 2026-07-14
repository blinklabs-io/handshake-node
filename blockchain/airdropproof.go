// Copyright (c) 2024-2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"math/big"

	"github.com/blinklabs-io/handshake-node/chaincfg"
	"github.com/blinklabs-io/handshake-node/hnsutil"
	"github.com/blinklabs-io/handshake-node/wire"
	"golang.org/x/crypto/blake2b"
)

const (
	airdropReward       = uint64(4246994314)
	airdropSponsorFee   = uint64(500000000)
	airdropRecipientFee = uint64(100000000)
	maxAirdropProof     = 3400
	airdropDepth        = 18
	airdropSubDepth     = 3
	airdropLeaves       = 216199
	airdropSubLeaves    = 8
	faucetDepth         = 11
	faucetLeaves        = 1358
	airdropTreeLeaves   = airdropLeaves + faucetLeaves
	airdropKeyRSA       = 0
	airdropKeyGoo       = 1
	airdropKeyP256      = 2
	airdropKeyED25519   = 3
	airdropKeyAddress   = 4
	airdropGooKeySize   = 256
)

var (
	airdropRoot = [32]byte{
		0x10, 0xd7, 0x48, 0xed, 0xa1, 0xb9, 0xc6, 0x7b,
		0x94, 0xd3, 0x24, 0x4e, 0x02, 0x11, 0x67, 0x76,
		0x18, 0xa9, 0xb4, 0xb3, 0x29, 0xe8, 0x96, 0xad,
		0x90, 0x43, 0x1f, 0x9f, 0x48, 0x03, 0x4b, 0xad,
	}
	faucetRoot = [32]byte{
		0xe2, 0xc0, 0x29, 0x9a, 0x1e, 0x46, 0x67, 0x73,
		0x51, 0x66, 0x55, 0xf0, 0x9a, 0x64, 0xb1, 0xe1,
		0x6b, 0x25, 0x79, 0x53, 0x0d, 0xe6, 0xc4, 0xa5,
		0x9c, 0xe5, 0x65, 0x4d, 0xea, 0x45, 0x18, 0x0f,
	}
	airdropSignatureContext = [32]byte{
		0x5b, 0x21, 0xff, 0x4a, 0x0f, 0xcf, 0x78, 0x12,
		0x39, 0x15, 0xea, 0xa0, 0x00, 0x3d, 0x2a, 0x3e,
		0x18, 0x55, 0xa9, 0xb1, 0x5e, 0x34, 0x41, 0xda,
		0x2e, 0xf5, 0xa4, 0xc0, 0x1e, 0xaf, 0x4f, 0xf3,
	}
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
	n       []byte
	e       []byte
	c1      []byte
	point   []byte
	nonce   []byte
	version uint8
	address []byte
	value   uint64
	sponsor bool
}

// AirdropProofMetadata is the policy-relevant metadata decoded from a
// serialized airdrop proof.
type AirdropProofMetadata struct {
	Position uint32
	Value    uint64
	Fee      uint64
	Version  uint8
	Address  []byte
	Weak     bool
	GooSig   bool
}

// DecodeAirdropProofMetadata decodes a serialized airdrop proof and returns
// the narrow set of metadata needed by policy code outside this package.
func DecodeAirdropProofMetadata(serialized []byte) (
	AirdropProofMetadata, error) {

	proof, err := parseAirdropProof(serialized)
	if err != nil {
		return AirdropProofMetadata{}, err
	}
	if !proof.isSane() {
		return AirdropProofMetadata{}, errors.New("airdrop proof is not sane")
	}

	position, err := proof.position()
	if err != nil {
		return AirdropProofMetadata{}, err
	}
	key, err := parseAirdropKey(proof.key)
	if err != nil {
		return AirdropProofMetadata{}, err
	}

	return AirdropProofMetadata{
		Position: position,
		Value:    proof.value(),
		Fee:      proof.fee,
		Version:  proof.version,
		Address:  append([]byte(nil), proof.address...),
		Weak:     key.isWeak(),
		GooSig:   key.keyType == airdropKeyGoo,
	}, nil
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

func verifyCoinbaseAirdropProof(tx *hnsutil.Tx, outputIndex int, height uint32,
	params *chaincfg.Params, deploymentFlags handshakeDeploymentFlags) (
	uint64, error) {

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
	proof, err := parseAirdropProof(txIn.Witness[0])
	if err != nil {
		return 0, badCovenant("airdrop proof is invalid")
	}

	return verifyCoinbaseAirdropProofData(txOut, height, params, proof,
		deploymentFlags)
}

func verifyCoinbaseAirdropProofData(txOut *wire.TxOut, height uint32,
	params *chaincfg.Params, proof *airdropProof,
	deploymentFlags handshakeDeploymentFlags) (uint64, error) {

	if !proof.isSane() {
		return 0, badCovenant("airdrop proof is not sane")
	}
	if txOut.Covenant.Type != wire.CovenantNone {
		return 0, badCovenant("coinbase airdrop output is invalid")
	}
	if params == nil || height >= params.AirdropGooSigStop {
		key, err := parseAirdropKey(proof.key)
		if err != nil {
			return 0, badCovenant("airdrop proof is invalid")
		}
		if key.keyType == airdropKeyGoo {
			return 0, badCovenant("GooSig airdrop proof is disabled")
		}
	}
	if deploymentFlags.hardeningActive && proof.isWeak() {
		return 0, badCovenant("airdrop proof uses weak algorithm")
	}
	if !proof.verifyMerkle() {
		return 0, badCovenant("airdrop proof merkle root mismatch")
	}
	if !proof.verifySignature() {
		return 0, badCovenant("airdrop proof signature invalid")
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

func (p *airdropProof) isWeak() bool {
	key, err := parseAirdropKey(p.key)
	if err != nil {
		return false
	}
	return key.isWeak()
}

func (p *airdropProof) position() (uint32, error) {
	index := p.index
	if p.isAddress() {
		if index >= faucetLeaves {
			return 0, errors.New("airdrop faucet index is invalid")
		}
		index += airdropLeaves
	} else if index >= airdropLeaves {
		return 0, errors.New("airdrop index is invalid")
	}
	if index >= airdropTreeLeaves {
		return 0, errors.New("airdrop position is invalid")
	}
	return index, nil
}

func (p *airdropProof) verifyMerkle() bool {
	leaf := blake2b.Sum256(p.key)
	if p.isAddress() {
		root := deriveAirdropMerkleRoot(leaf, p.proof, p.index)
		return bytes.Equal(root[:], faucetRoot[:])
	}

	subroot := deriveAirdropMerkleRoot(leaf, p.subproof,
		uint32(p.subindex))
	root := deriveAirdropMerkleRoot(subroot, p.proof, p.index)
	return bytes.Equal(root[:], airdropRoot[:])
}

func (p *airdropProof) verifySignature() bool {
	key, err := parseAirdropKey(p.key)
	if err != nil {
		return false
	}

	if key.keyType != airdropKeyAddress {
		msg := p.signatureHash()
		switch key.keyType {
		case airdropKeyRSA:
			return verifyAirdropRSASignature(key, msg[:],
				p.signature)
		case airdropKeyGoo:
			return verifyAirdropGooSignature(key, msg[:],
				p.signature)
		case airdropKeyP256:
			return verifyAirdropP256Signature(key, msg[:],
				p.signature)
		case airdropKeyED25519:
			return verifyAirdropED25519Signature(key, msg[:],
				p.signature)
		default:
			return false
		}
	}

	fee := airdropRecipientFee
	if key.sponsor {
		fee = airdropSponsorFee
	}

	return p.version == key.version &&
		p.fee == fee &&
		len(p.signature) == 0 &&
		bytes.Equal(p.address, key.address)
}

func (p *airdropProof) signatureHash() [32]byte {
	return sha256.Sum256(p.signatureData())
}

func (p *airdropProof) signatureData() []byte {
	var buf bytes.Buffer
	buf.Write(airdropSignatureContext[:])
	var raw [4]byte
	binary.LittleEndian.PutUint32(raw[:], p.index)
	buf.Write(raw[:])
	buf.WriteByte(byte(len(p.proof)))
	for _, hash := range p.proof {
		buf.Write(hash[:])
	}
	buf.WriteByte(p.subindex)
	buf.WriteByte(byte(len(p.subproof)))
	for _, hash := range p.subproof {
		buf.Write(hash[:])
	}
	writeAirdropVarBytes(&buf, p.key)
	buf.WriteByte(p.version)
	buf.WriteByte(byte(len(p.address)))
	buf.Write(p.address)
	if err := wire.WriteVarInt(&buf, 0, p.fee); err != nil {
		panic("wire.WriteVarInt to bytes.Buffer failed")
	}
	return buf.Bytes()
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
	case airdropKeyRSA:
		size, err := readAirdropU16(r)
		if err != nil {
			return nil, err
		}
		key.n = make([]byte, size)
		if _, err := io.ReadFull(r, key.n); err != nil {
			return nil, err
		}
		expSize, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		key.e = make([]byte, expSize)
		if _, err := io.ReadFull(r, key.e); err != nil {
			return nil, err
		}
		key.nonce = make([]byte, 32)
		if _, err := io.ReadFull(r, key.nonce); err != nil {
			return nil, err
		}
	case airdropKeyGoo:
		key.c1 = make([]byte, airdropGooKeySize)
		if _, err := io.ReadFull(r, key.c1); err != nil {
			return nil, err
		}
	case airdropKeyP256:
		key.point = make([]byte, 33)
		if _, err := io.ReadFull(r, key.point); err != nil {
			return nil, err
		}
		key.nonce = make([]byte, 32)
		if _, err := io.ReadFull(r, key.nonce); err != nil {
			return nil, err
		}
	case airdropKeyED25519:
		key.point = make([]byte, ed25519.PublicKeySize)
		if _, err := io.ReadFull(r, key.point); err != nil {
			return nil, err
		}
		key.nonce = make([]byte, 32)
		if _, err := io.ReadFull(r, key.nonce); err != nil {
			return nil, err
		}
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

func (k *airdropKey) isWeak() bool {
	if k == nil || k.keyType != airdropKeyRSA {
		return false
	}

	return new(big.Int).SetBytes(k.n).BitLen() < strongRSAKeyBits
}

func verifyAirdropRSASignature(key *airdropKey, msg, signature []byte) bool {
	n := new(big.Int).SetBytes(key.n)
	e := new(big.Int).SetBytes(key.e)
	if n.Sign() <= 0 || n.BitLen() < 512 || n.BitLen() > 16384 ||
		e.Sign() <= 0 || !e.IsInt64() {

		return false
	}

	maxInt := int64(^uint(0) >> 1)
	if e.Int64() > maxInt {
		return false
	}
	pubKey := &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}
	return rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, msg,
		signature) == nil
}

func verifyAirdropP256Signature(key *airdropKey, msg, signature []byte) bool {
	if len(signature) != 64 {
		return false
	}
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), key.point)
	if x == nil || y == nil {
		return false
	}
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	if r.Sign() == 0 || s.Sign() == 0 {
		return false
	}
	pubKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}
	return ecdsa.Verify(pubKey, msg, r, s)
}

func verifyAirdropED25519Signature(key *airdropKey, msg,
	signature []byte) bool {

	if len(key.point) != ed25519.PublicKeySize ||
		len(signature) != ed25519.SignatureSize {

		return false
	}
	return ed25519.Verify(ed25519.PublicKey(key.point), msg, signature)
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

func writeAirdropVarBytes(w io.Writer, data []byte) {
	if err := wire.WriteVarInt(w, 0, uint64(len(data))); err != nil {
		panic("wire.WriteVarInt to bytes.Buffer failed")
	}
	if _, err := w.Write(data); err != nil {
		panic("bytes.Buffer Write failed")
	}
}

func readAirdropU16(r *bytes.Reader) (uint16, error) {
	var raw [2]byte
	if _, err := io.ReadFull(r, raw[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(raw[:]), nil
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

func deriveAirdropMerkleRoot(leaf [32]byte, path [][32]byte,
	index uint32) [32]byte {

	sentinel := blake2b.Sum256(nil)
	root := airdropHashLeaf(leaf)

	for _, hash := range path {
		if index&1 == 1 && hash == sentinel {
			return [32]byte{}
		}
		if index&1 == 1 {
			root = airdropHashInternal(hash, root)
		} else {
			root = airdropHashInternal(root, hash)
		}
		index >>= 1
	}

	if index != 0 {
		return [32]byte{}
	}

	return root
}

func airdropHashLeaf(data [32]byte) [32]byte {
	var preimage [33]byte
	copy(preimage[1:], data[:])
	return blake2b.Sum256(preimage[:])
}

func airdropHashInternal(left, right [32]byte) [32]byte {
	var preimage [65]byte
	preimage[0] = 0x01
	copy(preimage[1:33], left[:])
	copy(preimage[33:], right[:])
	return blake2b.Sum256(preimage[:])
}
