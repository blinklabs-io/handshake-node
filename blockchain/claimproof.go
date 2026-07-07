// Copyright (c) 2024-2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"math/bits"
	"strings"

	"github.com/blinklabs-io/handshake-node/chaincfg"
	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/hnsutil"
	"github.com/blinklabs-io/handshake-node/wire"
	"github.com/miekg/dns"
	"golang.org/x/crypto/blake2b"
)

const (
	maxOwnershipProofSize = 10000
	strongRSAKeyBits      = 2041
)

var claimBase32 = base32.StdEncoding.WithPadding(base32.NoPadding)

type ownershipProof struct {
	zones []ownershipZone
}

type ownershipZone struct {
	keys     []dns.RR
	referral []dns.RR
	claim    []dns.RR
}

type claimProofData struct {
	name         string
	target       string
	weak         bool
	commitHash   chainhash.Hash
	commitHeight uint32
	inception    uint32
	expiration   uint32
	fee          uint64
	value        uint64
	version      uint8
	hash         []byte
}

func checkCoinbaseClaimProofSanity(tx *hnsutil.Tx, outputIndex int,
	covenant wire.Covenant) error {

	msgTx := tx.MsgTx()
	if outputIndex >= len(msgTx.TxIn) ||
		len(msgTx.TxIn[outputIndex].Witness) != 1 {

		return badCovenant("coinbase CLAIM witness is missing")
	}

	proof, err := parseOwnershipProof(msgTx.TxIn[outputIndex].Witness[0])
	if err != nil {
		return badCovenant("CLAIM ownership proof is invalid")
	}
	if !proof.isSane() {
		return badCovenant("CLAIM ownership proof is not sane")
	}

	name := covenantItem(covenant, 2)
	if proof.name() != string(name) {
		return badCovenant("CLAIM ownership proof name mismatch")
	}

	flags, _ := covenantU8(covenant, 3)
	weak := flags&1 != 0
	if proof.isWeak() != weak {
		return badCovenant("CLAIM ownership proof weakness mismatch")
	}

	return nil
}

func coinbaseConjuredValue(tx *hnsutil.Tx, height uint32, prevTime int64,
	params *chaincfg.Params) (uint64, error) {

	if !IsCoinBase(tx) {
		return 0, nil
	}

	msgTx := tx.MsgTx()
	var conjured uint64
	seenProofs := make(map[chainhash.Hash]struct{})
	if len(msgTx.TxIn) > 1 {
		seenProofs = make(map[chainhash.Hash]struct{},
			len(msgTx.TxIn)-1)
	}
	for i := 1; i < len(msgTx.TxIn); i++ {
		if i >= len(msgTx.TxOut) {
			return 0, badCovenant("coinbase proof input is unlinked")
		}

		if len(msgTx.TxIn[i].Witness) == 1 {
			proofHash := chainhash.HashH(msgTx.TxIn[i].Witness[0])
			if _, exists := seenProofs[proofHash]; exists {
				return 0, badCovenant("duplicate coinbase proof")
			}
			seenProofs[proofHash] = struct{}{}
		}

		if msgTx.TxOut[i].Covenant.Type != wire.CovenantClaim {
			value, err := verifyCoinbaseAirdropProof(tx, i)
			if err != nil {
				return 0, err
			}

			conjured, err = addCoinbaseConjured(conjured, value)
			if err != nil {
				return 0, err
			}
			continue
		}

		value, err := verifyCoinbaseClaimProof(tx, i, height,
			prevTime, params)
		if err != nil {
			return 0, err
		}

		conjured, err = addCoinbaseConjured(conjured, value)
		if err != nil {
			return 0, err
		}
	}

	return conjured, nil
}

func addCoinbaseConjured(conjured, value uint64) (uint64, error) {
	maxValue := uint64(hnsutil.MaxDoo)
	if conjured > maxValue || value > maxValue-conjured {
		return 0, ruleError(ErrBadCoinbaseValue,
			"coinbase proof value exceeds max money")
	}

	return conjured + value, nil
}

func verifyCoinbaseClaimProof(tx *hnsutil.Tx, outputIndex int, height uint32,
	prevTime int64, params *chaincfg.Params) (uint64, error) {

	msgTx := tx.MsgTx()
	if outputIndex >= len(msgTx.TxIn) ||
		outputIndex >= len(msgTx.TxOut) {

		return 0, badCovenant("coinbase CLAIM proof is unlinked")
	}

	txIn := msgTx.TxIn[outputIndex]
	if len(txIn.Witness) != 1 {
		return 0, badCovenant("coinbase CLAIM witness is invalid")
	}

	txOut := msgTx.TxOut[outputIndex]
	covenant := txOut.Covenant
	if covenant.Type != wire.CovenantClaim {
		return 0, badCovenant("coinbase proof is not a CLAIM")
	}

	claimHeight, ok := covenantU32(covenant, 1)
	if !ok || claimHeight != height {
		return 0, badCovenant("CLAIM covenant has nonlocal height")
	}

	proof, err := parseOwnershipProof(txIn.Witness[0])
	if err != nil {
		return 0, badCovenant("CLAIM ownership proof is invalid")
	}
	if !proof.verifyTimes(prevTime) {
		return 0, badCovenant("CLAIM ownership proof time is invalid")
	}

	data, err := proof.claimData(params)
	if err != nil {
		return 0, err
	}
	if data == nil {
		return 0, badCovenant("CLAIM ownership proof data is invalid")
	}

	if txOut.Address.Version != data.version ||
		!bytes.Equal(txOut.Address.Hash, data.hash) {

		return 0, badCovenant("CLAIM ownership proof address mismatch")
	}

	commitHash, _ := covenantHash(covenant, 4)
	if commitHash != data.commitHash {
		return 0, badCovenant("CLAIM ownership proof commit mismatch")
	}

	commitHeight, _ := covenantU32(covenant, 5)
	if commitHeight != data.commitHeight || data.commitHeight == 0 {
		return 0, badCovenant("CLAIM ownership proof height mismatch")
	}

	if data.value < data.fee {
		return 0, badCovenant("CLAIM ownership proof fee exceeds value")
	}

	outputValue := data.value - data.fee
	if outputValue > uint64(hnsutil.MaxDoo) ||
		txOut.Value != int64(outputValue) {

		return 0, badCovenant("CLAIM output value mismatch")
	}

	if height >= params.NameDeflationHeight {
		if data.commitHeight == 1 {
			maxFee := uint64(1000 * hnsutil.DooPerHNS)
			if data.fee > maxFee {
				return 0, badCovenant("CLAIM fee exceeds deflation cap")
			}
			return data.value, nil
		}
		return outputValue, nil
	}

	return data.value, nil
}

func parseOwnershipProof(serialized []byte) (*ownershipProof, error) {
	if len(serialized) > maxOwnershipProofSize {
		return nil, errors.New("ownership proof too large")
	}
	if len(serialized) == 0 {
		return nil, errors.New("empty ownership proof")
	}

	offset := 0
	zoneCount := int(serialized[offset])
	offset++

	proof := &ownershipProof{
		zones: make([]ownershipZone, 0, zoneCount),
	}
	for i := 0; i < zoneCount; i++ {
		zone, next, err := readOwnershipZone(serialized, offset)
		if err != nil {
			return nil, err
		}
		proof.zones = append(proof.zones, zone)
		offset = next
	}
	if offset != len(serialized) {
		return nil, errors.New("trailing ownership proof data")
	}

	return proof, nil
}

func readOwnershipZone(serialized []byte, offset int) (ownershipZone, int,
	error) {

	var zone ownershipZone
	counts := []*[]dns.RR{&zone.keys, &zone.referral, &zone.claim}
	expects := []uint16{dns.TypeDNSKEY, dns.TypeDS, dns.TypeTXT}

	for i, dest := range counts {
		if offset >= len(serialized) {
			return ownershipZone{}, offset, errors.New(
				"truncated ownership proof zone")
		}

		count := int(serialized[offset])
		offset++
		rrs := make([]dns.RR, 0, count)
		for j := 0; j < count; j++ {
			rr, next, err := readOwnershipRR(serialized, offset,
				expects[i])
			if err != nil {
				return ownershipZone{}, offset, err
			}
			rrs = append(rrs, rr)
			offset = next
		}
		*dest = rrs
	}

	return zone, offset, nil
}

func readOwnershipRR(serialized []byte, offset int, expect uint16) (dns.RR,
	int, error) {

	if err := checkOwnershipRR(serialized, offset, expect); err != nil {
		return nil, offset, err
	}

	rr, next, err := dns.UnpackRR(serialized, offset)
	if err != nil {
		return nil, offset, err
	}

	rrType := rr.Header().Rrtype
	if rrType != expect {
		sig, ok := rr.(*dns.RRSIG)
		if !ok || rrType != dns.TypeRRSIG || sig.TypeCovered != expect {
			return nil, offset, errors.New("unexpected proof record")
		}
	}

	return rr, next, nil
}

func checkOwnershipRR(serialized []byte, offset int, expect uint16) error {
	nameEnd, err := skipUncompressedName(serialized, offset, len(serialized))
	if err != nil {
		return err
	}
	if nameEnd+10 > len(serialized) {
		return errors.New("truncated proof record header")
	}

	rrType := binary.BigEndian.Uint16(serialized[nameEnd : nameEnd+2])
	if rrType != dns.TypeRRSIG {
		if rrType != expect {
			return errors.New("unexpected proof record type")
		}
		return nil
	}

	rdLen := int(binary.BigEndian.Uint16(serialized[nameEnd+8 : nameEnd+10]))
	rdStart := nameEnd + 10
	rdEnd := rdStart + rdLen
	if rdEnd > len(serialized) || rdStart+18 > rdEnd {
		return errors.New("truncated proof signature record")
	}
	if _, err := skipUncompressedName(serialized, rdStart+18, rdEnd); err != nil {
		return err
	}

	return nil
}

func skipUncompressedName(serialized []byte, offset, end int) (int, error) {
	for {
		if offset >= end {
			return offset, errors.New("truncated domain name")
		}

		labelLen := int(serialized[offset])
		offset++
		if labelLen&0xc0 != 0 {
			return offset, errors.New("compressed domain name")
		}
		if labelLen == 0 {
			return offset, nil
		}
		if labelLen > 63 || offset+labelLen > end {
			return offset, errors.New("invalid domain name")
		}
		offset += labelLen
	}
}

func (p *ownershipProof) records() []dns.RR {
	var records []dns.RR
	for _, zone := range p.zones {
		records = append(records, zone.keys...)
		records = append(records, zone.referral...)
		records = append(records, zone.claim...)
	}
	return records
}

func (p *ownershipProof) target() string {
	if len(p.zones) < 2 {
		return "."
	}

	zone := p.zones[len(p.zones)-1]
	if len(zone.claim) == 0 {
		return "."
	}

	return canonicalDNSName(zone.claim[0].Header().Name)
}

func (p *ownershipProof) name() string {
	target := p.target()
	if target == "." {
		return ""
	}

	labels := dns.SplitDomainName(target)
	if len(labels) == 0 {
		return ""
	}
	return labels[0]
}

func (p *ownershipProof) isSane() bool {
	if len(p.zones) < 2 {
		return false
	}

	parent := ""
	for i := range p.zones {
		zone := &p.zones[i]
		isLast := i == len(p.zones)-1
		if !zone.isSane(parent, isLast) {
			return false
		}
		parent = canonicalDNSName(zone.keys[0].Header().Name)
	}

	return true
}

func (z *ownershipZone) isSane(parent string, isLast bool) bool {
	if len(z.keys) == 0 {
		return false
	}
	if isLast {
		if len(z.referral) != 0 || len(z.claim) == 0 {
			return false
		}
	} else if len(z.referral) == 0 || len(z.claim) != 0 {
		return false
	}

	zoneName := canonicalDNSName(z.keys[0].Header().Name)
	zoneLabels := dns.CountLabel(zoneName)
	if !isDNSChild(parent, zoneName) {
		return false
	}

	sawKeys := false
	for _, rr := range z.keys {
		if !sameDNSName(rr.Header().Name, zoneName) {
			return false
		}

		switch typed := rr.(type) {
		case *dns.RRSIG:
			if typed.TypeCovered != dns.TypeDNSKEY ||
				!isValidDNSSECAlgorithm(typed.Algorithm) ||
				int(typed.Labels) != zoneLabels ||
				!sameDNSName(typed.SignerName, zoneName) ||
				sawKeys {

				return false
			}
			sawKeys = true
		case *dns.DNSKEY:
		default:
			return false
		}
	}
	if !sawKeys {
		return false
	}

	if len(z.claim) > 0 && !saneSignedSet(z.claim, zoneName, zoneName,
		dns.TypeTXT, zoneLabels) {

		return false
	}

	if len(z.referral) > 0 {
		dsName := canonicalDNSName(z.referral[0].Header().Name)
		if !isDNSChild(zoneName, dsName) {
			return false
		}
		if !saneSignedSet(z.referral, dsName, zoneName, dns.TypeDS,
			dns.CountLabel(dsName)) {

			return false
		}
	}

	return true
}

func saneSignedSet(rrs []dns.RR, rrName, signer string, covered uint16,
	labels int) bool {

	sawSig := false
	for _, rr := range rrs {
		if !sameDNSName(rr.Header().Name, rrName) {
			return false
		}

		switch typed := rr.(type) {
		case *dns.RRSIG:
			if typed.TypeCovered != covered ||
				!isValidDNSSECAlgorithm(typed.Algorithm) ||
				int(typed.Labels) != labels ||
				!sameDNSName(typed.SignerName, signer) ||
				sawSig {

				return false
			}
			sawSig = true
		case *dns.DS:
			if covered != dns.TypeDS {
				return false
			}
		case *dns.TXT:
			if covered != dns.TypeTXT {
				return false
			}
		default:
			return false
		}
	}

	return sawSig
}

func (p *ownershipProof) verifyTimes(unixTime int64) bool {
	if len(p.zones) < 2 {
		return false
	}

	start, end := p.window()
	if start == 0 && end == 0 {
		return false
	}

	return unixTime >= int64(start) && unixTime <= int64(end)
}

func (p *ownershipProof) window() (uint32, uint32) {
	var start, end uint32
	for _, rr := range p.records() {
		sig, ok := rr.(*dns.RRSIG)
		if !ok {
			continue
		}

		if start == 0 || sig.Inception > start {
			start = sig.Inception
		}
		if end == 0 || sig.Expiration < end {
			end = sig.Expiration
		}
	}
	if start == 0 || end == 0 || start > end {
		return 0, 0
	}
	return start, end
}

func (p *ownershipProof) isWeak() bool {
	for i := range p.zones {
		zone := &p.zones[i]
		if key := extractProofKey(zone.keys, zone.keys); key != nil &&
			isWeakRSAKey(key) {

			return true
		}
		if key := extractProofKey(zone.body(), zone.keys); key != nil &&
			isWeakRSAKey(key) {

			return true
		}
	}

	return false
}

func (z *ownershipZone) body() []dns.RR {
	if len(z.referral) > 0 {
		return z.referral
	}
	return z.claim
}

func extractProofKey(rrs, keys []dns.RR) *dns.DNSKEY {
	sig := firstProofSig(rrs)
	if sig == nil {
		return nil
	}
	return findProofKey(keys, sig.KeyTag)
}

func firstProofSig(rrs []dns.RR) *dns.RRSIG {
	for _, rr := range rrs {
		if sig, ok := rr.(*dns.RRSIG); ok {
			return sig
		}
	}
	return nil
}

func findProofKey(rrs []dns.RR, tag uint16) *dns.DNSKEY {
	for _, rr := range rrs {
		key, ok := rr.(*dns.DNSKEY)
		if !ok {
			continue
		}
		if key.KeyTag() != tag || key.Flags&dns.REVOKE != 0 {
			continue
		}
		return key
	}
	return nil
}

func isWeakRSAKey(key *dns.DNSKEY) bool {
	if !isRSAAlgorithm(key.Algorithm) {
		return false
	}

	keyBits, ok := rsaPublicKeyBits(key.PublicKey)
	return ok && keyBits < strongRSAKeyBits
}

func rsaPublicKeyBits(encoded string) (int, bool) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(raw) == 0 {
		return 0, false
	}

	exponentLen := int(raw[0])
	offset := 1
	if exponentLen == 0 {
		if len(raw) < 3 {
			return 0, false
		}
		exponentLen = int(binary.BigEndian.Uint16(raw[1:3]))
		offset = 3
	}
	if exponentLen <= 0 || offset+exponentLen >= len(raw) {
		return 0, false
	}

	modulus := raw[offset+exponentLen:]
	for len(modulus) > 0 && modulus[0] == 0 {
		modulus = modulus[1:]
	}
	if len(modulus) == 0 {
		return 0, false
	}

	return (len(modulus)-1)*8 + bits.Len8(modulus[0]), true
}

func (p *ownershipProof) claimData(params *chaincfg.Params) (*claimProofData,
	error) {

	if params == nil || params.NameClaimPrefix == "" {
		return nil, badCovenant("missing CLAIM proof prefix")
	}
	if len(p.zones) < 2 {
		return nil, badCovenant("incomplete CLAIM ownership proof")
	}

	zone := p.zones[len(p.zones)-1]
	if len(zone.claim) == 0 {
		return nil, badCovenant("missing CLAIM ownership proof records")
	}

	target := canonicalDNSName(zone.claim[0].Header().Name)
	for _, rr := range zone.claim {
		txt, ok := rr.(*dns.TXT)
		if !ok || len(txt.Txt) == 0 {
			continue
		}
		if !strings.HasPrefix(txt.Txt[0], params.NameClaimPrefix) {
			continue
		}

		return p.parseClaimTXT(target, txt.Txt[0], params)
	}

	return nil, badCovenant("missing CLAIM ownership proof data")
}

func (p *ownershipProof) parseClaimTXT(target, txt string,
	params *chaincfg.Params) (*claimProofData, error) {

	encoded := strings.TrimPrefix(txt, params.NameClaimPrefix)
	raw, err := claimBase32.DecodeString(strings.ToUpper(encoded))
	if err != nil {
		return nil, badCovenant("invalid CLAIM ownership proof data")
	}

	data, err := parseClaimProofPayload(raw)
	if err != nil {
		return nil, err
	}

	name := firstDNSLabel(target)
	entry, ok := reservedNameDB.get(hashName([]byte(name)))
	if !ok {
		return nil, badCovenant("CLAIM proof name is not reserved")
	}
	if target != canonicalDNSName(entry.target) {
		return nil, badCovenant("CLAIM proof target mismatch")
	}
	if data.fee > entry.value {
		return nil, badCovenant("CLAIM fee exceeds reserved value")
	}

	inception, expiration := p.window()
	if inception == 0 && expiration == 0 {
		return nil, badCovenant("CLAIM ownership proof has no window")
	}

	data.name = name
	data.target = target
	data.weak = p.isWeak()
	data.inception = inception
	data.expiration = expiration
	data.value = entry.value
	return data, nil
}

func parseClaimProofPayload(raw []byte) (*claimProofData, error) {
	if len(raw) < 1+1+2+1+chainhash.HashSize+4+4 {
		return nil, badCovenant("CLAIM ownership proof data is truncated")
	}

	offset := 0
	version := raw[offset]
	offset++
	if version > 31 {
		return nil, badCovenant("CLAIM proof address version is invalid")
	}

	hashSize := int(raw[offset])
	offset++
	if hashSize < 2 || hashSize > 40 || offset+hashSize > len(raw) {
		return nil, badCovenant("CLAIM proof address hash is invalid")
	}
	addressHash := append([]byte(nil), raw[offset:offset+hashSize]...)
	offset += hashSize

	r := bytes.NewReader(raw[offset:])
	fee, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return nil, badCovenant("CLAIM proof fee is invalid")
	}
	offset = len(raw) - r.Len()
	if fee > uint64(hnsutil.MaxDoo) {
		return nil, badCovenant("CLAIM proof fee exceeds max money")
	}

	if offset+chainhash.HashSize+4+4 != len(raw) {
		return nil, badCovenant("CLAIM ownership proof data size mismatch")
	}

	var commitHash chainhash.Hash
	copy(commitHash[:], raw[offset:offset+chainhash.HashSize])
	offset += chainhash.HashSize

	commitHeight := binary.LittleEndian.Uint32(raw[offset : offset+4])
	offset += 4

	checksum := blake2b.Sum256(raw[:offset])
	if !bytes.Equal(checksum[:4], raw[offset:offset+4]) {
		return nil, badCovenant("CLAIM ownership proof checksum mismatch")
	}

	return &claimProofData{
		commitHash:   commitHash,
		commitHeight: commitHeight,
		fee:          fee,
		version:      version,
		hash:         addressHash,
	}, nil
}

func firstDNSLabel(name string) string {
	labels := dns.SplitDomainName(name)
	if len(labels) == 0 {
		return ""
	}
	return labels[0]
}

func isDNSChild(parent, child string) bool {
	parent = canonicalDNSName(parent)
	child = canonicalDNSName(child)
	if parent == "" {
		return child == "."
	}
	if dns.CountLabel(child) != dns.CountLabel(parent)+1 {
		return false
	}
	return dns.IsSubDomain(parent, child)
}

func sameDNSName(a, b string) bool {
	return canonicalDNSName(a) == canonicalDNSName(b)
}

func canonicalDNSName(name string) string {
	if name == "" {
		return ""
	}
	return strings.ToLower(dns.Fqdn(name))
}

func isValidDNSSECAlgorithm(algorithm uint8) bool {
	switch algorithm {
	case dns.RSASHA1, dns.RSASHA1NSEC3SHA1, dns.RSASHA256,
		dns.RSASHA512, dns.ECDSAP256SHA256, dns.ECDSAP384SHA384,
		dns.ED25519, dns.ED448:

		return true
	default:
		return false
	}
}

func isRSAAlgorithm(algorithm uint8) bool {
	switch algorithm {
	case dns.RSASHA1, dns.RSASHA1NSEC3SHA1, dns.RSASHA256,
		dns.RSASHA512:

		return true
	default:
		return false
	}
}
