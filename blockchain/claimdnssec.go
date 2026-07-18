// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"bytes"
	"crypto"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"sort"
	"strings"

	ciphergost "github.com/deatil/go-cryptobin/cipher/gost"
	"github.com/deatil/go-cryptobin/hash/gost/gost341194"
	cryptobined448 "github.com/deatil/go-cryptobin/pubkey/ed448"
	"github.com/miekg/dns"
)

const (
	minOwnershipRSAKeyBits = 1017
	maxOwnershipRSAKeyBits = 4096
)

// ownershipRootAnchor returns the sole trust anchor accepted by hsd: ICANN's
// 2017 root KSK. Returning a fresh record prevents consensus validation from
// depending on mutable package state.
func ownershipRootAnchor() *dns.DS {
	return &dns.DS{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeDS,
			Class:  dns.ClassINET,
			Ttl:    172800,
		},
		KeyTag:     20326,
		Algorithm:  dns.RSASHA256,
		DigestType: dns.SHA256,
		Digest: "E06D44B80B8F1D39A95C0B0D7C65D084" +
			"58E880409BBC683457104237C7F8EC8D",
	}
}

// verifySignatures verifies the complete DNSSEC chain from ICANN's root trust
// anchor through each DNSKEY and DS set to the final signed TXT claim. It
// mirrors bns Ownership.verifySignatures with secure mode enabled.
func (p *ownershipProof) verifySignatures() bool {
	if len(p.zones) < 2 {
		return false
	}

	ds := []*dns.DS{ownershipRootAnchor()}
	for i := 0; i < len(p.zones)-1; i++ {
		zone := &p.zones[i]
		if !verifyOwnershipKeys(zone.keys, ds) ||
			!verifyOwnershipRecords(zone.referral, zone.keys) {

			return false
		}
		ds = ownershipDSSet(zone.referral)
	}

	zone := &p.zones[len(p.zones)-1]
	return verifyOwnershipKeys(zone.keys, ds) &&
		verifyOwnershipRecords(zone.claim, zone.keys)
}

func verifyOwnershipKeys(keys []dns.RR, ds []*dns.DS) bool {
	sig, rrset := splitOwnershipSet(keys)
	if sig == nil {
		return false
	}

	ksk := findProofKey(keys, sig.KeyTag)
	if ksk == nil || !verifyOwnershipChain(ksk, keys, ds) {
		return false
	}

	return verifyOwnershipSignature(sig, ksk, rrset)
}

func verifyOwnershipChain(ksk *dns.DNSKEY, keys []dns.RR,
	ds []*dns.DS) bool {

	keyMap := map[uint16]*dns.DNSKEY{ksk.KeyTag(): ksk}
	if ksk.Algorithm == dns.RSASHA256 || ksk.Algorithm == dns.RSASHA512 {
		kskRaw, err := base64.StdEncoding.DecodeString(ksk.PublicKey)
		if err != nil {
			return false
		}
		for _, rr := range keys {
			key, ok := rr.(*dns.DNSKEY)
			if !ok || (key.Algorithm != dns.RSASHA1 &&
				key.Algorithm != dns.RSASHA1NSEC3SHA1) ||
				key.Flags&dns.REVOKE != 0 {

				continue
			}
			raw, err := base64.StdEncoding.DecodeString(key.PublicKey)
			if err != nil || !bytes.Equal(raw, kskRaw) {
				continue
			}
			if _, exists := keyMap[key.KeyTag()]; !exists {
				keyMap[key.KeyTag()] = key
			}
		}
	}

	for _, item := range ds {
		// hsd's secure ownership verifier never permits SHA-1 DS digests.
		if item == nil || item.DigestType == dns.SHA1 {
			continue
		}
		key := keyMap[item.KeyTag]
		if key == nil {
			continue
		}
		computed := ownershipDS(key, item.DigestType)
		if computed == nil || computed.Algorithm != item.Algorithm ||
			!strings.EqualFold(computed.Digest, item.Digest) {

			continue
		}
		return true
	}

	return false
}

func ownershipDS(key *dns.DNSKEY, digestType uint8) *dns.DS {
	if digestType != dns.GOST94 {
		return key.ToDS(digestType)
	}

	copyKey := dns.Copy(key)
	copyKey.Header().Name = canonicalDNSName(copyKey.Header().Name)
	wire := make([]byte, dns.Len(copyKey)+1)
	n, err := dns.PackRR(copyKey, wire, 0, nil, false)
	if err != nil {
		return nil
	}
	rdata := ownershipRData(wire[:n])
	if len(rdata) == 0 {
		return nil
	}
	owner := make([]byte, 255)
	offset, err := dns.PackDomainName(copyKey.Header().Name, owner, 0,
		nil, false)
	if err != nil {
		return nil
	}

	hash := gost341194.New(func(key []byte) cipher.Block {
		block, err := ciphergost.NewCipher(key,
			ciphergost.SboxGostR341194CryptoProParamSet)
		if err != nil {
			panic(err)
		}
		return block
	})
	_, _ = hash.Write(owner[:offset])
	_, _ = hash.Write(rdata)

	return &dns.DS{
		Hdr: dns.RR_Header{
			Name:   key.Hdr.Name,
			Rrtype: dns.TypeDS,
			Class:  key.Hdr.Class,
			Ttl:    key.Hdr.Ttl,
		},
		KeyTag:     key.KeyTag(),
		Algorithm:  key.Algorithm,
		DigestType: digestType,
		Digest:     strings.ToUpper(hex.EncodeToString(hash.Sum(nil))),
	}
}

func verifyOwnershipRecords(rrs, keys []dns.RR) bool {
	sig, rrset := splitOwnershipSet(rrs)
	if sig == nil {
		return false
	}
	key := findProofKey(keys, sig.KeyTag)
	return key != nil && verifyOwnershipSignature(sig, key, rrset)
}

func splitOwnershipSet(rrs []dns.RR) (*dns.RRSIG, []dns.RR) {
	var sig *dns.RRSIG
	rrset := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		if candidate, ok := rr.(*dns.RRSIG); ok {
			sig = candidate
			continue
		}
		rrset = append(rrset, rr)
	}
	if sig == nil || len(rrset) == 0 {
		return nil, nil
	}
	return sig, rrset
}

func ownershipDSSet(rrs []dns.RR) []*dns.DS {
	ds := make([]*dns.DS, 0, len(rrs))
	for _, rr := range rrs {
		if item, ok := rr.(*dns.DS); ok {
			ds = append(ds, item)
		}
	}
	return ds
}

func verifyOwnershipSignature(sig *dns.RRSIG, key *dns.DNSKEY,
	rrset []dns.RR) bool {

	if sig == nil || key == nil || len(rrset) == 0 ||
		!isValidDNSSECAlgorithm(key.Algorithm) ||
		key.Algorithm == dns.RSASHA1 ||
		key.Algorithm == dns.RSASHA1NSEC3SHA1 ||
		sig.KeyTag != key.KeyTag() || sig.Hdr.Class != key.Hdr.Class ||
		sig.Algorithm != key.Algorithm ||
		!sameDNSName(sig.SignerName, key.Hdr.Name) || key.Protocol != 3 {

		return false
	}

	first := rrset[0].Header()
	if first.Class != sig.Hdr.Class || first.Rrtype != sig.TypeCovered {
		return false
	}
	for _, rr := range rrset[1:] {
		hdr := rr.Header()
		if hdr.Class != first.Class || hdr.Rrtype != first.Rrtype ||
			!sameDNSName(hdr.Name, first.Name) {

			return false
		}
	}

	data, ok := ownershipSignatureData(sig, rrset)
	if !ok {
		return false
	}
	signature, err := base64.StdEncoding.DecodeString(sig.Signature)
	if err != nil {
		return false
	}
	publicKey, err := base64.StdEncoding.DecodeString(key.PublicKey)
	if err != nil {
		return false
	}

	switch key.Algorithm {
	case dns.RSASHA256, dns.RSASHA512:
		if !validOwnershipRSAKeySize(key.PublicKey) {
			return false
		}
		var hash crypto.Hash
		if key.Algorithm == dns.RSASHA256 {
			hash = crypto.SHA256
		} else {
			hash = crypto.SHA512
		}
		digest := ownershipDigest(hash, data)
		return digest != nil && verifyOwnershipRSA(publicKey, signature,
			hash, digest)

	case dns.ECDSAP256SHA256, dns.ECDSAP384SHA384:
		curve := elliptic.P256()
		ecdhCurve := ecdh.P256()
		coordinateSize := 32
		hash := crypto.SHA256
		if key.Algorithm == dns.ECDSAP384SHA384 {
			curve = elliptic.P384()
			ecdhCurve = ecdh.P384()
			coordinateSize = 48
			hash = crypto.SHA384
		}
		if len(publicKey) != coordinateSize*2 ||
			len(signature) != coordinateSize*2 {

			return false
		}
		encodedPoint := append([]byte{4}, publicKey...)
		if _, err := ecdhCurve.NewPublicKey(encodedPoint); err != nil {
			return false
		}
		pub := &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(publicKey[:coordinateSize]),
			Y:     new(big.Int).SetBytes(publicKey[coordinateSize:]),
		}
		digest := ownershipDigest(hash, data)
		return digest != nil && ecdsa.Verify(pub, digest,
			new(big.Int).SetBytes(signature[:coordinateSize]),
			new(big.Int).SetBytes(signature[coordinateSize:]))

	case dns.ED25519:
		return verifyOwnershipEd25519(publicKey, signature, data)

	case dns.ED448:
		return verifyOwnershipEd448(publicKey, signature, data)
	}

	return false
}

func verifyOwnershipEd25519(publicKey, signature, data []byte) bool {
	return len(publicKey) == ed25519.PublicKeySize &&
		len(signature) == ed25519.SignatureSize &&
		canonicalEd25519Point(publicKey) &&
		canonicalEd25519Point(signature[:ed25519.PublicKeySize]) &&
		ed25519.Verify(ed25519.PublicKey(publicKey), data, signature)
}

func verifyOwnershipEd448(publicKey, signature, data []byte) bool {
	return len(publicKey) == cryptobined448.PublicKeySize &&
		len(signature) == cryptobined448.SignatureSize &&
		canonicalEd448Point(publicKey) &&
		canonicalEd448Point(signature[:cryptobined448.PublicKeySize]) &&
		cryptobined448.Verify(cryptobined448.PublicKey(publicKey), data,
			signature)
}

func canonicalEd25519Point(encoded []byte) bool {
	if len(encoded) != ed25519.PublicKeySize {
		return false
	}
	// RFC 8032 requires the sign bit to be zero when x is zero. On Ed25519,
	// x is zero for y = 1 and y = -1 (p-1).
	if encoded[len(encoded)-1]&0x80 != 0 {
		isOne := encoded[0] == 1
		for i := 1; i < len(encoded)-1 && isOne; i++ {
			isOne = encoded[i] == 0
		}
		isOne = isOne && encoded[len(encoded)-1]&0x7f == 0
		if isOne {
			return false
		}

		isMinusOne := encoded[0] == 0xec
		for i := 1; i < len(encoded)-1 && isMinusOne; i++ {
			isMinusOne = encoded[i] == 0xff
		}
		isMinusOne = isMinusOne && encoded[len(encoded)-1]&0x7f == 0x7f
		if isMinusOne {
			return false
		}
	}
	// RFC 8032 encodes y little-endian in 255 bits and stores x's sign in
	// the high bit. bcrypto rejects encodings where y >= 2^255-19, while
	// crypto/ed25519 accepts some non-canonical encodings such as p+1.
	prime := [ed25519.PublicKeySize]byte{0xed}
	for i := 1; i < len(prime)-1; i++ {
		prime[i] = 0xff
	}
	prime[len(prime)-1] = 0x7f
	for i := len(encoded) - 1; i >= 0; i-- {
		value := encoded[i]
		if i == len(encoded)-1 {
			value &= 0x7f
		}
		if value < prime[i] {
			return true
		}
		if value > prime[i] {
			return false
		}
	}
	return false
}

func canonicalEd448Point(encoded []byte) bool {
	if len(encoded) != cryptobined448.PublicKeySize {
		return false
	}
	// RFC 8032 encodes Ed448's 448-bit y-coordinate in 57 little-endian
	// bytes and reserves the high byte's low seven bits. CIRCL ignores those
	// bits, while bcrypto rejects them.
	if encoded[len(encoded)-1]&0x7f != 0 {
		return false
	}

	// Reject y >= p, where p = 2^448 - 2^224 - 1. The sign bit is in the
	// otherwise-unused high byte and is therefore outside this comparison.
	prime := [cryptobined448.PublicKeySize]byte{}
	for i := 0; i < len(prime)-1; i++ {
		prime[i] = 0xff
	}
	prime[28] = 0xfe
	for i := len(prime) - 2; i >= 0; i-- {
		if encoded[i] < prime[i] {
			break
		}
		if encoded[i] > prime[i] {
			return false
		}
		if i == 0 {
			return false
		}
	}

	// The sign of x must be zero when x is zero. On Ed448, x is zero for
	// y = 1 and y = -1 (p-1).
	if encoded[len(encoded)-1]&0x80 != 0 {
		isOne := encoded[0] == 1
		for i := 1; i < len(encoded)-1 && isOne; i++ {
			isOne = encoded[i] == 0
		}
		if isOne {
			return false
		}

		isMinusOne := encoded[0] == 0xfe
		for i := 1; i < 28 && isMinusOne; i++ {
			isMinusOne = encoded[i] == 0xff
		}
		if isMinusOne {
			isMinusOne = encoded[28] == 0xfe
		}
		for i := 29; i < len(encoded)-1 && isMinusOne; i++ {
			isMinusOne = encoded[i] == 0xff
		}
		if isMinusOne {
			return false
		}
	}

	return true
}

func validOwnershipRSAKeySize(encoded string) bool {
	keyBits, ok := rsaPublicKeyBits(encoded)
	return ok && keyBits >= minOwnershipRSAKeyBits &&
		keyBits <= maxOwnershipRSAKeyBits
}

func ownershipDigest(hash crypto.Hash, data []byte) []byte {
	switch hash {
	case crypto.SHA256:
		sum := sha256.Sum256(data)
		return sum[:]
	case crypto.SHA384:
		sum := sha512.Sum384(data)
		return sum[:]
	case crypto.SHA512:
		sum := sha512.Sum512(data)
		return sum[:]
	default:
		return nil
	}
}

func ownershipRSAPublicKey(raw []byte) (*big.Int, *big.Int, bool) {
	if len(raw) == 0 {
		return nil, nil, false
	}
	exponentLen := int(raw[0])
	offset := 1
	if exponentLen == 0 {
		if len(raw) < 3 {
			return nil, nil, false
		}
		exponentLen = int(binary.BigEndian.Uint16(raw[1:3]))
		offset = 3
	}
	if exponentLen == 0 || offset+exponentLen >= len(raw) {

		return nil, nil, false
	}
	exponent := new(big.Int).SetBytes(raw[offset : offset+exponentLen])
	modulus := new(big.Int).SetBytes(raw[offset+exponentLen:])
	if modulus.BitLen() < minOwnershipRSAKeyBits ||
		modulus.BitLen() > maxOwnershipRSAKeyBits || modulus.Bit(0) == 0 ||
		exponent.BitLen() > 33 || exponent.Cmp(big.NewInt(3)) < 0 ||
		exponent.Bit(0) == 0 {

		return nil, nil, false
	}
	return modulus, exponent, true
}

func verifyOwnershipRSA(rawPublicKey, signature []byte, hash crypto.Hash,
	digest []byte) bool {

	modulus, exponent, ok := ownershipRSAPublicKey(rawPublicKey)
	if !ok {
		return false
	}
	size := (modulus.BitLen() + 7) / 8
	if len(signature) > size {
		return false
	}
	signatureInt := new(big.Int).SetBytes(signature)
	if signatureInt.Cmp(modulus) >= 0 {
		return false
	}

	encodedInt := new(big.Int).Exp(signatureInt, exponent, modulus)
	encodedRaw := encodedInt.Bytes()
	encoded := make([]byte, size)
	copy(encoded[size-len(encodedRaw):], encodedRaw)

	var prefix []byte
	switch hash {
	case crypto.SHA256:
		prefix, _ = hex.DecodeString("3031300d060960864801650304020105000420")
	case crypto.SHA512:
		prefix, _ = hex.DecodeString("3051300d060960864801650304020305000440")
	default:
		return false
	}
	tailSize := len(prefix) + len(digest)
	if size < tailSize+11 {
		return false
	}
	expected := make([]byte, size)
	expected[0] = 0
	expected[1] = 1
	paddingEnd := size - tailSize - 1
	for i := 2; i < paddingEnd; i++ {
		expected[i] = 0xff
	}
	expected[paddingEnd] = 0
	copy(expected[paddingEnd+1:], prefix)
	copy(expected[size-len(digest):], digest)
	return bytes.Equal(encoded, expected)
}

func ownershipSignatureData(sig *dns.RRSIG, rrset []dns.RR) ([]byte, bool) {
	data := make([]byte, 18, 18+255)
	binary.BigEndian.PutUint16(data[0:2], sig.TypeCovered)
	data[2] = sig.Algorithm
	data[3] = sig.Labels
	binary.BigEndian.PutUint32(data[4:8], sig.OrigTtl)
	binary.BigEndian.PutUint32(data[8:12], sig.Expiration)
	binary.BigEndian.PutUint32(data[12:16], sig.Inception)
	binary.BigEndian.PutUint16(data[16:18], sig.KeyTag)

	nameWire := make([]byte, 255)
	offset, err := dns.PackDomainName(canonicalDNSName(sig.SignerName),
		nameWire, 0, nil, false)
	if err != nil {
		return nil, false
	}
	data = append(data, nameWire[:offset]...)

	wires := make([][]byte, 0, len(rrset))
	for _, rr := range rrset {
		copyRR := dns.Copy(rr)
		hdr := copyRR.Header()
		labels := dns.SplitDomainName(hdr.Name)
		if len(labels) < int(sig.Labels) {
			return nil, false
		}
		if len(labels) > int(sig.Labels) {
			hdr.Name = "*." +
				strings.Join(labels[len(labels)-int(sig.Labels):], ".") + "."
		}
		hdr.Name = canonicalDNSName(hdr.Name)
		hdr.Ttl = sig.OrigTtl

		wire := make([]byte, dns.Len(copyRR)+1)
		n, err := dns.PackRR(copyRR, wire, 0, nil, false)
		if err != nil {
			return nil, false
		}
		wires = append(wires, wire[:n])
	}

	sort.Slice(wires, func(i, j int) bool {
		return bytes.Compare(ownershipRData(wires[i]),
			ownershipRData(wires[j])) < 0
	})
	for i, wire := range wires {
		if i > 0 && bytes.Equal(wire, wires[i-1]) {
			continue
		}
		data = append(data, wire...)
	}
	return data, true
}

func ownershipRData(wire []byte) []byte {
	_, offset, err := dns.UnpackDomainName(wire, 0)
	if err != nil || offset+10 > len(wire) {
		return wire
	}
	return wire[offset+10:]
}
