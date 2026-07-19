// Copyright (c) 2024-2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockchain

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/blinklabs-io/handshake-node/chaincfg"
	"github.com/blinklabs-io/handshake-node/chaincfg/chainhash"
	"github.com/blinklabs-io/handshake-node/hnsutil"
	"github.com/blinklabs-io/handshake-node/wire"
	"github.com/cloudflare/circl/sign/ed448"
	"github.com/miekg/dns"
	"golang.org/x/crypto/blake2b"
)

func TestOwnershipProofVerifySignaturesMainnet(t *testing.T) {
	// This is the namecheap CLAIM witness mined by hsd in mainnet block
	// 62,517 (coinbase input/output index 2). Unlike hsd's regtest ownership
	// fixtures, its hns-claim TXT is part of the signed RRset.
	serialized := testMainnetClaimProof(t)
	proof, err := parseOwnershipProof(serialized)
	if err != nil {
		t.Fatalf("parseOwnershipProof: %v", err)
	}
	if !proof.isSane() {
		t.Fatal("mainnet ownership proof is not sane")
	}
	if !proof.verifySignatures() {
		t.Fatal("mainnet ownership proof signatures are invalid")
	}

	start, end := proof.window()
	relay, err := CoinbaseClaimProofFromRaw(serialized, 62517,
		int64(start+(end-start)/2), &chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("CoinbaseClaimProofFromRaw: %v", err)
	}
	if relay.Output.Covenant.Type != wire.CovenantClaim ||
		string(relay.Output.Covenant.Items[2]) != "namecheap" {

		t.Fatalf("claim covenant = %#v, want namecheap CLAIM",
			relay.Output.Covenant)
	}
}

func TestVerifyOwnershipSignatureEd448(t *testing.T) {
	publicKey, privateKey, err := ed448.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	name := "claim.example."
	key := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Flags:     dns.ZONE,
		Protocol:  3,
		Algorithm: dns.ED448,
		PublicKey: base64.StdEncoding.EncodeToString(publicKey),
	}
	rrset := []dns.RR{&dns.TXT{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Txt: []string{"hns-claim:ed448-test"},
	}}
	sig := &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeRRSIG,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		TypeCovered: dns.TypeTXT,
		Algorithm:   dns.ED448,
		Labels:      uint8(dns.CountLabel(name)),
		OrigTtl:     3600,
		Expiration:  200,
		Inception:   100,
		KeyTag:      key.KeyTag(),
		SignerName:  name,
	}
	data, ok := ownershipSignatureData(sig, rrset)
	if !ok {
		t.Fatal("ownershipSignatureData failed")
	}
	sig.Signature = base64.StdEncoding.EncodeToString(
		ed448.Sign(privateKey, data, ""))
	if !verifyOwnershipSignature(sig, key, rrset) {
		t.Fatal("valid ED448 signature was rejected")
	}

	signature, err := base64.StdEncoding.DecodeString(sig.Signature)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	signature[len(signature)-1] ^= 1
	sig.Signature = base64.StdEncoding.EncodeToString(signature)
	if verifyOwnershipSignature(sig, key, rrset) {
		t.Fatal("mutated ED448 signature was accepted")
	}
}

func TestOwnershipEdDSAHsdParity(t *testing.T) {
	message := []byte("hsd-edwards-identity-parity")
	t.Run("Ed25519", func(t *testing.T) {
		size := ed25519.PublicKeySize
		identity := make([]byte, size)
		identity[0] = 1
		zero := make([]byte, size)
		prime := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255),
			big.NewInt(19))
		order := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 252),
			mustBigInt(t, "27742317777372353535851937790883648493"))
		testEdDSAHsdCases(t, size, identity, zero, prime,
			testLittleEndianInt(order, size),
			func(key, sig []byte) bool {
				return verifyOwnershipEd25519(key, sig, message)
			})
	})

	t.Run("Ed448", func(t *testing.T) {
		size := ed448.PublicKeySize
		identity := make([]byte, size)
		identity[0] = 1
		zero := make([]byte, size)
		prime := new(big.Int).Sub(
			new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 448),
				new(big.Int).Lsh(big.NewInt(1), 224)), big.NewInt(1))
		order := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 446),
			mustBigInt(t, "13818066809895115352007386748515426880336692474882178609894547503885"))
		testEdDSAHsdCases(t, size, identity, zero, prime,
			testLittleEndianInt(order, size),
			func(key, sig []byte) bool {
				return verifyOwnershipEd448(key, sig, message)
			})

		// Pinned hsd v8.0.0 (bcrypto v5.4.0) native and JS backends
		// produce this exact message-dependent pattern for the order-two
		// public key A=(0,-1), R=identity, S=0. This exercises bcrypto's
		// cofactor-less equation rather than CIRCL's torsion-removing path.
		orderTwo := testLittleEndianInt(
			new(big.Int).Sub(prime, big.NewInt(1)), size)
		orderTwoSignature := append(append([]byte(nil), identity...), zero...)
		orderTwoResults := [...]bool{
			false, false, true, true, true, true, false, false,
			false, false, true, true, false, true, true, true,
			false, true, true, false, false, true, true, true,
			false, true, false, true, false, false, true, true,
		}
		for i, want := range orderTwoResults {
			msg := []byte(fmt.Sprintf("hsd-ed448-order-two-parity-%02d", i))
			t.Run(fmt.Sprintf("order-two-message-%02d", i), func(t *testing.T) {
				if got := verifyOwnershipEd448(orderTwo,
					orderTwoSignature, msg); got != want {

					t.Fatalf("verification = %v, want hsd result %v", got, want)
				}
			})
		}

		makeSignature := func(point []byte) []byte {
			signature := append([]byte(nil), point...)
			return append(signature, zero...)
		}
		for bit := byte(1); bit < 0x80; bit <<= 1 {
			t.Run(fmt.Sprintf("key-unused-bit-%02x", bit), func(t *testing.T) {
				key := append([]byte(nil), identity...)
				key[len(key)-1] |= bit
				if verifyOwnershipEd448(key, makeSignature(identity), message) {
					t.Fatal("non-canonical ED448 public key was accepted")
				}
			})
			t.Run(fmt.Sprintf("R-unused-bit-%02x", bit), func(t *testing.T) {
				point := append([]byte(nil), identity...)
				point[len(point)-1] |= bit
				if verifyOwnershipEd448(identity, makeSignature(point), message) {
					t.Fatal("non-canonical ED448 R point was accepted")
				}
			})
		}
	})
}

func testEdDSAHsdCases(t *testing.T, size int, identity, zero []byte,
	prime *big.Int, scalarOrder []byte, verify func([]byte, []byte) bool) {

	t.Helper()
	makeSignature := func(point, scalar []byte) []byte {
		signature := append([]byte(nil), point...)
		return append(signature, scalar...)
	}
	primeMinusOne := testLittleEndianInt(
		new(big.Int).Sub(prime, big.NewInt(1)), size)
	primeEncoded := testLittleEndianInt(prime, size)
	primePlusOne := testLittleEndianInt(
		new(big.Int).Add(prime, big.NewInt(1)), size)
	negativeIdentity := append([]byte(nil), identity...)
	negativeIdentity[len(negativeIdentity)-1] |= 0x80
	negativeOrderTwo := append([]byte(nil), primeMinusOne...)
	negativeOrderTwo[len(negativeOrderTwo)-1] |= 0x80
	for _, test := range []struct {
		name      string
		key       []byte
		signature []byte
		want      bool
	}{
		{"identity", identity, makeSignature(identity, zero), true},
		{"key-p-minus-one", primeMinusOne,
			makeSignature(identity, zero), false},
		{"R-p-minus-one", identity,
			makeSignature(primeMinusOne, zero), false},
		{"key-p", primeEncoded,
			makeSignature(identity, zero), false},
		{"R-p", identity,
			makeSignature(primeEncoded, zero), false},
		{"key-p-plus-one", primePlusOne,
			makeSignature(identity, zero), false},
		{"R-p-plus-one", identity,
			makeSignature(primePlusOne, zero), false},
		{"key-negative-identity", negativeIdentity,
			makeSignature(identity, zero), false},
		{"R-negative-identity", identity,
			makeSignature(negativeIdentity, zero), false},
		{"key-negative-order-two", negativeOrderTwo,
			makeSignature(identity, zero), false},
		{"R-negative-order-two", identity,
			makeSignature(negativeOrderTwo, zero), false},
		{"scalar-order", identity,
			makeSignature(identity, scalarOrder), false},
		{"scalar-all-ff", identity,
			makeSignature(identity, bytes.Repeat([]byte{0xff}, size)), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := verify(test.key, test.signature); got != test.want {
				t.Fatalf("verification = %v, want hsd result %v", got,
					test.want)
			}
		})
	}
}

func mustBigInt(t *testing.T, decimal string) *big.Int {
	t.Helper()
	value, ok := new(big.Int).SetString(decimal, 10)
	if !ok {
		t.Fatalf("invalid big integer %q", decimal)
	}
	return value
}

func testLittleEndianInt(value *big.Int, size int) []byte {
	raw := value.Bytes()
	encoded := make([]byte, size)
	for i := range raw {
		encoded[i] = raw[len(raw)-1-i]
	}
	return encoded
}

func TestVerifyOwnershipSignatureSupportedAlgorithms(t *testing.T) {
	for _, test := range []struct {
		name      string
		algorithm uint8
		bits      int
	}{
		{"RSA-SHA256", dns.RSASHA256, 1024},
		{"RSA-SHA512", dns.RSASHA512, 1024},
		{"ECDSA-P256", dns.ECDSAP256SHA256, 256},
		{"ECDSA-P384", dns.ECDSAP384SHA384, 384},
		{"ED25519", dns.ED25519, 256},
	} {
		t.Run(test.name, func(t *testing.T) {
			key, sig, rrset := testSignedOwnershipRRSet(t,
				test.algorithm, test.bits)
			if !verifyOwnershipSignature(sig, key, rrset) {
				t.Fatal("valid signature was rejected")
			}
		})
	}
}

func TestOwnershipECDSAHsdParity(t *testing.T) {
	for _, test := range []struct {
		name      string
		algorithm uint8
		bits      int
		prime     *big.Int
		order     *big.Int
	}{
		{"P256", dns.ECDSAP256SHA256, 256, elliptic.P256().Params().P,
			elliptic.P256().Params().N},
		{"P384", dns.ECDSAP384SHA384, 384, elliptic.P384().Params().P,
			elliptic.P384().Params().N},
	} {
		t.Run(test.name, func(t *testing.T) {
			key, sig, rrset := testSignedOwnershipRRSet(t,
				test.algorithm, test.bits)
			raw, err := base64.StdEncoding.DecodeString(sig.Signature)
			if err != nil {
				t.Fatalf("decode signature: %v", err)
			}
			size := test.bits / 8
			if len(raw) != size*2 {
				t.Fatalf("signature size = %d, want %d", len(raw), size*2)
			}
			r := new(big.Int).SetBytes(raw[:size])
			s := new(big.Int).SetBytes(raw[size:])
			encodeScalar := func(value *big.Int) []byte {
				encoded := make([]byte, size)
				rawValue := value.Bytes()
				copy(encoded[size-len(rawValue):], rawValue)
				return encoded
			}
			publicRaw, err := base64.StdEncoding.DecodeString(key.PublicKey)
			if err != nil || len(publicRaw) != size*2 {
				t.Fatalf("decode public key: size=%d err=%v", len(publicRaw), err)
			}
			zero := make([]byte, size)
			one := make([]byte, size)
			one[len(one)-1] = 1
			prime := encodeScalar(test.prime)
			for _, point := range []struct {
				name string
				x    []byte
				y    []byte
				want bool
			}{
				{"valid", publicRaw[:size], publicRaw[size:], true},
				{"x-zero", zero, publicRaw[size:], false},
				{"y-zero", publicRaw[:size], zero, false},
				{"x-field-prime", prime, publicRaw[size:], false},
				{"y-field-prime", publicRaw[:size], prime, false},
				{"off-curve-one-one", one, one, false},
			} {
				t.Run("point-"+point.name, func(t *testing.T) {
					copyKey := *key
					encoded := append(append([]byte(nil), point.x...),
						point.y...)
					copyKey.PublicKey = base64.StdEncoding.EncodeToString(encoded)
					if got := verifyOwnershipSignature(sig, &copyKey,
						rrset); got != point.want {

						t.Fatalf("verification = %v, want hsd result %v",
							got, point.want)
					}
				})
			}
			for _, mutation := range []struct {
				name string
				r    *big.Int
				s    *big.Int
				want bool
			}{
				{"zero-r", big.NewInt(0), s, false},
				{"zero-s", r, big.NewInt(0), false},
				{"out-of-range-r", test.order, s, false},
				{"out-of-range-s", r, test.order, false},
				{"high-s", r, new(big.Int).Sub(test.order, s), true},
			} {
				t.Run(mutation.name, func(t *testing.T) {
					mutated := append(encodeScalar(mutation.r),
						encodeScalar(mutation.s)...)
					copySig := *sig
					copySig.Signature = base64.StdEncoding.EncodeToString(mutated)
					if got := verifyOwnershipSignature(&copySig, key,
						rrset); got != mutation.want {

						t.Fatalf("verification = %v, want hsd result %v",
							got, mutation.want)
					}
				})
			}
		})
	}
}

func TestVerifyOwnershipSignatureRejectsSHA1(t *testing.T) {
	for _, algorithm := range []uint8{
		dns.RSASHA1,
		dns.RSASHA1NSEC3SHA1,
	} {
		t.Run(dns.AlgorithmToString[algorithm], func(t *testing.T) {
			key, sig, rrset := testSignedOwnershipRRSet(t, algorithm, 1024)
			if err := sig.Verify(key, rrset); err != nil {
				t.Fatalf("test fixture is not a valid SHA-1 signature: %v", err)
			}
			if verifyOwnershipSignature(sig, key, rrset) {
				t.Fatal("SHA-1 signature was accepted in secure mode")
			}
		})
	}
}

func TestVerifyOwnershipRSAAcceptsShortSignature(t *testing.T) {
	name := "claim.example."
	key := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Flags:     dns.ZONE,
		Protocol:  3,
		Algorithm: dns.RSASHA256,
	}
	privateKey, err := key.Generate(1024)
	if err != nil {
		t.Fatalf("DNSKEY.Generate: %v", err)
	}
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		t.Fatalf("DNSKEY.Generate returned %T, want crypto.Signer", privateKey)
	}
	rr := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
	}
	rrset := []dns.RR{rr}
	sig := &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeRRSIG,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		TypeCovered: dns.TypeTXT,
		Algorithm:   dns.RSASHA256,
		Labels:      uint8(dns.CountLabel(name)),
		OrigTtl:     3600,
		Expiration:  200,
		Inception:   100,
		KeyTag:      key.KeyTag(),
		SignerName:  name,
	}

	for i := 0; i < 4096; i++ {
		rr.Txt = []string{fmt.Sprintf("hns-claim:short-rsa-%d", i)}
		if err := sig.Sign(signer, rrset); err != nil {
			t.Fatalf("RRSIG.Sign: %v", err)
		}
		raw, err := base64.StdEncoding.DecodeString(sig.Signature)
		if err != nil {
			t.Fatalf("decode RRSIG signature: %v", err)
		}
		if len(raw) == 0 || raw[0] != 0 {
			continue
		}
		for len(raw) > 0 && raw[0] == 0 {
			raw = raw[1:]
		}
		sig.Signature = base64.StdEncoding.EncodeToString(raw)
		if !verifyOwnershipSignature(sig, key, rrset) {
			t.Fatal("valid RSA signature with omitted leading zero was rejected")
		}
		return
	}
	t.Fatal("could not generate an RSA signature with a leading zero")
}

func TestOwnershipRSAPublicKeyHsdParity(t *testing.T) {
	for _, test := range []struct {
		name         string
		bits         int
		exponent     uint64
		oddModulus   bool
		wantAccepted bool
	}{
		{"minimum-minus-one", 1016, 65537, true, false},
		{"minimum", 1017, 65537, true, true},
		{"maximum", 4096, 65537, true, true},
		{"maximum-plus-one", 4097, 65537, true, false},
		{"exponent-two", 1024, 2, true, false},
		{"even-exponent", 1024, 4, true, false},
		{"exponent-three", 1024, 3, true, true},
		{"33-bit-exponent", 1024, 1<<32 + 1, true, true},
		{"34-bit-exponent", 1024, 1<<33 + 1, true, false},
		{"even-modulus", 1024, 65537, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := testRawRSAPublicKey(test.bits, test.exponent,
				test.oddModulus)
			_, _, accepted := ownershipRSAPublicKey(raw)
			if accepted != test.wantAccepted {
				t.Fatalf("ownershipRSAPublicKey accepted = %v, want %v",
					accepted, test.wantAccepted)
			}
		})
	}
}

func testSignedOwnershipRRSet(t *testing.T, algorithm uint8,
	bits int) (*dns.DNSKEY, *dns.RRSIG, []dns.RR) {

	t.Helper()
	name := "claim.example."
	key := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Flags:     dns.ZONE,
		Protocol:  3,
		Algorithm: algorithm,
	}
	privateKey, err := key.Generate(bits)
	if err != nil {
		t.Fatalf("DNSKEY.Generate: %v", err)
	}
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		t.Fatalf("DNSKEY.Generate returned %T, want crypto.Signer", privateKey)
	}
	rrset := []dns.RR{&dns.TXT{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Txt: []string{"hns-claim:algorithm-test"},
	}}
	sig := &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeRRSIG,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		TypeCovered: dns.TypeTXT,
		Algorithm:   algorithm,
		Labels:      uint8(dns.CountLabel(name)),
		OrigTtl:     3600,
		Expiration:  200,
		Inception:   100,
		KeyTag:      key.KeyTag(),
		SignerName:  name,
	}
	if err := sig.Sign(signer, rrset); err != nil {
		t.Fatalf("RRSIG.Sign: %v", err)
	}
	return key, sig, rrset
}

func TestOwnershipSecureAlgorithmRules(t *testing.T) {
	key := testDNSKEY(".", 2048)
	sha256DS := key.ToDS(dns.SHA256)
	if sha256DS == nil || !verifyOwnershipChain(key,
		[]dns.RR{key}, []*dns.DS{sha256DS}) {

		t.Fatal("valid SHA-256 DS chain was rejected")
	}
	sha1DS := *sha256DS
	sha1DS.DigestType = dns.SHA1
	if verifyOwnershipChain(key, []dns.RR{key}, []*dns.DS{&sha1DS}) {
		t.Fatal("SHA-1 DS chain was accepted in secure mode")
	}

	proof := mustParseOwnershipProof(t, testMainnetClaimProof(t))
	var rootKey *dns.DNSKEY
	for _, rr := range proof.zones[0].keys {
		if candidate, ok := rr.(*dns.DNSKEY); ok {
			rootKey = candidate
			break
		}
	}
	if rootKey == nil {
		t.Fatal("mainnet fixture has no root DNSKEY")
	}
	gostDS := ownershipDS(rootKey, dns.GOST94)
	const hsdGOSTDigest = "F9A5422BA5DEEBCD8D44B77C9E33CD8D" +
		"091948013BC167DDFE65D3FCC4656020"
	if gostDS == nil || gostDS.Digest != hsdGOSTDigest {
		t.Fatalf("GOST94 DS digest = %v, want %s", gostDS, hsdGOSTDigest)
	}
	if !verifyOwnershipChain(rootKey, proof.zones[0].keys,
		[]*dns.DS{gostDS}) {

		t.Fatal("valid GOST94 DS chain was rejected")
	}

	for _, test := range []struct {
		bits int
		want bool
	}{
		{1016, false},
		{1017, true},
		{4096, true},
		{4097, false},
	} {
		t.Run(fmt.Sprintf("RSA-%d", test.bits), func(t *testing.T) {
			if got := validOwnershipRSAKeySize(
				testRSAPublicKey(test.bits)); got != test.want {

				t.Fatalf("validOwnershipRSAKeySize = %v, want %v",
					got, test.want)
			}
		})
	}
}

func TestOwnershipProofWindowHsdParity(t *testing.T) {
	for _, test := range []struct {
		name       string
		inception  uint32
		expiration uint32
		unixTime   int64
		wantStart  uint32
		wantEnd    uint32
		wantValid  bool
	}{
		{"zero-inception", 0, 100, 50, 0, 100, true},
		{"zero-expiration", 0, 0, 0, 0, 0, true},
		{"zero-expiration-after-zero", 0, 0, 1, 0, 0, false},
		{"crossed-window-at-zero", 100, 50, 0, 0, 0, true},
		{"crossed-window-after-zero", 100, 50, 75, 0, 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			proof := mustParseOwnershipProof(t, testOwnershipProof(t,
				"com", false, "hns-claim:window-test", test.inception,
				test.expiration))
			start, end := proof.window()
			if start != test.wantStart || end != test.wantEnd {
				t.Fatalf("window = [%d,%d], want [%d,%d]", start, end,
					test.wantStart, test.wantEnd)
			}
			if got := proof.verifyTimes(test.unixTime); got != test.wantValid {
				t.Fatalf("verifyTimes(%d) = %v, want %v", test.unixTime,
					got, test.wantValid)
			}
		})
	}
}

func TestOwnershipProofVerifySignaturesRejectsMutations(t *testing.T) {
	serialized := testMainnetClaimProof(t)

	t.Run("RRSIG signatures", func(t *testing.T) {
		testEachOwnershipRecordMutation(t, serialized,
			func(rr dns.RR) bool {
				_, ok := rr.(*dns.RRSIG)
				return ok
			}, func(t *testing.T, rr dns.RR) {
				sig := rr.(*dns.RRSIG)
				raw, err := base64.StdEncoding.DecodeString(sig.Signature)
				if err != nil || len(raw) == 0 {
					t.Fatalf("decode RRSIG signature: %v", err)
				}
				raw[len(raw)-1] ^= 1
				sig.Signature = base64.StdEncoding.EncodeToString(raw)
			})
	})

	t.Run("DNSKEY public keys", func(t *testing.T) {
		testEachOwnershipRecordMutation(t, serialized,
			func(rr dns.RR) bool {
				_, ok := rr.(*dns.DNSKEY)
				return ok
			}, func(t *testing.T, rr dns.RR) {
				key := rr.(*dns.DNSKEY)
				raw, err := base64.StdEncoding.DecodeString(key.PublicKey)
				if err != nil || len(raw) == 0 {
					t.Fatalf("decode DNSKEY public key: %v", err)
				}
				raw[len(raw)-1] ^= 1
				key.PublicKey = base64.StdEncoding.EncodeToString(raw)
			})
	})

	t.Run("DS digests", func(t *testing.T) {
		testEachOwnershipRecordMutation(t, serialized,
			func(rr dns.RR) bool {
				item, ok := rr.(*dns.DS)
				return ok && len(item.Digest) > 0
			}, func(_ *testing.T, rr dns.RR) {
				item := rr.(*dns.DS)
				if item.Digest[0] == '0' {
					item.Digest = "1" + item.Digest[1:]
				} else {
					item.Digest = "0" + item.Digest[1:]
				}
			})
	})

	t.Run("signed claim TXT", func(t *testing.T) {
		testEachOwnershipRecordMutation(t, serialized,
			func(rr dns.RR) bool {
				txt, ok := rr.(*dns.TXT)
				return ok && len(txt.Txt) > 0 && len(txt.Txt[0]) > 0
			}, func(_ *testing.T, rr dns.RR) {
				txt := rr.(*dns.TXT)
				last := len(txt.Txt[0]) - 1
				if txt.Txt[0][last] == 'a' {
					txt.Txt[0] = txt.Txt[0][:last] + "b"
				} else {
					txt.Txt[0] = txt.Txt[0][:last] + "a"
				}
			})
	})
}

func testEachOwnershipRecordMutation(t *testing.T, serialized []byte,
	matches func(dns.RR) bool, mutate func(*testing.T, dns.RR)) {

	t.Helper()
	base := mustParseOwnershipProof(t, serialized)
	total := 0
	for _, rr := range base.records() {
		if matches(rr) {
			total++
		}
	}
	if total == 0 {
		t.Fatal("fixture has no matching records to mutate")
	}

	for target := 0; target < total; target++ {
		t.Run(fmt.Sprintf("record-%d", target), func(t *testing.T) {
			proof := mustParseOwnershipProof(t, serialized)
			current := 0
			mutated := false
			for _, rr := range proof.records() {
				if !matches(rr) {
					continue
				}
				if current == target {
					mutate(t, rr)
					mutated = true
					break
				}
				current++
			}
			if !mutated {
				t.Fatal("target record was not mutated")
			}
			if !proof.isSane() {
				t.Fatal("structurally valid mutation failed sanity")
			}
			if proof.verifySignatures() {
				t.Fatal("mutated record passed signature verification")
			}
		})
	}
}

func TestCoinbaseClaimProofFromRawRejectsSignatureMutation(t *testing.T) {
	serialized := testMainnetClaimProof(t)
	proof := mustParseOwnershipProof(t, serialized)
	claimSig := firstProofSig(proof.zones[len(proof.zones)-1].claim)
	if claimSig == nil {
		t.Fatal("missing claim signature")
	}
	signature, err := base64.StdEncoding.DecodeString(claimSig.Signature)
	if err != nil || len(signature) == 0 {
		t.Fatalf("decode claim signature: %v", err)
	}
	signature[len(signature)-1] ^= 1
	claimSig.Signature = base64.StdEncoding.EncodeToString(signature)
	mutated := serializeOwnershipProof(t, proof)
	start, end := proof.window()

	_, err = CoinbaseClaimProofFromRaw(mutated, 62517,
		int64(start+(end-start)/2), &chaincfg.MainNetParams)
	if err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("CoinbaseClaimProofFromRaw error = %v, want signature rejection",
			err)
	}
}

func TestCoinbaseClaimConjuredValue(t *testing.T) {
	params := chaincfg.MainNetParams
	height := uint32(10)
	proof, data, prevTime := testMainnetClaimData(t)
	addr := wire.Address{
		Version: data.version,
		Hash:    data.hash,
	}
	tx := testCoinbaseClaimTxForNameWithWeak(t, data.name, height, addr,
		data.value-data.fee, data.commitHash, data.commitHeight, proof,
		data.weak)

	got, err := coinbaseConjuredValue(hnsutil.NewTx(tx), height, prevTime,
		&params)
	if err != nil {
		t.Fatalf("coinbaseConjuredValue: %v", err)
	}
	if got != data.value {
		t.Fatalf("coinbaseConjuredValue got %d, want %d", got, data.value)
	}
}

func TestCoinbaseClaimProofFromRaw(t *testing.T) {
	params := chaincfg.MainNetParams
	height := uint32(10)
	serialized, data, prevTime := testMainnetClaimData(t)
	proof, err := CoinbaseClaimProofFromRaw(serialized, height, prevTime,
		&params)
	if err != nil {
		t.Fatalf("CoinbaseClaimProofFromRaw: %v", err)
	}

	wantHash := chainhash.Hash(blake2b.Sum256(serialized))
	if proof.Hash != wantHash {
		t.Fatalf("proof hash = %x, want %x", proof.Hash[:],
			wantHash[:])
	}
	if !bytes.Equal(proof.Witness, serialized) {
		t.Fatal("proof witness does not match serialized claim")
	}
	if proof.Fee != int64(data.fee) {
		t.Fatalf("proof fee = %d, want %d", proof.Fee, data.fee)
	}
	if proof.Output.Value != int64(data.value-data.fee) {
		t.Fatalf("output value = %d, want %d", proof.Output.Value,
			data.value-data.fee)
	}
	if proof.Output.Covenant.Type != wire.CovenantClaim {
		t.Fatalf("covenant type = %d, want CLAIM",
			proof.Output.Covenant.Type)
	}
	if got := binary.LittleEndian.Uint32(
		proof.Output.Covenant.Items[1]); got != height {

		t.Fatalf("claim height = %d, want %d", got, height)
	}
}

func TestVerifyCoinbaseClaimProofDataRejectsNullData(t *testing.T) {
	txOut := wire.NewTxOut(0, wire.Address{Version: 31}, wire.Covenant{
		Type: wire.CovenantClaim,
	})
	_, err := verifyCoinbaseClaimProofData(txOut, txOut.Covenant, 10,
		&chaincfg.MainNetParams, &claimProofData{version: 31})
	if err == nil || !strings.Contains(err.Error(), "nulldata") {
		t.Fatalf("verifyCoinbaseClaimProofData error = %v, want nulldata rejection",
			err)
	}
}

func TestCoinbaseAirdropProofFromRaw(t *testing.T) {
	serialized := testHsdFaucetProof(t)
	if _, err := CoinbaseAirdropProofFromRaw(serialized, 10, nil); err == nil ||
		!strings.Contains(err.Error(), "missing chain parameters") {

		t.Fatalf("CoinbaseAirdropProofFromRaw nil params error = %v", err)
	}

	proof, err := CoinbaseAirdropProofFromRaw(serialized, 10,
		&chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("CoinbaseAirdropProofFromRaw: %v", err)
	}

	airdrop, err := parseAirdropProof(serialized)
	if err != nil {
		t.Fatalf("parseAirdropProof: %v", err)
	}
	wantHash := chainhash.Hash(blake2b.Sum256(serialized))
	if proof.Hash != wantHash {
		t.Fatalf("proof hash = %x, want %x", proof.Hash[:],
			wantHash[:])
	}
	if !bytes.Equal(proof.Witness, serialized) {
		t.Fatal("proof witness does not match serialized airdrop")
	}
	if proof.Fee != int64(airdrop.fee) {
		t.Fatalf("proof fee = %d, want %d", proof.Fee, airdrop.fee)
	}
	if proof.Output.Value != int64(airdrop.value()-airdrop.fee) {
		t.Fatalf("output value = %d, want %d", proof.Output.Value,
			airdrop.value()-airdrop.fee)
	}
	if proof.Output.Covenant.Type != wire.CovenantNone {
		t.Fatalf("covenant type = %d, want NONE",
			proof.Output.Covenant.Type)
	}
}

func TestCoinbaseClaimConjuredValueRejectsMismatch(t *testing.T) {
	params := chaincfg.MainNetParams
	height := uint32(10)
	proof, data, prevTime := testMainnetClaimData(t)
	addr := wire.Address{
		Version: data.version,
		Hash:    data.hash,
	}
	tx := testCoinbaseClaimTxForNameWithWeak(t, data.name, height, addr,
		data.value-data.fee-1, data.commitHash, data.commitHeight, proof,
		data.weak)

	_, err := coinbaseConjuredValue(hnsutil.NewTx(tx), height, prevTime,
		&params)
	if err == nil || !strings.Contains(err.Error(), "output value mismatch") {
		t.Fatalf("coinbaseConjuredValue error = %v, want output value mismatch",
			err)
	}
}

func TestCoinbaseClaimConjuredValueRejectsExpiredProof(t *testing.T) {
	params := chaincfg.MainNetParams
	height := uint32(10)
	commitHash := chainhash.Hash{0x44}
	commitHeight := uint32(1)
	addr := wire.Address{
		Version: 0,
		Hash:    testAddressHash(),
	}
	value, ok := reservedNameValue(hashName([]byte("com")))
	if !ok {
		t.Fatal("missing reserved value for com")
	}
	fee := uint64(1000)

	txt := testClaimTXT(t, &params, addr, fee, commitHash, commitHeight)
	proof := testOwnershipProof(t, "com", false, txt, 50, 75)
	tx := testCoinbaseClaimTx(t, height, addr, value-fee, commitHash,
		commitHeight, proof)

	if _, err := coinbaseConjuredValue(hnsutil.NewTx(tx), height, 100,
		&params); err == nil || !strings.Contains(err.Error(), "time is invalid") {

		t.Fatalf("coinbaseConjuredValue error = %v, want invalid proof time", err)
	}
}

func TestCoinbaseClaimConjuredValueRejectsWeakAfterHardening(t *testing.T) {
	params := chaincfg.MainNetParams
	height := uint32(10)
	proof, data, prevTime := testMainnetClaimData(t)
	if !data.weak {
		t.Fatal("mainnet namecheap CLAIM unexpectedly uses only strong keys")
	}
	addr := wire.Address{
		Version: data.version,
		Hash:    data.hash,
	}
	tx := testCoinbaseClaimTxForNameWithWeak(t, data.name, height, addr,
		data.value-data.fee, data.commitHash, data.commitHeight, proof,
		data.weak)

	got, err := coinbaseConjuredValue(hnsutil.NewTx(tx), height, prevTime,
		&params)
	if err != nil {
		t.Fatalf("coinbaseConjuredValue before hardening: %v", err)
	}
	if got != data.value {
		t.Fatalf("coinbaseConjuredValue got %d, want %d", got, data.value)
	}

	_, err = coinbaseConjuredValue(hnsutil.NewTx(tx), height, prevTime,
		&params, handshakeDeploymentFlags{hardeningActive: true})
	if err == nil {
		t.Fatal("coinbaseConjuredValue: expected weak CLAIM error")
	}
	if !strings.Contains(err.Error(), "weak algorithm") {
		t.Fatalf("coinbaseConjuredValue weak CLAIM error = %v", err)
	}
}

func TestCoinbaseAirdropConjuredValue(t *testing.T) {
	proof := testHsdFaucetProof(t)
	tx, value := testCoinbaseAirdropTxFromProof(t, proof)

	got, err := coinbaseConjuredValue(hnsutil.NewTx(tx), 10, 0,
		&chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("coinbaseConjuredValue: %v", err)
	}
	if got != value {
		t.Fatalf("coinbaseConjuredValue got %d, want %d", got, value)
	}
}

func TestCoinbaseAirdropConjuredValueRejectsAirstop(t *testing.T) {
	proof := testHsdFaucetProof(t)
	tx, _ := testCoinbaseAirdropTxFromProof(t, proof)

	if _, err := coinbaseConjuredValue(hnsutil.NewTx(tx), 10, 0,
		&chaincfg.MainNetParams,
		handshakeDeploymentFlags{airstopActive: true}); err == nil {

		t.Fatal("coinbaseConjuredValue: expected airstop error")
	}
}

func TestCoinbaseAirdropConjuredValueRejectsWeakAfterHardening(t *testing.T) {
	proof := testWeakRSAAirdropProof(t)
	tx, _ := testCoinbaseAirdropTxFromProof(t, proof)

	_, err := coinbaseConjuredValue(hnsutil.NewTx(tx), 10, 0,
		&chaincfg.MainNetParams,
		handshakeDeploymentFlags{hardeningActive: true})
	if err == nil {
		t.Fatal("coinbaseConjuredValue: expected weak airdrop error")
	}
	if !strings.Contains(err.Error(), "weak algorithm") {
		t.Fatalf("coinbaseConjuredValue weak airdrop error = %v", err)
	}
}

func TestCoinbaseAirdropConjuredValueRejectsGooSigCutoff(t *testing.T) {
	params := chaincfg.MainNetParams
	proof, err := base64.StdEncoding.DecodeString(hsdGooProofBase64)
	if err != nil {
		t.Fatalf("DecodeString hsd GooSig proof: %v", err)
	}
	tx, value := testCoinbaseAirdropTxFromProof(t, proof)

	got, err := coinbaseConjuredValue(hnsutil.NewTx(tx),
		params.AirdropGooSigStop-1, 0, &params)
	if err != nil {
		t.Fatalf("coinbaseConjuredValue before cutoff: %v", err)
	}
	if got != value {
		t.Fatalf("coinbaseConjuredValue got %d, want %d", got, value)
	}

	if _, err := coinbaseConjuredValue(hnsutil.NewTx(tx),
		params.AirdropGooSigStop, 0, &params); err == nil {

		t.Fatal("coinbaseConjuredValue: expected GooSig cutoff error")
	}
	if _, err := coinbaseConjuredValue(hnsutil.NewTx(tx),
		params.AirdropGooSigStop-1, 0, nil); err == nil {

		t.Fatal("coinbaseConjuredValue: expected nil params GooSig error")
	}
}

func TestCoinbaseAirdropConjuredValueRejectsDuplicateProof(t *testing.T) {
	proof := testHsdFaucetProof(t)
	airdrop, err := parseAirdropProof(proof)
	if err != nil {
		t.Fatalf("parseAirdropProof: %v", err)
	}
	value := airdrop.value()
	outputValue := value - airdrop.fee
	addr := wire.Address{
		Version: airdrop.version,
		Hash:    append([]byte(nil), airdrop.address...),
	}

	tx := wire.NewMsgTx(1)
	tx.AddTxIn(wire.NewTxIn(nullOutPoint(), ^uint32(0),
		wire.TxWitness{[]byte{0x02, 0x01}}))
	tx.AddTxIn(wire.NewTxIn(nullOutPoint(), ^uint32(0),
		wire.TxWitness{proof}))
	tx.AddTxIn(wire.NewTxIn(nullOutPoint(), ^uint32(0),
		wire.TxWitness{proof}))
	tx.AddTxOut(wire.NewTxOut(1, wire.Address{}, wire.Covenant{}))
	tx.AddTxOut(wire.NewTxOut(int64(outputValue), addr, wire.Covenant{}))
	tx.AddTxOut(wire.NewTxOut(int64(outputValue), addr, wire.Covenant{}))

	if _, err := coinbaseConjuredValue(hnsutil.NewTx(tx), 10, 0,
		&chaincfg.MainNetParams); err == nil {

		t.Fatal("coinbaseConjuredValue: expected duplicate proof error")
	}
}

func TestCoinbaseAirdropConjuredValueRejectsMismatch(t *testing.T) {
	proof := testHsdFaucetProof(t)
	tx, _ := testCoinbaseAirdropTxFromProof(t, proof)
	tx.TxOut[1].Value--

	if _, err := coinbaseConjuredValue(hnsutil.NewTx(tx), 10, 0,
		&chaincfg.MainNetParams); err == nil {

		t.Fatal("coinbaseConjuredValue: expected airdrop value error")
	}
}

func TestCoinbaseClaimProofSanityRejectsNameMismatch(t *testing.T) {
	tx := wire.NewMsgTx(1)
	tx.AddTxIn(wire.NewTxIn(nullOutPoint(), ^uint32(0),
		wire.TxWitness{[]byte{0x02, 0x01}}))
	tx.AddTxIn(wire.NewTxIn(nullOutPoint(), ^uint32(0),
		wire.TxWitness{testOwnershipProof(t, "net", false,
			"not-a-claim-payload", 1, 2)}))
	tx.AddTxOut(wire.NewTxOut(1, wire.Address{}, wire.Covenant{}))
	tx.AddTxOut(wire.NewTxOut(1, wire.Address{}, claimCovenant("com")))

	if err := CheckTransactionSanity(hnsutil.NewTx(tx)); err == nil {
		t.Fatal("CheckTransactionSanity: expected proof name mismatch")
	}
}

func testAirdropProof(t *testing.T, addr wire.Address, value, fee uint64) []byte {
	t.Helper()

	var key bytes.Buffer
	key.WriteByte(airdropKeyAddress)
	key.WriteByte(addr.Version)
	key.WriteByte(byte(len(addr.Hash)))
	key.Write(addr.Hash)
	var valueBytes [8]byte
	binary.LittleEndian.PutUint64(valueBytes[:], value)
	key.Write(valueBytes[:])
	key.WriteByte(0)

	var proof bytes.Buffer
	var index [4]byte
	proof.Write(index[:])
	proof.WriteByte(0)
	proof.WriteByte(0)
	proof.WriteByte(0)
	if err := wire.WriteVarInt(&proof, 0, uint64(key.Len())); err != nil {
		t.Fatalf("WriteVarInt key: %v", err)
	}
	proof.Write(key.Bytes())
	proof.WriteByte(addr.Version)
	proof.WriteByte(byte(len(addr.Hash)))
	proof.Write(addr.Hash)
	if err := wire.WriteVarInt(&proof, 0, fee); err != nil {
		t.Fatalf("WriteVarInt fee: %v", err)
	}
	proof.WriteByte(0)

	return proof.Bytes()
}

func testWeakRSAAirdropProof(t *testing.T) []byte {
	t.Helper()

	var key bytes.Buffer
	key.WriteByte(airdropKeyRSA)
	var sizeBytes [2]byte
	binary.LittleEndian.PutUint16(sizeBytes[:], 128)
	key.Write(sizeBytes[:])
	n := make([]byte, 128)
	n[0] = 0x80
	key.Write(n)
	key.WriteByte(3)
	key.Write([]byte{0x01, 0x00, 0x01})
	key.Write(bytes.Repeat([]byte{0x11}, 32))

	var proof bytes.Buffer
	var index [4]byte
	proof.Write(index[:])
	proof.WriteByte(0)
	proof.WriteByte(0)
	proof.WriteByte(0)
	writeAirdropVarBytes(&proof, key.Bytes())
	proof.WriteByte(0)
	proof.WriteByte(20)
	proof.Write(bytes.Repeat([]byte{0xbb}, 20))
	if err := wire.WriteVarInt(&proof, 0, 0); err != nil {
		t.Fatalf("WriteVarInt fee: %v", err)
	}
	writeAirdropVarBytes(&proof, nil)

	return proof.Bytes()
}

func testAddressHash() []byte {
	return bytes.Repeat([]byte{0xaa}, 20)
}

func testCoinbaseClaimTx(t *testing.T, height uint32, addr wire.Address,
	outputValue uint64, commitHash chainhash.Hash, commitHeight uint32,
	proof []byte) *wire.MsgTx {

	return testCoinbaseClaimTxWithWeak(t, height, addr, outputValue,
		commitHash, commitHeight, proof, false)
}

func testCoinbaseClaimTxWithWeak(t *testing.T, height uint32,
	addr wire.Address, outputValue uint64, commitHash chainhash.Hash,
	commitHeight uint32, proof []byte, weak bool) *wire.MsgTx {

	return testCoinbaseClaimTxForNameWithWeak(t, "com", height, addr,
		outputValue, commitHash, commitHeight, proof, weak)
}

func testCoinbaseClaimTxForNameWithWeak(t *testing.T, name string,
	height uint32, addr wire.Address, outputValue uint64,
	commitHash chainhash.Hash, commitHeight uint32, proof []byte,
	weak bool) *wire.MsgTx {

	t.Helper()
	if outputValue > uint64(hnsutil.MaxDoo) {
		t.Fatalf("output value %d exceeds max money", outputValue)
	}

	tx := wire.NewMsgTx(1)
	tx.AddTxIn(wire.NewTxIn(nullOutPoint(), ^uint32(0),
		wire.TxWitness{[]byte{0x02, 0x01}}))
	tx.AddTxIn(wire.NewTxIn(nullOutPoint(), ^uint32(0),
		wire.TxWitness{proof}))
	tx.AddTxOut(wire.NewTxOut(1, wire.Address{}, wire.Covenant{}))
	tx.AddTxOut(wire.NewTxOut(int64(outputValue), addr,
		claimCovenantAt(name, height, commitHash, commitHeight, weak)))
	return tx
}

func testClaimTXT(t *testing.T, params *chaincfg.Params, addr wire.Address,
	fee uint64, commitHash chainhash.Hash, commitHeight uint32) string {

	t.Helper()
	var buf bytes.Buffer
	buf.WriteByte(addr.Version)
	buf.WriteByte(byte(len(addr.Hash)))
	buf.Write(addr.Hash)
	if err := wire.WriteVarInt(&buf, 0, fee); err != nil {
		t.Fatalf("WriteVarInt: %v", err)
	}
	buf.Write(commitHash[:])
	var scratch [4]byte
	binary.LittleEndian.PutUint32(scratch[:], commitHeight)
	buf.Write(scratch[:])
	sum := blake2b.Sum256(buf.Bytes())
	buf.Write(sum[:4])

	return params.NameClaimPrefix + strings.ToLower(
		claimBase32.EncodeToString(buf.Bytes()))
}

func testOwnershipProof(t *testing.T, name string, weak bool, txt string,
	inception, expiration uint32) []byte {

	t.Helper()
	keyBits := 2048
	if weak {
		keyBits = 1024
	}

	rootKey := testDNSKEY(".", keyBits)
	rootSig := testRRSIG(".", ".", dns.TypeDNSKEY, rootKey, inception,
		expiration)
	dsName := dns.Fqdn(name)
	rootDS := &dns.DS{
		Hdr: dns.RR_Header{
			Name:   dsName,
			Rrtype: dns.TypeDS,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		KeyTag:     1,
		Algorithm:  dns.RSASHA256,
		DigestType: dns.SHA256,
		Digest:     strings.Repeat("00", 32),
	}
	rootDSSig := testRRSIG(dsName, ".", dns.TypeDS, rootKey, inception,
		expiration)

	claimKey := testDNSKEY(dsName, keyBits)
	claimKeySig := testRRSIG(dsName, dsName, dns.TypeDNSKEY, claimKey,
		inception, expiration)
	claimTXT := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   dsName,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Txt: []string{txt},
	}
	claimTXTSig := testRRSIG(dsName, dsName, dns.TypeTXT, claimKey,
		inception, expiration)

	var proof []byte
	proof = append(proof, 2)
	proof = appendProofZone(t, proof,
		[]dns.RR{rootKey, rootSig},
		[]dns.RR{rootDS, rootDSSig},
		nil)
	proof = appendProofZone(t, proof,
		[]dns.RR{claimKey, claimKeySig},
		nil,
		[]dns.RR{claimTXT, claimTXTSig})
	return proof
}

func testMainnetClaimProof(t *testing.T) []byte {
	t.Helper()
	encoded, err := os.ReadFile("testdata/mainnet-namecheap-claim.hex")
	if err != nil {
		t.Fatalf("read mainnet CLAIM fixture: %v", err)
	}
	serialized, err := hex.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatalf("decode mainnet CLAIM fixture: %v", err)
	}
	return serialized
}

func testMainnetClaimData(t *testing.T) ([]byte, *claimProofData, int64) {
	t.Helper()
	serialized := testMainnetClaimProof(t)
	proof := mustParseOwnershipProof(t, serialized)
	data, err := proof.claimData(&chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("claimData: %v", err)
	}
	start, end := proof.window()
	if start == 0 || end < start {
		t.Fatalf("invalid claim window %d..%d", start, end)
	}
	return serialized, data, int64(start + (end-start)/2)
}

func mustParseOwnershipProof(t *testing.T, serialized []byte) *ownershipProof {
	t.Helper()
	proof, err := parseOwnershipProof(serialized)
	if err != nil {
		t.Fatalf("parseOwnershipProof: %v", err)
	}
	return proof
}

func serializeOwnershipProof(t *testing.T, proof *ownershipProof) []byte {
	t.Helper()
	if len(proof.zones) > 255 {
		t.Fatal("too many ownership zones")
	}
	serialized := []byte{byte(len(proof.zones))}
	for i := range proof.zones {
		zone := &proof.zones[i]
		serialized = appendProofZone(t, serialized, zone.keys,
			zone.referral, zone.claim)
	}
	return serialized
}

func testDNSKEY(name string, keyBits int) *dns.DNSKEY {
	return &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(name),
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Flags:     dns.ZONE,
		Protocol:  3,
		Algorithm: dns.RSASHA256,
		PublicKey: testRSAPublicKey(keyBits),
	}
}

func testRRSIG(name, signer string, covered uint16, key *dns.DNSKEY,
	inception, expiration uint32) *dns.RRSIG {

	fqdnName := dns.Fqdn(name)
	return &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   fqdnName,
			Rrtype: dns.TypeRRSIG,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		TypeCovered: covered,
		Algorithm:   dns.RSASHA256,
		Labels:      uint8(dns.CountLabel(fqdnName)),
		OrigTtl:     3600,
		Expiration:  expiration,
		Inception:   inception,
		KeyTag:      key.KeyTag(),
		SignerName:  dns.Fqdn(signer),
		Signature:   "AQID",
	}
}

func appendProofZone(t *testing.T, proof []byte, keys, referral,
	claim []dns.RR) []byte {

	t.Helper()
	for _, set := range [][]dns.RR{keys, referral, claim} {
		if len(set) > 255 {
			t.Fatal("proof set too large")
		}
		proof = append(proof, byte(len(set)))
		for _, rr := range set {
			proof = appendPackedRR(t, proof, rr)
		}
	}
	return proof
}

func appendPackedRR(t *testing.T, proof []byte, rr dns.RR) []byte {
	t.Helper()
	var scratch [4096]byte
	n, err := dns.PackRR(rr, scratch[:], 0, nil, false)
	if err != nil {
		t.Fatalf("PackRR(%T): %v", rr, err)
	}
	return append(proof, scratch[:n]...)
}

func testRSAPublicKey(keyBits int) string {
	modulus := make([]byte, (keyBits+7)/8)
	modulus[0] = 1 << ((keyBits - 1) % 8)
	raw := append([]byte{3, 0x01, 0x00, 0x01}, modulus...)
	return base64.StdEncoding.EncodeToString(raw)
}

func testRawRSAPublicKey(keyBits int, exponent uint64,
	oddModulus bool) []byte {

	modulus := make([]byte, (keyBits+7)/8)
	modulus[0] = 1 << ((keyBits - 1) % 8)
	if oddModulus {
		modulus[len(modulus)-1] = 1
	}
	var exponentScratch [8]byte
	binary.BigEndian.PutUint64(exponentScratch[:], exponent)
	exponentRaw := exponentScratch[:]
	for len(exponentRaw) > 1 && exponentRaw[0] == 0 {
		exponentRaw = exponentRaw[1:]
	}
	raw := []byte{byte(len(exponentRaw))}
	raw = append(raw, exponentRaw...)
	return append(raw, modulus...)
}
