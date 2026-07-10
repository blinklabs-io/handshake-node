// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package brontide

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
)

// hashStream is a deterministic io.Reader producing a SHA256-based byte
// stream, used to make the randomized Elligator Squared inverse reproducible.
type hashStream struct {
	state   [32]byte
	pending []byte
}

func newHashStream(seed string) *hashStream {
	return &hashStream{state: sha256.Sum256([]byte(seed))}
}

func (h *hashStream) Read(p []byte) (int, error) {
	for len(h.pending) < len(p) {
		h.state = sha256.Sum256(h.state[:])
		h.pending = append(h.pending, h.state[:]...)
	}
	n := copy(p, h.pending)
	h.pending = h.pending[n:]
	return n, nil
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// TestSVDWConstants verifies the precomputed Shallue-van de Woestijne
// constants taken from bcrypto's SECP256K1 curve definition.
func TestSVDWConstants(t *testing.T) {
	// c = sqrt(-3): c^2 == -3 mod p.
	cSqr := feSqr(&svdwC)
	var three fieldVal
	three.SetInt(3)
	negThree := feNeg(&three)
	if !cSqr.Equals(&negThree) {
		t.Fatalf("c^2: got %x, want -3", cSqr.Bytes())
	}

	// g(z) = z^3 + b = 8 for z = 1, b = 7.
	var eight fieldVal
	eight.SetInt(8)
	if !svdwGz.Equals(&eight) {
		t.Fatalf("g(z): got %x, want 8", svdwGz.Bytes())
	}

	// i2 and i3 are inverses of 2 and 3.
	two := feTwo
	i2t := feMul(&svdwI2, &two)
	if !i2t.Equals(&feOne) {
		t.Fatalf("i2 * 2: got %x, want 1", i2t.Bytes())
	}
	i3t := feMul(&svdwI3, &three)
	if !i3t.Equals(&feOne) {
		t.Fatalf("i3 * 3: got %x, want 1", i3t.Bytes())
	}
}

// TestSVDWForwardMapOnCurve verifies the forward map always lands on the
// curve, including for edge inputs.
func TestSVDWForwardMapOnCurve(t *testing.T) {
	checkOnCurve := func(t *testing.T, u *fieldVal) {
		t.Helper()

		x, y, err := svdwMap(u)
		if err != nil {
			t.Fatalf("svdwMap(%x): %v", u.Bytes(), err)
		}
		ySqr := feSqr(&y)
		gx := feSolveY2(&x)
		if !ySqr.Equals(&gx) {
			t.Fatalf("svdwMap(%x): point (%x, %x) not on curve",
				u.Bytes(), x.Bytes(), y.Bytes())
		}
		if y.IsOdd() != u.IsOdd() {
			t.Fatalf("svdwMap(%x): y parity does not match u", u.Bytes())
		}
	}

	t.Run("zero", func(t *testing.T) {
		var u fieldVal
		checkOnCurve(t, &u)
	})
	t.Run("one", func(t *testing.T) {
		checkOnCurve(t, &feOne)
	})
	t.Run("p minus one", func(t *testing.T) {
		u := feNeg(&feOne)
		checkOnCurve(t, &u)
	})
	t.Run("random", func(t *testing.T) {
		for i := 0; i < 256; i++ {
			u, err := randomFieldElement(rand.Reader)
			if err != nil {
				t.Fatalf("randomFieldElement: %v", err)
			}
			checkOnCurve(t, &u)
		}
	})
}

// TestSVDWInvertRoundTrip verifies that every successful preimage hint
// inverts back through the forward map to the original point.
func TestSVDWInvertRoundTrip(t *testing.T) {
	successes := 0
	for i := 0; i < 64; i++ {
		priv, err := GenerateKey()
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}

		var point btcec.JacobianPoint
		priv.PubKey().AsJacobian(&point)
		point.ToAffine()

		for hint := uint32(0); hint < 4; hint++ {
			u, err := svdwInvert(&point.X, &point.Y, hint)
			if errors.Is(err, ErrInvalidPoint) {
				continue
			}
			if err != nil {
				t.Fatalf("svdwInvert(hint=%d): %v", hint, err)
			}
			successes++

			x, y, err := svdwMap(&u)
			if err != nil {
				t.Fatalf("svdwMap: %v", err)
			}
			if !x.Equals(&point.X) || !y.Equals(&point.Y) {
				t.Fatalf("hint %d: round trip mismatch", hint)
			}
		}
	}
	if successes == 0 {
		t.Fatal("no preimage hints succeeded across 64 random points")
	}
}

// TestPublicKeyHashRoundTrip verifies encode-decode round trips for many
// random keys.
func TestPublicKeyHashRoundTrip(t *testing.T) {
	for i := 0; i < 128; i++ {
		priv, err := GenerateKey()
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		pub := priv.PubKey()

		uniform, err := PublicKeyToHash(pub, rand.Reader)
		if err != nil {
			t.Fatalf("PublicKeyToHash: %v", err)
		}
		if len(uniform) != UniformPublicKeySize {
			t.Fatalf("uniform size: got %d, want %d",
				len(uniform), UniformPublicKeySize)
		}

		decoded, err := PublicKeyFromHash(uniform)
		if err != nil {
			t.Fatalf("PublicKeyFromHash: %v", err)
		}
		if !bytes.Equal(decoded.SerializeCompressed(),
			pub.SerializeCompressed()) {
			t.Fatalf("round trip #%d: got %x, want %x", i,
				decoded.SerializeCompressed(), pub.SerializeCompressed())
		}
	}
}

// TestPublicKeyToHashDeterministicRNG verifies the inverse map is randomized
// only through the injected reader.
func TestPublicKeyToHashDeterministicRNG(t *testing.T) {
	priv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub := priv.PubKey()

	first, err := PublicKeyToHash(pub, newHashStream("brontide elligator"))
	if err != nil {
		t.Fatalf("PublicKeyToHash #1: %v", err)
	}
	second, err := PublicKeyToHash(pub, newHashStream("brontide elligator"))
	if err != nil {
		t.Fatalf("PublicKeyToHash #2: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("deterministic encodings differ: %x vs %x", first, second)
	}

	other, err := PublicKeyToHash(pub, newHashStream("other seed"))
	if err != nil {
		t.Fatalf("PublicKeyToHash #3: %v", err)
	}
	if bytes.Equal(first, other) {
		t.Fatal("different seeds produced identical encodings")
	}

	decoded, err := PublicKeyFromHash(first)
	if err != nil {
		t.Fatalf("PublicKeyFromHash: %v", err)
	}
	if !bytes.Equal(decoded.SerializeCompressed(), pub.SerializeCompressed()) {
		t.Fatal("deterministic encoding does not decode to original key")
	}
}

// TestPublicKeyToHashEncodingsDiffer verifies repeated encodings of one key
// are randomized but all decode to the same point.
func TestPublicKeyToHashEncodingsDiffer(t *testing.T) {
	priv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub := priv.PubKey()

	seen := make(map[string]struct{})
	for i := 0; i < 16; i++ {
		uniform, err := PublicKeyToHash(pub, rand.Reader)
		if err != nil {
			t.Fatalf("PublicKeyToHash: %v", err)
		}
		seen[string(uniform)] = struct{}{}

		decoded, err := PublicKeyFromHash(uniform)
		if err != nil {
			t.Fatalf("PublicKeyFromHash: %v", err)
		}
		if !bytes.Equal(decoded.SerializeCompressed(),
			pub.SerializeCompressed()) {
			t.Fatal("encoding decoded to wrong key")
		}
	}
	if len(seen) < 2 {
		t.Fatal("randomized encodings never differed")
	}
}

// TestPublicKeyFromHashArbitraryBytes verifies decoding arbitrary bytes never
// panics and always yields a valid curve point or a clean error, matching
// bcrypto's behavior where every uniform string maps onto the curve.
func TestPublicKeyFromHashArbitraryBytes(t *testing.T) {
	check := func(t *testing.T, uniform []byte) {
		t.Helper()

		pub, err := PublicKeyFromHash(uniform)
		if err != nil {
			// The only decode failure mode for 64-byte input is the
			// negligible point-at-infinity case.
			if !errors.Is(err, ErrInvalidPoint) {
				t.Fatalf("PublicKeyFromHash(%x): unexpected error %v",
					uniform, err)
			}
			return
		}
		if !pub.IsOnCurve() {
			t.Fatalf("PublicKeyFromHash(%x): point off curve", uniform)
		}
	}

	t.Run("patterns", func(t *testing.T) {
		patterns := [][]byte{
			make([]byte, UniformPublicKeySize),
			bytes.Repeat([]byte{0xff}, UniformPublicKeySize),
			bytes.Repeat([]byte{0xaa}, UniformPublicKeySize),
			append(make([]byte, 32), bytes.Repeat([]byte{0xff}, 32)...),
			// Values >= p must reduce modulo p like bcrypto's
			// decodeUniform.
			append(mustHex(t, "fffffffffffffffffffffffffffffff"+
				"ffffffffffffffffffffffffefffffc2f"),
				make([]byte, 32)...),
		}
		for _, pattern := range patterns {
			check(t, pattern)
		}
	})

	t.Run("random", func(t *testing.T) {
		uniform := make([]byte, UniformPublicKeySize)
		for i := 0; i < 1024; i++ {
			if _, err := io.ReadFull(rand.Reader, uniform); err != nil {
				t.Fatalf("rand: %v", err)
			}
			check(t, uniform)
		}
	})
}

// TestPublicKeyFromHashFieldReduction verifies decodeUniform reduces values
// modulo the field prime, so congruent encodings decode identically.
func TestPublicKeyFromHashFieldReduction(t *testing.T) {
	// p + 1 = 1 mod p.
	pPlusOne := mustHex(t,
		"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30")
	one := make([]byte, fieldElementSize)
	one[fieldElementSize-1] = 0x01

	a, err := PublicKeyFromHash(append(pPlusOne, one...))
	if err != nil {
		t.Fatalf("PublicKeyFromHash(p+1||1): %v", err)
	}
	b, err := PublicKeyFromHash(append(one, one...))
	if err != nil {
		t.Fatalf("PublicKeyFromHash(1||1): %v", err)
	}
	if !bytes.Equal(a.SerializeCompressed(), b.SerializeCompressed()) {
		t.Fatal("congruent uniform encodings decoded differently")
	}
}

// TestPublicKeyHashRejectsInvalidInputs verifies input validation.
func TestPublicKeyHashRejectsInvalidInputs(t *testing.T) {
	if _, err := PublicKeyFromHash(make([]byte, 63)); !errors.Is(err, ErrInvalidUniformSize) {
		t.Fatalf("short input error: got %v, want %v", err, ErrInvalidUniformSize)
	}
	if _, err := PublicKeyFromHash(make([]byte, 65)); !errors.Is(err, ErrInvalidUniformSize) {
		t.Fatalf("long input error: got %v, want %v", err, ErrInvalidUniformSize)
	}
	if _, err := PublicKeyFromHash(nil); !errors.Is(err, ErrInvalidUniformSize) {
		t.Fatalf("nil input error: got %v, want %v", err, ErrInvalidUniformSize)
	}

	if _, err := PublicKeyToHash(nil, rand.Reader); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("nil key error: got %v, want %v", err, ErrInvalidKey)
	}

	priv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if _, err := PublicKeyToHash(priv.PubKey(), bytes.NewReader(nil)); err == nil {
		t.Fatal("PublicKeyToHash succeeded with exhausted rng")
	}
}

func TestPublicKeyToHashBoundsBadRNG(t *testing.T) {
	priv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	if _, err := PublicKeyToHash(priv.PubKey(), zeroReader{}); !errors.Is(err, ErrInvalidPoint) {
		t.Fatalf("PublicKeyToHash zero RNG error: got %v, want %v",
			err, ErrInvalidPoint)
	}
}
