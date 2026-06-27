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
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/btcsuite/btcd/btcec/v2"
)

// This file implements bcrypto's Elligator Squared uniform encoding for
// secp256k1 points, as used by hsd's Brontide handshake. hsd encodes the
// ephemeral keys in acts one and two with secp256k1.publicKeyToHash and
// decodes them with secp256k1.publicKeyFromHash. A point P is represented by
// two field elements (u1, u2) such that f(u1) + f(u2) = P, where f is the
// Shallue-van de Woestijne forward map. The encoded bytes are computationally
// indistinguishable from 64 uniformly random bytes.

const (
	// UniformPublicKeySize is the size of an Elligator Squared encoded
	// secp256k1 point: two big-endian field elements.
	UniformPublicKeySize = 64

	// fieldElementSize is the size of one big-endian secp256k1 field element.
	fieldElementSize = 32

	// maxUniformEncodeAttempts bounds the Elligator Squared rejection
	// sampling loop. bcrypto loops unconditionally and needs roughly four
	// attempts on average; the cap only guards against a broken randomness
	// source.
	maxUniformEncodeAttempts = 1000
)

var (
	// ErrInvalidPoint is returned when a secp256k1 point cannot be encoded
	// to, or decoded from, its Elligator Squared representation. It matches
	// bcrypto's 'Invalid point.' error.
	ErrInvalidPoint = errors.New("brontide: invalid point")

	// ErrInvalidUniformSize is returned when an Elligator Squared encoding
	// is not exactly 64 bytes. It matches bcrypto's 'Invalid hash size.'.
	ErrInvalidUniformSize = errors.New("brontide: invalid uniform key size")
)

// fieldVal aliases the optimized secp256k1 field arithmetic exposed by btcec.
type fieldVal = btcec.FieldVal

// Shallue-van de Woestijne constants for secp256k1 (a = 0, b = 7), matching
// bcrypto's SECP256K1 curve definition:
//
//	z  = 1
//	c  = sqrt(-3 * z^2) = sqrt(-3)
//	zi = 1 / z
//	i2 = 1 / 2
//	i3 = 1 / 3
//	gz = g(z) = z^3 + b
//	z3 = 1 / (3 * z^2)
var (
	svdwB  fieldVal
	svdwZ  fieldVal
	svdwC  fieldVal
	svdwI2 fieldVal
	svdwI3 fieldVal
	svdwGz fieldVal
	svdwZ3 fieldVal
	feOne  fieldVal
	feTwo  fieldVal
)

func init() {
	feOne.SetInt(1)
	feTwo.SetInt(2)
	svdwB.SetInt(7)
	svdwZ.SetInt(1)

	// sqrt(-3) mod p, from bcrypto's precomputed SECP256K1 'c' constant.
	svdwC.SetByteSlice([]byte{
		0x0a, 0x2d, 0x2b, 0xa9, 0x35, 0x07, 0xf1, 0xdf,
		0x23, 0x37, 0x70, 0xc2, 0xa7, 0x97, 0x96, 0x2c,
		0xc6, 0x1f, 0x6d, 0x15, 0xda, 0x14, 0xec, 0xd4,
		0x7d, 0x8d, 0x27, 0xae, 0x1c, 0xd5, 0xf8, 0x52,
	})
	svdwC.Normalize()

	svdwI2 = feInv(&feTwo)
	var three fieldVal
	three.SetInt(3)
	svdwI3 = feInv(&three)

	// gz = z^3 + b.
	zSqr := feSqr(&svdwZ)
	zCube := feMul(&zSqr, &svdwZ)
	svdwGz = feAdd(&zCube, &svdwB)

	// z3 = i3 * (1/z)^2 = 1 / (3 * z^2).
	zi := feInv(&svdwZ)
	ziSqr := feSqr(&zi)
	svdwZ3 = feMul(&svdwI3, &ziSqr)
}

// feAdd returns a + b. All field helpers take and return normalized values.
func feAdd(a, b *fieldVal) fieldVal {
	var r fieldVal
	r.Add2(a, b).Normalize()
	return r
}

// feSub returns a - b.
func feSub(a, b *fieldVal) fieldVal {
	var n fieldVal
	n.NegateVal(b, 1)
	var r fieldVal
	r.Add2(a, &n).Normalize()
	return r
}

// feMul returns a * b.
func feMul(a, b *fieldVal) fieldVal {
	var r fieldVal
	r.Mul2(a, b).Normalize()
	return r
}

// feMulInt returns a * n for a small integer n.
func feMulInt(a *fieldVal, n uint8) fieldVal {
	var r fieldVal
	r.Set(a).MulInt(n).Normalize()
	return r
}

// feSqr returns a^2.
func feSqr(a *fieldVal) fieldVal {
	var r fieldVal
	r.SquareVal(a).Normalize()
	return r
}

// feNeg returns -a.
func feNeg(a *fieldVal) fieldVal {
	var r fieldVal
	r.NegateVal(a, 1).Normalize()
	return r
}

// feInv returns 1/a, or zero when a is zero, matching bcrypto's guarded
// inversions.
func feInv(a *fieldVal) fieldVal {
	var r fieldVal
	r.Set(a).Inverse().Normalize()
	return r
}

// feSqrt returns a square root of a and whether one exists. Zero reports a
// square with root zero, matching bcrypto's jacobi-based selection.
func feSqrt(a *fieldVal) (fieldVal, bool) {
	var r fieldVal
	ok := r.SquareRootVal(a)
	r.Normalize()
	return r, ok
}

// feIsSquare returns whether a is a quadratic residue or zero.
func feIsSquare(a *fieldVal) bool {
	var r fieldVal
	return r.SquareRootVal(a)
}

// feDivSqrt returns sqrt(n / d), matching bcrypto's redDivSqrt. Division by
// zero and non-square quotients yield ErrInvalidPoint, the same error
// bcrypto's wrapErrors maps both failures to.
func feDivSqrt(n, d *fieldVal) (fieldVal, error) {
	if d.IsZero() {
		return fieldVal{}, ErrInvalidPoint
	}
	di := feInv(d)
	q := feMul(n, &di)
	r, ok := feSqrt(&q)
	if !ok {
		return fieldVal{}, ErrInvalidPoint
	}
	return r, nil
}

// feSolveY2 returns g(x) = x^3 + b for secp256k1.
func feSolveY2(x *fieldVal) fieldVal {
	xSqr := feSqr(x)
	xCube := feMul(&xSqr, x)
	return feAdd(&xCube, &svdwB)
}

// svdwF implements bcrypto's _svdwf: the Shallue-van de Woestijne forward map
// for a = 0 short Weierstrass curves. It returns the x coordinate and
// y^2 = g(x) of the mapped point:
//
//	t1 = u^2 + g(z)
//	t2 = 1 / (u^2 * t1)
//	t3 = u^4 * t2 * c
//	x1 = (c - z) / 2 - t3
//	x2 = t3 - (c + z) / 2
//	x3 = z - t1^3 * t2 / (3 * z^2)
//	x  = x1 if g(x1) is square, else x2 if g(x2) is square, else x3
func svdwF(u *fieldVal) (fieldVal, fieldVal) {
	u2 := feSqr(u)
	u4 := feSqr(&u2)
	t1 := feAdd(&u2, &svdwGz)
	u2t1 := feMul(&u2, &t1)
	t2 := feInv(&u2t1)
	t3a := feMul(&u4, &t2)
	t3 := feMul(&t3a, &svdwC)
	t1Sqr := feSqr(&t1)
	t4 := feMul(&t1Sqr, &t1)

	cmz := feSub(&svdwC, &svdwZ)
	x1a := feMul(&cmz, &svdwI2)
	x1 := feSub(&x1a, &t3)

	cpz := feAdd(&svdwC, &svdwZ)
	x2a := feMul(&cpz, &svdwI2)
	x2 := feSub(&t3, &x2a)

	x3a := feMul(&t4, &t2)
	x3b := feMul(&x3a, &svdwZ3)
	x3 := feSub(&svdwZ, &x3b)

	y1 := feSolveY2(&x1)
	y2 := feSolveY2(&x2)
	y3 := feSolveY2(&x3)

	// bcrypto selects with jacobi symbols: alpha = jacobi(y1) | 1 and
	// beta = jacobi(y2) | 1, picking x1, x2, or x3 in that order. The OR
	// folds jacobi's zero into the square case.
	switch {
	case feIsSquare(&y1):
		return x1, y1
	case feIsSquare(&y2):
		return x2, y2
	default:
		return x3, y3
	}
}

// svdwMap implements bcrypto's _svdw: the full forward map from a field
// element to an affine point, with the y sign matched to the parity of u.
func svdwMap(u *fieldVal) (fieldVal, fieldVal, error) {
	x, ySqr := svdwF(u)
	y, ok := feSqrt(&ySqr)
	if !ok {
		// Unreachable for secp256k1: at least one of g(x1), g(x2),
		// g(x3) is always square. Guarded to keep decoding panic-free.
		return fieldVal{}, fieldVal{}, ErrInvalidPoint
	}
	if y.IsOdd() != u.IsOdd() {
		y = feNeg(&y)
	}
	return x, y, nil
}

// svdwInvert implements bcrypto's _svdwi: the randomized inverse of the
// Shallue-van de Woestijne map. The hint selects one of four candidate
// preimages:
//
//	u1 = sqrt(g(z) * (c - 2x - z) / (c + 2x + z))
//	u2 = sqrt(g(z) * (c + 2x + z) / (c - 2x - z))
//	u3 = sqrt((3 * (z^3 - x * z^2) - 2 * g(z) + t4) / 2)
//	u4 = sqrt((3 * (z^3 - x * z^2) - 2 * g(z) - t4) / 2)
//
// where t4 = z * sqrt(9 * (x^2 * z^2 + z^4) - 18 * x * z^3 + 12 * g(z) * (x - z)).
// ErrInvalidPoint is returned when the selected preimage does not exist.
func svdwInvert(x, y *fieldVal, hint uint32) (fieldVal, error) {
	r := hint & 3

	z2 := feSqr(&svdwZ)
	z3 := feMul(&z2, &svdwZ)
	z4 := feSqr(&z2)
	gz2 := feMulInt(&svdwGz, 2)

	xx := feSqr(x)
	xDbl := feMulInt(x, 2)
	x2z := feAdd(&xDbl, &svdwZ)
	xz2 := feMul(x, &z2)
	c0 := feSub(&svdwC, &x2z)
	c1 := feAdd(&svdwC, &x2z)

	t0a := feMul(&xx, &z2)
	t0b := feAdd(&t0a, &z4)
	t0 := feMulInt(&t0b, 9)
	t1a := feMul(x, &z3)
	t1 := feMulInt(&t1a, 18)
	xmz := feSub(x, &svdwZ)
	t2a := feMul(&svdwGz, &xmz)
	t2 := feMulInt(&t2a, 12)

	var t3 fieldVal
	if r >= 2 {
		t3a := feSub(&t0, &t1)
		t3b := feAdd(&t3a, &t2)
		var ok bool
		t3, ok = feSqrt(&t3b)
		if !ok {
			return fieldVal{}, ErrInvalidPoint
		}
	}
	t4 := feMul(&t3, &svdwZ)
	t5a := feSub(&z3, &xz2)
	t5b := feMulInt(&t5a, 3)
	t5 := feSub(&t5b, &gz2)

	n0 := feMul(&svdwGz, &c0)
	n1 := feMul(&svdwGz, &c1)
	n2 := feAdd(&t5, &t4)
	n3 := feSub(&t5, &t4)

	nums := [4]fieldVal{n0, n1, n2, n3}
	dens := [4]fieldVal{c1, c0, feTwo, feTwo}

	u, err := feDivSqrt(&nums[r], &dens[r])
	if err != nil {
		return fieldVal{}, err
	}

	// Verify the preimage round-trips through the forward map.
	x0, _ := svdwF(&u)
	if !x0.Equals(x) {
		return fieldVal{}, ErrInvalidPoint
	}

	if u.IsOdd() != y.IsOdd() {
		u = feNeg(&u)
	}
	return u, nil
}

// decodeUniform interprets 32 big-endian bytes as a field element, reducing
// modulo the field prime like bcrypto's decodeUniform.
func decodeUniform(b []byte) fieldVal {
	var u fieldVal
	u.SetByteSlice(b)
	u.Normalize()
	return u
}

// PublicKeyFromHash decodes a 64-byte Elligator Squared encoding into a
// secp256k1 public key, matching bcrypto's publicKeyFromHash. Every 64-byte
// string decodes to a valid curve point except the negligible case where the
// two mapped points sum to infinity.
func PublicKeyFromHash(uniform []byte) (*btcec.PublicKey, error) {
	if len(uniform) != UniformPublicKeySize {
		return nil, fmt.Errorf("%w: got %d bytes, want %d",
			ErrInvalidUniformSize, len(uniform), UniformPublicKeySize)
	}

	u1 := decodeUniform(uniform[:fieldElementSize])
	u2 := decodeUniform(uniform[fieldElementSize:])

	x1, y1, err := svdwMap(&u1)
	if err != nil {
		return nil, err
	}
	x2, y2, err := svdwMap(&u2)
	if err != nil {
		return nil, err
	}

	p1 := btcec.MakeJacobianPoint(&x1, &y1, &feOne)
	p2 := btcec.MakeJacobianPoint(&x2, &y2, &feOne)

	var sum btcec.JacobianPoint
	btcec.AddNonConst(&p1, &p2, &sum)
	if (sum.Z.Normalize()).IsZero() {
		return nil, fmt.Errorf("%w: point at infinity", ErrInvalidPoint)
	}
	sum.ToAffine()

	return btcec.NewPublicKey(&sum.X, &sum.Y), nil
}

// PublicKeyToHash encodes a secp256k1 public key as 64 bytes that are
// indistinguishable from uniformly random bytes, matching bcrypto's
// publicKeyToHash. The encoding is randomized: rng supplies the random field
// elements and preimage hints, and defaults to crypto/rand when nil. The
// returned bytes decode back to pub via PublicKeyFromHash.
func PublicKeyToHash(pub *btcec.PublicKey, rng io.Reader) ([]byte, error) {
	if pub == nil {
		return nil, fmt.Errorf("%w: nil public key", ErrInvalidKey)
	}
	if rng == nil {
		rng = rand.Reader
	}

	var p0 btcec.JacobianPoint
	pub.AsJacobian(&p0)

	for i := 0; i < maxUniformEncodeAttempts; i++ {
		u1, err := randomFieldElement(rng)
		if err != nil {
			return nil, err
		}

		x1, y1, err := svdwMap(&u1)
		if err != nil {
			return nil, err
		}
		// Skip 2-torsion points like bcrypto. Unreachable on secp256k1,
		// whose group order is an odd prime.
		if y1.IsZero() {
			continue
		}

		// p2 = p0 - f(u1).
		negY1 := feNeg(&y1)
		negP1 := btcec.MakeJacobianPoint(&x1, &negY1, &feOne)
		var p2 btcec.JacobianPoint
		btcec.AddNonConst(&p0, &negP1, &p2)

		hint, err := randomHint(rng)
		if err != nil {
			return nil, err
		}

		// pointToUniform rejects the point at infinity.
		if (p2.Z.Normalize()).IsZero() {
			continue
		}
		p2.ToAffine()

		u2, err := svdwInvert(&p2.X, &p2.Y, hint&15)
		if errors.Is(err, ErrInvalidPoint) {
			continue
		}
		if err != nil {
			return nil, err
		}

		out := make([]byte, 0, UniformPublicKeySize)
		out = append(out, u1.Bytes()[:]...)
		out = append(out, u2.Bytes()[:]...)
		return out, nil
	}

	return nil, fmt.Errorf("%w: uniform encoding did not converge",
		ErrInvalidPoint)
}

// randomFieldElement samples a uniformly random field element in [1, p) by
// rejection, matching bcrypto's randomField.
func randomFieldElement(rng io.Reader) (fieldVal, error) {
	var buf [fieldElementSize]byte
	for {
		if _, err := io.ReadFull(rng, buf[:]); err != nil {
			return fieldVal{}, err
		}

		var u fieldVal
		if overflow := u.SetByteSlice(buf[:]); overflow {
			continue
		}
		if u.Normalize(); u.IsZero() {
			continue
		}
		return u, nil
	}
}

// randomHint samples the 32-bit preimage hint used by the inverse map,
// matching bcrypto's randomInt.
func randomHint(rng io.Reader) (uint32, error) {
	var buf [4]byte
	if _, err := io.ReadFull(rng, buf[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(buf[:]), nil
}
