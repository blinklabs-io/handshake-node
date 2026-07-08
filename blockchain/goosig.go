// Copyright (c) 2026 Blink Labs Software
// Copyright (c) 2018-2019 Christopher Jeffrey
// Portions based on libGooPy:
// Copyright (c) 2018 Dan Boneh, Riad S. Wahby
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.
//
// This file ports the verification-only subset of handshake-org/goosig's
// JavaScript/C verifier for Handshake airdrop proofs.

package blockchain

import (
	"crypto/hmac"
	"crypto/sha256"
	"math/big"
)

const (
	gooModBytes  = 256
	gooExpBytes  = 256
	gooChalBits  = 128
	gooChalBytes = 16
	gooEllBits   = 136
	gooEllBytes  = 17
	gooEllDiff   = 512
	gooSigSize   = 2*gooModBytes + 2 + gooChalBytes +
		gooEllBytes + 4*gooModBytes + gooExpBytes +
		8*gooEllBytes + 1
)

var (
	gooRSA2048 = mustGooIntFromHex(
		"c7970ceedcc3b0754490201a7aa613cd73911081c790f5f1a8726f463550" +
			"bb5b7ff0db8e1ea1189ec72f93d1650011bd721aeeacc2acde32a04107f0" +
			"648c2813a31f5b0b7765ff8b44b4b6ffc93384b646eb09c7cf5e8592d40e" +
			"a33c80039f35b4f14a04b51f7bfd781be4d1673164ba8eb991c2c4d730bb" +
			"be35f592bdef524af7e8daefd26c66fc02c479af89d64d373f442709439d" +
			"e66ceb955f3ea37d5159f6135809f85334b5cb1813addc80cd05609f10ac" +
			"6a95ad65872c909525bdad32bc729592642920f24c61dc5b3c3b7923e56b" +
			"16a4d9d373d8721f24a3fc0f1b3131f55615172866bccc30f95054c824e7" +
			"33a5eb6817f7bc16399d48c6361cc7e5")
	gooRSA2048Half = new(big.Int).Rsh(new(big.Int).Set(gooRSA2048), 1)
	gooG           = big.NewInt(2)
	gooH           = big.NewInt(3)
	gooHashPrefix  = []byte{
		0xc8, 0x30, 0xd5, 0xfd, 0xdc, 0xb2, 0x23, 0xcd,
		0x86, 0x00, 0x7a, 0xbf, 0x91, 0xc4, 0x40, 0x27,
		0x6b, 0x00, 0x80, 0x66, 0xbc, 0xb6, 0x45, 0x91,
		0xef, 0x80, 0x61, 0xc8, 0x9c, 0x1c, 0x58, 0x82,
	}
	gooPRNGDerive = []byte{
		0x99, 0x89, 0x61, 0x8e, 0x45, 0x0e, 0x09, 0xfb,
		0xed, 0x0b, 0xc9, 0x51, 0xa3, 0xb3, 0x09, 0xa9,
		0xb5, 0xd2, 0xba, 0xe3, 0xdb, 0x76, 0x96, 0xb7,
		0x6a, 0x89, 0x42, 0x81, 0xe5, 0x65, 0x34, 0xaf,
	}
	gooPRNGPrimality = []byte{
		0xf3, 0x31, 0x84, 0xc5, 0x6d, 0x6c, 0xc4, 0xf6,
		0x0e, 0x39, 0x62, 0xa3, 0xad, 0xa4, 0xef, 0x03,
		0x97, 0xa6, 0xd6, 0x0f, 0x14, 0xc1, 0xc3, 0xa6,
		0xd8, 0xa1, 0xe6, 0x7e, 0xb4, 0x33, 0x48, 0x55,
	}
	gooGroupHash   = computeGooGroupHash()
	gooSmallPrimes = map[uint64]struct{}{
		2: {}, 3: {}, 5: {}, 7: {}, 11: {}, 13: {}, 17: {}, 19: {},
		23: {}, 29: {}, 31: {}, 37: {}, 41: {}, 43: {}, 47: {}, 53: {},
		59: {}, 61: {}, 67: {}, 71: {}, 73: {}, 79: {}, 83: {}, 89: {},
		97: {}, 101: {}, 103: {}, 107: {}, 109: {}, 113: {}, 127: {},
		131: {}, 137: {}, 139: {}, 149: {}, 151: {}, 157: {}, 163: {},
		167: {}, 173: {}, 179: {}, 181: {}, 191: {}, 193: {}, 197: {},
		199: {}, 211: {}, 223: {}, 227: {}, 229: {}, 233: {}, 239: {},
		241: {}, 251: {}, 257: {}, 263: {}, 269: {}, 271: {}, 277: {},
		281: {}, 283: {}, 293: {}, 307: {}, 311: {}, 313: {}, 317: {},
		331: {}, 337: {}, 347: {}, 349: {}, 353: {}, 359: {}, 367: {},
		373: {}, 379: {}, 383: {}, 389: {}, 397: {}, 401: {}, 409: {},
		419: {}, 421: {}, 431: {}, 433: {}, 439: {}, 443: {}, 449: {},
		457: {}, 461: {}, 463: {}, 467: {}, 479: {}, 487: {}, 491: {},
		499: {}, 503: {}, 509: {}, 521: {}, 523: {}, 541: {}, 547: {},
		557: {}, 563: {}, 569: {}, 571: {}, 577: {}, 587: {}, 593: {},
		599: {}, 601: {}, 607: {}, 613: {}, 617: {}, 619: {}, 631: {},
		641: {}, 643: {}, 647: {}, 653: {}, 659: {}, 661: {}, 673: {},
		677: {}, 683: {}, 691: {}, 701: {}, 709: {}, 719: {}, 727: {},
		733: {}, 739: {}, 743: {}, 751: {}, 757: {}, 761: {}, 769: {},
		773: {}, 787: {}, 797: {}, 809: {}, 811: {}, 821: {}, 823: {},
		827: {}, 829: {}, 839: {}, 853: {}, 857: {}, 859: {}, 863: {},
		877: {}, 881: {}, 883: {}, 887: {}, 907: {}, 911: {}, 919: {},
		929: {}, 937: {}, 941: {}, 947: {}, 953: {}, 967: {}, 971: {},
		977: {}, 983: {}, 991: {}, 997: {},
	}
)

type gooSignature struct {
	c2, c3, t             *big.Int
	chal, ell             *big.Int
	aq, bq, cq, dq, eq    *big.Int
	zW, zW2, zS1, zA, zAN *big.Int
	zS1W, zSA, zS2        *big.Int
}

type gooDRBG struct {
	k, v  []byte
	save  *big.Int
	total uint
}

func verifyAirdropGooSignature(key *airdropKey, msg, signature []byte) bool {
	if len(key.c1) != airdropGooKeySize || len(msg) != sha256.Size ||
		len(signature) != gooSigSize {

		return false
	}

	sig, ok := parseGooSignature(signature)
	if !ok {
		return false
	}

	return verifyGooSignature(msg, sig, new(big.Int).SetBytes(key.c1))
}

func parseGooSignature(serialized []byte) (*gooSignature, bool) {
	if len(serialized) != gooSigSize {
		return nil, false
	}

	var off int
	read := func(size int) *big.Int {
		value := new(big.Int).SetBytes(serialized[off : off+size])
		off += size
		return value
	}

	sig := &gooSignature{}
	sig.c2 = read(gooModBytes)
	sig.c3 = read(gooModBytes)
	sig.t = read(2)
	sig.chal = read(gooChalBytes)
	sig.ell = read(gooEllBytes)
	sig.aq = read(gooModBytes)
	sig.bq = read(gooModBytes)
	sig.cq = read(gooModBytes)
	sig.dq = read(gooModBytes)
	sig.eq = read(gooExpBytes)
	sig.zW = read(gooEllBytes)
	sig.zW2 = read(gooEllBytes)
	sig.zS1 = read(gooEllBytes)
	sig.zA = read(gooEllBytes)
	sig.zAN = read(gooEllBytes)
	sig.zS1W = read(gooEllBytes)
	sig.zSA = read(gooEllBytes)
	sig.zS2 = read(gooEllBytes)

	sign := serialized[off]
	if sign > 1 {
		return nil, false
	}
	if sign == 1 {
		sig.eq.Neg(sig.eq)
	}

	return sig, true
}

func verifyGooSignature(msg []byte, sig *gooSignature, c1 *big.Int) bool {
	if !sig.t.IsUint64() {
		return false
	}
	if _, ok := gooSmallPrimes[sig.t.Uint64()]; !ok {
		return false
	}
	if sig.chal.BitLen() > gooChalBits ||
		sig.ell.Sign() == 0 || sig.ell.BitLen() > gooEllBits ||
		absBitLen(sig.eq) > 2048 {

		return false
	}

	for _, elem := range []*big.Int{
		c1, sig.c2, sig.c3, sig.aq, sig.bq, sig.cq, sig.dq,
	} {
		if !gooIsReduced(elem) {
			return false
		}
	}

	for _, z := range []*big.Int{
		sig.zW, sig.zW2, sig.zS1, sig.zA, sig.zAN,
		sig.zS1W, sig.zSA, sig.zS2,
	} {
		if z.Sign() < 0 || z.Cmp(sig.ell) >= 0 {
			return false
		}
	}

	c1i := gooModInverse(c1)
	c2i := gooModInverse(sig.c2)
	c3i := gooModInverse(sig.c3)
	aqi := gooModInverse(sig.aq)
	bqi := gooModInverse(sig.bq)
	cqi := gooModInverse(sig.cq)
	dqi := gooModInverse(sig.dq)
	if c1i == nil || c2i == nil || c3i == nil || aqi == nil ||
		bqi == nil || cqi == nil || dqi == nil {

		return false
	}

	A := gooRecover(sig.aq, aqi, sig.ell, sig.c2, c2i, sig.chal,
		sig.zW, sig.zS1)
	B := gooRecover(sig.bq, bqi, sig.ell, sig.c3, c3i, sig.chal,
		sig.zA, sig.zS2)
	C := gooRecover(sig.cq, cqi, sig.ell, sig.c2, c2i, sig.zW,
		sig.zW2, sig.zS1W)
	D := gooRecover(sig.dq, dqi, sig.ell, c1, c1i, sig.zA,
		sig.zAN, sig.zSA)

	E := new(big.Int).Mul(sig.eq, sig.ell)
	diff := new(big.Int).Sub(sig.zW2, sig.zAN)
	diff.Mod(diff, sig.ell)
	E.Add(E, diff)
	E.Sub(E, new(big.Int).Mul(sig.t, sig.chal))

	chal, ell, key, ok := gooDerive(c1, sig.c2, sig.c3, sig.t, A, B, C,
		D, E, msg)
	if !ok || sig.chal.Cmp(chal) != 0 {
		return false
	}

	maxEll := new(big.Int).Add(ell, big.NewInt(gooEllDiff))
	if sig.ell.Cmp(ell) < 0 || sig.ell.Cmp(maxEll) > 0 {
		return false
	}

	return gooIsPrime(sig.ell, key)
}

func gooRecover(b1, b1i, e1, b2, b2i, e2, e3, e4 *big.Int) *big.Int {
	ret := new(big.Int).Exp(b1, e1, gooRSA2048)
	ret.Mul(ret, new(big.Int).Exp(b2i, e2, gooRSA2048))
	ret.Mod(ret, gooRSA2048)
	ret.Mul(ret, gooPowGH(e3, e4))
	ret.Mod(ret, gooRSA2048)
	return gooReduce(ret)
}

func gooPowGH(e1, e2 *big.Int) *big.Int {
	ret := new(big.Int).Exp(gooG, e1, gooRSA2048)
	ret.Mul(ret, new(big.Int).Exp(gooH, e2, gooRSA2048))
	ret.Mod(ret, gooRSA2048)
	return ret
}

func gooDerive(c1, c2, c3, t, A, B, C, D, E *big.Int,
	msg []byte) (*big.Int, *big.Int, []byte, bool) {

	h := sha256.New()
	h.Write(gooHashPrefix)
	h.Write(gooGroupHash[:])
	for _, item := range []struct {
		value *big.Int
		size  int
	}{
		{c1, gooModBytes},
		{c2, gooModBytes},
		{c3, gooModBytes},
		{t, 4},
		{A, gooModBytes},
		{B, gooModBytes},
		{C, gooModBytes},
		{D, gooModBytes},
		{E, gooExpBytes},
	} {
		encoded, ok := gooEncodeFixed(item.value, item.size)
		if !ok {
			return nil, nil, nil, false
		}
		h.Write(encoded)
	}

	var sign [4]byte
	if E.Sign() < 0 {
		sign[3] = 1
	}
	h.Write(sign[:])
	h.Write(msg)

	key := h.Sum(nil)
	prng := newGooDRBG(key, gooPRNGDerive)
	return prng.randomBits(gooChalBits), prng.randomBits(gooEllBits),
		key, true
}

func newGooDRBG(key, iv []byte) *gooDRBG {
	entropy := make([]byte, 0, len(iv)+len(key))
	entropy = append(entropy, iv...)
	entropy = append(entropy, key...)

	d := &gooDRBG{
		k:     make([]byte, sha256.Size),
		v:     make([]byte, sha256.Size),
		save:  new(big.Int),
		total: 0,
	}
	for i := range d.v {
		d.v[i] = 0x01
	}
	d.update(entropy)
	return d
}

func (d *gooDRBG) update(seed []byte) {
	d.k = gooHMAC(d.k, d.v, []byte{0x00}, seed)
	d.v = gooHMAC(d.k, d.v)
	if len(seed) != 0 {
		d.k = gooHMAC(d.k, d.v, []byte{0x01}, seed)
		d.v = gooHMAC(d.k, d.v)
	}
}

func (d *gooDRBG) generate(size int) []byte {
	out := make([]byte, 0, size)
	for len(out) < size {
		d.v = gooHMAC(d.k, d.v)
		left := size - len(out)
		if left > len(d.v) {
			left = len(d.v)
		}
		out = append(out, d.v[:left]...)
	}
	d.update(nil)
	return out
}

func (d *gooDRBG) randomBits(bits uint) *big.Int {
	ret := new(big.Int).Set(d.save)
	total := d.total

	for total < bits {
		ret.Lsh(ret, 256)
		ret.Or(ret, new(big.Int).SetBytes(d.generate(sha256.Size)))
		total += 256
	}

	left := total - bits
	d.save = maskLowBits(ret, left)
	d.total = left
	ret.Rsh(ret, left)
	return ret
}

func (d *gooDRBG) randomInt(max *big.Int) *big.Int {
	if max.Sign() <= 0 {
		return new(big.Int)
	}
	bits := uint(max.BitLen())
	for {
		ret := d.randomBits(bits)
		if ret.Cmp(max) < 0 {
			return ret
		}
	}
}

func gooHMAC(key []byte, parts ...[]byte) []byte {
	mac := hmac.New(sha256.New, key)
	for _, part := range parts {
		mac.Write(part)
	}
	return mac.Sum(nil)
}

func gooModInverse(x *big.Int) *big.Int {
	if x.Sign() <= 0 {
		return nil
	}
	return new(big.Int).ModInverse(x, gooRSA2048)
}

func gooReduce(x *big.Int) *big.Int {
	x = new(big.Int).Mod(x, gooRSA2048)
	if x.Cmp(gooRSA2048Half) > 0 {
		x.Sub(gooRSA2048, x)
	}
	return x
}

func gooIsReduced(x *big.Int) bool {
	return x != nil && x.Sign() >= 0 && x.Cmp(gooRSA2048Half) <= 0
}

func gooIsPrime(x *big.Int, key []byte) bool {
	switch gooIsPrimeDiv(x) {
	case 0:
		return false
	case 1:
		return true
	}

	if !gooMillerRabin(x, key, 17, true) {
		return false
	}

	return x.ProbablyPrime(0)
}

func gooIsPrimeDiv(x *big.Int) int {
	if x.Cmp(big.NewInt(1)) <= 0 {
		return 0
	}
	if x.Bit(0) == 0 {
		if x.Cmp(big.NewInt(2)) == 0 {
			return 1
		}
		return 0
	}
	for p := range gooSmallPrimes {
		prime := new(big.Int).SetUint64(p)
		if x.Cmp(prime) == 0 {
			return 1
		}
		if new(big.Int).Mod(x, prime).Sign() == 0 {
			return 0
		}
	}
	return -1
}

func gooMillerRabin(x *big.Int, key []byte, reps int, force2 bool) bool {
	if x.Cmp(big.NewInt(7)) < 0 {
		return x.Cmp(big.NewInt(2)) == 0 ||
			x.Cmp(big.NewInt(3)) == 0 ||
			x.Cmp(big.NewInt(5)) == 0
	}
	if x.Bit(0) == 0 {
		return false
	}

	nm1 := new(big.Int).Sub(x, big.NewInt(1))
	nm3 := new(big.Int).Sub(nm1, big.NewInt(2))
	q := new(big.Int).Set(nm1)
	var k uint
	for q.Bit(0) == 0 {
		q.Rsh(q, 1)
		k++
	}

	prng := newGooDRBG(key, gooPRNGPrimality)

next:
	for i := 0; i < reps; i++ {
		var base *big.Int
		if i == reps-1 && force2 {
			base = big.NewInt(2)
		} else {
			base = prng.randomInt(nm3)
			base.Add(base, big.NewInt(2))
		}

		y := new(big.Int).Exp(base, q, x)
		if y.Cmp(big.NewInt(1)) == 0 || y.Cmp(nm1) == 0 {
			continue
		}

		for j := uint(1); j < k; j++ {
			y.Mul(y, y)
			y.Mod(y, x)
			if y.Cmp(nm1) == 0 {
				continue next
			}
			if y.Cmp(big.NewInt(1)) == 0 {
				return false
			}
		}

		return false
	}

	return true
}

func computeGooGroupHash() [32]byte {
	h := sha256.New()
	for _, item := range []struct {
		value *big.Int
		size  int
	}{
		{gooG, 4},
		{gooH, 4},
		{gooRSA2048, gooModBytes},
	} {
		encoded, ok := gooEncodeFixed(item.value, item.size)
		if !ok {
			panic("invalid GooSig group constant")
		}
		h.Write(encoded)
	}
	var hash [32]byte
	copy(hash[:], h.Sum(nil))
	return hash
}

func gooEncodeFixed(x *big.Int, size int) ([]byte, bool) {
	if x == nil {
		return nil, false
	}
	abs := new(big.Int).Abs(new(big.Int).Set(x))
	if len(abs.Bytes()) > size {
		return nil, false
	}
	out := make([]byte, size)
	abs.FillBytes(out)
	return out, true
}

func maskLowBits(x *big.Int, bits uint) *big.Int {
	if bits == 0 {
		return new(big.Int)
	}
	mask := new(big.Int).Lsh(big.NewInt(1), bits)
	mask.Sub(mask, big.NewInt(1))
	return new(big.Int).And(x, mask)
}

func absBitLen(x *big.Int) int {
	if x == nil {
		return 0
	}
	return new(big.Int).Abs(new(big.Int).Set(x)).BitLen()
}

func mustGooIntFromHex(s string) *big.Int {
	value, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("invalid GooSig integer constant")
	}
	return value
}
