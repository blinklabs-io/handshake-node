// Copyright (c) 2013, 2014 The btcsuite developers
// Copyright (c) 2024-2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package hnsutil

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// AmountUnit describes a method of converting an Amount to something other
// than the base unit of a Handshake coin.  The value of the AmountUnit is
// the exponent component of the decadic multiple to convert from an amount
// in HNS to an amount counted in units.  Handshake amounts have 6 decimal
// places (1 HNS = 1,000,000 dollarydoos), so a unit of 0 represents whole
// HNS and a unit of -6 represents dollarydoos.
type AmountUnit int

// These constants define various units used when describing a Handshake
// monetary amount.
const (
	AmountMegaHNS  AmountUnit = 6
	AmountKiloHNS  AmountUnit = 3
	AmountHNS      AmountUnit = 0
	AmountMilliHNS AmountUnit = -3
	AmountDoo      AmountUnit = -6
)

// String returns the unit as a string.  For recognized units, the SI prefix
// is used, or "Doo" (dollarydoo) for the base unit.  For all unrecognized
// units, "1eN HNS" is returned, where N is the AmountUnit.
func (u AmountUnit) String() string {
	switch u {
	case AmountMegaHNS:
		return "MHNS"
	case AmountKiloHNS:
		return "kHNS"
	case AmountHNS:
		return "HNS"
	case AmountMilliHNS:
		return "mHNS"
	case AmountDoo:
		return "Doo"
	default:
		return "1e" + strconv.FormatInt(int64(u), 10) + " HNS"
	}
}

// Amount represents the base Handshake monetary unit (colloquially referred
// to as a dollarydoo).  A single Amount is equal to 1e-6 of a HNS.
type Amount int64

// round converts a floating point number, which may or may not be representable
// as an integer, to the Amount integer type by rounding to the nearest integer.
// This is performed by adding or subtracting 0.5 depending on the sign, and
// relying on integer truncation to round the value to the nearest Amount.
func round(f float64) Amount {
	if f < 0 {
		return Amount(f - 0.5)
	}
	return Amount(f + 0.5)
}

// NewAmount creates an Amount from a floating point value representing some
// value in HNS.  NewAmount errors if f is NaN or +-Infinity, but does not
// check that the amount is within the total amount of HNS producible as f
// may not refer to an amount at a single moment in time.
//
// NewAmount is specifically for converting HNS to dollarydoos.  For creating
// a new Amount with an int64 value which denotes a quantity of dollarydoos,
// do a simple type conversion from type int64 to Amount.
func NewAmount(f float64) (Amount, error) {
	// The amount is only considered invalid if it cannot be represented
	// as an integer type.  This may happen if f is NaN or +-Infinity.
	switch {
	case math.IsNaN(f):
		fallthrough
	case math.IsInf(f, 1):
		fallthrough
	case math.IsInf(f, -1):
		return 0, errors.New("invalid HNS amount")
	}

	return round(f * DooPerHNS), nil
}

// ToUnit converts a monetary amount counted in HNS base units to a floating
// point value representing an amount of HNS.
func (a Amount) ToUnit(u AmountUnit) float64 {
	return float64(a) / math.Pow10(int(u+6))
}

// ToHNS is the equivalent of calling ToUnit with AmountHNS.
func (a Amount) ToHNS() float64 {
	return a.ToUnit(AmountHNS)
}

// Format formats a monetary amount counted in HNS base units as a string for
// a given unit.  The conversion will succeed for any unit, however, known
// units will be formatted with an appended label describing the units with
// SI notation, or "Doo" for the base unit.
func (a Amount) Format(u AmountUnit) string {
	units := " " + u.String()
	formatted := strconv.FormatFloat(a.ToUnit(u), 'f', -int(u+6), 64)

	// When formatting full HNS, add trailing zeroes for numbers with a
	// decimal point to ease reading of the dollarydoo amount.
	if u == AmountHNS {
		if strings.Contains(formatted, ".") {
			return fmt.Sprintf("%.6f%s", a.ToUnit(u), units)
		}
	}
	return formatted + units
}

// String is the equivalent of calling Format with AmountHNS.
func (a Amount) String() string {
	return a.Format(AmountHNS)
}

// MulF64 multiplies an Amount by a floating point value.  While this is not
// an operation that must typically be done by a full node or wallet, it is
// useful for services that build on top of Handshake (for example,
// calculating a fee by multiplying by a percentage).
func (a Amount) MulF64(f float64) Amount {
	return round(float64(a) * f)
}
