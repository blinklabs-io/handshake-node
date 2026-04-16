// Copyright (c) 2013, 2014 The btcsuite developers
// Copyright (c) 2024-2026 The blinklabs-io developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package hnsutil_test

import (
	"math"
	"testing"

	. "github.com/blinklabs-io/handshake-node/hnsutil"
)

func TestAmountCreation(t *testing.T) {
	tests := []struct {
		name     string
		amount   float64
		valid    bool
		expected Amount
	}{
		// Positive tests.
		{
			name:     "zero",
			amount:   0,
			valid:    true,
			expected: 0,
		},
		{
			name:     "max producible",
			amount:   2.04e9,
			valid:    true,
			expected: MaxDoo,
		},
		{
			name:     "min producible",
			amount:   -2.04e9,
			valid:    true,
			expected: -MaxDoo,
		},
		{
			name:     "exceeds max producible",
			amount:   2.04e9 + 1e-6,
			valid:    true,
			expected: MaxDoo + 1,
		},
		{
			name:     "exceeds min producible",
			amount:   -2.04e9 - 1e-6,
			valid:    true,
			expected: -MaxDoo - 1,
		},
		{
			name:     "one hundred",
			amount:   100,
			valid:    true,
			expected: 100 * DooPerHNS,
		},
		{
			name:     "fraction",
			amount:   0.012345,
			valid:    true,
			expected: 12345,
		},
		{
			name:     "rounding up",
			amount:   54.999999999999943157,
			valid:    true,
			expected: 55 * DooPerHNS,
		},
		{
			name:     "rounding down",
			amount:   55.000000000000056843,
			valid:    true,
			expected: 55 * DooPerHNS,
		},

		// Negative tests.
		{
			name:   "not-a-number",
			amount: math.NaN(),
			valid:  false,
		},
		{
			name:   "-infinity",
			amount: math.Inf(-1),
			valid:  false,
		},
		{
			name:   "+infinity",
			amount: math.Inf(1),
			valid:  false,
		},
	}

	for _, test := range tests {
		a, err := NewAmount(test.amount)
		switch {
		case test.valid && err != nil:
			t.Errorf("%v: Positive test Amount creation failed with: %v", test.name, err)
			continue
		case !test.valid && err == nil:
			t.Errorf("%v: Negative test Amount creation succeeded (value %v) when should fail", test.name, a)
			continue
		}

		if a != test.expected {
			t.Errorf("%v: Created amount %v does not match expected %v", test.name, a, test.expected)
			continue
		}
	}
}

func TestAmountUnitConversions(t *testing.T) {
	tests := []struct {
		name      string
		amount    Amount
		unit      AmountUnit
		converted float64
		s         string
	}{
		{
			name:      "MHNS",
			amount:    MaxDoo,
			unit:      AmountMegaHNS,
			converted: 2040,
			s:         "2040 MHNS",
		},
		{
			name:      "kHNS",
			amount:    444333222111,
			unit:      AmountKiloHNS,
			converted: 444.333222111,
			s:         "444.333222111 kHNS",
		},
		{
			name:      "HNS",
			amount:    444333222111,
			unit:      AmountHNS,
			converted: 444333.222111,
			s:         "444333.222111 HNS",
		},
		{
			name:      "a thousand dollarydoos as HNS",
			amount:    1000,
			unit:      AmountHNS,
			converted: 0.001,
			s:         "0.001000 HNS",
		},
		{
			name:      "a single dollarydoo as HNS",
			amount:    1,
			unit:      AmountHNS,
			converted: 0.000001,
			s:         "0.000001 HNS",
		},
		{
			name:      "amount with trailing zero but no decimals",
			amount:    10000000,
			unit:      AmountHNS,
			converted: 10,
			s:         "10 HNS",
		},
		{
			name:      "mHNS",
			amount:    444333222111,
			unit:      AmountMilliHNS,
			converted: 444333222.111,
			s:         "444333222.111 mHNS",
		},
		{

			name:      "dollarydoo",
			amount:    444333222111,
			unit:      AmountDoo,
			converted: 444333222111,
			s:         "444333222111 Doo",
		},
		{

			name:      "non-standard unit",
			amount:    444333222111,
			unit:      AmountUnit(-1),
			converted: 4443332.22111,
			s:         "4443332.22111 1e-1 HNS",
		},
	}

	for _, test := range tests {
		f := test.amount.ToUnit(test.unit)
		if f != test.converted {
			t.Errorf("%v: converted value %v does not match expected %v", test.name, f, test.converted)
			continue
		}

		s := test.amount.Format(test.unit)
		if s != test.s {
			t.Errorf("%v: format '%v' does not match expected '%v'", test.name, s, test.s)
			continue
		}

		// Verify that Amount.ToHNS works as advertised.
		f1 := test.amount.ToUnit(AmountHNS)
		f2 := test.amount.ToHNS()
		if f1 != f2 {
			t.Errorf("%v: ToHNS does not match ToUnit(AmountHNS): %v != %v", test.name, f1, f2)
		}

		// Verify that Amount.String works as advertised.
		s1 := test.amount.Format(AmountHNS)
		s2 := test.amount.String()
		if s1 != s2 {
			t.Errorf("%v: String does not match Format(AmountHNS): %v != %v", test.name, s1, s2)
		}
	}
}

func TestAmountMulF64(t *testing.T) {
	tests := []struct {
		name string
		amt  Amount
		mul  float64
		res  Amount
	}{
		{
			name: "Multiply 0.1 HNS by 2",
			amt:  100e3, // 0.1 HNS
			mul:  2,
			res:  200e3, // 0.2 HNS
		},
		{
			name: "Multiply 0.2 HNS by 1.02",
			amt:  200e3, // 0.2 HNS
			mul:  1.02,
			res:  204e3, // 0.204 HNS
		},
		{
			name: "Multiply 0.1 HNS by -2",
			amt:  100e3, // 0.1 HNS
			mul:  -2,
			res:  -200e3, // -0.2 HNS
		},
		{
			name: "Multiply 0.2 HNS by -1.02",
			amt:  200e3, // 0.2 HNS
			mul:  -1.02,
			res:  -204e3, // -0.204 HNS
		},
		{
			name: "Multiply -0.1 HNS by 2",
			amt:  -100e3, // -0.1 HNS
			mul:  2,
			res:  -200e3, // -0.2 HNS
		},
		{
			name: "Multiply -0.2 HNS by 1.02",
			amt:  -200e3, // -0.2 HNS
			mul:  1.02,
			res:  -204e3, // -0.204 HNS
		},
		{
			name: "Multiply -0.1 HNS by -2",
			amt:  -100e3, // -0.1 HNS
			mul:  -2,
			res:  200e3, // 0.2 HNS
		},
		{
			name: "Multiply -0.2 HNS by -1.02",
			amt:  -200e3, // -0.2 HNS
			mul:  -1.02,
			res:  204e3, // 0.204 HNS
		},
		{
			name: "Round down",
			amt:  49, // 49 dollarydoos
			mul:  0.01,
			res:  0,
		},
		{
			name: "Round up",
			amt:  50, // 50 dollarydoos
			mul:  0.01,
			res:  1, // 1 dollarydoo
		},
		{
			name: "Multiply by 0.",
			amt:  1e6, // 1 HNS
			mul:  0,
			res:  0, // 0 HNS
		},
		{
			name: "Multiply 1 by 0.5.",
			amt:  1, // 1 dollarydoo
			mul:  0.5,
			res:  1, // 1 dollarydoo
		},
		{
			name: "Multiply 100 by 66%.",
			amt:  100, // 100 dollarydoos
			mul:  0.66,
			res:  66, // 66 dollarydoos
		},
		{
			name: "Multiply 100 by 66.6%.",
			amt:  100, // 100 dollarydoos
			mul:  0.666,
			res:  67, // 67 dollarydoos
		},
		{
			name: "Multiply 100 by 2/3.",
			amt:  100, // 100 dollarydoos
			mul:  2.0 / 3,
			res:  67, // 67 dollarydoos
		},
	}

	for _, test := range tests {
		a := test.amt.MulF64(test.mul)
		if a != test.res {
			t.Errorf("%v: expected %v got %v", test.name, test.res, a)
		}
	}
}
