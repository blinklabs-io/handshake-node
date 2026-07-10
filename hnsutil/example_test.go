// Copyright (c) 2013, 2014 The btcsuite developers
// Copyright (c) 2024-2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package hnsutil_test

import (
	"fmt"
	"math"

	"github.com/blinklabs-io/handshake-node/hnsutil"
)

func ExampleAmount() {

	a := hnsutil.Amount(0)
	fmt.Println("Zero dollarydoos:", a)

	a = hnsutil.Amount(1e6)
	fmt.Println("1,000,000 dollarydoos:", a)

	a = hnsutil.Amount(1e3)
	fmt.Println("1,000 dollarydoos:", a)
	// Output:
	// Zero dollarydoos: 0 HNS
	// 1,000,000 dollarydoos: 1 HNS
	// 1,000 dollarydoos: 0.001000 HNS
}

func ExampleNewAmount() {
	amountOne, err := hnsutil.NewAmount(1)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(amountOne) //Output 1

	amountFraction, err := hnsutil.NewAmount(0.012345)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(amountFraction) //Output 2

	amountZero, err := hnsutil.NewAmount(0)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(amountZero) //Output 3

	amountNaN, err := hnsutil.NewAmount(math.NaN())
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(amountNaN) //Output 4

	// Output: 1 HNS
	// 0.012345 HNS
	// 0 HNS
	// invalid HNS amount
}

func ExampleAmount_unitConversions() {
	amount := hnsutil.Amount(444333222111)

	fmt.Println("dollarydoo to kHNS:", amount.Format(hnsutil.AmountKiloHNS))
	fmt.Println("dollarydoo to HNS:", amount)
	fmt.Println("dollarydoo to MilliHNS:", amount.Format(hnsutil.AmountMilliHNS))
	fmt.Println("dollarydoo to Doo:", amount.Format(hnsutil.AmountDoo))

	// Output:
	// dollarydoo to kHNS: 444.333222111 kHNS
	// dollarydoo to HNS: 444333.222111 HNS
	// dollarydoo to MilliHNS: 444333222.111 mHNS
	// dollarydoo to Doo: 444333222111 Doo
}
