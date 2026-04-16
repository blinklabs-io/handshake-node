// Copyright (c) 2013-2014 The btcsuite developers
// Copyright (c) 2024-2026 The blinklabs-io developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package hnsutil

const (
	// DooPerHNSCent is the number of dollarydoos in one HNS cent.
	DooPerHNSCent = 1e4

	// DooPerHNS is the number of dollarydoos in one HNS (1 HNS).
	//
	// Handshake uses 6 decimal places so 1 HNS = 1_000_000 dollarydoos.
	DooPerHNS = 1e6

	// MaxDoo is the maximum transaction amount allowed in dollarydoos.
	//
	// Handshake has a maximum supply of 2.04 billion HNS.
	MaxDoo = 2.04e9 * DooPerHNS
)
