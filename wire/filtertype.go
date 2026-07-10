// Copyright (c) 2026 Blink Labs Software
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

// FilterType represents a committed filter type. The Bitcoin compact-filter
// P2P packets are not part of Handshake's message table, but the filter index
// and RPC surface still key filters by type.
type FilterType uint8

const (
	// GCSFilterRegular is the regular filter type.
	GCSFilterRegular FilterType = iota
)

const (
	// MaxCFilterDataSize is the maximum byte size of a committed filter.
	MaxCFilterDataSize = 256 * 1024
)
