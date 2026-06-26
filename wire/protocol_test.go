// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestServiceFlagStringer tests the stringized output for service flag types.
func TestServiceFlagStringer(t *testing.T) {
	tests := []struct {
		in   ServiceFlag
		want string
	}{
		{0, "0x0"},
		{SFNodeNetwork, "SFNodeNetwork"},
		{SFNodeBloom, "SFNodeBloom"},
		{SFNodeGetUTXO, "0x4"},
		{SFNodeWitness, "0x8"},
		{SFNodeXthin, "0x10"},
		{SFNodeBit5, "0x20"},
		{SFNodeCF, "0x40"},
		{SFNode2X, "0x80"},
		{SFNodeNetworkLimited, "0x400"},
		{0xffffffff, "SFNodeNetwork|SFNodeBloom|0xfffffffc"},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		result := test.in.String()
		if result != test.want {
			t.Errorf("String #%d\n got: %s want: %s", i, result,
				test.want)
			continue
		}
	}
}

// TestBitcoinNetStringer tests the stringized output for bitcoin net types.
func TestBitcoinNetStringer(t *testing.T) {
	tests := []struct {
		in   BitcoinNet
		want string
	}{
		{MainNet, "MainNet"},
		{TestNet, "RegTest"},
		{0xffffffff, "Unknown BitcoinNet (4294967295)"},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		result := test.in.String()
		if result != test.want {
			t.Errorf("String #%d\n got: %s want: %s", i, result,
				test.want)
			continue
		}
	}
}

func TestHasFlag(t *testing.T) {
	tests := []struct {
		in    ServiceFlag
		check ServiceFlag
		want  bool
	}{
		{0, SFNodeNetwork, false},
		{SFNodeNetwork, SFNodeBloom, false},
		{SFNodeNetwork | SFNodeBloom, SFNodeBloom, true},
	}

	for _, test := range tests {
		require.Equal(t, test.want, test.in.HasFlag(test.check))
	}
}

func TestHandshakeProtocolConstants(t *testing.T) {
	require.Equal(t, uint32(3), HnsProtocolVersion)
	require.Equal(t, uint32(1), HnsMinProtocolVersion)
	require.Equal(t, ServiceFlag(1), SFNodeNetwork)
	require.Equal(t, ServiceFlag(2), SFNodeBloom)
}
